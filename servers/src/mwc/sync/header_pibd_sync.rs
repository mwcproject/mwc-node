// Copyright 2024 The MWC Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::mwc::sync::header_pibd_hashes_sync::HeadersPibdHashSyncSnapshot;
use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils::{self, LatencyTracker, SyncRequestResponses, SyncResponse};
use mwc_chain::pibd_params::{self, PibdParams};
use mwc_chain::txhashset::HeaderHashesDesegmenter;
use mwc_chain::types::HEADERS_PER_BATCH;
use mwc_chain::{pipe, Chain, Error, Options, SyncState, SyncStatus};
use mwc_core::core::{
	hash::{Hash, Hashed},
	BlockHeader,
};
use mwc_crates::log::{debug, info};
use mwc_crates::parking_lot::{Mutex, RwLock};
use mwc_crates::rand::seq::IteratorRandom;
use mwc_p2p::{Capabilities, Peer, PeerAddr, Peers};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

const BATCH_SIZE: usize = HEADERS_PER_BATCH as usize;

struct HeaderPibdTask {
	hash: Hash,
	// Height of the locator checkpoint; the response starts at height + 1.
	height: u64,
	end_hash: Option<Hash>,
	request: Option<HeaderPibdTaskRequest>,
}

struct HeaderPibdTaskRequest {
	peer: PeerAddr,
	// Keep the start only for latency samples; the deadline is fixed at send.
	sent_at: Instant,
	expires_at: Instant,
	// Contiguous headers received for this task, in height order.
	headers: Vec<BlockHeader>,
}

impl HeaderPibdTask {
	fn is_ready(&self) -> bool {
		self.request
			.as_ref()
			.is_some_and(|request| request.headers.len() == BATCH_SIZE)
	}

	fn reset(&mut self) {
		self.request = None;
	}

	fn applicable_headers(&self, target: u64) -> Result<&[BlockHeader], Error> {
		let count = target
			.checked_sub(self.height)
			.filter(|count| *count > 0)
			.ok_or_else(|| Error::Other("Invalid checkpoint task range".into()))?
			.min(HEADERS_PER_BATCH as u64) as usize;
		self.request
			.as_ref()
			.and_then(|request| request.headers.get(..count))
			.ok_or_else(|| Error::Other("Incomplete checkpoint task buffer".into()))
	}

	fn receive(
		&mut self,
		headers: &[BlockHeader],
		remaining: u64,
		target: u64,
		context_id: u32,
	) -> Result<(), Error> {
		let request = self
			.request
			.as_mut()
			.ok_or_else(|| Error::Other("Unassigned checkpoint task".into()))?;
		let first = headers
			.first()
			.ok_or_else(|| Error::InvalidBlocksSeries("Empty checkpoint response".into()))?;
		let start_height = self
			.height
			.checked_add(1)
			.ok_or_else(|| Error::Other("Checkpoint start height overflow".into()))?;
		let offset = first
			.height
			.checked_sub(start_height)
			.and_then(|n| usize::try_from(n).ok())
			.filter(|offset| *offset < BATCH_SIZE)
			.ok_or(Error::InvalidHeaderHeight(first.height))?;
		if offset > request.headers.len() {
			return Err(Error::InvalidBlocksSeries(
				"Skipped checkpoint headers".into(),
			));
		}
		// Note, already checked that offset < BATCH_SIZE
		if headers.len() > BATCH_SIZE - offset || remaining > (BATCH_SIZE - headers.len()) as u64 {
			return Err(Error::InvalidBlocksSeries(
				"Oversized checkpoint response".into(),
			));
		}
		for (i, header) in headers.iter().enumerate() {
			let expected_height = start_height
				.checked_add((offset + i) as u64)
				.ok_or_else(|| Error::Other("Checkpoint header height overflow".into()))?;
			if header.height != expected_height {
				return Err(Error::InvalidHeaderHeight(header.height));
			}
			if let Some(known) = request.headers.get(offset + i) {
				// A proof hash alone does not identify every field of a header.
				if known != header {
					return Err(Error::InvalidBlocksSeries(
						"Conflicting checkpoint response".into(),
					));
				}
			} else {
				request.headers.push(header.clone());
			}
		}
		if self.is_ready() {
			let mut prev = self.hash;
			// The wire response is always 512 headers. Only the prefix through
			// the archive target belongs to this checkpoint download.
			for header in self.applicable_headers(target)? {
				if header.prev_hash != prev {
					return Err(Error::InvalidBlocksSeries(
						"Broken checkpoint header linkage".into(),
					));
				}
				pipe::validate_header_context_id(context_id, header)?;
				prev = header.hash(context_id)?;
				pipe::validate_header_hash(context_id, &prev)?;
			}
			if self.end_hash.is_some_and(|expected| expected != prev) {
				return Err(Error::InvalidHash);
			}
		}
		Ok(())
	}
}

struct HeaderPibdDownload {
	root: Hash,
	target: u64,
	tasks: VecDeque<HeaderPibdTask>,
	agreed_peers: HashSet<PeerAddr>,
	latency: LatencyTracker,
}

impl HeaderPibdDownload {
	fn new(hashes: &[Hash], root: Hash, target: u64, current_height: u64) -> Result<Self, Error> {
		if current_height >= target {
			return Err(Error::Other(
				"Header download target already reached".into(),
			));
		}
		if hashes.len() as u64 != target / HEADERS_PER_BATCH as u64 + 1 {
			return Err(Error::Other("Incomplete checkpoint hash list".into()));
		}
		let tasks = hashes
			.iter()
			.enumerate()
			.skip((current_height / HEADERS_PER_BATCH as u64) as usize)
			.filter_map(|(i, hash)| {
				let height = i as u64 * HEADERS_PER_BATCH as u64;
				if height < target {
					Some(HeaderPibdTask {
						hash: *hash,
						height,
						end_hash: hashes.get(i + 1).copied(),
						request: None,
					})
				} else {
					None
				}
			})
			.collect();
		Ok(Self {
			root,
			target,
			tasks,
			agreed_peers: HashSet::new(),
			latency: LatencyTracker::new(),
		})
	}

	fn matches(&self, hashes: &HeaderHashesDesegmenter) -> bool {
		self.root == *hashes.get_headers_root_hash() && self.target == hashes.get_target_height()
	}

	fn request_timeout(&self) -> Duration {
		let max_timeout = Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64);
		self.latency
			.get_average_latency()
			.map_or(max_timeout, |latency| {
				latency
					.saturating_mul(2)
					.max(Duration::from_secs(5))
					.min(max_timeout)
			})
	}

	fn expire_tasks(
		&mut self,
		now: Instant,
		scores: &SyncPeers,
		task_limit: usize,
	) -> Result<(), Error> {
		for task in self.tasks.iter_mut().take(task_limit) {
			let Some(request) = &task.request else {
				continue;
			};
			if !task.is_ready() && now >= request.expires_at {
				let elapsed = request
					.expires_at
					.checked_duration_since(request.sent_at)
					.ok_or_else(|| Error::Other("Checkpoint deadline precedes send time".into()))?;
				scores.report_no_response(
					&request.peer,
					format!(
						"Incomplete checkpoint response at {}: {}/{} headers",
						task.height,
						request.headers.len(),
						BATCH_SIZE
					),
				);
				self.latency.add_latency(elapsed.as_millis() as i64);
				task.reset();
			}
		}
		Ok(())
	}

	fn receive_headers(
		&mut self,
		peer: &PeerAddr,
		headers: &[BlockHeader],
		remaining: u64,
		context_id: u32,
		now: Instant,
		scores: &SyncPeers,
	) -> Result<bool, Error> {
		let Some(first) = headers.first() else {
			return Ok(false);
		};
		let Some(front) = self.tasks.front() else {
			return Ok(false);
		};
		let Some(index) = first
			.height
			.checked_sub(1)
			.map(|height| height / HEADERS_PER_BATCH as u64)
			.and_then(|index| index.checked_sub(front.height / HEADERS_PER_BATCH as u64))
			.and_then(|index| usize::try_from(index).ok())
		else {
			return Ok(false);
		};
		let Some(task) = self.tasks.get_mut(index) else {
			return Ok(false);
		};
		let Some(request) = task
			.request
			.as_ref()
			.filter(|request| &request.peer == peer)
		else {
			return Ok(false);
		};
		if task.is_ready() {
			return Ok(true);
		}
		let sent_at = request.sent_at;
		match task.receive(headers, remaining, self.target, context_id) {
			Ok(()) if task.is_ready() => {
				info!(
					"Received {} block headers from {}, height {}",
					BATCH_SIZE,
					peer,
					task.height + 1,
				);
				let elapsed = now.saturating_duration_since(sent_at);
				self.latency.add_latency(elapsed.as_millis() as i64);
				scores.report_ok_response(peer);
			}
			Ok(()) => (),
			Err(err) if err.is_bad_data() => {
				scores.report_error_response(
					peer,
					format!("Invalid checkpoint headers at {}: {}", task.height, err),
				);
				task.reset();
			}
			Err(err) => return Err(err),
		}
		Ok(true)
	}
}

pub struct HeaderPibdSync {
	chain: Arc<Chain>,
	pibd_params: Arc<PibdParams>,
	download: Mutex<Option<HeaderPibdDownload>>,
	// Serializes initialization, sending and chain application. Responses only
	// hold download briefly while filling their own task's buffer.
	work_lock: Mutex<()>,
}

impl HeaderPibdSync {
	pub fn new(chain: Arc<Chain>) -> Self {
		Self {
			pibd_params: chain.get_pibd_params().clone(),
			chain,
			download: Mutex::new(None),
			work_lock: Mutex::new(()),
		}
	}

	// Called with work_lock held. A new commitment discards the old queue.
	fn prepare_download(
		&self,
		hashes: &HeaderHashesDesegmenter,
		agreed_peers: &HashSet<PeerAddr>,
	) -> Result<(), Error> {
		{
			// First check if current instance is good (archive height wasn't changed)
			let mut download = self.download.lock();
			if let Some(download) = download
				.as_mut()
				.filter(|download| download.matches(hashes))
			{
				download.agreed_peers = agreed_peers.clone();
				return Ok(());
			}
		}
		*self.download.lock() = None;
		let checkpoints = hashes.get_header_hashes()?;
		let target = hashes.get_target_height();
		{
			let tip = self.chain.header_head()?;
			let max_index = tip.height.min(target) / HEADERS_PER_BATCH as u64;
			for index in (0..=max_index).rev() {
				let header = match self
					.chain
					.get_header_by_height(index * HEADERS_PER_BATCH as u64)
				{
					Ok(header) => header,
					Err(err) if err.is_not_found() => continue,
					Err(err) => return Err(err),
				};
				let checkpoint = usize::try_from(index)
					.ok()
					.and_then(|index| checkpoints.get(index))
					.ok_or_else(|| Error::Other("Missing checkpoint hash".into()))?;
				if header.hash(self.chain.get_context_id())? == *checkpoint {
					continue;
				}
				// Preserve the existing below-horizon mismatch recovery policy.
				self.chain
					.reset_pibd_chain(mwc_chain::PibdResetMode::Both)?;
				// The selected chain is now at genesis; do not read its old heights.
				break;
			}
		}
		let current_height = self.chain.header_head()?.height;
		if current_height >= target {
			return Ok(());
		}
		let mut download = HeaderPibdDownload::new(
			&checkpoints,
			*hashes.get_headers_root_hash(),
			target,
			current_height,
		)?;
		download.agreed_peers = agreed_peers.clone();
		*self.download.lock() = Some(download);
		Ok(())
	}

	pub fn request(
		&self,
		peers: &Arc<Peers>,
		sync_state: &SyncState,
		scores: &SyncPeers,
		hashes: &HeadersPibdHashSyncSnapshot,
		best_height: u64,
	) -> Result<SyncResponse, Error> {
		let Some(_work) = self.work_lock.try_lock() else {
			return Ok(SyncResponse::new(
				SyncRequestResponses::HasMoreHeadersToApply,
				Capabilities::HEADER_HIST,
				"Applying checkpoint headers".into(),
			));
		};
		let tip = self.chain.header_head()?;
		let pending = self
			.download
			.lock()
			.as_ref()
			.is_some_and(|download| !download.tasks.is_empty());
		if !pending && tip.height >= best_height.saturating_sub(7) {
			return Ok(SyncResponse::new(
				SyncRequestResponses::HeadersReady,
				Capabilities::HEADER_HIST,
				format!("Header head {} vs {}", tip.height, best_height),
			));
		}
		if hashes.pibd_headers_are_loaded {
			*self.download.lock() = None;
		} else {
			if !hashes.is_complete() {
				*self.download.lock() = None;
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForHeadersHash,
					Capabilities::HEADER_HIST,
					"Waiting for checkpoint hashes".into(),
				));
			}
			let desegmenter = hashes
				.headers_hash_desegmenter
				.as_ref()
				.ok_or_else(|| Error::Other("Missing header hashes desegmenter".into()))?;
			{
				let desegmenter = desegmenter.read_recursive();
				if desegmenter.get_target_height() != hashes.target_archive_height {
					return Err(Error::Other("Checkpoint target changed".into()));
				}
				self.prepare_download(&desegmenter, &hashes.agreed_peers)?;
			}
			self.apply_ready_tasks(scores)?;
			let pending_target = {
				let download = self.download.lock();
				download
					.as_ref()
					.filter(|download| !download.tasks.is_empty())
					.map(|download| download.target)
			};
			if let Some(target) = pending_target {
				sync_state.update(SyncStatus::HeaderSync {
					current_height: self.chain.header_head()?.height.min(target),
					archive_height: target,
				});
				let peer_count = self.send_requests(peers, scores)?;
				return Ok(SyncResponse::new(
					if peer_count == 0 {
						SyncRequestResponses::WaitingForPeers
					} else {
						SyncRequestResponses::Syncing
					},
					Capabilities::HEADER_HIST,
					"Downloading checkpoint headers".into(),
				));
			}
		}
		Ok(SyncResponse::new(
			SyncRequestResponses::HeadersPibdReady,
			Capabilities::HEADER_HIST,
			"Checkpoint headers are ready".into(),
		))
	}

	pub fn receive_headers(
		&self,
		peer: &PeerAddr,
		headers: &[BlockHeader],
		remaining: u64,
		scores: &SyncPeers,
		hashes: Option<Arc<RwLock<HeaderHashesDesegmenter>>>,
		peers: &Arc<Peers>,
	) -> Result<bool, Error> {
		let Some(hashes) = hashes else {
			return Ok(false);
		};
		let handled = {
			let hashes = hashes.read_recursive();
			let mut download = self.download.lock();
			let Some(download) = download
				.as_mut()
				.filter(|download| download.matches(&hashes))
			else {
				return Ok(false);
			};
			download.receive_headers(
				peer,
				headers,
				remaining,
				self.chain.get_context_id(),
				Instant::now(),
				scores,
			)?
		};
		if handled {
			if let Some(_work) = self.work_lock.try_lock() {
				self.apply_ready_tasks(scores)?;
				self.send_requests(peers, scores)?;
			}
		}
		Ok(handled)
	}

	// Called with work_lock held. Pop only after the chain commits this task.
	fn apply_ready_tasks(&self, scores: &SyncPeers) -> Result<(), Error> {
		loop {
			let headers = {
				let download = self.download.lock();
				let Some(download) = download.as_ref() else {
					return Ok(());
				};
				let Some(task) = download.tasks.front().filter(|task| task.is_ready()) else {
					return Ok(());
				};
				task.applicable_headers(download.target)?.to_vec()
			};
			let last = headers
				.last()
				.ok_or_else(|| Error::Other("Empty checkpoint task".into()))?;
			let result = u64::try_from(last.timestamp.timestamp_micros())
				.map_err(|_| Error::InvalidBlockTime)
				.and_then(|time| {
					self.chain
						.sync_block_headers(&headers, Options::NONE, time.max(1))
				});
			let mut download = self.download.lock();
			let download = download
				.as_mut()
				.ok_or_else(|| Error::Other("Header download missing during application".into()))?;
			match result {
				Ok(_) => {
					download.tasks.pop_front().ok_or_else(|| {
						Error::Other("Checkpoint task missing during application".into())
					})?;
				}
				Err(err) if err.is_bad_data() => {
					let task = download.tasks.front_mut().ok_or_else(|| {
						Error::Other("Checkpoint task missing during application".into())
					})?;
					let request = task.request.as_ref().ok_or_else(|| {
						Error::Other("Complete checkpoint task has no request".into())
					})?;
					scores.report_error_response(
						&request.peer,
						format!("Invalid checkpoint headers at {}: {}", task.height, err),
					);
					task.reset();
					return Ok(());
				}
				Err(err) => return Err(err),
			}
		}
	}

	// Called with work_lock held. There is exactly one supplier per task.
	fn send_requests(&self, peers: &Arc<Peers>, scores: &SyncPeers) -> Result<usize, Error> {
		let mut sends = Vec::new();
		let peer_count;
		{
			let mut download = self.download.lock();
			let Some(download) = download.as_mut() else {
				return Ok(0);
			};
			let task_limit = self.pibd_params.get_headers_buffer_len();
			let now = Instant::now();
			download.expire_tasks(now, scores, task_limit)?;
			let candidates: Vec<Arc<Peer>> = sync_utils::get_qualify_peers(
				peers,
				download.target,
				Capabilities::HEADERS_HASH | Capabilities::HEADER_HIST,
			)
			.into_iter()
			.filter(|peer| download.agreed_peers.contains(&peer.info.addr))
			.collect();
			peer_count = candidates.len();
			let mut counts: HashMap<PeerAddr, usize> = HashMap::new();
			// Count live assignments before filling gaps, including tasks deferred
			// by a smaller window. Expired deferred requests retain their state
			// until processed but no longer consume a peer's request allowance.
			for request in download
				.tasks
				.iter()
				.filter_map(|task| task.request.as_ref())
			{
				if now < request.expires_at {
					*counts.entry(request.peer.clone()).or_default() += 1;
				}
			}
			let per_peer = self.pibd_params.get_segments_request_per_peer();
			let timeout = download.request_timeout();
			let expires_at = now
				.checked_add(timeout)
				.ok_or_else(|| Error::Other("Checkpoint request deadline overflow".into()))?;
			let mut rng = mwc_crates::rand::rng();
			// Ready buffers also occupy this window, so a stalled first task
			// cannot cause unbounded accumulation of later responses.
			for (index, task) in download.tasks.iter_mut().take(task_limit).enumerate() {
				if task.request.is_some() {
					continue;
				}
				let Some(peer) = candidates
					.iter()
					.filter(|peer| counts.get(&peer.info.addr).copied().unwrap_or(0) < per_peer)
					.choose(&mut rng)
				else {
					break;
				};
				task.request = Some(HeaderPibdTaskRequest {
					peer: peer.info.addr.clone(),
					sent_at: now,
					expires_at,
					headers: Vec::with_capacity(BATCH_SIZE),
				});
				*counts.entry(peer.info.addr.clone()).or_default() += 1;
				sends.push((index, peer.clone(), task.hash));
			}
		}
		for (index, peer, hash) in sends {
			debug!(
				"Requesting checkpoint headers after {} from {}",
				hash, peer.info.addr
			);
			if let Err(err) = peer.send_header_request(vec![hash]) {
				let mut download = self.download.lock();
				let task = download
					.as_mut()
					.and_then(|download| download.tasks.get_mut(index))
					.ok_or_else(|| {
						Error::Other("Checkpoint task missing after send failure".into())
					})?;
				if task
					.request
					.as_ref()
					.is_some_and(|request| request.peer == peer.info.addr)
					&& !task.is_ready()
				{
					task.reset();
					scores.report_no_response(
						&peer.info.addr,
						format!("Failed to send checkpoint headers request: {}", err),
					);
				}
			}
		}
		Ok(peer_count)
	}
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
	use super::*;
	use mwc_chain::types::NoopAdapter;
	use mwc_core::core::pmmr::{self, ReadablePMMR, VecBackend, PMMR};
	use mwc_core::{consensus, global, pow, ser::ProtocolVersion};
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_crates::tempfile::TempDir;
	use mwc_p2p::{
		msg::Msg,
		types::{Direction, PeerInfo, PeerLiveInfo},
		DummyAdapter,
	};

	fn addr(id: u8) -> PeerAddr {
		PeerAddr::Ip(([127, 0, 0, id], 3414).into())
	}

	fn hash(id: u8) -> Hash {
		Hash::from_vec(&[id; 32])
	}

	// Build linked synthetic headers for task assembly checks. They do not satisfy
	// chain validation; tests that commit headers use mine_headers instead.
	fn dummy_headers(height: u64, mut prev: Hash) -> Vec<BlockHeader> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		(1..=HEADERS_PER_BATCH as u64)
			.map(|offset| {
				let mut header = BlockHeader::default(0);
				header.height = height + offset;
				header.prev_hash = prev;
				prev = header.hash(0).unwrap();
				header
			})
			.collect()
	}

	fn assign(task: &mut HeaderPibdTask, peer: PeerAddr, now: Instant, timeout: Duration) {
		task.request = Some(HeaderPibdTaskRequest {
			peer,
			sent_at: now,
			expires_at: now + timeout,
			headers: Vec::with_capacity(BATCH_SIZE),
		});
	}

	fn download_for(headers: &[BlockHeader], target: u64) -> HeaderPibdDownload {
		let context_id = headers[0].pow.proof.context_id;
		let mut hashes = vec![headers[0].prev_hash];
		hashes.extend(
			headers
				.chunks_exact(BATCH_SIZE)
				.take((target / HEADERS_PER_BATCH as u64) as usize)
				.map(|batch| batch.last().unwrap().hash(context_id).unwrap()),
		);
		HeaderPibdDownload::new(&hashes, hash(42), target, 0).unwrap()
	}

	// Resume from height 700: the first remaining task must start at checkpoint 512.
	// Reject missing checkpoint hashes and already-reached targets, but allow a final
	// partial range whose target has no following checkpoint hash.
	#[test]
	fn tasks_resume_at_checkpoint_and_require_all_checkpoint_hashes() {
		let hashes = vec![hash(1), hash(2), hash(3), hash(4)];
		let download = HeaderPibdDownload::new(&hashes, hash(42), 1536, 700).unwrap();
		assert_eq!(download.tasks.len(), 2);
		assert_eq!(download.tasks[0].height, 512);
		assert_eq!(download.tasks[1].end_hash, Some(hash(4)));
		assert!(HeaderPibdDownload::new(&hashes[..3], hash(42), 1536, 0).is_err());
		for current_height in [1536, 1537] {
			assert!(matches!(
				HeaderPibdDownload::new(&hashes, hash(42), 1536, current_height),
				Err(Error::Other(message)) if message == "Header download target already reached"
			));
		}
		let partial = HeaderPibdDownload::new(&hashes[..2], hash(42), 600, 512).unwrap();
		assert_eq!(partial.tasks.len(), 1);
		assert_eq!(partial.tasks[0].end_hash, None);
	}

	// Assign two ranges to one peer, interleave their pages, and repeat every page.
	// Unassigned responses and other peers are ignored; each task must contain exactly
	// its own 512 headers, with duplicates leaving its original deadline unchanged.
	#[test]
	fn interleaved_and_repeated_pages_fill_only_the_assigned_task() {
		let first = dummy_headers(0, hash(1));
		let second = dummy_headers(512, first.last().unwrap().hash(0).unwrap());
		let all = [first.clone(), second.clone()].concat();
		let mut download = download_for(&all, 1024);
		let scores = SyncPeers::new();
		let now = Instant::now();
		assert!(!download
			.receive_headers(&addr(1), &first[..32], 480, 0, now, &scores)
			.unwrap());
		assert!(download.tasks.iter().all(|task| task.request.is_none()));
		for task in &mut download.tasks {
			assign(
				task,
				addr(1),
				now,
				Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
			);
		}
		assert!(!download
			.receive_headers(&addr(2), &second[..32], 480, 0, now, &scores)
			.unwrap());
		for offset in (0..512).step_by(32) {
			for batch in [&second, &first] {
				assert!(download
					.receive_headers(
						&addr(1),
						&batch[offset..offset + 32],
						(480 - offset) as u64,
						0,
						now,
						&scores
					)
					.unwrap());
				assert!(download
					.receive_headers(
						&addr(1),
						&batch[offset..offset + 32],
						(480 - offset) as u64,
						0,
						now,
						&scores
					)
					.unwrap());
			}
		}
		assert!(download.tasks.iter().all(HeaderPibdTask::is_ready));
		assert_eq!(download.tasks[0].request.as_ref().unwrap().headers, first);
		assert_eq!(download.tasks[1].request.as_ref().unwrap().headers, second);
		assert!(download
			.tasks
			.iter()
			.all(|task| task.request.as_ref().unwrap().expires_at
				== now + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)));
	}

	// Skip the first or a later page, then separately introduce a height gap within a page.
	// Each gap must reset the assigned request immediately, even above a partial target.
	#[test]
	fn skipped_pages_and_heights_reject_the_response_immediately() {
		let headers = dummy_headers(0, hash(1));
		let scores = SyncPeers::new();
		let now = Instant::now();
		for received in [0, 32] {
			let mut download = download_for(&headers, 512);
			assign(
				&mut download.tasks[0],
				addr(1),
				now,
				Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
			);
			if received > 0 {
				download
					.receive_headers(&addr(1), &headers[..received], 480, 0, now, &scores)
					.unwrap();
			}
			let offset = received + 32;
			assert!(download
				.receive_headers(
					&addr(1),
					&headers[offset..offset + 32],
					(480 - offset) as u64,
					0,
					now,
					&scores
				)
				.unwrap());
			assert!(download.tasks[0].request.is_none());
		}

		// A gap inside a page is also bad data, including in terminal padding.
		for target in [1, 512] {
			let mut download = download_for(&headers, target);
			assign(
				&mut download.tasks[0],
				addr(1),
				now,
				Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
			);
			let mut page = headers[..32].to_vec();
			page[8].height += 1;
			assert!(download
				.receive_headers(&addr(1), &page, 480, 0, now, &scores)
				.unwrap());
			assert!(download.tasks[0].request.is_none());
		}
	}

	// End a wire response after only 32 headers, expire the incomplete task, and reassign it.
	// The short response must not extend the deadline; only the new supplier can complete
	// the retry, while a late response from the previous supplier is ignored.
	#[test]
	fn incomplete_response_keeps_its_deadline_and_retry_ignores_old_supplier() {
		let headers = dummy_headers(0, hash(1));
		let mut download = download_for(&headers, 512);
		let scores = SyncPeers::new();
		let now = Instant::now();
		assign(
			&mut download.tasks[0],
			addr(1),
			now,
			Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
		);
		// Even an explicitly short wire reply is still missing most of the task.
		assert!(download
			.receive_headers(
				&addr(1),
				&headers[..32],
				0,
				0,
				now + Duration::from_secs(29),
				&scores
			)
			.unwrap());
		assert_eq!(
			download.tasks[0].request.as_ref().unwrap().expires_at,
			now + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)
		);
		// The expiration loop resets the incomplete task before it is retried.
		download
			.expire_tasks(
				now + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
				&scores,
				1,
			)
			.unwrap();
		assert!(download.tasks[0].request.is_none());
		assign(
			&mut download.tasks[0],
			addr(2),
			now + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
			Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
		);
		assert!(!download
			.receive_headers(
				&addr(1),
				&headers,
				0,
				0,
				now + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
				&scores
			)
			.unwrap());
		assert!(download
			.receive_headers(
				&addr(2),
				&headers,
				0,
				0,
				now + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
				&scores
			)
			.unwrap());
		assert!(download.tasks[0].is_ready());
	}

	// Deliver pages after the deadline but before running expiration, with and without
	// completing the range. A complete task survives and records its full latency;
	// an incomplete task is reset when the expiration loop finally runs.
	#[test]
	fn late_pages_are_processed_before_the_expiration_loop() {
		let headers = dummy_headers(0, hash(1));
		let timeout = Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64);
		let sent_at = Instant::now();
		let deadline = sent_at + timeout;
		let received_at = deadline + Duration::from_secs(1);
		for complete in [false, true] {
			let scores = SyncPeers::new();
			let mut download = download_for(&headers, 512);
			assign(&mut download.tasks[0], addr(1), sent_at, timeout);
			assert!(download
				.receive_headers(&addr(1), &headers[..32], 480, 0, received_at, &scores)
				.unwrap());
			let request = download.tasks[0].request.as_ref().unwrap();
			assert_eq!(request.headers.len(), 32);
			assert_eq!(request.expires_at, deadline);
			if complete {
				assert!(download
					.receive_headers(&addr(1), &headers[32..], 0, 0, received_at, &scores)
					.unwrap());
			}
			download.expire_tasks(received_at, &scores, 1).unwrap();
			if complete {
				assert!(download.tasks[0].is_ready());
				assert_eq!(download.tasks[0].request.as_ref().unwrap().peer, addr(1));
				assert_eq!(
					download.latency.get_average_latency(),
					Some(timeout + Duration::from_secs(1))
				);
			} else {
				assert!(download.tasks[0].request.is_none());
			}
		}
	}

	// Give three tasks partial buffers and expired deadlines, then grow a shrunken window.
	// Only tasks inside each current window are reset; deferred requests retain their
	// peer, timestamps, and buffered header until their turn enters the window.
	#[test]
	fn expiration_uses_current_window_and_preserves_deferred_tasks() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let mut download = HeaderPibdDownload::new(&[hash(1); 4], hash(42), 1536, 0).unwrap();
		let scores = SyncPeers::new();
		let now = Instant::now();
		let timeout = Duration::from_secs(10);
		for task in &mut download.tasks {
			assign(task, addr(1), now, timeout);
			let mut header = BlockHeader::default(0);
			header.height = task.height + 1;
			task.request.as_mut().unwrap().headers.push(header);
		}
		download.expire_tasks(now, &scores, 3).unwrap();
		// Shrink the window, then allow deferred tasks back into it.
		for task_limit in [1, 2, 3] {
			download
				.expire_tasks(now + timeout, &scores, task_limit)
				.unwrap();
			for (index, task) in download.tasks.iter().enumerate() {
				if index < task_limit {
					assert!(task.request.is_none());
				} else {
					let request = task.request.as_ref().unwrap();
					assert_eq!(request.peer, addr(1));
					assert_eq!(request.sent_at, now);
					assert_eq!(request.expires_at, now + timeout);
					assert_eq!(request.headers.len(), 1);
					assert_eq!(request.headers[0].height, task.height + 1);
				}
			}
		}
	}

	// Receive one page after two seconds and finish after four: only completion supplies
	// a latency sample, giving future attempts an eight-second timeout. Verify that the
	// original deadline stays fixed, timeouts affect later estimates, and bounds apply.
	#[test]
	fn timeout_uses_complete_response_latency_and_is_fixed_per_attempt() {
		let headers = dummy_headers(0, hash(1));
		let mut download = download_for(&headers, 512);
		let scores = SyncPeers::new();
		let now = Instant::now();
		assert_eq!(
			download.request_timeout(),
			Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)
		);
		let timeout = download.request_timeout();
		assign(&mut download.tasks[0], addr(1), now, timeout);
		download
			.receive_headers(
				&addr(1),
				&headers[..32],
				480,
				0,
				now + Duration::from_secs(2),
				&scores,
			)
			.unwrap();
		assert_eq!(download.latency.get_average_latency(), None);
		download
			.receive_headers(
				&addr(1),
				&headers[32..],
				0,
				0,
				now + Duration::from_secs(4),
				&scores,
			)
			.unwrap();
		assert_eq!(download.request_timeout(), Duration::from_secs(8));
		assert_eq!(
			download.tasks[0].request.as_ref().unwrap().expires_at,
			now + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)
		);
		// Expiring the next attempt adds its eight-second duration to the latency history.
		download.tasks[0].reset();
		assign(&mut download.tasks[0], addr(1), now, Duration::from_secs(8));
		download
			.expire_tasks(now + Duration::from_secs(8), &scores, 1)
			.unwrap();
		assert_eq!(download.request_timeout(), Duration::from_secs(12));
		// Extremely fast and slow samples must respect the minimum and configured maximum.
		for _ in 0..15 {
			download.latency.add_latency(1);
		}
		assert_eq!(download.request_timeout(), Duration::from_secs(5));
		for _ in 0..15 {
			download.latency.add_latency(60_000);
		}
		assert_eq!(
			download.request_timeout(),
			Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)
		);
	}

	// Corrupt each range invariant independently, then replay a page with changed content
	// but the same header hash. Reject every defect, empty pages, and an overflowing
	// task height through errors rather than accepting the data or panicking.
	#[test]
	fn checkpoint_validation_rejects_bad_ranges_and_conflicting_duplicates() {
		let headers = dummy_headers(0, hash(1));
		for defect in 0..5 {
			let mut download = download_for(&headers, 512);
			assign(
				&mut download.tasks[0],
				addr(1),
				Instant::now(),
				Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
			);
			let mut bad = headers.clone();
			// Exercise the start anchor, heights, internal links, end checkpoint, and context.
			match defect {
				0 => bad[0].prev_hash = hash(99),
				1 => bad[8].height += 1,
				2 => bad[8].prev_hash = hash(99),
				3 => download.tasks[0].end_hash = Some(hash(99)),
				_ => bad[8].pow.proof.context_id = 99,
			}
			assert!(
				download.tasks[0].receive(&bad, 0, 512, 0).is_err(),
				"defect {}",
				defect
			);
		}
		let mut download = download_for(&headers, 512);
		assign(
			&mut download.tasks[0],
			addr(1),
			Instant::now(),
			Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
		);
		download.tasks[0]
			.receive(&headers[..32], 480, 512, 0)
			.unwrap();
		let mut duplicate = headers[..32].to_vec();
		duplicate[8].timestamp += mwc_crates::chrono::Duration::seconds(1);
		assert_eq!(duplicate[8].hash(0).unwrap(), headers[8].hash(0).unwrap());
		assert!(download.tasks[0].receive(&duplicate, 480, 512, 0).is_err());
		assert!(matches!(
			download.tasks[0].receive(&[], 0, 512, 0),
			Err(Error::InvalidBlocksSeries(_))
		));
		download.tasks[0].height = u64::MAX;
		assert!(matches!(
			download.tasks[0].receive(&headers[..1], 511, u64::MAX, 0),
			Err(Error::Other(_))
		));
	}

	struct Fixture {
		sync: HeaderPibdSync,
		peers: Arc<Peers>,
		scores: SyncPeers,
		_chain_dir: TempDir,
		_peer_dir: TempDir,
	}

	impl Fixture {
		fn new() -> Self {
			Self::with_context(0)
		}

		fn with_context(context_id: u32) -> Self {
			if context_id != 0 {
				global::init_global_chain_type(context_id, global::ChainTypes::AutomatedTesting)
					.unwrap();
				global::init_global_nrd_enabled(context_id, false).unwrap();
			}
			global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
			global::set_local_nrd_enabled(false);
			let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			let chain_dir = TempDir::new().unwrap();
			let chain = Arc::new(
				Chain::init(
					&secp,
					context_id,
					chain_dir.path().to_str().unwrap().into(),
					Arc::new(NoopAdapter {}),
					global::get_genesis_block(&secp, context_id).unwrap(),
					pow::verify_size,
					false,
					HashSet::new(),
					None,
					None,
					false,
				)
				.unwrap(),
			);
			let peer_dir = TempDir::new().unwrap();
			let store =
				mwc_p2p::store::PeerStore::new(context_id, peer_dir.path().to_str().unwrap())
					.unwrap();
			Self {
				sync: HeaderPibdSync::new(chain),
				peers: Arc::new(Peers::new(
					store,
					Arc::new(DummyAdapter {}),
					&mwc_p2p::P2PConfig::default(),
				)),
				scores: SyncPeers::new(),
				_chain_dir: chain_dir,
				_peer_dir: peer_dir,
			}
		}

		fn peer(&self, id: u8, target: u64) -> mwc_crates::crossbeam::channel::Receiver<Msg> {
			let info = PeerInfo {
				capabilities: Capabilities::HEADERS_HASH | Capabilities::HEADER_HIST,
				user_agent: "header-task-test".into(),
				version: ProtocolVersion::local(),
				addr: addr(id),
				direction: Direction::Outbound,
				live_info: Arc::new(RwLock::new(PeerLiveInfo::new(pow::Difficulty::min()))),
				tx_base_fee: 0,
			};
			info.update(
				target + u64::from(global::state_sync_threshold(0)),
				pow::Difficulty::min(),
			);
			let (peer, receiver) = Peer::connected_for_test(info, 0, Arc::new(DummyAdapter {}));
			self.peers.add_connected(Arc::new(peer)).unwrap();
			receiver
		}
	}

	impl Drop for Fixture {
		fn drop(&mut self) {
			let context_id = self.sync.chain.get_context_id();
			pipe::release_context_data(context_id);
			if context_id != 0 {
				global::release_context_data(context_id);
			}
		}
	}

	// Connect peers with matching, missing, or different archive commitments and schedule.
	// Only eligible agreed peers receive tasks, within the buffer and per-peer limits.
	// Repeated scheduling sends nothing extra; expiring one partial task retries only it.
	#[test]
	fn scheduler_uses_agreed_peers_and_existing_limits_without_duplicate_sends() {
		let f = Fixture::new();
		let target = 51200;
		let first = f.peer(1, target);
		let second = f.peer(2, target);
		let uncommitted = f.peer(3, target);
		let other_height = f.peer(4, target + global::txhashset_archive_interval(0));
		let mut download =
			HeaderPibdDownload::new(&vec![hash(1); 101], hash(42), target, 0).unwrap();
		download.agreed_peers = [addr(1), addr(2), addr(4)].into_iter().collect();
		*f.sync.download.lock() = Some(download);
		let _work = f.sync.work_lock.lock();
		assert_eq!(f.sync.send_requests(&f.peers, &f.scores).unwrap(), 2);
		let n1 = first.try_iter().count();
		let n2 = second.try_iter().count();
		let per_peer = f.sync.pibd_params.get_segments_request_per_peer();
		let expected = (per_peer * 2).min(f.sync.pibd_params.get_headers_buffer_len());
		assert_eq!(n1 + n2, expected);
		assert!(n1 <= per_peer && n2 <= per_peer);
		assert_eq!(uncommitted.try_iter().count(), 0);
		assert_eq!(other_height.try_iter().count(), 0);
		f.sync.send_requests(&f.peers, &f.scores).unwrap();
		assert_eq!(first.try_iter().count() + second.try_iter().count(), 0);
		{
			let mut state = f.sync.download.lock();
			let task = &mut state.as_mut().unwrap().tasks[0];
			let request = task.request.as_mut().unwrap();
			request
				.headers
				.push(dummy_headers(task.height, task.hash)[0].clone());
			request.expires_at = Instant::now();
		}
		f.sync.send_requests(&f.peers, &f.scores).unwrap();
		assert_eq!(first.try_iter().count() + second.try_iter().count(), 1);
		{
			let state = f.sync.download.lock();
			let request = state.as_ref().unwrap().tasks[0].request.as_ref().unwrap();
			assert!(request.headers.is_empty());
			assert!(request.expires_at > Instant::now());
		}

		// A stalled front task plus ready later tasks fill the memory window.
		let window = f.sync.pibd_params.get_headers_buffer_len();
		{
			let mut state = f.sync.download.lock();
			let state = state.as_mut().unwrap();
			for task in state.tasks.iter_mut().take(window) {
				assign(
					task,
					addr(1),
					Instant::now(),
					Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
				);
				if task.height > 0 {
					task.request.as_mut().unwrap().headers = dummy_headers(task.height, task.hash);
				}
			}
		}
		f.sync.send_requests(&f.peers, &f.scores).unwrap();
		assert_eq!(first.try_iter().count() + second.try_iter().count(), 0);
		assert!(f
			.sync
			.download
			.lock()
			.as_ref()
			.unwrap()
			.tasks
			.iter()
			.skip(window)
			.all(|task| task.request.is_none()));
	}

	// Supply enough agreed peers to fill the header buffer while many more tasks remain.
	// Scheduling must assign exactly the first buffer-sized window, respect every peer's
	// request limit, and leave all later tasks unassigned.
	#[test]
	fn scheduler_uses_the_header_buffer_limit_for_outstanding_requests() {
		let f = Fixture::new();
		let target = HEADERS_PER_BATCH as u64 * 500;
		let task_limit = f.sync.pibd_params.get_headers_buffer_len();
		let per_peer = f.sync.pibd_params.get_segments_request_per_peer();
		let mut download =
			HeaderPibdDownload::new(&vec![hash(1); 501], hash(42), target, 0).unwrap();
		assert!(task_limit < download.tasks.len());
		let receivers: Vec<_> = (1..=task_limit.div_ceil(per_peer))
			.map(|id| {
				let id = u8::try_from(id).unwrap();
				download.agreed_peers.insert(addr(id));
				f.peer(id, target)
			})
			.collect();
		*f.sync.download.lock() = Some(download);
		let _work = f.sync.work_lock.lock();
		assert_eq!(
			f.sync.send_requests(&f.peers, &f.scores).unwrap(),
			receivers.len()
		);
		let requests: Vec<_> = receivers
			.iter()
			.map(|receiver| receiver.try_iter().count())
			.collect();
		assert_eq!(requests.iter().sum::<usize>(), task_limit);
		assert!(requests.iter().all(|count| *count <= per_peer));
		let state = f.sync.download.lock();
		let state = state.as_ref().unwrap();
		assert!(state
			.tasks
			.iter()
			.take(task_limit)
			.all(|task| task.request.is_some()));
		assert!(state
			.tasks
			.iter()
			.skip(task_limit)
			.all(|task| task.request.is_none()));
	}

	// Occupy a peer's request allowance with tasks beyond the current processing window.
	// Live deadlines block new sends; elapsed deadlines allow new work inside the window.
	// Deferred request state remains intact and contributes no latency sample yet.
	#[test]
	fn requests_outside_current_window_occupy_slots_until_they_expire() {
		for expired in [false, true] {
			let f = Fixture::new();
			let target = HEADERS_PER_BATCH as u64 * 500;
			let receiver = f.peer(1, target);
			let task_limit = f.sync.pibd_params.get_headers_buffer_len();
			let per_peer = f.sync.pibd_params.get_segments_request_per_peer();
			let mut download =
				HeaderPibdDownload::new(&vec![hash(1); 501], hash(42), target, 0).unwrap();
			download.agreed_peers.insert(addr(1));
			assert!(task_limit + per_peer <= download.tasks.len());
			let now = Instant::now();
			let timeout = if expired {
				Duration::ZERO
			} else {
				Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)
			};
			for task in download.tasks.iter_mut().skip(task_limit).take(per_peer) {
				assign(task, addr(1), now, timeout);
			}
			*f.sync.download.lock() = Some(download);
			let _work = f.sync.work_lock.lock();
			assert_eq!(f.sync.send_requests(&f.peers, &f.scores).unwrap(), 1);
			let expected_sends = if expired { per_peer } else { 0 };
			assert_eq!(receiver.try_iter().count(), expected_sends);
			let state = f.sync.download.lock();
			let state = state.as_ref().unwrap();
			assert_eq!(
				state
					.tasks
					.iter()
					.take(task_limit)
					.filter(|task| task.request.is_some())
					.count(),
				expected_sends
			);
			for task in state.tasks.iter().skip(task_limit).take(per_peer) {
				let request = task.request.as_ref().unwrap();
				assert_eq!(request.peer, addr(1));
				assert_eq!(request.expires_at, now + timeout);
			}
			assert_eq!(state.latency.get_average_latency(), None);
		}
	}

	// With a target of one header, alternate test cases between silence and a one-header
	// reply: both still lack the required 512-header task response. Repeated expiration
	// scans fine each attempt once, and seven failed attempts ban the supplier.
	#[test]
	fn empty_and_incomplete_tasks_are_fined_once_and_eventually_banned() {
		for partial in [false, true] {
			let f = Fixture::new();
			let _receiver = f.peer(1, 10);
			let headers = dummy_headers(0, f.sync.chain.genesis().hash(0).unwrap());
			let mut download = download_for(&headers, 1);
			let now = Instant::now();
			for attempt in 0..7 {
				assign(
					&mut download.tasks[0],
					addr(1),
					now,
					Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
				);
				if partial {
					download
						.receive_headers(&addr(1), &headers[..1], 0, 0, now, &f.scores)
						.unwrap();
				}
				assert!(!download.tasks[0].is_ready());
				for _ in 0..10 {
					download
						.expire_tasks(
							now + Duration::from_secs(
								pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64,
							),
							&f.scores,
							1,
						)
						.unwrap();
				}
				f.scores.apply_peers_status(&f.peers);
				assert_eq!(f.peers.is_banned(&addr(1)).unwrap(), attempt == 6);
			}
		}
	}

	// Corrupt local request metadata so its deadline precedes its send time.
	// Repeated scheduling must return an error without recording latency or banning
	// the peer for this local inconsistency.
	#[test]
	fn invalid_request_deadline_returns_error_without_fining_peer() {
		let f = Fixture::new();
		let _receiver = f.peer(1, 512);
		let headers = dummy_headers(0, hash(1));
		let now = Instant::now();
		let mut download = download_for(&headers, 512);
		assign(&mut download.tasks[0], addr(1), now, Duration::ZERO);
		download.tasks[0].request.as_mut().unwrap().sent_at = now + Duration::from_secs(1);
		*f.sync.download.lock() = Some(download);
		for _ in 0..7 {
			assert!(matches!(
				f.sync.send_requests(&f.peers, &f.scores),
				Err(Error::Other(_))
			));
		}
		assert_eq!(
			f.sync
				.download
				.lock()
				.as_ref()
				.unwrap()
				.latency
				.get_average_latency(),
			None
		);
		f.scores.apply_peers_status(&f.peers);
		assert!(!f.peers.is_banned(&addr(1)).unwrap());
	}

	// Fill two linked tasks with synthetic headers, then try to apply the queue.
	// The front task fails chain validation and is reset for retry; the complete later
	// task stays buffered, and the chain must remain at genesis.
	#[test]
	fn bad_front_task_is_retried_without_dropping_later_ready_tasks() {
		let f = Fixture::new();
		let first = dummy_headers(0, f.sync.chain.genesis().hash(0).unwrap());
		let second = dummy_headers(512, first.last().unwrap().hash(0).unwrap());
		let headers = [first, second].concat();
		let mut download = download_for(&headers, 1024);
		for (task, batch) in download.tasks.iter_mut().zip(headers.chunks(512)) {
			assign(
				task,
				addr(1),
				Instant::now(),
				Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
			);
			task.receive(batch, 0, 1024, 0).unwrap();
		}
		*f.sync.download.lock() = Some(download);
		f.sync.apply_ready_tasks(&f.scores).unwrap();
		let state = f.sync.download.lock();
		let tasks = &state.as_ref().unwrap().tasks;
		assert_eq!(tasks.len(), 2);
		assert!(tasks[0].request.is_none());
		assert!(tasks[1].is_ready());
		assert_eq!(f.sync.chain.header_head().unwrap().height, 0);
	}

	// Complete a task, then corrupt either the target or its starting height.
	// Applying inconsistent local metadata must return an error while preserving the
	// complete buffer and leaving the chain head unchanged.
	#[test]
	fn inconsistent_ready_task_returns_error_and_preserves_headers() {
		let f = Fixture::new();
		let headers = dummy_headers(0, f.sync.chain.genesis().hash(0).unwrap());
		for defect in 0..2 {
			let mut download = download_for(&headers, 1);
			assign(
				&mut download.tasks[0],
				addr(1),
				Instant::now(),
				Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
			);
			download.tasks[0].receive(&headers, 0, 1, 0).unwrap();
			if defect == 0 {
				download.target = 0;
			} else {
				download.tasks[0].height = 2;
			}
			*f.sync.download.lock() = Some(download);
			assert!(matches!(
				f.sync.apply_ready_tasks(&f.scores),
				Err(Error::Other(_))
			));
			assert_eq!(
				f.sync.download.lock().as_ref().unwrap().tasks[0]
					.request
					.as_ref()
					.unwrap()
					.headers,
				headers
			);
			assert_eq!(f.sync.chain.header_head().unwrap().height, 0);
		}
	}

	// Assemble a complete task whose parent is absent from the local chain.
	// Both direct application and the receive path must propagate the orphan error
	// and retain the ready task so its headers are not lost.
	#[test]
	fn local_apply_failure_retains_the_complete_task() {
		let f = Fixture::new();
		let headers = dummy_headers(0, hash(99));
		let mut download = download_for(&headers, 1);
		let hashes = checkpoint_hashes(&[hash(99)], 1);
		download.root = *hashes.get_headers_root_hash();
		assign(
			&mut download.tasks[0],
			addr(1),
			Instant::now(),
			Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
		);
		download.tasks[0].receive(&headers, 0, 1, 0).unwrap();
		*f.sync.download.lock() = Some(download);
		assert!(matches!(
			f.sync.apply_ready_tasks(&f.scores),
			Err(Error::Orphan(_))
		));
		assert!(matches!(
			f.sync.receive_headers(
				&addr(1),
				&headers,
				0,
				&f.scores,
				Some(Arc::new(RwLock::new(hashes))),
				&f.peers,
			),
			Err(Error::Orphan(_))
		));
		assert!(f.sync.download.lock().as_ref().unwrap().tasks[0].is_ready());
	}

	fn checkpoint_hashes(hashes: &[Hash], target: u64) -> HeaderHashesDesegmenter {
		let mut backend = VecBackend::new(0);
		let mut mmr = PMMR::new(&mut backend);
		for hash in hashes {
			mmr.push(hash).unwrap();
		}
		let root = mmr.root().unwrap();
		let mut desegmenter = HeaderHashesDesegmenter::new(0, hashes[0], target, root).unwrap();
		for id in desegmenter.next_segments(0, 10).unwrap() {
			let segment = mwc_core::core::Segment::<Hash>::from_pmmr(
				id,
				&mmr.readonly_pmmr(),
				None,
				Hash::LEN,
				pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			)
			.unwrap();
			let segment = desegmenter.validate_segment(segment).unwrap();
			desegmenter.apply_segment(&segment).unwrap();
		}
		assert!(desegmenter.is_complete());
		assert_eq!(desegmenter.get_header_hashes().unwrap(), hashes);
		desegmenter
	}

	// Finish checkpoint discovery and begin buffering headers, then connect more peers.
	// Peers agreeing with the selected root join the download; a different root does not.
	// Refreshing this peer list must preserve the active supplier, deadline, and buffer.
	#[test]
	fn new_peers_can_join_after_checkpoint_hashes_are_complete() {
		use crate::mwc::sync::header_pibd_hashes_sync::{
			HeadersPibdHashResponseStatus, HeadersPibdHashSync,
		};

		let f = Fixture::new();
		let target = global::txhashset_archive_interval(0);
		let best_height = target + u64::from(global::state_sync_threshold(0));
		let first = f.peer(1, target);
		let second = f.peer(2, target);
		let genesis = f.sync.chain.genesis().hash(0).unwrap();
		let mut backend = VecBackend::new(0);
		let mut mmr = PMMR::new(&mut backend);
		mmr.push(&genesis).unwrap();
		let root = mmr.root().unwrap();
		let sync_state = SyncState::new();
		let mut hashes = HeadersPibdHashSync::new(f.sync.chain.clone());
		// Agree on one root with two peers, then satisfy the single checkpoint segment.
		hashes
			.request_impl(&f.peers, &sync_state, &f.scores, best_height)
			.unwrap();
		assert_eq!(first.try_iter().count(), 1);
		assert_eq!(second.try_iter().count(), 1);
		for id in [1, 2] {
			assert!(matches!(
				hashes.receive_headers_hash_response(&addr(id), target, root, &f.scores),
				HeadersPibdHashResponseStatus::Accepted
			));
		}
		hashes
			.request_impl(&f.peers, &sync_state, &f.scores, best_height)
			.unwrap();
		let first_requests = first.try_iter().count();
		let second_requests = second.try_iter().count();
		assert_eq!(first_requests + second_requests, 1);
		let supplier = if first_requests == 1 {
			addr(1)
		} else {
			addr(2)
		};
		let desegmenter = hashes.get_headers_hash_desegmenter().unwrap();
		let segment_id = desegmenter
			.write()
			.next_segments(0, 1)
			.unwrap()
			.pop()
			.unwrap();
		let segment = mwc_core::core::Segment::<Hash>::from_pmmr(
			segment_id,
			&mmr.readonly_pmmr(),
			None,
			Hash::LEN,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
		)
		.unwrap();
		hashes
			.receive_header_hashes_segment(&supplier, root, segment, &f.scores)
			.unwrap();
		assert!(desegmenter.read().is_complete());

		// Start the header download and save a partial page before discovering new peers.
		let snapshot = hashes.snapshot_for_best_height(best_height);
		f.sync
			.request(&f.peers, &sync_state, &f.scores, &snapshot, best_height)
			.unwrap();
		let (assigned_peer, deadline) = {
			let download = f.sync.download.lock();
			let request = download.as_ref().unwrap().tasks[0]
				.request
				.as_ref()
				.unwrap();
			(request.peer.clone(), request.expires_at)
		};
		let headers = dummy_headers(0, genesis);
		assert!(f
			.sync
			.receive_headers(
				&assigned_peer,
				&headers[..32],
				480,
				&f.scores,
				Some(desegmenter.clone()),
				&f.peers,
			)
			.unwrap());
		first.try_iter().for_each(drop);
		second.try_iter().for_each(drop);

		let mut agreed = snapshot.agreed_peers;
		// Discover peers both on the first completion pass and on later passes.
		for (id, response_root) in [(3, root), (4, root), (5, hash(99))] {
			let receiver = f.peer(id, target);
			assert!(hashes.request_pre(best_height).unwrap().is_none());
			let response = hashes
				.request_impl(&f.peers, &sync_state, &f.scores, best_height)
				.unwrap();
			assert_eq!(response.response, SyncRequestResponses::HeadersHashReady);
			assert_eq!(receiver.try_iter().count(), 1);
			// Repeated scheduling must not duplicate the outstanding root request.
			hashes
				.request_impl(&f.peers, &sync_state, &f.scores, best_height)
				.unwrap();
			assert_eq!(receiver.try_iter().count(), 0);
			assert!(matches!(
				hashes.receive_headers_hash_response(&addr(id), target, response_root, &f.scores),
				HeadersPibdHashResponseStatus::Accepted
			));
			if response_root == root {
				agreed.insert(addr(id));
			}
			let snapshot = hashes.snapshot_for_best_height(best_height);
			assert_eq!(snapshot.agreed_peers, agreed);
			f.sync
				.request(&f.peers, &sync_state, &f.scores, &snapshot, best_height)
				.unwrap();
			let download = f.sync.download.lock();
			let download = download.as_ref().unwrap();
			assert_eq!(download.agreed_peers, agreed);
			let request = download.tasks[0].request.as_ref().unwrap();
			assert_eq!(request.headers, headers[..32]);
			assert_eq!(request.peer, assigned_peer);
			assert_eq!(request.expires_at, deadline);
		}
		assert_eq!(first.try_iter().count() + second.try_iter().count(), 0);
	}

	// Buffer a page, refresh the agreeing peers, then change the root and target in turn.
	// A peer-only update keeps the partial task; a new commitment replaces the queue,
	// ignores responses tied to the old root, and creates tasks for the new target.
	#[test]
	fn new_root_or_target_replaces_tasks_but_peer_updates_preserve_progress() {
		let f = Fixture::new();
		let genesis = f.sync.chain.genesis().hash(0).unwrap();
		let first = checkpoint_hashes(&[genesis, hash(1)], 512);
		let second = checkpoint_hashes(&[genesis, hash(2)], 512);
		let next_target = checkpoint_hashes(&[genesis, hash(2)], 513);
		let agreed = [addr(1)].into_iter().collect();
		f.sync.prepare_download(&first, &agreed).unwrap();
		let now = Instant::now();
		let headers = dummy_headers(0, genesis);
		{
			let mut state = f.sync.download.lock();
			let task = &mut state.as_mut().unwrap().tasks[0];
			assign(
				task,
				addr(1),
				now,
				Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
			);
			task.receive(&headers[..32], 480, 512, 0).unwrap();
		}
		let updated = [addr(1), addr(2)].into_iter().collect();
		f.sync.prepare_download(&first, &updated).unwrap();
		{
			let state = f.sync.download.lock();
			let state = state.as_ref().unwrap();
			assert_eq!(state.agreed_peers, updated);
			let request = state.tasks[0].request.as_ref().unwrap();
			assert_eq!(request.headers.len(), 32);
			assert_eq!(
				request.expires_at,
				now + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)
			);
		}
		f.sync.prepare_download(&second, &agreed).unwrap();
		assert!(f.sync.download.lock().as_ref().unwrap().tasks[0]
			.request
			.is_none());
		assert!(!f
			.sync
			.receive_headers(
				&addr(1),
				&headers,
				0,
				&f.scores,
				Some(Arc::new(RwLock::new(first))),
				&f.peers
			)
			.unwrap());
		f.sync.prepare_download(&next_target, &agreed).unwrap();
		assert_eq!(f.sync.download.lock().as_ref().unwrap().tasks.len(), 2);
	}

	// Keep an entirely matching prefix, then disagree first at an older checkpoint
	// and then at the newest one. Each mismatch must reset both chain heads and
	// restart at genesis without continuing lookups against the reset PMMR.
	#[test]
	fn prepare_download_checks_all_checkpoints_and_resets_on_any_mismatch() {
		let context_id = 971_202;
		let f = Fixture::with_context(context_id);
		let body_hash = mine_first_body(&f.sync.chain);
		let genesis = f.sync.chain.genesis();
		let genesis_hash = genesis.hash(context_id).unwrap();
		let headers = mine_headers(genesis, 1024);
		let checkpoints = [
			genesis_hash,
			headers[511].hash(context_id).unwrap(),
			headers[1023].hash(context_id).unwrap(),
			hash(99),
		];
		for mismatch in [None, Some(1), Some(2)] {
			for batch in headers.chunks(BATCH_SIZE) {
				f.sync
					.chain
					.sync_block_headers(batch, Options::NONE, 1)
					.unwrap();
			}
			let mut expected = checkpoints;
			if let Some(index) = mismatch {
				expected[index] = hash(98);
			}
			if mismatch != Some(2) {
				// The first mismatch must rebuild a real body whose retained tail
				// is above genesis. A normal reset_chain_head would reject it.
				assert_eq!(f.sync.chain.head().unwrap().height, 1);
				assert_eq!(f.sync.chain.tail().unwrap().height, 1);
			}
			f.sync
				.prepare_download(&checkpoint_hashes(&expected, 1536), &HashSet::new())
				.unwrap();
			let download = f.sync.download.lock();
			let download = download.as_ref().unwrap();
			if mismatch.is_none() {
				assert_eq!(f.sync.chain.header_head().unwrap().height, 1024);
				assert_eq!(download.tasks.front().unwrap().height, 1024);
				assert_eq!(download.tasks.len(), 1);
			} else {
				assert_eq!(
					f.sync.chain.header_head().unwrap().last_block_h,
					genesis_hash
				);
				assert_eq!(f.sync.chain.head().unwrap().last_block_h, genesis_hash);
				assert_eq!(f.sync.chain.tail().unwrap().last_block_h, genesis_hash);
				assert!(!f.sync.chain.block_exists(&body_hash).unwrap());
				assert!(f
					.sync
					.chain
					.get_block_header(&body_hash)
					.unwrap_err()
					.is_not_found());
				assert_eq!(f.sync.chain.get_header_by_height(0).unwrap().height, 0);
				for header in &headers {
					let hash = header.hash(context_id).unwrap();
					assert!(f
						.sync
						.chain
						.get_block_header(&hash)
						.unwrap_err()
						.is_not_found());
					assert!(f
						.sync
						.chain
						.get_header_progress_time(&hash)
						.unwrap_err()
						.is_not_found());
				}
				assert!(matches!(
					f.sync.chain.get_header_by_height(512),
					Err(Error::InvalidHeaderHeight(512))
				));
				assert_eq!(download.tasks.front().unwrap().height, 0);
				assert_eq!(download.tasks.len(), 3);
			}
		}
	}

	fn mine_first_body(chain: &Chain) -> Hash {
		use mwc_core::core::{Block, TransactionBody};
		use mwc_core::libtx::{reward, ProofBuilder};
		use mwc_keychain::{ExtKeychain, Keychain};

		let context_id = chain.get_context_id();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[71; 32], false).unwrap();
		let key = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let parent = chain.genesis();
		let binding = chain
			.coinbase_binding_for_template(&secp, &parent, &TransactionBody::empty())
			.unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let (output, kernel, opening) = reward::output_s2c(
			context_id,
			&keychain,
			&builder,
			&key,
			0,
			1,
			&mut secp,
			binding.digest().unwrap(),
		)
		.unwrap();
		let difficulty = consensus::next_difficulty(
			context_id,
			1,
			chain.difficulty_iter().unwrap(),
			&mut consensus::DifficultyCache::new(),
		)
		.unwrap();
		let mut block = Block::new(
			context_id,
			&parent,
			&[],
			difficulty.difficulty,
			(output, kernel),
			&secp,
		)
		.unwrap();
		block.coinbase_opening =
			consensus::is_coinbase_binding_enabled(context_id, 1).then_some(opening);
		block.header.timestamp = parent.timestamp + mwc_crates::chrono::Duration::seconds(60);
		block.header.pow.secondary_scaling = difficulty.secondary_scaling;
		chain.set_txhashset_roots(&secp, &mut block).unwrap();
		pow::pow_size(
			context_id,
			&mut block.header,
			difficulty.difficulty,
			global::proofsize(context_id),
			global::min_edge_bits(context_id),
		)
		.unwrap();
		let hash = block.hash(context_id).unwrap();
		chain
			.process_block(&mut secp, block, Options::NONE, HashSet::new())
			.unwrap();
		hash
	}

	fn mine_headers(genesis: BlockHeader, count: u64) -> Vec<BlockHeader> {
		let context_id = genesis.pow.proof.context_id;
		let mut backend = VecBackend::new(context_id);
		let mut mmr = PMMR::new(&mut backend);
		mmr.push(&genesis).unwrap();
		let mut history = vec![consensus::HeaderDifficultyInfo::new(
			0,
			Some(genesis.hash(context_id).unwrap()),
			genesis.timestamp.timestamp() as u64,
			genesis.total_difficulty(),
			genesis.pow.secondary_scaling,
			genesis.pow.is_secondary(),
		)];
		let mut difficulty_cache = consensus::DifficultyCache::new();
		let mut prev = genesis;
		let mut headers = Vec::new();
		for height in 1..=count {
			let next = consensus::next_difficulty(
				0,
				height,
				history.iter().rev().cloned(),
				&mut difficulty_cache,
			)
			.unwrap();
			let mut header = BlockHeader::default(context_id);
			header.height = height;
			header.version = consensus::header_version(context_id, height);
			header.prev_hash = prev.hash(context_id).unwrap();
			header.prev_root = mmr.root().unwrap();
			header.timestamp = prev.timestamp + mwc_crates::chrono::Duration::seconds(60);
			header.output_mmr_size = pmmr::insertion_to_pmmr_index(height).unwrap();
			header.kernel_mmr_size = header.output_mmr_size;
			header.pow.total_difficulty = (prev.total_difficulty() + next.difficulty).unwrap();
			header.pow.secondary_scaling = next.secondary_scaling;
			pow::pow_size(
				context_id,
				&mut header,
				next.difficulty,
				global::proofsize(context_id),
				global::min_edge_bits(context_id),
			)
			.unwrap();
			mmr.push(&header).unwrap();
			history.push(consensus::HeaderDifficultyInfo::new(
				height,
				Some(header.hash(context_id).unwrap()),
				header.timestamp.timestamp() as u64,
				next.difficulty,
				next.secondary_scaling,
				header.pow.is_secondary(),
			));
			prev = header.clone();
			headers.push(header);
		}
		headers
	}

	// Complete the second range before the first, with invalid padding above target 513.
	// Nothing may commit until the front task is ready; one apply pass must then drain
	// both tasks, commit only through the target, and preserve correct checkpoint hashes.
	#[test]
	fn completed_tasks_commit_in_order_and_ignore_terminal_padding() {
		let context_id = 971_201;
		let f = Fixture::with_context(context_id);
		let valid = mine_headers(f.sync.chain.genesis(), 513);
		let mut wire = valid[..512].to_vec();
		let mut last = dummy_headers(512, valid[511].hash(context_id).unwrap());
		last[0] = valid[512].clone();
		last[511].prev_hash = hash(99); // untrusted data above the selected target
		wire.extend(last.clone());
		let mut download = download_for(&wire, 513);
		for task in &mut download.tasks {
			assign(
				task,
				addr(1),
				Instant::now(),
				Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64),
			);
		}
		download.tasks[1]
			.receive(&last, 0, 513, context_id)
			.unwrap();
		*f.sync.download.lock() = Some(download);
		f.sync.apply_ready_tasks(&f.scores).unwrap();
		assert_eq!(f.sync.chain.header_head().unwrap().height, 0);
		// Completing the missing front range also makes the already-buffered tail applicable.
		f.sync.download.lock().as_mut().unwrap().tasks[0]
			.receive(&valid[..512], 0, 513, context_id)
			.unwrap();
		f.sync.apply_ready_tasks(&f.scores).unwrap();
		assert_eq!(f.sync.chain.header_head().unwrap().height, 513);
		assert!(f.sync.download.lock().as_ref().unwrap().tasks.is_empty());
		assert_eq!(f.sync.chain.get_header_by_height(513).unwrap(), valid[512]);
		// PIBD headers are committed, but GetHeaders serves only the body chain,
		// which is still at genesis until the snapshot or full bodies are applied.
		assert!(f
			.sync
			.chain
			.locate_headers(
				&[f.sync.chain.genesis().hash(context_id).unwrap()],
				HEADERS_PER_BATCH
			)
			.unwrap()
			.is_empty());
		// Checkpoint discovery must still use the committed header data.
		let mut checkpoints = VecBackend::new(context_id);
		let mut mmr = PMMR::new(&mut checkpoints);
		mmr.push(&f.sync.chain.genesis().hash(context_id).unwrap())
			.unwrap();
		mmr.push(&valid[511].hash(context_id).unwrap()).unwrap();
		assert_eq!(
			f.sync.chain.header_hashes_root(&valid[512]).unwrap(),
			mmr.root().unwrap()
		);

		// A fresh download is unnecessary if the chain reached or passed its
		// target after the header-hash snapshot was taken.
		let checkpoints = [
			f.sync.chain.genesis().hash(context_id).unwrap(),
			valid[511].hash(context_id).unwrap(),
		];
		for target in [512, 513] {
			let snapshot = HeadersPibdHashSyncSnapshot {
				agreed_peers: HashSet::new(),
				target_archive_height: target,
				pibd_headers_are_loaded: false,
				headers_hash_desegmenter: Some(Arc::new(RwLock::new(checkpoint_hashes(
					&checkpoints,
					target,
				)))),
			};
			*f.sync.download.lock() = None;
			let response = f
				.sync
				.request(&f.peers, &SyncState::new(), &f.scores, &snapshot, 1024)
				.unwrap();
			assert_eq!(response.response, SyncRequestResponses::HeadersPibdReady);
			assert!(f.sync.download.lock().is_none());
		}
	}
}
