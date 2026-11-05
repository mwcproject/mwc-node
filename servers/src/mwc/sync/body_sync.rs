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

use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils::{self, SyncRequestResponses, SyncResponse};
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::types::SYNC_STATUS_TIP_DISTANCE;
use mwc_chain::{Chain, Error, Options, SyncState, SyncStatus};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::{Block, BlockHeader};
use mwc_core::global;
use mwc_crates::log::{debug, info};
use mwc_crates::parking_lot::Mutex;
use mwc_crates::rand::prelude::*;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_p2p::{Capabilities, Peer, PeerAddr, PeerInfo, Peers};
use mwc_util::LatencyTracker;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

const SINGLE_BLOCK_TIP_DISTANCE: u64 = 100;

struct BodyTask {
	hash: Hash,
	height: u64,
	// Stop downloading/applying this task, but retain any request already sent.
	obsolete: bool,
	request: Option<BodyTaskRequest>,
	// Receipt consumes the request. Keep the actual supplier for later validation,
	// including when another peer supplies a block before the requested peer does.
	received: Option<ReceivedBlock>,
}

struct ReceivedBlock {
	block: Block,
	peer: PeerInfo,
	// A compact body can contain local txpool guesses. Never blame its peer
	// for those guesses, and allow a full response to replace them.
	reconstructed: bool,
}

struct BodyTaskRequest {
	peer: PeerAddr,
	supplier: Weak<Peer>,
	sent_at: Instant,
	expires_at: Instant,
}

impl BodyTask {
	fn send_request(
		&mut self,
		peer: &Arc<Peer>,
		timeout: Duration,
		scores: &SyncPeers,
	) -> Result<bool, Error> {
		let sent_at = Instant::now();
		let expires_at = sent_at
			.checked_add(timeout)
			.ok_or_else(|| Error::Other("Block deadline overflow".into()))?;
		if let Err(error) = peer.send_block_request(self.hash) {
			let message = format!(
				"Failed to request block {} at height {} from {}: {}",
				self.hash, self.height, peer.info.addr, error
			);
			info!("{}", message);
			scores.report_no_response(&peer.info.addr, message);
			return Ok(false);
		}
		self.request = Some(BodyTaskRequest {
			peer: peer.info.addr.clone(),
			supplier: Arc::downgrade(peer),
			sent_at,
			expires_at,
		});
		Ok(true)
	}
}

struct BodyDownload {
	tasks: VecDeque<BodyTask>,
	latency: LatencyTracker,
}

impl BodyDownload {
	fn obsolete_from(&mut self, index: usize) {
		for task in self.tasks.iter_mut().skip(index) {
			task.obsolete = true;
			task.received = None;
		}
		self.tasks
			.retain(|task| !task.obsolete || task.request.is_some());
	}

	fn expire_requests(&mut self, now: Instant, scores: &SyncPeers) {
		for task in &mut self.tasks {
			if let Some(request) = &task.request {
				if !sync_utils::request_peer_is_connected(&request.supplier) {
					task.request = None;
					continue;
				}
				if now >= request.expires_at {
					if let Some(supplier) = request.supplier.upgrade() {
						supplier.record_response_timeout();
					}
					scores.report_no_response(
						&request.peer,
						format!("Block {} at {} timed out", task.hash, task.height),
					);
					task.request = None;
				}
			}
		}
		// Expired obsolete requests finish here; only active tasks can be retried.
		self.tasks
			.retain(|task| !task.obsolete || task.request.is_some());
	}
}

/// Fill the selected header chain from its common ancestor with the body chain.
/// SyncManager calls this only after the required state snapshot is verified.
/// The bounded queue owns both unanswered requests and out-of-order responses.
pub struct BodySync {
	chain: Arc<Chain>,
	pibd_params: Arc<PibdParams>,
	// Serialize scheduling, receipt and application. Chain rejection callbacks
	// report bans and PIBD failures without reentering this queue.
	download: Mutex<BodyDownload>,
}

impl BodySync {
	pub(super) fn clear_peer_requests(&self, peer: &PeerAddr) {
		let mut download = self.download.lock();
		for task in &mut download.tasks {
			if task
				.request
				.as_ref()
				.is_some_and(|request| request.peer == *peer)
			{
				task.request = None;
			}
		}
		download
			.tasks
			.retain(|task| !task.obsolete || task.request.is_some());
	}

	pub fn new(chain: Arc<Chain>) -> Self {
		Self {
			pibd_params: chain.get_pibd_params().clone(),
			chain,
			download: Mutex::new(BodyDownload {
				tasks: VecDeque::new(),
				latency: LatencyTracker::new(),
			}),
		}
	}

	#[cfg(all(test, feature = "test-support"))]
	pub(crate) fn has_block_request(&self, peer: &PeerAddr, hash: &Hash) -> bool {
		self.download.lock().tasks.iter().any(|task| {
			task.hash == *hash && task.request.as_ref().is_some_and(|req| req.peer == *peer)
		})
	}

	pub(super) fn reset(&self, scores: &SyncPeers) {
		let mut download = self.download.lock();
		download.obsolete_from(0);
		// Continue accounting for requests even while snapshot work pauses BodySync.
		download.expire_requests(Instant::now(), scores);
	}

	fn get_task_num_limit(&self, download: &BodyDownload) -> usize {
		self.pibd_params.get_blocks_request_limit(
			download
				.latency
				.get_average_latency()
				.and_then(|latency| u32::try_from(latency.as_millis()).ok()),
		)
	}

	fn get_task_canonical_header(&self, task: &BodyTask) -> Result<Option<BlockHeader>, Error> {
		match self.chain.get_header_by_height(task.height) {
			Ok(header) if header.hash(self.chain.get_context_id())? == task.hash => {
				Ok(Some(header))
			}
			Ok(_) | Err(Error::InvalidHeaderHeight(_)) => Ok(None),
			Err(error) if error.is_not_found() => Ok(None),
			Err(error) => Err(error),
		}
	}

	fn retire_noncanonical_tasks(&self, download: &mut BodyDownload) -> Result<(), Error> {
		let mut obsolete = None;
		// Active tasks remain a contiguous chain. A canonical last active task
		// proves its predecessors are still canonical at this check.
		for (index, task) in download.tasks.iter().enumerate().rev() {
			if task.obsolete {
				continue;
			}
			if self.get_task_canonical_header(task)?.is_some() {
				break;
			}
			obsolete = Some(index);
		}
		if let Some(index) = obsolete {
			download.obsolete_from(index);
		}
		Ok(())
	}

	/// Update the window using the current resource limit and canonical headers.
	/// With no active tasks, start at the common ancestor and skip accepted fork
	/// bodies: those can be stored even while head() still belongs to another branch.
	fn fill_tasks(&self, download: &mut BodyDownload) -> Result<(), Error> {
		let limit = self.get_task_num_limit(download);
		let tasks = &mut download.tasks;
		// A smaller limit stops refilling; existing requests and buffered blocks
		// stay until applied, answered or expired. Obsolete requests still consume space.
		if tasks.len() >= limit {
			return Ok(());
		}
		let last = tasks.iter().rfind(|task| !task.obsolete);
		let mut has_active = last.is_some();
		let (mut height, mut hash) = if let Some(task) = last {
			(task.height, task.hash)
		} else {
			let fork = self.chain.fork_point()?;
			(fork.height, fork.hash(self.chain.get_context_id())?)
		};
		let target = self.chain.header_head()?.height;
		while tasks.len() < limit && height < target {
			height = height.checked_add(1).ok_or(Error::InvalidBlockHeight)?;
			let header = match self.chain.get_header_by_height(height) {
				Ok(header) => header,
				Err(Error::InvalidHeaderHeight(_)) => break,
				Err(error) if error.is_not_found() => break,
				Err(error) => return Err(error),
			};
			if header.prev_hash != hash {
				break; // A concurrent reorg changed the selected branch.
			}
			hash = header.hash(self.chain.get_context_id())?;
			if !has_active {
				match self.chain.is_known(&header) {
					// Resume beyond accepted fork bodies without a separate cursor.
					Err(error) if error.is_known_block() => continue,
					Err(error) => return Err(error),
					// Stored bodies with greater work must still be applied after a rewind.
					Ok(()) => {}
				}
			}
			// The selected branch may return while its old requests are pending.
			// Reuse those requests instead of creating two tasks for the same hash.
			if let Some(index) = tasks.iter().position(|task| task.hash == hash) {
				let mut task = tasks
					.remove(index)
					.ok_or_else(|| Error::Other("Missing retained body task".into()))?;
				task.obsolete = false;
				tasks.push_back(task);
			} else {
				tasks.push_back(BodyTask {
					hash,
					height,
					obsolete: false,
					request: None,
					received: None,
				});
			}
			has_active = true;
		}
		Ok(())
	}

	/// Request an accepted header's body from its announcing peer. Reuse the same
	/// queue, capacity, per-peer allowance and deadline as scheduled downloads.
	/// The caller selects a peer with a known height and difficulty.
	pub(super) fn request_header_block(
		&self,
		header: &BlockHeader,
		peer: &Arc<Peer>,
		scores: &SyncPeers,
	) -> Result<(), Error> {
		let mut download = self.download.lock();
		self.retire_noncanonical_tasks(&mut download)?;
		// Usually this adds just the announced tip. If its parents are missing,
		// build the intervening tasks first instead of creating a gap in the queue.
		self.fill_tasks(&mut download)?;
		let hash = header.hash(self.chain.get_context_id())?;
		let Some(index) = download
			.tasks
			.iter()
			.position(|task| !task.obsolete && task.hash == hash)
		else {
			return Ok(());
		};
		let peer_requests = download
			.tasks
			.iter()
			.filter(|task| {
				task.request
					.as_ref()
					.is_some_and(|request| request.peer == peer.info.addr)
			})
			.count();
		let (peer_height, _) = peer.info.get_height_and_difficulty();
		if peer_requests >= self.pibd_params.get_blocks_request_per_peer()
			|| !self.can_supply(peer, peer_height, header.height)
		{
			return Ok(());
		}
		let timeout = peer.request_timeout();
		let Some(task) = download.tasks.get_mut(index) else {
			return Ok(());
		};
		if task.request.is_none()
			&& task.received.is_none()
			&& self.get_task_canonical_header(task)?.as_ref() == Some(header)
			&& !self.chain.block_exists(&task.hash)?
		{
			task.send_request(peer, timeout, scores)?;
		}
		Ok(())
	}

	/// Collect the consecutive prefix of received full bodies eligible for batching.
	fn ready_full_blocks(
		&self,
		download: &BodyDownload,
	) -> Result<(Vec<Block>, Vec<usize>), Error> {
		let target = self.chain.header_head()?.height;
		let mut blocks = Vec::new();
		let mut indices = Vec::new();
		for (index, task) in download
			.tasks
			.iter()
			.enumerate()
			.filter(|(_, task)| !task.obsolete)
		{
			// A shared PMMR/DB commit breaks rewind by one block. Apply every
			// block within SINGLE_BLOCK_TIP_DISTANCE of the tip individually instead.
			if target.saturating_sub(task.height) < SINGLE_BLOCK_TIP_DISTANCE {
				break;
			}
			let Some(response) = &task.received else {
				break;
			};
			if response.reconstructed || self.get_task_canonical_header(task)?.is_none() {
				break;
			}
			blocks.push(response.block.clone());
			indices.push(index);
		}
		Ok((blocks, indices))
	}

	/// Apply only the ready prefix, including bodies already stored after a rewind.
	/// Return the rejected supplier, if any: a bad buffered child must not be
	/// attributed to the peer whose parent response made it ready.
	fn apply_ready_tasks(
		&self,
		download: &mut BodyDownload,
		secp: &mut Secp256k1,
		scores: &SyncPeers,
	) -> Result<Option<PeerAddr>, Error> {
		let (blocks, indices) = self.ready_full_blocks(download)?;
		if blocks.len() > 1 {
			match self
				.chain
				.process_blocks(secp, &blocks, Options::NONE, Default::default())
			{
				Ok(_) => {
					for index in indices {
						let task = &mut download.tasks[index];
						if let Some(response) = task.received.take() {
							response.peer.update(
								response.block.header.height,
								response.block.header.total_difficulty(),
							);
							scores.report_ok_response(&response.peer.addr);
						}
						task.obsolete = true;
					}
					// Requests still on the wire retain their allowance until settled.
					download
						.tasks
						.retain(|task| !task.obsolete || task.request.is_some());
				}
				Err(error) => {
					info!(
						"Failed to apply block batch; retrying one by one: {}",
						error
					);
				}
			}
		}
		// On batch failure all responses remain queued. The original single-block
		// path below identifies the failing block and its actual supplier.
		while let Some(index) = download.tasks.iter().position(|task| !task.obsolete) {
			let task = &mut download.tasks[index];
			let Some(header) = self.get_task_canonical_header(task)? else {
				download.obsolete_from(index);
				break;
			};
			let (block, supplier, reconstructed) = if self.chain.block_exists(&task.hash)? {
				(self.chain.get_block_for_header(&header)?, None, false)
			} else if let Some(response) = task.received.take() {
				(response.block, Some(response.peer), response.reconstructed)
			} else {
				break;
			};
			let result = if reconstructed {
				self.chain
					.process_reconstructed_block(secp, block.clone(), Options::NONE)
			} else {
				let sources = supplier.iter().map(|peer| peer.addr.to_string()).collect();
				self.chain
					.process_block(secp, block.clone(), Options::NONE, sources)
			};
			match result {
				Ok(_) => {}
				Err(error) if error.is_known_block() => {}
				Err(error)
					if reconstructed
						&& !error.requires_chain_recovery()
						&& (error.is_bad_data() || error.is_not_found()) =>
				{
					// Keep any outstanding full-body request. A failed local guess
					// must neither ban its peer nor count as that peer's response.
					debug!(
						"Reconstructed block {} needs a full body: {}",
						task.hash, error
					);
					break;
				}
				Err(Error::Orphan(_)) => {
					// A local rewind removed the parent. Chain processing checks ancestry
					// for both forks and snapshot-backed state; scheduling will rebuild.
					download.obsolete_from(index);
					break;
				}
				Err(error) => {
					if let Some(supplier) = supplier {
						if error.is_bad_data() && !error.requires_chain_recovery() {
							// ChainAdapter's rejection callback applies the existing BadBlock ban.
							// Leave this task empty for retry, retaining later buffered responses.
							task.request = None;
							info!(
								"Rejected body {} from {}: {}",
								task.hash, supplier.addr, error
							);
							return Ok(Some(supplier.addr));
						}
						// Keep valid-looking data through local failures; retry application
						// without penalizing the supplier or downloading it again.
						task.received = Some(ReceivedBlock {
							block,
							peer: supplier,
							reconstructed,
						});
					}
					return Err(error);
				}
			}
			if let Some(supplier) = supplier {
				supplier.update(header.height, header.total_difficulty());
				scores.report_ok_response(&supplier.addr);
			}
			if task.request.is_some() {
				// Another path (or a compact reconstruction) supplied this body.
				// The full request is still on the wire and retains its allowance.
				task.obsolete = true;
				task.received = None;
			} else {
				download.tasks.remove(index);
			}
		}
		Ok(None)
	}

	/// Match the complete advertised height/work pair to a validated canonical header.
	/// Higher work alone does not establish that the peer has this branch.
	fn canonical_peers(&self, peers: &Arc<Peers>) -> Result<Vec<(Arc<Peer>, u64)>, Error> {
		let tip = self.chain.header_head()?;
		let mut candidates = Vec::new();
		for peer in peers
			.iter()
			.connected()
			.filter(|peer| peer.info.has_known_tip())
			.into_iter()
		{
			let (height, difficulty) = peer.info.get_height_and_difficulty();
			if height > tip.height {
				continue;
			}
			match self.chain.get_header_by_height(height) {
				Ok(header) if header.total_difficulty() == difficulty => {
					candidates.push((peer, height))
				}
				Ok(_) | Err(Error::InvalidHeaderHeight(_)) => {}
				Err(error) if error.is_not_found() => {}
				Err(error) => return Err(error),
			}
		}
		Ok(candidates)
	}

	// checks whether a peer is eligible to supply a particular block
	fn can_supply(&self, peer: &Peer, peer_height: u64, height: u64) -> bool {
		let horizon_height = peer_height.saturating_sub(u64::from(global::cut_through_horizon(
			self.chain.get_context_id(),
		)));
		peer.is_connected()
			&& peer_height >= height
			&& peer
				.info
				.can_serve_block(self.chain.get_context_id(), height)
			&& (height >= horizon_height
				|| peer.info.capabilities.contains(Capabilities::BLOCK_HIST))
	}

	pub fn request(
		&self,
		peers: &Arc<Peers>,
		sync_state: &SyncState,
		scores: &SyncPeers,
		headers_in_flight: bool,
	) -> Result<SyncResponse, Error> {
		let target = self.chain.header_head()?;
		let head = self.chain.head()?;
		let Some(mut download) = self.download.try_lock() else {
			return Ok(SyncResponse::new(
				if sync_state.status() == SyncStatus::NoSync
					&& target.height.saturating_sub(head.height) < SYNC_STATUS_TIP_DISTANCE
				{
					SyncRequestResponses::SyncDone
				} else {
					SyncRequestResponses::Syncing
				},
				Capabilities::UNKNOWN,
				"Processing body tasks".into(),
			));
		};
		download.expire_requests(Instant::now(), scores);
		scores.apply_peers_status(peers);
		if head.last_block_h == target.last_block_h {
			download.obsolete_from(0);
			return Ok(SyncResponse::new(
				SyncRequestResponses::BodyReady,
				Capabilities::UNKNOWN,
				format!("Body and header heads match at {}", head.height),
			));
		}
		self.retire_noncanonical_tasks(&mut download)?;
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		self.apply_ready_tasks(&mut download, &mut secp, scores)?;
		let head = self.chain.head()?;
		let target = self.chain.header_head()?;
		if head.last_block_h == target.last_block_h {
			download.obsolete_from(0);
			return Ok(SyncResponse::new(
				SyncRequestResponses::BodyReady,
				Capabilities::UNKNOWN,
				format!("Body and header heads match at {}", head.height),
			));
		}
		self.fill_tasks(&mut download)?;
		let horizon = u64::from(global::cut_through_horizon(self.chain.get_context_id()));
		let horizon_height = target.height.saturating_sub(horizon);

		// Snapshot peer latencies once per pass. Eligibility and the
		// best latency are determined per block, since suppliers differ by height.
		let candidates: Vec<_> = self
			.canonical_peers(peers)?
			.into_iter()
			.map(|(peer, height)| {
				let latency = peer
					.response_latency()
					.map(|latency| latency.as_millis().max(1));
				(peer, height, latency)
			})
			.collect();
		let per_peer = self.pibd_params.get_blocks_request_per_peer();
		let mut peer_requests = HashMap::<PeerAddr, usize>::new();
		for request in download
			.tasks
			.iter()
			.filter_map(|task| task.request.as_ref())
		{
			*peer_requests.entry(request.peer.clone()).or_default() += 1;
		}
		let fork = self.chain.fork_point()?;
		let current_height = download
			.tasks
			.iter()
			.find(|task| !task.obsolete)
			.map_or(fork.height, |task| task.height.saturating_sub(1));
		// The fork point advances as blocks are accepted. Seed the baseline once;
		// later updates use the saved height, including during parallel header sync.
		let start_height = sync_state
			.body_sync_start_height()
			.unwrap_or(current_height);
		// Preserve Done (NoSync) only if it is the current status and the gap is
		// under ten blocks. Check under the status lock; all other states update normally.
		sync_state.update_if(
			SyncStatus::BodySync {
				archive_height: start_height,
				current_height,
				highest_height: target.height,
			},
			|status| {
				status != SyncStatus::NoSync
					|| target.height.saturating_sub(head.height) >= SYNC_STATUS_TIP_DISTANCE
			},
		);
		// Determine peer-discovery requirements even when all current suppliers
		// are at capacity and the assignment loop can be skipped.
		let mut required_capabilities = Capabilities::UNKNOWN;
		for task in download.tasks.iter().filter(|task| {
			!task.obsolete
				&& task.request.is_none()
				&& task.received.is_none()
				&& task.height < horizon_height
		}) {
			if !self.chain.block_exists(&task.hash)? {
				required_capabilities |= Capabilities::BLOCK_HIST;
				break;
			}
		}
		let mut available_requests: usize = candidates
			.iter()
			.map(|(peer, _, _)| {
				per_peer.saturating_sub(peer_requests.get(&peer.info.addr).copied().unwrap_or(0))
			})
			.sum();
		if available_requests > 0 {
			let mut rng = mwc_crates::rand::rng();
			let last_index = download.tasks.len().saturating_sub(1);
			// Retained requests from obsolete branches consume capacity, but must
			// not shift the latency offsets of the active queue.
			for (index, task) in download
				.tasks
				.iter_mut()
				.filter(|task| !task.obsolete)
				.enumerate()
			{
				if task.request.is_some()
					|| task.received.is_some()
					|| self.chain.block_exists(&task.hash)?
				{
					continue;
				}
				let eligible = candidates.iter().filter(|(peer, peer_height, _)| {
					self.can_supply(peer, *peer_height, task.height)
				});
				let best_latency = eligible
					.clone()
					.filter_map(|(_, _, latency)| *latency)
					.min()
					.unwrap_or(1);
				let Some(peer) = eligible
					.filter(|(peer, _, latency)| {
						let first_index = usize::try_from(
							(latency.unwrap_or(best_latency) / best_latency).saturating_sub(1),
						)
						.unwrap_or(usize::MAX)
						.min(last_index);
						index >= first_index
							&& peer_requests.get(&peer.info.addr).copied().unwrap_or(0) < per_peer
					})
					.map(|(peer, _, _)| peer)
					.choose(&mut rng)
				else {
					// A later block may have different eligible suppliers, so a
					// failed selection alone cannot end the scan.
					continue;
				};
				if task.send_request(peer, peer.request_timeout(), scores)? {
					*peer_requests.entry(peer.info.addr.clone()).or_default() += 1;
					available_requests -= 1;
					if available_requests == 0 {
						break;
					}
				}
			}
		}
		let requests = download
			.tasks
			.iter()
			.filter(|task| !task.obsolete && task.request.is_some())
			.count();
		Ok(SyncResponse::new(
			if sync_state.status() == SyncStatus::NoSync
				&& target.height.saturating_sub(head.height) < SYNC_STATUS_TIP_DISTANCE
			{
				SyncRequestResponses::SyncDone
			} else if requests == 0 {
				// Connected peers may not qualify until their advertised headers
				// are verified. That is a header wait, not missing peers.
				if headers_in_flight {
					SyncRequestResponses::WaitingForHeaders
				} else {
					SyncRequestResponses::WaitingForPeers
				}
			} else {
				SyncRequestResponses::Syncing
			},
			required_capabilities,
			format!(
				"Canonical bodies {}..{}, {} tasks, {} active requests",
				fork.height,
				target.height,
				download.tasks.len(),
				requests
			),
		))
	}

	/// Accept matching responses from any supplier, or append the next canonical
	/// body while capacity permits. With no active tasks, only a direct child of
	/// head() may be applied. While state is not ready, only settle obsolete requests.
	/// False identifies invalid peer data; ignored data returns true.
	pub fn receive_block(
		&self,
		secp: &mut Secp256k1,
		block: &Block,
		peer: &PeerInfo,
		reconstructed: bool,
		state_ready: bool,
		scores: &SyncPeers,
	) -> Result<bool, Error> {
		let hash = block.hash(self.chain.get_context_id())?;
		let mut download = self.download.lock();
		if !state_ready {
			download.obsolete_from(0);
		}
		// Old and current branches may have different hashes at the same height.
		// Match the original request even after its task became obsolete.
		let index = download.tasks.iter().position(|task| task.hash == hash);
		if !state_ready && index.is_none() {
			return Ok(true);
		}
		if let Some(matched) = index {
			if !download.tasks[matched].obsolete
				&& self
					.get_task_canonical_header(&download.tasks[matched])?
					.is_none()
			{
				// A reply may arrive before the scheduler notices the reorg.
				let pending = download.tasks[matched].request.is_some();
				download.obsolete_from(matched);
				if !pending {
					return Ok(true);
				}
				// Earlier tasks are retained, so the pending task keeps its index.
			}
			if download.tasks[matched].obsolete {
				// Discard the response without validation, peer scoring or latency samples.
				// A local reconstruction does not answer an outstanding full-body request.
				if !reconstructed {
					download.tasks.remove(matched);
				}
				return Ok(true);
			}
		}
		let header = match self.chain.get_block_header(&hash) {
			Ok(header) => Some(header),
			Err(error) if error.is_not_found() => None,
			Err(error) => return Err(error),
		};
		if header
			.as_ref()
			.is_some_and(|header| header != &block.header)
		{
			if let Some(index) = index {
				let task = &mut download.tasks[index];
				if task
					.request
					.as_ref()
					.is_some_and(|req| req.peer == peer.addr)
				{
					task.request = None;
				}
			}
			info!(
				"Block {} from {} differs from its validated header",
				hash, peer.addr
			);
			return Ok(false);
		}
		if header.is_some() {
			peer.update(block.header.height, block.header.total_difficulty());
		}
		let index = if let Some(index) = index {
			index
		} else if let Some(tail) = download.tasks.iter().rfind(|task| !task.obsolete) {
			// Check both linkage and the canonical hash: competing children can
			// share the same parent. A smaller limit never evicts existing tasks.
			if download.tasks.len() >= self.get_task_num_limit(&download)
				|| tail.height.checked_add(1) != Some(block.header.height)
				|| tail.hash != block.header.prev_hash
				|| self.get_task_canonical_header(tail)?.is_none()
			{
				peer.update(block.header.height, block.header.total_difficulty());
				return Ok(true);
			}
			if header.is_none() {
				let tip = self.chain.header_head()?;
				if block.header.prev_hash != tip.last_block_h
					|| tip.height.checked_add(1) != Some(block.header.height)
				{
					peer.update(block.header.height, block.header.total_difficulty());
					return Ok(true);
				}
				if let Err(error) = self
					.chain
					.process_block_header(&block.header, Options::NONE)
				{
					if error.is_bad_data() && !error.requires_chain_recovery() {
						info!("Rejected block header from {}: {}", peer.addr, error);
						return Ok(false);
					}
					return Err(error);
				}
			}
			let task = BodyTask {
				hash,
				height: block.header.height,
				obsolete: false,
				request: None,
				received: None,
			};
			if self.get_task_canonical_header(&task)?.is_none() {
				return Ok(true);
			}
			let index = download.tasks.len();
			download.tasks.push_back(task);
			index
		} else {
			// Keep the empty-queue check and application under the scheduling lock.
			// Queued fork bodies do NOT require their parent to be the current head.
			let head = self.chain.head()?;
			if block.header.prev_hash != head.last_block_h
				|| head.height.checked_add(1) != Some(block.header.height)
			{
				peer.update(block.header.height, block.header.total_difficulty());
				return Ok(true);
			}
			let result = if reconstructed {
				self.chain
					.process_reconstructed_block(secp, block.clone(), Options::NONE)
			} else {
				self.chain.process_block(
					secp,
					block.clone(),
					Options::NONE,
					std::collections::HashSet::from([peer.addr.to_string()]),
				)
			};
			match result {
				Ok(_) => scores.report_ok_response(&peer.addr),
				Err(error) if error.is_known_block() => {}
				Err(error)
					if reconstructed
						&& !error.requires_chain_recovery()
						&& (error.is_bad_data()
							|| error.is_not_found()
							|| matches!(error, Error::Orphan(_))) =>
				{
					debug!("Reconstructed block {} needs a full body: {}", hash, error);
					return Ok(true);
				}
				Err(error) if error.is_bad_data() && !error.requires_chain_recovery() => {
					// The chain rejection callback bans the actual full-body supplier.
					info!("Rejected block from {}: {}", peer.addr, error);
					return Ok(false);
				}
				Err(Error::Orphan(_)) => return Ok(true),
				Err(error) => return Err(error),
			}
			peer.update(block.header.height, block.header.total_difficulty());
			return Ok(true);
		};
		let task = &mut download.tasks[index];
		peer.update(block.header.height, block.header.total_difficulty());
		if task
			.received
			.as_ref()
			.is_some_and(|response| !response.reconstructed || reconstructed)
		{
			return Ok(true); // First full response keeps its data and supplier.
		}
		// A locally reconstructed guess is not a full response. Preserve the
		// outstanding request until the actual body arrives or its deadline expires.
		let latency = if reconstructed {
			None
		} else {
			task.request
				.take()
				.filter(|req| req.peer == peer.addr)
				.map(|req| {
					let latency = Instant::now().saturating_duration_since(req.sent_at);
					if let Some(supplier) = req.supplier.upgrade() {
						supplier.record_response_latency(latency);
					}
					latency
				})
		};
		task.received = Some(ReceivedBlock {
			block: block.clone(),
			peer: peer.clone(),
			reconstructed,
		});
		if let Some(latency) = latency {
			if let Ok(latency_ms) = i64::try_from(latency.as_millis()) {
				download.latency.add_latency(latency_ms);
			}
		}
		let rejected = self.apply_ready_tasks(&mut download, secp, scores)?;
		Ok(rejected.as_ref() != Some(&peer.addr))
	}
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
	use super::*;
	use mwc_chain::types::NoopAdapter;
	use mwc_core::core::pmmr::{self, ReadablePMMR, VecBackend, PMMR};
	use mwc_core::core::{transaction, Transaction};
	use mwc_core::libtx::{reward, ProofBuilder};
	use mwc_core::pow::Difficulty;
	use mwc_core::ser::ProtocolVersion;
	use mwc_core::{consensus, core, pow};
	use mwc_crates::chrono;
	use mwc_crates::parking_lot::RwLock;
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_crates::tempfile::TempDir;
	use mwc_keychain::{ExtKeychain, Keychain};
	use mwc_p2p::types::{Direction, PeerLiveInfo};
	use mwc_p2p::{DummyAdapter, P2PConfig, PeerInfo};
	use std::collections::HashSet;

	// Import valid headers from a separate mined chain, leaving their bodies missing
	// locally. Tests control body delivery and inspect outgoing peer request channels.
	struct Fixture {
		chain: Arc<Chain>,
		body: BodySync,
		peers: Arc<Peers>,
		scores: SyncPeers,
		state: SyncState,
		blocks: Vec<core::Block>,
		secp: Secp256k1,
		_dirs: Vec<TempDir>,
	}

	impl Fixture {
		fn new(context: u32, count: usize) -> Self {
			global::init_global_chain_type(context, global::ChainTypes::AutomatedTesting).unwrap();
			global::init_global_nrd_enabled(context, false).unwrap();
			let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			let chain_dir = TempDir::new().unwrap();
			let source_dir = TempDir::new().unwrap();
			let peer_dir = TempDir::new().unwrap();
			let chain = Arc::new(init_chain(context, &secp, &chain_dir, true));
			let source = init_chain(context, &secp, &source_dir, true);
			let keychain = ExtKeychain::from_seed(&secp, &[67; 32], false).unwrap();
			let mut blocks = Vec::new();
			for _ in 0..count {
				let block = next_block(&source, &mut secp, &keychain, &[]);
				source
					.process_block(&mut secp, block.clone(), Options::NONE, HashSet::new())
					.unwrap();
				blocks.push(block);
			}
			if !blocks.is_empty() {
				let headers: Vec<_> = blocks.iter().map(|block| block.header.clone()).collect();
				chain
					.sync_block_headers(&headers, Options::NONE, 1)
					.unwrap();
			}
			let peers = Arc::new(Peers::new(
				mwc_p2p::store::PeerStore::new(context, peer_dir.path().to_str().unwrap()).unwrap(),
				Arc::new(DummyAdapter {}),
				&P2PConfig::default(),
			));
			let body = BodySync::new(chain.clone());
			let state = SyncState::new();
			state.reset();
			Self {
				chain,
				body,
				peers,
				scores: SyncPeers::new(),
				state,
				blocks,
				secp,
				_dirs: vec![chain_dir, source_dir, peer_dir],
			}
		}

		// Scheduling tests only need headers beyond the bodies they actually apply.
		// Mine real header proofs in memory, then commit the tail in one batch.
		fn extend_headers_to(&self, target: u64) {
			Self::extend_chain_headers_to(&self.chain, target);
		}

		fn extend_chain_headers_to(chain: &Chain, target: u64) {
			let context = chain.get_context_id();
			let mut previous = chain
				.get_header_by_height(chain.header_head().unwrap().height)
				.unwrap();
			let mut backend = VecBackend::new(context);
			let mut mmr = PMMR::new(&mut backend);
			for height in 0..=previous.height {
				mmr.push(&chain.get_header_by_height(height).unwrap())
					.unwrap();
			}
			let mut history: VecDeque<_> = chain
				.difficulty_iter_from(previous.hash(context).unwrap())
				.unwrap()
				.collect::<Result<_, _>>()
				.unwrap();
			let mut cache = consensus::DifficultyCache::new();
			let mut headers = Vec::new();
			for height in previous.height + 1..=target {
				let difficulty = consensus::next_difficulty(
					context,
					height,
					history.iter().cloned(),
					&mut cache,
				)
				.unwrap();
				let mut header = previous.clone();
				header.height = height;
				header.version = consensus::header_version(context, height);
				header.prev_hash = previous.hash(context).unwrap();
				header.prev_root = mmr.root().unwrap();
				header.timestamp += chrono::Duration::seconds(60);
				header.output_mmr_size =
					pmmr::insertion_to_pmmr_index(previous.output_mmr_count().unwrap() + 1)
						.unwrap();
				header.kernel_mmr_size =
					pmmr::insertion_to_pmmr_index(previous.kernel_mmr_count().unwrap() + 1)
						.unwrap();
				header.pow.total_difficulty =
					(previous.total_difficulty() + difficulty.difficulty).unwrap();
				header.pow.secondary_scaling = difficulty.secondary_scaling;
				pow::pow_size(
					context,
					&mut header,
					difficulty.difficulty,
					global::proofsize(context),
					global::min_edge_bits(context),
				)
				.unwrap();
				mmr.push(&header).unwrap();
				history.push_front(consensus::HeaderDifficultyInfo::new(
					height,
					Some(header.hash(context).unwrap()),
					header.timestamp.timestamp() as u64,
					difficulty.difficulty,
					difficulty.secondary_scaling,
					header.pow.is_secondary(),
				));
				previous = header.clone();
				headers.push(header);
			}
			chain
				.sync_block_headers(&headers, Options::NONE, 1)
				.unwrap();
		}

		fn peer(
			&self,
			port: u16,
			height: u64,
			difficulty: Difficulty,
			capabilities: Capabilities,
		) -> (
			Arc<Peer>,
			mwc_crates::crossbeam::channel::Receiver<mwc_p2p::msg::Msg>,
		) {
			let info = PeerInfo {
				capabilities,
				user_agent: "body-sync-test".into(),
				version: ProtocolVersion::local(),
				addr: PeerAddr::Ip(([127, 0, 0, 1], port).into()),
				direction: Direction::Outbound,
				live_info: Arc::new(RwLock::new(PeerLiveInfo::new(difficulty))),
				tx_base_fee: 0,
			};
			info.update(height, difficulty);
			let (peer, receiver) = Peer::connected_for_test(
				info,
				self.chain.get_context_id(),
				Arc::new(DummyAdapter {}),
			);
			let peer = Arc::new(peer);
			self.peers.add_connected(peer.clone()).unwrap();
			(peer, receiver)
		}

		fn supplier(
			&self,
			port: u16,
		) -> (
			Arc<Peer>,
			mwc_crates::crossbeam::channel::Receiver<mwc_p2p::msg::Msg>,
		) {
			let tip = self.chain.header_head().unwrap();
			self.peer(
				port,
				tip.height,
				tip.total_difficulty,
				Capabilities::BLOCK_HIST | Capabilities::BLOCK_EXTRA,
			)
		}

		fn poll(&self) -> SyncResponse {
			self.body
				.request(&self.peers, &self.state, &self.scores, false)
				.unwrap()
		}

		fn deliver(&mut self, index: usize, peer: &PeerAddr) {
			let block = self.blocks[index].clone();
			let supplier = self.peers.get_connected_peer(peer).unwrap();
			assert_eq!(
				self.body
					.receive_block(
						&mut self.secp,
						&block,
						&supplier.info,
						false,
						true,
						&self.scores
					)
					.unwrap(),
				true
			);
		}

		fn expire_requests(&self) {
			for task in &mut self.body.download.lock().tasks {
				if let Some(request) = &mut task.request {
					request.expires_at = Instant::now();
				}
			}
		}

		fn requests_num(&self) -> usize {
			self.body
				.download
				.lock()
				.tasks
				.iter()
				.filter(|task| task.request.is_some())
				.count()
		}

		// Mine a competing branch and import only its headers. Pending body
		// requests still refer to the original blocks in self.blocks.
		fn select_fork(&mut self, count: usize) -> Vec<Block> {
			let dir = TempDir::new().unwrap();
			let fork = init_chain(self.chain.get_context_id(), &self.secp, &dir, true);
			let keychain = ExtKeychain::from_seed(&self.secp, &[68; 32], false).unwrap();
			let mut blocks = Vec::new();
			for _ in 0..count {
				let block = next_block(&fork, &mut self.secp, &keychain, &[]);
				fork.process_block(&mut self.secp, block.clone(), Options::NONE, HashSet::new())
					.unwrap();
				self.chain
					.process_block_header(&block.header, Options::NONE)
					.unwrap();
				blocks.push(block);
			}
			blocks
		}
	}

	#[test]
	fn body_series_preserves_bad_supplier_and_stops_at_tip_boundary() {
		let mut f = Fixture::new(1_935_030, 5);
		f.extend_headers_to(SINGLE_BLOCK_TIP_DISTANCE + 3);
		let (good, _good_rx) = f.supplier(4230);
		let (bad, _bad_rx) = f.supplier(4231);
		f.poll();
		f.deliver(2, &good.info.addr);
		let mut invalid = f.blocks[1].clone();
		invalid.body.outputs[0].proof.proof[0] ^= 1;
		assert!(f
			.body
			.receive_block(&mut f.secp, &invalid, &bad.info, false, true, &f.scores)
			.unwrap());
		// The parent is still missing.
		assert_eq!(f.chain.head().unwrap().height, 0);
		// Receiving the parent immediately applies the ready batch. Failure retries
		// individually, accepting the parent and rejecting the bad child's supplier.
		f.deliver(0, &good.info.addr);
		{
			let download = f.body.download.lock();
			assert_eq!(f.chain.head().unwrap().height, 1);
			assert!(download
				.tasks
				.iter()
				.find(|task| task.height == 2)
				.unwrap()
				.received
				.is_none());
			assert!(download
				.tasks
				.iter()
				.find(|task| task.height == 3)
				.unwrap()
				.received
				.is_some());
		}
		{
			let mut download = f.body.download.lock();
			// Supply the repaired child directly to inspect the ready batch before
			// applying it, including the transition to individual acceptance.
			let task = download
				.tasks
				.iter_mut()
				.find(|task| task.height == 2)
				.unwrap();
			task.received = Some(ReceivedBlock {
				block: f.blocks[1].clone(),
				peer: good.info.clone(),
				reconstructed: false,
			});
			let task = download
				.tasks
				.iter_mut()
				.find(|task| task.height == 4)
				.unwrap();
			task.received = Some(ReceivedBlock {
				block: f.blocks[3].clone(),
				peer: good.info.clone(),
				reconstructed: false,
			});
			// Compact reconstructions end the full-block batch; never skip them.
			for height in 2..=3 {
				let index = download
					.tasks
					.iter()
					.position(|task| task.height == height)
					.unwrap();
				download.tasks[index]
					.received
					.as_mut()
					.unwrap()
					.reconstructed = true;
				assert_eq!(
					f.body.ready_full_blocks(&download).unwrap().0.len(),
					(height - 2) as usize
				);
				download.tasks[index]
					.received
					.as_mut()
					.unwrap()
					.reconstructed = false;
			}
			let (blocks, _) = f.body.ready_full_blocks(&download).unwrap();
			assert_eq!(
				blocks
					.iter()
					.map(|block| block.header.height)
					.collect::<Vec<_>>(),
				vec![2, 3]
			);
			f.body
				.apply_ready_tasks(&mut download, &mut f.secp, &f.scores)
				.unwrap();
		}
		assert_eq!(f.chain.head().unwrap().height, 4);
		f.deliver(4, &good.info.addr);
		assert_eq!(f.chain.head().unwrap().height, 5); // Near-tip receipt applies immediately.
		f.chain
			.reset_chain_head(
				&f.secp,
				&f.blocks[3].header,
				mwc_chain::ChainHeadReset::Body,
			)
			.unwrap();
		assert_eq!(f.chain.head().unwrap().height, 4);
		f.chain.validate(&f.secp, false).unwrap();
	}

	// Receive one abandoned child before scheduling notices the reorg, then mix
	// old and current responses at the same heights. Each hash must settle only
	// its own request; obsolete tasks must not block application of the new branch.
	#[test]
	fn reorg_retains_requests_and_matches_both_branches_by_hash() {
		let mut f = Fixture::new(1_935_021, 3);
		let (old_peer, old_rx) = f.supplier(4191);
		f.poll();
		assert_eq!(old_rx.try_iter().count(), 3);
		let original: Vec<_> = f
			.body
			.download
			.lock()
			.tasks
			.iter()
			.map(|task| {
				let request = task.request.as_ref().unwrap();
				(task.hash, request.sent_at, request.expires_at)
			})
			.collect();
		let fork = f.select_fork(4);
		let target = f.chain.header_head().unwrap();
		f.deliver(2, &old_peer.info.addr);
		assert!(!f
			.body
			.has_block_request(&old_peer.info.addr, &original[2].0));
		assert_eq!(f.chain.head().unwrap().height, 0);
		let (new_peer, _rx) = f.supplier(4192);
		f.poll();
		{
			let download = f.body.download.lock();
			for (hash, sent_at, expires_at) in &original[..2] {
				let task = download
					.tasks
					.iter()
					.find(|task| task.hash == *hash)
					.unwrap();
				assert!(task.obsolete);
				let request = task.request.as_ref().unwrap();
				assert_eq!(request.peer, old_peer.info.addr);
				assert_eq!(request.sent_at, *sent_at);
				assert_eq!(request.expires_at, *expires_at);
			}
			assert!(download.tasks.len() <= f.body.get_task_num_limit(&download));
		}
		// New height 2 arrives before height 1; neither response answers the old hash.
		for index in [1, 0] {
			assert!(f
				.body
				.receive_block(
					&mut f.secp,
					&fork[index],
					&new_peer.info,
					false,
					true,
					&f.scores,
				)
				.unwrap());
			assert!(f
				.body
				.has_block_request(&old_peer.info.addr, &original[index].0));
		}
		let head = f.chain.head().unwrap();
		assert_eq!(
			head.last_block_h,
			fork[1].hash(f.chain.get_context_id()).unwrap()
		);
		// Old replies complete their original requests without applying the old fork.
		for index in [1, 0] {
			f.deliver(index, &old_peer.info.addr);
			assert!(!f
				.body
				.has_block_request(&old_peer.info.addr, &original[index].0));
			assert_eq!(f.chain.head().unwrap(), head);
		}
		f.blocks = fork;
		f.deliver(2, &new_peer.info.addr);
		f.deliver(3, &new_peer.info.addr);
		// Any leftover timer for a completed old request would now mark the peer Defunct.
		for _ in 0..4 {
			f.scores
				.elapse_no_response_merge_interval(&old_peer.info.addr);
			f.scores
				.report_no_response(&old_peer.info.addr, "earlier request".into());
		}
		f.scores
			.elapse_no_response_merge_interval(&old_peer.info.addr);
		f.expire_requests();
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert_eq!(f.chain.head().unwrap(), target);
		assert!(f.body.download.lock().tasks.is_empty());
		assert!(!f.peers.is_banned(&old_peer.info.addr).unwrap());
		assert!(old_peer.is_connected());
	}

	// Fill one peer's allowance, then replace the header branch. Obsolete requests
	// must continue consuming that allowance, including for direct header announcements.
	// Completing one old request frees exactly one slot for current work.
	#[test]
	fn obsolete_requests_keep_the_peer_allowance_until_answered() {
		let params = Arc::new(PibdParams::with_cpu_count_for_test(1));
		let count = params.get_blocks_request_per_peer();
		let mut f = Fixture::new(1_935_022, count);
		f.body.pibd_params = params;
		let (peer, rx) = f.supplier(4193);
		f.poll();
		let pending = rx.try_iter().count();
		assert_eq!(
			pending,
			count.min(f.body.get_task_num_limit(&f.body.download.lock()))
		);
		let fork = f.select_fork(count + 1);
		f.poll();
		assert_eq!(rx.try_iter().count(), 0);
		f.body
			.request_header_block(&fork[0].header, &peer, &f.scores)
			.unwrap();
		assert_eq!(rx.try_iter().count(), 0);
		assert_eq!(f.requests_num(), pending);
		f.deliver(0, &peer.info.addr);
		f.body
			.request_header_block(&fork[0].header, &peer, &f.scores)
			.unwrap();
		assert_eq!(rx.try_iter().count(), 1);
		assert!(f.body.has_block_request(
			&peer.info.addr,
			&fork[0].hash(f.chain.get_context_id()).unwrap()
		));
		assert_eq!(f.requests_num(), pending);
		let download = f.body.download.lock();
		assert!(download.tasks.len() <= f.body.get_task_num_limit(&download));
	}

	// Pause body application with a full request outstanding. A compact reconstruction
	// cannot fulfil it, but its full response can, without advancing either chain head.
	// Obsolete full data is discarded without validation or updating the peer's tip.
	#[test]
	fn paused_body_sync_accounts_for_full_responses_without_applying_them() {
		let mut f = Fixture::new(1_935_023, 2);
		let (peer, rx) = f.supplier(4194);
		f.poll();
		assert_eq!(rx.try_iter().count(), 2);
		let head = f.chain.head().unwrap();
		let headers = f.chain.header_head().unwrap();
		assert!(f
			.body
			.receive_block(
				&mut f.secp,
				&f.blocks[0],
				&peer.info,
				true,
				false,
				&f.scores,
			)
			.unwrap());
		assert_eq!(f.requests_num(), 2);
		assert!(f
			.body
			.download
			.lock()
			.tasks
			.iter()
			.all(|task| task.obsolete));
		assert!(f
			.body
			.receive_block(
				&mut f.secp,
				&f.blocks[0],
				&peer.info,
				false,
				false,
				&f.scores,
			)
			.unwrap());
		assert_eq!(f.requests_num(), 1);
		let mut invalid = f.blocks[1].clone();
		invalid.body.outputs[0].proof.proof[0] ^= 1;
		invalid.header.height = u64::MAX;
		invalid.coinbase_opening = None;
		let (other, _rx) = f.supplier(4198);
		let peer_tip = other.info.get_height_and_difficulty();
		assert!(f
			.body
			.receive_block(&mut f.secp, &invalid, &other.info, false, false, &f.scores,)
			.unwrap());
		assert_eq!(f.requests_num(), 0);
		assert_eq!(other.info.get_height_and_difficulty(), peer_tip);
		assert!(f
			.body
			.receive_block(&mut f.secp, &invalid, &peer.info, false, false, &f.scores,)
			.unwrap());
		assert!(f.body.download.lock().tasks.is_empty());
		assert_eq!(f.chain.head().unwrap(), head);
		assert_eq!(f.chain.header_head().unwrap(), headers);
	}

	// Abandon a sent request and expire it while body sync is paused. It must produce
	// exactly one timeout and no retry. Three prior failures plus this timeout stay
	// below the Defunct threshold; one later failure proves the timeout was recorded.
	#[test]
	fn obsolete_timeout_is_scored_once_and_never_retried() {
		let f = Fixture::new(1_935_024, 1);
		let (peer, rx) = f.supplier(4195);
		f.poll();
		assert_eq!(rx.try_iter().count(), 1);
		for _ in 0..3 {
			f.scores.elapse_no_response_merge_interval(&peer.info.addr);
			f.scores
				.report_no_response(&peer.info.addr, "earlier request".into());
		}
		f.body.reset(&f.scores);
		assert_eq!(f.requests_num(), 1);
		f.scores.elapse_no_response_merge_interval(&peer.info.addr);
		f.expire_requests();
		for _ in 0..2 {
			f.scores.elapse_no_response_merge_interval(&peer.info.addr);
			f.body.reset(&f.scores);
			f.scores.apply_peers_status(&f.peers);
			assert!(f.body.download.lock().tasks.is_empty());
			assert_eq!(rx.try_iter().count(), 0);
			assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
			assert!(peer.is_connected());
		}
		f.scores.elapse_no_response_merge_interval(&peer.info.addr);
		f.scores
			.report_no_response(&peer.info.addr, "later request".into());
		f.scores.apply_peers_status(&f.peers);
		assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
		assert_eq!(
			f.peers.get_peer(&peer.info.addr).unwrap().flags,
			mwc_p2p::State::Defunct
		);
		assert!(!peer.is_connected());
	}

	// Nine obsolete replies must not add success events that push earlier failures
	// out of the scoring window. No blocks are applied; a subsequent real timeout
	// still marks the peer Defunct after its four earlier failures.
	#[test]
	fn obsolete_responses_do_not_credit_the_peer() {
		let mut f = Fixture::new(1_935_027, 1);
		let (peer, rx) = f.supplier(4199);
		for _ in 0..4 {
			f.scores.elapse_no_response_merge_interval(&peer.info.addr);
			f.scores
				.report_no_response(&peer.info.addr, "earlier request".into());
		}
		for _ in 0..9 {
			f.poll();
			assert_eq!(rx.try_iter().count(), 1);
			f.body.reset(&f.scores);
			f.deliver(0, &peer.info.addr);
			assert!(f.body.download.lock().tasks.is_empty());
			assert_eq!(f.chain.head().unwrap().height, 0);
		}
		assert!(f
			.body
			.download
			.lock()
			.latency
			.get_average_latency()
			.is_none());
		f.scores.elapse_no_response_merge_interval(&peer.info.addr);
		f.scores
			.report_no_response(&peer.info.addr, "later request".into());
		f.scores.apply_peers_status(&f.peers);
		assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
		assert_eq!(
			f.peers.get_peer(&peer.info.addr).unwrap().flags,
			mwc_p2p::State::Defunct
		);
		assert!(!peer.is_connected());
	}

	// Resume the same canonical work after pausing it. Reusing the retained tasks
	// must preserve deadlines and produce neither duplicate hashes nor new sends.
	#[test]
	fn resumed_tasks_reuse_original_requests() {
		let f = Fixture::new(1_935_026, 3);
		let (peer, rx) = f.supplier(4197);
		f.poll();
		assert_eq!(rx.try_iter().count(), 3);
		let original: Vec<_> = f
			.body
			.download
			.lock()
			.tasks
			.iter()
			.map(|task| (task.hash, task.request.as_ref().unwrap().expires_at))
			.collect();
		f.body.reset(&f.scores);
		f.poll();
		assert_eq!(rx.try_iter().count(), 0);
		let download = f.body.download.lock();
		assert_eq!(download.tasks.len(), original.len());
		for (task, (hash, expires_at)) in download.tasks.iter().zip(original) {
			assert!(!task.obsolete);
			assert_eq!(task.hash, hash);
			let request = task.request.as_ref().unwrap();
			assert_eq!(request.peer, peer.info.addr);
			assert_eq!(request.expires_at, expires_at);
		}
	}

	// Another path stores the requested bodies and brings the heads together.
	// BodyReady must keep the unanswered requests, accept one reply, and expire the
	// other without creating more work or changing the already completed chain.
	#[test]
	fn matching_heads_keep_pending_requests_until_response_or_timeout() {
		let mut f = Fixture::new(1_935_025, 2);
		let (peer, rx) = f.supplier(4196);
		f.poll();
		assert_eq!(rx.try_iter().count(), 2);
		for block in &f.blocks {
			f.chain
				.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
				.unwrap();
		}
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert_eq!(f.requests_num(), 2);
		assert!(f
			.body
			.download
			.lock()
			.tasks
			.iter()
			.all(|task| task.obsolete));
		f.deliver(1, &peer.info.addr);
		assert_eq!(f.requests_num(), 1);
		f.expire_requests();
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert!(f.body.download.lock().tasks.is_empty());
		assert_eq!(rx.try_iter().count(), 0);
		assert_eq!(f.chain.head().unwrap(), f.chain.header_head().unwrap());
	}

	// Advertise a matching canonical tip, conflicting work, and a height beyond known headers.
	// Only the matching peer gets the missing block; polling must not resend it, and
	// delivering that block must bring the body head to the header head. The node
	// stays Running while downloading this single new block.
	#[test]
	fn near_tip_requests_only_canonical_claims_and_finishes_by_hash() {
		let mut f = Fixture::new(1_935_001, 1);
		let tip = f.chain.header_head().unwrap();
		let (good, good_rx) = f.supplier(4101);
		let (_, wrong_rx) = f.peer(
			4102,
			tip.height,
			(tip.total_difficulty + Difficulty::from_num(1)).unwrap(),
			Capabilities::BLOCK_HIST | Capabilities::BLOCK_EXTRA,
		);
		let (_, ahead_rx) = f.peer(
			4103,
			tip.height + 1,
			tip.total_difficulty,
			Capabilities::BLOCK_HIST | Capabilities::BLOCK_EXTRA,
		);
		assert_eq!(f.poll().response, SyncRequestResponses::SyncDone);
		assert_eq!(f.state.status(), SyncStatus::NoSync);
		assert_eq!(good_rx.try_iter().count(), 1);
		assert_eq!(wrong_rx.try_iter().count(), 0);
		assert_eq!(ahead_rx.try_iter().count(), 0);
		f.poll();
		assert_eq!(good_rx.try_iter().count(), 0);
		f.deliver(0, &good.info.addr);
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert_eq!(f.chain.head().unwrap().last_block_h, tip.last_block_h);
	}

	// PIBD leaves body-tail metadata absent until the first full block is saved.
	// With usable chain state, that absence must not prevent requesting and applying
	// the next block; normal block processing recreates the tail.
	#[test]
	fn missing_body_tail_does_not_prevent_downloads() {
		let mut f = Fixture::new(1_935_015, 1);
		let store = f.chain.get_store_for_tests();
		{
			let batch = store.batch_write().unwrap();
			batch.delete_body_tail().unwrap();
			batch.commit().unwrap();
		}
		assert!(f.chain.tail().unwrap_err().is_not_found());
		let (peer, receiver) = f.supplier(4185);
		f.poll();
		assert_eq!(receiver.try_iter().count(), 1);
		assert_eq!(f.requests_num(), 1);
		f.deliver(0, &peer.info.addr);
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert_eq!(f.chain.tail().unwrap().height, 1);
	}

	#[test]
	fn resumed_archive_download_progress_starts_at_the_existing_body_height() {
		let mut f = Fixture::new(1_935_090, 3);
		assert!(f.chain.archive_mode());
		f.chain
			.process_block(
				&mut f.secp,
				f.blocks[0].clone(),
				Options::NONE,
				HashSet::new(),
			)
			.unwrap();
		f.state.update(SyncStatus::Initial);
		let (peer, _messages) = f.supplier(4190);
		f.poll();
		assert_eq!(
			f.state.status(),
			SyncStatus::BodySync {
				archive_height: 1,
				current_height: 1,
				highest_height: 3
			}
		);
		f.deliver(1, &peer.info.addr);
		assert_eq!(f.chain.fork_point().unwrap().height, 2);
		assert_eq!(f.state.body_sync_start_height(), Some(1));
		f.poll();
		assert_eq!(
			f.state.status(),
			SyncStatus::BodySync {
				archive_height: 1,
				current_height: 2,
				highest_height: 3
			}
		);
	}

	// A ten-block gap starts visible sync. Reducing that gap to nine must keep
	// the existing sync status, even though is_syncing() tolerates a small gap.
	// For an already-running node, the same nine-block gap stays Running while
	// waiting for peers, applying blocks under the queue lock, or sending requests.
	#[test]
	fn short_catch_up_preserves_only_an_existing_running_status() {
		let mut f = Fixture::new(1_935_014, 1);
		f.extend_headers_to(SYNC_STATUS_TIP_DISTANCE);
		assert_eq!(f.poll().response, SyncRequestResponses::WaitingForPeers);
		assert!(matches!(f.state.status(), SyncStatus::BodySync { .. }));
		f.chain
			.process_block(
				&mut f.secp,
				f.blocks[0].clone(),
				Options::NONE,
				HashSet::new(),
			)
			.unwrap();
		assert_eq!(f.poll().response, SyncRequestResponses::WaitingForPeers);
		assert!(matches!(
			f.state.status(),
			SyncStatus::BodySync {
				current_height: 1,
				highest_height: 10,
				..
			}
		));

		// Start the same catch-up with the node already marked Running.
		f.state.reset();
		assert_eq!(f.poll().response, SyncRequestResponses::SyncDone);
		assert_eq!(f.state.status(), SyncStatus::NoSync);
		assert_eq!(f.body.download.lock().tasks.len(), 9);
		{
			let _download = f.body.download.lock();
			assert_eq!(f.poll().response, SyncRequestResponses::SyncDone);
		}
		let (_peer, receiver) = f.supplier(4184);
		assert_eq!(f.poll().response, SyncRequestResponses::SyncDone);
		assert_eq!(f.state.status(), SyncStatus::NoSync);
		assert!(f.requests_num() > 0);
		assert_eq!(receiver.try_iter().count(), f.requests_num());
	}

	// Queue 24 missing bodies with three eligible suppliers and inspect the first poll.
	// Sends must fill the smaller of the missing-block, resource, and per-peer allowances;
	// another poll must leave those outstanding requests alone.
	#[test]
	fn parallel_requests_use_resource_and_per_peer_limits() {
		let f = Fixture::new(1_935_002, 0);
		f.extend_headers_to(24);
		let suppliers: Vec<_> = (4110..4113).map(|port| f.supplier(port)).collect();
		f.poll();
		let per_peer = f.body.pibd_params.get_blocks_request_per_peer();
		let limit = f.body.pibd_params.get_blocks_request_limit(None);
		assert_eq!(f.body.download.lock().tasks.len(), 24.min(limit));
		let counts: Vec<_> = suppliers
			.iter()
			.map(|(_, rx)| rx.try_iter().count())
			.collect();
		assert!(counts.iter().all(|count| *count <= per_peer));
		assert_eq!(
			counts.iter().sum::<usize>(),
			24.min(per_peer * suppliers.len()).min(limit)
		);
		f.poll();
		assert!(suppliers.iter().all(|(_, rx)| rx.try_iter().count() == 0));
	}

	#[test]
	fn latency_scheduling_keeps_fast_peers_at_the_head_and_ignores_obsolete_indices() {
		let f = Fixture::new(1_935_081, 0);
		f.extend_headers_to(24);
		let (fast, fast_messages) = f.supplier(4180);
		let (slow, slow_messages) = f.supplier(4181);
		let per_peer = f.body.pibd_params.get_blocks_request_per_peer();
		let slow_index = per_peer + 2;
		fast.record_response_latency(Duration::from_millis(100));
		slow.record_response_latency(Duration::from_millis((slow_index as u64 + 1) * 100));
		// A retained old request consumes a slot without moving the active head.
		let sent_at = Instant::now();
		f.body.download.lock().tasks.push_back(BodyTask {
			hash: Hash::default(),
			height: 0,
			obsolete: true,
			request: Some(BodyTaskRequest {
				peer: fast.info.addr.clone(),
				supplier: Arc::downgrade(&fast),
				sent_at,
				expires_at: sent_at + Duration::from_secs(30),
			}),
			received: None,
		});
		f.poll();
		let download = f.body.download.lock();
		let active: Vec<_> = download
			.tasks
			.iter()
			.filter(|task| !task.obsolete)
			.collect();
		let fast_count = (per_peer - 1).min(active.len());
		let slow_count = per_peer.min(active.len().saturating_sub(slow_index));
		assert_eq!(fast_messages.try_iter().count(), fast_count);
		assert_eq!(slow_messages.try_iter().count(), slow_count);
		for (index, task) in active.iter().enumerate() {
			if index < fast_count {
				assert_eq!(task.request.as_ref().unwrap().peer, fast.info.addr);
			} else if (slow_index..slow_index + slow_count).contains(&index) {
				assert_eq!(task.request.as_ref().unwrap().peer, slow.info.addr);
			} else {
				assert!(task.request.is_none());
			}
		}
		let deadlines: Vec<_> = download
			.tasks
			.iter()
			.map(|task| task.request.as_ref().map(|request| request.expires_at))
			.collect();
		drop(download);
		f.poll();
		assert_eq!(
			fast_messages.try_iter().count() + slow_messages.try_iter().count(),
			0
		);
		assert_eq!(
			deadlines,
			f.body
				.download
				.lock()
				.tasks
				.iter()
				.map(|task| task.request.as_ref().map(|request| request.expires_at))
				.collect::<Vec<_>>()
		);
		// The timed-out peer moves to the tail. The retained obsolete request
		// still counts toward the queue length until it also expires.
		f.body
			.download
			.lock()
			.tasks
			.iter_mut()
			.find(|task| !task.obsolete)
			.unwrap()
			.request
			.as_mut()
			.unwrap()
			.expires_at = Instant::now();
		f.poll();
		assert_eq!(fast_messages.try_iter().count(), 0);
		assert_eq!(slow_messages.try_iter().count(), 0);
		f.body.download.lock().tasks[0]
			.request
			.as_mut()
			.unwrap()
			.expires_at = Instant::now();
		f.poll();
		assert_eq!(fast_messages.try_iter().count(), 1);
		assert_eq!(slow_messages.try_iter().count(), 0);
		let download = f.body.download.lock();
		let mut active = download.tasks.iter().filter(|task| !task.obsolete);
		assert!(active.next().unwrap().request.is_none());
		assert_eq!(
			active.last().unwrap().request.as_ref().unwrap().peer,
			fast.info.addr
		);
	}

	// Request one missing body and repeatedly age its unanswered request past the timeout.
	// Each poll retries until the fifth timeout marks the supplier Defunct and clears the request.
	#[test]
	fn unanswered_blocks_retry_and_repeated_timeouts_mark_supplier_defunct() {
		let f = Fixture::new(1_935_003, 1);
		let (peer, rx) = f.supplier(4120);
		f.poll();
		assert_eq!(rx.try_iter().count(), 1);
		for attempt in 0..5 {
			f.scores.elapse_no_response_merge_interval(&peer.info.addr);
			f.expire_requests();
			f.poll();
			assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
			assert_eq!(
				f.peers.get_peer(&peer.info.addr).unwrap().flags == mwc_p2p::State::Defunct,
				attempt == 4
			);
			assert_eq!(peer.is_connected(), attempt < 4);
			if attempt == 4 {
				// No block request or BanReason message is sent after disconnecting.
				assert_eq!(f.requests_num(), 0);
				assert_eq!(rx.try_iter().count(), 0);
			} else {
				assert_eq!(rx.try_iter().count(), 1);
			}
		}
	}

	// Close the supplier's outgoing channel before requesting its missing block.
	// Scheduling must return normally and leave an unassigned task for retry,
	// with no deadline for a request that was never sent and no ban for one failure.
	#[test]
	fn failed_block_send_leaves_task_unassigned() {
		let f = Fixture::new(1_935_009, 1);
		let (peer, receiver) = f.supplier(4170);
		drop(receiver);
		assert_eq!(f.poll().response, SyncRequestResponses::SyncDone);
		assert_eq!(f.requests_num(), 0);
		assert_eq!(f.body.download.lock().tasks.len(), 1);
		f.scores.apply_peers_status(&f.peers);
		assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
	}

	// Request a body from one peer, then deliver that same block from another address.
	// Matching by hash must clear the original request and complete sync, leaving no
	// outstanding request to expire against the original supplier.
	#[test]
	fn another_supplier_can_fulfil_an_outstanding_request() {
		let mut f = Fixture::new(1_935_004, 1);
		let (peer, rx) = f.supplier(4130);
		f.poll();
		assert_eq!(rx.try_iter().count(), 1);
		let (other, _other_rx) = f.supplier(4131);
		f.deliver(0, &other.info.addr);
		assert_eq!(f.requests_num(), 0);
		f.expire_requests();
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
	}

	#[test]
	fn unsolicited_bodies_append_only_the_next_canonical_task() {
		// Keep only the first task. A skipped height and a competing child of
		// its parent must not enter the queue. The canonical child may append,
		// wait for its parent, and then be applied in the same ready prefix.
		let mut f = Fixture::new(1_935_017, 3);
		let (peer, _rx) = f.supplier(4187);
		f.poll();
		f.body.download.lock().tasks.truncate(1);
		f.deliver(2, &peer.info.addr);
		assert_eq!(f.body.download.lock().tasks.len(), 1);
		let fork_dir = TempDir::new().unwrap();
		let fork = init_chain(f.chain.get_context_id(), &f.secp, &fork_dir, true);
		fork.process_block(
			&mut f.secp,
			f.blocks[0].clone(),
			Options::NONE,
			HashSet::new(),
		)
		.unwrap();
		let keychain = ExtKeychain::from_seed(&f.secp, &[70; 32], false).unwrap();
		let competing = next_block(&fork, &mut f.secp, &keychain, &[]);
		f.chain
			.process_block_header(&competing.header, Options::NONE)
			.unwrap();
		assert!(f
			.body
			.receive_block(&mut f.secp, &competing, &peer.info, false, true, &f.scores)
			.unwrap());
		assert_eq!(f.body.download.lock().tasks.len(), 1);
		f.deliver(1, &peer.info.addr);
		assert_eq!(f.body.download.lock().tasks.len(), 2);
		assert_eq!(f.chain.head().unwrap().height, 0);
		f.deliver(0, &peer.info.addr);
		assert_eq!(f.chain.head().unwrap().height, 2);
		assert!(f.body.download.lock().tasks.is_empty());
		f.deliver(2, &peer.info.addr);
		assert_eq!(f.chain.head().unwrap(), f.chain.header_head().unwrap());
	}

	#[test]
	fn reconnect_keeps_received_bodies_and_requires_a_known_tip() {
		let mut f = Fixture::new(1_935_080, 2);
		let (peer, messages) = f.supplier(4280);
		let tip = f.chain.header_head().unwrap();
		for (height, difficulty) in [(0, tip.total_difficulty), (tip.height, Difficulty::zero())] {
			{
				let mut info = peer.info.live_info.write();
				info.height = height;
				info.total_difficulty = difficulty;
			}
			f.poll();
			assert_eq!(messages.try_iter().count(), 0);
		}
		peer.info.update(tip.height, tip.total_difficulty);
		f.poll();
		assert_eq!(messages.try_iter().count(), 2);
		f.deliver(1, &peer.info.addr);
		f.body.clear_peer_requests(&peer.info.addr);
		{
			let download = f.body.download.lock();
			assert!(download.tasks[0].request.is_none());
			assert!(download.tasks[1].received.is_some());
		}
		f.poll();
		assert_eq!(messages.try_iter().count(), 1);
		for _ in 0..4 {
			f.scores.elapse_no_response_merge_interval(&peer.info.addr);
			f.scores
				.report_no_response(&peer.info.addr, "before disconnect".into());
		}
		f.scores.elapse_no_response_merge_interval(&peer.info.addr);
		peer.stop();
		f.body
			.download
			.lock()
			.expire_requests(Instant::now() + Duration::from_secs(60), &f.scores);
		assert!(f.body.download.lock().tasks[0].request.is_none());
		f.scores.apply_peers_status(&f.peers);
		assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
		assert_eq!(
			f.peers.get_peer(&peer.info.addr).unwrap().flags,
			mwc_p2p::State::Healthy
		);
	}

	#[test]
	fn appended_body_can_extend_the_header_tip() {
		// Start with just the parent header/task. Receiving its unrequested child
		// validates the new header and buffers the body, without applying it early.
		let mut f = Fixture::new(1_935_018, 1);
		let (peer, _rx) = f.supplier(4188);
		f.poll();
		let source_dir = TempDir::new().unwrap();
		let source = init_chain(f.chain.get_context_id(), &f.secp, &source_dir, true);
		source
			.process_block(
				&mut f.secp,
				f.blocks[0].clone(),
				Options::NONE,
				HashSet::new(),
			)
			.unwrap();
		let keychain = ExtKeychain::from_seed(&f.secp, &[67; 32], false).unwrap();
		let child = next_block(&source, &mut f.secp, &keychain, &[]);
		assert!(f
			.body
			.receive_block(&mut f.secp, &child, &peer.info, false, true, &f.scores)
			.unwrap());
		assert_eq!(f.chain.header_head().unwrap().height, 2);
		assert_eq!(f.chain.head().unwrap().height, 0);
		assert_eq!(f.body.download.lock().tasks.len(), 2);
		f.deliver(0, &peer.info.addr);
		assert_eq!(f.chain.head().unwrap(), f.chain.header_head().unwrap());
	}

	#[test]
	fn unsolicited_body_cannot_grow_a_full_window() {
		// Fill the resource-based window and deliver its next canonical block.
		// It must be discarded while full, then accepted after applying a task
		// frees space. Buffered and unanswered tasks share the same allowance.
		let params = Arc::new(PibdParams::with_cpu_count_for_test(1));
		let count = params.get_blocks_request_limit(None) + 1;
		let mut f = Fixture::new(1_935_019, count);
		f.body.pibd_params = params;
		let (peer, _rx) = f.supplier(4189);
		f.poll();
		let limit = f.body.get_task_num_limit(&f.body.download.lock());
		assert_eq!(f.body.download.lock().tasks.len(), limit);
		f.deliver(limit, &peer.info.addr);
		assert_eq!(f.body.download.lock().tasks.len(), limit);
		f.deliver(0, &peer.info.addr);
		{
			let mut download = f.body.download.lock();
			f.body
				.apply_ready_tasks(&mut download, &mut f.secp, &f.scores)
				.unwrap();
		}
		assert_eq!(f.body.download.lock().tasks.len(), limit - 1);
		f.deliver(limit, &peer.info.addr);
		let download = f.body.download.lock();
		assert_eq!(download.tasks.len(), limit);
		assert!(download.tasks.back().unwrap().received.is_some());
	}

	#[test]
	fn announced_headers_obey_the_same_peer_request_limit() {
		// Announcing several canonical headers must use the same body queue and
		// per-peer budget as polling. Repeated announcements must not resend.
		let f = Fixture::new(1_935_020, 0);
		f.extend_headers_to(10);
		let (peer, rx) = f.supplier(4190);
		for _ in 0..2 {
			for height in 1..=10 {
				let header = f.chain.get_header_by_height(height).unwrap();
				f.body
					.request_header_block(&header, &peer, &f.scores)
					.unwrap();
			}
		}
		let expected = 10
			.min(f.body.pibd_params.get_blocks_request_per_peer())
			.min(f.body.get_task_num_limit(&f.body.download.lock()));
		assert_eq!(rx.try_iter().count(), expected);
		assert_eq!(f.requests_num(), expected);
	}

	// After the first task is applied, its delayed duplicate is outside the window.
	// A requested block with a forged height must still reach header validation and
	// return false for the caller to ban its supplier. The valid block remains usable.
	#[test]
	fn height_lookup_rejects_forged_heights_and_ignores_applied_blocks() {
		let mut f = Fixture::new(1_935_016, 2);
		let (peer, _rx) = f.supplier(4186);
		f.poll();
		f.deliver(0, &peer.info.addr);
		assert_eq!(
			f.body
				.receive_block(
					&mut f.secp,
					&f.blocks[0],
					&peer.info,
					false,
					true,
					&f.scores
				)
				.unwrap(),
			true
		);
		assert_eq!(f.requests_num(), 1);
		for height in [0, u64::MAX] {
			let mut block = f.blocks[1].clone();
			block.header.height = height;
			assert_eq!(
				block.hash(f.chain.get_context_id()).unwrap(),
				f.blocks[1].hash(f.chain.get_context_id()).unwrap()
			);
			assert_eq!(
				f.body
					.receive_block(&mut f.secp, &block, &peer.info, false, true, &f.scores)
					.unwrap(),
				false
			);
		}
		assert_eq!(f.requests_num(), 0);
		assert_eq!(f.body.download.lock().tasks.len(), 1);
		f.deliver(1, &peer.info.addr);
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert_eq!(f.chain.head().unwrap().height, 2);
	}

	// Deliver bodies at heights 3 and 2 before height 1. They stay in the task queue,
	// without applying children early or sending duplicate downloads. Their parent must make the
	// whole ready prefix applicable and finish body sync at height 3.
	#[test]
	fn body_window_keeps_received_children_while_waiting_for_parent() {
		let mut f = Fixture::new(1_935_005, 3);
		let (peer, rx) = f.supplier(4140);
		f.poll();
		assert_eq!(rx.try_iter().count(), 3);
		f.deliver(2, &peer.info.addr);
		f.deliver(1, &peer.info.addr);
		assert_eq!(
			f.body
				.download
				.lock()
				.tasks
				.iter()
				.filter(|task| task.received.is_some())
				.count(),
			2
		);
		assert_eq!(f.requests_num(), 1);
		assert_eq!(f.chain.head().unwrap().height, 0);
		f.poll();
		assert_eq!(rx.try_iter().count(), 0);
		f.deliver(0, &peer.info.addr);
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert_eq!(f.chain.head().unwrap().height, 3);
	}

	// Start with a three-task window on a six-block chain and buffer its two children.
	// Accepting the parent must drain all three in order. Filling the empty window
	// must derive the current limit and resume at height 4 without caller-supplied tips.
	#[test]
	fn scheduling_refills_after_ready_prefix_is_applied() {
		let mut f = Fixture::new(1_935_010, 6);
		let (peer, _rx) = f.supplier(4180);
		let mut download = f.body.download.lock();
		f.body.fill_tasks(&mut download).unwrap();
		// Model a window retained from an earlier, smaller resource allowance.
		download.tasks.truncate(3);
		for index in 1..3 {
			download.tasks[index].received = Some(ReceivedBlock {
				block: f.blocks[index].clone(),
				peer: peer.info.clone(),
				reconstructed: false,
			});
		}
		f.body
			.apply_ready_tasks(&mut download, &mut f.secp, &f.scores)
			.unwrap();
		assert_eq!(download.tasks.len(), 3);
		assert_eq!(f.chain.head().unwrap().height, 0);
		download.tasks[0].received = Some(ReceivedBlock {
			block: f.blocks[0].clone(),
			peer: peer.info.clone(),
			reconstructed: false,
		});
		f.body
			.apply_ready_tasks(&mut download, &mut f.secp, &f.scores)
			.unwrap();
		assert_eq!(f.chain.head().unwrap().height, 3);
		assert!(download.tasks.is_empty());
		f.body.fill_tasks(&mut download).unwrap();
		assert_eq!(
			download
				.tasks
				.iter()
				.map(|task| task.height)
				.collect::<Vec<_>>(),
			vec![4, 5, 6]
		);
	}

	// Receive the child first, then expire all unanswered requests. Only its
	// missing parent should be retried; the buffered child has no timeout left.
	// Delivering the parent must still apply both bodies without a redownload.
	#[test]
	fn buffered_responses_do_not_expire_while_waiting_for_the_parent() {
		let mut f = Fixture::new(1_935_011, 2);
		let (peer, rx) = f.supplier(4181);
		f.poll();
		assert_eq!(rx.try_iter().count(), 2);
		f.deliver(1, &peer.info.addr);
		f.expire_requests();
		f.poll();
		assert_eq!(rx.try_iter().count(), 1);
		assert_eq!(f.requests_num(), 1);
		assert!(f.body.download.lock().tasks[1].received.is_some());
		f.deliver(0, &peer.info.addr);
		assert_eq!(f.chain.head().unwrap().height, 2);
	}

	// Seed a four-second latency sample: new requests get a sixteen-second deadline.
	// New samples cannot move that deadline, and an expired-but-not-yet-reaped
	// response remains acceptable, just as it does for header requests.
	#[test]
	fn adaptive_deadlines_stay_fixed_and_late_responses_are_accepted() {
		let mut f = Fixture::new(1_935_012, 1);
		let (peer, _rx) = f.supplier(4182);
		peer.record_response_latency(Duration::from_secs(4));
		f.poll();
		let deadline = {
			let download = f.body.download.lock();
			let request = download.tasks[0].request.as_ref().unwrap();
			assert_eq!(
				request.expires_at.duration_since(request.sent_at),
				Duration::from_secs(16)
			);
			request.expires_at
		};
		peer.record_response_latency(Duration::from_secs(20));
		f.poll();
		assert_eq!(
			f.body.download.lock().tasks[0]
				.request
				.as_ref()
				.unwrap()
				.expires_at,
			deadline
		);
		f.expire_requests();
		f.deliver(0, &peer.info.addr);
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
	}

	// Accept three bodies, then rewind the body head to height 1 while retaining headers
	// and stored blocks through height 3. The first poll queues the stored bodies;
	// the next poll applies them and finishes without peers or download requests.
	#[test]
	fn stored_bodies_are_reapplied_after_a_rewind_without_downloads() {
		let mut f = Fixture::new(1_935_008, 3);
		for block in &f.blocks {
			f.chain
				.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
				.unwrap();
		}
		f.chain
			.reset_chain_head(
				&f.secp,
				&f.blocks[0].header,
				mwc_chain::ChainHeadReset::Body,
			)
			.unwrap();
		assert_eq!(f.chain.head().unwrap().height, 1);
		assert_eq!(f.chain.header_head().unwrap().height, 3);
		assert!(f
			.chain
			.block_exists(&f.blocks[2].hash(f.chain.get_context_id()).unwrap())
			.unwrap());
		assert_eq!(f.poll().response, SyncRequestResponses::SyncDone);
		assert_eq!(f.chain.head().unwrap().height, 1);
		assert_eq!(f.requests_num(), 0);
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
		assert_eq!(f.chain.head().unwrap().height, 3);
		assert_eq!(f.requests_num(), 0);
	}

	// Compare archive, regular, and legacy suppliers at historical and encoding boundaries.
	// Blocks below the supplier's pruning horizon require archive support. Blocks
	// between the horizon and the PIBD snapshot cutoff remain eligible for regular
	// peers. Newer blocks require BLOCK_EXTRA and must not go to the legacy peer.
	#[test]
	fn archive_and_block_encoding_requirements_apply_per_block() {
		let f = Fixture::new(1_935_006, 0);
		f.extend_headers_to(5);
		let tip = f.chain.header_head().unwrap();
		let (archive, _archive_rx) = f.supplier(4150);
		let (regular, _regular_rx) = f.peer(
			4151,
			tip.height,
			tip.total_difficulty,
			Capabilities::BLOCK_EXTRA,
		);
		let (legacy, _legacy_rx) = f.peer(
			4152,
			tip.height,
			tip.total_difficulty,
			Capabilities::BLOCK_HIST,
		);
		let context = f.chain.get_context_id();
		let horizon_height = 100 - u64::from(global::cut_through_horizon(context));
		let snapshot_height = Chain::height_2_archive_height(context, 100);
		assert!(horizon_height < snapshot_height);
		assert!(f.body.can_supply(&archive, 100, horizon_height - 1));
		assert!(!f.body.can_supply(&regular, 100, horizon_height - 1));
		assert!(f.body.can_supply(&regular, 100, horizon_height));
		assert!(f.body.can_supply(&regular, 100, snapshot_height - 1));
		assert!(f.body.can_supply(&regular, 5, 4));
		assert!(!f.body.can_supply(&regular, 3, 4));
		assert!(f.body.can_supply(&legacy, 5, 3));
		assert!(!f.body.can_supply(&legacy, 5, 4));
		// The fastest peer cannot serve the newer encoding. Its latency must
		// not defer the compatible suppliers beyond the current task window.
		legacy.record_response_latency(Duration::from_millis(1));
		archive.record_response_latency(Duration::from_secs(1));
		regular.record_response_latency(Duration::from_secs(1));
		f.poll();
		for height in 4..=5 {
			let hash = f
				.chain
				.get_header_by_height(height)
				.unwrap()
				.hash(context)
				.unwrap();
			assert!(!f.body.has_block_request(&legacy.info.addr, &hash));
			assert!(
				f.body.has_block_request(&archive.info.addr, &hash)
					|| f.body.has_block_request(&regular.info.addr, &hash)
			);
		}
	}

	// Replace the canonical headers while old body requests are outstanding, then deliver
	// the new fork while the body head still follows the old branch. Expired obsolete
	// requests must disappear, stored fork bodies must not be requested again, and sync must finish.
	#[test]
	fn reorg_expires_old_requests_and_skips_already_stored_fork_bodies() {
		let mut f = Fixture::new(1_935_007, 3);
		let (old_peer, old_rx) = f.supplier(4160);
		f.poll();
		assert_eq!(old_rx.try_iter().count(), 3);
		let obsolete: Vec<_> = f
			.blocks
			.iter()
			.map(|b| b.hash(f.chain.get_context_id()).unwrap())
			.collect();
		// Make old requests overdue, then replace their branch before the next sync poll.
		f.expire_requests();
		let fork_dir = TempDir::new().unwrap();
		let fork = init_chain(f.chain.get_context_id(), &f.secp, &fork_dir, true);
		let keychain = ExtKeychain::from_seed(&f.secp, &[68; 32], false).unwrap();
		let mut blocks = Vec::new();
		for _ in 0..4 {
			let block = next_block(&fork, &mut f.secp, &keychain, &[]);
			fork.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
				.unwrap();
			f.chain
				.process_block_header(&block.header, Options::NONE)
				.unwrap();
			blocks.push(block);
		}
		let (_new_peer, new_rx) = f.supplier(4161);
		f.poll();
		assert!(f
			.body
			.download
			.lock()
			.tasks
			.iter()
			.all(|task| !obsolete.contains(&task.hash)));
		assert_eq!(old_rx.try_iter().count() + new_rx.try_iter().count(), 4);
		assert!(!f.peers.is_banned(&old_peer.info.addr).unwrap());
		// A body fork can remain behind the selected body head until enough work arrives.
		for block in &f.blocks {
			f.chain
				.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
				.unwrap();
		}
		f.blocks = blocks;
		// Drain a small window before this fork has enough work to move head().
		// Scheduling must discover the stored prefix and continue at height 3.
		f.body.download.lock().tasks.truncate(2);
		f.deliver(0, &old_peer.info.addr);
		f.deliver(1, &old_peer.info.addr);
		assert!(f.body.download.lock().tasks.is_empty());
		assert_eq!(f.chain.head().unwrap().last_block_h, obsolete[2]);
		f.poll();
		// The first two fork bodies are stored even though they have not won by work yet.
		assert!(f
			.body
			.download
			.lock()
			.tasks
			.iter()
			.all(|task| task.height > 2));
		f.deliver(2, &old_peer.info.addr);
		f.deliver(3, &old_peer.info.addr);
		assert_eq!(f.poll().response, SyncRequestResponses::BodyReady);
	}

	// Keep all historical bodies in archive mode, then select a higher-work header
	// branch that forks at genesis, one block beyond the allowed rewind depth.
	// Scheduling downloads the canonical bodies. Chain processing rejects the first
	// fork block's rewind; BodySync propagates the error, retains the block, and does
	// not penalize its supplier for a local rewind limit.
	#[test]
	fn chain_processing_enforces_the_rewind_horizon() {
		let count = global::AUTOMATED_TESTING_CUT_THROUGH_HORIZON as usize + 1;
		let mut f = Fixture::new(1_935_013, count);
		// This fixture only needs the final head; commit its existing bodies together.
		f.chain
			.process_blocks(&mut f.secp, &f.blocks, Options::NONE, Default::default())
			.unwrap();
		let original_head = f.chain.head().unwrap();
		assert!(f.chain.archive_mode());
		let fork_dir = TempDir::new().unwrap();
		let fork = init_chain(f.chain.get_context_id(), &f.secp, &fork_dir, true);
		let keychain = ExtKeychain::from_seed(&f.secp, &[69; 32], false).unwrap();
		// Only the first fork body is delivered; the remaining headers select the fork.
		let block = next_block(&fork, &mut f.secp, &keychain, &[]);
		fork.process_block(&mut f.secp, block.clone(), Options::NONE, HashSet::new())
			.unwrap();
		Fixture::extend_chain_headers_to(&fork, count as u64 + 1);
		let headers: Vec<_> = (1..=count as u64 + 1)
			.map(|height| fork.get_header_by_height(height).unwrap())
			.collect();
		f.chain
			.sync_block_headers(&headers, Options::NONE, 1)
			.unwrap();
		assert!(f.chain.header_head().unwrap().total_difficulty > original_head.total_difficulty);
		assert_eq!(f.chain.fork_point().unwrap().height, 0);
		let (peer, rx) = f.supplier(4183);
		f.poll();
		assert!(f.requests_num() > 0);
		assert_eq!(rx.try_iter().count(), f.requests_num());
		let error = f
			.body
			.receive_block(&mut f.secp, &block, &peer.info, false, true, &f.scores)
			.unwrap_err();
		assert!(matches!(
			error,
			Error::RewindBeyondHorizon {
				head_height,
				target_height: 0,
				minimum_height: 1,
			} if head_height == original_head.height
		));
		assert_eq!(f.chain.head().unwrap(), original_head);
		assert!(f.body.download.lock().tasks[0].received.is_some());
		f.scores.apply_peers_status(&f.peers);
		assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
	}

	fn init_chain(
		context: u32,
		secp: &Secp256k1,
		dir: &TempDir,
		archive: bool,
	) -> mwc_chain::Chain {
		mwc_chain::Chain::init(
			secp,
			context,
			dir.path().to_str().unwrap().into(),
			Arc::new(NoopAdapter {}),
			global::get_genesis_block(secp, context).unwrap(),
			pow::verify_size,
			archive,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap()
	}

	// Build a valid next block with chain-derived roots, coinbase binding, and real
	// proof of work at automated-testing difficulty. The caller controls when this
	// block is accepted locally or delivered to another chain in the test.
	fn next_block(
		chain: &mwc_chain::Chain,
		secp: &mut Secp256k1,
		keychain: &ExtKeychain,
		txs: &[Transaction],
	) -> core::Block {
		let context = chain.get_context_id();
		let parent = chain.head_header().unwrap();
		let height = parent.height + 1;
		let key = ExtKeychain::derive_key_id(1, u32::try_from(height).unwrap(), 0, 0, 0).unwrap();
		let aggregate = transaction::aggregate(context, txs, secp).unwrap();
		let binding = chain
			.coinbase_binding_for_template(secp, &parent, &aggregate.body)
			.unwrap();
		let builder = ProofBuilder::new(secp, keychain).unwrap();
		let (output, kernel, opening) = reward::output_s2c(
			context,
			keychain,
			&builder,
			&key,
			aggregate.fee().unwrap(),
			height,
			secp,
			binding.digest().unwrap(),
		)
		.unwrap();
		let difficulty = consensus::next_difficulty(
			context,
			height,
			chain.difficulty_iter().unwrap(),
			&mut consensus::DifficultyCache::new(),
		)
		.unwrap();
		let mut block = core::Block::new(
			context,
			&parent,
			txs,
			difficulty.difficulty,
			(output, kernel),
			secp,
		)
		.unwrap();
		block.coinbase_opening =
			consensus::is_coinbase_binding_enabled(context, height).then_some(opening);
		block.header.timestamp = parent.timestamp + chrono::Duration::seconds(60);
		block.header.pow.secondary_scaling = difficulty.secondary_scaling;
		chain.set_txhashset_roots(secp, &mut block).unwrap();
		pow::pow_size(
			context,
			&mut block.header,
			difficulty.difficulty,
			global::proofsize(context),
			global::min_edge_bits(context),
		)
		.unwrap();
		block
	}
}
