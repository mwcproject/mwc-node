// Copyright 2019 The Grin Developers
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
use crate::mwc::sync::sync_utils;
use crate::mwc::sync::sync_utils::{SyncRequestResponses, SyncResponse};
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::txhashset::{BitmapChunk, Desegmenter, StateSegment, ValidatedStateSegment};
use mwc_chain::{self, pibd_params, SyncState};
use mwc_chain::{Chain, SyncStatus};
use mwc_core::core::hash::Hash;
use mwc_core::core::{hash::Hashed, pmmr::segment::SegmentType};
use mwc_core::core::{OutputIdentifier, Segment, SegmentTypeIdentifier, TxKernel};
use mwc_crates::log::{debug, error, info, warn};
use mwc_crates::parking_lot::{Mutex, RwLock, RwLockReadGuard};
use mwc_crates::rand;
use mwc_crates::rand::prelude::IteratorRandom;
use mwc_crates::secp::pedersen::RangeProof;
use mwc_p2p::PeerAddr;
use mwc_p2p::{self, Capabilities, Peer};
use mwc_util::{LatencyTracker, StopState};
use std::cmp;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

const SEGMENT_TYPES: [SegmentType; 4] = [
	SegmentType::Bitmap,
	SegmentType::Output,
	SegmentType::RangeProof,
	SegmentType::Kernel,
];

// Bound each sync tick so request refilling and cancellation stay responsive.
const MAX_SEGMENTS_PER_BATCH: usize = 16;

const MIN_PIBD_ROOT_RESPONSES: usize = 2;
// Accepted commitments are never evicted during a PIBD session. This limit is
// enforced before sending a request, so every accepted response still has a slot.
const MAX_PIBD_ROOT_RESPONSE_ENTRIES: usize = 10240;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PibdRootSelection {
	Selected(Hash),
	NeedMoreResponses { responses: usize },
	NoQuorum { responses: usize, best_count: usize },
}

/// Fast sync has 3 "states":
/// * syncing headers
/// * once all headers are sync'd, requesting the txhashset state
/// * once we have the state, get blocks after that
///
/// The StateSync struct implements and monitors the middle step.
pub struct StateSync {
	chain: Arc<Chain>,
	// Write on initialization/reset. Receivers pin the session while validating
	// and buffering; the sync loop pins it while applying and scheduling tasks.
	desegmenter: RwLock<Option<Arc<Desegmenter>>>,
	reset_desegmenter: AtomicBool,

	// Target height needs to be calculated by the top peers, can be different from headers, it is no problem
	target_archive_height: AtomicU64,
	target_archive_hash: RwLock<Hash>,
	requested_root_hash: RwLock<HashMap<PeerAddr, Instant>>, // Lock 1
	// Session-long peer commitments. Retain these across disconnect/reconnect so
	// the peer remains tied to its advertised root and can be banned on failure.
	responded_root_hash: RwLock<HashMap<PeerAddr, (Hash, Instant)>>, // Lock 2
	// Serialize application and request planning. Lock before download, with the
	// session pinned; storage writes release download so proof checks can proceed.
	apply_lock: Mutex<()>,
	// Unanswered requests and buffered responses. The writer temporarily owns
	// a ready batch while apply_lock prevents refilling its slots.
	download: Mutex<StateDownload>,
	// Import completion is independent of the following ordinary block sync.
	is_complete: AtomicBool,
	pibd_params: Arc<PibdParams>,
}

struct StateDownload {
	tasks: VecDeque<StateTask>,
	latency: LatencyTracker,
}

struct StateTask {
	id: SegmentTypeIdentifier,
	request: Option<StateTaskRequest>,
	received: Option<ReceivedSegment>,
}

struct StateTaskRequest {
	peer: PeerAddr,
	supplier: Weak<Peer>,
	sent_at: Instant,
	expires_at: Instant,
}

struct ReceivedSegment {
	segment: ValidatedStateSegment,
	peer: PeerAddr,
}

impl StateDownload {
	fn new() -> Self {
		Self {
			tasks: VecDeque::new(),
			latency: LatencyTracker::new(),
		}
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
						format!("Snapshot segment {:?} timed out", task.id),
					);
					task.request = None;
				}
			}
		}
	}

	fn fill_tasks(
		&mut self,
		desegmenter: &Desegmenter,
		params: &PibdParams,
	) -> Result<(), mwc_chain::Error> {
		let latency_ms = self
			.latency
			.get_average_latency()
			.and_then(|latency| u32::try_from(latency.as_millis()).ok());
		let limit = params.get_segments_requests_limit(latency_ms);
		if self.tasks.len() >= limit {
			return Ok(()); // A smaller limit stops refilling; existing tasks finish normally.
		}
		let available = limit - self.tasks.len();
		let mut next = Vec::new();
		for kind in &SEGMENT_TYPES {
			let queued = self
				.tasks
				.iter()
				.filter(|task| &task.id.segment_type == kind)
				.count();
			let window = if *kind == SegmentType::Bitmap {
				params.get_bitmaps_buffer_len()
			} else {
				params.get_segments_buffer_len()
			};
			next.push(
				desegmenter
					.next_segments(kind, queued, available.min(window.saturating_sub(queued)))?
					.into_iter(),
			);
		}
		// Interleave independent streams so a missing segment of one type cannot
		// consume the entire window and prevent another type from progressing.
		while self.tasks.len() < limit {
			let mut added = false;
			for stream in &mut next {
				if self.tasks.len() == limit {
					break;
				}
				if let Some(id) = stream.next() {
					self.tasks.push_back(StateTask {
						id,
						request: None,
						received: None,
					});
					added = true;
				}
			}
			if !added {
				break;
			}
		}
		Ok(())
	}
}

enum DesegmenterValidation<'a> {
	Valid {
		// Bind validation and buffering to the live PIBD session.
		_guard: RwLockReadGuard<'a, Option<Arc<Desegmenter>>>,
		desegmenter: Arc<Desegmenter>,
	},
	// Keep the current session pinned until the caller has updated request
	// tracking. Otherwise a reset can replace the session between validation and
	// tracking, allowing this response to remove a new session's request.
	PeerMismatch {
		_guard: RwLockReadGuard<'a, Option<Arc<Desegmenter>>>,
	},
	// The response belongs to an inactive, locally invalidated, or replaced
	// session. It must not affect peer scoring or current-session requests.
	Stale,
}

pub(super) struct LiveDesegmenter<'a> {
	// Keep the live session pinned while applying and scheduling segments. Resetting
	// the PIBD session starts by taking the desegmenter write lock, so this
	// guard prevents target_archive_hash and request caches from being cleared
	// or replaced while tasks are selected, sent, and registered.
	_guard: RwLockReadGuard<'a, Option<Arc<Desegmenter>>>,
	pub(super) desegmenter: Arc<Desegmenter>,
	pub(super) archive_hash: Hash,
	pub(super) root_hash: Hash,
}

impl StateSync {
	pub(super) fn clear_peer_requests(&self, peer: &PeerAddr) {
		self.requested_root_hash.write().remove(peer);
		for task in &mut self.download.lock().tasks {
			if task
				.request
				.as_ref()
				.is_some_and(|request| request.peer == *peer)
			{
				task.request = None;
			}
		}
	}

	pub fn new(chain: Arc<Chain>) -> StateSync {
		StateSync {
			pibd_params: chain.get_pibd_params().clone(),
			chain,
			desegmenter: RwLock::new(None),
			reset_desegmenter: AtomicBool::new(false),
			target_archive_height: AtomicU64::new(0),
			target_archive_hash: RwLock::new(Hash::default()),
			requested_root_hash: RwLock::new(HashMap::new()),
			responded_root_hash: RwLock::new(HashMap::new()),
			apply_lock: Mutex::new(()),
			download: Mutex::new(StateDownload::new()),
			is_complete: AtomicBool::new(false),
		}
	}

	fn eligible_peers(&self, peers: &Arc<mwc_p2p::Peers>) -> Vec<Arc<Peer>> {
		let height = self.target_archive_height.load(Ordering::Relaxed);
		let mut candidates: Vec<_> = peers
			.iter()
			.connected()
			.filter(|peer| peer.info.has_known_tip())
			.with_capabilities(Capabilities::PIBD_HIST)
			.with_min_height(height)
			.into_iter()
			.filter(|peer| {
				Chain::height_2_archive_height(
					self.chain.get_context_id(),
					peer.info.get_height_and_difficulty().0,
				) == height
			})
			.collect();
		if candidates.iter().any(|peer| peer.info.is_outbound()) {
			candidates.retain(|peer| peer.info.is_outbound());
		}
		candidates
	}

	fn remaining_pibd_root_peer_capacity(
		requested_root_hash: &HashMap<PeerAddr, Instant>,
		responded_root_hash: &HashMap<PeerAddr, (Hash, Instant)>,
		max_entries: usize,
	) -> usize {
		max_entries.saturating_sub(
			requested_root_hash
				.len()
				.saturating_add(responded_root_hash.len()),
		)
	}

	fn select_pibd_root<'a>(
		root_hashes: impl Iterator<Item = &'a Hash>,
		required_responses: usize,
	) -> PibdRootSelection {
		match sync_utils::select_quorum(
			root_hashes.copied(),
			required_responses,
			MIN_PIBD_ROOT_RESPONSES,
			|root_hash| *root_hash,
		) {
			sync_utils::QuorumSelection::Selected {
				value: root_hash, ..
			} => PibdRootSelection::Selected(root_hash),
			sync_utils::QuorumSelection::NeedMoreResponses { responses } => {
				PibdRootSelection::NeedMoreResponses { responses }
			}
			sync_utils::QuorumSelection::NoQuorum {
				responses,
				best_count,
			} => PibdRootSelection::NoQuorum {
				responses,
				best_count,
			},
		}
	}

	pub fn request(
		&self,
		in_peers: &Arc<mwc_p2p::Peers>,
		sync_state: Arc<SyncState>,
		sync_peers: &SyncPeers,
		stop_state: Arc<StopState>,
		best_height: u64,
	) -> Result<SyncResponse, mwc_chain::Error> {
		// Keep the imported session and its root endorsements until ordinary
		// block sync advances the chain or requests that this import be reset.
		if self.has_imported_state() {
			let height = self.target_archive_height.load(Ordering::Relaxed);
			let head = self.chain.head()?;
			if head.height > height {
				// Normal block processing has advanced beyond the imported state.
				self.complete_pibd_sync();
			} else {
				let archive_hash = *self.target_archive_hash.read_recursive();
				let session = self.live_desegmenter();
				let archive = self.chain.get_header_by_height(height)?;
				let context_id = self.chain.get_context_id();
				if self.reset_desegmenter.load(Ordering::Relaxed)
					|| session.as_ref().map(|s| s.archive_hash) != Some(archive_hash)
					|| head.last_block_h != archive_hash
					|| archive.hash(context_id)? != archive_hash
					|| Chain::height_2_archive_height(context_id, best_height) != height
				{
					// A reset request, changed target, or local recovery ends the
					// imported session before ordinary block sync continues.
					drop(session);
					self.chain
						.reset_pibd_chain(mwc_chain::PibdResetMode::Body)?;
					self.reset_desegmenter_data();
					return Ok(SyncResponse::new(
						SyncRequestResponses::Syncing,
						Capabilities::PIBD_HIST,
						"Restarting PIBD after failed blocks or a changed session".into(),
					));
				}
				return Ok(SyncResponse::new(
					SyncRequestResponses::StatePibdReady,
					Capabilities::PIBD_HIST,
					"PIBD imported; continuing with normal block sync".into(),
				));
			}
		}

		// After complete_pibd_sync(), completion intentionally bypasses the archive-height
		// checks below; ordinary body sync handles subsequent catch-up in this process.
		// Accepted limitation: a node that stays running through prolonged network loss
		// can fall beyond non-archive peers' retained block horizon (about 7 days of
		// blocks on mainnet/floonet, sooner if already behind). Catch-up then requires
		// a peer with block history or a restart. Restarting creates StateSync with
		// is_complete=false, so nodes stopped for a long time can use PIBD normally.
		// Automatic PIBD re-entry for this prolonged-disconnection case is intentionally
		// omitted to keep sync transitions simple.
		// Archive nodes always skip PIBD and catch up through body sync.
		if self.is_complete.load(Ordering::Acquire) || self.chain.archive_mode() {
			return Ok(SyncResponse::new(
				SyncRequestResponses::StatePibdReady,
				Capabilities::UNKNOWN,
				"".into(),
			));
		}

		// Let's check if we need to calculate/update archive height.
		let target_archive_height =
			Chain::height_2_archive_height(self.chain.get_context_id(), best_height);

		// Event it is not atomic operation, it is safe because request called from a single thread
		if self.target_archive_height.load(Ordering::Relaxed) != target_archive_height {
			// total reset, nothing needs to be saved...
			self.reset_desegmenter_data();
			// Resetting all internal state, starting from the scratch
			self.target_archive_height
				.store(target_archive_height, Ordering::Relaxed);
		}

		if target_archive_height == 0 {
			return Ok(SyncResponse::new(
				SyncRequestResponses::StatePibdReady,
				Capabilities::UNKNOWN,
				"Genesis state is ready".into(),
			));
		}

		// State must cover the selected branch, including after a deep reorg.
		let fork = self.chain.fork_point()?;
		if fork.height >= target_archive_height {
			// We are good, no needs to PIBD sync
			info!("No needs to sync, data until archive is ready");
			self.complete_pibd_sync();
			return Ok(SyncResponse::new(
				SyncRequestResponses::StatePibdReady,
				Capabilities::UNKNOWN,
				format!(
					"fork.height={}  target_archive_height={}",
					fork.height, target_archive_height
				),
			));
		}

		// Checking if archive header is already in the chain
		let archive_header = match self.chain.get_header_by_height(target_archive_height) {
			Ok(archive_header) => archive_header,
			Err(e) => {
				if !e.is_not_found() {
					return Err(e);
				}
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForHeaders,
					Capabilities::PIBD_HIST,
					format!("Header at height {} doesn't exist", target_archive_height),
				));
			}
		};
		let archive_header_hash = archive_header.hash(self.chain.get_context_id())?;
		let prev_archive_header_hash = *self.target_archive_hash.read_recursive();
		if prev_archive_header_hash != Hash::default()
			&& prev_archive_header_hash != archive_header_hash
		{
			info!(
				"Archive header at PIBD target height {} changed from {} to {}, restarting state sync",
				target_archive_height, prev_archive_header_hash, archive_header_hash
			);
			self.reset_desegmenter_data();
		}
		let stale_desegmenter = self
			.desegmenter
			.read_recursive()
			.as_ref()
			.map(|desegmenter| !desegmenter.is_current())
			.unwrap_or(false);
		if stale_desegmenter {
			warn!("Discarding PIBD desegmenter invalidated by chain-state recovery");
			self.reset_desegmenter.store(true, Ordering::Relaxed);
		}
		if self.reset_desegmenter.swap(false, Ordering::Relaxed) {
			self.reset_desegmenter_data();
		}

		*self.target_archive_hash.write() = archive_header_hash;

		let now = Instant::now();
		let request_timeout = Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64);
		{
			let mut requested_root_hash = self.requested_root_hash.write();
			requested_root_hash.retain(|peer, req_time| {
				if in_peers.get_connected_peer(peer).is_none() {
					return false;
				}
				if now.saturating_duration_since(*req_time) > request_timeout {
					sync_peers.report_no_response(peer, "root hash".into());
					return false;
				}
				true
			});
		}

		// Expiration belongs to the main loop, including when no suppliers remain.
		// Pin the session so a local reset cannot turn an old timeout into a fine.
		if let Some(_session) = self.live_desegmenter() {
			self.download.lock().expire_requests(now, sync_peers);
		}
		let peers = self.eligible_peers(in_peers);
		if peers.is_empty() && self.desegmenter.read_recursive().is_none() {
			return Ok(SyncResponse::new(
				SyncRequestResponses::WaitingForPeers,
				Capabilities::PIBD_HIST,
				"No peers available for snapshot discovery".into(),
			));
		}

		let mut root_request_failures = 0;

		{
			let mut requested_root_hash = self.requested_root_hash.write();
			let responded_root_hash = self.responded_root_hash.read_recursive();
			let mut remaining_root_peer_capacity = Self::remaining_pibd_root_peer_capacity(
				&requested_root_hash,
				&responded_root_hash,
				MAX_PIBD_ROOT_RESPONSE_ENTRIES,
			);

			// request handshakes if needed
			for peer in &peers {
				if !peer.is_connected() {
					continue;
				}
				// Never make room by evicting a response: it is the peer's root
				// commitment for reconnect authorization and any later session ban.
				if remaining_root_peer_capacity == 0 {
					break;
				}
				if !(requested_root_hash.contains_key(&peer.info.addr)
					|| responded_root_hash.contains_key(&peer.info.addr))
				{
					// can request a handshake
					match peer
						.send_start_pibd_sync_request(archive_header.height, archive_header_hash)
					{
						Ok(_) => {
							requested_root_hash.insert(peer.info.addr.clone(), now);
							remaining_root_peer_capacity =
								remaining_root_peer_capacity.saturating_sub(1);
						}
						Err(e) => {
							root_request_failures += 1;
							let msg = format!(
								concat!(
									"Failed to send PIBD root request to {} ",
									"for archive height {}, Error: {}"
								),
								peer.info.addr, archive_header.height, e
							);
							info!("{}", msg);
							sync_peers.report_no_response(&peer.info.addr, msg);
						}
					}
				}
			}
		}

		// Checking if need to init desegmenter
		if self.desegmenter.read_recursive().is_none() {
			sync_state.update(SyncStatus::TxHashsetPibd {
				recieved_segments: 0,
				total_segments: 100,
			});
			let mut first_response = now;
			let requested_root_hash = self.requested_root_hash.read_recursive();
			let responded_root_hash = self.responded_root_hash.read_recursive();

			if requested_root_hash.is_empty()
				&& responded_root_hash.is_empty()
				&& root_request_failures > 0
			{
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Capabilities::PIBD_HIST,
					format!(
						"Unable to send PIBD root requests. Hash peers: {}, failures: {}",
						peers.len(),
						root_request_failures
					),
				));
			}

			for (_, (_, time)) in &*responded_root_hash {
				if *time < first_response {
					first_response = *time;
				}
			}
			let root_selection_timeout =
				Duration::from_secs((pibd_params::PIBD_REQUESTS_TIMEOUT_SECS / 2) as u64);

			if !responded_root_hash.is_empty()
				&& ((responded_root_hash.len() >= requested_root_hash.len()
					&& responded_root_hash.len() > 1)
					|| first_response.elapsed() > root_selection_timeout)
			{
				let required_responses = cmp::max(MIN_PIBD_ROOT_RESPONSES, peers.len() / 2 + 1);
				let root_selection = Self::select_pibd_root(
					peers.iter().filter_map(|peer| {
						responded_root_hash
							.get(&peer.info.addr)
							.map(|(hash, _)| hash)
					}),
					required_responses,
				);
				let best_root_hash = match root_selection {
					PibdRootSelection::Selected(hash) => hash,
					PibdRootSelection::NeedMoreResponses { responses } => {
						if requested_root_hash.is_empty() {
							let msg = format!(
								concat!(
									"Need more PIBD root responses. ",
									"Hash peers: {}, responses: {}, required: {}"
								),
								peers.len(),
								responses,
								required_responses
							);
							return Ok(SyncResponse::new(
								SyncRequestResponses::WaitingForPeers,
								Capabilities::PIBD_HIST,
								msg,
							));
						}
						return Ok(SyncResponse::new(
							SyncRequestResponses::Syncing,
							Capabilities::PIBD_HIST,
							format!(
								"Waiting for PIBD root. Hash peers: {} Get respoinses {} from {}",
								peers.len(),
								responded_root_hash.len(),
								requested_root_hash.len()
							),
						));
					}
					PibdRootSelection::NoQuorum {
						responses,
						best_count,
					} => {
						if requested_root_hash.is_empty() {
							let msg = format!(
								concat!(
									"No quorum for PIBD root at archive height {}. ",
									"Hash peers: {}, responses: {}, ",
									"best root responses: {}, required: {}"
								),
								target_archive_height,
								peers.len(),
								responses,
								best_count,
								required_responses
							);
							warn!("{}", msg);
							// A split vote proves disagreement, but does not identify the
							// dishonest peer. Keep the existing commitments so a newly
							// connected peer can break the tie, and do not feed ambiguous
							// votes into peer error scoring.
							return Ok(SyncResponse::new(
								SyncRequestResponses::WaitingForPeers,
								Capabilities::PIBD_HIST,
								msg,
							));
						}
						return Ok(SyncResponse::new(
							SyncRequestResponses::Syncing,
							Capabilities::PIBD_HIST,
							format!(
								"Waiting for PIBD root. Hash peers: {} Get respoinses {} from {}",
								peers.len(),
								responded_root_hash.len(),
								requested_root_hash.len()
							),
						));
					}
				};

				info!("Creating desegmenter for root hash {}", best_root_hash);
				if let Err(e) = self.chain.reset_pibd_chain(mwc_chain::PibdResetMode::Body) {
					let msg = format!(
						"Failed to reset chain before start BIPD state sync. Error: {}",
						e
					);
					error!("{}", msg);
					return Err(e);
				}
				match self
					.chain
					.init_desegmenter(archive_header.height, best_root_hash.clone())
				{
					Ok(desegmenter) => {
						*self.desegmenter.write() = Some(Arc::new(desegmenter));
					}
					Err(e) => {
						error!("Failed to create PIBD desgmenter, {}", e);
						// let's try to reset everything...
						if let Err(e) = self.chain.reset_pibd_chain(mwc_chain::PibdResetMode::Body)
						{
							error!("reset_pibd_chain failed with error: {}", e);
						}
						return Err(e);
					}
				}

				*self.download.lock() = StateDownload::new();
			// continue with requests...
			} else {
				return Ok(SyncResponse::new(
					SyncRequestResponses::Syncing,
					Capabilities::PIBD_HIST,
					format!(
						"Waiting for PIBD root. Hash peers: {} Get respoinses {} from {}",
						peers.len(),
						responded_root_hash.len(),
						requested_root_hash.len()
					),
				));
			}
		}

		let session = self
			.live_desegmenter()
			.ok_or(mwc_chain::Error::Other("Desegmenter is not created".into()))?;
		let desegmenter = session.desegmenter.as_ref();
		self.apply_ready_tasks(desegmenter, sync_peers)?;

		if desegmenter.is_complete() {
			// Be very conservative once the PIBD state is complete: any failure
			// while finalizing or validating it is treated as critical. The node
			// cannot safely start from a failed validation result, so the current
			// PIBD session is discarded and a full resync is required.
			info!("PIBD state is done, starting check_update_leaf_set_state...");
			if let Err(e) = desegmenter.check_update_leaf_set_state() {
				error!(
					"Restarting because check_update_leaf_set_state failed with error {}",
					e
				);
				self.ban_this_session(&session.root_hash, sync_peers);
				return Ok(SyncResponse::new(
					SyncRequestResponses::Syncing,
					Capabilities::PIBD_HIST,
					format!(
						"Restarting because check_update_leaf_set_state failed with error {}",
						e
					),
				));
			}

			// we are pretty good, we can do validation now...
			info!("PIBD state is done, starting validate_complete_state...");
			match desegmenter.validate_complete_state(sync_state.clone(), stop_state) {
				Ok(_) => {
					info!("PIBD state download and validation completed");
					let next_height = archive_header
						.height
						.checked_add(1)
						.ok_or(mwc_chain::Error::InvalidBlockHeight)?;
					let response = if mwc_core::consensus::is_coinbase_binding_enabled(
						self.chain.get_context_id(),
						next_height,
					) {
						// Retain root endorsements for SyncManager while ordinary
						// block sync checks the imported state. These endorsements
						// belong only to this process/session.
						let _apply = self.apply_lock.lock();
						self.is_complete.store(true, Ordering::Release);
						// BodySync now owns block requests and their normal retries.
						*self.download.lock() = StateDownload::new();
						SyncResponse::new(
							SyncRequestResponses::StatePibdReady,
							Capabilities::PIBD_HIST,
							"PIBD imported; waiting to validate its successor block".into(),
						)
					} else {
						self.complete_pibd_sync();
						SyncResponse::new(
							SyncRequestResponses::StatePibdReady,
							Capabilities::UNKNOWN,
							"PIBD download and validaion is done with success!".into(),
						)
					};
					// Both successful paths must leave validation, even when no newer headers
					// are available yet and BodySync returns without updating the status.
					sync_state.update(SyncStatus::BodySync {
						archive_height: archive_header.height,
						current_height: archive_header.height,
						highest_height: best_height,
					});
					return Ok(response);
				}
				Err(e) => {
					error!(
						"Restarting because validate_complete_state failed with error {}",
						e
					);
					self.ban_this_session(&session.root_hash, sync_peers);
					// Leave validation so SyncManager can run the queued session reset.
					sync_state.update(SyncStatus::TxHashsetPibd {
						recieved_segments: 0,
						total_segments: 100,
					});
					return Ok(SyncResponse::new(
						SyncRequestResponses::Syncing,
						Capabilities::PIBD_HIST,
						format!(
							"Restarting because validate_complete_state failed with error {}",
							e
						),
					));
				}
			}
		}

		debug_assert!(!desegmenter.is_complete());

		let buffered = self
			.download
			.lock()
			.tasks
			.iter()
			.filter(|task| task.received.is_some())
			.count();
		sync_state.update(desegmenter.get_pibd_progress(buffered));

		// let's check what peers with root hash are exist
		let mut root_hash_peers: Vec<Arc<Peer>> = Vec::new();
		let mut other_hashes = 0;
		for p in peers {
			let addr = &p.info.addr;
			if let Some((hash, _)) = self.responded_root_hash.read_recursive().get(addr) {
				if hash == &session.root_hash {
					root_hash_peers.push(p.clone());
				} else {
					other_hashes += 1;
				}
			}
		}

		if root_hash_peers.is_empty() {
			if other_hashes > 0 {
				// No peers committed to the selected root remain available while
				// alternatives exist, so treat the selected root's supporters as bad.
				// This ban is intentionally conservative: rotating out those peers
				// lets peer management connect replacements, which may form a more
				// robust quorum for the next PIBD attempt.
				self.ban_this_session(&session.root_hash, sync_peers);
				return Ok(SyncResponse::new(
					SyncRequestResponses::Syncing,
					Capabilities::PIBD_HIST,
					"Banning this PIBD session. Seems like that was a fraud".into(),
				));
			} else {
				let pending = self
					.download
					.lock()
					.tasks
					.iter()
					.filter(|task| task.request.is_some())
					.count();
				return Ok(SyncResponse::new(
					if pending == 0 {
						SyncRequestResponses::WaitingForPeers
					} else {
						SyncRequestResponses::Syncing
					},
					Capabilities::PIBD_HIST,
					format!(
						"Waiting for snapshot suppliers; {} requests pending",
						pending
					),
				));
			}
		}

		self.send_requests(&root_hash_peers, &session, sync_peers)
	}

	// return true: PIBD import is complete, and we still retain the peers’ root endorsements for the first-block failure handling.
	// return false: Either import is not complete, or those endorsements have already been cleared.
	fn has_imported_state(&self) -> bool {
		self.is_complete.load(Ordering::Acquire)
			&& !self.responded_root_hash.read_recursive().is_empty()
	}

	/// Pin a completed import and its retained root endorsements while the sync
	/// coordinator handles the result of ordinary block processing.
	pub(super) fn imported_state(&self) -> Option<LiveDesegmenter<'_>> {
		let session = self.live_desegmenter()?;
		self.has_imported_state().then_some(session)
	}

	pub(super) fn ban_this_session(&self, root_hash: &Hash, sync_peers: &SyncPeers) {
		error!("Banning all peers joind for root hash {}", root_hash);
		// Banning all peers that was agree with that hash...
		{
			let responded_root_hash = self.responded_root_hash.read_recursive();
			for (peer, (hash, _)) in &*responded_root_hash {
				if *hash == *root_hash {
					sync_peers.ban_peer(peer, "bad root hash".into());
				}
			}
		}
		self.reset_desegmenter.store(true, Ordering::Relaxed);
	}

	fn clear_pibd_root_tracking(&self) {
		self.requested_root_hash.write().clear();
		self.responded_root_hash.write().clear();
	}

	pub(super) fn complete_pibd_sync(&self) {
		let _apply = self.apply_lock.lock();
		// Publish completion before clearing peer commitments. Segment responses
		// already in flight can then be recognized as terminal-session traffic and
		// ignored instead of being counted as invalid peer responses.
		self.is_complete.store(true, Ordering::Release);
		self.clear_pibd_root_tracking();
		*self.download.lock() = StateDownload::new();
	}

	pub fn reset_desegmenter_data(&self) {
		// Keep this write lock as the first operation: receive handlers use the
		// desegmenter read guard as the session barrier from validation through
		// segment application.
		let mut session = self.desegmenter.write();
		*session = None;
		self.clear_pibd_root_tracking();
		*self.target_archive_hash.write() = Hash::default();
		*self.download.lock() = StateDownload::new();
		self.is_complete.store(false, Ordering::Release);
		self.reset_desegmenter.store(false, Ordering::Relaxed);
	}

	#[cfg(all(test, feature = "test-support"))]
	pub(super) fn set_imported_state_for_test(
		&self,
		height: u64,
		root: Hash,
		votes: Vec<(PeerAddr, Hash)>,
	) -> Result<(), mwc_chain::Error> {
		self.reset_desegmenter_data();
		let archive = self.chain.get_header_by_height(height)?;
		*self.desegmenter.write() = Some(Arc::new(self.chain.init_desegmenter(height, root)?));
		self.target_archive_height.store(height, Ordering::Relaxed);
		*self.target_archive_hash.write() = archive.hash(self.chain.get_context_id())?;
		*self.responded_root_hash.write() = votes
			.into_iter()
			.map(|(peer, root)| (peer, (root, Instant::now())))
			.collect();
		self.is_complete.store(true, Ordering::Release);
		Ok(())
	}

	pub fn recieve_pibd_status(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
		output_bitmap_root: Hash,
	) {
		let mut requested_root_hash = self.requested_root_hash.write();

		// Responses for another archive header are stale for the current PIBD
		// root collection. Ignore them and let the pending request naturally
		// time out so retry logic can ask again for the current archive.
		if header_height != self.target_archive_height.load(Ordering::Relaxed)
			|| header_hash != *self.target_archive_hash.read_recursive()
		{
			return;
		}

		// If no current root-hash request is outstanding for this peer then
		// the response is unsolicited from this state machine's perspective.
		// This can happen when a delayed response arrives after an archive
		// height change, so ignore it.
		if requested_root_hash.remove(peer).is_none() {
			return;
		}

		// Keep this commitment for the complete PIBD session. It authorizes this
		// peer again after reconnect and preserves evidence for a session-wide ban.
		self.responded_root_hash
			.write()
			.insert(peer.clone(), (output_bitmap_root, Instant::now()));
	}

	pub fn recieve_another_archive_header(
		&self,
		peer: &PeerAddr,
		header_hash: &Hash,
		header_height: u64,
	) {
		debug!(
			"Ignoring HasAnotherArchiveHeader from {}. Header {} at {}",
			peer, header_hash, header_height
		);
	}

	// Return the selected desegmenter and root hash if validation was successful.
	// Distinguish stale session traffic from a peer mismatch so delayed responses
	// after a reset are not counted against an honest peer.
	fn validated_desegmenter(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
	) -> DesegmenterValidation<'_> {
		let guard = self.desegmenter.read_recursive();
		let desegmenter = match guard.as_ref().cloned() {
			Some(desegmenter) => desegmenter,
			None => return DesegmenterValidation::Stale,
		};
		if !desegmenter.is_current() {
			self.reset_desegmenter.store(true, Ordering::Relaxed);
			return DesegmenterValidation::Stale;
		}
		if *self.target_archive_hash.read_recursive() != *archive_header_hash {
			return DesegmenterValidation::Stale;
		}

		let hash_for_peer = self.responded_root_hash.read_recursive().get(peer).cloned();
		match hash_for_peer {
			Some((hash, _)) if *desegmenter.get_bitmap_root_hash() == hash => {
				DesegmenterValidation::Valid {
					_guard: guard,
					desegmenter,
				}
			}
			_ => DesegmenterValidation::PeerMismatch { _guard: guard },
		}
	}

	fn live_desegmenter(&self) -> Option<LiveDesegmenter<'_>> {
		let guard = self.desegmenter.read_recursive();
		let desegmenter = guard.as_ref().cloned()?;
		if !desegmenter.is_current() {
			self.reset_desegmenter.store(true, Ordering::Relaxed);
			return None;
		}
		let archive_hash = self.target_archive_hash.read_recursive().clone();
		if archive_hash == Hash::default() {
			return None;
		}
		let root_hash = desegmenter.get_bitmap_root_hash().clone();
		Some(LiveDesegmenter {
			_guard: guard,
			desegmenter,
			archive_hash,
			root_hash,
		})
	}

	// The caller must pin the session until application and queue updates finish.
	fn apply_ready_tasks(
		&self,
		desegmenter: &Desegmenter,
		scores: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		let _apply = self.apply_lock.lock();
		// Another writer may have invalidated the session while we waited. Do
		// not attribute that local failure to an already buffered response.
		if !desegmenter.is_current() {
			return Err(mwc_chain::Error::ChainRestartRequired);
		}
		let tasks = {
			let mut download = self.download.lock();
			let mut tasks = Vec::new();
			let mut blocked = Vec::new();
			let mut index = 0;
			while index < download.tasks.len() && tasks.len() < MAX_SEGMENTS_PER_BATCH {
				let task = &download.tasks[index];
				let kind = &task.id.segment_type;
				if task.received.is_none() {
					blocked.push(kind.clone());
				}
				if blocked.contains(kind) {
					index += 1;
					continue;
				}
				tasks.push((
					index,
					download.tasks.remove(index).expect("ready task exists"),
				));
			}
			tasks
		};
		let segments: Vec<_> = tasks
			.iter()
			.map(|(_, task)| {
				&task
					.received
					.as_ref()
					.expect("ready task has a response")
					.segment
			})
			.collect();
		if let Err((failed, error)) = desegmenter.apply_segments(&segments) {
			if let Some(offset) = failed {
				let task = &tasks[offset].1;
				let response = task.received.as_ref().expect("ready task has a response");
				let message = format!(
					"Failed to apply snapshot segment {:?} from {}: {}",
					task.id, response.peer, error
				);
				error!("{}", message);
				scores.report_error_response(&response.peer, message);
			} else {
				error!("Failed to apply snapshot batch: {}", error);
				// Unattributed errors include invalid authenticated bitmaps. Ban
				// the selected root's endorsers before reset so the same peers
				// cannot repeatedly restart sync with that bad root. For simplicity,
				// storage failures also trigger this conservative ban, even when
				// endorsers are honest. ChainRestartRequired only means the local
				// session was invalidated and must not trigger a ban.
				if !matches!(&error, mwc_chain::Error::ChainRestartRequired) {
					self.ban_this_session(desegmenter.get_bitmap_root_hash(), scores);
				}
			}
			// Reverse the removals to restore every task at its original position.
			// The application lock and pinned session keep these positions valid.
			let mut download = self.download.lock();
			for (index, task) in tasks.into_iter().rev() {
				download.tasks.insert(index, task);
			}
			if !desegmenter.is_current() {
				self.reset_desegmenter.store(true, Ordering::Relaxed);
			}
			return Err(error);
		}
		Ok(())
	}

	fn receive_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: StateSegment,
		_peers: &Arc<mwc_p2p::Peers>,
		scores: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		if self.is_complete.load(Ordering::Acquire) {
			return Ok(());
		}
		let received_at = Instant::now();
		let id = segment.identifier();
		let validation = self.validated_desegmenter(peer, archive_header_hash);
		let desegmenter = match &validation {
			DesegmenterValidation::Valid { desegmenter, .. } => desegmenter,
			DesegmenterValidation::PeerMismatch { .. } => {
				if !self.is_complete.load(Ordering::Acquire) {
					scores.report_error_response(peer, "Snapshot root commitment mismatch".into());
				}
				return Ok(());
			}
			DesegmenterValidation::Stale => return Ok(()),
		};
		{
			let download = self.download.lock();
			if !download
				.tasks
				.iter()
				.any(|task| task.id == id && task.received.is_none())
			{
				return Ok(()); // Already completed, duplicate, or outside this bounded job.
			}
		}
		// Hold the session read guard, but release the task lock during proof
		// authentication. Different peer threads can validate segments concurrently.
		let result = desegmenter.validate_segment(segment);
		let mut download = self.download.lock();
		if !desegmenter.is_current() || self.is_complete.load(Ordering::Acquire) {
			return Ok(());
		}
		let Some(task) = download.tasks.iter_mut().find(|task| task.id == id) else {
			return Ok(());
		};
		if task.received.is_some() {
			return Ok(());
		}
		match result {
			Ok(segment) => {
				let latency = task
					.request
					.take()
					.filter(|request| request.peer == *peer)
					.map(|request| {
						let latency = received_at.saturating_duration_since(request.sent_at);
						if let Some(supplier) = request.supplier.upgrade() {
							supplier.record_response_latency(latency);
						}
						latency
					});
				task.received = Some(ReceivedSegment {
					segment,
					peer: peer.clone(),
				});
				if let Some(latency) = latency {
					if let Ok(latency_ms) = i64::try_from(latency.as_millis()) {
						download.latency.add_latency(latency_ms);
					}
				}
				scores.report_ok_response(peer);
			}
			Err(error) => {
				if task
					.request
					.as_ref()
					.is_some_and(|request| request.peer == *peer)
				{
					task.request = None;
				}
				let message = format!("Invalid snapshot segment {:?} from {}: {}", id, peer, error);
				info!("{}", message);
				scores.report_error_response(peer, message);
			}
		}
		// The existing sync loop applies and refills on its next tick. Peer
		// readers can immediately receive the next response while storage runs.
		Ok(())
	}

	pub fn receive_bitmap_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<BitmapChunk>,
		peers: &Arc<mwc_p2p::Peers>,
		scores: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		self.receive_segment(
			peer,
			archive_header_hash,
			StateSegment::Bitmap(segment),
			peers,
			scores,
		)
	}

	pub fn receive_output_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<OutputIdentifier>,
		peers: &Arc<mwc_p2p::Peers>,
		scores: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		self.receive_segment(
			peer,
			archive_header_hash,
			StateSegment::Output(segment),
			peers,
			scores,
		)
	}

	pub fn receive_rangeproof_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<RangeProof>,
		peers: &Arc<mwc_p2p::Peers>,
		scores: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		self.receive_segment(
			peer,
			archive_header_hash,
			StateSegment::RangeProof(segment),
			peers,
			scores,
		)
	}

	pub fn receive_kernel_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<TxKernel>,
		peers: &Arc<mwc_p2p::Peers>,
		scores: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		self.receive_segment(
			peer,
			archive_header_hash,
			StateSegment::Kernel(segment),
			peers,
			scores,
		)
	}

	fn send_requests(
		&self,
		peers: &[Arc<Peer>],
		session: &LiveDesegmenter<'_>,
		scores: &SyncPeers,
	) -> Result<SyncResponse, mwc_chain::Error> {
		// Planning uses committed cursors plus queued tasks. It must not observe
		// the queue while a removed task is still being applied.
		let _apply = self.apply_lock.lock();
		let mut download = self.download.lock();
		if let Err(error) = download.fill_tasks(&session.desegmenter, &self.pibd_params) {
			// Keep the existing session recovery policy for planning failures.
			error!("Failed to plan snapshot segments: {}", error);
			self.ban_this_session(&session.root_hash, scores);
			return Err(error);
		}
		let per_peer = self.pibd_params.get_segments_request_per_peer();
		let mut counts = HashMap::<PeerAddr, usize>::new();
		for request in download
			.tasks
			.iter()
			.filter_map(|task| task.request.as_ref())
		{
			*counts.entry(request.peer.clone()).or_default() += 1;
		}
		// Use the same zero-based latency offset as checkpoint headers. Unknown
		// peers can start at the head until a response or timeout gives a sample.
		let latencies: Vec<_> = peers
			.iter()
			.filter(|peer| peer.is_connected())
			.map(|peer| {
				(
					peer,
					peer.response_latency()
						.map(|latency| latency.as_millis().max(1)),
				)
			})
			.collect();
		let best_latency = latencies
			.iter()
			.filter_map(|(_, latency)| *latency)
			.min()
			.unwrap_or(1);
		let last_index = download.tasks.len().saturating_sub(1);
		let candidates: Vec<_> = latencies
			.into_iter()
			.map(|(peer, latency)| {
				let first_index = usize::try_from(
					(latency.unwrap_or(best_latency) / best_latency).saturating_sub(1),
				)
				.unwrap_or(usize::MAX)
				.min(last_index);
				(peer, first_index)
			})
			.collect();
		let max_first_index = candidates
			.iter()
			.filter(|(peer, _)| counts.get(&peer.info.addr).copied().unwrap_or(0) < per_peer)
			.map(|(_, first_index)| *first_index)
			.max();
		// No available peer means there is no reason to scan the task queue.
		if let Some(max_first_index) = max_first_index {
			let mut rng = rand::rng();
			for (index, task) in download.tasks.iter_mut().enumerate() {
				if task.request.is_some() || task.received.is_some() {
					continue;
				}
				let Some(peer) = candidates
					.iter()
					.filter(|(peer, first_index)| {
						index >= *first_index
							&& peer.is_connected()
							&& counts.get(&peer.info.addr).copied().unwrap_or(0) < per_peer
					})
					.map(|(peer, _)| *peer)
					.choose(&mut rng)
				else {
					// Later tasks can admit slower peers only before this index.
					if index >= max_first_index {
						break;
					}
					continue;
				};
				let sent_at = Instant::now();
				let timeout = peer.request_timeout();
				let expires_at = sent_at.checked_add(timeout).ok_or_else(|| {
					mwc_chain::Error::Other("Snapshot request deadline overflow".into())
				})?;
				task.request = Some(StateTaskRequest {
					peer: peer.info.addr.clone(),
					supplier: Arc::downgrade(peer),
					sent_at,
					expires_at,
				});
				// Registration and sending share the task lock, so even an immediate
				// response cannot arrive before its request is visible.
				let result = match task.id.segment_type {
					SegmentType::Bitmap => {
						peer.send_bitmap_segment_request(session.archive_hash, task.id.identifier)
					}
					SegmentType::Output => {
						peer.send_output_segment_request(session.archive_hash, task.id.identifier)
					}
					SegmentType::RangeProof => peer
						.send_rangeproof_segment_request(session.archive_hash, task.id.identifier),
					SegmentType::Kernel => {
						peer.send_kernel_segment_request(session.archive_hash, task.id.identifier)
					}
				};
				match result {
					Ok(()) => *counts.entry(peer.info.addr.clone()).or_default() += 1,
					Err(error) => {
						task.request = None;
						let message = format!(
							"Failed to request snapshot segment {:?} from {}: {}",
							task.id, peer.info.addr, error
						);
						info!("{}", message);
						scores.report_no_response(&peer.info.addr, message);
					}
				}
			}
		}
		let pending = download
			.tasks
			.iter()
			.filter(|task| task.request.is_some())
			.count();
		Ok(SyncResponse::new(
			if pending == 0 && peers.is_empty() {
				SyncRequestResponses::WaitingForPeers
			} else {
				SyncRequestResponses::Syncing
			},
			Capabilities::PIBD_HIST,
			format!(
				"Snapshot segments: {} tasks, {} requests pending",
				download.tasks.len(),
				pending
			),
		))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};

	fn test_hash(value: u8) -> Hash {
		Hash::from_vec(&[value; Hash::LEN])
	}

	#[test]
	fn root_capacity_check_keeps_existing_commitment() {
		let peer = PeerAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_001));
		let root = test_hash(9);
		let requested = HashMap::new();
		let responses = HashMap::from([(peer.clone(), (root, Instant::now()))]);

		assert_eq!(
			StateSync::remaining_pibd_root_peer_capacity(&requested, &responses, 1),
			0
		);
		assert_eq!(responses.get(&peer).map(|(hash, _)| *hash), Some(root));
	}

	#[test]
	fn select_pibd_root_rejects_single_response() {
		let root = test_hash(1);
		let roots = vec![root];

		assert_eq!(
			StateSync::select_pibd_root(roots.iter(), MIN_PIBD_ROOT_RESPONSES,),
			PibdRootSelection::NeedMoreResponses { responses: 1 }
		);
	}

	#[test]
	fn select_pibd_root_requires_strict_majority() {
		let root_a = test_hash(1);
		let root_b = test_hash(2);
		let roots = vec![root_a, root_b];

		assert_eq!(
			StateSync::select_pibd_root(roots.iter(), MIN_PIBD_ROOT_RESPONSES,),
			PibdRootSelection::NoQuorum {
				responses: 2,
				best_count: 1
			}
		);
	}

	#[test]
	fn select_pibd_root_accepts_quorum_with_strict_majority() {
		let root_a = test_hash(1);
		let root_b = test_hash(2);
		let roots = vec![root_a, root_a, root_b];

		assert_eq!(
			StateSync::select_pibd_root(roots.iter(), MIN_PIBD_ROOT_RESPONSES,),
			PibdRootSelection::Selected(root_a)
		);
	}

	#[test]
	fn select_pibd_root_rejects_even_split_without_strict_majority() {
		let root_a = test_hash(1);
		let root_b = test_hash(2);
		let roots = vec![root_a, root_a, root_b, root_b];

		assert_eq!(
			StateSync::select_pibd_root(roots.iter(), MIN_PIBD_ROOT_RESPONSES + 1,),
			PibdRootSelection::NoQuorum {
				responses: 4,
				best_count: 2
			}
		);
	}

	#[test]
	fn select_pibd_root_rejects_partial_majority_of_received_responses() {
		let root = test_hash(1);
		let roots = vec![root, root];

		assert_eq!(
			StateSync::select_pibd_root(roots.iter(), MIN_PIBD_ROOT_RESPONSES + 1,),
			PibdRootSelection::NeedMoreResponses { responses: 2 }
		);
	}
}

#[cfg(all(test, feature = "test-support"))]
mod task_tests {
	use super::*;
	use mwc_chain::types::NoopAdapter;
	use mwc_core::core::SegmentIdentifier;
	use mwc_core::ser::ProtocolVersion;
	use mwc_core::{genesis, global, pow};
	use mwc_crates::crossbeam::channel::Receiver;
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_crates::tempfile::TempDir;
	use mwc_p2p::msg::Msg;
	use mwc_p2p::types::{Direction, PeerLiveInfo};
	use mwc_p2p::{DummyAdapter, P2PConfig, PeerInfo, Peers};
	use std::collections::HashSet;
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};

	struct Fixture {
		sync: StateSync,
		source: Arc<Chain>,
		peers: Arc<Peers>,
		scores: SyncPeers,
		_source_dir: TempDir,
		_chain_dir: TempDir,
		_peer_dir: TempDir,
	}

	impl Fixture {
		fn poll(&self) {
			let session = self.sync.live_desegmenter().unwrap();
			self.sync
				.apply_ready_tasks(&session.desegmenter, &self.scores)
				.unwrap();
			self.sync
				.send_requests(
					&self.sync.eligible_peers(&self.peers),
					&session,
					&self.scores,
				)
				.unwrap();
		}

		fn new() -> Self {
			// Floonet genesis contains one output, rangeproof and kernel. It
			// provides real authenticated segments without mining a test chain.
			global::set_local_chain_type(global::ChainTypes::Floonet);
			global::set_local_nrd_enabled(false);
			let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			let genesis = genesis::genesis_floo(&secp, 0);
			let init = |dir: &TempDir| {
				Arc::new(
					Chain::init(
						&secp,
						0,
						dir.path().to_str().unwrap().into(),
						Arc::new(NoopAdapter {}),
						genesis.clone(),
						pow::verify_size,
						false,
						HashSet::new(),
						None,
						None,
						false,
					)
					.unwrap(),
				)
			};
			let source_dir = TempDir::new().unwrap();
			let chain_dir = TempDir::new().unwrap();
			let source = init(&source_dir);
			let chain = init(&chain_dir);
			let root = source.segmenter().unwrap().bitmap_root().unwrap();
			chain
				.reset_pibd_chain(mwc_chain::PibdResetMode::Body)
				.unwrap();
			let sync = StateSync::new(chain);
			*sync.target_archive_hash.write() = genesis.hash(0).unwrap();
			*sync.desegmenter.write() =
				Some(Arc::new(sync.chain.init_desegmenter(0, root).unwrap()));
			let peer_dir = TempDir::new().unwrap();
			let peers = Arc::new(Peers::new(
				mwc_p2p::store::PeerStore::new(0, peer_dir.path().to_str().unwrap()).unwrap(),
				Arc::new(DummyAdapter {}),
				&P2PConfig::default(),
			));
			Self {
				sync,
				source,
				peers,
				scores: SyncPeers::new(),
				_source_dir: source_dir,
				_chain_dir: chain_dir,
				_peer_dir: peer_dir,
			}
		}

		fn peer(&self, id: u8) -> (Arc<Peer>, Receiver<Msg>) {
			self.peer_with_direction(id, Direction::Outbound)
		}

		fn peer_with_direction(&self, id: u8, direction: Direction) -> (Arc<Peer>, Receiver<Msg>) {
			let addr = PeerAddr::Ip(SocketAddr::new(
				IpAddr::V4(Ipv4Addr::new(10, 1, 0, id)),
				3414,
			));
			let info = PeerInfo {
				capabilities: Capabilities::PIBD_HIST,
				user_agent: "state-task-test".into(),
				version: ProtocolVersion::local(),
				addr: addr.clone(),
				direction,
				live_info: Arc::new(RwLock::new(PeerLiveInfo::new(pow::Difficulty::min()))),
				tx_base_fee: 0,
			};
			info.update(1, pow::Difficulty::min());
			let (peer, messages) = Peer::connected_for_test(info, 0, Arc::new(DummyAdapter {}));
			let peer = Arc::new(peer);
			self.peers.add_connected(peer.clone()).unwrap();
			let root = self.source.segmenter().unwrap().bitmap_root().unwrap();
			self.sync
				.responded_root_hash
				.write()
				.insert(addr, (root, Instant::now()));
			(peer, messages)
		}
	}

	#[test]
	fn snapshot_suppliers_require_known_height_and_difficulty() {
		let f = Fixture::new();
		let (peer, _messages) = f.peer(1);
		for (height, difficulty) in [(0, pow::Difficulty::min()), (1, pow::Difficulty::zero())] {
			{
				let mut info = peer.info.live_info.write();
				info.height = height;
				info.total_difficulty = difficulty;
			}
			assert!(f.sync.eligible_peers(&f.peers).is_empty());
		}
		peer.info.update(1, pow::Difficulty::min());
		assert_eq!(f.sync.eligible_peers(&f.peers).len(), 1);
	}

	#[test]
	fn reconnect_cancels_snapshot_requests_but_keeps_root_commitments() {
		let f = Fixture::new();
		let (peer, messages) = f.peer(1);
		let session = f.sync.live_desegmenter().unwrap();
		f.sync
			.send_requests(&[peer.clone()], &session, &f.scores)
			.unwrap();
		assert_eq!(messages.try_iter().count(), 1);
		f.sync
			.requested_root_hash
			.write()
			.insert(peer.info.addr.clone(), Instant::now());
		let commitment = f.sync.responded_root_hash.read_recursive()[&peer.info.addr];
		f.sync.clear_peer_requests(&peer.info.addr);
		assert!(f.sync.requested_root_hash.read_recursive().is_empty());
		assert!(f
			.sync
			.download
			.lock()
			.tasks
			.iter()
			.all(|task| task.request.is_none()));
		assert_eq!(
			f.sync.responded_root_hash.read_recursive()[&peer.info.addr],
			commitment
		);
		f.sync
			.send_requests(&[peer.clone()], &session, &f.scores)
			.unwrap();
		assert_eq!(messages.try_iter().count(), 1);
		for _ in 0..4 {
			f.scores.elapse_no_response_merge_interval(&peer.info.addr);
			f.scores
				.report_no_response(&peer.info.addr, "before disconnect".into());
		}
		f.scores.elapse_no_response_merge_interval(&peer.info.addr);
		peer.stop();
		f.sync
			.download
			.lock()
			.expire_requests(Instant::now() + Duration::from_secs(60), &f.scores);
		assert!(f
			.sync
			.download
			.lock()
			.tasks
			.iter()
			.all(|task| task.request.is_none()));
		f.scores.apply_peers_status(&f.peers);
		assert!(!f.peers.is_banned(&peer.info.addr).unwrap());
		assert_eq!(
			f.peers.get_peer(&peer.info.addr).unwrap().flags,
			mwc_p2p::State::Healthy
		);
	}

	#[test]
	fn eligible_peers_prefers_outbound_over_both_transports() {
		use Direction::{Inbound, InboundTor, Outbound, OutboundTor};

		let cases: &[(&str, &[Direction], &[usize])] = &[
			(
				"Tor outbound peers exclude an inbound majority",
				&[OutboundTor, OutboundTor, Inbound, InboundTor, InboundTor],
				&[0, 1],
			),
			(
				"ordinary outbound peers retain Tor outbound peers",
				&[Outbound, OutboundTor, OutboundTor, Inbound, InboundTor],
				&[0, 1, 2],
			),
			(
				"inbound peers remain a fallback when no outbound peers qualify",
				&[Inbound, InboundTor],
				&[0, 1],
			),
		];
		for &(case, directions, expected_indices) in cases {
			let f = Fixture::new();
			let peers: Vec<_> = directions
				.iter()
				.enumerate()
				.map(|(index, direction)| {
					f.peer_with_direction(u8::try_from(index + 1).unwrap(), *direction)
				})
				.collect();
			let expected: HashSet<_> = expected_indices
				.iter()
				.map(|&index| peers[index].0.info.addr.clone())
				.collect();
			let selected: HashSet<_> = f
				.sync
				.eligible_peers(&f.peers)
				.iter()
				.map(|peer| peer.info.addr.clone())
				.collect();

			assert_eq!(selected, expected, "{}", case);
		}
	}

	#[test]
	fn segments_apply_independently_and_duplicate_responses_are_ignored() {
		let f = Fixture::new();
		let (first, first_messages) = f.peer(1);
		let (second, second_messages) = f.peer(2);
		let session = f.sync.live_desegmenter().unwrap();
		let suppliers = [first.clone(), second.clone()];
		f.sync
			.send_requests(&suppliers, &session, &f.scores)
			.unwrap();
		f.sync
			.send_requests(&suppliers, &session, &f.scores)
			.unwrap();
		assert_eq!(
			first_messages.try_iter().count() + second_messages.try_iter().count(),
			1
		);
		let (bitmap_id, requested_peer) = {
			let download = f.sync.download.lock();
			assert_eq!(download.tasks.len(), 1);
			let task = &download.tasks[0];
			(
				task.id.identifier,
				task.request.as_ref().unwrap().peer.clone(),
			)
		};
		let supplier = if first.info.addr == requested_peer {
			&second
		} else {
			&first
		};
		let segmenter = f.source.segmenter().unwrap();
		let bitmap = segmenter.bitmap_segment(bitmap_id).unwrap();

		// Another committed peer can fulfill the task. Responses only buffer;
		// the next tick applies the bitmap and requests the other three streams.
		f.sync
			.receive_bitmap_segment(
				&supplier.info.addr,
				&session.archive_hash,
				bitmap.clone(),
				&f.peers,
				&f.scores,
			)
			.unwrap();
		f.sync
			.receive_bitmap_segment(
				&supplier.info.addr,
				&session.archive_hash,
				bitmap,
				&f.peers,
				&f.scores,
			)
			.unwrap();
		assert_eq!(
			first_messages.try_iter().count() + second_messages.try_iter().count(),
			0
		);
		assert!(f.sync.download.lock().tasks[0].received.is_some());
		f.poll();
		assert_eq!(
			first_messages.try_iter().count() + second_messages.try_iter().count(),
			3
		);
		let ids: Vec<_> = f
			.sync
			.download
			.lock()
			.tasks
			.iter()
			.map(|task| task.id.clone())
			.collect();
		assert_eq!(ids.len(), 3);
		let kernel_id = ids
			.iter()
			.find(|id| id.segment_type == SegmentType::Kernel)
			.unwrap()
			.identifier;
		let kernel = segmenter.kernel_segment(kernel_id).unwrap();

		// Output is still pending at the front. The next tick must still apply
		// a lone kernel, without waiting for a minimum batch size.
		f.sync
			.receive_kernel_segment(
				&supplier.info.addr,
				&session.archive_hash,
				kernel.clone(),
				&f.peers,
				&f.scores,
			)
			.unwrap();
		f.poll();
		assert!(f
			.sync
			.download
			.lock()
			.tasks
			.iter()
			.all(|task| task.id.segment_type != SegmentType::Kernel));
		f.sync
			.receive_kernel_segment(
				&supplier.info.addr,
				&session.archive_hash,
				kernel,
				&f.peers,
				&f.scores,
			)
			.unwrap();
		assert!(!session.desegmenter.is_complete());
		let proof_id = ids
			.iter()
			.find(|id| id.segment_type == SegmentType::RangeProof)
			.unwrap()
			.identifier;
		f.sync
			.receive_rangeproof_segment(
				&supplier.info.addr,
				&session.archive_hash,
				segmenter.rangeproof_segment(proof_id).unwrap(),
				&f.peers,
				&f.scores,
			)
			.unwrap();
		let output_id = ids
			.iter()
			.find(|id| id.segment_type == SegmentType::Output)
			.unwrap()
			.identifier;
		f.sync
			.receive_output_segment(
				&supplier.info.addr,
				&session.archive_hash,
				segmenter.output_segment(output_id).unwrap(),
				&f.peers,
				&f.scores,
			)
			.unwrap();

		// Both responses are buffered until one tick applies the batch.
		assert_eq!(f.sync.download.lock().tasks.len(), 2);
		assert!(!session.desegmenter.is_complete());
		f.poll();
		// Every authenticated task has applied, and no more requests are needed.
		assert!(session.desegmenter.is_complete());
		assert!(f.sync.download.lock().tasks.is_empty());
		assert_eq!(
			first_messages.try_iter().count() + second_messages.try_iter().count(),
			0
		);
	}

	#[test]
	fn responses_validate_while_storage_is_blocked_and_reset_waits_for_application() {
		let f = Fixture::new();
		let (first, first_messages) = f.peer(1);
		let (second, second_messages) = f.peer(2);
		let (third, third_messages) = f.peer(3);
		let session = f.sync.live_desegmenter().unwrap();
		let archive_hash = session.archive_hash;
		let desegmenter = Arc::clone(&session.desegmenter);
		f.sync
			.send_requests(&[first.clone()], &session, &f.scores)
			.unwrap();
		let bitmap_id = f.sync.download.lock().tasks[0].id.identifier;
		drop(session);
		let segmenter = f.source.segmenter().unwrap();
		f.sync
			.receive_bitmap_segment(
				&first.info.addr,
				&archive_hash,
				segmenter.bitmap_segment(bitmap_id).unwrap(),
				&f.peers,
				&f.scores,
			)
			.unwrap();
		f.poll();
		assert_eq!(
			first_messages.try_iter().count()
				+ second_messages.try_iter().count()
				+ third_messages.try_iter().count(),
			4
		);
		let ids: Vec<_> = f
			.sync
			.download
			.lock()
			.tasks
			.iter()
			.map(|task| task.id.identifier)
			.collect();
		let output = StateSegment::Output(segmenter.output_segment(ids[0]).unwrap());
		let proof = StateSegment::RangeProof(segmenter.rangeproof_segment(ids[1]).unwrap());
		let kernel = StateSegment::Kernel(segmenter.kernel_segment(ids[2]).unwrap());
		let receive = |peer: &PeerAddr, segment: StateSegment| {
			global::set_local_chain_type(global::ChainTypes::Floonet);
			global::set_local_nrd_enabled(false);
			f.sync
				.receive_segment(peer, &archive_hash, segment, &f.peers, &f.scores)
		};
		let wait_for = |condition: &dyn Fn() -> bool| {
			let deadline = Instant::now() + Duration::from_secs(5);
			while !condition() {
				assert!(Instant::now() < deadline, "Segment processing stalled");
				std::thread::sleep(Duration::from_millis(1));
			}
		};

		std::thread::scope(|scope| {
			// Hold storage read locks so application pauses before it can write.
			// The closure releases them even if a concurrency assertion fails.
			let (writer, planner, reset) =
				f.sync
					.chain
					.with_output_read_snapshot(|_| {
						receive(&first.info.addr, output.clone()).unwrap();
						let writer = scope.spawn(|| {
							global::set_local_chain_type(global::ChainTypes::Floonet);
							global::set_local_nrd_enabled(false);
							let session = f.sync.live_desegmenter().unwrap();
							f.sync.apply_ready_tasks(&session.desegmenter, &f.scores)?;
							// Simulate the next tick under the same pinned session, so
							// the pending reset cannot discard the later responses.
							f.sync.apply_ready_tasks(&session.desegmenter, &f.scores)
						});
						wait_for(&|| {
							f.sync.download.try_lock().is_some_and(|download| {
								download.tasks.len() == 2
									&& download
										.tasks
										.iter()
										.all(|task| task.id.segment_type != SegmentType::Output)
							})
						});

						// A planner waiting for the writer must not hold the queue lock.
						let (planner_started, planner_ready) = std::sync::mpsc::channel();
						let sync = &f.sync;
						let scores = &f.scores;
						let supplier = &first;
						let planner = scope.spawn(move || {
							let session = sync.live_desegmenter().unwrap();
							planner_started.send(()).unwrap();
							sync.send_requests(&[supplier.clone()], &session, scores)
						});
						planner_ready.recv_timeout(Duration::from_secs(5)).unwrap();
						let (received, finished) = std::sync::mpsc::channel();
						for (peer, segment) in [
							(&second.info.addr, proof.clone()),
							(&third.info.addr, kernel.clone()),
						] {
							let received = received.clone();
							scope.spawn(move || received.send(receive(peer, segment)).unwrap());
						}
						// Both peer readers must return while the writer is still blocked.
						for _ in 0..2 {
							finished
								.recv_timeout(Duration::from_secs(5))
								.unwrap()
								.unwrap();
						}
						wait_for(&|| {
							f.sync.download.try_lock().is_some_and(|download| {
								download.tasks.len() == 2
									&& download.tasks.iter().all(|task| {
										task.received.is_some() && task.request.is_none()
									})
							})
						});

						// Duplicates of both the taken task and a buffered task must return
						// without waiting for storage or applying either segment twice.
						let (duplicate_done, duplicate_result) = std::sync::mpsc::channel();
						let duplicates = [output.clone(), kernel.clone()];
						let duplicate_peer = &first.info.addr;
						scope.spawn(move || {
							for duplicate in duplicates {
								duplicate_done
									.send(receive(duplicate_peer, duplicate))
									.unwrap();
							}
						});
						for _ in 0..2 {
							duplicate_result
								.recv_timeout(Duration::from_secs(5))
								.unwrap()
								.unwrap();
						}

						// Reset still waits for the writer to finish the pinned session.
						let (reset_done, reset_result) = std::sync::mpsc::channel();
						let sync = &f.sync;
						let reset = scope.spawn(move || {
							sync.reset_desegmenter_data();
							reset_done.send(()).unwrap();
						});
						assert!(matches!(
							reset_result.recv_timeout(Duration::from_millis(50)),
							Err(std::sync::mpsc::RecvTimeoutError::Timeout)
						));
						Ok::<_, mwc_chain::Error>((writer, planner, (reset, reset_result)))
					})
					.unwrap();
			writer.join().unwrap().unwrap();
			planner.join().unwrap().unwrap();
			reset.1.recv_timeout(Duration::from_secs(5)).unwrap();
			reset.0.join().unwrap();
		});
		assert!(desegmenter.is_complete());
		assert!(f.sync.desegmenter.read_recursive().is_none());
		assert!(f.sync.download.lock().tasks.is_empty());
		assert_eq!(
			first_messages.try_iter().count()
				+ second_messages.try_iter().count()
				+ third_messages.try_iter().count(),
			0
		);
		f.scores.apply_peers_status(&f.peers);
		assert!(f.scores.get_banned_peers().is_empty());
	}

	#[test]
	fn failed_batch_restores_all_tasks_without_advancing_any_stream() {
		let f = Fixture::new();
		let (peer, _messages) = f.peer(1);
		let session = f.sync.live_desegmenter().unwrap();
		f.sync
			.send_requests(&[peer.clone()], &session, &f.scores)
			.unwrap();
		let bitmap_id = f.sync.download.lock().tasks[0].id.identifier;
		let segmenter = f.source.segmenter().unwrap();
		f.sync
			.receive_bitmap_segment(
				&peer.info.addr,
				&session.archive_hash,
				segmenter.bitmap_segment(bitmap_id).unwrap(),
				&f.peers,
				&f.scores,
			)
			.unwrap();
		f.poll();
		let ids: Vec<_> = f
			.sync
			.download
			.lock()
			.tasks
			.iter()
			.map(|task| task.id.clone())
			.collect();
		// The batch takes output and kernel, leaving a pending proof between them.
		f.sync
			.receive_output_segment(
				&peer.info.addr,
				&session.archive_hash,
				segmenter.output_segment(ids[0].identifier).unwrap(),
				&f.peers,
				&f.scores,
			)
			.unwrap();
		let kernel_id = ids[2].identifier;
		// Authenticate the same kernel with a different segment height. Its proof
		// is valid, but application rejects it because it is outside the layout.
		let wrong_id = SegmentIdentifier::new(kernel_id.height + 1, kernel_id.idx);
		let segment = session
			.desegmenter
			.validate_segment(StateSegment::Kernel(
				segmenter.kernel_segment(wrong_id).unwrap(),
			))
			.unwrap();
		{
			let mut download = f.sync.download.lock();
			let task = &mut download.tasks[2];
			task.id.identifier = wrong_id;
			task.request = None;
			task.received = Some(ReceivedSegment {
				segment,
				peer: peer.info.addr.clone(),
			});
		}
		for _ in 0..2 {
			assert!(matches!(
				f.sync.apply_ready_tasks(&session.desegmenter, &f.scores),
				Err(mwc_chain::Error::InvalidSegmentId)
			));
			let download = f.sync.download.lock();
			assert_eq!(download.tasks.len(), 3);
			for (index, (task, id)) in download.tasks.iter().zip(&ids).take(2).enumerate() {
				assert_eq!(&task.id, id);
				assert_eq!(task.request.is_some(), index == 1);
				assert_eq!(task.received.is_some(), index == 0);
			}
			let restored = &download.tasks[2];
			assert_eq!(restored.id.identifier, wrong_id);
			assert!(restored.request.is_none());
			assert_eq!(restored.received.as_ref().unwrap().peer, peer.info.addr);
		}

		// Correct the later ID and retry both segments. This would fail if the
		// first segment's cursor advanced before the rejected batch completed.
		let segment = session
			.desegmenter
			.validate_segment(StateSegment::Kernel(
				segmenter.kernel_segment(kernel_id).unwrap(),
			))
			.unwrap();
		{
			let mut download = f.sync.download.lock();
			let task = &mut download.tasks[2];
			task.id = ids[2].clone();
			task.received.as_mut().unwrap().segment = segment;
		}
		f.sync
			.apply_ready_tasks(&session.desegmenter, &f.scores)
			.unwrap();
		let download = f.sync.download.lock();
		assert_eq!(
			download
				.tasks
				.iter()
				.map(|task| task.id.clone())
				.collect::<Vec<_>>(),
			ids[1..2]
		);
	}

	#[test]
	fn batch_rejects_duplicate_bitmap_before_advancing_its_cursor() {
		let f = Fixture::new();
		let session = f.sync.live_desegmenter().unwrap();
		let before = session
			.desegmenter
			.next_segments(&SegmentType::Bitmap, 0, 10)
			.unwrap();
		assert_eq!(before.len(), 1);
		let bitmap = f
			.source
			.segmenter()
			.unwrap()
			.bitmap_segment(before[0].identifier)
			.unwrap();
		let validated = session
			.desegmenter
			.validate_segment(StateSegment::Bitmap(bitmap))
			.unwrap();
		assert!(matches!(
			session
				.desegmenter
				.apply_segments(&[&validated, &validated]),
			Err((Some(1), mwc_chain::Error::InvalidSegmentId))
		));
		assert_eq!(
			session
				.desegmenter
				.next_segments(&SegmentType::Bitmap, 0, 10)
				.unwrap(),
			before
		);
		session.desegmenter.apply_segments(&[&validated]).unwrap();
		assert!(session
			.desegmenter
			.next_segments(&SegmentType::Bitmap, 0, 10)
			.unwrap()
			.is_empty());
		assert_eq!(
			session
				.desegmenter
				.next_segments(&SegmentType::Output, 0, 10)
				.unwrap()
				.len(),
			1
		);
	}

	#[test]
	fn batch_marker_failure_restores_tasks_and_bans_session_endorsers() {
		let f = Fixture::new();
		let (peer, _messages) = f.peer(1);
		let (endorser, _endorser_messages) = f.peer(2);
		let session = f.sync.live_desegmenter().unwrap();
		f.sync
			.send_requests(&[peer.clone()], &session, &f.scores)
			.unwrap();
		let segmenter = f.source.segmenter().unwrap();
		let bitmap_id = f.sync.download.lock().tasks[0].id.identifier;
		f.sync
			.receive_bitmap_segment(
				&peer.info.addr,
				&session.archive_hash,
				segmenter.bitmap_segment(bitmap_id).unwrap(),
				&f.peers,
				&f.scores,
			)
			.unwrap();
		f.poll();
		let ids: Vec<_> = f
			.sync
			.download
			.lock()
			.tasks
			.iter()
			.map(|task| task.id.clone())
			.collect();
		for id in &ids {
			let segment = match id.segment_type {
				SegmentType::Output => {
					StateSegment::Output(segmenter.output_segment(id.identifier).unwrap())
				}
				SegmentType::RangeProof => {
					StateSegment::RangeProof(segmenter.rangeproof_segment(id.identifier).unwrap())
				}
				SegmentType::Kernel => {
					StateSegment::Kernel(segmenter.kernel_segment(id.identifier).unwrap())
				}
				_ => unreachable!(),
			};
			f.sync
				.receive_segment(
					&peer.info.addr,
					&session.archive_hash,
					segment,
					&f.peers,
					&f.scores,
				)
				.unwrap();
		}
		// An existing recovery marker must prevent committing another batch.
		f.sync
			.chain
			.get_store_for_tests()
			.set_pending_chain_operation(&mwc_chain::store::PendingChainOperation::PibdReset)
			.unwrap();
		// The conservative session policy also bans root endorsers on local
		// commit failures, even without any previous supplier errors.
		let result = f.sync.apply_ready_tasks(&session.desegmenter, &f.scores);
		assert!(
			matches!(&result, Err(mwc_chain::Error::StoreErr(..))),
			"unexpected apply result: {:?}",
			result
		);
		let download = f.sync.download.lock();
		assert_eq!(
			download
				.tasks
				.iter()
				.map(|task| task.id.clone())
				.collect::<Vec<_>>(),
			ids
		);
		assert!(download.tasks.iter().all(|task| task.received.is_some()));
		drop(download);
		assert!(!session.desegmenter.is_current());
		assert!(f.sync.reset_desegmenter.load(Ordering::Relaxed));
		assert!(matches!(
			f.sync
				.chain
				.get_store_for_tests()
				.pending_chain_operation()
				.unwrap(),
			Some(mwc_chain::store::PendingChainOperation::PibdReset)
		));
		assert!(matches!(
			f.sync.apply_ready_tasks(&session.desegmenter, &f.scores),
			Err(mwc_chain::Error::ChainRestartRequired)
		));
		f.scores.apply_peers_status(&f.peers);
		assert_eq!(
			f.scores.get_banned_peers(),
			HashSet::from([peer.info.addr.clone(), endorser.info.addr.clone()])
		);
		assert!(!peer.is_connected());
		assert!(!endorser.is_connected());
	}

	#[test]
	fn invalid_authenticated_bitmap_bans_only_its_root_endorsers() {
		let f = Fixture::new();
		let (supplier, _supplier_messages) = f.peer(1);
		let (endorser, _endorser_messages) = f.peer(2);
		let (other_root_peer, _other_messages) = f.peer(3);
		// The fixture has one output. Bit 1 is its permitted synthetic sibling;
		// bit 2 is impossible, even with a valid proof against the endorsed root.
		let mut chunk = BitmapChunk::new();
		chunk.set(0, true).unwrap();
		chunk.set(2, true).unwrap();
		let mut accumulator = mwc_chain::txhashset::BitmapAccumulator::new(0);
		accumulator.append_chunk(chunk.clone()).unwrap();
		let root = accumulator.root().unwrap();
		*f.sync.desegmenter.write() =
			Some(Arc::new(f.sync.chain.init_desegmenter(0, root).unwrap()));
		for peer in [&supplier, &endorser] {
			f.sync
				.responded_root_hash
				.write()
				.insert(peer.info.addr.clone(), (root, Instant::now()));
		}
		let session = f.sync.live_desegmenter().unwrap();
		f.sync
			.send_requests(&[supplier.clone(), endorser.clone()], &session, &f.scores)
			.unwrap();
		let before = session.desegmenter.get_pibd_progress(0);
		let id = f.sync.download.lock().tasks[0].id.identifier;
		let original = f.source.segmenter().unwrap().bitmap_segment(id).unwrap();
		let segment = Segment::from_parts(
			id,
			vec![],
			vec![],
			vec![0],
			vec![chunk],
			original.proof().clone(),
		)
		.unwrap();
		f.sync
			.receive_bitmap_segment(
				&supplier.info.addr,
				&session.archive_hash,
				segment,
				&f.peers,
				&f.scores,
			)
			.unwrap();
		assert!(f.sync.download.lock().tasks[0].received.is_some());
		assert!(matches!(
			f.sync.apply_ready_tasks(&session.desegmenter, &f.scores),
			Err(mwc_chain::Error::InvalidSegment(_))
		));
		assert!(!session.desegmenter.is_current());
		assert_eq!(session.desegmenter.get_pibd_progress(0), before);
		assert!(f.sync.reset_desegmenter.load(Ordering::Relaxed));
		assert!(f.sync.download.lock().tasks[0].received.is_some());
		drop(session);
		// Clearing the failed session must preserve the independently queued bans.
		f.sync.reset_desegmenter_data();
		f.scores.apply_peers_status(&f.peers);
		assert_eq!(
			f.scores.get_banned_peers(),
			HashSet::from([supplier.info.addr.clone(), endorser.info.addr.clone()])
		);
		assert!(!supplier.is_connected());
		assert!(!endorser.is_connected());
		assert!(other_root_peer.is_connected());
	}

	#[test]
	fn invalidated_session_keeps_buffered_response_without_scoring_supplier() {
		let f = Fixture::new();
		let (peer, _messages) = f.peer(1);
		let session = f.sync.live_desegmenter().unwrap();
		f.sync
			.send_requests(&[peer.clone()], &session, &f.scores)
			.unwrap();
		let id = f.sync.download.lock().tasks[0].id.identifier;
		let bitmap = f.source.segmenter().unwrap().bitmap_segment(id).unwrap();
		let segment = session
			.desegmenter
			.validate_segment(StateSegment::Bitmap(bitmap))
			.unwrap();
		{
			let mut download = f.sync.download.lock();
			download.tasks[0].request = None;
			download.tasks[0].received = Some(ReceivedSegment {
				segment,
				peer: peer.info.addr.clone(),
			});
		}
		f.sync
			.chain
			.reset_pibd_chain(mwc_chain::PibdResetMode::Body)
			.unwrap();
		for _ in 0..2 {
			assert!(matches!(
				f.sync.apply_ready_tasks(&session.desegmenter, &f.scores),
				Err(mwc_chain::Error::ChainRestartRequired)
			));
		}
		let download = f.sync.download.lock();
		assert_eq!(download.tasks.len(), 1);
		assert!(download.tasks[0].received.is_some());
		f.scores.apply_peers_status(&f.peers);
		assert!(f.scores.get_banned_peers().is_empty());
		assert!(peer.is_connected());
	}

	#[test]
	fn scheduler_reserves_front_tasks_for_fast_peers_and_scans_to_slower_peers() {
		let f = Fixture::new();
		let (fast, fast_messages) = f.peer(1);
		let (slow, slow_messages) = f.peer(2);
		let (disconnected, disconnected_messages) = f.peer(3);
		let per_peer = f.sync.pibd_params.get_segments_request_per_peer();
		let slow_index = per_peer + 2;
		fast.record_response_latency(Duration::from_millis(100));
		// Include a fractional ratio to exercise rounding down.
		slow.record_response_latency(Duration::from_millis((slow_index as u64 + 1) * 100 + 50));
		disconnected.record_response_latency(Duration::from_millis(1));
		disconnected.stop();
		let session = f.sync.live_desegmenter().unwrap();
		let task_limit = f.sync.pibd_params.get_segments_requests_limit(None);
		assert!(task_limit > slow_index + per_peer);
		// Preload an interleaved scheduling window; these tests only send requests.
		f.sync.download.lock().tasks = (0..task_limit)
			.map(|index| StateTask {
				id: SegmentTypeIdentifier::new(
					SEGMENT_TYPES[index % SEGMENT_TYPES.len()].clone(),
					SegmentIdentifier::new(0, (index / SEGMENT_TYPES.len()) as u64),
				),
				request: None,
				received: None,
			})
			.collect();
		let response = f.sync.send_requests(&[], &session, &f.scores).unwrap();
		assert_eq!(response.response, SyncRequestResponses::WaitingForPeers);
		assert!(f
			.sync
			.download
			.lock()
			.tasks
			.iter()
			.all(|task| task.request.is_none()));
		let suppliers = [fast.clone(), slow.clone(), disconnected];
		f.sync
			.send_requests(&suppliers, &session, &f.scores)
			.unwrap();
		assert_eq!(fast_messages.try_iter().count(), per_peer);
		assert_eq!(slow_messages.try_iter().count(), per_peer);
		assert_eq!(disconnected_messages.try_iter().count(), 0);
		let before: Vec<_> = {
			let download = f.sync.download.lock();
			for (index, task) in download.tasks.iter().enumerate() {
				if index < per_peer {
					assert_eq!(task.request.as_ref().unwrap().peer, fast.info.addr);
				} else if (slow_index..slow_index + per_peer).contains(&index) {
					assert_eq!(task.request.as_ref().unwrap().peer, slow.info.addr);
				} else {
					assert!(task.request.is_none());
				}
			}
			download
				.tasks
				.iter()
				.map(|task| {
					task.request
						.as_ref()
						.map(|request| (request.peer.clone(), request.expires_at))
				})
				.collect()
		};
		// Full peer allowances skip further assignments and preserve deadlines.
		f.sync
			.send_requests(&suppliers, &session, &f.scores)
			.unwrap();
		assert_eq!(
			fast_messages.try_iter().count() + slow_messages.try_iter().count(),
			0
		);
		let after: Vec<_> = f
			.sync
			.download
			.lock()
			.tasks
			.iter()
			.map(|task| {
				task.request
					.as_ref()
					.map(|request| (request.peer.clone(), request.expires_at))
			})
			.collect();
		assert_eq!(before, after);

		// A timeout pushes the peer back, but never beyond the queued tasks.
		for _ in 0..7 {
			fast.record_response_latency(Duration::from_millis(1));
		}
		{
			let mut download = f.sync.download.lock();
			let request = download.tasks[slow_index].request.as_mut().unwrap();
			request.expires_at = request.sent_at;
			let deadline = request.expires_at;
			download.expire_requests(deadline, &f.scores);
		}
		f.sync
			.send_requests(&suppliers, &session, &f.scores)
			.unwrap();
		assert_eq!(fast_messages.try_iter().count(), 0);
		assert_eq!(slow_messages.try_iter().count(), 1);
		assert_eq!(
			f.sync
				.download
				.lock()
				.tasks
				.back()
				.unwrap()
				.request
				.as_ref()
				.unwrap()
				.peer,
			slow.info.addr,
		);
	}

	#[test]
	fn segment_requests_use_the_selected_peers_latency() {
		let f = Fixture::new();
		let (fast, fast_messages) = f.peer(1);
		let (slow, slow_messages) = f.peer(2);
		let (unknown, unknown_messages) = f.peer(3);
		let (zero, zero_messages) = f.peer(4);
		zero.record_response_latency(Duration::ZERO);
		fast.record_response_latency(Duration::from_millis(200));
		slow.record_response_latency(Duration::from_secs(12));
		let session = f.sync.live_desegmenter().unwrap();
		for (peer, messages, millis) in [
			(fast, fast_messages, 8400),
			(slow, slow_messages, 30000),
			(unknown, unknown_messages, 30000),
			(zero, zero_messages, 30000),
		] {
			f.sync
				.send_requests(&[peer.clone()], &session, &f.scores)
				.unwrap();
			assert_eq!(messages.try_iter().count(), 1);
			let mut download = f.sync.download.lock();
			let request = download.tasks[0].request.take().unwrap();
			assert_eq!(request.peer, peer.info.addr);
			assert_eq!(
				request.expires_at - request.sent_at,
				Duration::from_millis(millis)
			);
		}
	}

	#[test]
	fn expired_task_is_retried_once_and_repeated_timeouts_mark_supplier_defunct() {
		let f = Fixture::new();
		let (peer, messages) = f.peer(1);
		let session = f.sync.live_desegmenter().unwrap();
		for attempt in 0..5 {
			f.sync
				.send_requests(&[peer.clone()], &session, &f.scores)
				.unwrap();
			assert_eq!(messages.try_iter().count(), 1);
			let mut download = f.sync.download.lock();
			assert_eq!(download.tasks.len(), 1);
			let deadline = download.tasks[0].request.as_ref().unwrap().expires_at;

			// A task remains assigned until its deadline. After expiration it stays
			// in the job for retry, and another expiration pass must not fine twice.
			download.expire_requests(deadline - Duration::from_millis(1), &f.scores);
			assert!(download.tasks[0].request.is_some());
			f.scores.elapse_no_response_merge_interval(&peer.info.addr);
			download.expire_requests(deadline, &f.scores);
			f.scores.elapse_no_response_merge_interval(&peer.info.addr);
			download.expire_requests(deadline, &f.scores);
			assert!(download.tasks[0].request.is_none());
			drop(download);
			f.scores.apply_peers_status(&f.peers);
			assert!(f.scores.get_banned_peers().is_empty());
			assert_eq!(
				f.peers.get_peer(&peer.info.addr).unwrap().flags == mwc_p2p::State::Defunct,
				attempt == 4
			);
			assert_eq!(peer.is_connected(), attempt < 4);
		}
	}

	#[test]
	fn unmatched_segment_id_and_response_after_reset_leave_tasks_untouched() {
		let f = Fixture::new();
		let (peer, _messages) = f.peer(1);
		let session = f.sync.live_desegmenter().unwrap();
		f.sync
			.send_requests(&[peer.clone()], &session, &f.scores)
			.unwrap();
		let id = f.sync.download.lock().tasks[0].id.identifier;
		let archive_hash = session.archive_hash;
		drop(session);
		let segmenter = f.source.segmenter().unwrap();
		let wrong_id = SegmentIdentifier::new(id.height + 1, id.idx);

		// Matching only the index is insufficient: a different segment height
		// must not fulfill or cancel the outstanding task.
		f.sync
			.receive_bitmap_segment(
				&peer.info.addr,
				&archive_hash,
				segmenter.bitmap_segment(wrong_id).unwrap(),
				&f.peers,
				&f.scores,
			)
			.unwrap();
		assert_eq!(f.sync.download.lock().tasks[0].id.identifier, id);
		assert!(f.sync.download.lock().tasks[0].request.is_some());

		// Reset removes the job. Late responses for that session are ignored,
		// without recreating tasks or counting as invalid responses from its peer.
		f.sync.reset_desegmenter_data();
		for _ in 0..2 {
			f.sync
				.receive_bitmap_segment(
					&peer.info.addr,
					&archive_hash,
					segmenter.bitmap_segment(id).unwrap(),
					&f.peers,
					&f.scores,
				)
				.unwrap();
		}
		f.scores.apply_peers_status(&f.peers);
		assert!(f.scores.get_banned_peers().is_empty());
		assert!(f.sync.download.lock().tasks.is_empty());
	}
}
