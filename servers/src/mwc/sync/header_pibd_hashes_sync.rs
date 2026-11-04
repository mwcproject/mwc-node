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
use crate::mwc::sync::sync_utils::{CachedResponse, SyncRequestResponses, SyncResponse};
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::txhashset::{HeaderHashesDesegmenter, ValidatedHeaderHashesSegment};
use mwc_chain::{self, pibd_params, SyncState, SyncStatus};
use mwc_chain::{Chain, Error};
use mwc_core::core::hash::Hash;
use mwc_core::core::hash::Hashed;
use mwc_core::core::{Segment, SegmentIdentifier};
use mwc_crates::log::{error, info, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::rand;
use mwc_crates::rand::prelude::IteratorRandom;
use mwc_p2p::{self, Capabilities, Peer};
use mwc_p2p::{PeerAddr, ReasonForBan};
use mwc_util::LatencyTracker;
use std::cmp;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

const MIN_HEADERS_HASH_ROOT_RESPONSES: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeadersPibdRootSelection {
	Selected(Hash),
	NeedMoreResponses { responses: usize },
	NoQuorum { responses: usize, best_count: usize },
}

#[derive(Clone)]
struct PibdArchiveHeightCachedResponse {
	target_archive_height: u64,
	response: SyncResponse,
}

/// Headers Hash Sync is needed for Fast Headers synchronization
pub enum HeadersPibdHashResponseStatus {
	Accepted,
	Ignored,
	Rejected(String),
}

pub struct HeadersPibdHashSync {
	chain: Arc<Chain>,
	// The headers sync data
	headers_hash_desegmenter: Option<Arc<RwLock<HeaderHashesDesegmenter>>>,

	// sync tracking
	target_archive_height: u64,
	requested_headers_hash_from: HashMap<PeerAddr, Instant>,
	responded_headers_hash_from: HashMap<PeerAddr, (Hash, Instant)>,
	responded_with_another_height: HashMap<PeerAddr, Instant>,
	// One bounded window owns both unanswered requests and authenticated responses.
	tasks: VecDeque<HeaderHashTask>,
	latency: LatencyTracker,
	// pibd ready archive height for quick response during waiting time intervals
	pibd_headers_are_loaded: RwLock<Option<u64>>,

	cached_response: RwLock<Option<CachedResponse<PibdArchiveHeightCachedResponse>>>,
	pibd_params: Arc<PibdParams>,
}

struct HeaderHashTask {
	id: SegmentIdentifier,
	request: Option<HeaderHashRequest>,
	received: Option<ReceivedHeaderHashes>,
}

struct HeaderHashRequest {
	peer: PeerAddr,
	supplier: Weak<Peer>,
	sent_at: Instant,
	expires_at: Instant,
}

struct ReceivedHeaderHashes {
	segment: ValidatedHeaderHashesSegment,
	peer: PeerAddr,
}

/// A point-in-time view of the header-hash sync state for HeaderPibdSync.
///
/// SyncManager builds this while holding the outer HeadersPibdHashSync RwLock,
/// then drops that guard before HeaderPibdSync applies cached headers, schedules
/// requests, or sends network messages. The desegmenter is shared separately
/// through its own Arc<RwLock<_>>, so callers only lock the desegmenter when
/// they actually need desegmenter state.
#[derive(Clone)]
pub struct HeadersPibdHashSyncSnapshot {
	pub agreed_peers: HashSet<PeerAddr>,
	pub target_archive_height: u64,
	pub pibd_headers_are_loaded: bool,
	pub headers_hash_desegmenter: Option<Arc<RwLock<HeaderHashesDesegmenter>>>,
}

impl HeadersPibdHashSyncSnapshot {
	pub fn is_complete(&self) -> bool {
		self.headers_hash_desegmenter
			.as_ref()
			.map_or(false, |desegmenter| {
				desegmenter.read_recursive().is_complete()
			})
	}
}

impl HeadersPibdHashSync {
	pub(super) fn clear_peer_requests(&mut self, peer: &PeerAddr) {
		self.requested_headers_hash_from.remove(peer);
		for task in &mut self.tasks {
			if task
				.request
				.as_ref()
				.is_some_and(|request| request.peer == *peer)
			{
				task.request = None;
			}
		}
	}

	pub fn new(chain: Arc<Chain>) -> HeadersPibdHashSync {
		HeadersPibdHashSync {
			pibd_params: chain.get_pibd_params().clone(),
			chain: chain.clone(),
			headers_hash_desegmenter: None,
			target_archive_height: 0,
			requested_headers_hash_from: HashMap::new(),
			responded_headers_hash_from: HashMap::new(),
			responded_with_another_height: HashMap::new(),
			tasks: VecDeque::new(),
			latency: LatencyTracker::new(),
			pibd_headers_are_loaded: RwLock::new(None),
			cached_response: RwLock::new(None),
		}
	}

	pub fn is_pibd_headers_are_loaded(&self, target_archive_height: u64) -> bool {
		self.pibd_headers_are_loaded
			.read_recursive()
			.map_or(false, |loaded_archive_height| {
				loaded_archive_height == target_archive_height
			})
	}

	pub fn snapshot_for_best_height(&self, best_height: u64) -> HeadersPibdHashSyncSnapshot {
		let target_archive_height =
			Chain::height_2_archive_height(self.chain.get_context_id(), best_height);
		let agreed_peers = self
			.headers_hash_desegmenter
			.as_ref()
			.map(|desegmenter| {
				let root = *desegmenter.read_recursive().get_headers_root_hash();
				self.responded_headers_hash_from
					.keys()
					.filter(|peer| self.agrees_on_headers_root(peer, root))
					.cloned()
					.collect()
			})
			.unwrap_or_default();
		HeadersPibdHashSyncSnapshot {
			agreed_peers,
			target_archive_height: self.target_archive_height,
			pibd_headers_are_loaded: self.is_pibd_headers_are_loaded(target_archive_height),
			headers_hash_desegmenter: self.headers_hash_desegmenter.clone(),
		}
	}

	pub fn reset(&mut self) {
		self.headers_hash_desegmenter = None;
		self.target_archive_height = 0;
		self.requested_headers_hash_from.clear();
		self.responded_headers_hash_from.clear();
		self.responded_with_another_height.clear();
		self.tasks.clear();
		self.latency = LatencyTracker::new();
		*self.pibd_headers_are_loaded.write() = None;
		*self.cached_response.write() = None;
	}

	pub fn get_headers_hash_desegmenter(&self) -> Option<Arc<RwLock<HeaderHashesDesegmenter>>> {
		self.headers_hash_desegmenter.clone()
	}

	fn select_headers_root<'a>(
		root_hashes: impl Iterator<Item = &'a Hash>,
		required_responses: usize,
	) -> HeadersPibdRootSelection {
		match sync_utils::select_quorum(
			root_hashes.copied(),
			required_responses,
			MIN_HEADERS_HASH_ROOT_RESPONSES,
			|root_hash| *root_hash,
		) {
			sync_utils::QuorumSelection::Selected {
				value: root_hash, ..
			} => HeadersPibdRootSelection::Selected(root_hash),
			sync_utils::QuorumSelection::NeedMoreResponses { responses } => {
				HeadersPibdRootSelection::NeedMoreResponses { responses }
			}
			sync_utils::QuorumSelection::NoQuorum {
				responses,
				best_count,
			} => HeadersPibdRootSelection::NoQuorum {
				responses,
				best_count,
			},
		}
	}

	fn select_headers_root_from_peers(
		&self,
		headers_hash_peers: &[Arc<Peer>],
		required_responses: usize,
	) -> HeadersPibdRootSelection {
		Self::select_headers_root(
			headers_hash_peers.iter().filter_map(|peer| {
				let peer_addr = &peer.info.addr;
				if self.responded_with_another_height.contains_key(peer_addr) {
					return None;
				}
				self.responded_headers_hash_from
					.get(peer_addr)
					.map(|(hash, _)| hash)
			}),
			required_responses,
		)
	}

	fn agrees_on_headers_root(&self, peer: &PeerAddr, root: Hash) -> bool {
		!self.responded_with_another_height.contains_key(peer)
			&& self
				.responded_headers_hash_from
				.get(peer)
				.is_some_and(|(hash, _)| *hash == root)
	}

	fn peers_for_headers_root(
		&self,
		headers_hash_peers: &[Arc<Peer>],
		root_hash: Hash,
	) -> Vec<PeerAddr> {
		headers_hash_peers
			.iter()
			.filter(|peer| self.agrees_on_headers_root(&peer.info.addr, root_hash))
			.map(|peer| peer.info.addr.clone())
			.collect()
	}

	fn can_request_headers_root_from_peer(&self, peer: &Arc<Peer>) -> bool {
		!self
			.requested_headers_hash_from
			.contains_key(&peer.info.addr)
			&& !self
				.responded_headers_hash_from
				.contains_key(&peer.info.addr)
			&& !self
				.responded_with_another_height
				.contains_key(&peer.info.addr)
	}

	fn has_requestable_headers_root_peer(&self, headers_hash_peers: &[Arc<Peer>]) -> bool {
		headers_hash_peers
			.iter()
			.any(|peer| self.can_request_headers_root_from_peer(peer))
	}

	fn request_headers_root_from_peer(
		&mut self,
		peer: &Arc<Peer>,
		archive_height: u64,
		sync_peers: &SyncPeers,
	) -> bool {
		match peer.send_start_headers_hash_sync_request(archive_height) {
			Ok(()) => {
				self.requested_headers_hash_from
					.insert(peer.info.addr.clone(), Instant::now());
				true
			}
			Err(e) => {
				let msg = format!(
					"Failed to send headers hash root request to {} for archive height {}, Error: {}",
					peer.info.addr, archive_height, e
				);
				info!("{}", msg);
				sync_peers.report_no_response(&peer.info.addr, msg);
				false
			}
		}
	}

	fn reset_selected_headers_root(&mut self) {
		self.headers_hash_desegmenter = None;
		self.tasks.clear();
		self.latency = LatencyTracker::new();
	}

	// Reset data related to the commited to headres hash data. At this point all headers was found
	// and downloaded, so no commitments are expected
	pub fn reset_hash_data(&mut self) {
		self.requested_headers_hash_from.clear();
		self.responded_headers_hash_from.clear();
		self.responded_with_another_height.clear();
	}

	// At this point we found that all hash download process is failed. Now we need to ban peers that
	// was commited to headers hash roots. Other banned peers needs to be unbanned
	pub fn reset_ban_commited_to_hash(
		&mut self,
		peers: &Arc<mwc_p2p::Peers>,
		sync_peers: &SyncPeers,
	) {
		debug_assert!(self.headers_hash_desegmenter.is_some());

		if let Some(headers_hash_desegmenter) = self.headers_hash_desegmenter.as_ref() {
			let root_hash = *headers_hash_desegmenter
				.read_recursive()
				.get_headers_root_hash();

			// Ban/unban in this reset path is intentionally best effort. ban_peer()
			// returns the result of persisting the ban through add_banned/save_peer,
			// so a store failure can mean the peer was disconnected but not durably
			// banned. Log those errors and continue: this cleanup runs after a failed
			// headers hash download and must not block the sync workflow.
			let mut peers2ban: HashSet<PeerAddr> = HashSet::new();
			for (peer, (hash, _)) in &self.responded_headers_hash_from {
				if *hash == root_hash {
					if let Err(e) = peers.ban_peer(
						peer,
						ReasonForBan::HeadersHashFailure,
						"ban as commited to header hash",
					) {
						error!(
							"failed to ban peer {} committed to failed headers hash {}: {}",
							peer, root_hash, e
						);
					}
					peers2ban.insert(peer.clone());
				}
			}

			for peer in sync_peers.get_banned_peers() {
				if !peers2ban.contains(&peer) {
					if let Err(e) = peers.unban_peer(&peer) {
						error!(
							"failed to unban peer {} after headers hash reset: {}",
							peer, e
						);
					}
				}
			}
		}

		self.reset();
	}

	// Lightweight request processing for non active case. Immutable method
	pub fn request_pre(&self, best_height: u64) -> Result<Option<SyncResponse>, Error> {
		// Sending headers hash request to all peers that has the same archive height...
		let target_archive_height =
			Chain::height_2_archive_height(self.chain.get_context_id(), best_height);

		{
			let mut loaded_archive_height = self.pibd_headers_are_loaded.write();
			if loaded_archive_height.map_or(false, |loaded| loaded != target_archive_height) {
				*loaded_archive_height = None;
			}
		}

		let cached_response = self.cached_response.read_recursive().clone();
		if let Some(cached_response) = cached_response {
			if !cached_response.is_expired() {
				let cached_response = cached_response.to_response();
				if cached_response.target_archive_height == target_archive_height {
					return Ok(Some(cached_response.response));
				}
			}
			*self.cached_response.write() = None;
		}

		let tip = self.chain.header_head()?;
		if tip.height >= target_archive_height {
			*self.pibd_headers_are_loaded.write() = Some(target_archive_height);
			let resp = SyncResponse::new(
				SyncRequestResponses::HeadersPibdReady,
				Capabilities::HEADERS_HASH,
				format!(
					"tip.height: {} >= target_archive_height: {}",
					tip.height, target_archive_height
				),
			);
			*self.cached_response.write() = Some(CachedResponse::new(
				PibdArchiveHeightCachedResponse {
					target_archive_height,
					response: resp.clone(),
				},
				Duration::from_secs(60),
			)?);
			return Ok(Some(resp));
		}
		*self.pibd_headers_are_loaded.write() = None;
		Ok(None)
	}

	// Full processing, Mutable method
	pub fn request_impl(
		&mut self,
		peers: &Arc<mwc_p2p::Peers>,
		sync_state: &SyncState,
		sync_peers: &SyncPeers,
		best_height: u64,
	) -> Result<SyncResponse, Error> {
		let context_id = self.chain.get_context_id();
		let target_archive_height = Chain::height_2_archive_height(context_id, best_height);
		let request_timeout = Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64);
		self.responded_with_another_height
			.retain(|_, response_time| response_time.elapsed() <= request_timeout);

		if self.target_archive_height != target_archive_height {
			// A new archive target discards its old commitments and task window.
			self.reset();
			self.target_archive_height = target_archive_height;
		}

		self.requested_headers_hash_from.retain(|peer, req_time| {
			if peers.get_connected_peer(peer).is_none() {
				return false;
			}
			if req_time.elapsed() > request_timeout {
				sync_peers.report_no_response(peer, "header hashes".into());
				return false;
			}
			true
		});

		if self.headers_hash_desegmenter.is_none() {
			let headers_hash_peers = sync_utils::get_qualify_peers(
				peers,
				self.target_archive_height,
				Capabilities::HEADERS_HASH,
			);
			if headers_hash_peers.is_empty() {
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Capabilities::HEADERS_HASH,
					"No outbound peers with HEADERS_HASH capability".into(),
				));
			}

			// Let's check if there are enough responses got from the peers, or first/last response was done for a while ago
			let mut first_response = Instant::now();
			for (_, (_, time)) in &self.responded_headers_hash_from {
				if *time < first_response {
					first_response = *time;
				}
			}
			let root_selection_timeout =
				Duration::from_secs((pibd_params::PIBD_REQUESTS_TIMEOUT_SECS / 2) as u64);

			if !self.responded_headers_hash_from.is_empty()
				&& ((self.responded_headers_hash_from.len()
					>= self.requested_headers_hash_from.len()
					&& self.responded_headers_hash_from.len() > 1)
					|| first_response.elapsed() > root_selection_timeout)
			{
				let required_responses = cmp::max(
					MIN_HEADERS_HASH_ROOT_RESPONSES,
					headers_hash_peers
						.iter()
						.filter(|peer| {
							!self
								.responded_with_another_height
								.contains_key(&peer.info.addr)
						})
						.count() / 2 + 1,
				);
				match self.select_headers_root_from_peers(&headers_hash_peers, required_responses) {
					HeadersPibdRootSelection::Selected(best_root_hash) => {
						let genesis_hash = self.chain.genesis().hash(context_id)?;
						let desegmenter = match HeaderHashesDesegmenter::new(
							context_id,
							genesis_hash,
							target_archive_height,
							best_root_hash,
						) {
							Ok(desegmenter) => desegmenter,
							Err(e) if e.is_bad_data() => {
								let response_peers = self
									.peers_for_headers_root(&headers_hash_peers, best_root_hash);
								let msg = format!(
									"Invalid headers hash root selection at archive height {}, root {}: {}",
									target_archive_height, best_root_hash, e
								);
								warn!("{}", msg);
								for peer in &response_peers {
									sync_peers.report_error_response(peer, msg.clone());
								}
								self.reset_hash_data();
								return Ok(SyncResponse::new(
									SyncRequestResponses::WaitingForPeers,
									Capabilities::HEADERS_HASH,
									msg,
								));
							}
							Err(e) => return Err(e),
						};
						let segment_num = desegmenter.get_segments_total();
						self.headers_hash_desegmenter = Some(Arc::new(RwLock::new(desegmenter)));
						sync_state.update(SyncStatus::HeaderHashSync {
							completed_blocks: 0,
							total_blocks: segment_num,
						});
						// Headers desegmenter is ready - let's retry and request some headers
						return self.request_impl(peers, sync_state, sync_peers, best_height);
					}
					HeadersPibdRootSelection::NeedMoreResponses { responses } => {
						if self.requested_headers_hash_from.is_empty()
							&& !self.has_requestable_headers_root_peer(&headers_hash_peers)
						{
							return Ok(SyncResponse::new(
								SyncRequestResponses::WaitingForPeers,
								Capabilities::HEADERS_HASH,
								format!(
									"Need more headers hash root responses. Has peers: {}, responses: {}, required: {}",
									headers_hash_peers.len(),
									responses,
									required_responses
								),
							));
						}
					}
					HeadersPibdRootSelection::NoQuorum {
						responses,
						best_count,
					} => {
						if self.requested_headers_hash_from.is_empty()
							&& !self.has_requestable_headers_root_peer(&headers_hash_peers)
						{
							let response_peers: Vec<PeerAddr> = headers_hash_peers
								.iter()
								.filter_map(|peer| {
									let peer_addr = &peer.info.addr;
									if self.responded_with_another_height.contains_key(peer_addr) {
										return None;
									}
									if self.responded_headers_hash_from.contains_key(peer_addr) {
										Some(peer_addr.clone())
									} else {
										None
									}
								})
								.collect();
							let msg = format!(
								"No quorum for headers hash root at archive height {}. Has peers: {}, responses: {}, best root responses: {}, required: {}",
								target_archive_height,
								headers_hash_peers.len(),
								responses,
								best_count,
								required_responses
							);
							warn!("{}", msg);
							// NoQuorum does not prove which returned root is wrong. The
							// error reports below are a peer-election penalty: peers that
							// repeatedly fail to agree are eventually banned by SyncPeers, so
							// later rounds can elect different peers that may form a quorum.
							for peer in &response_peers {
								sync_peers.report_error_response(peer, msg.clone());
							}
							self.reset_hash_data();
							return Ok(SyncResponse::new(
								SyncRequestResponses::WaitingForPeers,
								Capabilities::HEADERS_HASH,
								msg,
							));
						}
					}
				}
			}

			if self.responded_headers_hash_from.is_empty() {
				sync_state.update(SyncStatus::HeaderHashSync {
					completed_blocks: 0,
					total_blocks: 1,
				});
			}

			// Requestiong more hashes...
			let mut request_failures = 0;
			for peer in &headers_hash_peers {
				if self.can_request_headers_root_from_peer(peer) {
					if !self.request_headers_root_from_peer(peer, target_archive_height, sync_peers)
					{
						request_failures += 1;
					}
				}
			}
			if self.requested_headers_hash_from.is_empty() && request_failures > 0 {
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Capabilities::HEADERS_HASH,
					format!(
						"Unable to send headers hash root requests. Has peers: {}, failures: {}",
						headers_hash_peers.len(),
						request_failures
					),
				));
			}
			if self.requested_headers_hash_from.is_empty()
				&& !self.has_requestable_headers_root_peer(&headers_hash_peers)
			{
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Capabilities::HEADERS_HASH,
					format!(
						"No requestable headers hash root peers. Has peers: {}, excluded by another archive height: {}",
						headers_hash_peers.len(),
						self.responded_with_another_height.len()
					),
				));
			}
			return Ok(SyncResponse::new(
				SyncRequestResponses::Syncing,
				Capabilities::HEADERS_HASH,
				format!(
					"Has peers: {}, Waiting root hash responses: {}",
					headers_hash_peers.len(),
					self.requested_headers_hash_from.len()
				),
			));
		}

		debug_assert!(self.headers_hash_desegmenter.is_some());
		debug_assert!(self.target_archive_height > 0);

		// Headers hashes are here, we can go forward and request some headers.
		let headers_hash_desegmenter =
			self.headers_hash_desegmenter
				.as_ref()
				.cloned()
				.ok_or(Error::Other(
					"internal error, headers_hash_desegmenter is empty".to_string(),
				))?;

		let headers_hash_peers = sync_utils::get_qualify_peers(
			peers,
			self.target_archive_height,
			Capabilities::HEADERS_HASH,
		);
		// Keep discovering suppliers while the checkpoint headers are downloading.
		let mut request_failures = 0;
		for peer in &headers_hash_peers {
			if self.can_request_headers_root_from_peer(peer) {
				if !self.request_headers_root_from_peer(
					peer,
					self.target_archive_height,
					sync_peers,
				) {
					request_failures += 1;
				}
			}
		}

		self.apply_ready_tasks(&mut headers_hash_desegmenter.write(), sync_peers)?;
		if headers_hash_desegmenter.read_recursive().is_complete() {
			// Continue root discovery on later passes so new agreed peers can
			// participate in the following checkpoint-header download.
			return Ok(SyncResponse::new(
				SyncRequestResponses::HeadersHashReady,
				Capabilities::HEADERS_HASH,
				"Checkpoint hashes are ready".into(),
			));
		}

		let headers_root_hash = {
			let desegmenter = headers_hash_desegmenter.read_recursive();
			self.fill_tasks(&desegmenter)?;
			let buffered = self
				.tasks
				.iter()
				.filter(|task| task.received.is_some())
				.count();
			sync_state.update(SyncStatus::HeaderHashSync {
				completed_blocks: desegmenter
					.get_segments_applied()
					.saturating_add(buffered)
					.min(desegmenter.get_segments_total()),
				total_blocks: desegmenter.get_segments_total(),
			});
			*desegmenter.get_headers_root_hash()
		};

		// Only the sync loop expires tasks, even if every supplier disconnected.
		// Retain the task itself so its next request retries the same segment.
		let now = Instant::now();
		for task in &mut self.tasks {
			if let Some(request) = &task.request {
				if !sync_utils::request_peer_is_connected(&request.supplier) {
					task.request = None;
					continue;
				}
				if now >= request.expires_at {
					sync_peers.report_no_response(
						&request.peer,
						format!("Checkpoint hash segment {} timed out", task.id),
					);
					task.request = None;
				}
			}
		}
		let suppliers: Vec<_> = headers_hash_peers
			.iter()
			.filter(|peer| self.agrees_on_headers_root(&peer.info.addr, headers_root_hash))
			.collect();
		let needs_supplier = self
			.tasks
			.iter()
			.any(|task| task.request.is_none() && task.received.is_none());
		if suppliers.is_empty() && needs_supplier {
			let has_alternative_root = headers_hash_peers.iter().any(|peer| {
				!self
					.responded_with_another_height
					.contains_key(&peer.info.addr)
					&& self
						.responded_headers_hash_from
						.get(&peer.info.addr)
						.is_some_and(|(hash, _)| *hash != headers_root_hash)
			});
			if has_alternative_root {
				self.reset_selected_headers_root();
				return self.request_impl(peers, sync_state, sync_peers, best_height);
			}
			return Ok(SyncResponse::new(
				SyncRequestResponses::WaitingForPeers,
				Capabilities::HEADERS_HASH,
				"No peers available for the selected checkpoint root".into(),
			));
		}

		let average = self.latency.get_average_latency();
		let request_limit = self.pibd_params.get_segments_requests_limit(
			average.and_then(|latency| u32::try_from(latency.as_millis()).ok()),
		);
		let per_peer = self.pibd_params.get_segments_request_per_peer();
		let mut counts = HashMap::<PeerAddr, usize>::new();
		let mut pending = 0;
		for request in self.tasks.iter().filter_map(|task| task.request.as_ref()) {
			*counts.entry(request.peer.clone()).or_default() += 1;
			pending += 1;
		}
		let mut rng = rand::rng();
		for task in &mut self.tasks {
			if pending >= request_limit {
				break;
			}
			if task.request.is_some() || task.received.is_some() {
				continue;
			}
			let Some(peer) = suppliers
				.iter()
				.filter(|peer| {
					peer.is_connected()
						&& counts.get(&peer.info.addr).copied().unwrap_or(0) < per_peer
				})
				.choose(&mut rng)
			else {
				break;
			};
			let sent_at = Instant::now();
			let timeout = peer.request_timeout();
			let expires_at = sent_at
				.checked_add(timeout)
				.ok_or_else(|| Error::Other("Checkpoint hash deadline overflow".into()))?;
			// The manager's outer write lock covers registration and sending.
			task.request = Some(HeaderHashRequest {
				peer: peer.info.addr.clone(),
				supplier: Arc::downgrade(peer),
				sent_at,
				expires_at,
			});
			match peer.send_headers_hash_segment_request(headers_root_hash, task.id) {
				Ok(()) => {
					*counts.entry(peer.info.addr.clone()).or_default() += 1;
					pending += 1;
				}
				Err(error) => {
					task.request = None;
					let message = format!(
						"Failed to request checkpoint hash segment {} from {}: {}",
						task.id, peer.info.addr, error
					);
					info!("{}", message);
					sync_peers.report_no_response(&peer.info.addr, message);
					// Give this supplier another chance on the next scheduling pass.
					counts.insert(peer.info.addr.clone(), per_peer);
				}
			}
		}
		Ok(SyncResponse::new(
			if pending == 0 {
				SyncRequestResponses::WaitingForPeers
			} else {
				SyncRequestResponses::Syncing
			},
			Capabilities::HEADERS_HASH,
			format!(
				"Checkpoint hashes: {} tasks, {} pending requests, {} failed root requests",
				self.tasks.len(),
				pending,
				request_failures
			),
		))
	}

	fn fill_tasks(&mut self, desegmenter: &HeaderHashesDesegmenter) -> Result<(), Error> {
		let limit = self.pibd_params.get_headers_hash_buffer_len();
		// A smaller resource limit stops refilling; existing tasks finish normally.
		for id in
			desegmenter.next_segments(self.tasks.len(), limit.saturating_sub(self.tasks.len()))?
		{
			self.tasks.push_back(HeaderHashTask {
				id,
				request: None,
				received: None,
			});
		}
		Ok(())
	}

	fn apply_ready_tasks(
		&mut self,
		desegmenter: &mut HeaderHashesDesegmenter,
		scores: &SyncPeers,
	) -> Result<(), Error> {
		while let Some(task) = self.tasks.front() {
			let Some(received) = &task.received else {
				break;
			};
			if let Err(error) = desegmenter.apply_segment(&received.segment) {
				let message = format!(
					"Failed to apply checkpoint hash segment {} from {}: {}",
					task.id, received.peer, error
				);
				error!("{}", message);
				scores.report_error_response(&received.peer, message);
				return Err(error);
			}
			self.tasks.pop_front();
		}
		Ok(())
	}

	pub fn receive_headers_hash_response(
		&mut self,
		peer: &PeerAddr,
		archive_height: u64,
		headers_hash_root: Hash,
		sync_peers: &SyncPeers,
	) -> HeadersPibdHashResponseStatus {
		if archive_height != self.target_archive_height {
			return HeadersPibdHashResponseStatus::Ignored;
		}
		if self.responded_headers_hash_from.contains_key(peer) {
			return HeadersPibdHashResponseStatus::Ignored;
		}
		if self.requested_headers_hash_from.remove(peer).is_none() {
			let msg = format!(
				"unsolicited headers hash response from {} for archive height {}",
				peer, archive_height
			);
			sync_peers.report_error_response(peer, msg.clone());
			return HeadersPibdHashResponseStatus::Rejected(msg);
		}

		// Adding only once, so attacker will not be able to escape the ban.
		sync_peers.report_ok_response(peer);
		self.responded_headers_hash_from
			.insert(peer.clone(), (headers_hash_root, Instant::now()));
		HeadersPibdHashResponseStatus::Accepted
	}

	pub fn recieve_another_archive_header(
		&mut self,
		peer: &PeerAddr,
		_header_hash: &Hash,
		new_height: u64,
	) {
		// HasAnotherArchiveHeader is a shared response used for several request types:
		// headers hash handshake, headers hash segment requests, PIBD handshake, and
		// PIBD segment requests. This handler is called for every such response, so
		// HeadersPibdHashSync cannot require a matching local headers-hash request here.
		if new_height != self.target_archive_height {
			self.responded_with_another_height
				.insert(peer.clone(), Instant::now());
		}
	}

	pub fn receive_header_hashes_segment(
		&mut self,
		peer: &PeerAddr,
		header_hashes_root: Hash,
		segment: Segment<Hash>,
		sync_peers: &SyncPeers,
	) -> Result<(), Error> {
		let Some(desegmenter) = self.headers_hash_desegmenter.clone() else {
			return Ok(());
		};
		if *desegmenter.read_recursive().get_headers_root_hash() != header_hashes_root {
			return Ok(()); // Delayed response for another root.
		}
		let id = *segment.id();
		let Some(index) = self.tasks.iter().position(|task| task.id == id) else {
			return Ok(());
		};
		if self.tasks[index].received.is_some() {
			return Ok(());
		}
		if self
			.responded_headers_hash_from
			.get(peer)
			.map(|(root, _)| *root)
			!= Some(header_hashes_root)
		{
			sync_peers.report_error_response(peer, "Checkpoint root commitment mismatch".into());
			return Ok(());
		}
		let received_at = Instant::now();
		let validated = desegmenter.read_recursive().validate_segment(segment);
		let segment = match validated {
			Ok(segment) => segment,
			Err(error) => {
				// An invalid unsolicited response must not cancel another supplier's request.
				let task = &mut self.tasks[index];
				if task
					.request
					.as_ref()
					.is_some_and(|request| request.peer == *peer)
				{
					task.request = None;
				}
				let message = format!(
					"Invalid checkpoint hash segment {} from {}: {}",
					id, peer, error
				);
				info!("{}", message);
				sync_peers.report_error_response(peer, message);
				return Err(error);
			}
		};
		let task = &mut self.tasks[index];
		if let Some(request) = task.request.take().filter(|request| request.peer == *peer) {
			let latency = received_at.saturating_duration_since(request.sent_at);
			if let Some(supplier) = request.supplier.upgrade() {
				supplier.record_response_latency(latency);
			}
			if let Ok(latency_ms) = i64::try_from(latency.as_millis()) {
				self.latency.add_latency(latency_ms);
			}
		}
		// A committed peer can fulfill a retry sent to another supplier. Remember
		// the actual sender for any application failure; later duplicates are ignored.
		task.received = Some(ReceivedHeaderHashes {
			segment,
			peer: peer.clone(),
		});
		sync_peers.report_ok_response(peer);
		self.apply_ready_tasks(&mut desegmenter.write(), sync_peers)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_hash(value: u8) -> Hash {
		Hash::from_vec(&[value; Hash::LEN])
	}

	#[test]
	fn select_headers_root_rejects_single_response() {
		let root = test_hash(1);
		let roots = vec![root];

		assert_eq!(
			HeadersPibdHashSync::select_headers_root(roots.iter(), MIN_HEADERS_HASH_ROOT_RESPONSES,),
			HeadersPibdRootSelection::NeedMoreResponses { responses: 1 }
		);
	}

	#[test]
	fn select_headers_root_requires_strict_majority() {
		let root_a = test_hash(1);
		let root_b = test_hash(2);
		let roots = vec![root_a, root_b];

		assert_eq!(
			HeadersPibdHashSync::select_headers_root(roots.iter(), MIN_HEADERS_HASH_ROOT_RESPONSES,),
			HeadersPibdRootSelection::NoQuorum {
				responses: 2,
				best_count: 1
			}
		);
	}

	#[test]
	fn select_headers_root_accepts_quorum_with_strict_majority() {
		let root_a = test_hash(1);
		let root_b = test_hash(2);
		let roots = vec![root_a, root_a, root_b];

		assert_eq!(
			HeadersPibdHashSync::select_headers_root(roots.iter(), MIN_HEADERS_HASH_ROOT_RESPONSES,),
			HeadersPibdRootSelection::Selected(root_a)
		);
	}

	#[test]
	fn select_headers_root_rejects_even_split_without_strict_majority() {
		let root_a = test_hash(1);
		let root_b = test_hash(2);
		let roots = vec![root_a, root_a, root_b, root_b];

		assert_eq!(
			HeadersPibdHashSync::select_headers_root(
				roots.iter(),
				MIN_HEADERS_HASH_ROOT_RESPONSES + 1,
			),
			HeadersPibdRootSelection::NoQuorum {
				responses: 4,
				best_count: 2
			}
		);
	}

	#[test]
	fn select_headers_root_rejects_partial_majority_of_received_responses() {
		let root = test_hash(1);
		let roots = vec![root, root];

		assert_eq!(
			HeadersPibdHashSync::select_headers_root(
				roots.iter(),
				MIN_HEADERS_HASH_ROOT_RESPONSES + 1,
			),
			HeadersPibdRootSelection::NeedMoreResponses { responses: 2 }
		);
	}
}

#[cfg(all(test, feature = "test-support"))]
mod task_tests {
	use super::*;
	use mwc_chain::types::{NoopAdapter, HEADERS_PER_BATCH};
	use mwc_core::core::pmmr::{ReadablePMMR, VecBackend, PMMR};
	use mwc_core::{global, pow, ser::ProtocolVersion};
	use mwc_crates::crossbeam::channel::Receiver;
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_crates::tempfile::TempDir;
	use mwc_p2p::{
		msg::Msg,
		types::{Direction, PeerInfo, PeerLiveInfo},
		DummyAdapter, P2PConfig, Peers,
	};

	struct Fixture {
		sync: HeadersPibdHashSync,
		peers: Arc<Peers>,
		scores: SyncPeers,
		backend: VecBackend<Hash>,
		hashes: Vec<Hash>,
		root: Hash,
		_chain_dir: TempDir,
		_peer_dir: TempDir,
	}

	impl Fixture {
		fn new(leaves: u64) -> Self {
			global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
			global::set_local_nrd_enabled(false);
			let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			let chain_dir = TempDir::new().unwrap();
			let chain = Arc::new(
				Chain::init(
					&secp,
					0,
					chain_dir.path().to_str().unwrap().into(),
					Arc::new(NoopAdapter {}),
					global::get_genesis_block(&secp, 0).unwrap(),
					pow::verify_size,
					false,
					HashSet::new(),
					None,
					None,
					false,
				)
				.unwrap(),
			);
			let mut hashes = vec![chain.genesis().hash(0).unwrap()];
			hashes.extend((1..leaves).map(|index| {
				let mut bytes = [0; Hash::LEN];
				bytes[..8].copy_from_slice(&index.to_le_bytes());
				Hash::from_vec(&bytes)
			}));
			let mut backend = VecBackend::new(0);
			let mut mmr = PMMR::new(&mut backend);
			for hash in &hashes {
				mmr.push(hash).unwrap();
			}
			let root = mmr.root().unwrap();
			let interval = global::txhashset_archive_interval(0);
			let target = ((leaves - 1) * u64::from(HEADERS_PER_BATCH))
				.max(1)
				.div_ceil(interval)
				* interval;
			let mut sync = HeadersPibdHashSync::new(chain);
			sync.target_archive_height = target;
			sync.headers_hash_desegmenter = Some(Arc::new(RwLock::new(
				HeaderHashesDesegmenter::new(0, hashes[0], target, root).unwrap(),
			)));
			let peer_dir = TempDir::new().unwrap();
			let peers = Arc::new(Peers::new(
				mwc_p2p::store::PeerStore::new(0, peer_dir.path().to_str().unwrap()).unwrap(),
				Arc::new(DummyAdapter {}),
				&P2PConfig::default(),
			));
			Self {
				sync,
				peers,
				scores: SyncPeers::new(),
				backend,
				hashes,
				root,
				_chain_dir: chain_dir,
				_peer_dir: peer_dir,
			}
		}

		fn peer(&mut self, id: u8, commitment: Hash) -> (PeerAddr, Receiver<Msg>) {
			let addr = PeerAddr::Ip(([10, 2, 0, id], 3414).into());
			let info = PeerInfo {
				capabilities: Capabilities::HEADERS_HASH,
				user_agent: "checkpoint-task-test".into(),
				version: ProtocolVersion::local(),
				addr: addr.clone(),
				direction: Direction::Outbound,
				live_info: Arc::new(RwLock::new(PeerLiveInfo::new(pow::Difficulty::min()))),
				tx_base_fee: 0,
			};
			info.update(
				self.sync.target_archive_height + u64::from(global::state_sync_threshold(0)),
				pow::Difficulty::min(),
			);
			let (peer, messages) = Peer::connected_for_test(info, 0, Arc::new(DummyAdapter {}));
			self.peers.add_connected(Arc::new(peer)).unwrap();
			self.sync
				.responded_headers_hash_from
				.insert(addr.clone(), (commitment, Instant::now()));
			(addr, messages)
		}

		fn schedule(&mut self) {
			let best_height =
				self.sync.target_archive_height + u64::from(global::state_sync_threshold(0));
			self.sync
				.request_impl(&self.peers, &SyncState::new(), &self.scores, best_height)
				.unwrap();
		}

		fn segment(&mut self, id: SegmentIdentifier) -> Segment<Hash> {
			let size = self.backend.size();
			let mmr = PMMR::at(&mut self.backend, size);
			Segment::from_pmmr(
				id,
				&mmr.readonly_pmmr(),
				None,
				Hash::LEN,
				pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			)
			.unwrap()
		}
	}

	#[test]
	fn out_of_order_responses_wait_for_the_prefix_and_duplicates_are_ignored() {
		let mut f = Fixture::new(8193);
		let (first, _first_messages) = f.peer(1, f.root);
		let (second, _second_messages) = f.peer(2, f.root);
		f.schedule();
		let ids: Vec<_> = f.sync.tasks.iter().map(|task| task.id).collect();
		assert!(ids.len() > 1);
		let desegmenter = f.sync.get_headers_hash_desegmenter().unwrap();

		// A different committed peer may satisfy an assigned task. Buffer all later
		// segments first: none may enter the PMMR until the missing prefix arrives.
		for id in ids.iter().skip(1).rev() {
			let owner = &f
				.sync
				.tasks
				.iter()
				.find(|task| task.id == *id)
				.unwrap()
				.request
				.as_ref()
				.unwrap()
				.peer;
			let supplier = if *owner == first { &second } else { &first };
			let segment = f.segment(*id);
			f.sync
				.receive_header_hashes_segment(supplier, f.root, segment.clone(), &f.scores)
				.unwrap();
			f.sync
				.receive_header_hashes_segment(supplier, f.root, segment, &f.scores)
				.unwrap();
		}
		assert_eq!(desegmenter.read().get_segments_applied(), 0);
		assert_eq!(f.sync.tasks.len(), ids.len());
		assert!(f
			.sync
			.tasks
			.iter()
			.skip(1)
			.all(|task| task.request.is_none() && task.received.is_some()));

		// A slightly late first response is accepted if the main expiry loop has
		// not run. It drains every buffered successor and completes the exact list.
		f.sync.tasks[0].request.as_mut().unwrap().expires_at = Instant::now();
		let segment = f.segment(ids[0]);
		f.sync
			.receive_header_hashes_segment(&first, f.root, segment.clone(), &f.scores)
			.unwrap();
		f.sync
			.receive_header_hashes_segment(&first, f.root, segment, &f.scores)
			.unwrap();
		assert!(f.sync.tasks.is_empty());
		assert_eq!(desegmenter.read().get_header_hashes().unwrap(), f.hashes);
	}

	#[test]
	fn scheduler_caps_assignments_and_retries_only_expired_work() {
		let mut f = Fixture::new(1);
		// Scheduling depends on the segment layout, so a large synthetic target
		// exercises resource limits without allocating its checkpoint payloads.
		let interval = global::txhashset_archive_interval(0);
		let target = (100 * 4096 * u64::from(HEADERS_PER_BATCH)).div_ceil(interval) * interval;
		f.sync.target_archive_height = target;
		f.sync.headers_hash_desegmenter = Some(Arc::new(RwLock::new(
			HeaderHashesDesegmenter::new(0, f.hashes[0], target, f.root).unwrap(),
		)));
		let (first, first_messages) = f.peer(1, f.root);
		let (second, second_messages) = f.peer(2, f.root);
		let (other, other_messages) = f.peer(3, Hash::default());
		f.peers
			.get_connected_peer(&first)
			.unwrap()
			.record_response_latency(Duration::from_millis(200));
		f.peers
			.get_connected_peer(&second)
			.unwrap()
			.record_response_latency(Duration::from_secs(12));
		f.schedule();
		let per_peer = f.sync.pibd_params.get_segments_request_per_peer();
		let n1 = first_messages.try_iter().count();
		let n2 = second_messages.try_iter().count();
		assert!(n1 <= per_peer && n2 <= per_peer && n1 + n2 > 0);
		assert!(n1 + n2 <= f.sync.pibd_params.get_segments_requests_limit(None));
		assert!(f.sync.tasks.len() <= f.sync.pibd_params.get_headers_hash_buffer_len());
		assert_eq!(other_messages.try_iter().count(), 0);
		for request in f.sync.tasks.iter().filter_map(|task| task.request.as_ref()) {
			let millis = if request.peer == first { 8400 } else { 30000 };
			assert_eq!(
				request.expires_at - request.sent_at,
				Duration::from_millis(millis)
			);
		}
		assert!(f
			.sync
			.tasks
			.iter()
			.filter_map(|task| task.request.as_ref())
			.all(|req| req.peer != other));

		// Repeated scheduling must not duplicate outstanding requests. Expiring one
		// assignment preserves its task and resends exactly that missing segment.
		f.schedule();
		assert_eq!(
			first_messages.try_iter().count() + second_messages.try_iter().count(),
			0
		);
		let id = f.sync.tasks[0].id;
		f.sync.tasks[0].request.as_mut().unwrap().expires_at = Instant::now();
		f.schedule();
		assert_eq!(f.sync.tasks[0].id, id);
		assert!(f.sync.tasks[0].request.is_some());
		assert_eq!(
			first_messages.try_iter().count() + second_messages.try_iter().count(),
			1
		);
	}

	#[test]
	fn reconnect_cancels_checkpoint_requests_but_keeps_root_commitments() {
		let mut f = Fixture::new(1);
		let (peer, messages) = f.peer(1, f.root);
		let supplier = f.peers.get_connected_peer(&peer).unwrap();
		let height = supplier.info.get_height_and_difficulty().0;
		// The shared selector gates both root queries and checkpoint segments.
		for (height, difficulty) in [
			(0, pow::Difficulty::min()),
			(height, pow::Difficulty::zero()),
		] {
			{
				let mut info = supplier.info.live_info.write();
				info.height = height;
				info.total_difficulty = difficulty;
			}
			f.schedule();
			assert_eq!(messages.try_iter().count(), 0);
		}
		supplier.info.update(height, pow::Difficulty::min());
		f.schedule();
		assert_eq!(messages.try_iter().count(), 1);
		f.sync
			.requested_headers_hash_from
			.insert(peer.clone(), Instant::now());
		let commitment = f.sync.responded_headers_hash_from[&peer];
		f.sync.clear_peer_requests(&peer);
		assert!(f.sync.requested_headers_hash_from.is_empty());
		assert!(f.sync.tasks[0].request.is_none());
		assert_eq!(f.sync.responded_headers_hash_from[&peer], commitment);
		f.schedule();
		assert_eq!(messages.try_iter().count(), 1);
		for _ in 0..4 {
			f.scores.elapse_no_response_merge_interval(&peer);
			f.scores
				.report_no_response(&peer, "before disconnect".into());
		}
		f.scores.elapse_no_response_merge_interval(&peer);
		supplier.stop();
		f.sync.tasks[0].request.as_mut().unwrap().expires_at = Instant::now();
		f.schedule();
		assert!(f.sync.tasks[0].request.is_none());
		f.scores.apply_peers_status(&f.peers);
		assert!(!f.peers.is_banned(&peer).unwrap());
		assert_eq!(
			f.peers.get_peer(&peer).unwrap().flags,
			mwc_p2p::State::Healthy
		);
	}

	#[test]
	fn repeated_timeouts_mark_the_supplier_defunct() {
		let mut f = Fixture::new(1);
		let (peer, messages) = f.peer(1, f.root);
		f.schedule();
		assert_eq!(messages.try_iter().count(), 1);
		// The first four whole-request timeouts are fines, with the same task
		// retried each pass. The fifth marks the supplier Defunct.
		for failure in 1..=5 {
			f.scores.elapse_no_response_merge_interval(&peer);
			f.sync.tasks[0].request.as_mut().unwrap().expires_at = Instant::now();
			f.schedule();
			assert_eq!(messages.try_iter().count(), 1);
			f.scores.apply_peers_status(&f.peers);
			assert!(f.scores.get_banned_peers().is_empty());
			assert_eq!(
				f.peers.get_peer(&peer).unwrap().flags == mwc_p2p::State::Defunct,
				failure == 5
			);
			assert_eq!(f.peers.get_connected_peer(&peer).is_some(), failure < 5);
		}
		// A timeout disconnect must not send a BanReason message.
		assert_eq!(messages.try_iter().count(), 0);
		// With no connected supplier, the last outstanding request still expires
		// and leaves an unassigned task, ready when an agreed peer joins again.
		f.sync.tasks[0].request.as_mut().unwrap().expires_at = Instant::now();
		f.schedule();
		assert!(f.sync.tasks[0].request.is_none());
		assert_eq!(messages.try_iter().count(), 0);
	}
}
