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
use mwc_chain::txhashset::{HeaderHashesDesegmenter, HEADER_HASHES_STUB_TYPE};
use mwc_chain::{self, pibd_params, SyncState, SyncStatus};
use mwc_chain::{Chain, Error};
use mwc_core::core::hash::Hash;
use mwc_core::core::hash::Hashed;
use mwc_core::core::{Segment, SegmentType};
use mwc_crates::log::{error, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::rand;
use mwc_crates::rand::seq::IndexedRandom;
use mwc_p2p::{self, Capabilities, Peer};
use mwc_p2p::{PeerAddr, ReasonForBan};
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MIN_HEADERS_HASH_ROOT_RESPONSES: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeadersRootSelection {
	Selected(Hash),
	NeedMoreResponses { responses: usize },
	NoQuorum { responses: usize, best_count: usize },
}

#[derive(Clone)]
struct ArchiveHeightCachedResponse {
	target_archive_height: u64,
	response: SyncResponse,
}

/// Headers Hash Sync is needed for Fast Headers synchronization
pub enum HeadersHashResponseStatus {
	Accepted,
	Ignored,
	Rejected(String),
}

pub struct HeadersHashSync {
	chain: Arc<Chain>,
	// The headers sync data
	headers_hash_desegmenter: Option<Arc<RwLock<HeaderHashesDesegmenter>>>,

	// sync tracking
	target_archive_height: u64,
	requested_headers_hash_from: HashMap<PeerAddr, Instant>,
	responded_headers_hash_from: HashMap<PeerAddr, (Hash, Instant)>,
	responded_with_another_height: HashMap<PeerAddr, Instant>,
	// sync for segments
	requested_segments: HashMap<(SegmentType, u64), (PeerAddr, Instant)>,
	// pibd ready archive height for quick response during waiting time intervals
	pibd_headers_are_loaded: RwLock<Option<u64>>,

	cached_response: RwLock<Option<CachedResponse<ArchiveHeightCachedResponse>>>,
	pibd_params: Arc<PibdParams>,
}

/// A point-in-time view of the header-hash sync state for HeaderSync.
///
/// SyncManager builds this while holding the outer HeadersHashSync RwLock,
/// then drops that guard before HeaderSync applies cached headers, schedules
/// requests, or sends network messages. The desegmenter is shared separately
/// through its own Arc<RwLock<_>>, so callers only lock the desegmenter when
/// they actually need desegmenter state.
#[derive(Clone)]
pub struct HeadersHashSyncSnapshot {
	pub target_archive_height: u64,
	pub pibd_headers_are_loaded: bool,
	pub headers_hash_desegmenter: Option<Arc<RwLock<HeaderHashesDesegmenter>>>,
}

impl HeadersHashSyncSnapshot {
	pub fn is_complete(&self) -> bool {
		self.headers_hash_desegmenter
			.as_ref()
			.map_or(false, |desegmenter| {
				desegmenter.read_recursive().is_complete()
			})
	}
}

impl HeadersHashSync {
	pub fn new(chain: Arc<Chain>) -> HeadersHashSync {
		HeadersHashSync {
			pibd_params: chain.get_pibd_params().clone(),
			chain: chain.clone(),
			headers_hash_desegmenter: None,
			target_archive_height: 0,
			requested_headers_hash_from: HashMap::new(),
			responded_headers_hash_from: HashMap::new(),
			responded_with_another_height: HashMap::new(),
			requested_segments: HashMap::new(),
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

	pub fn snapshot_for_best_height(&self, best_height: u64) -> HeadersHashSyncSnapshot {
		let target_archive_height =
			Chain::height_2_archive_height(self.chain.get_context_id(), best_height);
		HeadersHashSyncSnapshot {
			target_archive_height: self.target_archive_height,
			pibd_headers_are_loaded: self.is_pibd_headers_are_loaded(target_archive_height),
			headers_hash_desegmenter: self.headers_hash_desegmenter.clone(),
		}
	}

	fn get_peer_capabilities() -> Capabilities {
		return Capabilities::HEADERS_HASH;
	}

	pub fn reset(&mut self) {
		self.headers_hash_desegmenter = None;
		self.target_archive_height = 0;
		self.requested_headers_hash_from.clear();
		self.responded_headers_hash_from.clear();
		self.responded_with_another_height.clear();
		self.requested_segments.clear();
		*self.pibd_headers_are_loaded.write() = None;
		*self.cached_response.write() = None;
	}

	pub fn get_headers_hash_desegmenter(&self) -> Option<Arc<RwLock<HeaderHashesDesegmenter>>> {
		self.headers_hash_desegmenter.clone()
	}

	fn select_headers_root<'a>(
		root_hashes: impl Iterator<Item = &'a Hash>,
		required_responses: usize,
	) -> HeadersRootSelection {
		match sync_utils::select_quorum(
			root_hashes.copied(),
			required_responses,
			MIN_HEADERS_HASH_ROOT_RESPONSES,
			|root_hash| *root_hash,
		) {
			sync_utils::QuorumSelection::Selected {
				value: root_hash, ..
			} => HeadersRootSelection::Selected(root_hash),
			sync_utils::QuorumSelection::NeedMoreResponses { responses } => {
				HeadersRootSelection::NeedMoreResponses { responses }
			}
			sync_utils::QuorumSelection::NoQuorum {
				responses,
				best_count,
			} => HeadersRootSelection::NoQuorum {
				responses,
				best_count,
			},
		}
	}

	fn select_headers_root_from_peers(
		&self,
		headers_hash_peers: &[Arc<Peer>],
		required_responses: usize,
	) -> HeadersRootSelection {
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

	fn peers_for_headers_root(
		&self,
		headers_hash_peers: &[Arc<Peer>],
		root_hash: Hash,
	) -> Vec<PeerAddr> {
		headers_hash_peers
			.iter()
			.filter_map(|peer| {
				let peer_addr = &peer.info.addr;
				if self.responded_with_another_height.contains_key(peer_addr) {
					return None;
				}
				match self.responded_headers_hash_from.get(peer_addr) {
					Some((hash, _)) if *hash == root_hash => Some(peer_addr.clone()),
					_ => None,
				}
			})
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
				error!("{}", msg);
				sync_peers.report_no_response(&peer.info.addr, msg);
				false
			}
		}
	}

	fn reset_selected_headers_root(&mut self) {
		self.headers_hash_desegmenter = None;
		self.requested_segments.clear();
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
				Self::get_peer_capabilities(),
				format!(
					"tip.height: {} >= target_archive_height: {}",
					tip.height, target_archive_height
				),
			);
			*self.cached_response.write() = Some(CachedResponse::new(
				ArchiveHeightCachedResponse {
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
			// Reset target-specific state before using peers, segments, cached
			// responses, or a completed desegmenter from a previous archive height.
			self.headers_hash_desegmenter = None;
			self.target_archive_height = target_archive_height;
			self.requested_headers_hash_from.clear();
			self.responded_headers_hash_from.clear();
			self.responded_with_another_height.clear();
			self.requested_segments.clear();
			*self.pibd_headers_are_loaded.write() = None;
			*self.cached_response.write() = None;
		}

		if self.headers_hash_desegmenter.is_none() {
			self.requested_headers_hash_from.retain(|peer, req_time| {
				if req_time.elapsed() > request_timeout {
					sync_peers.report_no_response(peer, "header hashes".into());
					return false;
				}
				true
			});

			let headers_hash_peers = sync_utils::get_qualify_peers(
				peers,
				self.target_archive_height,
				Capabilities::HEADERS_HASH,
			);
			if headers_hash_peers.is_empty() {
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Self::get_peer_capabilities(),
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
					HeadersRootSelection::Selected(best_root_hash) => {
						let genesis_hash = self.chain.genesis().hash(context_id)?;
						let desegmenter = match HeaderHashesDesegmenter::new(
							context_id,
							genesis_hash,
							target_archive_height,
							best_root_hash,
							self.pibd_params.clone(),
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
									Self::get_peer_capabilities(),
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
					HeadersRootSelection::NeedMoreResponses { responses } => {
						if self.requested_headers_hash_from.is_empty()
							&& !self.has_requestable_headers_root_peer(&headers_hash_peers)
						{
							return Ok(SyncResponse::new(
								SyncRequestResponses::WaitingForPeers,
								Self::get_peer_capabilities(),
								format!(
									"Need more headers hash root responses. Has peers: {}, responses: {}, required: {}",
									headers_hash_peers.len(),
									responses,
									required_responses
								),
							));
						}
					}
					HeadersRootSelection::NoQuorum {
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
								Self::get_peer_capabilities(),
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
					Self::get_peer_capabilities(),
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
					Self::get_peer_capabilities(),
					format!(
						"No requestable headers hash root peers. Has peers: {}, excluded by another archive height: {}",
						headers_hash_peers.len(),
						self.responded_with_another_height.len()
					),
				));
			}
			return Ok(SyncResponse::new(
				SyncRequestResponses::Syncing,
				Self::get_peer_capabilities(),
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

		if headers_hash_desegmenter.read_recursive().is_complete() {
			let resp = SyncResponse::new(
				SyncRequestResponses::HeadersHashReady,
				Self::get_peer_capabilities(),
				format!("headers_hash_desegmenter is complete"),
			);
			*self.cached_response.write() = Some(CachedResponse::new(
				ArchiveHeightCachedResponse {
					target_archive_height: self.target_archive_height,
					response: resp.clone(),
				},
				Duration::from_secs(180),
			)?);
			return Ok(resp);
		}

		let (completed_blocks, total_blocks, headers_root_hash) = {
			let headers_hash_desegmenter = headers_hash_desegmenter.read_recursive();
			(
				headers_hash_desegmenter.get_segments_completed(),
				headers_hash_desegmenter.get_segments_total(),
				*headers_hash_desegmenter.get_headers_root_hash(),
			)
		};
		sync_state.update(SyncStatus::HeaderHashSync {
			completed_blocks,
			total_blocks,
		});

		let headers_hash_peers = sync_utils::get_qualify_peers(
			peers,
			self.target_archive_height,
			Capabilities::HEADERS_HASH,
		);
		if headers_hash_peers.is_empty() {
			return Ok(SyncResponse::new(SyncRequestResponses::WaitingForPeers, Self::get_peer_capabilities(), format!("No outbound peers with HEADERS_HASH capability. Waiting for Hash responses: {}. Segment responses: {}",
																														  self.requested_headers_hash_from.len(), self.requested_segments.len()) ));
		}

		// Need to request headers under the archive header. We can do that in parallel
		// Requesting more handshakes when have a chance
		let mut request_failures = 0;
		for peer in &headers_hash_peers {
			if !self
				.requested_headers_hash_from
				.contains_key(&peer.info.addr)
				&& !self
					.responded_headers_hash_from
					.contains_key(&peer.info.addr)
				&& !self
					.responded_with_another_height
					.contains_key(&peer.info.addr)
			{
				if !self.request_headers_root_from_peer(
					peer,
					self.target_archive_height,
					sync_peers,
				) {
					request_failures += 1;
				}
			}
		}

		// Clean up expired requests before choosing desired segments so stale
		// in-flight entries do not suppress retries.
		self.requested_segments.retain(|_idx, (peer, time)| {
			if time.elapsed() > request_timeout {
				sync_peers.report_no_response(peer, "header hashes".into());
				return false;
			}
			return true;
		});

		let segments = {
			let mut headers_hash_desegmenter = headers_hash_desegmenter.write();
			headers_hash_desegmenter.next_desired_segments(
				cmp::min(
					headers_hash_peers.len() * self.pibd_params.get_segments_request_per_peer(),
					self.pibd_params.get_segments_requests_limit(None),
				),
				&&self.requested_segments,
			)?
		};

		if !segments.is_empty() {
			// select random peer and request from it...
			let mut peers2send: Vec<Arc<Peer>> = Vec::new();
			for peer in headers_hash_peers.iter().filter(|&p| {
				let peer_adr = &p.info.addr;
				if self.responded_with_another_height.contains_key(peer_adr) {
					return false;
				}
				match self.responded_headers_hash_from.get(peer_adr) {
					Some((peer_headers_root_hash, _)) => {
						*peer_headers_root_hash == headers_root_hash
					}
					None => false,
				}
			}) {
				peers2send.push(peer.clone());
			}

			if peers2send.is_empty() {
				let has_alternative_root = headers_hash_peers.iter().any(|peer| {
					let peer_addr = &peer.info.addr;
					if self.responded_with_another_height.contains_key(peer_addr) {
						return false;
					}
					self.responded_headers_hash_from
						.get(peer_addr)
						.map(|(hash, _)| *hash != headers_root_hash)
						.unwrap_or(false)
				});
				if has_alternative_root {
					self.reset_selected_headers_root();
					return self.request_impl(peers, sync_state, sync_peers, best_height);
				}

				let msg = format!(
					"No peers to request segment. Headers_hash_peers:{}  Waiting segments responses: {}",
					headers_hash_peers.len(),
					self.requested_segments.len()
				);
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Self::get_peer_capabilities(),
					msg,
				));
			}

			let mut rng = rand::rng();

			for seg in segments {
				let leaf_offset = seg.leaf_offset()?;
				debug_assert!(!self
					.requested_segments
					.contains_key(&(HEADER_HASHES_STUB_TYPE, leaf_offset)));

				let peer = peers2send.choose(&mut rng).ok_or(Error::Other(
					"Internal error, unable to select peer".to_string(),
				))?;
				match peer.send_headers_hash_segment_request(headers_root_hash.clone(), seg) {
					Ok(_) => {
						self.requested_segments.insert(
							(HEADER_HASHES_STUB_TYPE, leaf_offset),
							(peer.info.addr.clone(), Instant::now()),
						);
					}
					Err(e) => {
						let msg = format!(
							"Unable to make send_headers_hash_segment_request for {}, Error: {}",
							peer.info.addr, e
						);
						error!("{}", msg);
						sync_peers.report_no_response(&peer.info.addr, msg); // it is expired
						                                   // no retry on error. Will retty on the next cycle.
					}
				}
			}
		}

		let msg = if request_failures > 0 {
			format!(
					"Has peers: {}  Waiting responses: {}. Failed to send headers hash root requests: {}",
					headers_hash_peers.len(),
					self.requested_segments.len(),
					request_failures
				)
		} else {
			format!(
				"Has peers: {}  Waiting responses: {}",
				headers_hash_peers.len(),
				self.requested_segments.len()
			)
		};

		return Ok(SyncResponse::new(
			SyncRequestResponses::Syncing,
			Self::get_peer_capabilities(),
			msg,
		));
	}

	pub fn receive_headers_hash_response(
		&mut self,
		peer: &PeerAddr,
		archive_height: u64,
		headers_hash_root: Hash,
		sync_peers: &SyncPeers,
	) -> HeadersHashResponseStatus {
		if archive_height != self.target_archive_height {
			return HeadersHashResponseStatus::Ignored;
		}
		if self.responded_headers_hash_from.contains_key(peer) {
			return HeadersHashResponseStatus::Ignored;
		}
		if self.requested_headers_hash_from.remove(peer).is_none() {
			let msg = format!(
				"unsolicited headers hash response from {} for archive height {}",
				peer, archive_height
			);
			sync_peers.report_error_response(peer, msg.clone());
			return HeadersHashResponseStatus::Rejected(msg);
		}

		// Adding only once, so attacker will not be able to escape the ban.
		sync_peers.report_ok_response(peer);
		self.responded_headers_hash_from
			.insert(peer.clone(), (headers_hash_root, Instant::now()));
		HeadersHashResponseStatus::Accepted
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
		// HeadersHashSync cannot require a matching local headers-hash request here.
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
		if let Some(headers_hash_desegmenter) = self.headers_hash_desegmenter.as_ref().cloned() {
			if *headers_hash_desegmenter
				.read_recursive()
				.get_headers_root_hash()
				!= header_hashes_root
			{
				return Ok(()); // Skipping this data, might be some old message
			}
			let segm_id = segment.id().clone();
			let leaf_offset = match segm_id.leaf_offset() {
				Ok(leaf_offset) => leaf_offset,
				Err(e) => {
					let msg = format!(
						"receive_header_hashes_segment invalid segment {} from {}: {}",
						segm_id, peer, e
					);
					error!("{}", msg);
					sync_peers.report_error_response(peer, msg);
					return Err(e.into());
				}
			};
			let request_key = (HEADER_HASHES_STUB_TYPE, leaf_offset);
			match self.requested_segments.get(&request_key) {
				Some((requested_peer, _)) if requested_peer == peer => {}
				Some((requested_peer, _)) => {
					let msg = format!(
						"receive_header_hashes_segment from {}, segment {}, was requested from {}",
						peer, segm_id, requested_peer
					);
					error!("{}", msg);
					sync_peers.report_error_response(peer, msg);
					return Ok(());
				}
				None => {
					return Ok(());
				}
			}
			match headers_hash_desegmenter
				.write()
				.add_headers_hash_segment(segment, &header_hashes_root)
			{
				Ok(_) => {
					self.requested_segments.remove(&request_key);
					sync_peers.report_ok_response(peer);
				}
				Err(e) => {
					self.requested_segments.remove(&request_key);
					let msg = format!(
						"receive_header_hashes_segment failed for {}, segment {}. Error: {}",
						peer, segm_id, e
					);
					error!("{}", msg);
					sync_peers.report_error_response(peer, msg);
					return Err(e);
				}
			}
		}
		Ok(())
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
			HeadersHashSync::select_headers_root(roots.iter(), MIN_HEADERS_HASH_ROOT_RESPONSES,),
			HeadersRootSelection::NeedMoreResponses { responses: 1 }
		);
	}

	#[test]
	fn select_headers_root_requires_strict_majority() {
		let root_a = test_hash(1);
		let root_b = test_hash(2);
		let roots = vec![root_a, root_b];

		assert_eq!(
			HeadersHashSync::select_headers_root(roots.iter(), MIN_HEADERS_HASH_ROOT_RESPONSES,),
			HeadersRootSelection::NoQuorum {
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
			HeadersHashSync::select_headers_root(roots.iter(), MIN_HEADERS_HASH_ROOT_RESPONSES,),
			HeadersRootSelection::Selected(root_a)
		);
	}

	#[test]
	fn select_headers_root_rejects_even_split_without_strict_majority() {
		let root_a = test_hash(1);
		let root_b = test_hash(2);
		let roots = vec![root_a, root_a, root_b, root_b];

		assert_eq!(
			HeadersHashSync::select_headers_root(roots.iter(), MIN_HEADERS_HASH_ROOT_RESPONSES + 1,),
			HeadersRootSelection::NoQuorum {
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
			HeadersHashSync::select_headers_root(roots.iter(), MIN_HEADERS_HASH_ROOT_RESPONSES + 1,),
			HeadersRootSelection::NeedMoreResponses { responses: 2 }
		);
	}
}
