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
use crate::mwc::sync::sync_utils::{RequestTracker, SyncRequestResponses, SyncResponse};
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::txhashset::{BitmapChunk, Desegmenter};
use mwc_chain::{self, pibd_params, SyncState};
use mwc_chain::{Chain, SyncStatus};
use mwc_core::core::hash::Hash;
use mwc_core::core::{hash::Hashed, pmmr::segment::SegmentType};
use mwc_core::core::{OutputIdentifier, Segment, SegmentTypeIdentifier, TxKernel};
use mwc_crates::log::{debug, error, info, warn};
use mwc_crates::parking_lot::{RwLock, RwLockReadGuard};
use mwc_crates::rand;
use mwc_crates::rand::prelude::IndexedRandom;
use mwc_crates::rand::prelude::IteratorRandom;
use mwc_crates::secp::pedersen::RangeProof;
use mwc_p2p::{self, Capabilities, Peer};
use mwc_p2p::{Error, PeerAddr};
use mwc_util::StopState;
use std::cmp;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MIN_PIBD_ROOT_RESPONSES: usize = 2;

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
	// Write on initialization/reset. Segment receive paths hold a read guard
	// across validation and segment application so reset cannot invalidate the
	// PIBD session after validation but before the segment is applied.
	desegmenter: RwLock<Option<Arc<Desegmenter>>>,
	reset_desegmenter: AtomicBool,

	// Target height needs to be calculated by the top peers, can be different from headers, it is no problem
	target_archive_height: AtomicU64,
	target_archive_hash: RwLock<Hash>,
	requested_root_hash: RwLock<HashMap<PeerAddr, Instant>>, // Lock 1
	responded_root_hash: RwLock<HashMap<PeerAddr, (Hash, Instant)>>, // Lock 2
	// sync for segments
	request_tracker: RequestTracker<(SegmentType, u64)>,
	is_complete: AtomicBool,
	pibd_params: Arc<PibdParams>,

	last_retry_idx: RwLock<HashMap<SegmentType, u64>>,
	retry_expiration_times: RwLock<VecDeque<Instant>>,

	excluded_peers: RwLock<HashSet<PeerAddr>>,
	send_requests_lock: RwLock<u8>,
}

struct ValidatedDesegmenter<'a> {
	// This guard binds the validation result to the live PIBD session. Without
	// it, reset_desegmenter_data() could clear/replace the current session while
	// the caller still applies a segment through the returned Arc.
	_guard: RwLockReadGuard<'a, Option<Arc<Desegmenter>>>,
	desegmenter: Arc<Desegmenter>,
	root_hash: Hash,
}

struct LiveDesegmenter<'a> {
	// Keep the live session pinned while scheduling segment requests. Resetting
	// the PIBD session starts by taking the desegmenter write lock, so this
	// guard prevents target_archive_hash and request caches from being cleared
	// or replaced while requests are selected, sent, and registered.
	_guard: RwLockReadGuard<'a, Option<Arc<Desegmenter>>>,
	desegmenter: Arc<Desegmenter>,
	archive_hash: Hash,
	root_hash: Hash,
}

impl StateSync {
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
			request_tracker: RequestTracker::new(),
			is_complete: AtomicBool::new(false),
			last_retry_idx: RwLock::new(HashMap::new()),
			retry_expiration_times: RwLock::new(VecDeque::new()),
			excluded_peers: RwLock::new(HashSet::new()),
			send_requests_lock: RwLock::new(0),
		}
	}

	fn get_peer_capabilities() -> Capabilities {
		return Capabilities::PIBD_HIST;
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
		// In case of archive mode, this step is must be skipped. Body sync will catch up.
		if self.is_complete.load(Ordering::Relaxed) || self.chain.archive_mode() {
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
				SyncRequestResponses::WaitingForPeers,
				Self::get_peer_capabilities(),
				format!(
					"best_height={}  target_archive_height={}",
					best_height, target_archive_height
				),
			));
		}

		// check if data is ready
		let head = self.chain.head()?;
		if head.height >= target_archive_height {
			// We are good, no needs to PIBD sync
			info!("No needs to sync, data until archive is ready");
			self.is_complete.store(true, Ordering::Relaxed);
			return Ok(SyncResponse::new(
				SyncRequestResponses::StatePibdReady,
				Capabilities::UNKNOWN,
				format!(
					"head.height={}  target_archive_height={}",
					head.height, target_archive_height
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
					Self::get_peer_capabilities(),
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
		*self.target_archive_hash.write() = archive_header_hash;

		let excluded_peers = self
			.request_tracker
			.retain_expired(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS, sync_peers);
		*self.excluded_peers.write() = excluded_peers;

		// Requesting root_hash...
		let (peers, excluded_requests, excluded_peers) = sync_utils::get_sync_peers(
			in_peers,
			self.pibd_params.get_segments_request_per_peer(),
			Capabilities::PIBD_HIST,
			target_archive_height,
			Some(target_archive_height),
			&self.request_tracker,
			&*self.excluded_peers.read_recursive(),
		);
		if peers.is_empty() {
			if excluded_peers == 0 {
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Self::get_peer_capabilities(),
					format!(
						"No peers to make requests. Waiting Q size: {}",
						self.request_tracker.get_requests_num()
					),
				));
			} else {
				return Ok(SyncResponse::new(
					SyncRequestResponses::Syncing,
					Self::get_peer_capabilities(),
					format!(
						"Has peers: {} Requests in waiting Q: {}",
						excluded_peers,
						self.request_tracker.get_requests_num()
					),
				));
			}
		}

		let now = Instant::now();
		let request_timeout = Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64);
		let mut root_request_failures = 0;

		{
			let mut requested_root_hash = self.requested_root_hash.write();
			let responded_root_hash = self.responded_root_hash.read_recursive();

			// checking to timeouts for handshakes...
			requested_root_hash.retain(|peer, req_time| {
				if req_time.elapsed() > request_timeout {
					sync_peers.report_no_response(peer, "root hash".into());
					return false;
				}
				true
			});

			// request handshakes if needed
			for peer in &peers {
				if !(requested_root_hash.contains_key(&peer.info.addr)
					|| responded_root_hash.contains_key(&peer.info.addr))
				{
					// can request a handshake
					match peer
						.send_start_pibd_sync_request(archive_header.height, archive_header_hash)
					{
						Ok(_) => {
							requested_root_hash.insert(peer.info.addr.clone(), now);
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
							error!("{}", msg);
							sync_peers.report_no_response(&peer.info.addr, msg);
						}
					}
				}
			}
		}

		if self.reset_desegmenter.swap(false, Ordering::Relaxed) {
			self.reset_desegmenter_data();
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
					Self::get_peer_capabilities(),
					format!(
						"Unable to send PIBD root requests. Hash peers: {}, failures: {}",
						peers.len() + excluded_peers,
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
				let required_responses = cmp::max(
					MIN_PIBD_ROOT_RESPONSES,
					(peers.len() + excluded_peers) / 2 + 1,
				);
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
								peers.len() + excluded_peers,
								responses,
								required_responses
							);
							return Ok(SyncResponse::new(
								SyncRequestResponses::WaitingForPeers,
								Self::get_peer_capabilities(),
								msg,
							));
						}
						return Ok(SyncResponse::new(
							SyncRequestResponses::Syncing,
							Self::get_peer_capabilities(),
							format!(
								"Waiting for PIBD root. Hash peers: {} Get respoinses {} from {}",
								peers.len() + excluded_peers,
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
							let response_peers: Vec<PeerAddr> = peers
								.iter()
								.filter_map(|peer| {
									if responded_root_hash.contains_key(&peer.info.addr) {
										Some(peer.info.addr.clone())
									} else {
										None
									}
								})
								.collect();
							let msg = format!(
								concat!(
									"No quorum for PIBD root at archive height {}. ",
									"Hash peers: {}, responses: {}, ",
									"best root responses: {}, required: {}"
								),
								target_archive_height,
								peers.len() + excluded_peers,
								responses,
								best_count,
								required_responses
							);
							drop(requested_root_hash);
							drop(responded_root_hash);
							warn!("{}", msg);
							for peer in &response_peers {
								sync_peers.report_error_response(peer, msg.clone());
							}
							self.requested_root_hash.write().clear();
							self.responded_root_hash.write().clear();
							return Ok(SyncResponse::new(
								SyncRequestResponses::WaitingForPeers,
								Self::get_peer_capabilities(),
								msg,
							));
						}
						return Ok(SyncResponse::new(
							SyncRequestResponses::Syncing,
							Self::get_peer_capabilities(),
							format!(
								"Waiting for PIBD root. Hash peers: {} Get respoinses {} from {}",
								peers.len() + excluded_peers,
								responded_root_hash.len(),
								requested_root_hash.len()
							),
						));
					}
				};

				info!("Creating desegmenter for root hash {}", best_root_hash);
				if let Err(e) = self.chain.reset_pibd_chain() {
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
						if let Err(e) = self.chain.reset_pibd_chain() {
							error!("reset_pibd_chain failed with error: {}", e);
						}
						return Err(e);
					}
				}

				self.request_tracker.clear();
			// continue with requests...
			} else {
				return Ok(SyncResponse::new(
					SyncRequestResponses::Syncing,
					Self::get_peer_capabilities(),
					format!(
						"Waiting for PIBD root. Hash peers: {} Get respoinses {} from {}",
						peers.len() + excluded_peers,
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
					Self::get_peer_capabilities(),
					format!(
						"Restarting because check_update_leaf_set_state failed with error {}",
						e
					),
				));
			}

			// we are pretty good, we can do validation now...
			info!("PIBD state is done, starting validate_complete_state...");
			match desegmenter.validate_complete_state(sync_state, stop_state) {
				Ok(_) => {
					info!("PIBD download and valiadion is done with success!");
					self.is_complete.store(true, Ordering::Relaxed);
					return Ok(SyncResponse::new(
						SyncRequestResponses::StatePibdReady,
						Capabilities::UNKNOWN,
						"PIBD download and validaion is done with success!".into(),
					));
				}
				Err(e) => {
					error!(
						"Restarting because validate_complete_state failed with error {}",
						e
					);
					self.ban_this_session(&session.root_hash, sync_peers);
					return Ok(SyncResponse::new(
						SyncRequestResponses::Syncing,
						Self::get_peer_capabilities(),
						format!(
							"Restarting because validate_complete_state failed with error {}",
							e
						),
					));
				}
			}
		}

		debug_assert!(!desegmenter.is_complete());

		sync_state.update(desegmenter.get_pibd_progress());

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
					Self::get_peer_capabilities(),
					"Banning this PIBD session. Seems like that was a fraud".into(),
				));
			} else {
				if excluded_requests == 0 {
					// Since there are no alternatives, keep waiting...
					return Ok(SyncResponse::new(
						SyncRequestResponses::WaitingForPeers,
						Self::get_peer_capabilities(),
						"No peers that support PIBD.".into(),
					));
				} else {
					return Ok(SyncResponse::new(
						SyncRequestResponses::Syncing,
						Self::get_peer_capabilities(),
						format!(
							"All PIBD peers are busy. Requests in waiting Q: {}",
							self.request_tracker.get_requests_num()
						),
					));
				}
			}
		}

		self.send_requests(
			&root_hash_peers,
			&root_hash_peers,
			excluded_requests,
			excluded_peers,
			&session,
			sync_peers,
		)
	}

	fn ban_this_session(&self, root_hash: &Hash, sync_peers: &SyncPeers) {
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

	pub fn reset_desegmenter_data(&self) {
		// Keep this write lock as the first operation: receive handlers use the
		// desegmenter read guard as the session barrier from validation through
		// segment application.
		*self.desegmenter.write() = None;
		self.requested_root_hash.write().clear();
		self.responded_root_hash.write().clear();
		*self.target_archive_hash.write() = Hash::default();
		self.request_tracker.clear();
		self.last_retry_idx.write().clear();
		self.retry_expiration_times.write().clear();
		self.is_complete.store(false, Ordering::Relaxed);
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
	fn validated_desegmenter(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
	) -> Option<ValidatedDesegmenter<'_>> {
		let guard = self.desegmenter.read_recursive();
		let desegmenter = guard.as_ref().cloned()?;
		if *self.target_archive_hash.read_recursive() != *archive_header_hash {
			return None;
		}

		let hash_for_peer = self.responded_root_hash.read_recursive().get(peer).cloned();
		match hash_for_peer {
			Some((hash, _)) if *desegmenter.get_bitmap_root_hash() == hash => {
				Some(ValidatedDesegmenter {
					_guard: guard,
					desegmenter,
					root_hash: hash,
				})
			}
			_ => None,
		}
	}

	fn live_desegmenter(&self) -> Option<LiveDesegmenter<'_>> {
		let guard = self.desegmenter.read_recursive();
		let desegmenter = guard.as_ref().cloned()?;
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

	// Return true if the response came from the registered peer.
	fn track_and_request_more_segments(
		&self,
		key: &(SegmentType, u64),
		peer: &PeerAddr,
		peers: &Arc<mwc_p2p::Peers>,
		sync_peers: &SyncPeers,
		accepted_response: bool,
	) -> bool {
		let registered_peer = if accepted_response {
			self.request_tracker.remove_request_by_key(key, peer)
		} else {
			self.request_tracker.remove_request(key, peer)
		};
		let matched_request = registered_peer
			.as_ref()
			.map_or(false, |registered_peer| registered_peer == peer);
		let resolved_request = registered_peer.is_some() && (accepted_response || matched_request);

		if !resolved_request {
			return matched_request;
		}

		if self.request_tracker.get_update_requests_to_next_ask() == 0 {
			let target_archive_height = self.target_archive_height.load(Ordering::Relaxed);
			let (peers, excluded_requests, excluded_peers) = sync_utils::get_sync_peers(
				peers,
				self.pibd_params.get_segments_request_per_peer(),
				Capabilities::PIBD_HIST,
				target_archive_height,
				Some(target_archive_height),
				&self.request_tracker,
				&*self.excluded_peers.read_recursive(),
			);
			if peers.is_empty() {
				return matched_request;
			}

			if let Some(session) = self.live_desegmenter() {
				let desegmenter = session.desegmenter.as_ref();
				if !desegmenter.is_complete() {
					// let's check what peers with root hash are exist
					let mut root_hash_peers: Vec<Arc<Peer>> = Vec::new();
					for p in peers {
						let addr = &p.info.addr;
						if let Some((hash, _)) = self.responded_root_hash.read_recursive().get(addr)
						{
							if hash == &session.root_hash {
								root_hash_peers.push(p.clone());
							}
						}
					}

					if root_hash_peers.is_empty() {
						return matched_request;
					}

					// Follow-up request scheduling can fail because local PIBD sync
					// state changed while processing this segment. These failures are
					// recoverable: the regular sync loop will retry scheduling, so do
					// not propagate the error to the p2p receive path and disconnect
					// the peer that sent the segment.
					if let Err(e) = self.send_requests(
						&root_hash_peers,
						&root_hash_peers,
						excluded_requests,
						excluded_peers,
						&session,
						sync_peers,
					) {
						info!("Failed to request more PIBD segments. Error: {}", e);
					}
				}
			}
		}

		matched_request
	}

	pub fn receive_bitmap_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<BitmapChunk>,
		peers: &Arc<mwc_p2p::Peers>,
		sync_peers: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		let key = (SegmentType::Bitmap, segment.leaf_offset()?);
		let mut accepted_segment = false;

		if let Some(validated) = self.validated_desegmenter(peer, archive_header_hash) {
			let res = validated
				.desegmenter
				.add_bitmap_segment(segment, &validated.root_hash);
			drop(validated);
			match res {
				Ok(_) => {
					accepted_segment = true;
				}
				Err(e) => {
					// Be conservative with bitmap segment failures: count every
					// add_bitmap_segment error against the responding peer. This is
					// only an error report for peer scoring, not an immediate ban.
					let msg = format!(
						"For Peer {}, add_bitmap_segment failed with error: {}",
						peer, e
					);
					error!("{}", msg);
					sync_peers.report_error_response(peer, msg);
				}
			}
		} else {
			sync_peers
				.report_error_response(peer, "bitmap_segment, validate_root_hash failure".into());
		}

		let matched_request =
			self.track_and_request_more_segments(&key, peer, peers, sync_peers, accepted_segment);
		if accepted_segment && matched_request {
			sync_peers.report_ok_response(peer);
		}
		Ok(())
	}

	pub fn receive_output_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<OutputIdentifier>,
		peers: &Arc<mwc_p2p::Peers>,
		sync_peers: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		let key = (SegmentType::Output, segment.leaf_offset()?);
		let mut accepted_segment = false;

		// Be conservative here: every output-segment failure is counted against
		// the peer. Reporting an error only feeds peer scoring; it is not an
		// immediate ban.
		if let Some(validated) = self.validated_desegmenter(peer, archive_header_hash) {
			let res = validated
				.desegmenter
				.add_output_segment(segment, &validated.root_hash);
			drop(validated);
			match res {
				Ok(_) => {
					accepted_segment = true;
				}
				Err(e) => {
					let msg = format!(
						"For Peer {}, add_output_segment failed with error: {}",
						peer, e
					);
					error!("{}", msg);
					sync_peers.report_error_response(peer, msg);
				}
			}
		} else {
			sync_peers.report_error_response(peer, "validate_root_hash failed".into());
		}

		let matched_request =
			self.track_and_request_more_segments(&key, peer, peers, sync_peers, accepted_segment);
		if accepted_segment && matched_request {
			sync_peers.report_ok_response(peer);
		}
		Ok(())
	}

	pub fn receive_rangeproof_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<RangeProof>,
		peers: &Arc<mwc_p2p::Peers>,
		sync_peers: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		let key = (SegmentType::RangeProof, segment.leaf_offset()?);
		let mut accepted_segment = false;

		// Process first, unregister after. During unregister we might issue more requests.
		if let Some(validated) = self.validated_desegmenter(peer, archive_header_hash) {
			let res = validated
				.desegmenter
				.add_rangeproof_segment(segment, &validated.root_hash);
			drop(validated);
			match res {
				Ok(_) => {
					accepted_segment = true;
				}
				Err(e) => {
					// add_rangeproof_segment can fail because the peer sent a bad
					// segment, but it can also fail for local PIBD/txhashset recovery
					// issues. State sync handles this as best effort: do not propagate
					// the sync error and risk disconnecting from the peer. Log it and
					// report an error response so PIBD peer scoring can penalize the
					// peer when bad responses repeat.
					let msg = format!(
						"For Peer {}, add_rangeproof_segment failed with error: {}",
						peer, e
					);
					error!("{}", msg);
					sync_peers.report_error_response(peer, msg);
				}
			}
		} else {
			sync_peers.report_error_response(peer, "validate_root_hash error".into());
		}

		let matched_request =
			self.track_and_request_more_segments(&key, peer, peers, sync_peers, accepted_segment);
		if accepted_segment && matched_request {
			sync_peers.report_ok_response(peer);
		}
		Ok(())
	}

	pub fn receive_kernel_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<TxKernel>,
		peers: &Arc<mwc_p2p::Peers>,
		sync_peers: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		let key = (SegmentType::Kernel, segment.leaf_offset()?);
		let mut accepted_segment = false;

		if let Some(validated) = self.validated_desegmenter(peer, archive_header_hash) {
			let res = validated
				.desegmenter
				.add_kernel_segment(segment, &validated.root_hash);
			drop(validated);
			match res {
				Ok(_) => {
					accepted_segment = true;
				}
				Err(e) => {
					// add_kernel_segment can fail both for bad peer data and for
					// local PIBD/txhashset recovery issues. State sync intentionally
					// does not classify those errors here: logging and reporting any
					// segment-apply failure against the peer keeps this receive path
					// simple, and that broad peer penalty is acceptable for PIBD sync.
					let msg = format!(
						"For Peer {}, add_kernel_segment failed with error: {}",
						peer, e
					);
					error!("{}", msg);
					sync_peers.report_error_response(peer, msg);
				}
			}
		} else {
			sync_peers.report_error_response(peer, "validate_root_hash failed".into());
		}

		let matched_request =
			self.track_and_request_more_segments(&key, peer, peers, sync_peers, accepted_segment);
		if accepted_segment && matched_request {
			sync_peers.report_ok_response(peer);
		}
		Ok(())
	}

	fn send_request(
		peer: &Arc<Peer>,
		segment: &SegmentTypeIdentifier,
		target_archive_hash: &Hash,
	) -> Result<(), Error> {
		let send_res = match segment.segment_type {
			SegmentType::Bitmap => {
				peer.send_bitmap_segment_request(target_archive_hash.clone(), segment.identifier)
			}
			SegmentType::Output => {
				peer.send_output_segment_request(target_archive_hash.clone(), segment.identifier)
			}
			SegmentType::RangeProof => peer
				.send_rangeproof_segment_request(target_archive_hash.clone(), segment.identifier),
			SegmentType::Kernel => {
				peer.send_kernel_segment_request(target_archive_hash.clone(), segment.identifier)
			}
		};
		send_res
	}

	fn push_retry_expiration(&self, now: Instant) -> Result<(), mwc_chain::Error> {
		let retry_latency = self.request_tracker.get_retry_latency();
		let retry_expiration = now.checked_add(retry_latency).ok_or_else(|| {
			mwc_chain::Error::DataOverflow(format!(
				"StateSync retry latency exceeds representable Instant range: {:?}",
				retry_latency
			))
		})?;

		self.retry_expiration_times
			.write()
			.push_back(retry_expiration);
		Ok(())
	}

	fn calc_retry_running_requests(&self) -> usize {
		let now = Instant::now();
		let mut retry_expiration_times = self.retry_expiration_times.write();
		while !retry_expiration_times.is_empty() {
			if retry_expiration_times[0] < now {
				retry_expiration_times.pop_front();
			} else {
				break;
			}
		}
		retry_expiration_times.len()
	}

	fn send_requests(
		&self,
		peers: &Vec<Arc<Peer>>,
		root_hash_peers: &Vec<Arc<Peer>>,
		excluded_requests: usize,
		excluded_peers: usize,
		session: &LiveDesegmenter<'_>,
		sync_peers: &SyncPeers,
	) -> Result<SyncResponse, mwc_chain::Error> {
		let desegmenter = session.desegmenter.as_ref();
		if let Some(_) = self.send_requests_lock.try_write() {
			let average_latency_ms = self.request_tracker.get_average_latency_ms();
			let mut need_request = self.request_tracker.calculate_needed_requests(
				root_hash_peers.len(),
				excluded_requests,
				excluded_peers,
				self.pibd_params.get_segments_request_per_peer(),
				self.pibd_params
					.get_segments_requests_limit(average_latency_ms),
			);
			need_request = need_request.saturating_sub(self.calc_retry_running_requests());
			if need_request > 0 {
				match desegmenter.next_desired_segments(need_request, &self.request_tracker) {
					Ok((req_segments, retry_segments, waiting_segments)) => {
						let mut rng = rand::rng();
						let now = Instant::now();
						let target_archive_hash = &session.archive_hash;

						if !retry_segments.is_empty() {
							let last_retry_idx = self.last_retry_idx.try_write();
							if let Some(mut last_retry_idx) = last_retry_idx {
								for segm in &retry_segments {
									let leaf_offset = segm.identifier.leaf_offset()?;
									let retry_idx = last_retry_idx
										.get(&segm.segment_type)
										.cloned()
										.unwrap_or(0);

									if leaf_offset <= retry_idx {
										continue;
									}

									if need_request == 0 {
										break;
									}

									// We don't want to send retry to the peer whom we already send the data
									if let Some(requested_peer) =
										self.request_tracker.get_expected_peer(&(
											segm.segment_type.clone(),
											leaf_offset,
										)) {
										let dup_peers: Vec<Arc<Peer>> = peers
											.iter()
											.filter(|p| p.info.addr != requested_peer)
											.cloned()
											.sample(&mut rng, 2);

										if dup_peers.len() == 0 {
											break;
										}

										if need_request < dup_peers.len() {
											need_request = 0;
											break;
										}
										// Safe: need_request was checked against dup_peers.len() above.
										need_request -= dup_peers.len();

										// we can do retry now
										for p in dup_peers {
											debug!("Processing duplicated request for the segment {:?} at {}, peer {:?}", segm.segment_type, leaf_offset, p.info.addr);
											match Self::send_request(&p, &segm, target_archive_hash)
											{
												Ok(_) => {
													self.push_retry_expiration(now)?;
												}
												Err(e) => {
													let msg = format!("Failed to send duplicate segment {:?} at {}, peer {:?}, Error: {}", segm.segment_type, leaf_offset, p.info.addr, e);
													error!("{}", msg);
													sync_peers
														.report_no_response(&p.info.addr, msg);
													break;
												}
											}
										}
									}

									(*last_retry_idx)
										.insert(segm.segment_type.clone(), leaf_offset);
								}
							}
						}

						for seg in req_segments {
							if need_request == 0 {
								break;
							}
							// Safe: need_request == 0 is handled above.
							need_request -= 1;

							let key = (seg.segment_type.clone(), seg.identifier.leaf_offset()?);
							debug_assert!(!self.request_tracker.has_request(&key));
							debug_assert!(!root_hash_peers.is_empty());
							// Pick a peer randomly for each segment. Preferring the fastest
							// or otherwise "best" peer would let an attacker run low-latency
							// peers and attract most PIBD traffic. Random selection reduces
							// that manipulation risk, even if the overall sync is slower.
							let peer =
								root_hash_peers
									.choose(&mut rng)
									.ok_or(mwc_chain::Error::Other(
										"Internal error, peers data is empty".into(),
									))?;

							let send_res = Self::send_request(peer, &seg, target_archive_hash);
							match send_res {
								Ok(_) => {
									let msg = format!("{:?}", key);
									self.request_tracker.register_request(
										key,
										peer.info.addr.clone(),
										msg,
									);
								}
								Err(e) => {
									let msg = format!(
										"Error sending segment request to peer at {}, reason: {:?}",
										peer.info.addr, e
									);
									info!("{}", msg);
									sync_peers.report_no_response(&peer.info.addr, msg);
								}
							}
						}

						if need_request > 0 {
							// If nothing to do, there are some requests are available. We can use them for more duplicates
							let duplicate_reqs: Vec<SegmentTypeIdentifier> = waiting_segments
								.sample(&mut rng, need_request)
								.cloned()
								.collect();

							for segm in &duplicate_reqs {
								let leaf_offset = segm.identifier.leaf_offset()?;
								// We don't want to send retry to the peer whom we already send the data
								if let Some(requested_peer) = self
									.request_tracker
									.get_expected_peer(&(segm.segment_type.clone(), leaf_offset))
								{
									let dup_peer = peers
										.iter()
										.filter(|p| p.info.addr != requested_peer)
										.choose(&mut rng);

									match dup_peer {
										None => break,
										Some(dup_peer) => {
											debug!("Processing duplicated request for the segment {:?} at {}, peer {:?}", segm.segment_type, leaf_offset, dup_peer.info.addr);
											match Self::send_request(
												&dup_peer,
												&segm,
												target_archive_hash,
											) {
												Ok(_) => {
													self.push_retry_expiration(now)?;
												}
												Err(e) => {
													let msg = format!("Failed to send duplicate segment {:?} at {}, peer {:?}, Error: {}", segm.segment_type, leaf_offset, dup_peer.info.addr, e);
													error!("{}", msg);
													sync_peers.report_no_response(
														&dup_peer.info.addr,
														msg,
													);
													break;
												}
											}
										}
									}
								}
							}
						}

						return Ok(SyncResponse::new(
							SyncRequestResponses::Syncing,
							Self::get_peer_capabilities(),
							format!(
								"Has peers: {} Requests in waiting Q: {}",
								root_hash_peers.len() + excluded_peers,
								self.request_tracker.get_requests_num()
							),
						));
					}
					Err(err) => {
						error!("Failed to request more segments. Error: {}", err);
						// Be super conservative here. Any desegmenter request-planning
						// error is treated as critical for this PIBD session, so ban all
						// participants for the selected root hash and start over.
						self.ban_this_session(&session.root_hash, sync_peers);
						return Ok(SyncResponse::new(
							SyncRequestResponses::Syncing,
							Self::get_peer_capabilities(),
							format!("Failed to request more segments. Error: {}", err),
						));
					}
				}
			}
		}
		// waiting for responses...
		return Ok(SyncResponse::new(
			SyncRequestResponses::Syncing,
			Self::get_peer_capabilities(),
			format!(
				"Has peers {}, Requests in waiting Q: {}",
				root_hash_peers.len() + excluded_peers,
				self.request_tracker.get_requests_num()
			),
		));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_hash(value: u8) -> Hash {
		Hash::from_vec(&[value; Hash::LEN])
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
