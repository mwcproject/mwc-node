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

use crate::chain::{self, pibd_params, SyncState};
use crate::core::core::{hash::Hashed, pmmr::segment::SegmentType};
use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils;
use crate::mwc::sync::sync_utils::{RequestTracker, SyncRequestResponses, SyncResponse};
use crate::p2p::{self, Capabilities, Peer};
use crate::util::StopState;
use chrono::prelude::{DateTime, Utc};
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::txhashset::{BitmapChunk, Desegmenter};
use mwc_chain::{Chain, SyncStatus};
use mwc_core::core::hash::Hash;
use mwc_core::core::{OutputIdentifier, Segment, SegmentTypeIdentifier, TxKernel};
use mwc_p2p::{Error, PeerAddr};
use mwc_util::secp::pedersen::RangeProof;
use mwc_util::RwLock;
use rand::prelude::IteratorRandom;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Fast sync has 3 "states":
/// * syncing headers
/// * once all headers are sync'd, requesting the txhashset state
/// * once we have the state, get blocks after that
///
/// The StateSync struct implements and monitors the middle step.
pub struct StateSync {
	chain: Arc<Chain>,
	desegmenter: RwLock<Option<Desegmenter>>, // Expected to have write only for initializetion. Then always read.
	reset_desegmenter: AtomicBool,

	// Target height needs to be calculated by the top peers, can be different from headers, it is no problem
	target_archive_height: AtomicU64,
	target_archive_hash: RwLock<Hash>,
	requested_root_hash: RwLock<HashMap<PeerAddr, DateTime<Utc>>>, // Lock 1
	responded_root_hash: RwLock<HashMap<PeerAddr, (Hash, DateTime<Utc>)>>, // Lock 2
	responded_with_another_height: RwLock<HashSet<PeerAddr>>,      // Lock 3
	// sync for segments
	request_tracker: RequestTracker<(SegmentType, u64)>,
	is_complete: AtomicBool,
	pibd_params: Arc<PibdParams>,

	last_retry_idx: RwLock<HashMap<SegmentType, u64>>,
	retry_expiration_times: RwLock<VecDeque<DateTime<Utc>>>,

	excluded_peers: RwLock<HashSet<PeerAddr>>,
	send_requests_lock: RwLock<u8>,
}

impl StateSync {
	pub fn new(chain: Arc<chain::Chain>) -> StateSync {
		StateSync {
			pibd_params: chain.get_pibd_params().clone(),
			chain,
			desegmenter: RwLock::new(None),
			reset_desegmenter: AtomicBool::new(false),
			target_archive_height: AtomicU64::new(0),
			target_archive_hash: RwLock::new(Hash::default()),
			requested_root_hash: RwLock::new(HashMap::new()),
			responded_root_hash: RwLock::new(HashMap::new()),
			responded_with_another_height: RwLock::new(HashSet::new()),
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

	pub fn request(
		&self,
		in_peers: &Arc<p2p::Peers>,
		sync_state: Arc<SyncState>,
		sync_peers: &SyncPeers,
		stop_state: Arc<StopState>,
		best_height: u64,
	) -> SyncResponse {
		// In case of archive mode, this step is must be skipped. Body sync will catch up.
		if self.is_complete.load(Ordering::Relaxed) || self.chain.archive_mode() {
			return SyncResponse::new(
				SyncRequestResponses::StatePibdReady,
				Capabilities::UNKNOWN,
				"".into(),
			);
		}

		// Let's check if we need to calculate/update archive height.
		let target_archive_height = Chain::height_2_archive_height(best_height);

		// Event it is not atomic operation, it is safe because request called from a single thread
		if self.target_archive_height.load(Ordering::Relaxed) != target_archive_height {
			// total reset, nothing needs to be saved...
			self.reset_desegmenter_data();
			// Resetting all internal state, starting from the scratch
			self.target_archive_height
				.store(target_archive_height, Ordering::Relaxed);
		}

		if target_archive_height == 0 {
			return SyncResponse::new(
				SyncRequestResponses::WaitingForPeers,
				Self::get_peer_capabilities(),
				format!(
					"best_height={}  target_archive_height={}",
					best_height, target_archive_height
				),
			);
		}

		// check if data is ready
		if let Ok(head) = self.chain.head() {
			if head.height >= target_archive_height {
				// We are good, no needs to PIBD sync
				info!("No needs to sync, data until archive is ready");
				self.is_complete.store(true, Ordering::Relaxed);
				return SyncResponse::new(
					SyncRequestResponses::StatePibdReady,
					Capabilities::UNKNOWN,
					format!(
						"head.height={}  target_archive_height={}",
						head.height, target_archive_height
					),
				);
			}
		}

		// Checking if archive header is already in the chain
		let archive_header = match self.chain.get_header_by_height(target_archive_height) {
			Ok(archive_header) => archive_header,
			Err(_) => {
				return SyncResponse::new(
					SyncRequestResponses::WaitingForHeaders,
					Self::get_peer_capabilities(),
					format!("Header at height {} doesn't exist", target_archive_height),
				);
			}
		};

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
			&self.request_tracker,
			&*self.excluded_peers.read(),
		);
		if peers.is_empty() {
			if excluded_peers == 0 {
				return SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Self::get_peer_capabilities(),
					format!(
						"No peers to make requests. Waiting Q size: {}",
						self.request_tracker.get_requests_num()
					),
				);
			} else {
				return SyncResponse::new(
					SyncRequestResponses::Syncing,
					Self::get_peer_capabilities(),
					format!(
						"Has peers: {} Requests in waiting Q: {}",
						excluded_peers,
						self.request_tracker.get_requests_num()
					),
				);
			}
		}

		let now = Utc::now();

		{
			let mut requested_root_hash = self.requested_root_hash.write();
			let responded_root_hash = self.responded_root_hash.read();
			let responded_with_another_height = self.responded_with_another_height.read();

			// checking to timeouts for handshakes...
			requested_root_hash.retain(|peer, req_time| {
				if (now - *req_time).num_seconds() > pibd_params::PIBD_REQUESTS_TIMEOUT_SECS {
					sync_peers.report_no_response(peer, "root hash".into());
					return false;
				}
				true
			});

			// request handshakes if needed
			for peer in &peers {
				if !(requested_root_hash.contains_key(&peer.info.addr)
					|| responded_root_hash.contains_key(&peer.info.addr)
					|| responded_with_another_height.contains(&peer.info.addr))
				{
					// can request a handshake
					match peer
						.send_start_pibd_sync_request(archive_header.height, archive_header.hash())
					{
						Ok(_) => {
							requested_root_hash.insert(peer.info.addr.clone(), now.clone());
						}
						Err(e) => {
							error!("send_start_pibd_sync_request failed with error: {}", e);
						}
					}
				}
			}
		}

		if self.reset_desegmenter.swap(false, Ordering::Relaxed) {
			self.reset_desegmenter_data();
		}

		// Checking if need to init desegmenter
		if self.desegmenter.read().is_none() {
			sync_state.update(SyncStatus::TxHashsetPibd {
				recieved_segments: 0,
				total_segments: 100,
			});
			let mut first_request = now;
			let requested_root_hash = self.requested_root_hash.read();
			let responded_root_hash = self.responded_root_hash.read();

			for (_, (_, time)) in &*responded_root_hash {
				if *time < first_request {
					first_request = *time;
				}
			}

			if !responded_root_hash.is_empty()
				&& ((responded_root_hash.len() >= requested_root_hash.len()
					&& responded_root_hash.len() > 1)
					|| (now - first_request).num_seconds()
						> pibd_params::PIBD_REQUESTS_TIMEOUT_SECS / 2)
			{
				// We can elect the group with a most representative hash
				let mut hash_counts: HashMap<Hash, i32> = HashMap::new();
				for (_, (hash, _)) in &*responded_root_hash {
					hash_counts.insert(hash.clone(), hash_counts.get(hash).unwrap_or(&0) + 1);
				}
				// selecting hash with max value
				debug_assert!(!hash_counts.is_empty());
				let (best_root_hash, _) = hash_counts
					.iter()
					.max_by_key(|&(_, count)| count)
					.expect("hash_counts is empty?");

				info!("Creating desegmenter for root hash {}", best_root_hash);

				if let Err(e) = self.chain.reset_pibd_chain() {
					let msg = format!(
						"Failed to reset chain before start BIPD state sync. Error: {}",
						e
					);
					error!("{}", msg);
					return SyncResponse::new(
						SyncRequestResponses::Syncing,
						Self::get_peer_capabilities(),
						msg,
					);
				}
				match self
					.chain
					.init_desegmenter(archive_header.height, best_root_hash.clone())
				{
					Ok(desegmenter) => {
						*self.target_archive_hash.write() = archive_header.hash();
						*self.desegmenter.write() = Some(desegmenter);
					}
					Err(e) => {
						error!("Failed to create PIBD desgmenter, {}", e);
						// let's try to reset everything...
						if let Err(e) = self.chain.reset_pibd_chain() {
							error!("reset_pibd_chain failed with error: {}", e);
						}
						return SyncResponse::new(
							SyncRequestResponses::Syncing,
							Self::get_peer_capabilities(),
							format!("Failed to create PIBD desgmenter, {}", e),
						);
					}
				}

				self.request_tracker.clear();
			// continue with requests...
			} else {
				return SyncResponse::new(
					SyncRequestResponses::Syncing,
					Self::get_peer_capabilities(),
					format!(
						"Waiting for PIBD root. Hash peers: {} Get respoinses {} from {}",
						peers.len() + excluded_peers as usize,
						responded_root_hash.len(),
						requested_root_hash.len()
					),
				);
			}
		}

		let desegmenter = self.desegmenter.read();
		debug_assert!(desegmenter.is_some());
		let desegmenter = desegmenter
			.as_ref()
			.expect("Desegmenter must be created at this point");

		if desegmenter.is_complete() {
			info!("PIBD state is done, starting check_update_leaf_set_state...");
			if let Err(e) = desegmenter.check_update_leaf_set_state() {
				error!(
					"Restarting because check_update_leaf_set_state failed with error {}",
					e
				);
				self.ban_this_session(desegmenter.get_bitmap_root_hash(), sync_peers);
				return SyncResponse::new(
					SyncRequestResponses::Syncing,
					Self::get_peer_capabilities(),
					format!(
						"Restarting because check_update_leaf_set_state failed with error {}",
						e
					),
				);
			}

			// we are pretty good, we can do validation now...
			info!("PIBD state is done, starting validate_complete_state...");
			match desegmenter.validate_complete_state(sync_state, stop_state, self.chain.secp()) {
				Ok(_) => {
					info!("PIBD download and valiadion is done with success!");
					self.is_complete.store(true, Ordering::Relaxed);
					return SyncResponse::new(
						SyncRequestResponses::StatePibdReady,
						Capabilities::UNKNOWN,
						"PIBD download and validaion is done with success!".into(),
					);
				}
				Err(e) => {
					error!(
						"Restarting because validate_complete_state failed with error {}",
						e
					);
					self.ban_this_session(desegmenter.get_bitmap_root_hash(), sync_peers);
					return SyncResponse::new(
						SyncRequestResponses::Syncing,
						Self::get_peer_capabilities(),
						format!(
							"Restarting because validate_complete_state failed with error {}",
							e
						),
					);
				}
			}
		}

		debug_assert!(!desegmenter.is_complete());

		sync_state.update(desegmenter.get_pibd_progress());

		// let's check what peers with root hash are exist
		let root_hash = desegmenter.get_bitmap_root_hash();
		let mut root_hash_peers: Vec<Arc<Peer>> = Vec::new();
		let mut other_hashes = 0;
		for p in peers {
			let addr = &p.info.addr;
			if self.responded_with_another_height.read().contains(addr) {
				continue;
			}
			if let Some((hash, _)) = self.responded_root_hash.read().get(addr) {
				if hash == root_hash {
					root_hash_peers.push(p.clone());
				} else {
					other_hashes += 1;
				}
			}
		}

		if root_hash_peers.is_empty() {
			if other_hashes > 0 {
				// no peers commited to hash, resetting download process if we have alternatives.
				// Sinse there are other groups, treating that as attack. Banning all supporters
				self.ban_this_session(desegmenter.get_bitmap_root_hash(), sync_peers);
				return SyncResponse::new(
					SyncRequestResponses::Syncing,
					Self::get_peer_capabilities(),
					"Banning this PIBD session. Seems like that was a fraud".into(),
				);
			} else {
				if excluded_requests == 0 {
					// Since there are no alternatives, keep waiting...
					return SyncResponse::new(
						SyncRequestResponses::WaitingForPeers,
						Self::get_peer_capabilities(),
						"No peers that support PIBD.".into(),
					);
				} else {
					return SyncResponse::new(
						SyncRequestResponses::Syncing,
						Self::get_peer_capabilities(),
						format!(
							"All PIBD peers are busy. Requests in waiting Q: {}",
							self.request_tracker.get_requests_num()
						),
					);
				}
			}
		}

		self.send_requests(
			&root_hash_peers,
			&root_hash_peers,
			excluded_requests,
			excluded_peers,
			desegmenter,
			sync_peers,
		)
	}

	fn ban_this_session(&self, root_hash: &Hash, sync_peers: &SyncPeers) {
		error!("Banning all peers joind for root hash {}", root_hash);
		// Banning all peers that was agree with that hash...
		{
			let responded_root_hash = self.responded_root_hash.read();
			for (peer, (hash, _)) in &*responded_root_hash {
				if *hash == *root_hash {
					sync_peers.ban_peer(peer, "bad root hash".into());
				}
			}
		}
		self.reset_desegmenter.store(true, Ordering::Relaxed);
	}

	pub fn reset_desegmenter_data(&self) {
		*self.desegmenter.write() = None;
		self.requested_root_hash.write().clear();
		self.responded_root_hash.write().clear();
		self.responded_with_another_height.write().clear();
		self.request_tracker.clear();
		self.is_complete.store(false, Ordering::Relaxed);
	}

	pub fn recieve_pibd_status(
		&self,
		peer: &PeerAddr,
		_header_hash: Hash,
		header_height: u64,
		output_bitmap_root: Hash,
	) {
		// Only one commitment allowed per peer.
		if self.responded_root_hash.read().contains_key(peer)
			|| header_height != self.target_archive_height.load(Ordering::Relaxed)
		{
			return;
		}

		self.responded_root_hash
			.write()
			.insert(peer.clone(), (output_bitmap_root, Utc::now()));
	}

	pub fn recieve_another_archive_header(
		&self,
		peer: &PeerAddr,
		_header_hash: &Hash,
		header_height: u64,
	) {
		if header_height == self.target_archive_height.load(Ordering::Relaxed) {
			return;
		}
		self.responded_with_another_height
			.write()
			.insert(peer.clone());
	}

	// return Some root hash if validation was successfull
	fn validate_root_hash(&self, peer: &PeerAddr, archive_header_hash: &Hash) -> Option<Hash> {
		let desegmenter = self.desegmenter.read();
		if desegmenter.is_none() || *self.target_archive_hash.read() != *archive_header_hash {
			return None;
		}

		let hash_for_peer = self.responded_root_hash.read().get(peer).cloned();
		match hash_for_peer {
			Some((hash, _)) => {
				if *desegmenter.as_ref().unwrap().get_bitmap_root_hash() == hash {
					return Some(hash);
				}
			}
			None => {}
		}
		None
	}

	fn is_expected_peer(&self, key: &(SegmentType, u64), peer: &PeerAddr) -> bool {
		if let Some(p) = self.request_tracker.get_expected_peer(key) {
			*peer == p
		} else {
			false
		}
	}

	// return true if peer matched registered, so we get response from whom it was requested
	fn track_and_request_more_segments(
		&self,
		key: &(SegmentType, u64),
		peer: &PeerAddr,
		peers: &Arc<p2p::Peers>,
		sync_peers: &SyncPeers,
	) {
		let _ = self.request_tracker.remove_request(key, peer);

		if self.request_tracker.get_update_requests_to_next_ask() == 0 {
			let (peers, excluded_requests, excluded_peers) = sync_utils::get_sync_peers(
				peers,
				self.pibd_params.get_segments_request_per_peer(),
				Capabilities::PIBD_HIST,
				self.target_archive_height.load(Ordering::Relaxed),
				&self.request_tracker,
				&*self.excluded_peers.read(),
			);
			if peers.is_empty() {
				return;
			}

			let desegmenter = self.desegmenter.read();
			if let Some(desegmenter) = desegmenter.as_ref() {
				if !desegmenter.is_complete() {
					// let's check what peers with root hash are exist
					let root_hash = desegmenter.get_bitmap_root_hash();
					let mut root_hash_peers: Vec<Arc<Peer>> = Vec::new();
					for p in peers {
						let addr = &p.info.addr;
						if self.responded_with_another_height.read().contains(addr) {
							continue;
						}
						if let Some((hash, _)) = self.responded_root_hash.read().get(addr) {
							if hash == root_hash {
								root_hash_peers.push(p.clone());
							}
						}
					}

					if root_hash_peers.is_empty() {
						return;
					}

					let _ = self.send_requests(
						&root_hash_peers,
						&root_hash_peers,
						excluded_requests,
						excluded_peers,
						desegmenter,
						sync_peers,
					);
				}
			}
		}
	}

	pub fn receive_bitmap_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<BitmapChunk>,
		peers: &Arc<p2p::Peers>,
		sync_peers: &SyncPeers,
	) {
		let key = (SegmentType::Bitmap, segment.leaf_offset());
		let expected_peer = self.is_expected_peer(&key, peer);

		if let Some(root_hash) = self.validate_root_hash(peer, archive_header_hash) {
			let desegmenter = self.desegmenter.read();
			let desegmenter = desegmenter
				.as_ref()
				.expect("Desegmenter must exist at this point");
			match desegmenter.add_bitmap_segment(segment, &root_hash) {
				Ok(_) => {
					if expected_peer {
						sync_peers.report_ok_response(peer);
					}
				}
				Err(e) => {
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

		self.track_and_request_more_segments(&key, peer, peers, sync_peers);
	}

	pub fn receive_output_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<OutputIdentifier>,
		peers: &Arc<p2p::Peers>,
		sync_peers: &SyncPeers,
	) {
		let key = (SegmentType::Output, segment.leaf_offset());
		let expected_peer = self.is_expected_peer(&key, peer);

		if let Some(root_hash) = self.validate_root_hash(peer, archive_header_hash) {
			let desegmenter = self.desegmenter.read();
			let desegmenter = desegmenter
				.as_ref()
				.expect("Desegmenter must exist at this point");
			match desegmenter.add_output_segment(segment, &root_hash) {
				Ok(_) => {
					if expected_peer {
						sync_peers.report_ok_response(peer);
					}
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

		self.track_and_request_more_segments(&key, peer, peers, sync_peers);
	}

	pub fn receive_rangeproof_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<RangeProof>,
		peers: &Arc<p2p::Peers>,
		sync_peers: &SyncPeers,
	) {
		let key = (SegmentType::RangeProof, segment.leaf_offset());
		let expected_peer = self.is_expected_peer(&key, peer);

		// Process first, unregister after. During unregister we might issue more requests.
		if let Some(root_hash) = self.validate_root_hash(peer, archive_header_hash) {
			let desegmenter = self.desegmenter.read();
			let desegmenter = desegmenter
				.as_ref()
				.expect("Desegmenter must exist at this point");
			match desegmenter.add_rangeproof_segment(segment, &root_hash) {
				Ok(_) => {
					if expected_peer {
						sync_peers.report_ok_response(peer);
					}
				}
				Err(e) => {
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

		self.track_and_request_more_segments(&key, peer, peers, sync_peers);
	}

	pub fn receive_kernel_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<TxKernel>,
		peers: &Arc<p2p::Peers>,
		sync_peers: &SyncPeers,
	) {
		let key = (SegmentType::Kernel, segment.leaf_offset());
		let expected_peer = self.is_expected_peer(&key, peer);

		if let Some(root_hash) = self.validate_root_hash(peer, archive_header_hash) {
			let desegmenter = self.desegmenter.read();
			let desegmenter = desegmenter
				.as_ref()
				.expect("Desegmenter must exist at this point");
			match desegmenter.add_kernel_segment(segment, &root_hash) {
				Ok(_) => {
					if expected_peer {
						sync_peers.report_ok_response(peer);
					}
				}
				Err(e) => {
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

		self.track_and_request_more_segments(&key, peer, peers, sync_peers);
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

	fn calc_retry_running_requests(&self) -> usize {
		let now = Utc::now();
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
		excluded_requests: u32,
		excluded_peers: u32,
		desegmenter: &Desegmenter,
		sync_peers: &SyncPeers,
	) -> SyncResponse {
		if let Some(_) = self.send_requests_lock.try_write() {
			let latency_ms = self
				.request_tracker
				.get_average_latency()
				.num_milliseconds();
			let mut need_request = self.request_tracker.calculate_needed_requests(
				root_hash_peers.len(),
				excluded_requests as usize,
				excluded_peers as usize,
				self.pibd_params.get_segments_request_per_peer(),
				self.pibd_params
					.get_segments_requests_limit(latency_ms as u32),
			);
			need_request = need_request.saturating_sub(self.calc_retry_running_requests());
			if need_request > 0 {
				match desegmenter.next_desired_segments(need_request, &self.request_tracker) {
					Ok((req_segments, retry_segments, waiting_segments)) => {
						let mut rng = rand::thread_rng();
						let now = Utc::now();
						let target_archive_hash = self.target_archive_hash.read().clone();

						if !retry_segments.is_empty() {
							let last_retry_idx = self.last_retry_idx.try_write();
							if let Some(mut last_retry_idx) = last_retry_idx {
								for segm in &retry_segments {
									let retry_idx = last_retry_idx
										.get(&segm.segment_type)
										.cloned()
										.unwrap_or(0);

									if segm.identifier.leaf_offset() <= retry_idx {
										continue;
									}

									if need_request == 0 {
										break;
									}

									// We don't want to send retry to the peer whom we already send the data
									if let Some(requested_peer) =
										self.request_tracker.get_expected_peer(&(
											segm.segment_type.clone(),
											segm.identifier.leaf_offset(),
										)) {
										let dup_peers: Vec<Arc<Peer>> = peers
											.iter()
											.filter(|p| p.info.addr != requested_peer)
											.cloned()
											.choose_multiple(&mut rng, 2);

										if dup_peers.len() == 0 {
											break;
										}

										if need_request < dup_peers.len() {
											need_request = 0;
											break;
										}
										need_request = need_request.saturating_sub(dup_peers.len());

										// we can do retry now
										for p in dup_peers {
											debug!("Processing duplicated request for the segment {:?} at {}, peer {:?}", segm.segment_type, segm.identifier.leaf_offset(), p.info.addr);
											match Self::send_request(
												&p,
												&segm,
												&target_archive_hash,
											) {
												Ok(_) => {
													self.retry_expiration_times.write().push_back(
														now + self
															.request_tracker
															.get_average_latency(),
													)
												}
												Err(e) => {
													let msg = format!("Failed to send duplicate segment {:?} at {}, peer {:?}, Error: {}", segm.segment_type, segm.identifier.leaf_offset(), p.info.addr, e);
													error!("{}", msg);
													sync_peers
														.report_no_response(&p.info.addr, msg);
													break;
												}
											}
										}
									}

									(*last_retry_idx).insert(
										segm.segment_type.clone(),
										segm.identifier.leaf_offset(),
									);
								}
							}
						}

						for seg in req_segments {
							if need_request == 0 {
								break;
							}
							need_request = need_request.saturating_sub(1);

							let key = (seg.segment_type.clone(), seg.identifier.leaf_offset());
							debug_assert!(!self.request_tracker.has_request(&key));
							debug_assert!(!root_hash_peers.is_empty());
							let peer = root_hash_peers
								.choose(&mut rng)
								.expect("peers is not empty");

							let send_res = Self::send_request(peer, &seg, &target_archive_hash);
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
								.choose_multiple(&mut rng, need_request)
								.cloned()
								.collect();

							for segm in &duplicate_reqs {
								// We don't want to send retry to the peer whom we already send the data
								if let Some(requested_peer) =
									self.request_tracker.get_expected_peer(&(
										segm.segment_type.clone(),
										segm.identifier.leaf_offset(),
									)) {
									let dup_peer = peers
										.iter()
										.filter(|p| p.info.addr != requested_peer)
										.choose(&mut rng);

									if dup_peer.is_none() {
										break;
									}
									let dup_peer = dup_peer.unwrap();

									debug!("Processing duplicated request for the segment {:?} at {}, peer {:?}", segm.segment_type, segm.identifier.leaf_offset(), dup_peer.info.addr);
									match Self::send_request(&dup_peer, &segm, &target_archive_hash)
									{
										Ok(_) => self.retry_expiration_times.write().push_back(
											now + self.request_tracker.get_average_latency(),
										),
										Err(e) => {
											let msg = format!("Failed to send duplicate segment {:?} at {}, peer {:?}, Error: {}", segm.segment_type, segm.identifier.leaf_offset(), dup_peer.info.addr, e);
											error!("{}", msg);
											sync_peers.report_no_response(&dup_peer.info.addr, msg);
											break;
										}
									}
								}
							}
						}

						return SyncResponse::new(
							SyncRequestResponses::Syncing,
							Self::get_peer_capabilities(),
							format!(
								"Has peers: {} Requests in waiting Q: {}",
								root_hash_peers.len() + excluded_peers as usize,
								self.request_tracker.get_requests_num()
							),
						);
					}
					Err(err) => {
						error!("Failed to request more segments. Error: {}", err);
						// let's reset everything and restart
						self.ban_this_session(desegmenter.get_bitmap_root_hash(), sync_peers);
						return SyncResponse::new(
							SyncRequestResponses::Syncing,
							Self::get_peer_capabilities(),
							format!("Failed to request more segments. Error: {}", err),
						);
					}
				}
			}
		}
		// waiting for responses...
		return SyncResponse::new(
			SyncRequestResponses::Syncing,
			Self::get_peer_capabilities(),
			format!(
				"Has peers {}, Requests in waiting Q: {}",
				root_hash_peers.len() + excluded_peers as usize,
				self.request_tracker.get_requests_num()
			),
		);
	}
}
