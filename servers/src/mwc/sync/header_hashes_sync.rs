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

use crate::chain::{self, pibd_params, SyncState, SyncStatus};
use crate::core::core::hash::Hashed;
use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils;
use crate::mwc::sync::sync_utils::{CachedResponse, SyncRequestResponses, SyncResponse};
use crate::p2p::{self, Capabilities, Peer};
use chrono::prelude::{DateTime, Utc};
use chrono::Duration;
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::txhashset::{HeaderHashesDesegmenter, HEADER_HASHES_STUB_TYPE};
use mwc_chain::Chain;
use mwc_core::core::hash::Hash;
use mwc_core::core::{Segment, SegmentType};
use mwc_p2p::{PeerAddr, ReasonForBan};
use mwc_util::RwLock;
use rand::seq::SliceRandom;
use std::cmp;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Headers Hash Sync is needed for Fast Headers synchronization
pub struct HeadersHashSync {
	chain: Arc<chain::Chain>,
	// The headers sync data
	headers_hash_desegmenter: Option<HeaderHashesDesegmenter>,

	// sync tracking
	target_archive_height: u64,
	requested_headers_hash_from: HashMap<PeerAddr, DateTime<Utc>>,
	responded_headers_hash_from: HashMap<PeerAddr, (Hash, DateTime<Utc>)>,
	responded_with_another_height: HashSet<PeerAddr>,
	// sync for segments
	requested_segments: HashMap<(SegmentType, u64), (PeerAddr, DateTime<Utc>)>,
	// pibd ready flag for quick response during waiting time intervals
	pibd_headers_are_loaded: RwLock<bool>,

	cached_response: RwLock<Option<CachedResponse<SyncResponse>>>,
	pibd_params: Arc<PibdParams>,
}

impl HeadersHashSync {
	pub fn new(chain: Arc<chain::Chain>) -> HeadersHashSync {
		HeadersHashSync {
			pibd_params: chain.get_pibd_params().clone(),
			chain: chain.clone(),
			headers_hash_desegmenter: None,
			target_archive_height: 0,
			requested_headers_hash_from: HashMap::new(),
			responded_headers_hash_from: HashMap::new(),
			responded_with_another_height: HashSet::new(),
			requested_segments: HashMap::new(),
			pibd_headers_are_loaded: RwLock::new(false),
			cached_response: RwLock::new(None),
		}
	}

	pub fn is_pibd_headers_are_loaded(&self) -> bool {
		*self.pibd_headers_are_loaded.read()
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
		*self.pibd_headers_are_loaded.write() = false;
		*self.cached_response.write() = None;
	}

	pub fn is_complete(&self) -> bool {
		match &self.headers_hash_desegmenter {
			Some(desegmenter) => desegmenter.is_complete(),
			None => false,
		}
	}

	pub fn get_target_archive_height(&self) -> u64 {
		self.target_archive_height
	}

	pub fn get_headers_hash_desegmenter(&self) -> Option<&HeaderHashesDesegmenter> {
		self.headers_hash_desegmenter.as_ref()
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
	pub fn reset_ban_commited_to_hash(&mut self, peers: &Arc<p2p::Peers>, sync_peers: &SyncPeers) {
		debug_assert!(self.headers_hash_desegmenter.is_some());

		if let Some(headers_hash_desegmenter) = self.headers_hash_desegmenter.as_ref() {
			let root_hash = headers_hash_desegmenter.get_headers_root_hash();

			let mut peers2ban: HashSet<PeerAddr> = HashSet::new();
			for (peer, (hash, _)) in &self.responded_headers_hash_from {
				if *hash == *root_hash {
					let _ = peers.ban_peer(
						peer,
						ReasonForBan::HeadersHashFailure,
						"ban as commited to header hash",
					);
					peers2ban.insert(peer.clone());
				}
			}

			for peer in sync_peers.get_banned_peers() {
				if !peers2ban.contains(&peer) {
					let _ = peers.unban_peer(&peer);
				}
			}
		}

		self.reset();
	}

	// Lightweight request processing for non active case. Immutable method
	pub fn request_pre(&self, best_height: u64) -> Option<SyncResponse> {
		// Sending headers hash request to all peers that has the same archive height...
		let cached_response = self.cached_response.read().clone();
		if let Some(cached_response) = cached_response {
			if !cached_response.is_expired() {
				return Some(cached_response.to_response());
			} else {
				*self.cached_response.write() = None;
			}
		}

		let target_archive_height = Chain::height_2_archive_height(best_height);

		if let Ok(tip) = self.chain.header_head() {
			if tip.height > target_archive_height {
				*self.pibd_headers_are_loaded.write() = true;
				let resp = SyncResponse::new(
					SyncRequestResponses::HeadersPibdReady,
					Self::get_peer_capabilities(),
					format!(
						"tip.height: {} > target_archive_height: {}",
						tip.height, target_archive_height
					),
				);
				*self.cached_response.write() =
					Some(CachedResponse::new(resp.clone(), Duration::seconds(60)));
				return Some(resp);
			}
		}
		None
	}

	// Full processing, Mutable method
	pub fn request_impl(
		&mut self,
		peers: &Arc<p2p::Peers>,
		sync_state: &SyncState,
		sync_peers: &SyncPeers,
		best_height: u64,
	) -> SyncResponse {
		let target_archive_height = Chain::height_2_archive_height(best_height);

		if self.headers_hash_desegmenter.is_none() {
			let now = Utc::now();
			if self.target_archive_height != target_archive_height {
				// Resetting all internal state, starting from the scratch
				self.target_archive_height = target_archive_height;
				self.requested_headers_hash_from.clear();
				self.responded_headers_hash_from.clear();
				self.responded_with_another_height.clear();
			}

			self.requested_headers_hash_from.retain(|peer, req_time| {
				if (now - *req_time).num_seconds() > pibd_params::PIBD_REQUESTS_TIMEOUT_SECS {
					sync_peers.report_no_response(peer, "header hashes".into());
					return false;
				}
				true
			});

			// Let's check if there are enough responses got from the peers, or first/last response was done for a while ago
			let mut first_request = now;
			for (_, (_, time)) in &self.responded_headers_hash_from {
				if *time < first_request {
					first_request = *time;
				}
			}

			if !self.responded_headers_hash_from.is_empty()
				&& ((self.responded_headers_hash_from.len()
					>= self.requested_headers_hash_from.len()
					&& self.responded_headers_hash_from.len() > 1)
					|| (now - first_request).num_seconds()
						> pibd_params::PIBD_REQUESTS_TIMEOUT_SECS / 2)
			{
				// We can elect the group with a most representative hash
				let mut hash_counts: HashMap<Hash, i32> = HashMap::new();
				for (_, (hash, _)) in &self.responded_headers_hash_from {
					hash_counts.insert(hash.clone(), hash_counts.get(hash).unwrap_or(&0) + 1);
				}
				// selecting hash with max value
				debug_assert!(!hash_counts.is_empty());
				let (best_root_hash, _) = hash_counts
					.iter()
					.max_by_key(|&(_, count)| count)
					.expect("hash_counts is empty?");

				let desegmenter = HeaderHashesDesegmenter::new(
					self.chain.genesis().hash(),
					target_archive_height,
					best_root_hash.clone(),
					self.pibd_params.clone(),
				);
				let segment_num = desegmenter.get_segments_total();
				self.headers_hash_desegmenter = Some(desegmenter);
				sync_state.update(SyncStatus::HeaderHashSync {
					completed_blocks: 0,
					total_blocks: segment_num,
				});
				// Headers desegmenter is ready - let's retry and request some headers
				return self.request_impl(peers, sync_state, sync_peers, best_height);
			}

			let headers_hash_peers = sync_utils::get_qualify_peers(
				peers,
				self.target_archive_height,
				Capabilities::HEADERS_HASH,
			);
			if headers_hash_peers.is_empty() {
				return SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Self::get_peer_capabilities(),
					"No outbound peers with HEADERS_HASH capability".into(),
				);
			}

			if self.responded_headers_hash_from.is_empty() {
				sync_state.update(SyncStatus::HeaderHashSync {
					completed_blocks: 0,
					total_blocks: 1,
				});
			}

			// Requestiong more hashes...
			for peer in &headers_hash_peers {
				if !self
					.requested_headers_hash_from
					.contains_key(&peer.info.addr)
					&& !self
						.responded_headers_hash_from
						.contains_key(&peer.info.addr)
					&& !self.responded_with_another_height.contains(&peer.info.addr)
				{
					match peer.send_start_headers_hash_sync_request(target_archive_height) {
						Ok(()) => {
							self.requested_headers_hash_from
								.insert(peer.info.addr.clone(), Utc::now());
						}
						Err(e) => error!(
							"send_start_headers_hash_sync_request failed with error: {}",
							e
						),
					}
				}
			}
			return SyncResponse::new(
				SyncRequestResponses::Syncing,
				Self::get_peer_capabilities(),
				format!(
					"Has peers: {}, Waiting root hash responses: {}",
					headers_hash_peers.len(),
					self.requested_headers_hash_from.len()
				),
			);
		}

		debug_assert!(self.headers_hash_desegmenter.is_some());
		debug_assert!(self.target_archive_height > 0);

		// Headers hashes are here, we can go forward and request some headers.
		let headers_hash_desegmenter = self
			.headers_hash_desegmenter
			.as_ref()
			.expect("internal error, headers_hash_desegmenter is empty ");

		if headers_hash_desegmenter.is_complete() {
			let resp = SyncResponse::new(
				SyncRequestResponses::HeadersHashReady,
				Self::get_peer_capabilities(),
				format!("headers_hash_desegmenter is complete"),
			);
			*self.cached_response.write() =
				Some(CachedResponse::new(resp.clone(), Duration::seconds(180)));
			return resp;
		}

		sync_state.update(SyncStatus::HeaderHashSync {
			completed_blocks: headers_hash_desegmenter.get_segments_completed(),
			total_blocks: headers_hash_desegmenter.get_segments_total(),
		});

		let headers_root_hash = headers_hash_desegmenter.get_headers_root_hash().clone();

		let headers_hash_peers = sync_utils::get_qualify_peers(
			peers,
			self.target_archive_height,
			Capabilities::HEADERS_HASH,
		);
		if headers_hash_peers.is_empty() {
			return SyncResponse::new(SyncRequestResponses::WaitingForPeers, Self::get_peer_capabilities(), format!("No outbound peers with HEADERS_HASH capability. Waiting for Hash responses: {}. Segment responses: {}",
																														  self.requested_headers_hash_from.len(), self.requested_segments.len()) );
		}

		// Need to request headers under the archive header. We can do that in parallel
		// Requesting more handshakes when have a chance
		for peer in &headers_hash_peers {
			if !self
				.requested_headers_hash_from
				.contains_key(&peer.info.addr)
				&& !self
					.responded_headers_hash_from
					.contains_key(&peer.info.addr)
				&& !self.responded_with_another_height.contains(&peer.info.addr)
			{
				match peer.send_start_headers_hash_sync_request(self.target_archive_height) {
					Ok(()) => {
						self.requested_headers_hash_from
							.insert(peer.info.addr.clone(), Utc::now());
					}
					Err(e) => error!(
						"send_start_headers_hash_sync_request failed with error: {}",
						e
					),
				}
			}
		}

		let segments = {
			let headers_hash_desegmenter = self
				.headers_hash_desegmenter
				.as_mut()
				.expect("internal error, headers_hash_desegmenter is empty ");
			headers_hash_desegmenter.next_desired_segments(
				cmp::min(
					headers_hash_peers.len() * self.pibd_params.get_segments_request_per_peer(),
					self.pibd_params.get_segments_requests_limit(0),
				),
				&&self.requested_segments,
			)
		};

		if !segments.is_empty() {
			// clean up expired
			let now = Utc::now();
			self.requested_segments.retain(|_idx, (peer, time)| {
				if (now - *time).num_seconds() > pibd_params::PIBD_REQUESTS_TIMEOUT_SECS {
					sync_peers.report_no_response(peer, "header hashes".into()); // it is expired
					return false;
				}
				return true;
			});

			// select random peer and request from it...
			let mut peers2send: Vec<Arc<Peer>> = Vec::new();
			for peer in headers_hash_peers.iter().filter(|&p| {
				let peer_adr = &p.info.addr;
				if self.responded_headers_hash_from.contains_key(peer_adr)
					&& !self.responded_with_another_height.contains(peer_adr)
				{
					return true;
				}
				false
			}) {
				peers2send.push(peer.clone());
			}

			if peers2send.is_empty() {
				return SyncResponse::new(SyncRequestResponses::WaitingForPeers, Self::get_peer_capabilities(),
												format!("No peers to request segment. Headers_hash_peers:{}  Waiting segments responses: {}", headers_hash_peers.len(), self.requested_segments.len()) );
			}

			let mut rng = rand::thread_rng();

			for seg in segments {
				debug_assert!(!self
					.requested_segments
					.contains_key(&(HEADER_HASHES_STUB_TYPE, seg.leaf_offset())));

				let peer = peers2send
					.choose(&mut rng)
					.expect("Internal error, unable to select peer");
				match peer.send_headers_hash_segment_request(headers_root_hash.clone(), seg) {
					Ok(_) => {
						self.requested_segments.insert(
							(HEADER_HASHES_STUB_TYPE, seg.leaf_offset()),
							(peer.info.addr.clone(), Utc::now()),
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

		return SyncResponse::new(
			SyncRequestResponses::Syncing,
			Self::get_peer_capabilities(),
			format!(
				"Has peers: {}  Waiting responses: {}",
				headers_hash_peers.len(),
				self.requested_segments.len()
			),
		);
	}

	pub fn receive_headers_hash_response(
		&mut self,
		peer: &PeerAddr,
		archive_height: u64,
		headers_hash_root: Hash,
		sync_peers: &SyncPeers,
	) {
		// Adding only once, so attacker will not be able to escape the ban
		if archive_height == self.target_archive_height
			&& !self.responded_headers_hash_from.contains_key(peer)
		{
			if let Some(_) = self.requested_headers_hash_from.remove(peer) {
				sync_peers.report_ok_response(peer);
			}
			self.responded_headers_hash_from
				.insert(peer.clone(), (headers_hash_root, Utc::now()));
		}
	}

	pub fn recieve_another_archive_header(
		&mut self,
		peer: &PeerAddr,
		_header_hash: &Hash,
		new_height: u64,
	) {
		if new_height != self.target_archive_height {
			self.responded_with_another_height.insert(peer.clone());
		}
	}

	pub fn receive_header_hashes_segment(
		&mut self,
		peer: &PeerAddr,
		header_hashes_root: Hash,
		segment: Segment<Hash>,
		sync_peers: &SyncPeers,
	) {
		if let Some(headers_hash_desegmenter) = self.headers_hash_desegmenter.as_mut() {
			if *headers_hash_desegmenter.get_headers_root_hash() != header_hashes_root {
				return; // Skipping this data, might be some old message
			}
			let segm_id = segment.id().clone();
			self.requested_segments
				.remove(&(HEADER_HASHES_STUB_TYPE, segm_id.leaf_offset()));
			match headers_hash_desegmenter.add_headers_hash_segment(segment, &header_hashes_root) {
				Ok(_) => {
					sync_peers.report_ok_response(peer);
				}
				Err(e) => {
					let msg = format!(
						"receive_header_hashes_segment failed for {}, segment {}. Error: {}",
						peer, segm_id, e
					);
					error!("{}", msg);
					sync_peers.report_error_response(peer, msg);
				}
			}
		}
	}
}
