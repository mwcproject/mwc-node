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
use mwc_chain::Chain;
use mwc_core::core::hash::Hash;
use mwc_core::core::{OutputIdentifier, Segment, TxKernel};
use mwc_p2p::PeerAddr;
use mwc_util::secp::pedersen::RangeProof;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Fast sync has 3 "states":
/// * syncing headers
/// * once all headers are sync'd, requesting the txhashset state
/// * once we have the state, get blocks after that
///
/// The StateSync struct implements and monitors the middle step.
pub struct StateSync {
	chain: Arc<Chain>,

	// Target height needs to be calculated by the top peers, can be different from headers, it is no problem
	target_archive_height: u64,
	target_archive_hash: Hash,
	requested_root_hash: HashMap<PeerAddr, DateTime<Utc>>,
	responded_root_hash: HashMap<PeerAddr, (Hash, DateTime<Utc>)>,
	responded_with_another_height: HashSet<PeerAddr>,
	// sync for segments
	request_tracker: RequestTracker<(SegmentType, u64)>,
	is_complete: bool,
	pibd_params: Arc<PibdParams>,
}

impl StateSync {
	pub fn new(chain: Arc<chain::Chain>) -> StateSync {
		StateSync {
			pibd_params: chain.get_pibd_params().clone(),
			chain,
			target_archive_height: 0,
			target_archive_hash: Hash::default(),
			requested_root_hash: HashMap::new(),
			responded_root_hash: HashMap::new(),
			responded_with_another_height: HashSet::new(),
			request_tracker: RequestTracker::new(),
			is_complete: false,
		}
	}

	fn get_peer_capabilities() -> Capabilities {
		return Capabilities::PIBD_HIST;
	}

	pub fn request(
		&mut self,
		peers: &Arc<p2p::Peers>,
		sync_state: Arc<SyncState>,
		sync_peers: &mut SyncPeers,
		stop_state: Arc<StopState>,
		best_height: u64,
	) -> SyncResponse {
		// In case of archive mode, this step is must be skipped. Body sync will catch up.
		if self.is_complete || self.chain.archive_mode() {
			return SyncResponse::new(
				SyncRequestResponses::StatePibdReady,
				Capabilities::UNKNOWN,
				format!(
					"is_complete={}  archive_mode={}",
					self.is_complete,
					self.chain.archive_mode()
				),
			);
		}

		// Let's check if we need to calculate/update archive height.
		let target_archive_height = Chain::height_2_archive_height(best_height);

		if self.target_archive_height != target_archive_height {
			// Resetting all internal state, starting from the scratch
			self.target_archive_height = target_archive_height;
			// total reset, nothing needs to be saved...
			self.reset_desegmenter_data();
		}

		if self.target_archive_height == 0 {
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
				self.is_complete = true;
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
		let archive_header = match self.chain.get_header_by_height(self.target_archive_height) {
			Ok(archive_header) => archive_header,
			Err(_) => {
				return SyncResponse::new(
					SyncRequestResponses::WaitingForHeaders,
					Self::get_peer_capabilities(),
					format!(
						"Header at height {} doesn't exist",
						self.target_archive_height
					),
				);
			}
		};

		// Requesting root_hash...
		let (peers, excluded_requests) = sync_utils::get_sync_peers(
			peers,
			self.pibd_params.get_segments_request_per_peer(),
			Capabilities::PIBD_HIST,
			self.target_archive_height,
			self.request_tracker.get_requests_num(),
			&self.request_tracker.get_peers_queue_size(),
		);
		if peers.is_empty() {
			return SyncResponse::new(
				SyncRequestResponses::WaitingForPeers,
				Self::get_peer_capabilities(),
				format!(
					"No peers to make requests. Waiting Q size: {}",
					self.request_tracker.get_requests_num()
				),
			);
		}

		let now = Utc::now();

		// checking to timeouts for handshakes...
		self.requested_root_hash.retain(|peer, req_time| {
			if (now - *req_time).num_seconds() > pibd_params::SEGMENT_REQUEST_TIMEOUT_SECS {
				sync_peers.report_no_response(peer, "root hash".into());
				return false;
			}
			true
		});

		// request handshakes if needed
		for peer in &peers {
			if !(self.requested_root_hash.contains_key(&peer.info.addr)
				|| self.responded_root_hash.contains_key(&peer.info.addr)
				|| self.responded_with_another_height.contains(&peer.info.addr))
			{
				// can request a handshake
				match peer
					.send_start_pibd_sync_request(archive_header.height, archive_header.hash())
				{
					Ok(_) => {
						self.requested_root_hash
							.insert(peer.info.addr.clone(), now.clone());
					}
					Err(e) => {
						error!("send_start_pibd_sync_request failed with error: {}", e);
					}
				}
			}
		}

		// Checking if need to init desegmenter
		if self.chain.get_desegmenter().read().is_none() {
			let mut first_request = now;
			for (_, (_, time)) in &self.responded_root_hash {
				if *time < first_request {
					first_request = *time;
				}
			}

			if !self.responded_root_hash.is_empty()
				&& (self.responded_root_hash.len() >= self.requested_root_hash.len()
					|| (now - first_request).num_seconds()
						> pibd_params::SEGMENT_REQUEST_TIMEOUT_SECS)
			{
				// We can elect the group with a most representative hash
				let mut hash_counts: HashMap<Hash, i32> = HashMap::new();
				for (_, (hash, _)) in &self.responded_root_hash {
					hash_counts.insert(hash.clone(), hash_counts.get(hash).unwrap_or(&0) + 1);
				}
				// selecting hash with max value
				debug_assert!(!hash_counts.is_empty());
				let (best_root_hash, _) = hash_counts
					.iter()
					.max_by_key(|&(_, count)| count)
					.expect("hash_counts is empty?");

				match self
					.chain
					.create_desegmenter(archive_header.height, best_root_hash.clone())
				{
					Ok(_) => {
						self.target_archive_hash = archive_header.hash();
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
						peers.len(),
						self.responded_root_hash.len(),
						self.requested_root_hash.len()
					),
				);
			}
		}

		let desegmenter = self.chain.get_desegmenter();
		let mut desegmenter = desegmenter.write();
		debug_assert!(desegmenter.is_some());
		let desegmenter = desegmenter
			.as_mut()
			.expect("Desegmenter must be created at this point");

		if desegmenter.is_complete() {
			info!("PIBD state is done, starting check_update_leaf_set_state...");
			if let Err(e) = desegmenter.check_update_leaf_set_state() {
				error!(
					"Restarting because check_update_leaf_set_state failed with error {}",
					e
				);
				self.ban_this_session(desegmenter, sync_peers);
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
					self.is_complete = true;
					return SyncResponse::new(
						SyncRequestResponses::StatePibdReady,
						Capabilities::UNKNOWN,
						"PIBD download and valiadion is done with success!".into(),
					);
				}
				Err(e) => {
					error!(
						"Restarting because validate_complete_state failed with error {}",
						e
					);
					self.ban_this_session(desegmenter, sync_peers);
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

		self.request_tracker
			.retain_expired(pibd_params::SEGMENT_REQUEST_TIMEOUT_SECS, sync_peers);
		sync_state.update(desegmenter.get_pibd_progress());

		let mut rng = rand::thread_rng();

		// let's check what peers with root hash are exist
		let root_hash = desegmenter.get_bitmap_root_hash();
		let mut root_hash_peers: Vec<Arc<Peer>> = Vec::new();
		let mut other_hashes = 0;
		for p in peers {
			let addr = &p.info.addr;
			if self.responded_with_another_height.contains(addr) {
				continue;
			}
			if let Some((hash, _)) = self.responded_root_hash.get(addr) {
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
				self.chain.reset_desegmenter();

				// Sinse there are other groups, treating that as attack. Banning all supporters
				self.ban_this_session(desegmenter, sync_peers);
				return SyncResponse::new(
					SyncRequestResponses::Syncing,
					Self::get_peer_capabilities(),
					"Banning this PIBD session. Seems like that was a fraud".into(),
				);
			} else {
				// Since there are no alternatives, keep waiting...
				return SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Self::get_peer_capabilities(),
					"No peers that support PIBD.".into(),
				);
			}
		}

		let need_request = self.request_tracker.calculate_needed_requests(
			root_hash_peers.len(),
			excluded_requests as usize,
			self.pibd_params.get_segments_request_per_peer(),
			self.pibd_params.get_segments_requests_limit(),
		);
		if need_request > 0 {
			match desegmenter
				.next_desired_segments(need_request, self.request_tracker.get_requested())
			{
				Ok(segments) => {
					for seg in segments {
						let key = (seg.segment_type.clone(), seg.identifier.idx.clone());
						debug_assert!(!self.request_tracker.has_request(&key));
						debug_assert!(!root_hash_peers.is_empty());
						let peer = root_hash_peers
							.choose(&mut rng)
							.expect("peers is not empty");

						let send_res = match seg.segment_type {
							SegmentType::Bitmap => peer.send_bitmap_segment_request(
								self.target_archive_hash.clone(),
								seg.identifier,
							),
							SegmentType::Output => peer.send_output_segment_request(
								self.target_archive_hash.clone(),
								seg.identifier,
							),
							SegmentType::RangeProof => peer.send_rangeproof_segment_request(
								self.target_archive_hash.clone(),
								seg.identifier,
							),
							SegmentType::Kernel => peer.send_kernel_segment_request(
								self.target_archive_hash.clone(),
								seg.identifier,
							),
						};
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
								sync_peers.report_error_response(&peer.info.addr, msg);
							}
						}
					}
					return SyncResponse::new(
						SyncRequestResponses::Syncing,
						Self::get_peer_capabilities(),
						format!(
							"Has peers: {} Requests in waiting Q: {}",
							root_hash_peers.len(),
							self.request_tracker.get_requests_num()
						),
					);
				}
				Err(err) => {
					error!("Failed to request more segments. Error: {}", err);
					// let's reset everything and restart
					self.ban_this_session(desegmenter, sync_peers);
					return SyncResponse::new(
						SyncRequestResponses::Syncing,
						Self::get_peer_capabilities(),
						format!("Failed to request more segments. Error: {}", err),
					);
				}
			}
		}
		// waiting for responses...
		return SyncResponse::new(
			SyncRequestResponses::Syncing,
			Self::get_peer_capabilities(),
			format!(
				"Has peers {}, Requests in waiting Q: {}",
				root_hash_peers.len(),
				self.request_tracker.get_requests_num()
			),
		);
	}

	fn ban_this_session(&mut self, desegmenter: &Desegmenter, sync_peers: &mut SyncPeers) {
		let root_hash = desegmenter.get_bitmap_root_hash();
		error!(
			"Banning all peers joind for root hash {}",
			desegmenter.get_bitmap_root_hash()
		);
		// Banning all peers that was agree with that hash...
		for (peer, (hash, _)) in &self.responded_root_hash {
			if *hash == *root_hash {
				sync_peers.ban_peer(peer, "bad root hash".into());
			}
		}
		self.reset_desegmenter_data();
	}

	pub fn reset_desegmenter_data(&mut self) {
		self.chain.reset_desegmenter();
		self.requested_root_hash.clear();
		self.responded_root_hash.clear();
		self.responded_with_another_height.clear();
		self.request_tracker.clear();
		self.is_complete = false;
	}

	pub fn recieve_pibd_status(
		&mut self,
		peer: &PeerAddr,
		_header_hash: Hash,
		header_height: u64,
		output_bitmap_root: Hash,
	) {
		// Only one commitment allowed per peer.
		if self.responded_root_hash.contains_key(peer)
			|| header_height != self.target_archive_height
		{
			return;
		}

		self.responded_root_hash
			.insert(peer.clone(), (output_bitmap_root, Utc::now()));
	}

	pub fn recieve_another_archive_header(
		&mut self,
		peer: &PeerAddr,
		_header_hash: &Hash,
		header_height: u64,
	) {
		if header_height == self.target_archive_height {
			return;
		}
		self.responded_with_another_height.insert(peer.clone());
	}

	// return Some root hash if validation was successfull
	fn validate_root_hash(&self, peer: &PeerAddr, archive_header_hash: &Hash) -> Option<Hash> {
		let desegmenter = self.chain.get_desegmenter();
		let desegmenter = desegmenter.read();
		if desegmenter.is_none() || self.target_archive_hash != *archive_header_hash {
			return None;
		}

		match self.responded_root_hash.get(peer) {
			Some((hash, _)) => {
				if desegmenter.as_ref().unwrap().get_bitmap_root_hash() == hash {
					return Some(hash.clone());
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
		&mut self,
		key: &(SegmentType, u64),
		peer: &PeerAddr,
		peers: &Arc<p2p::Peers>,
		sync_peers: &mut SyncPeers,
	) {
		if let Some(peer_addr) = self.request_tracker.remove_request(key) {
			if peer_addr == *peer {
				if self.request_tracker.get_update_requests_to_next_ask() == 0 {
					let (peers, excluded_requests) = sync_utils::get_sync_peers(
						peers,
						self.pibd_params.get_segments_request_per_peer(),
						Capabilities::PIBD_HIST,
						self.target_archive_height,
						self.request_tracker.get_requests_num(),
						&self.request_tracker.get_peers_queue_size(),
					);
					if peers.is_empty() {
						return;
					}

					let desegmenter = self.chain.get_desegmenter();
					let mut desegmenter = desegmenter.write();
					if let Some(desegmenter) = desegmenter.as_mut() {
						if !desegmenter.is_complete() {
							let mut rng = rand::thread_rng();

							// let's check what peers with root hash are exist
							let root_hash = desegmenter.get_bitmap_root_hash();
							let mut root_hash_peers: Vec<Arc<Peer>> = Vec::new();
							for p in peers {
								let addr = &p.info.addr;
								if self.responded_with_another_height.contains(addr) {
									continue;
								}
								if let Some((hash, _)) = self.responded_root_hash.get(addr) {
									if hash == root_hash {
										root_hash_peers.push(p.clone());
									}
								}
							}

							if root_hash_peers.is_empty() {
								return;
							}

							let need_request = self.request_tracker.calculate_needed_requests(
								root_hash_peers.len(),
								excluded_requests as usize,
								self.pibd_params.get_segments_request_per_peer(),
								self.pibd_params.get_segments_requests_limit(),
							);
							if need_request > 0 {
								match desegmenter.next_desired_segments(
									need_request,
									self.request_tracker.get_requested(),
								) {
									Ok(segments) => {
										for seg in segments {
											let key = (
												seg.segment_type.clone(),
												seg.identifier.idx.clone(),
											);
											debug_assert!(!self.request_tracker.has_request(&key));
											debug_assert!(!root_hash_peers.is_empty());
											let peer = root_hash_peers
												.choose(&mut rng)
												.expect("peers is not empty");

											let send_res = match seg.segment_type {
												SegmentType::Bitmap => peer
													.send_bitmap_segment_request(
														self.target_archive_hash.clone(),
														seg.identifier,
													),
												SegmentType::Output => peer
													.send_output_segment_request(
														self.target_archive_hash.clone(),
														seg.identifier,
													),
												SegmentType::RangeProof => peer
													.send_rangeproof_segment_request(
														self.target_archive_hash.clone(),
														seg.identifier,
													),
												SegmentType::Kernel => peer
													.send_kernel_segment_request(
														self.target_archive_hash.clone(),
														seg.identifier,
													),
											};
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
													let msg = format!("Error sending segment request to peer at {}, reason: {:?}",peer.info.addr, e);
													info!("{}", msg);
													sync_peers.report_error_response(
														&peer.info.addr,
														msg,
													);
												}
											}
										}
									}
									Err(err) => {
										error!("Failed to request more segments during update. Error: {}", err);
									}
								}
							}
						}
					}
				}
			}
		}
	}

	pub fn receive_bitmap_segment(
		&mut self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<BitmapChunk>,
		peers: &Arc<p2p::Peers>,
		sync_peers: &mut SyncPeers,
	) {
		let key = (SegmentType::Bitmap, segment.id().idx);
		let expected_peer = self.is_expected_peer(&key, peer);

		if let Some(root_hash) = self.validate_root_hash(peer, archive_header_hash) {
			let desegmenter = self.chain.get_desegmenter();
			let mut desegmenter = desegmenter.write();
			let desegmenter = desegmenter
				.as_mut()
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
		&mut self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<OutputIdentifier>,
		peers: &Arc<p2p::Peers>,
		sync_peers: &mut SyncPeers,
	) {
		let key = (SegmentType::Output, segment.id().idx);
		let expected_peer = self.is_expected_peer(&key, peer);

		if let Some(root_hash) = self.validate_root_hash(peer, archive_header_hash) {
			let desegmenter = self.chain.get_desegmenter();
			let mut desegmenter = desegmenter.write();
			let desegmenter = desegmenter
				.as_mut()
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
		&mut self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<RangeProof>,
		peers: &Arc<p2p::Peers>,
		sync_peers: &mut SyncPeers,
	) {
		let key = (SegmentType::RangeProof, segment.id().idx);
		let expected_peer = self.is_expected_peer(&key, peer);

		// Process first, unregister after. During unregister we might issue more requests.
		if let Some(root_hash) = self.validate_root_hash(peer, archive_header_hash) {
			let desegmenter = self.chain.get_desegmenter();
			let mut desegmenter = desegmenter.write();
			let desegmenter = desegmenter
				.as_mut()
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
		&mut self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<TxKernel>,
		peers: &Arc<p2p::Peers>,
		sync_peers: &mut SyncPeers,
	) {
		let key = (SegmentType::Kernel, segment.id().idx);
		let expected_peer = self.is_expected_peer(&key, peer);

		if let Some(root_hash) = self.validate_root_hash(peer, archive_header_hash) {
			let desegmenter = self.chain.get_desegmenter();
			let mut desegmenter = desegmenter.write();
			let desegmenter = desegmenter
				.as_mut()
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
}
