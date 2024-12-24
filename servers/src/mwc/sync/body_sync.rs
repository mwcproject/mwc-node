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

use crate::chain::{self, SyncState, SyncStatus};
use crate::core::core::hash::{Hash, Hashed};
use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils;
use crate::mwc::sync::sync_utils::{RequestTracker, SyncRequestResponses, SyncResponse};
use crate::p2p;
use chrono::{DateTime, Utc};
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::{pibd_params, Chain};
use mwc_p2p::{Peer, PeerAddr};
use mwc_util::RwLock;
use p2p::Capabilities;
use rand::prelude::*;
use std::cmp;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

pub struct BodySync {
	chain: Arc<Chain>,
	required_capabilities: RwLock<Capabilities>,
	request_tracker: RequestTracker<Hash>,
	request_series: RwLock<Vec<(Hash, u64)>>, // Hash, height
	pibd_params: Arc<PibdParams>,
	last_retry_height: RwLock<u64>,
	retry_expiration_times: RwLock<VecDeque<DateTime<Utc>>>,
	excluded_peers: RwLock<HashSet<PeerAddr>>,
}

impl BodySync {
	pub fn new(chain: Arc<Chain>) -> BodySync {
		BodySync {
			pibd_params: chain.get_pibd_params().clone(),
			chain,
			required_capabilities: RwLock::new(Capabilities::UNKNOWN),
			request_tracker: RequestTracker::new(),
			request_series: RwLock::new(Vec::new()),
			last_retry_height: RwLock::new(0),
			retry_expiration_times: RwLock::new(VecDeque::new()),
			excluded_peers: RwLock::new(HashSet::new()),
		}
	}

	pub fn get_peer_capabilities(&self) -> Capabilities {
		self.required_capabilities.read().clone()
	}

	// Expected that it is called ONLY when state_sync is done
	pub fn request(
		&self,
		in_peers: &Arc<p2p::Peers>,
		sync_state: &SyncState,
		sync_peers: &SyncPeers,
		best_height: u64,
	) -> Result<SyncResponse, chain::Error> {
		// check if we need something
		let head = self.chain.head()?;
		let header_head = self.chain.header_head()?;

		let max_avail_height = cmp::min(best_height, header_head.height);

		// Last few blocks no need to sync, new mined blocks will be synced regular way
		if head.height > max_avail_height.saturating_sub(7) {
			// Expected by QT wallet
			info!(
				"synchronized at {} @ {} [{}]",
				head.total_difficulty.to_num(),
				head.height,
				head.last_block_h
			);

			// sync is done, we are ready.
			return Ok(SyncResponse::new(
				SyncRequestResponses::BodyReady,
				Capabilities::UNKNOWN,
				format!(
					"head.height={} vs max_avail_height={}",
					head.height, max_avail_height
				),
			));
		}

		let archive_height = Chain::height_2_archive_height(best_height);

		let head = self.chain.head()?;
		let mut fork_point = self.chain.fork_point()?;

		if !self.chain.archive_mode() {
			if fork_point.height < archive_height {
				warn!("body_sync: cannot sync full blocks earlier than horizon. will request txhashset");
				return Ok(SyncResponse::new(
					SyncRequestResponses::BadState,
					self.get_peer_capabilities(),
					format!(
						"fork_point.height={} < archive_height={}",
						fork_point.height, archive_height
					),
				));
			}
		}

		let (peer_capabilities, required_capabilities) =
			if self.chain.archive_mode() && head.height <= archive_height {
				(
					Capabilities::BLOCK_HIST,
					Capabilities::BLOCK_HIST | Capabilities::HEADER_HIST,
				)
			} else {
				(Capabilities::UNKNOWN, Capabilities::HEADER_HIST) // needed for headers sync, that can go in parallel
			};
		*self.required_capabilities.write() = required_capabilities;

		// requested_blocks, check for expiration
		let excluded_peers = self
			.request_tracker
			.retain_expired(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS, sync_peers);
		*self.excluded_peers.write() = excluded_peers;

		let (peers, excluded_requests, excluded_peers) = sync_utils::get_sync_peers(
			in_peers,
			self.pibd_params.get_blocks_request_per_peer(),
			peer_capabilities,
			head.height,
			&self.request_tracker,
			&*self.excluded_peers.read(),
		);
		if peers.is_empty() {
			if excluded_peers == 0 {
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					self.get_peer_capabilities(),
					format!(
						"No available peers, waiting Q size: {}",
						self.request_tracker.get_requests_num()
					),
				));
			} else {
				return Ok(SyncResponse::new(
					SyncRequestResponses::Syncing,
					self.get_peer_capabilities(),
					format!(
						"Peers: {}  Waiting Q size: {}",
						peers.len() + excluded_peers as usize,
						self.request_tracker.get_requests_num()
					),
				));
			}
		}

		sync_state.update(SyncStatus::BodySync {
			archive_height: if self.chain.archive_mode() {
				0
			} else {
				archive_height
			},
			current_height: fork_point.height,
			highest_height: best_height,
		});

		// Check for stuck orphan
		if let Ok(next_block) = self.chain.get_header_by_height(fork_point.height + 1) {
			let next_block_hash = next_block.hash();
			// Kick the stuck orphan
			match self.chain.get_orphan(&next_block_hash) {
				Some(orph) => {
					debug!("There is stuck orphan is found, let's kick it...");
					if self.chain.process_block(orph.block, orph.opts).is_ok() {
						debug!("push stuck orphan was successful. Should be able continue to go forward now");
						fork_point = self.chain.fork_point()?;
					}
				}
				None => {}
			}
		}

		// if we have 5 peers to sync from then ask for 50 blocks total (peer_count *
		// 10) max will be 80 if all 8 peers are advertising more work
		// also if the chain is already saturated with orphans, throttle

		let latency_ms = self
			.request_tracker
			.get_average_latency()
			.num_milliseconds();
		let mut need_request = self.request_tracker.calculate_needed_requests(
			peers.len(),
			excluded_requests as usize,
			excluded_peers as usize,
			self.pibd_params.get_blocks_request_per_peer(),
			self.pibd_params.get_blocks_request_limit(latency_ms as u32),
		);

		if need_request > 0 {
			let mut waiting_requests = self.send_requests(&mut need_request, &peers, sync_peers)?;

			// We can send more requests, let's check if we need to update request_series
			if need_request > 0 {
				let mut need_refresh_request_series = false;

				// If request_series first if processed, need to update
				let last_request_series = self.request_series.read().last().cloned();
				if let Some((hash, height)) = last_request_series {
					debug!("Updating body request series for {} / {}", hash, height);
					if self.chain.block_exists(&hash)? {
						// The tail is updated, so we can request more
						need_refresh_request_series = true;
					}
				} else {
					need_refresh_request_series = true;
				}

				if need_refresh_request_series {
					let mut new_request_series: Vec<(Hash, u64)> = Vec::new();

					// Don't collect more than 500 blocks in the cache. The block size limit is 1.5MB, so total cache mem can be up to 750 Mb which is ok
					let max_height = cmp::min(
						fork_point.height + (self.pibd_params.get_orphans_num_limit() / 2) as u64,
						max_avail_height,
					);
					let mut current = self.chain.get_header_by_height(max_height)?;

					while current.height > fork_point.height {
						let hash = current.hash();
						if !self.chain.is_orphan(&hash) {
							new_request_series.push((hash, current.height));
						}
						current = self.chain.get_previous_header(&current)?;
					}

					if let Some((hash, height)) = new_request_series.last() {
						debug!(
							"New body request series starting from {} / {}",
							hash, height
						);
					}
					*self.request_series.write() = new_request_series;
				}

				// Now we can try to submit more requests...
				waiting_requests = self.send_requests(&mut need_request, &peers, sync_peers)?;
			}

			if need_request > 0 && !waiting_requests.is_empty() {
				self.send_waiting_requests(waiting_requests, need_request, &peers, sync_peers)?;
			}
		}

		return Ok(SyncResponse::new(
			SyncRequestResponses::Syncing,
			self.get_peer_capabilities(),
			format!(
				"Peers: {}  Waiting Q size: {}",
				peers.len() + excluded_peers as usize,
				self.request_tracker.get_requests_num()
			),
		));
	}

	pub fn recieve_block_reporting(
		&self,
		valid_block: bool, // block accepted/rejected flag
		block_hash: &Hash,
		peer: &PeerAddr,
		peers: &Arc<p2p::Peers>,
		sync_peers: &SyncPeers,
	) {
		// Applying valid only to initiated requests. Others and duplicated shouldn't affect this workflow
		if let Some(peer_adr) = self.request_tracker.remove_request(block_hash, peer) {
			if peer_adr == *peer {
				if valid_block {
					sync_peers.report_ok_response(peer);
				} else {
					sync_peers.report_error_response(
						peer,
						format!("Get bad block {} for peer {}", block_hash, peer),
					);
				}

				// let's request next package since we get this one...
				if self.request_tracker.get_update_requests_to_next_ask() == 0 {
					if let Ok(head) = self.chain.head() {
						let (peers, excluded_requests, excluded_peers) = sync_utils::get_sync_peers(
							peers,
							self.pibd_params.get_blocks_request_per_peer(),
							*self.required_capabilities.read(),
							head.height,
							&self.request_tracker,
							&*self.excluded_peers.read(),
						);
						if !peers.is_empty() {
							// requested_blocks, check for expiration
							let latency_ms = self
								.request_tracker
								.get_average_latency()
								.num_milliseconds();
							let mut need_request = self.request_tracker.calculate_needed_requests(
								peers.len(),
								excluded_requests as usize,
								excluded_peers as usize,
								self.pibd_params.get_blocks_request_per_peer(),
								self.pibd_params.get_blocks_request_limit(latency_ms as u32),
							);
							if need_request > 0 {
								if let Err(e) =
									self.send_requests(&mut need_request, &peers, sync_peers)
								{
									error!("Unable to call send_requests, error: {}", e);
								}
							}
						}
					}
				}
			}
		}
	}

	fn is_block_recieved(&self, hash: &Hash) -> Result<bool, chain::Error> {
		Ok(self.chain.is_orphan(&hash) || self.chain.block_exists(&hash)?)
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

	// return waiting requests
	fn send_requests(
		&self,
		need_request: &mut usize,
		peers: &Vec<Arc<Peer>>,
		sync_peers: &SyncPeers,
	) -> Result<Vec<(u64, Hash)>, chain::Error> {
		// request_series naturally from head to tail, but requesting better to send from tail to the head....
		let mut peers = peers.clone();
		let mut waiting_heights: Vec<(u64, Hash)> = Vec::new();
		// Requests wuth try write because otherwise somebody else is sending, it is mean we are good...
		if let Some(request_series) = self.request_series.try_write() {
			*need_request = need_request.saturating_sub(self.calc_retry_running_requests());
			if *need_request == 0 {
				return Ok(waiting_heights);
			}

			let mut rng = rand::thread_rng();
			let now = Utc::now();

			let mut new_requests: Vec<(u64, Hash)> = Vec::new();

			let mut first_in_cache = 0;
			let mut last_in_cache = 0;
			let mut has10_idx = 0;
			let retry_delta = cmp::max(7, request_series.len() as u64 / 5);

			for (hash, height) in request_series.iter().rev() {
				if self.is_block_recieved(&hash)? {
					if *height == last_in_cache + 1 {
						last_in_cache = *height;
					} else {
						first_in_cache = *height;
						last_in_cache = *height;
					}
					continue;
				}

				if last_in_cache > 0 {
					if last_in_cache - first_in_cache > retry_delta {
						has10_idx = first_in_cache;
					}
					first_in_cache = 0;
					last_in_cache = 0;
				}

				if self.request_tracker.has_request(&hash) {
					waiting_heights.push((height.clone(), hash.clone()));
				} else {
					new_requests.push((height.clone(), hash.clone()));
					if new_requests.len() >= *need_request {
						break;
					}
				}
			}

			let mut retry_requests: Vec<(u64, Hash)> = Vec::new();
			if has10_idx > 0 {
				for (height, req) in &waiting_heights {
					if *height >= has10_idx {
						break;
					}
					retry_requests.push((height.clone(), req.clone()));
				}
			}

			// Now let's try to send retry requests first
			if let Some(mut last_retry_height) = self.last_retry_height.try_write() {
				for (height, hash) in retry_requests {
					if height <= *last_retry_height {
						continue;
					}

					if *need_request == 0 {
						break;
					}

					// We don't want to send retry to the peer whom we already send the data
					if let Some(requested_peer) = self.request_tracker.get_expected_peer(&hash) {
						let dup_peers: Vec<Arc<Peer>> = peers
							.iter()
							.filter(|p| {
								p.info.addr != requested_peer
									&& p.info.live_info.read().height >= height
							})
							.cloned()
							.choose_multiple(&mut rng, 2);

						if dup_peers.len() == 0 {
							break;
						}

						if *need_request < dup_peers.len() {
							*need_request = 0;
							break;
						}
						*need_request = need_request.saturating_sub(dup_peers.len());

						// we can do retry now
						for p in dup_peers {
							debug!(
								"Processing duplicated request for the block {} at {}, peer {:?}",
								hash, height, p.info.addr
							);
							match p.send_block_request(hash, chain::Options::SYNC) {
								Ok(_) => self
									.retry_expiration_times
									.write()
									.push_back(now + self.request_tracker.get_average_latency()),
								Err(e) => {
									let msg = format!(
										"Failed to send duplicate block request to peer {}, {}",
										p.info.addr, e
									);
									warn!("{}", msg);
									sync_peers.report_no_response(&p.info.addr, msg);
									break;
								}
							}
						}

						*last_retry_height = height;
					}
				}
			}

			// Now sending normal requests, no retry for now
			for (height, hash) in new_requests {
				if *need_request == 0 {
					break;
				}
				*need_request = need_request.saturating_sub(1);

				peers.retain(|p| p.info.live_info.read().height >= height);
				if peers.is_empty() {
					*need_request = 0;
					return Ok(waiting_heights);
				}

				// sending request
				let peer = peers
					.choose(&mut rng)
					.expect("Internal error. peers are empty");

				debug!(
					"Processing request for the block {} at {}, peer {:?}",
					hash, height, peer.info.addr
				);
				if let Err(e) = peer.send_block_request(hash.clone(), chain::Options::SYNC) {
					let msg = format!(
						"Failed to send block request to peer {}, {}",
						peer.info.addr, e
					);
					warn!("{}", msg);
					sync_peers.report_no_response(&peer.info.addr, msg);
				} else {
					self.request_tracker.register_request(
						hash.clone(),
						peer.info.addr.clone(),
						format!("Block {}, {}", hash, height),
					);
				}
			}
		}
		Ok(waiting_heights)
	}

	fn send_waiting_requests(
		&self,
		waiting_heights: Vec<(u64, Hash)>,
		need_request: usize,
		peers: &Vec<Arc<Peer>>,
		sync_peers: &SyncPeers,
	) -> Result<(), chain::Error> {
		debug_assert!(need_request > 0);

		let mut rng = rand::thread_rng();
		let now = Utc::now();

		// Free requests, lets duplicated some random from the expected buffer
		let duplicate_reqs: Vec<(u64, Hash)> = waiting_heights
			.into_iter()
			.choose_multiple(&mut rng, need_request);

		for (height, hash) in duplicate_reqs {
			// We don't want to send retry to the peer whom we already send the data
			if let Some(requested_peer) = self.request_tracker.get_expected_peer(&hash) {
				let dup_peer = peers
					.iter()
					.filter(|p| p.info.addr != requested_peer)
					.choose(&mut rng);

				if dup_peer.is_none() {
					break;
				}
				let dup_peer = dup_peer.unwrap();
				debug!(
					"Processing duplicated request for the block {} at {}, peer {:?}",
					hash, height, dup_peer.info.addr
				);

				match dup_peer.send_block_request(hash, chain::Options::SYNC) {
					Ok(_) => self
						.retry_expiration_times
						.write()
						.push_back(now + self.request_tracker.get_average_latency()),
					Err(e) => {
						let msg = format!(
							"Failed to send duplicate block request to peer {}, {}",
							dup_peer.info.addr, e
						);
						warn!("{}", msg);
						sync_peers.report_no_response(&dup_peer.info.addr, msg);
						break;
					}
				}
			}
		}
		Ok(())
	}
}
