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
use crate::common::types::Error;
use crate::core::core::hash::Hash;
use crate::core::pow::Difficulty;
use crate::mwc::sync::header_hashes_sync::HeadersHashSync;
use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils;
use crate::mwc::sync::sync_utils::{
	CachedResponse, RequestTracker, SyncRequestResponses, SyncResponse,
};
use crate::p2p::{self, Capabilities, Peer};
use chrono::prelude::{DateTime, Utc};
use chrono::Duration;
use mwc_chain::pibd_params;
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::txhashset::{HeaderHashesDesegmenter, HeadersRecieveCache};
use mwc_core::core::hash::Hashed;
use mwc_core::core::BlockHeader;
use mwc_p2p::PeerAddr;
use mwc_util::RwLock;
use rand::seq::IteratorRandom;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

pub struct HeaderSync {
	chain: Arc<chain::Chain>,
	received_cache: RwLock<Option<HeadersRecieveCache>>,
	// requested_heights is expected to be at response height, the next tothe requested
	request_tracker: RequestTracker<Hash>, // Vec<Hash> - locator data for headers request
	cached_response: RwLock<Option<CachedResponse<SyncResponse>>>,
	headers_series_cache: RwLock<HashMap<(PeerAddr, Hash), (Vec<BlockHeader>, DateTime<Utc>)>>,
	pibd_params: Arc<PibdParams>,
	last_retry_height: RwLock<u64>,
	retry_expiration_times: RwLock<VecDeque<DateTime<Utc>>>,
	send_requests_lock: RwLock<u8>,
	excluded_peers: RwLock<HashSet<PeerAddr>>,
}

impl HeaderSync {
	pub fn new(chain: Arc<chain::Chain>) -> HeaderSync {
		HeaderSync {
			pibd_params: chain.get_pibd_params().clone(),
			chain: chain.clone(),
			received_cache: RwLock::new(None),
			request_tracker: RequestTracker::new(),
			cached_response: RwLock::new(None),
			headers_series_cache: RwLock::new(HashMap::new()),
			last_retry_height: RwLock::new(0),
			retry_expiration_times: RwLock::new(VecDeque::new()),
			send_requests_lock: RwLock::new(0),
			excluded_peers: RwLock::new(HashSet::new()),
		}
	}

	fn get_peer_capabilities() -> Capabilities {
		return Capabilities::HEADER_HIST;
	}

	pub fn request(
		&self,
		peers: &Arc<p2p::Peers>,
		sync_state: &SyncState,
		sync_peers: &SyncPeers,
		header_hashes: &HeadersHashSync,
		best_height: u64,
	) -> SyncResponse {
		let cached_response = self.cached_response.read().clone();
		if let Some(cached_response) = cached_response {
			if !cached_response.is_expired() {
				return cached_response.to_response();
			} else {
				*self.cached_response.write() = None;
			}
		}

		let header_head = self.chain.header_head().expect("header_head is broken");

		// Quick check - nothing to sync if we are caught up with the peer.
		if header_head.height >= best_height.saturating_sub(7) {
			// we can relax for a pretty long time, headers are ready
			let resp = SyncResponse::new(
				SyncRequestResponses::HeadersReady,
				Self::get_peer_capabilities(),
				format!("Header head {} vs {}", header_head.height, best_height),
			);
			*self.cached_response.write() =
				Some(CachedResponse::new(resp.clone(), Duration::seconds(60)));
			return resp;
		}

		let excluded_peers = self
			.request_tracker
			.retain_expired(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS, sync_peers);
		*self.excluded_peers.write() = excluded_peers;

		// it is initial statis flag
		if !header_hashes.is_pibd_headers_are_loaded() {
			if !header_hashes.is_complete() {
				// Even we can request headers from the bottom, the old style method, but we better to wait
				// for all hashes be ready, it is just 3 segments
				return SyncResponse::new(
					SyncRequestResponses::WaitingForHeadersHash,
					Self::get_peer_capabilities(),
					"Header hashes are expected but not ready yet".into(),
				);
			} else {
				// finally we have a hashes, on the first attempt we need to validate if what is already uploaded is good
				if self.received_cache.read().is_none() {
					let header_hashes = header_hashes
						.get_headers_hash_desegmenter()
						.expect("header_hashes must be is_complete");
					let received_cache =
						HeadersRecieveCache::new(self.chain.clone(), header_hashes);
					*self.received_cache.write() = Some(received_cache);
					self.request_tracker.clear();
				}

				let received_cache = self.received_cache.read();
				let received_cache = received_cache
					.as_ref()
					.expect("Internal error. Received_cache is not initialized.");

				// filrst checking if some headers needs to be uploaded to the chain
				match received_cache.apply_cache() {
					Ok(has_more_data) => {
						if has_more_data {
							return SyncResponse::new(
								SyncRequestResponses::HashMoreHeadersToApply,
								Self::get_peer_capabilities(),
								"Has more headers data to apply".into(),
							);
						}
					}
					Err((peer, err)) => {
						let msg =
							format!("Failed to process add_headers for {}. Error: {}", peer, err);
						error!("{}", msg);
						sync_peers.report_error_response_for_peerstr(peer, msg);
					}
				}

				let headers_hash_desegmenter = header_hashes.get_headers_hash_desegmenter().expect(
					"Internal error. header_hashes.get_headers_hash_desegmenter is not ready",
				);

				if !received_cache.is_complete().expect(
					"Chain is corrupted, please clean up the data manually and restart the node",
				) {
					// Requesting multiple headers
					let (peers, excluded_requests, excluded_peers) = sync_utils::get_sync_peers(
						peers,
						self.pibd_params.get_segments_request_per_peer(),
						Capabilities::HEADER_HIST,
						header_hashes.get_target_archive_height(),
						&self.request_tracker,
						&*self.excluded_peers.read(),
					);
					if peers.is_empty() {
						if excluded_peers == 0 {
							return SyncResponse::new(
								SyncRequestResponses::WaitingForPeers,
								Self::get_peer_capabilities(),
								format!(
									"No peers are available, requests waiting: {}",
									self.request_tracker.get_requests_num()
								),
							);
						} else {
							return SyncResponse::new(
								SyncRequestResponses::Syncing,
								Self::get_peer_capabilities(),
								format!(
									"Has peers {}, requests waiting: {}",
									excluded_peers,
									self.request_tracker.get_requests_num()
								),
							);
						}
					}

					sync_state.update(SyncStatus::HeaderSync {
						current_height: self.chain.header_head().expect("Chain is corrupted, please clean up the data manually and restart the node").height,
						archive_height: received_cache.get_archive_header_height(),
					});

					self.send_requests(
						&peers,
						headers_hash_desegmenter,
						sync_peers,
						excluded_requests,
						excluded_peers,
					);

					return SyncResponse::new(
						SyncRequestResponses::Syncing,
						Self::get_peer_capabilities(),
						format!(
							"Loading headers below horizon. Has peers: {} Requests in waiting Q: {}",
							peers.len() + excluded_peers as usize,
							self.request_tracker.get_requests_num()
						),
					);
				}
			}
		}

		// At this point we are above the archive height, so we can request headers sequentually the normal way...
		// sync_state is no needs to update
		let sync_peer = Self::choose_sync_peer(peers);

		if sync_peer.is_none() {
			return SyncResponse::new(
				SyncRequestResponses::WaitingForPeers,
				Self::get_peer_capabilities(),
				format!(
					"Loading headers above horizon, no peers are available, requests waiting: {}",
					self.request_tracker.get_requests_num()
				),
			);
		}

		let sync_peer = sync_peer.unwrap();
		let header_head = self.chain.header_head().expect("header_head is broken");
		let header_head_hash = header_head.hash();

		if self.request_tracker.has_request(&header_head_hash) {
			return SyncResponse::new(
				SyncRequestResponses::HeadersPibdReady,
				Self::get_peer_capabilities(),
				"Loading headers above horizon".into(),
			);
		}

		let (_, peer_diff) = {
			let info = sync_peer.info.live_info.read();
			(info.height, info.total_difficulty)
		};

		// Quick check - nothing to sync if we are caught up with the peer.
		if peer_diff <= header_head.total_difficulty {
			// we can relax for a pretty long time
			let resp = SyncResponse::new(
				SyncRequestResponses::HeadersReady,
				Self::get_peer_capabilities(),
				format!("At height {} now", header_head.height),
			);
			*self.cached_response.write() =
				Some(CachedResponse::new(resp.clone(), Duration::seconds(60)));
			return resp;
		}

		match self.request_headers(header_head, sync_peer.clone()) {
			Ok(_) => {
				self.request_tracker.register_request(
					header_head_hash,
					sync_peer.info.addr.clone(),
					format!("Tail header for {}", header_head.height),
				);
			}
			Err(e) => {
				let msg = format!(
					"Failed to send headers request to {} for height {}, Error: {}",
					sync_peer.info.addr, header_head.height, e
				);
				error!("{}", msg);
				sync_peers.report_no_response(&sync_peer.info.addr, msg);
			}
		}

		return SyncResponse::new(
			SyncRequestResponses::HeadersPibdReady,
			Self::get_peer_capabilities(),
			"Loading headers above horizon, just requested one.".into(),
		);
	}

	/// Recieved headers handler
	pub fn receive_headers(
		&self,
		peer: &PeerAddr,
		bhs: &[BlockHeader],
		remaining: u64,
		sync_peers: &SyncPeers,
		header_hashes: Option<&HeaderHashesDesegmenter>,
		peers: &Arc<p2p::Peers>,
	) -> Result<(), mwc_chain::Error> {
		debug_assert!(!bhs.is_empty());

		let series_key = (
			peer.clone(),
			bhs.first().expect("bhs can't be empty").prev_hash.clone(),
		);

		let bhs = {
			let mut headers_series_cache = self.headers_series_cache.write();
			let bhs = match headers_series_cache.remove(&series_key) {
				Some((mut peer_bhs, _)) => {
					debug_assert!(!peer_bhs.is_empty());
					peer_bhs.extend_from_slice(bhs);
					if remaining > 0 {
						headers_series_cache.insert(
							(
								series_key.0,
								peer_bhs.last().expect("peer_bhs can't be empty").hash(),
							),
							(peer_bhs, Utc::now()),
						);
						return Ok(());
					}
					peer_bhs
				}
				None => {
					if remaining == 0 {
						// no need to combine anything
						bhs.to_vec()
					} else {
						// putting into the cache and waiting for the rest
						headers_series_cache.insert(
							(series_key.0, bhs.last().expect("bhs can't be empty").hash()),
							(bhs.to_vec(), Utc::now()),
						);
						return Ok(());
					}
				}
			};

			// some stale data we better to retain sometimes
			if headers_series_cache.len() > 2000 {
				let expiration_time =
					Utc::now() - Duration::seconds(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS * 2);
				headers_series_cache.retain(|_, (_, time)| *time > expiration_time);
			}
			bhs
		};

		let mut expected_peer = false;
		let peer_adr = self.request_tracker.remove_request(&bhs[0].prev_hash, peer);
		if let Some(peer_addr) = peer_adr {
			expected_peer = peer_addr == *peer;

			// let's request next package since we get this one...
			if self.request_tracker.get_update_requests_to_next_ask() == 0 {
				// it is initial statis flag
				if header_hashes.is_some() {
					let headers_hash_desegmenter = header_hashes.unwrap();
					if headers_hash_desegmenter.is_complete() {
						// Requesting multiple headers

						let (peers, excluded_requests, excluded_peers) = sync_utils::get_sync_peers(
							peers,
							self.pibd_params.get_segments_request_per_peer(),
							Capabilities::HEADER_HIST,
							headers_hash_desegmenter.get_target_height(),
							&self.request_tracker,
							&*self.excluded_peers.read(),
						);

						if !peers.is_empty() {
							self.send_requests(
								&peers,
								headers_hash_desegmenter,
								sync_peers,
								excluded_requests,
								excluded_peers,
							);
						}
					}
				}
			}
		}

		let bad_block = Hash::from_hex(chain::BLOCK_TO_BAN)?;
		if bhs.iter().find(|h| h.hash() == bad_block).is_some() {
			debug!(
				"headers_received: found known bad header, all data is rejected. Peer: {}",
				peer
			);
			sync_peers
				.report_error_response(peer, "headers_received: found known bad header".into());
			return Ok(());
		}

		// That is needed for sync tracking
		info!(
			"Received {} block headers from {}, height {}",
			bhs.len(),
			peer,
			bhs[0].height,
		);

		// try to add headers to our header chain
		if let Some(header_hashes) = header_hashes {
			if bhs[0].height <= header_hashes.get_target_height() {
				if let Some(received_cache) = self.received_cache.read().as_ref() {
					// Processing with a cache
					match received_cache.add_headers_to_cache(header_hashes, bhs, peer.to_string())
					{
						Ok(_) => {
							// Reporting ok only for expected. We don't want attacker to make good points with not expected responses
							if expected_peer {
								sync_peers.report_ok_response(peer);
							}
						}
						Err((peer, err)) => {
							let msg = format!(
								"Failed to process add_headers for {}. Error: {}",
								peer, err
							);
							error!("{}", msg);
							sync_peers.report_error_response_for_peerstr(peer, msg);
						}
					}
					// Cache we neeed apply once from here. Even if data exist
					if let Err((peer, err)) = received_cache.apply_cache() {
						let msg =
							format!("Failed to process add_headers for {}. Error: {}", peer, err);
						error!("{}", msg);
						sync_peers.report_error_response_for_peerstr(peer, msg);
					}
					return Ok(());
				}
			}
		}

		// At this point we are processing the headers the regular way, it is expecte that it is a sequentual reponse
		let sync_head = self
			.chain
			.header_head()
			.expect("Header head must be always defined");

		match self
			.chain
			.sync_block_headers(&bhs, sync_head, chain::Options::SYNC)
		{
			Ok(sync_head) => {
				if let Some(sync_head) = sync_head {
					// If we have an updated sync_head after processing this batch of headers,
					// then we can request relevant headers in the next batch.
					if !self.request_tracker.has_request(&sync_head.last_block_h) {
						if let Some(sync_peer) = Self::choose_sync_peer(peers) {
							match self.request_headers(sync_head, sync_peer.clone()) {
								Ok(_) => {
									self.request_tracker.register_request(
										sync_head.last_block_h,
										sync_peer.info.addr.clone(),
										format!("Tail headers for {}", sync_head.height),
									);
									sync_peers.report_ok_response(peer);
								}
								Err(e) => {
									let msg = format!("Failed to send headers request to {} for height {}, Error: {}", sync_peer.info.addr, sync_head.height, e);
									error!("{}", msg);
									sync_peers.report_no_response(&sync_peer.info.addr, msg);
								}
							}
						}
					}
				}
			}
			Err(e) => {
				debug!("Headers refused by chain: {:?}", e);
				sync_peers.report_error_response(
					&peer,
					format!("sync_block_headers failed with error {}", e),
				);
			}
		}
		Ok(())
	}

	fn choose_sync_peer(peers: &Arc<p2p::Peers>) -> Option<Arc<Peer>> {
		let peers_iter = || {
			peers
				.iter()
				.with_capabilities(Capabilities::HEADER_HIST)
				.connected()
		};

		// Filter peers further based on max difficulty.
		let max_diff = peers_iter().max_difficulty().unwrap_or(Difficulty::zero());
		let peers_iter = || peers_iter().with_difficulty(|x| x >= max_diff);

		// Choose a random "most work" peer, preferring outbound if at all possible.
		peers_iter().outbound().choose_random().or_else(|| {
			debug!("no suitable outbound peer for header sync, considering inbound");
			peers_iter().inbound().choose_random()
		})
	}

	/// Request some block headers from a peer to advance us.
	fn request_headers(&self, sync_head: chain::Tip, peer: Arc<Peer>) -> Result<(), chain::Error> {
		let locator = self
			.get_locator(sync_head)
			.map_err(|e| chain::Error::Other(format!("{}", e)))?;
		debug!(
			"sync: request_headers: asking {} for headers at {}",
			peer.info.addr, sync_head.height
		);
		peer.send_header_request(locator)
			.map_err(|e| chain::Error::Other(format!("{}", e)))?;
		Ok(())
	}

	fn request_headers_for_hash(
		&self,
		header_hash: Hash,
		height: u64,
		peer: Arc<Peer>,
	) -> Result<(), chain::Error> {
		debug!(
			"sync: request_headers: asking {} for headers at hash {}, height {}",
			peer.info.addr, header_hash, height
		);
		peer.send_header_request(vec![header_hash])
			.map_err(|e| chain::Error::Other(format!("{}", e)))?;
		Ok(())
	}

	/// We build a locator based on sync_head.
	/// Even if sync_head is significantly out of date we will "reset" it once we
	/// start getting headers back from a peer.
	fn get_locator(&self, sync_head: chain::Tip) -> Result<Vec<Hash>, Error> {
		let heights = get_locator_heights(sync_head.height);
		let locator = self.chain.get_locator_hashes(sync_head, &heights)?;
		Ok(locator)
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
		headers_hash_desegmenter: &HeaderHashesDesegmenter,
		sync_peers: &SyncPeers,
		excluded_requests: u32,
		excluded_peers: u32,
	) {
		if let Some(_) = self.send_requests_lock.try_write() {
			let latency_ms = self
				.request_tracker
				.get_average_latency()
				.num_milliseconds();
			let mut need_request = self.request_tracker.calculate_needed_requests(
				peers.len(),
				excluded_requests as usize,
				excluded_peers as usize,
				self.pibd_params.get_segments_request_per_peer(),
				self.pibd_params
					.get_segments_requests_limit(latency_ms as u32),
			);
			need_request = need_request.saturating_sub(self.calc_retry_running_requests());
			if need_request > 0 {
				let received_cache = self.received_cache.read();
				let received_cache = received_cache
					.as_ref()
					.expect("Internal error. Received_cache is not initialized.");

				let (hashes, retry_reqs, waiting_reqs) = received_cache.next_desired_headers(headers_hash_desegmenter,
																			   need_request, &self.request_tracker,
																			   self.pibd_params.get_headers_buffer_len())
					.expect("Chain is corrupted, please clean up the data manually and restart the node");

				// let's do retry requests first.
				let mut rng = rand::thread_rng();
				let now = Utc::now();

				// Whoever lock, can send duplicate requests
				let last_retry_height = self.last_retry_height.try_write();
				if let Some(mut last_retry_height) = last_retry_height {
					for (hash, height) in retry_reqs {
						if height <= *last_retry_height {
							continue;
						}

						if need_request == 0 {
							break;
						}

						// We don't want to send retry to the peer whom we already send the data
						if let Some(requested_peer) = self.request_tracker.get_expected_peer(&hash)
						{
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
								debug!("Processing duplicated request for the headers {} at {}, peer {:?}", hash, height, p.info.addr);
								match self.request_headers_for_hash(hash.clone(), height, p.clone())
								{
									Ok(_) => self.retry_expiration_times.write().push_back(
										now + self.request_tracker.get_average_latency(),
									),
									Err(e) => {
										let msg = format!("Failed to send duplicate headers request to {} for hash {}, Error: {}", p.info.addr, hash, e);
										error!("{}", msg);
										sync_peers.report_no_response(&p.info.addr, msg);
										break;
									}
								}
							}
						}

						*last_retry_height = height;
					}
				}

				for (hash, height) in hashes {
					if need_request == 0 {
						break;
					}
					need_request = need_request.saturating_sub(1);
					// sending request
					let peer = peers
						.choose(&mut rng)
						.expect("Internal error. peers are empty");
					match self.request_headers_for_hash(hash.clone(), height, peer.clone()) {
						Ok(_) => {
							self.request_tracker.register_request(
								hash,
								peer.info.addr.clone(),
								format!("Header {}, {}", hash, height),
							);
						}
						Err(e) => {
							let msg = format!(
								"Failed to send headers request to {} for hash {}, Error: {}",
								peer.info.addr, hash, e
							);
							error!("{}", msg);
							sync_peers.report_no_response(&peer.info.addr, msg);
						}
					}
				}

				if need_request > 0 {
					// Free requests, lets duplicated some random from the expected buffer
					let duplicate_reqs: Vec<(Hash, u64)> = waiting_reqs
						.choose_multiple(&mut rng, need_request)
						.cloned()
						.collect();
					for (hash, height) in duplicate_reqs {
						// We don't want to send retry to the peer whom we already send the data
						if let Some(requested_peer) = self.request_tracker.get_expected_peer(&hash)
						{
							let dup_peer = peers
								.iter()
								.filter(|p| p.info.addr != requested_peer)
								.choose(&mut rng);

							if dup_peer.is_none() {
								break;
							}
							let dup_peer = dup_peer.unwrap();

							debug!(
								"Processing duplicated request for the headers {} at {}, peer {:?}",
								hash, height, dup_peer.info.addr
							);
							match self.request_headers_for_hash(
								hash.clone(),
								height,
								dup_peer.clone(),
							) {
								Ok(_) => self
									.retry_expiration_times
									.write()
									.push_back(now + self.request_tracker.get_average_latency()),
								Err(e) => {
									let msg = format!("Failed to send duplicate headers request to {} for hash {}, Error: {}", dup_peer.info.addr, hash, e);
									error!("{}", msg);
									sync_peers.report_no_response(&dup_peer.info.addr, msg);
									break;
								}
							}
						}
					}
				}
			}
		}
	}
}

// current height back to 0 decreasing in powers of 2
pub fn get_locator_heights(height: u64) -> Vec<u64> {
	let mut current = height;
	let mut heights = vec![];
	while current > 0 {
		heights.push(current);
		if heights.len() >= (p2p::MAX_LOCATORS as usize) - 1 {
			break;
		}
		let next = 2u64.pow(heights.len() as u32);
		current = if current > next { current - next } else { 0 }
	}
	heights.push(0);
	heights
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_get_locator_heights() {
		assert_eq!(get_locator_heights(0), vec![0]);
		assert_eq!(get_locator_heights(1), vec![1, 0]);
		assert_eq!(get_locator_heights(2), vec![2, 0]);
		assert_eq!(get_locator_heights(3), vec![3, 1, 0]);
		assert_eq!(get_locator_heights(10), vec![10, 8, 4, 0]);
		assert_eq!(get_locator_heights(100), vec![100, 98, 94, 86, 70, 38, 0]);
		assert_eq!(
			get_locator_heights(1000),
			vec![1000, 998, 994, 986, 970, 938, 874, 746, 490, 0]
		);
		// check the locator is still a manageable length, even for large numbers of
		// headers
		assert_eq!(
			get_locator_heights(10000),
			vec![10000, 9998, 9994, 9986, 9970, 9938, 9874, 9746, 9490, 8978, 7954, 5906, 1810, 0,]
		);
	}
}
