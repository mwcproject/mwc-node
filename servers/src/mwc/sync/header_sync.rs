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

use crate::common::types::Error;
use crate::mwc::sync::header_hashes_sync::HeadersHashSyncSnapshot;
use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils;
use crate::mwc::sync::sync_utils::{
	CachedResponse, RequestTracker, SyncRequestResponses, SyncResponse,
};
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::txhashset::{HeaderHashesDesegmenter, HeadersRecieveCache};
use mwc_chain::{self, SyncState, SyncStatus};
use mwc_chain::{pibd_params, pipe};
use mwc_core::core::hash::Hash;
use mwc_core::core::hash::Hashed;
use mwc_core::core::BlockHeader;
use mwc_core::pow::Difficulty;
use mwc_crates::log::{debug, error, info};
use mwc_crates::parking_lot::{Mutex, RwLock};
use mwc_crates::rand;
use mwc_crates::rand::prelude::IndexedRandom;
use mwc_crates::rand::seq::IteratorRandom;
use mwc_p2p::PeerAddr;
use mwc_p2p::{self, Capabilities, Peer};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HEADERS_SERIES_CACHE_MAX_LEN: usize = 1000;
const HEADERS_SERIES_CACHE_MAX_HEADERS: usize = 20_000;

type HeadersSeriesCache = HashMap<(PeerAddr, Hash), (Vec<BlockHeader>, Instant)>;

fn prune_headers_series_cache(
	headers_series_cache: &mut HeadersSeriesCache,
	now: Instant,
	header_head_height: u64,
) {
	let expiration_time = Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64 * 2);
	headers_series_cache.retain(|_, (_, time)| {
		now.checked_duration_since(*time)
			.map_or(true, |age| age <= expiration_time)
	});

	let total_headers: usize = headers_series_cache
		.values()
		.map(|(headers, _)| headers.len())
		.sum();
	if headers_series_cache.len() <= HEADERS_SERIES_CACHE_MAX_LEN
		&& total_headers <= HEADERS_SERIES_CACHE_MAX_HEADERS
	{
		return;
	}

	let mut entries: Vec<_> = headers_series_cache
		.iter()
		.map(|(key, (headers, time))| {
			let known = headers
				.last()
				.map_or(false, |header| header.height <= header_head_height);
			(key.clone(), headers.len(), *time, known)
		})
		.collect();
	entries.sort_by(
		|(_, _, left_time, left_known), (_, _, right_time, right_known)| {
			right_known
				.cmp(left_known)
				.then_with(|| left_time.cmp(right_time))
		},
	);

	let mut total_headers = total_headers;
	for (key, header_count, _, _) in entries {
		if headers_series_cache.len() <= HEADERS_SERIES_CACHE_MAX_LEN
			&& total_headers <= HEADERS_SERIES_CACHE_MAX_HEADERS
		{
			break;
		}
		if headers_series_cache.remove(&key).is_some() {
			total_headers = total_headers.saturating_sub(header_count);
		}
	}
}

pub struct HeaderSync {
	chain: Arc<mwc_chain::Chain>,
	received_cache: RwLock<Option<HeadersRecieveCache<PeerAddr>>>,
	// requested_heights is expected to be at response height, the next tothe requested
	request_tracker: RequestTracker<Hash>, // Vec<Hash> - locator data for headers request
	cached_response: RwLock<Option<CachedResponse<SyncResponse>>>,
	headers_series_cache: RwLock<HeadersSeriesCache>,
	pibd_params: Arc<PibdParams>,
	last_retry_height: RwLock<u64>,
	retry_expiration_times: RwLock<VecDeque<Instant>>,
	send_requests_lock: RwLock<u8>,
	excluded_peers: RwLock<HashSet<PeerAddr>>,
	// PIBD header batches arrive on multiple p2p reader threads. Applying them
	// feeds the chain and takes header_pmmr/txhashset write locks, so only one
	// thread should attempt it at a time.
	apply_headers_lock: Mutex<()>,
}

impl HeaderSync {
	pub fn new(chain: Arc<mwc_chain::Chain>) -> HeaderSync {
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
			apply_headers_lock: Mutex::new(()),
		}
	}

	fn get_peer_capabilities() -> Capabilities {
		return Capabilities::HEADER_HIST;
	}

	fn ensure_received_cache(
		&self,
		headers_hash_desegmenter: &HeaderHashesDesegmenter,
	) -> Result<(), mwc_chain::Error> {
		let recreate_received_cache = {
			let received_cache = self.received_cache.read_recursive();
			received_cache.as_ref().map_or(true, |cache| {
				!cache.matches_desegmenter(headers_hash_desegmenter)
			})
		};

		if recreate_received_cache {
			// Cached PIBD header batches are authenticated by the selected headers
			// root. HeadersHashSync can reset and choose a new root/target, so
			// discard old batches and in-flight request state before applying cache
			// data or choosing the next header requests.
			let received_cache =
				HeadersRecieveCache::new(self.chain.clone(), headers_hash_desegmenter)?;
			*self.received_cache.write() = Some(received_cache);
			self.request_tracker.clear();
			*self.last_retry_height.write() = 0;
			self.retry_expiration_times.write().clear();
			self.headers_series_cache.write().clear();
			self.excluded_peers.write().clear();
		}

		Ok(())
	}

	fn update_header_sync_status(
		&self,
		sync_state: &SyncState,
		received_cache: &HeadersRecieveCache<PeerAddr>,
	) -> Result<(), mwc_chain::Error> {
		let archive_height = received_cache.get_archive_header_height();
		let current_height = self.chain.header_head()?.height.min(archive_height);
		sync_state.update(SyncStatus::HeaderSync {
			current_height,
			archive_height,
		});
		Ok(())
	}

	fn try_apply_received_cache(
		&self,
		received_cache: &HeadersRecieveCache<PeerAddr>,
	) -> Option<Result<bool, (Option<PeerAddr>, mwc_chain::Error)>> {
		let _apply_guard = self.apply_headers_lock.try_lock()?;
		Some(received_cache.apply_cache())
	}

	pub fn request(
		&self,
		peers: &Arc<mwc_p2p::Peers>,
		sync_state: &SyncState,
		sync_peers: &SyncPeers,
		header_hashes: &HeadersHashSyncSnapshot,
		best_height: u64,
	) -> Result<SyncResponse, mwc_chain::Error> {
		let cached_response = self.cached_response.read_recursive().clone();
		if let Some(cached_response) = cached_response {
			if !cached_response.is_expired() {
				return Ok(cached_response.to_response());
			} else {
				*self.cached_response.write() = None;
			}
		}

		let header_head = self
			.chain
			.header_head()
			.map_err(|e| mwc_chain::Error::Other(format!("Unable to get header_head, {}", e)))?;

		// Quick check - nothing to sync if we are caught up with the peer.
		if header_head.height >= best_height.saturating_sub(7) {
			// we can relax for a pretty long time, headers are ready
			let resp = SyncResponse::new(
				SyncRequestResponses::HeadersReady,
				Self::get_peer_capabilities(),
				format!("Header head {} vs {}", header_head.height, best_height),
			);
			*self.cached_response.write() =
				Some(CachedResponse::new(resp.clone(), Duration::from_secs(60))?);
			return Ok(resp);
		}

		let excluded_peers = self
			.request_tracker
			.retain_expired(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS, sync_peers);
		*self.excluded_peers.write() = excluded_peers;

		// it is initial statis flag
		if !header_hashes.pibd_headers_are_loaded {
			if !header_hashes.is_complete() {
				// Even we can request headers from the bottom, the old style method, but we better to wait
				// for all hashes be ready, it is just 3 segments
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForHeadersHash,
					Self::get_peer_capabilities(),
					"Header hashes are expected but not ready yet".into(),
				));
			} else {
				// finally we have a hashes, on the first attempt we need to validate if what is already uploaded is good
				let headers_hash_desegmenter = header_hashes
					.headers_hash_desegmenter
					.clone()
					.ok_or(mwc_chain::Error::Other(
						"headers_hash_desegmenter is not available".to_string(),
					))?;
				{
					let headers_hash_desegmenter = headers_hash_desegmenter.read_recursive();
					self.ensure_received_cache(&headers_hash_desegmenter)?;
				}

				let received_cache = self.received_cache.read_recursive();
				let received_cache = received_cache.as_ref().ok_or(mwc_chain::Error::Other(
					"Internal error. Received_cache is not initialized.".into(),
				))?;

				// First checking if some headers need to be uploaded to the chain.
				let has_more_data = match self.try_apply_received_cache(received_cache) {
					Some(Ok(has_more_data)) => has_more_data,
					Some(Err((Some(peer), err))) => {
						let msg =
							format!("Failed to process add_headers for {}. Error: {}", peer, err);
						error!("{}", msg);
						sync_peers.report_error_response(&peer, msg);
						false
					}
					Some(Err((None, err))) => {
						error!(
							"Failed to process add_headers without peer attribution. Error: {}",
							err
						);
						return Err(err);
					}
					// Another thread is already applying cached headers. Report pending
					// work so the sync loop retries instead of sending more requests.
					None => true,
				};

				let headers_complete = received_cache.is_complete()?;
				if !headers_complete {
					self.update_header_sync_status(sync_state, received_cache)?;
				}

				if has_more_data {
					return Ok(SyncResponse::new(
						SyncRequestResponses::HasMoreHeadersToApply,
						Self::get_peer_capabilities(),
						"Has more headers data to apply".into(),
					));
				}

				if !headers_complete {
					// Requesting multiple headers
					let (peers, excluded_requests, excluded_peers) = sync_utils::get_sync_peers(
						peers,
						self.pibd_params.get_segments_request_per_peer(),
						Capabilities::HEADER_HIST,
						header_hashes.target_archive_height,
						None,
						&self.request_tracker,
						&*self.excluded_peers.read_recursive(),
					);
					if peers.is_empty() {
						if excluded_peers == 0 {
							return Ok(SyncResponse::new(
								SyncRequestResponses::WaitingForPeers,
								Self::get_peer_capabilities(),
								format!(
									"No peers are available, requests waiting: {}",
									self.request_tracker.get_requests_num()
								),
							));
						} else {
							return Ok(SyncResponse::new(
								SyncRequestResponses::Syncing,
								Self::get_peer_capabilities(),
								format!(
									"Has peers {}, requests waiting: {}",
									excluded_peers,
									self.request_tracker.get_requests_num()
								),
							));
						}
					}

					self.send_requests(
						&peers,
						&headers_hash_desegmenter.read_recursive(),
						sync_peers,
						excluded_requests,
						excluded_peers,
					)?;

					return Ok(SyncResponse::new(
						SyncRequestResponses::Syncing,
						Self::get_peer_capabilities(),
						format!(
							"Loading headers below horizon. Has peers: {} Requests in waiting Q: {}",
							peers.len() + excluded_peers,
							self.request_tracker.get_requests_num()
						),
					));
				}
			}
		}

		// At this point we are above the archive height, so we can request headers sequentually the normal way...
		// sync_state is no needs to update
		let sync_peer = match Self::choose_sync_peer(peers) {
			None => {
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Self::get_peer_capabilities(),
					format!(
						"Loading headers above horizon, no peers are available, requests waiting: {}",
						self.request_tracker.get_requests_num()
					),
				));
			}
			Some(sync_peer) => sync_peer,
		};

		let header_head = self.chain.header_head()?;
		let header_head_hash = header_head.hash(self.chain.get_context_id())?;

		if self.request_tracker.has_request(&header_head_hash) {
			return Ok(SyncResponse::new(
				SyncRequestResponses::HeadersPibdReady,
				Self::get_peer_capabilities(),
				"Loading headers above horizon".into(),
			));
		}

		let (_, peer_diff) = {
			let info = sync_peer.info.live_info.read_recursive();
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
				Some(CachedResponse::new(resp.clone(), Duration::from_secs(60))?);
			return Ok(resp);
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

		return Ok(SyncResponse::new(
			SyncRequestResponses::HeadersPibdReady,
			Self::get_peer_capabilities(),
			"Loading headers above horizon, just requested one.".into(),
		));
	}

	/// Recieved headers handler
	pub fn receive_headers(
		&self,
		peer: &PeerAddr,
		bhs: &[BlockHeader],
		remaining: u64,
		sync_peers: &SyncPeers,
		header_hashes: Option<Arc<RwLock<HeaderHashesDesegmenter>>>,
		peers: &Arc<mwc_p2p::Peers>,
	) -> Result<(), mwc_chain::Error> {
		debug_assert!(!bhs.is_empty());

		let series_key = (
			peer.clone(),
			bhs.first()
				.ok_or(mwc_chain::Error::Other(
					"Invalid bhs data, it can't be empty".into(),
				))?
				.prev_hash
				.clone(),
		);

		let context_id = self.chain.get_context_id();
		let header_head_height = self.chain.header_head()?.height;

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
								peer_bhs
									.last()
									.ok_or(mwc_chain::Error::Other(
										"Invalid bhs data, it can't be empty".into(),
									))?
									.hash(context_id)?,
							),
							(peer_bhs, Instant::now()),
						);
						prune_headers_series_cache(
							&mut headers_series_cache,
							Instant::now(),
							header_head_height,
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
							(
								series_key.0,
								bhs.last()
									.ok_or(mwc_chain::Error::Other(
										"Invalid bhs data, it can't be empty".into(),
									))?
									.hash(context_id)?,
							),
							(bhs.to_vec(), Instant::now()),
						);
						prune_headers_series_cache(
							&mut headers_series_cache,
							Instant::now(),
							header_head_height,
						);
						return Ok(());
					}
				}
			};

			prune_headers_series_cache(
				&mut headers_series_cache,
				Instant::now(),
				header_head_height,
			);
			bhs
		};

		let request_key = bhs[0].prev_hash;
		let tracked_request = self.request_tracker.has_request(&request_key);

		for b in &bhs {
			if pipe::validate_header_hash(context_id, &b.hash(context_id)?).is_err() {
				debug!(
					"headers_received: found known bad header, all data is rejected. Peer: {}",
					peer
				);
				let registered_peer = self.request_tracker.remove_request(&request_key, peer);
				let matched_request = registered_peer
					.as_ref()
					.map_or(false, |registered_peer| registered_peer == peer);
				sync_peers
					.report_error_response(peer, "headers_received: found known bad header".into());
				if matched_request {
					self.request_more_pibd_headers(header_hashes.as_ref(), peers, sync_peers)?;
				}
				return Ok(());
			}
		}

		// That is needed for sync tracking
		info!(
			"Received {} block headers from {}, height {}",
			bhs.len(),
			peer,
			bhs[0].height,
		);

		// try to add headers to our header chain
		if let Some(header_hashes_desegmenter) = header_hashes.as_ref() {
			let header_hashes = header_hashes_desegmenter.read_recursive();
			if bhs[0].height <= header_hashes.get_target_height() {
				if !tracked_request {
					debug!(
						"headers_received: ignored unsolicited PIBD headers from {}, height {}",
						peer, bhs[0].height
					);
					return Ok(());
				}
				self.ensure_received_cache(&header_hashes)?;
				if !self.request_tracker.has_request(&request_key) {
					debug!(
						"headers_received: ignored stale PIBD headers from {}, height {}",
						peer, bhs[0].height
					);
					return Ok(());
				}
				if let Some(received_cache) = self.received_cache.read_recursive().as_ref() {
					// PIBD cache processing failures are handled locally here. For
					// peer-attributable bad data we log and update peer scoring, but we
					// intentionally do not propagate the error to the p2p receive path
					// because that would disconnect the peer instead of continuing sync.
					// Processing with a cache
					match received_cache.add_headers_to_cache(&header_hashes, bhs, peer.clone()) {
						Ok(_) => {
							let registered_peer = self
								.request_tracker
								.remove_request_by_key(&request_key, peer);
							let matched_request = registered_peer
								.as_ref()
								.map_or(false, |registered_peer| registered_peer == peer);
							// Reporting ok only for expected. We don't want attacker to make good points with not expected responses
							if matched_request {
								sync_peers.report_ok_response(peer);
							}
							if registered_peer.is_some() {
								self.request_more_pibd_headers(
									Some(header_hashes_desegmenter),
									peers,
									sync_peers,
								)?;
							}
						}
						Err((bad_peer, err)) => {
							let registered_peer =
								self.request_tracker.remove_request(&request_key, peer);
							let matched_request = registered_peer
								.as_ref()
								.map_or(false, |registered_peer| registered_peer == peer);
							let msg = format!(
								"Failed to process add_headers for {}. Error: {}",
								bad_peer, err
							);
							error!("{}", msg);
							sync_peers.report_error_response(&bad_peer, msg);
							if matched_request {
								self.request_more_pibd_headers(
									Some(header_hashes_desegmenter),
									peers,
									sync_peers,
								)?;
							}
						}
					}
					// Opportunistically apply cached headers from here. If the sync loop
					// or another p2p reader is already applying, skip instead of blocking
					// this network thread on the chain write locks. Cache application
					// failures are handled locally: propagating them to the p2p receive
					// path would disconnect the current peer instead of continuing sync.
					if let Some(apply_result) = self.try_apply_received_cache(received_cache) {
						if let Err((peer, err)) = apply_result {
							let msg = format!(
								"Failed to process add_headers for {:?}. Error: {}",
								peer, err
							);
							error!("{}", msg);
							if let Some(peer) = peer {
								sync_peers.report_error_response(&peer, msg);
							}
						}
					}
					return Ok(());
				}
			}
		}

		// At this point we are processing the headers the regular way, it is expecte that it is a sequentual reponse
		let sync_head = self.chain.header_head()?;

		match self
			.chain
			.sync_block_headers(&bhs, sync_head, mwc_chain::Options::SYNC)
		{
			Ok(sync_head) => {
				let registered_peer = self
					.request_tracker
					.remove_request_by_key(&request_key, peer);
				let matched_request = registered_peer
					.as_ref()
					.map_or(false, |registered_peer| registered_peer == peer);
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
									if matched_request {
										sync_peers.report_ok_response(peer);
									}
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
				if e.is_bad_data() {
					let _ = self.request_tracker.remove_request(&request_key, peer);
					sync_peers.report_error_response(
						&peer,
						format!("sync_block_headers failed with error {}", e),
					);
				} else {
					return Err(e);
				}
			}
		}
		Ok(())
	}

	fn request_more_pibd_headers(
		&self,
		header_hashes: Option<&Arc<RwLock<HeaderHashesDesegmenter>>>,
		peers: &Arc<mwc_p2p::Peers>,
		sync_peers: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		let Some(headers_hash_desegmenter) = header_hashes else {
			return Ok(());
		};
		let headers_hash_desegmenter = headers_hash_desegmenter.read_recursive();
		if !headers_hash_desegmenter.is_complete() {
			return Ok(());
		}
		if self.request_tracker.get_update_requests_to_next_ask() != 0 {
			return Ok(());
		}

		let (peers, excluded_requests, excluded_peers) = sync_utils::get_sync_peers(
			peers,
			self.pibd_params.get_segments_request_per_peer(),
			Capabilities::HEADER_HIST,
			headers_hash_desegmenter.get_target_height(),
			None,
			&self.request_tracker,
			&*self.excluded_peers.read_recursive(),
		);

		if !peers.is_empty() {
			self.send_requests(
				&peers,
				&headers_hash_desegmenter,
				sync_peers,
				excluded_requests,
				excluded_peers,
			)?;
		}

		Ok(())
	}

	fn choose_sync_peer(peers: &Arc<mwc_p2p::Peers>) -> Option<Arc<Peer>> {
		let peers_iter = || {
			peers
				.iter()
				.with_capabilities(Capabilities::HEADER_HIST)
				.connected()
		};

		let mut difficulties: Vec<Difficulty> = peers_iter()
			.into_iter()
			.map(|peer| peer.info.live_info.read_recursive().total_difficulty)
			.collect();
		if difficulties.is_empty() {
			return None;
		}
		difficulties.sort_unstable();
		let median_diff = difficulties[(difficulties.len() - 1) / 2];
		let peers_iter = || peers_iter().with_difficulty(|x| x >= median_diff);

		// Choose a random peer at or above median work, preferring outbound if at all possible.
		peers_iter().outbound().choose_random().or_else(|| {
			debug!("no suitable outbound peer for header sync, considering inbound");
			peers_iter().inbound().choose_random()
		})
	}

	/// Request some block headers from a peer to advance us.
	fn request_headers(
		&self,
		sync_head: mwc_chain::Tip,
		peer: Arc<Peer>,
	) -> Result<(), mwc_chain::Error> {
		let locator = self
			.get_locator(sync_head)
			.map_err(|e| mwc_chain::Error::Other(format!("{}", e)))?;
		debug!(
			"sync: request_headers: asking {} for headers at {}",
			peer.info.addr, sync_head.height
		);
		peer.send_header_request(locator)
			.map_err(|e| mwc_chain::Error::Other(format!("{}", e)))?;
		Ok(())
	}

	fn request_headers_for_hash(
		&self,
		header_hash: Hash,
		height: u64,
		peer: Arc<Peer>,
	) -> Result<(), mwc_chain::Error> {
		debug!(
			"sync: request_headers: asking {} for headers at hash {}, height {}",
			peer.info.addr, header_hash, height
		);
		peer.send_header_request(vec![header_hash])
			.map_err(|e| mwc_chain::Error::Other(format!("{}", e)))?;
		Ok(())
	}

	/// We build a locator based on sync_head.
	/// Even if sync_head is significantly out of date we will "reset" it once we
	/// start getting headers back from a peer.
	fn get_locator(&self, sync_head: mwc_chain::Tip) -> Result<Vec<Hash>, Error> {
		let heights = get_locator_heights(sync_head.height);
		let locator = self.chain.get_locator_hashes(sync_head, &heights)?;
		Ok(locator)
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
		headers_hash_desegmenter: &HeaderHashesDesegmenter,
		sync_peers: &SyncPeers,
		excluded_requests: usize,
		excluded_peers: usize,
	) -> Result<(), mwc_chain::Error> {
		if let Some(_) = self.send_requests_lock.try_write() {
			self.ensure_received_cache(headers_hash_desegmenter)?;
			let average_latency_ms = self.request_tracker.get_average_latency_ms();
			let mut need_request = self.request_tracker.calculate_needed_requests(
				peers.len(),
				excluded_requests,
				excluded_peers,
				self.pibd_params.get_segments_request_per_peer(),
				self.pibd_params
					.get_segments_requests_limit(average_latency_ms),
			);
			need_request = need_request.saturating_sub(self.calc_retry_running_requests());
			if need_request > 0 {
				let received_cache = self.received_cache.read_recursive();
				let received_cache = received_cache.as_ref().ok_or(mwc_chain::Error::Other(
					"Internal error. Received_cache is not initialized.".into(),
				))?;

				let (hashes, retry_reqs, waiting_reqs) = received_cache.next_desired_headers(
					headers_hash_desegmenter,
					need_request,
					&self.request_tracker,
					self.pibd_params.get_headers_buffer_len(),
				)?;

				// let's do retry requests first.
				let mut rng = rand::rng();
				let now = Instant::now();

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
								.sample(&mut rng, need_request.min(2));

							if dup_peers.is_empty() {
								break;
							}

							// we can do retry now
							for p in dup_peers {
								if need_request == 0 {
									break;
								}
								need_request -= 1;
								debug!("Processing duplicated request for the headers {} at {}, peer {:?}", hash, height, p.info.addr);
								match self.request_headers_for_hash(hash.clone(), height, p.clone())
								{
									Ok(_) => self
										.retry_expiration_times
										.write()
										.push_back(now + self.request_tracker.get_retry_latency()),
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
					// Safe: need_request == 0 is handled above.
					need_request -= 1;
					// sending request
					let peer = peers.choose(&mut rng).ok_or(mwc_chain::Error::Other(
						"Internal error. peers are empty".into(),
					))?;
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
						.sample(&mut rng, need_request)
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

							match dup_peer {
								None => break,
								Some(dup_peer) => {
									debug!(
										"Processing duplicated request for the headers {} at {}, peer {:?}",
										hash, height, dup_peer.info.addr
									);
									match self.request_headers_for_hash(
										hash.clone(),
										height,
										dup_peer.clone(),
									) {
										Ok(_) => self.retry_expiration_times.write().push_back(
											now + self.request_tracker.get_retry_latency(),
										),
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
		Ok(())
	}
}

// current height back to 0 decreasing in powers of 2
pub fn get_locator_heights(height: u64) -> Vec<u64> {
	let mut current = height;
	let mut heights = vec![];
	while current > 0 {
		heights.push(current);
		if heights.len() >= (mwc_p2p::MAX_LOCATORS as usize) - 1 {
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

	fn series_cache_key(idx: u16) -> (PeerAddr, Hash) {
		(
			PeerAddr::Ip(format!("127.0.0.1:{}", 10_000u16 + idx).parse().unwrap()),
			Hash::from_vec(&(idx as u64).to_be_bytes()),
		)
	}

	fn insert_series_cache_entry(
		headers_series_cache: &mut HeadersSeriesCache,
		idx: u16,
		time: Instant,
	) {
		headers_series_cache.insert(series_cache_key(idx), (Vec::new(), time));
	}

	fn insert_series_cache_headers(
		headers_series_cache: &mut HeadersSeriesCache,
		idx: u16,
		header_count: usize,
		last_height: u64,
		time: Instant,
	) {
		mwc_core::global::set_local_chain_type(mwc_core::global::ChainTypes::AutomatedTesting);
		let mut header = BlockHeader::default(0);
		header.height = last_height;
		headers_series_cache.insert(series_cache_key(idx), (vec![header; header_count], time));
	}

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

	#[test]
	fn prune_headers_series_cache_expires_and_caps_oldest_entries() {
		let now = Instant::now();
		let mut headers_series_cache = HeadersSeriesCache::new();
		let expired_age =
			Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64 * 2 + 1);

		for idx in 0..3 {
			insert_series_cache_entry(&mut headers_series_cache, 9_000 + idx, now - expired_age);
		}

		let entry_count = HEADERS_SERIES_CACHE_MAX_LEN + 5;
		for idx in 0..entry_count {
			let age_ms = (entry_count - idx) as i64;
			insert_series_cache_entry(
				&mut headers_series_cache,
				idx as u16,
				now - Duration::from_millis(age_ms as u64),
			);
		}

		prune_headers_series_cache(&mut headers_series_cache, now, 0);

		assert_eq!(headers_series_cache.len(), HEADERS_SERIES_CACHE_MAX_LEN);
		for idx in 0..3 {
			assert!(!headers_series_cache.contains_key(&series_cache_key(9_000 + idx)));
		}
		for idx in 0..5 {
			assert!(!headers_series_cache.contains_key(&series_cache_key(idx)));
		}
		for idx in 5..entry_count {
			assert!(headers_series_cache.contains_key(&series_cache_key(idx as u16)));
		}
	}

	#[test]
	fn prune_headers_series_cache_evicts_known_headers_before_oldest_unknown_headers() {
		let now = Instant::now();
		let mut headers_series_cache = HeadersSeriesCache::new();
		let header_count = HEADERS_SERIES_CACHE_MAX_HEADERS / 3 + 1;

		insert_series_cache_headers(
			&mut headers_series_cache,
			1,
			header_count,
			300,
			now - Duration::from_millis(1),
		);
		insert_series_cache_headers(
			&mut headers_series_cache,
			2,
			header_count,
			900,
			now - Duration::from_millis(3),
		);
		insert_series_cache_headers(
			&mut headers_series_cache,
			3,
			header_count,
			901,
			now - Duration::from_millis(2),
		);

		prune_headers_series_cache(&mut headers_series_cache, now, 500);

		assert!(!headers_series_cache.contains_key(&series_cache_key(1)));
		assert!(headers_series_cache.contains_key(&series_cache_key(2)));
		assert!(headers_series_cache.contains_key(&series_cache_key(3)));
		assert!(
			headers_series_cache
				.values()
				.map(|(headers, _)| headers.len())
				.sum::<usize>()
				<= HEADERS_SERIES_CACHE_MAX_HEADERS
		);
	}

	#[test]
	fn prune_headers_series_cache_evicts_oldest_headers_after_known_headers() {
		let now = Instant::now();
		let mut headers_series_cache = HeadersSeriesCache::new();
		let header_count = HEADERS_SERIES_CACHE_MAX_HEADERS / 3 + 1;

		insert_series_cache_headers(
			&mut headers_series_cache,
			1,
			header_count,
			900,
			now - Duration::from_millis(3),
		);
		insert_series_cache_headers(
			&mut headers_series_cache,
			2,
			header_count,
			901,
			now - Duration::from_millis(2),
		);
		insert_series_cache_headers(
			&mut headers_series_cache,
			3,
			header_count,
			902,
			now - Duration::from_millis(1),
		);

		prune_headers_series_cache(&mut headers_series_cache, now, 500);

		assert!(!headers_series_cache.contains_key(&series_cache_key(1)));
		assert!(headers_series_cache.contains_key(&series_cache_key(2)));
		assert!(headers_series_cache.contains_key(&series_cache_key(3)));
		assert!(
			headers_series_cache
				.values()
				.map(|(headers, _)| headers.len())
				.sum::<usize>()
				<= HEADERS_SERIES_CACHE_MAX_HEADERS
		);
	}
}
