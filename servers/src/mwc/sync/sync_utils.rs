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

// sync_utils contain banch of shared between mutiple sync modules routines
// Normally we would put that into the base class, but rust doesn't support that.

use crate::mwc::sync::sync_peers::SyncPeers;
use chrono::{DateTime, Duration, Utc};
use mwc_chain::txhashset::request_lookup::RequestLookup;
use mwc_chain::{pibd_params, Chain};
use mwc_p2p::{Capabilities, Peer, PeerAddr, Peers};
use mwc_util::RwLock;
use std::cmp;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq)]
pub enum SyncRequestResponses {
	Syncing,
	WaitingForPeers,
	HeadersHashReady,
	WaitingForHeadersHash,
	HeadersPibdReady,
	HeadersReady,
	HashMoreHeadersToApply,
	WaitingForHeaders,
	StatePibdReady,
	BadState, // need update state, probably horizon was changed, need to retry
	BodyReady,
	SyncDone,
}

#[derive(Clone, Debug)]
pub struct SyncResponse {
	pub response: SyncRequestResponses,
	pub peers_capabilities: Capabilities,
	pub message: String,
}

impl SyncResponse {
	pub fn new(
		response: SyncRequestResponses,
		peers_capabilities: Capabilities,
		message: String,
	) -> Self {
		SyncResponse {
			response,
			peers_capabilities,
			message,
		}
	}
}

#[derive(Clone)]
pub struct CachedResponse<T> {
	time: DateTime<Utc>,
	response: T,
}

impl<T> CachedResponse<T> {
	pub fn new(response: T, timeout: Duration) -> Self {
		CachedResponse {
			time: Utc::now() + timeout,
			response,
		}
	}

	pub fn is_expired(&self) -> bool {
		Utc::now() > self.time
	}

	pub fn to_response(self) -> T {
		self.response
	}
}

#[derive(Clone)]
pub struct PeerTrackData {
	requests: u32,
}

impl PeerTrackData {
	fn new(requests: u32) -> Self {
		PeerTrackData { requests }
	}
}

pub struct RequestData {
	peer: PeerAddr,
	request_time: DateTime<Utc>,
	request_message: String, // for logging and debugging
}

impl RequestData {
	fn new(peer: PeerAddr, request_message: String) -> Self {
		let now = Utc::now();
		RequestData {
			peer,
			request_time: now.clone(),
			request_message,
		}
	}
}

struct LatencyTracker {
	latency_history: VecDeque<i64>,
	latency_sum: i64,
}

impl LatencyTracker {
	fn new() -> Self {
		LatencyTracker {
			latency_history: VecDeque::new(),
			latency_sum: 0,
		}
	}

	fn clear(&mut self) {
		self.latency_history.clear();
		self.latency_sum = 0;
	}

	fn add_latency(&mut self, latency_ms: i64) {
		self.latency_history.push_back(latency_ms);
		self.latency_sum += latency_ms;
		while self.latency_history.len() > 15 {
			let lt = self.latency_history.pop_front().expect("non empty data");
			self.latency_sum -= lt;
		}
	}

	fn get_average_latency(&self) -> Duration {
		let dur_ms = if self.latency_history.is_empty() {
			pibd_params::PIBD_REQUESTS_TIMEOUT_SECS * 1000
		} else {
			self.latency_sum / self.latency_history.len() as i64
		};
		Duration::milliseconds(dur_ms)
	}
}

/// Utility class or tracking requests. Here we put common request related functionality
/// Idea behind that is to make sync tolerate stale peer. We don't want to wait slow peer for full timeout,
/// instead we want to utilize more faster peers. Also, we don't want superfast peer to take more
/// traffic. In other words, we don't want peers be able to manipulate traffic shceduler.
pub struct RequestTracker<K>
where
	K: std::cmp::Eq + std::hash::Hash,
{
	// Values: peer, time, message.
	requested: RwLock<HashMap<K, RequestData>>, //  Lock 1
	// there are so many peers and many requests, so we better to hande 'slow' peer cases
	peers_stats: RwLock<HashMap<PeerAddr, PeerTrackData>>, // Lock 2
	requests_to_next_ask: AtomicI32,
	// latency in MS
	latency_tracker: RwLock<LatencyTracker>,
}

impl<K> RequestLookup<K> for RequestTracker<K>
where
	K: std::cmp::Eq + std::hash::Hash,
{
	fn contains_request(&self, key: &K) -> bool {
		self.requested.read().contains_key(key)
	}
}

impl<K> RequestTracker<K>
where
	K: std::cmp::Eq + std::hash::Hash,
{
	pub fn new() -> Self {
		RequestTracker {
			requested: RwLock::new(HashMap::new()),
			peers_stats: RwLock::new(HashMap::new()),
			requests_to_next_ask: AtomicI32::new(0),
			latency_tracker: RwLock::new(LatencyTracker::new()),
		}
	}

	pub fn retain_expired(
		&self,
		expiration_time_interval_sec: i64,
		sync_peers: &SyncPeers,
	) -> HashSet<PeerAddr> {
		let mut requested = self.requested.write();
		let peers_stats = &mut self.peers_stats.write();
		let now = Utc::now();

		let mut res: HashSet<PeerAddr> = HashSet::new();

		// first let's clean up stale requests...
		requested.retain(|_, request_data| {
			let peer_stat = peers_stats.get_mut(&request_data.peer);
			if (now - request_data.request_time).num_seconds() > expiration_time_interval_sec {
				sync_peers
					.report_no_response(&request_data.peer, request_data.request_message.clone());
				res.insert(request_data.peer.clone());
				if let Some(n) = peer_stat {
					n.requests = n.requests.saturating_sub(1);
				}
				return false;
			}
			true
		});
		res
	}

	pub fn clear(&self) {
		self.requested.write().clear();
		self.peers_stats.write().clear();
		self.requests_to_next_ask.store(0, Ordering::Relaxed);
		self.latency_tracker.write().clear();
	}

	/// Calculate how many new requests we can make to the peers. This call updates requests_to_next_ask
	pub fn calculate_needed_requests(
		&self,
		peer_num: usize,
		excluded_requests: usize,
		_excluded_peers: usize,
		request_per_peer: usize,
		requests_limit: usize,
	) -> usize {
		let requests_in_queue = self
			.requested
			.read()
			.len()
			.saturating_sub(excluded_requests);
		let expected_total_request = cmp::min(peer_num * request_per_peer, requests_limit);
		self.requests_to_next_ask.store(
			(expected_total_request + excluded_requests) as i32 / 5,
			Ordering::Relaxed,
		);
		expected_total_request.saturating_sub(requests_in_queue)
	}

	pub fn get_requests_num(&self) -> usize {
		self.requested.read().len()
	}

	pub fn has_request(&self, req: &K) -> bool {
		self.requested.read().contains_key(req)
	}

	pub fn get_update_requests_to_next_ask(&self) -> usize {
		let res = self.requests_to_next_ask.fetch_sub(1, Ordering::Relaxed);
		if res >= 0 {
			res as usize
		} else {
			0
		}
	}

	pub fn get_peer_track_data(&self, peer: &PeerAddr) -> Option<PeerTrackData> {
		self.peers_stats.read().get(peer).cloned()
	}

	pub fn register_request(&self, key: K, peer: PeerAddr, message: String) {
		let mut requested = self.requested.write();
		let peers_stats = &mut self.peers_stats.write();

		match peers_stats.get_mut(&peer) {
			Some(n) => {
				n.requests += 1;
			}
			None => {
				peers_stats.insert(peer.clone(), PeerTrackData::new(1));
			}
		}
		requested.insert(key, RequestData::new(peer, message));
	}

	pub fn remove_request(&self, key: &K, peer: &PeerAddr) -> Option<PeerAddr> {
		let mut requested = self.requested.write();
		let peers_stats = &mut self.peers_stats.write();

		if let Some(request_data) = requested.get(key) {
			let res_peer = request_data.peer.clone();
			if request_data.peer == *peer {
				if let Some(n) = peers_stats.get_mut(&request_data.peer) {
					n.requests = n.requests.saturating_sub(1);
				}
				let latency_ms = (Utc::now() - request_data.request_time).num_milliseconds();
				debug_assert!(latency_ms >= 0);
				self.latency_tracker.write().add_latency(latency_ms);
				requested.remove(key);
			}
			Some(res_peer)
		} else {
			None
		}
	}

	pub fn get_average_latency(&self) -> Duration {
		self.latency_tracker.read().get_average_latency()
	}

	pub fn get_expected_peer(&self, key: &K) -> Option<PeerAddr> {
		if let Some(req_data) = self.requested.read().get(key) {
			Some(req_data.peer.clone())
		} else {
			None
		}
	}
}

/// Get a list of qualify peers. Peers that has needed height and capability
pub fn get_qualify_peers(
	peers: &Arc<Peers>,
	archive_height: u64,
	capability: Capabilities,
) -> Vec<Arc<Peer>> {
	// First, get max difficulty or greater peers
	peers
		.iter()
		.outbound()
		.connected()
		.into_iter()
		.filter(|peer| {
			Chain::height_2_archive_height(peer.info.height()) == archive_height
				&& peer.info.capabilities.contains(capability)
		})
		.collect()
}

// return: (peers, number of excluded requests)
pub fn get_sync_peers<T: std::cmp::Eq + std::hash::Hash>(
	peers: &Arc<Peers>,
	expected_requests_per_peer: usize,
	capabilities: Capabilities,
	min_height: u64,
	request_tracker: &RequestTracker<T>,
	excluded_peer_addr: &HashSet<PeerAddr>,
) -> (Vec<Arc<Peer>>, u32, u32) {
	// Excluding peers with totally full Q
	let peer_requests_limit = expected_requests_per_peer as u32;
	let mut res: Vec<Arc<Peer>> = Vec::new();
	// for excluded we nned to cover offline prrs as well. That is why we are counting back
	let mut excluded_requests: usize = request_tracker.get_requests_num();
	let mut excluded_peers = 0;
	let mut found_outbound = false;
	for peer in peers
		.iter()
		.with_capabilities(capabilities)
		.connected()
		.outbound()
		.with_min_height(min_height)
	{
		let mut excluded = excluded_peer_addr.contains(&peer.info.addr);
		found_outbound = true;
		if let Some(track_data) = request_tracker.get_peer_track_data(&peer.info.addr) {
			if !excluded && track_data.requests < peer_requests_limit {
				excluded_requests = excluded_requests.saturating_sub(track_data.requests as usize);
			} else {
				excluded = true;
			}
		}
		if !excluded {
			res.push(peer);
		} else {
			excluded_peers += 1;
		}
	}
	if !found_outbound {
		// adding inbounds since no outbound is found...
		for peer in peers
			.iter()
			.with_capabilities(capabilities)
			.connected()
			.inbound()
			.with_min_height(min_height)
		{
			let mut excluded = excluded_peer_addr.contains(&peer.info.addr);
			if let Some(track_data) = request_tracker.get_peer_track_data(&peer.info.addr) {
				if !excluded && track_data.requests < peer_requests_limit {
					excluded_requests =
						excluded_requests.saturating_sub(track_data.requests as usize);
				} else {
					excluded = true;
				}
			}
			if !excluded {
				res.push(peer);
			} else {
				excluded_peers += 1;
			}
		}
	}
	(res, excluded_requests as u32, excluded_peers)
}
