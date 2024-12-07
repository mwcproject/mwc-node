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
use mwc_chain::{pibd_params, Chain};
use mwc_p2p::{Capabilities, Peer, PeerAddr, Peers};
use std::cmp;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

#[derive(Clone, Debug, PartialEq)]
pub enum SyncRequestResponses {
	Syncing,
	WaitingForPeers,
	HeadersHashReady,
	WaitingForHeadersHash,
	HeadersPibdReady,
	HeadersReady,
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

	pub fn get_response(&self) -> &T {
		&self.response
	}
}

pub struct PeerTrackData {
	requests: u32,
	response_time: VecDeque<i64>,
	response_time_sum: i64,
}

impl PeerTrackData {
	fn new(requests: u32) -> Self {
		PeerTrackData {
			requests,
			response_time: VecDeque::new(), // units: ms
			response_time_sum: 0,
		}
	}

	fn get_response_time(&self) -> i64 {
		if self.response_time.is_empty() {
			pibd_params::SEGMENT_DEFAULT_RETRY_MS
		} else {
			self.response_time_sum / self.response_time.len() as i64
		}
	}

	fn report_response(&mut self, response_latency: Duration) {
		self.requests = self.requests.saturating_sub(1);
		let response_latency = response_latency.num_milliseconds();
		self.response_time_sum += response_latency;
		self.response_time.push_back(response_latency);
		if self.response_time.len() > 10 {
			self.response_time_sum -= self
				.response_time
				.pop_front()
				.expect("response_time not empty");
		}
	}
}

pub struct RequestData<V> {
	peer: PeerAddr,
	request_time: DateTime<Utc>,
	retry_time: DateTime<Utc>,
	request_message: String, // for logging and debugging
	request_data: V,         // data enough to retry the same request
}

impl<V> RequestData<V> {
	fn new(peer: PeerAddr, request_message: String, request_data: V) -> Self {
		let now = Utc::now();
		RequestData {
			peer,
			request_time: now.clone(),
			retry_time: now,
			request_message,
			request_data,
		}
	}
}

/// Utility class or tracking requests. Here we put common request related functionality
/// Idea behind that is to make sync tolerate stale peer. We don't want to wait slow peer for full timeout,
/// instead we want to utilize more faster peers. Also, we don't want superfast peer to take more
/// traffic. In other words, we don't want peers be able to manipulate traffic shceduler.
pub struct RequestTracker<K, V>
where
	K: std::cmp::Eq + std::hash::Hash,
{
	requested: HashMap<K, RequestData<V>>, // Values: peer, time, message
	peers_stats: HashMap<PeerAddr, PeerTrackData>, // there are so many peers and many requests, so we better to hande 'slow' peer cases
	requests_to_next_ask: usize,
}

impl<K, V> RequestTracker<K, V>
where
	K: std::cmp::Eq + std::hash::Hash,
{
	pub fn new() -> Self {
		RequestTracker {
			requested: HashMap::new(),
			peers_stats: HashMap::new(),
			requests_to_next_ask: 0,
		}
	}

	pub fn retain_expired<F>(
		&mut self,
		expiration_time_interval_sec: i64,
		sync_peers: &mut SyncPeers,
		retry_callback: F,
	) where
		// Callback function that suppose to retry request to the peer. Return true if peer was alive and retry was sent.
		F: Fn(&PeerAddr, &V) -> bool,
	{
		let requested = &mut self.requested;
		let peers_stats = &mut self.peers_stats;
		let now = Utc::now();

		// first let's clean up stale requests...
		requested.retain(|_, request_data| {
			let peer_stat = peers_stats.get_mut(&request_data.peer);
			if (now - request_data.request_time).num_seconds() > expiration_time_interval_sec {
				sync_peers
					.report_no_response(&request_data.peer, request_data.request_message.clone());
				if let Some(n) = peer_stat {
					n.requests = n.requests.saturating_sub(1);
				}
				return false;
			}
			// check we want to retry
			let retry_ms = match peer_stat.as_ref() {
				Some(ps) => ps.get_response_time() * 2,
				None => pibd_params::SEGMENT_DEFAULT_RETRY_MS * 2,
			};
			if (now - request_data.retry_time).num_milliseconds() > retry_ms {
				if !retry_callback(&request_data.peer, &request_data.request_data) {
					// retry failed, so the peer is offline.
					sync_peers.report_no_response(
						&request_data.peer,
						request_data.request_message.clone(),
					);
					if let Some(n) = peer_stat {
						n.requests = n.requests.saturating_sub(1);
					}
					return false;
				}
				// retry was sent, we are good...
				request_data.retry_time = now;
			}
			true
		});
	}

	pub fn clear(&mut self) {
		self.requested.clear();
		self.peers_stats.clear();
		self.requests_to_next_ask = 0;
	}

	pub fn get_requested(&self) -> &HashMap<K, RequestData<V>> {
		&self.requested
	}

	/// Calculate how many new requests we can make to the peers. This call updates requests_to_next_ask
	pub fn calculate_needed_requests(
		&mut self,
		peer_num: usize,
		excluded_requests: usize,
		_excluded_peers: usize,
		request_per_peer: usize,
		requests_limit: usize,
	) -> usize {
		let requests_in_queue = self.requested.len().saturating_sub(excluded_requests);
		let expected_total_request = cmp::min(peer_num * request_per_peer, requests_limit);
		self.requests_to_next_ask = (expected_total_request + excluded_requests) / 5;
		expected_total_request.saturating_sub(requests_in_queue)
	}

	pub fn get_requests_num(&self) -> usize {
		self.requested.len()
	}

	pub fn has_request(&self, req: &K) -> bool {
		self.requested.contains_key(req)
	}

	pub fn get_update_requests_to_next_ask(&mut self) -> usize {
		self.requests_to_next_ask = self.requests_to_next_ask.saturating_sub(1);
		self.requests_to_next_ask
	}

	pub fn get_peers_track_data(&self) -> &HashMap<PeerAddr, PeerTrackData> {
		&self.peers_stats
	}

	pub fn register_request(&mut self, key: K, peer: PeerAddr, message: String, request_data: V) {
		match self.peers_stats.get_mut(&peer) {
			Some(n) => {
				n.requests += 1;
			}
			None => {
				self.peers_stats.insert(peer.clone(), PeerTrackData::new(1));
			}
		}
		self.requested
			.insert(key, RequestData::new(peer, message, request_data));
	}

	pub fn remove_request(&mut self, key: &K) -> Option<PeerAddr> {
		if let Some(request_data) = self.requested.remove(key) {
			if let Some(n) = self.peers_stats.get_mut(&request_data.peer) {
				n.report_response(Utc::now() - request_data.request_time);
			}
			Some(request_data.peer)
		} else {
			None
		}
	}

	pub fn get_expected_peer(&self, key: &K) -> Option<PeerAddr> {
		if let Some(req_data) = self.requested.get(key) {
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
pub fn get_sync_peers(
	peers: &Arc<Peers>,
	expected_requests_per_peer: usize,
	capabilities: Capabilities,
	min_height: u64,
	total_queue_requests: usize,
	peers_queue_size: &HashMap<PeerAddr, PeerTrackData>,
) -> (Vec<Arc<Peer>>, u32, u32) {
	// Excluding peers with totally full Q
	let peer_requests_limit = expected_requests_per_peer as u32;
	let mut res: Vec<Arc<Peer>> = Vec::new();
	// for excluded we nned to cover offline prrs as well. That is why we are counting back
	let mut excluded_requests: usize = total_queue_requests;
	let mut excluded_peers = 0;
	let mut found_outbound = false;
	for peer in peers
		.iter()
		.with_capabilities(capabilities)
		.connected()
		.outbound()
		.with_min_height(min_height)
	{
		found_outbound = true;
		if let Some(track_data) = peers_queue_size.get(&peer.info.addr) {
			if track_data.requests < peer_requests_limit {
				excluded_requests = excluded_requests.saturating_sub(track_data.requests as usize);
			} else {
				excluded_peers += 1;
				continue;
			}
		}
		res.push(peer);
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
			if let Some(track_data) = peers_queue_size.get(&peer.info.addr) {
				if track_data.requests < peer_requests_limit {
					excluded_requests =
						excluded_requests.saturating_sub(track_data.requests as usize);
				} else {
					excluded_peers += 1;
					continue;
				}
			}
			res.push(peer);
		}
	}
	(res, excluded_requests as u32, excluded_peers)
}
