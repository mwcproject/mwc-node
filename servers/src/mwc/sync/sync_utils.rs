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
use mwc_chain::Chain;
use mwc_p2p::{Capabilities, Peer, PeerAddr, Peers};
use std::cmp;
use std::collections::HashMap;
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

/// Utility class or tracking requests. Here we put common request related functionality
/// Idea behind that is to make sync tolerate stale peer. We don't want to wait slow peer for full timeout,
/// instead we want to utilize more faster peers. Also, we don't want superfast peer to take more
/// traffic. In other words, we don't want peers be able to manipulate traffic shceduler.
pub struct RequestTracker<K>
where
	K: std::cmp::Eq + std::hash::Hash,
{
	requested_hashes: HashMap<K, (PeerAddr, DateTime<Utc>, String)>, // Values: peer, time, message
	peers_queue_size: HashMap<PeerAddr, u32>, // there are so many peers and many requests, so we better to hande 'slow' peer cases
	requests_to_next_ask: usize,
}

impl<K> RequestTracker<K>
where
	K: std::cmp::Eq + std::hash::Hash,
{
	pub fn new() -> Self {
		RequestTracker {
			requested_hashes: HashMap::new(),
			peers_queue_size: HashMap::new(),
			requests_to_next_ask: 0,
		}
	}

	pub fn retain_expired(
		&mut self,
		expiration_time_interval_sec: i64,
		sync_peers: &mut SyncPeers,
	) {
		let requested_hashes = &mut self.requested_hashes;
		let peers_queue_size = &mut self.peers_queue_size;
		let now = Utc::now();

		// first let's clean up stale requests...
		requested_hashes.retain(|_, (peer, req_time, message)| {
			if (now - *req_time).num_seconds() > expiration_time_interval_sec {
				sync_peers.report_no_response(peer, message.clone());
				if let Some(n) = peers_queue_size.get_mut(peer) {
					*n = n.saturating_sub(1);
				}
				return false;
			}
			true
		});
	}

	pub fn clear(&mut self) {
		self.requested_hashes.clear();
		self.peers_queue_size.clear();
		self.requests_to_next_ask = 0;
	}

	pub fn get_requested(&self) -> &HashMap<K, (PeerAddr, DateTime<Utc>, String)> {
		&self.requested_hashes
	}

	/// Calculate how many new requests we can make to the peers. This call updates requests_to_next_ask
	pub fn calculate_needed_requests(
		&mut self,
		peer_num: usize,
		excluded_requests: usize,
		request_per_peer: usize,
		requests_limit: usize,
	) -> usize {
		let requests_in_queue = self
			.requested_hashes
			.len()
			.saturating_sub(excluded_requests);
		let expected_total_request = cmp::min(peer_num * request_per_peer, requests_limit);
		self.requests_to_next_ask = expected_total_request / 5;
		expected_total_request.saturating_sub(requests_in_queue)
	}

	pub fn get_requests_num(&self) -> usize {
		self.requested_hashes.len()
	}

	pub fn has_request(&self, req: &K) -> bool {
		self.requested_hashes.contains_key(req)
	}

	pub fn get_update_requests_to_next_ask(&mut self) -> usize {
		self.requests_to_next_ask = self.requests_to_next_ask.saturating_sub(1);
		self.requests_to_next_ask
	}

	pub fn get_peers_queue_size(&self) -> &HashMap<PeerAddr, u32> {
		&self.peers_queue_size
	}

	pub fn register_request(&mut self, key: K, peer: PeerAddr, message: String) {
		match self.peers_queue_size.get_mut(&peer) {
			Some(n) => {
				*n = n.saturating_add(1);
			}
			None => {
				self.peers_queue_size.insert(peer.clone(), 1);
			}
		}
		self.requested_hashes
			.insert(key, (peer, Utc::now(), message));
	}

	pub fn remove_request(&mut self, key: &K) -> Option<PeerAddr> {
		if let Some((peer, _time, _message)) = self.requested_hashes.remove(key) {
			if let Some(n) = self.peers_queue_size.get_mut(&peer) {
				*n = n.saturating_sub(1);
			}
			Some(peer)
		} else {
			None
		}
	}

	pub fn get_expected_peer(&self, key: &K) -> Option<PeerAddr> {
		if let Some((peer, _time, _message)) = self.requested_hashes.get(key) {
			Some(peer.clone())
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
	peers_queue_size: &HashMap<PeerAddr, u32>,
) -> (Vec<Arc<Peer>>, u32) {
	// Excluding peers with totally full Q
	let peer_requests_limit = (expected_requests_per_peer * 2) as u32;
	let mut res: Vec<Arc<Peer>> = Vec::new();
	// for excluded we nned to cover offline prrs as well. That is why we are counting back
	let mut excluded_requests: usize = total_queue_requests;
	let mut found_outbound = false;
	for peer in peers
		.iter()
		.with_capabilities(capabilities)
		.connected()
		.outbound()
		.with_min_height(min_height)
	{
		found_outbound = true;
		if let Some(sz) = peers_queue_size.get(&peer.info.addr) {
			if *sz < peer_requests_limit {
				excluded_requests = excluded_requests.saturating_sub(*sz as usize);
			} else {
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
			if let Some(sz) = peers_queue_size.get(&peer.info.addr) {
				if *sz < peer_requests_limit {
					excluded_requests = excluded_requests.saturating_sub(*sz as usize);
				} else {
					continue;
				}
			}
			res.push(peer);
		}
	}
	(res, excluded_requests as u32)
}
