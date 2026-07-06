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
use mwc_chain::txhashset::request_lookup::RequestLookup;
use mwc_chain::{pibd_params, Chain, Error};
use mwc_crates::parking_lot::RwLock;
use mwc_p2p::{Capabilities, Peer, PeerAddr, Peers};
use std::cmp;
use std::cmp::max;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq)]
pub enum SyncRequestResponses {
	Syncing,
	WaitingForPeers,
	HeadersHashReady,
	WaitingForHeadersHash,
	HeadersPibdReady,
	HeadersReady,
	HasMoreHeadersToApply,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuorumSelection<V, I> {
	Selected { value: V, items: Vec<I> },
	NeedMoreResponses { responses: usize },
	NoQuorum { responses: usize, best_count: usize },
}

pub fn select_quorum<I, V>(
	items: impl Iterator<Item = I>,
	required_responses: usize,
	min_responses: usize,
	value_fn: impl Fn(&I) -> V,
) -> QuorumSelection<V, I>
where
	V: Copy + Eq + std::hash::Hash,
{
	let required_responses = cmp::max(required_responses, min_responses);
	let mut items_by_value: HashMap<V, Vec<I>> = HashMap::new();
	let mut responses = 0;
	for item in items {
		responses += 1;
		items_by_value
			.entry(value_fn(&item))
			.or_default()
			.push(item);
	}

	if responses < required_responses {
		return QuorumSelection::NeedMoreResponses { responses };
	}

	let (best_value, best_items) = match items_by_value
		.into_iter()
		.max_by_key(|(_, items)| items.len())
	{
		Some(best) => best,
		None => {
			return QuorumSelection::NeedMoreResponses { responses };
		}
	};
	let best_count = best_items.len();
	if best_count >= required_responses {
		QuorumSelection::Selected {
			value: best_value,
			items: best_items,
		}
	} else {
		QuorumSelection::NoQuorum {
			responses,
			best_count,
		}
	}
}

#[derive(Clone)]
pub struct CachedResponse<T> {
	time: Instant,
	response: T,
}

impl<T> CachedResponse<T> {
	pub fn new(response: T, timeout: Duration) -> Result<Self, Error> {
		let now = Instant::now();
		let time = now.checked_add(timeout).ok_or_else(|| {
			Error::DataOverflow(format!(
				"CachedResponse timeout exceeds representable Instant range: {:?}",
				timeout
			))
		})?;
		Ok(CachedResponse { time, response })
	}

	pub fn is_expired(&self) -> bool {
		Instant::now() > self.time
	}

	pub fn to_response(self) -> T {
		self.response
	}
}

#[derive(Clone)]
pub struct PeerTrackData {
	requests: usize,
}

impl PeerTrackData {
	fn new(requests: usize) -> Self {
		PeerTrackData { requests }
	}
}

pub struct RequestData {
	peer: PeerAddr,
	request_time: Instant,
	request_message: String, // for logging and debugging
}

impl RequestData {
	fn new(peer: PeerAddr, request_message: String) -> Self {
		RequestData {
			peer,
			request_time: Instant::now(),
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
		if latency_ms <= 0 {
			return;
		}
		self.latency_history.push_back(latency_ms);
		// Safe: request latency is measured from an in-process timestamp and the
		// history is capped at 15 entries, so the accumulated milliseconds stay
		// far below i64::MAX.
		self.latency_sum += latency_ms;
		while self.latency_history.len() > 15 {
			let Some(lt) = self.latency_history.pop_front() else {
				break;
			};
			// Safe: lt was previously included in latency_sum.
			self.latency_sum -= lt;
		}
	}

	fn get_average_latency(&self) -> Option<Duration> {
		if self.latency_history.is_empty() {
			None
		} else {
			let latency_ms = self.latency_sum / self.latency_history.len() as i64;
			if latency_ms <= 0 {
				Some(Duration::ZERO)
			} else {
				Some(Duration::from_millis(latency_ms as u64))
			}
		}
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
	requests_to_next_ask: AtomicUsize,
	// latency in MS
	latency_tracker: RwLock<LatencyTracker>,
}

impl<K> RequestLookup<K> for RequestTracker<K>
where
	K: std::cmp::Eq + std::hash::Hash,
{
	fn contains_request(&self, key: &K) -> bool {
		self.requested.read_recursive().contains_key(key)
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
			requests_to_next_ask: AtomicUsize::new(0),
			latency_tracker: RwLock::new(LatencyTracker::new()),
		}
	}

	pub fn retain_expired(
		&self,
		expiration_time_interval_sec: u32,
		sync_peers: &SyncPeers,
	) -> HashSet<PeerAddr> {
		let mut requested = self.requested.write();
		let peers_stats = &mut self.peers_stats.write();
		let expiration_time_interval = Duration::from_secs(expiration_time_interval_sec as u64);

		let mut res: HashSet<PeerAddr> = HashSet::new();

		// first let's clean up stale requests...
		requested.retain(|_, request_data| {
			let peer_stat = peers_stats.get_mut(&request_data.peer);
			if request_data.request_time.elapsed() > expiration_time_interval {
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
		let mut requested = self.requested.write();
		let mut peers_stats = self.peers_stats.write();
		requested.clear();
		peers_stats.clear();
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
			.read_recursive()
			.len()
			.saturating_sub(excluded_requests);
		let expected_total_request =
			cmp::min(peer_num.saturating_mul(request_per_peer), requests_limit);
		self.requests_to_next_ask.store(
			max(
				1,
				expected_total_request.saturating_add(excluded_requests) / 5,
			),
			Ordering::Relaxed,
		);
		expected_total_request.saturating_sub(requests_in_queue)
	}

	pub fn get_requests_num(&self) -> usize {
		self.requested.read_recursive().len()
	}

	pub fn has_request(&self, req: &K) -> bool {
		self.requested.read_recursive().contains_key(req)
	}

	pub fn get_update_requests_to_next_ask(&self) -> usize {
		self.requests_to_next_ask
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				Some(current.saturating_sub(1))
			})
			.unwrap_or_else(|current| current)
	}

	pub fn get_peer_track_data(&self, peer: &PeerAddr) -> Option<PeerTrackData> {
		self.peers_stats.read_recursive().get(peer).cloned()
	}

	pub fn register_request(&self, key: K, peer: PeerAddr, message: String) {
		let mut requested = self.requested.write();
		let peers_stats = &mut self.peers_stats.write();

		if let Some(request_data) = requested.insert(key, RequestData::new(peer.clone(), message)) {
			if let Some(n) = peers_stats.get_mut(&request_data.peer) {
				n.requests = n.requests.saturating_sub(1);
			}
		}

		match peers_stats.get_mut(&peer) {
			Some(n) => {
				n.requests = n.requests.saturating_add(1);
			}
			None => {
				peers_stats.insert(peer.clone(), PeerTrackData::new(1));
			}
		}
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
				let latency_ms = i64::try_from(request_data.request_time.elapsed().as_millis())
					.unwrap_or(i64::MAX / 15);
				self.latency_tracker.write().add_latency(latency_ms);
				requested.remove(key);
			}
			Some(res_peer)
		} else {
			None
		}
	}

	pub fn remove_request_by_key(&self, key: &K, peer: &PeerAddr) -> Option<PeerAddr> {
		let mut requested = self.requested.write();
		let peers_stats = &mut self.peers_stats.write();

		if let Some(request_data) = requested.get(key) {
			let res_peer = request_data.peer.clone();

			if let Some(n) = peers_stats.get_mut(&request_data.peer) {
				n.requests = n.requests.saturating_sub(1);
			}

			if request_data.peer == *peer {
				let latency_ms = i64::try_from(request_data.request_time.elapsed().as_millis())
					.unwrap_or(i64::MAX / 15);
				self.latency_tracker.write().add_latency(latency_ms);
			}

			requested.remove(key);
			Some(res_peer)
		} else {
			None
		}
	}

	pub fn get_average_latency(&self) -> Option<Duration> {
		self.latency_tracker.read_recursive().get_average_latency()
	}

	pub fn get_average_latency_ms(&self) -> Option<u32> {
		// If latency no longer fits in u32 milliseconds, drop the statistic.
		// Latency that large only indicates severe network issues, and treating
		// it as missing statistics is adequate here.
		self.get_average_latency()
			.and_then(|latency| u32::try_from(latency.as_millis()).ok())
	}

	pub fn get_retry_latency(&self) -> Duration {
		self.get_average_latency()
			.unwrap_or_else(|| Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64))
	}

	pub fn get_expected_peer(&self, key: &K) -> Option<PeerAddr> {
		if let Some(req_data) = self.requested.read_recursive().get(key) {
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
			Chain::height_2_archive_height(peers.get_context_id(), peer.info.height())
				== archive_height
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
	exact_archive_height: Option<u64>,
	request_tracker: &RequestTracker<T>,
	excluded_peer_addr: &HashSet<PeerAddr>,
) -> (Vec<Arc<Peer>>, usize, usize) {
	// Excluding peers with totally full Q
	let peer_requests_limit = expected_requests_per_peer;
	let mut res: Vec<Arc<Peer>> = Vec::new();
	// for excluded we nned to cover offline prrs as well. That is why we are counting back
	let mut excluded_requests: usize = request_tracker.get_requests_num();
	let mut excluded_peers = 0;
	let mut found_outbound = false;
	let context_id = peers.get_context_id();
	let mismatched_archive_height = |peer: &Arc<Peer>| {
		exact_archive_height
			.map(|archive_height| {
				Chain::height_2_archive_height(context_id, peer.info.height()) != archive_height
			})
			.unwrap_or(false)
	};
	for peer in peers
		.iter()
		.with_capabilities(capabilities)
		.connected()
		.outbound()
		.with_min_height(min_height)
	{
		if mismatched_archive_height(&peer) {
			continue;
		}

		let mut excluded = excluded_peer_addr.contains(&peer.info.addr);
		found_outbound = true;
		if let Some(track_data) = request_tracker.get_peer_track_data(&peer.info.addr) {
			if !excluded && track_data.requests < peer_requests_limit {
				excluded_requests = excluded_requests.saturating_sub(track_data.requests);
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
			if mismatched_archive_height(&peer) {
				continue;
			}

			let mut excluded = excluded_peer_addr.contains(&peer.info.addr);
			if let Some(track_data) = request_tracker.get_peer_track_data(&peer.info.addr) {
				if !excluded && track_data.requests < peer_requests_limit {
					excluded_requests = excluded_requests.saturating_sub(track_data.requests);
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
	(res, excluded_requests, excluded_peers)
}

#[cfg(test)]
mod tests {
	use super::{CachedResponse, LatencyTracker, QuorumSelection, RequestTracker};
	use mwc_chain::pibd_params;
	use mwc_p2p::PeerAddr;
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};
	use std::time::Duration;

	fn peer_for_idx(idx: u8) -> PeerAddr {
		PeerAddr::Ip(SocketAddr::new(
			IpAddr::V4(Ipv4Addr::new(8, 8, 8, idx)),
			3414,
		))
	}

	#[test]
	fn empty_latency_history_has_no_average() {
		let tracker = LatencyTracker::new();

		assert_eq!(tracker.get_average_latency(), None);
	}

	#[test]
	fn cached_response_returns_error_for_oversized_timeout() {
		let response = CachedResponse::new(42, Duration::new(u64::MAX, 999_999_999));

		assert!(matches!(response, Err(mwc_chain::Error::DataOverflow(_))));
	}

	#[test]
	fn quorum_selection_returns_selected_value_and_items() {
		let selection = super::select_quorum(
			vec![("a", 1), ("b", 2), ("c", 1)].into_iter(),
			2,
			2,
			|(_, value)| *value,
		);

		assert_eq!(
			selection,
			super::QuorumSelection::Selected {
				value: 1,
				items: vec![("a", 1), ("c", 1)]
			}
		);
	}

	#[test]
	fn sync_height_selection_ignores_single_archive_height_outlier() {
		let votes = vec![(300, 350), (100, 150), (100, 160), (100, 170)];
		let selection = super::select_quorum(votes.into_iter(), 3, 2, |(archive_height, _)| {
			*archive_height
		});

		match selection {
			QuorumSelection::Selected {
				value: archive_height,
				items,
			} => {
				let best_height = items.iter().map(|(_, height)| *height).max();
				assert_eq!(archive_height, 100);
				assert_eq!(best_height, Some(170));
				assert_eq!(items, vec![(100, 150), (100, 160), (100, 170)]);
			}
			_ => panic!("expected selected archive height"),
		}
	}

	#[test]
	fn sync_height_selection_rejects_split_without_strict_majority() {
		let selection = super::select_quorum(
			vec![(200, 250), (200, 251), (100, 150), (100, 151)].into_iter(),
			3,
			2,
			|(archive_height, _)| *archive_height,
		);

		assert_eq!(
			selection,
			QuorumSelection::NoQuorum {
				responses: 4,
				best_count: 2
			}
		);
	}

	#[test]
	fn sync_height_selection_requires_at_least_two_peers() {
		let selection =
			super::select_quorum(vec![(100, 150)].into_iter(), 1, 2, |(archive_height, _)| {
				*archive_height
			});

		assert_eq!(
			selection,
			QuorumSelection::NeedMoreResponses { responses: 1 }
		);
	}

	#[test]
	fn timeout_latency_sample_is_measured_latency() {
		let mut tracker = LatencyTracker::new();
		let timeout_ms = pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as i64 * 1000;

		tracker.add_latency(timeout_ms);

		assert_eq!(
			tracker.get_average_latency(),
			Some(Duration::from_millis(timeout_ms as u64))
		);
	}

	#[test]
	fn retry_latency_uses_timeout_without_samples() {
		let tracker = RequestTracker::<u64>::new();

		assert_eq!(
			tracker.get_retry_latency(),
			Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)
		);
	}

	#[test]
	fn duplicate_request_for_same_peer_keeps_single_count() {
		let tracker = RequestTracker::<u64>::new();
		let peer = peer_for_idx(1);

		tracker.register_request(42, peer.clone(), "first".into());
		tracker.register_request(42, peer.clone(), "second".into());

		assert_eq!(tracker.get_requests_num(), 1);
		assert_eq!(
			tracker
				.get_peer_track_data(&peer)
				.expect("peer stats")
				.requests,
			1
		);

		assert_eq!(tracker.remove_request(&42, &peer), Some(peer.clone()));
		assert_eq!(tracker.get_requests_num(), 0);
		assert_eq!(
			tracker
				.get_peer_track_data(&peer)
				.expect("peer stats")
				.requests,
			0
		);
	}

	#[test]
	fn replacing_request_key_decrements_previous_peer() {
		let tracker = RequestTracker::<u64>::new();
		let first_peer = peer_for_idx(1);
		let second_peer = peer_for_idx(2);

		tracker.register_request(42, first_peer.clone(), "first".into());
		tracker.register_request(42, second_peer.clone(), "second".into());

		assert_eq!(tracker.get_requests_num(), 1);
		assert_eq!(tracker.get_expected_peer(&42), Some(second_peer.clone()));
		assert_eq!(
			tracker
				.get_peer_track_data(&first_peer)
				.expect("first peer stats")
				.requests,
			0
		);
		assert_eq!(
			tracker
				.get_peer_track_data(&second_peer)
				.expect("second peer stats")
				.requests,
			1
		);

		assert_eq!(
			tracker.remove_request(&42, &second_peer),
			Some(second_peer.clone())
		);
		assert_eq!(
			tracker
				.get_peer_track_data(&second_peer)
				.expect("second peer stats")
				.requests,
			0
		);
	}

	#[test]
	fn unmatched_remove_request_keeps_original_request() {
		let tracker = RequestTracker::<u64>::new();
		let original_peer = peer_for_idx(1);
		let duplicate_peer = peer_for_idx(2);

		tracker.register_request(42, original_peer.clone(), "original".into());

		assert_eq!(
			tracker.remove_request(&42, &duplicate_peer),
			Some(original_peer.clone())
		);
		assert_eq!(tracker.get_requests_num(), 1);
		assert_eq!(tracker.get_expected_peer(&42), Some(original_peer.clone()));
		assert_eq!(
			tracker
				.get_peer_track_data(&original_peer)
				.expect("original peer stats")
				.requests,
			1
		);
	}

	#[test]
	fn remove_request_by_key_clears_unmatched_request() {
		let tracker = RequestTracker::<u64>::new();
		let original_peer = peer_for_idx(1);
		let duplicate_peer = peer_for_idx(2);

		tracker.register_request(42, original_peer.clone(), "original".into());

		assert_eq!(
			tracker.remove_request_by_key(&42, &duplicate_peer),
			Some(original_peer.clone())
		);
		assert_eq!(tracker.get_requests_num(), 0);
		assert_eq!(tracker.get_expected_peer(&42), None);
		assert_eq!(
			tracker
				.get_peer_track_data(&original_peer)
				.expect("original peer stats")
				.requests,
			0
		);
		assert!(tracker.get_peer_track_data(&duplicate_peer).is_none());
		assert_eq!(tracker.get_average_latency(), None);
	}
}
