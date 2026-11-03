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

use mwc_crates::log::{debug, info, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_p2p::{PeerAddr, Peers, ReasonForBan};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
enum PeerStatusEvent {
	Success,
	NoResponse(String),
	Error(String),
	Ban(String),
}

const MIN_RESPONSE_NUM: usize = 13; // 6*2+1  8 requests per peer is expected, see get_segments_request_per_peer()
const MAX_PEER_STATUS_ENTRIES: usize = 10240;
const MAX_BANNED_PEERS: usize = 10240;
const NO_RESPONSE_MERGE_INTERVAL: Duration = Duration::from_secs(1);

pub struct PeerPibdStatus {
	responses: VecDeque<(Instant, PeerStatusEvent)>,
	peer_addr: PeerAddr,
	last_updated: Instant,
}

impl PeerPibdStatus {
	fn new(peer_addr: &PeerAddr, now: Instant) -> PeerPibdStatus {
		PeerPibdStatus {
			responses: VecDeque::new(),
			peer_addr: peer_addr.clone(),
			last_updated: now,
		}
	}

	fn update_peer_addr(&mut self, peer_addr: &PeerAddr) {
		self.peer_addr = peer_addr.clone();
	}

	fn add_event(&mut self, event: PeerStatusEvent, now: Instant) -> bool {
		if matches!(&event, PeerStatusEvent::NoResponse(_)) {
			for (time, previous) in self.responses.iter().rev() {
				if now.saturating_duration_since(*time) >= NO_RESPONSE_MERGE_INTERVAL {
					break;
				}
				if matches!(previous, PeerStatusEvent::NoResponse(_)) {
					info!(
						"Skipping as collapsed NoResponse event for peer {}",
						self.peer_addr
					);
					return false;
				}
			}
		}
		match &event {
			PeerStatusEvent::Success => {
				debug!("Adding event {:?} for peer {}", event, self.peer_addr)
			}
			PeerStatusEvent::NoResponse(_) => {
				info!("Adding NoResponse event for peer {}", self.peer_addr)
			}
			PeerStatusEvent::Error(_) | PeerStatusEvent::Ban(_) => {
				warn!("Adding event {:?} for peer {}", event, self.peer_addr)
			}
		}
		self.last_updated = now;
		self.responses.push_back((now, event));
		// Bans are queued until apply_peers_status runs. MIN_RESPONSE_NUM newer
		// events (currently 13) can evict a pending Ban before it is applied.
		// This is intentional: if the newer events are successful responses and
		// the peer is acting honestly, we do not want to ban it for the older event.
		while self.responses.len() > MIN_RESPONSE_NUM {
			self.responses.pop_front();
		}
		true
	}

	/// Checking events log to decide if peer wasn't active enough
	/// The responses log is bounded at insertion time, with trimming retained
	/// here as a defensive fallback for any preexisting oversized queues.
	/// Return: (ban, comment)
	fn check_for_ban(&mut self, peer: &String) -> (bool, String) {
		let mut bans = 0;
		let mut errors = 0;
		let mut no_response = 0;
		let mut success = 0;
		let mut comment = String::new();
		for (_, e) in &self.responses {
			match e {
				PeerStatusEvent::Success => success += 1,
				PeerStatusEvent::NoResponse(m) => {
					if comment.len() > 0 {
						comment.push_str(", ");
					}
					comment.push_str("No resp: ");
					comment.push_str(m);
					no_response += 1;
				}
				PeerStatusEvent::Error(m) => {
					if comment.len() > 0 {
						comment.push_str(", ");
					}
					comment.push_str("Err: ");
					comment.push_str(m);
					errors += 1;
				}
				PeerStatusEvent::Ban(m) => {
					if comment.len() > 0 {
						comment.push_str(", ");
					}
					comment.push_str("Ban: ");
					comment.push_str(m);
					bans += 1;
				}
			}
		}

		// Tolerate six missed responses in the recent window; the seventh bans.
		let res_ban = bans > 0 || errors > 1 || no_response > MIN_RESPONSE_NUM / 2;

		debug!(
			"Checking for Ban. Peer: {}, bans={} errors={} no_resp={} ok={}  RES={}",
			peer, bans, errors, no_response, success, res_ban
		);

		while self.responses.len() > MIN_RESPONSE_NUM {
			self.responses.pop_front();
		}

		(res_ban, comment)
	}

	pub fn reset(&mut self) {
		self.responses.clear();
	}
}

pub struct SyncPeers {
	peers_status: RwLock<HashMap<String, PeerPibdStatus>>,
	banned_peers: RwLock<HashMap<PeerAddr, Instant>>, // collecting banned peers because we might need to unban them.
	new_events_peers: RwLock<HashSet<String>>,
}

impl SyncPeers {
	pub fn new() -> Self {
		SyncPeers {
			peers_status: RwLock::new(HashMap::new()),
			banned_peers: RwLock::new(HashMap::new()),
			new_events_peers: RwLock::new(HashSet::new()),
		}
	}

	pub fn reset(&self) {
		self.peers_status.write().clear();
		self.banned_peers.write().clear();
		self.new_events_peers.write().clear();
	}

	pub fn get_banned_peers(&self) -> HashSet<PeerAddr> {
		self.banned_peers.read_recursive().keys().cloned().collect()
	}

	pub fn report_no_response(&self, peer: &PeerAddr, message: String) {
		self.add_event(peer, PeerStatusEvent::NoResponse(message));
	}

	pub fn report_error_response(&self, peer: &PeerAddr, message: String) {
		self.add_event(peer, PeerStatusEvent::Error(message));
	}

	pub fn report_ok_response(&self, peer: &PeerAddr) {
		self.add_event(peer, PeerStatusEvent::Success);
	}

	pub fn ban_peer(&self, peer: &PeerAddr, message: String) {
		self.add_event(peer, PeerStatusEvent::Ban(message));
	}

	pub fn apply_peers_status(&self, peers: &Arc<Peers>) {
		let now = Instant::now();
		let mut peers_status = self.peers_status.write();
		let mut check_peers = self.new_events_peers.write();

		let check_peer_keys: Vec<String> = check_peers.iter().cloned().collect();
		let mut retry_peers = HashSet::new();
		let mut remove_peer_keys = HashSet::new();
		let mut banned_peer_addrs = Vec::new();
		for cp in check_peer_keys {
			if let Some(status) = peers_status.get_mut(&cp) {
				let (ban, comment) = status.check_for_ban(&cp);
				let peer_addr = status.peer_addr.clone();
				if ban {
					match peers.ban_peer(&peer_addr, ReasonForBan::PibdFailure, &comment) {
						Ok(()) => {
							status.reset();
							banned_peer_addrs.push(peer_addr.clone());
							remove_peer_keys.insert(cp.clone());
						}
						Err(e) => {
							warn!("failed to ban peer {}: {}", peer_addr, e);
							retry_peers.insert(cp.clone());
						}
					}
				}
			}
		}
		for peer_key in remove_peer_keys {
			peers_status.remove(&peer_key);
			retry_peers.remove(&peer_key);
		}
		*check_peers = retry_peers;
		drop(check_peers);
		drop(peers_status);

		if !banned_peer_addrs.is_empty() {
			let mut banned_peers = self.banned_peers.write();
			for peer_addr in banned_peer_addrs {
				banned_peers.insert(peer_addr, now);
			}
			while banned_peers.len() > MAX_BANNED_PEERS {
				let peer_addr = banned_peers
					.iter()
					.min_by(|(_, left), (_, right)| left.cmp(right))
					.map(|(peer_addr, _)| peer_addr.clone());
				match peer_addr {
					Some(peer_addr) => {
						banned_peers.remove(&peer_addr);
					}
					None => break,
				}
			}
		}
	}

	fn add_event(&self, peer: &PeerAddr, event: PeerStatusEvent) {
		let peer_key = peer.as_key();
		let mut peers_status = self.peers_status.write();
		let now = Instant::now();
		let mut new_events_peers = self.new_events_peers.write();
		let status = peers_status
			.entry(peer_key.clone())
			.or_insert_with(|| PeerPibdStatus::new(peer, now));
		status.update_peer_addr(peer);
		if !status.add_event(event, now) {
			return;
		}
		new_events_peers.insert(peer_key);
		while peers_status.len() > MAX_PEER_STATUS_ENTRIES {
			let peer_key = peers_status
				.iter()
				.min_by(|(_, left), (_, right)| left.last_updated.cmp(&right.last_updated))
				.map(|(peer_key, _)| peer_key.clone());
			match peer_key {
				Some(peer_key) => {
					peers_status.remove(&peer_key);
					new_events_peers.remove(&peer_key);
				}
				None => break,
			}
		}
	}

	#[cfg(test)]
	pub(super) fn elapse_no_response_merge_interval(&self, peer: &PeerAddr) {
		// Simulate separate timeout periods without sleeping in sync tests.
		if let Some(status) = self.peers_status.write().get_mut(&peer.as_key()) {
			for (time, _) in &mut status.responses {
				*time -= NO_RESPONSE_MERGE_INTERVAL;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::global;
	use mwc_p2p::{store::PeerStore, DummyAdapter, P2PConfig};
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};

	fn non_loopback_peer() -> PeerAddr {
		PeerAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 3414))
	}

	fn peer_for_idx(idx: usize) -> PeerAddr {
		PeerAddr::Ip(SocketAddr::new(
			IpAddr::V4(Ipv4Addr::new(
				8,
				((idx / 65_536) % 256) as u8,
				((idx / 256) % 256) as u8,
				(idx % 256) as u8,
			)),
			3414,
		))
	}

	fn wait_until_after(instant: Instant) {
		while Instant::now() <= instant {
			std::hint::spin_loop();
		}
	}

	fn seed_peer_statuses(sync_peers: &SyncPeers, count: usize, now: Instant) {
		let mut peers_status = sync_peers.peers_status.write();
		let mut new_events_peers = sync_peers.new_events_peers.write();
		let mut newest_update = now;
		for idx in 0..count {
			let peer = peer_for_idx(idx);
			let peer_key = peer.as_key();
			let updated_at = now.checked_add(Duration::from_nanos(idx as u64)).unwrap();
			newest_update = updated_at;
			peers_status.insert(peer_key.clone(), PeerPibdStatus::new(&peer, updated_at));
			new_events_peers.insert(peer_key);
		}
		drop(new_events_peers);
		drop(peers_status);
		if count > 0 {
			wait_until_after(newest_update);
		}
	}

	fn seed_banned_peers(sync_peers: &SyncPeers, count: usize, now: Instant) {
		let mut banned_peers = sync_peers.banned_peers.write();
		let mut newest_update = now;
		for idx in 0..count {
			let updated_at = now.checked_add(Duration::from_nanos(idx as u64)).unwrap();
			newest_update = updated_at;
			banned_peers.insert(peer_for_idx(idx), updated_at);
		}
		drop(banned_peers);
		if count > 0 {
			wait_until_after(newest_update);
		}
	}

	fn test_peers() -> (Arc<Peers>, mwc_crates::tempfile::TempDir) {
		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = Arc::new(Peers::new(
			store,
			Arc::new(DummyAdapter {}),
			&P2PConfig::default(),
		));
		(peers, dir)
	}

	#[test]
	fn ban_peer_preserves_non_loopback_socket_address() {
		let sync_peers = SyncPeers::new();
		let peer = non_loopback_peer();
		let peer_key = peer.as_key();

		assert_ne!(peer_key, peer.to_string());
		assert!(PeerAddr::from_str(&peer_key).is_err());

		sync_peers.ban_peer(&peer, "bad root hash".into());

		let peers_status = sync_peers.peers_status.read_recursive();
		let status = peers_status.get(&peer_key).expect("peer status");
		assert!(status.peer_addr.matches_exactly(&peer));
	}

	#[test]
	fn full_address_event_updates_existing_status() {
		let sync_peers = SyncPeers::new();
		let peer = non_loopback_peer();
		let peer_key = peer.as_key();
		let updated_peer =
			PeerAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 3415));

		sync_peers.report_no_response(&peer, "timeout".into());
		{
			let peers_status = sync_peers.peers_status.read_recursive();
			let status = peers_status.get(&peer_key).expect("peer status");
			assert!(status.peer_addr.matches_exactly(&peer));
		}

		sync_peers.ban_peer(&updated_peer, "bad root hash".into());

		let peers_status = sync_peers.peers_status.read_recursive();
		let status = peers_status.get(&peer_key).expect("peer status");
		assert!(status.peer_addr.matches_exactly(&updated_peer));
	}

	#[test]
	fn repeated_no_responses_ban_within_the_recent_response_window() {
		let peer = non_loopback_peer();
		let now = Instant::now();
		let mut status = PeerPibdStatus::new(&peer, now);
		for second in 0..6 {
			status.add_event(
				PeerStatusEvent::NoResponse("timeout".into()),
				now + Duration::from_secs(second),
			);
			assert!(!status.check_for_ban(&peer.as_key()).0);
		}
		let now = now + Duration::from_secs(6);
		status.add_event(PeerStatusEvent::NoResponse("timeout".into()), now);
		assert!(status.check_for_ban(&peer.as_key()).0);
		// Successes eventually move older failures out of the bounded window.
		for _ in 0..7 {
			status.add_event(PeerStatusEvent::Success, now);
		}
		assert!(!status.check_for_ban(&peer.as_key()).0);
	}

	#[test]
	fn no_response_events_are_bounded_at_insertion() {
		let peer = non_loopback_peer();
		let now = Instant::now();
		let mut status = PeerPibdStatus::new(&peer, now);

		for idx in 0..(MIN_RESPONSE_NUM + 5) {
			status.add_event(
				PeerStatusEvent::NoResponse(format!("timeout {}", idx)),
				now + Duration::from_secs(idx as u64),
			);
		}

		assert_eq!(status.responses.len(), MIN_RESPONSE_NUM);
		assert!(matches!(
			status.responses.front(),
			Some((_, PeerStatusEvent::NoResponse(msg))) if msg == "timeout 5"
		));
	}

	#[test]
	fn no_responses_merge_from_the_last_accepted_timeout() {
		let peer = non_loopback_peer();
		let now = Instant::now();
		let mut status = PeerPibdStatus::new(&peer, now);
		assert!(status.add_event(PeerStatusEvent::NoResponse("first".into()), now));
		assert!(status.add_event(PeerStatusEvent::Success, now + Duration::from_millis(100)));
		assert!(status.add_event(
			PeerStatusEvent::Error("invalid data".into()),
			now + Duration::from_millis(200),
		));
		for millis in [200, 500, 999] {
			assert!(!status.add_event(
				PeerStatusEvent::NoResponse("merged".into()),
				now + Duration::from_millis(millis),
			));
		}
		assert!(status.add_event(
			PeerStatusEvent::NoResponse("second".into()),
			now + Duration::from_secs(1),
		));
		assert_eq!(status.responses.len(), 4);
		assert!(matches!(
			status.responses.back(),
			Some((_, PeerStatusEvent::NoResponse(msg))) if msg == "second"
		));
		assert!(!status.check_for_ban(&peer.as_key()).0);
		// Invalid responses retain their normal scoring even inside the interval.
		assert!(status.add_event(
			PeerStatusEvent::Error("another invalid response".into()),
			now + Duration::from_secs(1),
		));
		assert!(status.check_for_ban(&peer.as_key()).0);
	}

	#[test]
	fn no_response_merge_uses_only_retained_history() {
		let peer = non_loopback_peer();
		let now = Instant::now();
		let mut status = PeerPibdStatus::new(&peer, now);
		status.add_event(PeerStatusEvent::NoResponse("old timeout".into()), now);
		for _ in 0..MIN_RESPONSE_NUM {
			status.add_event(PeerStatusEvent::Success, now + Duration::from_millis(100));
		}
		// Successful responses have evicted the old timeout from the scoring window.
		assert!(status.add_event(
			PeerStatusEvent::NoResponse("new timeout".into()),
			now + Duration::from_millis(500),
		));
		assert!(!status.check_for_ban(&peer.as_key()).0);
	}

	#[test]
	fn simultaneous_timeouts_are_merged_separately_for_each_peer() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let sync_peers = SyncPeers::new();
		let (peers, _dir) = test_peers();
		for idx in 1..=2 {
			let peer = peer_for_idx(idx);
			for request in 0..8 {
				sync_peers.report_no_response(&peer, format!("timeout {}", request));
			}
			let peers_status = sync_peers.peers_status.read_recursive();
			let status = peers_status.get(&peer.as_key()).unwrap();
			assert_eq!(status.responses.len(), 1);
			assert!(matches!(
				status.responses.front(),
				Some((_, PeerStatusEvent::NoResponse(msg))) if msg == "timeout 0"
			));
		}
		sync_peers.apply_peers_status(&peers);
		assert!(sync_peers.get_banned_peers().is_empty());
	}

	#[test]
	fn peer_status_pruning_caps_entries_by_oldest_update() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let now = Instant::now();
		let sync_peers = SyncPeers::new();
		seed_peer_statuses(&sync_peers, MAX_PEER_STATUS_ENTRIES, now);

		let oldest_key = peer_for_idx(0).as_key();
		let newest_key = peer_for_idx(MAX_PEER_STATUS_ENTRIES).as_key();
		sync_peers.report_ok_response(&peer_for_idx(MAX_PEER_STATUS_ENTRIES));

		let peers_status = sync_peers.peers_status.read_recursive();
		let new_events_peers = sync_peers.new_events_peers.read_recursive();

		assert_eq!(peers_status.len(), MAX_PEER_STATUS_ENTRIES);
		assert!(!peers_status.contains_key(&oldest_key));
		assert!(!new_events_peers.contains(&oldest_key));
		assert!(peers_status.contains_key(&newest_key));
		assert!(new_events_peers.contains(&newest_key));
	}

	#[test]
	fn peer_status_update_refreshes_recency_for_size_cap() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let now = Instant::now();
		let sync_peers = SyncPeers::new();
		seed_peer_statuses(&sync_peers, MAX_PEER_STATUS_ENTRIES, now);

		let refreshed_peer = peer_for_idx(0);
		let refreshed_key = peer_for_idx(0).as_key();
		let evicted_key = peer_for_idx(1).as_key();
		let newest_key = peer_for_idx(MAX_PEER_STATUS_ENTRIES).as_key();
		sync_peers.report_ok_response(&refreshed_peer);
		sync_peers.report_ok_response(&peer_for_idx(MAX_PEER_STATUS_ENTRIES));

		let peers_status = sync_peers.peers_status.read_recursive();
		let new_events_peers = sync_peers.new_events_peers.read_recursive();

		assert_eq!(peers_status.len(), MAX_PEER_STATUS_ENTRIES);
		assert!(peers_status.contains_key(&refreshed_key));
		assert!(new_events_peers.contains(&refreshed_key));
		assert!(!peers_status.contains_key(&evicted_key));
		assert!(!new_events_peers.contains(&evicted_key));
		assert!(peers_status.contains_key(&newest_key));
	}

	#[test]
	fn banned_peer_pruning_caps_entries_by_oldest_update() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let now = Instant::now();
		let sync_peers = SyncPeers::new();
		let (peers, _dir) = test_peers();
		seed_banned_peers(&sync_peers, MAX_BANNED_PEERS, now);

		let oldest_peer = peer_for_idx(0);
		let newest_peer = peer_for_idx(MAX_BANNED_PEERS);
		sync_peers.ban_peer(&newest_peer, "bad root hash".into());
		sync_peers.apply_peers_status(&peers);

		let banned_peers = sync_peers.banned_peers.read_recursive();

		assert_eq!(banned_peers.len(), MAX_BANNED_PEERS);
		assert!(!banned_peers.contains_key(&oldest_peer));
		assert!(banned_peers.contains_key(&newest_peer));
	}

	#[test]
	fn banned_peer_update_refreshes_recency_for_size_cap() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let now = Instant::now();
		let sync_peers = SyncPeers::new();
		let (peers, _dir) = test_peers();
		seed_banned_peers(&sync_peers, MAX_BANNED_PEERS, now);

		let refreshed_peer = peer_for_idx(0);
		let evicted_peer = peer_for_idx(1);
		let newest_peer = peer_for_idx(MAX_BANNED_PEERS);
		sync_peers.ban_peer(&refreshed_peer, "refresh".into());
		sync_peers.apply_peers_status(&peers);
		sync_peers.ban_peer(&newest_peer, "bad root hash".into());
		sync_peers.apply_peers_status(&peers);

		let banned_peers = sync_peers.banned_peers.read_recursive();
		assert_eq!(banned_peers.len(), MAX_BANNED_PEERS);
		assert!(banned_peers.contains_key(&refreshed_peer));
		assert!(!banned_peers.contains_key(&evicted_peer));
		assert!(banned_peers.contains_key(&newest_peer));
	}
}
