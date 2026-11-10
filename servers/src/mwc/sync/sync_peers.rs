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
use mwc_crates::parking_lot::RecursiveRwLock;
use mwc_p2p::{PeerAddr, Peers, ReasonForBan, State};
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

const MIN_RESPONSE_NUM: usize = 13; // Retain the latest response events for peer scoring.
const NO_RESPONSE_THRESHOLD: usize = 5;
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

	/// Decide whether recent events require disconnecting or banning the peer.
	/// The responses log is bounded at insertion time, with trimming retained
	/// here as a defensive fallback for any preexisting oversized queues.
	fn check_status(&mut self, peer: &str) -> (State, String) {
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

		// Missing replies can result from our own network outage, so the fifth
		// timeout makes the peer Defunct and eligible for retry, not banned.
		// Bad-data errors and explicit bans retain their thresholds and take priority.
		let state = if bans > 0 || errors > 1 {
			State::Banned
		} else if no_response >= NO_RESPONSE_THRESHOLD {
			State::Defunct
		} else {
			State::Healthy
		};

		debug!(
			"Checking peer status. Peer: {}, bans={} errors={} no_resp={} ok={} state={:?}",
			peer, bans, errors, no_response, success, state
		);

		while self.responses.len() > MIN_RESPONSE_NUM {
			self.responses.pop_front();
		}

		(state, comment)
	}

	pub fn reset(&mut self) {
		self.responses.clear();
	}
}

pub struct SyncPeers {
	peers_status: RecursiveRwLock<HashMap<String, PeerPibdStatus>>,
	banned_peers: RecursiveRwLock<HashMap<PeerAddr, Instant>>, // collecting banned peers because we might need to unban them.
	new_events_peers: RecursiveRwLock<HashSet<String>>,
}

impl SyncPeers {
	pub fn new() -> Self {
		SyncPeers {
			peers_status: RecursiveRwLock::new(HashMap::new()),
			banned_peers: RecursiveRwLock::new(HashMap::new()),
			new_events_peers: RecursiveRwLock::new(HashSet::new()),
		}
	}

	pub fn reset(&self) {
		self.peers_status.write().clear();
		self.banned_peers.write().clear();
		self.new_events_peers.write().clear();
	}

	pub fn get_banned_peers(&self) -> HashSet<PeerAddr> {
		self.banned_peers.read().keys().cloned().collect()
	}

	pub fn report_no_response(&self, peer: &PeerAddr, message: String) {
		self.add_event(peer, PeerStatusEvent::NoResponse(message));
	}

	/// A new connection gets a fresh timeout history, while valid responses,
	/// bad-data errors and explicit bans retain their original order/timestamps.
	pub fn clear_no_response(&self, peer: &PeerAddr) {
		if let Some(status) = self.peers_status.write().get_mut(&peer.as_key()) {
			status
				.responses
				.retain(|(_, event)| !matches!(event, PeerStatusEvent::NoResponse(_)));
		}
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
				let (state, comment) = status.check_status(&cp);
				let peer_addr = status.peer_addr.clone();
				if state == State::Banned {
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
				} else if state == State::Defunct {
					info!(
						"Marking unresponsive peer {} Defunct: {}",
						peer_addr, comment
					);
					// The store preserves an existing ban. Stop the connection even if
					// persistence fails, and retry the state update on the next pass.
					let result = peers.update_state(&peer_addr, State::Defunct);
					if let Some(peer) = peers.remove_connected(&peer_addr) {
						peers.stop_and_reap_peer(peer);
					}
					if let Err(e) = result {
						warn!("failed to mark peer {} Defunct: {}", peer_addr, e);
						retry_peers.insert(cp.clone());
					}
					// Preserve other events; reconnect clears only NoResponse history.
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

	#[cfg(feature = "test-support")]
	fn connect_peer(
		peers: &Peers,
		addr: &PeerAddr,
	) -> (
		Arc<mwc_p2p::Peer>,
		mwc_crates::crossbeam::channel::Receiver<mwc_p2p::msg::Msg>,
	) {
		let info = mwc_p2p::PeerInfo {
			capabilities: mwc_p2p::Capabilities::UNKNOWN,
			user_agent: "sync-status-test".into(),
			version: mwc_core::ser::ProtocolVersion::local(),
			addr: addr.clone(),
			direction: mwc_p2p::Direction::Outbound,
			live_info: Arc::new(RecursiveRwLock::new(mwc_p2p::types::PeerLiveInfo::new(
				mwc_core::pow::Difficulty::min(),
			))),
			tx_base_fee: 0,
		};
		let (peer, messages) =
			mwc_p2p::Peer::connected_for_test(info, 1, Arc::new(DummyAdapter {}));
		let peer = Arc::new(peer);
		peers.add_connected(peer.clone()).unwrap();
		(peer, messages)
	}

	#[test]
	#[cfg(feature = "test-support")]
	fn no_response_disconnect_preserves_errors_for_reconnect() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let scores = SyncPeers::new();
		let (peers, _dir) = test_peers();
		let addr = non_loopback_peer();
		let (peer, messages) = connect_peer(&peers, &addr);
		scores.report_ok_response(&addr);
		scores.report_error_response(&addr, "invalid data".into());
		for failure in 1..=5 {
			scores.elapse_no_response_merge_interval(&addr);
			scores.report_no_response(&addr, "timeout".into());
			scores.apply_peers_status(&peers);
			assert_eq!(
				peers.get_peer(&addr).unwrap().flags,
				if failure == 5 {
					State::Defunct
				} else {
					State::Healthy
				}
			);
			assert_eq!(peer.is_connected(), failure < 5);
			assert_eq!(peers.get_connected_peer(&addr).is_some(), failure < 5);
			assert!(!peers.is_banned(&addr).unwrap());
			assert!(scores.get_banned_peers().is_empty());
			assert_eq!(messages.try_iter().count(), 0);
		}

		// Use the existing reconnect hook: timeouts are cleared, but the prior
		// bad-data error must still combine with a new error to cause a ban.
		scores.clear_no_response(&addr);
		{
			let statuses = scores.peers_status.read();
			let retained = &statuses[&addr.as_key()].responses;
			assert_eq!(retained.len(), 2);
			assert!(matches!(&retained[0].1, PeerStatusEvent::Success));
			assert!(matches!(&retained[1].1, PeerStatusEvent::Error(_)));
		}
		let (reconnected, messages) = connect_peer(&peers, &addr);
		scores.report_no_response(&addr, "new connection timeout".into());
		scores.apply_peers_status(&peers);
		assert!(reconnected.is_connected());
		assert_eq!(peers.get_peer(&addr).unwrap().flags, State::Healthy);
		scores.report_error_response(&addr, "more invalid data".into());
		scores.apply_peers_status(&peers);
		assert!(peers.is_banned(&addr).unwrap());
		assert!(scores.get_banned_peers().contains(&addr));
		assert!(!reconnected.is_connected());
		assert_eq!(
			messages
				.try_iter()
				.map(|msg| msg.message_type_for_test())
				.collect::<Vec<_>>(),
			vec![mwc_p2p::msg::Type::BanReason]
		);
	}

	#[test]
	#[cfg(feature = "test-support")]
	fn bad_data_and_explicit_bans_take_priority_over_no_response() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for explicit_ban in [false, true] {
			let scores = SyncPeers::new();
			let (peers, _dir) = test_peers();
			let addr = non_loopback_peer();
			let (peer, messages) = connect_peer(&peers, &addr);
			for _ in 0..5 {
				scores.elapse_no_response_merge_interval(&addr);
				scores.report_no_response(&addr, "timeout".into());
			}
			if explicit_ban {
				scores.ban_peer(&addr, "invalid root hash".into());
			} else {
				scores.report_error_response(&addr, "invalid data".into());
				scores.report_error_response(&addr, "more invalid data".into());
			}
			scores.apply_peers_status(&peers);
			assert!(peers.is_banned(&addr).unwrap());
			assert!(scores.get_banned_peers().contains(&addr));
			assert!(!peer.is_connected());
			assert_eq!(
				messages
					.try_iter()
					.map(|msg| msg.message_type_for_test())
					.collect::<Vec<_>>(),
				vec![mwc_p2p::msg::Type::BanReason]
			);
		}
	}

	#[test]
	fn no_response_does_not_change_an_existing_ban() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let scores = SyncPeers::new();
		let (peers, _dir) = test_peers();
		let addr = non_loopback_peer();
		peers
			.ban_peer(&addr, ReasonForBan::BadRequest, "bad request")
			.unwrap();
		let banned = peers.get_peer(&addr).unwrap();
		for _ in 0..5 {
			scores.elapse_no_response_merge_interval(&addr);
			scores.report_no_response(&addr, "timeout".into());
		}
		scores.apply_peers_status(&peers);
		let stored = peers.get_peer(&addr).unwrap();
		assert_eq!(stored.flags, State::Banned);
		assert_eq!(stored.ban_reason, banned.ban_reason);
		assert_eq!(stored.last_banned, banned.last_banned);
		assert!(scores.get_banned_peers().is_empty());
	}

	#[test]
	#[cfg(feature = "test-support")]
	fn failed_defunct_update_disconnects_and_is_retried() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let scores = SyncPeers::new();
		let (peers, _dir) = test_peers();
		let addr = non_loopback_peer();
		let (peer, _messages) = connect_peer(&peers, &addr);
		let stored = peers.get_peer(&addr).unwrap();
		peers.delete_peer(&addr).unwrap();
		for _ in 0..5 {
			scores.elapse_no_response_merge_interval(&addr);
			scores.report_no_response(&addr, "timeout".into());
		}
		scores.apply_peers_status(&peers);
		assert!(!peer.is_connected());
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(scores.new_events_peers.read().contains(&addr.as_key()));
		peers.save_peer(&stored).unwrap();
		scores.apply_peers_status(&peers);
		assert_eq!(peers.get_peer(&addr).unwrap().flags, State::Defunct);
		assert!(scores.new_events_peers.read().is_empty());
		assert!(scores.get_banned_peers().is_empty());
	}

	#[test]
	fn ban_peer_preserves_non_loopback_socket_address() {
		let sync_peers = SyncPeers::new();
		let peer = non_loopback_peer();
		let peer_key = peer.as_key();

		assert_ne!(peer_key, peer.to_string());
		assert!(PeerAddr::from_str(&peer_key).is_err());

		sync_peers.ban_peer(&peer, "bad root hash".into());

		let peers_status = sync_peers.peers_status.read();
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
			let peers_status = sync_peers.peers_status.read();
			let status = peers_status.get(&peer_key).expect("peer status");
			assert!(status.peer_addr.matches_exactly(&peer));
		}

		sync_peers.ban_peer(&updated_peer, "bad root hash".into());

		let peers_status = sync_peers.peers_status.read();
		let status = peers_status.get(&peer_key).expect("peer status");
		assert!(status.peer_addr.matches_exactly(&updated_peer));
	}

	#[test]
	fn reconnect_clears_only_no_response_history() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let scores = SyncPeers::new();
		let peer = non_loopback_peer();
		for _ in 0..4 {
			scores.elapse_no_response_merge_interval(&peer);
			scores.report_no_response(&peer, "old connection".into());
		}
		scores.report_ok_response(&peer);
		scores.report_error_response(&peer, "invalid data".into());
		let retained_times: Vec<_> = scores.peers_status.read()[&peer.as_key()]
			.responses
			.iter()
			.skip(4)
			.map(|(time, _)| *time)
			.collect();
		let last_updated = scores.peers_status.read()[&peer.as_key()].last_updated;
		scores.clear_no_response(&peer);
		{
			let statuses = scores.peers_status.read();
			let status = &statuses[&peer.as_key()];
			assert_eq!(status.responses.len(), 2);
			assert!(matches!(&status.responses[0].1, PeerStatusEvent::Success));
			assert!(
				matches!(&status.responses[1].1, PeerStatusEvent::Error(msg) if msg == "invalid data")
			);
			assert_eq!(
				status
					.responses
					.iter()
					.map(|(time, _)| *time)
					.collect::<Vec<_>>(),
				retained_times
			);
			assert_eq!(status.last_updated, last_updated);
		}
		let (peers, _dir) = test_peers();
		// The first timeout on the new connection does not combine with the old four.
		scores.report_no_response(&peer, "new connection".into());
		scores.apply_peers_status(&peers);
		assert!(!peers.is_banned(&peer).unwrap());
		// The previous bad-data error still counts toward the normal two-error ban.
		scores.report_error_response(&peer, "more invalid data".into());
		scores.apply_peers_status(&peers);
		assert!(peers.is_banned(&peer).unwrap());
	}

	#[test]
	fn reconnect_preserves_pending_bans_and_other_peers_history() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let scores = SyncPeers::new();
		let peer = non_loopback_peer();
		let other = peer_for_idx(1);
		scores.report_no_response(&peer, "old timeout".into());
		scores.ban_peer(&peer, "invalid root".into());
		scores.report_no_response(&other, "other timeout".into());
		scores.clear_no_response(&peer);
		{
			let statuses = scores.peers_status.read();
			assert_eq!(statuses[&peer.as_key()].responses.len(), 1);
			assert!(
				matches!(&statuses[&peer.as_key()].responses[0].1, PeerStatusEvent::Ban(msg) if msg == "invalid root")
			);
			assert!(matches!(
				&statuses[&other.as_key()].responses[0].1,
				PeerStatusEvent::NoResponse(_)
			));
		}
		let (peers, _dir) = test_peers();
		scores.apply_peers_status(&peers);
		assert!(peers.is_banned(&peer).unwrap());
		assert!(!peers.is_banned(&other).unwrap());
	}

	#[test]
	fn repeated_no_responses_mark_defunct_within_the_recent_response_window() {
		let peer = non_loopback_peer();
		let now = Instant::now();
		let mut status = PeerPibdStatus::new(&peer, now);
		for second in 0..4 {
			status.add_event(
				PeerStatusEvent::NoResponse("timeout".into()),
				now + Duration::from_secs(second),
			);
			assert_eq!(status.check_status(&peer.as_key()).0, State::Healthy);
		}
		let now = now + Duration::from_secs(4);
		status.add_event(PeerStatusEvent::NoResponse("timeout".into()), now);
		assert_eq!(status.check_status(&peer.as_key()).0, State::Defunct);
		// The 13-event history still retains all five failures after eight successes.
		for _ in 0..8 {
			status.add_event(PeerStatusEvent::Success, now);
		}
		assert_eq!(status.check_status(&peer.as_key()).0, State::Defunct);
		// One more success moves the oldest failure out of the bounded window.
		status.add_event(PeerStatusEvent::Success, now);
		assert_eq!(status.check_status(&peer.as_key()).0, State::Healthy);
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
		assert_eq!(status.check_status(&peer.as_key()).0, State::Healthy);
		// Invalid responses retain their normal scoring even inside the interval.
		assert!(status.add_event(
			PeerStatusEvent::Error("another invalid response".into()),
			now + Duration::from_secs(1),
		));
		assert_eq!(status.check_status(&peer.as_key()).0, State::Banned);
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
		assert_eq!(status.check_status(&peer.as_key()).0, State::Healthy);
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
			let peers_status = sync_peers.peers_status.read();
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

		let peers_status = sync_peers.peers_status.read();
		let new_events_peers = sync_peers.new_events_peers.read();

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

		let peers_status = sync_peers.peers_status.read();
		let new_events_peers = sync_peers.new_events_peers.read();

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

		let banned_peers = sync_peers.banned_peers.read();

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

		let banned_peers = sync_peers.banned_peers.read();
		assert_eq!(banned_peers.len(), MAX_BANNED_PEERS);
		assert!(banned_peers.contains_key(&refreshed_peer));
		assert!(!banned_peers.contains_key(&evicted_peer));
		assert!(banned_peers.contains_key(&newest_peer));
	}
}
