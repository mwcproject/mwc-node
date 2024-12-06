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

use mwc_p2p::{PeerAddr, Peers, ReasonForBan};
use mwc_util::RwLock;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

#[derive(Debug)]
enum PeerStatusEvent {
	Success,
	NoResponse(String),
	Error(String),
	Ban(String),
}

const MIN_RESPONSE_NUM: usize = 13; // 6*2+1  8 requests per peer is expected, see get_segments_request_per_peer()

pub struct PeerPibdStatus {
	responses: VecDeque<PeerStatusEvent>,
}

impl PeerPibdStatus {
	fn default() -> PeerPibdStatus {
		PeerPibdStatus {
			responses: VecDeque::new(),
		}
	}

	fn add_event(&mut self, event: PeerStatusEvent) {
		self.responses.push_back(event);
	}

	/// Checking events log to decide if peer wasn't active enough
	/// Note, this method is expecting to truncate responses, so data will be managable
	/// during long run
	fn check_for_ban(&mut self, peer: &String) -> (bool, String) {
		let mut bans = 0;
		let mut errors = 0;
		let mut no_response = 0;
		let mut success = 0;
		let mut comment = String::new();
		for e in &self.responses {
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

		let res = bans > 0
			|| errors > 1
			|| (self.responses.len() >= MIN_RESPONSE_NUM && success <= self.responses.len() / 2);

		debug!(
			"Checking for Ban. Peer: {}, bans={} errors={} no_resp={} ok={}  RES={}",
			peer, bans, errors, no_response, success, res
		);

		while self.responses.len() > MIN_RESPONSE_NUM {
			self.responses.pop_front();
		}

		(res, comment)
	}
}

pub struct SyncPeers {
	peers_status: RwLock<HashMap<String, PeerPibdStatus>>,
	banned_peers: RwLock<HashSet<PeerAddr>>, // collecting banned peers because we might need to unban them.
	new_events_peers: RwLock<HashSet<String>>,
}

impl SyncPeers {
	pub fn new() -> Self {
		SyncPeers {
			peers_status: RwLock::new(HashMap::new()),
			banned_peers: RwLock::new(HashSet::new()),
			new_events_peers: RwLock::new(HashSet::new()),
		}
	}

	pub fn reset(&mut self) {
		self.peers_status.write().clear();
		self.banned_peers.write().clear();
		self.new_events_peers.write().clear();
	}

	pub fn get_banned_peers(&self) -> HashSet<PeerAddr> {
		self.banned_peers.read().clone()
	}

	pub fn report_no_response(&self, peer: &PeerAddr, message: String) {
		self.add_event(peer.as_key(), PeerStatusEvent::NoResponse(message));
	}

	pub fn report_error_response(&self, peer: &PeerAddr, message: String) {
		self.report_error_response_for_peerstr(peer.as_key(), message);
	}

	pub fn report_error_response_for_peerstr(&self, peer: String, message: String) {
		self.add_event(peer, PeerStatusEvent::Error(message));
	}

	pub fn report_ok_response(&self, peer: &PeerAddr) {
		self.report_ok_response_for_peerstr(peer.as_key());
	}

	pub fn report_ok_response_for_peerstr(&self, peer: String) {
		self.add_event(peer, PeerStatusEvent::Success);
	}

	pub fn ban_peer(&self, peer: &PeerAddr, message: String) {
		self.add_event(peer.as_key(), PeerStatusEvent::Ban(message));
	}

	pub fn apply_peers_status(&self, peers: &Arc<Peers>) {
		let mut peers_status = self.peers_status.write();
		let mut check_peers = self.new_events_peers.write();
		for cp in check_peers.iter() {
			if let Some(status) = peers_status.get_mut(cp) {
				let (ban, comment) = status.check_for_ban(cp);
				if ban {
					let peer_addr = PeerAddr::from_str(cp);
					if let Err(e) = peers.ban_peer(&peer_addr, ReasonForBan::PibdFailure, &comment)
					{
						warn!("ban_peer is failed with error: {}", e);
					}
					self.banned_peers.write().insert(peer_addr);
				}
			}
		}
		check_peers.clear();
	}

	fn add_event(&self, peer: String, event: PeerStatusEvent) {
		match &event {
			PeerStatusEvent::Success | PeerStatusEvent::NoResponse(_) => {
				debug!("Adding event {:?} for peer {}", event, peer)
			}
			PeerStatusEvent::Error(_) | PeerStatusEvent::Ban(_) => {
				warn!("Adding event {:?} for peer {}", event, peer)
			}
		}

		let mut peers_status = self.peers_status.write();
		self.new_events_peers.write().insert(peer.clone());
		match peers_status.get_mut(&peer) {
			Some(status) => status.add_event(event),
			None => {
				let mut status = PeerPibdStatus::default();
				status.add_event(event);
				peers_status.insert(peer, status);
			}
		}
	}
}
