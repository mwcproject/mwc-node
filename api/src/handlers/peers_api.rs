// Copyright 2019 The Grin Developers
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

use super::utils::w;
use crate::rest::*;
use mwc_p2p::types::Direction;
use mwc_p2p::types::PeerInfoDisplayLegacy;
use mwc_p2p::types::{PeerAddr, PeerInfoDisplay, ReasonForBan};
use mwc_p2p::Capabilities;
use mwc_p2p::{self, PeerData};
use std::net::SocketAddr;
use std::sync::Weak;

pub struct PeersConnectedHandler {
	pub peers: Weak<mwc_p2p::Peers>,
}

impl PeersConnectedHandler {
	pub fn get_connected_peers(&self) -> Result<Vec<PeerInfoDisplayLegacy>, Error> {
		let peers = w(&self.peers)?
			.iter()
			.connected()
			.into_iter()
			.map(|p| p.info.clone().into())
			.collect::<Vec<PeerInfoDisplay>>();

		let mut peers_ret: Vec<PeerInfoDisplayLegacy> = Vec::new();

		for peer in peers {
			let peer_addr_str = match peer.addr {
				PeerAddr::Onion(onion) => onion,
				PeerAddr::Ip(ip) => ip.to_string(),
			};

			// PeerInfoDisplayLegacy predates Tor peer support, so keep its
			// direction field in the legacy inbound/outbound-only form.
			let peer_direction = if peer.direction == Direction::OutboundTor {
				Direction::Outbound
			} else if peer.direction == Direction::InboundTor {
				Direction::Inbound
			} else {
				peer.direction
			};

			let peer_display = PeerInfoDisplayLegacy {
				capabilities: peer.capabilities,
				user_agent: peer.user_agent,
				version: peer.version,
				addr: peer_addr_str,
				direction: peer_direction,
				total_difficulty: peer.total_difficulty,
				height: peer.height,
				last_seen: peer.last_seen,
			};
			peers_ret.push(peer_display);
		}
		Ok(peers_ret)
	}
}

/// Peer operations
pub struct PeerHandler {
	pub peers: Weak<mwc_p2p::Peers>,
}

impl PeerHandler {
	fn is_peer_not_found_error(error: &mwc_p2p::Error) -> bool {
		match error {
			mwc_p2p::Error::Store(e) => e.store_error_is_not_found(),
			mwc_p2p::Error::PeerNotFound => true,
			_ => false,
		}
	}

	pub fn get_peers(&self, addr: Option<SocketAddr>) -> Result<Vec<PeerData>, Error> {
		if let Some(addr) = addr {
			let peer_addr = PeerAddr::Ip(addr);
			let peer_data: PeerData = match w(&self.peers)?.get_peer(&peer_addr) {
				Ok(peer_data) => peer_data,
				Err(e) if Self::is_peer_not_found_error(&e) => {
					return Err(Error::NotFound(format!("peer {} not found", peer_addr)));
				}
				Err(e) => {
					return Err(Error::Internal(format!(
						"Unable to get peer for address {}, {}",
						peer_addr, e
					)));
				}
			};
			return Ok(vec![peer_data]);
		}
		let peers = w(&self.peers)?
			.all_peer_data(Capabilities::UNKNOWN)
			.map_err(|e| Error::P2pError(format!("Unable to read peer data, {}", e)))?;
		Ok(peers)
	}

	pub fn ban_peer(&self, addr: SocketAddr) -> Result<(), Error> {
		let peer_addr = PeerAddr::Ip(addr);
		w(&self.peers)?
			.ban_peer(&peer_addr, ReasonForBan::ManualBan, "banned from api")
			.map_err(|e| {
				Error::Internal(format!(
					"Unable to ban peer for address {}, {}",
					peer_addr, e
				))
			})
	}

	pub fn unban_peer(&self, addr: SocketAddr) -> Result<(), Error> {
		let peer_addr = PeerAddr::Ip(addr);
		w(&self.peers)?.unban_peer(&peer_addr).map_err(|e| {
			Error::Internal(format!(
				"Unable to unban peer for address {}, {}",
				peer_addr, e
			))
		})
	}
}
