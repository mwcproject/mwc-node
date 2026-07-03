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
use crate::router::{Handler, ResponseFuture};
use crate::web::*;
use mwc_crates::bytes::Bytes;
use mwc_crates::hyper::{Request, StatusCode};
use mwc_p2p::tor::arti::canonical_onion_v3;
use mwc_p2p::types::Direction;
use mwc_p2p::types::PeerInfoDisplayLegacy;
use mwc_p2p::types::{PeerAddr, PeerInfoDisplay, ReasonForBan};
use mwc_p2p::Capabilities;
use mwc_p2p::{self, PeerData};
use std::net::{IpAddr, SocketAddr};
use std::sync::Weak;

pub struct PeersAllHandler {
	pub peers: Weak<mwc_p2p::Peers>,
}

impl Handler for PeersAllHandler {
	fn get(&self, _req: Request<Bytes>) -> ResponseFuture {
		let peers = w_fut!(&self.peers);
		result_to_response(
			peers
				.all_peer_data(Capabilities::UNKNOWN)
				.map_err(|e| Error::P2pError(format!("Unable to read peer data, {}", e))),
		)
	}
}

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
				// for tor we just return this because older wallets
				// can't process this.
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

impl Handler for PeersConnectedHandler {
	fn get(&self, _req: Request<Bytes>) -> ResponseFuture {
		let peers: Vec<PeerInfoDisplay> = w_fut!(&self.peers)
			.iter()
			.connected()
			.into_iter()
			.map(|p| p.info.clone().into())
			.collect();

		let mut peers_ret: Vec<PeerInfoDisplayLegacy> = Vec::new();
		for peer in peers.clone() {
			let peer_addr_str = match peer.addr {
				// for tor we just return this because older wallets
				// can't process this.
				PeerAddr::Onion(_) => format!("127.0.0.1:{}", 3414),
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
		json_response(&peers_ret)
	}
}

/// Peer operations
/// GET /v1/peers/10.12.12.13
/// POST /v1/peers/10.12.12.13/ban
/// POST /v1/peers/10.12.12.13/unban
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

	fn parse_peer_addr(context_id: u32, addr: &str) -> Option<PeerAddr> {
		if let Ok(ip_addr) = addr.parse::<IpAddr>() {
			Some(PeerAddr::from_ip(context_id, ip_addr))
		} else if let Ok(addr) = addr.parse::<SocketAddr>() {
			Some(PeerAddr::Ip(addr))
		} else if let Some(onion) = canonical_onion_v3(addr) {
			Some(PeerAddr::Onion(onion))
		} else {
			None
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

impl Handler for PeerHandler {
	fn get(&self, req: Request<Bytes>) -> ResponseFuture {
		#![allow(irrefutable_let_patterns)]
		let command = right_path_element!(req);

		// We support both "ip" and "ip:port" here for peer_addr.
		// "ip:port" is only really useful for local usernet testing on loopback address.
		// Normally we map peers to ip and only allow a single peer per ip address.
		let peers = w_fut!(&self.peers);
		let peer_addr = match Self::parse_peer_addr(peers.get_context_id(), command) {
			Some(peer_addr) => peer_addr,
			None => {
				return response(
					StatusCode::BAD_REQUEST,
					format!("peer address unrecognized: {}", req.uri().path()),
				);
			}
		};

		match peers.get_peer(&peer_addr) {
			Ok(peer) => json_response(&peer),
			Err(e) if Self::is_peer_not_found_error(&e) => response(
				StatusCode::NOT_FOUND,
				format!("peer {} not found", peer_addr),
			),
			Err(e) => response(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("Unable to get peer for address {}, {}", peer_addr, e),
			),
		}
	}

	fn post(&self, req: Request<Bytes>) -> ResponseFuture {
		#![allow(irrefutable_let_patterns)]
		let mut path_elems = req.uri().path().trim_end_matches('/').rsplit('/');
		let command = match path_elems.next() {
			None => return response(StatusCode::BAD_REQUEST, "invalid url"),
			Some(c) => c,
		};
		let peers = w_fut!(&self.peers);
		let addr = match path_elems.next() {
			None => return response(StatusCode::BAD_REQUEST, "invalid url"),
			Some(a) => match Self::parse_peer_addr(peers.get_context_id(), a) {
				Some(addr) => addr,
				None => {
					return response(
						StatusCode::BAD_REQUEST,
						format!("invalid peer address: {}", req.uri().path()),
					);
				}
			},
		};

		match command {
			"ban" => match peers.ban_peer(&addr, ReasonForBan::ManualBan, "banned from CLI") {
				Ok(_) => response(StatusCode::OK, "{}"),
				Err(e) => response(
					StatusCode::INTERNAL_SERVER_ERROR,
					format!("ban for peer {} failed, {:?}", addr, e),
				),
			},
			"unban" => match peers.unban_peer(&addr) {
				Ok(_) => response(StatusCode::OK, "{}"),
				Err(e) => response(
					StatusCode::INTERNAL_SERVER_ERROR,
					format!("unban for peer {} failed, {:?}", addr, e),
				),
			},
			_ => response(
				StatusCode::BAD_REQUEST,
				format!("invalid command {}", command),
			),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_peer_addr_accepts_valid_onion_v3() {
		let onion = "zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion";
		assert_eq!(
			PeerHandler::parse_peer_addr(0, onion),
			Some(PeerAddr::Onion(onion.to_string()))
		);
	}

	#[test]
	fn parse_peer_addr_rejects_noncanonical_onion() {
		assert_eq!(
			PeerHandler::parse_peer_addr(
				0,
				"ZWECAV6DGFTSOSCYBPZUFBO77D452MK3MOX2FQZJQOCU7265BXGQ6OAD.onion"
			),
			None
		);
		assert_eq!(
			PeerHandler::parse_peer_addr(
				0,
				"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oadaaaaaaaa.onion"
			),
			None
		);
	}

	#[test]
	fn parse_peer_addr_rejects_invalid_onion() {
		assert_eq!(PeerHandler::parse_peer_addr(0, "not-an-onion"), None);
	}
}
