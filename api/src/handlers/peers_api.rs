// Copyright 2021 The Grin Developers
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
use crate::p2p::types::{PeerAddr, PeerInfoDisplay, ReasonForBan};
use crate::p2p::{self, PeerData};
use crate::rest::*;
use crate::router::{Handler, ResponseFuture};
use crate::web::*;
use grin_p2p::types::Direction;
use grin_p2p::types::PeerInfoDisplayLegacy;
use hyper::{Body, Request, StatusCode};
use std::net::SocketAddr;
use std::sync::Weak;

pub struct PeersAllHandler {
	pub peers: Weak<p2p::Peers>,
}

impl Handler for PeersAllHandler {
	fn get(&self, _req: Request<Body>) -> ResponseFuture {
		let peers = &w_fut!(&self.peers).all_peer_data();
		json_response_pretty(&peers)
	}
}

pub struct PeersConnectedHandler {
	pub peers: Weak<p2p::Peers>,
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
				PeerAddr::Onion(_) => format!("127.0.0.1:{}", 3414),
				PeerAddr::Ip(ip) => format!("{}:{}", ip.ip(), ip.port()),
			};

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
			};
			peers_ret.push(peer_display);
		}
		Ok(peers_ret)
	}
}

impl Handler for PeersConnectedHandler {
	fn get(&self, _req: Request<Body>) -> ResponseFuture {
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
				PeerAddr::Ip(ip) => format!("{}:{}", ip.ip(), ip.port()),
			};

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
	pub peers: Weak<p2p::Peers>,
}

impl PeerHandler {
	pub fn get_peers(&self, addr: Option<SocketAddr>) -> Result<Vec<PeerData>, Error> {
		if let Some(addr) = addr {
			let peer_addr = PeerAddr::Ip(addr);
			let peer_data: PeerData = w(&self.peers)?.get_peer(peer_addr.clone()).map_err(|e| {
				Error::Internal(format!(
					"Unable to get peer for address {}, {}",
					peer_addr, e
				))
			})?;
			return Ok(vec![peer_data]);
		}
		let peers = w(&self.peers)?.all_peer_data();
		Ok(peers)
	}

	pub fn ban_peer(&self, addr: SocketAddr) -> Result<(), Error> {
		let peer_addr = PeerAddr::Ip(addr);
		w(&self.peers)?
			.ban_peer(peer_addr.clone(), ReasonForBan::ManualBan)
			.map_err(|e| {
				Error::Internal(format!(
					"Unable to ban peer for address {}, {}",
					peer_addr, e
				))
			})
	}

	pub fn unban_peer(&self, addr: SocketAddr) -> Result<(), Error> {
		let peer_addr = PeerAddr::Ip(addr);
		w(&self.peers)?.unban_peer(peer_addr.clone()).map_err(|e| {
			Error::Internal(format!(
				"Unable to unban peer for address {}, {}",
				peer_addr, e
			))
		})
	}
}

impl Handler for PeerHandler {
	fn get(&self, req: Request<Body>) -> ResponseFuture {
		let command = right_path_element!(req);

		// We support both "ip" and "ip:port" here for peer_addr.
		// "ip:port" is only really useful for local usernet testing on loopback address.
		// Normally we map peers to ip and only allow a single peer per ip address.
		let peer_addr;
		if let Ok(ip_addr) = command.parse() {
			peer_addr = PeerAddr::from_ip(ip_addr);
		} else if let Ok(addr) = command.parse() {
			peer_addr = PeerAddr::Ip(addr);
		} else if let Ok(onion) = command.parse() {
			peer_addr = PeerAddr::Onion(onion);
		} else {
			return response(
				StatusCode::BAD_REQUEST,
				format!("peer address unrecognized: {}", req.uri().path()),
			);
		}

		match w_fut!(&self.peers).get_peer(peer_addr.clone()) {
			Ok(peer) => json_response(&peer),
			Err(_) => response(
				StatusCode::NOT_FOUND,
				format!("peer {} not found", peer_addr),
			),
		}
	}
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		let mut path_elems = req.uri().path().trim_end_matches('/').rsplit('/');
		let command = match path_elems.next() {
			None => return response(StatusCode::BAD_REQUEST, "invalid url"),
			Some(c) => c,
		};
		let addr = match path_elems.next() {
			None => return response(StatusCode::BAD_REQUEST, "invalid url"),
			Some(a) => {
				if let Ok(ip_addr) = a.parse() {
					PeerAddr::from_ip(ip_addr)
				} else if let Ok(addr) = a.parse() {
					PeerAddr::Ip(addr)
				} else if let Ok(addr) = a.parse() {
					PeerAddr::Onion(addr)
				} else {
					return response(
						StatusCode::BAD_REQUEST,
						format!("invalid peer address: {}", req.uri().path()),
					);
				}
			}
		};

		match command {
			"ban" => match w_fut!(&self.peers).ban_peer(addr.clone(), ReasonForBan::ManualBan) {
				Ok(_) => response(StatusCode::OK, "{}"),
				Err(e) => response(
					StatusCode::INTERNAL_SERVER_ERROR,
					format!("ban for peer {} failed, {:?}", addr, e),
				),
			},
			"unban" => match w_fut!(&self.peers).unban_peer(addr.clone()) {
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
