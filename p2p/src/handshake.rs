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

use crate::conn::Tracker;
use crate::msg::{read_message, write_message, Hand, Msg, Shake, TorAddress, Type, USER_AGENT};
use crate::mwc_core::core::hash::Hash;
use crate::mwc_core::pow::Difficulty;
use crate::mwc_core::ser::ProtocolVersion;
use crate::peer::Peer;
use crate::types::{
	Capabilities, Direction, Error, P2PConfig, PeerAddr, PeerAddr::Ip, PeerAddr::Onion, PeerInfo,
	PeerLiveInfo,
};
use crate::util::RwLock;
use mwc_core::global;
use rand::{thread_rng, Rng};
use std::collections::VecDeque;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Local generated nonce for peer connecting.
/// Used for self-connecting detection (on receiver side),
/// nonce(s) in recent 100 connecting requests are saved
const NONCES_CAP: usize = 100;
/// Socket addresses of self, extracted from stream when a self-connecting is detected.
/// Used in connecting request to avoid self-connecting request,
/// 10 should be enough since most of servers don't have more than 10 IP addresses.
const ADDRS_CAP: usize = 10;

/// The initial Hand message should come in immediately after the connection is initiated.
/// But for consistency use the same timeout for reading both Hand and Shake messages.
const HAND_READ_TIMEOUT: Duration = Duration::from_millis(10_000);

/// We need to allow time for the peer to receive our Hand message and send back a Shake reply.
const SHAKE_READ_TIMEOUT: Duration = Duration::from_millis(10_000);

/// Fail fast when trying to write a Hand message to the tcp stream.
/// If we cannot write it within a couple of seconds then something has likely gone wrong.
const HAND_WRITE_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Fail fast when trying to write a Shake message to the tcp stream.
/// If we cannot write it within a couple of seconds then something has likely gone wrong.
const SHAKE_WRITE_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Handles the handshake negotiation when two peers connect and decides on
/// protocol.
pub struct Handshake {
	/// Ring buffer of nonces sent to detect self connections without requiring
	/// a node id.
	nonces: Arc<RwLock<VecDeque<u64>>>,
	/// Ring buffer of self addr(s) collected from PeerWithSelf detection (by nonce).
	pub addrs: Arc<RwLock<VecDeque<PeerAddr>>>,
	/// The genesis block header of the chain seen by this node.
	/// We only want to connect to other nodes seeing the same chain (forks are
	/// ok).
	genesis: Hash,
	config: P2PConfig,
	protocol_version: ProtocolVersion,
	tracker: Arc<Tracker>,
	onion_address: Option<String>,
}

impl Handshake {
	/// Creates a new handshake handler
	pub fn new(genesis: Hash, config: P2PConfig, onion_address: Option<String>) -> Handshake {
		Handshake {
			nonces: Arc::new(RwLock::new(VecDeque::with_capacity(NONCES_CAP))),
			addrs: Arc::new(RwLock::new(VecDeque::with_capacity(ADDRS_CAP))),
			genesis,
			config,
			protocol_version: ProtocolVersion::local(),
			tracker: Arc::new(Tracker::new()),
			onion_address: onion_address,
		}
	}

	/// Select a protocol version here that we know is supported by both us and the remote peer.
	///
	/// Current strategy is to simply use `min(local, remote)`.
	///
	/// We can enforce "minimum" protocol version here in the future
	/// by raising an error and forcing the connection to close.
	///
	fn negotiate_protocol_version(&self, other: ProtocolVersion) -> Result<ProtocolVersion, Error> {
		let version = std::cmp::min(self.protocol_version, other);
		Ok(version)
	}

	pub fn initiate(
		&self,
		capabilities: Capabilities,
		total_difficulty: Difficulty,
		self_addr: PeerAddr,
		conn: &mut TcpStream,
		peer_addr: Option<PeerAddr>,
	) -> Result<PeerInfo, Error> {
		// Set explicit timeouts on the tcp stream for hand/shake messages.
		// Once the peer is up and running we will set new values for these.
		// We initiate this connection, writing a Hand message and read a Shake reply.
		let _ = conn.set_write_timeout(Some(HAND_WRITE_TIMEOUT));
		let _ = conn.set_read_timeout(Some(SHAKE_READ_TIMEOUT));

		// prepare the first part of the handshake
		let nonce = self.next_nonce();
		let peer_addr = peer_addr.unwrap_or(match conn.peer_addr() {
			Ok(addr) => PeerAddr::Ip(addr),
			Err(e) => {
				return Err(Error::ConnectionClose(format!(
					"unable to get peer address, {}",
					e
				)))
			}
		});

		let hand = Hand {
			version: self.protocol_version,
			capabilities,
			nonce,
			genesis: self.genesis,
			total_difficulty,
			sender_addr: self_addr.clone(),
			receiver_addr: peer_addr.clone(),
			user_agent: USER_AGENT.to_string(),
			tx_fee_base: global::get_accept_fee_base(),
		};

		// write and read the handshake response
		let msg = Msg::new(Type::Hand, hand, self.protocol_version)?;
		write_message(conn, &vec![msg], self.tracker.clone())?;

		let shake: Shake = read_message(conn, self.protocol_version, Type::Shake)?;
		if shake.genesis != self.genesis {
			return Err(Error::GenesisMismatch {
				us: self.genesis,
				peer: shake.genesis,
			});
		}

		if shake.capabilities.contains(Capabilities::TOR_ADDRESS) && self.onion_address.is_some() {
			let onion_address = self.onion_address.as_ref().unwrap().to_string();
			debug!(
				"Tor enabled peer {:?}, sending onion_address = {}",
				self_addr, onion_address
			);

			// send tor address
			let tor_address = TorAddress::new(onion_address);
			let msg = Msg::new(Type::TorAddress, tor_address, self.protocol_version)?;
			write_message(conn, &vec![msg], self.tracker.clone())?;
		} else {
			debug!("non-Tor peer {:?}", self_addr);
		}

		let negotiated_version = self.negotiate_protocol_version(shake.version)?;

		let peer_info = PeerInfo {
			capabilities: shake.capabilities,
			user_agent: shake.user_agent,
			addr: peer_addr,
			version: negotiated_version,
			live_info: Arc::new(RwLock::new(PeerLiveInfo::new(shake.total_difficulty))),
			direction: if self.onion_address.is_some() {
				Direction::OutboundTor
			} else {
				Direction::Outbound
			},
			tx_base_fee: shake.tx_fee_base,
		};

		// If denied then we want to close the connection
		// (without providing our peer with any details why).
		if Peer::is_denied(&self.config, &peer_info.addr) {
			return Err(Error::ConnectionClose(format!(
				"{:?} is denied",
				peer_info.addr
			)));
		}

		debug!(
			"Connected! Cumulative {} offered from {:?}, {:?}, {:?}, {:?}",
			shake.total_difficulty.to_num(),
			peer_info.addr,
			peer_info.version,
			peer_info.user_agent,
			peer_info.capabilities,
		);
		// when more than one protocol version is supported, choosing should go here
		Ok(peer_info)
	}

	pub fn accept(
		&self,
		capab: Capabilities,
		total_difficulty: Difficulty,
		conn: &mut TcpStream,
	) -> Result<PeerInfo, Error> {
		// Set explicit timeouts on the tcp stream for hand/shake messages.
		// Once the peer is up and running we will set new values for these.
		// We accept an inbound connection, reading a Hand then writing a Shake reply.
		let _ = conn.set_read_timeout(Some(HAND_READ_TIMEOUT));
		let _ = conn.set_write_timeout(Some(SHAKE_WRITE_TIMEOUT));

		let hand: Hand = read_message(conn, self.protocol_version, Type::Hand)?;

		// all the reasons we could refuse this connection for
		if hand.genesis != self.genesis {
			return Err(Error::GenesisMismatch {
				us: self.genesis,
				peer: hand.genesis,
			});
		} else {
			// check the nonce to see if we are trying to connect to ourselves
			let nonces = self.nonces.read();
			let addr = resolve_peer_addr(hand.sender_addr.clone(), &conn);
			if nonces.contains(&hand.nonce) {
				// save ip addresses of ourselves
				let mut addrs = self.addrs.write();
				addrs.push_back(addr);
				if addrs.len() >= ADDRS_CAP {
					addrs.pop_front();
				}
				return Err(Error::PeerWithSelf);
			}
		}

		let negotiated_version = self.negotiate_protocol_version(hand.version)?;

		// all good, keep peer info
		let peer_info = PeerInfo {
			capabilities: hand.capabilities,
			user_agent: hand.user_agent,
			addr: resolve_peer_addr(hand.sender_addr.clone(), &conn),
			version: negotiated_version,
			live_info: Arc::new(RwLock::new(PeerLiveInfo::new(hand.total_difficulty))),
			direction: if self.onion_address.is_some() {
				Direction::InboundTor
			} else {
				Direction::Inbound
			},
			tx_base_fee: hand.tx_fee_base,
		};

		// At this point we know the published ip and port of the peer
		// so check if we are configured to explicitly allow or deny it.
		// If denied then we want to close the connection
		// (without providing our peer with any details why).
		if Peer::is_denied(&self.config, &peer_info.addr) {
			return Err(Error::ConnectionClose(String::from(
				"Peer denied because it is in config black list",
			)));
		}

		// send our reply with our info
		let shake = Shake {
			version: self.protocol_version,
			capabilities: capab,
			genesis: self.genesis,
			total_difficulty: total_difficulty,
			user_agent: USER_AGENT.to_string(),
			tx_fee_base: global::get_accept_fee_base(),
		};

		let msg = Msg::new(Type::Shake, shake, negotiated_version)?;
		write_message(conn, &vec![msg], self.tracker.clone())?;

		trace!("Success handshake with {}.", peer_info.addr);

		Ok(peer_info)
	}

	/// Generate a new random nonce and store it in our ring buffer
	fn next_nonce(&self) -> u64 {
		let nonce = thread_rng().gen();

		let mut nonces = self.nonces.write();
		nonces.push_back(nonce);
		if nonces.len() >= NONCES_CAP {
			nonces.pop_front();
		}
		nonce
	}
}

/// Resolve the correct peer_addr based on the connection and the advertised port.
fn resolve_peer_addr(advertised: PeerAddr, conn: &TcpStream) -> PeerAddr {
	match advertised {
		Ip(socket_addr) => {
			let port = socket_addr.port();
			if let Ok(addr) = conn.peer_addr() {
				PeerAddr::Ip(SocketAddr::new(addr.ip(), port))
			} else {
				advertised
			}
		}
		Onion(_) => advertised,
	}
}
