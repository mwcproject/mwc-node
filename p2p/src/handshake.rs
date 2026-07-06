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
use crate::msg::{
	read_body, read_header, read_message, write_message, Hand, Msg, MsgHeaderWrapper, Shake, Type,
	ONION_PROOF_SIGNATURE_LEN, USER_AGENT,
};
use crate::peer::Peer;
use crate::tor::arti::{canonical_onion_v3, is_valid_onion_v3, parse_onion_expanded_key};
use crate::tor::tcp_data_stream::TcpDataStream;
use crate::types::{
	Capabilities, Direction, Error, NetAdapter, P2PConfig, PeerAddr, PeerAddr::Ip, PeerAddr::Onion,
	PeerInfo, PeerLiveInfo,
};
use mwc_core::core::hash::Hash;
use mwc_core::global;
use mwc_core::pow::Difficulty;
use mwc_core::ser::{BinWriter, ProtocolVersion, Writeable, Writer};
use mwc_crates::chrono::prelude::Utc;
use mwc_crates::ed25519_dalek::Signature as DalekSignature;
use mwc_crates::log::{debug, info, trace};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::rand::TryRng;
use mwc_crates::zeroize::Zeroizing;
use mwc_util::OnionV3Address;
use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
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
const HAND_READ_TIMEOUT: Duration = Duration::from_millis(15_000);

/// We need to allow time for the peer to receive our Hand message and send back a Shake reply.
const SHAKE_READ_TIMEOUT: Duration = Duration::from_millis(15_000);

/// Fail fast when trying to write a Hand message to the tcp stream.
/// If we cannot write it within a couple of seconds then something has likely gone wrong.
const HAND_WRITE_TIMEOUT: Duration = Duration::from_millis(10_000);

/// Fail fast when trying to write a Shake message to the tcp stream.
/// If we cannot write it within a couple of seconds then something has likely gone wrong.
const SHAKE_WRITE_TIMEOUT: Duration = Duration::from_millis(10_000);
pub const ONION_PROOF_PROTOCOL_VERSION: u32 = 5;
const ONION_HAND_PROOF_DOMAIN: &[u8] = b"MWC_ONION_HAND_PROOF_V2";
const ONION_HAND_PROOF_MAX_CLOCK_SKEW_SECS: i64 = 10 * 60;
const IP_RECEIVER_ADDRS_CAP: usize = 5;
const IP_RECEIVER_ADDRS_MIN_AGREEMENT: usize = 4;
type IpReceiverAddrSample = (SocketAddr, PeerAddr);

fn bad_handshake(message: impl Into<String>) -> Error {
	Error::BadHandshake(message.into())
}

fn read_hand_message<R: Read>(
	stream: &mut R,
	version: ProtocolVersion,
	context_id: u32,
) -> Result<Hand, Error> {
	match read_header(stream, version, context_id)? {
		MsgHeaderWrapper::Known(header) => {
			if header.msg_type == Type::Hand {
				read_body(&header, stream, version, context_id)
			} else {
				Err(Error::BadMessage(format!(
					"header.msg_type={:?} but expected {:?}",
					header.msg_type,
					Type::Hand
				)))
			}
		}
		MsgHeaderWrapper::Unknown(msg_len, tp) => Err(Error::BadMessage(format!(
			"Unknown message of length {} and type {} while expecting {:?}",
			msg_len,
			tp,
			Type::Hand
		))),
	}
}

/// Handles the handshake negotiation when two peers connect and decides on
/// protocol.
pub struct Handshake {
	/// Ring buffer of nonces sent to detect self connections without requiring
	/// a node id.
	nonces: Arc<RwLock<VecDeque<u64>>>,
	/// Ring buffer of self addr(s) collected from PeerWithSelf detection (by nonce).
	pub addrs: Arc<RwLock<VecDeque<PeerAddr>>>,
	/// Recent receiver addresses advertised by inbound Hand requests, paired
	/// with the source peer that reported them. Used to learn the address peers
	/// use to reach IP-based nodes.
	ip_receiver_addrs: Arc<RwLock<VecDeque<IpReceiverAddrSample>>>,
	/// The genesis block header of the chain seen by this node.
	/// We only want to connect to other nodes seeing the same chain (forks are
	/// ok).
	genesis: Hash,
	config: P2PConfig,
	protocol_version: ProtocolVersion,
	context_id: u32,
	tracker: Arc<Tracker>,
	pub onion_address: Option<String>,
	onion_expanded_key: Option<Zeroizing<[u8; 64]>>,
}

impl Handshake {
	/// Creates a new handshake handler
	pub fn new(
		context_id: u32,
		genesis: Hash,
		config: P2PConfig,
		onion_address: Option<String>,
		onion_expanded_key: Option<Zeroizing<[u8; 64]>>,
	) -> Handshake {
		Handshake {
			nonces: Arc::new(RwLock::new(VecDeque::with_capacity(NONCES_CAP))),
			addrs: Arc::new(RwLock::new(VecDeque::with_capacity(ADDRS_CAP))),
			ip_receiver_addrs: Arc::new(RwLock::new(VecDeque::with_capacity(
				IP_RECEIVER_ADDRS_CAP,
			))),
			genesis,
			// Accepted risk: config.onion_expanded_key may keep the original onion
			// identity key string alive as a duplicate of the parsed Zeroizing key
			// below. Keep the full P2PConfig here because handshake validation uses
			// the peer policy settings from it, and callers rely on the complete
			// config being preserved across handshake setup. P2PConfig zeroizes this
			// field when the retained config is dropped.
			config,
			protocol_version: ProtocolVersion::local(),
			context_id,
			tracker: Arc::new(Tracker::new()),
			onion_address: onion_address,
			onion_expanded_key,
		}
	}

	/// Select a protocol version here that we know is supported by both us and the remote peer.
	///
	/// Current strategy is to simply use `min(local, remote)`.
	///
	/// There is no way to advertise support for a protocol version while
	/// preventing a peer from selecting it. A peer can choose any protocol
	/// version we still support by offering it. To stop supporting older
	/// versions, enforce a minimum protocol version here by raising an error
	/// and forcing the connection to close.
	///
	fn negotiate_protocol_version(&self, other: ProtocolVersion) -> Result<ProtocolVersion, Error> {
		let version = std::cmp::min(self.protocol_version, other);
		Ok(version)
	}

	fn validate_inbound_receiver_addr(&self, hand: &Hand) -> Result<(), Error> {
		if self.onion_address.is_some() {
			return self.validate_tor_receiver_addr(&hand.receiver_addr, &hand.sender_addr);
		}

		let receiver_addr = match &hand.receiver_addr {
			Ip(receiver_addr) => *receiver_addr,
			Onion(_) => {
				return Err(bad_handshake(format!(
					"ip handshake for {} targets onion receiver address {}",
					hand.sender_addr, hand.receiver_addr
				)));
			}
		};

		self.validate_ip_receiver_addr(receiver_addr, &hand.sender_addr)
	}

	fn observe_inbound_receiver_addr(&self, hand: &Hand, sender_addr: &PeerAddr) {
		if self.onion_address.is_some() {
			return;
		}
		if let Ip(receiver_addr) = &hand.receiver_addr {
			self.record_ip_receiver_addr(*receiver_addr, sender_addr.clone());
		}
	}

	fn validate_tor_receiver_addr(
		&self,
		receiver_addr: &PeerAddr,
		sender_addr: &PeerAddr,
	) -> Result<(), Error> {
		let local_onion = self.onion_address.as_ref().ok_or_else(|| {
			Error::ConnectionClose(format!(
				"tor handshake for {} cannot be bound to a configured onion address",
				sender_addr
			))
		})?;
		let local_onion = canonical_onion_v3(local_onion).ok_or_else(|| {
			Error::ConnectionClose("configured onion address is not canonical".into())
		})?;
		let receiver_onion = match receiver_addr {
			Onion(receiver_onion) => receiver_onion,
			Ip(_) => {
				return Err(bad_handshake(format!(
					"tor handshake for {} targets non-onion receiver address {}",
					sender_addr, receiver_addr
				)));
			}
		};
		let receiver_onion = canonical_onion_v3(receiver_onion).ok_or_else(|| {
			bad_handshake(format!(
				"tor handshake for {} targets a non-canonical receiver address",
				sender_addr
			))
		})?;
		if receiver_onion != local_onion {
			return Err(bad_handshake(format!(
				"tor handshake for {} is not bound to our onion address",
				sender_addr
			)));
		}
		Ok(())
	}

	fn validate_ip_receiver_addr(
		&self,
		receiver_addr: SocketAddr,
		sender_addr: &PeerAddr,
	) -> Result<(), Error> {
		// Accepted risk: for IP handshakes we do not have an authenticated
		// receiver identity comparable to a configured onion address. The best
		// available signal is the receiver address repeatedly reported by
		// inbound peers, so the no-quorum learning window can be poisoned by
		// peers that advertise the same bogus receiver address. Once learned,
		// mismatches are rejected before new samples are recorded, which can pin
		// the node until restart or manual state change. We accept this tradeoff
		// because it is the best IP receiver-address binding currently available.
		let expected_addr = self.learned_ip_receiver_addr();

		if let Some(expected_addr) = expected_addr {
			if receiver_addr != expected_addr {
				return Err(bad_handshake(format!(
					"ip handshake for {} targets receiver address {}, expected {}",
					sender_addr, receiver_addr, expected_addr
				)));
			}
		}
		Ok(())
	}

	fn learned_ip_receiver_addr(&self) -> Option<SocketAddr> {
		let receiver_addrs = self.ip_receiver_addrs.read_recursive();
		learned_ip_receiver_addr_from_samples(&receiver_addrs)
	}

	fn record_ip_receiver_addr(&self, receiver_addr: SocketAddr, sender_addr: PeerAddr) {
		let sender_key = sender_addr.as_key();
		let mut receiver_addrs = self.ip_receiver_addrs.write();
		if receiver_addrs
			.iter()
			.any(|(_, sample_sender_addr)| sample_sender_addr.as_key() == sender_key)
		{
			return;
		}
		receiver_addrs.push_back((receiver_addr, sender_addr));
		if receiver_addrs.len() > IP_RECEIVER_ADDRS_CAP {
			receiver_addrs.pop_front();
		}
	}

	fn record_peer_with_self_addr(&self, hand: &Hand, addr: &PeerAddr) {
		// Call only after sender authentication and peer policy validation.
		if let Onion(_) = addr {
			if hand.version.value() < ONION_PROOF_PROTOCOL_VERSION
				|| hand.onion_sig.is_none()
				|| hand.onion_sig_timestamp.is_none()
			{
				debug!(
					"not caching unauthenticated onion PeerWithSelf addr: {}",
					addr
				);
				return;
			}
		}

		let mut addrs = self.addrs.write();
		addrs.push_back(addr.clone());
		if addrs.len() >= ADDRS_CAP {
			addrs.pop_front();
		}
	}

	fn onion_hand_proof_transcript(
		&self,
		sender_addr: &PeerAddr,
		receiver_addr: &PeerAddr,
		nonce: u64,
		timestamp: i64,
		genesis: &Hash,
		version: ProtocolVersion,
	) -> Result<Vec<u8>, Error> {
		// Intentional scope: this signature is only an onion identity proof.
		// It binds the advertised onion sender address to this receiver/genesis
		// context and recent handshake nonce/timestamp. Other Hand fields such
		// as capabilities, total_difficulty, user_agent, and tx_fee_base are
		// ordinary inbound peer metadata; they are not supposed to be protected
		// by the onion identity signature.
		let mut transcript = Vec::new();
		{
			let mut writer = BinWriter::new(&mut transcript, version, self.context_id);
			writer.write_bytes(ONION_HAND_PROOF_DOMAIN)?;
			sender_addr.write(&mut writer)?;
			receiver_addr.write(&mut writer)?;
			writer.write_u64(nonce)?;
			writer.write_i64(timestamp)?;
			genesis.write(&mut writer)?;
			version.write(&mut writer)?;
		}
		Ok(transcript)
	}

	fn sign_onion_hand_proof(
		&self,
		sender_addr: &PeerAddr,
		receiver_addr: &PeerAddr,
		nonce: u64,
		timestamp: i64,
		genesis: &Hash,
	) -> Result<Option<[u8; ONION_PROOF_SIGNATURE_LEN]>, Error> {
		// Sign when advertising an onion sender identity. The receiver may be onion
		// or IP; onion receivers are strictly bound during verification when this
		// node has a configured onion address.
		let sender_onion = match sender_addr {
			Onion(onion) => onion,
			Ip(_) => return Ok(None),
		};
		let expanded_key = self.onion_expanded_key.as_ref().ok_or_else(|| {
			Error::TorConfig("onion identity key is required to advertise onion address".into())
		})?;
		let keypair = parse_onion_expanded_key(&*expanded_key)
			.map_err(|e| Error::TorConfig(format!("invalid onion identity key, {}", e)))?;
		let sender_onion_addr = OnionV3Address::try_from(sender_onion.as_str()).map_err(|e| {
			Error::TorConfig(format!(
				"unable to parse local onion address {}: {}",
				sender_onion, e
			))
		})?;
		if sender_onion_addr.as_bytes() != keypair.public().as_bytes() {
			return Err(Error::TorConfig(format!(
				"onion identity key does not match advertised onion address {}",
				sender_onion
			)));
		}

		let transcript = self.onion_hand_proof_transcript(
			sender_addr,
			receiver_addr,
			nonce,
			timestamp,
			genesis,
			self.protocol_version,
		)?;
		Ok(Some(keypair.sign(&transcript).to_bytes()))
	}

	fn verify_onion_hand_proof(&self, hand: &Hand, adapter: &dyn NetAdapter) -> Result<(), Error> {
		let stored_version = adapter.peer_version(&hand.sender_addr)?;
		self.verify_onion_hand_proof_with_stored_version(hand, stored_version)
	}

	fn verify_onion_hand_proof_with_stored_version(
		&self,
		hand: &Hand,
		stored_version: Option<ProtocolVersion>,
	) -> Result<(), Error> {
		let sender_onion = match &hand.sender_addr {
			Onion(onion) => onion,
			Ip(_) => return Ok(()),
		};
		let stored_v5_or_newer = stored_version.map_or(false, |version| {
			version.value() >= ONION_PROOF_PROTOCOL_VERSION
		});

		if hand.version.value() < ONION_PROOF_PROTOCOL_VERSION {
			// Accepted risk: v4 and older onion peers use a legacy protocol that
			// we still support, and their self-reported version is not
			// authenticated by an onion identity proof. A new legacy peer can be
			// impersonated by another node that claims its onion sender address.
			// The v5+ signature is intended to prevent peers from impersonating
			// v5 Tor nodes; once an onion peer has been stored as v5 or newer,
			// reject later legacy handshakes for that same sender address.
			if stored_v5_or_newer {
				return Err(bad_handshake(format!(
					"rejecting legacy onion handshake for previously verified peer {}",
					hand.sender_addr
				)));
			}
			return Ok(());
		}

		if self.onion_address.is_some() {
			self.validate_tor_receiver_addr(&hand.receiver_addr, &hand.sender_addr)?;
		}

		let onion_sig = hand.onion_sig.as_ref().ok_or_else(|| {
			bad_handshake(format!(
				"missing onion identity proof for protocol {} peer {}",
				hand.version, hand.sender_addr
			))
		})?;
		let timestamp = hand.onion_sig_timestamp.ok_or_else(|| {
			bad_handshake(format!(
				"missing onion identity proof timestamp for protocol {} peer {}",
				hand.version, hand.sender_addr
			))
		})?;
		// Accepted risk: the onion proof uses a sender-supplied nonce and
		// timestamp, so a captured Hand can be replayed to the same receiver
		// until the timestamp leaves the allowed skew window. We intentionally
		// avoid adding an extra receiver-challenge interaction to the protocol.
		// The proof is tied to the peer addresses, and duplicate connection
		// requests for the same peer are rejected while that peer is still
		// online.
		verify_onion_hand_proof_timestamp(&hand.sender_addr, timestamp)?;
		let sender_onion_addr = OnionV3Address::try_from(sender_onion.as_str()).map_err(|e| {
			bad_handshake(format!(
				"unable to parse onion identity {}: {}",
				sender_onion, e
			))
		})?;
		let verifying_key = sender_onion_addr.to_ed25519().map_err(|e| {
			bad_handshake(format!(
				"unable to build onion verifying key for {}: {}",
				sender_onion, e
			))
		})?;
		let transcript = self.onion_hand_proof_transcript(
			&hand.sender_addr,
			&hand.receiver_addr,
			hand.nonce,
			timestamp,
			&hand.genesis,
			hand.version,
		)?;
		let signature = DalekSignature::from_bytes(onion_sig);
		verifying_key
			.verify_strict(&transcript, &signature)
			.map_err(|e| {
				bad_handshake(format!(
					"invalid onion identity proof for {}: {}",
					hand.sender_addr, e
				))
			})
	}

	pub fn initiate(
		&self,
		capabilities: Capabilities,
		total_difficulty: Difficulty,
		self_addr: PeerAddr,
		conn: &mut TcpDataStream,
		peer_addr: PeerAddr,
	) -> Result<PeerInfo, Error> {
		// Set explicit timeouts on the tcp stream for hand/shake messages.
		// Once the peer is up and running we will set new values for these.
		// We initiate this connection, writing a Hand message and read a Shake reply.
		conn.set_write_timeout(HAND_WRITE_TIMEOUT);
		conn.set_read_timeout(SHAKE_READ_TIMEOUT);

		// prepare the first part of the handshake
		let nonce = self.next_nonce()?;
		let onion_sig_timestamp = Utc::now().timestamp();
		let onion_sig = self.sign_onion_hand_proof(
			&self_addr,
			&peer_addr,
			nonce,
			onion_sig_timestamp,
			&self.genesis,
		)?;

		let hand = Hand {
			version: self.protocol_version,
			capabilities,
			nonce,
			genesis: self.genesis,
			total_difficulty,
			sender_addr: self_addr.clone(),
			receiver_addr: peer_addr.clone(),
			user_agent: USER_AGENT.to_string(),
			tx_fee_base: global::get_accept_fee_base(self.context_id),
			onion_sig,
			onion_sig_timestamp: onion_sig.map(|_| onion_sig_timestamp),
		};

		// write and read the handshake response
		let msg = Msg::new(Type::Hand, hand, self.protocol_version, self.context_id)?;
		write_message(conn, &vec![msg], self.tracker.clone())?;

		let shake: Shake = read_message(conn, self.protocol_version, self.context_id, Type::Shake)
			.map_err(|err| match err {
				Error::Serialization(err) => {
					bad_handshake(format!("invalid Shake message from peer: {}", err))
				}
				err => err,
			})?;
		if shake.genesis != self.genesis {
			return Err(Error::GenesisMismatch {
				us: self.genesis,
				peer: shake.genesis,
			});
		}

		// TorAddress message is no need to send. The onion address is already known from the Hand message
		// Duplicated data, also withotu a proof is not needed

		let negotiated_version = self.negotiate_protocol_version(shake.version)?;

		let peer_info = PeerInfo {
			capabilities: shake.capabilities,
			user_agent: shake.user_agent,
			direction: if peer_addr.tor_address().is_ok() {
				Direction::OutboundTor
			} else {
				Direction::Outbound
			},
			addr: peer_addr,
			version: negotiated_version,
			live_info: Arc::new(RwLock::new(PeerLiveInfo::new(shake.total_difficulty))),
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
		conn: &mut TcpDataStream,
		adapter: &dyn NetAdapter,
	) -> Result<PeerInfo, Error> {
		// Set explicit timeouts on the tcp stream for hand/shake messages.
		// Once the peer is up and running we will set new values for these.
		// We accept an inbound connection, reading a Hand then writing a Shake reply.
		let _ = conn.set_read_timeout(HAND_READ_TIMEOUT);
		let _ = conn.set_write_timeout(SHAKE_WRITE_TIMEOUT);

		let hand: Hand = read_hand_message(conn, self.protocol_version, self.context_id)?;

		if hand.genesis != self.genesis {
			return Err(Error::GenesisMismatch {
				us: self.genesis,
				peer: hand.genesis,
			});
		}

		let addr = resolve_peer_addr(&hand.sender_addr, &conn)?;
		// Check the nonce to see if we are trying to connect to ourselves.
		let peer_with_self = self.nonces.read_recursive().contains(&hand.nonce);

		self.verify_onion_hand_proof(&hand, adapter)?;

		let negotiated_version = self.negotiate_protocol_version(hand.version)?;

		if let Onion(onion_addr) = &addr {
			if !is_valid_onion_v3(&onion_addr) {
				info!(
					"Peer advertize invalid onion address {}, not accepting it",
					onion_addr
				);
				return Err(Error::TorConnect(format!(
					"Peer advertize invalid onion address {}",
					onion_addr
				)));
			}
		}

		// At this point we know the published ip and port of the peer
		// so check if we are configured to explicitly allow or deny it.
		// If denied then we want to close the connection
		// (without providing our peer with any details why).
		if Peer::is_denied(&self.config, &addr) {
			return Err(Error::ConnectionClose(String::from(
				"Peer denied because it is in config black list",
			)));
		}

		if adapter.is_banned(&addr).map_err(|e| {
			Error::ConnectionClose(format!("Unable to verify ban state for {}: {}", addr, e))
		})? {
			return Err(Error::ConnectionClose(String::from(
				"Peer denied because it is banned",
			)));
		}

		self.validate_inbound_receiver_addr(&hand)?;

		if peer_with_self {
			self.record_peer_with_self_addr(&hand, &addr);
			return Err(Error::PeerWithSelf);
		}

		// send our reply with our info
		let shake = Shake {
			version: self.protocol_version,
			capabilities: capab,
			genesis: self.genesis,
			total_difficulty: total_difficulty,
			user_agent: USER_AGENT.to_string(),
			tx_fee_base: global::get_accept_fee_base(self.context_id),
		};

		let msg = Msg::new(Type::Shake, shake, negotiated_version, self.context_id)?;
		write_message(conn, &vec![msg], self.tracker.clone())?;

		self.observe_inbound_receiver_addr(&hand, &addr);

		// all good, keep peer info
		let peer_info = PeerInfo {
			capabilities: hand.capabilities,
			user_agent: hand.user_agent,
			direction: if addr.tor_address().is_ok() {
				Direction::InboundTor
			} else {
				Direction::Inbound
			},
			addr,
			version: negotiated_version,
			live_info: Arc::new(RwLock::new(PeerLiveInfo::new(hand.total_difficulty))),
			tx_base_fee: hand.tx_fee_base,
		};

		trace!("Success handshake with {}.", peer_info.addr);

		Ok(peer_info)
	}

	/// Generate a new random nonce and store it in our ring buffer
	fn next_nonce(&self) -> Result<u64, Error> {
		let nonce = SysRng
			.try_next_u64()
			.map_err(|e| Error::Internal(format!("SysRng failure, {}", e)))?;

		let mut nonces = self.nonces.write();
		nonces.push_back(nonce);
		if nonces.len() > NONCES_CAP {
			nonces.pop_front();
		}
		Ok(nonce)
	}
}

fn verify_onion_hand_proof_timestamp(peer_addr: &PeerAddr, timestamp: i64) -> Result<(), Error> {
	let now = Utc::now().timestamp();
	let skew = if timestamp <= now {
		now.saturating_sub(timestamp)
	} else {
		timestamp.saturating_sub(now)
	};
	if skew > ONION_HAND_PROOF_MAX_CLOCK_SKEW_SECS {
		return Err(bad_handshake(format!(
			"onion identity proof timestamp for {} is outside the allowed {} second window: timestamp={}, now={}",
			peer_addr, ONION_HAND_PROOF_MAX_CLOCK_SKEW_SECS, timestamp, now
		)));
	}
	Ok(())
}

fn learned_ip_receiver_addr_from_samples(
	samples: &VecDeque<IpReceiverAddrSample>,
) -> Option<SocketAddr> {
	let mut counts = HashMap::new();
	for (receiver_addr, _) in samples {
		*counts.entry(*receiver_addr).or_insert(0usize) += 1;
	}

	counts
		.into_iter()
		.max_by_key(|(_, count)| *count)
		.and_then(|(receiver_addr, count)| {
			if count >= IP_RECEIVER_ADDRS_MIN_AGREEMENT {
				Some(receiver_addr)
			} else {
				None
			}
		})
}

/// Resolve the correct peer_addr based on the connection and the advertised port.
///
/// For IP peers we can bind the advertised listening port to the accepted socket
/// IP. Onion peers are different: Tor does not expose a caller onion identity to
/// the service, so protocol versions before v5 only provide an advertised
/// address. In v5+ an onion sender must include a Hand signature proving control
/// of the advertised onion key. That proof does not prove reachability; only a
/// successful outbound Tor connection proves the address can be dialed.
fn resolve_peer_addr(advertised: &PeerAddr, conn: &TcpDataStream) -> Result<PeerAddr, Error> {
	match advertised {
		Ip(socket_addr) => resolve_ip_peer_addr(socket_addr, conn.peer_addr()),
		Onion(_) => match conn.peer_addr() {
			Err(Error::IpAddressRequestFromTor) => Ok(advertised.clone()),
			Ok(PeerAddr::Ip(ip_addr)) => Err(bad_handshake(format!(
				"cannot accept advertised onion sender address {} over IP transport {}",
				advertised, ip_addr
			))),
			Ok(addr) => Err(bad_handshake(format!(
				"cannot verify advertised onion sender address {} over non-Tor transport {}",
				advertised, addr
			))),
			Err(err) => Err(Error::ConnectionClose(format!(
				"cannot verify advertised onion sender address {}: {}",
				advertised, err
			))),
		},
	}
}

fn resolve_ip_peer_addr(
	advertised: &SocketAddr,
	transport_addr: Result<PeerAddr, Error>,
) -> Result<PeerAddr, Error> {
	if advertised.port() == 0 {
		return Err(bad_handshake(format!(
			"cannot accept advertised IP sender address {} with port 0",
			advertised
		)));
	}

	match transport_addr {
		Ok(PeerAddr::Ip(ip_addr)) => {
			let transport_ip = match ip_addr {
				SocketAddr::V4(addr) => IpAddr::V4(*addr.ip()),
				SocketAddr::V6(addr) => {
					if addr.flowinfo() != 0 || addr.scope_id() != 0 {
						return Err(bad_handshake(format!(
							"cannot verify advertised IP sender address {} over IPv6 transport {} with nonzero flowinfo or scope_id",
							advertised, addr
						)));
					}
					IpAddr::V6(*addr.ip())
				}
			};
			Ok(PeerAddr::Ip(SocketAddr::new(
				normalize_transport_ip(transport_ip),
				advertised.port(),
			)))
		}
		Ok(addr) => Err(bad_handshake(format!(
			"cannot verify advertised IP sender address {} over non-IP transport {}",
			advertised, addr
		))),
		Err(err) => Err(Error::ConnectionClose(format!(
			"cannot verify advertised IP sender address {}: {}",
			advertised, err
		))),
	}
}

fn normalize_transport_ip(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(ipv6) => ipv6
			.to_ipv4_mapped()
			.map(IpAddr::V4)
			.unwrap_or(IpAddr::V6(ipv6)),
		IpAddr::V4(_) => ip,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::msg::MsgHeader;
	use mwc_core::ser;
	use mwc_crates::tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};

	fn onion_from_seed(seed: &[u8; 32]) -> String {
		format!(
			"{}.onion",
			OnionV3Address::from_private(seed).unwrap().to_ov3_str()
		)
	}

	fn expanded_key_from_seed(seed: &[u8; 32]) -> Zeroizing<[u8; 64]> {
		let keypair = Keypair::from_bytes(seed);
		Zeroizing::new(ExpandedKeypair::from(&keypair).to_secret_key_bytes())
	}

	fn test_handshake(
		onion_address: Option<String>,
		onion_expanded_key: Option<Zeroizing<[u8; 64]>>,
	) -> Handshake {
		Handshake::new(
			0,
			Hash::from_vec(&[]),
			P2PConfig::default(),
			onion_address,
			onion_expanded_key,
		)
	}

	fn test_hand(
		version: ProtocolVersion,
		sender_addr: PeerAddr,
		receiver_addr: PeerAddr,
		onion_sig_timestamp: Option<i64>,
		onion_sig: Option<[u8; ONION_PROOF_SIGNATURE_LEN]>,
	) -> Hand {
		Hand {
			version,
			capabilities: Capabilities::UNKNOWN,
			nonce: 42,
			genesis: Hash::from_vec(&[]),
			total_difficulty: Difficulty::min(),
			sender_addr,
			receiver_addr,
			user_agent: "test".to_string(),
			tx_fee_base: 0,
			onion_sig,
			onion_sig_timestamp,
		}
	}

	fn test_sender_addr(idx: usize) -> PeerAddr {
		PeerAddr::Ip(format!("198.51.100.{}:3414", idx + 1).parse().unwrap())
	}

	fn record_ip_receiver_addr_samples(
		receiver_hs: &Handshake,
		receiver_addr: SocketAddr,
		count: usize,
	) {
		for idx in 0..count {
			receiver_hs.record_ip_receiver_addr(receiver_addr, test_sender_addr(idx));
		}
	}

	#[test]
	fn read_hand_message_rejects_unknown_type_without_body_discard() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let mut header = ser::ser_vec(
			0,
			&MsgHeader::new(0, Type::Ping, 10),
			ProtocolVersion::local(),
		)
		.unwrap();
		header[2] = 255;

		match read_hand_message(&mut &header[..], ProtocolVersion::local(), 0) {
			Err(Error::BadMessage(message)) => {
				assert!(message.contains("while expecting Hand"), "{}", message);
			}
			Ok(_) => panic!("expected BadMessage, got decoded Hand"),
			Err(err) => panic!("expected BadMessage, got {:?}", err),
		}
	}

	#[test]
	fn resolve_ip_peer_addr_uses_transport_ip_and_advertised_port() {
		let advertised: SocketAddr = "198.51.100.25:3414".parse().unwrap();
		let transport_addr = PeerAddr::Ip("203.0.113.8:60000".parse().unwrap());

		assert_eq!(
			resolve_ip_peer_addr(&advertised, Ok(transport_addr)).unwrap(),
			PeerAddr::Ip("203.0.113.8:3414".parse().unwrap())
		);
	}

	#[test]
	fn resolve_ip_peer_addr_normalizes_ipv4_mapped_ipv6_transport_ip() {
		let advertised: SocketAddr = "198.51.100.25:3414".parse().unwrap();
		let transport_addr = PeerAddr::Ip("[::ffff:203.0.113.8]:60000".parse().unwrap());

		assert_eq!(
			resolve_ip_peer_addr(&advertised, Ok(transport_addr)).unwrap(),
			PeerAddr::Ip("203.0.113.8:3414".parse().unwrap())
		);
	}

	#[test]
	fn resolve_ip_peer_addr_does_not_normalize_ipv4_compatible_ipv6_transport_ip() {
		let advertised: SocketAddr = "198.51.100.25:3414".parse().unwrap();
		let transport_addr = PeerAddr::Ip("[::203.0.113.8]:60000".parse().unwrap());

		assert_eq!(
			resolve_ip_peer_addr(&advertised, Ok(transport_addr)).unwrap(),
			PeerAddr::Ip("[::203.0.113.8]:3414".parse().unwrap())
		);
	}

	#[test]
	fn resolve_ip_peer_addr_rejects_advertised_port_zero() {
		let advertised: SocketAddr = "198.51.100.25:0".parse().unwrap();
		let transport_addr = PeerAddr::Ip("203.0.113.8:60000".parse().unwrap());

		let err = resolve_ip_peer_addr(&advertised, Ok(transport_addr)).unwrap_err();

		match err {
			Error::BadHandshake(message) => {
				assert!(message.contains("port 0"));
			}
			err => panic!("expected BadHandshake, got {:?}", err),
		}
	}

	#[test]
	fn resolve_ip_peer_addr_rejects_ipv6_flowinfo_or_scope_id() {
		let advertised: SocketAddr = "198.51.100.25:3414".parse().unwrap();
		let transport_addrs = [
			SocketAddr::V6(std::net::SocketAddrV6::new(
				std::net::Ipv6Addr::LOCALHOST,
				60000,
				1,
				0,
			)),
			SocketAddr::V6(std::net::SocketAddrV6::new(
				std::net::Ipv6Addr::LOCALHOST,
				60000,
				0,
				2,
			)),
		];

		for transport_addr in transport_addrs {
			let err =
				resolve_ip_peer_addr(&advertised, Ok(PeerAddr::Ip(transport_addr))).unwrap_err();

			match err {
				Error::BadHandshake(message) => {
					assert!(message.contains("nonzero flowinfo or scope_id"));
				}
				err => panic!("expected BadHandshake, got {:?}", err),
			}
		}
	}

	#[test]
	fn resolve_ip_peer_addr_rejects_missing_transport_addr() {
		let advertised: SocketAddr = "198.51.100.25:3414".parse().unwrap();

		let err = resolve_ip_peer_addr(
			&advertised,
			Err(Error::Internal(
				"Requesting peer address for tor connection".into(),
			)),
		)
		.unwrap_err();

		match err {
			Error::ConnectionClose(message) => {
				assert!(message.contains("cannot verify advertised IP sender address"));
			}
			err => panic!("expected ConnectionClose, got {:?}", err),
		}
	}

	#[test]
	fn resolve_ip_peer_addr_rejects_non_ip_transport_addr() {
		let advertised: SocketAddr = "198.51.100.25:3414".parse().unwrap();
		let transport_addr = PeerAddr::Onion(onion_from_seed(&[21u8; 32]));

		let err = resolve_ip_peer_addr(&advertised, Ok(transport_addr)).unwrap_err();

		match err {
			Error::BadHandshake(message) => {
				assert!(message.contains("over non-IP transport"));
			}
			err => panic!("expected BadHandshake, got {:?}", err),
		}
	}

	#[test]
	fn peer_with_self_cache_records_ip_addr() {
		let receiver_hs = test_handshake(None, None);
		let sender_addr = PeerAddr::Ip("198.51.100.10:3414".parse().unwrap());
		let receiver_addr = PeerAddr::Ip("203.0.113.10:3414".parse().unwrap());
		let hand = test_hand(
			ProtocolVersion(4),
			sender_addr.clone(),
			receiver_addr,
			None,
			None,
		);

		receiver_hs.record_peer_with_self_addr(&hand, &sender_addr);

		assert_eq!(
			receiver_hs.addrs.read_recursive().front().cloned(),
			Some(sender_addr)
		);
	}

	#[test]
	fn peer_with_self_cache_does_not_record_unauthenticated_onion_addr() {
		let receiver_hs = test_handshake(None, None);
		let sender_addr = PeerAddr::Onion(onion_from_seed(&[22u8; 32]));
		let receiver_addr = PeerAddr::Ip("203.0.113.10:3414".parse().unwrap());
		let legacy_hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION - 1),
			sender_addr.clone(),
			receiver_addr.clone(),
			None,
			None,
		);
		let unsigned_v5_hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION),
			sender_addr.clone(),
			receiver_addr,
			None,
			None,
		);

		receiver_hs.record_peer_with_self_addr(&legacy_hand, &sender_addr);
		receiver_hs.record_peer_with_self_addr(&unsigned_v5_hand, &sender_addr);

		assert!(receiver_hs.addrs.read_recursive().is_empty());
	}

	#[test]
	fn inbound_hand_observation_records_ip_receiver_addr() {
		let receiver_hs = test_handshake(None, None);
		let sender_addr = PeerAddr::Ip("198.51.100.10:3414".parse().unwrap());
		let source_addr = sender_addr.clone();
		let receiver_addr = PeerAddr::Ip("203.0.113.10:3414".parse().unwrap());
		let hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION),
			sender_addr,
			receiver_addr.clone(),
			None,
			None,
		);

		receiver_hs.observe_inbound_receiver_addr(&hand, &source_addr);

		assert_eq!(
			receiver_hs
				.ip_receiver_addrs
				.read_recursive()
				.front()
				.cloned(),
			match receiver_addr {
				PeerAddr::Ip(receiver_addr) => Some((receiver_addr, source_addr)),
				PeerAddr::Onion(_) => None,
			}
		);
	}

	#[test]
	fn ip_receiver_addr_learns_recent_majority() {
		let receiver_hs = test_handshake(None, None);
		let sender_addr = PeerAddr::Ip("198.51.100.10:3414".parse().unwrap());
		let learned_addr: SocketAddr = "203.0.113.10:3414".parse().unwrap();
		let other_addr: SocketAddr = "203.0.113.11:3414".parse().unwrap();

		record_ip_receiver_addr_samples(
			&receiver_hs,
			learned_addr,
			IP_RECEIVER_ADDRS_MIN_AGREEMENT,
		);

		assert!(receiver_hs
			.validate_ip_receiver_addr(other_addr, &sender_addr)
			.is_err());
	}

	#[test]
	fn ip_receiver_addr_uses_strongest_majority() {
		let first_addr: SocketAddr = "203.0.113.10:3414".parse().unwrap();
		let majority_addr: SocketAddr = "203.0.113.11:3414".parse().unwrap();
		let mut samples = VecDeque::new();
		samples.push_back((first_addr, test_sender_addr(0)));
		samples.push_back((first_addr, test_sender_addr(1)));
		for idx in 0..IP_RECEIVER_ADDRS_MIN_AGREEMENT {
			samples.push_back((majority_addr, test_sender_addr(idx + 2)));
		}

		assert_eq!(
			learned_ip_receiver_addr_from_samples(&samples),
			Some(majority_addr)
		);
	}

	#[test]
	fn ip_receiver_addr_samples_ignore_duplicate_source() {
		let receiver_hs = test_handshake(None, None);
		let learned_addr: SocketAddr = "203.0.113.10:3414".parse().unwrap();
		let sender_addr = PeerAddr::Ip("198.51.100.10:3414".parse().unwrap());

		for _ in 0..IP_RECEIVER_ADDRS_MIN_AGREEMENT {
			receiver_hs.record_ip_receiver_addr(learned_addr, sender_addr.clone());
		}

		let samples = receiver_hs.ip_receiver_addrs.read_recursive();
		assert_eq!(samples.len(), 1);
		assert_eq!(learned_ip_receiver_addr_from_samples(&samples), None);
	}

	#[test]
	fn ip_receiver_addr_samples_ignore_same_public_ip_with_different_ports() {
		let receiver_hs = test_handshake(None, None);
		let learned_addr: SocketAddr = "203.0.113.10:3414".parse().unwrap();

		for port in 3414..3414 + IP_RECEIVER_ADDRS_MIN_AGREEMENT as u16 {
			let sender_addr = PeerAddr::Ip(format!("198.51.100.10:{}", port).parse().unwrap());
			receiver_hs.record_ip_receiver_addr(learned_addr, sender_addr);
		}

		let samples = receiver_hs.ip_receiver_addrs.read_recursive();
		assert_eq!(samples.len(), 1);
		assert_eq!(learned_ip_receiver_addr_from_samples(&samples), None);
	}

	#[test]
	fn ip_receiver_addr_match_requires_exact_port() {
		let receiver_hs = test_handshake(None, None);
		let sender_addr = PeerAddr::Ip("198.51.100.10:3414".parse().unwrap());
		let learned_addr: SocketAddr = "203.0.113.10:3414".parse().unwrap();
		let same_ip_other_port: SocketAddr = "203.0.113.10:3415".parse().unwrap();

		record_ip_receiver_addr_samples(
			&receiver_hs,
			learned_addr,
			IP_RECEIVER_ADDRS_MIN_AGREEMENT,
		);

		assert!(receiver_hs
			.validate_ip_receiver_addr(same_ip_other_port, &sender_addr)
			.is_err());
	}

	#[test]
	fn ip_receiver_addr_can_be_relearned() {
		let receiver_hs = test_handshake(None, None);
		let sender_addr = PeerAddr::Ip("198.51.100.10:3414".parse().unwrap());
		let old_addr: SocketAddr = "203.0.113.10:3414".parse().unwrap();
		let new_addr: SocketAddr = "203.0.113.11:3414".parse().unwrap();

		record_ip_receiver_addr_samples(&receiver_hs, old_addr, IP_RECEIVER_ADDRS_CAP);

		receiver_hs.record_ip_receiver_addr(new_addr, test_sender_addr(5));
		assert!(receiver_hs
			.validate_ip_receiver_addr(new_addr, &sender_addr)
			.is_err());
		receiver_hs.record_ip_receiver_addr(new_addr, test_sender_addr(6));
		receiver_hs
			.validate_ip_receiver_addr(new_addr, &sender_addr)
			.unwrap();
		receiver_hs.record_ip_receiver_addr(new_addr, test_sender_addr(7));
		receiver_hs
			.validate_ip_receiver_addr(new_addr, &sender_addr)
			.unwrap();
		receiver_hs.record_ip_receiver_addr(new_addr, test_sender_addr(8));
		receiver_hs
			.validate_ip_receiver_addr(new_addr, &sender_addr)
			.unwrap();

		assert!(receiver_hs
			.validate_ip_receiver_addr(old_addr, &sender_addr)
			.is_err());
	}

	#[test]
	fn tor_receiver_addr_must_match_configured_onion() {
		let receiver_seed = [17u8; 32];
		let wrong_receiver_seed = [18u8; 32];
		let receiver_onion = onion_from_seed(&receiver_seed);
		let wrong_receiver_onion = onion_from_seed(&wrong_receiver_seed);
		let sender_addr = PeerAddr::Ip("198.51.100.10:3414".parse().unwrap());
		let receiver_hs = test_handshake(Some(receiver_onion.clone()), None);

		receiver_hs
			.validate_tor_receiver_addr(&PeerAddr::Onion(receiver_onion), &sender_addr)
			.unwrap();

		assert!(receiver_hs
			.validate_tor_receiver_addr(&PeerAddr::Onion(wrong_receiver_onion), &sender_addr)
			.is_err());
		assert!(receiver_hs
			.validate_tor_receiver_addr(
				&PeerAddr::Ip("203.0.113.10:3414".parse().unwrap()),
				&sender_addr
			)
			.is_err());

		assert!(test_handshake(None, None)
			.validate_tor_receiver_addr(
				&PeerAddr::Onion(onion_from_seed(&receiver_seed)),
				&sender_addr
			)
			.is_err());
	}

	#[test]
	fn valid_onion_hand_proof_verifies() {
		let sender_seed = [1u8; 32];
		let receiver_seed = [2u8; 32];
		let sender_onion = onion_from_seed(&sender_seed);
		let receiver_onion = onion_from_seed(&receiver_seed);
		let sender_addr = PeerAddr::Onion(sender_onion.clone());
		let receiver_addr = PeerAddr::Onion(receiver_onion.clone());
		let sender_hs = test_handshake(
			Some(sender_onion),
			Some(expanded_key_from_seed(&sender_seed)),
		);
		let receiver_hs = test_handshake(Some(receiver_onion), None);
		let timestamp = Utc::now().timestamp();
		let sig = sender_hs
			.sign_onion_hand_proof(
				&sender_addr,
				&receiver_addr,
				42,
				timestamp,
				&Hash::from_vec(&[]),
			)
			.unwrap()
			.unwrap();
		let hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION),
			sender_addr,
			receiver_addr,
			Some(timestamp),
			Some(sig),
		);

		receiver_hs
			.verify_onion_hand_proof_with_stored_version(&hand, None)
			.unwrap();
	}

	#[test]
	fn invalid_onion_hand_proof_is_rejected() {
		let sender_seed = [3u8; 32];
		let receiver_seed = [4u8; 32];
		let sender_onion = onion_from_seed(&sender_seed);
		let receiver_onion = onion_from_seed(&receiver_seed);
		let sender_addr = PeerAddr::Onion(sender_onion.clone());
		let receiver_addr = PeerAddr::Onion(receiver_onion.clone());
		let sender_hs = test_handshake(
			Some(sender_onion),
			Some(expanded_key_from_seed(&sender_seed)),
		);
		let receiver_hs = test_handshake(Some(receiver_onion), None);
		let timestamp = Utc::now().timestamp();
		let mut sig = sender_hs
			.sign_onion_hand_proof(
				&sender_addr,
				&receiver_addr,
				42,
				timestamp,
				&Hash::from_vec(&[]),
			)
			.unwrap()
			.unwrap();
		sig[0] ^= 1;
		let hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION),
			sender_addr,
			receiver_addr,
			Some(timestamp),
			Some(sig),
		);

		assert!(receiver_hs
			.verify_onion_hand_proof_with_stored_version(&hand, None)
			.is_err());
	}

	#[test]
	fn onion_hand_proof_must_target_receiver_onion() {
		let sender_seed = [5u8; 32];
		let signed_receiver_seed = [6u8; 32];
		let actual_receiver_seed = [7u8; 32];
		let sender_onion = onion_from_seed(&sender_seed);
		let signed_receiver_onion = onion_from_seed(&signed_receiver_seed);
		let actual_receiver_onion = onion_from_seed(&actual_receiver_seed);
		let sender_addr = PeerAddr::Onion(sender_onion.clone());
		let signed_receiver_addr = PeerAddr::Onion(signed_receiver_onion);
		let sender_hs = test_handshake(
			Some(sender_onion),
			Some(expanded_key_from_seed(&sender_seed)),
		);
		let actual_receiver_hs = test_handshake(Some(actual_receiver_onion), None);
		let timestamp = Utc::now().timestamp();
		let sig = sender_hs
			.sign_onion_hand_proof(
				&sender_addr,
				&signed_receiver_addr,
				42,
				timestamp,
				&Hash::from_vec(&[]),
			)
			.unwrap()
			.unwrap();
		let hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION),
			sender_addr,
			signed_receiver_addr,
			Some(timestamp),
			Some(sig),
		);

		assert!(actual_receiver_hs
			.verify_onion_hand_proof_with_stored_version(&hand, None)
			.is_err());
	}

	#[test]
	fn onion_sender_can_prove_identity_to_ip_receiver() {
		let sender_seed = [16u8; 32];
		let sender_onion = onion_from_seed(&sender_seed);
		let sender_addr = PeerAddr::Onion(sender_onion.clone());
		let receiver_addr = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
		let sender_hs = test_handshake(
			Some(sender_onion),
			Some(expanded_key_from_seed(&sender_seed)),
		);
		let receiver_hs = test_handshake(None, None);
		let timestamp = Utc::now().timestamp();
		let sig = sender_hs
			.sign_onion_hand_proof(
				&sender_addr,
				&receiver_addr,
				42,
				timestamp,
				&Hash::from_vec(&[]),
			)
			.unwrap()
			.unwrap();
		let hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION),
			sender_addr,
			receiver_addr,
			Some(timestamp),
			Some(sig),
		);

		receiver_hs
			.verify_onion_hand_proof_with_stored_version(&hand, None)
			.unwrap();
	}

	#[test]
	fn stale_onion_hand_proof_timestamp_is_rejected() {
		let sender_seed = [10u8; 32];
		let receiver_seed = [11u8; 32];
		let sender_onion = onion_from_seed(&sender_seed);
		let receiver_onion = onion_from_seed(&receiver_seed);
		let sender_addr = PeerAddr::Onion(sender_onion.clone());
		let receiver_addr = PeerAddr::Onion(receiver_onion.clone());
		let sender_hs = test_handshake(
			Some(sender_onion),
			Some(expanded_key_from_seed(&sender_seed)),
		);
		let receiver_hs = test_handshake(Some(receiver_onion), None);
		let timestamp = Utc::now().timestamp() - ONION_HAND_PROOF_MAX_CLOCK_SKEW_SECS - 1;
		let sig = sender_hs
			.sign_onion_hand_proof(
				&sender_addr,
				&receiver_addr,
				42,
				timestamp,
				&Hash::from_vec(&[]),
			)
			.unwrap()
			.unwrap();
		let hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION),
			sender_addr,
			receiver_addr,
			Some(timestamp),
			Some(sig),
		);

		assert!(receiver_hs
			.verify_onion_hand_proof_with_stored_version(&hand, None)
			.is_err());
	}

	#[test]
	fn future_onion_hand_proof_timestamp_is_rejected() {
		let sender_seed = [12u8; 32];
		let receiver_seed = [13u8; 32];
		let sender_onion = onion_from_seed(&sender_seed);
		let receiver_onion = onion_from_seed(&receiver_seed);
		let sender_addr = PeerAddr::Onion(sender_onion.clone());
		let receiver_addr = PeerAddr::Onion(receiver_onion.clone());
		let sender_hs = test_handshake(
			Some(sender_onion),
			Some(expanded_key_from_seed(&sender_seed)),
		);
		let receiver_hs = test_handshake(Some(receiver_onion), None);
		let timestamp = Utc::now().timestamp() + ONION_HAND_PROOF_MAX_CLOCK_SKEW_SECS + 1;
		let sig = sender_hs
			.sign_onion_hand_proof(
				&sender_addr,
				&receiver_addr,
				42,
				timestamp,
				&Hash::from_vec(&[]),
			)
			.unwrap()
			.unwrap();
		let hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION),
			sender_addr,
			receiver_addr,
			Some(timestamp),
			Some(sig),
		);

		assert!(receiver_hs
			.verify_onion_hand_proof_with_stored_version(&hand, None)
			.is_err());
	}

	#[test]
	fn onion_hand_proof_without_timestamp_is_rejected() {
		let sender_seed = [14u8; 32];
		let receiver_seed = [15u8; 32];
		let sender_onion = onion_from_seed(&sender_seed);
		let receiver_onion = onion_from_seed(&receiver_seed);
		let sender_addr = PeerAddr::Onion(sender_onion.clone());
		let receiver_addr = PeerAddr::Onion(receiver_onion.clone());
		let sender_hs = test_handshake(
			Some(sender_onion),
			Some(expanded_key_from_seed(&sender_seed)),
		);
		let receiver_hs = test_handshake(Some(receiver_onion), None);
		let timestamp = Utc::now().timestamp();
		let sig = sender_hs
			.sign_onion_hand_proof(
				&sender_addr,
				&receiver_addr,
				42,
				timestamp,
				&Hash::from_vec(&[]),
			)
			.unwrap()
			.unwrap();
		let hand = test_hand(
			ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION),
			sender_addr,
			receiver_addr,
			None,
			Some(sig),
		);

		assert!(receiver_hs
			.verify_onion_hand_proof_with_stored_version(&hand, None)
			.is_err());
	}

	#[test]
	fn legacy_onion_hand_is_rejected_for_known_v5_peer() {
		let sender_seed = [8u8; 32];
		let receiver_seed = [9u8; 32];
		let sender_addr = PeerAddr::Onion(onion_from_seed(&sender_seed));
		let receiver_addr = PeerAddr::Onion(onion_from_seed(&receiver_seed));
		let receiver_hs = test_handshake(Some(onion_from_seed(&receiver_seed)), None);
		let hand = test_hand(ProtocolVersion(4), sender_addr, receiver_addr, None, None);

		assert!(receiver_hs
			.verify_onion_hand_proof_with_stored_version(
				&hand,
				Some(ProtocolVersion(ONION_PROOF_PROTOCOL_VERSION))
			)
			.is_err());
	}
}
