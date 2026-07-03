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

use crate::types::PeerAddr::Ip;
use crate::types::PeerAddr::Onion;
use mwc_crates::bitflags::bitflags;
use std::convert::{From, TryFrom};
use std::ffi::CString;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use mwc_crates::chrono::prelude::*;
use mwc_crates::serde::de::{Error as SerdeDeError, SeqAccess, Visitor};
use mwc_crates::serde::{self, Deserialize, Deserializer, Serialize};

use crate::msg::PeerAddrs;
use crate::tor::arti;
use mwc_chain::txhashset::BitmapChunk;
use mwc_chain::txhashset::Segmenter;
use mwc_chain::types::HEADERS_PER_BATCH;
use mwc_core::core;
use mwc_core::core::hash::Hash;
use mwc_core::core::{OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use mwc_core::global;
use mwc_core::global::{get_chain_type, ChainTypes};
use mwc_core::pow::Difficulty;
use mwc_core::ser::{self, ProtocolVersion, Readable, Reader, Writeable, Writer};
use mwc_core::ser_multiwrite;
use mwc_core::try_iter_map_vec;
use mwc_crates::enum_primitive::{
	enum_from_primitive, enum_from_primitive_impl, enum_from_primitive_impl_ty,
};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp;
use mwc_crates::secp::pedersen::RangeProof;
use mwc_crates::secp::Secp256k1;
use mwc_crates::zeroize::Zeroize;

/// Maximum number of block headers a peer should ever send
pub const MAX_BLOCK_HEADERS: u32 = HEADERS_PER_BATCH;

/// Maximum number of block bodies a peer should ever ask for and send
#[allow(dead_code)]
pub const MAX_BLOCK_BODIES: u32 = 16;

/// Maximum number of peer addresses a peer should ever send
pub const MAX_PEER_ADDRS: u32 = 256;

/// Maximum number of block header hashes to send as part of a locator
pub const MAX_LOCATORS: u32 = 20;

/// How long a banned peer should be banned for
pub const BAN_WINDOW: i64 = 10800;

/// The max inbound peer count
pub const PEER_MAX_INBOUND_COUNT: u32 = 128;

/// The max outbound peer count
const PEER_MAX_OUTBOUND_COUNT: u32 = 10;

/// The min preferred outbound peer count
const PEER_MIN_PREFERRED_OUTBOUND_COUNT_MAIN: u32 = 8;
const PEER_MIN_PREFERRED_OUTBOUND_COUNT_FLOO: u32 = 3;

/// During sync process we want to boost peers discovery.
const PEER_BOOST_OUTBOUND_COUNT_MAIN: u32 = 20;
/// Booost for floonet is much smaller, there are not many servers
const PEER_BOOST_OUTBOUND_COUNT_FLOO: u32 = 8;

/// The peer listener buffer count. Allows temporarily accepting more connections
/// than allowed by PEER_MAX_INBOUND_COUNT to encourage network bootstrapping.
pub(crate) const PEER_LISTENER_BUFFER_COUNT: u32 = 8;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("Secp error, {0}")]
	SecpError(secp::Error),
	#[error("p2p Serialization error, {0}")]
	Serialization(#[from] ser::Error),
	#[error("p2p Connection error, {0}")]
	Connection(#[from] io::Error),
	/// Header type does not match the expected message type
	#[error("p2p bad message: {0}")]
	BadMessage(String),
	#[error("p2p bad handshake: {0}")]
	BadHandshake(String),
	#[error("p2p unexpected message {0}")]
	UnexpectedMessage(String),
	#[error("p2p message Length error")]
	MsgLen,
	#[error("p2p banned")]
	Banned,
	#[error("p2p closed connection, {0}")]
	ConnectionClose(String),
	#[error("p2p timeout")]
	Timeout,
	#[error("p2p store error, {0}")]
	Store(#[from] mwc_store::Error),
	#[error("p2p chain error, {0}")]
	Chain(#[from] mwc_chain::Error),
	#[error("peer with self")]
	PeerWithSelf,
	#[error("p2p no dandelion relay")]
	NoDandelionRelay,
	#[error("p2p genesis mismatch: {us} vs peer {peer}")]
	GenesisMismatch { us: Hash, peer: Hash },
	#[error("p2p send error, {0}")]
	Send(String),
	#[error("peer not found")]
	PeerNotFound,
	#[error("peer not banned")]
	PeerNotBanned,
	#[error("peer exception, {0}")]
	PeerException(String),
	#[error("peer thread panicked: {0}")]
	PeerThreadPanic(String),
	#[error("p2p internal error: {0}")]
	Internal(String),
	#[error("ip address requested from Tor")]
	IpAddressRequestFromTor,
	#[error("p2p data overflow error: {0}")]
	DataOverflow(String),
	#[error("configuration error: {0}")]
	ConfigError(String),
	/// Tor Configuration Error
	#[error("Tor Config Error: {0}")]
	TorConfig(String),
	/// Tor Process error
	#[error("Tor Process Error: {0}")]
	TorProcess(String),
	/// Tor is not initialized
	#[error("Tor is not initialized")]
	TorNotInitialized,
	/// Tor is not initialized
	#[error("Tor is restarting")]
	TorRestarting,
	/// Tor Process error
	#[error("Onion Service Error: {0}")]
	TorOnionService(String),
	/// Tor Connect error
	#[error("Tor outbound connection error: {0}")]
	TorConnect(String),
	#[error("process is interrupted by request")]
	Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundConnectFailure {
	/// The connection failed because of local state or policy, not peer quality.
	Ignore,
	/// The connection reached a peer/network failure that can affect reputation.
	MarkDefunct,
}

impl Error {
	/// Classify an outbound connection failure for peer-store reputation.
	///
	/// This is intentionally conservative. Variants that can represent local
	/// state, local policy, transport availability, store/chain failures, or
	/// ambiguous connection closure are ignored so they do not poison peer
	/// reputation. Only clear protocol-level peer failures mark a peer defunct.
	pub fn outbound_connect_failure(&self) -> OutboundConnectFailure {
		match self {
			Error::BadHandshake(_)
			| Error::BadMessage(_)
			| Error::GenesisMismatch { .. }
			| Error::MsgLen
			| Error::UnexpectedMessage(_) => OutboundConnectFailure::MarkDefunct,
			_ => OutboundConnectFailure::Ignore,
		}
	}
}

#[derive(Debug, thiserror::Error)]
pub enum BroadcastError {
	#[error("p2p broadcast error, {0}")]
	P2p(#[from] Error),
	#[error("transaction error, {0}")]
	Transaction(#[from] core::transaction::Error),
}

impl From<secp::Error> for Error {
	fn from(err: secp::Error) -> Self {
		Error::SecpError(err)
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum PeerAddr {
	Ip(SocketAddr),
	Onion(String),
}

impl Writeable for PeerAddr {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			Ip(ip) => match ip {
				SocketAddr::V4(sav4) => {
					ser_multiwrite!(
						writer,
						[write_u8, 0],
						[write_fixed_bytes, &sav4.ip().octets().to_vec()],
						[write_u16, sav4.port()]
					);
				}
				SocketAddr::V6(sav6) => {
					if sav6.flowinfo() != 0 || sav6.scope_id() != 0 {
						return Err(ser::Error::CorruptedData(format!(
							"IPv6 peer address {} contains nonzero flowinfo or scope_id",
							sav6
						)));
					}
					writer.write_u8(1)?;
					for seg in &sav6.ip().segments() {
						writer.write_u16(*seg)?;
					}
					writer.write_u16(sav6.port())?;
				}
			},
			Onion(onion) => {
				if !arti::is_valid_onion_v3(onion.as_str()) {
					return Err(ser::Error::CorruptedData(format!(
						"Invalid onion address string {}",
						onion
					)));
				}
				writer.write_u8(2)?;
				writer.write_bytes(onion)?;
			}
		}
		Ok(())
	}
}

impl Readable for PeerAddr {
	fn read<R: Reader>(reader: &mut R) -> Result<PeerAddr, ser::Error> {
		match reader.read_u8()? {
			0 => {
				let ip = reader.read_fixed_bytes(4)?;
				let port = reader.read_u16()?;
				Ok(PeerAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
					Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
					port,
				))))
			}
			1 => {
				let ip = try_iter_map_vec!(0..8, |_| reader.read_u16());
				let ipv6 = Ipv6Addr::new(ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7]);
				let port = reader.read_u16()?;
				Ok(PeerAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
					ipv6, port, 0, 0,
				))))
			}
			2 => {
				let oa = reader.read_bytes_len_prefix()?;
				let onion_address =
					String::from_utf8(oa).map_err(|e| ser::Error::Utf8Conversion(e.to_string()))?;
				if !arti::is_valid_onion_v3(onion_address.as_str()) {
					return Err(ser::Error::CorruptedData(format!(
						"Invalid onion address string {}",
						onion_address
					)));
				}
				if CString::new(onion_address.as_str()).is_err() {
					return Err(ser::Error::CorruptedData(
						"onion_address contains NUL".into(),
					));
				}
				Ok(PeerAddr::Onion(onion_address))
			}
			tag => Err(ser::Error::CorruptedData(format!(
				"Invalid peer address type tag {}",
				tag
			))),
		}
	}
}

impl<'de> Visitor<'de> for PeerAddrs {
	type Value = PeerAddrs;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		formatter.write_str("an array of dns names or IP addresses")
	}

	fn visit_seq<M>(self, mut access: M) -> Result<Self::Value, M::Error>
	where
		M: SeqAccess<'de>,
	{
		let mut peers = Vec::with_capacity(access.size_hint().unwrap_or(0));

		while let Some(entry) = access.next_element::<&str>()? {
			// Config parsing must reject invalid peer entries instead of
			// treating every unresolved string as an onion address.
			peers.push(PeerAddr::parse_config_addr(entry).map_err(M::Error::custom)?);
		}
		Ok(PeerAddrs { peers })
	}
}

impl<'de> Deserialize<'de> for PeerAddrs {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		deserializer.deserialize_seq(PeerAddrs { peers: vec![] })
	}
}

impl std::hash::Hash for PeerAddr {
	/// If loopback address then we care about ip and port.
	/// If regular address then we only care about the ip and ignore the port.
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		match self {
			Ip(ip) => {
				if ip_addr_is_loopback(ip.ip()) {
					ip.hash(state);
				} else {
					ip.ip().hash(state);
				}
			}
			Onion(onion) => {
				onion.hash(state);
			}
		}
	}
}

impl PartialEq for PeerAddr {
	/// If loopback address then we care about ip and port.
	/// If regular address then we only care about the ip and ignore the port.
	fn eq(&self, other: &PeerAddr) -> bool {
		match self {
			Ip(ip) => match other {
				Ip(other_ip) => {
					if ip_addr_is_loopback(ip.ip()) {
						ip == other_ip
					} else {
						ip.ip() == other_ip.ip()
					}
				}
				_ => false,
			},
			Onion(onion) => match other {
				Onion(other_onion) => onion == other_onion,
				_ => false,
			},
		}
	}
}

impl Eq for PeerAddr {}

fn ip_addr_is_loopback(ip: IpAddr) -> bool {
	match ip {
		IpAddr::V4(ipv4) => ipv4.is_loopback(),
		IpAddr::V6(ipv6) => {
			ipv6.is_loopback()
				|| ipv6
					.to_ipv4_mapped()
					.map(|ipv4| ipv4.is_loopback())
					.unwrap_or(false)
		}
	}
}

fn ipv4_gossip_rejection_reason(ip: &Ipv4Addr) -> Option<&'static str> {
	let [a, b, c, _] = ip.octets();

	if ip.is_unspecified() {
		return Some("unspecified IPv4 address");
	}
	if a == 0 {
		return Some("IPv4 0.0.0.0/8 is reserved for this network");
	}
	if ip.is_loopback() {
		return Some("loopback IPv4 address");
	}
	if ip.is_private() {
		return Some("private IPv4 address");
	}
	if a == 100 && (64..=127).contains(&b) {
		return Some("carrier-grade NAT IPv4 address");
	}
	if ip.is_link_local() {
		return Some("link-local IPv4 address");
	}
	if ip.is_multicast() {
		return Some("multicast IPv4 address");
	}
	if ip.is_broadcast() {
		return Some("broadcast IPv4 address");
	}
	if (a, b, c) == (192, 0, 0) {
		return Some("IETF protocol assignment IPv4 address");
	}
	if (a, b, c) == (192, 88, 99) {
		return Some("deprecated 6to4 relay anycast IPv4 address");
	}
	if a == 198 && (b == 18 || b == 19) {
		return Some("network benchmarking IPv4 address");
	}
	if (a, b, c) == (192, 0, 2) || (a, b, c) == (198, 51, 100) || (a, b, c) == (203, 0, 113) {
		return Some("documentation IPv4 address");
	}
	if a >= 240 {
		return Some("reserved IPv4 address");
	}

	None
}

fn ipv6_gossip_rejection_reason(ip: &Ipv6Addr) -> Option<&'static str> {
	let segments = ip.segments();

	if ip.is_unspecified() {
		return Some("unspecified IPv6 address");
	}
	if ip.is_loopback() {
		return Some("loopback IPv6 address");
	}
	if ip.is_multicast() {
		return Some("multicast IPv6 address");
	}
	if (segments[0] & 0xfe00) == 0xfc00 {
		return Some("unique-local IPv6 address");
	}
	if (segments[0] & 0xffc0) == 0xfe80 {
		return Some("link-local IPv6 address");
	}
	if segments[0] == 0x2001 && segments[1] == 0x0db8 {
		return Some("documentation IPv6 address");
	}
	if segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0 {
		return Some("network benchmarking IPv6 address");
	}
	if segments[0] == 0x2001 && (segments[1] & 0xfe00) == 0 {
		return Some("IETF protocol assignment IPv6 address");
	}
	if segments[0] == 0
		&& segments[1] == 0
		&& segments[2] == 0
		&& segments[3] == 0
		&& segments[4] == 0
		&& segments[5] == 0xffff
	{
		return Some("IPv4-mapped IPv6 address");
	}
	if segments[0] == 0x2002 {
		return Some("6to4 IPv6 address");
	}
	if segments[0] == 0x3fff && (segments[1] & 0xf000) == 0 {
		return Some("documentation IPv6 address");
	}
	if (segments[0] & 0xe000) != 0x2000 {
		return Some("IPv6 address outside global unicast 2000::/3");
	}

	None
}

impl std::fmt::Display for PeerAddr {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Ip(ip) => write!(f, "{}", ip),
			Onion(onion) => {
				let onion_address = &onion.to_string();
				write!(f, "tor://{}", onion_address)
			}
		}
	}
}

impl PeerAddr {
	/// Convenient way of constructing a new peer_addr from an ip_addr
	/// defaults to port 3414 on mainnet and 13414 on floonet.
	pub fn from_ip(context_id: u32, addr: IpAddr) -> PeerAddr {
		let port = if global::is_floonet(context_id) {
			13414
		} else {
			3414
		};
		PeerAddr::Ip(SocketAddr::new(addr, port))
	}

	pub fn from_str(addr: &str) -> Result<PeerAddr, String> {
		PeerAddr::parse_config_addr(addr)
	}

	fn parse_config_addr(addr: &str) -> Result<PeerAddr, String> {
		if let Ok(socket_addr) = SocketAddr::from_str(addr) {
			return Ok(PeerAddr::Ip(socket_addr));
		}
		if arti::is_valid_onion_v3(addr) {
			return Ok(PeerAddr::Onion(addr.to_string()));
		}
		if config_addr_onion_host(addr).is_some() {
			return Err(format!("invalid onion v3 address '{}'", addr));
		}

		let mut socket_addrs = addr
			.to_socket_addrs()
			.map_err(|e| format!("invalid peer address '{}': {}", addr, e))?;
		match socket_addrs.next() {
			Some(socket_addr) => Ok(PeerAddr::Ip(socket_addr)),
			None => Err(format!(
				"invalid peer address '{}': DNS lookup returned no addresses",
				addr
			)),
		}
	}

	/// Returns true only when the address variant and all address fields match.
	/// This intentionally does not use PeerAddr equality, which ignores ports
	/// for non-loopback IP addresses.
	pub fn matches_exactly(&self, other: &PeerAddr) -> bool {
		match (self, other) {
			(Ip(ip), Ip(other_ip)) => ip == other_ip,
			(Onion(onion), Onion(other_onion)) => onion == other_onion,
			_ => false,
		}
	}

	/// If the ip is loopback then our key is the full socket address
	/// (mainly for local usernet testing).
	/// Otherwise we only care about the ip (we disallow multiple peers on the same ip address).
	/// The address family is not included in this key. For now this is acceptable
	/// because callers are expected to use normalized IP addresses or valid v3
	/// onion addresses, so IP/onion key collisions are not expected. Onion
	/// address correctness will be tightened separately.
	pub fn as_key(&self) -> String {
		match self {
			Ip(ip) => {
				if ip_addr_is_loopback(ip.ip()) {
					format!("{}", ip)
				} else {
					format!("{}", ip.ip())
				}
			}
			Onion(onion) => format!("{}", onion),
		}
	}

	pub fn tor_address(&self) -> Result<String, Error> {
		match self {
			Ip(_ip) => Err(Error::Internal(
				"requested TOR pub key from IP address".to_string(),
			)),
			Onion(onion) => {
				let onion_address = if onion.ends_with(".onion") {
					onion.clone()
				} else {
					format!("{}.onion", onion)
				};
				let canonical = arti::canonical_onion_v3(&onion_address).ok_or_else(|| {
					Error::Internal(format!("invalid onion v3 address {}", onion))
				})?;
				Ok(canonical
					.strip_suffix(".onion")
					.unwrap_or(canonical.as_str())
					.to_string())
			}
		}
	}

	pub fn is_loopback(&self) -> bool {
		match self {
			Ip(ip) => ip_addr_is_loopback(ip.ip()),
			Onion(_) => {
				false // we can't detect self onion address here in any case
			}
		}
	}

	/// Returns why an address should be rejected when it arrives from untrusted
	/// peer gossip. This intentionally applies only to gossip candidates; local
	/// configuration can still opt into private or otherwise special addresses.
	pub fn gossip_rejection_reason(&self) -> Option<&'static str> {
		match self {
			Ip(socket) => {
				if socket.port() == 0 {
					return Some("port 0 is not connectable");
				}
				match socket.ip() {
					IpAddr::V4(ip) => ipv4_gossip_rejection_reason(&ip),
					IpAddr::V6(ip) => ipv6_gossip_rejection_reason(&ip),
				}
			}
			Onion(onion) => {
				if arti::is_valid_onion_v3(onion.as_str()) {
					None
				} else {
					Some("invalid onion v3 address")
				}
			}
		}
	}

	pub fn is_valid_gossip_candidate(&self) -> bool {
		self.gossip_rejection_reason().is_none()
	}
}

fn config_addr_onion_host(addr: &str) -> Option<&str> {
	let host = match addr.rsplit_once(':') {
		Some((host, _port)) => host,
		None => addr,
	};
	let host = host.strip_suffix('.').unwrap_or(host);
	if host
		.as_bytes()
		.get(host.len().saturating_sub(".onion".len())..)
		.map(|suffix| suffix.eq_ignore_ascii_case(b".onion"))
		.unwrap_or(false)
	{
		Some(host)
	} else {
		None
	}
}

/// Type for Tor Configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(crate = "serde")]
pub struct TorConfig {
	/// Whether to start tor listener on listener startup (default true)
	pub tor_enabled: Option<bool>,
	/// alternative webtunnel bridge. In not specified, the community bridges might be used
	pub webtunnel_bridge: Option<String>,
}

impl Default for TorConfig {
	fn default() -> TorConfig {
		TorConfig {
			tor_enabled: None,
			webtunnel_bridge: None,
		}
	}
}

impl TorConfig {
	pub fn no_tor_config() -> Self {
		TorConfig {
			tor_enabled: Some(false),
			webtunnel_bridge: None,
		}
	}

	pub fn arti_tor_config() -> Self {
		TorConfig {
			tor_enabled: Some(true),
			webtunnel_bridge: None,
		}
	}
	/// If tor service is enabled. Default: true
	pub fn is_tor_enabled(&self) -> bool {
		self.tor_enabled.unwrap_or(true)
	}

	pub fn need_start_arti(&self) -> bool {
		self.is_tor_enabled()
	}
}

/// Configuration for the peer-to-peer server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(crate = "serde")]
pub struct P2PConfig {
	pub port: u16,

	/// Method used to get the list of seed nodes for initial bootstrap.
	#[serde(default)]
	pub seeding_type: Seeding,

	/// The list of seed nodes, if using Seeding as a seed type
	pub seeds: Option<PeerAddrs>,

	pub peers_allow: Option<PeerAddrs>,

	pub peers_deny: Option<PeerAddrs>,

	/// The list of preferred peers that we will try to connect to
	pub peers_preferred: Option<PeerAddrs>,

	pub ban_window: Option<i64>,

	pub peer_max_inbound_count: Option<u32>,

	pub peer_max_outbound_count: Option<u32>,

	pub peer_min_preferred_outbound_count: Option<u32>,

	pub peer_listener_buffer_count: Option<u32>,

	pub dandelion_peer: Option<PeerAddr>,

	/// Expanded key (for seed nodes). The key to generate the onion service
	pub onion_expanded_key: Option<String>,
}

impl Drop for P2PConfig {
	fn drop(&mut self) {
		if let Some(onion_expanded_key) = &mut self.onion_expanded_key {
			onion_expanded_key.zeroize();
		}
	}
}

/// Default address for peer-to-peer connections.
impl Default for P2PConfig {
	fn default() -> P2PConfig {
		P2PConfig {
			port: 3414,
			seeding_type: Seeding::default(),
			seeds: None,
			peers_allow: None,
			peers_deny: None,
			peers_preferred: None,
			ban_window: None,
			peer_max_inbound_count: None,
			peer_max_outbound_count: None,
			peer_min_preferred_outbound_count: None,
			peer_listener_buffer_count: None,
			dandelion_peer: None,
			onion_expanded_key: None,
		}
	}
}

/// Note certain fields are options just so they don't have to be
/// included in mwc-server.toml, but we don't want them to ever return none
impl P2PConfig {
	pub fn clone_without_secrets(&self) -> P2PConfig {
		P2PConfig {
			port: self.port,
			seeding_type: self.seeding_type,
			seeds: self.seeds.clone(),
			peers_allow: self.peers_allow.clone(),
			peers_deny: self.peers_deny.clone(),
			peers_preferred: self.peers_preferred.clone(),
			ban_window: self.ban_window,
			peer_max_inbound_count: self.peer_max_inbound_count,
			peer_max_outbound_count: self.peer_max_outbound_count,
			peer_min_preferred_outbound_count: self.peer_min_preferred_outbound_count,
			peer_listener_buffer_count: self.peer_listener_buffer_count,
			dandelion_peer: self.dandelion_peer.clone(),
			onion_expanded_key: None,
		}
	}

	/// return maximum outbound peer connections count
	pub fn peer_max_outbound_count(&self, peers_sync_mode: bool) -> u32 {
		if peers_sync_mode {
			PEER_BOOST_OUTBOUND_COUNT_MAIN + PEER_MIN_PREFERRED_OUTBOUND_COUNT_MAIN
		} else {
			match self.peer_max_outbound_count {
				Some(n) => n,
				None => PEER_MAX_OUTBOUND_COUNT,
			}
		}
	}

	/// return minimum preferred outbound peer count
	pub fn peer_min_preferred_outbound_count(&self, context_id: u32, peers_sync_mode: bool) -> u32 {
		if peers_sync_mode {
			match get_chain_type(context_id) {
				ChainTypes::Mainnet => PEER_BOOST_OUTBOUND_COUNT_MAIN,
				_ => PEER_BOOST_OUTBOUND_COUNT_FLOO,
			}
		} else {
			match self.peer_min_preferred_outbound_count {
				Some(n) => n,
				None => match get_chain_type(context_id) {
					ChainTypes::Mainnet => PEER_MIN_PREFERRED_OUTBOUND_COUNT_MAIN,
					_ => PEER_MIN_PREFERRED_OUTBOUND_COUNT_FLOO,
				},
			}
		}
	}
}

/// Type of seeding the server will use to find other peers on the network.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(crate = "serde")]
pub enum Seeding {
	/// No seeding, mostly for tests that programmatically connect
	None,
	/// A list of seeds provided to the server (can be addresses or DNS names)
	List,
	/// Automatically get a list of seeds from multiple DNS
	DNSSeed,
}

impl Default for Seeding {
	fn default() -> Seeding {
		Seeding::DNSSeed
	}
}

bitflags! {
	/// Options for what type of interaction a peer supports
	#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
	#[serde(crate = "serde")]
	pub struct Capabilities: u32 {
		/// We don't know (yet) what the peer can do.
		const UNKNOWN = 0b0000_0000;
		/// Can provide full history of headers back to genesis
		/// (for at least one arbitrary fork).
		const HEADER_HIST = 0b0000_0001;
		/// Can provide recent txhashset archive for fast sync.
		const TXHASHSET_HIST = 0b0000_0010;
		/// Can provide a list of healthy peers
		const PEER_LIST = 0b0000_0100;
		/// Can broadcast and request txs by kernel hash.
		const TX_KERNEL_HASH = 0b0000_1000;
		/// Can send/receive tor addresses
		const TOR_ADDRESS = 0b0001_0000;
		/// Can provide PIBD segments during initial byte download (fast sync).
		const PIBD_HIST = 0b0010_0000;
		/// Can provide historical blocks for archival sync.
		const BLOCK_HIST = 0b0100_0000;
		/// Can provide PIBD Headers Hashes
		const HEADERS_HASH = 0b1000_0000;
	}
}

/// Default capabilities.
impl Capabilities {
	/// Capability instance to match node features
	pub fn new(tor: bool, archive_mode: bool) -> Self {
		let mut res = Capabilities::HEADER_HIST
			| Capabilities::TXHASHSET_HIST
			| Capabilities::PEER_LIST
			| Capabilities::TX_KERNEL_HASH
			| Capabilities::PIBD_HIST
			| Capabilities::HEADERS_HASH;
		if tor {
			res |= Capabilities::TOR_ADDRESS;
		}
		if archive_mode {
			res |= Capabilities::BLOCK_HIST;
		}
		res
	}
}

// Types of connection
enum_from_primitive! {
	#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
	#[serde(crate = "serde")]
	pub enum Direction {
		Inbound = 0,
		Outbound = 1,
		InboundTor = 2,
		OutboundTor = 3,
	}
}

// Ban reason
enum_from_primitive! {
	#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
	#[serde(crate = "serde")]
	pub enum ReasonForBan {
		None = 0,
		BadBlock = 1,
		BadCompactBlock = 2,
		BadBlockHeader = 3,
		BadTxHashSet = 4,
		ManualBan = 5,
		FraudHeight = 6,
		BadHandshake = 7,
		HeadersHashFailure = 8,
		PibdFailure = 9,
		BadRequest = 10,
	}
}

#[derive(Clone, Debug)]
pub struct PeerAdvertised {
	pub addr: PeerAddr,
	source: PeerAddr,
	last_advertised_ts: i64,
	last_checked_ts: i64,
	chunk_size: usize,
}

impl PeerAdvertised {
	pub fn new(source: PeerAddr, addr: PeerAddr, chunk_size: usize, now: i64) -> Self {
		PeerAdvertised {
			addr,
			source,
			last_advertised_ts: now,
			last_checked_ts: -1,
			chunk_size,
		}
	}

	/// Rank of that peer. Bigger is better
	pub fn calc_rank(&self) -> i64 {
		if self.last_checked_ts <= 0 {
			let chunk_size = i64::try_from(self.chunk_size)
				.ok()
				.filter(|chunk_size| *chunk_size > 0)
				.unwrap_or(i64::MAX);
			return self.last_advertised_ts / chunk_size;
		}
		-self.last_checked_ts
	}

	pub fn get_last_advertised_ts(&self) -> i64 {
		self.last_advertised_ts
	}

	pub fn source(&self) -> &PeerAddr {
		&self.source
	}

	pub fn set_checked(&mut self, now: i64) {
		self.last_checked_ts = now;
	}

	pub fn reset_checked(&mut self) {
		self.last_checked_ts = -1;
	}

	pub fn set_advertised(&mut self, chunk_size: usize, now: i64) {
		self.last_advertised_ts = now;
		self.chunk_size = std::cmp::min(chunk_size, self.chunk_size);
	}
}

#[derive(Clone, Debug)]
pub struct PeerLiveInfo {
	pub total_difficulty: Difficulty,
	pub max_total_difficulty: Difficulty,
	pub height: u64,
	pub last_seen: DateTime<Utc>,
	pub stuck_detector: Instant,
	pub first_seen: DateTime<Utc>,
}

/// General information about a connected peer that's useful to other modules.
#[derive(Clone, Debug)]
pub struct PeerInfo {
	pub capabilities: Capabilities,
	pub user_agent: String,
	pub version: ProtocolVersion,
	pub addr: PeerAddr,
	pub direction: Direction,
	pub live_info: Arc<RwLock<PeerLiveInfo>>,
	pub tx_base_fee: u64,
}

impl PeerLiveInfo {
	pub fn new(difficulty: Difficulty) -> PeerLiveInfo {
		PeerLiveInfo {
			total_difficulty: difficulty,
			max_total_difficulty: difficulty,
			height: 0,
			first_seen: Utc::now(),
			last_seen: Utc::now(),
			stuck_detector: Instant::now(),
		}
	}
}

impl PeerInfo {
	/// The current total_difficulty of the peer.
	pub fn total_difficulty(&self) -> Difficulty {
		self.live_info.read_recursive().total_difficulty
	}

	pub fn is_outbound(&self) -> bool {
		self.direction == Direction::Outbound || self.direction == Direction::OutboundTor
	}

	pub fn is_inbound(&self) -> bool {
		self.direction == Direction::Inbound || self.direction == Direction::InboundTor
	}

	/// The current height of the peer.
	pub fn height(&self) -> u64 {
		self.live_info.read_recursive().height
	}

	/// Time of last_seen for this peer (via ping/pong).
	pub fn last_seen(&self) -> DateTime<Utc> {
		self.live_info.read_recursive().last_seen
	}

	/// Time of first_seen for this peer.
	pub fn first_seen(&self) -> DateTime<Utc> {
		self.live_info.read_recursive().first_seen
	}

	/// Update the total_difficulty, height and last_seen of the peer.
	/// Takes a write lock on the live_info.
	pub fn update(&self, height: u64, total_difficulty: Difficulty) {
		let now = Utc::now();
		let mut live_info = self.live_info.write();
		if total_difficulty > live_info.max_total_difficulty {
			live_info.max_total_difficulty = total_difficulty;
			live_info.stuck_detector = Instant::now();
		}
		live_info.height = height;
		live_info.total_difficulty = total_difficulty;
		live_info.last_seen = now
	}
}

/// This is needed for legacy purposes
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct PeerInfoDisplayLegacy {
	pub capabilities: Capabilities,
	pub user_agent: String,
	pub version: ProtocolVersion,
	pub addr: String,
	pub direction: Direction,
	pub total_difficulty: Difficulty,
	pub height: u64,
	pub last_seen: u32, // last seen seconds ago
}

/// Flatten out a PeerInfo and nested PeerLiveInfo (taking a read lock on it)
/// so we can serialize/deserialize the data for the API and the TUI.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct PeerInfoDisplay {
	pub capabilities: Capabilities,
	pub user_agent: String,
	pub version: ProtocolVersion,
	pub addr: PeerAddr,
	pub direction: Direction,
	pub total_difficulty: Difficulty,
	pub height: u64,
	pub last_seen: u32, // last seen seconds ago
}

impl From<PeerInfo> for PeerInfoDisplay {
	fn from(info: PeerInfo) -> PeerInfoDisplay {
		let peer_last_seen = info.live_info.read_recursive().last_seen;
		let last_seen = last_seen_seconds_ago(peer_last_seen);
		PeerInfoDisplay {
			capabilities: info.capabilities,
			user_agent: info.user_agent.clone(),
			version: info.version,
			addr: info.clone().addr,
			direction: info.direction,
			total_difficulty: info.total_difficulty(),
			height: info.height(),
			last_seen,
		}
	}
}

fn last_seen_seconds_ago(peer_last_seen: DateTime<Utc>) -> u32 {
	let seconds = (Utc::now() - peer_last_seen).num_seconds();
	seconds.clamp(0, u32::MAX as i64) as u32
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct ProcessStatus {
	/// How long this process is running
	pub process_running_time: u64,
	/// How long arti is running
	pub tor_online_time: u64,
	/// This host CPU usage, percentage
	pub host_cpu_usage: f64,
	/// This host memory usage, percentage
	pub host_ram_usage: f64,
	/// This host swap usage, percantage
	pub host_swap_usage: f64,
}

/// Bridge between the networking layer and the rest of the system. Handles the
/// forwarding or querying of blocks and transactions from the network among
/// other things.
pub trait ChainAdapter: Sync + Send {
	/// Current total difficulty on our chain
	fn total_difficulty(&self) -> Result<Difficulty, mwc_chain::Error>;

	/// Current total height
	fn total_height(&self) -> Result<u64, mwc_chain::Error>;

	/// A valid transaction has been received from one of our peers
	fn transaction_received(
		&self,
		secp: &mut Secp256k1,
		tx: core::Transaction,
		stem: bool,
	) -> Result<bool, mwc_chain::Error>;

	fn get_transaction(
		&self,
		kernel_hash: Hash,
	) -> Result<Option<core::Transaction>, mwc_chain::Error>;

	fn tx_kernel_received(
		&self,
		kernel_hash: Hash,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error>;

	/// A block has been received from one of our peers. Returns true if the
	/// block could be handled properly and is not deemed defective by the
	/// chain. Returning false means the block will never be valid and
	/// may result in the peer being banned.
	fn block_received(
		&self,
		secp: &mut Secp256k1,
		b: core::Block,
		peer_info: &PeerInfo,
		opts: mwc_chain::Options,
	) -> Result<bool, mwc_chain::Error>;

	fn compact_block_received(
		&self,
		secp: &mut Secp256k1,
		cb: core::CompactBlock,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error>;

	fn header_received(
		&self,
		bh: core::BlockHeader,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error>;

	/// A set of block header has been received, typically in response to a
	/// block
	/// header request.
	fn headers_received(
		&self,
		bh: &[core::BlockHeader],
		remaining: u64,
		peer_info: &PeerInfo,
	) -> Result<(), mwc_chain::Error>;

	/// Get header locator
	fn header_locator(&self) -> Result<Vec<Hash>, mwc_chain::Error>;

	/// Finds a list of block headers based on the provided locator. Tries to
	/// identify the common chain and gets the headers that follow it
	/// immediately.
	fn locate_headers(&self, locator: &[Hash]) -> Result<Vec<core::BlockHeader>, mwc_chain::Error>;

	/// Gets a full block by its hash.
	/// Converts block to v2 compatibility if necessary (based on peer protocol version).
	fn get_block(
		&self,
		secp: &Secp256k1,
		h: Hash,
		peer_info: &PeerInfo,
	) -> Result<Option<core::Block>, mwc_chain::Error>;

	/// Header of the txhashset archive currently being served to peers.
	fn txhashset_archive_header(&self) -> Result<core::BlockHeader, mwc_chain::Error>;

	/// Get the Grin specific tmp dir
	fn get_tmp_dir(&self) -> Result<PathBuf, mwc_chain::Error>;

	/// Get a tmp file path in above specific tmp dir (create tmp dir if not exist)
	/// Delete file if tmp file already exists
	fn get_tmpfile_pathname(&self, tmpfile_name: String) -> Result<PathBuf, mwc_chain::Error>;

	/// For MWC handshake we need to have a segmenter ready with output bitmap ready and commited.
	fn prepare_segmenter(&self) -> Result<Segmenter, mwc_chain::Error>;

	fn get_kernel_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<TxKernel>, mwc_chain::Error>;

	fn get_bitmap_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<BitmapChunk>, mwc_chain::Error>;

	fn get_output_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<OutputIdentifier>, mwc_chain::Error>;

	fn get_rangeproof_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<RangeProof>, mwc_chain::Error>;

	fn recieve_pibd_status(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
		output_bitmap_root: Hash,
	) -> Result<(), mwc_chain::Error>;

	fn recieve_another_archive_header(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
	) -> Result<(), mwc_chain::Error>;

	fn receive_headers_hash_response(
		&self,
		peer: &PeerAddr,
		archive_height: u64,
		headers_hash_root: Hash,
	) -> Result<(), mwc_chain::Error>;

	fn get_header_hashes_segment(
		&self,
		header_hashes_root: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<Hash>, mwc_chain::Error>;

	fn receive_header_hashes_segment(
		&self,
		peer: &PeerAddr,
		header_hashes_root: Hash,
		segment: Segment<Hash>,
	) -> Result<(), mwc_chain::Error>;

	fn receive_bitmap_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<BitmapChunk>,
	) -> Result<(), mwc_chain::Error>;

	fn receive_output_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<OutputIdentifier>,
	) -> Result<(), mwc_chain::Error>;

	fn receive_rangeproof_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<RangeProof>,
	) -> Result<(), mwc_chain::Error>;

	fn receive_kernel_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<TxKernel>,
	) -> Result<(), mwc_chain::Error>;

	/// Heard total_difficulty from a connected peer (via ping/pong).
	fn peer_difficulty(&self, peer: &PeerAddr, difficulty: Difficulty, height: u64);
}

/// Additional methods required by the protocol that don't need to be
/// externally implemented.
pub trait NetAdapter: ChainAdapter {
	/// Find good peers we know with the provided capability and return their
	/// addresses.
	fn find_peer_addrs(&self, capab: Capabilities) -> Result<Vec<PeerAddr>, Error>;

	/// A list of peers has been received from one of our peers.
	fn peer_addrs_received(&self, _: &PeerAddr, _: Vec<PeerAddr>);

	/// Is this peer currently banned?
	fn is_banned(&self, addr: &PeerAddr) -> Result<bool, Error>;

	/// Last stored protocol version for this peer, if we have historical data.
	fn peer_version(&self, addr: &PeerAddr) -> Result<Option<ProtocolVersion>, Error>;

	/// Ban peer
	fn ban_peer(
		&self,
		addr: &PeerAddr,
		ban_reason: ReasonForBan,
		message: &str,
	) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
pub struct AttachmentMeta {
	pub size: usize,
	pub hash: Hash,
	pub height: u64,
	pub start_time: DateTime<Utc>,
	pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct AttachmentUpdate {
	pub read: usize,
	pub left: usize,
	pub meta: Arc<AttachmentMeta>,
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::chrono::Duration;
	use std::time::Duration as StdDuration;

	#[test]
	fn outbound_connect_failure_ignores_local_and_ambiguous_failures() {
		for err in [
			Error::TorRestarting,
			Error::TorNotInitialized,
			Error::Interrupted,
			Error::PeerWithSelf,
			Error::Connection(std::io::Error::new(
				std::io::ErrorKind::TimedOut,
				"connect timeout",
			)),
			Error::ConnectionClose("node is stopping".into()),
			Error::ConnectionClose("connection closed by peer".into()),
			Error::Timeout,
			Error::TorConnect("Unable connect to peer".into()),
			Error::Internal("invalid onion v3 address abc".into()),
			Error::Serialization(ser::Error::CorruptedData(
				"Invalid onion address string abc".into(),
			)),
		] {
			assert_eq!(
				err.outbound_connect_failure(),
				OutboundConnectFailure::Ignore,
				"{:?}",
				err
			);
		}
	}

	#[test]
	fn outbound_connect_failure_marks_peer_failures_defunct() {
		for err in [
			Error::BadHandshake("invalid handshake".into()),
			Error::BadMessage("invalid message".into()),
			Error::MsgLen,
			Error::UnexpectedMessage("unexpected message".into()),
		] {
			assert_eq!(
				err.outbound_connect_failure(),
				OutboundConnectFailure::MarkDefunct,
				"{:?}",
				err
			);
		}
	}

	#[test]
	fn peer_addr_write_rejects_ipv6_flowinfo_or_scope_id() {
		for addr in [
			SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3414, 1, 0),
			SocketAddrV6::new(Ipv6Addr::LOCALHOST, 3414, 0, 1),
		] {
			match ser::ser_vec(
				0,
				&PeerAddr::Ip(SocketAddr::V6(addr)),
				ProtocolVersion::local(),
			) {
				Err(ser::Error::CorruptedData(msg)) => {
					assert!(msg.contains("nonzero flowinfo or scope_id"));
				}
				other => panic!("expected corrupted data error, got {:?}", other),
			}
		}
	}

	#[test]
	fn gossip_rejection_reason_documents_non_gossipable_ipv4() {
		for (addr, reason) in [
			(
				SocketAddr::from(([8, 8, 8, 8], 0)),
				"port 0 is not connectable",
			),
			(
				SocketAddr::from(([0, 1, 2, 3], 3414)),
				"IPv4 0.0.0.0/8 is reserved for this network",
			),
			(
				SocketAddr::from(([10, 1, 2, 3], 3414)),
				"private IPv4 address",
			),
			(
				SocketAddr::from(([100, 64, 0, 1], 3414)),
				"carrier-grade NAT IPv4 address",
			),
			(
				SocketAddr::from(([192, 0, 0, 8], 3414)),
				"IETF protocol assignment IPv4 address",
			),
			(
				SocketAddr::from(([192, 0, 0, 9], 3414)),
				"IETF protocol assignment IPv4 address",
			),
			(
				SocketAddr::from(([192, 0, 0, 10], 3414)),
				"IETF protocol assignment IPv4 address",
			),
			(
				SocketAddr::from(([192, 88, 99, 1], 3414)),
				"deprecated 6to4 relay anycast IPv4 address",
			),
			(
				SocketAddr::from(([198, 18, 0, 1], 3414)),
				"network benchmarking IPv4 address",
			),
			(
				SocketAddr::from(([192, 0, 2, 1], 3414)),
				"documentation IPv4 address",
			),
			(
				SocketAddr::from(([240, 0, 0, 1], 3414)),
				"reserved IPv4 address",
			),
		] {
			assert_eq!(PeerAddr::Ip(addr).gossip_rejection_reason(), Some(reason));
		}
		assert_eq!(
			PeerAddr::Ip(SocketAddr::from(([8, 8, 8, 8], 3414))).gossip_rejection_reason(),
			None
		);
	}

	#[test]
	fn gossip_rejection_reason_documents_non_gossipable_ipv6() {
		for (addr, reason) in [
			(
				SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 3414),
				"loopback IPv6 address",
			),
			(
				SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)), 3414),
				"unique-local IPv6 address",
			),
			(
				SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 3414),
				"link-local IPv6 address",
			),
			(
				SocketAddr::new(
					IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
					3414,
				),
				"documentation IPv6 address",
			),
			(
				SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1)), 3414),
				"IETF protocol assignment IPv6 address",
			),
			(
				SocketAddr::new(
					IpAddr::V6(Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 1)),
					3414,
				),
				"IETF protocol assignment IPv6 address",
			),
			(
				SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 1)), 3414),
				"6to4 IPv6 address",
			),
			(
				SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 1)), 3414),
				"documentation IPv6 address",
			),
		] {
			assert_eq!(PeerAddr::Ip(addr).gossip_rejection_reason(), Some(reason));
		}
		assert_eq!(
			PeerAddr::Ip(SocketAddr::new(
				IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
				3414
			))
			.gossip_rejection_reason(),
			None
		);
	}

	#[test]
	fn last_seen_seconds_ago_clamps_future_times_to_zero() {
		let peer_last_seen = Utc::now() + Duration::seconds(60);

		assert_eq!(last_seen_seconds_ago(peer_last_seen), 0);
	}

	#[test]
	fn peer_advertised_calc_rank_handles_invalid_chunk_size() {
		let source = PeerAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 3414)));
		let addr = PeerAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 3415)));

		assert_eq!(
			PeerAdvertised::new(source.clone(), addr.clone(), 10, 100).calc_rank(),
			10
		);
		assert_eq!(
			PeerAdvertised::new(source.clone(), addr.clone(), 0, 100).calc_rank(),
			0
		);
		assert_eq!(
			PeerAdvertised::new(source.clone(), addr.clone(), usize::MAX, 100).calc_rank(),
			0
		);

		let _ = PeerAdvertised::new(source, addr, usize::MAX, i64::MIN).calc_rank();
	}

	#[test]
	fn clone_without_onion_expanded_key_drops_secret_field() {
		let mut config = P2PConfig::default();
		config.port = 1234;
		config.peer_min_preferred_outbound_count = Some(7);
		config.onion_expanded_key = Some("0123456789abcdef".to_string());

		let sanitized = config.clone_without_secrets();

		assert_eq!(sanitized.port, config.port);
		assert_eq!(
			sanitized.peer_min_preferred_outbound_count,
			config.peer_min_preferred_outbound_count
		);
		assert_eq!(sanitized.onion_expanded_key, None);
		assert_eq!(
			config.onion_expanded_key.as_deref(),
			Some("0123456789abcdef")
		);
	}

	#[test]
	fn peer_update_only_refreshes_stuck_detector_on_new_max_difficulty() {
		let peer_info = PeerInfo {
			capabilities: Capabilities::UNKNOWN,
			user_agent: "test".to_string(),
			version: ProtocolVersion::local(),
			addr: PeerAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 3414))),
			direction: Direction::Outbound,
			live_info: Arc::new(RwLock::new(PeerLiveInfo::new(Difficulty::from_num(100)))),
			tx_base_fee: 0,
		};
		let old_stuck_detector = Instant::now() - StdDuration::from_secs(60);
		peer_info.live_info.write().stuck_detector = old_stuck_detector;

		peer_info.update(1, Difficulty::from_num(99));
		assert_eq!(
			peer_info.live_info.read_recursive().stuck_detector,
			old_stuck_detector
		);

		peer_info.update(2, Difficulty::from_num(100));
		assert_eq!(
			peer_info.live_info.read_recursive().stuck_detector,
			old_stuck_detector
		);

		peer_info.update(3, Difficulty::from_num(101));
		assert!(peer_info.live_info.read_recursive().stuck_detector > old_stuck_detector);
	}

	#[test]
	fn last_seen_seconds_ago_clamps_values_above_u32_max() {
		let peer_last_seen = Utc::now() - Duration::seconds(u32::MAX as i64 + 1);

		assert_eq!(last_seen_seconds_ago(peer_last_seen), u32::MAX);
	}
}
