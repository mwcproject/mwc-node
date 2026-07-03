// Copyright 2019 The Grin Developers
// Copyright 2025 The MWC Developers
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

use crate::handshake::Handshake;
use crate::peer::Peer;
use crate::peers::Peers;
use crate::store::PeerStore;
use crate::tor::arti;
use crate::tor::tcp_data_stream::TcpDataStream;
use crate::types::PeerAddr::Onion;
use crate::types::{
	Capabilities, ChainAdapter, Error, NetAdapter, P2PConfig, PeerAddr, PeerInfo, ReasonForBan,
	TorConfig, PEER_LISTENER_BUFFER_COUNT, PEER_MAX_INBOUND_COUNT,
};
use crate::PeerAddr::Ip;
use mwc_chain;
use mwc_chain::txhashset::BitmapChunk;
use mwc_chain::txhashset::Segmenter;
use mwc_chain::SyncState;
use mwc_core::core;
use mwc_core::core::hash::Hash;
use mwc_core::core::{OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use mwc_core::global;
use mwc_core::pow::Difficulty;
use mwc_crates::log::{debug, error, trace, warn};
use mwc_crates::parking_lot::{Mutex, RwLock};
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::pedersen::RangeProof;
use mwc_crates::secp::{Secp256k1, SecretKey};
use mwc_crates::tokio;
use mwc_crates::tokio::net::TcpStream;
use mwc_crates::tokio::time::Duration;
use mwc_crates::tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};
use mwc_crates::tor_proto::client::stream::DataStream;
use mwc_crates::zeroize::{Zeroize, Zeroizing};
use mwc_util::run_global_async_block;
use mwc_util::secp_static;
use mwc_util::StopState;
use std::convert::TryFrom;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;

/// P2P server implementation, handling bootstrapping to find and connect to
/// peers, receiving connections from other peers and keep track of all of them.
#[derive(Clone)]
pub struct Server {
	pub config: P2PConfig,
	tor_config: TorConfig,
	capabilities: Capabilities,
	pub peers: Arc<Peers>,
	sync_state: Arc<SyncState>,
	stop_state: Arc<StopState>,
	genesis: Hash,
	db_root: String,
	handshake: Arc<RwLock<Option<Arc<Handshake>>>>,
	context_id: u32,
}

struct InboundHandshakeGuard {
	in_flight: Arc<AtomicU32>,
}

impl InboundHandshakeGuard {
	fn try_acquire(
		in_flight: Arc<AtomicU32>,
		max_inbound_count: usize,
		established_inbound_count: usize,
	) -> Option<Self> {
		if in_flight
			.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
				if established_inbound_count
					.saturating_add(usize::try_from(current).unwrap_or(usize::MAX))
					< max_inbound_count
				{
					current.checked_add(1)
				} else {
					None
				}
			})
			.is_ok()
		{
			Some(InboundHandshakeGuard { in_flight })
		} else {
			None
		}
	}
}

impl Drop for InboundHandshakeGuard {
	fn drop(&mut self) {
		self.in_flight.fetch_sub(1, Ordering::AcqRel);
	}
}

// TODO TLS
impl Server {
	/// Creates a new idle p2p server with no peers
	pub fn new(
		context_id: u32,
		db_root: &str,
		capabilities: Capabilities,
		config: &P2PConfig,
		tor_config: &TorConfig,
		adapter: Arc<dyn ChainAdapter>,
		genesis: Hash,
		sync_state: Arc<SyncState>,
		stop_state: Arc<StopState>,
	) -> Result<Server, Error> {
		Ok(Server {
			config: config.clone(),
			tor_config: tor_config.clone(),
			capabilities,
			peers: Arc::new(Peers::new(
				PeerStore::new(context_id, db_root)?,
				adapter,
				config,
			)),
			sync_state,
			stop_state,
			genesis,
			db_root: String::from(db_root),
			handshake: Arc::new(RwLock::new(None)),
			context_id,
		})
	}

	/// Return true if server is ready to connect to the others peers.
	/// Server is ready when handshake record is built.
	pub fn is_ready(&self) -> bool {
		self.handshake.read_recursive().is_some()
	}

	pub fn listen(
		&self,
		ready_tx: Option<std::sync::mpsc::SyncSender<Result<(), Error>>>,
	) -> Result<(), Error> {
		let onion_expanded_key = if self.tor_config.is_tor_enabled() {
			Some(self.read_expanded_key(self.config.onion_expanded_key.clone())?)
		} else {
			None
		};

		let ready_tx = Arc::new(Mutex::new(ready_tx));
		let onion_expanded_key2 = onion_expanded_key.clone();

		let service_started_callback = |onion_address: Option<String>| {
			*self.handshake.write() = Some(Arc::new(Handshake::new(
				self.context_id,
				self.genesis.clone(),
				self.config.clone(),
				onion_address,
				onion_expanded_key2.clone(),
			)));

			if let Some(tx) = ready_tx.lock().take() {
				if let Err(e) = tx.send(Ok(())) {
					error!("Unable to report p2p listener startup success: {}", e);
				}
			}
		};

		let service_failed_callback = |e: &Error| match ready_tx.lock().take() {
			Some(tx) => {
				if let Err(send_error) = tx.send(Err(Error::TorProcess(format!(
					"Unable to start arti, {}",
					e
				)))) {
					error!(
						"Unable to report p2p listener startup failure: {}",
						send_error
					);
				}
				true
			}
			None => false,
		};

		let is_global_listener = !self.tor_config.is_tor_enabled();
		let inbound_handshakes = Arc::new(AtomicU32::new(0));
		let max_inbound_count = usize::try_from(
			self.config
				.peer_max_inbound_count
				.unwrap_or(PEER_MAX_INBOUND_COUNT),
		)
		.unwrap_or(usize::MAX)
		.saturating_add(
			usize::try_from(
				self.config
					.peer_listener_buffer_count
					.unwrap_or(PEER_LISTENER_BUFFER_COUNT),
			)
			.unwrap_or(usize::MAX),
		);
		let server = self.clone();

		let handle_new_connection_callback =
			move |stream: TcpDataStream, peer_address: Option<PeerAddr>| {
				let peer_address = if is_global_listener {
					peer_address
				} else {
					None
				};

				if server.check_undesirable(peer_address.as_ref()) {
					// Shutdown the incoming TCP connection if it is not desired
					if let Err(e) = stream.shutdown() {
						debug!("Error shutting down conn: {:?}", e);
					};
					return;
				}

				let established_inbound_count = server.peers.iter().inbound().connected().count();
				let Some(guard) = InboundHandshakeGuard::try_acquire(
					inbound_handshakes.clone(),
					max_inbound_count,
					established_inbound_count,
				) else {
					debug!(
						"Too many inbound peers or handshakes in progress, refusing connection."
					);
					if let Err(e) = stream.shutdown() {
						debug!("Error shutting down conn: {:?}", e);
					}
					return;
				};

				let server = server.clone();
				if let Err(e) = thread::Builder::new()
					.name(format!("p2p_inbound_handshake_{}", server.context_id))
					.spawn(move || {
						let _guard = guard;
						server.handle_new_connection(stream, peer_address);
					}) {
					debug!("Unable to start inbound handshake thread: {}", e);
				}
			};

		let result = crate::listen::listen(
			self.context_id,
			self.stop_state.clone(),
			Some(self.tor_config.clone()),
			Some(SocketAddr::new(
				IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)),
				self.config.port,
			)),
			onion_expanded_key,
			Some(service_started_callback),
			Some(service_failed_callback),
			None::<Box<dyn Fn(bool) + Send + Sync + 'static>>,
			handle_new_connection_callback,
		);
		result
	}

	fn read_tor_key_file(torkey_path: &Path) -> io::Result<Zeroizing<[u8; 64]>> {
		let mut bytes = mwc_util::file::read_owner_only_file(torkey_path)?;
		if bytes.len() != 64 {
			let actual = bytes.len();
			bytes.zeroize();
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!(
					"Invalid tor id file length. Expected 64 bytes, got {}",
					actual
				),
			));
		}
		let mut key = Zeroizing::new([0u8; 64]);
		key.copy_from_slice(&bytes);
		bytes.zeroize();
		Ok(key)
	}

	fn validate_tor_key_file(
		torkey_path: &Path,
		key: Zeroizing<[u8; 64]>,
	) -> Result<Zeroizing<[u8; 64]>, Error> {
		arti::parse_onion_expanded_key(&key).map_err(|e| {
			Error::TorOnionService(format!(
				"Invalid tor id data in file {}, {}",
				torkey_path.display(),
				e
			))
		})?;
		Ok(key)
	}

	fn read_expanded_key(
		&self,
		onion_expanded_key: Option<String>,
	) -> Result<Zeroizing<[u8; 64]>, Error> {
		let expanded_key = match onion_expanded_key {
			Some(mut key_hex) => {
				let key = match mwc_util::decode_secret_key_hex::<64>(&key_hex) {
					Ok(key) => key,
					Err(mwc_util::Error::InvalidLength { actual, .. }) => {
						key_hex.zeroize();
						return Err(Error::TorConfig(format!(
							"Invalid onion_expanded_key length. Expected 64 byte key, got {}",
							actual
						)));
					}
					Err(e) => {
						key_hex.zeroize();
						return Err(Error::TorConfig(format!(
							"Invalid onion_expanded_key configulation, {}",
							e
						)));
					}
				};
				key_hex.zeroize();
				arti::parse_onion_expanded_key(&key)
					.map_err(|e| Error::TorConfig(format!("Invalid onion_expanded_key, {}", e)))?;
				key
			}
			None => {
				let torkey_path = Path::new(&self.db_root).join("node_tor_id");

				match Self::read_tor_key_file(&torkey_path) {
					Ok(key) => Self::validate_tor_key_file(&torkey_path, key)?,
					Err(e) if e.kind() == io::ErrorKind::NotFound => {
						// generate a new key, save it in the file for the reuse
						let sec_key = secp_static::with_none(Error::from, |secp| {
							Ok(SecretKey::new(secp, &mut SysRng)?)
						})?;

						// It is how Arti want as constract the keys. Our goal is to extract 32b of secret following 32b of hash.
						// It is what to_secret_key_bytes does.
						let keypair = Keypair::from_bytes(&sec_key.0);
						let exp_key = ExpandedKeypair::from(&keypair);
						let exp_key_bytes = Zeroizing::new(exp_key.to_secret_key_bytes());

						match mwc_util::file::write_new_owner_only_file(
							&torkey_path,
							&*exp_key_bytes,
						) {
							Ok(()) => exp_key_bytes,
							Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
								let key = Self::read_tor_key_file(&torkey_path).map_err(|e| {
									Error::TorOnionService(format!(
										"Unable to read tor id data from file {}, {}",
										torkey_path.display(),
										e
									))
								})?;
								Self::validate_tor_key_file(&torkey_path, key)?
							}
							Err(e) => {
								return Err(Error::TorOnionService(format!(
									"Unable to write tor id into file {}, {}",
									torkey_path.display(),
									e
								)));
							}
						}
					}
					Err(e) => {
						return Err(Error::TorOnionService(format!(
							"Unable to read tor id data from file {}, {}",
							torkey_path.display(),
							e
						)));
					}
				}
			}
		};
		Ok(expanded_key)
	}

	fn format_onion_address(address: &String) -> String {
		if address.to_lowercase().ends_with(".onion") {
			address.clone()
		} else {
			address.clone() + ".onion"
		}
	}

	/// Asks the server to connect to a new peer. Directly returns the peer if
	/// we're already connected to the provided address.
	pub fn connect(&self, addr: &PeerAddr) -> Result<Arc<Peer>, Error> {
		if self.stop_state.is_stopped() {
			return Err(Error::ConnectionClose(String::from("node is stopping")));
		}

		if Peer::is_denied(&self.config, addr) {
			debug!("connect_peer: peer {:?} denied, not connecting.", addr);
			return Err(Error::ConnectionClose(String::from(
				"Peer is denied because it is in config black list",
			)));
		}

		match self.peers.is_banned(addr) {
			Ok(true) => {
				debug!("connect_peer: peer {:?} banned, not connecting.", addr);
				return Err(Error::ConnectionClose(String::from(
					"Peer denied because it is banned",
				)));
			}
			Ok(false) => {}
			Err(e) => {
				return Err(Error::ConnectionClose(format!(
					"Unable to verify ban state for {}: {}",
					addr, e
				)));
			}
		}

		let max_allowed_connections = usize::try_from(
			self.config
				.peer_max_inbound_count
				.unwrap_or(PEER_MAX_INBOUND_COUNT),
		)
		.unwrap_or(usize::MAX)
		.saturating_add(
			usize::try_from(self.config.peer_max_outbound_count(true)).unwrap_or(usize::MAX),
		)
		.saturating_add(10);
		// This is a soft admission guard, not a strict live-map invariant.
		// Concurrent connects can temporarily push the live connection count
		// above this limit; that spike is acceptable and normal peer cleanup
		// will gradually close excess or failed connections.
		if self.peers.get_number_connected_peers() > max_allowed_connections {
			return Err(Error::ConnectionClose(String::from(
				"Too many established connections...",
			)));
		}

		let self_onion_address = if global::is_production_mode(self.context_id) {
			let hs = self.handshake.read_recursive();
			let hs = hs
				.as_ref()
				.ok_or(Error::TorConnect("handshake is empty".into()))?;
			let addrs = hs.addrs.read_recursive();
			if addrs.contains(addr) {
				debug!("connect: ignore connecting to PeerWithSelf, addr: {}", addr);
				return Err(Error::PeerWithSelf);
			}
			hs.onion_address.clone()
		} else {
			None
		};

		// check if the onion address is self
		if global::is_production_mode(self.context_id) && self_onion_address.is_some() {
			match addr {
				Onion(address) => {
					if self_onion_address.as_ref() == Some(address) {
						debug!("error trying to connect with self: {}", address);
						return Err(Error::PeerWithSelf);
					}
					debug!("not self, connecting to {}", address);
				}
				Ip(_) => {
					if addr.is_loopback() {
						debug!("error trying to connect with self: {:?}", addr);
						return Err(Error::PeerWithSelf);
					}
				}
			}
		}

		if let Some(p) = self.peers.get_connected_peer(addr) {
			// if we're already connected to the addr, just return the peer
			trace!("connect_peer: already connected {}", addr);
			return Ok(p);
		}

		let stream: TcpDataStream = if self.tor_config.is_tor_enabled() {
			let stream: DataStream = arti::access_arti(|arti| {
				arti::arti_async_block(async {
					let arti_cancelled =
						arti::get_arti_cancell_token(self.context_id).ok_or(Error::Interrupted)?;
					let stream = match addr {
						Ip(socket) => {
							let connect_res = tokio::select! {
								res = arti.connect((socket.ip().to_string(), socket.port())) => res,
								_ = arti_cancelled.cancelled() => {
									return Err(Error::Interrupted);
								},
							};
							connect_res.map_err(|e| {
								Error::TorConnect(format!(
									"Unable connect to {}:{}, {}",
									socket.ip(),
									socket.port(),
									e
								))
							})?
						}
						Onion(onion_address) => {
							let onion_address = Self::format_onion_address(onion_address);
							let connect_res = tokio::select! {
								res = arti.connect((onion_address.as_str(), 80)) => res,
								_ = arti_cancelled.cancelled() => {
									return Err(Error::Interrupted);
								},
							};

							// For Tor using port 80 for p2p connections. No configs for that
							connect_res.map_err(|e| {
								Error::TorConnect(format!(
									"Unable connect to {}:{}, {}",
									onion_address, 80, e
								))
							})?
						}
					};
					Ok::<DataStream, Error>(stream)
				})
			})??;
			let stream_id = arti::allocate_arti_object_id();
			TcpDataStream::from_data(
				stream,
				format!("mwc_nodeCdata_stream_{}_{}", self.context_id, stream_id),
			)?
		} else {
			// No Tor,  just a regular socket
			match addr {
				PeerAddr::Ip(address) => run_global_async_block(async {
					let stream =
						tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(address))
							.await
							.map_err(|_| {
								Error::Connection(std::io::Error::new(
									std::io::ErrorKind::TimedOut,
									format!("connect timeout for {}", address),
								))
							})?
							.map_err(|e| Error::TorConnect(e.to_string()))?;
					Ok::<TcpDataStream, Error>(TcpDataStream::from_tcp(stream))
				})
				.map_err(|e| Error::Internal(e.to_string()))??,
				PeerAddr::Onion(onion_address) => {
					return Err(Error::ConnectionClose(format!(
						"Failed connect to Tor address {} because Tor socks is not configured",
						onion_address
					)));
				}
			}
		};

		let total_diff = self.peers.total_difficulty()?;
		let hs = self
			.handshake
			.read_recursive()
			.as_ref()
			.cloned()
			.ok_or(Error::TorConnect("handshake is empty".into()))?;

		let self_addr = match self_onion_address {
			Some(onion_addr) => PeerAddr::Onion(onion_addr),
			None => {
				if self.tor_config.is_tor_enabled() {
					PeerAddr::Ip(SocketAddr::new(
						IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
						self.config.port,
					))
				} else {
					PeerAddr::Ip(SocketAddr::new(
						IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
						self.config.port,
					))
				}
			}
		};

		let (peer, stream) = Peer::connect(
			stream,
			self.capabilities,
			total_diff,
			self_addr,
			hs.as_ref(),
			self.peers.clone(),
			addr, // peer address
			self.get_context_id(),
		)?;
		self.add_connected_peer(peer, stream)
	}

	fn add_connected_peer(&self, peer: Peer, stream: TcpDataStream) -> Result<Arc<Peer>, Error> {
		let peer = Arc::new(peer);
		if let Err(e) = self.peers.add_connected(peer.clone()) {
			peer.stop();
			return Err(e);
		}

		if let Err(e) = peer.start_listening(stream, self.sync_state.clone(), self.clone()) {
			self.peers.remove_connected_if_same(&peer);
			peer.stop();
			return Err(e.into());
		}

		let persisted_banned = match self.peers.is_banned(&peer.info.addr) {
			Ok(banned) => banned,
			Err(e) => {
				self.peers.remove_connected_if_same(&peer);
				peer.stop();
				return Err(e);
			}
		};

		if self.stop_state.is_stopped()
			|| !self.peers.is_connected_same(&peer)
			|| !peer.is_connected()
			|| peer.is_banned()
			|| persisted_banned
		{
			self.peers.remove_connected_if_same(&peer);
			peer.stop();
			return Err(Error::ConnectionClose(format!(
				"Peer {} stopped during startup",
				peer.info.addr
			)));
		}

		Ok(peer)
	}

	fn handle_new_connection(&self, stream: TcpDataStream, peer_address: Option<PeerAddr>) {
		match self.handle_new_peer(stream) {
			Err(Error::BadHandshake(err)) => {
				self.ban_bad_handshake(peer_address.as_ref(), &err);
			}
			Err(Error::ConnectionClose(err)) => {
				debug!("shutting down, ignoring a new peer, {}", err)
			}
			Err(e) => self.ban_bad_handshake(peer_address.as_ref(), &e),
			Ok(_) => {}
		}
	}

	fn ban_bad_handshake<E: std::fmt::Display + ?Sized>(
		&self,
		peer_address: Option<&PeerAddr>,
		err: &E,
	) {
		match peer_address {
			Some(peer) => {
				debug!("Error accepting peer {}: {}", peer, err);
				// Use a conservative policy for accept failures: ban the peer
				// even if the immediate error may be local/internal. This keeps
				// the accept path simple, and banning a self address is acceptable
				// because we normally should not connect to ourselves and the ban
				// prevents reusing that address while it is suspect. Accidental bans
				// are not critical and will be lifted by normal ban expiry.
				if let Err(e) = self
					.peers
					.add_banned(peer.clone(), ReasonForBan::BadHandshake)
				{
					warn!("Failed to ban peer {} after bad handshake: {}", peer, e);
				}
			}
			None => debug!("Error accepting onion peer. {}", err),
		}
	}

	fn handle_new_peer(&self, stream: TcpDataStream) -> Result<(), Error> {
		if self.stop_state.is_stopped() {
			return Err(Error::ConnectionClose(String::from("Server is stopping")));
		}

		let max_allowed_connections = usize::try_from(
			self.config
				.peer_max_inbound_count
				.unwrap_or(PEER_MAX_INBOUND_COUNT),
		)
		.unwrap_or(usize::MAX)
		.saturating_add(
			usize::try_from(self.config.peer_max_outbound_count(true)).unwrap_or(usize::MAX),
		)
		.saturating_add(10);
		// This is a soft admission guard, not a strict live-map invariant.
		// Concurrent inbound handshakes can temporarily push the live
		// connection count above this limit; that spike is acceptable and
		// normal peer cleanup will gradually close excess or failed
		// connections.
		if self.peers.get_number_connected_peers() > max_allowed_connections {
			return Err(Error::ConnectionClose(String::from(
				"Too many established connections...",
			)));
		}

		let total_diff = self.peers.total_difficulty()?;

		let hs = self
			.handshake
			.read_recursive()
			.as_ref()
			.cloned()
			.ok_or(Error::TorConnect("handshake is empty".into()))?;

		// accept the peer and add it to the server map
		let (peer, stream) = Peer::accept(
			stream,
			self.capabilities,
			total_diff,
			hs.as_ref(),
			self.peers.clone(),
			self.get_context_id(),
		)?;
		// if we are using TOR, it will be the local addressed because it comes from the proxy
		// Will still need to save all the peers and renameit after peer will share the TOR address
		self.add_connected_peer(peer, stream)?;
		Ok(())
	}

	/// Checks whether there's any reason we don't want to accept an incoming peer
	/// connection. There can be a few of them:
	/// 1. Accepting the peer connection would exceed the configured maximum allowed
	/// inbound peer count. Note that seed nodes may wish to increase the default
	/// value for PEER_LISTENER_BUFFER_COUNT to help with network bootstrapping.
	/// A default buffer of 8 peers is allowed to help with network growth.
	/// 2. The peer has been previously banned and the ban period hasn't
	/// expired yet.
	/// 3. We're already connected to a peer at the same IP. While there are
	/// many reasons multiple peers can legitimately share identical IP
	/// addresses (NAT), network distribution is improved if they choose
	/// different sets of peers themselves. In addition, it prevent potential
	/// duplicate connections, malicious or not.
	fn check_undesirable(&self, peer_address: Option<&PeerAddr>) -> bool {
		let max_inbound_count = usize::try_from(
			self.config
				.peer_max_inbound_count
				.unwrap_or(PEER_MAX_INBOUND_COUNT),
		)
		.unwrap_or(usize::MAX)
		.saturating_add(
			usize::try_from(
				self.config
					.peer_listener_buffer_count
					.unwrap_or(PEER_LISTENER_BUFFER_COUNT),
			)
			.unwrap_or(usize::MAX),
		);
		if self.peers.iter().inbound().connected().count() >= max_inbound_count {
			debug!("Accepting new connection will exceed peer limit, refusing connection.");
			return true;
		}
		if let Some(peer_addr) = peer_address {
			match self.peers.is_banned(&peer_addr) {
				Ok(true) => {
					debug!("Peer {} banned, refusing connection.", peer_addr);
					return true;
				}
				Ok(false) => {}
				Err(e) => {
					debug!(
						"Unable to verify ban state for {}, refusing connection: {}",
						peer_addr, e
					);
					return true;
				}
			}
			// The call to is_known() can fail due to contention on the peers map.
			// If it fails we want to default to refusing the connection.
			if self.peers.is_known(&peer_addr) {
				debug!("Peer {} already known, refusing connection.", peer_addr);
				return true;
			}
		}
		false
	}

	/// Check if server in syning state
	pub fn is_syncing(&self) -> bool {
		self.sync_state.is_syncing()
	}

	pub fn stop(&self) -> Result<(), Error> {
		self.stop_state.stop();
		if self.tor_config.is_tor_enabled() {
			arti::release_arti_cancelling(self.context_id);
		}
		self.peers.stop()
	}

	/// Pause means: stop all the current peers connection, only for tests.
	/// Note:
	/// 1. must pause the 'seed' thread also, to avoid the new egress peer connection
	/// 2. must pause the 'p2p-server' thread also, to avoid the new ingress peer connection.
	pub fn pause(&self) -> Result<(), Error> {
		self.peers.stop()
	}

	/// Get Onion address
	pub fn get_self_onion_address(&self) -> Result<Option<String>, Error> {
		let addr = self
			.handshake
			.read_recursive()
			.as_ref()
			.ok_or(Error::TorConnect("handshake is not defined".into()))?
			.onion_address
			.clone();
		Ok(addr)
	}

	/// Context ID (app session ID)
	pub fn get_context_id(&self) -> u32 {
		self.context_id
	}
}

/// A no-op network adapter used for testing.
///
/// This adapter accepts inbound chain events without validating or storing
/// them. In particular, `block_received` returns `Ok(true)` for every block,
/// which means callers will treat the block as handled successfully and will
/// not take the bad-block `false` path that can ban a malicious peer. Do not
/// wire this adapter into a live `Server`.
///
/// This remains public instead of being hidden behind `#[cfg(test)]` because
/// existing tests and external test crates use `mwc_p2p::DummyAdapter` through
/// the public p2p API. Gating it as a library unit-test-only item would break
/// those integration-style users. Prefer replacing those users with local test
/// adapters or a dedicated test-utils feature before making this type private.
pub struct DummyAdapter {}

impl ChainAdapter for DummyAdapter {
	fn total_difficulty(&self) -> Result<Difficulty, mwc_chain::Error> {
		Ok(Difficulty::min())
	}
	fn total_height(&self) -> Result<u64, mwc_chain::Error> {
		Ok(0)
	}
	fn get_transaction(&self, _h: Hash) -> Result<Option<core::Transaction>, mwc_chain::Error> {
		Ok(None)
	}

	fn tx_kernel_received(
		&self,
		_h: Hash,
		_peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		Ok(true)
	}
	fn transaction_received(
		&self,
		_secp: &mut Secp256k1,
		_: core::Transaction,
		_stem: bool,
	) -> Result<bool, mwc_chain::Error> {
		Ok(true)
	}
	fn compact_block_received(
		&self,
		_secp: &mut Secp256k1,
		_cb: core::CompactBlock,
		_peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		Ok(true)
	}
	fn header_received(
		&self,
		_bh: core::BlockHeader,
		_peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		Ok(true)
	}
	fn block_received(
		&self,
		_secp: &mut Secp256k1,
		_: core::Block,
		_: &PeerInfo,
		_: mwc_chain::Options,
	) -> Result<bool, mwc_chain::Error> {
		Ok(true)
	}
	fn headers_received(
		&self,
		_: &[core::BlockHeader],
		_remaining: u64,
		_: &PeerInfo,
	) -> Result<(), mwc_chain::Error> {
		Ok(())
	}

	fn header_locator(&self) -> Result<Vec<Hash>, mwc_chain::Error> {
		Ok(Vec::new())
	}

	fn locate_headers(&self, _: &[Hash]) -> Result<Vec<core::BlockHeader>, mwc_chain::Error> {
		Ok(vec![])
	}
	fn get_block(
		&self,
		_secp: &Secp256k1,
		_: Hash,
		_: &PeerInfo,
	) -> Result<Option<core::Block>, mwc_chain::Error> {
		Ok(None)
	}

	fn txhashset_archive_header(&self) -> Result<core::BlockHeader, mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support txhashset_archive_header".into(),
		))
	}

	fn get_tmp_dir(&self) -> Result<PathBuf, mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support get_tmp_dir".into(),
		))
	}

	fn get_tmpfile_pathname(&self, _tmpfile_name: String) -> Result<PathBuf, mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support get_tmpfile_pathname".into(),
		))
	}

	fn prepare_segmenter(&self) -> Result<Segmenter, mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support prepare_segmenter".into(),
		))
	}

	fn get_kernel_segment(
		&self,
		_hash: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<TxKernel>, mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support get_kernel_segment".into(),
		))
	}

	fn get_bitmap_segment(
		&self,
		_hash: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<BitmapChunk>, mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support get_bitmap_segment".into(),
		))
	}

	fn get_output_segment(
		&self,
		_hash: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<OutputIdentifier>, mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support get_output_segment".into(),
		))
	}

	fn get_rangeproof_segment(
		&self,
		_hash: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<RangeProof>, mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support get_rangeproof_segment".into(),
		))
	}

	fn receive_bitmap_segment(
		&self,
		_peer: &PeerAddr,
		_archive_header_hash: Hash,
		_segment: Segment<BitmapChunk>,
	) -> Result<(), mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support receive_bitmap_segment".into(),
		))
	}

	fn receive_output_segment(
		&self,
		_peer: &PeerAddr,
		_archive_header_hash: Hash,
		_segment: Segment<OutputIdentifier>,
	) -> Result<(), mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support receive_output_segment".into(),
		))
	}

	fn receive_rangeproof_segment(
		&self,
		_peer: &PeerAddr,
		_archive_header_hash: Hash,
		_segment: Segment<RangeProof>,
	) -> Result<(), mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support receive_rangeproof_segment".into(),
		))
	}

	fn receive_kernel_segment(
		&self,
		_peer: &PeerAddr,
		_archive_header_hash: Hash,
		_segment: Segment<TxKernel>,
	) -> Result<(), mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support receive_kernel_segment".into(),
		))
	}

	fn recieve_pibd_status(
		&self,
		_peer: &PeerAddr,
		_header_hash: Hash,
		_header_height: u64,
		_output_bitmap_root: Hash,
	) -> Result<(), mwc_chain::Error> {
		Ok(())
	}

	fn recieve_another_archive_header(
		&self,
		_peer: &PeerAddr,
		_header_hash: Hash,
		_header_height: u64,
	) -> Result<(), mwc_chain::Error> {
		Ok(())
	}

	fn receive_headers_hash_response(
		&self,
		_peer: &PeerAddr,
		_archive_height: u64,
		_headers_hash_root: Hash,
	) -> Result<(), mwc_chain::Error> {
		Ok(())
	}

	fn get_header_hashes_segment(
		&self,
		_header_hashes_root: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<Hash>, mwc_chain::Error> {
		Err(mwc_chain::Error::Other(
			"DummyAdapter does not support get_header_hashes_segment".into(),
		))
	}

	fn receive_header_hashes_segment(
		&self,
		_peer: &PeerAddr,
		_header_hashes_root: Hash,
		_segment: Segment<Hash>,
	) -> Result<(), mwc_chain::Error> {
		Ok(())
	}

	fn peer_difficulty(&self, _: &PeerAddr, _: Difficulty, _: u64) {}
}

impl NetAdapter for DummyAdapter {
	fn find_peer_addrs(&self, _: Capabilities) -> Result<Vec<PeerAddr>, Error> {
		Ok(vec![])
	}
	fn peer_addrs_received(&self, _: &PeerAddr, _: Vec<PeerAddr>) {}
	fn is_banned(&self, _: &PeerAddr) -> Result<bool, Error> {
		Ok(false)
	}

	fn peer_version(&self, _: &PeerAddr) -> Result<Option<mwc_core::ser::ProtocolVersion>, Error> {
		Ok(None)
	}

	fn ban_peer(
		&self,
		_addr: &PeerAddr,
		_ban_reason: ReasonForBan,
		_message: &str,
	) -> Result<(), Error> {
		Ok(())
	}
}

#[test]
fn stop_cancels_arti_context_for_tor_server() {
	let context_id = 250;
	global::init_global_chain_type(context_id, global::ChainTypes::AutomatedTesting).unwrap();
	global::init_global_accept_fee_base(context_id, 1000).unwrap();
	arti::init_arti_cancelling(context_id);

	let dir = mwc_crates::tempfile::TempDir::new().unwrap();
	let server = Server::new(
		context_id,
		dir.path().to_str().unwrap(),
		Capabilities::UNKNOWN,
		&P2PConfig::default(),
		&TorConfig::arti_tor_config(),
		Arc::new(DummyAdapter {}),
		Hash::from_vec(&vec![]),
		Arc::new(SyncState::new()),
		Arc::new(StopState::new()),
	)
	.unwrap();

	assert!(!arti::is_arti_cancelled(context_id));
	server.stop().unwrap();
	assert!(arti::is_arti_cancelled(context_id));
}

#[test]
fn stop_keeps_arti_context_for_non_tor_server() {
	let context_id = 251;
	global::init_global_chain_type(context_id, global::ChainTypes::AutomatedTesting).unwrap();
	global::init_global_accept_fee_base(context_id, 1000).unwrap();
	arti::init_arti_cancelling(context_id);

	let dir = mwc_crates::tempfile::TempDir::new().unwrap();
	let server = Server::new(
		context_id,
		dir.path().to_str().unwrap(),
		Capabilities::UNKNOWN,
		&P2PConfig::default(),
		&TorConfig::no_tor_config(),
		Arc::new(DummyAdapter {}),
		Hash::from_vec(&vec![]),
		Arc::new(SyncState::new()),
		Arc::new(StopState::new()),
	)
	.unwrap();

	assert!(!arti::is_arti_cancelled(context_id));
	server.stop().unwrap();
	assert!(!arti::is_arti_cancelled(context_id));
	arti::release_arti_cancelling(context_id);
}

#[test]
fn test_tor_address_parsing() {
	use mwc_crates::arti_client::IntoTorAddr;

	let address1 = "4vrh6vagyrw7du3vdcjk4u4g42qsb6dga6vevpds23fkgh6tw363hhyd";
	let address2 = "v4rw3evkwyg2y7nk2rwuhcsuums75vfr2u2ssrlo6rjxueza7gbppsuz";
	let address3 = "xhgwudthrz6hl7pcauz7jw6xyjc4anibplgnzmaszvdnxr7ibtg3q4f7";

	let r1 = (address1, 80).into_tor_addr();
	assert!(r1.is_ok());
	let r2 = (address2, 80).into_tor_addr();
	assert!(r2.is_ok());
	let r3 = (address3, 80).into_tor_addr();
	assert!(r3.is_ok());

	let address1 = "4vrh6vagyrw7du3vdcjk4u4g42qsb6dga6vevpds23fkgh6tw363hhyd.onion";
	let address2 = "v4rw3evkwyg2y7nk2rwuhcsuums75vfr2u2ssrlo6rjxueza7gbppsuz.onion";
	let address3 = "xhgwudthrz6hl7pcauz7jw6xyjc4anibplgnzmaszvdnxr7ibtg3q4f7.onion";

	let r1 = (address1, 80).into_tor_addr();
	assert!(r1.is_ok());
	let r2 = (address2, 80).into_tor_addr();
	assert!(r2.is_ok());
	let r3 = (address3, 80).into_tor_addr();
	assert!(r3.is_ok());

	let address1 = "tor://4vrh6vagyrw7du3vdcjk4u4g42qsb6dga6vevpds23fkgh6tw363hhyd.onion";
	let address2 = "tor://v4rw3evkwyg2y7nk2rwuhcsuums75vfr2u2ssrlo6rjxueza7gbppsuz.onion";
	let address3 = "tor://xhgwudthrz6hl7pcauz7jw6xyjc4anibplgnzmaszvdnxr7ibtg3q4f7.onion";

	let r1 = (address1, 80).into_tor_addr();
	assert!(r1.is_err());
	let r2 = (address2, 80).into_tor_addr();
	assert!(r2.is_err());
	let r3 = (address3, 80).into_tor_addr();
	assert!(r3.is_err());
}
