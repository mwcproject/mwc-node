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

use crate::chain;
use crate::chain::txhashset::BitmapChunk;
use crate::handshake::Handshake;
use crate::mwc_core::core;
use crate::mwc_core::core::hash::Hash;
use crate::mwc_core::core::{OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use crate::mwc_core::global;
use crate::mwc_core::pow::Difficulty;
use crate::peer::Peer;
use crate::peers::Peers;
use crate::store::PeerStore;
use crate::tor::arti;
use crate::tor::arti::{arti_async_block, get_shutdown_arti_token};
use crate::tor::tcp_data_stream::TcpDataStream;
use crate::types::PeerAddr::Onion;
use crate::types::{
	Capabilities, ChainAdapter, Error, NetAdapter, P2PConfig, PeerAddr, PeerInfo, ReasonForBan,
	TorConfig, TxHashSetRead,
};
use crate::util::secp::pedersen::RangeProof;
use crate::util::StopState;
use crate::PeerAddr::Ip;
use ed25519_dalek::ExpandedSecretKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use mwc_chain::txhashset::Segmenter;
use mwc_chain::SyncState;
use mwc_util::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_util::tokio::net::TcpStream;
use mwc_util::tokio::time::Duration;
use mwc_util::tokio_socks::tcp::Socks5Stream;
use mwc_util::{run_global_async_block, tokio};
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tor_proto::client::stream::DataStream;

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
	handshake: Arc<RwLock<Option<Handshake>>>,
	context_id: u32,
	arti_streams: Arc<AtomicI64>,
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
			arti_streams: Arc::new(AtomicI64::new(0)),
		})
	}

	/// Return true if server is ready to connect to the others peers.
	/// Server is ready when handshake record is built.
	pub fn is_ready(&self) -> bool {
		self.handshake
			.read()
			.unwrap_or_else(|e| e.into_inner())
			.is_some()
	}

	pub fn listen(
		&self,
		ready_tx: Option<std::sync::mpsc::SyncSender<Result<(), Error>>>,
	) -> Result<(), Error> {
		let onion_expanded_key = if self.tor_config.is_tor_internal_arti() {
			Some(self.read_expanded_key(self.config.onion_expanded_key.clone())?)
		} else {
			None
		};

		let ready_tx = Arc::new(Mutex::new(ready_tx));

		let service_started_callback = |onion_address: Option<String>| {
			*self.handshake.write().unwrap_or_else(|e| e.into_inner()) = Some(Handshake::new(
				self.context_id,
				self.genesis.clone(),
				self.config.clone(),
				onion_address,
			));

			ready_tx
				.lock()
				.unwrap_or_else(|e| e.into_inner())
				.take()
				.map(|tx| {
					let _ = tx.send(Ok(()));
				});
		};

		let service_failed_callback =
			|e: &Error| match ready_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
				Some(tx) => {
					let _ = tx.send(Err(Error::TorProcess(format!(
						"Unable to start arti, {}",
						e
					))));
					true
				}
				None => false,
			};

		let is_global_listener = !self.tor_config.is_tor_enabled();

		let handle_new_connection_callback =
			|stream: TcpDataStream, peer_address: Option<PeerAddr>| {
				let peer_address = if is_global_listener {
					peer_address
				} else {
					None
				};

				if self.check_undesirable(peer_address.as_ref()) {
					// Shutdown the incoming TCP connection if it is not desired
					if let Err(e) = stream.shutdown() {
						debug!("Error shutting down conn: {:?}", e);
					};
					return;
				}

				match self.handle_new_peer(stream) {
					Err(Error::ConnectionClose(err)) => {
						debug!("shutting down, ignoring a new peer, {}", err)
					}
					Err(e) => match &peer_address {
						Some(peer) => {
							debug!("Error accepting peer {}: {:?}", peer.to_string(), e);
							let _ = self
								.peers
								.add_banned(peer.clone(), ReasonForBan::BadHandshake);
						}
						None => debug!("Error accepting onion peer. {}", e),
					},
					Ok(_) => {}
				}
			};

		crate::listen::listen(
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
		)
	}

	fn read_expanded_key(&self, onion_expanded_key: Option<String>) -> Result<[u8; 64], Error> {
		let expanded_key = match onion_expanded_key {
			Some(key_hex) => {
				let bytes = mwc_util::from_hex(&key_hex).map_err(|e| {
					Error::TorConfig(format!(
						"Invalid onion_expanded_key configulation {}, {}",
						key_hex, e
					))
				})?;
				let key: [u8; 64] = bytes.try_into().map_err(|_| {
					Error::TorConfig(
						"Invalid onion_expanded_key length. Expected 64 byte key".into(),
					)
				})?;
				key
			}
			None => {
				let torkey_path = format!("{}/node_tor_id", self.db_root);

				if Path::new(&torkey_path).exists() {
					let mut file = File::open(&torkey_path).map_err(|e| {
						Error::TorOnionService(format!(
							"Unable to open existing tor id file {}, {}",
							torkey_path, e
						))
					})?;
					let mut buf = [0u8; 64];
					file.read_exact(&mut buf).map_err(|e| {
						Error::TorOnionService(format!(
							"Unable to read tor id data form the file {}, {}",
							torkey_path, e
						))
					})?;
					buf
				} else {
					// generate a new key, save it in the file for the reuse
					let secp = Secp256k1::with_caps(ContextFlag::None);
					let sec_key = SecretKey::new(&secp, &mut rand::thread_rng());
					let sec_key = DalekSecretKey::from_bytes(&sec_key.0).map_err(|e| {
						Error::TorOnionService(format!("Unable to build a DalekSecretKey, {}", e))
					})?;
					let exp_key = ExpandedSecretKey::from(&sec_key);
					let exp_key = exp_key.to_bytes();
					let mut file = File::create(&torkey_path).map_err(|e| {
						Error::TorOnionService(format!(
							"Unable to create tor id file {}, {}",
							torkey_path, e
						))
					})?;
					file.write_all(&exp_key).map_err(|e| {
						Error::TorOnionService(format!(
							"Unable to write tor id into file {}, {}",
							torkey_path, e
						))
					})?;
					exp_key
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

		let max_allowed_connections =
			self.config.peer_max_inbound_count() + self.config.peer_max_outbound_count(true) + 10;
		if self.peers.get_number_connected_peers() > max_allowed_connections as usize {
			return Err(Error::ConnectionClose(String::from(
				"Too many established connections...",
			)));
		}

		let self_onion_address = if global::is_production_mode(self.context_id) {
			let hs = self.handshake.read().unwrap_or_else(|e| e.into_inner());
			let hs = hs
				.as_ref()
				.ok_or(Error::TorConnect("handshake is empty".into()))?;
			let addrs = hs.addrs.read().unwrap_or_else(|e| e.into_inner());
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
					if self_onion_address.as_ref().unwrap() == address {
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
			if !self.tor_config.is_tor_external() {
				// Using arti to connect
				let stream: DataStream = arti::access_arti(|arti| {
					arti_async_block(async {
						let arti_shutdown = get_shutdown_arti_token();
						let stream = match addr {
							Ip(socket) => {
								let connect_res = tokio::select! {
									res = arti.connect((socket.ip().to_string(), socket.port())) => res,
									_ = arti_shutdown.cancelled() => {
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
									_ = arti_shutdown.cancelled() => {
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
				let stream_id = self.arti_streams.fetch_add(1, Ordering::Relaxed);
				TcpDataStream::from_data(stream, format!("mwc_nodeCdata_stream_{}", stream_id))
			} else {
				// External Tor
				let socks_port = self.tor_config.socks_port.ok_or(Error::TorConfig(
					"socks_port is not defined at Tor config".into(),
				))?;
				run_global_async_block(async {
					match addr {
						PeerAddr::Ip(address) => {
							// we do this, not a good solution, but for now, we'll use it. Other side usually detects with ip.
							let stream = Socks5Stream::connect(
								("127.0.0.1", socks_port),
								address.to_string(),
							)
							.await
							.map_err(|e| {
								Error::TorConnect(format!(
									"Unable connect to External Tor as 127.0.0.1:{}, {}",
									self.config.port, e
								))
							})?;
							Ok::<TcpDataStream, Error>(TcpDataStream::from_tcp(stream.into_inner()))
						}
						PeerAddr::Onion(onion_address) => {
							let onion_address = Self::format_onion_address(onion_address);
							// Target port for onion is 80
							let proxy_address = format!("127.0.0.1:{}", socks_port);
							let stream =
								Socks5Stream::connect(proxy_address.as_str(), (onion_address, 80))
									.await
									.map_err(|e| {
										Error::TorConnect(format!(
											"Unable connect to External Tor as 127.0.0.1:{}, {}",
											socks_port, e
										))
									});
							let stream = stream?;
							Ok(TcpDataStream::from_tcp(stream.into_inner()))
						}
					}
				})?
			}
		} else {
			// No Tor,  just a regular socket
			match addr {
				PeerAddr::Ip(address) => run_global_async_block(async {
					let stream = mwc_util::tokio::time::timeout(
						Duration::from_secs(10),
						TcpStream::connect(address),
					)
					.await
					.map_err(|_| {
						Error::Connection(std::io::Error::new(
							std::io::ErrorKind::TimedOut,
							format!("connect timeout for {}", address),
						))
					})?
					.map_err(|e| Error::TorConnect(e.to_string()))?;
					Ok::<TcpDataStream, Error>(TcpDataStream::from_tcp(stream))
				})?,
				PeerAddr::Onion(onion_address) => {
					return Err(Error::ConnectionClose(format!(
						"Failed connect to Tor address {} because Tor socks is not configured",
						onion_address
					)));
				}
			}
		};

		let total_diff = self.peers.total_difficulty()?;
		let hs = self.handshake.read().unwrap_or_else(|e| e.into_inner());
		let hs = hs
			.as_ref()
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

		let peer = Peer::connect(
			stream,
			self.capabilities,
			total_diff,
			self_addr,
			hs,
			self.peers.clone(),
			addr, // peer address
			self.sync_state.clone(),
			(*self).clone(),
		)?;
		let peer = Arc::new(peer);
		self.peers.add_connected(peer.clone())?;
		Ok(peer)
	}

	fn handle_new_peer(&self, stream: TcpDataStream) -> Result<(), Error> {
		if self.stop_state.is_stopped() {
			return Err(Error::ConnectionClose(String::from("Server is stopping")));
		}

		let max_allowed_connections =
			self.config.peer_max_inbound_count() + self.config.peer_max_outbound_count(true) + 10;
		if self.peers.get_number_connected_peers() > max_allowed_connections as usize {
			return Err(Error::ConnectionClose(String::from(
				"Too many established connections...",
			)));
		}

		let total_diff = self.peers.total_difficulty()?;

		let hs = self.handshake.read().unwrap_or_else(|e| e.into_inner());
		let hs = hs
			.as_ref()
			.ok_or(Error::TorConnect("handshake is empty".into()))?;

		// accept the peer and add it to the server map
		let peer = Peer::accept(
			stream,
			self.capabilities,
			total_diff,
			hs,
			self.peers.clone(),
			self.sync_state.clone(),
			self.clone(),
		)?;
		// if we are using TOR, it will be the local addressed because it comes from the proxy
		// Will still need to save all the peers and renameit after peer will share the TOR address
		self.peers.add_connected(Arc::new(peer))?;
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
		if self.peers.iter().inbound().connected().count() as u32
			>= self.config.peer_max_inbound_count() + self.config.peer_listener_buffer_count()
		{
			debug!("Accepting new connection will exceed peer limit, refusing connection.");
			return true;
		}
		if let Some(peer_addr) = peer_address {
			if self.peers.is_banned(&peer_addr) {
				debug!("Peer {} banned, refusing connection.", peer_addr);
				return true;
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

	pub fn stop(&self) {
		self.stop_state.stop();
		self.peers.stop();
	}

	/// Pause means: stop all the current peers connection, only for tests.
	/// Note:
	/// 1. must pause the 'seed' thread also, to avoid the new egress peer connection
	/// 2. must pause the 'p2p-server' thread also, to avoid the new ingress peer connection.
	pub fn pause(&self) {
		self.peers.stop();
	}

	/// Get Onion address
	pub fn get_self_onion_address(&self) -> Result<Option<String>, Error> {
		let addr = self
			.handshake
			.read()
			.unwrap_or_else(|e| e.into_inner())
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
pub struct DummyAdapter {}

impl ChainAdapter for DummyAdapter {
	fn total_difficulty(&self) -> Result<Difficulty, chain::Error> {
		Ok(Difficulty::min())
	}
	fn total_height(&self) -> Result<u64, chain::Error> {
		Ok(0)
	}
	fn get_transaction(&self, _h: Hash) -> Option<core::Transaction> {
		None
	}

	fn tx_kernel_received(&self, _h: Hash, _peer_info: &PeerInfo) -> Result<bool, chain::Error> {
		Ok(true)
	}
	fn transaction_received(
		&self,
		_: core::Transaction,
		_stem: bool,
	) -> Result<bool, chain::Error> {
		Ok(true)
	}
	fn compact_block_received(
		&self,
		_cb: core::CompactBlock,
		_peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		Ok(true)
	}
	fn header_received(
		&self,
		_bh: core::BlockHeader,
		_peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		Ok(true)
	}
	fn block_received(
		&self,
		_: core::Block,
		_: &PeerInfo,
		_: chain::Options,
	) -> Result<bool, chain::Error> {
		Ok(true)
	}
	fn headers_received(
		&self,
		_: &[core::BlockHeader],
		_remaining: u64,
		_: &PeerInfo,
	) -> Result<(), chain::Error> {
		Ok(())
	}

	fn header_locator(&self) -> Result<Vec<Hash>, chain::Error> {
		Ok(Vec::new())
	}

	fn locate_headers(&self, _: &[Hash]) -> Result<Vec<core::BlockHeader>, chain::Error> {
		Ok(vec![])
	}
	fn get_block(&self, _: Hash, _: &PeerInfo) -> Option<core::Block> {
		None
	}
	fn txhashset_read(&self, _h: Hash) -> Option<TxHashSetRead> {
		unimplemented!()
	}

	fn txhashset_archive_header(&self) -> Result<core::BlockHeader, chain::Error> {
		unimplemented!()
	}

	fn get_tmp_dir(&self) -> Result<PathBuf, chain::Error> {
		unimplemented!()
	}

	fn get_tmpfile_pathname(&self, _tmpfile_name: String) -> Result<PathBuf, chain::Error> {
		unimplemented!()
	}

	fn prepare_segmenter(&self) -> Result<Segmenter, chain::Error> {
		unimplemented!()
	}

	fn get_kernel_segment(
		&self,
		_hash: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<TxKernel>, chain::Error> {
		unimplemented!()
	}

	fn get_bitmap_segment(
		&self,
		_hash: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<BitmapChunk>, chain::Error> {
		unimplemented!()
	}

	fn get_output_segment(
		&self,
		_hash: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<OutputIdentifier>, chain::Error> {
		unimplemented!()
	}

	fn get_rangeproof_segment(
		&self,
		_hash: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<RangeProof>, chain::Error> {
		unimplemented!()
	}

	fn receive_bitmap_segment(
		&self,
		_peer: &PeerAddr,
		_archive_header_hash: Hash,
		_segment: Segment<BitmapChunk>,
	) -> Result<(), chain::Error> {
		unimplemented!()
	}

	fn receive_output_segment(
		&self,
		_peer: &PeerAddr,
		_archive_header_hash: Hash,
		_segment: Segment<OutputIdentifier>,
	) -> Result<(), chain::Error> {
		unimplemented!()
	}

	fn receive_rangeproof_segment(
		&self,
		_peer: &PeerAddr,
		_archive_header_hash: Hash,
		_segment: Segment<RangeProof>,
	) -> Result<(), chain::Error> {
		unimplemented!()
	}

	fn receive_kernel_segment(
		&self,
		_peer: &PeerAddr,
		_archive_header_hash: Hash,
		_segment: Segment<TxKernel>,
	) -> Result<(), chain::Error> {
		unimplemented!()
	}

	fn recieve_pibd_status(
		&self,
		_peer: &PeerAddr,
		_header_hash: Hash,
		_header_height: u64,
		_output_bitmap_root: Hash,
	) -> Result<(), chain::Error> {
		Ok(())
	}

	fn recieve_another_archive_header(
		&self,
		_peer: &PeerAddr,
		_header_hash: Hash,
		_header_height: u64,
	) -> Result<(), chain::Error> {
		Ok(())
	}

	fn receive_headers_hash_response(
		&self,
		_peer: &PeerAddr,
		_archive_height: u64,
		_headers_hash_root: Hash,
	) -> Result<(), chain::Error> {
		Ok(())
	}

	fn get_header_hashes_segment(
		&self,
		_header_hashes_root: Hash,
		_id: SegmentIdentifier,
	) -> Result<Segment<Hash>, chain::Error> {
		unimplemented!()
	}

	fn receive_header_hashes_segment(
		&self,
		_peer: &PeerAddr,
		_header_hashes_root: Hash,
		_segment: Segment<Hash>,
	) -> Result<(), chain::Error> {
		Ok(())
	}

	fn peer_difficulty(&self, _: &PeerAddr, _: Difficulty, _: u64) {}
}

impl NetAdapter for DummyAdapter {
	fn find_peer_addrs(&self, _: Capabilities) -> Vec<PeerAddr> {
		vec![]
	}
	fn peer_addrs_received(&self, _: Vec<PeerAddr>) {}
	fn is_banned(&self, _: &PeerAddr) -> bool {
		false
	}

	fn ban_peer(&self, _addr: &PeerAddr, _ban_reason: ReasonForBan, _message: &str) {}
}

#[test]
fn test_tor_address_parsing() {
	use arti_client::IntoTorAddr;

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
