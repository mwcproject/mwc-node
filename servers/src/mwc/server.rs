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

//! Mwc server implementation, glues the different parts of the system (mostly
//! the peer-to-peer server, the blockchain and the transaction pool) and acts
//! as a facade.

use mwc_crates::parking_lot::RwLock;
use std::convert::TryFrom;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use mwc_crates::fs2::FileExt;
use mwc_crates::walkdir::WalkDir;

use crate::common::adapters::{
	ChainToPoolAndNetAdapter, NetToChainAdapter, PoolToChainAdapter, PoolToNetAdapter,
};
use crate::common::hooks::init_hooks;
use crate::common::stats::{
	ChainStats, DiffBlock, DiffStats, PeerStats, ServerStateInfo, ServerStats, TxStats,
};
use crate::common::types::{ServerConfig, StratumServerConfig};
use crate::mining::stratumserver;
use crate::mwc::{dandelion_monitor, seed, sync};
use crate::Error;
use mwc_api::TLSConfig;
use mwc_chain::{self, SyncState, SyncStatus};
use mwc_core::core::hash::{Hashed, ZERO_HASH};
use mwc_core::ser::ProtocolVersion;
use mwc_core::stratum::connections;
use mwc_core::{consensus, global, pow};
use mwc_util::file::get_owner_only_first_line_zeroizing;
use mwc_util::StopState;
use std::collections::HashSet;
use std::sync::atomic::Ordering;

use crate::mwc::sync::sync_manager::SyncManager;
use mwc_api::Router;
use mwc_core::core::hash::Hash;
use mwc_crates::log::{debug, error, info, warn};
use mwc_crates::secp::Secp256k1;
use mwc_p2p::Capabilities;

/// Arcified  thread-safe TransactionPool with type parameters used by server components
pub type ServerTxPool =
	Arc<RwLock<mwc_pool::TransactionPool<PoolToChainAdapter, PoolToNetAdapter>>>;

/// Pending p2p listener startup. Waiting on this can block on TCP bind/Tor
/// readiness, so callers should not hold global registry locks while waiting.
pub struct PendingPeerListener {
	listen_peers_thread: JoinHandle<Result<(), mwc_p2p::Error>>,
	startup_rx: mpsc::Receiver<Result<(), mwc_p2p::Error>>,
}

/// Successfully started p2p listener thread handle.
pub struct StartedPeerListener {
	listen_peers_thread: JoinHandle<Result<(), mwc_p2p::Error>>,
}

impl PendingPeerListener {
	pub fn wait_for_startup(self) -> Result<StartedPeerListener, Error> {
		match self.startup_rx.recv() {
			Ok(Ok(())) => Ok(StartedPeerListener {
				listen_peers_thread: self.listen_peers_thread,
			}),
			Ok(Err(e)) => Err(Server::join_failed_peer_listener_startup(
				self.listen_peers_thread,
				e.to_string(),
			)),
			Err(e) => Err(Server::join_failed_peer_listener_startup(
				self.listen_peers_thread,
				format!("p2p startup status channel closed, {}", e),
			)),
		}
	}
}

impl StartedPeerListener {
	/// Wait for listener shutdown.
	///
	/// Listener shutdown is best effort: join panics and listener errors are
	/// logged, and callers do not need the final shutdown result.
	pub fn wait_for_shutdown(self) {
		Server::wait_for_result_thread(Some(self.listen_peers_thread), "listen_peers_thread");
	}
}

/// Mwc server holding internal structures.
pub struct Server {
	/// server config
	pub config: ServerConfig,
	/// handle to our network server
	pub p2p: Arc<mwc_p2p::Server>,
	/// data store access
	pub chain: Arc<mwc_chain::Chain>,
	/// in-memory transaction pool
	pub tx_pool: ServerTxPool,
	/// Whether we're currently syncing
	pub sync_state: Arc<SyncState>,
	/// To be passed around to collect stats and info
	state_info: ServerStateInfo,
	/// Stop flag
	pub stop_state: Arc<StopState>,
	/// Maintain a lock_file so we do not run multiple Mwc nodes from same dir.
	lock_file: Arc<File>,
	connect_thread: Option<JoinHandle<()>>,
	sync_thread: Option<JoinHandle<()>>,
	dandelion_thread: Option<JoinHandle<()>>,
	stratum_thread: Option<JoinHandle<Result<(), Error>>>,
	connect_and_monitor_thread: Option<JoinHandle<()>>,
	listen_peers_starting: bool,
	listen_peers_thread: Option<JoinHandle<Result<(), mwc_p2p::Error>>>,
	api_thread: Option<JoinHandle<()>>,
	api_monitor_thread: Option<JoinHandle<Result<(), String>>>,

	// Stratum pool
	stratum_ip_pool: Arc<connections::StratumIpPool>,
	// Sync manager (shared between running services)
	sync_manager: Arc<SyncManager>,
	// Tx pool vs network adapter
	pool_net_adapter: Arc<PoolToNetAdapter>,
}

impl Server {
	/// Create a new server instance. No jobs will be started
	pub fn create_server(
		secp: &Secp256k1,
		context_id: u32,
		config: ServerConfig,
	) -> Result<Self, Error> {
		if let Some(ban_window) = config.p2p_config.ban_window {
			if ban_window <= 0 {
				return Err(Error::Config(format!(
					"Invalid p2p_config.ban_window: {}. ban_window must be positive.",
					ban_window
				)));
			}
		}

		config.dandelion_config.validate().map_err(Error::Config)?;

		let stratum_ip_pool = Arc::new(connections::StratumIpPool::new(
			config.stratum_mining_config.ban_action_limit,
			config.stratum_mining_config.shares_weight,
			config.stratum_mining_config.connection_pace_ms,
		));

		// Obtain our lock_file or fail immediately with an error.
		let lock_file = Server::one_mwc_at_a_time(&config).map_err(|e| {
			error!(
				"Unable to lock db. Likely your DB path is wrong. Error: {}",
				e
			);
			e
		})?;

		// Defaults to None (optional) in config file.
		// This translates to false here.
		let archive_mode = match config.archive_mode {
			None => false,
			Some(b) => b,
		};

		let stop_state = Arc::new(StopState::new());

		let pool_adapter = Arc::new(PoolToChainAdapter::new());
		let pool_net_adapter = Arc::new(PoolToNetAdapter::new(
			context_id,
			config.dandelion_config.clone(),
		));
		let tx_pool = Arc::new(RwLock::new(mwc_pool::TransactionPool::new(
			context_id,
			config.pool_config.clone(),
			pool_adapter.clone(),
			pool_net_adapter.clone(),
		)));

		let sync_state = Arc::new(SyncState::new());
		// Defaults to None (optional) in config file.
		// This translates to false here so we do not skip by default.
		sync_state.update(SyncStatus::AwaitingPeers);

		let hooks = init_hooks(&config)?;
		let chain_hooks = hooks.chain_hooks;
		let net_hooks = hooks.net_hooks;

		let chain_adapter = Arc::new(ChainToPoolAndNetAdapter::new(
			tx_pool.clone(),
			sync_state.clone(),
			chain_hooks,
		));

		let genesis = global::get_genesis_block(secp, context_id)
			.map_err(|e| Error::ServerError(format!("Unable to build genesis, {}", e)))?;

		info!(
			"Starting server, genesis block: {}",
			genesis.hash(context_id)?
		);

		let invalid_blocks: HashSet<Hash> = match &config.invalid_block_hashes {
			Some(hashes_str) => {
				let mut banned_headers: HashSet<Hash> = HashSet::new();
				for hstr in hashes_str {
					let h = Hash::from_hex(&hstr).map_err(|_| {
						Error::Config(format!("invalid_block_hashes hash value: {}", hstr))
					})?;
					banned_headers.insert(h);
				}
				banned_headers
			}
			None => HashSet::new(),
		};

		let shared_chain = Arc::new(
			mwc_chain::Chain::init(
				secp,
				context_id,
				config.db_root.clone(),
				chain_adapter.clone(),
				genesis.clone(),
				pow::verify_size,
				archive_mode,
				invalid_blocks,
				Some(sync_state.clone()),
				Some(stop_state.clone()),
			)
			.map_err(|e| Error::ServerError(format!("Unable to read blockchain data, {}", e)))?,
		);

		pool_adapter
			.set_chain(shared_chain.clone())
			.map_err(|e| Error::ServerError(e.to_string()))?;

		let sync_manager: Arc<SyncManager> = Arc::new(SyncManager::new(
			shared_chain.clone(),
			sync_state.clone(),
			stop_state.clone(),
		));

		let net_adapter = Arc::new(NetToChainAdapter::new(
			context_id,
			sync_state.clone(),
			shared_chain.clone(),
			sync_manager.clone(),
			tx_pool.clone(),
			config.chain_validation_mode.clone(),
			net_hooks,
		));

		// Initialize our capabilities.
		// Currently either "default" or with optional "archive_mode" (block history) support enabled.
		let use_tor = config.tor_config.is_tor_enabled();
		let capabilities = Capabilities::new(use_tor, config.archive_mode.unwrap_or(false));
		debug!("Capabilities: {:?}", capabilities);

		let p2p_server = Arc::new(
			mwc_p2p::Server::new(
				context_id,
				&config.db_root,
				capabilities,
				&config.p2p_config,
				&config.tor_config,
				net_adapter.clone(),
				genesis.hash(context_id)?,
				sync_state.clone(),
				stop_state.clone(),
			)
			.map_err(|e| Error::ServerError(e.to_string()))?,
		);

		// Initialize various adapters with our dynamic set of connected peers.
		chain_adapter.init(p2p_server.peers.clone())?;
		pool_net_adapter
			.init(p2p_server.peers.clone())
			.map_err(|e| Error::ServerError(e.to_string()))?;
		net_adapter
			.init(p2p_server.peers.clone())
			.map_err(|e| Error::ServerError(e.to_string()))?;

		Ok(Server {
			config,
			p2p: p2p_server,
			chain: shared_chain,
			tx_pool,
			sync_state,
			state_info: ServerStateInfo {
				..Default::default()
			},
			stop_state,
			lock_file,
			connect_thread: None,
			sync_thread: None,
			dandelion_thread: None,
			stratum_thread: None,
			connect_and_monitor_thread: None,
			listen_peers_starting: false,
			listen_peers_thread: None,
			api_thread: None,
			api_monitor_thread: None,
			stratum_ip_pool,
			sync_manager,
			pool_net_adapter,
		})
	}

	/// Start Stratum protocol, needed for the mining
	pub fn start_stratum(&mut self) -> Result<(), Error> {
		if self
			.config
			.stratum_mining_config
			.enable_stratum_server
			.unwrap_or(false)
		{
			self.state_info
				.stratum_stats
				.is_enabled
				.store(true, Ordering::Relaxed);
			self.start_stratum_server(self.config.stratum_mining_config.clone())?;
		}
		Ok(())
	}

	/// Start pees discovery p2p peers job
	pub fn start_discover_peers(&mut self) -> Result<(), Error> {
		if self.connect_and_monitor_thread.is_some() {
			return Err(Error::ServerError(
				"peer discovery is already running".into(),
			));
		}

		let seed_list = match self.config.p2p_config.seeding_type {
			mwc_p2p::Seeding::None => {
				warn!("No seed configured, will stay solo until connected to");
				seed::predefined_seeds(vec![])
			}
			mwc_p2p::Seeding::List => match &self.config.p2p_config.seeds {
				Some(seeds) => seed::predefined_seeds(seeds.peers.clone()),
				None => {
					return Err(Error::ServerError(
						"Seeds must be configured for seeding type List".to_owned(),
					));
				}
			},
			mwc_p2p::Seeding::DNSSeed => seed::default_dns_seeds(self.chain.get_context_id()),
		};

		// Peer discovery can fail on peer-store reads or persistence, but it can
		// also spend a long time on DNS, Tor health checks, and outbound connects.
		// Do not block server startup waiting for those operations just so this
		// method can report discovery errors synchronously. Keep startup fast and
		// let the seed monitor log and retry discovery failures after it starts.
		let connect_thread = seed::connect_and_monitor(
			self.p2p.clone(),
			seed_list,
			self.config.p2p_config.clone_without_secrets(),
			self.stop_state.clone(),
			self.config.tor_config.is_tor_enabled(),
		)
		.map_err(|e| Error::ServerError(format!("Unable to start monitoring, {}", e)))?;

		self.connect_and_monitor_thread = Some(connect_thread);
		Ok(())
	}

	/// Start node syncing job
	pub fn start_sync_monitoring(&mut self) -> Result<(), Error> {
		if self.sync_thread.is_some() {
			return Err(Error::ServerError("sync thread is already running".into()));
		}

		let sync_thread = sync::run_sync(
			self.sync_state.clone(),
			self.p2p.peers.clone(),
			self.chain.clone(),
			self.stop_state.clone(),
			self.sync_manager.clone(),
		)
		.map_err(|e| Error::ServerError(format!("Unable to start sync thread, {}", e)))?;

		self.sync_thread = Some(sync_thread);
		Ok(())
	}

	/// Start p2p listening job. Needed for inbound peers connection
	/// startup is always confirmed so listener bind/Tor failures are returned.
	pub fn start_listen_peers(&mut self) -> Result<(), Error> {
		let pending_listener = self.begin_start_listen_peers()?;
		match pending_listener.wait_for_startup() {
			Ok(started_listener) => self.finish_start_listen_peers(started_listener),
			Err(e) => {
				self.finish_failed_listen_peers_startup();
				Err(e)
			}
		}
	}

	/// Spawn the p2p listener thread and return its pending startup status.
	///
	/// The returned handle must be waited on and then finalized with either
	/// `finish_start_listen_peers` or `finish_failed_listen_peers_startup`.
	pub fn begin_start_listen_peers(&mut self) -> Result<PendingPeerListener, Error> {
		if self.listen_peers_starting || self.listen_peers_thread.is_some() {
			return Err(Error::ServerError(
				"peer listener is already running".into(),
			));
		}

		let p2p_inner = self.p2p.clone();
		let (p2p_tx, p2p_rx) = mpsc::sync_channel::<Result<(), mwc_p2p::Error>>(1);

		let listen_peers_thread = thread::Builder::new()
			.name("p2p-server".to_string())
			.spawn(move || p2p_inner.listen(Some(p2p_tx)))
			.map_err(|e| Error::ServerError(format!("Listen job is failed, {}", e)))?;

		self.listen_peers_starting = true;
		Ok(PendingPeerListener {
			listen_peers_thread,
			startup_rx: p2p_rx,
		})
	}

	/// Store a successfully started p2p listener thread in the server state.
	pub fn finish_start_listen_peers(
		&mut self,
		started_listener: StartedPeerListener,
	) -> Result<(), Error> {
		if !self.listen_peers_starting {
			self.stop_state.stop();
			started_listener.wait_for_shutdown();
			return Err(Error::ServerError(
				"peer listener startup was not pending".into(),
			));
		}

		self.listen_peers_starting = false;
		self.listen_peers_thread = Some(started_listener.listen_peers_thread);
		Ok(())
	}

	/// Clear the pending p2p listener startup state after startup failure.
	pub fn finish_failed_listen_peers_startup(&mut self) {
		self.listen_peers_starting = false;
	}

	fn join_failed_peer_listener_startup(
		listen_peers_thread: JoinHandle<Result<(), mwc_p2p::Error>>,
		startup_error: String,
	) -> Error {
		match listen_peers_thread.join() {
			Ok(Err(e)) => Error::ServerError(format!("Failed to start p2p server, {}", e)),
			Ok(Ok(())) => {
				Error::ServerError(format!("Failed to start p2p server, {}", startup_error))
			}
			Err(e) => Error::ServerError(format!(
				"Failed to start p2p server, {}; p2p listener thread panicked: {:?}",
				startup_error, e
			)),
		}
	}

	/// Starting node rest API, needed for communication with mwc-wallet
	pub fn start_rest_api(&mut self) -> Result<(), Error> {
		if self.api_thread.is_some() || self.api_monitor_thread.is_some() {
			return Err(Error::ServerError("rest api is already running".into()));
		}

		info!("Starting rest apis at: {}", &self.config.api_http_addr);
		let api_secret = get_owner_only_first_line_zeroizing(self.config.api_secret_path.clone())
			.map_err(|e| Error::Config(format!("Unable to read API secret, {}", e)))?;
		let foreign_api_secret =
			get_owner_only_first_line_zeroizing(self.config.foreign_api_secret_path.clone())
				.map_err(|e| Error::Config(format!("Unable to read foreign API secret, {}", e)))?;
		// TLS is intentionally controlled by configuration. Node operators choose
		// the transport security level that is appropriate for their deployment.
		let tls_conf = build_tls_config(&self.config)?;

		let api_threads = mwc_api::node_apis(
			&self.config.api_http_addr,
			self.chain.clone(),
			self.tx_pool.clone(),
			self.p2p.peers.clone(),
			self.sync_state.clone(),
			api_secret,
			foreign_api_secret,
			tls_conf,
			self.stratum_ip_pool.clone(),
			self.stop_state.clone(),
		)
		.map_err(|e| Error::ServerError(format!("Node API starting error, {}", e)))?;

		self.api_thread = Some(api_threads.api_thread);
		self.api_monitor_thread = Some(api_threads.api_monitor_thread);
		Ok(())
	}

	/// Build router for Lib related API. Note, secrets for all APIs are None
	pub fn build_api_router_no_secrets(&self) -> Result<Router, Error> {
		let route = mwc_api::build_node_router(
			self.chain.clone(),
			self.tx_pool.clone(),
			self.p2p.peers.clone(),
			self.sync_state.clone(),
			None,
			None,
			self.stratum_ip_pool.clone(),
			self.stop_state.clone(),
		)
		.map_err(|e| Error::ServerError(format!("Failed to build node router, {}", e)))?;

		Ok(route)
	}

	/// Start dandelion protocol. Needed for publishing transactions
	pub fn start_dandelion(&mut self) -> Result<(), Error> {
		if self.dandelion_thread.is_some() {
			return Err(Error::ServerError(
				"dandelion monitor is already running".into(),
			));
		}

		info!("Starting dandelion monitor...");
		let dandelion_thread = dandelion_monitor::monitor_transactions(
			self.config.dandelion_config.clone(),
			self.tx_pool.clone(),
			self.pool_net_adapter.clone(),
			self.stop_state.clone(),
		)
		.map_err(|e| Error::ServerError(format!("Dandellion starting error, {}", e)))?;
		self.dandelion_thread = Some(dandelion_thread);
		Ok(())
	}

	// Exclusive (advisory) lock_file to ensure we do not run multiple
	// instance of mwc server from the same dir.
	// This uses fs2 and should be safe cross-platform unless somebody abuses the file itself.
	fn one_mwc_at_a_time(config: &ServerConfig) -> Result<Arc<File>, Error> {
		let path = Path::new(&config.db_root);
		fs::create_dir_all(&path).map_err(|e| {
			Error::ServerError(format!(
				"Unable to create data directory {}, {}",
				path.to_str().unwrap_or("<Unknown>"),
				e
			))
		})?;
		let path = path.join("mwc.lock");
		let lock_file = fs::OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.open(&path)
			.map_err(|e| {
				Error::ServerError(format!(
					"Unable to create lock file {}, {}",
					path.to_str().unwrap_or("<Unknown>"),
					e
				))
			})?;
		lock_file
			.try_lock_exclusive()
			.map_err(|e| {
				let mut stderr = std::io::stderr();
				_ = writeln!(
					&mut stderr,
					"Failed to lock {:?} (mwc server already running?)",
					path
				);
				e
			})
			.map_err(|e| {
				Error::ServerError(format!(
					"Unable to get a lock for file {}, {}",
					path.to_str().unwrap_or("<Unknown>"),
					e
				))
			})?;
		Ok(Arc::new(lock_file))
	}

	/// Number of peers
	pub fn peer_count(&self) -> usize {
		self.p2p.peers.iter().connected().count()
	}

	/// Start a minimal "stratum" mining service on a separate thread
	/// Returns ip_pool that needed for stratum API
	fn start_stratum_server(&mut self, config: StratumServerConfig) -> Result<(), Error> {
		if self.stratum_thread.is_some() {
			return Err(Error::ServerError("Startum is already running".into()));
		}

		let mut stratum_server = stratumserver::StratumServer::new(
			config,
			self.chain.clone(),
			self.tx_pool.clone(),
			self.state_info.stratum_stats.clone(),
			self.stratum_ip_pool.clone(),
			self.sync_state.clone(),
			self.stop_state.clone(),
		);

		let proof_size = global::proofsize(self.p2p.get_context_id());
		let (startup_tx, startup_rx) = mpsc::channel();
		stratum_server.set_startup_status_tx(startup_tx);
		let stratum_thread = thread::Builder::new()
			.name("stratum_server".to_string())
			.spawn(move || stratum_server.run_loop(proof_size))
			.map_err(|e| Error::ServerError(format!("Unable to start stratum thread, {}", e)))?;

		match startup_rx.recv() {
			Ok(Ok(())) => {
				// The stratum thread can still return an error after startup has
				// succeeded. That result is intentionally deferred until shutdown:
				// server services are started only once by this manager, and callers
				// do not need a runtime restart/running-state contract for stratum.
				self.stratum_thread = Some(stratum_thread);
				Ok(())
			}
			Ok(Err(e)) => Err(Self::join_failed_stratum_startup(stratum_thread, e)),
			Err(e) => Err(Self::join_failed_stratum_startup(
				stratum_thread,
				format!("stratum startup status channel closed, {}", e),
			)),
		}
	}

	fn join_failed_stratum_startup(
		stratum_thread: JoinHandle<Result<(), Error>>,
		startup_error: String,
	) -> Error {
		match stratum_thread.join() {
			Ok(Err(e)) => e,
			Ok(Ok(())) => {
				Error::ServerError(format!("Unable to start stratum server, {}", startup_error))
			}
			Err(e) => Error::ServerError(format!(
				"Unable to start stratum server, {}; stratum thread panicked: {:?}",
				startup_error, e
			)),
		}
	}

	/// The chain head
	pub fn head(&self) -> Result<mwc_chain::Tip, Error> {
		self.chain
			.head()
			.map_err(|e| Error::ServerError(format!("Get chain head error, {}", e)))
	}

	/// The head of the block header chain
	pub fn header_head(&self) -> Result<mwc_chain::Tip, Error> {
		self.chain
			.header_head()
			.map_err(|e| Error::ServerError(format!("Get chain header head error, {}", e)))
	}

	/// The p2p layer protocol version for this node.
	pub fn protocol_version() -> ProtocolVersion {
		ProtocolVersion::local()
	}

	/// Returns a set of stats about this server. This and the ServerStats
	/// structure
	/// can be updated over time to include any information needed by tests or
	/// other consumers
	pub fn get_server_stats(&self) -> Result<ServerStats, Error> {
		// Fill out stats on our current difficulty calculation
		// TODO: check the overhead of calculating this again isn't too much
		// could return it from next_difficulty, but would rather keep consensus
		// code clean. This may be handy for testing but not really needed
		// for release
		let diff_stats = {
			let mut cache_values = consensus::DifficultyCache::new();
			let last_blocks: Vec<consensus::HeaderDifficultyInfo> =
				global::difficulty_data_to_vector(
					self.p2p.get_context_id(),
					self.chain.difficulty_iter().map_err(|e| {
						Error::ServerError(format!("Chain data access error, {}", e))
					})?,
					&mut cache_values,
				)
				.map_err(|e| Error::ServerError(format!("Difficulty data error, {}", e)))?
				.into_iter()
				.collect();

			let tip_height = self.head()?.height;
			// difficulty_data_to_vector pads early chains to a full difficulty window.
			// Clamp synthetic history to the current tip instead of failing stats.
			let displayed_blocks = last_blocks.len().saturating_sub(1) as u64;

			let diff_entries: Vec<DiffBlock> = last_blocks
				.windows(2)
				.enumerate()
				.map(|(idx, pair)| {
					let prev = &pair[0];
					let next = &pair[1];

					let block_hash = next.hash.unwrap_or(ZERO_HASH);
					let height_lag = displayed_blocks
						.saturating_sub(1)
						.saturating_sub(idx as u64);

					DiffBlock {
						block_height: tip_height.saturating_sub(height_lag),
						block_hash,
						difficulty: next.difficulty.to_num(),
						time: next.timestamp,
						duration: next.timestamp - prev.timestamp,
						secondary_scaling: next.secondary_scaling,
						is_secondary: next.is_secondary,
					}
				})
				.collect();

			let block_time_sum = diff_entries.iter().fold(0, |sum, t| sum + t.duration);
			let block_diff_sum: u128 = diff_entries.iter().map(|d| u128::from(d.difficulty)).sum();
			let average_difficulty =
				block_diff_sum / u128::from(consensus::DIFFICULTY_ADJUST_WINDOW - 1);
			let average_difficulty = u64::try_from(average_difficulty).map_err(|_| {
				Error::DataOverflow(format!(
					"Difficulty stats average difficulty {} exceeds u64::MAX",
					average_difficulty
				))
			})?;
			DiffStats {
				height: tip_height,
				last_blocks: diff_entries,
				average_block_time: block_time_sum / (consensus::DIFFICULTY_ADJUST_WINDOW - 1),
				average_difficulty,
				window_size: consensus::DIFFICULTY_ADJUST_WINDOW,
			}
		};

		let peer_stats = self
			.p2p
			.peers
			.iter()
			.connected()
			.into_iter()
			.map(|p| PeerStats::from_peer(&p))
			.collect();

		// Updating TUI stats should not block any other processing so only attempt to
		// acquire various read locks with a timeout.

		let tx_stats = {
			let pool = self.tx_pool.read_recursive();
			TxStats {
				tx_pool_size: pool.txpool.size(),
				tx_pool_kernels: pool.txpool.kernel_count(),
				stem_pool_size: pool.stempool.size(),
				stem_pool_kernels: pool.stempool.kernel_count(),
			}
		};

		let head = self
			.chain
			.head_header()
			.map_err(|e| Error::ServerError(format!("Chain header head access error, {}", e)))?;
		let head_stats = ChainStats {
			latest_timestamp: head.timestamp,
			height: head.height,
			last_block_h: head.hash(self.chain.get_context_id())?,
			total_difficulty: head.total_difficulty(),
		};

		let header_head = self
			.chain
			.header_head()
			.map_err(|e| Error::ServerError(format!("Chain header head access error, {}", e)))?;
		let header = self
			.chain
			.get_block_header(&header_head.hash(self.chain.get_context_id())?)
			.map_err(|e| Error::ServerError(format!("Chain block header access error, {}", e)))?;
		let header_stats = ChainStats {
			latest_timestamp: header.timestamp,
			height: header.height,
			last_block_h: header.hash(self.chain.get_context_id())?,
			total_difficulty: header.total_difficulty(),
		};

		let disk_usage_bytes = WalkDir::new(&self.config.db_root)
			.min_depth(1)
			.max_depth(3)
			.into_iter()
			.try_fold(0_u64, |acc, entry| -> Result<u64, Error> {
				let entry = entry
					.map_err(|e| Error::ServerError(format!("Disk usage walk error, {}", e)))?;
				let metadata = entry.metadata().map_err(|e| {
					Error::ServerError(format!(
						"Disk usage metadata access error for {}, {}",
						entry.path().display(),
						e
					))
				})?;

				if metadata.is_file() {
					Ok(acc.saturating_add(metadata.len()))
				} else {
					Ok(acc)
				}
			})?;

		let disk_usage_gb = format!("{:.*}", 3, (disk_usage_bytes as f64 / 1_000_000_000_f64));

		Ok(ServerStats {
			peer_count: self.peer_count(),
			chain_stats: head_stats,
			header_stats: header_stats,
			sync_status: self.sync_state.status(),
			disk_usage_gb: disk_usage_gb,
			stratum_stats: self.state_info.stratum_stats.clone(),
			peer_stats: peer_stats,
			diff_stats: diff_stats,
			tx_stats: Some(tx_stats),
		})
	}

	/// Stop the server.
	pub fn stop(self) {
		self.sync_state.update(SyncStatus::Shutdown);
		self.stop_state.stop();

		// Shutdown is best effort once the server is being consumed. Thread joins,
		// service shutdowns, p2p stop, and lock release can fail independently; with
		// this stop(self) API the best we can do is log each error and keep trying to
		// release the remaining resources.
		//
		// Stop p2p before waiting on the seed/listener threads. The seed monitor can
		// be joining outbound peer_connect workers, including Tor connects. Stopping
		// p2p first cancels those workers and stops active peers from continuing to
		// process sync traffic during shutdown.
		if let Err(e) = self.p2p.stop() {
			error!("failed to stop p2p server: {}", e);
		}
		Self::wait_for_thread(self.connect_thread, "connect_thread");
		Self::wait_for_thread(self.sync_thread, "sync_thread");
		Self::wait_for_thread(self.dandelion_thread, "dandelion_thread");
		Self::wait_for_result_thread(self.stratum_thread, "stratum_thread");
		Self::wait_for_thread(
			self.connect_and_monitor_thread,
			"connect_and_monitor_thread",
		);
		Self::wait_for_result_thread(self.listen_peers_thread, "listen_peers_thread");
		Self::wait_for_result_thread(self.api_monitor_thread, "api_monitor_thread");
		Self::wait_for_thread(self.api_thread, "api_thread");

		if let Err(e) = FileExt::unlock(&*self.lock_file) {
			error!("failed to unlock server lock file: {}", e);
		}
		warn!("Shutdown complete");
	}

	// Thread waits follow the same best-effort shutdown policy as Server::stop:
	// join failures are logged because the caller is already using best-effort
	// shutdown and has no useful recovery path for these background threads.
	fn wait_for_thread(thread: Option<JoinHandle<()>>, thread_name: &str) {
		if let Some(sync_thread) = thread {
			match sync_thread.join() {
				Err(e) => error!("failed to join to thread {}: {:?}", thread_name, e),
				Ok(_) => info!("{} thread is stopped", thread_name),
			}
		}
	}

	fn wait_for_result_thread<E: std::fmt::Display>(
		thread: Option<JoinHandle<Result<(), E>>>,
		thread_name: &str,
	) {
		if let Some(sync_thread) = thread {
			match sync_thread.join() {
				Err(e) => error!("failed to join to thread {}: {:?}", thread_name, e),
				Ok(Err(e)) => error!("{} thread failed: {}", thread_name, e),
				Ok(Ok(_)) => info!("{} thread is stopped", thread_name),
			}
		}
	}

	/// Resume p2p server.
	/// TODO - We appear not to resume the p2p server (peer connections) here?
	pub fn resume(&self) {
		self.stop_state.resume();
	}

	/// Stops the test miner without stopping the p2p layer
	pub fn stop_test_miner(&self, stop: Arc<StopState>) {
		stop.stop();
		info!("stop_test_miner - stop",);
	}
}

fn build_tls_config(config: &ServerConfig) -> Result<Option<TLSConfig>, Error> {
	match (
		config.tls_certificate_file.clone(),
		config.tls_certificate_key.clone(),
	) {
		(None, None) => Ok(None),
		(Some(file), Some(key)) => Ok(Some(TLSConfig::new(file, key))),
		(Some(_), None) => Err(Error::Config(
			"Private key for certificate is not set".into(),
		)),
		(None, Some(_)) => Err(Error::Config("Certificate file is not set".into())),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn build_tls_config_without_certificate_or_key_disables_tls() {
		let config = ServerConfig {
			tls_certificate_file: None,
			tls_certificate_key: None,
			..ServerConfig::default()
		};

		assert!(build_tls_config(&config).unwrap().is_none());
	}

	#[test]
	fn build_tls_config_with_certificate_and_key_enables_tls() {
		let config = ServerConfig {
			tls_certificate_file: Some("cert.pem".to_string()),
			tls_certificate_key: Some("key.pem".to_string()),
			..ServerConfig::default()
		};

		let tls_config = build_tls_config(&config).unwrap().unwrap();
		assert_eq!(tls_config.certificate, "cert.pem");
		assert_eq!(tls_config.private_key, "key.pem");
	}

	#[test]
	fn build_tls_config_rejects_certificate_without_key() {
		let config = ServerConfig {
			tls_certificate_file: Some("cert.pem".to_string()),
			tls_certificate_key: None,
			..ServerConfig::default()
		};

		match build_tls_config(&config) {
			Err(Error::Config(msg)) => assert_eq!(msg, "Private key for certificate is not set"),
			other => panic!("expected certificate key config error, got {:?}", other),
		}
	}

	#[test]
	fn build_tls_config_rejects_key_without_certificate() {
		let config = ServerConfig {
			tls_certificate_file: None,
			tls_certificate_key: Some("key.pem".to_string()),
			..ServerConfig::default()
		};

		match build_tls_config(&config) {
			Err(Error::Config(msg)) => assert_eq!(msg, "Certificate file is not set"),
			other => panic!("expected certificate file config error, got {:?}", other),
		}
	}

	#[test]
	fn create_server_rejects_invalid_dandelion_config() {
		let secp = Secp256k1::with_caps(mwc_crates::secp::ContextFlag::Commit).unwrap();
		let mut config = ServerConfig::default();
		config.dandelion_config.stem_probability = 101;

		match Server::create_server(&secp, 0, config) {
			Err(Error::Config(msg)) => {
				assert!(msg.contains("stem_probability"));
				assert!(msg.contains("0..=100"));
			}
			Err(e) => panic!("expected dandelion config error, got {}", e),
			Ok(_) => panic!("expected dandelion config error"),
		}
	}
}
