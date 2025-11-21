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

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::sync::Arc;
use std::sync::{mpsc, RwLock};
use std::{convert::TryInto, fs};
use std::{
	thread::{self, JoinHandle},
	time,
};

use fs2::FileExt;
use walkdir::WalkDir;

use crate::api;
use crate::api::TLSConfig;
use crate::chain::{self, SyncState, SyncStatus};
use crate::common::adapters::{
	ChainToPoolAndNetAdapter, NetToChainAdapter, PoolToChainAdapter, PoolToNetAdapter,
};
use crate::common::hooks::{init_chain_hooks, init_net_hooks};
use crate::common::stats::{
	ChainStats, DiffBlock, DiffStats, PeerStats, ServerStateInfo, ServerStats, TxStats,
};
use crate::common::types::{ServerConfig, StratumServerConfig};
use crate::core::core::hash::{Hashed, ZERO_HASH};
use crate::core::ser::ProtocolVersion;
use crate::core::stratum::connections;
use crate::core::{consensus, genesis, global, pow};
use crate::mining::stratumserver;
use crate::mining::test_miner::Miner;
use crate::mwc::{dandelion_monitor, seed, sync};
use crate::p2p;
use crate::pool;
use crate::util::file::get_first_line;
use crate::util::StopState;
use crate::Error;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::Ordering;

use crate::mwc::sync::sync_manager::SyncManager;
#[cfg(feature = "libp2p")]
use crate::p2p::libp2p_connection;
#[cfg(feature = "libp2p")]
use chrono::Utc;
use mwc_api::Router;
use mwc_core::consensus::HeaderDifficultyInfo;
#[cfg(feature = "libp2p")]
use mwc_core::core::TxKernel;
use mwc_p2p::Capabilities;
#[cfg(feature = "libp2p")]
use mwc_util::from_hex;
#[cfg(feature = "libp2p")]
use mwc_util::secp::constants::SECRET_KEY_SIZE;
#[cfg(feature = "libp2p")]
use mwc_util::secp::pedersen::Commitment;
#[cfg(feature = "libp2p")]
use std::collections::HashMap;

/// Arcified  thread-safe TransactionPool with type parameters used by server components
pub type ServerTxPool = Arc<RwLock<pool::TransactionPool<PoolToChainAdapter, PoolToNetAdapter>>>;

/// Mwc server holding internal structures.
pub struct Server {
	/// server config
	pub config: ServerConfig,
	/// handle to our network server
	pub p2p: Arc<p2p::Server>,
	/// data store access
	pub chain: Arc<chain::Chain>,
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
	stratum_thread: Option<JoinHandle<()>>,
	miner_thread: Option<JoinHandle<()>>,
	connect_and_monitor_thread: Option<JoinHandle<()>>,
	listen_peers_thread: Option<JoinHandle<()>>,
	api_thread: Option<JoinHandle<()>>,

	// Stratum pool
	stratum_ip_pool: Arc<connections::StratumIpPool>,
	// Sync manager (shared between running services)
	sync_manager: Arc<SyncManager>,
	// Tx pool vs network adapter
	pool_net_adapter: Arc<PoolToNetAdapter>,
}

impl Server {
	/// Create a new server instance. No jobs will be started
	pub fn create_server(context_id: u32, config: ServerConfig) -> Result<Self, Error> {
		let mining_config = config.stratum_mining_config.clone();

		let (ban_action_limit, shares_weight, connection_pace_ms) = match mining_config.clone() {
			Some(c) => (c.ban_action_limit, c.shares_weight, c.connection_pace_ms),
			None => {
				let c = StratumServerConfig::default();
				(c.ban_action_limit, c.shares_weight, c.connection_pace_ms)
			}
		};

		let stratum_ip_pool = Arc::new(connections::StratumIpPool::new(
			ban_action_limit,
			shares_weight,
			connection_pace_ms,
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
		let tx_pool = Arc::new(RwLock::new(pool::TransactionPool::new(
			context_id,
			config.pool_config.clone(),
			pool_adapter.clone(),
			pool_net_adapter.clone(),
		)));

		let sync_state = Arc::new(SyncState::new());
		// Defaults to None (optional) in config file.
		// This translates to false here so we do not skip by default.
		sync_state.update(SyncStatus::AwaitingPeers);

		let chain_adapter = Arc::new(ChainToPoolAndNetAdapter::new(
			tx_pool.clone(),
			init_chain_hooks(&config),
		));

		let genesis = match config.chain_type {
			global::ChainTypes::AutomatedTesting => pow::mine_genesis_block(context_id).unwrap(),
			global::ChainTypes::UserTesting => pow::mine_genesis_block(context_id).unwrap(),
			global::ChainTypes::Floonet => genesis::genesis_floo(context_id),
			global::ChainTypes::Mainnet => genesis::genesis_main(context_id),
		};

		info!("Starting server, genesis block: {}", genesis.hash());

		let shared_chain = Arc::new(
			chain::Chain::init(
				context_id,
				config.db_root.clone(),
				chain_adapter.clone(),
				genesis.clone(),
				pow::verify_size,
				archive_mode,
			)
			.map_err(|e| Error::ServerError(format!("Unable to read blockchain data, {}", e)))?,
		);

		pool_adapter.set_chain(shared_chain.clone());

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
			config.clone(),
			init_net_hooks(&config),
		));

		// Initialize our capabilities.
		// Currently either "default" or with optional "archive_mode" (block history) support enabled.
		let use_tor = config.tor_config.is_tor_enabled();
		let capabilities = Capabilities::new(use_tor, config.archive_mode.unwrap_or(false));
		debug!("Capabilities: {:?}", capabilities);

		let p2p_server = Arc::new(
			p2p::Server::new(
				context_id,
				&config.db_root,
				capabilities,
				&config.p2p_config,
				&config.tor_config,
				net_adapter.clone(),
				genesis.hash(),
				sync_state.clone(),
				stop_state.clone(),
			)
			.map_err(|e| Error::ServerError(e.to_string()))?,
		);

		// Initialize various adapters with our dynamic set of connected peers.
		chain_adapter.init(p2p_server.peers.clone());
		pool_net_adapter.init(p2p_server.peers.clone());
		net_adapter.init(p2p_server.peers.clone());

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
			miner_thread: None,
			connect_and_monitor_thread: None,
			listen_peers_thread: None,
			api_thread: None,
			stratum_ip_pool,
			sync_manager,
			pool_net_adapter,
		})
	}

	/// Start Stratum protocol, needed for the mining
	pub fn start_stratum(&mut self) -> Result<(), Error> {
		let mining_config = self.config.stratum_mining_config.clone();
		if let Some(c) = mining_config {
			let enable_stratum_server = c.enable_stratum_server;
			if let Some(s) = enable_stratum_server {
				if s {
					self.state_info
						.stratum_stats
						.is_enabled
						.store(true, Ordering::Relaxed);
					self.start_stratum_server(c)?;
				}
			}
		}

		let enable_test_miner = self.config.run_test_miner;
		let test_miner_wallet_url = self.config.test_miner_wallet_url.clone();

		if let Some(s) = enable_test_miner {
			if s {
				self.start_test_miner(test_miner_wallet_url)?;
			}
		}
		Ok(())
	}

	/// Start pees discovery p2p peers job
	pub fn start_discover_peers(&mut self) -> Result<(), Error> {
		if self.config.p2p_config.seeding_type != p2p::Seeding::Programmatic {
			let seed_list = match self.config.p2p_config.seeding_type {
				p2p::Seeding::None => {
					warn!("No seed configured, will stay solo until connected to");
					seed::predefined_seeds(vec![])
				}
				p2p::Seeding::List => match &self.config.p2p_config.seeds {
					Some(seeds) => seed::predefined_seeds(seeds.peers.clone()),
					None => {
						return Err(Error::ServerError(
							"Seeds must be configured for seeding type List".to_owned(),
						));
					}
				},
				p2p::Seeding::DNSSeed => seed::default_dns_seeds(self.chain.get_context_id()),
				_ => unreachable!(),
			};

			let connect_thread = seed::connect_and_monitor(
				self.p2p.clone(),
				seed_list,
				self.config.p2p_config.clone(),
				self.stop_state.clone(),
				self.config.tor_config.is_tor_enabled(),
			)
			.map_err(|e| Error::ServerError(format!("Unable to start monitoring, {}", e)))?;

			self.connect_and_monitor_thread = Some(connect_thread);
		}
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
	pub fn start_listen_peers(&mut self) -> Result<(), Error> {
		let p2p_inner = self.p2p.clone();
		let (p2p_tx, p2p_rx) = mpsc::sync_channel::<Result<(), mwc_p2p::Error>>(1);
		let listen_peers_thread = thread::Builder::new()
			.name("p2p-server".to_string())
			.spawn(move || {
				if let Err(e) = p2p_inner.listen(p2p_tx) {
					// QW wallet using for tracking
					error!("P2P server failed with erorr: {:?}", e);
				}
			})
			.map_err(|e| Error::ServerError(format!("Listen job is failed, {}", e)))?;
		// waiting until p2p server was able to init
		let p2p_start_result = p2p_rx
			.recv()
			.map_err(|e| Error::ServerError(format!("Brocken  mpsc::sync_channel, {}", e)))?;
		p2p_start_result
			.map_err(|e| Error::ServerError(format!("Failed to start p2p server, {}", e)))?;

		self.listen_peers_thread = Some(listen_peers_thread);

		Ok(())
	}

	/// Starting node rest API, needed for communication with mwc-wallet
	pub fn start_rest_api(&mut self) -> Result<(), Error> {
		info!("Starting rest apis at: {}", &self.config.api_http_addr);
		let api_secret = get_first_line(self.config.api_secret_path.clone());
		let foreign_api_secret = get_first_line(self.config.foreign_api_secret_path.clone());
		let tls_conf = match self.config.tls_certificate_file.clone() {
			None => None,
			Some(file) => {
				let key = match self.config.tls_certificate_key.clone() {
					Some(k) => k,
					None => {
						return Err(Error::Config(
							"Private key for certificate is not set".into(),
						));
					}
				};
				Some(TLSConfig::new(file, key))
			}
		};

		// TODO fix API shutdown and join this thread
		let api_thread = api::node_apis(
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

		self.api_thread = Some(api_thread);
		Ok(())
	}

	/// Build router for Lib related API. Note, secrets for all APIs are None
	pub fn build_api_router_no_secrets(&self) -> Result<Router, Error> {
		let route = api::build_node_router(
			self.chain.clone(),
			self.tx_pool.clone(),
			self.p2p.peers.clone(),
			self.sync_state.clone(),
			None,
			None,
			self.stratum_ip_pool.clone(),
		)
		.map_err(|e| Error::ServerError(format!("Failed to build node router, {}", e)))?;

		Ok(route)
	}

	/// Start dandelion protocol. Needed for publishing transactions
	pub fn start_dandelion(&mut self) -> Result<(), Error> {
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

	// Lib p2p currently is disabled, just storing the code here
	#[cfg(feature = "libp2p")]
	pub fn start_libp2p_node(&self) {
		// if config.libp2p_enabled.unwrap_or(true) && onion_address.is_some() && tor_secret.is_some()

		let onion_address = onion_address.clone().unwrap();
		let tor_secret = tor_secret.unwrap();
		let tor_secret = from_hex(&tor_secret).map_err(|e| {
			Error::General(format!("Unable to parse secret hex {}, {}", tor_secret, e))
		})?;

		let libp2p_port = config.libp2p_port;
		let tor_socks_port = config.tor_config.socks_port;
		let fee_base = config.pool_config.tx_fee_base;
		api::set_server_onion_address(&onion_address);

		let clone_shared_chain = shared_chain.clone();
		let libp2p_topics = config
			.libp2p_topics
			.clone()
			.unwrap_or(vec!["SwapMarketplace".to_string()]);

		thread::Builder::new()
			.name("libp2p_node".to_string())
			.spawn(move || {
				let requested_kernel_cache: RwLock<HashMap<Commitment, (TxKernel, u64)>> =
					RwLock::new(HashMap::new());
				let last_time_cache_cleanup: RwLock<i64> = RwLock::new(0);

				let output_validation_fn =
					move |excess: &Commitment| -> Result<Option<TxKernel>, mwc_p2p::Error> {
						// Tip is needed in order to request from last 24 hours (1440 blocks)
						let tip_height = clone_shared_chain.head()?.height;

						let cur_time = Utc::now().timestamp();
						// let's clean cache every 10 minutes. Removing all expired items
						{
							let mut last_time_cache_cleanup = last_time_cache_cleanup.write();
							if cur_time - 600 > *last_time_cache_cleanup {
								let min_height = tip_height
									- libp2p_connection::INTEGRITY_FEE_VALID_BLOCKS
									- libp2p_connection::INTEGRITY_FEE_VALID_BLOCKS / 12;
								requested_kernel_cache
									.write()
									.retain(|_k, v| v.1 > min_height);
								*last_time_cache_cleanup = cur_time;
							}
						}

						// Checking if we hit the cache
						if let Some(tx) = requested_kernel_cache.read().get(excess) {
							return Ok(Some(tx.clone().0));
						}

						// !!! Note, get_kernel_height does iteration through the MMR. That will work until we
						// Ban nodes that sent us incorrect excess. For now it should work fine. Normally
						// peers reusing the integrity kernels so cache hit should happen most of the time.
						match clone_shared_chain.get_kernel_height(
							excess,
							Some(tip_height - libp2p_connection::INTEGRITY_FEE_VALID_BLOCKS),
							None,
						)? {
							Some((tx_kernel, height, _)) => {
								requested_kernel_cache
									.write()
									.insert(excess.clone(), (tx_kernel.clone(), height));
								Ok(Some(tx_kernel))
							}
							None => Ok(None),
						}
					};

				let mut secret: [u8; SECRET_KEY_SIZE] = [0; SECRET_KEY_SIZE];
				secret.copy_from_slice(&tor_secret);

				let validation_fn = Arc::new(output_validation_fn);

				let libp2p_stopper = Arc::new(std::sync::Mutex::new(1));

				loop {
					for t in &libp2p_topics {
						libp2p_connection::add_topic(t, 1);
					}

					let libp2p_node_runner = libp2p_connection::run_libp2p_node(
						tor_socks_port,
						&secret,
						libp2p_port.unwrap_or(3417),
						fee_base,
						validation_fn.clone(),
						libp2p_stopper.clone(), // passing new obj, because we never will stop the libp2p process
					);

					info!("Starting gossipsub libp2p server");
					let rt = tokio::runtime::Runtime::new().unwrap();

					match rt.block_on(libp2p_node_runner) {
						Ok(_) => info!("libp2p node is exited"),
						Err(e) => error!("Unable to start libp2p node, {}", e),
					}
					// Swarm is not valid any more, let's update our global instance.
					libp2p_connection::reset_libp2p_swarm();

					if *libp2p_stopper.lock().unwrap() == 0 {
						// Should never happen for the node
						debug_assert!(false);
						break;
					}
				}
			})?;

		// TODO store thread handle in the server, wait for thread at stopping
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
				writeln!(
					&mut stderr,
					"Failed to lock {:?} (mwc server already running?)",
					path
				)
				.expect("Could not write to stderr");
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

	/// Ping all peers, mostly useful for tests to have connected peers share
	/// their heights
	pub fn ping_peers(&self) -> Result<(), Error> {
		let head = self
			.chain
			.head()
			.map_err(|e| Error::ServerError(format!("Get chain tip error, {}", e)))?;
		self.p2p.peers.check_all(head.total_difficulty, head.height);
		Ok(())
	}

	/// Number of peers
	pub fn peer_count(&self) -> u32 {
		self.p2p
			.peers
			.iter()
			.connected()
			.count()
			.try_into()
			.unwrap()
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
		let stratum_thread = thread::Builder::new()
			.name("stratum_server".to_string())
			.spawn(move || {
				stratum_server.run_loop(proof_size);
			})
			.map_err(|e| Error::ServerError(format!("Unable to start stratum thread, {}", e)))?;
		self.stratum_thread = Some(stratum_thread);
		Ok(())
	}

	/// Start mining for blocks internally on a separate thread. Relies on
	/// internal miner, and should only be used for automated testing. Burns
	/// reward if wallet_listener_url is 'None'
	fn start_test_miner(&mut self, wallet_listener_url: Option<String>) -> Result<(), Error> {
		if self.miner_thread.is_some() {
			return Err(Error::ServerError("test miner is already running".into()));
		}
		info!("start_test_miner - start",);
		let sync_state = self.sync_state.clone();
		let config_wallet_url = match wallet_listener_url.clone() {
			Some(u) => u,
			None => String::from("http://127.0.0.1:13415"),
		};

		let config = StratumServerConfig {
			attempt_time_per_block: 60,
			burn_reward: false,
			enable_stratum_server: None,
			stratum_server_addr: None,
			wallet_listener_url: config_wallet_url,
			minimum_share_difficulty: 1,
			ip_tracking: false,
			workers_connection_limit: 30000,
			ban_action_limit: 5,
			shares_weight: 5,
			worker_login_timeout_ms: -1,
			ip_pool_ban_history_s: 3600,
			connection_pace_ms: -1,
			ip_white_list: HashSet::new(),
			ip_black_list: HashSet::new(),
		};

		let mut miner = Miner::new(
			config,
			self.chain.clone(),
			self.tx_pool.clone(),
			self.stop_state.clone(),
			sync_state,
		);
		miner.set_debug_output_id(format!("Port {}", self.config.p2p_config.port));
		let miner_thread = thread::Builder::new()
			.name("test_miner".to_string())
			.spawn(move || miner.run_loop(wallet_listener_url))
			.map_err(|e| {
				Error::ServerError(format!("Unable to start the test miner thread, {}", e))
			})?;

		self.miner_thread = Some(miner_thread);
		Ok(())
	}

	/// The chain head
	pub fn head(&self) -> Result<chain::Tip, Error> {
		self.chain
			.head()
			.map_err(|e| Error::ServerError(format!("Get chain head error, {}", e)))
	}

	/// The head of the block header chain
	pub fn header_head(&self) -> Result<chain::Tip, Error> {
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
			let mut cache_values: VecDeque<HeaderDifficultyInfo> = VecDeque::new();
			let last_blocks: Vec<consensus::HeaderDifficultyInfo> =
				global::difficulty_data_to_vector(
					self.p2p.get_context_id(),
					self.chain.difficulty_iter().map_err(|e| {
						Error::ServerError(format!("Chain data access error, {}", e))
					})?,
					&mut cache_values,
				)
				.into_iter()
				.collect();

			let tip_height = self.head()?.height as i64;
			let mut height = tip_height as i64 - last_blocks.len() as i64 + 1;

			let diff_entries: Vec<DiffBlock> = last_blocks
				.windows(2)
				.map(|pair| {
					let prev = &pair[0];
					let next = &pair[1];

					height += 1;

					let block_hash = next.hash.unwrap_or(ZERO_HASH);

					DiffBlock {
						block_height: height,
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
			let block_diff_sum = diff_entries.iter().fold(0, |sum, d| sum + d.difficulty);
			DiffStats {
				height: height as u64,
				last_blocks: diff_entries,
				average_block_time: block_time_sum / (consensus::DIFFICULTY_ADJUST_WINDOW - 1),
				average_difficulty: block_diff_sum / (consensus::DIFFICULTY_ADJUST_WINDOW - 1),
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
			let pool = self.tx_pool.read().expect("RwLock failure");
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
			last_block_h: head.hash(),
			total_difficulty: head.total_difficulty(),
		};

		let header_head = self
			.chain
			.header_head()
			.map_err(|e| Error::ServerError(format!("Chain header head access error, {}", e)))?;
		let header = self
			.chain
			.get_block_header(&header_head.hash())
			.map_err(|e| Error::ServerError(format!("Chain block header access error, {}", e)))?;
		let header_stats = ChainStats {
			latest_timestamp: header.timestamp,
			height: header.height,
			last_block_h: header.hash(),
			total_difficulty: header.total_difficulty(),
		};

		let disk_usage_bytes = WalkDir::new(&self.config.db_root)
			.min_depth(1)
			.max_depth(3)
			.into_iter()
			.filter_map(|entry| entry.ok())
			.filter_map(|entry| entry.metadata().ok())
			.filter(|metadata| metadata.is_file())
			.fold(0, |acc, m| acc + m.len());

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

		Self::wait_for_thread(self.connect_thread, "connect_thread");
		Self::wait_for_thread(self.sync_thread, "sync_thread");
		Self::wait_for_thread(self.dandelion_thread, "dandelion_thread");
		Self::wait_for_thread(self.stratum_thread, "stratum_thread");
		Self::wait_for_thread(self.miner_thread, "miner_thread");
		Self::wait_for_thread(
			self.connect_and_monitor_thread,
			"connect_and_monitor_thread",
		);
		Self::wait_for_thread(self.listen_peers_thread, "listen_peers_thread");
		Self::wait_for_thread(self.api_thread, "api_thread");

		// this call is blocking and makes sure all peers stop, however
		// we can't be sure that we stopped a listener blocked on accept, so we don't join the p2p thread
		self.p2p.stop();
		let _ = FileExt::unlock(&*self.lock_file);
		warn!("Shutdown complete");
	}

	fn wait_for_thread(thread: Option<JoinHandle<()>>, thread_name: &str) {
		if let Some(sync_thread) = thread {
			match sync_thread.join() {
				Err(e) => error!("failed to join to thread {}: {:?}", thread_name, e),
				Ok(_) => info!("{} thread is stopped", thread_name),
			}
		}
	}

	/// Pause the p2p server.
	pub fn pause(&self) {
		self.stop_state.pause();
		thread::sleep(time::Duration::from_secs(1));
		self.p2p.pause();
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
