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

use crate::tor::config as tor_config;
use crate::util::secp;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;
use std::path::{Path, MAIN_SEPARATOR};
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::{convert::TryInto, fs};
use std::{
	thread::{self, JoinHandle},
	time::{self, Duration},
};

use fs2::FileExt;
use mwc_util::{static_secp_instance, to_hex, OnionV3Address};
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
use crate::common::types::{Error, ServerConfig, StratumServerConfig};
use crate::core::core::hash::{Hashed, ZERO_HASH};
use crate::core::ser::ProtocolVersion;
use crate::core::stratum::connections;
use crate::core::{consensus, genesis, global, pow};
use crate::mining::stratumserver;
use crate::mining::test_miner::Miner;
use crate::mwc::{dandelion_monitor, seed, sync};
use crate::p2p;
use crate::p2p::types::PeerAddr;
use crate::pool;
use crate::tor::process as tor_process;
use crate::util::file::get_first_line;
use crate::util::{RwLock, StopState};
use futures::channel::oneshot;
use mwc_util::logger::LogEntry;
use mwc_util::secp::SecretKey;
use std::collections::HashSet;
use std::sync::atomic::Ordering;

use crate::p2p::libp2p_connection;
use chrono::Utc;
use mwc_core::core::TxKernel;
use mwc_p2p::Capabilities;
use mwc_util::from_hex;
use mwc_util::secp::constants::SECRET_KEY_SIZE;
use mwc_util::secp::pedersen::Commitment;
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
	sync_thread: JoinHandle<()>,
	dandelion_thread: JoinHandle<()>,
}

impl Server {
	/// Instantiates and starts a new server. Optionally takes a callback
	/// for the server to send an ARC copy of itself, to allow another process
	/// to poll info about the server status
	pub fn start<F>(
		config: ServerConfig,
		logs_rx: Option<mpsc::Receiver<LogEntry>>,
		mut info_callback: F,
		allow_to_stop: bool,
		stop_state: Option<Arc<StopState>>,
		api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>),
	) -> Result<(), Error>
	where
		F: FnMut(Server, Option<mpsc::Receiver<LogEntry>>),
	{
		if let Some(hashes) = config.invalid_block_hashes.as_ref() {
			if hashes.len() > 0 {
				info!("config.invalid_block_hashes = {:?}", hashes);
			}
		}

		mwc_chain::pipe::init_invalid_lock_hashes(&config.invalid_block_hashes)?;

		let mining_config = config.stratum_mining_config.clone();
		let enable_test_miner = config.run_test_miner;
		let test_miner_wallet_url = config.test_miner_wallet_url.clone();

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
		let serv = Server::new(
			config,
			allow_to_stop,
			stratum_ip_pool.clone(),
			stop_state,
			api_chan,
		)?;

		if let Some(c) = mining_config {
			let enable_stratum_server = c.enable_stratum_server;
			if let Some(s) = enable_stratum_server {
				if s {
					{
						serv.state_info
							.stratum_stats
							.is_enabled
							.store(true, Ordering::Relaxed);
					}
					serv.start_stratum_server(c, stratum_ip_pool);
				}
			}
		}

		if let Some(s) = enable_test_miner {
			if s {
				serv.start_test_miner(test_miner_wallet_url, serv.stop_state.clone());
			}
		}

		info_callback(serv, logs_rx);
		Ok(())
	}

	// Exclusive (advisory) lock_file to ensure we do not run multiple
	// instance of mwc server from the same dir.
	// This uses fs2 and should be safe cross-platform unless somebody abuses the file itself.
	fn one_mwc_at_a_time(config: &ServerConfig) -> Result<Arc<File>, Error> {
		let path = Path::new(&config.db_root);
		fs::create_dir_all(&path)?;
		let path = path.join("mwc.lock");
		let lock_file = fs::OpenOptions::new()
			.read(true)
			.write(true)
			.create(true)
			.open(&path)?;
		lock_file.try_lock_exclusive().map_err(|e| {
			let mut stderr = std::io::stderr();
			writeln!(
				&mut stderr,
				"Failed to lock {:?} (mwc server already running?)",
				path
			)
			.expect("Could not write to stderr");
			e
		})?;
		Ok(Arc::new(lock_file))
	}

	// We don't want allow_to_stop in config because it is too dangerous flag. We don't
	// want to forget about that, make default e.t.c. That is why it is separated

	/// Instantiates a new server associated with the provided future reactor.
	pub fn new(
		config: ServerConfig,
		allow_to_stop: bool,
		stratum_ip_pool: Arc<connections::StratumIpPool>,
		stop_state: Option<Arc<StopState>>,
		api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>),
	) -> Result<Server, Error> {
		//let duration_sync_long = config.duration_sync_long.unwrap_or(150);
		//let duration_sync_short = config.duration_sync_short.unwrap_or(100);

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

		let stop_state = if stop_state.is_some() {
			stop_state.unwrap()
		} else {
			Arc::new(StopState::new())
		};

		let pool_adapter = Arc::new(PoolToChainAdapter::new());
		let pool_net_adapter = Arc::new(PoolToNetAdapter::new(config.dandelion_config.clone()));
		let tx_pool = Arc::new(RwLock::new(pool::TransactionPool::new(
			config.pool_config.clone(),
			pool_adapter.clone(),
			pool_net_adapter.clone(),
		)));

		let sync_state = Arc::new(SyncState::new());

		let chain_adapter = Arc::new(ChainToPoolAndNetAdapter::new(
			tx_pool.clone(),
			init_chain_hooks(&config),
		));

		let genesis = match config.chain_type {
			global::ChainTypes::AutomatedTesting => pow::mine_genesis_block().unwrap(),
			global::ChainTypes::UserTesting => pow::mine_genesis_block().unwrap(),
			global::ChainTypes::Floonet => genesis::genesis_floo(),
			global::ChainTypes::Mainnet => genesis::genesis_main(),
		};

		info!("Starting server, genesis block: {}", genesis.hash());

		let shared_chain = Arc::new(chain::Chain::init(
			config.db_root.clone(),
			chain_adapter.clone(),
			genesis.clone(),
			pow::verify_size,
			archive_mode,
		)?);

		pool_adapter.set_chain(shared_chain.clone());

		let net_adapter = Arc::new(NetToChainAdapter::new(
			sync_state.clone(),
			shared_chain.clone(),
			tx_pool.clone(),
			config.clone(),
			init_net_hooks(&config),
		));

		api::reset_server_onion_address();

		let (onion_address, tor_secret) = if config.tor_config.tor_enabled {
			if !config.p2p_config.host.is_loopback() {
				error!("If Tor is enabled, host must be '127.0.0.1'.");
				return Err(Error::Configuration(
					"If Tor is enabled, host must be '127.0.0.1'.".to_owned(),
				));
			}

			if !config.tor_config.tor_external {
				let stop_state_clone = stop_state.clone();
				let cloned_config = config.clone();

				let (input, output): (Sender<Option<String>>, Receiver<Option<String>>) =
					mpsc::channel();

				println!("Starting TOR, please wait...");

				thread::Builder::new()
					.name("tor_listener".to_string())
					.spawn(move || {
						let res = Server::init_tor_listener(
							&format!(
								"{}:{}",
								cloned_config.p2p_config.host, cloned_config.p2p_config.port
							),
							&cloned_config.api_http_addr,
							cloned_config.libp2p_port.unwrap_or(3417),
							Some(&cloned_config.db_root),
							cloned_config.tor_config.socks_port,
						);

						let _ = match res {
							Ok(res) => {
								let (listener, onion_address, secret) = res;
								input
									.send(Some(format!("{}.onion", onion_address.clone())))
									.unwrap();
								input.send(Some(to_hex(&secret.0))).unwrap();

								loop {
									std::thread::sleep(std::time::Duration::from_millis(10));
									if stop_state_clone.is_stopped() {
										break;
									}
								}
								Ok(listener)
							}
							Err(e) => {
								input.send(None).unwrap();
								error!("failed to start Tor due to {}", e);
								Err(crate::Error::TorConfig(format!(
									"Failed to init tor, {}",
									e
								)))
							}
						};
					})?;

				let resp = output.recv();
				info!("Finished with TOR");
				let onion_address = resp.unwrap_or(None);
				if onion_address.is_some() {
					info!("Tor successfully started: resp = {:?}", onion_address);
				} else {
					error!("Tor failed to start!");
					std::process::exit(-1);
				}
				let secret = output.recv().map_err(|e| {
					Error::General(format!("Unable to read the data from pipe, {}", e))
				})?;
				debug_assert!(secret.is_some());
				(onion_address, secret)
			} else {
				let onion_address = config.tor_config.onion_address.clone();

				if onion_address.is_none() {
					error!("onion_address must be specified with external tor. Halting!");
					std::process::exit(-1);
				}
				let otemp = onion_address.clone().unwrap();
				if otemp == "" {
					error!("onion_address must be specified with external tor. Halting!");
					std::process::exit(-1);
				}
				info!(
					"Tor configured to run externally! Onion address = {:?}.",
					otemp.clone()
				);
				(onion_address, None)
			}
		} else {
			(None, None)
		};

		let socks_port = if config.tor_config.tor_enabled {
			config.tor_config.socks_port
		} else {
			0
		};
		info!(
			"socks = {}, tor_enabled = {}",
			socks_port, config.tor_config.tor_enabled
		);

		// Initialize libp2p server
		if config.libp2p_enabled.unwrap_or(true) && onion_address.is_some() && tor_secret.is_some()
		{
			let onion_address = onion_address.clone().unwrap();
			let tor_secret = tor_secret.unwrap();
			let tor_secret = from_hex(&tor_secret).map_err(|e| {
				Error::General(format!("Unable to parse secret hex {}, {}", tor_secret, e))
			})?;

			let libp2p_port = config.libp2p_port;
			let tor_socks_port = config.tor_config.socks_port;
			let fee_base = config.pool_config.accept_fee_base;
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
						let mut rt = tokio::runtime::Runtime::new().unwrap();

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
		}

		// Initialize our capabilities.
		// Currently either "default" or with optional "archive_mode" (block history) support enabled.
		let capabilities = if let Some(true) = config.archive_mode {
			Capabilities::default() | Capabilities::BLOCK_HIST
		} else {
			Capabilities::default()
		};
		debug!("Capabilities: {:?}", capabilities);

		let p2p_server = Arc::new(p2p::Server::new(
			&config.db_root,
			capabilities,
			config.p2p_config.clone(),
			net_adapter.clone(),
			genesis.hash(),
			stop_state.clone(),
			socks_port,
			onion_address,
		)?);

		// Initialize various adapters with our dynamic set of connected peers.
		chain_adapter.init(p2p_server.peers.clone());
		pool_net_adapter.init(p2p_server.peers.clone());
		net_adapter.init(p2p_server.peers.clone());

		let mut connect_thread = None;

		if config.p2p_config.seeding_type != p2p::Seeding::Programmatic {
			let seed_list = match config.p2p_config.seeding_type {
				p2p::Seeding::None => {
					warn!("No seed configured, will stay solo until connected to");
					seed::predefined_seeds(vec![])
				}
				p2p::Seeding::List => match &config.p2p_config.seeds {
					Some(seeds) => seed::predefined_seeds(seeds.peers.clone()),
					None => {
						return Err(Error::Configuration(
							"Seeds must be configured for seeding type List".to_owned(),
						));
					}
				},
				p2p::Seeding::DNSSeed => seed::default_dns_seeds(),
				_ => unreachable!(),
			};

			connect_thread = Some(seed::connect_and_monitor(
				p2p_server.clone(),
				seed_list,
				config.p2p_config.clone(),
				stop_state.clone(),
			)?);
		}

		// Defaults to None (optional) in config file.
		// This translates to false here so we do not skip by default.
		let skip_sync_wait = config.skip_sync_wait.unwrap_or(false);
		sync_state.update(SyncStatus::AwaitingPeers(!skip_sync_wait));

		let sync_thread = sync::run_sync(
			sync_state.clone(),
			p2p_server.peers.clone(),
			shared_chain.clone(),
			stop_state.clone(),
		)?;

		let p2p_inner = p2p_server.clone();
		let _ = thread::Builder::new()
			.name("p2p-server".to_string())
			.spawn(move || {
				if let Err(e) = p2p_inner.listen() {
					error!("P2P server failed with erorr: {:?}", e);
				}
			})?;

		info!("Starting rest apis at: {}", &config.api_http_addr);
		let api_secret = get_first_line(config.api_secret_path.clone());
		let foreign_api_secret = get_first_line(config.foreign_api_secret_path.clone());
		let tls_conf = match config.tls_certificate_file.clone() {
			None => None,
			Some(file) => {
				let key = match config.tls_certificate_key.clone() {
					Some(k) => k,
					None => {
						let msg = "Private key for certificate is not set".to_string();
						return Err(Error::ArgumentError(msg));
					}
				};
				Some(TLSConfig::new(file, key))
			}
		};

		// TODO fix API shutdown and join this thread
		api::node_apis(
			&config.api_http_addr,
			shared_chain.clone(),
			tx_pool.clone(),
			p2p_server.peers.clone(),
			sync_state.clone(),
			api_secret,
			foreign_api_secret,
			tls_conf,
			allow_to_stop,
			stratum_ip_pool,
			api_chan,
			stop_state.clone(),
		)?;

		info!("Starting dandelion monitor: {}", &config.api_http_addr);
		let dandelion_thread = dandelion_monitor::monitor_transactions(
			config.dandelion_config.clone(),
			tx_pool.clone(),
			pool_net_adapter,
			stop_state.clone(),
		)?;

		warn!("MWC server started.");
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
			connect_thread,
			sync_thread,
			dandelion_thread,
		})
	}

	#[cfg(not(target_os = "windows"))]
	fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
		p.as_ref().display().to_string()
	}

	#[cfg(target_os = "windows")]
	fn adjust_canonicalization<P: AsRef<Path>>(p: P) -> String {
		const VERBATIM_PREFIX: &str = r#"\\?\"#;
		let p = p.as_ref().display().to_string();
		if p.starts_with(VERBATIM_PREFIX) {
			p[VERBATIM_PREFIX.len()..].to_string()
		} else {
			p
		}
	}
	/// Start the Tor listener for inbound connections
	/// Return (<tor_process>, <onion_address>, <secret for tor address>)
	pub fn init_tor_listener(
		addr: &str,
		api_addr: &str,
		libp2p_port: u16,
		tor_base: Option<&str>,
		socks_port: u16,
	) -> Result<(tor_process::TorProcess, String, SecretKey), Error> {
		let mut process = tor_process::TorProcess::new();
		let tor_dir = if tor_base.is_some() {
			format!("{}/tor/listener", tor_base.unwrap())
		} else {
			format!("{}/tor/listener", "~/.mwc/main")
		};

		let home_dir = dirs::home_dir()
			.map(|p| p.to_str().unwrap().to_string())
			.unwrap_or("~".to_string());
		let tor_dir = tor_dir.replace("~", &home_dir);

		// remove all other onion addresses that were previously used.

		let onion_service_dir = format!("{}/onion_service_addresses", tor_dir.clone());
		let mut onion_address = "".to_string();
		let mut found = false;
		if std::path::Path::new(&onion_service_dir).exists() {
			for entry in fs::read_dir(onion_service_dir.clone())? {
				onion_address = entry.unwrap().file_name().into_string().unwrap();

				if fs::metadata(format!(
					"{}{}{}{}{}",
					onion_service_dir,
					MAIN_SEPARATOR,
					onion_address,
					MAIN_SEPARATOR,
					crate::tor::config::SEC_KEY_FILE_COPY
				))
				.is_err()
				{
					// Secret copy doesn't exist, we can't reuse this tor directory. Creating a new one
					let onion_dir =
						format!("{}{}{}", onion_service_dir, MAIN_SEPARATOR, onion_address);
					if fs::remove_dir_all(onion_dir.clone()).is_err() {
						error!("Unable to clean TOR directory {}", onion_dir);
					}
					break;
				}
				found = true;
				break;
			}
		}

		let mut sec_key_vec = None;
		let scoped_vec;
		let mut existing_onion = None;
		let secret = if !found {
			let secp = static_secp_instance();
			let secp = secp.lock();

			let sec_key = secp::key::SecretKey::new(&secp, &mut rand::thread_rng());
			scoped_vec = vec![sec_key.clone()];
			sec_key_vec = Some((scoped_vec).as_slice());

			onion_address = OnionV3Address::from_private(&sec_key.0)
				.map_err(|e| {
					crate::Error::TorConfig(format!("Unable to build onion address, {}", e))
				})
				.unwrap()
				.to_string();
			sec_key
		} else {
			let secp = static_secp_instance();
			let secp = secp.lock();

			existing_onion = Some(onion_address.clone());
			// Read Secret from the file.
			let sec = tor_config::read_sec_key_file(
				&format!("{}{}{}", onion_service_dir, MAIN_SEPARATOR, onion_address),
				&secp,
			)
			.map_err(|e| Error::General(format!("Unable to read tor secret, {}", e)))?;
			sec
		};

		// Let's validate secret & found onion address
		let addr_to_test = OnionV3Address::from_private(&secret.0)
			.map_err(|e| Error::General(format!("Unable to build onion address, {}", e)))?;
		if addr_to_test.to_string() != onion_address {
			return Err(Error::General(
				"Internal error. Tor key doesn't match onion address".to_string(),
			)
			.into());
		}

		tor_config::output_tor_listener_config(
			&tor_dir,
			addr,
			api_addr,
			libp2p_port,
			sec_key_vec,
			existing_onion,
			socks_port,
		)
		.map_err(|e| crate::Error::TorConfig(format!("Failed to configure tor, {}", e).into()))
		.unwrap();

		info!(
			"Starting Tor inbound listener at address {}.onion, binding to {}",
			onion_address, addr
		);

		// Start Tor process
		let tor_path = PathBuf::from(format!("{}/torrc", tor_dir));
		let tor_path = fs::canonicalize(&tor_path)?;
		let tor_path = Server::adjust_canonicalization(tor_path);

		let res = process
			.torrc_path(&tor_path)
			.working_dir(&tor_dir)
			.timeout(200)
			.completion_percent(100)
			.launch();

		if res.is_err() {
			Err(Error::Configuration(format!(
				"Unable to start tor due error: {}  Started with config: {}, working dir: {}",
				res.err().unwrap(),
				tor_path,
				tor_dir
			)))
		} else {
			Ok((process, onion_address.to_string(), secret))
		}
	}

	/// Asks the server to connect to a peer at the provided network address.
	pub fn connect_peer(&self, addr: PeerAddr) -> Result<(), Error> {
		self.p2p.connect(addr)?;
		Ok(())
	}

	/// Ping all peers, mostly useful for tests to have connected peers share
	/// their heights
	pub fn ping_peers(&self) -> Result<(), Error> {
		let head = self.chain.head()?;
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
	pub fn start_stratum_server(
		&self,
		config: StratumServerConfig,
		ip_pool: Arc<connections::StratumIpPool>,
	) {
		let proof_size = global::proofsize();
		let sync_state = self.sync_state.clone();

		let mut stratum_server = stratumserver::StratumServer::new(
			config,
			self.chain.clone(),
			self.tx_pool.clone(),
			self.state_info.stratum_stats.clone(),
			ip_pool,
		);
		let _ = thread::Builder::new()
			.name("stratum_server".to_string())
			.spawn(move || {
				stratum_server.run_loop(proof_size, sync_state);
			});
	}

	/// Start mining for blocks internally on a separate thread. Relies on
	/// internal miner, and should only be used for automated testing. Burns
	/// reward if wallet_listener_url is 'None'
	pub fn start_test_miner(
		&self,
		wallet_listener_url: Option<String>,
		stop_state: Arc<StopState>,
	) {
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
			stop_state,
			sync_state,
		);
		miner.set_debug_output_id(format!("Port {}", self.config.p2p_config.port));
		let _ = thread::Builder::new()
			.name("test_miner".to_string())
			.spawn(move || miner.run_loop(wallet_listener_url));
	}

	/// The chain head
	pub fn head(&self) -> Result<chain::Tip, Error> {
		self.chain.head().map_err(|e| e.into())
	}

	/// The head of the block header chain
	pub fn header_head(&self) -> Result<chain::Tip, Error> {
		self.chain.header_head().map_err(|e| e.into())
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
			let last_blocks: Vec<consensus::HeaderDifficultyInfo> =
				global::difficulty_data_to_vector(self.chain.difficulty_iter()?)
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
		let read_timeout = Duration::from_millis(500);

		let tx_stats = self.tx_pool.try_read_for(read_timeout).map(|pool| TxStats {
			tx_pool_size: pool.txpool.size(),
			tx_pool_kernels: pool.txpool.kernel_count(),
			stem_pool_size: pool.stempool.size(),
			stem_pool_kernels: pool.stempool.kernel_count(),
		});

		let head = self.chain.head_header()?;
		let head_stats = ChainStats {
			latest_timestamp: head.timestamp,
			height: head.height,
			last_block_h: head.hash(),
			total_difficulty: head.total_difficulty(),
		};

		let header_head = self.chain.header_head()?;
		let header = self.chain.get_block_header(&header_head.hash())?;
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
			tx_stats: tx_stats,
		})
	}

	/// Stop the server.
	pub fn stop(self) {
		{
			self.sync_state.update(SyncStatus::Shutdown);
			self.stop_state.stop();

			if let Some(connect_thread) = self.connect_thread {
				match connect_thread.join() {
					Err(e) => error!("failed to join to connect_and_monitor thread: {:?}", e),
					Ok(_) => info!("connect_and_monitor thread stopped"),
				}
			} else {
				info!("No active connect_and_monitor thread")
			}

			match self.sync_thread.join() {
				Err(e) => error!("failed to join to sync thread: {:?}", e),
				Ok(_) => info!("sync thread stopped"),
			}

			match self.dandelion_thread.join() {
				Err(e) => error!("failed to join to dandelion_monitor thread: {:?}", e),
				Ok(_) => info!("dandelion_monitor thread stopped"),
			}
		}
		// this call is blocking and makes sure all peers stop, however
		// we can't be sure that we stopped a listener blocked on accept, so we don't join the p2p thread
		self.p2p.stop();
		let _ = self.lock_file.unlock();
		warn!("Shutdown complete");
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
