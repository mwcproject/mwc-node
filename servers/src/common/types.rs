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

//! Server types
use std::convert::From;
use std::sync::Arc;

use chrono::prelude::Utc;
use rand::prelude::*;

use crate::api;
use crate::chain;
use crate::core::global::ChainTypes;
use crate::core::{core, libtx, pow};
use crate::keychain;
use crate::p2p;
use crate::pool;
use crate::pool::types::DandelionConfig;
use crate::store;
use std::collections::HashSet;

/// Error type wrapping underlying module errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Error originating from the core implementation.
	#[error("Core error, {0}")]
	Core(core::block::Error),
	/// Error originating from the libtx implementation.
	#[error("LibTx error, {0}")]
	LibTx(libtx::Error),
	/// Error originating from the db storage.
	#[error("Db Store error, {0}")]
	Store(store::Error),
	/// Error originating from the blockchain implementation.
	#[error("Blockchain error, {0}")]
	Chain(chain::Error),
	/// Error originating from the peer-to-peer network.
	#[error("P2P error, {0}")]
	P2P(p2p::Error),
	/// Error originating from HTTP API calls.
	#[error("Http API error, {0}")]
	API(api::Error),
	/// Error originating from the cuckoo miner
	#[error("Cuckoo miner error, {0}")]
	Cuckoo(pow::Error),
	/// Error originating from the transaction pool.
	#[error("Tx Pool error, {0}")]
	Pool(pool::PoolError),
	/// Error originating from the keychain.
	#[error("Keychain error, {0}")]
	Keychain(keychain::Error),
	/// Invalid Arguments.
	#[error("Invalid argument, {0}")]
	ArgumentError(String),
	/// Wallet communication error
	#[error("Wallet coomunication error, {0}")]
	WalletComm(String),
	/// Error originating from some I/O operation (likely a file on disk).
	#[error("IO error, {0}")]
	IOError(std::io::Error),
	/// Configuration error
	#[error("Configuration error, {0}")]
	Configuration(String),
	/// General error
	#[error("General error, {0}")]
	General(String),
}

impl From<core::block::Error> for Error {
	fn from(e: core::block::Error) -> Error {
		Error::Core(e)
	}
}
impl From<chain::Error> for Error {
	fn from(e: chain::Error) -> Error {
		Error::Chain(e)
	}
}
impl From<std::io::Error> for Error {
	fn from(e: std::io::Error) -> Error {
		Error::IOError(e)
	}
}
impl From<p2p::Error> for Error {
	fn from(e: p2p::Error) -> Error {
		Error::P2P(e)
	}
}

impl From<pow::Error> for Error {
	fn from(e: pow::Error) -> Error {
		Error::Cuckoo(e)
	}
}

impl From<store::Error> for Error {
	fn from(e: store::Error) -> Error {
		Error::Store(e)
	}
}

impl From<api::Error> for Error {
	fn from(e: api::Error) -> Error {
		Error::API(e)
	}
}

impl From<pool::PoolError> for Error {
	fn from(e: pool::PoolError) -> Error {
		Error::Pool(e)
	}
}

impl From<keychain::Error> for Error {
	fn from(e: keychain::Error) -> Error {
		Error::Keychain(e)
	}
}

impl From<libtx::Error> for Error {
	fn from(e: libtx::Error) -> Error {
		Error::LibTx(e)
	}
}

/// Type of seeding the server will use to find other peers on the network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChainValidationMode {
	/// Run full chain validation after processing every block.
	EveryBlock,
	/// Do not automatically run chain validation during normal block
	/// processing.
	Disabled,
}

impl Default for ChainValidationMode {
	fn default() -> ChainValidationMode {
		ChainValidationMode::Disabled
	}
}

/// Type for Tor Configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TorConfig {
	/// Whether to start tor listener on listener startup (default true)
	pub tor_enabled: bool,
	/// The port for the tor socks proxy to bind to
	pub socks_port: u16,
	/// Tor running externally (default false)
	pub tor_external: bool,
	/// Onion address to use, only applicable with external tor
	pub onion_address: Option<String>,
}

impl Default for TorConfig {
	fn default() -> TorConfig {
		TorConfig {
			tor_enabled: false,
			socks_port: 51234,
			tor_external: false,
			onion_address: Some("".to_string()),
		}
	}
}

/// Full server configuration, aggregating configurations required for the
/// different components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
	/// Directory under which the rocksdb stores will be created
	pub db_root: String,

	/// Network address for the Rest API HTTP server.
	pub api_http_addr: String,

	/// Location of secret for basic auth on Rest API HTTP and V2 Owner API server.
	pub api_secret_path: Option<String>,

	/// Location of secret for basic auth on v2 Foreign API server.
	pub foreign_api_secret_path: Option<String>,

	/// TLS certificate file
	pub tls_certificate_file: Option<String>,
	/// TLS certificate private key file
	pub tls_certificate_key: Option<String>,

	/// Setup the server for tests, testnet or mainnet
	#[serde(default)]
	pub chain_type: ChainTypes,

	/// Automatically run full chain validation during normal block processing?
	#[serde(default)]
	pub chain_validation_mode: ChainValidationMode,

	/// Whether this node is a full archival node or a fast-sync, pruned node
	pub archive_mode: Option<bool>,

	/// Whether to skip the sync timeout on startup
	/// (To assist testing on solo chains)
	pub skip_sync_wait: Option<bool>,

	/// time to wait between header sync requests (short).
	/// (Default: 30 ms)
	pub duration_sync_short: Option<i64>,

	/// time to wait between header sync requests (long).
	/// (Default: 50 ms)
	pub duration_sync_long: Option<i64>,

	/// Invalid Block hash list
	/// (Default: none)
	pub invalid_block_hashes: Option<Vec<String>>,

	/// Whether to run the TUI
	/// if enabled, this will disable logging to stdout
	pub run_tui: Option<bool>,

	/// Whether to run the test miner (internal, cuckoo 16)
	pub run_test_miner: Option<bool>,

	/// Test miner wallet URL
	pub test_miner_wallet_url: Option<String>,

	/// Enable libp2p server. It can run only with TOR. Needed for wallets to send messages to each other.
	/// Default value: enabled
	pub libp2p_enabled: Option<bool>,

	/// Topics that node will listen on and collect the data.
	/// Default: SwapMarketplace
	pub libp2p_topics: Option<Vec<String>>,

	/// libp2p connection port (will be activated with Tor)
	pub libp2p_port: Option<u16>,

	/// Configuration for the peer-to-peer server
	pub p2p_config: p2p::P2PConfig,

	/// Transaction pool configuration
	#[serde(default)]
	pub pool_config: pool::PoolConfig,

	/// Dandelion configuration
	#[serde(default)]
	pub dandelion_config: pool::DandelionConfig,

	/// Configuration for the mining daemon
	#[serde(default)]
	pub stratum_mining_config: Option<StratumServerConfig>,

	/// Configuration for the webhooks that trigger on certain events
	#[serde(default)]
	pub webhook_config: WebHooksConfig,

	/// Tor Configuration
	#[serde(default)]
	pub tor_config: TorConfig,
}

impl Default for ServerConfig {
	fn default() -> ServerConfig {
		ServerConfig {
			db_root: "mwc_chain".to_string(),
			api_http_addr: "127.0.0.1:3413".to_string(),
			api_secret_path: Some(".api_secret".to_string()),
			foreign_api_secret_path: Some(".foreign_api_secret".to_string()),
			tls_certificate_file: None,
			tls_certificate_key: None,
			p2p_config: p2p::P2PConfig::default(),
			dandelion_config: pool::DandelionConfig::default(),
			stratum_mining_config: Some(StratumServerConfig::default()),
			chain_type: ChainTypes::default(),
			archive_mode: Some(false),
			chain_validation_mode: ChainValidationMode::default(),
			pool_config: pool::PoolConfig::default(),
			skip_sync_wait: Some(false),
			invalid_block_hashes: Some(vec![]),
			duration_sync_short: Some(30),
			duration_sync_long: Some(50),
			run_tui: Some(true),
			run_test_miner: Some(false),
			test_miner_wallet_url: None,
			libp2p_enabled: Some(true),
			libp2p_port: Some(3417),
			libp2p_topics: None,
			webhook_config: WebHooksConfig::default(),
			tor_config: TorConfig::default(),
		}
	}
}

/// Stratum (Mining server) configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StratumServerConfig {
	/// Run a stratum mining server (the only way to communicate to mine this
	/// node via mwc-miner
	pub enable_stratum_server: Option<bool>,

	/// If enabled, the address and port to listen on
	pub stratum_server_addr: Option<String>,

	/// How long to wait before stopping the miner, recollecting transactions
	/// and starting again. Units: seconds
	pub attempt_time_per_block: u32,

	/// Minimum difficulty for worker shares
	pub minimum_share_difficulty: u64,

	/// Base address to the HTTP wallet receiver
	pub wallet_listener_url: String,

	/// Attributes the reward to a random private key instead of contacting the
	/// wallet receiver. Mostly used for tests.
	pub burn_reward: bool,

	/// Activate IP tracking and ban
	#[serde(default = "StratumServerConfig::default_ip_tracking")]
	pub ip_tracking: bool,

	/// Maximum number of connections. Stratum will drop some workers if that limit will be exceeded.
	#[serde(default = "StratumServerConfig::default_workers_connection_limit")]
	pub workers_connection_limit: i32,

	/// Number of points to ban IP address
	#[serde(default = "StratumServerConfig::default_ban_action_limit")]
	pub ban_action_limit: i32,

	/// Weight of 'submit shares' event vs ban events
	#[serde(default = "StratumServerConfig::default_shares_weight")]
	pub shares_weight: i32,

	/// Timeout for worker's login
	#[serde(default = "StratumServerConfig::default_worker_login_timeout_ms")]
	pub worker_login_timeout_ms: i64,

	/// History length used for ban IPs. After that period, ban will be lifted
	#[serde(default = "StratumServerConfig::default_ip_pool_ban_history_s")]
	pub ip_pool_ban_history_s: i64,

	/// Connection pace per IP per worker (average time interval between connections from the same IP)
	#[serde(default = "StratumServerConfig::default_connection_pace_ms")]
	pub connection_pace_ms: i64,

	/// White list of IPs
	#[serde(default)]
	pub ip_white_list: HashSet<String>,

	/// Black list of IPs
	#[serde(default)]
	pub ip_black_list: HashSet<String>,
}

impl StratumServerConfig {
	fn default_ip_tracking() -> bool {
		false
	}
	fn default_workers_connection_limit() -> i32 {
		10000
	}
	fn default_ban_action_limit() -> i32 {
		5
	}
	fn default_shares_weight() -> i32 {
		5
	}
	fn default_worker_login_timeout_ms() -> i64 {
		-1
	}
	fn default_ip_pool_ban_history_s() -> i64 {
		3600
	}
	fn default_connection_pace_ms() -> i64 {
		-1
	}
}

impl Default for StratumServerConfig {
	fn default() -> StratumServerConfig {
		StratumServerConfig {
			wallet_listener_url: "http://127.0.0.1:3415".to_string(),
			burn_reward: false,
			attempt_time_per_block: 15,
			minimum_share_difficulty: 1,
			enable_stratum_server: Some(false),
			stratum_server_addr: Some("127.0.0.1:3416".to_string()),
			ip_tracking: StratumServerConfig::default_ip_tracking(),
			workers_connection_limit: StratumServerConfig::default_workers_connection_limit(),
			ban_action_limit: StratumServerConfig::default_ban_action_limit(),
			shares_weight: StratumServerConfig::default_shares_weight(),
			worker_login_timeout_ms: StratumServerConfig::default_worker_login_timeout_ms(),
			ip_pool_ban_history_s: StratumServerConfig::default_ip_pool_ban_history_s(),
			connection_pace_ms: StratumServerConfig::default_connection_pace_ms(),
			ip_white_list: HashSet::new(),
			ip_black_list: HashSet::new(),
		}
	}
}

/// Web hooks configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebHooksConfig {
	/// url to POST transaction data when a new transaction arrives from a peer
	pub tx_received_url: Option<String>,
	/// url to POST header data when a new header arrives from a peer
	pub header_received_url: Option<String>,
	/// url to POST block data when a new block arrives from a peer
	pub block_received_url: Option<String>,
	/// url to POST block data when a new block is accepted by our node (might be a reorg or a fork)
	pub block_accepted_url: Option<String>,
	/// number of worker threads in the tokio runtime
	#[serde(default = "default_nthreads")]
	pub nthreads: u16,
	/// timeout in seconds for the http request
	#[serde(default = "default_timeout")]
	pub timeout: u16,
}

fn default_timeout() -> u16 {
	10
}

fn default_nthreads() -> u16 {
	4
}

impl Default for WebHooksConfig {
	fn default() -> WebHooksConfig {
		WebHooksConfig {
			tx_received_url: None,
			header_received_url: None,
			block_received_url: None,
			block_accepted_url: None,
			nthreads: default_nthreads(),
			timeout: default_timeout(),
		}
	}
}

/// A node is either "stem" of "fluff" for the duration of a single epoch.
/// A node also maintains an outbound relay peer for the epoch.
#[derive(Debug)]
pub struct DandelionEpoch {
	config: DandelionConfig,
	// When did this epoch start?
	start_time: Option<i64>,
	// Are we in "stem" mode or "fluff" mode for this epoch?
	is_stem: bool,
	// Our current Dandelion relay peer (effective for this epoch).
	relay_peer: Option<Arc<p2p::Peer>>,
}

impl DandelionEpoch {
	/// Create a new Dandelion epoch, defaulting to "stem" and no outbound relay peer.
	pub fn new(config: DandelionConfig) -> DandelionEpoch {
		DandelionEpoch {
			config,
			start_time: None,
			is_stem: true,
			relay_peer: None,
		}
	}

	/// Is the current Dandelion epoch expired?
	/// It is expired if start_time is older than the configured epoch_secs.
	pub fn is_expired(&self) -> bool {
		match self.start_time {
			None => true,
			Some(start_time) => {
				let epoch_secs = self.config.epoch_secs;
				Utc::now().timestamp().saturating_sub(start_time) > epoch_secs as i64
			}
		}
	}

	/// Transition to next Dandelion epoch.
	/// Select stem/fluff based on configured stem_probability.
	/// Choose a new outbound stem relay peer.
	pub fn next_epoch(&mut self, peers: &Arc<p2p::Peers>) {
		self.start_time = Some(Utc::now().timestamp());
		self.relay_peer = peers.iter().outbound().connected().choose_random();

		// If stem_probability == 90 then we stem 90% of the time.
		let stem_probability = self.config.stem_probability;
		let mut rng = rand::thread_rng();
		self.is_stem = rng.gen_range(0, 100) < stem_probability;

		let addr = self.relay_peer.clone().map(|p| p.info.addr.clone());
		info!(
			"DandelionEpoch: next_epoch: is_stem: {} ({}%), relay: {:?}",
			self.is_stem, stem_probability, addr
		);
	}

	/// Are we stemming (or fluffing) transactions in this epoch?
	pub fn is_stem(&self) -> bool {
		self.is_stem
	}

	/// Always stem our (pushed via api) txs regardless of stem/fluff epoch?
	pub fn always_stem_our_txs(&self) -> bool {
		self.config.always_stem_our_txs
	}

	/// What is our current relay peer?
	/// If it is not connected then choose a new one.
	pub fn relay_peer(&mut self, peers: &Arc<p2p::Peers>) -> Option<Arc<p2p::Peer>> {
		let mut update_relay = false;
		if let Some(peer) = &self.relay_peer {
			if !peer.is_connected() {
				info!(
					"DandelionEpoch: relay_peer: {:?} not connected, choosing a new one.",
					peer.info.addr
				);
				update_relay = true;
			}
		} else {
			update_relay = true;
		}

		if update_relay {
			self.relay_peer = peers.iter().outbound().connected().choose_random();
			info!(
				"DandelionEpoch: relay_peer: new peer chosen: {:?}",
				self.relay_peer.clone().map(|p| p.info.addr.clone())
			);
		}

		self.relay_peer.clone()
	}
}
