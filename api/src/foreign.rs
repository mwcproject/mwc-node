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

//! Foreign API External Definition

use crate::handlers::blocks_api::{BlockHandler, HeaderHandler};
use crate::handlers::chain_api::{ChainHandler, KernelHandler, OutputHandler};
use crate::handlers::peers_api::PeersConnectedHandler;
use crate::handlers::pool_api::PoolHandler;
use crate::handlers::transactions_api::TxHashSetHandler;
use crate::handlers::version_api::VersionHandler;
use crate::types::{
	BlockHeaderPrintable, BlockPrintable, LocatedTxKernel, OutputListing, OutputPrintable, Tip,
	Version,
};
use crate::{rest::*, BlockListing};
use mwc_chain::{Chain, SyncState};
use mwc_core::core::hash::Hash;
use mwc_core::core::hash::Hashed;
use mwc_core::core::transaction::Transaction;
use mwc_crates::log::warn;
use mwc_crates::parking_lot::{Mutex, RwLock};
use mwc_crates::secp::Secp256k1;
use mwc_crates::sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
use mwc_p2p::types::PeerInfoDisplayLegacy;
use mwc_pool::{self, BlockChain, PoolAdapter};
use std::cmp::max;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

const PROCESS_STATUS_CACHE_MAX_AGE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
pub struct ProcessHostMetrics {
	pub host_cpu_usage: f64,
	pub host_ram_usage: f64,
	pub host_swap_usage: f64,
}

pub struct ProcessStatusCache {
	system: System,
	sampled_at: Instant,
	updated_at: Option<Instant>,
	metrics: ProcessHostMetrics,
}

impl ProcessStatusCache {
	pub fn new() -> Self {
		let system = System::new_with_specifics(
			RefreshKind::nothing()
				.with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
				.with_memory(MemoryRefreshKind::everything()),
		);
		ProcessStatusCache {
			system,
			sampled_at: Instant::now(),
			updated_at: None,
			metrics: ProcessHostMetrics {
				host_cpu_usage: 0.0,
				host_ram_usage: 0.0,
				host_swap_usage: 0.0,
			},
		}
	}

	pub fn get(&mut self) -> ProcessHostMetrics {
		if self.updated_at.map_or(true, |updated_at| {
			updated_at.elapsed() >= PROCESS_STATUS_CACHE_MAX_AGE
		}) {
			self.refresh();
		}
		self.metrics
	}

	fn refresh(&mut self) {
		self.system.refresh_memory();
		if self.updated_at.is_none() {
			std::thread::sleep(
				mwc_crates::sysinfo::MINIMUM_CPU_UPDATE_INTERVAL
					.saturating_sub(self.sampled_at.elapsed()),
			);
		}
		self.system.refresh_cpu_usage();
		self.sampled_at = Instant::now();

		let cpus = self.system.cpus();
		let cpu_usage_sum = cpus.iter().map(|cpu| cpu.cpu_usage()).sum::<f32>();
		let host_cpu_usage = (cpu_usage_sum / max(1, cpus.len()) as f32) as f64;
		let total_ram = self.system.total_memory();
		let total_swap = self.system.total_swap();

		self.metrics = ProcessHostMetrics {
			host_cpu_usage,
			host_ram_usage: self.system.used_memory() as f64 / max(1u64, total_ram) as f64,
			host_swap_usage: self.system.used_swap() as f64 / max(1u64, total_swap) as f64,
		};
		self.updated_at = Some(Instant::now());
	}
}

/// Main interface into all node API functions.
/// Node APIs are split into two separate blocks of functionality
/// called the ['Owner'](struct.Owner.html) and ['Foreign'](struct.Foreign.html) APIs
///
/// Methods in this API are intended to be 'single use'.
///

pub struct Foreign<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	pub peers: Weak<mwc_p2p::Peers>,
	pub chain: Weak<Chain>,
	pub tx_pool: Weak<RwLock<mwc_pool::TransactionPool<B, P>>>,
	pub sync_state: Weak<SyncState>,
	pub process_status_cache: Arc<Mutex<ProcessStatusCache>>,
	start_time: Instant,
}

impl<B, P> Foreign<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	/// Create a new API instance with the chain, transaction pool, peers and `sync_state`. All subsequent
	/// API calls will operate on this instance of node API.
	///
	/// # Arguments
	/// * `peers` - A non-owning reference of the peers.
	/// * `chain` - A non-owning reference of the chain.
	/// * `tx_pool` - A non-owning reference of the transaction pool.
	/// * `sync_state` - A non-owning reference of the `sync_state`.
	///
	/// # Returns
	/// * An instance of the Node holding references to the current chain, transaction pool, peers and sync_state.
	///

	pub fn new(
		peers: Weak<mwc_p2p::Peers>,
		chain: Weak<Chain>,
		tx_pool: Weak<RwLock<mwc_pool::TransactionPool<B, P>>>,
		sync_state: Weak<SyncState>,
		start_time: Instant,
		process_status_cache: Arc<Mutex<ProcessStatusCache>>,
	) -> Self {
		Foreign {
			peers,
			chain,
			tx_pool,
			sync_state,
			process_status_cache,
			start_time,
		}
	}

	/// Gets block header given either a height, a hash or an unspent output commitment. Only one parameters is needed.
	/// If multiple parameters are provided only the first one in the list is used.
	///
	/// # Arguments
	/// * `height` - block height.
	/// * `hash` - block hash.
	/// * `commit` - output commitment.
	///
	/// # Returns
	/// * Result Containing:
	/// * A [`BlockHeaderPrintable`](types/struct.BlockHeaderPrintable.html)
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_header(
		&self,
		secp: &Secp256k1,
		height: Option<u64>,
		hash: Option<Hash>,
		commit: Option<String>,
	) -> Result<BlockHeaderPrintable, Error> {
		let header_handler = HeaderHandler {
			chain: self.chain.clone(),
		};
		let hash = header_handler.parse_inputs(secp, height, hash, commit)?;
		header_handler.get_header_v2(&hash)
	}

	/// Gets block details given either a height, a hash or an unspent output commitment. Only one parameters is needed.
	/// If multiple parameters are provided only the first one in the list is used.
	///
	/// # Arguments
	/// * `height` - block height.
	/// * `hash` - block hash.
	/// * `commit` - output commitment.
	/// * `include_proof` - include range proofs for outputs. Default: false
	/// * `include_merkle_proof` - include merkle proofs (for unspent coinbase outputs).  Default: false
	///
	/// # Returns
	/// * Result Containing:
	/// * A [`BlockPrintable`](types/struct.BlockPrintable.html)
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_block(
		&self,
		secp: &Secp256k1,
		height: Option<u64>,
		hash: Option<Hash>,
		commit: Option<String>,
		include_proof: Option<bool>,
		include_merkle_proof: Option<bool>,
	) -> Result<BlockPrintable, Error> {
		let block_handler = BlockHandler {
			chain: self.chain.clone(),
		};
		let hash = block_handler.parse_inputs(secp, height, hash, commit)?;
		block_handler.get_block(
			secp,
			&hash,
			include_proof.unwrap_or(true),
			include_merkle_proof.unwrap_or(false),
		)
	}

	/// Returns a [`BlockListing`](types/struct.BlockListing.html) of available blocks
	/// between `min_height` and `max_height`
	/// The method will query the database for blocks starting at the block height `min_height`
	/// and continue until `max_height`, stopping at the first block that isn't available.
	///
	/// # Arguments
	/// * `start_height` - starting height to lookup.
	/// * `end_height` - ending height to to lookup.
	/// * 'max` - The max number of blocks to return.
	///   Must be greater than 0.
	///   Note this is overriden with BLOCK_TRANSFER_LIMIT if BLOCK_TRANSFER_LIMIT is exceeded
	///
	/// # Returns
	/// * Result Containing:
	/// * A [`BlockListing`](types/struct.BlockListing.html)
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_blocks(
		&self,
		secp: &Secp256k1,
		start_height: u64,
		end_height: u64,
		max: u64,
		include_proof: Option<bool>,
	) -> Result<BlockListing, Error> {
		let block_handler = BlockHandler {
			chain: self.chain.clone(),
		};
		block_handler.get_blocks(secp, start_height, end_height, max, include_proof)
	}

	/// Returns the node version and block header version (used by mwc-wallet).
	///
	/// # Returns
	/// * Result Containing:
	/// * A [`Version`](types/struct.Version.html)
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_version(&self) -> Result<Version, Error> {
		let version_handler = VersionHandler {
			chain: self.chain.clone(),
		};
		version_handler.get_version()
	}

	/// Returns details about the state of the current fork tip.
	///
	/// # Returns
	/// * Result Containing:
	/// * A [`Tip`](types/struct.Tip.html)
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_tip(&self) -> Result<Tip, Error> {
		let chain_handler = ChainHandler {
			chain: self.chain.clone(),
		};
		chain_handler.get_tip()
	}

	/// Returns a [`LocatedTxKernel`](types/struct.LocatedTxKernel.html) based on the kernel excess.
	/// The `min_height` and `max_height` parameters are both optional.
	/// If not supplied, `min_height` will be set to 0 and `max_height` will be set to the head of the chain.
	/// The method will start at the block height `max_height` and traverse the kernel MMR backwards,
	/// until either the kernel is found or `min_height` is reached.
	///
	/// # Arguments
	/// * `excess` - kernel excess to look for.
	/// * `min_height` - minimum height to stop the lookup.
	/// * `max_height` - maximum height to start the lookup.
	///
	/// # Returns
	/// * Result Containing:
	/// * A [`LocatedTxKernel`](types/struct.LocatedTxKernel.html)
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_kernel(
		&self,
		excess: String,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<LocatedTxKernel, Error> {
		let kernel_handler = KernelHandler {
			chain: self.chain.clone(),
		};
		kernel_handler.get_kernel_v2(excess, min_height, max_height)
	}

	/// Retrieves details about specifics outputs. Supports retrieval of multiple outputs in a single request.
	/// Support retrieval by both commitment string and block height.
	///
	/// # Arguments
	/// * `commits` - a vector of unspent output commitments.
	/// * `include_proof` - whether or not to include the range proof in the response.
	/// * `include_merkle_proof` - whether or not to include the merkle proof in the response.
	///
	/// # Returns
	/// * Result Containing:
	/// * An [`OutputPrintable`](types/struct.OutputPrintable.html)
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_outputs(
		&self,
		secp: &Secp256k1,
		commits: Vec<String>,
		include_proof: Option<bool>,
		include_merkle_proof: Option<bool>,
	) -> Result<Vec<OutputPrintable>, Error> {
		let output_handler = OutputHandler {
			chain: self.chain.clone(),
		};
		output_handler.get_outputs_v2(
			secp,
			Some(commits),
			None,
			None,
			include_proof,
			include_merkle_proof,
		)
	}

	/// UTXO traversal. Retrieves last utxos since a `start_index` until a `max`.
	///
	/// # Arguments
	/// * `start_index` - start index in the MMR.
	/// * `end_index` - optional index so stop in the MMR.
	/// * `max` - max index in the MMR.
	/// * `include_proof` - whether or not to include the range proof in the response.
	///
	/// # Returns
	/// * Result Containing:
	/// * An [`OutputListing`](types/struct.OutputListing.html)
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_unspent_outputs(
		&self,
		secp: &Secp256k1,
		start_index: u64,
		end_index: Option<u64>,
		max: u64,
		include_proof: Option<bool>,
	) -> Result<OutputListing, Error> {
		let output_handler = OutputHandler {
			chain: self.chain.clone(),
		};
		output_handler.get_unspent_outputs(secp, start_index, end_index, max, include_proof)
	}

	/// Retrieves the PMMR indices based on the provided block height(s).
	///
	/// # Arguments
	/// * `start_block_height` - start index in the MMR.
	/// * `end_block_height` - optional index so stop in the MMR.
	///
	/// # Returns
	/// * Result Containing:
	/// * An [`OutputListing`](types/struct.OutputListing.html)
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_pmmr_indices(
		&self,
		start_block_height: u64,
		end_block_height: Option<u64>,
	) -> Result<OutputListing, Error> {
		let txhashset_handler = TxHashSetHandler {
			chain: self.chain.clone(),
		};
		txhashset_handler.block_height_range_to_pmmr_indices(start_block_height, end_block_height)
	}

	pub fn get_connected_peers(&self) -> Result<Vec<PeerInfoDisplayLegacy>, Error> {
		let peers_connected_handler = PeersConnectedHandler {
			peers: self.peers.clone(),
		};
		peers_connected_handler
			.get_connected_peers()
			.map_err(|e| Error::Internal(format!("Unable to request the connected peers, {}", e)))
	}

	/// Returns the number of transaction in the transaction pool.
	///
	/// # Returns
	/// * Result Containing:
	/// * `usize`
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_pool_size(&self) -> Result<usize, Error> {
		let pool_handler = PoolHandler {
			tx_pool: self.tx_pool.clone(),
		};
		pool_handler.get_pool_size()
	}

	/// Returns up to 1,000 unconfirmed transactions in the transaction pool.
	/// Will not return transactions in the stempool.
	///
	/// # Returns
	/// * Result Containing:
	/// * A vector of transactions.
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///

	pub fn get_unconfirmed_transactions(&self) -> Result<Vec<Transaction>, Error> {
		let pool_handler = PoolHandler {
			tx_pool: self.tx_pool.clone(),
		};
		pool_handler.get_unconfirmed_transactions()
	}

	/// Push new transaction to our local transaction pool.
	///
	/// Transactions accepted into the local pool are handed to the network adapter
	/// for relay on a best-effort basis. Adapter relay failures are logged by the
	/// pool and do not make this method fail after local acceptance.
	///
	/// # Arguments
	/// * `tx` - the Mwc transaction to push.
	/// * `fluff` - boolean to bypass Dandelion relay.
	///
	/// # Returns
	/// * Result Containing:
	/// * `Ok(())` if the transaction was accepted into the local transaction pool
	/// * or [`Error`](struct.Error.html) if an error is encountered.
	///
	pub fn push_transaction(
		&self,
		tx: Transaction,
		fluff: Option<bool>,
		secp: &mut Secp256k1,
	) -> Result<(), Error> {
		let context_id = self
			.chain
			.upgrade()
			.ok_or_else(|| Error::Internal("chain is not available".into()))?
			.get_context_id();
		let tx_hash = tx.hash(context_id)?;
		let pool_handler = PoolHandler {
			tx_pool: self.tx_pool.clone(),
		};
		pool_handler.push_transaction(tx, fluff, secp).map_err(|e| {
			warn!(
				"Unable to push transaction {} into the pool, {}",
				tx_hash, e
			);
			e
		})
	}

	pub fn get_running_time(&self) -> u64 {
		let now = Instant::now();
		now.duration_since(self.start_time).as_secs()
	}
}
