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

//! Transaction pool implementation leveraging txhashset for chain state
//! validation. It is a valid operation to add a tx to the tx pool if the
//! resulting tx pool can be added to the current chain state to produce a
//! valid chain state.

use self::core::core::hash::{Hash, Hashed};
use self::core::core::id::ShortId;
use self::core::core::{
	transaction, Block, BlockHeader, HeaderVersion, OutputIdentifier, Transaction, Weighting,
};
use self::core::global;
use self::util::RwLock;
use crate::pool::Pool;
use crate::types::{BlockChain, PoolAdapter, PoolConfig, PoolEntry, PoolError, TxSource};
use chrono::prelude::*;
use lru::LruCache;
use mwc_core as core;
use mwc_core::ser;
use mwc_keychain::base58;
use mwc_util as util;
use mwc_util::secp::Secp256k1;
use std::collections::VecDeque;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Transaction pool implementation.
pub struct TransactionPool<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	/// Pool Config
	pub config: PoolConfig,
	/// Our transaction pool.
	pub txpool: Pool<B>,
	/// Our Dandelion "stempool".
	pub stempool: Pool<B>,
	/// Cache of previous txs in case of a re-org.
	pub reorg_cache: Arc<RwLock<VecDeque<PoolEntry>>>,
	/// The blockchain
	pub blockchain: Arc<B>,
	/// The pool adapter
	pub adapter: Arc<P>,
	///the replay attack cache
	pub replay_verifier_cache: Arc<RwLock<LruCache<[u8; 32], ()>>>,
}

impl<B, P> TransactionPool<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	/// Create a new transaction pool
	pub fn new(config: PoolConfig, chain: Arc<B>, adapter: Arc<P>) -> Self {
		TransactionPool {
			config,
			txpool: Pool::new(chain.clone(), "txpool".to_string()),
			stempool: Pool::new(chain.clone(), "stempool".to_string()),
			reorg_cache: Arc::new(RwLock::new(VecDeque::new())),
			blockchain: chain,
			adapter,
			replay_verifier_cache: Arc::new(RwLock::new(LruCache::new(
				NonZeroUsize::new(1000).unwrap(),
			))),
		}
	}

	pub fn chain_head(&self) -> Result<BlockHeader, PoolError> {
		self.blockchain.chain_head()
	}

	// Add tx to stempool (passing in all txs from txpool to validate against).
	fn add_to_stempool(
		&mut self,
		entry: &PoolEntry,
		header: &BlockHeader,
		extra_tx: Option<Transaction>,
		secp: &Secp256k1,
	) -> Result<(), PoolError> {
		self.stempool
			.add_to_pool(entry.clone(), extra_tx, header, secp)
	}

	fn add_to_reorg_cache(&mut self, entry: &PoolEntry) {
		let mut cache = self.reorg_cache.write();
		cache.push_back(entry.clone());

		// We cache 30 mins of txs but we have a hard limit to avoid catastrophic failure.
		// For simplicity use the same value as the actual tx pool limit.
		if cache.len() > self.config.max_pool_size {
			let _ = cache.pop_front();
		}
		debug!("added tx to reorg_cache: size now {}", cache.len());
	}

	// Deaggregate this tx against the txpool.
	// Returns the new deaggregated tx or the original tx if no deaggregation.
	fn deaggregate_tx(&self, entry: PoolEntry, secp: &Secp256k1) -> Result<PoolEntry, PoolError> {
		if entry.tx.kernels().len() > 1 {
			let txs = self.txpool.find_matching_transactions(entry.tx.kernels());
			if !txs.is_empty() {
				let tx = transaction::deaggregate(entry.tx, &txs, secp)?;
				return Ok(PoolEntry::new(tx, TxSource::Deaggregate));
			}
		}
		Ok(entry)
	}

	fn add_to_txpool(
		&mut self,
		entry: &PoolEntry,
		header: &BlockHeader,
		secp: &Secp256k1,
	) -> Result<(), PoolError> {
		self.txpool.add_to_pool(entry.clone(), None, header, secp)?;

		// We now need to reconcile the stempool based on the new state of the txpool.
		// Some stempool txs may no longer be valid and we need to evict them.
		let txpool_agg = self.txpool.all_transactions_aggregate(None, secp)?;
		self.stempool.reconcile(txpool_agg, header, secp)?;

		Ok(())
	}

	/// Verify the tx kernel variants and ensure they can all be accepted to the txpool/stempool
	/// with respect to current header version.
	fn verify_kernel_variants(
		&self,
		tx: &Transaction,
		header: &BlockHeader,
	) -> Result<(), PoolError> {
		if tx.kernels().iter().any(|k| k.is_nrd()) {
			if !global::is_nrd_enabled() {
				return Err(PoolError::NRDKernelNotEnabled);
			}
			if header.version < HeaderVersion(4) {
				return Err(PoolError::NRDKernelPreHF3);
			}
		}
		Ok(())
	}

	/// Add the given tx to the pool, directing it to either the stempool or
	/// txpool based on stem flag provided.
	pub fn add_to_pool(
		&mut self,
		src: TxSource,
		tx: Transaction,
		stem: bool,
		header: &BlockHeader,
		secp: &Secp256k1,
	) -> Result<(), PoolError> {
		// Quick check for duplicate txs.
		// Our stempool is private and we do not want to reveal anything about the txs contained.
		// If this is a stem tx and is already present in stempool then fluff by adding to txpool.
		// Otherwise if already present in txpool return a "duplicate tx" error.
		if stem && self.stempool.contains_tx(&tx) {
			return self.add_to_pool(src, tx, false, header, secp);
		} else if self.txpool.contains_tx(&tx) {
			return Err(PoolError::DuplicateTx);
		}

		// Attempt to deaggregate the tx if not stem tx.
		let entry = if stem {
			PoolEntry::new(tx, src)
		} else {
			self.deaggregate_tx(PoolEntry::new(tx, src), secp)?
		};
		let ref tx = entry.tx;

		// Check this tx is valid based on current header version.
		// NRD kernels only valid post HF3 and if NRD feature enabled.
		self.verify_kernel_variants(tx, header)?;

		// Does this transaction pay the required fees and fit within the pool capacity?
		let acceptability = self.is_acceptable(tx, stem);
		let mut evict = false;
		if !stem && acceptability.as_ref().err() == Some(&PoolError::OverCapacity) {
			evict = true;
		} else if acceptability.is_err() {
			return acceptability;
		}

		// Make sure the transaction is valid before anything else.
		// Validate tx accounting for max tx weight.
		tx.validate(Weighting::AsTransaction, header.height, secp)
			.map_err(PoolError::InvalidTx)?;

		// Check the tx lock_time is valid based on current chain state.
		self.blockchain.verify_tx_lock_height(tx)?;

		{
			let mut replay_cache = self.replay_verifier_cache.write();
			let mut vec = Vec::new();
			ser::serialize_default(&mut vec, &tx)
				.map_err(|e| PoolError::Other(format!("Unable to serialize tx, {}", e)))?;
			// let mut sha2 = Sha256::new();
			// sha2.input(vec);
			// let tx_hash = sha2.result();
			let tx_hash = base58::sha256d_hash(&vec);
			let mut tx_need_to_verify = false;
			if !replay_cache.contains(&tx_hash) {
				tx_need_to_verify = true;
			}
			if tx_need_to_verify {
				self.blockchain.replay_attack_check(tx)?;
				replay_cache.put(tx_hash, ());
			}
		}

		// If stem we want to account for the txpool.
		let extra_tx = if stem {
			self.txpool.all_transactions_aggregate(None, secp)?
		} else {
			None
		};

		// Locate outputs being spent from pool and current utxo.
		let (spent_pool, spent_utxo) = if stem {
			self.stempool.locate_spends(tx, extra_tx.clone(), secp)
		} else {
			self.txpool.locate_spends(tx, None, secp)
		}?;

		// Check coinbase maturity before we go any further.
		let coinbase_inputs: Vec<_> = spent_utxo
			.iter()
			.filter(|x| x.is_coinbase())
			.cloned()
			.collect();
		self.blockchain
			.verify_coinbase_maturity(&coinbase_inputs.as_slice().into())?;

		// Convert the tx to "v2" compatibility with "features and commit" inputs.
		let ref entry = self.convert_tx_v2(entry, &spent_pool, &spent_utxo, secp)?;

		// If this is a stem tx then attempt to add it to stempool.
		// If the adapter fails to accept the new stem tx then fallback to fluff via txpool.
		if stem {
			self.add_to_stempool(entry, header, extra_tx, secp)?;
			if self.adapter.stem_tx_accepted(entry).is_ok() {
				return Ok(());
			}
		}

		// Add tx to txpool.
		self.add_to_txpool(entry, header, secp)?;
		self.add_to_reorg_cache(entry);
		self.adapter.tx_accepted(entry, header.height);

		// Transaction passed all the checks but we have to make space for it
		if evict {
			self.evict_from_txpool(secp);
		}

		Ok(())
	}

	/// Convert a transaction for v2 compatibility.
	/// We may receive a transaction with "commit only" inputs.
	/// We convert it to "features and commit" so we can safely relay it to v2 peers.
	/// Conversion is done using outputs previously looked up in both the pool and the current utxo.
	fn convert_tx_v2(
		&self,
		entry: PoolEntry,
		spent_pool: &[OutputIdentifier],
		spent_utxo: &[OutputIdentifier],
		secp: &Secp256k1,
	) -> Result<PoolEntry, PoolError> {
		let tx = entry.tx;
		debug!(
			"convert_tx_v2: {} ({} -> v2)",
			tx.hash(),
			tx.inputs().version_str(),
		);

		let mut inputs = spent_utxo.to_vec();
		inputs.extend_from_slice(spent_pool);
		inputs.sort_unstable();

		let tx = Transaction {
			body: tx.body.replace_inputs(inputs.as_slice().into()),
			..tx
		};

		// Validate the tx to ensure our converted inputs are correct.
		let header = self.chain_head()?;
		tx.validate(Weighting::AsTransaction, header.height, secp)?;

		Ok(PoolEntry::new(tx, entry.src))
	}

	// Evict a transaction from the txpool.
	// Uses bucket logic to identify the "last" transaction.
	// No other tx depends on it and it has low fee_rate
	pub fn evict_from_txpool(&mut self, secp: &Secp256k1) {
		self.txpool.evict_transaction(secp)
	}

	// Old txs will "age out" after 30 mins.
	pub fn truncate_reorg_cache(&mut self, cutoff: DateTime<Utc>) {
		let mut cache = self.reorg_cache.write();

		while cache.front().map(|x| x.tx_at < cutoff).unwrap_or(false) {
			let _tx = cache.pop_front();
			debug!(
				"truncate_reorg_cache: for {:?},  new size: {}",
				_tx,
				cache.len()
			);
		}
	}

	pub fn reconcile_reorg_cache(
		&mut self,
		header: &BlockHeader,
		secp: &Secp256k1,
	) -> Result<(), PoolError> {
		let entries = self.reorg_cache.read().iter().cloned().collect::<Vec<_>>();
		debug!(
			"reconcile_reorg_cache: size: {}, block: {:?} ...",
			entries.len(),
			header.hash(),
		);
		for entry in entries {
			let _ = self.add_to_txpool(&entry, header, secp);
		}
		debug!(
			"reconcile_reorg_cache: block: {:?} ... done.",
			header.hash()
		);
		Ok(())
	}

	/// Reconcile the transaction pool (both txpool and stempool) against the
	/// provided block.
	pub fn reconcile_block(&mut self, block: &Block, secp: &Secp256k1) -> Result<(), PoolError> {
		if log_enabled!(log::Level::Debug) {
			debug!("reconcile_block Started for block {:?}", block);

			debug!("---------------- BEFORE START --------------");
			let reorg_cache = self.reorg_cache.read();

			debug!("reorg_cache size: {}", reorg_cache.len());
			for pe in reorg_cache.iter() {
				debug!("  reorg_cache tx: {:?}", pe);
			}

			debug!("txpool size: {}", self.txpool.entries.len());
			for pe in &self.txpool.entries {
				debug!("  txpool tx: {:?}", pe);
			}
			debug!("---------------- BEFORE END --------------");
		}

		// First reconcile the txpool.
		self.txpool.reconcile_block(block);
		self.txpool.reconcile(None, &block.header, secp)?;

		// Now reconcile our stempool, accounting for the updated txpool txs.
		self.stempool.reconcile_block(block);
		{
			let txpool_tx = self.txpool.all_transactions_aggregate(None, secp)?;
			self.stempool.reconcile(txpool_tx, &block.header, secp)?;
		}

		if log_enabled!(log::Level::Debug) {
			debug!("---------------- AFTER START --------------");
			let reorg_cache = self.reorg_cache.read();

			debug!("reorg_cache size: {}", reorg_cache.len());
			for pe in reorg_cache.iter() {
				debug!("  reorg_cache tx: {:?}", pe);
			}
			debug!("txpool size: {}", self.txpool.entries.len());
			for pe in &self.txpool.entries {
				debug!("  txpool tx: {:?}", pe);
			}
			debug!("---------------- AFTER END --------------");
		}

		Ok(())
	}

	/// Retrieve individual transaction for the given kernel hash.
	pub fn retrieve_tx_by_kernel_hash(&self, hash: Hash) -> Option<Transaction> {
		self.txpool.retrieve_tx_by_kernel_hash(hash)
	}

	/// Retrieve all transactions matching the provided "compact block"
	/// based on the kernel set.
	/// Note: we only look in the txpool for this (stempool is under embargo).
	pub fn retrieve_transactions(
		&self,
		hash: Hash,
		nonce: u64,
		kern_ids: &[ShortId],
	) -> (Vec<Transaction>, Vec<ShortId>) {
		self.txpool.retrieve_transactions(hash, nonce, kern_ids)
	}

	/// Whether the transaction is acceptable to the pool, given both how
	/// full the pool is and the transaction weight.
	fn is_acceptable(&self, tx: &Transaction, stem: bool) -> Result<(), PoolError> {
		if self.total_size() > self.config.max_pool_size {
			return Err(PoolError::OverCapacity);
		}

		// Check that the stempool can accept this transaction
		if stem && self.stempool.size() > self.config.max_stempool_size
			|| self.total_size() > self.config.max_pool_size
		{
			return Err(PoolError::OverCapacity);
		}

		// weight for a basic transaction (2 inputs, 2 outputs, 1 kernel) -
		// (2 * 1) + (2 * 21) + (1 * 3) = 47
		// minfees = 47 * 500_000 = 23_500_000
		let header = self.chain_head()?;
		if tx.shifted_fee(header.height) < tx.accept_fee(header.height) {
			return Err(PoolError::LowFeeTransaction(tx.shifted_fee(header.height)));
		}
		Ok(())
	}

	/// Get the total size of the pool.
	/// Note: we only consider the txpool here as stempool is under embargo.
	pub fn total_size(&self) -> usize {
		self.txpool.size()
	}

	/// Returns a vector of transactions from the txpool so we can build a
	/// block from them.
	pub fn prepare_mineable_transactions(
		&self,
		secp: &Secp256k1,
	) -> Result<Vec<Transaction>, PoolError> {
		self.txpool
			.prepare_mineable_transactions(self.config.mineable_max_weight, secp)
	}
}
