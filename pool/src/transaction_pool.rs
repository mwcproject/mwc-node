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

use crate::pool::{Pool, ReconcileWorkBudget, ValidatedPoolAggregate, ValidatedPoolEntry};
use crate::types::{BlockChain, PoolAdapter, PoolConfig, PoolEntry, PoolError, TxSource};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::id::ShortId;
use mwc_core::core::{Block, BlockHeader, HeaderVersion, Inputs, OutputIdentifier, Transaction};
use mwc_core::global;
use mwc_crates::log::{debug, log_enabled};
use mwc_crates::log::{warn, Level};
use mwc_crates::parking_lot::{Mutex, RwLock};
use mwc_crates::secp::Secp256k1;
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

enum PoolAddOutcome {
	/// The transaction was accepted into the stempool and relayed through the
	/// Dandelion stem path.
	Stemmed,
	/// The transaction was accepted into the public txpool and should be
	/// broadcast on a best-effort basis.
	Fluff(PoolEntry),
}

/// Tracks a transaction while it is undergoing the expensive, state-independent
/// cryptographic portion of public pool admission.
///
/// This is intentionally independent of the pool lock. Holding either side of
/// the pool `RwLock` while validating rangeproofs and kernel signatures would
/// block otherwise unrelated pool work. The key is the full transaction hash,
/// so this suppresses byte-for-byte concurrent submissions without using the
/// private stempool as an externally observable duplicate cache.
struct PendingValidationGuard {
	pending: Arc<Mutex<HashSet<Hash>>>,
	tx_hash: Hash,
}

impl PendingValidationGuard {
	fn try_acquire(
		pending: Arc<Mutex<HashSet<Hash>>>,
		tx_hash: Hash,
	) -> Option<PendingValidationGuard> {
		let inserted = pending.lock().insert(tx_hash);
		if inserted {
			Some(PendingValidationGuard { pending, tx_hash })
		} else {
			None
		}
	}
}

impl Drop for PendingValidationGuard {
	fn drop(&mut self) {
		self.pending.lock().remove(&self.tx_hash);
	}
}

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
	context_id: u32,
	/// Full transaction hashes currently undergoing standalone cryptographic
	/// admission validation.
	pending_validations: Arc<Mutex<HashSet<Hash>>>,
}

impl<B, P> TransactionPool<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	/// Create a new transaction pool
	pub fn new(context_id: u32, config: PoolConfig, chain: Arc<B>, adapter: Arc<P>) -> Self {
		TransactionPool {
			config,
			txpool: Pool::new(context_id, chain.clone(), "txpool".to_string()),
			stempool: Pool::new(context_id, chain.clone(), "stempool".to_string()),
			reorg_cache: Arc::new(RwLock::new(VecDeque::new())),
			blockchain: chain,
			adapter,
			context_id,
			pending_validations: Arc::new(Mutex::new(HashSet::new())),
		}
	}

	pub fn chain_head(&self) -> Result<BlockHeader, PoolError> {
		self.blockchain.chain_head()
	}

	/// Reconcile the private stempool against the current public txpool without
	/// re-authenticating rangeproofs and kernel signatures already checked at
	/// admission. The pool reconciliation path validates the complete aggregate
	/// once and permits individual fallback only within its strict work budget.
	fn reconcile_stempool_against_txpool(
		&mut self,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<(), PoolError> {
		match self.txpool.validated_pool_aggregate(secp)? {
			Some(txpool_tx) => self
				.stempool
				.reconcile_with_pool_aggregate(txpool_tx, header, secp),
			None => self.stempool.reconcile(None, header, secp),
		}
	}

	/// Reconcile the stempool for Dandelion fluffing and return every retained
	/// transaction together with the number of entries evicted during validation.
	pub fn reconcile_stempool_for_fluff(
		&mut self,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<(Vec<Transaction>, usize), PoolError> {
		let entries_before = self.stempool.size();
		self.reconcile_stempool_against_txpool(header, secp)?;
		let fluffable_txs = self.stempool.all_transactions();
		let removed = entries_before
			.checked_sub(fluffable_txs.len())
			.ok_or_else(|| {
				PoolError::Other(format!(
					"stempool grew during exclusive fluff reconciliation, before={} after={}",
					entries_before,
					fluffable_txs.len(),
				))
			})?;
		Ok((fluffable_txs, removed))
	}

	// Add tx to stempool (passing in all txs from txpool to validate against).
	fn add_to_stempool(
		&mut self,
		entry: &ValidatedPoolEntry,
		header: &BlockHeader,
		extra_tx: Option<ValidatedPoolAggregate>,
		secp: &mut Secp256k1,
	) -> Result<(), PoolError> {
		self.stempool
			.add_entry_with_validated_extra(entry.clone(), extra_tx, header, secp)
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
	// Returns the resulting entry and whether deaggregation changed the tx.
	fn deaggregate_tx(
		&self,
		entry: ValidatedPoolEntry,
		secp: &Secp256k1,
	) -> Result<(ValidatedPoolEntry, bool), PoolError> {
		if entry.transaction().kernels().len() > 1 {
			let txs = self
				.txpool
				.find_matching_transactions(entry.transaction().kernels())?;
			if !txs.is_empty() {
				return Ok((entry.deaggregate(&txs, secp)?, true));
			}
		}
		Ok((entry, false))
	}

	fn add_to_txpool(
		&mut self,
		entry: &ValidatedPoolEntry,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<(), PoolError> {
		let txpool_agg = self
			.txpool
			.add_entry_with_pool_aggregate(entry.clone(), header, secp)?;

		// We now need to reconcile the stempool based on the new state of the txpool.
		// Some stempool txs may no longer be valid and we need to evict them.
		// The insertion call returns the exact aggregate it already checked
		// before insertion. Every older component was fully verified on admission, so
		// rebuilding the aggregate and rechecking every proof and signature here would
		// add pool-size-amplified cryptographic work while the pool write lock is held.
		self.stempool
			.reconcile_with_pool_aggregate(txpool_agg, header, secp)?;

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
			if !global::is_nrd_enabled(self.context_id) {
				return Err(PoolError::NRDKernelNotEnabled);
			}
			if header.version < HeaderVersion(4) {
				return Err(PoolError::NRDKernelPreHF3);
			}
		}
		Ok(())
	}

	/// Validate and submit a transaction through the shared transaction pool.
	///
	/// This is the public transaction-admission boundary. Cheap structural,
	/// duplicate, and immutable fee-policy checks happen before state-independent
	/// cryptographic validation. Pool- and chain-dependent admission is rechecked
	/// under the write lock, and public fluff relay happens after the lock is
	/// released.
	pub fn submit_to_pool(
		tx_pool: &RwLock<Self>,
		src: TxSource,
		tx: Transaction,
		stem: bool,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<(), PoolError> {
		let (context_id, adapter, pending_validations) = {
			let tx_pool = tx_pool.read_recursive();
			(
				tx_pool.context_id,
				tx_pool.adapter.clone(),
				tx_pool.pending_validations.clone(),
			)
		};

		// Reject malformed structure, invalid ordering, cut-through violations,
		// and excessive weight before hashing or consulting admission state. This
		// deliberately skips rangeproof and kernel-signature verification.
		tx.validate_read(context_id)?;
		let tx_hash = tx.hash(context_id)?;

		// Fast read-only admission preflight. Never use private stempool
		// membership to reject a public fluff transaction. A repeated stem
		// transaction is allowed through so the locked path can preserve the
		// documented stem-to-fluff promotion behavior.
		{
			let tx_pool = tx_pool.read_recursive();
			if tx_pool.context_id != context_id {
				return Err(PoolError::Other(format!(
					"transaction context {} does not match pool context {}",
					context_id, tx_pool.context_id
				)));
			}
			if tx_pool.txpool.contains_tx(&tx)? {
				return Err(PoolError::DuplicateTx);
			}

			// Preserve the existing policy order: public duplicates are rejected
			// before fee checks, and fee checks precede mutable capacity checks.
			Self::verify_fee_policy(context_id, &tx)?;

			let repeated_stem = stem && tx_pool.stempool.contains_tx(&tx)?;
			if !repeated_stem {
				tx_pool.verify_capacity(stem)?;
			}
		}

		// Collapse simultaneous byte-for-byte submissions. This closes the race
		// where many requests all pass the read-only duplicate check before the
		// first request inserts the transaction.
		let _pending_guard = PendingValidationGuard::try_acquire(pending_validations, tx_hash)
			.ok_or(PoolError::DuplicateTx)?;

		// A transaction may have been accepted between the first read-only check
		// and registration in the in-flight set. Avoid cryptographic work in that
		// case as well.
		{
			let tx_pool = tx_pool.read_recursive();
			if tx_pool.context_id != context_id {
				return Err(PoolError::Other(format!(
					"transaction context {} does not match pool context {}",
					context_id, tx_pool.context_id
				)));
			}
			if tx_pool.txpool.contains_tx(&tx)? {
				return Err(PoolError::DuplicateTx);
			}
		}

		// Deliberate admission-order tradeoff: a structurally and cryptographically
		// valid transaction can still reference an unknown or already-spent input,
		// because UTXO membership is independent of its proofs, signatures, and
		// kernel sums. We nevertheless authenticate the standalone transaction here
		// before the pool- and chain-dependent checks in `admit_prevalidated()`.
		// Moving those mutable checks ahead of authentication would require tentative
		// deaggregation plus a second authoritative check after taking the write lock,
		// duplicating state-sensitive logic and increasing race and regression risk.
		// Keeping cryptographic work outside the write lock also prevents one slow
		// validation from blocking all transaction-pool operations. Unknown or spent
		// inputs are still rejected before any pool-wide aggregate is constructed.
		// Do not add CPU/load heuristics or admission throttling at this boundary as a
		// substitute: that introduces additional state, fairness decisions, and failure
		// modes without strengthening transaction validity.
		let entry = ValidatedPoolEntry::authenticate(context_id, tx, src, secp)?;

		let outcome = {
			let mut tx_pool = tx_pool.write();
			if tx_pool.context_id != context_id {
				return Err(PoolError::Other(format!(
					"transaction context {} does not match pool context {}",
					context_id, tx_pool.context_id
				)));
			}
			tx_pool.admit_prevalidated(entry, stem, header, secp)?
		};

		if let PoolAddOutcome::Fluff(entry) = outcome {
			if let Err(e) = adapter.tx_accepted(&entry) {
				// Local acceptance is the contract here; network relay is best-effort.
				warn!("txpool adapter failed after accepting tx: {}", e);
			}
		}

		Ok(())
	}

	fn admit_prevalidated(
		&mut self,
		entry: ValidatedPoolEntry,
		stem: bool,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<PoolAddOutcome, PoolError> {
		// Quick check for duplicate txs.
		// Our stempool is private and we do not want to reveal anything about the txs contained.
		// If this is a stem tx and is already present in stempool then fluff by adding to txpool.
		// Otherwise if already present in txpool return a "duplicate tx" error.
		if stem && self.stempool.contains_tx(entry.transaction())? {
			return self.admit_prevalidated(entry, false, header, secp);
		} else if self.txpool.contains_tx(entry.transaction())? {
			return Err(PoolError::DuplicateTx);
		}

		// Attempt to deaggregate the tx if not stem tx.
		let entry = if stem {
			entry
		} else {
			self.deaggregate_tx(entry, secp)?.0
		};
		let tx = entry.transaction();

		// Check this tx is valid based on current header version.
		// NRD kernels only valid post HF3 and if NRD feature enabled.
		self.verify_kernel_variants(tx, header)?;

		// Does this transaction pay the required fees and fit within the pool capacity?
		self.is_acceptable(tx, stem)?;

		// Reject conflicts through the exact per-pool indexes before spend lookup or
		// aggregate construction touches every retained transaction. A peer can vary
		// an otherwise valid transaction while repeatedly spending the same input;
		// transaction-hash caches do not stop that pattern, but the input commitment
		// is stable across all variants.
		//
		// These checks are negative filters only. A miss does not authorize the
		// transaction: all chain-state and aggregate checks below still run. Public
		// fluff admission deliberately consults only the public txpool, preserving the
		// existing rule that stempool contents are not exposed through duplicate
		// responses. Stem admission must account for both pools.
		if stem {
			self.stempool.check_pool_conflicts(tx)?;
			self.txpool.check_pool_conflicts(tx)?;
		} else {
			self.txpool.check_pool_conflicts(tx)?;
		}

		// Check the tx lock_time is valid based on current chain state.
		self.blockchain.verify_tx_lock_height(tx)?;

		self.blockchain.replay_attack_check(tx)?;

		// Locate outputs being spent from the pools and current UTXO using only
		// input/output metadata from already admitted entries. In particular, do
		// this before building a txpool aggregate: an unknown or already-spent
		// input must not make us process every retained proof and signature while
		// the transaction-pool write lock is held.
		let (spent_pool, spent_utxo) = if stem {
			self.stempool
				.locate_spends_from_pools(tx, Some(&self.txpool))
		} else {
			self.txpool.locate_spends_from_pools(tx, None)
		}?;

		// Check coinbase maturity before we go any further.
		let coinbase_inputs: Vec<_> = spent_utxo
			.iter()
			.filter(|x| x.is_coinbase())
			.cloned()
			.collect();
		let coinbase_inputs =
			Inputs::from_output_identifiers(self.context_id, coinbase_inputs.as_slice())?;
		self.blockchain.verify_coinbase_maturity(&coinbase_inputs)?;

		// Convert the tx to "v2" compatibility with "features and commit" inputs.
		let entry = self.convert_tx_v2(entry, &spent_pool, &spent_utxo, secp)?;

		// Stempool aggregate validation must account for the public txpool. Its
		// entries were fully authenticated when admitted, so preserve that fact in
		// the type instead of re-verifying every rangeproof and kernel signature.
		// This is intentionally after input lookup so rejected inputs cannot cause
		// even the linear aggregate construction work.
		let extra_tx = if stem {
			self.txpool.validated_pool_aggregate(secp)?
		} else {
			None
		};

		// If this is a stem tx then attempt to add it to stempool.
		// If the adapter fails to accept the new stem tx then fallback to fluff via txpool.
		if stem {
			self.add_to_stempool(&entry, header, extra_tx, secp)?;
			if self.adapter.stem_tx_accepted(entry.pool_entry()).is_ok() {
				return Ok(PoolAddOutcome::Stemmed);
			}
		}

		// Add tx to txpool. If this is a failed stem relay then the entry has
		// already been inserted into stempool. Roll that insertion back if the
		// fluff fallback also fails so a rejected submission cannot be relayed
		// later by the Dandelion monitor.
		if let Err(add_err) = self.add_to_txpool(&entry, header, secp) {
			if stem {
				if let Err(remove_err) = self.stempool.remove_tx(entry.transaction()) {
					return Err(PoolError::Other(format!(
						"failed to fluff stem transaction: {}; failed to remove it from stempool: {}",
						add_err, remove_err
					)));
				}
			}
			return Err(add_err);
		}
		self.add_to_reorg_cache(entry.pool_entry());

		Ok(PoolAddOutcome::Fluff(entry.into_pool_entry()))
	}

	/// Convert a transaction for v2 compatibility.
	/// We may receive a transaction with "commit only" inputs.
	/// We convert it to "features and commit" so we can safely relay it to v2 peers.
	/// Conversion is done using outputs previously looked up in both the pool and the current utxo.
	fn convert_tx_v2(
		&self,
		entry: ValidatedPoolEntry,
		spent_pool: &[OutputIdentifier],
		spent_utxo: &[OutputIdentifier],
		secp: &Secp256k1,
	) -> Result<ValidatedPoolEntry, PoolError> {
		let tx = entry.transaction();
		debug!(
			"convert_tx_v2: {} ({} -> v2)",
			tx.hash(self.context_id)?,
			tx.inputs().version_str(),
		);
		entry.convert_inputs_v2(spent_pool, spent_utxo, secp)
	}

	// Evict a transaction from the txpool.
	// Uses bucket logic to identify the "last" transaction.
	// No other tx depends on it and it has low fee_rate
	pub fn evict_from_txpool(&mut self, secp: &mut Secp256k1) -> Result<(), PoolError> {
		self.txpool.evict_transaction(secp)
	}

	// Old txs will "age out" after 30 mins.
	// This is intentionally best-effort cleanup for a bounded reorg cache,
	// not a correctness boundary. Pruning from the front is enough to keep
	// normally ordered entries from lingering for a long time.
	pub fn truncate_reorg_cache(&mut self, max_age: Duration) {
		let mut cache = self.reorg_cache.write();

		while cache
			.front()
			.map_or(false, |entry| entry.tx_at.elapsed() > max_age)
		{
			let _tx = cache.pop_front();
			debug!(
				"truncate_reorg_cache: for {:?},  new size: {}",
				_tx,
				cache.len()
			);
		}
	}

	pub fn reconcile_reorg_cache(&mut self, header: &BlockHeader, secp: &mut Secp256k1) {
		let entries = {
			let cache = self.reorg_cache.read_recursive();
			cache.iter().cloned().collect::<Vec<_>>()
		};
		debug!(
			"reconcile_reorg_cache: size: {}, block: {:?} ...",
			entries.len(),
			header.hash(self.context_id),
		);

		let mut replayed = 0;
		let mut duplicates = 0;
		let mut dropped = 0;
		let mut retained = VecDeque::new();
		let mut entries = entries.into_iter();
		let mut added = false;
		let mut replay_budget = ReconcileWorkBudget::new(self.txpool.component_count());

		while let Some(entry) = entries.next() {
			if self.total_size() >= self.config.max_pool_size {
				retained.push_back(entry);
				retained.extend(entries);
				break;
			}

			// Cache entries already present in the txpool only need the cheap
			// representative-kernel lookup. Do not charge them as projected aggregate
			// rebuilds, especially when the existing txpool is already large.
			match self.txpool.contains_tx(&entry.tx) {
				Ok(true) => {
					duplicates += 1;
					debug!("reconcile_reorg_cache: skipping duplicate tx {:?}", entry);
					retained.push_back(entry);
					continue;
				}
				Ok(false) => {}
				Err(e) => {
					dropped += 1;
					debug!(
						"reconcile_reorg_cache: dropping cached tx after duplicate check failed {:?}: {}",
						entry, e
					);
					continue;
				}
			}

			if !replay_budget.charge_attempt(&entry.tx) {
				let deferred = entries.len().saturating_add(1);
				warn!(
					"reconcile_reorg_cache: work budget exhausted; deferring {} cached entries",
					deferred,
				);
				retained.push_back(entry);
				retained.extend(entries);
				break;
			}

			// Reorg-cache entries already passed the public txpool admission path
			// before they were cached. Replay uses the lower-level pool insertion
			// path so we revalidate the aggregate against the current chain state
			// without repeating top-level side effects such as deaggregation,
			// re-caching, or network acceptance callbacks.
			//
			// This intentionally does not re-run fee policy here because
			// accept_fee_base is initialized once per node context. Pool::add_entry()
			// authenticates the cached component and re-runs the context-sensitive
			// checks that can change across blocks or reorgs. The work budget above
			// bounds the cumulative cost of rebuilding growing aggregate prefixes.
			match self.txpool.add_entry(entry.clone(), None, header, secp) {
				Ok(()) => {
					replay_budget.record_accept(&entry.tx);
					added = true;
					replayed += 1;
					retained.push_back(entry);
				}
				Err(PoolError::DuplicateTx) => {
					// The reorg cache mirrors previously accepted txpool entries.
					// If reconcile_block kept the tx valid and in txpool, replaying
					// the cached entry is expected to hit the duplicate path.
					duplicates += 1;
					debug!("reconcile_reorg_cache: skipping duplicate tx {:?}", entry);
					retained.push_back(entry);
				}
				Err(e) => {
					// Reorg cache replay is best-effort. Cached txs can become stale
					// after blocks or reorgs, and it is acceptable to miss a few extra
					// transactions here instead of keeping failed replay candidates.
					dropped += 1;
					debug!(
						"reconcile_reorg_cache: dropping stale cached tx {:?}: {}",
						entry, e
					);
				}
			}
		}

		if added {
			match self.txpool.all_transactions_aggregate(None, secp) {
				Ok(txpool_agg) => {
					if let Err(e) = self.stempool.reconcile(txpool_agg, header, secp) {
						warn!(
							"reconcile_reorg_cache failed to reconcile stempool after replay: {}",
							e
						);
						self.clear_pool_state();
						return;
					}
				}
				Err(e) => {
					warn!(
						"reconcile_reorg_cache failed to aggregate txpool after replay: {}",
						e
					);
					self.clear_pool_state();
					return;
				}
			}
		}

		while retained.len() > self.config.max_pool_size {
			let _ = retained.pop_front();
		}

		let retained_len = retained.len();
		*self.reorg_cache.write() = retained;

		debug!(
			"reconcile_reorg_cache: block: {:?} ... done. replayed: {}, duplicate: {}, dropped: {}, retained: {}",
			header.hash(self.context_id),
			replayed,
			duplicates,
			dropped,
			retained_len,
		);
	}

	fn clear_pool_state(&mut self) {
		self.txpool.clear();
		self.stempool.clear();
	}

	/// Reconcile the transaction pool (both txpool and stempool) against the
	/// provided block.
	pub fn reconcile_block(&mut self, block: &Block, secp: &mut Secp256k1) {
		if log_enabled!(Level::Debug) {
			debug!("reconcile_block Started for block {:?}", block);

			debug!("---------------- BEFORE START --------------");
			let reorg_cache = self.reorg_cache.read_recursive();

			debug!("reorg_cache size: {}", reorg_cache.len());
			for pe in reorg_cache.iter() {
				debug!("  reorg_cache tx: {:?}", pe);
			}

			debug!("txpool size: {}", self.txpool.size());
			for pe in self.txpool.all_entries() {
				debug!("  txpool tx: {:?}", pe);
			}
			debug!("---------------- BEFORE END --------------");
		}

		let res: Result<(), PoolError> = (|| {
			self.txpool.reconcile_block(block)?;
			self.txpool.reconcile(None, &block.header, secp)?;

			self.stempool.reconcile_block(block)?;
			self.reconcile_stempool_against_txpool(&block.header, secp)?;

			Ok(())
		})();

		if let Err(e) = res {
			warn!(
				"reconcile_block failed, clearing txpool and stempool: {}",
				e
			);
			self.clear_pool_state();
		}

		if log_enabled!(Level::Debug) {
			debug!("---------------- AFTER START --------------");
			let reorg_cache = self.reorg_cache.read_recursive();

			debug!("reorg_cache size: {}", reorg_cache.len());
			for pe in reorg_cache.iter() {
				debug!("  reorg_cache tx: {:?}", pe);
			}
			debug!("txpool size: {}", self.txpool.size());
			for pe in self.txpool.all_entries() {
				debug!("  txpool tx: {:?}", pe);
			}
			debug!("---------------- AFTER END --------------");
		}
	}

	/// Retrieve individual transaction for the given kernel hash.
	pub fn retrieve_tx_by_kernel_hash(&self, hash: Hash) -> Result<Option<Transaction>, PoolError> {
		Ok(self.txpool.retrieve_tx_by_kernel_hash(hash))
	}

	/// Check whether the txpool contains an entry for the given kernel hash.
	pub fn contains_tx_by_kernel_hash(&self, hash: Hash) -> bool {
		self.txpool.contains_tx_by_kernel_hash(hash)
	}

	/// Retrieve all transactions matching the provided "compact block"
	/// based on the kernel set.
	/// Note: we only look in the txpool for this (stempool is under embargo).
	pub fn retrieve_transactions(
		&self,
		hash: Hash,
		nonce: u64,
		kern_ids: &[ShortId],
	) -> Result<(Vec<Transaction>, Vec<ShortId>), PoolError> {
		self.txpool.retrieve_transactions(hash, nonce, kern_ids)
	}

	/// Check immutable transaction fee policy without consulting mutable pool
	/// state. This is safe to run before expensive cryptographic validation.
	fn verify_fee_policy(context_id: u32, tx: &Transaction) -> Result<(), PoolError> {
		// weight for a basic transaction (2 inputs, 2 outputs, 1 kernel) -
		// (2 * 1) + (2 * 21) + (1 * 3) = 47
		// minfees = 47 * 500_000 = 23_500_000
		let fee = tx.fee()?;
		let accept_fee = tx.accept_fee(context_id)?;
		if fee < accept_fee {
			return Err(PoolError::LowFeeTransaction(fee));
		}
		Ok(())
	}

	/// Check mutable pool and stempool capacity.
	fn verify_capacity(&self, stem: bool) -> Result<(), PoolError> {
		// Treat equality as full because accepting this tx would insert one more entry.
		if self.total_size() >= self.config.max_pool_size {
			return Err(PoolError::OverCapacity);
		}

		// Check that the stempool can accept this transaction.
		if stem && self.stempool.size() >= self.config.max_stempool_size {
			return Err(PoolError::OverCapacity);
		}
		Ok(())
	}

	/// Whether the transaction is acceptable to the pool, given both immutable
	/// fee policy and mutable pool capacity.
	fn is_acceptable(&self, tx: &Transaction, stem: bool) -> Result<(), PoolError> {
		Self::verify_fee_policy(self.context_id, tx)?;
		self.verify_capacity(stem)
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
		secp: &mut Secp256k1,
	) -> Result<Vec<Transaction>, PoolError> {
		self.txpool
			.prepare_mineable_transactions(self.config.mineable_max_weight, secp)
	}

	// App sessions id
	pub fn get_context_id(&self) -> u32 {
		self.context_id
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pending_validation_guard_suppresses_and_releases_identical_hash() {
		let pending = Arc::new(Mutex::new(HashSet::new()));
		let tx_hash = Hash::default();

		let first = PendingValidationGuard::try_acquire(pending.clone(), tx_hash).unwrap();
		assert!(PendingValidationGuard::try_acquire(pending.clone(), tx_hash).is_none());

		drop(first);
		assert!(PendingValidationGuard::try_acquire(pending, tx_hash).is_some());
	}
}
