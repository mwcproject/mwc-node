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

//! Transaction pool implementation.
//! Used for both the txpool and stempool layers in the pool.

use crate::types::{BlockChain, PoolEntry, PoolError, TxSource};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::id::{ShortId, ShortIdentifiable};
use mwc_core::core::transaction;
#[cfg(all(test, feature = "test-support"))]
use mwc_core::core::Output;
use mwc_core::core::{
	Block, BlockHeader, BlockSums, Committed, HeaderVersion, Inputs, OutputFeatures,
	OutputIdentifier, Transaction, TxKernel, Weighting,
};
use mwc_core::global;
use mwc_core::ser;
use mwc_crates::indexmap::IndexMap;
use mwc_crates::log::{debug, warn};
use mwc_crates::secp::pedersen::Commitment;
use mwc_crates::secp::Secp256k1;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// Rebuilding a growing aggregate processes every retained prefix. Keep the
// conservative per-entry reconciliation path strictly bounded so a large pool
// cannot turn one stale entry into quadratic work while the pool write lock is
// held.
const MAX_RECONCILE_FALLBACK_ENTRIES: usize = 512;
const MAX_RECONCILE_FALLBACK_WORK: u128 = 1_000_000;

#[derive(Clone, Copy)]
struct ReconcileFallbackLimits {
	max_entries: usize,
	max_work: u128,
}

const RECONCILE_FALLBACK_LIMITS: ReconcileFallbackLimits = ReconcileFallbackLimits {
	max_entries: MAX_RECONCILE_FALLBACK_ENTRIES,
	max_work: MAX_RECONCILE_FALLBACK_WORK,
};

fn transaction_components(tx: &Transaction) -> u128 {
	(tx.body.inputs.len() as u128)
		.saturating_add(tx.body.outputs.len() as u128)
		.saturating_add(tx.body.kernels.len() as u128)
}

/// Bounds paths that repeatedly add a transaction to an already growing pool
/// aggregate. Work is measured as the cumulative number of transaction body
/// components visited across all projected aggregate prefixes.
pub(crate) struct ReconcileWorkBudget {
	limits: ReconcileFallbackLimits,
	attempts: usize,
	prefix_components: u128,
	work: u128,
}

/// Exact post-insertion aggregate of a pool whose entries were fully
/// authenticated when admitted.
///
/// Keep this wrapper crate-private and construct it only at the pool admission
/// boundary. It lets another `Pool` reuse the aggregate without treating an
/// arbitrary `Transaction` as if its rangeproofs and kernel signatures had
/// already been verified.
pub(crate) struct ValidatedPoolAggregate(Transaction);

/// A pool entry whose rangeproofs and kernel signatures were fully
/// authenticated before the transaction-pool write lock was acquired.
///
/// The inner entry is private so code cannot manufacture this marker from an
/// arbitrary transaction. The only transformations exposed below either
/// remove already authenticated components during deaggregation or replace
/// input metadata; both recheck every structural property and the resulting
/// kernel sums without repeating rangeproof or signature verification.
#[derive(Clone)]
pub(crate) struct ValidatedPoolEntry {
	entry: PoolEntry,
	context_id: u32,
}

impl ValidatedPoolEntry {
	/// Fully authenticate a transaction before it crosses the pool write-lock
	/// boundary.
	pub(crate) fn authenticate(
		context_id: u32,
		tx: Transaction,
		src: TxSource,
		secp: &mut Secp256k1,
	) -> Result<Self, PoolError> {
		tx.validate(context_id, Weighting::AsTransaction, secp)?;
		Ok(ValidatedPoolEntry {
			entry: PoolEntry::new(tx, src),
			context_id,
		})
	}

	fn from_authenticated_entry(context_id: u32, entry: PoolEntry) -> Self {
		ValidatedPoolEntry { entry, context_id }
	}

	pub(crate) fn transaction(&self) -> &Transaction {
		&self.entry.tx
	}

	pub(crate) fn pool_entry(&self) -> &PoolEntry {
		&self.entry
	}

	pub(crate) fn into_pool_entry(self) -> PoolEntry {
		self.entry
	}

	/// Remove transactions whose authenticated kernels are already represented
	/// by this aggregate. `transaction::deaggregate` only removes components from
	/// the authenticated transaction; it cannot introduce a new proof or kernel
	/// signature. Recheck the properties and kernel sums that can change.
	pub(crate) fn deaggregate(
		self,
		txs: &[Transaction],
		secp: &Secp256k1,
	) -> Result<Self, PoolError> {
		let tx = transaction::deaggregate(self.context_id, self.entry.tx, txs, secp)?;
		tx.validate_aggregate_from_validated_components(
			self.context_id,
			Weighting::AsTransaction,
			secp,
		)
		.map_err(PoolError::InvalidTx)?;
		Ok(ValidatedPoolEntry::from_authenticated_entry(
			self.context_id,
			PoolEntry::new(tx, TxSource::Deaggregate),
		))
	}

	/// Replace commitment-only inputs with identifiers resolved from authenticated
	/// pool indexes and chain state. Outputs, rangeproofs, kernels, and signatures
	/// remain unchanged, while structural validity and kernel sums are rechecked.
	pub(crate) fn convert_inputs_v2(
		self,
		spent_pool: &[OutputIdentifier],
		spent_utxo: &[OutputIdentifier],
		secp: &Secp256k1,
	) -> Result<Self, PoolError> {
		let mut inputs = spent_utxo.to_vec();
		inputs.extend_from_slice(spent_pool);
		ser::sort_by_hash(self.context_id, &mut inputs)
			.map_err(|e| PoolError::Other(format!("convert_tx_v2 input sorting error, {}", e)))?;

		let tx = self.entry.tx;
		let tx = Transaction {
			body: tx.body.replace_inputs(
				self.context_id,
				Inputs::from_output_identifiers(self.context_id, inputs.as_slice())?,
			)?,
			..tx
		};
		tx.validate_aggregate_from_validated_components(
			self.context_id,
			Weighting::AsTransaction,
			secp,
		)
		.map_err(PoolError::InvalidTx)?;

		Ok(ValidatedPoolEntry::from_authenticated_entry(
			self.context_id,
			PoolEntry::new(tx, self.entry.src),
		))
	}
}

/// Component identities for a single pool entry.
///
/// Build these before mutating the pool so every fallible conversion and hash
/// calculation completes before `entries` and its derived indexes are updated.
struct PoolEntryIndexKeys {
	inputs: Vec<Commitment>,
	outputs: Vec<OutputIdentifier>,
	kernels: Vec<Hash>,
	nrd_excesses: Vec<Commitment>,
	components: u128,
}

impl PoolEntryIndexKeys {
	fn from_transaction(context_id: u32, tx: &Transaction) -> Result<Self, PoolError> {
		let inputs = tx
			.inputs()
			.into_commit_wrappers(context_id)?
			.into_iter()
			.map(|input| input.commitment())
			.collect();
		let outputs = tx
			.outputs()
			.iter()
			.map(|output| output.identifier())
			.collect();
		let kernels = tx
			.kernels()
			.iter()
			.map(|kernel| kernel.hash(context_id))
			.collect::<Result<Vec<_>, _>>()?;
		let nrd_excesses = tx
			.kernels()
			.iter()
			.filter(|kernel| kernel.is_nrd())
			.map(TxKernel::excess)
			.collect();

		Ok(PoolEntryIndexKeys {
			inputs,
			outputs,
			kernels,
			nrd_excesses,
			components: transaction_components(tx),
		})
	}
}

/// An output retained in the exact pool index.
#[derive(Clone, Copy)]
struct IndexedPoolOutput {
	owner: Hash,
	features: OutputFeatures,
}

/// Exact derived indexes for entries currently held by a `Pool`.
///
/// These indexes reject known conflicts early and locate candidate inputs that
/// spend currently unspent pool outputs. A lookup never authenticates a
/// candidate: standalone cryptographic validation, aggregate validation, and
/// chain-state validation remain authoritative.
///
/// Security properties:
/// - remote data cannot populate an index until its entry has passed every
///   admission check;
/// - full commitments, NRD excess commitments, and kernel hashes are stored in
///   exact maps, not truncated or probabilistic keys, and memory use grows only
///   with accepted pool data;
/// - `entries` and these maps are mutated together under the pool's exclusive
///   borrow, so there is no independently expiring or asynchronously refreshed
///   cache state;
/// - a hypothetical missing produced-output record makes a pool child fail its
///   chain lookup; it cannot authorize an invalid candidate;
/// - an unexpected stale record cannot cause invalid acceptance because the
///   post-lookup aggregate is still validated against chain state;
/// - removal verifies every expected index owner and output identifier before
///   changing either the entries or the indexes.
///
/// Keep all mutation behind `Pool::insert_entry`, `Pool::shift_remove_entry`,
/// `Pool::remove_entries`, and `Pool::clear_entries`. Do not persist or evict
/// these records separately from their owning entries.
#[derive(Default)]
struct PoolIndexes {
	spent_inputs: HashMap<Commitment, Hash>,
	produced_outputs: HashMap<Commitment, IndexedPoolOutput>,
	kernels: HashMap<Hash, Hash>,
	nrd_excesses: HashMap<Commitment, Hash>,
	component_count: u128,
}

impl PoolIndexes {
	fn check_conflicts(&self, keys: &PoolEntryIndexKeys) -> Result<u128, PoolError> {
		for input in &keys.inputs {
			if let Some(owner) = self.spent_inputs.get(input) {
				return Err(PoolError::DuplicateKernelOrDuplicateSpent(format!(
					"input commitment {:?} is already spent by pool entry {}",
					input, owner,
				)));
			}
		}

		for output in &keys.outputs {
			if self.produced_outputs.contains_key(&output.commitment()) {
				return Err(PoolError::DuplicateCommitment);
			}
		}

		for kernel in &keys.kernels {
			if let Some(owner) = self.kernels.get(kernel) {
				return Err(PoolError::DuplicateKernelOrDuplicateSpent(format!(
					"kernel {} is already present in pool entry {}",
					kernel, owner,
				)));
			}
		}

		// NRD uniqueness is defined by public excess, not by the full kernel
		// hash. Different valid signatures or features can produce distinct
		// kernel hashes for the same excess.
		for excess in &keys.nrd_excesses {
			if self.nrd_excesses.contains_key(excess) {
				return Err(PoolError::NRDKernelRelativeHeight);
			}
		}

		self.component_count
			.checked_add(keys.components)
			.ok_or_else(|| PoolError::Other("pool component count overflow".into()))
	}

	fn check_owned_by(&self, owner: &Hash, keys: &PoolEntryIndexKeys) -> Result<u128, PoolError> {
		for input in &keys.inputs {
			if self.spent_inputs.get(input) != Some(owner) {
				return Err(PoolError::Other(format!(
					"pool spent-input index is inconsistent for entry {}",
					owner,
				)));
			}
		}
		for output in &keys.outputs {
			let indexed = self.produced_outputs.get(&output.commitment());
			if !indexed.is_some_and(|indexed| {
				indexed.owner == *owner && indexed.features == output.features
			}) {
				return Err(PoolError::Other(format!(
					"pool output index is inconsistent for entry {}",
					owner,
				)));
			}
		}
		for kernel in &keys.kernels {
			if self.kernels.get(kernel) != Some(owner) {
				return Err(PoolError::Other(format!(
					"pool kernel index is inconsistent for entry {}",
					owner,
				)));
			}
		}
		for excess in &keys.nrd_excesses {
			if self.nrd_excesses.get(excess) != Some(owner) {
				return Err(PoolError::Other(format!(
					"pool NRD excess index is inconsistent for entry {}",
					owner,
				)));
			}
		}
		self.component_count
			.checked_sub(keys.components)
			.ok_or_else(|| PoolError::Other("pool component count underflow".into()))
	}

	fn insert(&mut self, owner: Hash, keys: &PoolEntryIndexKeys, component_count: u128) {
		for input in &keys.inputs {
			let previous = self.spent_inputs.insert(*input, owner);
			debug_assert!(previous.is_none());
		}
		for output in &keys.outputs {
			let previous = self.produced_outputs.insert(
				output.commitment(),
				IndexedPoolOutput {
					owner,
					features: output.features,
				},
			);
			debug_assert!(previous.is_none());
		}
		for kernel in &keys.kernels {
			let previous = self.kernels.insert(*kernel, owner);
			debug_assert!(previous.is_none());
		}
		for excess in &keys.nrd_excesses {
			let previous = self.nrd_excesses.insert(*excess, owner);
			debug_assert!(previous.is_none());
		}
		self.component_count = component_count;
	}

	fn remove(&mut self, owner: &Hash, keys: &PoolEntryIndexKeys, component_count: u128) {
		self.remove_mappings(owner, keys);
		self.component_count = component_count;
	}

	fn remove_many(&mut self, removals: &[(Hash, PoolEntryIndexKeys)], component_count: u128) {
		for (owner, keys) in removals {
			self.remove_mappings(owner, keys);
		}
		self.component_count = component_count;
	}

	fn remove_mappings(&mut self, owner: &Hash, keys: &PoolEntryIndexKeys) {
		for input in &keys.inputs {
			let removed = self.spent_inputs.remove(input);
			debug_assert_eq!(removed, Some(*owner));
		}
		for output in &keys.outputs {
			let removed = self.produced_outputs.remove(&output.commitment());
			debug_assert!(removed.is_some_and(|indexed| indexed.owner == *owner));
		}
		for kernel in &keys.kernels {
			let removed = self.kernels.remove(kernel);
			debug_assert_eq!(removed, Some(*owner));
		}
		for excess in &keys.nrd_excesses {
			let removed = self.nrd_excesses.remove(excess);
			debug_assert_eq!(removed, Some(*owner));
		}
	}

	fn clear(&mut self) {
		self.spent_inputs.clear();
		self.produced_outputs.clear();
		self.kernels.clear();
		self.nrd_excesses.clear();
		self.component_count = 0;
	}

	fn lookup_unspent_output(
		&self,
		input: &Commitment,
	) -> Result<Option<OutputIdentifier>, PoolError> {
		if let Some(owner) = self.spent_inputs.get(input) {
			return Err(PoolError::DuplicateKernelOrDuplicateSpent(format!(
				"input commitment {:?} is already spent by pool entry {}",
				input, owner,
			)));
		}

		Ok(self
			.produced_outputs
			.get(input)
			.map(|indexed| OutputIdentifier::new(indexed.features, input)))
	}
}

impl ReconcileWorkBudget {
	pub(crate) fn new(prefix_components: u128) -> Self {
		Self::with_limits(prefix_components, RECONCILE_FALLBACK_LIMITS)
	}

	fn with_limits(prefix_components: u128, limits: ReconcileFallbackLimits) -> Self {
		ReconcileWorkBudget {
			limits,
			attempts: 0,
			prefix_components,
			work: 0,
		}
	}

	/// Charge one projected add attempt. The accepted prefix is updated
	/// separately because a rejected or duplicate transaction does not enlarge it.
	pub(crate) fn charge_attempt(&mut self, tx: &Transaction) -> bool {
		if self.attempts >= self.limits.max_entries {
			return false;
		}

		let Some(candidate_components) = self
			.prefix_components
			.checked_add(transaction_components(tx))
		else {
			return false;
		};
		let Some(next_work) = self.work.checked_add(candidate_components) else {
			return false;
		};
		if next_work > self.limits.max_work {
			return false;
		}

		self.attempts += 1;
		self.work = next_work;
		true
	}

	pub(crate) fn record_accept(&mut self, tx: &Transaction) {
		self.prefix_components = self
			.prefix_components
			.saturating_add(transaction_components(tx));
	}
}

pub struct Pool<B>
where
	B: BlockChain,
{
	/// Entries keyed by the representative kernel hash (first kernel) used for tx-kernel gossip.
	/// Lookup APIs retain their documented representative-hash semantics. The
	/// separate `PoolIndexes::kernels` map covers every kernel for admission
	/// conflict detection.
	entries: IndexMap<Hash, PoolEntry>,
	/// Exact derived indexes used to reject pool conflicts before rebuilding a
	/// pool-wide aggregate. They are updated under the same exclusive borrow as
	/// `entries` and never replace authoritative transaction validation.
	indexes: PoolIndexes,
	/// The blockchain
	pub blockchain: Arc<B>,
	pub name: String,
	context_id: u32,
}

impl<B> Pool<B>
where
	B: BlockChain,
{
	pub fn new(context_id: u32, chain: Arc<B>, name: String) -> Self {
		Pool {
			entries: IndexMap::new(),
			indexes: PoolIndexes::default(),
			blockchain: chain,
			name,
			context_id,
		}
	}

	fn tx_key(context_id: u32, tx: &Transaction) -> Result<Hash, PoolError> {
		let kernel = tx.kernels().first().ok_or_else(|| {
			PoolError::InvalidTx(transaction::Error::Generic(
				"pool entry transaction has no kernels".into(),
			))
		})?;
		Ok(kernel.hash(context_id)?)
	}

	/// Reject conflicts that are already known from accepted pool entries.
	///
	/// This is deliberately only a negative filter. Returning `Ok(())` does not
	/// authenticate `tx`; callers must continue through normal standalone,
	/// aggregate, and chain-state validation.
	pub(crate) fn check_pool_conflicts(&self, tx: &Transaction) -> Result<(), PoolError> {
		let keys = PoolEntryIndexKeys::from_transaction(self.context_id, tx)?;
		self.indexes.check_conflicts(&keys).map(|_| ())
	}

	fn insert_entry(
		&mut self,
		entry_key: Hash,
		entry: PoolEntry,
		keys: &PoolEntryIndexKeys,
	) -> Result<(), PoolError> {
		if self.entries.contains_key(&entry_key) {
			return Err(PoolError::DuplicateTx);
		}
		// Recheck immediately before mutation. All checks are fallible, while the
		// following map updates are infallible apart from process-wide allocation
		// failure, so callers never observe a partially committed insertion.
		let component_count = self.indexes.check_conflicts(keys)?;

		let previous = self.entries.insert(entry_key, entry);
		debug_assert!(previous.is_none());
		self.indexes.insert(entry_key, keys, component_count);
		Ok(())
	}

	fn shift_remove_entry(&mut self, entry_key: &Hash) -> Result<Option<PoolEntry>, PoolError> {
		let keys = match self.entries.get(entry_key) {
			Some(entry) => PoolEntryIndexKeys::from_transaction(self.context_id, &entry.tx)?,
			None => return Ok(None),
		};
		// Verify the complete derived state before mutating either side.
		let component_count = self.indexes.check_owned_by(entry_key, &keys)?;

		let removed = self.entries.shift_remove(entry_key).ok_or_else(|| {
			PoolError::Other(format!(
				"pool entry {} disappeared during exclusive removal",
				entry_key,
			))
		})?;
		self.indexes.remove(entry_key, &keys, component_count);
		Ok(Some(removed))
	}

	/// Remove several entries while preserving insertion order in one linear
	/// `IndexMap` pass. Complete every fallible conversion and consistency check
	/// before mutating either the entries or their derived indexes.
	fn remove_entries(&mut self, entry_keys: &HashSet<Hash>) -> Result<(), PoolError> {
		if entry_keys.is_empty() {
			return Ok(());
		}

		let mut removals = Vec::with_capacity(entry_keys.len());
		let mut removed_components = 0u128;
		for entry_key in entry_keys {
			let entry = self.entries.get(entry_key).ok_or_else(|| {
				PoolError::Other(format!(
					"pool entry {} disappeared during exclusive bulk removal",
					entry_key,
				))
			})?;
			let keys = PoolEntryIndexKeys::from_transaction(self.context_id, &entry.tx)?;
			self.indexes.check_owned_by(entry_key, &keys)?;
			removed_components = removed_components
				.checked_add(keys.components)
				.ok_or_else(|| PoolError::Other("removed component count overflow".into()))?;
			removals.push((*entry_key, keys));
		}

		let component_count = self
			.indexes
			.component_count
			.checked_sub(removed_components)
			.ok_or_else(|| PoolError::Other("pool component count underflow".into()))?;

		// `IndexMap::retain` preserves the relative order of retained entries and
		// rebuilds its positional index once instead of shifting it for every key.
		self.entries
			.retain(|entry_key, _| !entry_keys.contains(entry_key));
		self.indexes.remove_many(&removals, component_count);
		Ok(())
	}

	fn clear_entries(&mut self) {
		self.entries.clear();
		self.indexes.clear();
	}

	pub fn ordered_entry_refs(&self) -> impl Iterator<Item = &PoolEntry> {
		self.entries.values()
	}

	pub fn all_entries(&self) -> Vec<PoolEntry> {
		self.ordered_entry_refs().cloned().collect()
	}

	/// Does the transaction pool contain an entry for the given transaction?
	/// Transactions are compared by their kernels.
	pub fn contains_tx(&self, tx: &Transaction) -> Result<bool, PoolError> {
		let tx_key = Self::tx_key(self.context_id, tx)?;
		match self.entries.get(&tx_key) {
			Some(entry) => Ok(ser::slices_equal_by_hash(
				self.context_id,
				entry.tx.kernels(),
				tx.kernels(),
			)?),
			None => Ok(false),
		}
	}

	/// Query the tx pool for an individual tx matching the representative kernel hash.
	pub fn retrieve_tx_by_kernel_hash(&self, hash: Hash) -> Option<Transaction> {
		self.entries.get(&hash).map(|entry| entry.tx.clone())
	}

	/// Check whether the tx pool contains a tx matching the representative kernel hash.
	pub fn contains_tx_by_kernel_hash(&self, hash: Hash) -> bool {
		self.entries.contains_key(&hash)
	}

	/// Remove the entry matching the provided transaction.
	///
	/// The pool is keyed by representative kernel hash, so callers should use this
	/// instead of reaching into `entries` directly when removing by transaction.
	pub fn remove_tx(&mut self, tx: &Transaction) -> Result<Option<PoolEntry>, PoolError> {
		let tx_key = Self::tx_key(self.context_id, tx)?;
		let remove = self
			.entries
			.get(&tx_key)
			.map(|entry| {
				ser::slices_equal_by_hash(self.context_id, entry.tx.kernels(), tx.kernels())
			})
			.transpose()?
			.unwrap_or(false);

		if remove {
			self.shift_remove_entry(&tx_key)
		} else {
			Ok(None)
		}
	}

	/// Query the tx pool for all known txs based on kernel short_ids
	/// from the provided compact_block.
	/// Note: does not validate that we return the full set of required txs.
	/// The caller will need to validate that themselves.
	pub fn retrieve_transactions(
		&self,
		hash: Hash,
		nonce: u64,
		kern_ids: &[ShortId],
	) -> Result<(Vec<Transaction>, Vec<ShortId>), PoolError> {
		if kern_ids.is_empty() {
			return Ok((vec![], vec![]));
		}

		let kern_id_hashes = kern_ids
			.iter()
			.map(|id| id.hash(self.context_id))
			.collect::<Result<HashSet<Hash>, _>>()?;
		let mut txs = vec![];
		let mut found_id_hashes = HashSet::with_capacity(kern_id_hashes.len());

		// Rehash all entries in the pool using short_ids based on provided hash and nonce.
		'outer: for x in self.entries.values() {
			for k in x.tx.kernels() {
				// rehash each kernel to calculate the block specific short_id
				let short_id = k.short_id(self.context_id, &hash, nonce)?;
				let short_id_hash = short_id.hash(self.context_id)?;
				if kern_id_hashes.contains(&short_id_hash) {
					txs.push(x.tx.clone());
					found_id_hashes.insert(short_id_hash);
				}
				if found_id_hashes.len() == kern_id_hashes.len() {
					break 'outer;
				}
			}
		}

		let mut dedup_txs = Vec::with_capacity(txs.len());
		let mut dedup_tx_hashes = HashSet::with_capacity(txs.len());
		for tx in txs {
			if dedup_tx_hashes.insert(tx.hash(self.context_id)?) {
				dedup_txs.push(tx);
			}
		}

		let mut missing_short_ids = Vec::new();
		for id in kern_ids {
			if !found_id_hashes.contains(&id.hash(self.context_id)?) {
				missing_short_ids.push(id.clone());
			}
		}

		Ok((dedup_txs, missing_short_ids))
	}

	/// Take pool transactions, filtering and ordering them in a way that's
	/// appropriate to put in a mined block. Aggregates chains of dependent
	/// transactions, orders by fee over weight and ensures the total weight
	/// does not exceed the provided max_weight (miner defined block weight).
	pub fn prepare_mineable_transactions(
		&self,
		max_weight: u64,
		secp: &mut Secp256k1,
	) -> Result<Vec<Transaction>, PoolError> {
		let weighting = Weighting::AsLimitedTransaction(max_weight);

		// Sort the txs in the pool via the "bucket" logic to -
		//   * maintain dependency ordering
		//   * maximize cut-through
		//   * maximize overall fees
		let txs = self.bucket_transactions(secp)?;

		// Iteratively apply the txs to the current chain state,
		// rejecting any that do not result in a valid state.
		// Verify these txs produce an aggregated tx below max_weight.
		// Return a vec of all the valid txs.
		let header = self.blockchain.chain_head()?;
		let valid_txs = self.validate_raw_txs(&txs, None, &header, weighting, secp)?;
		Ok(valid_txs)
	}

	pub fn all_transactions(&self) -> Vec<Transaction> {
		self.entries
			.values()
			.map(|entry| entry.tx.clone())
			.collect()
	}

	/// Build the exact aggregate represented by this pool without rechecking
	/// rangeproofs or kernel signatures.
	///
	/// Every entry can reach `entries` only after full component authentication.
	/// Keep that invariant explicit in the return type so this faster path cannot
	/// be used with an arbitrary transaction supplied by a caller.
	pub(crate) fn validated_pool_aggregate(
		&self,
		secp: &Secp256k1,
	) -> Result<Option<ValidatedPoolAggregate>, PoolError> {
		let txs = self.all_transactions();
		if txs.is_empty() {
			return Ok(None);
		}

		Ok(Some(ValidatedPoolAggregate(transaction::aggregate(
			self.context_id,
			&txs,
			secp,
		)?)))
	}

	/// Return a single aggregate tx representing all txs in the pool.
	/// Takes an optional "extra tx" to include in the aggregation.
	/// Returns None if there is nothing to aggregate.
	/// Validates any returned tx, including the single extra tx case.
	pub fn all_transactions_aggregate(
		&self,
		extra_tx: Option<Transaction>,
		secp: &mut Secp256k1,
	) -> Result<Option<Transaction>, PoolError> {
		let mut txs = self.all_transactions();
		txs.extend(extra_tx);

		if txs.is_empty() {
			return Ok(None);
		}

		let tx = transaction::aggregate(self.context_id, &txs, secp)?;

		// Validate the single aggregate transaction "as pool", not subject to tx weight limits.
		tx.validate(self.context_id, Weighting::NoLimit, secp)?;

		Ok(Some(tx))
	}

	// Aggregate this new tx with all existing txs in the pool.
	// If we can validate the aggregated tx against the current chain state
	// then we can safely add the tx to the pool.
	pub(crate) fn add_entry(
		&mut self,
		entry: PoolEntry,
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<(), PoolError> {
		self.add_entry_internal(entry, extra_tx, header, secp)
			.map(|_| ())
	}

	/// Add an entry authenticated before the transaction-pool write lock was
	/// acquired, while accounting for an authenticated aggregate from another
	/// pool. Structural, aggregate, and chain-state validation still runs here;
	/// only unchanged rangeproof and kernel-signature checks are reused.
	pub(crate) fn add_entry_with_validated_extra(
		&mut self,
		entry: ValidatedPoolEntry,
		extra_tx: Option<ValidatedPoolAggregate>,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<(), PoolError> {
		self.add_prevalidated_entry_internal(
			entry,
			extra_tx.map(|aggregate| aggregate.0),
			header,
			secp,
		)
		.map(|_| ())
	}

	/// Add an entry authenticated before the transaction-pool write lock was
	/// acquired and return the exact post-insertion pool aggregate.
	pub(crate) fn add_entry_with_pool_aggregate(
		&mut self,
		entry: ValidatedPoolEntry,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<ValidatedPoolAggregate, PoolError> {
		let aggregate = self.add_prevalidated_entry_internal(entry, None, header, secp)?;
		Ok(ValidatedPoolAggregate(aggregate))
	}

	/// Run the cheap, pool-local portion of admission before any component
	/// authentication or pool-wide aggregate construction.
	fn prepare_entry_for_admission(
		&self,
		entry: &PoolEntry,
	) -> Result<PoolEntryIndexKeys, PoolError> {
		if self.contains_tx(&entry.tx)? {
			return Err(PoolError::DuplicateTx);
		}

		entry.tx.validate_read(self.context_id)?;
		let entry_index_keys = PoolEntryIndexKeys::from_transaction(self.context_id, &entry.tx)?;
		self.indexes.check_conflicts(&entry_index_keys)?;
		Ok(entry_index_keys)
	}

	fn add_entry_internal(
		&mut self,
		entry: PoolEntry,
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<Transaction, PoolError> {
		// Validate cheap structural properties before deriving conflict keys. The
		// indexes are needed because aggregate construction discovers duplicate
		// inputs, outputs, and kernels only after cloning and sorting every retained
		// pool component. Without this precheck, a peer can repeatedly submit
		// distinct, individually valid double spends and make every rejection cost
		// work proportional to the full pool.
		//
		// This index check is not an acceptance shortcut. A miss says only that no
		// already indexed conflict was found; full component authentication,
		// aggregate validation, and chain-state validation below remain mandatory.
		let entry_index_keys = self.prepare_entry_for_admission(&entry)?;

		// The aggregate validation below deliberately skips rangeproof and kernel
		// signature verification for components already accepted into the pool.
		// Fully validate the new component first so add_entry() remains a safe
		// admission boundary independent of its callers.
		entry
			.tx
			.validate(self.context_id, Weighting::AsTransaction, secp)?;
		self.add_authenticated_entry_internal(entry, extra_tx, entry_index_keys, header, secp)
	}

	/// Insert an entry whose individual rangeproofs and kernel signatures have
	/// already been authenticated. This is the path used by `TransactionPool`
	/// after its off-lock validation. Lower-level entry points continue through
	/// `add_entry_internal` and authenticate arbitrary entries themselves.
	fn add_prevalidated_entry_internal(
		&mut self,
		entry: ValidatedPoolEntry,
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<Transaction, PoolError> {
		if entry.context_id != self.context_id {
			return Err(PoolError::Other(format!(
				"validated entry context {} does not match pool context {}",
				entry.context_id, self.context_id,
			)));
		}
		let entry = entry.into_pool_entry();
		let entry_index_keys = self.prepare_entry_for_admission(&entry)?;
		self.add_authenticated_entry_internal(entry, extra_tx, entry_index_keys, header, secp)
	}

	fn add_authenticated_entry_internal(
		&mut self,
		entry: PoolEntry,
		extra_tx: Option<Transaction>,
		entry_index_keys: PoolEntryIndexKeys,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<Transaction, PoolError> {
		// Reject outputs already present in the chain before cloning, sorting, and
		// validating every retained pool component. This is only a negative
		// preflight: validate_raw_aggregate_tx() remains authoritative in case chain
		// state changes after this lookup.
		self.blockchain.validate_outputs(entry.tx.outputs())?;

		// Combine all the txs from the pool with any extra txs provided.
		// extra_tx is crate-internal and must be an aggregate produced from an
		// already validated pool (the txpool aggregate used by the stempool).
		let mut txs = self.all_transactions();

		// Make sure we take extra_tx into consideration here.
		// When adding to stempool we need to account for current txpool.
		txs.extend(extra_tx);

		let agg_tx = if txs.is_empty() {
			// If we have nothing to aggregate then simply return the tx itself.
			entry.tx.clone()
		} else {
			// Create a single aggregated tx from the existing pool txs and the
			// new entry
			txs.push(entry.tx.clone());
			transaction::aggregate(self.context_id, &txs, secp)?
		};

		// Validate aggregated tx (existing pool + new tx), ignoring tx weight limits.
		// Validate against known chain state at the provided header.
		self.validate_raw_aggregate_tx(&agg_tx, header, Weighting::NoLimit, secp)?;
		// If we get here successfully then we can safely add the entry to the pool.
		let entry_key = Self::tx_key(self.context_id, &entry.tx)?;
		self.log_pool_add(&entry, header);
		self.insert_entry(entry_key, entry, &entry_index_keys)?;

		Ok(agg_tx)
	}

	fn log_pool_add(&self, entry: &PoolEntry, header: &BlockHeader) {
		debug!(
			"pool add_entry [{}]: {} ({:?}) [in/out/kern: {}/{}/{}] pool: {} (at block {})",
			self.name,
			entry.tx.hash(self.context_id).unwrap_or(Hash::default()),
			entry.src,
			entry.tx.inputs().len(),
			entry.tx.outputs().len(),
			entry.tx.kernels().len(),
			self.size(),
			header.hash(self.context_id).unwrap_or(Hash::default()),
		);
	}

	fn validate_raw_tx(
		&self,
		tx: &Transaction,
		header: &BlockHeader,
		weighting: Weighting,
		secp: &mut Secp256k1,
	) -> Result<BlockSums, PoolError> {
		// Validate the tx, conditionally checking against weight limits,
		// based on weight verification type.
		tx.validate(self.context_id, weighting, secp)?;
		self.validate_raw_tx_state(tx, header, secp)
	}

	/// Validate an aggregate whose component transactions have already passed
	/// full rangeproof and kernel-signature verification.
	fn validate_raw_aggregate_tx(
		&self,
		tx: &Transaction,
		header: &BlockHeader,
		weighting: Weighting,
		secp: &mut Secp256k1,
	) -> Result<BlockSums, PoolError> {
		tx.validate_aggregate_from_validated_components(self.context_id, weighting, secp)?;
		self.validate_raw_tx_state(tx, header, secp)
	}

	fn validate_raw_tx_state(
		&self,
		tx: &Transaction,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<BlockSums, PoolError> {
		// NRD kernels are only valid once HF3/header version 4 rules apply.
		if tx.kernels().iter().any(|k| k.is_nrd()) {
			if !global::is_nrd_enabled(self.context_id) {
				return Err(PoolError::NRDKernelNotEnabled);
			}
			if header.version < HeaderVersion(4) {
				return Err(PoolError::NRDKernelPreHF3);
			}
		}

		// Re-run context-sensitive admission checks for aggregate candidates.
		self.blockchain.verify_tx_lock_height(tx)?;
		self.blockchain.replay_attack_check(tx)?;

		// Validate the tx against current chain state.
		// Check all inputs are in the current UTXO set.
		// Check all outputs are unique in current UTXO set.
		self.blockchain.validate_tx(tx)?;

		// validate_tx() does not expose spent output metadata, so look up the
		// spent UTXO identifiers here for the coinbase maturity check.
		let spent_utxo = self.blockchain.validate_inputs(&tx.inputs())?;
		let coinbase_inputs: Vec<_> = spent_utxo
			.iter()
			.filter(|x| x.is_coinbase())
			.cloned()
			.collect();
		let coinbase_inputs =
			Inputs::from_output_identifiers(self.context_id, coinbase_inputs.as_slice())?;
		self.blockchain.verify_coinbase_maturity(&coinbase_inputs)?;

		// The supplied header is not required to match the current chain head.
		// It represents the block header the caller is building or setting, so
		// trust this header data here; the pool cannot validate it against the
		// live chain state.
		let new_sums = self.apply_tx_to_block_sums(tx, header, secp)?;
		Ok(new_sums)
	}

	pub fn validate_raw_txs(
		&self,
		txs: &[Transaction],
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		weighting: Weighting,
		secp: &mut Secp256k1,
	) -> Result<Vec<Transaction>, PoolError> {
		let mut valid_txs = vec![];
		let mut candidate_txs = Vec::with_capacity(txs.len().saturating_add(1));

		if let Some(extra_tx) = extra_tx {
			candidate_txs.push(extra_tx);
		};

		for tx in txs {
			candidate_txs.push(tx.clone());

			// Build a single aggregate tx from candidate txs.
			//
			// Keep aggregation failable here. validate_raw_tx() failures below
			// can be treated as candidate-local because they are expected while
			// selecting a best-effort mineable set against current chain state.
			// By contrast, aggregate() failures indicate real structural or
			// cryptographic errors that should be reported to the caller:
			// - input/output/kernel count overflow while sizing aggregate buffers,
			// - consensus hash/sort errors while converting or ordering inputs,
			// - cut-through failure from duplicate remaining inputs or outputs,
			// - kernel offset summing failures from invalid blinds or secp errors,
			// - consensus hash/sort errors while rebuilding the aggregate body.
			let agg_tx = transaction::aggregate(self.context_id, &candidate_txs, secp)?;

			// We know the tx is valid if the entire aggregate tx is valid.
			// validate_raw_tx() failures can represent either candidate invalidity
			// or local validation infrastructure failures (chain validation, header
			// hashing, block sums). We intentionally avoid finer classification here:
			// this path is selecting a best-effort mineable set from already accepted
			// transactions, and distinguishing every local failure from every candidate
			// rejection adds complexity without much practical benefit. Log the concrete
			// error before rejecting the candidate so the details are not lost.
			match self.validate_raw_tx(&agg_tx, header, weighting, secp) {
				Ok(_) => valid_txs.push(tx.clone()),
				Err(e) => {
					let tx_hash = tx.hash(self.context_id).unwrap_or(Hash::default());
					debug!(
						"validate_raw_txs [{}]: skipping tx {} from mineable set due to validation error: {}",
						self.name, tx_hash, e
					);
					candidate_txs.pop();
				}
			}
		}

		Ok(valid_txs)
	}

	/// Lookup unspent outputs to be spent by the provided transaction.
	/// We look for unspent outputs in the current txpool and then in the current utxo.
	pub fn locate_spends(
		&self,
		tx: &Transaction,
		extra_tx: Option<Transaction>,
		secp: &mut Secp256k1,
	) -> Result<(Vec<OutputIdentifier>, Vec<OutputIdentifier>), PoolError> {
		let mut inputs = tx.inputs().into_commit_wrappers(self.context_id)?;

		let agg_tx = self
			.all_transactions_aggregate(extra_tx, secp)?
			.unwrap_or(Transaction::empty());
		let mut outputs: Vec<OutputIdentifier> = agg_tx
			.outputs()
			.iter()
			.map(|out| out.identifier())
			.collect();

		// By applying cut_through to tx inputs and agg_tx outputs we can
		// determine the outputs being spent from the pool and those still unspent
		// that need to be looked up via the current utxo.
		let (spent_utxo, _, _, spent_pool) =
			transaction::cut_through(self.context_id, &mut inputs[..], &mut outputs[..])?;

		// Lookup remaining outputs to be spent from the current utxo.
		let spent_utxo = self.blockchain.validate_inputs(&spent_utxo.into())?;

		Ok((spent_pool.to_vec(), spent_utxo))
	}

	/// Locate spends against the exact indexes for this pool and, optionally,
	/// another pool. Unlike `locate_spends`, this path accepts no raw extra
	/// transaction and therefore does not need to scan or re-authenticate retained
	/// entries.
	pub(crate) fn locate_spends_from_pools(
		&self,
		tx: &Transaction,
		extra_pool: Option<&Pool<B>>,
	) -> Result<(Vec<OutputIdentifier>, Vec<OutputIdentifier>), PoolError> {
		if let Some(extra_pool) = extra_pool {
			if extra_pool.context_id != self.context_id {
				return Err(PoolError::Other(format!(
					"cannot locate spends across pool contexts {} and {}",
					self.context_id, extra_pool.context_id,
				)));
			}
		}

		let mut inputs = tx.inputs().into_commit_wrappers(self.context_id)?;
		ser::sort_by_hash(self.context_id, &mut inputs)?;
		match ser::verify_sorted_and_unique_by_hash(self.context_id, &inputs) {
			Ok(()) => {}
			Err(ser::Error::DuplicateError) => {
				return Err(PoolError::InvalidTx(transaction::Error::CutThrough));
			}
			Err(e) => return Err(e.into()),
		}

		let mut spent_pool = Vec::with_capacity(inputs.len());
		let mut spent_utxo = Vec::with_capacity(inputs.len());
		for input in inputs {
			let commitment = input.commitment();
			let local_output = self.indexes.lookup_unspent_output(&commitment)?;
			let extra_output = match extra_pool {
				Some(extra_pool) => extra_pool.indexes.lookup_unspent_output(&commitment)?,
				None => None,
			};

			match (local_output, extra_output) {
				(Some(_), Some(_)) => return Err(PoolError::DuplicateCommitment),
				(Some(output), None) | (None, Some(output)) => spent_pool.push(output),
				(None, None) => spent_utxo.push(input),
			}
		}

		ser::sort_by_hash(self.context_id, &mut spent_pool)?;
		let spent_utxo = self
			.blockchain
			.validate_inputs(&Inputs::from(spent_utxo.as_slice()))?;

		Ok((spent_pool, spent_utxo))
	}

	fn apply_tx_to_block_sums(
		&self,
		tx: &Transaction,
		header: &BlockHeader,
		secp: &Secp256k1,
	) -> Result<BlockSums, PoolError> {
		let overage = tx.overage()?;

		let offset = { header.total_kernel_offset().add(&tx.offset, &secp) }?;

		let block_sums = self
			.blockchain
			.get_block_sums(&header.hash(self.context_id)?)?;

		// Verify the kernel sums for the block_sums with the new tx applied,
		// accounting for overage and offset.
		let (utxo_sum, kernel_sum) =
			(block_sums, tx as &dyn Committed).verify_kernel_sums(overage, offset, secp)?;

		Ok(BlockSums::new(utxo_sum, kernel_sum))
	}

	/// Reconcile pool entries against the current chain state.
	///
	/// Re-admission is intentionally conservative: any failure to re-add a
	/// transaction is treated as an eviction reason. The pool is only a cache
	/// of unconfirmed transactions, and keeping a transaction whose validity
	/// could not be re-established is worse than dropping it. A false eviction
	/// is not critical because the user can always repost the transaction.
	pub fn reconcile(
		&mut self,
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<(), PoolError> {
		self.reconcile_with_limits(extra_tx, header, secp, RECONCILE_FALLBACK_LIMITS)
	}

	/// Reconcile against an aggregate returned directly by another pool's
	/// admission boundary.
	///
	/// The wrapper proves that every component already passed full rangeproof and
	/// kernel-signature verification. Reconciliation still checks all structural,
	/// aggregate-kernel-sum, and current-chain-state properties; it skips only the
	/// redundant cryptographic authentication of unchanged components.
	pub(crate) fn reconcile_with_pool_aggregate(
		&mut self,
		extra_tx: ValidatedPoolAggregate,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<(), PoolError> {
		let existing_entries = self.all_entries();
		if existing_entries.is_empty() {
			return Ok(());
		}

		self.reconcile_authenticated_with_limits(
			existing_entries,
			Some(extra_tx.0),
			header,
			secp,
			RECONCILE_FALLBACK_LIMITS,
		)
	}

	fn reconcile_with_limits(
		&mut self,
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		secp: &mut Secp256k1,
		fallback_limits: ReconcileFallbackLimits,
	) -> Result<(), PoolError> {
		let existing_entries = self.all_entries();
		if existing_entries.is_empty() {
			return Ok(());
		}

		// The retained entries were fully validated when admitted, but extra_tx is
		// supplied separately. Authenticate it once before using the aggregate fast
		// path so callers cannot smuggle unverified cryptographic components into the
		// candidate set.
		if let Some(extra_tx) = &extra_tx {
			extra_tx.validate(self.context_id, Weighting::NoLimit, secp)?;
		}

		self.reconcile_authenticated_with_limits(
			existing_entries,
			extra_tx,
			header,
			secp,
			fallback_limits,
		)
	}

	/// Common reconciliation path. Callers must either authenticate `extra_tx`
	/// immediately before entering or obtain it as a `ValidatedPoolAggregate`.
	fn reconcile_authenticated_with_limits(
		&mut self,
		existing_entries: Vec<PoolEntry>,
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		secp: &mut Secp256k1,
		fallback_limits: ReconcileFallbackLimits,
	) -> Result<(), PoolError> {
		// Reconciliation normally retains the complete pool. Validate that aggregate
		// once instead of clearing the pool and validating every growing prefix, which
		// is quadratic. If the bulk candidate is invalid, fall back to conservative
		// per-entry filtering so stale transactions are still evicted individually.
		let mut candidate_txs = existing_entries
			.iter()
			.map(|entry| entry.tx.clone())
			.collect::<Vec<_>>();
		candidate_txs.extend(extra_tx.clone());
		let aggregate_result = transaction::aggregate(self.context_id, &candidate_txs, secp)
			.map_err(PoolError::from)
			.and_then(|aggregate| {
				self.validate_raw_aggregate_tx(&aggregate, header, Weighting::NoLimit, secp)
			});
		if aggregate_result.is_ok() {
			return Ok(());
		}
		if let Err(e) = aggregate_result {
			debug!(
				"reconcile [{}]: bulk validation failed, filtering entries individually: {}",
				self.name, e,
			);
		}

		// Re-adding entries one at a time rebuilds and validates every growing
		// aggregate prefix. Estimate that cumulative work before clearing the pool
		// and only use the precise fallback when it is strictly bounded. A false
		// eviction is preferable to holding the pool write lock for quadratic work.
		let prefix_components = extra_tx.as_ref().map(transaction_components).unwrap_or(0);
		let mut fallback_budget =
			ReconcileWorkBudget::with_limits(prefix_components, fallback_limits);
		let fallback_is_bounded = existing_entries.iter().all(|entry| {
			if fallback_budget.charge_attempt(&entry.tx) {
				fallback_budget.record_accept(&entry.tx);
				true
			} else {
				false
			}
		});
		if !fallback_is_bounded {
			warn!(
				"reconcile [{}]: bulk validation failed; dropping {} entries because individual filtering exceeds the reconciliation work budget",
				self.name,
				existing_entries.len(),
			);
			self.clear_entries();
			return Ok(());
		}

		// Logging hashes are diagnostic only; do not let them abort
		// reconciliation after the pool has been cleared.
		let header_hash = header.hash(self.context_id).unwrap_or(Hash::default());
		self.clear_entries();
		for x in existing_entries {
			let tx_hash = x.tx.hash(self.context_id).unwrap_or(Hash::default());
			if let Err(e) = self.add_entry(x, extra_tx.clone(), header, secp) {
				warn!(
					"reconcile [{}]: evicting tx {} at block {} due to error: {}",
					self.name, tx_hash, header_hash, e,
				);
			}
		}
		Ok(())
	}

	// Use our bucket logic to identify the best transaction for eviction and evict it.
	// We want to avoid evicting a transaction where another transaction depends on it.
	// We want to evict a transaction with low fee_rate.
	// This is intentionally a simple heuristic. bucket_transactions() skips rare
	// multi-parent dependency cases instead of merging buckets or building a full
	// dependency graph, so the eviction candidate set can be incomplete. That may
	// temporarily evict a parent while a dependent transaction remains in the
	// pool, but reconciliation/validation can clean this up and users can repost
	// unconfirmed transactions. Avoid overcomplicating pool reconciliation for
	// this non-critical case.
	//
	// Resource-bound contract: in normal node operation this pool is populated
	// through TransactionPool, whose admission checks cap it at the configured
	// PoolConfig::max_pool_size. This is an explicit maintenance operation, not a
	// peer-triggered admission path. ReconcileWorkBudget limits are for repeated
	// replay/reconciliation work and intentionally do not gate eviction, because
	// exhausting such a budget here would leave a full pool unchanged. If eviction
	// becomes automatically triggerable by untrusted traffic, add a bounded
	// fallback that still removes an entry.
	pub fn evict_transaction(&mut self, secp: &mut Secp256k1) -> Result<(), PoolError> {
		let txs = self.bucket_transactions(secp)?;
		if let Some(evictable_transaction) = txs.last() {
			let mut evict_keys = Vec::new();
			for (key, entry) in &self.entries {
				if entry
					.tx
					.eq_by_hash(self.context_id, evictable_transaction)?
				{
					evict_keys.push(*key);
				}
			}
			for key in evict_keys {
				self.shift_remove_entry(&key)?;
			}
		};
		Ok(())
	}

	/// Buckets consist of a vec of txs and track the aggregate fee_rate.
	/// We aggregate (cut-through) dependent transactions within a bucket *unless* adding a tx
	/// would reduce the aggregate fee_rate, in which case we start a new bucket.
	/// Note this new bucket will by definition have a lower fee_rate than the bucket
	/// containing the tx it depends on.
	/// Sorting the buckets by fee_rate will therefore preserve dependency ordering,
	/// maximizing both cut-through and overall fees.
	fn bucket_transactions(&self, secp: &mut Secp256k1) -> Result<Vec<Transaction>, PoolError> {
		let mut tx_buckets: Vec<Bucket> = Vec::new();
		let mut output_commits = HashMap::new();
		let mut rejected = HashSet::new();

		for entry in self.entries.values() {
			// check the commits index to find parents and their position
			// if single parent then we are good, we can bucket it with its parent
			// if multiple parents then we need to combine buckets, but for now simply reject it (rare case)
			let mut insert_pos = None;
			let mut is_rejected = false;

			let tx_inputs = entry.tx.inputs().into_commit_wrappers(self.context_id)?;
			for input in tx_inputs {
				if rejected.contains(&input.commitment()) {
					// Depends on a rejected tx, so reject this one.
					is_rejected = true;
					continue;
				} else if let Some(pos) = output_commits.get(&input.commitment()) {
					if insert_pos.is_some() {
						// Multiple dependencies so reject this tx (pick it up in next block).
						is_rejected = true;
						continue;
					} else {
						// Track the pos of the bucket we fall into.
						insert_pos = Some(*pos);
					}
				}
			}

			// If this tx is rejected then store all output commitments in our rejected set.
			if is_rejected {
				for out in entry.tx.outputs() {
					rejected.insert(out.commitment());
				}

				// Done with this entry (rejected), continue to next entry.
				continue;
			}

			match insert_pos {
				None => {
					// No parent tx, just add to the end in its own bucket.
					// This is the common case for non 0-conf txs in the txpool.
					// We assume the tx is valid here as we validated it on the way into the txpool.
					insert_pos = Some(tx_buckets.len());
					tx_buckets.push(Bucket::new(entry.tx.clone(), tx_buckets.len())?);
				}
				Some(pos) => {
					// We found a single parent tx, so aggregate in the bucket
					// if the aggregate tx is a valid tx.
					// Otherwise discard and let the next block pick this tx up.
					let bucket = &tx_buckets[pos];

					match bucket.aggregate_with_tx(self.context_id, entry.tx.clone(), secp) {
						Ok(new_bucket) => {
							if new_bucket.fee_rate >= bucket.fee_rate {
								// Only aggregate if it would not reduce the fee_rate ratio.
								tx_buckets[pos] = new_bucket;
							} else {
								// Otherwise put it in its own bucket at the end.
								// Note: This bucket will have a lower fee_rate
								// than the bucket it depends on.
								insert_pos = Some(tx_buckets.len());
								tx_buckets.push(Bucket::new(entry.tx.clone(), tx_buckets.len())?);
							}
						}
						Err(e) => {
							let tx_hash = entry.tx.hash(self.context_id).unwrap_or(Hash::default());
							warn!(
								"bucket_transactions [{}]: rejecting tx {} due to bucket aggregation error: {}",
								self.name, tx_hash, e,
							);
							// Be conservative here: aggregate_with_tx can fail in lower-level
							// aggregation or fee-rate calculation. We intentionally avoid full
							// cryptographic validation in this bucket-ordering heuristic; final
							// mineable candidates are validated later against the chain state.
							is_rejected = true;
						}
					}
				}
			}

			if is_rejected {
				for out in entry.tx.outputs() {
					rejected.insert(out.commitment());
				}
			} else if let Some(insert_pos) = insert_pos {
				// We successfully added this tx to our set of buckets.
				// Update commits index for subsequent txs.
				for out in entry.tx.outputs() {
					output_commits.insert(out.commitment(), insert_pos);
				}
			}
		}

		// Sort buckets by fee_rate (descending) and age (oldest first).
		// Txs with highest fee_rate will be prioritied.
		// Aggregation that increases the fee_rate of a bucket will prioritize the bucket.
		// Oldest (based on pool insertion time) will then be prioritized.
		//
		// This is intentionally not a full dependency-aware package selection algorithm.
		// A child tx that lowers its parent bucket fee_rate can be split into its own
		// bucket, and later descendants can raise that child bucket above the parent
		// after this sort. Linear selection may then skip those high-fee descendants
		// until the low-fee parent is selected. We accept that tradeoff: dependencies
		// should not let low-fee parents gain priority just because a later child pays
		// more, and keeping this heuristic simple is preferable here.
		tx_buckets.sort_unstable_by_key(|x| (Reverse(x.fee_rate), x.age_idx));

		Ok(tx_buckets.into_iter().flat_map(|x| x.raw_txs).collect())
	}

	/// TODO - This is kernel based. How does this interact with NRD?
	///
	/// Resolve possible matches through the exact kernel index. Admission calls this
	/// while holding the transaction-pool write lock, so work here must depend on
	/// the submitted kernel set rather than on every retained pool entry.
	pub fn find_matching_transactions(
		&self,
		kernels: &[TxKernel],
	) -> Result<Vec<Transaction>, PoolError> {
		// While the inputs outputs can be cut-through the kernel will stay intact
		// In order to deaggregate tx we look for tx with the same kernel
		let kernel_hashes = kernels
			.iter()
			.map(|kernel| kernel.hash(self.context_id))
			.collect::<Result<Vec<_>, _>>()?;
		let kernel_set = kernel_hashes.iter().copied().collect::<HashSet<_>>();

		// A matching pool entry must own at least one submitted kernel. Deduplicate
		// owners and retain pool insertion order without walking unrelated entries.
		let mut seen_owners = HashSet::with_capacity(kernel_hashes.len());
		let mut candidate_owners = Vec::new();
		for kernel_hash in &kernel_hashes {
			if let Some(owner) = self.indexes.kernels.get(kernel_hash) {
				if seen_owners.insert(*owner) {
					let position = self.entries.get_index_of(owner).ok_or_else(|| {
						PoolError::Other(format!(
							"pool kernel index references missing entry {}",
							owner,
						))
					})?;
					candidate_owners.push((position, *owner));
				}
			}
		}
		candidate_owners.sort_unstable_by_key(|(position, _)| *position);

		let mut found_txs = Vec::with_capacity(candidate_owners.len());
		for (_, owner) in candidate_owners {
			let entry = self.entries.get(&owner).ok_or_else(|| {
				PoolError::Other(format!(
					"pool kernel index references missing entry {}",
					owner,
				))
			})?;
			let mut is_subset = true;
			for entry_kernel in entry.tx.kernels() {
				if !kernel_set.contains(&entry_kernel.hash(self.context_id)?) {
					is_subset = false;
					break;
				}
			}
			if is_subset {
				found_txs.push(entry.tx.clone());
			}
		}
		Ok(found_txs)
	}

	/// Quick reconciliation step - we can evict any txs in the pool where
	/// inputs or kernels intersect with the block.
	pub fn reconcile_block(&mut self, block: &Block) -> Result<(), PoolError> {
		// Filter txs in the pool based on the latest block.
		// Reject any txs where we see a matching tx kernel in the block.
		// Also reject any txs where we see a conflicting tx,
		// where an input is spent in a different tx.
		let block_inputs = block.inputs().into_commit_wrappers(self.context_id)?;
		let block_kernel_hashes = block
			.kernels()
			.iter()
			.map(|kernel| kernel.hash(self.context_id))
			.collect::<Result<HashSet<_>, _>>()?;
		let block_input_hashes = block_inputs
			.iter()
			.map(|input| input.hash(self.context_id))
			.collect::<Result<HashSet<_>, _>>()?;
		let mut evict_keys = HashSet::new();
		for (key, entry) in &self.entries {
			let mut kernel_conflict = false;
			for kernel in entry.tx.kernels() {
				if block_kernel_hashes.contains(&kernel.hash(self.context_id)?) {
					kernel_conflict = true;
					break;
				}
			}
			let mut input_conflict = false;
			if !kernel_conflict {
				let tx_inputs = entry.tx.inputs().into_commit_wrappers(self.context_id)?;
				for input in &tx_inputs {
					if block_input_hashes.contains(&input.hash(self.context_id)?) {
						input_conflict = true;
						break;
					}
				}
			}
			if kernel_conflict || input_conflict {
				evict_keys.insert(*key);
			}
		}

		self.remove_entries(&evict_keys)
	}

	/// Size of the pool.
	pub fn size(&self) -> usize {
		self.entries.len()
	}

	/// Number of input, output, and kernel components currently represented by
	/// pool entries. Used to budget operations that repeatedly rebuild aggregates.
	pub(crate) fn component_count(&self) -> u128 {
		self.indexes.component_count
	}

	/// Remove all entries from the pool.
	pub fn clear(&mut self) {
		self.clear_entries();
	}

	/// Number of transaction kernels in the pool.
	/// This may differ from the size (number of transactions) due to tx aggregation.
	pub fn kernel_count(&self) -> usize {
		self.entries.values().map(|x| x.tx.kernels().len()).sum()
	}

	/// Is the pool empty?
	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}
}

struct Bucket {
	raw_txs: Vec<Transaction>,
	fee_rate: u64,
	age_idx: usize,
}

impl Bucket {
	/// Construct a new bucket with the given tx.
	/// also specifies an "age_idx" so we can sort buckets by age
	/// as well as fee_rate. Txs are maintained in the pool in insert order
	/// so buckets with low age_idx contain oldest txs.
	fn new(tx: Transaction, age_idx: usize) -> Result<Bucket, PoolError> {
		Ok(Bucket {
			fee_rate: tx.fee_rate()?,
			raw_txs: vec![tx],
			age_idx,
		})
	}

	fn aggregate_with_tx(
		&self,
		context_id: u32,
		new_tx: Transaction,
		secp: &mut Secp256k1,
	) -> Result<Bucket, PoolError> {
		let mut raw_txs = self.raw_txs.clone();
		raw_txs.push(new_tx);
		let agg_tx = transaction::aggregate(context_id, &raw_txs, secp)?;
		Ok(Bucket {
			fee_rate: agg_tx.fee_rate()?,
			raw_txs: raw_txs,
			age_idx: self.age_idx,
		})
	}
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
	use super::*;
	use crate::transaction_pool::TransactionPool;
	use crate::types::{NoopPoolAdapter, PoolConfig, TxSource};
	use mwc_core::core::{KernelFeatures, NRDRelativeHeight};
	use mwc_core::libtx::{aggsig, build, ProofBuilder};
	use mwc_crates::secp::{pedersen::Commitment, ContextFlag};
	use mwc_keychain::{BlindingFactor, ExtKeychain, Keychain};
	use std::convert::TryInto;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Mutex;

	struct AcceptingChain;

	impl BlockChain for AcceptingChain {
		fn verify_coinbase_maturity(&self, _inputs: &Inputs) -> Result<(), PoolError> {
			Ok(())
		}

		fn verify_tx_lock_height(&self, _tx: &Transaction) -> Result<(), PoolError> {
			Ok(())
		}

		fn validate_tx(&self, _tx: &Transaction) -> Result<(), PoolError> {
			Ok(())
		}

		fn validate_outputs(&self, _outputs: &[Output]) -> Result<(), PoolError> {
			Ok(())
		}

		fn validate_inputs(&self, _inputs: &Inputs) -> Result<Vec<OutputIdentifier>, PoolError> {
			Ok(vec![])
		}

		fn chain_head(&self) -> Result<BlockHeader, PoolError> {
			Err(PoolError::Other("unused test method".into()))
		}

		fn get_block_header(&self, _hash: &Hash) -> Result<BlockHeader, PoolError> {
			Err(PoolError::Other("unused test method".into()))
		}

		fn get_block_sums(&self, _hash: &Hash) -> Result<BlockSums, PoolError> {
			Ok(BlockSums::empty())
		}

		fn replay_attack_check(&self, _tx: &Transaction) -> Result<(), PoolError> {
			Ok(())
		}
	}

	#[derive(Default)]
	struct SelectiveChain {
		rejected_output: Mutex<Option<Commitment>>,
		validate_output_calls: AtomicUsize,
		validate_calls: AtomicUsize,
	}

	impl SelectiveChain {
		fn reject_output(&self, commitment: Commitment) {
			*self.rejected_output.lock().unwrap() = Some(commitment);
		}

		fn validate_calls(&self) -> usize {
			self.validate_calls.load(Ordering::Relaxed)
		}

		fn validate_output_calls(&self) -> usize {
			self.validate_output_calls.load(Ordering::Relaxed)
		}
	}

	impl BlockChain for SelectiveChain {
		fn verify_coinbase_maturity(&self, _inputs: &Inputs) -> Result<(), PoolError> {
			Ok(())
		}

		fn verify_tx_lock_height(&self, _tx: &Transaction) -> Result<(), PoolError> {
			Ok(())
		}

		fn validate_tx(&self, tx: &Transaction) -> Result<(), PoolError> {
			self.validate_calls.fetch_add(1, Ordering::Relaxed);
			let rejected_output = *self.rejected_output.lock().unwrap();
			if rejected_output.is_some_and(|commitment| {
				tx.outputs()
					.iter()
					.any(|output| output.commitment() == commitment)
			}) {
				return Err(PoolError::DuplicateCommitment);
			}
			Ok(())
		}

		fn validate_outputs(&self, outputs: &[Output]) -> Result<(), PoolError> {
			self.validate_output_calls.fetch_add(1, Ordering::Relaxed);
			let rejected_output = *self.rejected_output.lock().unwrap();
			if rejected_output.is_some_and(|commitment| {
				outputs
					.iter()
					.any(|output| output.commitment() == commitment)
			}) {
				return Err(PoolError::DuplicateCommitment);
			}
			Ok(())
		}

		fn validate_inputs(&self, _inputs: &Inputs) -> Result<Vec<OutputIdentifier>, PoolError> {
			Ok(vec![])
		}

		fn chain_head(&self) -> Result<BlockHeader, PoolError> {
			Err(PoolError::Other("unused test method".into()))
		}

		fn get_block_header(&self, _hash: &Hash) -> Result<BlockHeader, PoolError> {
			Err(PoolError::Other("unused test method".into()))
		}

		fn get_block_sums(&self, _hash: &Hash) -> Result<BlockSums, PoolError> {
			Ok(BlockSums::empty())
		}

		fn replay_attack_check(&self, _tx: &Transaction) -> Result<(), PoolError> {
			Ok(())
		}
	}

	fn test_transaction(
		input_value: u64,
		output_value: u64,
		key_index: u32,
		keychain: &ExtKeychain,
		secp: &mut Secp256k1,
	) -> Transaction {
		let input_id = ExtKeychain::derive_key_id(1, key_index, 0, 0, 0).unwrap();
		let output_id = ExtKeychain::derive_key_id(1, key_index + 1, 0, 0, 0).unwrap();
		build::transaction(
			0,
			secp,
			KernelFeatures::Plain {
				fee: (input_value - output_value).try_into().unwrap(),
			},
			&[
				build::input(input_value, input_id),
				build::output(output_value, output_id),
			],
			keychain,
			&ProofBuilder::new(secp, keychain).unwrap(),
		)
		.unwrap()
	}

	fn test_nrd_transaction(
		input_value: u64,
		output_value: u64,
		input_key_index: u32,
		output_key_index: u32,
		relative_height: u64,
		excess: &BlindingFactor,
		keychain: &ExtKeychain,
		secp: &mut Secp256k1,
	) -> Transaction {
		let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: (input_value - output_value).try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(relative_height).unwrap(),
		})
		.unwrap();
		let msg = kernel.msg_to_sign(0).unwrap();
		let secret_key = excess.secret_key(secp).unwrap();
		kernel.excess = secp.commit(0, secret_key).unwrap();
		let public_key = kernel.excess.to_pubkey(secp).unwrap();
		kernel.excess_sig = aggsig::sign_with_blinding(secp, &msg, excess, &public_key).unwrap();
		kernel.verify(0, secp).unwrap();

		let input_id = ExtKeychain::derive_key_id(1, input_key_index, 0, 0, 0).unwrap();
		let output_id = ExtKeychain::derive_key_id(1, output_key_index, 0, 0, 0).unwrap();
		build::transaction_with_kernel(
			0,
			secp,
			&[
				build::input(input_value, input_id),
				build::output(output_value, output_id),
			],
			kernel,
			excess.clone(),
			keychain,
			&ProofBuilder::new(secp, keychain).unwrap(),
		)
		.unwrap()
	}

	fn populated_test_pool() -> (
		Pool<SelectiveChain>,
		Arc<SelectiveChain>,
		Vec<Transaction>,
		BlockHeader,
		Secp256k1,
	) {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[11u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let chain = Arc::new(SelectiveChain::default());
		let mut pool = Pool::new(0, chain.clone(), "test".into());
		let txs = vec![
			test_transaction(10, 8, 1, &keychain, &mut secp),
			test_transaction(11, 9, 3, &keychain, &mut secp),
			test_transaction(12, 10, 5, &keychain, &mut secp),
		];

		for tx in &txs {
			pool.add_entry(
				PoolEntry::new(tx.clone(), TxSource::Broadcast),
				None,
				&header,
				&mut secp,
			)
			.unwrap();
		}

		(pool, chain, txs, header, secp)
	}

	fn assert_pool_indexes_consistent<B: BlockChain>(pool: &Pool<B>) {
		let mut expected_inputs = HashMap::new();
		let mut expected_outputs = HashMap::new();
		let mut expected_kernels = HashMap::new();
		let mut expected_nrd_excesses = HashMap::new();
		let mut expected_components = 0u128;

		for (entry_key, entry) in &pool.entries {
			let keys = PoolEntryIndexKeys::from_transaction(pool.context_id, &entry.tx).unwrap();
			for input in keys.inputs {
				assert_eq!(expected_inputs.insert(input, *entry_key), None);
			}
			for output in keys.outputs {
				assert!(expected_outputs
					.insert(output.commitment(), (*entry_key, output))
					.is_none());
			}
			for kernel in keys.kernels {
				assert_eq!(expected_kernels.insert(kernel, *entry_key), None);
			}
			for excess in keys.nrd_excesses {
				assert_eq!(expected_nrd_excesses.insert(excess, *entry_key), None);
			}
			expected_components = expected_components.checked_add(keys.components).unwrap();
		}

		assert_eq!(pool.indexes.spent_inputs, expected_inputs);
		assert_eq!(pool.indexes.produced_outputs.len(), expected_outputs.len());
		for (commitment, (owner, identifier)) in expected_outputs {
			let indexed = pool.indexes.produced_outputs.get(&commitment).unwrap();
			assert_eq!(indexed.owner, owner);
			assert_eq!(indexed.features, identifier.features);
		}
		assert_eq!(pool.indexes.kernels, expected_kernels);
		assert_eq!(pool.indexes.nrd_excesses, expected_nrd_excesses);
		assert_eq!(pool.indexes.component_count, expected_components);
	}

	#[test]
	fn find_matching_transactions_uses_kernel_index_without_scanning_unrelated_entries() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[29u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let mut pool = Pool::new(0, Arc::new(AcceptingChain), "test".into());

		let first = test_transaction(10, 8, 1, &keychain, &mut secp);
		let second = test_transaction(11, 9, 3, &keychain, &mut secp);
		let known = transaction::aggregate(0, &[first.clone(), second], &secp).unwrap();
		let unrelated = test_transaction(12, 10, 5, &keychain, &mut secp);
		let fresh = test_transaction(13, 11, 7, &keychain, &mut secp);
		let complete_candidate =
			transaction::aggregate(0, &[known.clone(), fresh.clone()], &secp).unwrap();
		let partial_candidate = transaction::aggregate(0, &[first, fresh], &secp).unwrap();

		pool.add_entry(
			PoolEntry::new(known.clone(), TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();
		pool.add_entry(
			PoolEntry::new(unrelated.clone(), TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();

		// Production mutation paths keep entries and indexes synchronized. Clearing
		// this unrelated entry's kernels is a canary: a full-pool scan would inspect
		// it and incorrectly treat its empty kernel set as a subset of every request.
		let unrelated_key = Pool::<AcceptingChain>::tx_key(0, &unrelated).unwrap();
		pool.entries
			.get_mut(&unrelated_key)
			.unwrap()
			.tx
			.body
			.kernels
			.clear();

		let found = pool
			.find_matching_transactions(complete_candidate.kernels())
			.unwrap();
		assert_eq!(found.len(), 1);
		assert_eq!(found[0].hash(0).unwrap(), known.hash(0).unwrap());

		// Sharing only one kernel with an aggregated pool entry is not enough; all
		// kernels belonging to that entry must be present before deaggregation.
		assert!(pool
			.find_matching_transactions(partial_candidate.kernels())
			.unwrap()
			.is_empty());
	}

	#[test]
	fn reconcile_block_bulk_removal_preserves_order_and_indexes() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[23u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let mut pool = Pool::new(0, Arc::new(AcceptingChain), "test".into());
		let mut txs = Vec::new();

		for index in 0..5u32 {
			let input_value = 10 + u64::from(index);
			let tx = test_transaction(
				input_value,
				input_value - 2,
				1 + index * 2,
				&keychain,
				&mut secp,
			);
			pool.add_entry(
				PoolEntry::new(tx.clone(), TxSource::Broadcast),
				None,
				&header,
				&mut secp,
			)
			.unwrap();
			txs.push(tx);
		}

		let expected_entry_keys = [0usize, 2, 4]
			.into_iter()
			.map(|index| Pool::<AcceptingChain>::tx_key(0, &txs[index]).unwrap())
			.collect::<Vec<_>>();
		let mut block = Block::default(0);
		block.body.kernels.extend_from_slice(txs[1].kernels());
		block.body.kernels.extend_from_slice(txs[3].kernels());

		pool.reconcile_block(&block).unwrap();

		assert_eq!(
			pool.entries.keys().copied().collect::<Vec<_>>(),
			expected_entry_keys
		);
		assert!(!pool.contains_tx(&txs[1]).unwrap());
		assert!(!pool.contains_tx(&txs[3]).unwrap());
		assert_pool_indexes_consistent(&pool);
	}

	#[test]
	fn transaction_pool_block_reconcile_reuses_authenticated_components() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[37u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let chain = Arc::new(AcceptingChain);
		let mut transaction_pool = TransactionPool::new(
			0,
			PoolConfig::default(),
			chain.clone(),
			Arc::new(NoopPoolAdapter {}),
		);

		let public_tx = test_transaction(10, 8, 1, &keychain, &mut secp);
		transaction_pool
			.txpool
			.add_entry(
				PoolEntry::new(public_tx, TxSource::Broadcast),
				None,
				&header,
				&mut secp,
			)
			.unwrap();

		let txpool_aggregate = transaction_pool
			.txpool
			.validated_pool_aggregate(&secp)
			.unwrap();
		let stem_tx = test_transaction(11, 9, 3, &keychain, &mut secp);
		let stem_hash = stem_tx.hash(0).unwrap();
		let stem_entry =
			ValidatedPoolEntry::authenticate(0, stem_tx, TxSource::Broadcast, &mut secp).unwrap();
		transaction_pool
			.stempool
			.add_entry_with_validated_extra(stem_entry, txpool_aggregate, &header, &mut secp)
			.unwrap();

		// Production insertion authenticates this proof. Corrupt it afterward as a
		// canary: reconciliation must reuse that admission invariant instead of
		// repeating rangeproof and kernel-signature verification for every block.
		let retained = transaction_pool.txpool.entries.values_mut().next().unwrap();
		retained.tx.body.outputs[0].proof.proof[0] ^= 1;
		assert!(retained
			.tx
			.validate(0, Weighting::AsTransaction, &mut secp)
			.is_err());
		assert!(transaction_pool
			.txpool
			.all_transactions_aggregate(None, &mut secp)
			.is_err());

		let (fluffable_txs, removed) = transaction_pool
			.reconcile_stempool_for_fluff(&header, &mut secp)
			.unwrap();
		assert_eq!(removed, 0);
		assert_eq!(fluffable_txs.len(), 1);
		assert_eq!(fluffable_txs[0].hash(0).unwrap(), stem_hash);

		let block = Block {
			header,
			body: Default::default(),
		};
		transaction_pool.reconcile_block(&block, &mut secp);

		assert_eq!(transaction_pool.txpool.size(), 1);
		assert_eq!(transaction_pool.stempool.size(), 1);
		assert_pool_indexes_consistent(&transaction_pool.txpool);
		assert_pool_indexes_consistent(&transaction_pool.stempool);
	}

	#[test]
	fn add_entry_fully_validates_new_component_before_aggregate_fast_path() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[7u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let mut pool = Pool::new(0, Arc::new(AcceptingChain), "test".into());

		let first = test_transaction(10, 8, 1, &keychain, &mut secp);
		pool.add_entry(
			PoolEntry::new(first, TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();

		let mut invalid = test_transaction(11, 9, 3, &keychain, &mut secp);
		invalid.body.outputs[0].proof.proof[0] ^= 1;
		let err = pool
			.add_entry(
				PoolEntry::new(invalid.clone(), TxSource::Broadcast),
				None,
				&header,
				&mut secp,
			)
			.unwrap_err();

		assert!(matches!(err, PoolError::InvalidTx(_)));
		assert_eq!(pool.size(), 1);

		assert_pool_indexes_consistent(&pool);
	}

	#[test]
	fn prevalidated_entry_reuses_authentication_after_input_conversion() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[41u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let mut pool = Pool::new(0, Arc::new(AcceptingChain), "test".into());

		let tx = test_transaction(10, 8, 1, &keychain, &mut secp);
		let mut entry =
			ValidatedPoolEntry::authenticate(0, tx, TxSource::Broadcast, &mut secp).unwrap();
		let resolved_inputs = entry
			.transaction()
			.inputs()
			.into_commit_wrappers(0)
			.unwrap()
			.into_iter()
			.map(|input| OutputIdentifier::new(OutputFeatures::Plain, &input.commitment()))
			.collect::<Vec<_>>();

		// The private wrapper prevents this mutation in production. Corrupt the
		// authenticated proof here as a canary: input conversion and locked pool
		// admission must reuse component authentication, while still rechecking
		// structural validity, kernel sums, conflicts, and chain state.
		entry.entry.tx.body.outputs[0].proof.proof[0] ^= 1;
		assert!(entry
			.transaction()
			.validate(0, Weighting::AsTransaction, &mut secp)
			.is_err());

		let entry = entry
			.convert_inputs_v2(&[], &resolved_inputs, &secp)
			.unwrap();
		pool.add_entry_with_pool_aggregate(entry, &header, &mut secp)
			.unwrap();

		assert_eq!(pool.size(), 1);
		assert_pool_indexes_consistent(&pool);
	}

	#[test]
	fn chain_output_conflict_is_rejected_before_pool_aggregate_construction() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[43u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let chain = Arc::new(SelectiveChain::default());
		let mut pool = Pool::new(0, chain.clone(), "test".into());

		let retained_tx = test_transaction(10, 8, 1, &keychain, &mut secp);
		pool.add_entry(
			PoolEntry::new(retained_tx, TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();

		let rejected_tx = test_transaction(12, 10, 3, &keychain, &mut secp);
		chain.reject_output(rejected_tx.outputs()[0].commitment());
		let validate_calls = chain.validate_calls();
		let validate_output_calls = chain.validate_output_calls();

		// Poison the retained transaction with duplicate inputs as an aggregation
		// canary. Production code cannot mutate an admitted entry this way. If the
		// output preflight moves behind aggregate construction, cut-through will fail
		// before the expected chain duplicate-output error is returned.
		let original_retained_tx = pool.entries.values().next().unwrap().tx.clone();
		let mut duplicate_inputs = original_retained_tx
			.inputs()
			.into_commit_wrappers(0)
			.unwrap();
		duplicate_inputs.push(duplicate_inputs[0].clone());
		pool.entries.values_mut().next().unwrap().tx.body.inputs =
			Inputs::from(duplicate_inputs.as_slice());

		let entry =
			ValidatedPoolEntry::authenticate(0, rejected_tx, TxSource::Broadcast, &mut secp)
				.unwrap();
		let err = pool
			.add_entry_with_pool_aggregate(entry, &header, &mut secp)
			.err()
			.expect("chain output conflict must be rejected");

		pool.entries.values_mut().next().unwrap().tx = original_retained_tx;

		assert!(matches!(err, PoolError::DuplicateCommitment));
		assert_eq!(chain.validate_calls(), validate_calls);
		assert_eq!(
			chain.validate_output_calls(),
			validate_output_calls.checked_add(1).unwrap()
		);
		assert_eq!(pool.size(), 1);
		assert_pool_indexes_consistent(&pool);
	}

	#[test]
	fn conflicting_input_is_rejected_before_pool_wide_validation() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[13u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let chain = Arc::new(SelectiveChain::default());
		let mut pool = Pool::new(0, chain.clone(), "test".into());

		let accepted = test_transaction(10, 8, 1, &keychain, &mut secp);
		pool.add_entry(
			PoolEntry::new(accepted, TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();
		let validation_calls = chain.validate_calls();

		// Same input commitment, but a different output, fee, kernel, signature,
		// proof, and transaction hash. A transaction-hash cache cannot recognize
		// this retry, while the spent-input index rejects it without scanning the
		// pool.
		let conflicting = test_transaction(10, 7, 1, &keychain, &mut secp);
		let err = pool
			.add_entry(
				PoolEntry::new(conflicting, TxSource::Broadcast),
				None,
				&header,
				&mut secp,
			)
			.err()
			.expect("conflicting input must be rejected");

		assert!(matches!(err, PoolError::DuplicateKernelOrDuplicateSpent(_)));
		assert_eq!(chain.validate_calls(), validation_calls);
		assert_eq!(pool.size(), 1);
		assert_pool_indexes_consistent(&pool);
	}

	#[test]
	fn conflicting_nrd_excess_is_rejected_by_exact_index() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(true);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[31u8; 32], false).unwrap();
		let mut header = global::get_genesis_block(&secp, 0).unwrap().header;
		header.version = HeaderVersion(4);
		let mut pool = Pool::new(0, Arc::new(AcceptingChain), "test".into());
		let excess = BlindingFactor::rand(&secp).unwrap();

		let accepted = test_nrd_transaction(10, 8, 1, 2, 2, &excess, &keychain, &mut secp);
		let conflicting = test_nrd_transaction(12, 10, 3, 4, 3, &excess, &keychain, &mut secp);

		assert_eq!(
			accepted.kernels()[0].excess(),
			conflicting.kernels()[0].excess()
		);
		assert_ne!(
			accepted.kernels()[0].hash(0).unwrap(),
			conflicting.kernels()[0].hash(0).unwrap()
		);

		pool.add_entry(
			PoolEntry::new(accepted.clone(), TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();
		assert_pool_indexes_consistent(&pool);

		// The full kernel hashes differ, but NRD uniqueness is based on excess.
		// Reject through the exact index before building a pool-wide aggregate.
		assert!(matches!(
			pool.check_pool_conflicts(&conflicting),
			Err(PoolError::NRDKernelRelativeHeight)
		));
		assert!(matches!(
			pool.add_entry(
				PoolEntry::new(conflicting.clone(), TxSource::Broadcast),
				None,
				&header,
				&mut secp,
			),
			Err(PoolError::NRDKernelRelativeHeight)
		));
		assert_eq!(pool.size(), 1);
		assert_pool_indexes_consistent(&pool);

		// Removing the owner must remove its NRD excess index record as well.
		assert!(pool.remove_tx(&accepted).unwrap().is_some());
		assert!(pool.check_pool_conflicts(&conflicting).is_ok());
		pool.add_entry(
			PoolEntry::new(conflicting, TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();
		assert_pool_indexes_consistent(&pool);
		pool.clear();
		assert_pool_indexes_consistent(&pool);
	}

	#[test]
	fn pool_child_spend_is_allowed_once_and_removal_updates_indexes() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[15u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let mut pool = Pool::new(0, Arc::new(AcceptingChain), "test".into());

		let parent = test_transaction(10, 8, 1, &keychain, &mut secp);
		let child = test_transaction(8, 6, 2, &keychain, &mut secp);
		pool.add_entry(
			PoolEntry::new(parent, TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();
		pool.add_entry(
			PoolEntry::new(child.clone(), TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();
		assert_pool_indexes_consistent(&pool);

		let alternate_child = test_transaction(8, 5, 2, &keychain, &mut secp);
		assert!(matches!(
			pool.add_entry(
				PoolEntry::new(alternate_child.clone(), TxSource::Broadcast),
				None,
				&header,
				&mut secp,
			),
			Err(PoolError::DuplicateKernelOrDuplicateSpent(_))
		));

		assert!(pool.remove_tx(&child).unwrap().is_some());
		assert_pool_indexes_consistent(&pool);
		pool.add_entry(
			PoolEntry::new(alternate_child, TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();
		assert_pool_indexes_consistent(&pool);

		pool.clear();
		assert!(pool.is_empty());
		assert_pool_indexes_consistent(&pool);
	}

	#[test]
	fn indexed_spend_lookup_tracks_internal_spends_and_removals() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[17u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let mut pool = Pool::new(0, Arc::new(AcceptingChain), "test".into());

		let parent = test_transaction(10, 8, 1, &keychain, &mut secp);
		let parent_output = parent.outputs()[0].identifier();
		let child = test_transaction(8, 6, 2, &keychain, &mut secp);
		let child_output = child.outputs()[0].identifier();
		pool.add_entry(
			PoolEntry::new(parent, TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();
		pool.add_entry(
			PoolEntry::new(child.clone(), TxSource::Broadcast),
			None,
			&header,
			&mut secp,
		)
		.unwrap();

		let grandchild = test_transaction(6, 4, 3, &keychain, &mut secp);
		let (spent_pool, spent_utxo) = pool.locate_spends_from_pools(&grandchild, None).unwrap();
		assert_eq!(spent_pool.len(), 1);
		assert_eq!(spent_pool[0].commitment(), child_output.commitment());
		assert!(spent_utxo.is_empty());

		let alternate_child = test_transaction(8, 5, 2, &keychain, &mut secp);
		assert!(matches!(
			pool.locate_spends_from_pools(&alternate_child, None),
			Err(PoolError::DuplicateKernelOrDuplicateSpent(_))
		));

		assert!(pool.remove_tx(&child).unwrap().is_some());
		let (spent_pool, spent_utxo) = pool
			.locate_spends_from_pools(&alternate_child, None)
			.unwrap();
		assert_eq!(spent_pool.len(), 1);
		assert_eq!(spent_pool[0].commitment(), parent_output.commitment());
		assert!(spent_utxo.is_empty());
		assert_pool_indexes_consistent(&pool);
	}

	#[test]
	fn indexed_spend_lookup_combines_pool_indexes() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[19u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let chain = Arc::new(AcceptingChain);
		let mut txpool = Pool::new(0, chain.clone(), "txpool".into());
		let mut stempool = Pool::new(0, chain, "stempool".into());

		let parent = test_transaction(10, 8, 1, &keychain, &mut secp);
		let child = test_transaction(8, 6, 2, &keychain, &mut secp);
		let child_output = child.outputs()[0].identifier();
		txpool
			.add_entry(
				PoolEntry::new(parent, TxSource::Broadcast),
				None,
				&header,
				&mut secp,
			)
			.unwrap();
		let txpool_aggregate = txpool.validated_pool_aggregate(&secp).unwrap();
		let child_entry =
			ValidatedPoolEntry::authenticate(0, child, TxSource::Broadcast, &mut secp).unwrap();
		stempool
			.add_entry_with_validated_extra(child_entry, txpool_aggregate, &header, &mut secp)
			.unwrap();

		let grandchild = test_transaction(6, 4, 3, &keychain, &mut secp);
		let (spent_pool, spent_utxo) = stempool
			.locate_spends_from_pools(&grandchild, Some(&txpool))
			.unwrap();
		assert_eq!(spent_pool.len(), 1);
		assert_eq!(spent_pool[0].commitment(), child_output.commitment());
		assert!(spent_utxo.is_empty());

		let alternate_child = test_transaction(8, 5, 2, &keychain, &mut secp);
		assert!(matches!(
			stempool.locate_spends_from_pools(&alternate_child, Some(&txpool)),
			Err(PoolError::DuplicateKernelOrDuplicateSpent(_))
		));
		assert_pool_indexes_consistent(&txpool);
		assert_pool_indexes_consistent(&stempool);
	}

	#[test]
	fn admission_spend_lookup_does_not_scan_or_revalidate_retained_pool_entries() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[9u8; 32], false).unwrap();
		let header = global::get_genesis_block(&secp, 0).unwrap().header;
		let mut txpool = Pool::new(0, Arc::new(AcceptingChain), "txpool".into());
		let stempool = Pool::new(0, Arc::new(AcceptingChain), "stempool".into());

		let parent = test_transaction(10, 8, 1, &keychain, &mut secp);
		let parent_output = parent.outputs()[0].identifier();
		txpool
			.add_entry(
				PoolEntry::new(parent, TxSource::Broadcast),
				None,
				&header,
				&mut secp,
			)
			.unwrap();

		// Poison an already admitted proof solely as a verification canary. The
		// production API cannot mutate retained entries this way, but a call to
		// full transaction validation will now reliably fail and expose a
		// regression to the old whole-pool authentication path.
		let retained = txpool.entries.values_mut().next().unwrap();
		retained.tx.body.outputs[0].proof.proof[0] ^= 1;
		assert!(retained
			.tx
			.validate(0, Weighting::AsTransaction, &mut secp)
			.is_err());
		assert!(txpool.all_transactions_aggregate(None, &mut secp).is_err());

		// The trusted aggregate builder and admission lookup use the fact that
		// pool entries were authenticated at insertion. Neither should recheck
		// the retained proof.
		assert!(txpool.validated_pool_aggregate(&secp).unwrap().is_some());

		// Poison retained metadata after checking the aggregate builder. The
		// production API cannot create this mismatch, but it is a canary for a
		// regression that scans retained entries instead of using their exact index.
		let decoy = test_transaction(12, 10, 20, &keychain, &mut secp);
		txpool.entries.values_mut().next().unwrap().tx.body.outputs[0].identifier =
			decoy.outputs()[0].identifier();

		// The child spends the originally indexed parent output from the public
		// txpool while being admitted to the stempool.
		let child = test_transaction(8, 6, 2, &keychain, &mut secp);
		let (spent_pool, spent_utxo) = stempool
			.locate_spends_from_pools(&child, Some(&txpool))
			.unwrap();

		assert_eq!(spent_pool.len(), 1);
		assert_eq!(spent_pool[0].commitment(), parent_output.commitment());
		assert!(spent_utxo.is_empty());
	}

	#[test]
	fn reconcile_filters_a_small_pool_after_bulk_validation_fails() {
		let (mut pool, chain, txs, header, mut secp) = populated_test_pool();
		chain.reject_output(txs[1].outputs()[0].commitment());

		pool.reconcile(None, &header, &mut secp).unwrap();

		assert_eq!(pool.size(), 2);
		assert!(pool.contains_tx(&txs[0]).unwrap());
		assert!(!pool.contains_tx(&txs[1]).unwrap());
		assert!(pool.contains_tx(&txs[2]).unwrap());
	}

	#[test]
	fn fluff_reconcile_filters_a_small_stempool_after_bulk_validation_fails() {
		let (stempool, chain, txs, header, mut secp) = populated_test_pool();
		let mut transaction_pool = TransactionPool::new(
			0,
			PoolConfig::default(),
			chain.clone(),
			Arc::new(NoopPoolAdapter {}),
		);
		transaction_pool.stempool = stempool;
		chain.reject_output(txs[1].outputs()[0].commitment());

		let (fluffable_txs, removed) = transaction_pool
			.reconcile_stempool_for_fluff(&header, &mut secp)
			.unwrap();

		assert_eq!(removed, 1);
		assert_eq!(fluffable_txs.len(), 2);
		assert_eq!(
			fluffable_txs
				.iter()
				.map(|tx| tx.hash(0).unwrap())
				.collect::<Vec<_>>(),
			vec![txs[0].hash(0).unwrap(), txs[2].hash(0).unwrap()]
		);
		assert_pool_indexes_consistent(&transaction_pool.stempool);
	}

	#[test]
	fn reconcile_drops_an_over_budget_pool_without_individual_fallback() {
		let (mut pool, chain, txs, header, mut secp) = populated_test_pool();
		chain.reject_output(txs[1].outputs()[0].commitment());
		let calls_before_reconcile = chain.validate_calls();

		// Three one-input/one-output/one-kernel transactions have cumulative
		// prefix work 3 + 6 + 9 = 18. A test limit of 17 exercises the same
		// fail-closed branch used for a production pool above the hard budget.
		pool.reconcile_with_limits(
			None,
			&header,
			&mut secp,
			ReconcileFallbackLimits {
				max_entries: MAX_RECONCILE_FALLBACK_ENTRIES,
				max_work: 17,
			},
		)
		.unwrap();

		assert!(pool.is_empty());
		assert_eq!(chain.validate_calls() - calls_before_reconcile, 1);
	}
}
