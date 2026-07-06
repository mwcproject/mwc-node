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

use crate::types::{BlockChain, PoolEntry, PoolError};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::id::{ShortId, ShortIdentifiable};
use mwc_core::core::transaction;
use mwc_core::core::{
	Block, BlockHeader, BlockSums, Committed, HeaderVersion, Inputs, OutputIdentifier, Transaction,
	TxKernel, Weighting,
};
use mwc_core::global;
use mwc_core::ser;
use mwc_crates::indexmap::IndexMap;
use mwc_crates::log::{debug, warn};
use mwc_crates::secp::Secp256k1;
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub struct Pool<B>
where
	B: BlockChain,
{
	/// Entries keyed by the representative kernel hash (first kernel) used for tx-kernel gossip.
	/// This is not a full multi-kernel index: lookup is O(1) for the advertised
	/// representative kernel, but requests for other kernels in the same tx will
	/// miss. A full index should map every kernel hash in a tx to the same pool
	/// entry id, so `retrieve_tx_by_kernel_hash` works for any kernel without a
	/// full-pool scan.
	pub entries: IndexMap<Hash, PoolEntry>,
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
			Ok(self.entries.shift_remove(&tx_key))
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
	pub fn add_to_pool(
		&mut self,
		entry: PoolEntry,
		extra_tx: Option<Transaction>,
		header: &BlockHeader,
		secp: &mut Secp256k1,
	) -> Result<(), PoolError> {
		// Combine all the txs from the pool with any extra txs provided.
		let mut txs = self.all_transactions();

		// Quick check to see if we have seen this tx before.
		if ser::contains_by_hash(self.context_id, &txs, &entry.tx)? {
			return Err(PoolError::DuplicateTx);
		}

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
		self.validate_raw_tx(&agg_tx, header, Weighting::NoLimit, secp)?;
		// If we get here successfully then we can safely add the entry to the pool.
		let entry_key = Self::tx_key(self.context_id, &entry.tx)?;
		if self.entries.contains_key(&entry_key) {
			return Err(PoolError::DuplicateTx);
		}
		self.log_pool_add(&entry, header);
		self.entries.insert(entry_key, entry);

		Ok(())
	}

	fn log_pool_add(&self, entry: &PoolEntry, header: &BlockHeader) {
		debug!(
			"add_to_pool [{}]: {} ({:?}) [in/out/kern: {}/{}/{}] pool: {} (at block {})",
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
		let existing_entries = self.all_entries();
		// Logging hashes are diagnostic only; do not let them abort
		// reconciliation after the pool has been cleared.
		let header_hash = header.hash(self.context_id).unwrap_or(Hash::default());
		self.entries.clear();
		for x in existing_entries {
			let tx_hash = x.tx.hash(self.context_id).unwrap_or(Hash::default());
			if let Err(e) = self.add_to_pool(x, extra_tx.clone(), header, secp) {
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
				self.entries.shift_remove(&key);
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
	pub fn find_matching_transactions(
		&self,
		kernels: &[TxKernel],
	) -> Result<Vec<Transaction>, PoolError> {
		// While the inputs outputs can be cut-through the kernel will stay intact
		// In order to deaggregate tx we look for tx with the same kernel
		let mut found_txs = vec![];

		// Gather all the kernels of the multi-kernel transaction in one set
		let kernel_set = kernels
			.iter()
			.map(|kernel| kernel.hash(self.context_id))
			.collect::<Result<HashSet<_>, _>>()?;

		// Check each transaction in the pool
		for entry in self.entries.values() {
			let entry_kernel_set = entry
				.tx
				.kernels()
				.iter()
				.map(|kernel| kernel.hash(self.context_id))
				.collect::<Result<HashSet<_>, _>>()?;
			if entry_kernel_set.is_subset(&kernel_set) {
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
		let mut evict_keys = Vec::new();
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
				evict_keys.push(*key);
			}
		}

		for key in evict_keys {
			self.entries.shift_remove(&key);
		}
		Ok(())
	}

	/// Size of the pool.
	pub fn size(&self) -> usize {
		self.entries.len()
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
