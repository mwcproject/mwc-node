// Copyright 2026 The MWC Developers
// Licensed under the Apache License, Version 2.0.

use crate::types::NoopPoolAdapter;
use crate::{
	BlockChain, PoolConfig, PoolError, PromotionBudget, PromotionOutcome, TransactionPool, TxSource,
};
use mwc_core::core::hash::Hash;
use mwc_core::core::{
	transaction, BlockHeader, BlockSums, Inputs, KernelFeatures, Output, OutputFeatures,
	OutputIdentifier, Transaction,
};
use mwc_core::global;
use mwc_core::libtx::{build, ProofBuilder};
use mwc_crates::parking_lot::{Mutex, RecursiveRwLock};
use mwc_crates::secp::{pedersen::Commitment, ContextFlag, Secp256k1};
use mwc_keychain::{ExtKeychain, Keychain};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

struct TestChain {
	header: BlockHeader,
	utxos: RecursiveRwLock<HashMap<Commitment, OutputIdentifier>>,
	rejected_output: Mutex<Option<Commitment>>,
	validate_calls: AtomicUsize,
}

impl BlockChain for TestChain {
	fn verify_tx_not_confirmed(&self, _: &Transaction) -> Result<(), PoolError> {
		Ok(())
	}

	fn verify_coinbase_maturity(&self, _: &Inputs) -> Result<(), PoolError> {
		Ok(())
	}

	fn verify_tx_lock_height(&self, _: &Transaction) -> Result<(), PoolError> {
		Ok(())
	}

	fn validate_tx(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.validate_calls.fetch_add(1, Ordering::Relaxed);
		self.validate_outputs(tx.outputs())?;
		self.validate_inputs(&tx.inputs())?;
		Ok(())
	}

	fn validate_outputs(&self, outputs: &[Output]) -> Result<(), PoolError> {
		let rejected = *self.rejected_output.lock();
		let utxos = self.utxos.read();
		if outputs.iter().any(|output| {
			Some(output.commitment()) == rejected || utxos.contains_key(&output.commitment())
		}) {
			return Err(PoolError::DuplicateCommitment);
		}
		Ok(())
	}

	fn validate_inputs(&self, inputs: &Inputs) -> Result<Vec<OutputIdentifier>, PoolError> {
		let utxos = self.utxos.read();
		inputs
			.to_commit_wrappers(0)?
			.iter()
			.map(|input| {
				utxos.get(&input.commitment()).cloned().ok_or_else(|| {
					PoolError::Other("input is not in the test chain UTXO set".into())
				})
			})
			.collect()
	}

	fn chain_head(&self) -> Result<BlockHeader, PoolError> {
		Ok(self.header.clone())
	}

	fn get_block_header(&self, _: &Hash) -> Result<BlockHeader, PoolError> {
		Ok(self.header.clone())
	}

	fn get_block_sums(&self, _: &Hash) -> Result<BlockSums, PoolError> {
		Ok(BlockSums::empty())
	}

	fn replay_attack_check(&self, _: &Transaction) -> Result<(), PoolError> {
		Ok(())
	}
}

struct Fixture {
	pool: RecursiveRwLock<TransactionPool<TestChain, NoopPoolAdapter>>,
	chain: Arc<TestChain>,
	keychain: ExtKeychain,
	secp: Secp256k1,
}

impl Fixture {
	fn new() -> Self {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		global::set_local_accept_fee_base(1).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[71u8; 32], false).unwrap();
		let chain = Arc::new(TestChain {
			header: global::get_genesis_block(&secp, 0).unwrap().header,
			utxos: RecursiveRwLock::new(HashMap::new()),
			rejected_output: Mutex::new(None),
			validate_calls: AtomicUsize::new(0),
		});
		Self {
			pool: RecursiveRwLock::new(TransactionPool::new(
				0,
				PoolConfig::default(),
				chain.clone(),
				Arc::new(NoopPoolAdapter {}),
			)),
			chain,
			keychain,
			secp,
		}
	}

	fn transaction(&mut self, input_value: u64, input_key: u32) -> Transaction {
		let input_id = ExtKeychain::derive_key_id(3, input_key, 0, 0, 0).unwrap();
		let output_id = ExtKeychain::derive_key_id(3, input_key + 1, 0, 0, 0).unwrap();
		let builder = ProofBuilder::new(&self.secp, &self.keychain).unwrap();
		build::transaction(
			0,
			&mut self.secp,
			KernelFeatures::Plain {
				fee: 10u32.try_into().unwrap(),
			},
			&[
				build::feature_input(input_value, OutputFeatures::Plain, input_id),
				build::height_tagged_output(input_value - 10, output_id, 1),
			],
			&self.keychain,
			&builder,
		)
		.unwrap()
	}

	fn fund(&self, tx: &Transaction) {
		for input in tx.inputs().to_commit_wrappers(0).unwrap() {
			self.chain.utxos.write().insert(
				input.commitment(),
				OutputIdentifier::new(OutputFeatures::Plain, &input.commitment()),
			);
		}
	}

	fn stem(&mut self, tx: &Transaction) {
		TransactionPool::submit_to_pool(
			&self.pool,
			TxSource::Broadcast,
			tx.clone(),
			true,
			&self.chain.header,
			&mut self.secp,
		)
		.unwrap();
	}

	fn independent_stems(&mut self, count: u32) -> Vec<Transaction> {
		(0..count)
			.map(|i| {
				let tx = self.transaction(1_000, 2 * i + 1);
				self.fund(&tx);
				self.stem(&tx);
				tx
			})
			.collect()
	}

	fn promote(
		&mut self,
		tx: &Transaction,
		budget: &mut PromotionBudget,
	) -> Result<PromotionOutcome, PoolError> {
		TransactionPool::submit_expired_to_pool(
			&self.pool,
			tx.clone(),
			&self.chain.header,
			budget,
			&mut self.secp,
		)
	}

	fn stem_timestamp(&self, tx: &Transaction) -> Instant {
		self.pool
			.read()
			.stempool
			.ordered_entry_refs()
			.find(|entry| entry.tx.eq_by_hash(0, tx).unwrap())
			.unwrap()
			.tx_at
	}
}

#[test]
fn expiry_promotions_avoid_repeated_reconciliation_fallback() {
	let mut fixture = Fixture::new();
	let txs = fixture.independent_stems(16);
	fixture.chain.validate_calls.store(0, Ordering::Relaxed);
	let mut budget = PromotionBudget::new();
	for tx in &txs {
		assert_eq!(
			fixture.promote(tx, &mut budget).unwrap(),
			PromotionOutcome::Accepted
		);
	}
	let pool = fixture.pool.read();
	assert!(pool.stempool.is_empty());
	assert_eq!(pool.txpool.size(), txs.len());
	// One public aggregate per promotion, plus one private/public aggregate
	// while stems remain. Previously this cohort required 136 validations.
	assert_eq!(fixture.chain.validate_calls.load(Ordering::Relaxed), 31);
}

#[test]
fn expiry_budget_defers_without_evicting_or_resetting_embargo() {
	// Exercise both exhaustion before authentication and refusal of another
	// full-pool operation after authentication has consumed part of the budget.
	for limit in [19, 30] {
		let mut fixture = Fixture::new();
		let txs = fixture.independent_stems(3);
		let timestamp = fixture.stem_timestamp(&txs[1]);
		let mut budget = PromotionBudget::with_work_limit(limit);
		assert_eq!(
			fixture.promote(&txs[0], &mut budget).unwrap(),
			PromotionOutcome::Accepted
		);
		assert_eq!(
			fixture.promote(&txs[1], &mut budget).unwrap(),
			PromotionOutcome::Deferred
		);
		assert_eq!(fixture.stem_timestamp(&txs[1]), timestamp);
		{
			let pool = fixture.pool.read();
			assert_eq!(pool.txpool.size(), 1);
			assert_eq!(pool.stempool.size(), 2);
			assert_eq!(pool.reorg_cache.read().len(), 1);
		}
		// The next monitor pass can continue immediately using the same entry.
		let mut next_pass = PromotionBudget::new();
		for tx in &txs[1..] {
			assert_eq!(
				fixture.promote(tx, &mut next_pass).unwrap(),
				PromotionOutcome::Accepted
			);
		}
		assert!(fixture.pool.read().stempool.is_empty());
	}
}

#[test]
fn expiry_budget_allows_one_oversized_pool_operation_to_make_progress() {
	let mut fixture = Fixture::new();
	let txs = fixture.independent_stems(3);
	// The standalone transaction fits, but even the first pool aggregate does
	// not. Each pass must still progress, without granting a second exception.
	for (i, tx) in txs.iter().enumerate() {
		let mut budget = PromotionBudget::with_work_limit(3);
		assert_eq!(
			fixture.promote(tx, &mut budget).unwrap(),
			PromotionOutcome::Accepted
		);
		if let Some(next) = txs.get(i + 1) {
			assert_eq!(
				fixture.promote(next, &mut budget).unwrap(),
				PromotionOutcome::Deferred
			);
		}
	}
	assert!(fixture.pool.read().stempool.is_empty());
}

#[test]
fn expiry_reconciliation_fallback_spends_the_shared_budget() {
	let mut fixture = Fixture::new();
	let txs = fixture.independent_stems(3);
	let timestamp = fixture.stem_timestamp(&txs[2]);
	// Simulate a chain change invalidating another retained stem entry.
	*fixture.chain.rejected_output.lock() = Some(txs[1].outputs()[0].commitment());
	// A second promotion would fit if fallback incorrectly received a fresh
	// allowance, so deferral here specifically checks the shared accounting.
	let mut budget = PromotionBudget::with_work_limit(40);
	assert_eq!(
		fixture.promote(&txs[0], &mut budget).unwrap(),
		PromotionOutcome::Accepted
	);
	{
		let pool = fixture.pool.read();
		assert_eq!(pool.txpool.size(), 1);
		assert_eq!(pool.stempool.size(), 1);
		assert!(!pool.stempool.contains_tx(&txs[1]).unwrap());
	}
	assert_eq!(
		fixture.promote(&txs[2], &mut budget).unwrap(),
		PromotionOutcome::Deferred
	);
	assert_eq!(fixture.stem_timestamp(&txs[2]), timestamp);
	assert_eq!(
		fixture
			.promote(&txs[2], &mut PromotionBudget::new())
			.unwrap(),
		PromotionOutcome::Accepted
	);
}

#[test]
fn expiry_finishes_committed_admission_when_invalid_fallback_exceeds_budget() {
	let mut fixture = Fixture::new();
	let txs = fixture.independent_stems(3);
	*fixture.chain.rejected_output.lock() = Some(txs[1].outputs()[0].commitment());
	let mut budget = PromotionBudget::with_work_limit(18);
	assert_eq!(
		fixture.promote(&txs[0], &mut budget).unwrap(),
		PromotionOutcome::Accepted
	);
	let pool = fixture.pool.read();
	assert!(pool.txpool.contains_tx(&txs[0]).unwrap());
	// Preserve the existing conservative eviction policy for an invalid bulk
	// candidate when individual filtering cannot fit; never defer post-insert.
	assert!(pool.stempool.is_empty());
	assert_eq!(pool.reorg_cache.read().len(), 1);
}

#[test]
fn failed_public_admission_does_not_remove_the_stem_entry() {
	let mut fixture = Fixture::new();
	let txs = fixture.independent_stems(1);
	let timestamp = fixture.stem_timestamp(&txs[0]);
	*fixture.chain.rejected_output.lock() = Some(txs[0].outputs()[0].commitment());
	assert!(matches!(
		fixture.promote(&txs[0], &mut PromotionBudget::new()),
		Err(PoolError::DuplicateCommitment)
	));
	assert!(fixture.pool.read().txpool.is_empty());
	assert_eq!(fixture.stem_timestamp(&txs[0]), timestamp);
}

#[test]
fn promoting_parent_preserves_dependent_stem_for_later_promotion() {
	let mut fixture = Fixture::new();
	let parent = fixture.transaction(1_000, 1);
	let child = fixture.transaction(990, 2);
	fixture.fund(&parent);
	fixture.stem(&parent);
	fixture.stem(&child);
	let timestamp = fixture.stem_timestamp(&child);
	let mut budget = PromotionBudget::new();
	assert_eq!(
		fixture.promote(&parent, &mut budget).unwrap(),
		PromotionOutcome::Accepted
	);
	assert_eq!(fixture.stem_timestamp(&child), timestamp);
	assert_eq!(
		fixture.promote(&child, &mut budget).unwrap(),
		PromotionOutcome::Accepted
	);
	let pool = fixture.pool.read();
	assert_eq!(pool.txpool.size(), 2);
	assert!(pool.stempool.is_empty());
}

#[test]
fn aggregate_promotion_filters_overlapping_stems_and_keeps_unrelated_entries() {
	let mut fixture = Fixture::new();
	let txs = fixture.independent_stems(3);
	let timestamp = fixture.stem_timestamp(&txs[2]);
	let aggregate = transaction::aggregate(0, &txs[..2], &fixture.secp).unwrap();
	let mut budget = PromotionBudget::new();
	assert_eq!(
		fixture.promote(&aggregate, &mut budget).unwrap(),
		PromotionOutcome::Accepted
	);
	{
		let pool = fixture.pool.read();
		assert_eq!(pool.txpool.size(), 1);
		assert_eq!(pool.stempool.size(), 1);
	}
	assert_eq!(fixture.stem_timestamp(&txs[2]), timestamp);
	assert_eq!(
		fixture.promote(&txs[2], &mut budget).unwrap(),
		PromotionOutcome::Accepted
	);
	assert!(fixture.pool.read().stempool.is_empty());
}
