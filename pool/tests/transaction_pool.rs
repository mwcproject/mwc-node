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

pub mod common;

use crate::common::*;
use mwc_core::core::hash::Hashed;
use mwc_core::core::{transaction, Weighting};
use mwc_core::global;
use mwc_core::ser;
use mwc_crates::parking_lot::{Mutex, RwLock};
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{ExtKeychain, Keychain};
use mwc_pool::{PoolAdapter, PoolConfig, PoolEntry, PoolError, TransactionPool, TxSource};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Default)]
struct RelayLockCheckingAdapter {
	pool_is_unlocked: Mutex<Option<Box<dyn Fn() -> bool + Send + Sync>>>,
	relay_observed_unlocked_pool: AtomicBool,
}

impl PoolAdapter for RelayLockCheckingAdapter {
	fn tx_accepted(&self, _entry: &PoolEntry) -> Result<(), PoolError> {
		let pool_is_unlocked = self
			.pool_is_unlocked
			.lock()
			.as_ref()
			.map(|check| check())
			.unwrap_or(false);
		self.relay_observed_unlocked_pool
			.store(pool_is_unlocked, Ordering::SeqCst);
		Ok(())
	}

	fn stem_tx_accepted(&self, _entry: &PoolEntry) -> Result<(), PoolError> {
		Ok(())
	}
}

#[derive(Default)]
struct FailSecondStemAdapter {
	stem_attempts: AtomicUsize,
}

impl PoolAdapter for FailSecondStemAdapter {
	fn tx_accepted(&self, _entry: &PoolEntry) -> Result<(), PoolError> {
		Ok(())
	}

	fn stem_tx_accepted(&self, _entry: &PoolEntry) -> Result<(), PoolError> {
		if self.stem_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
			Ok(())
		} else {
			Err(PoolError::DandelionError)
		}
	}
}

#[test]
fn fluff_relay_runs_after_pool_write_lock_is_released() {
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(1).unwrap();
	global::set_local_nrd_enabled(false);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain: ExtKeychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let db_root = "target/.transaction_pool_relay_unlock";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(&secp, db_root, genesis));
	add_some_blocks(&mut secp, &chain, 4 * 3, &keychain);
	let header = chain.head_header().unwrap();
	let header_1 = chain.get_header_by_height(1).unwrap();
	let tx = test_transaction_spending_coinbase(&mut secp, &keychain, &header_1, vec![500]);

	let adapter = Arc::new(RelayLockCheckingAdapter::default());
	let pool = Arc::new(RwLock::new(TransactionPool::new(
		0,
		PoolConfig {
			tx_fee_base: mwc_pool::types::default_tx_fee_base(),
			reorg_cache_timeout: 1_440,
			max_pool_size: 50,
			max_stempool_size: 50,
			mineable_max_weight: 10_000,
		},
		Arc::new(ChainAdapter {
			chain: chain.clone(),
		}),
		adapter.clone(),
	)));
	let weak_pool = Arc::downgrade(&pool);
	*adapter.pool_is_unlocked.lock() = Some(Box::new(move || {
		weak_pool
			.upgrade()
			.map(|pool| pool.try_write().is_some())
			.unwrap_or(false)
	}));

	TransactionPool::submit_to_pool(pool.as_ref(), test_source(), tx, false, &header, &mut secp)
		.unwrap();

	assert!(adapter.relay_observed_unlocked_pool.load(Ordering::SeqCst));
	assert_eq!(pool.read_recursive().total_size(), 1);
	clean_output_dir(db_root.into());
}

#[test]
fn failed_dependent_stem_fallback_removes_child_from_stempool() {
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(1).unwrap();
	global::set_local_nrd_enabled(false);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain: ExtKeychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let db_root = "target/.transaction_pool_failed_stem_fallback";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(&secp, db_root, genesis));
	add_some_blocks(&mut secp, &chain, 4 * 3, &keychain);
	let header = chain.head_header().unwrap();
	let header_1 = chain.get_header_by_height(1).unwrap();

	let adapter = Arc::new(FailSecondStemAdapter::default());
	let mut pool = TransactionPool::new(
		0,
		PoolConfig {
			tx_fee_base: mwc_pool::types::default_tx_fee_base(),
			reorg_cache_timeout: 1_440,
			max_pool_size: 50,
			max_stempool_size: 50,
			mineable_max_weight: 10_000,
		},
		Arc::new(ChainAdapter {
			chain: chain.clone(),
		}),
		adapter,
	);

	let initial_tx = test_transaction_spending_coinbase(&mut secp, &keychain, &header_1, vec![500]);
	submit_to_pool!(pool, test_source(), initial_tx, false, &header, &mut secp).unwrap();

	let parent = test_transaction(&mut secp, &keychain, vec![500], vec![469]);
	submit_to_pool!(
		pool,
		test_source(),
		parent.clone(),
		true,
		&header,
		&mut secp
	)
	.unwrap();
	assert!(pool.stempool.contains_tx(&parent).unwrap());

	let child = test_transaction(&mut secp, &keychain, vec![469], vec![438]);
	let err =
		submit_to_pool!(pool, test_source(), child.clone(), true, &header, &mut secp).unwrap_err();

	assert!(!matches!(err, PoolError::DandelionError));
	assert_eq!(pool.txpool.size(), 1);
	assert_eq!(pool.stempool.size(), 1);
	assert!(pool.stempool.contains_tx(&parent).unwrap());
	assert!(!pool.stempool.contains_tx(&child).unwrap());
	assert!(!pool.txpool.contains_tx(&child).unwrap());

	clean_output_dir(db_root.into());
}

/// Test we can add some txs to the pool (both stempool and txpool).
#[test]
fn test_the_transaction_pool() {
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(1).unwrap();
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain: ExtKeychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();

	let db_root = "target/.transaction_pool";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(&secp, db_root, genesis));

	// Initialize a new pool with our chain adapter.
	let mut pool = init_transaction_pool(Arc::new(ChainAdapter {
		chain: chain.clone(),
	}));

	// mine past HF4 to see effect of set_local_accept_fee_base
	add_some_blocks(&mut secp, &chain, 4 * 3, &keychain);
	let header = chain.head_header().unwrap();

	let header_1 = chain.get_header_by_height(1).unwrap();
	let initial_tx = test_transaction_spending_coinbase(
		&mut secp,
		&keychain,
		&header_1,
		vec![500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400],
	);

	// Add this tx to the pool (stem=false, direct to txpool).
	{
		submit_to_pool!(pool, test_source(), initial_tx, false, &header, &mut secp).unwrap();
		assert_eq!(pool.total_size(), 1);
	}

	// Test adding a tx that "double spends" an output currently spent by a tx
	// already in the txpool. In this case we attempt to spend the original coinbase twice.
	{
		let tx = test_transaction_spending_coinbase(&mut secp, &keychain, &header, vec![501]);
		assert!(submit_to_pool!(pool, test_source(), tx, false, &header, &mut secp).is_err());
	}

	// tx1 spends some outputs from the initial test tx.
	let tx1 = test_transaction(&mut secp, &keychain, vec![500, 600], vec![469, 569]);
	// tx2 spends some outputs from both tx1 and the initial test tx.
	let tx2 = test_transaction(&mut secp, &keychain, vec![469, 700], vec![498]);

	{
		// Check we have a single initial tx in the pool.
		assert_eq!(pool.total_size(), 1);

		// First, add a simple tx directly to the txpool (stem = false).
		submit_to_pool!(pool, test_source(), tx1.clone(), false, &header, &mut secp).unwrap();
		assert_eq!(pool.total_size(), 2);
		let tx1_kernel_hash = tx1
			.kernels()
			.first()
			.unwrap()
			.hash(chain.get_context_id())
			.unwrap();
		let retrieved_tx = pool
			.retrieve_tx_by_kernel_hash(tx1_kernel_hash)
			.unwrap()
			.unwrap();
		assert!(ser::slices_equal_by_hash(
			chain.get_context_id(),
			retrieved_tx.kernels(),
			tx1.kernels()
		)
		.unwrap());

		// Add another tx spending outputs from the previous tx.
		submit_to_pool!(pool, test_source(), tx2.clone(), false, &header, &mut secp).unwrap();
		assert_eq!(pool.total_size(), 3);
	}

	// Test adding the exact same tx multiple times (same kernel signature).
	// Corrupt the duplicate's proof so the precise DuplicateTx result also proves
	// the cheap pool lookup happens before expensive rangeproof validation.
	{
		let mut duplicate = tx1.clone();
		duplicate.body.outputs[0].proof.proof[0] ^= 1;
		let err =
			submit_to_pool!(pool, test_source(), duplicate, false, &header, &mut secp).unwrap_err();
		assert!(matches!(err, PoolError::DuplicateTx));
	}

	// Test adding a duplicate tx with the same input and outputs.
	// Note: not the *same* tx, just same underlying inputs/outputs.
	{
		let tx1a = test_transaction(&mut secp, &keychain, vec![500, 600], vec![469, 569]);
		assert!(submit_to_pool!(pool, test_source(), tx1a, false, &header, &mut secp).is_err());
	}

	// Test adding a tx attempting to spend a non-existent output.
	{
		let bad_tx = test_transaction(&mut secp, &keychain, vec![10_001], vec![9_900]);
		assert!(submit_to_pool!(pool, test_source(), bad_tx, false, &header, &mut secp).is_err());
	}

	// Test adding a tx that would result in a duplicate output (conflicts with
	// output from tx2). For reasons of security all outputs in the UTXO set must
	// be unique. Otherwise spending one will almost certainly cause the other
	// to be immediately stolen via a "replay" tx.
	{
		let tx = test_transaction(&mut secp, &keychain, vec![900], vec![498]);
		assert!(submit_to_pool!(pool, test_source(), tx, false, &header, &mut secp).is_err());
	}

	// Confirm the tx pool correctly identifies an invalid tx (already spent).
	{
		let tx3 = test_transaction(&mut secp, &keychain, vec![500], vec![467]);
		assert!(submit_to_pool!(pool, test_source(), tx3, false, &header, &mut secp).is_err());
		assert_eq!(pool.total_size(), 3);
	}

	// Now add a couple of txs to the stempool (stem = true).
	{
		let tx = test_transaction(&mut secp, &keychain, vec![569], vec![538]);
		submit_to_pool!(pool, test_source(), tx, true, &header, &mut secp).unwrap();
		let tx2 = test_transaction(&mut secp, &keychain, vec![538], vec![507]);
		submit_to_pool!(pool, test_source(), tx2, true, &header, &mut secp).unwrap();
		assert_eq!(pool.total_size(), 3);
		assert_eq!(pool.stempool.size(), 2);
	}

	// Check we can take some entries from the stempool and "fluff" them into the
	// txpool. This also exercises multi-kernel txs.
	{
		let agg_tx = pool
			.stempool
			.all_transactions_aggregate(None, &mut secp)
			.unwrap()
			.unwrap();
		assert_eq!(agg_tx.kernels().len(), 2);
		submit_to_pool!(pool, test_source(), agg_tx, false, &header, &mut secp).unwrap();
		assert_eq!(pool.total_size(), 4);
		assert!(pool.stempool.is_empty());
	}

	// Adding a duplicate tx to the stempool will result in it being fluffed.
	// This handles the case of the stem path having a cycle in it.
	{
		let tx = test_transaction(&mut secp, &keychain, vec![507], vec![476]);
		submit_to_pool!(pool, test_source(), tx.clone(), true, &header, &mut secp).unwrap();
		assert_eq!(pool.total_size(), 4);
		assert_eq!(pool.txpool.size(), 4);
		assert_eq!(pool.stempool.size(), 1);

		// Duplicate stem tx so fluff, adding it to txpool and removing it from stempool.
		submit_to_pool!(pool, test_source(), tx.clone(), true, &header, &mut secp).unwrap();
		assert_eq!(pool.total_size(), 5);
		assert_eq!(pool.txpool.size(), 5);
		assert!(pool.stempool.is_empty());
	}

	// Now check we can correctly deaggregate a multi-kernel tx based on current
	// contents of the txpool.
	// We will do this be adding a new tx to the pool
	// that is a superset of a tx already in the pool.
	{
		let tx4 = test_transaction(&mut secp, &keychain, vec![800], vec![769]);

		// tx1 and tx2 are already in the txpool (in aggregated form)
		// tx4 is the "new" part of this aggregated tx that we care about
		let agg_tx = transaction::aggregate(
			chain.get_context_id(),
			&[tx1.clone(), tx2.clone(), tx4],
			&mut secp,
		)
		.unwrap();

		agg_tx
			.validate(0, Weighting::AsTransaction, &mut secp)
			.unwrap();

		submit_to_pool!(pool, test_source(), agg_tx, false, &header, &mut secp).unwrap();
		assert_eq!(pool.total_size(), 6);
		let entries = pool.txpool.all_entries();
		let entry = entries.last().unwrap();
		assert_eq!(entry.tx.kernels().len(), 1);
		assert_eq!(entry.src, TxSource::Deaggregate);
	}

	// Check we cannot "double spend" an output spent in a previous block.
	// We use the initial coinbase output here for convenience.
	{
		let double_spend_tx =
			test_transaction_spending_coinbase(&mut secp, &keychain, &header, vec![1000]);

		// check we cannot add a double spend to the stempool
		assert!(submit_to_pool!(
			pool,
			test_source(),
			double_spend_tx.clone(),
			true,
			&header,
			&mut secp
		)
		.is_err());

		// check we cannot add a double spend to the txpool
		assert!(submit_to_pool!(
			pool,
			test_source(),
			double_spend_tx.clone(),
			false,
			&header,
			&mut secp
		)
		.is_err());
		assert_eq!(pool.total_size(), 6);
	}

	// Cleanup db directory
	clean_output_dir(db_root.into());
}

#[test]
fn test_stempool_remove_tx_by_transaction() {
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(1).unwrap();
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain: ExtKeychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();

	let db_root = "target/.transaction_pool_remove_tx";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(&secp, db_root, genesis));
	add_some_blocks(&mut secp, &chain, 4 * 3, &keychain);
	let header = chain.head_header().unwrap();
	let header_1 = chain.get_header_by_height(1).unwrap();

	let mut pool = init_transaction_pool(Arc::new(ChainAdapter {
		chain: chain.clone(),
	}));
	let initial_tx =
		test_transaction_spending_coinbase(&mut secp, &keychain, &header_1, vec![500, 600]);
	submit_to_pool!(pool, test_source(), initial_tx, false, &header, &mut secp).unwrap();

	let stem_tx = test_transaction(&mut secp, &keychain, vec![500], vec![469]);
	submit_to_pool!(
		pool,
		test_source(),
		stem_tx.clone(),
		true,
		&header,
		&mut secp
	)
	.unwrap();
	assert_eq!(pool.stempool.size(), 1);
	assert!(pool.stempool.contains_tx(&stem_tx).unwrap());

	let removed = pool.stempool.remove_tx(&stem_tx).unwrap();
	assert!(removed.is_some());
	assert!(pool.stempool.is_empty());
	assert!(pool.stempool.remove_tx(&stem_tx).unwrap().is_none());

	clean_output_dir(db_root.into());
}

#[test]
fn test_reconcile_reorg_cache_retains_valid_entries() {
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(1).unwrap();
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain: ExtKeychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();

	let db_root = "target/.transaction_pool_reorg_cache";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(&secp, db_root, genesis));
	add_some_blocks(&mut secp, &chain, 4 * 3, &keychain);
	let header = chain.head_header().unwrap();
	let header_1 = chain.get_header_by_height(1).unwrap();

	let mut pool = init_transaction_pool(Arc::new(ChainAdapter {
		chain: chain.clone(),
	}));
	let tx = test_transaction_spending_coinbase(&mut secp, &keychain, &header_1, vec![500, 600]);
	submit_to_pool!(pool, test_source(), tx, false, &header, &mut secp).unwrap();

	assert_eq!(pool.txpool.size(), 1);
	assert_eq!(pool.reorg_cache.read().len(), 1);

	pool.reconcile_reorg_cache(&header, &mut secp);
	assert_eq!(pool.txpool.size(), 1);
	assert_eq!(pool.reorg_cache.read().len(), 1);

	pool.txpool.clear();
	assert_eq!(pool.txpool.size(), 0);

	pool.reconcile_reorg_cache(&header, &mut secp);
	assert_eq!(pool.txpool.size(), 1);
	assert_eq!(pool.reorg_cache.read().len(), 1);

	clean_output_dir(db_root.into());
}

#[test]
fn test_transaction_pool_capacity_limits() {
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(1).unwrap();
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain: ExtKeychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();

	let db_root = "target/.transaction_pool_capacity_limits";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(&secp, db_root, genesis));

	// mine past HF4 to see effect of set_local_accept_fee_base
	add_some_blocks(&mut secp, &chain, 4 * 3, &keychain);
	let header = chain.head_header().unwrap();
	let header_1 = chain.get_header_by_height(1).unwrap();
	let header_2 = chain.get_header_by_height(2).unwrap();
	let header_3 = chain.get_header_by_height(3).unwrap();

	{
		let mut pool = init_transaction_pool(Arc::new(ChainAdapter {
			chain: chain.clone(),
		}));
		pool.config.max_pool_size = 1;

		let initial_tx =
			test_transaction_spending_coinbase(&mut secp, &keychain, &header_1, vec![500, 600]);
		submit_to_pool!(
			pool,
			test_source(),
			initial_tx.clone(),
			false,
			&header,
			&mut secp
		)
		.unwrap();
		assert_eq!(pool.txpool.size(), 1);

		let mut low_fee_tx = test_transaction(&mut secp, &keychain, vec![600], vec![599]);
		// A malformed proof would fail full validation. LowFeeTransaction proves
		// immutable fee policy rejects it before rangeproof verification.
		low_fee_tx.body.outputs[0].proof.proof[0] ^= 1;
		let err = submit_to_pool!(pool, test_source(), low_fee_tx, false, &header, &mut secp)
			.unwrap_err();
		assert!(matches!(err, PoolError::LowFeeTransaction(1)));
		assert_eq!(pool.txpool.size(), 1);

		let mut tx = test_transaction(&mut secp, &keychain, vec![500], vec![469]);
		// Capacity is checked before full cryptographic validation and before the
		// expensive whole-pool aggregate admission path.
		tx.body.outputs[0].proof.proof[0] ^= 1;
		let err = submit_to_pool!(pool, test_source(), tx, false, &header, &mut secp).unwrap_err();
		assert!(matches!(err, PoolError::OverCapacity));
		assert_eq!(pool.txpool.size(), 1);
		assert!(pool.txpool.contains_tx(&initial_tx).unwrap());
	}

	{
		let mut pool = init_transaction_pool(Arc::new(ChainAdapter {
			chain: chain.clone(),
		}));
		pool.config.max_pool_size = 0;

		let tx = test_transaction_spending_coinbase(&mut secp, &keychain, &header_2, vec![700]);
		let err = submit_to_pool!(pool, test_source(), tx, false, &header, &mut secp).unwrap_err();
		assert!(matches!(err, PoolError::OverCapacity));
		assert_eq!(pool.txpool.size(), 0);
	}

	{
		let mut pool = init_transaction_pool(Arc::new(ChainAdapter {
			chain: chain.clone(),
		}));
		pool.config.max_stempool_size = 1;

		let initial_tx =
			test_transaction_spending_coinbase(&mut secp, &keychain, &header_3, vec![800, 900]);
		submit_to_pool!(pool, test_source(), initial_tx, false, &header, &mut secp).unwrap();

		let tx = test_transaction(&mut secp, &keychain, vec![800], vec![769]);
		submit_to_pool!(pool, test_source(), tx, true, &header, &mut secp).unwrap();
		assert_eq!(pool.stempool.size(), 1);

		let mut tx = test_transaction(&mut secp, &keychain, vec![900], vec![869]);
		// The hard stem-capacity snapshot is also checked before cryptography.
		tx.body.outputs[0].proof.proof[0] ^= 1;
		let err = submit_to_pool!(pool, test_source(), tx, true, &header, &mut secp).unwrap_err();
		assert!(matches!(err, PoolError::OverCapacity));
		assert_eq!(pool.stempool.size(), 1);
	}

	clean_output_dir(db_root.into());
}
