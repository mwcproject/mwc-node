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

use crate::common::ChainAdapter;
use crate::common::*;
use mwc_core::core::hash::Hashed;
use mwc_core::global;
use mwc_core::ser;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{ExtKeychain, Keychain};
use std::sync::Arc;

#[test]
fn test_transaction_pool_block_reconciliation() {
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	global::set_local_accept_fee_base(1).unwrap();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain: ExtKeychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();

	let db_root = "target/.block_reconciliation";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(&secp, db_root, genesis));

	// Initialize a new pool with our chain adapter.
	let mut pool = init_transaction_pool(Arc::new(ChainAdapter {
		chain: chain.clone(),
	}));

	// mine past HF4 to see effect of set_local_accept_fee_base
	add_some_blocks(&mut secp, &chain, 4 * 3, &keychain);

	let header_1 = chain.get_header_by_height(1).unwrap();

	// Now create tx to spend an early coinbase (now matured).
	// Provides us with some useful outputs to test with.
	let initial_tx = test_transaction_spending_coinbase(
		&mut secp,
		&keychain,
		&header_1,
		vec![1_000, 2_000, 3_000, 4_000],
	);

	// Mine that initial tx so we can spend it with multiple txs.
	add_block(&mut secp, &chain, &[initial_tx], &keychain);

	let header = chain.head_header().unwrap();

	// Preparation: We will introduce three root pool transactions.
	// 1. A transaction that should be invalidated because it is exactly
	//  contained in the block.
	// 2. A transaction that should be invalidated because the input is
	//  consumed in the block, although it is not exactly consumed.
	// 3. A transaction that should remain after block reconciliation.
	let block_transaction = test_transaction(&mut secp, &keychain, vec![1_000], vec![800]);
	let conflict_transaction =
		test_transaction(&mut secp, &keychain, vec![2_000], vec![1_200, 600]);
	let valid_transaction = test_transaction(&mut secp, &keychain, vec![3_000], vec![1_300, 1_500]);

	// We will also introduce a few children:
	// 4. A transaction that descends from transaction 1, that is in
	//  turn exactly contained in the block.
	let block_child = test_transaction(&mut secp, &keychain, vec![800], vec![500, 100]);
	// 5. A transaction that descends from transaction 4, that is not
	//  contained in the block at all and should be valid after
	//  reconciliation.
	let pool_child = test_transaction(&mut secp, &keychain, vec![500], vec![300]);
	// 6. A transaction that descends from transaction 2 that does not
	//  conflict with anything in the block in any way, but should be
	//  invalidated (orphaned).
	let conflict_child = test_transaction(&mut secp, &keychain, vec![1_200], vec![200]);
	// 7. A transaction that descends from transaction 2 that should be
	//  valid due to its inputs being satisfied by the block.
	let conflict_valid_child = test_transaction(&mut secp, &keychain, vec![600], vec![400]);
	// 8. A transaction that descends from transaction 3 that should be
	//  invalidated due to an output conflict.
	let valid_child_conflict = test_transaction(&mut secp, &keychain, vec![1_300], vec![900]);
	// 9. A transaction that descends from transaction 3 that should remain
	//  valid after reconciliation.
	let valid_child_valid = test_transaction(&mut secp, &keychain, vec![1_500], vec![1_100]);
	// 10. A transaction that descends from both transaction 6 and
	//  transaction 9
	let mixed_child = test_transaction(&mut secp, &keychain, vec![200, 1_100], vec![700]);

	let txs_to_add = vec![
		block_transaction,
		conflict_transaction,
		valid_transaction.clone(),
		block_child,
		pool_child.clone(),
		conflict_child,
		conflict_valid_child.clone(),
		valid_child_conflict.clone(),
		valid_child_valid.clone(),
		mixed_child,
	];

	// First we add the above transactions to the pool.
	// All should be accepted.
	assert_eq!(pool.total_size(), 0);

	for tx in &txs_to_add {
		pool.add_to_pool(test_source(), tx.clone(), false, &header, &mut secp)
			.unwrap();
	}

	assert_eq!(pool.total_size(), txs_to_add.len());

	// Now we prepare the block that will cause the above conditions to be met.
	// First, the transactions we want in the block:
	// - Copy of 1
	let block_tx_1 = test_transaction(&mut secp, &keychain, vec![1_000], vec![800]);
	// - Conflict w/ 2, satisfies 7
	let block_tx_2 = test_transaction(&mut secp, &keychain, vec![2_000], vec![600]);
	// - Copy of 4
	let block_tx_3 = test_transaction(&mut secp, &keychain, vec![800], vec![500, 100]);
	// - Output conflict w/ 8
	let block_tx_4 = test_transaction(&mut secp, &keychain, vec![4_000], vec![900, 2_900]);

	let block_txs = &[block_tx_1, block_tx_2, block_tx_3, block_tx_4];
	add_block(&mut secp, &chain, block_txs, &keychain);
	let block = chain
		.get_block(&chain.head().unwrap().hash(chain.get_context_id()).unwrap())
		.unwrap();

	// Check the pool still contains everything we expect at this point.
	assert_eq!(pool.total_size(), txs_to_add.len());

	// And reconcile the pool with this latest block.
	pool.reconcile_block(&block, &mut secp);

	assert_eq!(pool.total_size(), 4);
	// Compare the various txs by their kernels as entries in the pool are "v2" compatibility.
	let entries = pool.txpool.all_entries();
	assert!(ser::slices_equal_by_hash(
		chain.get_context_id(),
		entries[0].tx.kernels(),
		valid_transaction.kernels()
	)
	.unwrap());
	assert!(ser::slices_equal_by_hash(
		chain.get_context_id(),
		entries[1].tx.kernels(),
		pool_child.kernels()
	)
	.unwrap());
	assert!(ser::slices_equal_by_hash(
		chain.get_context_id(),
		entries[2].tx.kernels(),
		conflict_valid_child.kernels()
	)
	.unwrap());
	assert!(ser::slices_equal_by_hash(
		chain.get_context_id(),
		entries[3].tx.kernels(),
		valid_child_valid.kernels()
	)
	.unwrap());

	// Cleanup db directory
	clean_output_dir(db_root.into());
}
