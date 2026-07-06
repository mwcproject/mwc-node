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
use mwc_core::consensus;
use mwc_core::core::hash::Hashed;
use mwc_core::core::{HeaderVersion, KernelFeatures, NRDRelativeHeight, TxKernel};
use mwc_core::global;
use mwc_core::libtx::aggsig;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{BlindingFactor, ExtKeychain, Keychain};
use mwc_pool::types::PoolError;
use std::convert::TryInto;
use std::sync::Arc;

#[test]
fn test_nrd_kernel_relative_height() -> Result<(), PoolError> {
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_accept_fee_base(10).unwrap();
	global::set_local_nrd_enabled(true);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let keychain: ExtKeychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();

	let db_root = "target/.nrd_kernel_relative_height";
	clean_output_dir(db_root.into());

	let genesis = genesis_block(&keychain);
	let chain = Arc::new(init_chain(&secp, db_root, genesis));

	// Initialize a new pool with our chain adapter.
	let mut pool = init_transaction_pool(Arc::new(ChainAdapter {
		chain: chain.clone(),
	}));

	add_some_blocks(&mut secp, &chain, 3, &keychain);

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

	// mine past HF4 to see effect of set_local_accept_fee_base
	add_some_blocks(&mut secp, &chain, 8, &keychain);

	let header = chain.head_header().unwrap();

	// Note, in MWC NRD will be activated from Header 3. But 4 for the testing does work well too
	assert_eq!(header.height, 4 * consensus::TESTING_HARD_FORK_INTERVAL);
	assert_eq!(header.version, HeaderVersion(4));

	let (tx1, tx2, tx3) = {
		let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 600u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(2)?,
		})?;
		let msg = kernel.msg_to_sign(chain.get_context_id()).unwrap();

		// Generate a kernel with public excess and associated signature.
		let excess = BlindingFactor::rand(&secp)?;
		let skey = excess.secret_key(&secp).unwrap();
		kernel.excess = secp.commit(0, skey).unwrap();
		let pubkey = &kernel.excess.to_pubkey(&secp).unwrap();
		kernel.excess_sig = aggsig::sign_with_blinding(&&secp, &msg, &excess, &pubkey).unwrap();
		kernel.verify(chain.get_context_id(), &secp).unwrap();

		// Generate a 2nd NRD kernel sharing the same excess commitment but with different signature.
		let mut kernel2 = kernel.clone();
		kernel2.excess_sig = aggsig::sign_with_blinding(&&secp, &msg, &excess, &pubkey).unwrap();
		kernel2.verify(chain.get_context_id(), &secp).unwrap();

		let tx1 = test_transaction_with_kernel(
			&mut secp,
			&keychain,
			vec![1_000, 2_000],
			vec![2_400],
			kernel.clone(),
			excess.clone(),
		);

		let tx2 = test_transaction_with_kernel(
			&mut secp,
			&keychain,
			vec![2_400],
			vec![1_800],
			kernel2.clone(),
			excess.clone(),
		);

		// Now reuse kernel excess for tx3 but with NRD relative_height=1 (and different fee).
		let mut kernel_short = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 300u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(1)?,
		})?;
		let msg_short = kernel_short.msg_to_sign(chain.get_context_id()).unwrap();
		kernel_short.excess = kernel.excess;
		kernel_short.excess_sig =
			aggsig::sign_with_blinding(&&secp, &msg_short, &excess, &pubkey).unwrap();
		kernel_short.verify(chain.get_context_id(), &secp).unwrap();

		let tx3 = test_transaction_with_kernel(
			&mut secp,
			&keychain,
			vec![1_800],
			vec![1_500],
			kernel_short.clone(),
			excess.clone(),
		);

		(tx1, tx2, tx3)
	};

	// Confirm we can successfully add tx1 with NRD kernel to stempool.
	assert!(pool
		.add_to_pool(test_source(), tx1.clone(), true, &header, &mut secp)
		.is_ok());
	assert_eq!(pool.stempool.size(), 1);

	// Confirm we cannot add tx2 to stempool while tx1 is in there (duplicate NRD kernels).
	assert!(matches!(
		pool.add_to_pool(test_source(), tx2.clone(), true, &header, &mut secp),
		Err(PoolError::NRDKernelRelativeHeight)
	));

	// Confirm we can successfully add tx1 with NRD kernel to txpool,
	// removing existing instance of tx1 from stempool in the process.
	assert!(pool
		.add_to_pool(test_source(), tx1.clone(), false, &header, &mut secp)
		.is_ok());
	assert_eq!(pool.txpool.size(), 1);
	assert_eq!(pool.stempool.size(), 0);

	// Confirm we cannot add tx2 to stempool while tx1 is in txpool (duplicate NRD kernels).
	assert!(matches!(
		pool.add_to_pool(test_source(), tx2.clone(), true, &header, &mut secp),
		Err(PoolError::NRDKernelRelativeHeight)
	));

	// Confirm we cannot add tx2 to txpool while tx1 is in there (duplicate NRD kernels).
	assert!(matches!(
		pool.add_to_pool(test_source(), tx2.clone(), false, &header, &mut secp),
		Err(PoolError::NRDKernelRelativeHeight)
	));

	assert_eq!(pool.total_size(), 1);
	assert_eq!(pool.txpool.size(), 1);
	assert_eq!(pool.stempool.size(), 0);

	let txs = pool.prepare_mineable_transactions(&mut secp).unwrap();
	assert_eq!(txs.len(), 1);

	// Mine block containing tx1 from the txpool.
	add_block(&mut secp, &chain, &txs, &keychain);
	let header = chain.head_header().unwrap();
	let block = chain
		.get_block(&header.hash(chain.get_context_id()).unwrap())
		.unwrap();

	// Confirm the stempool/txpool is empty after reconciling the new block.
	pool.reconcile_block(&block, &mut secp);
	assert_eq!(pool.total_size(), 0);
	assert_eq!(pool.txpool.size(), 0);
	assert_eq!(pool.stempool.size(), 0);

	// Confirm we cannot add tx2 to stempool with tx1 in previous block (NRD relative_height=2)
	assert!(matches!(
		pool.add_to_pool(test_source(), tx2.clone(), true, &header, &mut secp),
		Err(PoolError::NRDKernelRelativeHeight)
	));

	// Confirm we cannot add tx2 to txpool with tx1 in previous block (NRD relative_height=2)
	assert!(matches!(
		pool.add_to_pool(test_source(), tx2.clone(), false, &header, &mut secp),
		Err(PoolError::NRDKernelRelativeHeight)
	));

	// Add another block so NRD relative_height rule is now met.
	add_block(&mut secp, &chain, &[], &keychain);
	let header = chain.head_header().unwrap();

	// Confirm we can now add tx2 to stempool with NRD relative_height rule met.
	assert!(pool
		.add_to_pool(test_source(), tx2.clone(), true, &header, &mut secp)
		.is_ok());
	assert_eq!(pool.total_size(), 0);
	assert_eq!(pool.txpool.size(), 0);
	assert_eq!(pool.stempool.size(), 1);

	// Confirm we cannot yet add tx3 to stempool (NRD relative_height=1)
	assert!(matches!(
		pool.add_to_pool(test_source(), tx3.clone(), true, &header, &mut secp),
		Err(PoolError::NRDKernelRelativeHeight)
	));

	// Confirm we can now add tx2 to txpool with NRD relative_height rule met.
	assert!(pool
		.add_to_pool(test_source(), tx2.clone(), false, &header, &mut secp)
		.is_ok());

	// Confirm we cannot yet add tx3 to txpool (NRD relative_height=1)
	assert!(matches!(
		pool.add_to_pool(test_source(), tx3.clone(), false, &header, &mut secp),
		Err(PoolError::NRDKernelRelativeHeight)
	));

	assert_eq!(pool.total_size(), 1);
	assert_eq!(pool.txpool.size(), 1);
	assert_eq!(pool.stempool.size(), 0);

	let txs = pool.prepare_mineable_transactions(&mut secp).unwrap();
	assert_eq!(txs.len(), 1);

	// Mine block containing tx2 from the txpool.
	add_block(&mut secp, &chain, &txs, &keychain);
	let header = chain.head_header().unwrap();
	let block = chain
		.get_block(&header.hash(chain.get_context_id()).unwrap())
		.unwrap();
	pool.reconcile_block(&block, &mut secp);

	assert_eq!(pool.total_size(), 0);
	assert_eq!(pool.txpool.size(), 0);
	assert_eq!(pool.stempool.size(), 0);

	// Confirm we can now add tx3 to stempool with tx2 in immediate previous block (NRD relative_height=1)
	assert!(pool
		.add_to_pool(test_source(), tx3.clone(), true, &header, &mut secp)
		.is_ok());

	assert_eq!(pool.total_size(), 0);
	assert_eq!(pool.txpool.size(), 0);
	assert_eq!(pool.stempool.size(), 1);

	// Confirm we can now add tx3 to txpool with tx2 in immediate previous block (NRD relative_height=1)
	assert!(pool
		.add_to_pool(test_source(), tx3.clone(), false, &header, &mut secp)
		.is_ok());

	assert_eq!(pool.total_size(), 1);
	assert_eq!(pool.txpool.size(), 1);
	assert_eq!(pool.stempool.size(), 0);

	// Cleanup db directory
	clean_output_dir(db_root.into());

	Ok(())
}
