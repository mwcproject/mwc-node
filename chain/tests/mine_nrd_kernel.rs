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

#[path = "../src/tests/chain_test_helper.rs"]
mod chain_test_helper;

use self::chain_test_helper::{clean_output_dir, genesis_block, init_chain};
use mwc_chain::{Chain, Options};
use mwc_core::core::{Block, KernelFeatures, NRDRelativeHeight, Transaction};
use mwc_core::libtx::{build, reward, ProofBuilder};
use mwc_core::{consensus, global, pow};
use mwc_crates::chrono::Duration;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{ExtKeychain, ExtKeychainPath, Identifier, Keychain};
use std::convert::TryInto;
use std::sync::{Mutex, MutexGuard};

const TEST_CHAIN_CONFIG_CONTEXT_ID: u32 = 0;
static GLOBAL_CHAIN_CONFIG_LOCK: Mutex<()> = Mutex::new(());

struct GlobalChainConfigGuard {
	context_id: u32,
	_lock: MutexGuard<'static, ()>,
}

impl GlobalChainConfigGuard {
	fn automated_testing_with_nrd_enabled() -> Self {
		let lock = GLOBAL_CHAIN_CONFIG_LOCK
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		global::release_context_data(TEST_CHAIN_CONFIG_CONTEXT_ID);
		global::init_global_chain_type(
			TEST_CHAIN_CONFIG_CONTEXT_ID,
			global::ChainTypes::AutomatedTesting,
		)
		.unwrap();
		global::init_global_nrd_enabled(TEST_CHAIN_CONFIG_CONTEXT_ID, true).unwrap();
		GlobalChainConfigGuard {
			context_id: TEST_CHAIN_CONFIG_CONTEXT_ID,
			_lock: lock,
		}
	}
}

impl Drop for GlobalChainConfigGuard {
	fn drop(&mut self) {
		global::release_context_data(self.context_id);
	}
}

fn build_block<K>(chain: &Chain, keychain: &K, key_id: &Identifier, txs: Vec<Transaction>) -> Block
where
	K: Keychain,
{
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let prev = chain.head_header().unwrap();
	let mut cache_values = consensus::DifficultyCache::new();
	let next_header_info = consensus::next_difficulty(
		0,
		prev.height + 1,
		chain.difficulty_iter().unwrap(),
		&mut cache_values,
	)
	.unwrap();
	let fee = txs.iter().map(|x| x.fee().unwrap()).sum();
	let reward = reward::output(
		0,
		keychain,
		&ProofBuilder::new(&secp, keychain).unwrap(),
		key_id,
		fee,
		false,
		prev.height + 1,
		&mut secp,
	)
	.unwrap();

	let mut block = Block::new(
		0,
		&prev,
		&txs,
		next_header_info.clone().difficulty,
		reward,
		&mut secp,
	)
	.unwrap();

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	chain.set_txhashset_roots(&secp, &mut block).unwrap();

	let edge_bits = global::min_edge_bits(0);
	block.header.pow.proof.edge_bits = edge_bits;
	pow::pow_size(
		0,
		&mut block.header,
		next_header_info.difficulty,
		global::proofsize(0),
		edge_bits,
	)
	.unwrap();

	block
}

#[test]
fn mine_block_with_nrd_kernel_and_nrd_feature_enabled() {
	let _global_chain_config = GlobalChainConfigGuard::automated_testing_with_nrd_enabled();

	mwc_util::init_test_logger().unwrap();

	let chain_dir = ".mwc.nrd_kernel";
	clean_output_dir(chain_dir);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let pb = ProofBuilder::new(&secp, &keychain).unwrap();
	let genesis = genesis_block(&mut secp, &keychain);
	let chain = init_chain(&secp, chain_dir, genesis.clone());

	for n in 1..9 {
		let key_id = ExtKeychainPath::new(1, n, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let block = build_block(&chain, &keychain, &key_id, vec![]);
		chain
			.process_block(
				&mut secp,
				block,
				Options::MINE,
				std::collections::HashSet::new(),
			)
			.unwrap();
	}

	assert_eq!(chain.head().unwrap().height, 8);

	let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::NoRecentDuplicate {
			fee: 20000u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(1440).unwrap(),
		},
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id2.clone()),
		],
		&keychain,
		&pb,
	)
	.unwrap();

	let key_id9 = ExtKeychainPath::new(1, 9, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let block = build_block(&chain, &keychain, &key_id9, vec![tx]);
	chain
		.process_block(
			&mut secp,
			block,
			Options::MINE,
			std::collections::HashSet::new(),
		)
		.unwrap();
	chain.validate(&secp, false).unwrap();

	clean_output_dir(chain_dir);
}

#[test]
fn mine_invalid_block_with_nrd_kernel_and_nrd_feature_enabled_before_hf() {
	let _global_chain_config = GlobalChainConfigGuard::automated_testing_with_nrd_enabled();

	mwc_util::init_test_logger().unwrap();

	let chain_dir = ".mwc.invalid_nrd_kernel";
	clean_output_dir(chain_dir);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let pb = ProofBuilder::new(&secp, &keychain).unwrap();
	let genesis = genesis_block(&mut secp, &keychain);
	let chain = init_chain(&secp, chain_dir, genesis.clone());

	for n in 1..8 {
		let key_id = ExtKeychainPath::new(1, n, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let block = build_block(&chain, &keychain, &key_id, vec![]);
		chain
			.process_block(
				&mut secp,
				block,
				Options::MINE,
				std::collections::HashSet::new(),
			)
			.unwrap();
	}

	assert_eq!(chain.head().unwrap().height, 7);

	let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::NoRecentDuplicate {
			fee: 20000u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(1440).unwrap(),
		},
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id2.clone()),
		],
		&keychain,
		&pb,
	)
	.unwrap();

	let key_id8 = ExtKeychainPath::new(1, 8, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let block = build_block(&chain, &keychain, &key_id8, vec![tx]);
	let res = chain.process_block(
		&mut secp,
		block,
		Options::MINE,
		std::collections::HashSet::new(),
	);
	assert!(res.is_err());
	clean_output_dir(chain_dir);
}
