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

use self::chain_test_helper::build;
use self::chain_test_helper::{clean_output_dir, genesis_block, init_chain};
use mwc_chain::{Chain, Error, Options};
use mwc_core::core::hash::Hashed;
use mwc_core::core::{
	Block, BlockHeader, KernelFeatures, NRDRelativeHeight, Transaction, TxKernel,
};
use mwc_core::libtx::{aggsig, reward, ProofBuilder};
use mwc_core::{consensus, global, pow};
use mwc_crates::chrono::Duration;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{BlindingFactor, ExtKeychain, ExtKeychainPath, Identifier, Keychain};
use std::convert::TryInto;

fn build_block<K>(
	secp: &mut Secp256k1,
	chain: &Chain,
	keychain: &K,
	key_id: &Identifier,
	txs: Vec<Transaction>,
) -> Result<Block, Error>
where
	K: Keychain,
{
	let prev = chain.head_header()?;
	build_block_from_prev(secp, &prev, chain, keychain, key_id, txs)
}

fn build_block_from_prev<K>(
	secp: &mut Secp256k1,
	prev: &BlockHeader,
	chain: &Chain,
	keychain: &K,
	key_id: &Identifier,
	txs: Vec<Transaction>,
) -> Result<Block, Error>
where
	K: Keychain,
{
	let mut cache_values = consensus::DifficultyCache::new();
	let prev_hash = prev.hash(0)?;
	let next_header_info = consensus::next_difficulty(
		0,
		prev.height + 1,
		chain.difficulty_iter_from(prev_hash)?,
		&mut cache_values,
	)
	.map_err(|e| Error::Other(format!("Difficulty calculation error, {}", e)))?;
	let fee = txs.iter().map(|x| x.fee().unwrap()).sum();
	let reward = reward::output(
		0,
		keychain,
		&ProofBuilder::new(secp, keychain).unwrap(),
		key_id,
		fee,
		false,
		prev.height + 1,
		secp,
	)
	.unwrap();

	let mut block = Block::new(
		0,
		prev,
		&txs,
		next_header_info.clone().difficulty,
		reward,
		secp,
	)
	.map_err(|e| Error::Block(e))?;

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	chain.set_txhashset_roots(secp, &mut block)?;

	block.header.pow.proof.edge_bits = global::min_edge_bits(0);
	pow::pow_size(
		0,
		&mut block.header,
		next_header_info.difficulty,
		global::proofsize(0),
		global::min_edge_bits(0),
	)
	.unwrap();
	Ok(block)
}

#[test]
fn process_block_nrd_validation() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	mwc_util::init_test_logger().unwrap();

	let chain_dir = ".mwc.nrd_kernel";
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let genesis = genesis_block(&mut secp, &keychain);
	let chain = init_chain(&secp, chain_dir, genesis.clone());

	for n in 1..9 {
		let key_id = ExtKeychainPath::new(1, n, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let block = build_block(&mut secp, &chain, &keychain, &key_id, vec![])?;
		chain.process_block(
			&mut secp,
			block,
			Options::NONE,
			std::collections::HashSet::new(),
		)?;
	}

	assert_eq!(chain.head()?.height, 8);

	let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000u32.try_into().unwrap(),
		relative_height: NRDRelativeHeight::new(2)?,
	})?;

	// // Construct the message to be signed.
	let msg = kernel.msg_to_sign(0).unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand(&secp)?;
	let skey = excess.secret_key(&secp).unwrap();
	kernel.excess = secp.commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey(&secp).unwrap();
	kernel.excess_sig = aggsig::sign_with_blinding(&&secp, &msg, &excess, &pubkey).unwrap();
	kernel.verify(0, &secp).unwrap();

	let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();

	let tx1 = build::transaction_with_kernel(
		0,
		&mut secp,
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id2.clone()),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let tx2 = build::transaction_with_kernel(
		0,
		&mut secp,
		&[
			build::input(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id2.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 40000, key_id3.clone()),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let key_id9 = ExtKeychainPath::new(1, 9, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id10 = ExtKeychainPath::new(1, 10, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id11 = ExtKeychainPath::new(1, 11, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();

	// Block containing both tx1 and tx2 is invalid.
	// Not valid for two duplicate NRD kernels to co-exist in same block.
	// Jump through some hoops to build an invalid block by disabling the feature flag.
	// TODO - We need a good way of building invalid stuff in tests.
	let block_invalid_9 = {
		global::set_local_nrd_enabled(false);
		let block = build_block(
			&mut secp,
			&chain,
			&keychain,
			&key_id9,
			vec![tx1.clone(), tx2.clone()],
		)?;
		global::set_local_nrd_enabled(true);
		block
	};
	assert!(chain
		.process_block(
			&mut secp,
			block_invalid_9,
			Options::NONE,
			std::collections::HashSet::new()
		)
		.is_err());

	assert_eq!(chain.head()?.height, 8);

	// Block containing tx1 is valid.
	let block_valid_9 = build_block(&mut secp, &chain, &keychain, &key_id9, vec![tx1.clone()])?;
	chain.process_block(
		&mut secp,
		block_valid_9,
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	// Block at height 10 is invalid if it contains tx2 due to NRD rule (relative_height=2).
	// Jump through some hoops to build an invalid block by disabling the feature flag.
	// TODO - We need a good way of building invalid stuff in tests.
	let block_invalid_10 = {
		global::set_local_nrd_enabled(false);
		let block = build_block(&mut secp, &chain, &keychain, &key_id10, vec![tx2.clone()])?;
		global::set_local_nrd_enabled(true);
		block
	};

	assert!(chain
		.process_block(
			&mut secp,
			block_invalid_10,
			Options::NONE,
			std::collections::HashSet::new()
		)
		.is_err());

	// Block at height 10 is valid if we do not include tx2.
	let block_valid_10 = build_block(&mut secp, &chain, &keychain, &key_id10, vec![])?;
	chain.process_block(
		&mut secp,
		block_valid_10,
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	// Block at height 11 is valid with tx2 as NRD rule is met (relative_height=2).
	let block_valid_11 = build_block(&mut secp, &chain, &keychain, &key_id11, vec![tx2.clone()])?;
	chain.process_block(
		&mut secp,
		block_valid_11,
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	clean_output_dir(chain_dir);
	Ok(())
}

#[test]
fn process_block_nrd_validation_relative_height_1() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	mwc_util::init_test_logger().unwrap();

	let chain_dir = ".mwc.nrd_kernel_relative_height_1";
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let genesis = genesis_block(&mut secp, &keychain);
	let chain = init_chain(&secp, chain_dir, genesis.clone());

	for n in 1..9 {
		let key_id = ExtKeychainPath::new(1, n, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let block = build_block(&mut secp, &chain, &keychain, &key_id, vec![])?;
		chain.process_block(
			&mut secp,
			block,
			Options::NONE,
			std::collections::HashSet::new(),
		)?;
	}

	assert_eq!(chain.head()?.height, 8);

	let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000u32.try_into().unwrap(),
		relative_height: NRDRelativeHeight::new(1)?,
	})?;

	// // Construct the message to be signed.
	let msg = kernel.msg_to_sign(0).unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand(&secp)?;
	let skey = excess.secret_key(&secp).unwrap();
	kernel.excess = secp.commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey(&secp).unwrap();
	kernel.excess_sig = aggsig::sign_with_blinding(&&secp, &msg, &excess, &pubkey).unwrap();
	kernel.verify(0, &secp).unwrap();

	let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();

	let tx1 = build::transaction_with_kernel(
		0,
		&mut secp,
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id2.clone()),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let tx2 = build::transaction_with_kernel(
		0,
		&mut secp,
		&[
			build::input(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id2.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 40000, key_id3.clone()),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let key_id9 = ExtKeychainPath::new(1, 9, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id10 = ExtKeychainPath::new(1, 10, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();

	// Block containing both tx1 and tx2 is invalid.
	// Not valid for two duplicate NRD kernels to co-exist in same block.
	// Jump through some hoops here to build an "invalid" block.
	// TODO - We need a good way of building invalid stuff for tests.
	let block_invalid_9 = {
		global::set_local_nrd_enabled(false);
		let block = build_block(
			&mut secp,
			&chain,
			&keychain,
			&key_id9,
			vec![tx1.clone(), tx2.clone()],
		)?;
		global::set_local_nrd_enabled(true);
		block
	};

	assert!(chain
		.process_block(
			&mut secp,
			block_invalid_9,
			Options::NONE,
			std::collections::HashSet::new()
		)
		.is_err());

	assert_eq!(chain.head()?.height, 8);

	// Block containing tx1 is valid.
	let block_valid_9 = build_block(&mut secp, &chain, &keychain, &key_id9, vec![tx1.clone()])?;
	chain.process_block(
		&mut secp,
		block_valid_9,
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	// Block at height 10 is valid with tx2 as NRD rule is met (relative_height=1).
	let block_valid_10 = build_block(&mut secp, &chain, &keychain, &key_id10, vec![tx2.clone()])?;
	chain.process_block(
		&mut secp,
		block_valid_10,
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	clean_output_dir(chain_dir);
	Ok(())
}

#[test]
fn process_block_nrd_validation_fork() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	mwc_util::init_test_logger().unwrap();

	let chain_dir = ".mwc.nrd_kernel_fork";
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let genesis = genesis_block(&mut secp, &keychain);
	let chain = init_chain(&secp, chain_dir, genesis.clone());

	for n in 1..9 {
		let key_id = ExtKeychainPath::new(1, n, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let block = build_block(&mut secp, &chain, &keychain, &key_id, vec![])?;
		chain.process_block(
			&mut secp,
			block,
			Options::NONE,
			std::collections::HashSet::new(),
		)?;
	}

	let header_8 = chain.head_header()?;
	assert_eq!(header_8.height, 8);

	let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000u32.try_into().unwrap(),
		relative_height: NRDRelativeHeight::new(2)?,
	})?;

	// // Construct the message to be signed.
	let msg = kernel.msg_to_sign(0).unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand(&secp)?;
	let skey = excess.secret_key(&secp).unwrap();
	kernel.excess = secp.commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey(&secp).unwrap();
	kernel.excess_sig = aggsig::sign_with_blinding(&&secp, &msg, &excess, &pubkey).unwrap();
	kernel.verify(0, &secp).unwrap();

	let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();

	let tx1 = build::transaction_with_kernel(
		0,
		&mut secp,
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id2.clone()),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let tx2 = build::transaction_with_kernel(
		0,
		&mut secp,
		&[
			build::input(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id2.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 40000, key_id3.clone()),
		],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let key_id9 = ExtKeychainPath::new(1, 9, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id10 = ExtKeychainPath::new(1, 10, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let key_id11 = ExtKeychainPath::new(1, 11, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();

	// Block containing tx1 is valid.
	let block_valid_9 = build_block_from_prev(
		&mut secp,
		&header_8,
		&chain,
		&keychain,
		&key_id9,
		vec![tx1.clone()],
	)?;
	chain.process_block(
		&mut secp,
		block_valid_9.clone(),
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	// Block at height 10 is valid if we do not include tx2.
	let block_valid_10 = build_block_from_prev(
		&mut secp,
		&block_valid_9.header,
		&chain,
		&keychain,
		&key_id10,
		vec![],
	)?;
	chain.process_block(
		&mut secp,
		block_valid_10,
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	// Process an alternative "fork" block also at height 9.
	// The "other" block at height 9 should not affect this one in terms of NRD kernels
	// as the recent kernel index should be rewound.
	let block_valid_9b = build_block_from_prev(
		&mut secp,
		&header_8,
		&chain,
		&keychain,
		&key_id9,
		vec![tx1.clone()],
	)?;
	chain.process_block(
		&mut secp,
		block_valid_9b.clone(),
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	// Process an alternative block at height 10 on this same fork.
	let block_valid_10b = build_block_from_prev(
		&mut secp,
		&block_valid_9b.header,
		&chain,
		&keychain,
		&key_id10,
		vec![],
	)?;
	chain.process_block(
		&mut secp,
		block_valid_10b.clone(),
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	// Block at height 11 is valid with tx2 as NRD rule is met (relative_height=2).
	let block_valid_11b = build_block_from_prev(
		&mut secp,
		&block_valid_10b.header,
		&chain,
		&keychain,
		&key_id11,
		vec![tx2.clone()],
	)?;
	chain.process_block(
		&mut secp,
		block_valid_11b,
		Options::NONE,
		std::collections::HashSet::new(),
	)?;

	clean_output_dir(chain_dir);
	Ok(())
}
