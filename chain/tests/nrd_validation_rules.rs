// Copyright 2020 The Grin Developers
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

mod chain_test_helper;

use grin_chain as chain;
use grin_core as core;
use grin_keychain as keychain;
use grin_util as util;

use self::chain_test_helper::{clean_output_dir, genesis_block, init_chain};
use crate::chain::{Chain, Error, Options};
use crate::core::core::{
	Block, BlockHeader, KernelFeatures, NRDRelativeHeight, Transaction, TxKernel,
};
use crate::core::libtx::{aggsig, build, reward, ProofBuilder};
use crate::core::{consensus, global, pow};
use crate::keychain::{BlindingFactor, ExtKeychain, ExtKeychainPath, Identifier, Keychain};
use chrono::Duration;

fn build_block<K>(
	chain: &Chain,
	keychain: &K,
	key_id: &Identifier,
	txs: Vec<Transaction>,
) -> Result<Block, Error>
where
	K: Keychain,
{
	let prev = chain.head_header()?;
	build_block_from_prev(&prev, chain, keychain, key_id, txs)
}

fn build_block_from_prev<K>(
	prev: &BlockHeader,
	chain: &Chain,
	keychain: &K,
	key_id: &Identifier,
	txs: Vec<Transaction>,
) -> Result<Block, Error>
where
	K: Keychain,
{
	let next_header_info =
		consensus::next_difficulty(prev.height, chain.difficulty_iter().unwrap());
	let fee = txs.iter().map(|x| x.fee()).sum();
	let reward = reward::output(
		keychain,
		&ProofBuilder::new(keychain),
		key_id,
		fee,
		false,
		prev.height + 1,
	)
	.unwrap();

	let mut block = Block::new(prev, &txs, next_header_info.clone().difficulty, reward)?;

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	chain.set_txhashset_roots(&mut block)?;

	block.header.pow.proof.edge_bits = global::min_edge_bits();
	pow::pow_size(
		&mut block.header,
		next_header_info.difficulty,
		global::proofsize(),
		global::min_edge_bits(),
	)
	.unwrap();
	Ok(block)
}

#[test]
fn process_block_nrd_validation() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	util::init_test_logger();

	let chain_dir = ".grin.nrd_kernel";
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());

	for n in 1..9 {
		let key_id = ExtKeychainPath::new(1, n, 0, 0, 0).to_identifier();
		let block = build_block(&chain, &keychain, &key_id, vec![])?;
		chain.process_block(block, Options::NONE)?;
	}

	assert_eq!(chain.head()?.height, 8);

	let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000,
		relative_height: NRDRelativeHeight::new(2)?,
	});

	// // Construct the message to be signed.
	let msg = kernel.msg_to_sign().unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand();
	let skey = excess.secret_key().unwrap();
	kernel.excess = keychain.secp().commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey().unwrap();
	kernel.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg, &excess, Some(&pubkey)).unwrap();
	kernel.verify().unwrap();

	let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
	let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

	let tx1 = build::transaction_with_kernel(
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

	let key_id9 = ExtKeychainPath::new(1, 9, 0, 0, 0).to_identifier();
	let key_id10 = ExtKeychainPath::new(1, 10, 0, 0, 0).to_identifier();
	let key_id11 = ExtKeychainPath::new(1, 11, 0, 0, 0).to_identifier();

	// Block containing both tx1 and tx2 is invalid.
	// Not valid for two duplicate NRD kernels to co-exist in same block.
	// Jump through some hoops to build an invalid block by disabling the feature flag.
	// TODO - We need a good way of building invalid stuff in tests.
	let block_invalid_9 = {
		global::set_local_nrd_enabled(false);
		let block = build_block(&chain, &keychain, &key_id9, vec![tx1.clone(), tx2.clone()])?;
		global::set_local_nrd_enabled(true);
		block
	};
	assert!(chain.process_block(block_invalid_9, Options::NONE).is_err());

	assert_eq!(chain.head()?.height, 8);

	// Block containing tx1 is valid.
	let block_valid_9 = build_block(&chain, &keychain, &key_id9, vec![tx1.clone()])?;
	chain.process_block(block_valid_9, Options::NONE)?;

	// Block at height 10 is invalid if it contains tx2 due to NRD rule (relative_height=2).
	// Jump through some hoops to build an invalid block by disabling the feature flag.
	// TODO - We need a good way of building invalid stuff in tests.
	let block_invalid_10 = {
		global::set_local_nrd_enabled(false);
		let block = build_block(&chain, &keychain, &key_id10, vec![tx2.clone()])?;
		global::set_local_nrd_enabled(true);
		block
	};

	assert!(chain
		.process_block(block_invalid_10, Options::NONE)
		.is_err());

	// Block at height 10 is valid if we do not include tx2.
	let block_valid_10 = build_block(&chain, &keychain, &key_id10, vec![])?;
	chain.process_block(block_valid_10, Options::NONE)?;

	// Block at height 11 is valid with tx2 as NRD rule is met (relative_height=2) but it will fail due to replay attack.
	let block_invalid_11 = build_block(&chain, &keychain, &key_id11, vec![tx2.clone()])?;
	assert!(chain
		.process_block(block_invalid_11, Options::NONE)
		.is_err());

	clean_output_dir(chain_dir);
	Ok(())
}

#[test]
fn process_block_nrd_validation_relative_height_1() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	util::init_test_logger();

	let chain_dir = ".grin.nrd_kernel_relative_height_1";
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());

	for n in 1..9 {
		let key_id = ExtKeychainPath::new(1, n, 0, 0, 0).to_identifier();
		let block = build_block(&chain, &keychain, &key_id, vec![])?;
		chain.process_block(block, Options::NONE)?;
	}

	assert_eq!(chain.head()?.height, 8);

	let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000,
		relative_height: NRDRelativeHeight::new(1)?,
	});

	// // Construct the message to be signed.
	let msg = kernel.msg_to_sign().unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand();
	let skey = excess.secret_key().unwrap();
	kernel.excess = keychain.secp().commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey().unwrap();
	kernel.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg, &excess, Some(&pubkey)).unwrap();
	kernel.verify().unwrap();

	let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
	let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

	let tx1 = build::transaction_with_kernel(
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

	let key_id9 = ExtKeychainPath::new(1, 9, 0, 0, 0).to_identifier();
	let key_id10 = ExtKeychainPath::new(1, 10, 0, 0, 0).to_identifier();

	// Block containing both tx1 and tx2 is invalid.
	// Not valid for two duplicate NRD kernels to co-exist in same block.
	// Jump through some hoops here to build an "invalid" block.
	// TODO - We need a good way of building invalid stuff for tests.
	let block_invalid_9 = {
		global::set_local_nrd_enabled(false);
		let block = build_block(&chain, &keychain, &key_id9, vec![tx1.clone(), tx2.clone()])?;
		global::set_local_nrd_enabled(true);
		block
	};

	assert!(chain.process_block(block_invalid_9, Options::NONE).is_err());

	assert_eq!(chain.head()?.height, 8);

	// Block containing tx1 is valid.
	let block_valid_9 = build_block(&chain, &keychain, &key_id9, vec![tx1.clone()])?;
	chain.process_block(block_valid_9, Options::NONE)?;

	// Block at height 10 is valid with tx2 as NRD rule is met (relative_height=1) and fail with replay attack check.
	let block_invalid_10 = build_block(&chain, &keychain, &key_id10, vec![tx2.clone()])?;
	assert!(chain
		.process_block(block_invalid_10, Options::NONE)
		.is_err());

	clean_output_dir(chain_dir);
	Ok(())
}

#[test]
fn process_block_nrd_validation_fork() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	util::init_test_logger();

	let chain_dir = ".grin.nrd_kernel_fork";
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let builder = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());

	for n in 1..9 {
		let key_id = ExtKeychainPath::new(1, n, 0, 0, 0).to_identifier();
		let block = build_block(&chain, &keychain, &key_id, vec![])?;
		chain.process_block(block, Options::NONE)?;
	}

	let header_8 = chain.head_header()?;
	assert_eq!(header_8.height, 8);

	let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000,
		relative_height: NRDRelativeHeight::new(2)?,
	});

	// // Construct the message to be signed.
	let msg = kernel.msg_to_sign().unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand();
	let skey = excess.secret_key().unwrap();
	kernel.excess = keychain.secp().commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey().unwrap();
	kernel.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg, &excess, Some(&pubkey)).unwrap();
	kernel.verify().unwrap();

	//	let  (mut kernel, excess)  = getRandomKenel(&keychain, 2000)?;

	let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
	let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

	let tx1 = build::transaction_with_kernel(
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

	let mut kernel2 = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000,
		relative_height: NRDRelativeHeight::new(2)?,
	});
	// // Construct the message to be signed.
	let msg2 = kernel2.msg_to_sign().unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess2 = BlindingFactor::rand();
	let skey2 = excess2.secret_key().unwrap();
	kernel2.excess = keychain.secp().commit(0, skey2).unwrap();
	let pubkey2 = &kernel2.excess.to_pubkey().unwrap();
	kernel2.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg2, &excess2, Some(&pubkey2)).unwrap();
	kernel2.verify().unwrap();
	//	let  (kernel2, excess2) = getRandomKenel(&keychain, 2000)?;

	let key_id4 = ExtKeychainPath::new(1, 4, 0, 0, 0).to_identifier();
	let key_id5 = ExtKeychainPath::new(1, 5, 0, 0, 0).to_identifier();
	let key_id6 = ExtKeychainPath::new(1, 6, 0, 0, 0).to_identifier();
	let key_id7 = ExtKeychainPath::new(1, 7, 0, 0, 0).to_identifier();

	let tx3 = build::transaction_with_kernel(
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id4.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id5.clone()),
		],
		kernel2.clone(),
		excess2.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let mut kernel3 = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: 20000,
		relative_height: NRDRelativeHeight::new(2)?,
	});
	// // Construct the message to be signed.
	let msg3 = kernel3.msg_to_sign().unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess3 = BlindingFactor::rand();
	let skey3 = excess3.secret_key().unwrap();
	kernel3.excess = keychain.secp().commit(0, skey3).unwrap();
	let pubkey3 = &kernel3.excess.to_pubkey().unwrap();
	kernel3.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg3, &excess3, Some(&pubkey3)).unwrap();
	kernel3.verify().unwrap();
	//	let  (kernel3, excess3)  = getRandomKenel(&keychain, 2000)?;

	let tx4 = build::transaction_with_kernel(
		&[
			build::input(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id5.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD - 40000, key_id6.clone()),
		],
		kernel3.clone(),
		excess3.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let key_id9 = ExtKeychainPath::new(1, 9, 0, 0, 0).to_identifier();
	let key_id10 = ExtKeychainPath::new(1, 10, 0, 0, 0).to_identifier();
	let key_id11 = ExtKeychainPath::new(1, 11, 0, 0, 0).to_identifier();
	let key_id12 = ExtKeychainPath::new(1, 12, 0, 0, 0).to_identifier();

	// Block containing tx1 is valid.
	let block_valid_9 =
		build_block_from_prev(&header_8, &chain, &keychain, &key_id9, vec![tx1.clone()])?;
	chain.process_block(block_valid_9.clone(), Options::NONE)?;

	// Block at height 10 is valid if we do not include tx2.
	let block_valid_10 =
		build_block_from_prev(&block_valid_9.header, &chain, &keychain, &key_id10, vec![])?;
	chain.process_block(block_valid_10, Options::NONE)?;

	// Process an alternative "fork" block also at height 9.
	// The "other" block at height 9 should not affect this one in terms of NRD kernels
	// as the recent kernel index should be rewound.
	let block_invalid_9b =
		build_block_from_prev(&header_8, &chain, &keychain, &key_id9, vec![tx1.clone()])?;
	assert!(chain
		.process_block(block_invalid_9b, Options::NONE)
		.is_err());

	// Process an alternative block at height 10 on this same fork.
	let block_valid_9b =
		build_block_from_prev(&header_8, &chain, &keychain, &key_id10, vec![tx3.clone()])?;
	chain.process_block(block_valid_9b.clone(), Options::NONE)?;

	// Process an alternative block at height 10 on this same fork.
	let block_valid_10b = build_block_from_prev(
		&block_valid_9b.header,
		&chain,
		&keychain,
		&key_id11,
		vec![tx4.clone()],
	)?;
	chain.process_block(block_valid_10b.clone(), Options::NONE)?;

	// Block at height 11 is valid with tx1 as NRD rule is met (relative_height=2) but fail with replay attack check
	let block_invalid_11b = build_block_from_prev(
		&block_valid_10b.header,
		&chain,
		&keychain,
		&key_id9,
		vec![tx1.clone()],
	)?;
	assert!(chain
		.process_block(block_invalid_11b, Options::NONE)
		.is_err());

	clean_output_dir(chain_dir);
	Ok(())
}

fn getRandomKenel(keychain: &ExtKeychain, fee: u64) -> Result<(TxKernel, BlindingFactor), Error> {
	let mut kernel2 = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
		fee: fee,
		relative_height: NRDRelativeHeight::new(2)?,
	});
	// // Construct the message to be signed.
	let msg2 = kernel2.msg_to_sign().unwrap();

	// // Generate a kernel with public excess and associated signature.
	let excess2 = BlindingFactor::rand();
	let skey2 = excess2.secret_key().unwrap();
	kernel2.excess = keychain.secp().commit(0, skey2).unwrap();
	let pubkey2 = &kernel2.excess.to_pubkey().unwrap();
	kernel2.excess_sig =
		aggsig::sign_with_blinding(&keychain.secp(), &msg2, &excess2, Some(&pubkey2)).unwrap();
	kernel2.verify().unwrap();
	Ok((kernel2, excess2))
}
