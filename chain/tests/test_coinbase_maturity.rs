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

use mwc_chain::types::NoopAdapter;
use mwc_chain::Error;
use mwc_core::core::KernelFeatures;
use mwc_core::global::{self, ChainTypes};
use mwc_core::libtx::{self, ProofBuilder};
use mwc_core::{consensus, pow};
use mwc_crates::chrono::Duration;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{ExtKeychain, ExtKeychainPath, Keychain};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs;
use std::sync::Arc;

#[path = "../src/tests/chain_test_helper.rs"]
mod chain_test_helper;
use self::chain_test_helper::build;

fn clean_output_dir(dir_name: &str) {
	let _ = fs::remove_dir_all(dir_name);
}

#[test]
fn test_coinbase_maturity() {
	mwc_util::init_test_logger().unwrap();
	let chain_dir = ".mwc_coinbase";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let genesis_block = global::get_genesis_block(&secp, 0).unwrap();

	{
		let chain = mwc_chain::Chain::init(
			&secp,
			0,
			chain_dir.to_string(),
			Arc::new(NoopAdapter {}),
			genesis_block,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			true,
		)
		.unwrap();

		let prev = chain.head_header().unwrap();

		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
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
		let key_id4 = ExtKeychainPath::new(1, 4, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();

		let mut cache_values = consensus::DifficultyCache::new();

		let next_header_info = consensus::next_difficulty(
			0,
			prev.height + 1,
			chain.difficulty_iter().unwrap(),
			&mut cache_values,
		)
		.unwrap();
		let reward =
			libtx::reward::output(0, &keychain, &builder, &key_id1, 0, false, 1, &mut secp)
				.unwrap();
		let mut block = mwc_core::core::Block::new(
			0,
			&prev,
			&[],
			next_header_info.difficulty,
			reward,
			&mut secp,
		)
		.unwrap();
		block.header.timestamp = prev.timestamp + Duration::seconds(60);
		block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

		chain.set_txhashset_roots(&secp, &mut block).unwrap();

		pow::pow_size(
			0,
			&mut block.header,
			next_header_info.difficulty,
			global::proofsize(0),
			global::min_edge_bits(0),
		)
		.unwrap();

		assert_eq!(block.outputs().len(), 1);
		let coinbase_output = block.outputs()[0];
		assert!(coinbase_output.is_coinbase());

		chain
			.process_block(
				&mut secp,
				block.clone(),
				mwc_chain::Options::MINE,
				std::collections::HashSet::new(),
			)
			.unwrap();

		let prev = chain.head_header().unwrap();

		let amount = consensus::MWC_FIRST_GROUP_REWARD;

		let lock_height = 1 + global::coinbase_maturity(0);
		assert_eq!(lock_height, 4);

		// here we build a tx that attempts to spend the earlier coinbase output
		// this is not a valid tx as the coinbase output cannot be spent yet
		let coinbase_txn = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 2u32.try_into().unwrap(),
			},
			&[
				build::coinbase_input(amount, key_id1.clone()),
				build::output(amount - 2, key_id2.clone()),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		let txs = &[coinbase_txn.clone()];
		let fees = txs.iter().map(|tx| tx.fee().unwrap()).sum();
		let reward = libtx::reward::output(
			0,
			&keychain,
			&builder,
			&key_id3,
			fees,
			false,
			prev.height + 1,
			&mut secp,
		)
		.unwrap();
		let next_header_info = consensus::next_difficulty(
			0,
			prev.height + 1,
			chain.difficulty_iter().unwrap(),
			&mut cache_values,
		)
		.unwrap();
		let mut block = mwc_core::core::Block::new(
			0,
			&prev,
			txs,
			next_header_info.difficulty,
			reward,
			&mut secp,
		)
		.unwrap();
		block.header.timestamp = prev.timestamp + Duration::seconds(60);
		block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

		chain.set_txhashset_roots(&secp, &mut block).unwrap();

		// Confirm the tx attempting to spend the coinbase output
		// is not valid at the current block height given the current chain state.
		match chain.verify_coinbase_maturity(&coinbase_txn.inputs()) {
			Ok(_) => {}
			Err(e) => match e {
				Error::ImmatureCoinbase => {}
				_ => panic!("Expected transaction error with immature coinbase."),
			},
		}

		pow::pow_size(
			0,
			&mut block.header,
			next_header_info.difficulty,
			global::proofsize(0),
			global::min_edge_bits(0),
		)
		.unwrap();

		// mine enough blocks to increase the height sufficiently for
		// coinbase to reach maturity and be spendable in the next block
		for _ in 0..3 {
			let prev = chain.head_header().unwrap();

			let keychain = ExtKeychain::from_seed(
				&secp,
				&SecretKey::new(&secp, &mut SysRng).unwrap().0,
				false,
			)
			.unwrap();
			let builder = ProofBuilder::new(&secp, &keychain).unwrap();
			let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0)
				.unwrap()
				.to_identifier()
				.unwrap();

			let next_header_info = consensus::next_difficulty(
				0,
				prev.height + 1,
				chain.difficulty_iter().unwrap(),
				&mut cache_values,
			)
			.unwrap();
			let reward = libtx::reward::output(
				0,
				&keychain,
				&builder,
				&key_id1,
				0,
				false,
				prev.height + 1,
				&mut secp,
			)
			.unwrap();
			let mut block = mwc_core::core::Block::new(
				0,
				&prev,
				&[],
				next_header_info.difficulty,
				reward,
				&mut secp,
			)
			.unwrap();

			block.header.timestamp = prev.timestamp + Duration::seconds(60);
			block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

			chain.set_txhashset_roots(&secp, &mut block).unwrap();

			pow::pow_size(
				0,
				&mut block.header,
				next_header_info.difficulty,
				global::proofsize(0),
				global::min_edge_bits(0),
			)
			.unwrap();

			assert_eq!(block.outputs().len(), 1);
			let coinbase_output = block.outputs()[0];
			assert!(coinbase_output.is_coinbase());

			chain
				.process_block(
					&mut secp,
					block.clone(),
					mwc_chain::Options::MINE,
					std::collections::HashSet::new(),
				)
				.unwrap();

			let prev = chain.head_header().unwrap();

			let amount = consensus::MWC_FIRST_GROUP_REWARD;

			let lock_height = 1 + global::coinbase_maturity(0);
			assert_eq!(lock_height, 4);

			// here we build a tx that attempts to spend the earlier coinbase output
			// this is not a valid tx as the coinbase output cannot be spent yet
			let coinbase_txn = build::transaction(
				0,
				&mut secp,
				KernelFeatures::Plain {
					fee: 2u32.try_into().unwrap(),
				},
				&[
					build::coinbase_input(amount, key_id1.clone()),
					build::output(amount - 2, key_id2.clone()),
				],
				&keychain,
				&builder,
			)
			.unwrap();

			let txs = &[coinbase_txn.clone()];
			let fees = txs.iter().map(|tx| tx.fee().unwrap()).sum();
			let reward = libtx::reward::output(
				0,
				&keychain,
				&builder,
				&key_id3,
				fees,
				false,
				prev.height + 1,
				&mut secp,
			)
			.unwrap();
			let next_header_info = consensus::next_difficulty(
				0,
				prev.height + 1,
				chain.difficulty_iter().unwrap(),
				&mut cache_values,
			)
			.unwrap();
			let mut block = mwc_core::core::Block::new(
				0,
				&prev,
				txs,
				next_header_info.difficulty,
				reward,
				&mut secp,
			)
			.unwrap();
			block.header.timestamp = prev.timestamp + Duration::seconds(60);
			block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

			chain.set_txhashset_roots(&secp, &mut block).unwrap();

			// Confirm the tx attempting to spend the coinbase output
			// is not valid at the current block height given the current chain state.
			match chain.verify_coinbase_maturity(&coinbase_txn.inputs()) {
				Ok(_) => {}
				Err(e) => match e {
					Error::ImmatureCoinbase => {}
					_ => panic!("Expected transaction error with immature coinbase."),
				},
			}

			pow::pow_size(
				0,
				&mut block.header,
				next_header_info.difficulty,
				global::proofsize(0),
				global::min_edge_bits(0),
			)
			.unwrap();

			// mine enough blocks to increase the height sufficiently for
			// coinbase to reach maturity and be spendable in the next block
			for _ in 0..3 {
				let prev = chain.head_header().unwrap();

				let keychain = ExtKeychain::from_seed(
					&secp,
					&SecretKey::new(&secp, &mut SysRng).unwrap().0,
					false,
				)
				.unwrap();
				let builder = ProofBuilder::new(&secp, &keychain).unwrap();
				let pk = ExtKeychainPath::new(1, 1, 0, 0, 0)
					.unwrap()
					.to_identifier()
					.unwrap();

				let reward = libtx::reward::output(
					0,
					&keychain,
					&builder,
					&pk,
					0,
					false,
					prev.height + 1,
					&mut secp,
				)
				.unwrap();
				let next_header_info = consensus::next_difficulty(
					0,
					prev.height + 1,
					chain.difficulty_iter().unwrap(),
					&mut cache_values,
				)
				.unwrap();
				let mut block = mwc_core::core::Block::new(
					0,
					&prev,
					&[],
					next_header_info.difficulty,
					reward,
					&mut secp,
				)
				.unwrap();
				block.header.timestamp = prev.timestamp + Duration::seconds(60);
				block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

				chain.set_txhashset_roots(&secp, &mut block).unwrap();

				pow::pow_size(
					0,
					&mut block.header,
					next_header_info.difficulty,
					global::proofsize(0),
					global::min_edge_bits(0),
				)
				.unwrap();

				chain
					.process_block(
						&mut secp,
						block,
						mwc_chain::Options::MINE,
						std::collections::HashSet::new(),
					)
					.unwrap();
			}

			let prev = chain.head_header().unwrap();

			// Confirm the tx spending the coinbase output is now valid.
			// The coinbase output has matured sufficiently based on current chain state.
			chain
				.verify_coinbase_maturity(&coinbase_txn.inputs())
				.unwrap();

			let txs = &[coinbase_txn];
			let fees = txs.iter().map(|tx| tx.fee().unwrap()).sum();
			let next_header_info = consensus::next_difficulty(
				0,
				prev.height + 1,
				chain.difficulty_iter().unwrap(),
				&mut cache_values,
			)
			.unwrap();
			let reward = libtx::reward::output(
				0,
				&keychain,
				&builder,
				&key_id4,
				fees,
				false,
				prev.height + 1,
				&mut secp,
			)
			.unwrap();
			let mut block = mwc_core::core::Block::new(
				0,
				&prev,
				txs,
				next_header_info.difficulty,
				reward,
				&mut secp,
			)
			.unwrap();

			block.header.timestamp = prev.timestamp + Duration::seconds(60);
			block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

			chain.set_txhashset_roots(&secp, &mut block).unwrap();

			pow::pow_size(
				0,
				&mut block.header,
				next_header_info.difficulty,
				global::proofsize(0),
				global::min_edge_bits(0),
			)
			.unwrap();

			let result = chain.process_block(
				&mut secp,
				block,
				mwc_chain::Options::MINE,
				std::collections::HashSet::new(),
			);
			match result {
				Ok(_) => (),
				Err(_) => panic!("we did not expect an error here"),
			};
		}
	}
	// Cleanup chain directory
	clean_output_dir(chain_dir);
}
