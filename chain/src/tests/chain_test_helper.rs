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
use mwc_chain::types::Options;
use mwc_chain::Chain;
use mwc_core::core::hash::Hashed;
use mwc_core::core::pmmr::{ReadablePMMR, VecBackend, PMMR};
use mwc_core::core::Block;
use mwc_core::global::ChainTypes;
use mwc_core::libtx::{self, reward};
use mwc_core::{consensus, global, pow};
use mwc_crates::chrono::Duration;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{ExtKeychainPath, Keychain};
use std::collections::HashSet;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static TEST_DIR_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[allow(dead_code)]
#[cfg(test)]
pub fn clean_output_dir(dir_name: &str) {
	let _ = fs::remove_dir_all(dir_name);
}

#[allow(dead_code)]
#[cfg(test)]
pub fn test_chain_dir(test_name: &str) -> String {
	let counter = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
	let sanitized = test_name
		.chars()
		.map(|c| {
			if c.is_ascii_alphanumeric() || c == '_' {
				c
			} else {
				'_'
			}
		})
		.collect::<String>();

	format!(".mwc_test_{}_{}_{}", sanitized, std::process::id(), counter)
}

pub fn init_chain(secp: &Secp256k1, dir_name: &str, genesis: Block) -> Chain {
	Chain::init(
		&secp,
		0,
		dir_name.to_string(),
		Arc::new(NoopAdapter {}),
		genesis,
		pow::verify_size,
		false,
		HashSet::new(),
		None,
		None,
	)
	.unwrap()
}

/// Build genesis block with reward (non-empty, like we have in mainnet).
pub fn genesis_block<K>(secp: &mut Secp256k1, keychain: &K) -> Block
where
	K: Keychain,
{
	let key_id = mwc_keychain::ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let reward = reward::output(
		0,
		keychain,
		&libtx::ProofBuilder::new(secp, keychain).unwrap(),
		&key_id,
		0,
		false,
		0, // at MWC genesys block has to has height 0, mwc it tolerant to that.
		secp,
	)
	.unwrap();

	let mut genesis = global::get_genesis_block(secp, 0)
		.expect("testing genesis must be available")
		.with_reward(reward.0, reward.1)
		.expect("genesis block body must be empty before reward");
	set_genesis_mmr_roots(&mut genesis);
	let context_id = genesis.header.pow.proof.context_id;
	let difficulty = genesis.header.pow.total_difficulty;
	pow::pow_size(
		context_id,
		&mut genesis.header,
		difficulty,
		global::proofsize(context_id),
		global::min_edge_bits(context_id),
	)
	.expect("testing genesis PoW must be mineable");
	genesis
}

fn set_genesis_mmr_roots(genesis: &mut Block) {
	let context_id = genesis.header.pow.proof.context_id;

	let mut output_backend = VecBackend::new(context_id);
	let mut output_pmmr = PMMR::new(&mut output_backend);
	for output in genesis.outputs() {
		output_pmmr.push(&output.identifier()).unwrap();
	}
	genesis.header.output_mmr_size = output_pmmr.size();
	genesis.header.output_root = output_pmmr.root().unwrap();

	let mut rproof_backend = VecBackend::new(context_id);
	let mut rproof_pmmr = PMMR::new(&mut rproof_backend);
	for output in genesis.outputs() {
		rproof_pmmr.push(&output.proof()).unwrap();
	}
	genesis.header.range_proof_root = rproof_pmmr.root().unwrap();

	let mut kernel_backend = VecBackend::new(context_id);
	let mut kernel_pmmr = PMMR::new(&mut kernel_backend);
	for kernel in genesis.kernels() {
		kernel_pmmr.push(kernel).unwrap();
	}
	genesis.header.kernel_mmr_size = kernel_pmmr.size();
	genesis.header.kernel_root = kernel_pmmr.root().unwrap();
}

/// Mine a chain of specified length to assist with automated tests.
/// Probably a good idea to call clean_output_dir at the beginning and end of each test.
#[allow(dead_code)]
pub fn mine_chain(dir_name: &str, chain_length: u64) -> Chain {
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = mwc_keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let genesis = genesis_block(&mut secp, &keychain);
	let mut chain = init_chain(&secp, dir_name, genesis.clone());
	mine_some_on_top(&mut secp, &mut chain, chain_length, &keychain);
	chain
}

#[allow(dead_code)]
fn mine_some_on_top<K>(secp: &mut Secp256k1, chain: &mut Chain, chain_length: u64, keychain: &K)
where
	K: Keychain,
{
	let mut cache_values = consensus::DifficultyCache::new();
	for n in 1..chain_length {
		let prev = chain.head_header().unwrap();
		let next_header_info = consensus::next_difficulty(
			0,
			prev.height + 1,
			chain.difficulty_iter().unwrap(),
			&mut cache_values,
		)
		.unwrap();
		let pk = ExtKeychainPath::new(1, n as u32, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let reward = libtx::reward::output(
			0,
			keychain,
			&libtx::ProofBuilder::new(secp, keychain).unwrap(),
			&pk,
			0,
			false,
			n,
			secp,
		)
		.unwrap();
		let mut b = Block::new(0, &prev, &[], next_header_info.difficulty, reward, secp).unwrap();
		b.header.timestamp = prev.timestamp + Duration::seconds(60);
		b.header.pow.secondary_scaling = next_header_info.secondary_scaling;

		chain.set_txhashset_roots(secp, &mut b).unwrap();

		let edge_bits = global::min_edge_bits(0);
		b.header.pow.proof.edge_bits = edge_bits;
		pow::pow_size(
			0,
			&mut b.header,
			next_header_info.difficulty,
			global::proofsize(0),
			edge_bits,
		)
		.unwrap();

		let bhash = b.hash(0).unwrap();
		chain
			.process_block(secp, b, Options::MINE, std::collections::HashSet::new())
			.unwrap();

		// checking our new head
		let head = chain.head().unwrap();
		assert_eq!(head.height, n);
		assert_eq!(head.last_block_h, bhash);

		// now check the block_header of the head
		let header = chain.head_header().unwrap();
		assert_eq!(header.height, n);
		assert_eq!(header.hash(0).unwrap(), bhash);

		// now check the block itself
		let block = chain.get_block(&header.hash(0).unwrap()).unwrap();
		assert_eq!(block.header.height, n);
		assert_eq!(block.hash(0).unwrap(), bhash);
		assert_eq!(block.outputs().len(), 1);

		// now check the block height index
		let header_by_height = chain.get_header_by_height(n).unwrap();
		assert_eq!(header_by_height.hash(0).unwrap(), bhash);

		chain.validate(secp, false).unwrap();
	}
}
