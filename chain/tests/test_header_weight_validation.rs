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

use self::chain_test_helper::{clean_output_dir, mine_chain};
use mwc_chain::{Chain, Error, Options};
use mwc_core::{
	consensus,
	core::{block, Block},
	global,
	libtx::{reward, ProofBuilder},
	pow,
};
use mwc_crates::chrono::Duration;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{ExtKeychain, ExtKeychainPath, Keychain};

fn build_block(secp: &mut Secp256k1, chain: &Chain) -> Block {
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let pk = ExtKeychainPath::new(1, 1, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();

	let mut cache_values = consensus::DifficultyCache::new();
	let prev = chain.head_header().unwrap();
	let next_header_info = consensus::next_difficulty(
		0,
		prev.height + 1,
		chain.difficulty_iter().unwrap(),
		&mut cache_values,
	)
	.unwrap();
	let reward = reward::output(
		0,
		&keychain,
		&ProofBuilder::new(secp, &keychain).unwrap(),
		&pk,
		0,
		false,
		prev.height + 1,
		secp,
	)
	.unwrap();
	let mut block = Block::new(
		0,
		&prev,
		&[],
		next_header_info.clone().difficulty,
		reward,
		secp,
	)
	.unwrap();

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	chain.set_txhashset_roots(secp, &mut block).unwrap();

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
fn test_header_weight_validation() {
	let chain_dir = ".mwc.header_weight";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 5);
	assert_eq!(chain.head().unwrap().height, 4);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let block = build_block(&mut secp, &chain);
	let mut header = block.header;

	// Artificially set the output_mmr_size to a complete PMMR boundary that is
	// too large for a valid block.
	// Note: We will validate this even if just processing the header.
	header.output_mmr_size = 63;

	let res = chain.process_block_header(&header, Options::NONE);

	// Weight validation is done via transaction body and results in a slightly counter-intuitive tx error.
	assert!(matches!(res, Err(Error::Block(block::Error::TooHeavy))));

	clean_output_dir(chain_dir);
}
