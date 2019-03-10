// Copyright 2018 The Grin Developers
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

use self::core::genesis;
use grin_core as core;
use grin_util as util;

mod chain_test_helper;

use self::chain_test_helper::{clean_output_dir, init_chain, mine_chain};

#[test]
fn data_files() {
// disable for merge
/*
	util::init_test_logger();
	let chain_dir = ".grin_df";
	//new block so chain references should be freed
	{
		let chain = setup(chain_dir);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();

		for n in 1..4 {
			let prev = chain.head_header().unwrap();
			let next_header_info = consensus::next_difficulty(1, chain.difficulty_iter().unwrap());
			let pk = ExtKeychainPath::new(1, n as u32, 0, 0, 0).to_identifier();
			let reward = libtx::reward::output(&keychain, &pk, 0, false, prev.height + 1).unwrap();
			let mut b =
				core::core::Block::new(&prev, vec![], next_header_info.clone().difficulty, reward)
					.unwrap();
			b.header.timestamp = prev.timestamp + Duration::seconds(60);
			b.header.pow.secondary_scaling = next_header_info.secondary_scaling;

			chain.set_txhashset_roots(&mut b).unwrap();

	let chain_dir = ".grin_df";
	clean_output_dir(chain_dir);

	// Mine a few blocks on a new chain.
	{
		let chain = mine_chain(chain_dir, 4);
		chain.validate(false).unwrap();
		assert_eq!(chain.head().unwrap().height, 3);
	};

	// Now reload the chain from existing data files and check it is valid.
	{
		let chain = init_chain(chain_dir, genesis::genesis_dev());
		chain.validate(false).unwrap();
		assert_eq!(chain.head().unwrap().height, 3);
	}

	// Cleanup chain directory
	clean_output_dir(chain_dir);
*/
}

fn _prepare_block(kc: &ExtKeychain, prev: &BlockHeader, chain: &Chain, diff: u64) -> Block {
	let mut b = _prepare_block_nosum(kc, prev, diff, vec![]);
	chain.set_txhashset_roots(&mut b).unwrap();
	b
}

fn _prepare_block_tx(
	kc: &ExtKeychain,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
	txs: Vec<&Transaction>,
) -> Block {
	let mut b = _prepare_block_nosum(kc, prev, diff, txs);
	chain.set_txhashset_roots(&mut b).unwrap();
	b
}

fn _prepare_fork_block(kc: &ExtKeychain, prev: &BlockHeader, chain: &Chain, diff: u64) -> Block {
	let mut b = _prepare_block_nosum(kc, prev, diff, vec![]);
	chain.set_txhashset_roots_forked(&mut b, prev).unwrap();
	b
}

fn _prepare_fork_block_tx(
	kc: &ExtKeychain,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
	txs: Vec<&Transaction>,
) -> Block {
	let mut b = _prepare_block_nosum(kc, prev, diff, txs);
	chain.set_txhashset_roots_forked(&mut b, prev).unwrap();
	b
}

fn _prepare_block_nosum(
	kc: &ExtKeychain,
	prev: &BlockHeader,
	diff: u64,
	txs: Vec<&Transaction>,
) -> Block {
	let key_id = ExtKeychainPath::new(1, diff as u32, 0, 0, 0).to_identifier();

	let fees = txs.iter().map(|tx| tx.fee()).sum();
	let reward = libtx::reward::output(kc, &key_id, fees, false, prev.height + 1).unwrap();
	let mut b = match core::core::Block::new(
		prev,
		txs.into_iter().cloned().collect(),
		Difficulty::from_num(diff),
		reward,
	) {
		Err(e) => panic!("{:?}", e),
		Ok(b) => b,
	};
	b.header.timestamp = prev.timestamp + Duration::seconds(60);
	b.header.pow.total_difficulty = Difficulty::from_num(diff);
	b
}
>>>>>>> MWC changes
