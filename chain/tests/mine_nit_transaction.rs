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
use crate::chain::{Chain, Options};
use crate::core::address::Address;
use crate::core::core::hash::Hashed;
use crate::core::core::{Block, KernelFeatures, TransactionV4, TxImpl, VersionedTransaction};
use crate::core::libtx::{build_v4, reward, PaymentId, ProofBuilder};
use crate::core::{consensus, global, pow};
use crate::keychain::{ExtKeychain, ExtKeychainPath, Identifier, Keychain};
use chrono::Duration;
use grin_core::core::Commit;
use rand::thread_rng;

fn build_block<K>(
	chain: &Chain,
	keychain: &K,
	key_id: &Identifier,
	txs: Vec<TransactionV4>,
) -> Block
where
	K: Keychain,
{
	let prev = chain.head_header().unwrap();
	let next_header_info = consensus::next_difficulty(1, chain.difficulty_iter().unwrap());
	let fee = txs.iter().map(|x| x.fee()).sum();
	let reward = reward::output(
		keychain,
		&ProofBuilder::new(keychain),
		key_id,
		fee,
		false,
		1,
	)
	.unwrap();

	let txs = txs
		.iter()
		.map(|tx| tx.clone().ver())
		.collect::<Vec<VersionedTransaction>>();
	let mut block = Block::new(&prev, &txs, next_header_info.clone().difficulty, reward).unwrap();

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	chain.set_txhashset_roots(&mut block).unwrap();

	let edge_bits = global::min_edge_bits();
	block.header.pow.proof.edge_bits = edge_bits;
	pow::pow_size(
		&mut block.header,
		next_header_info.difficulty,
		global::proofsize(),
		edge_bits,
	)
	.unwrap();

	block
}

#[test]
fn mine_block_with_nit_tx() {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);

	util::init_test_logger();

	let chain_dir = ".grin.nit_tx";
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let pb = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());

	let height = consensus::TESTING_THIRD_HARD_FORK as u32;
	for n in 1..height {
		let key_id = ExtKeychainPath::new(1, n, 0, 0, 0).to_identifier();
		let block = build_block(&chain, &keychain, &key_id, vec![]);
		chain.process_block(block, Options::MINE).unwrap();
	}

	assert_eq!(chain.head().unwrap().height as u32, height - 1);

	// prepare a non-interactive transaction output in block #9
	let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr = Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
	let payment_id = PaymentId::new();
	let (pri_nonce, _pub_nonce) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

	let value = consensus::MWC_FIRST_GROUP_REWARD;
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
	let tx = build_v4::transaction(
		KernelFeatures::Plain { fee: 20000 },
		&[
			build_v4::coinbase_input(value, key_id2.clone()),
			build_v4::output_wrnp(
				value - 20000,
				pri_nonce,
				recipient_addr.clone(),
				payment_id,
				1,
			),
		],
		&keychain,
		&pb,
	)
	.unwrap();

	let key_id9 = ExtKeychainPath::new(1, 9, 0, 0, 0).to_identifier();
	let block = build_block(&chain, &keychain, &key_id9, vec![tx.clone()]);
	chain.process_block(block, Options::MINE).unwrap();
	chain.validate(false).unwrap();

	// use it as the input in a new transaction in block #10
	let spending_output = tx.outputs_with_rnp().first().unwrap();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();

	let (_pri_view2, pub_view2) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr2 =
		Address::from_one_pubkey(&pub_view2, global::ChainTypes::AutomatedTesting);
	let payment_id2 = PaymentId::new();
	let (pri_nonce2, _pub_nonce2) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let simulated_index: u64 = chain
		.get_output_pos(&spending_output.commitment())
		.unwrap()
		.1;
	let simulated_rp_hash = (simulated_index - 1, spending_output.proof).hash();
	println!(
		"simulated_index: {}, simulated_rp_hash: {:?}",
		simulated_index, simulated_rp_hash
	);

	let tx = build_v4::transaction(
		KernelFeatures::Plain { fee: 20000 },
		&[
			build_v4::input_with_sig(
				value - 20000,
				pri_view.clone(),
				pri_view,
				spending_output.identifier_with_rnp(),
				recipient_addr.clone(),
				simulated_rp_hash,
			),
			build_v4::output(value - 80000, key_id2),
			build_v4::output_wrnp(40000, pri_nonce2, recipient_addr2, payment_id2, 10),
		],
		&keychain,
		&pb,
	)
	.unwrap();

	let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();
	let block = build_block(&chain, &keychain, &key_id3, vec![tx]);
	chain.process_block(block, Options::MINE).unwrap();
	chain.validate(false).unwrap();

	clean_output_dir(chain_dir);
}
