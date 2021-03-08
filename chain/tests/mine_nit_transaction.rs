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
use crate::core::core::transaction::Weighting;
use crate::core::core::verifier_cache::LruVerifierCache;
use crate::core::core::{
	Block, CommitWithSig, Inputs, KernelFeatures, TransactionV4, TxImpl, VersionedTransaction,
};
use crate::core::libtx::{build_v4, reward, PaymentId, ProofBuilder};
use crate::core::{consensus, global, pow};
use crate::keychain::{ExtKeychain, ExtKeychainPath, Identifier, Keychain};
use chrono::Duration;
use grin_core::core::Commit;
use rand::thread_rng;
use std::sync::Arc;
use util::RwLock;

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

	let vc = Arc::new(RwLock::new(LruVerifierCache::new()));

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
	tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();

	let key_id9 = ExtKeychainPath::new(1, 9, 0, 0, 0).to_identifier();
	let block = build_block(&chain, &keychain, &key_id9, vec![tx.clone()]);
	chain.process_block(block, Options::MINE).unwrap();
	chain.validate(false).unwrap();

	// a new transaction (1ni-1o1no) in block #10

	let spending_output = tx.outputs_with_rnp().first().unwrap();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();

	let (pri_view2, pub_view2) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr2 =
		Address::from_one_pubkey(&pub_view2, global::ChainTypes::AutomatedTesting);
	let payment_id2 = PaymentId::new();
	let (pri_nonce2, _pub_nonce2) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let simulated_index: u64 = chain
		.get_output_pos(&spending_output.commitment())
		.unwrap()
		.1;
	let simulated_rp_hash = (simulated_index - 1, spending_output.proof).hash();

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
			build_v4::output(value - 80000, key_id2.clone()),
			build_v4::output_wrnp(40000, pri_nonce2, recipient_addr2.clone(), payment_id2, 10),
		],
		&keychain,
		&pb,
	)
	.unwrap();
	tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();

	let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();
	let block = build_block(&chain, &keychain, &key_id3, vec![tx.clone()]);
	chain.process_block(block, Options::MINE).unwrap();
	chain.validate(false).unwrap();
	//println!("transaction 1ni1o1no: {}", serde_json::to_string_pretty(&tx).unwrap());

	// a new transaction (1i1ni-2no) in block #11

	let spending_output1 = tx.outputs_with_rnp().first().unwrap();

	let (pri_view3, pub_view3) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr3 =
		Address::from_one_pubkey(&pub_view3, global::ChainTypes::AutomatedTesting);
	let payment_id3 = PaymentId::new();
	let (pri_nonce3, pub_nonce3) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

	let (pri_view4, pub_view4) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr4 =
		Address::from_one_pubkey(&pub_view4, global::ChainTypes::AutomatedTesting);
	let payment_id4 = PaymentId::new();
	let (pri_nonce4, _pub_nonce4) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

	let simulated_index: u64 = chain
		.get_output_pos(&spending_output1.commitment())
		.unwrap()
		.1;
	let simulated_rp_hash = (simulated_index - 1, spending_output1.proof).hash();

	let tx = build_v4::transaction(
		KernelFeatures::Plain { fee: 30000 },
		&[
			build_v4::input(value - 80000, key_id2.clone()),
			build_v4::input_with_sig(
				40000,
				pri_view2.clone(),
				pri_view2,
				spending_output1.identifier_with_rnp(),
				recipient_addr2.clone(),
				simulated_rp_hash,
			),
			build_v4::output_wrnp(90000, pri_nonce3, recipient_addr3.clone(), payment_id3, 11),
			build_v4::output_wrnp(
				value - 160000,
				pri_nonce4,
				recipient_addr4.clone(),
				payment_id4,
				11,
			),
		],
		&keychain,
		&pb,
	)
	.unwrap();
	tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();

	let key_id4 = ExtKeychainPath::new(1, 4, 0, 0, 0).to_identifier();
	let block = build_block(&chain, &keychain, &key_id4, vec![tx.clone()]);
	chain.process_block(block, Options::MINE).unwrap();
	chain.validate(false).unwrap();
	println!(
		"transaction 1i1ni2no: {}",
		serde_json::to_string_pretty(&tx).unwrap()
	);

	// a new transaction (2ni-1no) in block #12

	let o1 = tx.outputs_with_rnp().first().unwrap();
	let o2 = tx.outputs_with_rnp().last().unwrap();
	let (spending_output2, spending_output3) = if o1.identifier_with_rnp().nonce == pub_nonce3 {
		(o1, o2)
	} else {
		(o2, o1)
	};

	let (pri_view5, pub_view5) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let recipient_addr5 =
		Address::from_one_pubkey(&pub_view5, global::ChainTypes::AutomatedTesting);
	let payment_id5 = PaymentId::new();
	let (pri_nonce5, _pub_nonce5) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

	let simulated_index2: u64 = chain
		.get_output_pos(&spending_output2.commitment())
		.unwrap()
		.1;
	let simulated_rp_hash2 = (simulated_index2 - 1, spending_output2.proof).hash();
	let simulated_index3: u64 = chain
		.get_output_pos(&spending_output3.commitment())
		.unwrap()
		.1;
	let simulated_rp_hash3 = (simulated_index3 - 1, spending_output3.proof).hash();

	let tx = build_v4::transaction(
		KernelFeatures::Plain { fee: 40000 },
		&[
			build_v4::input_with_sig(
				90000,
				pri_view3.clone(),
				pri_view3,
				spending_output2.identifier_with_rnp(),
				recipient_addr3.clone(),
				simulated_rp_hash2,
			),
			build_v4::input_with_sig(
				value - 160000,
				pri_view4.clone(),
				pri_view4,
				spending_output3.identifier_with_rnp(),
				recipient_addr4.clone(),
				simulated_rp_hash3,
			),
			build_v4::output_wrnp(
				value - 110000,
				pri_nonce5,
				recipient_addr5.clone(),
				payment_id5,
				12,
			),
		],
		&keychain,
		&pb,
	)
	.unwrap();
	tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();
	let sig_saved = tx
		.inputs_with_sig()
		.inputs_with_sig()
		.first()
		.unwrap()
		.sig
		.clone();

	let key_id5 = ExtKeychainPath::new(1, 5, 0, 0, 0).to_identifier();
	let block = build_block(&chain, &keychain, &key_id5, vec![tx.clone()]);
	chain.process_block(block, Options::MINE).unwrap();
	chain.validate(false).unwrap();
	println!(
		"transaction 2ni1no: {}",
		serde_json::to_string_pretty(&tx).unwrap()
	);

	// a transaction with wrong input signature (1ni-2o) in block #13

	let spending_output = tx.outputs_with_rnp().first().unwrap();
	let key_id6 = ExtKeychainPath::new(1, 6, 0, 0, 0).to_identifier();
	let key_id7 = ExtKeychainPath::new(1, 7, 0, 0, 0).to_identifier();

	let simulated_index: u64 = chain
		.get_output_pos(&spending_output.commitment())
		.unwrap()
		.1;
	let simulated_rp_hash = (simulated_index - 1, spending_output.proof).hash();

	let tx = build_v4::transaction(
		KernelFeatures::Plain { fee: 20000 },
		&[
			build_v4::input_with_sig(
				value - 110000,
				pri_view5.clone(),
				pri_view5,
				spending_output.identifier_with_rnp(),
				recipient_addr5.clone(),
				simulated_rp_hash,
			),
			build_v4::output(value - 110000 - 20000 - 80000, key_id6.clone()),
			build_v4::output(80000, key_id7.clone()),
		],
		&keychain,
		&pb,
	)
	.unwrap();
	tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();

	let mut wrong_tx = tx.clone();
	let inputs = Inputs::CommitsWithSig(vec![CommitWithSig {
		commit: wrong_tx
			.body
			.inputs_with_sig
			.commits()
			.first()
			.unwrap()
			.clone(),
		sig: sig_saved,
	}]);
	wrong_tx.body = wrong_tx.body.replace_inputs_wsig(inputs);

	// manually build this block
	let key_id8 = ExtKeychainPath::new(1, 8, 0, 0, 0).to_identifier();
	let prev = chain.head_header().unwrap();
	let next_header_info = consensus::next_difficulty(1, chain.difficulty_iter().unwrap());
	let fee = wrong_tx.fee();
	let reward = reward::output(
		&keychain,
		&ProofBuilder::new(&keychain),
		&key_id8,
		fee,
		false,
		13,
	)
	.unwrap();

	let txs = vec![wrong_tx.ver()];
	let mut block = Block::new(&prev, &txs, next_header_info.clone().difficulty, reward).unwrap();

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	//todo: assert IncorrectSignature
	assert!(chain.set_txhashset_roots(&mut block).is_err());

	clean_output_dir(chain_dir);
}
