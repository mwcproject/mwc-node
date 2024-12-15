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

mod chain_test_helper;

use mwc_chain as chain;
use mwc_core as core;
use mwc_keychain as keychain;
use mwc_util as util;
use std::collections::VecDeque;

use self::chain_test_helper::{clean_output_dir, genesis_block, init_chain};
use crate::chain::{pipe, Chain, Options};
use crate::core::core::{block, pmmr, transaction};
use crate::core::core::{Block, FeeFields, KernelFeatures, Transaction, Weighting};
use crate::core::libtx::{build, reward, ProofBuilder};
use crate::core::{consensus, global, pow};
use crate::keychain::{ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType};
use chrono::Duration;

fn build_block<K>(
	chain: &Chain,
	keychain: &K,
	txs: &[Transaction],
	skip_roots: bool,
) -> Result<Block, chain::Error>
where
	K: Keychain,
{
	let prev = chain.head_header().unwrap();
	let next_height = prev.height + 1;
	let mut cache_values = VecDeque::new();
	let next_header_info =
		consensus::next_difficulty(1, chain.difficulty_iter()?, &mut cache_values);
	let fee = txs.iter().map(|x| x.fee(next_height)).sum();
	let key_id = ExtKeychainPath::new(1, next_height as u32, 0, 0, 0).to_identifier();
	let reward = reward::output(
		keychain,
		&ProofBuilder::new(keychain),
		&key_id,
		fee,
		false,
		next_height,
		chain.secp(),
	)
	.unwrap();

	let mut block = Block::new(
		&prev,
		txs,
		next_header_info.clone().difficulty,
		reward,
		chain.secp(),
	)
	.map_err(|e| chain::Error::Block(e))?;

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	// If we are skipping roots then just set the header prev_root and skip the other MMR roots.
	// This allows us to build a header for an "invalid" block by ignoring outputs and kernels.
	if skip_roots {
		chain.set_prev_root_only(&mut block.header)?;

		// Manually set the mmr sizes for a "valid" block (increment prev output and kernel counts).
		// The 2 lines below were bogus before when using 1-based positions.
		// They worked only for even output_mmr_count()s
		// But it was actually correct for 0-based position!
		block.header.output_mmr_size = pmmr::insertion_to_pmmr_index(prev.output_mmr_count() + 1);
		block.header.kernel_mmr_size = pmmr::insertion_to_pmmr_index(prev.kernel_mmr_count() + 1);
	} else {
		chain.set_txhashset_roots(&mut block)?;
	}

	let edge_bits = global::min_edge_bits();
	block.header.pow.proof.edge_bits = edge_bits;
	pow::pow_size(
		&mut block.header,
		next_header_info.difficulty,
		global::proofsize(),
		edge_bits,
	)
	.unwrap();

	Ok(block)
}

#[test]
fn process_block_cut_through() -> Result<(), chain::Error> {
	let chain_dir = ".mwc.cut_through";
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	util::init_test_logger();
	clean_output_dir(chain_dir);

	let keychain = ExtKeychain::from_random_seed(false)?;
	let pb = ProofBuilder::new(&keychain);
	let genesis = genesis_block(&keychain);
	let chain = init_chain(chain_dir, genesis.clone());

	// Mine a few empty blocks.
	for _ in 1..6 {
		let block = build_block(&chain, &keychain, &[], false)?;
		chain.process_block(block, Options::MINE)?;
	}

	let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
	let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
	let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

	// Build a tx that spends a couple of early coinbase outputs and produces some new outputs.
	// Note: We reuse key_ids resulting in an input and an output sharing the same commitment.
	// The input is coinbase and the output is plain.
	let tx = build::transaction(
		KernelFeatures::Plain {
			fee: FeeFields::zero(),
		},
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id2.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::output(500_000_000, key_id2.clone()),
			build::output(100_000_000, key_id3.clone()),
		],
		&keychain,
		&pb,
	)
	.expect("valid tx");

	// The offending commitment, reused in both an input and an output.
	let commit = keychain.commit(
		consensus::MWC_FIRST_GROUP_REWARD,
		&key_id1,
		SwitchCommitmentType::Regular,
	)?;
	let inputs: Vec<_> = tx.inputs().into();
	assert!(inputs.iter().any(|input| input.commitment() == commit));
	assert!(tx
		.outputs()
		.iter()
		.any(|output| output.commitment() == commit));

	// Transaction is invalid due to cut-through.
	let height = 7;
	assert_eq!(
		tx.validate(Weighting::AsTransaction, height, chain.secp()),
		Err(transaction::Error::CutThrough),
	);

	// Transaction will not validate against the chain (utxo).
	assert_eq!(
		chain.validate_tx(&tx),
		Err(chain::Error::DuplicateCommitment(commit)),
	);

	// Build a block with this single invalid transaction.
	let block = build_block(&chain, &keychain, &[tx.clone()], true)?;

	// The block is invalid due to cut-through.
	let prev = chain.head_header()?;
	assert_eq!(
		block.validate(&prev.total_kernel_offset(), chain.secp()),
		Err(block::Error::Transaction(transaction::Error::CutThrough))
	);

	// The block processing pipeline will refuse to accept the block due to "duplicate commitment".
	// Note: The error is "Other" with a stringified backtrace and is effectively impossible to introspect here...
	assert!(chain.process_block(block.clone(), Options::MINE).is_err());

	// Now exercise the internal call to pipe::process_block() directly so we can introspect the error
	// without it being wrapped as above.
	{
		let store = chain.get_store_for_tests();
		let header_pmmr = chain.get_header_pmmr_for_test();
		let txhashset = chain.get_txhashset_for_test();

		let mut header_pmmr = header_pmmr.write();
		let mut txhashset = txhashset.write();
		let batch = store.batch_write()?;

		let mut ctx = chain.new_ctx(Options::NONE, batch, &mut header_pmmr, &mut txhashset)?;
		let mut cache_values = VecDeque::new();
		let res =
			pipe::process_blocks_series(&vec![block], &mut ctx, &mut cache_values, chain.secp());
		assert_eq!(
			res,
			Err(chain::Error::Block(block::Error::Transaction(
				transaction::Error::CutThrough
			)))
		);
	}

	clean_output_dir(chain_dir);
	Ok(())
}
