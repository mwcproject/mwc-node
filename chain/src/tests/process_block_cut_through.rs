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

use super::chain_test_helper::{clean_output_dir, genesis_block, init_chain};
use mwc_chain::{pipe, store::PendingChainOperation, Chain, Options};
use mwc_core::core::hash::Hash;
use mwc_core::core::{block, pmmr, transaction};
use mwc_core::core::{Block, FeeFields, KernelFeatures, Transaction, Weighting};
use mwc_core::libtx::{build, reward, ProofBuilder};
use mwc_core::{consensus, global, pow};
use mwc_crates::chrono::Duration;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{ExtKeychain, ExtKeychainPath, Keychain, SwitchCommitmentType};

fn build_block<K>(
	secp: &mut Secp256k1,
	chain: &Chain,
	keychain: &K,
	txs: &[Transaction],
	skip_roots: bool,
) -> Result<Block, mwc_chain::Error>
where
	K: Keychain,
{
	let prev = chain.head_header().unwrap();
	let next_height = prev.height + 1;
	let mut cache_values = consensus::DifficultyCache::new();
	let next_header_info =
		consensus::next_difficulty(0, next_height, chain.difficulty_iter()?, &mut cache_values)
			.unwrap();
	let fee = txs.iter().map(|x| x.fee().unwrap()).sum();
	let key_id = ExtKeychainPath::new(1, next_height as u32, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let reward = reward::output(
		0,
		keychain,
		&ProofBuilder::new(secp, keychain).unwrap(),
		&key_id,
		fee,
		false,
		next_height,
		secp,
	)
	.unwrap();

	let mut block = Block::new(
		0,
		&prev,
		txs,
		next_header_info.clone().difficulty,
		reward,
		secp,
	)
	.map_err(|e| mwc_chain::Error::Block(e))?;

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
		block.header.output_mmr_size =
			pmmr::insertion_to_pmmr_index(prev.output_mmr_count().unwrap() + 1).unwrap();
		block.header.kernel_mmr_size =
			pmmr::insertion_to_pmmr_index(prev.kernel_mmr_count().unwrap() + 1).unwrap();
	} else {
		chain.set_txhashset_roots(secp, &mut block)?;
	}

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

	Ok(block)
}

#[test]
fn missing_predecessor_header_returns_orphan() -> Result<(), mwc_chain::Error> {
	let chain_dir = ".mwc.missing_predecessor_header";
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)?;
	let genesis = genesis_block(&mut secp, &keychain);
	let chain = init_chain(&secp, chain_dir, genesis.clone());
	let mut block = build_block(&mut secp, &chain, &keychain, &[], false)?;
	block.header.prev_hash = Hash::from_vec(&[42]);

	{
		let store = chain.get_store_for_tests();
		let header_pmmr = chain.get_header_pmmr_for_test();
		let txhashset = chain.get_txhashset_for_test();

		let mut header_pmmr = header_pmmr.write();
		let mut txhashset = txhashset.write();
		let batch = store.batch_write()?;

		let mut ctx = chain.new_ctx(Options::SKIP_POW, batch, &mut header_pmmr, &mut txhashset)?;
		let mut state_may_have_changed = false;
		let res = pipe::process_blocks_series(
			0,
			&vec![block],
			&mut ctx,
			&mut state_may_have_changed,
			&mut secp,
		);
		assert!(matches!(res, Err(mwc_chain::Error::Orphan(_))));
	}

	clean_output_dir(chain_dir);
	Ok(())
}

#[test]
fn process_block_cut_through() -> Result<(), mwc_chain::Error> {
	let chain_dir = ".mwc.cut_through";
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)?;
	let pb = ProofBuilder::new(&secp, &keychain).unwrap();
	let genesis = genesis_block(&mut secp, &keychain);
	let chain = init_chain(&secp, chain_dir, genesis.clone());

	// Mine a few empty blocks.
	for _ in 1..6 {
		let block = build_block(&mut secp, &chain, &keychain, &[], false)?;
		chain.process_block(
			&mut secp,
			block,
			Options::MINE,
			std::collections::HashSet::new(),
		)?;
	}

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

	// Build a tx that spends a couple of early coinbase outputs and produces some new outputs.
	// Note: We reuse key_ids resulting in an input and an output sharing the same commitment.
	// The input is coinbase and the output is plain.
	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: FeeFields::new(10).unwrap(),
		},
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id2.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::output(500_000_000 - 10, key_id2.clone()),
			build::output(100_000_000, key_id3.clone()),
		],
		&keychain,
		&pb,
	)
	.expect("valid tx");

	// The offending commitment, reused in both an input and an output.
	let commit = keychain.commit(
		&mut secp,
		consensus::MWC_FIRST_GROUP_REWARD,
		&key_id1,
		SwitchCommitmentType::Regular,
	)?;
	let inputs = tx.inputs().into_commit_wrappers(0)?;
	assert!(inputs.iter().any(|input| input.commitment() == commit));
	assert!(tx
		.outputs()
		.iter()
		.any(|output| output.commitment() == commit));

	// Transaction is invalid due to cut-through.
	assert!(matches!(
		tx.validate(0, Weighting::AsTransaction, &mut secp),
		Err(transaction::Error::CutThrough)
	));

	// Transaction will not validate against the chain (utxo).
	assert!(
		matches!(chain.validate_tx(&tx), Err(mwc_chain::Error::DuplicateCommitment(c)) if c==commit)
	);

	// Build a block with this single invalid transaction.
	let block = build_block(&mut secp, &chain, &keychain, &[tx.clone()], true)?;

	// The block is invalid due to cut-through.
	let prev = chain.head_header()?;
	assert!(matches!(
		block.validate(0, &prev.total_kernel_offset(), &mut secp),
		Err(block::Error::Transaction(transaction::Error::CutThrough))
	));

	// The block processing pipeline will refuse to accept the block due to "duplicate commitment".
	// Note: The error is "Other" with a stringified backtrace and is effectively impossible to introspect here...
	assert!(chain
		.process_block(
			&mut secp,
			block.clone(),
			Options::MINE,
			std::collections::HashSet::new()
		)
		.is_err());

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
		let mut state_may_have_changed = false;
		let res = pipe::process_blocks_series(
			0,
			&vec![block],
			&mut ctx,
			&mut state_may_have_changed,
			&mut secp,
		);
		assert!(matches!(
			res,
			Err(mwc_chain::Error::Block(block::Error::Transaction(
				transaction::Error::CutThrough
			)))
		));
	}

	clean_output_dir(chain_dir);
	Ok(())
}

#[test]
fn readonly_pmmr_operation_preserves_existing_pending_marker() -> Result<(), mwc_chain::Error> {
	let chain_dir = ".mwc.readonly_pmmr_existing_marker";
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)?;
	let genesis = genesis_block(&mut secp, &keychain);
	let chain = init_chain(&secp, chain_dir, genesis.clone());
	let marker = PendingChainOperation::ResetToGenesis;

	chain
		.get_store_for_tests()
		.set_pending_chain_operation(&marker)?;
	let _block = build_block(&mut secp, &chain, &keychain, &[], false)?;

	assert_eq!(
		chain.get_store_for_tests().pending_chain_operation()?,
		Some(marker)
	);

	clean_output_dir(chain_dir);
	Ok(())
}
