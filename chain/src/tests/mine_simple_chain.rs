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

use mwc_chain::types::{CommitPos, KernelPos, NoopAdapter, Tip};
use mwc_chain::Chain;
use mwc_chain::{BlockStatus, ChainAdapter, Options};
use mwc_core::core::hash::Hashed;
use mwc_core::core::{
	block, pmmr, transaction, Block, BlockHeader, KernelFeatures, Output, OutputFeatures,
	Transaction,
};
use mwc_core::global::ChainTypes;
use mwc_core::libtx::build::{self, Append};
use mwc_core::libtx::proof::{self, ProofBuild};
use mwc_core::libtx::{self, Error, ProofBuilder};
use mwc_core::pow::Difficulty;
use mwc_core::{consensus, genesis, global, pow};
use mwc_crates::chrono::Duration;
use mwc_crates::parking_lot::RwLock;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{
	BlindSum, ExtKeychain, ExtKeychainPath, Identifier, Keychain, SwitchCommitmentType,
};
use mwc_util::StopState;
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Arc;

use super::chain_test_helper::{
	clean_output_dir, genesis_block, init_chain, mine_chain, test_chain_dir,
};

/// Adapter to retrieve last status
pub struct StatusAdapter {
	pub last_status: RwLock<Option<BlockStatus>>,
}

impl StatusAdapter {
	pub fn new(last_status: RwLock<Option<BlockStatus>>) -> Self {
		StatusAdapter { last_status }
	}
}

impl ChainAdapter for StatusAdapter {
	fn block_accepted(
		&self,
		_secp: &mut Secp256k1,
		_b: &Block,
		status: BlockStatus,
		_opts: Options,
	) {
		*self.last_status.write() = Some(status);
	}
}

/// Creates a `Chain` instance with `StatusAdapter` attached to it.
fn setup_with_status_adapter(
	secp: &Secp256k1,
	dir_name: &str,
	genesis: Block,
	adapter: Arc<StatusAdapter>,
) -> Chain {
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(dir_name);
	let chain = Chain::init(
		secp,
		0,
		dir_name.to_string(),
		adapter,
		genesis,
		pow::verify_size,
		false,
		HashSet::new(),
		None,
		None,
	)
	.unwrap();

	chain
}

#[test]
fn mine_empty_chain() {
	let chain_dir = ".mwc.empty";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 1);
	assert_eq!(chain.head().unwrap().height, 0);
	clean_output_dir(chain_dir);
}

#[test]
fn mine_short_chain() {
	let chain_dir = ".mwc.short";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 4);
	assert_eq!(chain.head().unwrap().height, 3);
	clean_output_dir(chain_dir);
}

#[test]
fn block_height_range_to_pmmr_indices_rejects_reversed_range() {
	let chain_dir = ".mwc.pmmr_height_range";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 4);

	let res = chain.block_height_range_to_pmmr_indices(3, Some(1));
	assert!(matches!(
		res,
		Err(mwc_chain::Error::Other(msg))
			if msg.contains("start_block_height=3") && msg.contains("end_block_height=1")
	));

	clean_output_dir(chain_dir);
}

#[test]
fn unspent_outputs_by_pmmr_index_clamps_reported_highest_index() {
	let chain_dir = test_chain_dir("unspent_outputs_by_pmmr_index_clamps_reported_highest_index");
	clean_output_dir(&chain_dir);
	let chain = mine_chain(&chain_dir, 4);
	let output_mmr_size = chain.head_header().unwrap().output_mmr_size;

	let capped = chain
		.unspent_outputs_by_pmmr_index(1, 10_000, Some(output_mmr_size + 100))
		.unwrap();
	let unbounded = chain
		.unspent_outputs_by_pmmr_index(1, 10_000, None)
		.unwrap();

	assert_eq!(capped.0, unbounded.0);
	assert_eq!(capped.1, output_mmr_size);
	assert_eq!(capped.2.len(), unbounded.2.len());

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(&chain_dir);
}

#[test]
fn locate_headers_returns_header_pmmr_lookup_error() {
	let chain_dir = ".mwc.locate_headers_pmmr_lookup_error";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 4);
	let genesis_hash = chain.genesis().hash(0).unwrap();

	{
		let header_pmmr = chain.get_header_pmmr_for_test();
		header_pmmr.write().size = 1;
	}

	let res = chain.locate_headers(&[genesis_hash], 32);

	assert!(matches!(res, Err(mwc_chain::Error::InvalidHeaderHeight(1))));

	clean_output_dir(chain_dir);
}

#[test]
fn locator_hashes_rejects_height_above_sync_head() {
	let chain_dir = test_chain_dir("locator_hashes_rejects_height_above_sync_head");
	clean_output_dir(&chain_dir);
	let chain = mine_chain(&chain_dir, 4);
	let sync_head = chain.head().unwrap();
	let invalid_height = sync_head.height + 1;

	let res = chain.get_locator_hashes(sync_head, &[invalid_height]);

	assert!(matches!(
		res,
		Err(mwc_chain::Error::InvalidHeaderHeight(height)) if height == invalid_height
	));

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(&chain_dir);
}

#[test]
fn locator_hashes_errors_if_rewound_extension_missing_requested_height() {
	let chain_dir =
		test_chain_dir("locator_hashes_errors_if_rewound_extension_missing_requested_height");
	clean_output_dir(&chain_dir);
	let chain = mine_chain(&chain_dir, 4);
	let head = chain.head().unwrap();
	let genesis = chain.genesis();
	let genesis_hash = genesis.hash(chain.get_context_id()).unwrap();
	let inconsistent_sync_head = Tip {
		height: head.height,
		last_block_h: genesis_hash,
		prev_block_h: genesis.prev_hash,
		total_difficulty: head.total_difficulty,
	};

	let res = chain.get_locator_hashes(inconsistent_sync_head, &[head.height]);

	assert!(matches!(
		res,
		Err(mwc_chain::Error::Other(msg))
			if msg.contains("missing header PMMR entry for locator height")
	));

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(&chain_dir);
}

#[test]
fn block_height_range_to_pmmr_indices_caps_header_only_end_height() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.pmmr_height_range_header_only";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);
	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	process_header(&chain, &block_b.header);

	let body_head_header = chain.head_header().unwrap();
	assert_eq!(body_head_header.height, block_a.header.height);
	assert_eq!(chain.header_head().unwrap().height, block_b.header.height);
	assert_ne!(
		body_head_header.output_mmr_size,
		block_b.header.output_mmr_size
	);

	let capped = chain
		.block_height_range_to_pmmr_indices(0, Some(block_b.header.height))
		.unwrap();
	let unbounded = chain.block_height_range_to_pmmr_indices(0, None).unwrap();

	assert_eq!(capped, unbounded);
	assert_eq!(capped.1, body_head_header.output_mmr_size);

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(chain_dir);
}

#[test]
fn block_height_range_to_pmmr_indices_uses_body_chain_on_header_fork() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.pmmr_height_range_header_fork";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let body_block = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	process_block(&mut secp, &chain, &body_block);

	let mut header_fork = prepare_block(&mut secp, &kc, &block_a.header, &chain, 3).header;
	header_fork.output_mmr_size =
		pmmr::insertion_to_pmmr_index(block_a.header.output_mmr_count().unwrap() + 2).unwrap();
	process_header(&chain, &header_fork);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&body_block.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&header_fork).unwrap()
	);
	assert_ne!(
		body_block.header.output_mmr_size,
		header_fork.output_mmr_size
	);

	let indices = chain
		.block_height_range_to_pmmr_indices(0, Some(body_block.header.height))
		.unwrap();

	assert_eq!(indices.1, body_block.header.output_mmr_size);

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(chain_dir);
}

#[test]
fn block_height_range_to_pmmr_indices_rejects_body_chain_predecessor_skip() {
	let chain_dir = ".mwc.pmmr_height_range_body_prev_skip";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 5);
	let context_id = chain.get_context_id();
	let store = chain.get_store_for_tests();
	let skipped_to_header = chain.get_header_by_height(1).unwrap();
	let mut corrupt_head = chain.head_header().unwrap();
	corrupt_head.prev_hash = skipped_to_header.hash(context_id).unwrap();
	corrupt_head.pow.proof.nonces[0] += 1;
	let corrupt_tip = Tip::try_from_header(&corrupt_head).unwrap();

	{
		let batch = store.batch_write().unwrap();
		batch.save_block_header(&corrupt_head).unwrap();
		batch.save_body_head(&corrupt_tip).unwrap();
		batch.commit().unwrap();
	}

	let res = chain.block_height_range_to_pmmr_indices(3, Some(corrupt_head.height));
	assert!(matches!(
		res,
		Err(mwc_chain::Error::Other(msg))
			if msg.contains("body chain header traversal stopped at height 1")
				&& msg.contains("below requested height 2")
	));

	clean_output_dir(chain_dir);
}

#[test]
fn init_output_pos_index_rebuilds_missing_genesis_output_at_height_zero() {
	let chain_dir = ".mwc.output_pos_genesis";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::Floonet);
	global::set_local_nrd_enabled(false);
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let genesis = genesis::genesis_floo(&secp, 0);
	let commit = genesis.outputs()[0].commitment();
	let chain = init_chain(&secp, chain_dir, genesis);
	let store = chain.get_store_for_tests();
	assert!(store
		.batch_read()
		.unwrap()
		.is_output_pos_index_complete()
		.unwrap());

	{
		let batch = store.batch_write().unwrap();
		batch.delete_output_pos_height(&commit).unwrap();
		batch.set_output_pos_index_complete(false).unwrap();
		batch.commit().unwrap();
	}

	{
		let txhashset = chain.get_txhashset_for_test();
		let txhashset = txhashset.read_recursive();
		let batch = store.batch_write().unwrap();
		txhashset.init_output_pos_index(&batch, None, None).unwrap();
		batch.commit().unwrap();
	}

	let header = chain.get_header_for_output(commit).unwrap();
	assert_eq!(header.height, 0);
	assert!(store
		.batch_read()
		.unwrap()
		.is_output_pos_index_complete()
		.unwrap());
	clean_output_dir(chain_dir);
}

#[test]
fn reset_pibd_chain_keeps_genesis_output_visible_after_compaction() {
	let chain_dir = test_chain_dir("pibd_reset_genesis_after_compaction");
	clean_output_dir(&chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let proof_builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let genesis = genesis_block(&mut secp, &keychain);
	let genesis_commit = genesis.outputs()[0].commitment();

	{
		let chain = init_chain(&secp, &chain_dir, genesis);
		let mut head = chain.head_header().unwrap();

		let b = prepare_block_key_idx(&mut secp, &keychain, &head, &chain, 2, 2);
		assert!(b.outputs()[0].is_coinbase());
		head = b.header.clone();
		chain
			.process_block(
				&mut secp,
				b,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		for n in 3..6 {
			let b = prepare_block(&mut secp, &keychain, &head, &chain, n);
			head = b.header.clone();
			chain
				.process_block(
					&mut secp,
					b,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		let key_id_coinbase = ExtKeychainPath::new(1, 2, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id30 = ExtKeychainPath::new(1, 30, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();

		let tx1 = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 20000u32.try_into().unwrap(),
			},
			&[
				build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id_coinbase),
				build::output(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id30),
			],
			&keychain,
			&proof_builder,
		)
		.unwrap();

		let b = prepare_block_tx(&mut secp, &keychain, &head, &chain, 6, &[tx1]);
		head = b.header.clone();
		chain
			.process_block(
				&mut secp,
				b,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		for n in 7..30 {
			let b = prepare_block(&mut secp, &keychain, &head, &chain, n);
			head = b.header.clone();
			chain
				.process_block(
					&mut secp,
					b,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		let store = chain.get_store_for_tests();
		let horizon_header = chain.get_header_by_height(20).unwrap();
		{
			let txhashset = chain.get_txhashset_for_test();
			let mut txhashset = txhashset.write();
			let batch = store.batch_write().unwrap();
			txhashset.compact(&horizon_header, &batch).unwrap();
			batch.commit().unwrap();
		}

		chain.reset_pibd_chain().unwrap();

		let txhashset = chain.get_txhashset_for_test();
		let txhashset = txhashset.read_recursive();
		let (_, pos) = txhashset
			.get_unspent(genesis_commit)
			.unwrap()
			.expect("genesis output must remain visible after PIBD reset");
		assert_eq!(pos.pos, 1);
		assert_eq!(pos.height, 0);
	}

	clean_output_dir(&chain_dir);
}

#[test]
fn get_unspent_rebuilds_index_with_stale_height() {
	let chain_dir = ".mwc.get_unspent_stale_height";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 4);
	let store = chain.get_store_for_tests();
	let block_header = chain.get_header_by_height(1).unwrap();
	let block = chain.get_block(&block_header.hash(0).unwrap()).unwrap();
	let commit = block.outputs()[0].commitment();
	let original_pos = store.get_output_pos_height(&commit).unwrap().unwrap();
	assert_eq!(original_pos.height, 1);

	{
		let batch = store.batch_write().unwrap();
		batch
			.save_output_pos_height(
				&commit,
				CommitPos {
					pos: original_pos.pos,
					height: 2,
				},
			)
			.unwrap();
		batch.commit().unwrap();
	}

	let (_, pos) = chain.get_unspent(commit).unwrap().unwrap();
	assert_eq!(pos, original_pos);
	assert_eq!(
		store.get_output_pos_height(&commit).unwrap(),
		Some(original_pos)
	);
	clean_output_dir(chain_dir);
}

#[test]
fn get_unspent_rebuild_repairs_all_stale_heights() {
	let chain_dir = ".mwc.get_unspent_all_stale_heights";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 4);
	let store = chain.get_store_for_tests();

	let block_a_header = chain.get_header_by_height(1).unwrap();
	let block_a = chain.get_block(&block_a_header.hash(0).unwrap()).unwrap();
	let commit_a = block_a.outputs()[0].commitment();
	let original_a = store.get_output_pos_height(&commit_a).unwrap().unwrap();
	assert_eq!(original_a.height, 1);

	let block_b_header = chain.get_header_by_height(2).unwrap();
	let block_b = chain.get_block(&block_b_header.hash(0).unwrap()).unwrap();
	let commit_b = block_b.outputs()[0].commitment();
	let original_b = store.get_output_pos_height(&commit_b).unwrap().unwrap();
	assert_eq!(original_b.height, 2);

	{
		let batch = store.batch_write().unwrap();
		batch
			.save_output_pos_height(
				&commit_a,
				CommitPos {
					pos: original_a.pos,
					height: original_a.height + 1,
				},
			)
			.unwrap();
		batch
			.save_output_pos_height(
				&commit_b,
				CommitPos {
					pos: original_b.pos,
					height: original_b.height + 1,
				},
			)
			.unwrap();
		batch.commit().unwrap();
	}

	let (_, pos_a) = chain.get_unspent(commit_a).unwrap().unwrap();
	assert_eq!(pos_a, original_a);
	assert_eq!(
		store.get_output_pos_height(&commit_a).unwrap(),
		Some(original_a)
	);
	assert_eq!(
		store.get_output_pos_height(&commit_b).unwrap(),
		Some(original_b)
	);

	clean_output_dir(chain_dir);
}

#[test]
fn get_unspent_does_not_rebuild_index_with_missing_entry() {
	let chain_dir = ".mwc.get_unspent_missing_index";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 4);
	let store = chain.get_store_for_tests();
	let block_header = chain.get_header_by_height(1).unwrap();
	let block = chain.get_block(&block_header.hash(0).unwrap()).unwrap();
	let commit = block.outputs()[0].commitment();
	let original_pos = store.get_output_pos_height(&commit).unwrap().unwrap();
	assert_eq!(original_pos.height, 1);

	{
		let batch = store.batch_write().unwrap();
		batch.delete_output_pos_height(&commit).unwrap();
		batch.commit().unwrap();
	}

	assert_eq!(store.get_output_pos_height(&commit).unwrap(), None);
	assert!(chain.get_unspent(commit).unwrap().is_none());
	assert_eq!(store.get_output_pos_height(&commit).unwrap(), None);
	clean_output_dir(chain_dir);
}

#[test]
fn get_header_for_output_rebuilds_index_with_stale_height() {
	let chain_dir = ".mwc.output_pos_stale_height";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 4);
	let store = chain.get_store_for_tests();
	let block_header = chain.get_header_by_height(1).unwrap();
	let block = chain.get_block(&block_header.hash(0).unwrap()).unwrap();
	let commit = block.outputs()[0].commitment();
	let original_pos = store.get_output_pos_height(&commit).unwrap().unwrap();
	assert_eq!(original_pos.height, 1);

	{
		let batch = store.batch_write().unwrap();
		batch
			.save_output_pos_height(
				&commit,
				CommitPos {
					pos: original_pos.pos,
					height: 2,
				},
			)
			.unwrap();
		batch.commit().unwrap();
	}

	let header = chain.get_header_for_output(commit).unwrap();
	assert_eq!(header.height, 1);
	assert_eq!(
		store.get_output_pos_height(&commit).unwrap(),
		Some(original_pos)
	);
	clean_output_dir(chain_dir);
}

#[test]
fn get_header_for_output_uses_body_chain_when_header_pmmr_is_on_fork() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = test_chain_dir("output_pos_body_chain_header_fork");
	clean_output_dir(&chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, &chain_dir, genesis);
	let context_id = chain.get_context_id();

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let body_block = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	process_block(&mut secp, &chain, &body_block);

	let commit = body_block.outputs()[0].commitment();
	let original_pos = chain
		.get_store_for_tests()
		.get_output_pos_height(&commit)
		.unwrap()
		.unwrap();
	assert_eq!(original_pos.height, body_block.header.height);

	let mut header_fork = prepare_block(&mut secp, &kc, &block_a.header, &chain, 3).header;
	header_fork.output_mmr_size = body_block.header.output_mmr_size;
	process_header(&chain, &header_fork);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&body_block.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&header_fork).unwrap()
	);
	assert_ne!(
		body_block.header.hash(context_id).unwrap(),
		header_fork.hash(context_id).unwrap()
	);

	let header = chain.get_header_for_output(commit).unwrap();
	assert_eq!(
		header.hash(context_id).unwrap(),
		body_block.header.hash(context_id).unwrap()
	);
	assert_ne!(
		header.hash(context_id).unwrap(),
		header_fork.hash(context_id).unwrap()
	);
	let (_, pos) = chain.get_unspent(commit).unwrap().unwrap();
	assert_eq!(pos, original_pos);

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(&chain_dir);
}

#[test]
fn get_kernel_height_rejects_stale_kernel_pos_height() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = test_chain_dir("kernel_pos_stale_height");
	clean_output_dir(&chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, &chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let body_block = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	process_block(&mut secp, &chain, &body_block);

	let excess = body_block.kernels()[0].excess;
	let (_, height, kernel_mmr_index) = chain
		.get_kernel_height(&excess, None, None)
		.unwrap()
		.unwrap();
	assert_eq!(height, body_block.header.height);

	let stale_height = height - 1;
	let store = chain.get_store_for_tests();
	{
		let batch = store.batch_write().unwrap();
		batch
			.save_kernel_pos(
				&excess,
				KernelPos {
					pos: kernel_mmr_index,
					height: stale_height,
				},
			)
			.unwrap();
		batch.commit().unwrap();
	}

	let err = chain
		.get_kernel_height(&excess, None, Some(stale_height))
		.unwrap_err();
	match err {
		mwc_chain::Error::TxHashSetErr(msg) => {
			assert!(msg.contains("kernel_pos index height mismatch"), "{}", msg);
		}
		other => panic!("expected kernel_pos height mismatch error, got {:?}", other),
	}

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(&chain_dir);
}

#[test]
fn get_header_for_kernel_index_uses_body_chain_when_header_pmmr_is_on_fork() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = test_chain_dir("kernel_index_body_chain_header_fork");
	clean_output_dir(&chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, &chain_dir, genesis);
	let context_id = chain.get_context_id();

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let body_block = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	process_block(&mut secp, &chain, &body_block);

	let (_, _, kernel_mmr_index) = chain
		.get_kernel_height(&body_block.kernels()[0].excess, None, None)
		.unwrap()
		.unwrap();

	let mut header_fork = prepare_block(&mut secp, &kc, &block_a.header, &chain, 3).header;
	header_fork.kernel_mmr_size = body_block.header.kernel_mmr_size;
	process_header(&chain, &header_fork);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&body_block.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&header_fork).unwrap()
	);
	assert_ne!(
		body_block.header.hash(context_id).unwrap(),
		header_fork.hash(context_id).unwrap()
	);

	let header = chain
		.get_header_for_kernel_index(kernel_mmr_index, None, None)
		.unwrap();
	assert_eq!(
		header.hash(context_id).unwrap(),
		body_block.header.hash(context_id).unwrap()
	);
	assert_ne!(
		header.hash(context_id).unwrap(),
		header_fork.hash(context_id).unwrap()
	);

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(&chain_dir);
}

#[test]
fn init_output_pos_index_maps_missing_outputs_from_body_chain() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = test_chain_dir("output_pos_repair_body_chain");
	clean_output_dir(&chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, &chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);
	let body_block = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	process_block(&mut secp, &chain, &body_block);

	let commit = body_block.outputs()[0].commitment();
	let store = chain.get_store_for_tests();
	let original_pos = store.get_output_pos_height(&commit).unwrap().unwrap();
	assert_eq!(original_pos.height, body_block.header.height);

	let mut header_fork = prepare_block(&mut secp, &kc, &chain.genesis(), &chain, 10).header;
	header_fork.output_mmr_size = body_block.header.output_mmr_size;
	process_header(&chain, &header_fork);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&body_block.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&header_fork).unwrap()
	);
	assert!(header_fork.height < body_block.header.height);
	assert!(header_fork.output_mmr_size >= original_pos.pos);

	{
		let batch = store.batch_write().unwrap();
		batch.delete_output_pos_height(&commit).unwrap();
		batch.commit().unwrap();
	}

	{
		let txhashset = chain.get_txhashset_for_test();
		let txhashset = txhashset.read_recursive();
		let batch = store.batch_write().unwrap();
		txhashset.init_output_pos_index(&batch, None, None).unwrap();
		batch.commit().unwrap();
	}

	assert_eq!(
		store.get_output_pos_height(&commit).unwrap(),
		Some(original_pos)
	);

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(&chain_dir);
}

#[test]
fn init_output_pos_index_errors_on_unmapped_missing_output() {
	let chain_dir = ".mwc.output_pos_unmapped";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 2);
	let block_header = chain.get_header_by_height(1).unwrap();
	let block = chain.get_block(&block_header.hash(0).unwrap()).unwrap();
	let commit = block.outputs()[0].commitment();
	let genesis_tip = Tip::try_from_header(&chain.genesis()).unwrap();
	let store = chain.get_store_for_tests();

	{
		let batch = store.batch_write().unwrap();
		batch.delete_output_pos_height(&commit).unwrap();
		batch.save_body_head(&genesis_tip).unwrap();
		batch.commit().unwrap();
	}

	{
		let txhashset = chain.get_txhashset_for_test();
		let txhashset = txhashset.read_recursive();
		let batch = store.batch_write().unwrap();
		let res = txhashset.init_output_pos_index(&batch, None, None);
		assert!(matches!(
			res,
			Err(mwc_chain::Error::Other(msg))
				if msg.contains("failed to map") && msg.contains("utxos to block heights")
		));
	}

	clean_output_dir(chain_dir);
}

// Convenience wrapper for processing a full block on the test chain.
fn process_header(chain: &Chain, header: &BlockHeader) {
	chain
		.process_block_header(header, Options::SKIP_POW)
		.unwrap();
}

// Convenience wrapper for processing a block header on the test chain.
fn process_block(secp: &mut Secp256k1, chain: &Chain, block: &Block) {
	chain
		.process_block(
			secp,
			block.clone(),
			Options::SKIP_POW,
			std::collections::HashSet::new(),
		)
		.unwrap();
}

#[test]
fn rewind_bad_block_removes_header_only_chain_state() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.rewind_bad_header_only";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	process_header(&chain, &block_b.header);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_a.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_b.header).unwrap()
	);

	let bad_hash = block_b.hash(0).unwrap();
	let mut invalid_blocks = HashSet::new();
	invalid_blocks.insert(bad_hash);
	chain.apply_invalid_blocks(&secp, invalid_blocks).unwrap();

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_a.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_a.header).unwrap()
	);
	assert!(chain.get_block_header(&bad_hash).is_err());

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(chain_dir);
}

#[test]
fn rewind_bad_block_on_header_fork_preserves_body_head() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.rewind_bad_header_fork";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	let block_b_fork = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);

	process_header(&chain, &block_b.header);
	process_header(&chain, &block_b_fork.header);
	process_block(&mut secp, &chain, &block_b_fork);
	process_block(&mut secp, &chain, &block_b);

	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_b.header).unwrap()
	);
	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_b_fork.header).unwrap()
	);

	let bad_hash = block_b.hash(0).unwrap();
	let body_hash = block_b_fork.hash(0).unwrap();
	let mut invalid_blocks = HashSet::new();
	invalid_blocks.insert(bad_hash);
	chain.apply_invalid_blocks(&secp, invalid_blocks).unwrap();

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_b_fork.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_a.header).unwrap()
	);
	assert!(chain.get_block_header(&bad_hash).is_err());
	assert!(chain.get_block(&body_hash).is_ok());

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(chain_dir);
}

#[test]
fn known_header_fast_path_rejects_different_header() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.known_header_mismatch";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);
	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	process_header(&chain, &block_b.header);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_a.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_b.header).unwrap()
	);

	let mut mutated_block_b = block_b.clone();
	mutated_block_b.header.timestamp = mutated_block_b.header.timestamp + Duration::seconds(1);
	assert_eq!(block_b.hash(0).unwrap(), mutated_block_b.hash(0).unwrap());
	assert_ne!(block_b.header, mutated_block_b.header);

	let res = chain.process_block_header(&mutated_block_b.header, Options::SKIP_POW);
	assert!(res.is_err());
	assert!(chain
		.get_store_for_tests()
		.pending_chain_operation()
		.unwrap()
		.is_none());

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(chain_dir);
}

#[test]
fn header_only_validation_rejects_incomplete_body_mmr_sizes() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.invalid_header_mmr_size";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);
	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);

	assert_eq!(block_a.header.output_mmr_size, 1);
	assert_eq!(block_a.header.kernel_mmr_size, 1);
	assert_eq!(block_b.header.output_mmr_size, 3);
	assert_eq!(block_b.header.kernel_mmr_size, 3);

	let mut invalid_output = block_b.header.clone();
	invalid_output.output_mmr_size = 2;
	let res = chain.process_block_header(&invalid_output, Options::SKIP_POW);
	assert!(matches!(res, Err(mwc_chain::Error::InvalidMMRSize)));

	let mut invalid_kernel = block_b.header.clone();
	invalid_kernel.kernel_mmr_size = 2;
	let res = chain.process_block_header(&invalid_kernel, Options::SKIP_POW);
	assert!(matches!(res, Err(mwc_chain::Error::InvalidMMRSize)));

	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_a.header).unwrap()
	);

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(chain_dir);
}

#[test]
fn header_only_validation_rejects_wrong_height_as_bad_data() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.invalid_header_height";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);
	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);

	let mut invalid = block_b.header.clone();
	invalid.height = invalid.height.saturating_add(1);
	let res = chain.process_block_header(&invalid, Options::SKIP_POW);
	let err = res.unwrap_err();
	assert!(matches!(err, mwc_chain::Error::InvalidBlockHeight));
	assert!(err.is_bad_data());

	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_a.header).unwrap()
	);

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(chain_dir);
}

#[test]
fn known_full_block_fast_path_rejects_different_header() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.known_full_block_mismatch";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = init_chain(&secp, chain_dir, genesis);

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);
	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	process_block(&mut secp, &chain, &block_b);
	let block_c = prepare_block(&mut secp, &kc, &block_b.header, &chain, 3);
	process_block(&mut secp, &chain, &block_c);

	let mut mutated_head = block_c.clone();
	mutated_head.header.timestamp = mutated_head.header.timestamp + Duration::seconds(1);
	assert_eq!(block_c.hash(0).unwrap(), mutated_head.hash(0).unwrap());
	assert_ne!(block_c.header, mutated_head.header);
	assert!(chain
		.process_block_header(&mutated_head.header, Options::SKIP_POW)
		.is_err());

	let mut mutated_store = block_a.clone();
	mutated_store.header.timestamp = mutated_store.header.timestamp + Duration::seconds(1);
	assert_eq!(block_a.hash(0).unwrap(), mutated_store.hash(0).unwrap());
	assert_ne!(block_a.header, mutated_store.header);
	assert!(chain
		.process_block_header(&mutated_store.header, Options::SKIP_POW)
		.is_err());

	mwc_chain::pipe::release_context_data(chain.get_context_id());
	clean_output_dir(chain_dir);
}

//
// a - b - c
//  \
//   - b'
//
// Process in the following order -
// 1. block_a
// 2. block_b
// 3. block_b'
// 4. header_c
// 5. block_c
//
#[test]
fn test_block_a_block_b_block_b_fork_header_c_fork_block_c() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.block_a_block_b_block_b_fork_header_c_fork_block_c";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let last_status = RwLock::new(None);
	let adapter = Arc::new(StatusAdapter::new(last_status));
	let chain = setup_with_status_adapter(&secp, chain_dir, genesis.clone(), adapter.clone());

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	let block_b_fork = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);

	process_block(&mut secp, &chain, &block_b);
	process_block(&mut secp, &chain, &block_b_fork);

	let block_c = prepare_block(&mut secp, &kc, &block_b.header, &chain, 3);
	process_header(&chain, &block_c.header);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_b.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_c.header).unwrap()
	);

	process_block(&mut secp, &chain, &block_c);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_c.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_c.header).unwrap()
	);

	clean_output_dir(chain_dir);
}

//
// a - b
//  \
//   - b' - c'
//
// Process in the following order -
// 1. block_a
// 2. block_b
// 3. block_b'
// 4. header_c'
// 5. block_c'
//
#[test]
fn test_block_a_block_b_block_b_fork_header_c_fork_block_c_fork() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.block_a_block_b_block_b_fork_header_c_fork_block_c_fork";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let last_status = RwLock::new(None);
	let adapter = Arc::new(StatusAdapter::new(last_status));
	let chain = setup_with_status_adapter(&secp, chain_dir, genesis.clone(), adapter.clone());

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	let block_b_fork = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);

	process_block(&mut secp, &chain, &block_b);
	process_block(&mut secp, &chain, &block_b_fork);

	let block_c_fork = prepare_block(&mut secp, &kc, &block_b_fork.header, &chain, 3);
	process_header(&chain, &block_c_fork.header);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_b.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_c_fork.header).unwrap()
	);

	process_block(&mut secp, &chain, &block_c_fork);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_c_fork.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_c_fork.header).unwrap()
	);

	clean_output_dir(chain_dir);
}

//
// a - b - c
//  \
//   - b'
//
// Process in the following order -
// 1. block_a
// 2. header_b
// 3. header_b_fork
// 4. block_b_fork
// 5. block_b
// 6. block_c
//
#[test]
fn test_block_a_header_b_header_b_fork_block_b_fork_block_b_block_c() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.test_block_a_header_b_header_b_fork_block_b_fork_block_b_block_c";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let last_status = RwLock::new(None);
	let adapter = Arc::new(StatusAdapter::new(last_status));
	let chain = setup_with_status_adapter(&secp, chain_dir, genesis.clone(), adapter.clone());

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	let block_b_fork = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);

	process_header(&chain, &block_b.header);
	process_header(&chain, &block_b_fork.header);
	process_block(&mut secp, &chain, &block_b_fork);
	process_block(&mut secp, &chain, &block_b);

	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_b.header).unwrap()
	);
	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_b_fork.header).unwrap()
	);

	let block_c = prepare_block(&mut secp, &kc, &block_b.header, &chain, 3);
	process_block(&mut secp, &chain, &block_c);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_c.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_c.header).unwrap()
	);

	clean_output_dir(chain_dir);
}

//
// a - b
//  \
//   - b' - c'
//
// Process in the following order -
// 1. block_a
// 2. header_b
// 3. header_b_fork
// 4. block_b_fork
// 5. block_b
// 6. block_c_fork
//
#[test]
fn test_block_a_header_b_header_b_fork_block_b_fork_block_b_block_c_fork() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = ".mwc.test_block_a_header_b_header_b_fork_block_b_fork_block_b_block_c_fork";
	clean_output_dir(chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let last_status = RwLock::new(None);
	let adapter = Arc::new(StatusAdapter::new(last_status));
	let chain = setup_with_status_adapter(&secp, chain_dir, genesis.clone(), adapter.clone());

	let block_a = prepare_block(&mut secp, &kc, &chain.head_header().unwrap(), &chain, 1);
	process_block(&mut secp, &chain, &block_a);

	let block_b = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);
	let block_b_fork = prepare_block(&mut secp, &kc, &block_a.header, &chain, 2);

	process_header(&chain, &block_b.header);
	process_header(&chain, &block_b_fork.header);
	process_block(&mut secp, &chain, &block_b_fork);
	process_block(&mut secp, &chain, &block_b);

	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_b.header).unwrap()
	);
	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_b_fork.header).unwrap()
	);

	let block_c_fork = prepare_block(&mut secp, &kc, &block_b_fork.header, &chain, 3);
	process_block(&mut secp, &chain, &block_c_fork);

	assert_eq!(
		chain.head().unwrap(),
		Tip::try_from_header(&block_c_fork.header).unwrap()
	);
	assert_eq!(
		chain.header_head().unwrap(),
		Tip::try_from_header(&block_c_fork.header).unwrap()
	);

	clean_output_dir(chain_dir);
}

// This test creates a reorg at REORG_DEPTH by mining a block with difficulty that
// exceeds original chain total difficulty.
//
// Illustration of reorg with NUM_BLOCKS_MAIN = 6 and REORG_DEPTH = 5:
//
// difficulty:    1        2        3        4        5        6
//
//                       / [ 2  ] - [ 3  ] - [ 4  ] - [ 5  ] - [ 6  ] <- original chain
// [ Genesis ] -[ 1 ]- *
//                     ^ \ [ 2' ] - ................................  <- reorg chain with depth 5
//                     |
// difficulty:    1    |   24
//                     |
//                     \----< Fork point and chain reorg
#[test]
fn mine_reorg() {
	// Test configuration
	const NUM_BLOCKS_MAIN: u64 = 6; // Number of blocks to mine in main chain
	const REORG_DEPTH: u64 = 5; // Number of blocks to be discarded from main chain after reorg

	let chain_dir = test_chain_dir("mine_reorg");
	clean_output_dir(&chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();

	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	{
		// Create chain that reports last block status
		let last_status = RwLock::new(None);
		let adapter = Arc::new(StatusAdapter::new(last_status));
		let chain = setup_with_status_adapter(&secp, &chain_dir, genesis.clone(), adapter.clone());

		// Add blocks to main chain with gradually increasing difficulty
		let mut prev = chain.head_header().unwrap();
		for n in 1..=NUM_BLOCKS_MAIN {
			let b = prepare_block(&mut secp, &kc, &prev, &chain, n);
			prev = b.header.clone();
			chain
				.process_block(
					&mut secp,
					b,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		let head = chain.head().unwrap();
		assert_eq!(head.height, NUM_BLOCKS_MAIN);
		assert_eq!(head.hash(0).unwrap(), prev.hash(0).unwrap());

		// Reorg chain should exceed main chain's total difficulty to be considered
		let reorg_difficulty = head.total_difficulty.to_num();

		// Create one block for reorg chain forking off NUM_BLOCKS_MAIN - REORG_DEPTH height
		let fork_head = chain
			.get_header_by_height(NUM_BLOCKS_MAIN - REORG_DEPTH)
			.unwrap();
		let b = prepare_block(&mut secp, &kc, &fork_head, &chain, reorg_difficulty);
		let reorg_head = b.header.clone();
		chain
			.process_block(
				&mut secp,
				b,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		// Check that reorg is correctly reported in block status
		let fork_point = chain.get_header_by_height(1).unwrap();
		assert_eq!(
			*adapter.last_status.read_recursive(),
			Some(BlockStatus::Reorg {
				prev: Tip::try_from_header(&fork_head).unwrap(),
				prev_head: head,
				fork_point: Tip::try_from_header(&fork_point).unwrap()
			})
		);

		// Chain should be switched to the reorganized chain
		let head = chain.head().unwrap();
		assert_eq!(head.height, NUM_BLOCKS_MAIN - REORG_DEPTH + 1);
		assert_eq!(head.hash(0).unwrap(), reorg_head.hash(0).unwrap());
	}

	// Cleanup chain directory
	clean_output_dir(&chain_dir);
}

#[test]
fn mine_forks() {
	clean_output_dir(".mwc2");
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	{
		let chain = init_chain(&secp, ".mwc2", global::get_genesis_block(&secp, 0).unwrap());
		let kc =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();

		// add a first block to not fork genesis
		let prev = chain.head_header().unwrap();
		let b = prepare_block(&mut secp, &kc, &prev, &chain, 2);
		chain
			.process_block(
				&mut secp,
				b,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		// mine and add a few blocks

		for n in 1..4 {
			// first block for one branch
			let prev = chain.head_header().unwrap();
			let b1 = prepare_block(&mut secp, &kc, &prev, &chain, 3 * n);

			// process the first block to extend the chain
			let bhash = b1.hash(0).unwrap();
			chain
				.process_block(
					&mut secp,
					b1,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();

			// checking our new head
			let head = chain.head().unwrap();
			assert_eq!(head.height, (n + 1) as u64);
			assert_eq!(head.last_block_h, bhash);
			assert_eq!(head.prev_block_h, prev.hash(0).unwrap());

			// 2nd block with higher difficulty for other branch
			let b2 = prepare_block(&mut secp, &kc, &prev, &chain, 3 * n + 1);

			// process the 2nd block to build a fork with more work
			let bhash = b2.hash(0).unwrap();
			chain
				.process_block(
					&mut secp,
					b2,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();

			// checking head switch
			let head = chain.head().unwrap();
			assert_eq!(head.height, (n + 1) as u64);
			assert_eq!(head.last_block_h, bhash);
			assert_eq!(head.prev_block_h, prev.hash(0).unwrap());
		}
	}
	// Cleanup chain directory
	clean_output_dir(".mwc2");
}

#[test]
fn mine_losing_fork() {
	let chain_dir = test_chain_dir("mine_losing_fork");
	clean_output_dir(&chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	{
		let chain = init_chain(
			&secp,
			&chain_dir,
			global::get_genesis_block(&secp, 0).unwrap(),
		);

		// add a first block we'll be forking from
		let prev = chain.head_header().unwrap();
		let b1 = prepare_block(&mut secp, &kc, &prev, &chain, 2);
		let b1head = b1.header.clone();
		chain
			.process_block(
				&mut secp,
				b1,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		// prepare the 2 successor, sibling blocks, one with lower diff
		let b2 = prepare_block(&mut secp, &kc, &b1head, &chain, 4);
		let b2head = b2.header.clone();
		let bfork = prepare_block(&mut secp, &kc, &b1head, &chain, 3);

		// add higher difficulty first, prepare its successor, then fork
		// with lower diff
		chain
			.process_block(
				&mut secp,
				b2,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();
		assert_eq!(
			chain.head_header().unwrap().hash(0).unwrap(),
			b2head.hash(0).unwrap()
		);
		let b3 = prepare_block(&mut secp, &kc, &b2head, &chain, 5);
		chain
			.process_block(
				&mut secp,
				bfork,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		// adding the successor
		let b3head = b3.header.clone();
		chain
			.process_block(
				&mut secp,
				b3,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();
		assert_eq!(
			chain.head_header().unwrap().hash(0).unwrap(),
			b3head.hash(0).unwrap()
		);
	}
	// Cleanup chain directory
	clean_output_dir(&chain_dir);
}

#[test]
fn longer_fork() {
	clean_output_dir(".mwc4");
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let kc = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
		.unwrap();
	// to make it easier to compute the txhashset roots in the test, we
	// prepare 2 chains, the 2nd will be have the forked blocks we can
	// then send back on the 1st
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	{
		let chain = init_chain(&secp, ".mwc4", genesis.clone());

		// add blocks to both chains, 20 on the main one, only the first 5
		// for the forked chain
		let mut prev = chain.head_header().unwrap();
		for n in 0..10 {
			let b = prepare_block(&mut secp, &kc, &prev, &chain, 2 * n + 2);
			prev = b.header.clone();
			chain
				.process_block(
					&mut secp,
					b,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		let forked_block = chain.get_header_by_height(5).unwrap();

		let head = chain.head_header().unwrap();
		assert_eq!(head.height, 10);
		assert_eq!(head.hash(0).unwrap(), prev.hash(0).unwrap());

		let mut prev = forked_block;
		for n in 0..7 {
			let b = prepare_block(&mut secp, &kc, &prev, &chain, 2 * n + 11);
			prev = b.header.clone();
			chain
				.process_block(
					&mut secp,
					b,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		let new_head = prev;

		// After all this the chain should have switched to the fork.
		let head = chain.head_header().unwrap();
		assert_eq!(head.height, 12);
		assert_eq!(head.hash(0).unwrap(), new_head.hash(0).unwrap());
	}
	// Cleanup chain directory
	clean_output_dir(".mwc4");
}

#[test]
fn spend_rewind_spend() {
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	let chain_dir = ".mwc_spend_rewind_spend";
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	{
		let chain = init_chain(
			&secp,
			chain_dir,
			global::get_genesis_block(&secp, 0).unwrap(),
		);
		let prev = chain.head_header().unwrap();
		let kc =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let pb = ProofBuilder::new(&secp, &kc).unwrap();

		let mut head = prev;

		// mine the first block and keep track of the block_hash
		// so we can spend the coinbase later
		let b = prepare_block_key_idx(&mut secp, &kc, &head, &chain, 2, 1);
		assert!(b.outputs()[0].is_coinbase());
		head = b.header.clone();
		chain
			.process_block(
				&mut secp,
				b.clone(),
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		// now mine three further blocks
		for n in 3..6 {
			let b = prepare_block(&mut secp, &kc, &head, &chain, n);
			head = b.header.clone();
			chain
				.process_block(
					&mut secp,
					b,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		// Make a note of this header as we will rewind back to here later.
		let rewind_to = head.clone();

		let key_id_coinbase = ExtKeychainPath::new(1, 1, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id30 = ExtKeychainPath::new(1, 30, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();

		let tx1 = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 20000u32.try_into().unwrap(),
			},
			&[
				build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id_coinbase.clone()),
				build::output(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id30.clone()),
			],
			&kc,
			&pb,
		)
		.unwrap();

		let b = prepare_block_tx(&mut secp, &kc, &head, &chain, 6, &[tx1.clone()]);
		head = b.header.clone();
		chain
			.process_block(
				&mut secp,
				b.clone(),
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();
		chain.validate(&secp, false).unwrap();

		// Now mine another block, reusing the private key for the coinbase we just spent.
		{
			let b = prepare_block_key_idx(&mut secp, &kc, &head, &chain, 7, 1);
			//due to recent change of checking output against spent output, this process will fail.
			assert!(chain
				.process_block(
					&mut secp,
					b,
					Options::SKIP_POW,
					std::collections::HashSet::new()
				)
				.is_err());
		}

		// Now mine a competing block also spending the same coinbase output from earlier.
		// Rewind back prior to the tx that spends it to "unspend" it.
		{
			let b = prepare_block_tx(&mut secp, &kc, &rewind_to, &chain, 6, &[tx1]);
			chain
				.process_block(
					&mut secp,
					b.clone(),
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
			chain.validate(&secp, false).unwrap();
		}
	}

	clean_output_dir(chain_dir);
}

#[test]
fn spend_in_fork_and_compact() {
	clean_output_dir(".mwc6");
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	{
		let chain = init_chain(&secp, ".mwc6", global::get_genesis_block(&secp, 0).unwrap());
		let prev = chain.head_header().unwrap();
		let kc =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let pb = ProofBuilder::new(&secp, &kc).unwrap();

		let mut fork_head = prev;

		// mine the first block and keep track of the block_hash
		// so we can spend the coinbase later
		let b = prepare_block(&mut secp, &kc, &fork_head, &chain, 2);
		assert!(b.outputs()[0].is_coinbase());
		fork_head = b.header.clone();
		chain
			.process_block(
				&mut secp,
				b.clone(),
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		//only mine 2 blocks because from height 6 it will be header version 3 and it
		//will trigger replay attack check.
		for n in 3..5 {
			//only mine 2 blocks because from height 6 it will be header version 3 and it
			let b = prepare_block(&mut secp, &kc, &fork_head, &chain, n);
			fork_head = b.header.clone();
			chain
				.process_block(
					&mut secp,
					b,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		// Check the height of the "fork block".
		assert_eq!(fork_head.height, 3);
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id30 = ExtKeychainPath::new(1, 30, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id31 = ExtKeychainPath::new(1, 31, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();

		let tx1 = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 20000u32.try_into().unwrap(),
			},
			&[
				build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id2.clone()),
				build::output(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id30.clone()),
			],
			&kc,
			&pb,
		)
		.unwrap();

		let next = prepare_block_tx(&mut secp, &kc, &fork_head, &chain, 7, &[tx1.clone()]);
		let prev_main = next.header.clone();
		chain
			.process_block(
				&mut secp,
				next.clone(),
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();
		chain.validate(&secp, false).unwrap();

		let tx2 = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 20000u32.try_into().unwrap(),
			},
			&[
				build::input(consensus::MWC_FIRST_GROUP_REWARD - 20000, key_id30.clone()),
				build::output(consensus::MWC_FIRST_GROUP_REWARD - 40000, key_id31.clone()),
			],
			&kc,
			&pb,
		)
		.unwrap();

		let next = prepare_block_tx(&mut secp, &kc, &prev_main, &chain, 9, &[tx2.clone()]);
		let prev_main = next.header.clone();
		chain
			.process_block(
				&mut secp,
				next,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		// Full chain validation for completeness.
		chain.validate(&secp, false).unwrap();
		// check state
		let head = chain.head_header().unwrap();
		assert_eq!(head.height, 5);
		assert_eq!(head.hash(0).unwrap(), prev_main.hash(0).unwrap());
		assert!(chain
			.get_unspent(tx2.outputs()[0].commitment())
			.unwrap()
			.is_some());
		assert!(chain
			.get_unspent(tx1.outputs()[0].commitment())
			.unwrap()
			.is_none());

		// mine 2 forked blocks from the first
		let fork = prepare_block_tx(&mut secp, &kc, &fork_head, &chain, 6, &[tx1.clone()]);
		let prev_fork = fork.header.clone();
		chain
			.process_block(
				&mut secp,
				fork,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		let fork_next = prepare_block_tx(&mut secp, &kc, &prev_fork, &chain, 8, &[tx2.clone()]);
		let prev_fork = fork_next.header.clone();
		chain
			.process_block(
				&mut secp,
				fork_next,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		chain.validate(&secp, false).unwrap();

		// check state
		let head = chain.head_header().unwrap();
		assert_eq!(head.height, 5);
		assert_eq!(head.hash(0).unwrap(), prev_main.hash(0).unwrap());
		assert!(chain
			.get_unspent(tx2.outputs()[0].commitment())
			.unwrap()
			.is_some());
		assert!(chain
			.get_unspent(tx1.outputs()[0].commitment())
			.unwrap()
			.is_none());

		// make the fork win
		let fork_next = prepare_block(&mut secp, &kc, &prev_fork, &chain, 10);
		let prev_fork = fork_next.header.clone();
		chain
			.process_block(
				&mut secp,
				fork_next,
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();
		chain.validate(&secp, false).unwrap();

		// check state
		let head = chain.head_header().unwrap();
		assert_eq!(head.height, 6);
		assert_eq!(head.hash(0).unwrap(), prev_fork.hash(0).unwrap());
		assert!(chain
			.get_unspent(tx2.outputs()[0].commitment())
			.unwrap()
			.is_some());
		assert!(chain
			.get_unspent(tx1.outputs()[0].commitment())
			.unwrap()
			.is_none());

		// add 20 blocks to go past the test horizon
		let mut prev = prev_fork;
		for n in 0..20 {
			let next = prepare_block(&mut secp, &kc, &prev, &chain, 11 + n);
			prev = next.header.clone();
			chain
				.process_block(
					&mut secp,
					next,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		chain.validate(&secp, false).unwrap();
		if let Err(e) = chain.compact(None, Arc::new(StopState::new())) {
			panic!("Error compacting chain: {:?}", e);
		}
		if let Err(e) = chain.validate(&secp, false) {
			panic!("Validation error after compacting chain: {:?}", e);
		}
	}
	// Cleanup chain directory
	clean_output_dir(".mwc6");
}

fn compact_missing_output_pos_result(test_name: &str, index_complete: bool) -> Option<CommitPos> {
	let chain_dir = test_chain_dir(test_name);
	clean_output_dir(&chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let genesis = genesis_block(&mut secp, &keychain);
	let genesis_commit = genesis.outputs()[0].commitment();

	let result = {
		let chain = init_chain(&secp, &chain_dir, genesis);
		let mut head = chain.head_header().unwrap();
		for n in 1..80 {
			let next = prepare_block(&mut secp, &keychain, &head, &chain, n);
			head = next.header.clone();
			chain
				.process_block(
					&mut secp,
					next,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		let store = chain.get_store_for_tests();
		assert!(store
			.get_output_pos_height(&genesis_commit)
			.unwrap()
			.is_some());
		{
			let batch = store.batch_write().unwrap();
			assert!(batch.is_output_pos_index_complete().unwrap());
			batch.delete_output_pos_height(&genesis_commit).unwrap();
			batch.set_output_pos_index_complete(index_complete).unwrap();
			batch.commit().unwrap();
		}

		chain.compact(None, Arc::new(StopState::new())).unwrap();
		store.get_output_pos_height(&genesis_commit).unwrap()
	};

	clean_output_dir(&chain_dir);
	result
}

#[test]
fn compact_skips_output_pos_rebuild_when_index_complete() {
	assert!(compact_missing_output_pos_result(
		"compact_skips_output_pos_rebuild_when_index_complete",
		true
	)
	.is_none());
}

#[test]
fn compact_rebuilds_output_pos_when_index_incomplete() {
	assert!(compact_missing_output_pos_result(
		"compact_rebuilds_output_pos_when_index_incomplete",
		false
	)
	.is_some());
}

/// Test ability to retrieve block headers for a given output
#[test]
fn output_header_mappings() {
	let chain_dir = test_chain_dir("output_header_mappings");
	clean_output_dir(&chain_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	{
		clean_output_dir(&chain_dir);
		let chain = init_chain(
			&secp,
			&chain_dir,
			global::get_genesis_block(&secp, 0).unwrap(),
		);
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let mut reward_outputs = vec![];

		let mut cache_values = consensus::DifficultyCache::new();

		for n in 1..15 {
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
				&keychain,
				&libtx::ProofBuilder::new(&secp, &keychain).unwrap(),
				&pk,
				0,
				false,
				prev.height + 1,
				&mut secp,
			)
			.unwrap();
			reward_outputs.push(reward.0.clone());
			let mut b = Block::new(
				0,
				&prev,
				&[],
				next_header_info.clone().difficulty,
				reward,
				&mut secp,
			)
			.unwrap();
			b.header.timestamp = prev.timestamp + Duration::seconds(60);
			b.header.pow.secondary_scaling = next_header_info.secondary_scaling;

			chain.set_txhashset_roots(&secp, &mut b).unwrap();

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
			b.header.pow.proof.edge_bits = edge_bits;

			chain
				.process_block(
					&mut secp,
					b,
					Options::MINE,
					std::collections::HashSet::new(),
				)
				.unwrap();

			let header_for_output = chain
				.get_header_for_output(reward_outputs[n - 1].commitment())
				.unwrap();
			assert_eq!(header_for_output.height, n as u64);

			chain.validate(&secp, false).unwrap();
		}

		// Check all output positions are as expected
		for n in 1..15 {
			let header_for_output = chain
				.get_header_for_output(reward_outputs[n - 1].commitment())
				.unwrap();
			assert_eq!(header_for_output.height, n as u64);
		}
	}
	// Cleanup chain directory
	clean_output_dir(&chain_dir);
}

/// Build a negative output. This function must not be used outside of tests.
/// The commitment will be an inversion of the value passed in and the value is
/// subtracted from the sum.
fn build_output_negative<K, B>(value: u64, key_id: Identifier) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum), Error> {
			let (tx, sum) = acc?;

			// TODO: proper support for different switch commitment schemes
			let switch = SwitchCommitmentType::Regular;

			// Keep the output commitment inverted for this negative-output test, but build
			// the temporary proof against a matching normal commitment. proof::create
			// validates its commitment argument, and this proof is replaced before block
			// validation below.
			// Reason for that - rengeproof validating input data, so the real commit must match expected
			//  values now. Invert commitment will fail the test, that is why proof_commit is introduced.
			let output_commit = build.keychain.commit(build.secp, value, &key_id, switch)?;
			let proof_commit = build.keychain.commit(build.secp, 0, &key_id, switch)?;

			// invert commitment
			let commit = build.secp.commit_sum(vec![], vec![output_commit])?;

			eprintln!("Building output: {}, {:?}", value, commit);

			// Build a valid placeholder proof; the test replaces it before block validation.
			let proof = proof::create(
				build.secp,
				build.keychain,
				build.builder,
				0,
				&key_id,
				switch,
				proof_commit,
				None,
			)?;

			// we return the output and the value is subtracted instead of added
			Ok((
				tx.with_output(0, Output::new(OutputFeatures::Plain, commit, proof))?,
				sum.sub_key_id(key_id.to_value_path(value).unwrap()),
			))
		},
	)
}

/// Test the duplicate rangeproof bug
#[test]
fn test_overflow_cached_rangeproof() {
	clean_output_dir(".mwc_overflow");
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	{
		let chain = init_chain(
			&secp,
			".mwc_overflow",
			global::get_genesis_block(&secp, 0).unwrap(),
		);
		let prev = chain.head_header().unwrap();
		let kc =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let pb = ProofBuilder::new(&secp, &kc).unwrap();

		let mut head = prev;

		// mine the first block and keep track of the block_hash
		// so we can spend the coinbase later
		let b = prepare_block(&mut secp, &kc, &head, &chain, 2);

		assert!(b.outputs()[0].is_coinbase());
		head = b.header.clone();
		chain
			.process_block(
				&mut secp,
				b.clone(),
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();

		// now mine three further blocks
		for n in 3..6 {
			let b = prepare_block(&mut secp, &kc, &head, &chain, n);
			head = b.header.clone();
			chain
				.process_block(
					&mut secp,
					b,
					Options::SKIP_POW,
					std::collections::HashSet::new(),
				)
				.unwrap();
		}

		// create a few keys for use in txns
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id30 = ExtKeychainPath::new(1, 30, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id31 = ExtKeychainPath::new(1, 31, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id32 = ExtKeychainPath::new(1, 32, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();

		// build a regular transaction so we have a rangeproof to copy
		let tx1 = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 20000u32.try_into().unwrap(),
			},
			&[
				build::coinbase_input(
					consensus::calc_mwc_block_reward(0, chain.head().unwrap().height),
					key_id2.clone(),
				),
				build::output(
					consensus::calc_mwc_block_reward(0, chain.head().unwrap().height) - 20000,
					key_id30.clone(),
				),
			],
			&kc,
			&pb,
		)
		.unwrap();

		// mine block with tx1
		let next = prepare_block_tx(&mut secp, &kc, &head, &chain, 7, &[tx1.clone()]);
		let prev_main = next.header.clone();
		chain
			.process_block(
				&mut secp,
				next.clone(),
				Options::SKIP_POW,
				std::collections::HashSet::new(),
			)
			.unwrap();
		chain.validate(&secp, false).unwrap();

		// create a second tx that contains a negative output
		// and a positive output for 1m mwc
		let tx2_fee = 20u32;
		let mut tx2 = build::transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: tx2_fee.try_into().unwrap(),
			},
			&[
				build::input(
					consensus::calc_mwc_block_reward(0, chain.head().unwrap().height) - 20000,
					key_id30.clone(),
				),
				build::output(
					consensus::calc_mwc_block_reward(0, chain.head().unwrap().height)
						- 20000 - u64::from(tx2_fee)
						+ 1_000_000_000_000_000,
					key_id31.clone(),
				),
				build_output_negative(1_000_000_000_000_000, key_id32.clone()),
			],
			&kc,
			&pb,
		)
		.unwrap();

		// make sure tx1 only has one output as expected
		assert_eq!(tx1.body.outputs.len(), 1);
		let last_rp = tx1.body.outputs[0].proof;

		// overwrite all our rangeproofs with the rangeproof from last block
		for i in 0..tx2.body.outputs.len() {
			tx2.body.outputs[i].proof = last_rp;
		}

		let next = prepare_block_tx(&mut secp, &kc, &prev_main, &chain, 8, &[tx2.clone()]);
		// process_block fails with verifier_cache disabled or with correct verifier_cache
		// implementations
		let res = chain.process_block(
			&mut secp,
			next,
			Options::SKIP_POW,
			std::collections::HashSet::new(),
		);

		assert!(matches!(
			res,
			Err(mwc_chain::Error::Block(block::Error::Transaction(
				transaction::Error::Secp(secp::Error::InvalidRangeProof)
			)))
		));
	}
	clean_output_dir(".mwc_overflow");
}

// Use diff as both diff *and* key_idx for convenience (deterministic private key for test blocks)
fn prepare_block<K>(
	secp: &mut Secp256k1,
	kc: &K,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
) -> Block
where
	K: Keychain,
{
	let key_idx = diff as u32;
	prepare_block_key_idx(secp, kc, prev, chain, diff, key_idx)
}

fn prepare_block_key_idx<K>(
	secp: &mut Secp256k1,
	kc: &K,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
	key_idx: u32,
) -> Block
where
	K: Keychain,
{
	let mut b = prepare_block_nosum(secp, kc, prev, diff, key_idx, &[]);
	chain.set_txhashset_roots(secp, &mut b).unwrap();
	b
}

// Use diff as both diff *and* key_idx for convenience (deterministic private key for test blocks)
fn prepare_block_tx<K>(
	secp: &mut Secp256k1,
	kc: &K,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
	txs: &[Transaction],
) -> Block
where
	K: Keychain,
{
	let key_idx = diff as u32;
	prepare_block_tx_key_idx(secp, kc, prev, chain, diff, key_idx, txs)
}

fn prepare_block_tx_key_idx<K>(
	secp: &mut Secp256k1,
	kc: &K,
	prev: &BlockHeader,
	chain: &Chain,
	diff: u64,
	key_idx: u32,
	txs: &[Transaction],
) -> Block
where
	K: Keychain,
{
	let mut b = prepare_block_nosum(secp, kc, prev, diff, key_idx, txs);
	chain.set_txhashset_roots(secp, &mut b).unwrap();
	b
}

fn prepare_block_nosum<K>(
	secp: &mut Secp256k1,
	kc: &K,
	prev: &BlockHeader,
	diff: u64,
	key_idx: u32,
	txs: &[Transaction],
) -> Block
where
	K: Keychain,
{
	let proof_size = global::proofsize(0);
	let key_id = ExtKeychainPath::new(1, key_idx, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();

	let fees = txs.iter().map(|tx| tx.fee().unwrap()).sum();
	let reward = libtx::reward::output(
		0,
		kc,
		&libtx::ProofBuilder::new(secp, kc).unwrap(),
		&key_id,
		fees,
		false,
		prev.height + 1,
		secp,
	)
	.unwrap();
	let mut b = match Block::new(0, prev, txs, Difficulty::from_num(diff), reward, secp) {
		Err(e) => panic!("{:?}", e),
		Ok(b) => b,
	};
	b.header.timestamp = prev.timestamp + Duration::seconds(60);
	b.header.pow.total_difficulty = (prev.total_difficulty() + Difficulty::from_num(diff)).unwrap();
	b.header.pow.proof = pow::Proof::random(0, proof_size).unwrap();
	b
}

#[test]
#[ignore]
fn actual_diff_iter_output() {
	global::set_local_chain_type(ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let genesis_block = global::get_genesis_block(&secp, 0).unwrap();
	let chain = Chain::init(
		&secp,
		0,
		"../.mwc".to_string(),
		Arc::new(NoopAdapter {}),
		genesis_block,
		pow::verify_size,
		false,
		HashSet::new(),
		None,
		None,
	)
	.unwrap();
	let iter = chain.difficulty_iter().unwrap();
	let mut last_time = 0;
	let mut first = true;
	for elem in iter.into_iter() {
		let elem = elem.unwrap();
		if first {
			last_time = elem.timestamp;
			first = false;
		}
		println!(
			"next_difficulty time: {}, diff: {}, duration: {} ",
			elem.timestamp,
			elem.difficulty.to_num(),
			last_time - elem.timestamp
		);
		last_time = elem.timestamp;
	}
}
