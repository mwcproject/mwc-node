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

use super::chain_test_helper::{clean_output_dir, init_chain, mine_chain};
use mwc_chain::store::PendingChainOperation;
use mwc_chain::types::NoopAdapter;
use mwc_chain::Chain;
use mwc_chain::Error;
use mwc_chain::Options;
use mwc_chain::Tip;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::{block, BlockHeader};
use mwc_core::{genesis, global, pow};
use mwc_crates::chrono::Duration;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

fn accept_pow(_: u32, _: &BlockHeader) -> Result<(), pow::Error> {
	Ok(())
}

fn reject_pow(_: u32, _: &BlockHeader) -> Result<(), pow::Error> {
	Err(pow::Error::Verification(
		"forced genesis PoW failure".into(),
	))
}

#[test]
fn check_known() {
	let chain_dir = ".mwc.check_known";
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	// mine some blocks
	let (latest, genesis) = {
		let chain = mine_chain(chain_dir, 3);
		let genesis = chain
			.get_block(&chain.get_header_by_height(0).unwrap().hash(0).unwrap())
			.unwrap();
		let head = chain.head().unwrap();
		let latest = chain.get_block(&head.last_block_h).unwrap();
		(latest, genesis)
	};

	// attempt to reprocess latest block
	{
		let chain = init_chain(&secp, chain_dir, genesis.clone(), true);
		let res = chain.process_block(
			&mut secp,
			latest.clone(),
			mwc_chain::Options::NONE,
			std::collections::HashSet::new(),
		);
		assert!(matches!( res, Err(Error::Unfit(ref s)) if s == "already known in head"));
	}

	// attempt to reprocess genesis block
	{
		let chain = init_chain(&secp, chain_dir, genesis.clone(), true);
		let res = chain.process_block(
			&mut secp,
			genesis.clone(),
			mwc_chain::Options::NONE,
			std::collections::HashSet::new(),
		);
		assert!(matches!( res, Err(Error::Unfit(ref s)) if s == "already known in store"));
	}

	// reset chain head to earlier state
	{
		let chain = init_chain(&secp, chain_dir, genesis.clone(), true);
		let store = chain.get_store_for_tests();
		let batch = store.batch_write().unwrap();
		let head_header = chain.head_header().unwrap();
		let prev = batch.get_previous_header(&head_header).unwrap();
		batch
			.save_body_head(&Tip::try_from_header(&prev).unwrap())
			.unwrap();
		batch.commit().unwrap();
	}

	// reprocess latest block and check the updated head
	{
		let chain = init_chain(&secp, chain_dir, genesis.clone(), true);
		let head = chain
			.process_block(
				&mut secp,
				latest.clone(),
				mwc_chain::Options::NONE,
				std::collections::HashSet::new(),
			)
			.unwrap();
		assert_eq!(head, Some(Tip::try_from_header(&latest.header).unwrap()));
	}

	clean_output_dir(chain_dir);
}

#[test]
fn full_block_known_hash_with_different_body_is_not_duplicate() {
	let chain_dir = ".mwc.full_block_known_hash_mismatch";
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let chain = mine_chain(chain_dir, 2);
	let head = chain.head().unwrap();
	let mut block = chain.get_block(&head.last_block_h).unwrap();
	assert!(!block.body.outputs.is_empty());
	let original_hash = block.hash(0).unwrap();

	block.body.outputs.pop();
	assert_eq!(block.hash(0).unwrap(), original_hash);

	let res = chain.process_block(
		&mut secp,
		block,
		Options::NONE,
		std::collections::HashSet::new(),
	);
	assert!(matches!(res, Err(ref e) if e.is_bad_data()), "{:?}", res);

	clean_output_dir(chain_dir);
}

#[test]
fn sync_headers_rejects_known_hash_with_different_header() {
	let chain_dir = ".mwc.sync_header_hash_mismatch";
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(chain_dir);

	let chain = mine_chain(chain_dir, 2);
	let sync_head = chain.header_head().unwrap();
	let original = chain.get_header_by_height(1).unwrap();
	let original_hash = original.hash(0).unwrap();

	let mut conflicting = original.clone();
	conflicting.timestamp = conflicting.timestamp + Duration::seconds(1);

	assert_ne!(conflicting, original);
	assert_eq!(conflicting.hash(0).unwrap(), original_hash);

	let res = chain.sync_block_headers(&[conflicting], sync_head, Options::SKIP_POW);
	assert!(matches!(
		res,
		Err(Error::Block(block::Error::Other(ref s)))
			if s == "known header hash matches a different header"
	));

	clean_output_dir(chain_dir);
}

#[test]
fn reset_to_genesis_rebuilds_missing_genesis_body_mmrs() {
	let chain_dir = ".mwc.reset_genesis_rebuild_mmrs";
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(chain_dir);
	global::set_local_chain_type(global::ChainTypes::Floonet);
	global::set_local_nrd_enabled(false);
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let genesis = genesis::genesis_floo(&secp, 0);
	let genesis_hash = genesis.hash(0).unwrap();
	assert!(genesis.header.output_mmr_size > 0);
	assert!(genesis.header.kernel_mmr_size > 0);

	{
		let chain = init_chain(&secp, chain_dir, genesis.clone(), true);
		chain
			.get_store_for_tests()
			.set_pending_chain_operation(&PendingChainOperation::ResetToGenesis)
			.unwrap();
		chain
			.get_txhashset_for_test()
			.write()
			.release_backend_files();
	}

	fs::remove_dir_all(Path::new(chain_dir).join("txhashset")).unwrap();

	let chain = init_chain(&secp, chain_dir, genesis.clone(), true);
	let genesis_header = chain.genesis();
	let roots = chain
		.get_txhashset_for_test()
		.read_recursive()
		.roots()
		.unwrap();
	roots.validate(&genesis_header).unwrap();
	assert_eq!(
		(
			roots.output_mmr_size,
			roots.rproof_mmr_size,
			roots.kernel_mmr_size
		),
		(
			genesis_header.output_mmr_size,
			genesis_header.output_mmr_size,
			genesis_header.kernel_mmr_size
		)
	);
	assert_eq!(chain.head().unwrap().last_block_h, genesis_hash);
	assert!(chain
		.get_store_for_tests()
		.pending_chain_operation()
		.unwrap()
		.is_none());

	clean_output_dir(chain_dir);
}

#[test]
fn reset_to_genesis_restores_genesis_metadata() {
	let chain_dir = ".mwc.reset_genesis_metadata";
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(chain_dir);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let chain = mine_chain(chain_dir, 3);
	let genesis_header = chain.get_header_by_height(0).unwrap();
	let genesis_hash = genesis_header.hash(0).unwrap();
	let first_header = chain.get_header_by_height(1).unwrap();
	let first_block = chain.get_block(&first_header.hash(0).unwrap()).unwrap();

	{
		let store = chain.get_store_for_tests();
		let batch = store.batch_write().unwrap();
		batch.delete_block(&genesis_hash).unwrap();
		batch.commit().unwrap();
	}
	assert!(chain.get_block(&genesis_hash).is_err());
	assert!(chain.get_block_sums(&genesis_hash).is_err());

	chain.reset_chain_head_to_genesis().unwrap();

	assert_eq!(chain.head().unwrap().last_block_h, genesis_hash);
	assert_eq!(chain.tail().unwrap().last_block_h, genesis_hash);
	assert!(chain.get_block(&genesis_hash).is_ok());
	assert!(chain.get_block_sums(&genesis_hash).is_ok());

	let head = chain
		.process_block(
			&mut secp,
			first_block.clone(),
			Options::NONE,
			std::collections::HashSet::new(),
		)
		.unwrap();
	assert_eq!(
		head,
		Some(Tip::try_from_header(&first_block.header).unwrap())
	);

	clean_output_dir(chain_dir);
}

#[test]
fn rejects_genesis_context_id_mismatch() {
	let chain_dir = ".mwc.genesis_context_mismatch";
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	clean_output_dir(chain_dir);

	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	let res = Chain::init(
		&secp,
		1,
		chain_dir.to_string(),
		Arc::new(NoopAdapter {}),
		global::get_genesis_block(&secp, 0).unwrap(),
		pow::verify_size,
		false,
		HashSet::new(),
		None,
		None,
		true,
	);
	assert!(matches!(res, Err(Error::InvalidGenesisHash)));
	assert!(!Path::new(chain_dir).exists());

	let valid_genesis = global::get_genesis_block(&secp, 1).unwrap();
	let valid_genesis_hash = valid_genesis.hash(1).unwrap();
	{
		let chain = Chain::init(
			&secp,
			1,
			chain_dir.to_string(),
			Arc::new(NoopAdapter {}),
			valid_genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			true,
		)
		.unwrap();
		assert_eq!(chain.head().unwrap().last_block_h, valid_genesis_hash);
	}

	clean_output_dir(chain_dir);
}

#[test]
fn rejects_genesis_with_invalid_height() {
	let chain_dir = ".mwc.genesis_invalid_height";
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	clean_output_dir(chain_dir);

	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let mut invalid_genesis = global::get_genesis_block(&secp, 0).unwrap();
	invalid_genesis.header.height = 1;

	let res = Chain::init(
		&secp,
		0,
		chain_dir.to_string(),
		Arc::new(NoopAdapter {}),
		invalid_genesis,
		pow::verify_size,
		false,
		HashSet::new(),
		None,
		None,
		true,
	);
	assert!(matches!(res, Err(Error::InvalidGenesisHash)));
	assert!(!Path::new(chain_dir).exists());
}

#[test]
fn rejects_genesis_with_invalid_pow() {
	let chain_dir = ".mwc.genesis_invalid_pow";
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	clean_output_dir(chain_dir);

	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let valid_genesis = global::get_genesis_block(&secp, 0).unwrap();

	let res = Chain::init(
		&secp,
		0,
		chain_dir.to_string(),
		Arc::new(NoopAdapter {}),
		valid_genesis,
		reject_pow,
		false,
		HashSet::new(),
		None,
		None,
		true,
	);
	assert!(matches!(res, Err(Error::InvalidPow)));
	assert!(!Path::new(chain_dir).exists());
}

#[test]
fn rejects_production_genesis_with_mutated_txhashset_commitments() {
	let chain_dir = ".mwc.genesis_invalid_txhashset";
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::Floonet);
	global::set_local_nrd_enabled(false);
	clean_output_dir(chain_dir);

	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let mut invalid_genesis = genesis::genesis_floo(&secp, 0);
	invalid_genesis.header.output_root = Hash::from_vec(&[42]);

	let res = Chain::init(
		&secp,
		0,
		chain_dir.to_string(),
		Arc::new(NoopAdapter {}),
		invalid_genesis,
		accept_pow,
		false,
		HashSet::new(),
		None,
		None,
		true,
	);
	assert!(matches!(res, Err(Error::InvalidGenesisHash)));

	clean_output_dir(chain_dir);
}

#[test]
fn rejects_genesis_hash_mismatch_with_existing_chain_data() {
	let chain_dir = ".mwc.genesis_hash_mismatch";
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	clean_output_dir(chain_dir);

	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let valid_genesis = global::get_genesis_block(&secp, 0).unwrap();
	let valid_genesis_hash = valid_genesis.hash(0).unwrap();

	{
		let chain = Chain::init(
			&secp,
			0,
			chain_dir.to_string(),
			Arc::new(NoopAdapter {}),
			valid_genesis.clone(),
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			true,
		)
		.unwrap();
		assert_eq!(chain.head().unwrap().last_block_h, valid_genesis_hash);
	}

	let mut invalid_genesis = valid_genesis.clone();
	invalid_genesis.header.pow.proof.nonces[0] += 1;
	let invalid_genesis_hash = invalid_genesis.hash(0).unwrap();
	assert_ne!(invalid_genesis_hash, valid_genesis_hash);

	let res = Chain::init(
		&secp,
		0,
		chain_dir.to_string(),
		Arc::new(NoopAdapter {}),
		invalid_genesis,
		accept_pow,
		false,
		HashSet::new(),
		None,
		None,
		true,
	);
	assert!(matches!(res, Err(Error::InvalidGenesisHash)));

	{
		let chain = Chain::init(
			&secp,
			0,
			chain_dir.to_string(),
			Arc::new(NoopAdapter {}),
			valid_genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			true,
		)
		.unwrap();
		assert_eq!(chain.head().unwrap().last_block_h, valid_genesis_hash);
		assert!(chain.get_block_header(&invalid_genesis_hash).is_err());
	}

	clean_output_dir(chain_dir);
}
