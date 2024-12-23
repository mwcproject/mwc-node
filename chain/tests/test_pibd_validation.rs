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

use mwc_chain as chain;
use mwc_core as core;
use mwc_util as util;

use std::sync::Arc;

use crate::chain::txhashset::BitmapAccumulator;
use crate::chain::types::NoopAdapter;
use crate::core::core::hash::Hashed;
use crate::core::core::pmmr;
use crate::core::{genesis, global, pow};

use croaring::Bitmap;
use mwc_chain::pibd_params;
use mwc_chain::txhashset::{BitmapChunk, Desegmenter};
use mwc_core::core::TxKernel;
use mwc_util::secp::constants;

mod chain_test_helper;

fn test_pibd_chain_validation_impl(is_test_chain: bool, src_root_dir: &str) {
	global::set_local_chain_type(global::ChainTypes::Mainnet);
	let mut genesis = genesis::genesis_main();
	// Height at which to read kernel segments (lower than thresholds defined in spec - for testing)

	if is_test_chain {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		genesis = pow::mine_genesis_block().unwrap();
	}

	{
		println!("Reading Chain, genesis block: {}", genesis.hash());
		let dummy_adapter = Arc::new(NoopAdapter {});

		// The original chain we're reading from
		let src_chain = Arc::new(
			chain::Chain::init(
				src_root_dir.into(),
				dummy_adapter.clone(),
				genesis.clone(),
				pow::verify_size,
				false,
			)
			.unwrap(),
		);

		// For test compaction purposes
		/*src_chain.compact().unwrap();
		src_chain
		.validate(true)
		.expect("Source chain validation failed, stop");*/

		let sh = src_chain.get_header_by_height(0).unwrap();
		println!("Source Genesis - {}", sh.hash());

		let horizon_header = src_chain.txhashset_archive_header().unwrap();

		println!("Horizon header: {:?}", horizon_header);

		// Copy the header from source to output
		// Not necessary for this test, we're just validating the source
		/*for h in 1..=horizon_height {
			let h = src_chain.get_header_by_height(h).unwrap();
			dest_chain.process_block_header(&h, options).unwrap();
		}*/

		// Init segmenter, (note this still has to be lazy init somewhere on a peer)
		// This is going to use the same block as horizon_header
		let segmenter = src_chain.segmenter().unwrap();

		let bitmap_root = segmenter.bitmap_root().unwrap();
		println!(
			"Bitmap segmenter reports output bitmap root hash is {:?}",
			bitmap_root
		);

		// BITMAP - Read + Validate, Also recreate bitmap accumulator for target tx hash set
		// Predict number of leaves (chunks) in the bitmap MMR from the number of outputs
		let bitmap_mmr_num_leaves =
			(pmmr::n_leaves(horizon_header.output_mmr_size) as f64 / 1024f64).ceil() as u64;
		println!("BITMAP PMMR NUM_LEAVES: {}", bitmap_mmr_num_leaves);

		// And total size of the bitmap PMMR
		let bitmap_pmmr_size = pmmr::peaks(bitmap_mmr_num_leaves)
			.last()
			.unwrap_or(&pmmr::insertion_to_pmmr_index(bitmap_mmr_num_leaves))
			.clone();
		println!("BITMAP PMMR SIZE: {}", bitmap_pmmr_size);
		let bitmap_segments = Desegmenter::generate_segments(
			BitmapChunk::LEN_BYTES,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			bitmap_pmmr_size,
			None,
		);
		println!("Bitmap Segments required: {}", bitmap_segments.len());

		let mut bitmap_accumulator = BitmapAccumulator::new();
		// Raw bitmap for validation
		let mut bitmap = Bitmap::new();
		let mut chunk_count = 0;

		for sid in bitmap_segments {
			println!("Getting bitmap segment with Segment Identifier {:?}", sid);
			let bitmap_segment = segmenter.bitmap_segment(sid).unwrap();
			// Validate bitmap segment with provided output hash
			if let Err(e) = bitmap_segment.validate(
				bitmap_pmmr_size, // Last MMR pos at the height being validated, in this case of the bitmap root
				None,
				&bitmap_root,
			) {
				panic!("Unable to validate bitmap_root: {}", e);
			}

			let (_sid, _hash_pos, _hashes, _leaf_pos, leaf_data, _proof) = bitmap_segment.parts();

			// Add to raw bitmap to use in further validation
			for chunk in leaf_data.iter() {
				bitmap.add_many(&chunk.set_iter(chunk_count * 1024).collect::<Vec<u32>>());
				chunk_count += 1;
			}

			// and append to bitmap accumulator
			for chunk in leaf_data.into_iter() {
				bitmap_accumulator.append_chunk(chunk).unwrap();
			}
		}

		println!("Accumulator Root: {}", bitmap_accumulator.root());

		let output_segments = Desegmenter::generate_segments(
			constants::PEDERSEN_COMMITMENT_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			horizon_header.output_mmr_size,
			Some(&bitmap),
		);
		for sid in output_segments {
			println!("Getting output segment with Segment Identifier {:?}", sid);
			let output_segment = segmenter.output_segment(sid).unwrap();
			// Validate Output
			if let Err(e) = output_segment.validate(
				horizon_header.output_mmr_size, // Last MMR pos at the height being validated
				Some(&bitmap),
				&horizon_header.output_root, // Output root we're checking for
			) {
				panic!("Unable to validate output segment root: {}", e);
			}
		}

		let rangeproof_segments = Desegmenter::generate_segments(
			constants::SINGLE_BULLET_PROOF_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			horizon_header.output_mmr_size,
			Some(&bitmap),
		);
		for sid in rangeproof_segments {
			println!(
				"Getting rangeproof segment with Segment Identifier {:?}",
				sid
			);
			let rangeproof_segment = segmenter.rangeproof_segment(sid).unwrap();
			// Validate Kernel segment (which does not require a bitmap)
			if let Err(e) = rangeproof_segment.validate(
				horizon_header.output_mmr_size, // Last MMR pos at the height being validated
				Some(&bitmap),
				&horizon_header.range_proof_root, // Output root we're checking for
			) {
				panic!("Unable to validate rangeproof segment root: {}", e);
			}
		}

		// KERNELS - Read + Validate
		let kernel_segments = Desegmenter::generate_segments(
			TxKernel::DATA_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			horizon_header.kernel_mmr_size,
			None,
		);
		for sid in kernel_segments {
			println!("Getting kernel segment with Segment Identifier {:?}", sid);
			let kernel_segment = segmenter.kernel_segment(sid).unwrap();
			// Validate Kernel segment (which does not require a bitmap)
			if let Err(e) = kernel_segment.validate(
				horizon_header.kernel_mmr_size,
				None,
				&horizon_header.kernel_root,
			) {
				panic!("Unable to validate kernel_segment root: {}", e);
			}
		}
	}
}

#[test]
#[ignore]
fn test_pibd_chain_validation_sample() {
	util::init_test_logger();
	// Note there is now a 'test' in mwc_wallet_controller/build_chain
	// that can be manually tweaked to create a
	// small test chain with actual transaction data

	// Test on uncompacted and non-compacted chains
	let src_root_dir = format!("./tests/test_data/chain_raw");
	test_pibd_chain_validation_impl(true, &src_root_dir);
	let src_root_dir = format!("./tests/test_data/chain_compacted");
	test_pibd_chain_validation_impl(true, &src_root_dir);
}

#[test]
#[ignore]
// As above, but run on a real instance of a chain pointed where you like
fn test_pibd_chain_validation_real() {
	util::init_test_logger();
	// if testing against a real chain, insert location here
	let src_root_dir = format!("/Users/bay/.mwc/main_orig/chain_data");
	test_pibd_chain_validation_impl(false, &src_root_dir);
}
