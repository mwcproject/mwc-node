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

use mwc_chain::pibd_params::PibdParams;
use mwc_chain::txhashset::BitmapChunk;
use mwc_chain::txhashset::{Desegmenter, HeaderHashesDesegmenter, HeadersRecieveCache};
use mwc_chain::types::NoopAdapter;
use mwc_chain::types::HEADERS_PER_BATCH;
use mwc_chain::{Error, Options, SyncState};
use mwc_core::core::{
	hash::{Hash, Hashed},
	pmmr::segment::{Segment, SegmentIdentifier, SegmentType},
	Block, OutputIdentifier, TxKernel,
};
use mwc_core::{genesis, global, pow};
use mwc_crates::log::debug;
use mwc_crates::rand::prelude::IndexedRandom;
use mwc_crates::rand::seq::SliceRandom;
use mwc_crates::rand::{rng, RngExt};
use mwc_crates::secp::pedersen::RangeProof;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_util::StopState;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use std::{cmp, fs, io};

use super::chain_test_helper::{clean_output_dir, init_chain, test_chain_dir};

fn _copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
	fs::create_dir_all(&dst)?;
	for entry in fs::read_dir(src)? {
		let entry = entry?;
		let ty = entry.file_type()?;
		if ty.is_dir() {
			_copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
		} else {
			fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
		}
	}
	Ok(())
}

// segmenter responder, which will simulate feeding back segments as requested
// by the desegmenter
struct SegmenterResponder {
	chain: Arc<mwc_chain::Chain>,
}

impl SegmenterResponder {
	pub fn new(secp: &Secp256k1, chain_src_dir: &str, genesis: Block) -> Self {
		let dummy_adapter = Arc::new(NoopAdapter {});
		debug!(
			"Reading SegmenterResponder chain, genesis block: {}",
			genesis.hash(0).unwrap()
		);

		// The original chain we're reading from
		let res = SegmenterResponder {
			chain: Arc::new(
				mwc_chain::Chain::init(
					secp,
					0,
					chain_src_dir.into(),
					dummy_adapter.clone(),
					genesis,
					pow::verify_size,
					false,
					HashSet::new(),
					None,
					None,
				)
				.unwrap(),
			),
		};
		let sh = res.chain.get_header_by_height(0).unwrap();
		debug!("Source Genesis - {}", sh.hash(0).unwrap());
		res
	}

	pub fn chain(&self) -> Arc<mwc_chain::Chain> {
		self.chain.clone()
	}

	pub fn get_headers_root_hash(&self) -> Hash {
		self.chain.segmenter().unwrap().headers_root().unwrap()
	}

	pub fn get_headers_segment(&self, seg_id: SegmentIdentifier) -> Segment<Hash> {
		let segmenter = self.chain.segmenter().unwrap();
		segmenter.headers_segment(seg_id).unwrap()
	}

	pub fn get_bitmap_root_hash(&self) -> Hash {
		self.chain.segmenter().unwrap().bitmap_root().unwrap()
	}

	pub fn get_bitmap_segment(&self, seg_id: SegmentIdentifier) -> Segment<BitmapChunk> {
		let segmenter = self.chain.segmenter().unwrap();
		segmenter.bitmap_segment(seg_id).unwrap()
	}

	pub fn get_output_segment(&self, seg_id: SegmentIdentifier) -> Segment<OutputIdentifier> {
		let segmenter = self.chain.segmenter().unwrap();
		segmenter.output_segment(seg_id).unwrap()
	}

	pub fn get_rangeproof_segment(&self, seg_id: SegmentIdentifier) -> Segment<RangeProof> {
		let segmenter = self.chain.segmenter().unwrap();
		segmenter.rangeproof_segment(seg_id).unwrap()
	}

	pub fn get_kernel_segment(&self, seg_id: SegmentIdentifier) -> Segment<TxKernel> {
		let segmenter = self.chain.segmenter().unwrap();
		segmenter.kernel_segment(seg_id).unwrap()
	}
}

// Canned segmenter 'peer', building up its local chain from requested PIBD segments
struct DesegmenterRequestor {
	chain: Arc<mwc_chain::Chain>,
	responder: Arc<SegmenterResponder>,
}

impl DesegmenterRequestor {
	pub fn new(
		secp: &Secp256k1,
		chain_src_dir: &str,
		genesis: Block,
		responder: Arc<SegmenterResponder>,
	) -> Self {
		let dummy_adapter = Arc::new(NoopAdapter {});
		debug!(
			"Reading DesegmenterRequestor chain, genesis block: {}",
			genesis.hash(0).unwrap()
		);

		// The original chain we're reading from
		let res = DesegmenterRequestor {
			chain: Arc::new(
				mwc_chain::Chain::init(
					secp,
					0,
					chain_src_dir.into(),
					dummy_adapter.clone(),
					genesis,
					pow::verify_size,
					false,
					HashSet::new(),
					None,
					None,
				)
				.unwrap(),
			),
			responder,
		};
		let sh = res.chain.get_header_by_height(0).unwrap();
		debug!("Dest Genesis - {}", sh.hash(0).unwrap());
		res
	}

	pub fn init_desegmenter(
		&mut self,
		archive_header_height: u64,
		bitmap_root_hash: Hash,
	) -> Desegmenter {
		self.chain.reset_pibd_chain().unwrap();

		self.chain
			.init_desegmenter(archive_header_height, bitmap_root_hash)
			.unwrap()
	}

	// return whether is complete
	pub fn continue_headers_pibd(
		&mut self,
		header_desegmenter: &mut HeaderHashesDesegmenter,
		header_root_hash: &Hash,
	) -> bool {
		let empty_map: HashMap<(SegmentType, u64), u8> = HashMap::new();
		let empty_map = &empty_map;
		let asks = header_desegmenter
			.next_desired_segments(10, &empty_map)
			.unwrap();

		debug!("Next segment IDS: {:?}", asks);

		// let's satisfy one item...
		if asks.is_empty() {
			assert!(header_desegmenter.is_complete());
			return true;
		}

		let mut rng = rng();
		let target_segment = asks.choose(&mut rng).unwrap();

		debug!("Applying segment: {:?}", target_segment);

		let segment = self.responder.get_headers_segment(target_segment.clone());
		header_desegmenter
			.add_headers_hash_segment(segment, header_root_hash)
			.unwrap();

		false
	}

	// return whether is complete
	pub fn continue_copy_headers(
		&mut self,
		header_desegmenter: &HeaderHashesDesegmenter,
		headers_cache: &mut HeadersRecieveCache,
	) -> bool {
		if headers_cache.is_complete().unwrap() {
			return true;
		}
		let empty_map: HashMap<Hash, u8> = HashMap::new();
		let empty_map = &empty_map;
		let (hashes, _reply_hashes, _) = headers_cache
			.next_desired_headers(header_desegmenter, 15, &empty_map, 100)
			.unwrap();
		if hashes.is_empty() {
			assert!(false);
			return false;
		}

		debug!("Next hashes requested: {:?}", hashes);

		let mut rng = rng();
		let target_hash = hashes.choose(&mut rng).unwrap().0;

		debug!("Selected Hash: {:?}", target_hash);

		let src_chain = self.responder.chain();

		// Code similar to what we have at locate_headers
		{
			let max_height = src_chain.header_head().unwrap().height;

			let header_pmmr = src_chain.get_header_pmmr_for_test();
			let header_pmmr = header_pmmr.read_recursive();

			let header = src_chain.get_block_header(&target_hash).unwrap();

			// looks like we know one, getting as many following headers as allowed
			let hh = header.height;

			let mut headers = vec![];
			for h in (hh + 1)..=(hh + (HEADERS_PER_BATCH as u64)) {
				if h > max_height {
					break;
				}

				if let Ok(hash) = header_pmmr.get_header_hash_by_height(h) {
					let header = src_chain.get_block_header(&hash).unwrap();
					headers.push(header);
				} else {
					panic!("Failed to locate headers successfully.");
				}
			}

			assert_eq!(headers.len(), HEADERS_PER_BATCH as usize);
			if let Err((peer, err)) =
				headers_cache.add_headers_to_cache(header_desegmenter, headers, "0".to_string())
			{
				panic!("Error {}, for peer id {}", err, peer);
			}
			while headers_cache.apply_cache().unwrap() {
				debug!("Applying headers cache once more...");
			}
		}

		false
	}

	// Emulate `continue_pibd` function, which would be called from state sync
	// return whether is complete
	pub fn continue_pibd(&mut self, bitmap_root_hash: Hash, desegmenter: &Desegmenter) -> bool {
		//let archive_header = self.chain.txhashset_archive_header_header_only().unwrap();

		// Figure out the next segments we need
		// (12 is divisible by 3, to try and evenly spread the requests among the 3
		// main pmmrs. Bitmaps segments will always be requested first)
		let now = Instant::now();
		let empty_map: HashMap<(SegmentType, u64), u8> = HashMap::new();
		let empty_map = &empty_map;
		let (mut next_segment_ids, _retry_ids, _) =
			desegmenter.next_desired_segments(60, &empty_map).unwrap();
		debug!("next_desired_segments took {}ms", now.elapsed().as_millis());
		let is_complete = desegmenter.is_complete();

		debug!("Next segment IDS: {:?}", next_segment_ids);
		let mut rng = rng();
		next_segment_ids.shuffle(&mut rng);

		// For each segment, pick a desirable peer and send message
		for seg_id in next_segment_ids.iter() {
			// Perform request and response
			match seg_id.segment_type {
				SegmentType::Bitmap => {
					let seg = self.responder.get_bitmap_segment(seg_id.identifier.clone());
					let now = Instant::now();
					desegmenter
						.add_bitmap_segment(seg, &bitmap_root_hash)
						.unwrap();
					debug!("next_desired_segments took {}ms", now.elapsed().as_millis());
				}
				SegmentType::Output => {
					let seg = self.responder.get_output_segment(seg_id.identifier.clone());
					let now = Instant::now();
					let id = seg.id().clone();
					desegmenter
						.add_output_segment(seg, &bitmap_root_hash)
						.unwrap();
					debug!(
						"Added output segment {}, took {}ms",
						id,
						now.elapsed().as_millis()
					);
				}
				SegmentType::RangeProof => {
					let seg = self
						.responder
						.get_rangeproof_segment(seg_id.identifier.clone());
					let now = Instant::now();
					let id = seg.id().clone();
					desegmenter
						.add_rangeproof_segment(seg, &bitmap_root_hash)
						.unwrap();
					debug!(
						"Added rangeproof segment {}, took {}ms",
						id,
						now.elapsed().as_millis()
					);
				}
				SegmentType::Kernel => {
					let seg = self.responder.get_kernel_segment(seg_id.identifier.clone());
					let now = Instant::now();
					let id = seg.id().clone();
					desegmenter
						.add_kernel_segment(seg, &bitmap_root_hash)
						.unwrap();
					debug!(
						"Added kernels segment {}, took {}ms",
						id,
						now.elapsed().as_millis()
					);
				}
			};
		}
		is_complete
	}

	pub fn check_roots(&self, archive_header_height: u64) {
		let roots = self
			.chain
			.get_txhashset_for_test()
			.read_recursive()
			.roots()
			.unwrap();
		let archive_header = self
			.chain
			.get_header_by_height(archive_header_height)
			.unwrap();
		debug!("Archive Header is {:?}", archive_header);
		debug!("TXHashset output root is {:?}", roots);
		debug!("TXHashset merged output root is {:?}", roots.output_root);
		assert_eq!(archive_header.range_proof_root, roots.rproof_root);
		assert_eq!(archive_header.kernel_root, roots.kernel_root);
		assert_eq!(archive_header.output_root, roots.output_root);
	}

	pub fn validate_complete_state(&self, desegmenter: &Desegmenter) {
		let status = Arc::new(SyncState::new());
		let stop_state = Arc::new(StopState::new());

		desegmenter.check_update_leaf_set_state().unwrap();

		desegmenter
			.validate_complete_state(status, stop_state)
			.unwrap();
	}
}
fn test_pibd_copy_impl(secp: &Secp256k1, src_root_dir: &str, dest_root_dir: &str) {
	global::set_local_chain_type(global::ChainTypes::Floonet);
	global::set_local_nrd_enabled(false);
	let genesis = genesis::genesis_floo(secp, 0);

	let src_responder = Arc::new(SegmenterResponder::new(secp, src_root_dir, genesis.clone()));

	let archive_header_height = src_responder
		.chain
		.txhashset_archive_header_header_only()
		.unwrap()
		.height;

	let headers_root_hash = src_responder.get_headers_root_hash();
	let bitmap_root_hash = src_responder.get_bitmap_root_hash();
	let genesis_hash = src_responder.chain.genesis().hash(0).unwrap();

	let pibd_params = Arc::new(PibdParams::new());

	let mut dest_requestor =
		DesegmenterRequestor::new(secp, dest_root_dir, genesis.clone(), src_responder);

	let mut header_desegmenter = HeaderHashesDesegmenter::new(
		0,
		genesis_hash,
		archive_header_height,
		headers_root_hash,
		pibd_params.clone(),
	)
	.unwrap();

	while !dest_requestor.continue_headers_pibd(&mut header_desegmenter, &headers_root_hash) {}

	// Heads must be done. Now we should be able to request series of headers as we can do now
	let mut headers_cache =
		HeadersRecieveCache::new(dest_requestor.chain.clone(), &header_desegmenter).unwrap();

	while !dest_requestor.continue_copy_headers(&header_desegmenter, &mut headers_cache) {}

	let desegmenter = dest_requestor.init_desegmenter(archive_header_height, bitmap_root_hash);

	// Perform until desegmenter reports it's done
	while !dest_requestor.continue_pibd(bitmap_root_hash, &desegmenter) {}

	dest_requestor.check_roots(archive_header_height);

	dest_requestor.validate_complete_state(&desegmenter);
}

#[test]
fn headers_receive_cache_rejects_missing_header_hash_entry() {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);

	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = test_chain_dir("headers_receive_cache_missing_header_hash");
	clean_output_dir(&chain_dir);
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = Arc::new(init_chain(&secp, &chain_dir, genesis.clone()));
	let context_id = chain.get_context_id();
	let header_desegmenter = HeaderHashesDesegmenter::new(
		context_id,
		genesis.hash(context_id).unwrap(),
		u64::from(HEADERS_PER_BATCH),
		Hash::default(),
		Arc::new(PibdParams::new()),
	)
	.unwrap();

	let res = HeadersRecieveCache::<String>::new(chain.clone(), &header_desegmenter);
	assert!(matches!(
		res,
		Err(Error::Other(msg)) if msg.contains("missing header hash at index 0")
	));

	mwc_chain::pipe::release_context_data(context_id);
	clean_output_dir(&chain_dir);
}

#[test]
#[ignore]
// Note this test is intended to be run manually, as testing the copy of an
// entire live chain is beyond the capability of current CI
// As above, but run on a real instance of a chain pointed where you like
fn test_pibd_copy_real() {
	mwc_util::init_test_logger().unwrap();

	// if testing against a real chain, insert location here
	let src_root_dir = format!("/Users/bay/.mwc/floo_orig");
	let dest_root_dir = format!("/Users/bay/.mwc/floo_copy");
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	//super::chain_test_helper::clean_output_dir(&dest_root_dir);
	test_pibd_copy_impl(&secp, &src_root_dir, &dest_root_dir);

	//super::chain_test_helper::clean_output_dir(&dest_root_dir);
}

#[test]
#[ignore]
// After test_pibd_copy_real() call we need to validate the blockchain. This test is designed for profiling
// and optimization test. That is why it is done separately, we want to be able workd with small steps.
fn test_chain_validation() {
	mwc_util::init_test_logger().unwrap();

	let src_root_dir = format!("/Users/bay/.mwc/main_orig/chain_data");
	let dest_root_dir = format!("/Users/bay/.mwc/main_copy/chain_data");

	global::set_local_chain_type(global::ChainTypes::Mainnet);
	global::set_local_nrd_enabled(true);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let genesis = genesis::genesis_main(&secp, 0);

	let dummy_adapter = Arc::new(NoopAdapter {});

	// The original chain we're reading from
	let src_chain = mwc_chain::Chain::init(
		&secp,
		0,
		src_root_dir.into(),
		dummy_adapter.clone(),
		genesis.clone(),
		pow::verify_size,
		false,
		HashSet::new(),
		None,
		None,
	)
	.unwrap();

	let dst_chain = mwc_chain::Chain::init(
		&secp,
		0,
		dest_root_dir.into(),
		dummy_adapter.clone(),
		genesis,
		pow::verify_size,
		false,
		HashSet::new(),
		None,
		None,
	)
	.unwrap();

	let dst_head = dst_chain.head().unwrap();
	let src_head = src_chain.head().unwrap();

	debug!(
		"Starting sync process. src_head {}  dst_head {}",
		src_head.height, dst_head.height
	);

	// see BodySync::body_sync  for details. We are trying to mimic this logic

	let mut headers_are_done = false;
	let mut blocks_are_done = false;

	let mut rng = rng();

	while !headers_are_done || !blocks_are_done {
		if rng.random_range(0..100) == 5 {
			// requesting more headers
			let header_head = dst_chain.header_head().unwrap();

			// looks like we know one, getting as many following headers as allowed
			let hh = header_head.height;

			let mut headers = vec![];
			for h in (hh + 1)..=(hh + (HEADERS_PER_BATCH as u64)) {
				if let Ok(header) = src_chain.get_header_by_height(h) {
					headers.push(header);
				} else {
					break;
				}
			}

			debug!(
				"Synching headers. Requested from height {}. Got {} items",
				header_head.height,
				headers.len()
			);

			if !headers.is_empty() {
				dst_chain
					.sync_block_headers(&headers, header_head, Options::NONE)
					.unwrap();
				headers_are_done = false;
			} else {
				headers_are_done = true;
			}
		} else {
			// let's sync with one block
			let header_head = dst_chain.header_head().unwrap();
			let fork_point = dst_chain.fork_point().unwrap();

			debug!(
				"header_head at {}, fork_point at {}",
				header_head.height, fork_point.height
			);

			// here is what we have at block_hashes_to_sync
			let count = 256;
			let mut hashes = vec![];
			let max_height = cmp::min(fork_point.height + count, header_head.height);
			let mut current = dst_chain.get_header_by_height(max_height).unwrap();
			while current.height > fork_point.height {
				let current_hash = current.hash(0).unwrap();
				if !dst_chain.is_orphan(&current_hash) {
					hashes.push(current_hash);
				}
				current = dst_chain.get_previous_header(&current).unwrap();
			}
			hashes.reverse();

			// Now select random hash so we get a block for it....
			if hashes.is_empty() {
				debug!("No new blocks are NOT needed (2)!");
				blocks_are_done = true;
				continue;
			}

			blocks_are_done = false;

			let block_hash = hashes.choose(&mut rng).unwrap();
			let block = src_chain.get_block(block_hash).unwrap();

			debug!(
				"Request size: {},  requested block {} at height {}",
				hashes.len(),
				block_hash,
				block.header.height
			);

			// Code similar to what we have in Adapters
			if dst_chain.is_known(&block.header).is_err() {
				panic!("block expected to be know");
			}

			match dst_chain.process_block(
				&mut secp,
				block,
				Options::NONE,
				std::collections::HashSet::new(),
			) {
				Ok(tip) => debug!("Accepted SOME!!! New tip now at {}", tip.unwrap().height),
				Err(Error::Orphan(_)) => {}
				Err(e) => panic!("Unexpected error is occured, {}", e),
			}
		}
	}

	let dst_head = dst_chain.head().unwrap();
	let src_head = src_chain.head().unwrap();

	debug!(
		"Full sync is done. src_head {}  dst_head {}",
		src_head.height, dst_head.height
	);

	//dst_chain.validate(true).unwrap();
	debug!("DST chain validation is done");
}
