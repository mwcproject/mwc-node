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

use mwc_chain::txhashset::BitmapChunk;
use mwc_chain::txhashset::StateSegment;
use mwc_chain::txhashset::{Desegmenter, HeaderHashesDesegmenter};
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
use mwc_crates::rand::seq::SliceRandom;
use mwc_crates::rand::{rng, RngExt};
use mwc_crates::secp::pedersen::RangeProof;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_util::StopState;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::{fs, io};

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
					false,
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
					false,
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
		self.chain
			.reset_pibd_chain(crate::PibdResetMode::Body)
			.unwrap();

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
		assert_eq!(header_desegmenter.get_headers_root_hash(), header_root_hash);
		// Deliver a window out of order, authenticate each response, then apply
		// the validated hashes in layout order. The caller owns the buffers.
		let ids = header_desegmenter.next_segments(0, 10).unwrap();
		let mut order: Vec<_> = (0..ids.len()).collect();
		order.shuffle(&mut rng());
		let mut received: Vec<_> = ids.iter().map(|_| None).collect();
		for index in order {
			let segment = self.responder.get_headers_segment(ids[index]);
			received[index] = Some(header_desegmenter.validate_segment(segment).unwrap());
		}
		for segment in received {
			header_desegmenter.apply_segment(&segment.unwrap()).unwrap();
		}
		header_desegmenter.is_complete()
	}

	// return whether is complete
	pub fn continue_copy_headers(&mut self, header_desegmenter: &HeaderHashesDesegmenter) -> bool {
		let tip = self.chain.header_head().unwrap();
		let target = header_desegmenter.get_target_height();
		if tip.height >= target {
			return true;
		}
		let hashes = header_desegmenter.get_header_hashes().unwrap();
		let index = (tip.height / HEADERS_PER_BATCH as u64) as usize;
		let src_chain = self.responder.chain();
		let start = src_chain.get_block_header(&hashes[index]).unwrap().height;
		let headers = ((start + 1)..=(start + HEADERS_PER_BATCH as u64).min(target))
			.map(|height| src_chain.get_header_by_height(height).unwrap())
			.collect::<Vec<_>>();
		let time = crate::store::header_creation_time(headers.last().unwrap()).unwrap();
		self.chain
			.sync_block_headers(&headers, Options::NONE, time)
			.unwrap();
		false
	}

	// Emulate `continue_pibd` function, which would be called from state sync
	// return whether is complete
	pub fn continue_pibd(&mut self, bitmap_root_hash: Hash, desegmenter: &Desegmenter) -> bool {
		assert_eq!(&bitmap_root_hash, desegmenter.get_bitmap_root_hash());
		// The caller now owns the response window. Deliver segments out of order,
		// authenticate them immediately, then apply the window in stream order.
		let mut tasks = Vec::new();
		for kind in [
			SegmentType::Bitmap,
			SegmentType::Output,
			SegmentType::RangeProof,
			SegmentType::Kernel,
		] {
			tasks.extend(
				desegmenter
					.next_segments(&kind, 0, 60)
					.unwrap()
					.into_iter()
					.map(|id| (id, None)),
			);
		}
		let mut order: Vec<_> = (0..tasks.len()).collect();
		order.shuffle(&mut rng());
		for index in order {
			let id = tasks[index].0.clone();
			let segment = match id.segment_type {
				SegmentType::Bitmap => {
					StateSegment::Bitmap(self.responder.get_bitmap_segment(id.identifier))
				}
				SegmentType::Output => {
					StateSegment::Output(self.responder.get_output_segment(id.identifier))
				}
				SegmentType::RangeProof => {
					StateSegment::RangeProof(self.responder.get_rangeproof_segment(id.identifier))
				}
				SegmentType::Kernel => {
					StateSegment::Kernel(self.responder.get_kernel_segment(id.identifier))
				}
			};
			tasks[index].1 = Some(desegmenter.validate_segment(segment).unwrap());
		}
		// The complete requested window is ready; tasks were created in stream order.
		for (_, segment) in tasks {
			desegmenter.apply_segment(&segment.unwrap()).unwrap();
		}
		desegmenter.is_complete()
	}

	pub fn check_roots(&self, archive_header_height: u64) {
		let roots = self.chain.get_txhashset_for_test().read().roots().unwrap();
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

	let mut dest_requestor =
		DesegmenterRequestor::new(secp, dest_root_dir, genesis.clone(), src_responder);

	let mut header_desegmenter =
		HeaderHashesDesegmenter::new(0, genesis_hash, archive_header_height, headers_root_hash)
			.unwrap();

	while !dest_requestor.continue_headers_pibd(&mut header_desegmenter, &headers_root_hash) {}

	// Copy the headers selected by the authenticated checkpoint list.
	while !dest_requestor.continue_copy_headers(&header_desegmenter) {}

	let desegmenter = dest_requestor.init_desegmenter(archive_header_height, bitmap_root_hash);

	// Perform until desegmenter reports it's done
	while !dest_requestor.continue_pibd(bitmap_root_hash, &desegmenter) {}

	dest_requestor.check_roots(archive_header_height);

	dest_requestor.validate_complete_state(&desegmenter);
}

#[test]
fn checkpoint_hashes_are_unavailable_until_complete() {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);

	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let chain_dir = test_chain_dir("checkpoint_hashes_incomplete");
	clean_output_dir(&chain_dir);
	let genesis = global::get_genesis_block(&secp, 0).unwrap();
	let chain = Arc::new(init_chain(&secp, &chain_dir, genesis.clone()));
	let context_id = chain.get_context_id();
	let header_desegmenter = HeaderHashesDesegmenter::new(
		context_id,
		genesis.hash(context_id).unwrap(),
		u64::from(HEADERS_PER_BATCH),
		Hash::default(),
	)
	.unwrap();

	let res = header_desegmenter.get_header_hashes();
	assert!(matches!(
		res,
		Err(Error::Other(msg)) if msg.contains("not complete")
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
		false,
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
		false,
	)
	.unwrap();

	let dst_head = dst_chain.head().unwrap();
	let src_head = src_chain.head().unwrap();

	debug!(
		"Starting sync process. src_head {}  dst_head {}",
		src_head.height, dst_head.height
	);

	// Continue downloading headers and applying bodies after the snapshot import.

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
				let base_time =
					crate::store::header_creation_time(headers.last().unwrap()).unwrap();
				dst_chain
					.sync_block_headers(&headers, Options::NONE, base_time)
					.unwrap();
				headers_are_done = false;
			} else {
				headers_are_done = true;
			}
		} else {
			// After the snapshot and headers are ready, apply bodies in chain order.
			// Out-of-order network buffering is covered by the BodySync task tests.
			let header_head = dst_chain.header_head().unwrap();
			let fork_point = dst_chain.fork_point().unwrap();
			blocks_are_done = fork_point.height == header_head.height;
			for height in (fork_point.height + 1)..=header_head.height {
				let header = dst_chain.get_header_by_height(height).unwrap();
				let block = src_chain.get_block_for_header(&header).unwrap();
				match dst_chain.process_block(
					&mut secp,
					block,
					Options::NONE,
					std::collections::HashSet::new(),
				) {
					Ok(_) => {}
					Err(error) if error.is_known_block() => {}
					Err(error) => panic!("Body synchronization failed: {}", error),
				}
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
