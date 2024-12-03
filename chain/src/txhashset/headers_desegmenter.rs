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

//! Manages the reconsitution of a headers from segments produced by the
//! segmenter

use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::pmmr;
use crate::core::core::{BlockHeader, Segment};
use crate::error::Error;
use crate::pibd_params::PibdParams;
use crate::txhashset::segments_cache::SegmentsCache;
use crate::txhashset::{sort_pmmr_hashes_and_leaves, OrderedHashLeafNode};
use crate::types::HEADERS_PER_BATCH;
use crate::Options;
use mwc_core::core::pmmr::{VecBackend, PMMR};
use mwc_core::core::{SegmentIdentifier, SegmentType};
use std::cmp;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// There is no reasons to introduce a special type, for that. For place maker any type will work
pub const HEADER_HASHES_STUB_TYPE: SegmentType = SegmentType::Bitmap;

/// Desegmenter for rebuilding a header_pmmr from PIBD segments
pub struct HeaderHashesDesegmenter {
	genesis_hash: Hash,
	header_pmmr: VecBackend<Hash>,
	target_height: u64,
	headers_root_hash: Hash, // target height and headers_root_hash must be get as a result of handshake process.
	header_pmmr_size: u64,

	header_segment_cache: SegmentsCache<Hash>,
	pibd_params: Arc<PibdParams>,
}

impl HeaderHashesDesegmenter {
	/// Create a new segmenter based on the provided txhashset and the specified block header
	pub fn new(
		genesis_hash: Hash,
		target_height: u64,
		headers_root_hash: Hash, // target height and headers_root_hash must be get as a result of handshake process.
		pibd_params: Arc<PibdParams>,
	) -> Self {
		let size = 1u64 << pibd_params.get_headers_segment_height();
		let n_leaves = target_height / HEADERS_PER_BATCH as u64 + 1;
		let need_segments = (n_leaves + size - 1) / size;

		let header_pmmr_size = pmmr::insertion_to_pmmr_index(n_leaves);

		HeaderHashesDesegmenter {
			genesis_hash,
			header_pmmr: VecBackend::new(),
			target_height,
			headers_root_hash,
			header_pmmr_size,
			header_segment_cache: SegmentsCache::new(HEADER_HASHES_STUB_TYPE, need_segments),
			pibd_params,
		}
	}

	/// Get number of completed segments
	pub fn get_segments_completed(&self) -> u64 {
		self.header_segment_cache.get_received_segments()
	}

	/// Get number of total segments
	pub fn get_segments_total(&self) -> u64 {
		self.header_segment_cache.get_required_segments()
	}

	/// Reset all state
	pub fn reset(&mut self) {
		self.header_segment_cache.reset();
	}

	/// Whether we have all the segments we need
	pub fn is_complete(&self) -> bool {
		self.header_segment_cache.is_complete()
	}

	/// get Root hash for all headers
	pub fn get_headers_root_hash(&self) -> &Hash {
		return &self.headers_root_hash;
	}

	/// Get PIBD height to retrieve data for. Normally it is archive header height.
	pub fn get_target_height(&self) -> u64 {
		self.target_height
	}

	/// Return list of the next preferred segments the desegmenter needs based on
	/// the current real state of the underlying elements
	pub fn next_desired_segments<T>(
		&mut self,
		max_elements: usize,
		requested_segments: &HashMap<(SegmentType, u64), T>,
		pibd_params: &PibdParams,
	) -> Vec<SegmentIdentifier> {
		self.header_segment_cache.next_desired_segments(
			pibd_params.get_headers_segment_height(),
			max_elements,
			requested_segments,
			self.pibd_params.get_headers_hash_buffer_len(),
		)
	}

	/// Adds a output segment
	pub fn add_headers_hash_segment(
		&mut self,
		segment: Segment<Hash>,
		headers_root_hash: &Hash,
	) -> Result<(), Error> {
		if *headers_root_hash != self.headers_root_hash {
			return Err(Error::InvalidHeadersRoot);
		}

		if segment.identifier().height != self.pibd_params.get_headers_segment_height() {
			return Err(Error::InvalidSegmentHeght);
		}

		let segm_idx = segment.identifier().idx;

		// Checking if first hash matching genesis
		if segm_idx == 0 {
			if let Some((_, first_hash)) = segment.leaf_iter().next() {
				if *first_hash != self.genesis_hash {
					return Err(Error::InvalidGenesisHash);
				}
			}
		}

		if self.header_segment_cache.is_duplicate_segment(segm_idx) {
			info!(
				"headers_desegmenter: skipping duplicated header segment with id {}",
				segment.identifier().idx
			);
			return Ok(());
		}

		info!(
			"headers_desegmenter: adding headers segment with id {}",
			segment.identifier().idx
		);
		segment.validate(self.header_pmmr_size, None, &self.headers_root_hash)?;

		let header_segment_cache = &mut self.header_segment_cache;
		let header_pmmr = &mut self.header_pmmr;

		// Let's apply the data
		header_segment_cache.apply_new_segment(segment, |segments| {
			let size = header_pmmr.size();
			let mut header_pmmr = PMMR::at(header_pmmr, size);

			for segm in segments {
				let (_sid, hash_pos, _, leaf_pos, leaf_data, _proof) = segm.parts();

				// insert either leaves or pruned subtrees as we go
				for insert in sort_pmmr_hashes_and_leaves(hash_pos, leaf_pos, None) {
					match insert {
						OrderedHashLeafNode::Hash(_, _) => {
							return Err(Error::InvalidSegment(
								"Headers PMMR is non-prunable, should not have hash data"
									.to_string(),
							));
						}
						OrderedHashLeafNode::Leaf(idx, pos0) => {
							if pos0 == header_pmmr.size {
								header_pmmr
									.push(&leaf_data[idx])
									.map_err(&Error::TxHashSetErr)?;
							}
						}
					}
				}
			}
			Ok(())
		})?;
		Ok(())
	}
}

/// Cache data for received haders.
/// T id peer ID type. Headers we will be able to validate with some delay. In case of error, we better to
/// be able to reject them and panish the peer.
pub struct HeadersRecieveCache<T = String> {
	// Archive header height used for the sync process
	archive_header_height: u64,
	// cahce with recievd headers
	main_headers_cache: BTreeMap<u64, (Vec<BlockHeader>, T)>,
	// target chain to feed the data
	chain: Arc<crate::Chain>,
}

impl<T> HeadersRecieveCache<T> {
	/// Create a new segmenter based on the provided txhashset and the specified block header
	pub fn new(
		chain: Arc<crate::Chain>, // target height and headers_root_hash must be get as a result of handshake process.
		header_desegmenter: &HeaderHashesDesegmenter,
	) -> Self {
		let mut res = HeadersRecieveCache {
			archive_header_height: 0,
			main_headers_cache: BTreeMap::new(),
			chain: chain.clone(),
		};
		res.prepare_download_headers(header_desegmenter)
			.expect("Chain is corrupted, please clean up the data manually and restart the node");
		res
	}

	/// Archive (horizon) height
	pub fn get_archive_header_height(&self) -> u64 {
		self.archive_header_height
	}

	/// Check downloaded headers against the hashes. That will allow to continue download headers instead of starting from the beginning.
	fn prepare_download_headers(
		&mut self,
		header_desegmenter: &HeaderHashesDesegmenter,
	) -> Result<(), Error> {
		// Let's validate that available headers are matching the hashes.
		let tip = self.chain.header_head()?;
		let base_hash_idx = tip.height / HEADERS_PER_BATCH as u64;

		self.archive_header_height = header_desegmenter.target_height;
		debug_assert!(self.archive_header_height > 0);

		for hash_idx in (0..=base_hash_idx).rev() {
			let height = hash_idx * HEADERS_PER_BATCH as u64;
			if let Ok(header) = self.chain.get_header_by_height(height) {
				if let Some(hash) = header_desegmenter
					.header_pmmr
					.data
					.as_ref()
					.unwrap()
					.get(hash_idx as usize)
				{
					if header.hash() != *hash {
						// need to check the first hash, if it doesn't match, let's reset all blockchain. Hashes are below horizon,
						// if something not matching better to reset all the data, including block data and restart with headers download
						self.chain.reset_chain_head(self.chain.genesis(), true)?;
					} else {
						break;
					}
				}
			}
		}
		Ok(())
	}

	/// Reset all state
	pub fn reset(&mut self) {
		self.main_headers_cache.clear();
		self.archive_header_height = 0;
	}

	/// Whether we have all the segments we need
	pub fn is_complete(&self) -> Result<bool, Error> {
		debug_assert!(self.archive_header_height > 0);
		let collected_headers = self.chain.header_head()?.height;
		Ok(self.archive_header_height <= collected_headers)
	}

	/// Return list of the next preferred segments the desegmenter needs based on
	/// the current real state of the underlying elements
	pub fn next_desired_headers<K>(
		&mut self,
		headers: &HeaderHashesDesegmenter,
		elements: usize,
		requested_hashes: &HashMap<Hash, K>,
	) -> Result<Vec<(Hash, u64)>, Error> {
		let mut return_vec = vec![];
		let tip = self.chain.header_head()?;
		let base_hash_idx = tip.height / HEADERS_PER_BATCH as u64;
		// Still limiting by 1000 because of memory. Cache is limited, we better wait if theer are so many behind...
		let max_idx = cmp::min(
			base_hash_idx + 1000,
			self.archive_header_height / HEADERS_PER_BATCH as u64,
		);

		for hash_idx in base_hash_idx..=max_idx {
			// let's check if cache already have it
			if self
				.main_headers_cache
				.contains_key(&(hash_idx * HEADERS_PER_BATCH as u64 + 1))
			{
				continue;
			}

			let hinfo: Option<&Hash> = headers
				.header_pmmr
				.data
				.as_ref()
				.unwrap()
				.get(hash_idx as usize);
			match hinfo {
				Some(h) => {
					// check if already requested first
					if !requested_hashes.contains_key(h) {
						return_vec.push((h.clone(), hash_idx * HEADERS_PER_BATCH as u64));
						if return_vec.len() >= elements {
							break;
						}
					}
				}
				None => break,
			}
		}
		Ok(return_vec)
	}

	/// Adds a output segment
	pub fn add_headers(
		&mut self,
		headers: &HeaderHashesDesegmenter,
		bhs: Vec<BlockHeader>,
		peer_info: T,
	) -> Result<(), (T, Error)> {
		if bhs.len() < HEADERS_PER_BATCH as usize {
			return Err((
				peer_info,
				Error::InvalidSegment(format!(
					"Segment is too short, expected {}, but get {} items",
					HEADERS_PER_BATCH,
					bhs.len()
				)),
			));
		}
		let first_header = &bhs.first().unwrap();
		let hash_idx = first_header.height / HEADERS_PER_BATCH as u64;

		if let Some(next_hash) = headers
			.header_pmmr
			.data
			.as_ref()
			.expect("header_pmmr data must exist")
			.get(hash_idx as usize + 1)
		{
			let last_header = bhs.last().unwrap();
			if last_header.hash() != *next_hash {
				return Err((
					peer_info,
					Error::InvalidSegment(
						"Last header in the series doesn't match expected hash".to_string(),
					),
				));
			}
		}

		let expected_height = hash_idx * HEADERS_PER_BATCH as u64 + 1;
		if first_header.height != expected_height {
			return Err((
				peer_info,
				Error::InvalidSegment(format!(
					"First header in the segment has wrong height. Expected {}, but get {}",
					expected_height, first_header.height
				)),
			));
		}

		// duplicated data, skipping it
		if self.main_headers_cache.contains_key(&first_header.height) {
			return Ok(());
		}

		self.main_headers_cache
			.insert(first_header.height, (bhs, peer_info));

		// Apply data from cache if possible
		let mut headers_all: Vec<BlockHeader> = Vec::new();
		let mut headers_by_peer: Vec<(Vec<BlockHeader>, T)> = Vec::new();
		let tip = self
			.chain
			.header_head()
			.expect("Header head must be always defined");

		let mut tip_height = tip.height;

		while let Some((height, (headers, _))) = self.main_headers_cache.first_key_value() {
			debug_assert!(!headers.is_empty());
			debug_assert!(headers.len() == HEADERS_PER_BATCH as usize);
			debug_assert!(headers.first().unwrap().height == *height);
			let ending_height = headers.last().expect("headers can't empty").height;
			if ending_height <= tip_height {
				// duplicated data, skipping it...
				let _ = self.main_headers_cache.pop_first();
				continue;
			}
			if *height > tip_height + 1 {
				break;
			}
			let (_, (mut bhs, peer)) = self.main_headers_cache.pop_first().unwrap();
			tip_height = bhs.last().expect("bhs can't be empty").height;

			headers_by_peer.push((bhs.clone(), peer));
			headers_all.append(&mut bhs);
		}

		if !headers_all.is_empty() {
			match self
				.chain
				.sync_block_headers(&headers_all, tip, Options::NONE)
			{
				Ok(_) => {}
				Err(e) => {
					warn!(
						"add_headers in bulk is failed, will add one by one. Error: {}",
						e
					);
					// apply one by one
					for (hdr, peer) in headers_by_peer {
						let tip = self
							.chain
							.header_head()
							.expect("Header head must be always defined");

						match self.chain.sync_block_headers(&hdr, tip, Options::NONE) {
							Ok(_) => {}
							Err(e) => return Err((peer, e)),
						}
					}
				}
			}
		}

		Ok(())
	}
}
