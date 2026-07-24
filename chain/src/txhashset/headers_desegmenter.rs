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

use crate::error::Error;
use crate::pibd_params::PibdParams;
use crate::txhashset::request_lookup::RequestLookup;
use crate::txhashset::segments_cache::SegmentsCache;
use crate::txhashset::{sort_pmmr_hashes_and_leaves, Desegmenter, OrderedHashLeafNode};
use crate::types::HEADERS_PER_BATCH;
use crate::{pibd_params, Options};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::pmmr;
use mwc_core::core::pmmr::{VecBackend, PMMR};
use mwc_core::core::{BlockHeader, Segment};
use mwc_core::core::{SegmentIdentifier, SegmentType};
use mwc_crates::log::{info, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use std::cmp;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::Arc;

/// There is no reasons to introduce a special type, for that. For place maker any type will work
pub const HEADER_HASHES_STUB_TYPE: SegmentType = SegmentType::Bitmap;
/// Maximum number of header-hash segments to allocate for a PIBD headers sync.
pub const MAX_HEADER_HASH_SEGMENTS: u64 = 65_536;

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

/// This formula must be the same for segmenter and desegmenter
/// Both party needs to be onthe same page regarding the size of the data
pub fn calc_header_hashes_from_target_height(target_height: u64) -> u64 {
	// Safe: HEADERS_PER_BATCH is a non-zero u32 constant, and conversion to u64 is lossless.
	target_height / u64::from(HEADERS_PER_BATCH) + 1
}

fn checked_next_header_height(context: &str, height: u64) -> Result<u64, Error> {
	height.checked_add(1).ok_or_else(|| {
		Error::DataOverflow(format!(
			"HeadersRecieveCache::{}, height={}",
			context, height
		))
	})
}

fn cached_run_retry_index(cached_run: Option<(u64, u64)>, headers_to_retry: u64) -> Option<u64> {
	cached_run.and_then(|(first, last)| {
		if last.saturating_sub(first) > headers_to_retry {
			Some(first)
		} else {
			None
		}
	})
}

impl HeaderHashesDesegmenter {
	/// Create a new segmenter based on the provided txhashset and the specified block header
	pub fn new(
		context_id: u32,
		genesis_hash: Hash,
		target_height: u64,
		headers_root_hash: Hash, // target height and headers_root_hash must be get as a result of handshake process.
		pibd_params: Arc<PibdParams>,
	) -> Result<Self, Error> {
		let n_leaves = calc_header_hashes_from_target_height(target_height);
		let header_pmmr_size = pmmr::insertion_to_pmmr_index(n_leaves)?;
		let header_segments_num = Desegmenter::count_non_prunable_segments(
			Hash::LEN,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			header_pmmr_size,
		)?;
		if header_segments_num > MAX_HEADER_HASH_SEGMENTS {
			return Err(Error::InvalidHeaderHeight(target_height));
		}
		let header_segments = Desegmenter::generate_segments(
			Hash::LEN,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			header_pmmr_size,
			None,
		)?;

		Ok(HeaderHashesDesegmenter {
			genesis_hash,
			header_pmmr: VecBackend::new(context_id),
			target_height,
			headers_root_hash,
			header_pmmr_size,
			header_segment_cache: SegmentsCache::new(HEADER_HASHES_STUB_TYPE, header_segments),
			pibd_params,
		})
	}

	/// Get number of completed segments (including cached)
	pub fn get_segments_completed(&self) -> usize {
		self.header_segment_cache.get_accepted_segments()
	}

	/// Get number of total segments
	pub fn get_segments_total(&self) -> usize {
		self.header_segment_cache.get_required_segments_num()
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
	pub fn next_desired_segments(
		&mut self,
		max_elements: usize,
		requested_segments: &dyn RequestLookup<(SegmentType, u64)>,
	) -> Result<Vec<SegmentIdentifier>, Error> {
		// For headers hashes there is no duplicate requests. There are not much data...
		Ok(self
			.header_segment_cache
			.next_desired_segments(
				max_elements,
				requested_segments,
				self.pibd_params.get_headers_hash_buffer_len(),
			)?
			.0)
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

		let cache_size_limit = self.pibd_params.get_headers_hash_buffer_len();
		if !self
			.header_segment_cache
			.has_segment(segment.identifier())?
		{
			return Err(Error::InvalidSegmentId);
		}

		let leaf_offset = segment.identifier().leaf_offset()?;

		// Checking if first hash matching genesis
		if leaf_offset == 0 {
			if let Some((_, first_hash)) = segment.leaf_iter().next() {
				if *first_hash != self.genesis_hash {
					return Err(Error::InvalidGenesisHash);
				}
			}
		}

		if self
			.header_segment_cache
			.is_duplicate_segment(segment.identifier())?
		{
			info!(
				"headers_desegmenter: skipping duplicated header segment {}",
				leaf_offset,
			);
			return Ok(());
		}
		if !self
			.header_segment_cache
			.is_segment_in_receive_window(segment.identifier(), cache_size_limit)?
		{
			return Err(Error::InvalidSegmentId);
		}

		info!(
			"headers_desegmenter: adding headers segment {}",
			leaf_offset,
		);
		let segment = segment.validate(0, self.header_pmmr_size, None, &self.headers_root_hash)?;

		let header_segment_cache = &mut self.header_segment_cache;
		let header_pmmr = &mut self.header_pmmr;

		// Let's apply the data
		header_segment_cache.apply_new_segment(segment, false, cache_size_limit, |segments| {
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
							if pos0 == header_pmmr.size() {
								header_pmmr.push(&leaf_data[idx])?;
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
	// Headers root hash that authenticated the cached header batches.
	headers_root_hash: Hash,
	// cahce with recievd headers
	main_headers_cache: RwLock<BTreeMap<u64, (Vec<BlockHeader>, T)>>,
	// target chain to feed the data
	chain: Arc<crate::Chain>,
}

impl<T: Clone> HeadersRecieveCache<T> {
	/// Create a new segmenter based on the provided txhashset and the specified block header
	pub fn new(
		chain: Arc<crate::Chain>, // target height and headers_root_hash must be get as a result of handshake process.
		header_desegmenter: &HeaderHashesDesegmenter,
	) -> Result<Self, Error> {
		let mut res = HeadersRecieveCache {
			archive_header_height: 0,
			headers_root_hash: *header_desegmenter.get_headers_root_hash(),
			main_headers_cache: RwLock::new(BTreeMap::new()),
			chain: chain.clone(),
		};
		res.prepare_download_headers(header_desegmenter)?;
		Ok(res)
	}

	/// Archive (horizon) height
	pub fn get_archive_header_height(&self) -> u64 {
		self.archive_header_height
	}

	/// Header batches accepted by the chain or held in the receive cache.
	pub fn get_progress_segments_including_cache(&self) -> Result<(u64, u64), Error> {
		let headers_per_batch = HEADERS_PER_BATCH as u64;
		let header_head = self.chain.header_head()?;
		let applied_height = header_head.height.min(self.archive_header_height);
		let applied_segments = header_batch_count(applied_height, headers_per_batch);
		let cached_segments = self.main_headers_cache.read_recursive().len() as u64;
		let completed_segments = applied_segments.saturating_add(cached_segments);
		let total_segments = header_batch_count(self.archive_header_height, headers_per_batch);
		Ok((completed_segments.min(total_segments), total_segments))
	}

	/// Cache-inclusive header progress expressed as a height for SyncStatus.
	pub fn get_progress_height_including_cache(&self) -> Result<u64, Error> {
		let headers_per_batch = HEADERS_PER_BATCH as u64;
		let (completed_segments, _) = self.get_progress_segments_including_cache()?;
		Ok(completed_segments
			.saturating_mul(headers_per_batch)
			.min(self.archive_header_height))
	}

	/// Whether this receive cache belongs to the same PIBD headers commitment.
	pub fn matches_desegmenter(&self, header_desegmenter: &HeaderHashesDesegmenter) -> bool {
		self.archive_header_height == header_desegmenter.get_target_height()
			&& self.headers_root_hash == *header_desegmenter.get_headers_root_hash()
	}

	/// Check downloaded headers against the hashes. That will allow to continue download headers instead of starting from the beginning.
	fn prepare_download_headers(
		&mut self,
		header_desegmenter: &HeaderHashesDesegmenter,
	) -> Result<(), Error> {
		// Let's validate that available headers are matching the hashes.
		let tip = self.chain.header_head()?;
		let base_hash_idx = tip.height / HEADERS_PER_BATCH as u64;
		let target_hash_idx = header_desegmenter.target_height / HEADERS_PER_BATCH as u64;
		let max_hash_idx = cmp::min(base_hash_idx, target_hash_idx);

		self.archive_header_height = header_desegmenter.target_height;
		debug_assert!(self.archive_header_height > 0);

		let header_pmmr_data = header_desegmenter
			.header_pmmr
			.data
			.as_ref()
			.ok_or(Error::Other("Internal error at prepare_download_headers, header_desegmenter pmmr data not initialized".into()))?;

		for hash_idx in (0..=max_hash_idx).rev() {
			let height = hash_idx * HEADERS_PER_BATCH as u64;
			let header = match self.chain.get_header_by_height(height) {
				Ok(header) => header,
				Err(e) if e.is_not_found() => continue,
				Err(e) => return Err(e),
			};
			let hash_idx_usize = usize::try_from(hash_idx).map_err(|_| {
				Error::DataOverflow(format!(
					"HeadersRecieveCache::prepare_download_headers, hash_idx={}",
					hash_idx
				))
			})?;
			let hash = header_pmmr_data
				.get(hash_idx_usize)
				.ok_or_else(|| {
					Error::Other(format!(
						"Internal error at prepare_download_headers, missing header hash at index {} for target height {}",
						hash_idx, header_desegmenter.target_height
					))
				})?
				.as_ref()
				.ok_or_else(|| {
					Error::Other(format!(
						"Internal error at prepare_download_headers, empty header hash at index {} for target height {}",
						hash_idx, header_desegmenter.target_height
					))
				})?;

			if header.hash(self.chain.get_context_id())? != *hash {
				// need to check the first hash, if it doesn't match, let's reset all blockchain. Hashes are below horizon,
				// if something not matching better to reset all the data, including block data and restart with headers download
				let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
				self.chain
					.reset_chain_head(&secp, &self.chain.genesis(), true)?;
			} else {
				break;
			}
		}
		Ok(())
	}

	/// Reset all state
	pub fn reset(&mut self) {
		self.main_headers_cache.write().clear();
		self.archive_header_height = 0;
		self.headers_root_hash = Hash::default();
	}

	/// Whether we have all the segments we need
	pub fn is_complete(&self) -> Result<bool, Error> {
		debug_assert!(self.archive_header_height > 0);
		let collected_headers = self.chain.header_head()?.height;
		Ok(self.archive_header_height <= collected_headers)
	}

	/// Return list of the next preferred segments the desegmenter needs based on
	/// the current real state of the underlying elements. Second array - list of delayed requests. We better to retry them
	/// 3rd array - all requesrs that are expected.
	pub fn next_desired_headers(
		&self,
		headers: &HeaderHashesDesegmenter,
		elements: usize,
		request_tracker: &dyn RequestLookup<Hash>,
		headers_cache_size_limit: usize,
	) -> Result<(Vec<(Hash, u64)>, Vec<(Hash, u64)>, Vec<(Hash, u64)>), Error> {
		let mut return_vec = vec![];
		let tip = self.chain.header_head()?;
		let base_hash_idx = tip.height / HEADERS_PER_BATCH as u64;
		// Still limiting by 1000 because of memory. Cache is limited, we better wait if theer are so many behind...
		let max_idx = cmp::min(
			base_hash_idx.saturating_add(headers_cache_size_limit as u64),
			self.archive_header_height / HEADERS_PER_BATCH as u64,
		);

		let mut waiting_indexes: Vec<(u64, (Hash, u64))> = Vec::new();

		let mut cached_run: Option<(u64, u64)> = None;
		let mut retry_before_idx: Option<u64> = None;
		let headers_to_retry = headers_cache_size_limit as u64 / 5;

		for hash_idx in base_hash_idx..=max_idx {
			// let's check if cache already have it
			if self
				.main_headers_cache
				.read_recursive()
				.contains_key(&(hash_idx * HEADERS_PER_BATCH as u64 + 1))
			{
				cached_run = match cached_run {
					Some((first, last)) if last.checked_add(1) == Some(hash_idx) => {
						Some((first, hash_idx))
					}
					_ => Some((hash_idx, hash_idx)),
				};
				continue;
			}

			if let Some(idx) = cached_run_retry_index(cached_run.take(), headers_to_retry) {
				retry_before_idx = Some(idx);
			}

			let hash_idx_usize = usize::try_from(hash_idx).map_err(|_| {
				Error::DataOverflow(format!(
					"HeadersRecieveCache::next_desired_headers, hash_idx={}",
					hash_idx
				))
			})?;
			let hinfo: Option<&Option<Hash>> = headers
				.header_pmmr
				.data
				.as_ref()
				.ok_or(Error::Other("Internal error at next_desired_headers, header_desegmenter pmmr data not initialized".into()))?
				.get(hash_idx_usize);
			match hinfo {
				Some(hash) => {
					if let Some(h) = hash {
						let request = (h.clone(), hash_idx * HEADERS_PER_BATCH as u64);
						// check if already requested first
						if !request_tracker.contains_request(h) {
							if return_vec.len() >= elements {
								break;
							}
							return_vec.push(request);
						} else {
							waiting_indexes.push((hash_idx, request));
						}
					} else {
						break;
					}
				}
				None => break,
			}
		}

		if let Some(idx) = cached_run_retry_index(cached_run, headers_to_retry) {
			retry_before_idx = Some(idx);
		}

		// Let's check if we want to retry something...
		let mut retry_vec = vec![];
		if let Some(retry_before_idx) = retry_before_idx {
			for (idx, req) in &waiting_indexes {
				if *idx >= retry_before_idx {
					break;
				}
				retry_vec.push(req.clone());
			}
		}

		Ok((
			return_vec,
			retry_vec,
			waiting_indexes.into_iter().map(|(_, v)| v).collect(),
		))
	}

	/// Adds a output segment
	pub fn add_headers_to_cache(
		&self,
		headers: &HeaderHashesDesegmenter,
		bhs: Vec<BlockHeader>,
		peer_info: T,
	) -> Result<(), (T, Error)> {
		if bhs.len() != HEADERS_PER_BATCH as usize {
			return Err((
				peer_info,
				Error::InvalidSegment(format!(
					"Segment has wrong length, expected {}, but get {} items",
					HEADERS_PER_BATCH,
					bhs.len()
				)),
			));
		}
		let first_header = &bhs.first().ok_or((
			peer_info.clone(),
			Error::Other("add_headers_to_cache param bhs is empty".into()),
		))?;
		let hash_idx = first_header.height / HEADERS_PER_BATCH as u64;
		let hash_idx_usize = usize::try_from(hash_idx).map_err(|_| {
			(
				peer_info.clone(),
				Error::DataOverflow(format!(
					"HeadersRecieveCache::add_headers_to_cache, hash_idx={}",
					hash_idx
				)),
			)
		})?;
		let next_hash_idx = hash_idx_usize.checked_add(1).ok_or_else(|| {
			(
				peer_info.clone(),
				Error::DataOverflow(format!(
					"HeadersRecieveCache::add_headers_to_cache, hash_idx_usize={}",
					hash_idx_usize
				)),
			)
		})?;

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
		if first_header.height > headers.target_height {
			return Err((
				peer_info,
				Error::InvalidSegment(format!(
					"Header segment starts after target height. Target {}, but get {}",
					headers.target_height, first_header.height
				)),
			));
		}

		let batch_end_height = first_header
			.height
			.checked_add(u64::from(HEADERS_PER_BATCH) - 1)
			.ok_or_else(|| {
				(
					peer_info.clone(),
					Error::DataOverflow(format!(
						"HeadersRecieveCache::add_headers_to_cache, first_header.height={}",
						first_header.height
					)),
				)
			})?;
		let next_checkpoint_required = headers.target_height >= batch_end_height;
		let header_pmmr_data = headers.header_pmmr.data.as_ref().ok_or((
			peer_info.clone(),
			Error::Other("header_pmmr data must exist".into()),
		))?;

		let next_hash = match header_pmmr_data.get(next_hash_idx) {
			Some(Some(next_hash)) => Some(next_hash),
			Some(None) if next_checkpoint_required => {
				return Err((
					peer_info,
					Error::InvalidSegment(format!(
						"Next header hash checkpoint at index {} is empty",
						next_hash_idx
					)),
				));
			}
			None if next_checkpoint_required => {
				return Err((
					peer_info,
					Error::InvalidSegment(format!(
						"Next header hash checkpoint at index {} is missing",
						next_hash_idx
					)),
				));
			}
			_ => None,
		};

		// The request locator/checkpoint identifies the header immediately
		// before this batch. Validate the batch chain locally before caching so
		// malformed internal height or prev_hash links cannot poison the cache.
		let start_hash = match header_pmmr_data.get(hash_idx_usize) {
			Some(Some(start_hash)) => *start_hash,
			Some(None) => {
				return Err((
					peer_info,
					Error::InvalidSegment(format!(
						"Start header hash checkpoint at index {} is empty",
						hash_idx_usize
					)),
				));
			}
			None => {
				return Err((
					peer_info,
					Error::InvalidSegment(format!(
						"Start header hash checkpoint at index {} is missing",
						hash_idx_usize
					)),
				));
			}
		};

		// The final PIBD batch may contain full-batch padding above target_height;
		// apply_cache truncates that tail before chain validation. Only require
		// full structural validation when a next checkpoint proves the whole batch.
		let headers_to_validate = if next_hash.is_some() {
			bhs.len()
		} else {
			let target_remaining = headers
				.target_height
				.checked_sub(first_header.height)
				.and_then(|remaining| remaining.checked_add(1))
				.ok_or_else(|| {
					(
						peer_info.clone(),
						Error::DataOverflow(format!(
							"HeadersRecieveCache::add_headers_to_cache, target range {}..{}",
							first_header.height, headers.target_height
						)),
					)
				})?;
			let target_remaining = usize::try_from(target_remaining).map_err(|_| {
				(
					peer_info.clone(),
					Error::DataOverflow(format!(
						"HeadersRecieveCache::add_headers_to_cache, target_remaining={}",
						target_remaining
					)),
				)
			})?;
			cmp::min(bhs.len(), target_remaining)
		};

		let context_id = self.chain.get_context_id();
		let mut expected_height = first_header.height;
		let mut expected_prev_hash = start_hash;
		let mut last_header_hash = None;

		for (idx, header) in bhs.iter().take(headers_to_validate).enumerate() {
			if header.height != expected_height {
				return Err((
					peer_info.clone(),
					Error::InvalidSegment(format!(
						"Header {} in the series has wrong height. Expected {}, but get {}",
						idx, expected_height, header.height
					)),
				));
			}
			if header.prev_hash != expected_prev_hash {
				return Err((
					peer_info.clone(),
					Error::InvalidSegment(format!(
						"Header {} in the series has wrong prev_hash. Expected {}, but get {}",
						idx, expected_prev_hash, header.prev_hash
					)),
				));
			}

			let header_hash = match header.hash(context_id) {
				Ok(hash) => hash,
				Err(e) => return Err((peer_info.clone(), e.into())),
			};
			last_header_hash = Some(header_hash);
			expected_prev_hash = header_hash;
			if idx + 1 < headers_to_validate {
				expected_height = checked_next_header_height(
					"add_headers_to_cache, expected_height",
					expected_height,
				)
				.map_err(|e| (peer_info.clone(), e))?;
			}
		}

		if let Some(next_hash) = next_hash {
			let last_header_hash = last_header_hash.ok_or((
				peer_info.clone(),
				Error::Other("add_headers_to_cache param bhs is empty".into()),
			))?;
			if last_header_hash != *next_hash {
				return Err((
					peer_info,
					Error::InvalidSegment(
						"Last header in the series doesn't match expected hash".to_string(),
					),
				));
			}
		}

		let mut main_headers_cache = self.main_headers_cache.write();
		// duplicated data, skipping it
		if main_headers_cache.contains_key(&first_header.height) {
			return Ok(());
		}

		main_headers_cache.insert(first_header.height, (bhs, peer_info));

		Ok(())
	}

	fn remove_cached_header_batches(&self, heights: &[u64]) {
		if heights.is_empty() {
			return;
		}

		let mut main_headers_cache = self.main_headers_cache.write();
		for height in heights {
			main_headers_cache.remove(height);
		}
	}

	/// Apply cache to the chain. Return true if more data is available
	pub fn apply_cache(&self) -> Result<bool, (Option<T>, Error)> {
		// Apply data from cache if possible
		let mut headers_all: Vec<BlockHeader> = Vec::new();
		let mut headers_by_peer: Vec<(u64, Vec<BlockHeader>, T)> = Vec::new();
		let mut stale_heights: Vec<u64> = Vec::new();
		let tip = self.chain.header_head().map_err(|e| {
			(
				None,
				Error::Other(format!(
					"Internal error, header expected to be defined, {}",
					e
				)),
			)
		})?;

		let mut tip_height = tip.height;

		{
			// Scan without removing entries. Batches are dropped from the cache only
			// after the chain accepts them, so a fallback error cannot discard later
			// contiguous batches that were never attempted.
			let main_headers_cache = self.main_headers_cache.read_recursive();
			for (height, (headers, peer)) in main_headers_cache.iter() {
				debug_assert!(!headers.is_empty());
				debug_assert!(headers.len() == HEADERS_PER_BATCH as usize);
				debug_assert!(headers.first().map(|header| header.height) == Some(*height));
				let ending_height = headers
					.last()
					.ok_or((
						None,
						Error::Other("Internal error, header expected to be defined".into()),
					))?
					.height;
				if ending_height <= tip_height {
					// duplicated data, skipping it...
					stale_heights.push(*height);
					continue;
				}
				let next_tip_height =
					checked_next_header_height("apply_cache, tip_height", tip_height)
						.map_err(|e| (None, e))?;
				if *height > next_tip_height {
					break;
				}
				let mut bhs = headers.clone();
				// The terminal PIBD batch can be full sized even when the archive target
				// falls inside it. Keep the applied range bounded by the PIBD target.
				// Note, trancating addrees the comment that said that series length/consystency is
				// not validated above the header height.
				if let Some(idx) = bhs
					.iter()
					.position(|header| header.height > self.archive_header_height)
				{
					bhs.truncate(idx);
				}
				if bhs.is_empty() {
					stale_heights.push(*height);
					continue;
				}
				tip_height = bhs
					.last()
					.ok_or((
						Some(peer.clone()),
						Error::Other("Internal error, bhs expected to be defined".into()),
					))?
					.height;

				headers_by_peer.push((*height, bhs.clone(), peer.clone()));
				headers_all.append(&mut bhs);

				if headers_all.len() > 2000 {
					break; //  we don't want add too much at a single session.
				}
				if tip_height >= self.archive_header_height {
					break;
				}
			}
		}

		self.remove_cached_header_batches(&stale_heights);

		if !headers_all.is_empty() {
			match self
				.chain
				.sync_block_headers(&headers_all, tip, Options::NONE)
			{
				Ok(_) => {
					let applied_heights = headers_by_peer
						.iter()
						.map(|(height, _, _)| *height)
						.collect::<Vec<_>>();
					self.remove_cached_header_batches(&applied_heights);
				}
				Err(e) => {
					warn!(
						"add_headers in bulk is failed, will add one by one. Error: {}",
						e
					);
					// apply one by one
					for (height, hdr, peer) in headers_by_peer {
						let tip = self.chain.header_head().map_err(|e| {
							(
								None,
								Error::Other(format!(
									"Internal error, header expected to be defined, {}",
									e
								)),
							)
						})?;

						match self.chain.sync_block_headers(&hdr, tip, Options::NONE) {
							Ok(_) => self.remove_cached_header_batches(&[height]),
							Err(e) => {
								let evict_cached_batch =
									e.is_bad_data() || matches!(&e, Error::Orphan(_));

								let err = if e.is_bad_data() || matches!(&e, Error::Orphan(_)) {
									(Some(peer), e)
								} else {
									(None, e)
								};

								if evict_cached_batch {
									self.remove_cached_header_batches(&[height]);
								}
								return Err(err);
							}
						}
					}
				}
			}

			let tip = self.chain.header_head().map_err(|e| {
				(
					None,
					Error::Other(format!(
						"Internal error, header expected to be defined, {}",
						e
					)),
				)
			})?;

			let next_tip_height = checked_next_header_height("apply_cache, tip.height", tip.height)
				.map_err(|e| (None, e))?;
			match self.main_headers_cache.read_recursive().first_key_value() {
				Some((height, _)) => Ok(*height <= next_tip_height),
				None => Ok(false),
			}
		} else {
			Ok(false)
		}
	}
}

fn header_batch_count(height: u64, headers_per_batch: u64) -> u64 {
	if height == 0 || headers_per_batch == 0 {
		return 0;
	}
	1 + (height - 1) / headers_per_batch
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::types::NoopAdapter;
	use mwc_core::{global, pow};
	use std::collections::{HashMap, HashSet};
	use std::fs;
	use std::time::{SystemTime, UNIX_EPOCH};

	fn init_test_chain(test_name: &str) -> (Arc<crate::Chain>, String) {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let chain_dir = std::env::temp_dir()
			.join(format!(
				"mwc_headers_desegmenter_{}_{}_{}",
				test_name,
				std::process::id(),
				unique
			))
			.to_string_lossy()
			.into_owned();
		let _ = fs::remove_dir_all(&chain_dir);
		let genesis = global::get_genesis_block(&secp, 0).unwrap();
		let chain = crate::Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(NoopAdapter {}),
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			true,
		)
		.unwrap();

		(Arc::new(chain), chain_dir)
	}

	fn cleanup_test_chain(chain: &crate::Chain, chain_dir: &str) {
		crate::pipe::release_context_data(chain.get_context_id());
		let _ = fs::remove_dir_all(chain_dir);
	}

	fn dummy_headers(context_id: u32, start_height: u64) -> Vec<BlockHeader> {
		(0..u64::from(HEADERS_PER_BATCH))
			.map(|idx| {
				let mut header = BlockHeader::default(context_id);
				header.height = start_height + idx;
				header
			})
			.collect()
	}

	fn linked_dummy_headers(
		context_id: u32,
		start_height: u64,
		prev_hash: Hash,
	) -> Vec<BlockHeader> {
		let mut prev_hash = prev_hash;
		(0..u64::from(HEADERS_PER_BATCH))
			.map(|idx| {
				let mut header = BlockHeader::default(context_id);
				header.height = start_height + idx;
				header.prev_hash = prev_hash;
				prev_hash = header.hash(context_id).unwrap();
				header
			})
			.collect()
	}

	fn headers_receive_cache(
		chain: Arc<crate::Chain>,
		archive_header_height: u64,
	) -> HeadersRecieveCache<String> {
		HeadersRecieveCache {
			archive_header_height,
			headers_root_hash: Hash::default(),
			main_headers_cache: RwLock::new(BTreeMap::new()),
			chain,
		}
	}

	#[test]
	fn receive_cache_matches_only_same_target_and_root() {
		let (chain, chain_dir) = init_test_chain("receive_cache_matches_only_same_target_and_root");
		let context_id = chain.get_context_id();
		let genesis_hash = chain.genesis().hash(context_id).unwrap();
		let target_height = u64::from(HEADERS_PER_BATCH) + 1;
		let headers_root_hash = Hash::from_vec(&1u64.to_be_bytes());
		let other_headers_root_hash = Hash::from_vec(&2u64.to_be_bytes());
		let pibd_params = Arc::new(PibdParams::new());

		let mut header_desegmenter = HeaderHashesDesegmenter::new(
			context_id,
			genesis_hash,
			target_height,
			headers_root_hash,
			pibd_params.clone(),
		)
		.unwrap();
		header_desegmenter.header_pmmr.data = Some(vec![Some(genesis_hash), Some(Hash::default())]);
		let headers_cache: HeadersRecieveCache<String> =
			HeadersRecieveCache::new(chain.clone(), &header_desegmenter).unwrap();

		let mut same_identity = HeaderHashesDesegmenter::new(
			context_id,
			genesis_hash,
			target_height,
			headers_root_hash,
			pibd_params.clone(),
		)
		.unwrap();
		same_identity.header_pmmr.data = Some(vec![Some(genesis_hash), Some(Hash::default())]);
		assert!(headers_cache.matches_desegmenter(&same_identity));

		let mut changed_root = HeaderHashesDesegmenter::new(
			context_id,
			genesis_hash,
			target_height,
			other_headers_root_hash,
			pibd_params.clone(),
		)
		.unwrap();
		changed_root.header_pmmr.data = Some(vec![Some(genesis_hash), Some(Hash::default())]);
		assert!(!headers_cache.matches_desegmenter(&changed_root));

		let mut changed_target = HeaderHashesDesegmenter::new(
			context_id,
			genesis_hash,
			target_height + u64::from(HEADERS_PER_BATCH),
			headers_root_hash,
			pibd_params,
		)
		.unwrap();
		changed_target.header_pmmr.data = Some(vec![Some(genesis_hash), Some(Hash::default())]);
		assert!(!headers_cache.matches_desegmenter(&changed_target));

		cleanup_test_chain(&chain, &chain_dir);
	}

	#[test]
	fn cached_run_retry_index_handles_zero_and_trailing_runs() {
		assert_eq!(cached_run_retry_index(Some((0, 3)), 2), Some(0));
		assert_eq!(cached_run_retry_index(Some((4, 7)), 2), Some(4));
		assert_eq!(cached_run_retry_index(Some((4, 6)), 2), None);
		assert_eq!(cached_run_retry_index(None, 2), None);
	}

	#[test]
	fn header_batch_count_uses_overflow_free_ceil_division() {
		assert_eq!(header_batch_count(0, 512), 0);
		assert_eq!(header_batch_count(1, 512), 1);
		assert_eq!(header_batch_count(512, 512), 1);
		assert_eq!(header_batch_count(513, 512), 2);
		assert_eq!(header_batch_count(u64::MAX, 512), u64::MAX / 512 + 1);
	}

	#[test]
	fn apply_cache_evicts_bad_batch_and_keeps_later_unapplied_batches() {
		let (chain, chain_dir) =
			init_test_chain("apply_cache_evicts_bad_batch_and_keeps_later_unapplied_batches");
		let context_id = chain.get_context_id();
		let headers_per_batch = u64::from(HEADERS_PER_BATCH);
		let headers_cache = headers_receive_cache(chain.clone(), 2 * headers_per_batch);

		{
			let mut main_headers_cache = headers_cache.main_headers_cache.write();
			main_headers_cache.insert(1, (dummy_headers(context_id, 1), "bad-peer".to_string()));
			main_headers_cache.insert(
				headers_per_batch + 1,
				(
					dummy_headers(context_id, headers_per_batch + 1),
					"honest-peer".to_string(),
				),
			);
		}

		let res = headers_cache.apply_cache();
		assert!(res.is_err(), "{:?}", res);

		let main_headers_cache = headers_cache.main_headers_cache.read_recursive();
		assert!(!main_headers_cache.contains_key(&1));
		assert!(main_headers_cache.contains_key(&(headers_per_batch + 1)));

		cleanup_test_chain(&chain, &chain_dir);
	}

	#[test]
	fn next_desired_headers_retries_waiting_before_trailing_cached_run() {
		let (chain, chain_dir) =
			init_test_chain("next_desired_headers_retries_waiting_before_trailing_cached_run");
		let context_id = chain.get_context_id();
		let genesis_hash = chain.genesis().hash(context_id).unwrap();
		let headers_per_batch = u64::from(HEADERS_PER_BATCH);
		let target_height = 6 * headers_per_batch;
		let mut header_desegmenter = HeaderHashesDesegmenter::new(
			context_id,
			genesis_hash,
			target_height,
			Hash::default(),
			Arc::new(PibdParams::new()),
		)
		.unwrap();
		let header_hashes = (0_u64..=6)
			.map(|idx| Hash::from_vec(&idx.to_le_bytes()))
			.collect::<Vec<_>>();
		header_desegmenter.header_pmmr.data =
			Some(header_hashes.iter().cloned().map(Some).collect());

		let headers_cache = headers_receive_cache(chain.clone(), target_height);
		{
			let mut main_headers_cache = headers_cache.main_headers_cache.write();
			for hash_idx in 3_u64..=6 {
				let height = hash_idx * headers_per_batch + 1;
				main_headers_cache.insert(
					height,
					(dummy_headers(context_id, height), "peer".to_string()),
				);
			}
		}

		let request_tracker = header_hashes
			.iter()
			.take(3)
			.cloned()
			.map(|hash| (hash, ()))
			.collect::<HashMap<_, _>>();
		let request_tracker = &request_tracker;
		let (new_reqs, retry_reqs, waiting_reqs) = headers_cache
			.next_desired_headers(&header_desegmenter, 10, &request_tracker, 6)
			.unwrap();

		assert!(new_reqs.is_empty());
		assert_eq!(
			retry_reqs
				.iter()
				.map(|(_, height)| *height)
				.collect::<Vec<_>>(),
			vec![0, headers_per_batch, 2 * headers_per_batch]
		);
		assert_eq!(retry_reqs, waiting_reqs);

		cleanup_test_chain(&chain, &chain_dir);
	}

	#[test]
	fn rejects_target_height_requiring_too_many_header_hash_segments() {
		let pibd_params = Arc::new(PibdParams::new());
		let res = HeaderHashesDesegmenter::new(
			0,
			Hash::default(),
			u64::MAX,
			Hash::default(),
			pibd_params,
		);

		match res {
			Err(Error::InvalidHeaderHeight(height)) => assert_eq!(height, u64::MAX),
			Err(e) => panic!("unexpected error: {}", e),
			Ok(_) => panic!("huge target height should be rejected"),
		}
	}

	#[test]
	fn add_headers_to_cache_rejects_missing_non_terminal_checkpoint() {
		let (chain, chain_dir) =
			init_test_chain("add_headers_to_cache_rejects_missing_non_terminal_checkpoint");
		let context_id = chain.get_context_id();
		let genesis_hash = chain.genesis().hash(context_id).unwrap();
		let target_height = 2 * u64::from(HEADERS_PER_BATCH);
		let mut header_desegmenter = HeaderHashesDesegmenter::new(
			context_id,
			genesis_hash,
			target_height,
			Hash::default(),
			Arc::new(PibdParams::new()),
		)
		.unwrap();
		let headers_cache = headers_receive_cache(chain.clone(), target_height);

		header_desegmenter.header_pmmr.data = Some(vec![Some(genesis_hash)]);
		let res = headers_cache.add_headers_to_cache(
			&header_desegmenter,
			dummy_headers(context_id, 1),
			"peer".to_string(),
		);
		assert!(matches!(
			res,
			Err((peer, Error::InvalidSegment(msg)))
				if peer == "peer" && msg.contains("checkpoint at index 1 is missing")
		));

		header_desegmenter.header_pmmr.data = Some(vec![Some(genesis_hash), None]);
		let res = headers_cache.add_headers_to_cache(
			&header_desegmenter,
			dummy_headers(context_id, 1),
			"peer".to_string(),
		);
		assert!(matches!(
			res,
			Err((peer, Error::InvalidSegment(msg)))
				if peer == "peer" && msg.contains("checkpoint at index 1 is empty")
		));

		cleanup_test_chain(&chain, &chain_dir);
	}

	#[test]
	fn add_headers_to_cache_rejects_non_consecutive_heights() {
		let (chain, chain_dir) =
			init_test_chain("add_headers_to_cache_rejects_non_consecutive_heights");
		let context_id = chain.get_context_id();
		let genesis_hash = chain.genesis().hash(context_id).unwrap();
		let target_height = 2 * u64::from(HEADERS_PER_BATCH);
		let mut header_desegmenter = HeaderHashesDesegmenter::new(
			context_id,
			genesis_hash,
			target_height,
			Hash::default(),
			Arc::new(PibdParams::new()),
		)
		.unwrap();
		header_desegmenter.header_pmmr.data = Some(vec![Some(genesis_hash), Some(Hash::default())]);
		let headers_cache = headers_receive_cache(chain.clone(), target_height);
		let mut bhs = linked_dummy_headers(context_id, 1, genesis_hash);
		bhs[1].height += 1;

		let res = headers_cache.add_headers_to_cache(&header_desegmenter, bhs, "peer".to_string());

		assert!(matches!(
			res,
			Err((peer, Error::InvalidSegment(msg)))
				if peer == "peer" && msg.contains("wrong height")
		));
		assert!(headers_cache.main_headers_cache.read_recursive().is_empty());

		cleanup_test_chain(&chain, &chain_dir);
	}

	#[test]
	fn add_headers_to_cache_rejects_broken_prev_hash_linkage() {
		let (chain, chain_dir) =
			init_test_chain("add_headers_to_cache_rejects_broken_prev_hash_linkage");
		let context_id = chain.get_context_id();
		let genesis_hash = chain.genesis().hash(context_id).unwrap();
		let target_height = 2 * u64::from(HEADERS_PER_BATCH);
		let mut header_desegmenter = HeaderHashesDesegmenter::new(
			context_id,
			genesis_hash,
			target_height,
			Hash::default(),
			Arc::new(PibdParams::new()),
		)
		.unwrap();
		header_desegmenter.header_pmmr.data = Some(vec![Some(genesis_hash), Some(Hash::default())]);
		let headers_cache = headers_receive_cache(chain.clone(), target_height);
		let mut bhs = linked_dummy_headers(context_id, 1, genesis_hash);
		bhs[1].prev_hash = Hash::from_vec(&[42]);

		let res = headers_cache.add_headers_to_cache(&header_desegmenter, bhs, "peer".to_string());

		assert!(matches!(
			res,
			Err((peer, Error::InvalidSegment(msg)))
				if peer == "peer" && msg.contains("wrong prev_hash")
		));
		assert!(headers_cache.main_headers_cache.read_recursive().is_empty());

		cleanup_test_chain(&chain, &chain_dir);
	}

	#[test]
	fn add_headers_to_cache_allows_missing_terminal_checkpoint() {
		let (chain, chain_dir) =
			init_test_chain("add_headers_to_cache_allows_missing_terminal_checkpoint");
		let context_id = chain.get_context_id();
		let genesis_hash = chain.genesis().hash(context_id).unwrap();
		let target_height = u64::from(HEADERS_PER_BATCH) + 1;
		let mut header_desegmenter = HeaderHashesDesegmenter::new(
			context_id,
			genesis_hash,
			target_height,
			Hash::default(),
			Arc::new(PibdParams::new()),
		)
		.unwrap();
		header_desegmenter.header_pmmr.data = Some(vec![Some(genesis_hash), Some(Hash::default())]);
		let headers_cache = headers_receive_cache(chain.clone(), target_height);

		let res = headers_cache.add_headers_to_cache(
			&header_desegmenter,
			dummy_headers(context_id, u64::from(HEADERS_PER_BATCH) + 1),
			"peer".to_string(),
		);

		assert!(res.is_ok());
		cleanup_test_chain(&chain, &chain_dir);
	}
}
