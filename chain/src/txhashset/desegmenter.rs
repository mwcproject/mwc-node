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

//! Manages the reconsitution of a txhashset from segments produced by the
//! segmenter

use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::pmmr;
use crate::core::core::{
	BlockHeader, BlockSums, OutputIdentifier, Segment, SegmentIdentifier, SegmentType,
	SegmentTypeIdentifier, TxKernel,
};
use crate::error::Error;
use crate::txhashset;
use crate::txhashset::{BitmapAccumulator, BitmapChunk, TxHashSet};
use crate::types::Tip;
use crate::util::secp::pedersen::RangeProof;
use crate::util::{RwLock, StopState};
use crate::{pibd_params, store};
use crate::{Chain, SyncState, SyncStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::pibd_params::PibdParams;
use crate::txhashset::request_lookup::RequestLookup;
use crate::txhashset::segments_cache::SegmentsCache;
use croaring::Bitmap;
use log::Level;
use mwc_util::secp::{constants, Secp256k1};
use tokio::runtime::Builder;
use tokio::task;

/// Desegmenter for rebuilding a txhashset from PIBD segments
/// Note!!! header_pmmr, txhashset & store are from the Chain. Same locking rules are applicable
pub struct Desegmenter {
	txhashset: Arc<RwLock<TxHashSet>>,
	header_pmmr: Arc<RwLock<txhashset::PMMRHandle<BlockHeader>>>,
	archive_header: BlockHeader,
	bitmap_root_hash: Hash, // bitmap root hash must come as a result of handshake process
	store: Arc<store::ChainStore>,

	genesis: BlockHeader,

	outputs_bitmap_accumulator: RwLock<BitmapAccumulator>, // Lock 1
	outputs_bitmap_mmr_size: u64,
	/// In-memory 'raw' bitmap corresponding to contents of bitmap accumulator
	outputs_bitmap: RwLock<Option<Bitmap>>,

	bitmap_segment_cache: RwLock<SegmentsCache<BitmapChunk>>, // Lock 1
	output_segment_cache: RwLock<Option<SegmentsCache<OutputIdentifier>>>,
	rangeproof_segment_cache: RwLock<Option<SegmentsCache<RangeProof>>>,
	kernel_segment_cache: RwLock<Option<SegmentsCache<TxKernel>>>,

	pibd_params: Arc<PibdParams>,
}

impl Desegmenter {
	/// Create a new segmenter based on the provided txhashset and the specified block header
	pub fn new(
		txhashset: Arc<RwLock<TxHashSet>>,
		header_pmmr: Arc<RwLock<txhashset::PMMRHandle<BlockHeader>>>,
		archive_header: BlockHeader,
		bitmap_root_hash: Hash,
		genesis: BlockHeader,
		store: Arc<store::ChainStore>,
		pibd_params: Arc<PibdParams>,
	) -> Desegmenter {
		info!(
			"Creating new desegmenter for bitmap_root_hash {}, height {}",
			bitmap_root_hash, archive_header.height
		);

		let bitmap_mmr_size = Self::calc_bitmap_mmr_size(&archive_header);
		let bitmap_segments = Self::generate_segments(
			BitmapChunk::LEN_BYTES,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			bitmap_mmr_size,
			None,
		);

		Desegmenter {
			txhashset,
			header_pmmr,
			archive_header,
			bitmap_root_hash,
			store,
			genesis,
			outputs_bitmap_accumulator: RwLock::new(BitmapAccumulator::new()),
			outputs_bitmap_mmr_size: bitmap_mmr_size,
			bitmap_segment_cache: RwLock::new(SegmentsCache::new(
				SegmentType::Bitmap,
				bitmap_segments,
			)),
			output_segment_cache: RwLock::new(None),
			rangeproof_segment_cache: RwLock::new(None),
			kernel_segment_cache: RwLock::new(None),
			outputs_bitmap: RwLock::new(None),
			pibd_params,
		}
	}

	/// Access to root hash
	pub fn get_bitmap_root_hash(&self) -> &Hash {
		&self.bitmap_root_hash
	}

	/// Reset all state
	pub fn reset(&self) {
		self.bitmap_segment_cache.write().reset();
		*self.output_segment_cache.write() = None;
		*self.rangeproof_segment_cache.write() = None;
		*self.kernel_segment_cache.write() = None;
		*self.outputs_bitmap.write() = None;
		self.outputs_bitmap_accumulator.write().reset();
	}

	/// Return reference to the header used for validation
	pub fn header(&self) -> &BlockHeader {
		&self.archive_header
	}

	/// Whether we have all the segments we need
	pub fn is_complete(&self) -> bool {
		if !self
			.output_segment_cache
			.read()
			.as_ref()
			.map(|c| c.is_complete())
			.unwrap_or(false)
		{
			return false;
		}
		if !self
			.rangeproof_segment_cache
			.read()
			.as_ref()
			.map(|c| c.is_complete())
			.unwrap_or(false)
		{
			return false;
		}
		if !self
			.kernel_segment_cache
			.read()
			.as_ref()
			.map(|c| c.is_complete())
			.unwrap_or(false)
		{
			return false;
		}
		true
	}

	/// Check progress, update status if needed, returns true if all required
	/// segments are in place
	pub fn get_pibd_progress(&self) -> SyncStatus {
		let (req1, rec1) = {
			let cache = self.bitmap_segment_cache.read();
			(
				cache.get_required_segments_num(),
				cache.get_received_segments(),
			)
		};

		let (req2, rec2) = self
			.output_segment_cache
			.read()
			.as_ref()
			.map(|cache| {
				(
					cache.get_required_segments_num(),
					cache.get_received_segments(),
				)
			})
			.unwrap_or((100, 0));
		let (req3, rec3) = self
			.rangeproof_segment_cache
			.read()
			.as_ref()
			.map(|cache| {
				(
					cache.get_required_segments_num(),
					cache.get_received_segments(),
				)
			})
			.unwrap_or((400, 0));
		let (req4, rec4) = self
			.kernel_segment_cache
			.read()
			.as_ref()
			.map(|cache| {
				(
					cache.get_required_segments_num(),
					cache.get_received_segments(),
				)
			})
			.unwrap_or((1000, 0));

		let required = req1 + req2 + req3 + req4;
		let received = rec1 + rec2 + rec3 + rec4;

		// Expected by QT wallet
		info!("PIBD sync progress: {} from {}", received, required);

		SyncStatus::TxHashsetPibd {
			recieved_segments: received,
			total_segments: required,
		}
	}

	/// Once the PIBD set is downloaded, we need to ensure that the respective leaf sets
	/// match the bitmap (particularly in the case of outputs being spent after a PIBD catch-up)
	pub fn check_update_leaf_set_state(&self) -> Result<(), Error> {
		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		let mut _batch = self.store.batch_write()?;
		txhashset::extending(&mut header_pmmr, &mut txhashset, &mut _batch, |ext, _| {
			let extension = &mut ext.extension;
			let outputs_bitmap = self.outputs_bitmap.read();
			if let Some(b) = outputs_bitmap.as_ref() {
				extension.update_leaf_sets(b)?;
			}
			Ok(())
		})?;
		Ok(())
	}

	/// This is largely copied from chain.rs txhashset_write and related functions,
	/// the idea being that the txhashset version will eventually be removed
	pub fn validate_complete_state(
		&self,
		status: Arc<SyncState>,
		stop_state: Arc<StopState>,
		secp: &Secp256k1,
	) -> Result<(), Error> {
		// Quick root check first:
		{
			let txhashset = self.txhashset.read();
			txhashset.roots()?.validate(&self.archive_header)?;
		}

		status.update(SyncStatus::ValidatingKernelsHistory);

		// Validate kernel history
		{
			info!("desegmenter validation: rewinding and validating kernel history (readonly)");
			let txhashset = self.txhashset.clone();
			let current = self.archive_header.clone();
			let total = current.height;

			// Let's validate everything in multiple threads
			let num_cores = num_cpus::get();
			let mut runtime = Builder::new()
				.threaded_scheduler()
				.enable_all()
				.core_threads(num_cores)
				.build()
				.unwrap();

			runtime.block_on(async {
				let mut handles = Vec::with_capacity(num_cores);
				let processed = Arc::new(AtomicU64::new(0));
				for thr_idx in 0..num_cores {
					let start_height = current.height * (thr_idx + 1) as u64 / num_cores as u64;
					let end_height = current.height * thr_idx as u64 / num_cores as u64;
					let start_block_hash = self
						.header_pmmr
						.read()
						.get_header_hash_by_height(start_height)?;
					let start_block = self.txhashset.read().get_block_header(&start_block_hash)?;
					let processed = processed.clone();
					assert_eq!(start_block.height, start_height);
					let txhashset = txhashset.clone();
					let status = status.clone();
					let stop_state = stop_state.clone();

					let handle: tokio::task::JoinHandle<Result<(), Error>> =
						task::spawn(async move {
							// Process the chunk
							txhashset::rewindable_kernel_view(&*txhashset.read(), |view, batch| {
								let mut start_block = start_block.clone();
								while start_block.height > end_height {
									view.rewind(&start_block)?;
									view.validate_root()?;
									start_block = batch.get_previous_header(&start_block)?;
									let processed = processed.fetch_add(1, Ordering::Relaxed);
									if processed % 100000 == 0 || processed == total {
										status.update(SyncStatus::TxHashsetHeadersValidation {
											headers: processed,
											headers_total: total,
										});
									}
									if stop_state.is_stopped() {
										return Ok(());
									}
								}
								Ok(())
							})
						});
					handles.push(handle);
				}
				for handle in handles {
					match handle.await.expect("Tokio runtime failure") {
						Ok(_) => {}
						Err(e) => return Err(e),
					}
				}
				debug!(
					"desegmenter validation: validated kernel root on {} headers",
					processed.load(Ordering::Relaxed)
				);

				Ok(())
			})?;
		}

		if stop_state.is_stopped() {
			return Ok(());
		}

		// Validate full kernel history.
		// Check kernel MMR root for every block header.
		// Check NRD relative height rules for full kernel history.
		{
			info!("desegmenter validation: validating kernel history");
			// Note, locking order is: header_pmmr->txhashset->batch !!!
			{
				// validate_kernel_history is long operation, that is why let's lock txhashset twice.
				let txhashset = self.txhashset.read();
				Chain::validate_kernel_history(&self.archive_header, &txhashset)?;
			}
			let header_pmmr = self.header_pmmr.read();
			let txhashset = self.txhashset.read();
			let batch = self.store.batch_read()?;
			txhashset.verify_kernel_pos_index(
				&self.genesis,
				&header_pmmr,
				&batch,
				Some(status.clone()),
				Some(stop_state.clone()),
			)?;
		}

		if stop_state.is_stopped() {
			return Ok(());
		}

		// Prepare a new batch and update all the required records
		{
			info!("desegmenter validation: rewinding a 2nd time (writeable)");
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let mut batch = self.store.batch_write()?;
			txhashset::extending(
				&mut header_pmmr,
				&mut txhashset,
				&mut batch,
				|ext, batch| {
					let extension = &mut ext.extension;
					let header_extension = &mut ext.header_extension;
					extension.rewind(&self.archive_header, batch, header_extension)?;

					// Validate the extension, generating the utxo_sum and kernel_sum.
					// Full validation, including rangeproofs and kernel signature verification.
					let (utxo_sum, kernel_sum) = extension.validate(
						&self.genesis,
						false,
						Some(status.clone()),
						&self.archive_header,
						Some(stop_state.clone()),
						secp,
					)?;

					if stop_state.is_stopped() {
						return Ok(());
					}

					// Save the block_sums (utxo_sum, kernel_sum) to the db for use later.
					batch.save_block_sums(
						&self.archive_header.hash(),
						BlockSums {
							utxo_sum,
							kernel_sum,
						},
					)?;

					Ok(())
				},
			)?;

			if stop_state.is_stopped() {
				return Ok(());
			}

			info!("desegmenter_validation: finished validating and rebuilding");
			{
				// Save the new head to the db and rebuild the header by height index.
				let tip = Tip::from_header(&self.archive_header);

				batch.save_body_head(&tip)?;

				// Reset the body tail to the body head after a txhashset write
				batch.save_body_tail(&tip)?;
			}

			// Rebuild our output_pos index in the db based on fresh UTXO set.
			txhashset.init_output_pos_index(&header_pmmr, &batch)?;

			// Rebuild our NRD kernel_pos index based on recent kernel history.
			txhashset.init_recent_kernel_pos_index(&header_pmmr, &batch)?;

			// Commit all the changes to the db.
			batch.commit()?;

			info!("desegmenter_validation: finished committing the batch (head etc.)");
		}
		Ok(())
	}

	/// Return list of the next preferred segments the desegmenter needs based on
	/// the current real state of the underlying elements. Second array - list of delayed requests. We better to retry them
	/// 3-rd array - the list of waiting requests
	pub fn next_desired_segments(
		&self,
		need_requests: usize,
		requested: &dyn RequestLookup<(SegmentType, u64)>,
	) -> Result<
		(
			Vec<SegmentTypeIdentifier>,
			Vec<SegmentTypeIdentifier>,
			Vec<SegmentTypeIdentifier>,
		),
		Error,
	> {
		// First check for required bitmap elements
		if self.outputs_bitmap.read().is_none() {
			let mut bitmap_result: Vec<SegmentTypeIdentifier> = Vec::new();
			// For bitmaps there is no duplicated requests, there is not much data.
			for id in self
				.bitmap_segment_cache
				.read()
				.next_desired_segments(
					need_requests,
					requested,
					self.pibd_params.get_bitmaps_buffer_len(),
				)
				.0
			{
				bitmap_result.push(SegmentTypeIdentifier::new(SegmentType::Bitmap, id))
			}
			return Ok((bitmap_result, Vec::new(), Vec::new()));
		} else {
			// We have all required bitmap segments and have recreated our local
			// bitmap, now continue with other segments, evenly spreading requests
			// among MMRs
			debug_assert!(self.outputs_bitmap.read().is_some());
			debug_assert!(self.rangeproof_segment_cache.read().is_some());
			debug_assert!(self.kernel_segment_cache.read().is_some());
			debug_assert!(self.output_segment_cache.read().is_some());

			debug_assert!(need_requests > 0);
			let mut need_requests = need_requests;

			// Note, first requesting segments largest data items. Since item is large, the number of items per segment is low,
			// so the number of segments is high.
			let mut res_req: Vec<SegmentTypeIdentifier> = Vec::new();
			let mut res_dup_req: Vec<SegmentTypeIdentifier> = Vec::new();
			let mut waiting_req: Vec<SegmentTypeIdentifier> = Vec::new();

			self.query_requests(
				&mut need_requests,
				&self.kernel_segment_cache,
				requested,
				&mut res_req,
				&mut res_dup_req,
				&mut waiting_req,
			);

			self.query_requests(
				&mut need_requests,
				&self.output_segment_cache,
				requested,
				&mut res_req,
				&mut res_dup_req,
				&mut waiting_req,
			);

			self.query_requests(
				&mut need_requests,
				&self.rangeproof_segment_cache,
				requested,
				&mut res_req,
				&mut res_dup_req,
				&mut waiting_req,
			);

			return Ok((res_req, res_dup_req, waiting_req));
		}
	}

	fn query_requests<T>(
		&self,
		need_requests: &mut usize,
		cache: &RwLock<Option<SegmentsCache<T>>>,
		requested: &dyn RequestLookup<(SegmentType, u64)>,
		res_req: &mut Vec<SegmentTypeIdentifier>,
		res_dup_req: &mut Vec<SegmentTypeIdentifier>,
		waiting_req: &mut Vec<SegmentTypeIdentifier>,
	) {
		if *need_requests > 0 {
			let cache = cache.read();
			if let Some(cache) = &*cache {
				if !cache.is_complete() {
					let (requests, retry_requests, waiting_requests) = cache.next_desired_segments(
						*need_requests,
						requested,
						self.pibd_params.get_segments_buffer_len(),
					);
					debug_assert!(requests.len() <= *need_requests);
					*need_requests = need_requests.saturating_sub(requests.len());
					let segment_type = cache.get_segment_type();
					res_req.extend(
						requests
							.into_iter()
							.map(|id| SegmentTypeIdentifier::new(segment_type.clone(), id)),
					);
					res_dup_req.extend(
						retry_requests
							.into_iter()
							.map(|id| SegmentTypeIdentifier::new(segment_type.clone(), id)),
					);
					waiting_req.extend(
						waiting_requests
							.into_iter()
							.map(|id| SegmentTypeIdentifier::new(segment_type.clone(), id)),
					);
				}
			}
		}
	}

	/// 'Finalize' the bitmap accumulator, storing an in-memory copy of the bitmap for
	/// use in further validation and setting the accumulator on the underlying txhashset
	fn finalize_bitmap_init_segment_caches(&self) -> Result<(), Error> {
		trace!(
			"pibd_desegmenter: finalizing and caching bitmap - accumulator root: {}",
			self.outputs_bitmap_accumulator.read().root()
		);
		let bitmap = self.outputs_bitmap_accumulator.read().build_bitmap();
		let mut bitmap_pairs: Bitmap = Bitmap::new();

		for bit in bitmap.iter() {
			bitmap_pairs.add(bit);
			// also adding sibling
			if bit % 2 == 0 {
				bitmap_pairs.add(bit + 1);
			} else {
				bitmap_pairs.add(bit - 1);
			}
		}

		let rangeproof_segments = Self::generate_segments(
			constants::SINGLE_BULLET_PROOF_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			self.archive_header.output_mmr_size,
			Some(&bitmap_pairs),
		);
		let output_segments = Self::generate_segments(
			constants::PEDERSEN_COMMITMENT_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			self.archive_header.output_mmr_size,
			Some(&bitmap_pairs),
		);
		let kernel_segments = Self::generate_segments(
			TxKernel::DATA_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			self.archive_header.kernel_mmr_size,
			None,
		);

		info!("Bitmap data is arrived. Generating other segments - rangeproof_segments: {}, output_segments: {}, kernel_segments: {}", rangeproof_segments.len(), output_segments.len(), kernel_segments.len());

		*self.outputs_bitmap.write() = Some(bitmap);
		*self.output_segment_cache.write() =
			Some(SegmentsCache::new(SegmentType::Output, output_segments));
		*self.rangeproof_segment_cache.write() = Some(SegmentsCache::new(
			SegmentType::RangeProof,
			rangeproof_segments,
		));
		*self.kernel_segment_cache.write() =
			Some(SegmentsCache::new(SegmentType::Kernel, kernel_segments));
		Ok(())
	}

	// Calculate and store number of leaves and positions in the bitmap mmr given the number of
	// outputs specified in the header. Should be called whenever the header changes
	fn calc_bitmap_mmr_size(archive_header: &BlockHeader) -> u64 {
		// Number of leaves (BitmapChunks)
		let bitmap_mmr_leaf_count = (pmmr::n_leaves(archive_header.output_mmr_size) + 1023) / 1024;
		trace!(
			"pibd_desegmenter - expected number of leaves in bitmap MMR: {}",
			bitmap_mmr_leaf_count
		);
		// Total size of Bitmap PMMR
		let bitmap_mmr_size = 1 + pmmr::peaks(pmmr::insertion_to_pmmr_index(bitmap_mmr_leaf_count))
			.last()
			.unwrap_or(
				&(pmmr::peaks(pmmr::insertion_to_pmmr_index(bitmap_mmr_leaf_count - 1))
					.last()
					.unwrap()),
			)
			.clone();

		trace!(
			"pibd_desegmenter - expected size of bitmap MMR: {}",
			bitmap_mmr_size
		);
		bitmap_mmr_size
	}

	/// Adds and validates a bitmap chunk
	pub fn add_bitmap_segment(
		&self,
		segment: Segment<BitmapChunk>,
		bitmap_root_hash: &Hash,
	) -> Result<(), Error> {
		if *bitmap_root_hash != self.bitmap_root_hash {
			return Err(Error::InvalidBitmapRoot);
		}

		if !self.bitmap_segment_cache.read().has_segment(&segment.id()) {
			return Err(Error::InvalidSegmentId);
		}

		trace!("pibd_desegmenter: add bitmap segment");
		segment.validate(
			self.outputs_bitmap_mmr_size, // Last MMR pos at the height being validated, in this case of the bitmap root
			None,
			&self.bitmap_root_hash,
		)?;
		trace!("pibd_desegmenter: adding segment to cache");
		// All okay, add to our cached list of bitmap segments

		{
			let mut bitmap_segment_cache = self.bitmap_segment_cache.write();
			let mut bitmap_accumulator = self.outputs_bitmap_accumulator.write();

			bitmap_segment_cache.apply_new_segment(segment, false, |segm_v| {
				for segm in segm_v {
					trace!(
						"pibd_desegmenter: apply bitmap segment at segment {}",
						segm.identifier().leaf_offset()
					);
					let (_sid, _hash_pos, _hashes, _leaf_pos, leaf_data, _proof) = segm.parts();
					for chunk in leaf_data.into_iter() {
						bitmap_accumulator.append_chunk(chunk)?;
					}
				}
				Ok(())
			})?;
		}

		if self.bitmap_segment_cache.read().is_complete() {
			self.finalize_bitmap_init_segment_caches()?;
		}

		Ok(())
	}

	/// Adds a output segment
	pub fn add_output_segment(
		&self,
		segment: Segment<OutputIdentifier>,
		bitmap_root_hash: &Hash,
	) -> Result<(), Error> {
		if *bitmap_root_hash != self.bitmap_root_hash {
			return Err(Error::InvalidBitmapRoot);
		}

		if let Some(outputs_bitmap) = self.outputs_bitmap.read().as_ref() {
			if let Some(output_segment_cache) = self.output_segment_cache.write().as_mut() {
				if !output_segment_cache.has_segment(segment.id()) {
					return Err(Error::InvalidSegmentId);
				}

				trace!("pibd_desegmenter: add output segment");
				segment.validate(
					self.archive_header.output_mmr_size, // Last MMR pos at the height being validated
					Some(outputs_bitmap),
					&self.archive_header.output_root, // Output root we're checking for
				)?;

				let mut header_pmmr = self.header_pmmr.write();
				let mut txhashset = self.txhashset.write();
				let mut batch = self.store.batch_write()?;

				output_segment_cache.apply_new_segment(segment, true, |segm| {
					if log_enabled!(Level::Trace) {
						trace!(
							"pibd_desegmenter: applying output segment at segment {}-{}",
							segm.first().unwrap().identifier().leaf_offset(),
							segm.last().unwrap().identifier().leaf_offset()
						);
					}
					txhashset::extending(
						&mut header_pmmr,
						&mut txhashset,
						&mut batch,
						|ext, _batch| {
							let extension = &mut ext.extension;
							extension.apply_output_segments(segm, outputs_bitmap)?;
							Ok(())
						},
					)?;
					Ok(())
				})?;
				return Ok(());
			}
		}
		return Err(Error::BitmapNotReady);
	}

	/// Adds a Rangeproof segment
	pub fn add_rangeproof_segment(
		&self,
		segment: Segment<RangeProof>,
		bitmap_root_hash: &Hash,
	) -> Result<(), Error> {
		if *bitmap_root_hash != self.bitmap_root_hash {
			return Err(Error::InvalidBitmapRoot);
		}

		if let Some(outputs_bitmap) = self.outputs_bitmap.read().as_ref() {
			if let Some(rangeproof_segment_cache) = self.rangeproof_segment_cache.write().as_mut() {
				if !rangeproof_segment_cache.has_segment(segment.id()) {
					return Err(Error::InvalidSegmentId);
				}

				trace!("pibd_desegmenter: add rangeproof segment");
				segment.validate(
					self.archive_header.output_mmr_size, // Last MMR pos at the height being validated
					Some(outputs_bitmap),
					&self.archive_header.range_proof_root, // Range proof root we're checking for
				)?;

				let mut header_pmmr = self.header_pmmr.write();
				let mut txhashset = self.txhashset.write();
				let mut batch = self.store.batch_write()?;

				rangeproof_segment_cache.apply_new_segment(segment, true, |seg| {
					trace!(
						"pibd_desegmenter: applying rangeproof segment at segment {}-{}",
						seg.first().unwrap().identifier().leaf_offset(),
						seg.last().unwrap().identifier().leaf_offset(),
					);
					txhashset::extending(
						&mut header_pmmr,
						&mut txhashset,
						&mut batch,
						|ext, _batch| {
							let extension = &mut ext.extension;
							extension.apply_rangeproof_segments(seg, outputs_bitmap)?;
							Ok(())
						},
					)?;
					Ok(())
				})?;

				return Ok(());
			}
		}

		return Err(Error::BitmapNotReady);
	}

	/// Adds a Kernel segment
	pub fn add_kernel_segment(
		&self,
		segment: Segment<TxKernel>,
		bitmap_root_hash: &Hash,
	) -> Result<(), Error> {
		if *bitmap_root_hash != self.bitmap_root_hash {
			return Err(Error::InvalidBitmapRoot);
		}

		if let Some(kernel_segment_cache) = self.kernel_segment_cache.write().as_mut() {
			if !kernel_segment_cache.has_segment(segment.id()) {
				return Err(Error::InvalidSegmentId);
			}

			trace!("pibd_desegmenter: add kernel segment");
			segment.validate(
				self.archive_header.kernel_mmr_size, // Last MMR pos at the height being validated
				None,
				&self.archive_header.kernel_root, // Kernel root we're checking for
			)?;

			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let mut batch = self.store.batch_write()?;

			kernel_segment_cache.apply_new_segment(segment, false, |segm| {
				trace!(
					"pibd_desegmenter: applying kernel segment at segment {}-{}",
					segm.first().unwrap().identifier().leaf_offset(),
					segm.last().unwrap().identifier().leaf_offset(),
				);
				txhashset::extending(
					&mut header_pmmr,
					&mut txhashset,
					&mut batch,
					|ext, _batch| {
						let extension = &mut ext.extension;
						extension.apply_kernel_segments(segm)?;
						Ok(())
					},
				)?;
				Ok(())
			})?;

			return Ok(());
		}

		return Err(Error::BitmapNotReady);
	}

	// Rough estimation of the segment size. This method is overestimated on hashes, so we should be below real data size limit
	fn estimate_segment_size(leaves_num: u64, capacity: u64, leaf_size: usize) -> u64 {
		debug_assert!(leaves_num <= capacity);
		debug_assert!(capacity > 0);

		let mut hash_num = 0;
		let mut cur_cap = capacity / 2;
		debug_assert!(leaves_num % 2 == 0); // Ciblings are expected to be here
		let hash_per_line = leaves_num / 2;
		while cur_cap > 0 {
			hash_num += std::cmp::min(cur_cap, hash_per_line);
			cur_cap /= 2;
		}

		// Node hash is 32 bytes. Positions for all are 8 bytes. Assuming that empty is proportional to the fill ratio
		let full_leaves_size = leaves_num * (leaf_size as u64 + 8);
		let full_hashes_size = hash_num * (32 + 8);
		full_leaves_size + full_hashes_size
	}

	// Return the segments and position of the next leaf
	fn calc_next_segment(
		leaf_size: usize,
		data_size_limit: usize,
		bitmap: &Bitmap,
		current_leave: u64,
		leaves_num: u64,
	) -> (Vec<SegmentIdentifier>, u64) {
		// Let's find the optimal height for the next pair of segments (second segment can be splitted in smaller)
		let mut cur_height = 6;
		let mut cur_capacity = SegmentIdentifier::segment_capacity_ex(cur_height);
		let mut leaves_num1 =
			bitmap.range_cardinality(current_leave as u32..(current_leave + cur_capacity) as u32);
		let mut leaves_num2 = bitmap.range_cardinality(
			(current_leave + cur_capacity) as u32..(current_leave + cur_capacity * 2) as u32,
		);

		while cur_height < 128 && current_leave + cur_capacity < leaves_num {
			let next_size =
				Self::estimate_segment_size(leaves_num1 + leaves_num2, cur_capacity * 2, leaf_size);
			let can_increase_capacity = current_leave % (cur_capacity * 2) == 0;

			// We can't generate the empty segment, more preferable solution to get over capacity.
			if can_increase_capacity && next_size <= data_size_limit as u64 {
				cur_height += 1;
				cur_capacity *= 2;
				leaves_num1 += leaves_num2;
				leaves_num2 = bitmap.range_cardinality(
					(current_leave + cur_capacity) as u32
						..(current_leave + cur_capacity * 2) as u32,
				);
				continue;
			}

			if leaves_num1 == 0 {
				debug!("Requesting PIBD segment with zero elements, PIDB validation might fail if pruning is in the progress, but chances for that is low. Also that problem will be gone after few hours.");
			}

			// The first segment height if found. Checking if it really is.
			#[cfg(debug_assertions)]
			{
				let s1_size = Self::estimate_segment_size(leaves_num1, cur_capacity, leaf_size);
				let s2_size = Self::estimate_segment_size(leaves_num2, cur_capacity, leaf_size);
				debug_assert!(s1_size <= data_size_limit as u64); // Might happen, but very not likely. In this case investigate if it is really true and if other nodes will be able to deal with that.
				debug_assert!(s2_size > 0 || !can_increase_capacity); // otherwise  s1_size + s2_size <= data_size_limit is true. Note, there is can_increase_capacity but it passing on the real data for now
			}

			debug_assert!(cur_capacity == SegmentIdentifier::segment_capacity_ex(cur_height));
			debug_assert!(current_leave % cur_capacity == 0);

			let segm_idx = current_leave / cur_capacity;
			return (
				vec![SegmentIdentifier::new(cur_height, segm_idx)],
				current_leave + cur_capacity,
			);
		}

		// Case when we have only one segment, no pairs. It is totally fine, must be last segment, no needs to have a pair for it
		debug_assert!(current_leave + cur_capacity >= leaves_num);
		debug_assert!(current_leave % cur_capacity == 0);
		(
			vec![SegmentIdentifier::new(
				cur_height,
				current_leave / cur_capacity,
			)],
			current_leave + cur_capacity * 2,
		)
	}

	/// Genarate segments that suppose to fit into the memory
	pub fn generate_segments(
		leaf_size: usize,
		data_size_limit: usize,
		target_mmr_size: u64,
		bitmap: Option<&Bitmap>,
	) -> Vec<SegmentIdentifier> {
		// for the data size we will use estimation based on the density
		match bitmap {
			Some(bitmap) => {
				// prunable PMMR, we can use variable length
				// Note, every segment have to have some data
				let leaves_num = pmmr::n_leaves(target_mmr_size);
				// last leave expected to be in the bitmap because it is outputs that can be spendable
				debug_assert!(bitmap.contains((leaves_num - 1) as u32));
				debug_assert!(leaves_num % 2 == 1 || !bitmap.contains((leaves_num - 1 + 1) as u32));
				debug_assert!(!bitmap.contains((leaves_num - 1 + 2) as u32));

				let mut current_leave = 0;
				let mut res: Vec<SegmentIdentifier> = Vec::new();
				while current_leave < leaves_num {
					let (mut segms, next_leave) = Self::calc_next_segment(
						leaf_size,
						data_size_limit,
						bitmap,
						current_leave,
						leaves_num,
					);
					debug_assert!(!segms.is_empty());
					debug_assert!(next_leave > current_leave);
					#[cfg(debug_assertions)]
					{
						for s in &segms {
							debug!("Extracting segments: {}", s);
							debug!(
								"New current_leave={}  leaves_num={}",
								current_leave, leaves_num
							);
						}
					}

					res.append(&mut segms);
					current_leave = next_leave;
				}

				#[cfg(debug_assertions)]
				{
					// let's validate if generated data covers all the leaves
					debug_assert!(res.first().unwrap().leaf_offset() == 0);

					for i in 1..res.len() {
						let s1 = res[i - 1];
						let s2 = res[i];
						let (_pos11, pos12) = s1.segment_pos_range(target_mmr_size);
						let (pos21, _pos22) = s2.segment_pos_range(target_mmr_size);
						debug_assert!(pos12 < pos21);
						debug_assert!(pos12 + 15 >= pos21); // + X depends on the Two mountains heights difference that we are merging. Values might be increased whaen chain become larger.
					}

					let last = res.last().unwrap();
					let (pos1, pos2) = last.segment_pos_range(target_mmr_size);
					debug_assert!(pos1 < target_mmr_size);
					debug_assert!(pos2 + 1 == target_mmr_size);
				}

				res
			}
			None => {
				// Non prunable mmr, easy case. All segemnst are the same size. Just leaves, no
				// intermediate hashes.
				let mut best_height = 4;
				// Finding max height that generates segments below data size limit
				for height in 6..128 {
					let leaves_num = SegmentIdentifier::segment_capacity_ex(height);
					// 8 bytes for position
					if leaves_num * (leaf_size + 8) as u64 > data_size_limit as u64 {
						best_height = height - 1;
						break;
					}
				}
				// For found best_height generating series of the segments with the same height
				let mut res: Vec<SegmentIdentifier> = Vec::new();
				let leaves_num = SegmentIdentifier::segment_capacity_ex(best_height);
				let segments_num = (pmmr::n_leaves(target_mmr_size) + leaves_num - 1) / leaves_num;
				for segm_idx in 0..segments_num {
					res.push(SegmentIdentifier::new(best_height, segm_idx));
				}
				res
			}
		}
	}
}
