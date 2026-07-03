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

use crate::error::Error;
use crate::store::PendingChainOperation;
use crate::txhashset;
use crate::txhashset::{BitmapAccumulator, BitmapChunk, TxHashSet};
use crate::types::{SyncStatusUpdateThrottle, Tip, TxHashsetStateValidationStage};
use crate::{pibd_params, store};
use crate::{Chain, SyncState, SyncStatus};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::pmmr;
use mwc_core::core::{
	BlockHeader, BlockSums, OutputIdentifier, Segment, SegmentIdentifier, SegmentType,
	SegmentTypeIdentifier, TxKernel,
};
use mwc_core::ser::PMMRable;
use mwc_crates::num_cpus;
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp::pedersen::RangeProof;
use mwc_util::StopState;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::pibd_params::PibdParams;
use crate::txhashset::request_lookup::RequestLookup;
use crate::txhashset::segments_cache::SegmentsCache;
use mwc_crates::croaring::Bitmap;
use mwc_crates::log::Level;
use mwc_crates::log::{debug, info, log_enabled, trace, warn};
use mwc_crates::secp::{constants, ContextFlag, Secp256k1};
use std::convert::TryFrom;

const MIN_NON_PRUNABLE_SEGMENT_HEIGHT: u8 = 5;
const MAX_NON_PRUNABLE_SEGMENT_HEIGHT: u8 = 127;

/// Desegmenter for rebuilding a txhashset from PIBD segments
/// Note!!! header_pmmr, txhashset & store are from the Chain. Same locking rules are applicable
pub struct Desegmenter {
	txhashset: Arc<RwLock<TxHashSet>>,
	header_pmmr: Arc<RwLock<txhashset::PMMRHandle<BlockHeader>>>,
	archive_header: BlockHeader,
	bitmap_root_hash: Hash, // bitmap root hash must come as a result of handshake process
	store: Arc<store::ChainStore>,

	genesis: BlockHeader,
	requires_init_recovery: Arc<AtomicBool>,

	outputs_bitmap_accumulator: RwLock<BitmapAccumulator>, // Lock 1
	outputs_bitmap_mmr_size: u64,
	/// In-memory 'raw' bitmap corresponding to contents of bitmap accumulator
	outputs_bitmap: RwLock<Option<Bitmap>>,

	bitmap_segment_cache: RwLock<SegmentsCache<BitmapChunk>>, // Lock 1
	output_segment_cache: RwLock<Option<SegmentsCache<OutputIdentifier>>>,
	rangeproof_segment_cache: RwLock<Option<SegmentsCache<RangeProof>>>,
	kernel_segment_cache: RwLock<Option<SegmentsCache<TxKernel>>>,

	pibd_params: Arc<PibdParams>,
	progress_logged: AtomicU64,
}

fn kernel_validation_thread_range(
	height: u64,
	thr_idx: usize,
	num_threads: usize,
) -> Result<(u64, u64), Error> {
	// start_height = current.height * (thr_idx + 1) as u64 / num_cores as u64;
	// end_height = current.height * thr_idx as u64 / num_cores as u64;

	if num_threads == 0 {
		return Err(Error::DataOverflow(
			"Desegmenter::validate_complete_state, num_threads=0".to_string(),
		));
	}

	let start_factor = thr_idx.checked_add(1).ok_or_else(|| {
		Error::DataOverflow(format!(
			"Desegmenter::validate_complete_state, thr_idx={}",
			thr_idx
		))
	})?;
	let end_factor = thr_idx as u64;

	let start_height = height
		.checked_mul(start_factor as u64)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Desegmenter::validate_complete_state, height={} start_factor={}",
				height, start_factor
			))
		})?
		.checked_div(num_threads as u64)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Desegmenter::validate_complete_state, num_threads={}",
				num_threads
			))
		})?;
	let end_height = height
		.checked_mul(end_factor)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Desegmenter::validate_complete_state, height={} end_factor={}",
				height, end_factor
			))
		})?
		.checked_div(num_threads as u64)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Desegmenter::validate_complete_state, num_threads={}",
				num_threads
			))
		})?;

	Ok((start_height, end_height))
}

impl Desegmenter {
	fn non_prunable_segment_height(leaf_size: usize, data_size_limit: usize) -> Result<u8, Error> {
		// Non-prunable MMR, easy case. All segments are the same size. Just leaves,
		// no intermediate hashes.
		// Conversion usize -> u64  is safe
		let data_size_limit = data_size_limit as u64;
		let leaf_size_with_pos = leaf_size.checked_add(8).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Desegmenter::non_prunable_segment_height, leaf_size={}",
				leaf_size
			))
		})?;
		// Conversion usize -> u64  is safe
		let leaf_size_with_pos = leaf_size_with_pos as u64;
		let segment_size = |height| -> Result<u64, Error> {
			let leaves_num = SegmentIdentifier::segment_capacity_ex(height)?;
			leaves_num.checked_mul(leaf_size_with_pos).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::non_prunable_segment_height, height={} leaves_num={} leaf_size_with_pos={}",
					height, leaves_num, leaf_size_with_pos
				))
			})
		};

		let min_segment_size = segment_size(MIN_NON_PRUNABLE_SEGMENT_HEIGHT)?;
		if min_segment_size > data_size_limit {
			return Err(Error::DataOverflow(format!(
				"Desegmenter::non_prunable_segment_height, minimum segment size {} at height={} exceeds data_size_limit={}",
				min_segment_size, MIN_NON_PRUNABLE_SEGMENT_HEIGHT, data_size_limit
			)));
		}

		// Finding max height that generates segments below data size limit
		for height in (MIN_NON_PRUNABLE_SEGMENT_HEIGHT + 1)..=MAX_NON_PRUNABLE_SEGMENT_HEIGHT {
			if segment_size(height)? > data_size_limit {
				return Ok(height - 1);
			}
		}
		Ok(MAX_NON_PRUNABLE_SEGMENT_HEIGHT)
	}

	/// Count fixed-size segments needed to cover a non-prunable PMMR.
	pub fn count_non_prunable_segments(
		leaf_size: usize,
		data_size_limit: usize,
		target_mmr_size: u64,
	) -> Result<u64, Error> {
		let best_height = Self::non_prunable_segment_height(leaf_size, data_size_limit)?;
		let leaves_num = SegmentIdentifier::segment_capacity_ex(best_height)?;
		let total_leaves = pmmr::n_leaves(target_mmr_size)?;
		total_leaves
			.checked_add(leaves_num)
			.and_then(|x| x.checked_sub(1))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::count_non_prunable_segments, total_leaves={} leaves_num={}",
					total_leaves, leaves_num
				))
			})
			.map(|x| x / leaves_num)
	}

	fn ensure_robust(&self) -> Result<(), Error> {
		if self.requires_init_recovery.load(Ordering::SeqCst) {
			return Err(Error::ChainRestartRequired);
		}
		Ok(())
	}

	fn require_init_recovery(&self, reason: impl std::fmt::Display) {
		let was_required = self.requires_init_recovery.swap(true, Ordering::SeqCst);
		warn!(
			"pibd_desegmenter: init recovery required: {}; archive_header_height={}, bitmap_root_hash={}, already_required={}; subsequent PIBD desegmenter operations will return ChainRestartRequired",
			reason, self.archive_header.height, self.bitmap_root_hash, was_required,
		);
	}

	fn ensure_header_pmmr_locked_for_marker(&self, op_name: &str) -> Result<(), Error> {
		// Defensive invariant check: parking_lot does not expose lock ownership,
		// so this proves only that the lock is not currently free.
		if let Some(header_pmmr) = self.header_pmmr.try_write() {
			drop(header_pmmr);
			return Err(Error::Other(format!(
				"{} attempted to set a chain operation marker without holding header_pmmr lock",
				op_name
			)));
		}
		Ok(())
	}

	fn ensure_archive_header_canonical(
		&self,
		header_pmmr: &txhashset::PMMRHandle<BlockHeader>,
	) -> Result<(), Error> {
		let archive_hash = self.archive_header.hash(self.store.get_context_id())?;
		let canonical_hash = header_pmmr.get_header_hash_by_height(self.archive_header.height)?;
		if archive_hash != canonical_hash {
			return Err(Error::Other(format!(
				"Desegmenter::validate_complete_state, archive header {} at height {} is no longer canonical, current header {}",
				archive_hash, self.archive_header.height, canonical_hash
			)));
		}
		Ok(())
	}

	fn set_pending_operation(&self, op: &PendingChainOperation) -> Result<(), Error> {
		self.ensure_header_pmmr_locked_for_marker("desegmenter set_pending_operation")?;
		match self.store.set_pending_chain_operation(op) {
			Ok(()) => Ok(()),
			Err(e) => {
				self.require_init_recovery(format_args!(
					"failed to set pending chain operation {:?}: {}",
					op, e
				));
				Err(e.into())
			}
		}
	}

	fn clear_pending_operation_checked(&self) -> Result<(), Error> {
		match self.store.clear_pending_chain_operation() {
			Ok(()) => Ok(()),
			Err(e) => {
				self.require_init_recovery(format_args!(
					"failed to clear pending chain operation marker: {}",
					e
				));
				Err(e.into())
			}
		}
	}

	/// Create a new segmenter based on the provided txhashset and the specified block header
	pub fn new(
		txhashset: Arc<RwLock<TxHashSet>>,
		header_pmmr: Arc<RwLock<txhashset::PMMRHandle<BlockHeader>>>,
		archive_header: BlockHeader,
		bitmap_root_hash: Hash,
		genesis: BlockHeader,
		store: Arc<store::ChainStore>,
		pibd_params: Arc<PibdParams>,
		requires_init_recovery: Arc<AtomicBool>,
	) -> Result<Desegmenter, Error> {
		info!(
			"Creating new desegmenter for bitmap_root_hash {}, height {}",
			bitmap_root_hash, archive_header.height
		);

		let bitmap_mmr_size = Self::calc_bitmap_mmr_size(&archive_header)?;
		let bitmap_segments = Self::generate_segments(
			BitmapChunk::LEN_BYTES,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			bitmap_mmr_size,
			None,
		)?;
		let context_id = store.get_context_id();

		Ok(Desegmenter {
			txhashset,
			header_pmmr,
			archive_header,
			bitmap_root_hash,
			store,
			genesis,
			requires_init_recovery,
			outputs_bitmap_accumulator: RwLock::new(BitmapAccumulator::new(context_id)),
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
			progress_logged: AtomicU64::new(0),
		})
	}

	/// Access to root hash
	pub fn get_bitmap_root_hash(&self) -> &Hash {
		&self.bitmap_root_hash
	}

	/// Reset all state
	pub fn reset(&self) {
		// Keep this lock order in sync with add_bitmap_segment().
		let mut bitmap_segment_cache = self.bitmap_segment_cache.write();
		let mut bitmap_accumulator = self.outputs_bitmap_accumulator.write();

		bitmap_segment_cache.reset();
		bitmap_accumulator.reset();
		*self.output_segment_cache.write() = None;
		*self.rangeproof_segment_cache.write() = None;
		*self.kernel_segment_cache.write() = None;
		*self.outputs_bitmap.write() = None;
	}

	/// Return reference to the header used for validation
	pub fn header(&self) -> &BlockHeader {
		&self.archive_header
	}

	/// Whether we have all the segments we need
	pub fn is_complete(&self) -> bool {
		if !self
			.output_segment_cache
			.read_recursive()
			.as_ref()
			.map(|c| c.is_complete())
			.unwrap_or(false)
		{
			return false;
		}
		if !self
			.rangeproof_segment_cache
			.read_recursive()
			.as_ref()
			.map(|c| c.is_complete())
			.unwrap_or(false)
		{
			return false;
		}
		if !self
			.kernel_segment_cache
			.read_recursive()
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
			let cache = self.bitmap_segment_cache.read_recursive();
			(
				cache.get_required_segments_num(),
				cache.get_accepted_segments(),
			)
		};

		let (req2, rec2) = self
			.output_segment_cache
			.read_recursive()
			.as_ref()
			.map(|cache| {
				(
					cache.get_required_segments_num(),
					cache.get_accepted_segments(),
				)
			})
			.unwrap_or((100, 0));
		let (req3, rec3) = self
			.rangeproof_segment_cache
			.read_recursive()
			.as_ref()
			.map(|cache| {
				(
					cache.get_required_segments_num(),
					cache.get_accepted_segments(),
				)
			})
			.unwrap_or((400, 0));
		let (req4, rec4) = self
			.kernel_segment_cache
			.read_recursive()
			.as_ref()
			.map(|cache| {
				(
					cache.get_required_segments_num(),
					cache.get_accepted_segments(),
				)
			})
			.unwrap_or((1000, 0));

		// Safe: each required count is the length of a real Vec<SegmentIdentifier>
		// or a small fallback constant, and there are only four caches. Each received
		// count is a cursor bounded by its corresponding required count.
		let required = req1 + req2 + req3 + req4;
		let received = rec1 + rec2 + rec3 + rec4;

		// Should be updated once in every 3 seconds.
		if self.progress_logged.fetch_add(1, Ordering::Relaxed) % 15 == 0 {
			info!("PIBD sync progress: {} from {}", received, required);
		}

		SyncStatus::TxHashsetPibd {
			recieved_segments: received,
			total_segments: required,
		}
	}

	/// Once the PIBD set is downloaded, we need to ensure that the respective leaf sets
	/// match the bitmap (particularly in the case of outputs being spent after a PIBD catch-up)
	pub fn check_update_leaf_set_state(&self) -> Result<(), Error> {
		self.ensure_robust()?;
		let outputs_bitmap = self.outputs_bitmap.read_recursive();
		let outputs_bitmap = outputs_bitmap.as_ref().ok_or(Error::BitmapNotReady)?;

		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		self.set_pending_operation(&PendingChainOperation::PibdReset)?;
		let res = (|| {
			let mut _batch = self.store.batch_write()?;
			txhashset::extending(&mut header_pmmr, &mut txhashset, &mut _batch, |ext, _| {
				let extension = &mut ext.extension;
				extension.update_leaf_sets(outputs_bitmap)?;
				Ok(())
			})?;
			Ok(())
		})();
		match res {
			Ok(()) => self.clear_pending_operation_checked(),
			Err(e) => {
				self.require_init_recovery(format_args!(
					"check_update_leaf_set_state failed while updating txhashset leaf sets: {}",
					e
				));
				Err(e)
			}
		}
	}

	fn validate_kernel_history_parallel(
		&self,
		status: Arc<SyncState>,
		stop_state: Arc<StopState>,
		thread_name_prefix: &str,
	) -> Result<(), Error> {
		let txhashset = self.txhashset.clone();
		let current = self.archive_header.clone();
		let total = current.height;
		status.update(SyncStatus::ValidatingKernelsHistory {
			headers: 0,
			headers_total: total,
		});

		let num_cores = num_cpus::get();
		if num_cores == 0 {
			return Err(Error::DataOverflow(
				"Desegmenter::validate_complete_state, num_cores=0".to_string(),
			));
		}

		let header_pmmr = self.header_pmmr.read_recursive();
		self.ensure_archive_header_canonical(&header_pmmr)?;
		let mut handles = Vec::with_capacity(num_cores);
		let mut first_error = None;
		let processed = Arc::new(AtomicU64::new(0));
		let status_throttle = Arc::new(SyncStatusUpdateThrottle::new());
		for thr_idx in 0..num_cores {
			let handle_result =
				(|| -> Result<std::thread::JoinHandle<Result<(), Error>>, Error> {
					let (start_height, end_height) =
						kernel_validation_thread_range(current.height, thr_idx, num_cores)?;
					let start_block_hash = header_pmmr.get_header_hash_by_height(start_height)?;
					let start_block = self
						.txhashset
						.read_recursive()
						.get_block_header(&start_block_hash)?;
					let processed = processed.clone();
					if start_block.height != start_height {
						return Err(Error::InvalidSegment(format!(
							"Desegmenter::validate_complete_state, start_block.height={} start_height={}",
							start_block.height, start_height
						)));
					}
					let txhashset = txhashset.clone();
					let status = status.clone();
					let stop_state = stop_state.clone();
					let status_throttle = status_throttle.clone();
					let thread_name = format!("{}_{}", thread_name_prefix, thr_idx);

					std::thread::Builder::new()
						.name(thread_name)
						.spawn(move || {
							txhashset::rewindable_kernel_view(
								&*txhashset.read_recursive(),
								|view, batch| {
									let mut start_block = start_block.clone();
									while start_block.height > end_height {
										view.rewind(&start_block)?;
										view.validate_root()?;
										start_block = batch.get_previous_header(&start_block)?;
										let completed = processed
											.fetch_add(1, Ordering::Relaxed)
											.saturating_add(1);
										if status_throttle.should_update(completed == total) {
											status.update(SyncStatus::ValidatingKernelsHistory {
												headers: completed,
												headers_total: total,
											});
										}
										if stop_state.is_stopped() {
											return Err(Error::Stopped);
										}
									}
									Ok(())
								},
							)
						})
						.map_err(|e| {
							Error::Other(format!(
								"Unable to start a new thread for validating blocks, {}",
								e
							))
						})
				})();
			match handle_result {
				Ok(handle) => handles.push(handle),
				Err(e) => {
					first_error = Some(e);
					break;
				}
			}
		}
		for handle in handles {
			match handle
				.join()
				.map_err(|_| Error::Other("validating_blocks thread runtime error".into()))
			{
				Ok(Ok(_)) => {}
				Ok(Err(e)) | Err(e) => {
					if first_error.is_none() {
						first_error = Some(e);
					}
				}
			}
		}
		if let Some(e) = first_error {
			return Err(e);
		}
		debug!(
			"desegmenter validation: validated kernel root on {} headers",
			processed.load(Ordering::Relaxed)
		);
		Ok(())
	}

	/// This is largely copied from chain.rs txhashset_write and related functions,
	/// the idea being that the txhashset version will eventually be removed
	pub fn validate_complete_state(
		&self,
		status: Arc<SyncState>,
		stop_state: Arc<StopState>,
	) -> Result<(), Error> {
		self.ensure_robust()?;
		// Quick root check first:
		{
			let txhashset = self.txhashset.read_recursive();
			txhashset.roots()?.validate(&self.archive_header)?;
		}

		// Validate full kernel history.
		// Check the kernel MMR root for every block header, then check NRD
		// relative height rules for the full kernel history.
		{
			info!("desegmenter validation: validating kernel history");
			self.validate_kernel_history_parallel(
				status.clone(),
				stop_state.clone(),
				"validating_kernel_history",
			)?;
			let header_pmmr = self.header_pmmr.read_recursive();
			self.ensure_archive_header_canonical(&header_pmmr)?;
			let txhashset = self.txhashset.read_recursive();
			let batch = self.store.batch_write()?;
			txhashset.verify_kernel_pos_index(
				&self.genesis,
				&header_pmmr,
				&batch,
				Some(status.clone()),
				Some(stop_state.clone()),
			)?;
		}

		if stop_state.is_stopped() {
			return Err(Error::Stopped);
		}

		// Prepare a new batch and update all the required records
		let mut header_pmmr = self.header_pmmr.write();
		self.ensure_archive_header_canonical(&header_pmmr)?;
		let mut txhashset = self.txhashset.write();
		self.set_pending_operation(&PendingChainOperation::PibdReset)?;
		let res = (|| {
			info!("desegmenter validation: rewinding a 2nd time (writeable)");
			let mut batch = self.store.batch_write()?;
			let archive_tip = Tip::try_from_header(&self.archive_header)?;
			txhashset::extending_with_head(
				&mut header_pmmr,
				&mut txhashset,
				&mut batch,
				archive_tip,
				|ext, batch| {
					let extension = &mut ext.extension;
					let header_extension = &mut ext.header_extension;
					{
						let status_throttle = SyncStatusUpdateThrottle::new();
						let mut rewind_progress = |current: u64, total: u64| {
							let total = total.max(1);
							let current = current.min(total);
							if status_throttle.should_update(current == total) {
								status.update(SyncStatus::TxHashsetStateValidation {
									stage: TxHashsetStateValidationStage::Rewind,
									current,
									total,
								});
							}
							if stop_state.is_stopped() {
								return Err(Error::Stopped);
							}
							Ok(())
						};
						extension.rewind(
							&self.archive_header,
							batch,
							header_extension,
							Some(&mut rewind_progress),
						)?;
					}

					let secp = Secp256k1::with_caps(ContextFlag::Commit)?;

					// Validate the extension, generating the utxo_sum and kernel_sum.
					// Full validation, including rangeproofs and kernel signature verification.
					let (utxo_sum, kernel_sum) = extension.validate(
						&self.genesis,
						false,
						Some(status.clone()),
						&self.archive_header,
						Some(stop_state.clone()),
						&secp,
					)?;

					if stop_state.is_stopped() {
						return Err(Error::Stopped);
					}

					// Save the block_sums (utxo_sum, kernel_sum) to the db for use later.
					batch.save_block_sums(
						&self.archive_header.hash(self.store.get_context_id())?,
						BlockSums::new(utxo_sum, kernel_sum),
					)?;

					Ok(())
				},
			)?;

			if stop_state.is_stopped() {
				return Err(Error::Stopped);
			}

			info!("desegmenter_validation: finished validating and rebuilding");
			{
				// Save the new head to the db and rebuild the header by height index.
				let tip = Tip::try_from_header(&self.archive_header)?;

				batch.save_body_head(&tip)?;
				// PIBD restores txhashset/header state, but it does not store the
				// archive header full block body. Keep BODY_TAIL empty until the
				// first post-PIBD full block is downloaded and saved.
				batch.delete_body_tail()?;
			}

			// Rebuild our output_pos index in the db based on fresh UTXO set.
			txhashset.init_output_pos_index(
				&batch,
				Some(status.clone()),
				Some(stop_state.clone()),
			)?;

			// Rebuild our NRD kernel_pos index based on recent kernel history.
			txhashset.init_recent_kernel_pos_index(
				&header_pmmr,
				&batch,
				Some(status.clone()),
				Some(stop_state.clone()),
			)?;

			// The full kernel excess index is rebuilt after this commit in chunks.
			batch.set_kernel_pos_index_complete(false)?;
			batch.set_retained_spent_commitment_index_complete(false)?;

			// Commit all the changes to the db.
			batch.commit()?;

			info!("desegmenter_validation: finished committing the batch (head etc.)");
			txhashset.init_kernel_pos_index_chunked(
				&self.store,
				Some(status.clone()),
				Some(stop_state.clone()),
			)?;
			info!("desegmenter_validation: rebuilt full kernel_pos index");
			Chain::init_empty_retained_spent_commitment_index(self.store.as_ref())?;
			info!("desegmenter_validation: initialized empty spent commitment replay index");
			Ok(())
		})();
		match res {
			Ok(()) => self.clear_pending_operation_checked(),
			Err(e) => {
				self.require_init_recovery(format_args!(
					"validate_complete_state failed while validating and rebuilding txhashset: {}",
					e
				));
				Err(e)
			}
		}
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
		self.ensure_robust()?;
		if need_requests == 0 {
			return Ok((Vec::new(), Vec::new(), Vec::new()));
		}

		// First check for required bitmap elements
		if self.outputs_bitmap.read_recursive().is_none() {
			let mut bitmap_result: Vec<SegmentTypeIdentifier> = Vec::new();
			// For bitmaps there is no duplicated requests, there is not much data.
			for id in self
				.bitmap_segment_cache
				.read_recursive()
				.next_desired_segments(
					need_requests,
					requested,
					self.pibd_params.get_bitmaps_buffer_len(),
				)?
				.0
			{
				bitmap_result.push(SegmentTypeIdentifier::new(SegmentType::Bitmap, id))
			}
			return Ok((bitmap_result, Vec::new(), Vec::new()));
		} else {
			// We have all required bitmap segments and have recreated our local
			// bitmap, now continue with other segments, evenly spreading requests
			// among MMRs
			debug_assert!(self.outputs_bitmap.read_recursive().is_some());
			debug_assert!(self.rangeproof_segment_cache.read_recursive().is_some());
			debug_assert!(self.kernel_segment_cache.read_recursive().is_some());
			debug_assert!(self.output_segment_cache.read_recursive().is_some());

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
			)?;

			self.query_requests(
				&mut need_requests,
				&self.output_segment_cache,
				requested,
				&mut res_req,
				&mut res_dup_req,
				&mut waiting_req,
			)?;

			self.query_requests(
				&mut need_requests,
				&self.rangeproof_segment_cache,
				requested,
				&mut res_req,
				&mut res_dup_req,
				&mut waiting_req,
			)?;

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
	) -> Result<(), Error> {
		if *need_requests > 0 {
			let cache = cache.read_recursive();
			if let Some(cache) = &*cache {
				if !cache.is_complete() {
					let (requests, retry_requests, waiting_requests) = cache
						.next_desired_segments(
							*need_requests,
							requested,
							self.pibd_params.get_segments_buffer_len(),
						)?;
					debug_assert!(requests.len() <= *need_requests);
					*need_requests =
						need_requests.checked_sub(requests.len()).ok_or_else(|| {
							Error::DataOverflow(format!(
								"Desegmenter::query_requests, need_requests={} requests_len={}",
								*need_requests,
								requests.len()
							))
						})?;
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
		Ok(())
	}

	/// 'Finalize' the bitmap accumulator, storing an in-memory copy of the bitmap for
	/// use in further validation and setting the accumulator on the underlying txhashset
	fn finalize_bitmap_init_segment_caches(&self) -> Result<(), Error> {
		if self.outputs_bitmap.read_recursive().is_some() {
			return Ok(());
		}

		let bitmap = self
			.outputs_bitmap_accumulator
			.read_recursive()
			.build_bitmap()?;

		let rangeproof_leaf_size = RangeProof::elmt_size()
			.map(usize::from)
			.ok_or_else(|| Error::Other("RangeProof size must be fixed".into()))?;
		let rangeproof_segments = Self::generate_segments(
			rangeproof_leaf_size,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			self.archive_header.output_mmr_size,
			Some(&bitmap),
		)?;
		let output_segments = Self::generate_segments(
			constants::PEDERSEN_COMMITMENT_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			self.archive_header.output_mmr_size,
			Some(&bitmap),
		)?;
		let kernel_segments = Self::generate_segments(
			TxKernel::DATA_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			self.archive_header.kernel_mmr_size,
			None,
		)?;

		info!(
			"Bitmap data is arrived. Generating other segments - rangeproof_segments: {}, output_segments: {}, kernel_segments: {}",
			rangeproof_segments.len(),
			output_segments.len(),
			kernel_segments.len()
		);

		*self.output_segment_cache.write() =
			Some(SegmentsCache::new(SegmentType::Output, output_segments));
		*self.rangeproof_segment_cache.write() = Some(SegmentsCache::new(
			SegmentType::RangeProof,
			rangeproof_segments,
		));
		*self.kernel_segment_cache.write() =
			Some(SegmentsCache::new(SegmentType::Kernel, kernel_segments));
		*self.outputs_bitmap.write() = Some(bitmap);
		Ok(())
	}

	// Calculate and store number of leaves and positions in the bitmap mmr given the number of
	// outputs specified in the header. Should be called whenever the header changes
	fn calc_bitmap_mmr_size(archive_header: &BlockHeader) -> Result<u64, Error> {
		// Number of leaves (BitmapChunks)
		let output_leaves = pmmr::n_leaves(archive_header.output_mmr_size)?;
		let bitmap_mmr_leaf_count = output_leaves.checked_add(1023).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Desegmenter::calc_bitmap_mmr_size, output_leaves={}",
				output_leaves
			))
		})? / 1024;
		trace!(
			"pibd_desegmenter - expected number of leaves in bitmap MMR: {}",
			bitmap_mmr_leaf_count
		);
		if bitmap_mmr_leaf_count == 0 {
			return Ok(0);
		}
		// Total size of Bitmap PMMR
		let bitmap_mmr_pos = pmmr::insertion_to_pmmr_index(bitmap_mmr_leaf_count)?;
		let bitmap_peaks = pmmr::peaks(bitmap_mmr_pos)?;
		let last_peak = if let Some(last_peak) = bitmap_peaks.last() {
			*last_peak
		} else {
			let prev_leaf_count = bitmap_mmr_leaf_count.checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::calc_bitmap_mmr_size, bitmap_mmr_leaf_count={}",
					bitmap_mmr_leaf_count
				))
			})?;
			let prev_pos = pmmr::insertion_to_pmmr_index(prev_leaf_count)?;
			pmmr::peaks(prev_pos)?.last().copied().unwrap_or(0)
		};
		let bitmap_mmr_size = last_peak.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Desegmenter::calc_bitmap_mmr_size, last_peak={}",
				last_peak
			))
		})?;

		trace!(
			"pibd_desegmenter - expected size of bitmap MMR: {}",
			bitmap_mmr_size
		);
		Ok(bitmap_mmr_size)
	}

	/// Adds and validates a bitmap chunk
	pub fn add_bitmap_segment(
		&self,
		segment: Segment<BitmapChunk>,
		bitmap_root_hash: &Hash,
	) -> Result<(), Error> {
		self.ensure_robust()?;
		if *bitmap_root_hash != self.bitmap_root_hash {
			return Err(Error::InvalidBitmapRoot);
		}

		let cache_size_limit = self.pibd_params.get_bitmaps_buffer_len();
		{
			let bitmap_segment_cache = self.bitmap_segment_cache.read_recursive();
			if !bitmap_segment_cache.has_segment(segment.id())? {
				return Err(Error::InvalidSegmentId);
			}
			if bitmap_segment_cache.is_duplicate_segment(segment.id())? {
				return Ok(());
			}
			if !bitmap_segment_cache.is_segment_in_receive_window(segment.id(), cache_size_limit)? {
				return Err(Error::InvalidSegmentId);
			}
		}

		trace!("pibd_desegmenter: add bitmap segment");
		let segment = segment.validate(
			self.store.get_context_id(),
			self.outputs_bitmap_mmr_size, // Last MMR pos at the height being validated, in this case of the bitmap root
			None,
			&self.bitmap_root_hash,
		)?;
		trace!("pibd_desegmenter: adding segment to cache");
		// All okay, add to our cached list of bitmap segments

		let bitmap_cache_became_complete = {
			let mut bitmap_segment_cache = self.bitmap_segment_cache.write();
			let mut bitmap_accumulator = self.outputs_bitmap_accumulator.write();
			let was_complete = bitmap_segment_cache.is_complete();

			let res = bitmap_segment_cache.apply_new_segment(
				segment,
				false,
				cache_size_limit,
				|segm_v| {
					for segm in segm_v {
						trace!(
							"pibd_desegmenter: apply bitmap segment at segment {}",
							segm.identifier().leaf_offset()?
						);
						let (_sid, _hash_pos, _hashes, _leaf_pos, leaf_data, _proof) = segm.parts();
						for chunk in leaf_data.into_iter() {
							bitmap_accumulator.append_chunk(chunk)?;
						}
					}
					Ok(())
				},
			);

			match res {
				Ok(()) => !was_complete && bitmap_segment_cache.is_complete(),
				Err(e) => {
					self.require_init_recovery(format_args!(
						"add_bitmap_segment failed while applying bitmap chunks to accumulator: {}",
						e
					));
					return Err(e);
				}
			}
		};

		if bitmap_cache_became_complete {
			if let Err(e) = self.finalize_bitmap_init_segment_caches() {
				self.require_init_recovery(format_args!(
					"add_bitmap_segment failed while finalizing completed bitmap segment cache: {}",
					e
				));
				return Err(e);
			}
		}

		Ok(())
	}

	/// Adds a output segment
	pub fn add_output_segment(
		&self,
		segment: Segment<OutputIdentifier>,
		bitmap_root_hash: &Hash,
	) -> Result<(), Error> {
		self.ensure_robust()?;
		if *bitmap_root_hash != self.bitmap_root_hash {
			return Err(Error::InvalidBitmapRoot);
		}

		let cache_size_limit = self.pibd_params.get_segments_buffer_len();
		if let Some(outputs_bitmap) = self.outputs_bitmap.read_recursive().as_ref() {
			// Only hold the cache lock for cheap eligibility checks. Segment
			// authentication is CPU-heavy, so keeping it outside this lock lets
			// peer receive threads validate different segments concurrently.
			{
				let output_segment_cache = self.output_segment_cache.read_recursive();
				if let Some(output_segment_cache) = output_segment_cache.as_ref() {
					if !output_segment_cache.has_segment(segment.id())? {
						return Err(Error::InvalidSegmentId);
					}
					if output_segment_cache.is_duplicate_segment(segment.id())? {
						return Ok(());
					}
					if !output_segment_cache
						.is_segment_in_receive_window(segment.id(), cache_size_limit)?
					{
						return Err(Error::InvalidSegmentId);
					}
				} else {
					return Err(Error::BitmapNotReady);
				}
			}

			trace!("pibd_desegmenter: add output segment");
			let segment = segment.validate(
				self.store.get_context_id(),
				self.archive_header.output_mmr_size, // Last MMR pos at the height being validated
				Some(outputs_bitmap),
				&self.archive_header.output_root, // Output root we're checking for
			)?;

			// Another peer may have completed or advanced the cache while this
			// thread was validating, so repeat the cheap checks before mutating.
			if let Some(output_segment_cache) = self.output_segment_cache.write().as_mut() {
				if !output_segment_cache.has_segment(segment.id())? {
					return Err(Error::InvalidSegmentId);
				}
				if output_segment_cache.is_duplicate_segment(segment.id())? {
					return Ok(());
				}
				if !output_segment_cache
					.is_segment_in_receive_window(segment.id(), cache_size_limit)?
				{
					return Err(Error::InvalidSegmentId);
				}

				let mut header_pmmr = self.header_pmmr.write();
				let mut txhashset = self.txhashset.write();
				self.set_pending_operation(&PendingChainOperation::PibdReset)?;
				let res = (|| {
					let mut batch = self.store.batch_write()?;

					output_segment_cache.apply_new_segment(
						segment,
						true,
						cache_size_limit,
						|segm| {
							if log_enabled!(Level::Trace) {
								trace!(
									"pibd_desegmenter: applying output segment at segment {}-{}",
									segm.first()
										.ok_or(Error::Other(
											"add_output_segment, empty segm value".into()
										))?
										.identifier()
										.leaf_offset()?,
									segm.last()
										.ok_or(Error::Other(
											"add_output_segment, empty segm value".into()
										))?
										.identifier()
										.leaf_offset()?,
								);
							}
							txhashset::extending(
								&mut header_pmmr,
								&mut txhashset,
								&mut batch,
								|ext, _batch| {
									let extension = &mut ext.extension;
									// The segment was authenticated above; do not run the
									// Merkle proof/hash validation again while applying.
									extension
										.apply_validated_output_segments(segm, outputs_bitmap)?;
									Ok(())
								},
							)?;
							Ok(())
						},
					)?;
					Ok(())
				})();
				return match res {
					Ok(()) => self.clear_pending_operation_checked(),
					Err(e) => {
						self.require_init_recovery(format_args!(
							"add_output_segment failed while applying output segment to txhashset: {}",
							e
						));
						Err(e)
					}
				};
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
		self.ensure_robust()?;
		if *bitmap_root_hash != self.bitmap_root_hash {
			return Err(Error::InvalidBitmapRoot);
		}

		let cache_size_limit = self.pibd_params.get_segments_buffer_len();
		if let Some(outputs_bitmap) = self.outputs_bitmap.read_recursive().as_ref() {
			// Only hold the cache lock for cheap eligibility checks. Segment
			// authentication is CPU-heavy, so keeping it outside this lock lets
			// peer receive threads validate different segments concurrently.
			{
				let rangeproof_segment_cache = self.rangeproof_segment_cache.read_recursive();
				if let Some(rangeproof_segment_cache) = rangeproof_segment_cache.as_ref() {
					if !rangeproof_segment_cache.has_segment(segment.id())? {
						return Err(Error::InvalidSegmentId);
					}
					if rangeproof_segment_cache.is_duplicate_segment(segment.id())? {
						return Ok(());
					}
					if !rangeproof_segment_cache
						.is_segment_in_receive_window(segment.id(), cache_size_limit)?
					{
						return Err(Error::InvalidSegmentId);
					}
				} else {
					return Err(Error::BitmapNotReady);
				}
			}

			trace!("pibd_desegmenter: add rangeproof segment");
			let segment = segment.validate(
				self.store.get_context_id(),
				self.archive_header.output_mmr_size, // Last MMR pos at the height being validated
				Some(outputs_bitmap),
				&self.archive_header.range_proof_root, // Range proof root we're checking for
			)?;

			// Another peer may have completed or advanced the cache while this
			// thread was validating, so repeat the cheap checks before mutating.
			if let Some(rangeproof_segment_cache) = self.rangeproof_segment_cache.write().as_mut() {
				if !rangeproof_segment_cache.has_segment(segment.id())? {
					return Err(Error::InvalidSegmentId);
				}
				if rangeproof_segment_cache.is_duplicate_segment(segment.id())? {
					return Ok(());
				}
				if !rangeproof_segment_cache
					.is_segment_in_receive_window(segment.id(), cache_size_limit)?
				{
					return Err(Error::InvalidSegmentId);
				}

				let mut header_pmmr = self.header_pmmr.write();
				let mut txhashset = self.txhashset.write();
				self.set_pending_operation(&PendingChainOperation::PibdReset)?;
				let res = (|| {
					let mut batch = self.store.batch_write()?;

					rangeproof_segment_cache.apply_new_segment(
						segment,
						true,
						cache_size_limit,
						|seg| {
							trace!(
								"pibd_desegmenter: applying rangeproof segment at segment {}-{}",
								seg.first()
									.ok_or(Error::Other(
										"add_rangeproof_segment, empty seg value".into()
									))?
									.identifier()
									.leaf_offset()?,
								seg.last()
									.ok_or(Error::Other(
										"add_rangeproof_segment, empty seg value".into()
									))?
									.identifier()
									.leaf_offset()?,
							);
							txhashset::extending(
								&mut header_pmmr,
								&mut txhashset,
								&mut batch,
								|ext, _batch| {
									let extension = &mut ext.extension;
									// The segment was authenticated above; do not run the
									// Merkle proof/hash validation again while applying.
									extension
										.apply_validated_rangeproof_segments(seg, outputs_bitmap)?;
									Ok(())
								},
							)?;
							Ok(())
						},
					)?;

					Ok(())
				})();
				return match res {
					Ok(()) => self.clear_pending_operation_checked(),
					Err(e) => {
						self.require_init_recovery(format_args!(
							"add_rangeproof_segment failed while applying rangeproof segment to txhashset: {}",
							e
						));
						Err(e)
					}
				};
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
		self.ensure_robust()?;
		if *bitmap_root_hash != self.bitmap_root_hash {
			return Err(Error::InvalidBitmapRoot);
		}

		let cache_size_limit = self.pibd_params.get_segments_buffer_len();
		// Only hold the cache lock for cheap eligibility checks. Segment
		// authentication is CPU-heavy, so keeping it outside this lock lets peer
		// receive threads validate different segments concurrently.
		{
			let kernel_segment_cache = self.kernel_segment_cache.read_recursive();
			if let Some(kernel_segment_cache) = kernel_segment_cache.as_ref() {
				if !kernel_segment_cache.has_segment(segment.id())? {
					return Err(Error::InvalidSegmentId);
				}
				if kernel_segment_cache.is_duplicate_segment(segment.id())? {
					return Ok(());
				}
				if !kernel_segment_cache
					.is_segment_in_receive_window(segment.id(), cache_size_limit)?
				{
					return Err(Error::InvalidSegmentId);
				}
			} else {
				return Err(Error::BitmapNotReady);
			}
		}

		trace!("pibd_desegmenter: add kernel segment");
		let context_id = self.store.get_context_id();
		let kernel_mmr_size = self.archive_header.kernel_mmr_size;
		let kernel_root = self.archive_header.kernel_root;
		let segment = segment.validate(
			context_id,
			kernel_mmr_size, // Last MMR pos at the height being validated
			None,
			&kernel_root, // Kernel root we're checking for
		)?;

		// Another peer may have completed or advanced the cache while this
		// thread was validating, so repeat the cheap checks before mutating.
		if let Some(kernel_segment_cache) = self.kernel_segment_cache.write().as_mut() {
			if !kernel_segment_cache.has_segment(segment.id())? {
				return Err(Error::InvalidSegmentId);
			}
			if kernel_segment_cache.is_duplicate_segment(segment.id())? {
				return Ok(());
			}
			if !kernel_segment_cache.is_segment_in_receive_window(segment.id(), cache_size_limit)? {
				return Err(Error::InvalidSegmentId);
			}

			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			self.set_pending_operation(&PendingChainOperation::PibdReset)?;
			let res = (|| {
				let mut batch = self.store.batch_write()?;

				kernel_segment_cache.apply_new_segment(
					segment,
					false,
					cache_size_limit,
					|segm| {
						trace!(
							"pibd_desegmenter: applying kernel segment at segment {}-{}",
							segm.first()
								.ok_or(Error::Other("add_kernel_segment, empty segm value".into()))?
								.identifier()
								.leaf_offset()?,
							segm.last()
								.ok_or(Error::Other("add_kernel_segment, empty segm value".into()))?
								.identifier()
								.leaf_offset()?,
						);
						txhashset::extending(
							&mut header_pmmr,
							&mut txhashset,
							&mut batch,
							|ext, _batch| {
								let extension = &mut ext.extension;
								// The segment was authenticated above; do not run the
								// Merkle proof/hash validation again while applying.
								extension.apply_validated_kernel_segments(segm)?;
								Ok(())
							},
						)?;
						Ok(())
					},
				)?;

				Ok(())
			})();
			return match res {
				Ok(()) => self.clear_pending_operation_checked(),
				Err(e) => {
					self.require_init_recovery(format_args!(
						"add_kernel_segment failed while applying kernel segment to txhashset: {}",
						e
					));
					Err(e)
				}
			};
		}

		return Err(Error::BitmapNotReady);
	}

	fn sibling_expanded_bitmap(bitmap: &Bitmap, leaves_num: u64) -> Result<Bitmap, Error> {
		let mut expanded = Bitmap::new();
		let allows_synthetic_last_sibling = leaves_num % 2 == 1;

		let validate_bit = |bit: u32| -> Result<(), Error> {
			let bit = u64::from(bit);
			if bit < leaves_num || allows_synthetic_last_sibling && bit == leaves_num {
				return Ok(());
			}
			Err(Error::InvalidSegment(format!(
				"prunable bitmap leaf {} is outside {} leaves",
				bit, leaves_num
			)))
		};

		for bit in bitmap.iter() {
			validate_bit(bit)?;
			expanded.add(bit);

			let sibling = if bit % 2 == 0 {
				bit.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Desegmenter::sibling_expanded_bitmap, bit={}",
						bit
					))
				})?
			} else {
				// Safe: odd bit values are always non-zero.
				bit - 1
			};
			validate_bit(sibling)?;
			expanded.add(sibling);
		}

		Ok(expanded)
	}

	// Rough estimation of the segment size. This method is overestimated on hashes, so we should be below real data size limit
	fn estimate_segment_size(
		leaves_num: u64,
		capacity: u64,
		leaf_size: usize,
	) -> Result<u64, Error> {
		if leaves_num > capacity || capacity == 0 || leaves_num % 2 != 0 {
			return Err(Error::InvalidSegment(format!(
				"invalid prunable segment sizing input: leaves_num={}, capacity={}",
				leaves_num, capacity
			)));
		}

		let mut hash_num = 0u64;
		let mut cur_cap = capacity / 2;
		// Siblings are expected to be present in the bitmap count.
		let hash_per_line = leaves_num / 2;
		while cur_cap > 0 {
			let hashes = std::cmp::min(cur_cap, hash_per_line);
			hash_num = hash_num.checked_add(hashes).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::estimate_segment_size, hash_num={} hashes={}",
					hash_num, hashes
				))
			})?;
			cur_cap /= 2;
		}

		// Node hash is 32 bytes. Positions for all are 8 bytes. Assuming that empty is proportional to the fill ratio
		let leaf_size = u64::try_from(leaf_size).map_err(|_| {
			Error::DataOverflow(format!(
				"Desegmenter::estimate_segment_size, leaf_size={}",
				leaf_size
			))
		})?;
		let full_leaves_size = leaves_num
			.checked_mul(leaf_size.checked_add(8).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::estimate_segment_size, leaf_size={}",
					leaf_size
				))
			})?)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::estimate_segment_size, leaves_num={} leaf_size={}",
					leaves_num, leaf_size
				))
			})?;
		let full_hashes_size = hash_num.checked_mul(32 + 8).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Desegmenter::estimate_segment_size, hash_num={}",
				hash_num
			))
		})?;
		full_leaves_size
			.checked_add(full_hashes_size)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::estimate_segment_size, full_leaves_size={} full_hashes_size={}",
					full_leaves_size, full_hashes_size
				))
			})
	}

	// Return the segments and position of the next leaf
	fn calc_next_segment(
		leaf_size: usize,
		data_size_limit: usize,
		bitmap: &Bitmap,
		current_leave: u64,
		leaves_num: u64,
	) -> Result<(Vec<SegmentIdentifier>, u64), Error> {
		let range_cardinality = |start: u64, end: u64| -> Result<u64, Error> {
			let start = u32::try_from(start).map_err(|_| {
				Error::DataOverflow(format!(
					"Desegmenter::calc_next_segment, range_start={}",
					start
				))
			})?;
			let end = u32::try_from(end).map_err(|_| {
				Error::DataOverflow(format!("Desegmenter::calc_next_segment, range_end={}", end))
			})?;
			Ok(bitmap.range_cardinality(start..end))
		};
		let data_size_limit = u64::try_from(data_size_limit).map_err(|_| {
			Error::DataOverflow(format!(
				"Desegmenter::calc_next_segment, data_size_limit={}",
				data_size_limit
			))
		})?;
		let validate_segment_size = |leaves_num, capacity, height| {
			let segment_size = Self::estimate_segment_size(leaves_num, capacity, leaf_size)?;
			if segment_size > data_size_limit {
				return Err(Error::DataOverflow(format!(
					"Desegmenter::calc_next_segment, selected segment size {} at height={} exceeds data_size_limit={}",
					segment_size, height, data_size_limit
				)));
			}
			Ok(())
		};

		// Let's find the optimal height for the next pair of segments (second segment can be splitted in smaller)
		let mut cur_height = 6u8;
		let mut cur_capacity = SegmentIdentifier::segment_capacity_ex(cur_height)?;
		let first_end = current_leave.checked_add(cur_capacity).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Desegmenter::calc_next_segment, current_leave={} cur_capacity={}",
				current_leave, cur_capacity
			))
		})?;
		let second_end = cur_capacity
			.checked_mul(2)
			.and_then(|double| current_leave.checked_add(double))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::calc_next_segment, current_leave={} cur_capacity={}",
					current_leave, cur_capacity
				))
			})?;
		let mut leaves_num1 = range_cardinality(current_leave, first_end)?;
		let mut leaves_num2 = range_cardinality(first_end, second_end)?;

		while cur_height < 128
			&& current_leave.checked_add(cur_capacity).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::calc_next_segment, current_leave={} cur_capacity={}",
					current_leave, cur_capacity
				))
			})? < leaves_num
		{
			let combined_leaves = leaves_num1.checked_add(leaves_num2).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::calc_next_segment, leaves_num1={} leaves_num2={}",
					leaves_num1, leaves_num2
				))
			})?;
			let double_capacity = cur_capacity.checked_mul(2).ok_or_else(|| {
				Error::DataOverflow(format!(
					"Desegmenter::calc_next_segment, cur_capacity={}",
					cur_capacity
				))
			})?;
			let next_size =
				Self::estimate_segment_size(combined_leaves, double_capacity, leaf_size)?;
			let can_increase_capacity = current_leave % double_capacity == 0;

			// We can't generate the empty segment, more preferable solution to get over capacity.
			if can_increase_capacity && next_size <= data_size_limit {
				cur_height = cur_height.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Desegmenter::calc_next_segment, cur_height={}",
						cur_height
					))
				})?;
				cur_capacity = double_capacity;
				leaves_num1 = combined_leaves;
				let second_start = current_leave.checked_add(cur_capacity).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Desegmenter::calc_next_segment, current_leave={} cur_capacity={}",
						current_leave, cur_capacity
					))
				})?;
				let second_end = cur_capacity
					.checked_mul(2)
					.and_then(|double| current_leave.checked_add(double))
					.ok_or_else(|| {
						Error::DataOverflow(format!(
							"Desegmenter::calc_next_segment, current_leave={} cur_capacity={}",
							current_leave, cur_capacity
						))
					})?;
				leaves_num2 = range_cardinality(second_start, second_end)?;
				continue;
			}

			if leaves_num1 == 0 {
				debug!(
					"Requesting PIBD segment with zero elements, PIDB validation might fail if pruning is in the progress, but chances for that is low. Also that problem will be gone after few hours."
				);
			}

			// The first segment height if found. Checking if it really is.
			validate_segment_size(leaves_num1, cur_capacity, cur_height)?;
			#[cfg(debug_assertions)]
			{
				let s1_size = Self::estimate_segment_size(leaves_num1, cur_capacity, leaf_size)?;
				let s2_size = Self::estimate_segment_size(leaves_num2, cur_capacity, leaf_size)?;
				debug_assert!(s1_size <= data_size_limit); // Might happen, but very not likely. In this case investigate if it is really true and if other nodes will be able to deal with that.
				if leaves_num2 > 0 {
					debug_assert!(s2_size > 0 || !can_increase_capacity); // otherwise  s1_size + s2_size <= data_size_limit is true. Note, there is can_increase_capacity but it passing on the real data for now
				}
			}

			debug_assert!(cur_capacity == SegmentIdentifier::segment_capacity_ex(cur_height)?);
			debug_assert!(current_leave % cur_capacity == 0);

			let segm_idx = current_leave / cur_capacity;
			return Ok((
				vec![SegmentIdentifier::new(cur_height, segm_idx)],
				current_leave.checked_add(cur_capacity).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Desegmenter::calc_next_segment, current_leave={} cur_capacity={}",
						current_leave, cur_capacity
					))
				})?,
			));
		}

		// Case when we have only one segment, no pairs. It is totally fine, must be last segment, no needs to have a pair for it
		debug_assert!(current_leave
			.checked_add(cur_capacity)
			.map(|pos| pos >= leaves_num)
			.unwrap_or(false));
		debug_assert!(current_leave % cur_capacity == 0);
		validate_segment_size(leaves_num1, cur_capacity, cur_height)?;
		Ok((
			vec![SegmentIdentifier::new(
				cur_height,
				current_leave / cur_capacity,
			)],
			cur_capacity
				.checked_mul(2)
				.and_then(|double| current_leave.checked_add(double))
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"Desegmenter::calc_next_segment, current_leave={} cur_capacity={}",
						current_leave, cur_capacity
					))
				})?,
		))
	}

	/// Genarate segments that suppose to fit into the memory
	pub fn generate_segments(
		leaf_size: usize,
		data_size_limit: usize,
		target_mmr_size: u64,
		bitmap: Option<&Bitmap>,
	) -> Result<Vec<SegmentIdentifier>, Error> {
		// for the data size we will use estimation based on the density
		match bitmap {
			Some(bitmap) => {
				// prunable PMMR, we can use variable length
				// Note, every segment have to have some data
				let leaves_num = pmmr::n_leaves(target_mmr_size)?;
				let bitmap = Self::sibling_expanded_bitmap(bitmap, leaves_num)?;
				// last leave expected to be in the bitmap because it is outputs that can be spendable
				#[cfg(debug_assertions)]
				{
					let last_leaf = leaves_num.checked_sub(1).ok_or_else(|| {
						Error::DataOverflow(format!(
							"Desegmenter::generate_segments, leaves_num={}",
							leaves_num
						))
					})?;
					let last_leaf_next = last_leaf.checked_add(1).ok_or_else(|| {
						Error::DataOverflow(format!(
							"Desegmenter::generate_segments, last_leaf={}",
							last_leaf
						))
					})?;
					let last_leaf_next2 = last_leaf.checked_add(2).ok_or_else(|| {
						Error::DataOverflow(format!(
							"Desegmenter::generate_segments, last_leaf={}",
							last_leaf
						))
					})?;
					debug_assert!(bitmap.contains(u32::try_from(last_leaf).map_err(|_| {
						Error::DataOverflow(format!(
							"Desegmenter::generate_segments, last_leaf={}",
							last_leaf
						))
					})?));
					debug_assert!(
						leaves_num % 2 == 1
							|| !bitmap.contains(u32::try_from(last_leaf_next).map_err(|_| {
								Error::DataOverflow(format!(
									"Desegmenter::generate_segments, last_leaf_next={}",
									last_leaf_next
								))
							})?)
					);
					debug_assert!(!bitmap.contains(u32::try_from(last_leaf_next2).map_err(
						|_| {
							Error::DataOverflow(format!(
								"Desegmenter::generate_segments, last_leaf_next2={}",
								last_leaf_next2
							))
						}
					)?));
				}

				let mut current_leave = 0;
				let mut res: Vec<SegmentIdentifier> = Vec::new();
				while current_leave < leaves_num {
					let (mut segms, next_leave) = Self::calc_next_segment(
						leaf_size,
						data_size_limit,
						&bitmap,
						current_leave,
						leaves_num,
					)?;
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
					debug_assert!(res.first().map(|s| s.leaf_offset()).transpose()? == Some(0));

					for i in 1..res.len() {
						let s1 = res[i - 1];
						let s2 = res[i];
						let (_pos11, pos12) = s1.segment_pos_range(target_mmr_size)?;
						let (pos21, _pos22) = s2.segment_pos_range(target_mmr_size)?;
						debug_assert!(pos12 < pos21);
						debug_assert!(match pos12.checked_add(15) {
							Some(max_pos) => max_pos >= pos21,
							None => false,
						}); // + X depends on the Two mountains heights difference that we are merging. Values might be increased whaen chain become larger.
					}

					if let Some(last) = res.last() {
						let (pos1, pos2) = last.segment_pos_range(target_mmr_size)?;
						debug_assert!(pos1 < target_mmr_size);
						debug_assert!(pos2.checked_add(1) == Some(target_mmr_size));
					} else {
						debug_assert!(false);
					}
				}

				Ok(res)
			}
			None => {
				// For found best_height generating series of the segments with the same height
				let best_height = Self::non_prunable_segment_height(leaf_size, data_size_limit)?;
				let segments_num =
					Self::count_non_prunable_segments(leaf_size, data_size_limit, target_mmr_size)?;
				let mut res: Vec<SegmentIdentifier> = Vec::new();
				for segm_idx in 0..segments_num {
					res.push(SegmentIdentifier::new(best_height, segm_idx));
				}
				Ok(res)
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn kernel_validation_thread_range_splits_height() {
		assert_eq!(kernel_validation_thread_range(100, 0, 4).unwrap(), (25, 0));
		assert_eq!(kernel_validation_thread_range(100, 1, 4).unwrap(), (50, 25));
		assert_eq!(
			kernel_validation_thread_range(100, 3, 4).unwrap(),
			(100, 75)
		);
	}

	#[test]
	fn kernel_validation_thread_range_rejects_overflow() {
		assert!(matches!(
			kernel_validation_thread_range(u64::MAX, 1, 2),
			Err(Error::DataOverflow(_))
		));
	}

	#[test]
	fn kernel_validation_thread_range_rejects_zero_threads() {
		assert!(matches!(
			kernel_validation_thread_range(100, 0, 0),
			Err(Error::DataOverflow(_))
		));
	}

	#[test]
	fn non_prunable_segment_height_rejects_limit_below_minimum_segment() {
		assert!(matches!(
			Desegmenter::non_prunable_segment_height(100, 1),
			Err(Error::DataOverflow(_))
		));
	}

	#[test]
	fn non_prunable_segment_height_accepts_minimum_segment() {
		assert_eq!(
			Desegmenter::non_prunable_segment_height(100, 32 * (100 + 8)).unwrap(),
			MIN_NON_PRUNABLE_SEGMENT_HEIGHT
		);
	}

	#[test]
	fn prunable_estimate_segment_size_rejects_unpaired_leaf_count() {
		assert!(matches!(
			Desegmenter::estimate_segment_size(1, 64, 100),
			Err(Error::InvalidSegment(_))
		));
	}

	#[test]
	fn prunable_generate_segments_expands_raw_bitmap_siblings() {
		let target_mmr_size = pmmr::insertion_to_pmmr_index(129).unwrap();
		let mut raw = Bitmap::new();
		raw.add(0);
		raw.add(64);
		raw.add(128);

		let mut expanded = Bitmap::new();
		for bit in [0, 1, 64, 65, 128, 129] {
			expanded.add(bit);
		}

		assert_eq!(
			Desegmenter::generate_segments(
				100,
				pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
				target_mmr_size,
				Some(&raw)
			)
			.unwrap(),
			Desegmenter::generate_segments(
				100,
				pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
				target_mmr_size,
				Some(&expanded)
			)
			.unwrap()
		);
	}

	#[test]
	fn prunable_generate_segments_rejects_out_of_range_bitmap_leaf() {
		let target_mmr_size = pmmr::insertion_to_pmmr_index(128).unwrap();
		let mut bitmap = Bitmap::new();
		bitmap.add(128);

		assert!(matches!(
			Desegmenter::generate_segments(
				100,
				pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
				target_mmr_size,
				Some(&bitmap)
			),
			Err(Error::InvalidSegment(_))
		));
	}

	#[test]
	fn prunable_calc_next_segment_rejects_limit_below_minimum_segment() {
		let mut bitmap = Bitmap::new();
		bitmap.add_range(0..128);

		assert!(matches!(
			Desegmenter::calc_next_segment(100, 1, &bitmap, 0, 128),
			Err(Error::DataOverflow(_))
		));
	}

	#[test]
	fn prunable_calc_next_segment_rejects_last_segment_above_limit() {
		let mut bitmap = Bitmap::new();
		bitmap.add_range(0..64);

		assert!(matches!(
			Desegmenter::calc_next_segment(100, 1, &bitmap, 0, 64),
			Err(Error::DataOverflow(_))
		));
	}
}
