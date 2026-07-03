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

//! Generation of the various necessary segments requested during PIBD.

use crate::error::Error;
use crate::pibd_params;
use crate::txhashset::{BitmapAccumulator, BitmapChunk, TxHashSet};
use crate::types::HEADERS_PER_BATCH;
use mwc_core::core::hash::Hash;
use mwc_core::core::pmmr::{self, ReadablePMMR, ReadonlyPMMR, VecBackend};
use mwc_core::core::{BlockHeader, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use mwc_core::ser::PMMRable;
use mwc_crates::croaring::Bitmap;
use mwc_crates::log::debug;
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp::pedersen::RangeProof;
use std::convert::TryFrom;
use std::{sync::Arc, time::Instant};

// Accept alternate peer segment layouts, but do not let one request scan an
// unbounded sparse prunable PMMR range before the payload limit is reached.
const MAX_PRUNABLE_SEGMENT_SCAN_POSITIONS: u64 = 2_000_000;
const SEGMENT_POSITION_BYTES: usize = 8;

fn segment_leaf_count(id: SegmentIdentifier, mmr_size: u64) -> Result<u64, Error> {
	id.segment_pos_range(mmr_size)?;
	Ok(id
		.segment_capacity()?
		.min(pmmr::n_leaves(mmr_size)?.saturating_sub(id.leaf_offset()?)))
}

fn validate_non_prunable_segment_payload(
	segment_type: &str,
	id: SegmentIdentifier,
	mmr_size: u64,
	leaf_size: usize,
	segment_size_limit: usize,
) -> Result<(), Error> {
	let segment_leaves = segment_leaf_count(id, mmr_size)?;
	let leaf_payload_size = leaf_size
		.checked_add(SEGMENT_POSITION_BYTES)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Segmenter::{}, leaf_size={} position_size={}",
				segment_type, leaf_size, SEGMENT_POSITION_BYTES
			))
		})?;
	let segment_leaves = usize::try_from(segment_leaves).map_err(|_| {
		Error::DataOverflow(format!(
			"Segmenter::{}, segment_leaves={}",
			segment_type, segment_leaves
		))
	})?;
	let segment_payload_size = segment_leaves
		.checked_mul(leaf_payload_size)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Segmenter::{}, segment_leaves={} leaf_payload_size={}",
				segment_type, segment_leaves, leaf_payload_size
			))
		})?;
	if segment_payload_size > segment_size_limit {
		return Err(Error::InvalidSegment(format!(
			"{} segment {} has leaf payload size {}, maximum allowed {}",
			segment_type, id, segment_payload_size, segment_size_limit
		)));
	}
	Ok(())
}

fn bitmap_mmr_size(output_mmr_size: u64) -> Result<u64, Error> {
	let output_leaves = pmmr::n_leaves(output_mmr_size)?;
	let bitmap_chunk_bits = u64::try_from(BitmapChunk::LEN_BYTES)
		.ok()
		.and_then(|x| x.checked_mul(8))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Segmenter::bitmap_mmr_size, LEN_BYTES={}",
				BitmapChunk::LEN_BYTES
			))
		})?;
	let bitmap_mmr_leaf_count = output_leaves
		.checked_add(bitmap_chunk_bits - 1)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Segmenter::bitmap_mmr_size, output_leaves={} bitmap_chunk_bits={}",
				output_leaves, bitmap_chunk_bits
			))
		})? / bitmap_chunk_bits;
	if bitmap_mmr_leaf_count == 0 {
		return Ok(0);
	}

	let bitmap_mmr_pos = pmmr::insertion_to_pmmr_index(bitmap_mmr_leaf_count)?;
	let bitmap_peaks = pmmr::peaks(bitmap_mmr_pos)?;
	let last_peak = if let Some(last_peak) = bitmap_peaks.last() {
		*last_peak
	} else {
		let prev_leaf_count = bitmap_mmr_leaf_count.checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Segmenter::bitmap_mmr_size, bitmap_mmr_leaf_count={}",
				bitmap_mmr_leaf_count
			))
		})?;
		let prev_pos = pmmr::insertion_to_pmmr_index(prev_leaf_count)?;
		pmmr::peaks(prev_pos)?.last().copied().unwrap_or(0)
	};
	last_peak.checked_add(1).ok_or_else(|| {
		Error::DataOverflow(format!(
			"Segmenter::bitmap_mmr_size, last_peak={}",
			last_peak
		))
	})
}

fn header_hashes_mmr_size(target_height: u64) -> Result<u64, Error> {
	let header_hashes = target_height
		.checked_div(u64::from(HEADERS_PER_BATCH))
		.and_then(|x| x.checked_add(1))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Segmenter::header_hashes_mmr_size, target_height={}",
				target_height
			))
		})?;
	pmmr::insertion_to_pmmr_index(header_hashes).map_err(Error::from)
}

fn validate_prunable_segment_scan_span(
	segment_type: &str,
	id: SegmentIdentifier,
	mmr_size: u64,
) -> Result<(), Error> {
	let (segment_first_pos, segment_last_pos) = id.segment_pos_range(mmr_size)?;
	let scan_positions = segment_last_pos
		.checked_sub(segment_first_pos)
		.and_then(|x| x.checked_add(1))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Segmenter::{}, first_pos={} last_pos={}",
				segment_type, segment_first_pos, segment_last_pos
			))
		})?;
	if scan_positions > MAX_PRUNABLE_SEGMENT_SCAN_POSITIONS {
		return Err(Error::InvalidSegment(format!(
			"{} segment {} spans {} PMMR positions, maximum allowed {}",
			segment_type, id, scan_positions, MAX_PRUNABLE_SEGMENT_SCAN_POSITIONS
		)));
	}
	Ok(())
}

/// Cheaply validate a kernel segment request before initializing a Segmenter.
pub fn validate_kernel_segment_request(
	id: SegmentIdentifier,
	kernel_mmr_size: u64,
) -> Result<(), Error> {
	validate_non_prunable_segment_payload(
		"kernel_segment",
		id,
		kernel_mmr_size,
		TxKernel::DATA_SIZE,
		pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
	)
}

/// Cheaply validate a bitmap segment request before initializing a Segmenter.
pub fn validate_bitmap_segment_request(
	id: SegmentIdentifier,
	output_mmr_size: u64,
) -> Result<(), Error> {
	validate_non_prunable_segment_payload(
		"bitmap_segment",
		id,
		bitmap_mmr_size(output_mmr_size)?,
		BitmapChunk::LEN_BYTES,
		pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
	)
}

/// Cheaply validate an output segment request before initializing a Segmenter.
pub fn validate_output_segment_request(
	id: SegmentIdentifier,
	output_mmr_size: u64,
) -> Result<(), Error> {
	validate_prunable_segment_scan_span("output_segment", id, output_mmr_size)
}

/// Cheaply validate a rangeproof segment request before initializing a Segmenter.
pub fn validate_rangeproof_segment_request(
	id: SegmentIdentifier,
	output_mmr_size: u64,
) -> Result<(), Error> {
	validate_prunable_segment_scan_span("rangeproof_segment", id, output_mmr_size)
}

/// Cheaply validate a header-hashes segment request before initializing a Segmenter.
pub fn validate_header_hashes_segment_request(
	id: SegmentIdentifier,
	target_height: u64,
) -> Result<(), Error> {
	validate_non_prunable_segment_payload(
		"headers_segment",
		id,
		header_hashes_mmr_size(target_height)?,
		Hash::LEN,
		pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
	)
}

/// Segmenter for generating PIBD segments.
/// Note!!! header_pmmr, txhashset & store are from the Chain. Same locking rules are applicable
#[derive(Clone)]
pub struct Segmenter {
	// every 512th header (HEADERS_PER_BATCH) must be here, we don't need all header hashes
	header_pmmr: Arc<RwLock<VecBackend<Hash>>>,
	txhashset: Arc<RwLock<TxHashSet>>,
	bitmap_snapshot: Arc<BitmapAccumulator>,
	bitmap: Bitmap,
	header: BlockHeader,
}

impl Segmenter {
	/// Create a new segmenter based on the provided txhashset.
	pub fn new(
		header_pmmr: Arc<RwLock<VecBackend<Hash>>>,
		txhashset: Arc<RwLock<TxHashSet>>,
		bitmap_snapshot: BitmapAccumulator,
		header: BlockHeader,
	) -> Result<Segmenter, Error> {
		let bitmap = bitmap_snapshot
			.build_bitmap()
			.map_err(|e| Error::TxHashSetErr(format!("Invalid bitmap_snapshot, {}", e)))?;

		Ok(Segmenter {
			header_pmmr,
			txhashset,
			bitmap_snapshot: Arc::new(bitmap_snapshot),
			bitmap,
			header,
		})
	}

	/// Header associated with this segmenter instance.
	/// The bitmap "snapshot" corresponds to rewound state at this header.
	pub fn header(&self) -> &BlockHeader {
		&self.header
	}

	/// Root hash for headers Hashes MMR
	pub fn headers_root(&self) -> Result<Hash, Error> {
		let header_pmmr = self.header_pmmr.read_recursive();
		let pmmr = ReadonlyPMMR::at(&*header_pmmr, header_pmmr.size());
		let root = pmmr.root()?;
		Ok(root)
	}

	/// The root of the bitmap snapshot PMMR.
	pub fn bitmap_root(&self) -> Result<Hash, Error> {
		let pmmr = self.bitmap_snapshot.readonly_pmmr();
		let root = pmmr.root()?;
		Ok(root)
	}

	/// Create a utxo bitmap segment based on our bitmap "snapshot" and return it with
	/// the corresponding output root.
	pub fn bitmap_segment(&self, id: SegmentIdentifier) -> Result<Segment<BitmapChunk>, Error> {
		let now = Instant::now();
		let bitmap_pmmr = self.bitmap_snapshot.readonly_pmmr();
		let segment = Segment::<BitmapChunk>::from_pmmr(
			id,
			&bitmap_pmmr,
			None,
			BitmapChunk::LEN_BYTES,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
		)?;
		debug!(
			"bitmap_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}

	/// Create headers segment.
	pub fn headers_segment(&self, id: SegmentIdentifier) -> Result<Segment<Hash>, Error> {
		let now = Instant::now();
		let header_pmmr = self.header_pmmr.read_recursive();
		let header_pmmr = ReadonlyPMMR::at(&*header_pmmr, header_pmmr.size());
		let segment = Segment::<Hash>::from_pmmr(
			id,
			&header_pmmr,
			None,
			Hash::LEN,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
		)?;
		debug!(
			"headers_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}

	/// Create an output segment and return it with the corresponding bitmap root.
	pub fn output_segment(
		&self,
		id: SegmentIdentifier,
	) -> Result<Segment<OutputIdentifier>, Error> {
		let now = Instant::now();
		let txhashset = self.txhashset.read_recursive();
		let output_pmmr = txhashset.output_pmmr_at(&self.header);
		validate_prunable_segment_scan_span("output_segment", id, output_pmmr.unpruned_size())?;
		let leaf_size = OutputIdentifier::elmt_size()
			.map(usize::from)
			.ok_or_else(|| Error::Other("OutputIdentifier size must be fixed".into()))?;
		let segment = Segment::<OutputIdentifier>::from_pmmr(
			id,
			&output_pmmr,
			Some(&self.bitmap),
			leaf_size,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT * 2, // In reality 1x should be enough, using 2x to cover some edge cases
		)?;
		debug!(
			"output_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}

	/// Create a kernel segment.
	pub fn kernel_segment(&self, id: SegmentIdentifier) -> Result<Segment<TxKernel>, Error> {
		let now = Instant::now();
		let txhashset = self.txhashset.read_recursive();
		let kernel_pmmr = txhashset.kernel_pmmr_at(&self.header);
		let segment = Segment::<TxKernel>::from_pmmr(
			id,
			&kernel_pmmr,
			None,
			TxKernel::DATA_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
		)?;
		debug!(
			"kernel_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}

	/// Create a rangeproof segment.
	pub fn rangeproof_segment(&self, id: SegmentIdentifier) -> Result<Segment<RangeProof>, Error> {
		let now = Instant::now();
		let txhashset = self.txhashset.read_recursive();
		let pmmr = txhashset.rangeproof_pmmr_at(&self.header);
		validate_prunable_segment_scan_span("rangeproof_segment", id, pmmr.unpruned_size())?;
		let segment_size_limit = pibd_params::PIBD_MESSAGE_SIZE_LIMIT * 2;
		let leaf_size = RangeProof::elmt_size()
			.map(usize::from)
			.ok_or_else(|| Error::Other("RangeProof size must be fixed".into()))?;
		// Some overhead is fine, there are chances that we can't make optimal segments
		let segment = Segment::<RangeProof>::from_pmmr(
			id,
			&pmmr,
			Some(&self.bitmap),
			leaf_size,
			segment_size_limit, // In reality 1x should be enough, using 2x to cover some edge cases
		)?;
		debug!(
			"rangeproof_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}
}
