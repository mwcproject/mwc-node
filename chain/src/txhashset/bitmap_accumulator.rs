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

use std::cmp::min;
use std::convert::TryFrom;
use std::time::Instant;

use mwc_crates::bit_vec::BitVec;
use mwc_crates::croaring::Bitmap;

use crate::error::Error;
use mwc_core::core::hash::{DefaultHashable, Hash};
use mwc_core::core::pmmr::segment::{Segment, SegmentIdentifier, SegmentProof};
use mwc_core::core::pmmr::{
	self, Backend, ReadablePMMR, ReadonlyPMMR, VecBackend, VecBackendTail, PMMR,
};
use mwc_core::ser::{self, PMMRable, Readable, Reader, Writeable, Writer};
use mwc_crates::enum_primitive::FromPrimitive;
use mwc_crates::enum_primitive::{
	enum_from_primitive, enum_from_primitive_impl, enum_from_primitive_impl_ty,
};
use mwc_crates::log::debug;

/// The "bitmap accumulator" allows us to commit to a specific bitmap by splitting it into
/// fragments and inserting these fragments into an MMR to produce an overall root hash.
/// Leaves in the MMR are fragments of the bitmap consisting of 1024 contiguous bits
/// from the overall bitmap. The first (leftmost) leaf in the MMR represents the first 1024 bits
/// of the bitmap, the next leaf is the next 1024 bits of the bitmap etc.
///
/// Flipping a single bit does not require the full bitmap to be rehashed, only the path from the
/// relevant leaf up to its associated peak.
///
/// Flipping multiple bits *within* a single chunk is no more expensive than flipping a single bit
/// as a leaf node in the MMR represents a sequence of 1024 bits. Flipping multiple bits located
/// close together is a relatively cheap operation with minimal rehashing required to update the
/// relevant peaks and the overall MMR root.
///
/// It is also possible to generate Merkle proofs for these 1024 bit fragments, proving
/// both inclusion and location in the overall "accumulator" MMR. We plan to take advantage of
/// this during fast sync, allowing for validation of partial data.
///
#[derive(Clone)]
pub struct BitmapAccumulator {
	backend: VecBackend<BitmapChunk>,
}

impl BitmapAccumulator {
	const NBITS: u64 = BitmapChunk::LEN_BITS as u64;

	/// Crate a new empty bitmap accumulator.
	pub fn new(context_id: u32) -> BitmapAccumulator {
		BitmapAccumulator {
			backend: VecBackend::new(context_id),
		}
	}

	/// Reset bitmap data
	pub fn reset(&mut self) {
		self.backend.reset();
	}

	/// Initialize a bitmap accumulator given the provided idx iterator.
	/// The iterator must yield indices in ascending order.
	pub fn init<T: IntoIterator<Item = Result<u64, mwc_core::core::pmmr::Error>>>(
		&mut self,
		idx: T,
		size: u64,
	) -> Result<(), Error> {
		self.reset();
		self.apply_from(idx, 0, size)
	}

	/// Find the start of the first "chunk" of 1024 bits from the provided idx.
	/// Zero the last 10 bits to round down to multiple of 1024.
	pub fn chunk_start_idx(idx: u64) -> u64 {
		idx & !(Self::NBITS - 1)
	}

	/// The first 1024 belong to chunk 0, the next 1024 to chunk 1 etc.
	fn chunk_idx(idx: u64) -> u64 {
		idx / Self::NBITS
	}

	/// Number of chunks required to represent a bitmap of size bits.
	fn chunk_count(size: u64) -> Result<u64, Error> {
		if size == 0 {
			return Ok(0);
		}
		BitmapAccumulator::chunk_idx(size - 1)
			.checked_add(1)
			.ok_or_else(|| {
				Error::DataOverflow(format!("BitmapAccumulator::chunk_count, size={}", size))
			})
	}

	/// Apply the provided idx iterator to our bitmap accumulator.
	/// We start at the chunk containing from_idx and rebuild chunks as necessary
	/// for the bitmap, limiting it to size (in bits).
	/// If from_idx is 1023 and size is 1024 then we rebuild a single chunk.
	fn apply_from<T>(&mut self, idx: T, from_idx: u64, size: u64) -> Result<(), Error>
	where
		T: IntoIterator<Item = Result<u64, mwc_core::core::pmmr::Error>>,
	{
		let now = Instant::now();
		let target_chunk_count = BitmapAccumulator::chunk_count(size)?;

		// Find the (1024 bit chunk) chunk_idx for the (individual bit) from_idx.
		let from_chunk_idx = BitmapAccumulator::chunk_idx(from_idx);
		let mut chunk_idx = from_chunk_idx;

		let mut chunk = BitmapChunk::new();
		let mut last_idx = None;

		let mut idx_iter = idx
			.into_iter()
			.filter(|x| match x {
				Ok(x) => *x < size,
				Err(_) => true,
			})
			.peekable();
		while let Some(x) = idx_iter.peek() {
			let x = match x {
				Ok(x) => *x,
				Err(_) => {
					// Getting erro with next because peek return reference and we can't clone io error.
					let err = idx_iter
						.next()
						.expect("peeked error must be available")
						.err()
						.expect("peeked item must be an error");
					return Err(err.into());
				}
			};
			if let Some(prev_idx) = last_idx {
				if x < prev_idx {
					return Err(Error::Other(format!(
						"BitmapAccumulator::apply_from expected sorted indices, got {} after {}",
						x, prev_idx
					)));
				}
			}
			last_idx = Some(x);

			let x_chunk_idx = BitmapAccumulator::chunk_idx(x);
			if x_chunk_idx < chunk_idx {
				// Sorted callers may provide indices before the chunk being rebuilt.
				// Skip until we reach our first chunk.
				idx_iter.next();
			} else if x_chunk_idx == chunk_idx {
				let idx = idx_iter.next().ok_or(Error::Other(
					"Bitmap accumulator internal error, no data next after peek is found".into(),
				))?;
				let idx = idx?;
				chunk.set(idx % Self::NBITS, true)?;
			} else {
				self.append_chunk(chunk)?;
				chunk_idx = chunk_idx.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"BitmapAccumulator::apply_from, chunk_idx={}",
						chunk_idx
					))
				})?;
				chunk = BitmapChunk::new();
			}
		}
		while chunk_idx < target_chunk_count {
			self.append_chunk(chunk)?;
			chunk_idx = chunk_idx.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"BitmapAccumulator::apply_from, chunk_idx={}",
					chunk_idx
				))
			})?;
			chunk = BitmapChunk::new();
		}
		// Safe to use saturated because it is a debug logs.
		debug!(
			"applied {} chunks from idx {} to idx {} ({}ms)",
			chunk_idx.saturating_sub(from_chunk_idx),
			from_chunk_idx,
			chunk_idx.saturating_sub(1),
			now.elapsed().as_millis(),
		);
		Ok(())
	}

	/// Apply updates to the bitmap accumulator given an iterator of invalidated idx and
	/// an iterator of idx to be set to true.
	/// We determine the existing chunks to be rebuilt given the invalidated idx.
	/// We then rebuild given idx, extending the accumulator with new chunk(s) as necessary.
	/// Resulting bitmap accumulator will contain sufficient bitmap chunks to cover size.
	/// If size is 0 then we will have no chunks.
	/// If size is between 1 and 1024 inclusive then we will have a single chunk.
	/// If size is 1025 then we will have two chunks.
	/// TODO: first argument is an iterator for no good reason;
	/// might as well pass from_idx as first argument
	pub fn apply<T, U>(&mut self, invalidated_idx: T, idx: U, size: u64) -> Result<(), Error>
	where
		T: IntoIterator<Item = u64>,
		U: IntoIterator<Item = Result<u64, mwc_core::core::pmmr::Error>>,
	{
		// Determine the earliest chunk by looking at the min invalidated idx (assume sorted).
		// Rewind prior to this and reapply new_idx.
		// Note: We rebuild everything after rewind point but much of the bitmap may be
		// unchanged. This can be further optimized by only rebuilding necessary chunks and
		// rehashing.
		let from_idx = match invalidated_idx.into_iter().next() {
			Some(from_idx) => {
				if from_idx >= size {
					return Err(Error::Other(format!(
						"BitmapAccumulator::apply invalidated index {} outside bitmap size {}",
						from_idx, size
					)));
				}
				from_idx
			}
			None => 0,
		};

		let rewind_tail = self.rewind_prior(from_idx)?;
		let result = self
			.pad_left(from_idx)
			.and_then(|_| self.apply_from(idx, from_idx, size));
		if let Err(err) = result {
			if let Err(rollback_err) = self.backend.restore_tail(rewind_tail) {
				return Err(Error::Other(format!(
					"BitmapAccumulator::apply failed: {}; rollback failed: {}",
					err, rollback_err
				)));
			}
			return Err(err);
		}

		Ok(())
	}

	/// Given the provided (bit) idx rewind the bitmap accumulator to the end of the
	/// previous chunk ready for the updated chunk to be appended.
	fn rewind_prior(&mut self, from_idx: u64) -> Result<VecBackendTail<BitmapChunk>, Error> {
		let chunk_idx = BitmapAccumulator::chunk_idx(from_idx);
		let last_pos = self.backend.size();
		let rewind_pos = pmmr::insertion_to_pmmr_index(chunk_idx)?;
		self.backend
			.detach_tail(min(rewind_pos, last_pos))
			.map_err(|e| Error::Other(format!("pmmr rewind error, {}", e)))
	}

	/// Make sure we append empty chunks to fill in any gap before we append the chunk
	/// we actually care about. This effectively pads the bitmap with 1024 chunks of 0s
	/// as necessary to put the new chunk at the correct place.
	fn pad_left(&mut self, from_idx: u64) -> Result<(), Error> {
		let chunk_idx = BitmapAccumulator::chunk_idx(from_idx);
		let current_chunk_idx = pmmr::n_leaves(self.backend.size())?;
		for _ in current_chunk_idx..chunk_idx {
			self.append_chunk(BitmapChunk::new())?;
		}
		Ok(())
	}

	/// Append a new chunk to the BitmapAccumulator.
	/// Append parent hashes (if any) as necessary to build associated peak.
	pub fn append_chunk(&mut self, chunk: BitmapChunk) -> Result<u64, Error> {
		let last_pos = self.backend.size();
		PMMR::at(&mut self.backend, last_pos)
			.push(&chunk)
			.map_err(Error::from)
	}

	/// The root hash of the bitmap accumulator MMR.
	pub fn root(&self) -> Result<Hash, Error> {
		self.readonly_pmmr().root().map_err(|e| {
			Error::Other(format!(
				"Internal bitmap accumulator error, unable to get PMMR root, {}",
				e
			))
		})
	}

	/// Readonly access to our internal data.
	pub fn readonly_pmmr(&'_ self) -> ReadonlyPMMR<'_, BitmapChunk, VecBackend<BitmapChunk>> {
		ReadonlyPMMR::at(&self.backend, self.backend.size())
	}

	/// Return a raw in-memory bitmap of this accumulator.
	pub fn build_bitmap(&self) -> Result<Bitmap, Error> {
		let mut bitmap = Bitmap::new();
		for (chunk_index, chunk_pos) in self.backend.leaf_pos_iter()?.enumerate() {
			let chunk_pos = chunk_pos?;
			let chunk = self.backend.get_data(chunk_pos)?;
			if let Some(chunk) = chunk {
				let idx_offset =
					chunk_index
						.checked_mul(BitmapChunk::LEN_BITS)
						.ok_or_else(|| {
							Error::DataOverflow(format!(
								"BitmapAccumulator::build_bitmap, chunk_index={} LEN_BITS={}",
								chunk_index,
								BitmapChunk::LEN_BITS
							))
						})?;
				let additive = chunk.get_indexes(idx_offset)?;
				if !additive.is_empty() {
					bitmap.add_many(&additive);
				}
			}
		}
		Ok(bitmap)
	}
}

/// A bitmap "chunk" representing 1024 contiguous bits of the overall bitmap.
/// The first 1024 bits belong in one chunk. The next 1024 bits in the next chunk, etc.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitmapChunk(BitVec);

impl BitmapChunk {
	const LEN_BITS: usize = 1024;
	/// Size of the bitmap chain in bytes
	pub const LEN_BYTES: usize = Self::LEN_BITS / 8;

	/// Create a new bitmap chunk, defaulting all bits in the chunk to false.
	pub fn new() -> BitmapChunk {
		BitmapChunk(BitVec::from_elem(Self::LEN_BITS, false))
	}

	/// Set a single bit in this chunk.
	/// 0-indexed from start of chunk.
	/// Panics if idx is outside the valid range of bits in a chunk.
	pub fn set(&mut self, idx: u64, value: bool) -> Result<(), Error> {
		let idx = usize::try_from(idx)
			.map_err(|_| Error::Other(format!("Invalid chunk index value: {}", idx)))?;

		if idx >= Self::LEN_BITS {
			return Err(Error::Other(format!("Invalid chunk index value: {}", idx)));
		}

		debug_assert!(idx < Self::LEN_BITS);
		self.0.set(idx, value);
		Ok(())
	}

	/// Does this bitmap chunk have any bits set to 1?
	pub fn any(&self) -> bool {
		self.0.any()
	}

	/// Iterator over the integer set represented by this chunk, applying the given
	/// offset to the values
	pub fn get_indexes(&self, idx_offset: usize) -> Result<Vec<u32>, Error> {
		let idx_offset = u32::try_from(idx_offset).map_err(|_| {
			Error::DataOverflow(format!("BitmapChunk::set_iter, idx_offset={}", idx_offset))
		})?;
		self.0
			.iter()
			.enumerate()
			.filter(|(_, val)| *val)
			.map(move |(idx, _)| {
				// idx as u32 + idx_offset as u32
				let idx = u32::try_from(idx).map_err(|_| {
					Error::DataOverflow(format!("BitmapChunk::set_iter, idx={}", idx))
				})?;
				idx.checked_add(idx_offset).ok_or_else(|| {
					Error::DataOverflow(format!(
						"BitmapChunk::set_iter, idx={} idx_offset={}",
						idx, idx_offset
					))
				})
			})
			.collect()
	}

	/// Convert the BitVec to a hexadecimal string
	pub fn to_hex(&self) -> String {
		// Convert the BitVec to a vector of bytes
		let bytes = self.0.to_bytes();

		// Format the bytes as a hexadecimal string
		let hex_str = bytes
			.iter()
			.map(|byte| format!("{:02X}", byte))
			.collect::<Vec<_>>()
			.join("");
		return format!("BitmapChunk(Len:{}  Data:{})", self.0.len(), hex_str);
	}
}

impl PMMRable for BitmapChunk {
	type E = Self;

	fn as_elmt(&self) -> Result<BitmapChunk, ser::Error> {
		Ok(self.clone())
	}

	fn elmt_size() -> Option<u16> {
		Some(Self::LEN_BYTES as u16)
	}
}

impl DefaultHashable for BitmapChunk {}

impl Writeable for BitmapChunk {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.0.to_bytes().write(writer)
	}
}

impl Readable for BitmapChunk {
	fn read<R: Reader>(reader: &mut R) -> Result<BitmapChunk, ser::Error> {
		let bytes = reader.read_fixed_bytes(Self::LEN_BYTES)?;
		let bits = BitVec::from_bytes(&bytes);
		if bits.len() != Self::LEN_BITS {
			return Err(ser::Error::CorruptedData(format!(
				"BitmapChunk expected {} bits, got {}",
				Self::LEN_BITS,
				bits.len()
			)));
		}
		Ok(BitmapChunk(bits))
	}
}

///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitmapSegment {
	/// This segment Identifier
	pub identifier: SegmentIdentifier,
	blocks: Vec<BitmapBlock>,
	proof: SegmentProof,
}

impl Writeable for BitmapSegment {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		Writeable::write(&self.identifier, writer)?;
		writer.write_u16(u16::try_from(self.blocks.len()).map_err(|_| {
			ser::Error::DataOverflow(format!(
				"BitmapSegment::write, blocks_len={}",
				self.blocks.len()
			))
		})?)?;
		for block in &self.blocks {
			Writeable::write(block, writer)?;
		}
		Writeable::write(&self.proof, writer)?;
		Ok(())
	}
}

impl Readable for BitmapSegment {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let identifier: SegmentIdentifier = Readable::read(reader)?;

		let n_blocks_raw = reader.read_u16()?;
		let n_blocks = n_blocks_raw as usize;
		if n_blocks == 0 {
			return Err(ser::Error::CorruptedData(
				"BitmapSegment must contain at least one block".to_string(),
			));
		}

		let chunk_limit = bitmap_segment_chunk_limit().map_err(ser::Error::DataOverflow)?;
		let max_blocks_for_message =
			bitmap_segment_block_limit().map_err(ser::Error::DataOverflow)?;
		let segment_capacity = identifier.segment_capacity().map_err(|e| {
			ser::Error::CorruptedData(format!("Invalid bitmap segment identifier: {}", e))
		})?;
		let max_blocks_for_identifier = segment_capacity
			.checked_add(BitmapBlock::NCHUNKS as u64 - 1)
			.map(|x| x / BitmapBlock::NCHUNKS as u64)
			.ok_or_else(|| {
				ser::Error::DataOverflow(format!(
					"BitmapSegment::read, segment_capacity={}",
					segment_capacity
				))
			})?;
		let max_blocks_for_message = max_blocks_for_message as u64;
		let max_blocks = min(max_blocks_for_identifier, max_blocks_for_message);
		if n_blocks_raw as u64 > max_blocks {
			return Err(ser::Error::TooLargeReadErr(format!(
				"BitmapSegment requested {} blocks, limit is {}",
				n_blocks, max_blocks
			)));
		}

		let mut blocks = Vec::<BitmapBlock>::with_capacity(n_blocks);
		let mut decoded_chunks = 0usize;
		for block_idx in 0..n_blocks {
			let block: BitmapBlock = Readable::read(reader)?;
			let block_chunks = block.checked_n_chunks()?;
			if block_chunks == 0 {
				return Err(ser::Error::CorruptedData(format!(
					"BitmapSegment block {} has zero chunks",
					block_idx
				)));
			}
			if block_idx + 1 < n_blocks && block_chunks != BitmapBlock::NCHUNKS {
				return Err(ser::Error::CorruptedData(format!(
					"BitmapSegment non-final block {} has {} chunks, expected {}",
					block_idx,
					block_chunks,
					BitmapBlock::NCHUNKS
				)));
			}
			decoded_chunks = decoded_chunks.checked_add(block_chunks).ok_or_else(|| {
				ser::Error::DataOverflow("BitmapSegment decoded chunk count overflow".to_string())
			})?;
			if decoded_chunks > chunk_limit {
				return Err(ser::Error::TooLargeReadErr(format!(
					"BitmapSegment decoded {} chunks, PIBD limit is {}",
					decoded_chunks, chunk_limit
				)));
			}
			if decoded_chunks as u64 > segment_capacity {
				return Err(ser::Error::TooLargeReadErr(format!(
					"BitmapSegment decoded {} chunks, identifier limit is {}",
					decoded_chunks, segment_capacity
				)));
			}
			blocks.push(block);
		}
		let proof = Readable::read(reader)?;

		Ok(Self {
			identifier,
			blocks,
			proof,
		})
	}
}

const BITMAP_SEGMENT_POSITION_BYTES: usize = 8;

fn bitmap_segment_chunk_limit() -> Result<usize, String> {
	let leaf_size_with_pos = BitmapChunk::LEN_BYTES
		.checked_add(BITMAP_SEGMENT_POSITION_BYTES)
		.ok_or_else(|| {
			format!(
				"BitmapSegment chunk limit, leaf_size={} position_size={}",
				BitmapChunk::LEN_BYTES,
				BITMAP_SEGMENT_POSITION_BYTES
			)
		})?;

	// Match Desegmenter::generate_segments for bitmap PIBD segments: choose the
	// largest power-of-two leaf count whose leaf+position payload fits the limit.
	let mut best_height = 4u32;
	for height in 6..128u32 {
		let leaves_num = 1usize
			.checked_shl(height)
			.ok_or_else(|| format!("BitmapSegment chunk limit, invalid height={}", height))?;
		let segment_size = leaves_num.checked_mul(leaf_size_with_pos).ok_or_else(|| {
			format!(
				"BitmapSegment chunk limit, leaves_num={} leaf_size_with_pos={}",
				leaves_num, leaf_size_with_pos
			)
		})?;
		if segment_size > crate::pibd_params::PIBD_MESSAGE_SIZE_LIMIT {
			best_height = height
				.checked_sub(1)
				.ok_or_else(|| format!("BitmapSegment chunk limit, height={}", height))?;
			break;
		}
	}

	1usize.checked_shl(best_height).ok_or_else(|| {
		format!(
			"BitmapSegment chunk limit, invalid best_height={}",
			best_height
		)
	})
}

fn bitmap_segment_block_limit() -> Result<usize, String> {
	bitmap_segment_chunk_limit()?
		.checked_add(BitmapBlock::NCHUNKS - 1)
		.map(|x| x / BitmapBlock::NCHUNKS)
		.ok_or_else(|| {
			format!(
				"BitmapSegment block limit, nchunks={}",
				BitmapBlock::NCHUNKS
			)
		})
}

fn validate_bitmap_segment_layout(
	identifier: &SegmentIdentifier,
	blocks: &[BitmapBlock],
) -> Result<usize, Error> {
	if blocks.is_empty() {
		return Err(Error::InvalidSegment(
			"BitmapSegment must contain at least one block".to_string(),
		));
	}

	let chunk_limit = bitmap_segment_chunk_limit().map_err(Error::DataOverflow)?;
	let segment_capacity = identifier.segment_capacity()?;
	let mut n_chunks = 0usize;

	for (block_idx, block) in blocks.iter().enumerate() {
		let block_chunks = block.checked_n_chunks()?;
		if block_chunks == 0 {
			return Err(Error::InvalidSegment(format!(
				"BitmapSegment block {} has zero chunks",
				block_idx
			)));
		}
		if block_idx + 1 < blocks.len() && block_chunks != BitmapBlock::NCHUNKS {
			return Err(Error::InvalidSegment(format!(
				"BitmapSegment non-final block {} has {} chunks, expected {}",
				block_idx,
				block_chunks,
				BitmapBlock::NCHUNKS
			)));
		}

		n_chunks = n_chunks.checked_add(block_chunks).ok_or_else(|| {
			Error::DataOverflow("BitmapSegment decoded chunk count overflow".to_string())
		})?;
		if n_chunks > chunk_limit {
			return Err(Error::InvalidSegment(format!(
				"BitmapSegment decoded {} chunks, PIBD limit is {}",
				n_chunks, chunk_limit
			)));
		}
		if u64::try_from(n_chunks).map_err(|_| {
			Error::DataOverflow(format!("BitmapSegment::try_from, n_chunks={}", n_chunks))
		})? > segment_capacity
		{
			return Err(Error::InvalidSegment(format!(
				"BitmapSegment decoded {} chunks, identifier limit is {}",
				n_chunks, segment_capacity
			)));
		}
	}

	Ok(n_chunks)
}

fn validate_bitmap_segment_parts_for_write(
	identifier: &SegmentIdentifier,
	hash_pos: &[u64],
	hashes: &[Hash],
	leaf_pos: &[u64],
	n_chunks: usize,
) -> Result<(), ser::Error> {
	if !hash_pos.is_empty() || !hashes.is_empty() {
		return Err(ser::Error::CorruptedData(format!(
			"BitmapSegment cannot encode pruned hashes: {} hash positions, {} hashes",
			hash_pos.len(),
			hashes.len()
		)));
	}
	if leaf_pos.len() != n_chunks {
		return Err(ser::Error::CorruptedData(format!(
			"BitmapSegment leaf position count {} does not match chunk count {}",
			leaf_pos.len(),
			n_chunks
		)));
	}
	if n_chunks == 0 {
		return Err(ser::Error::CorruptedData(
			"BitmapSegment must contain at least one block".to_string(),
		));
	}

	let chunk_limit = bitmap_segment_chunk_limit().map_err(ser::Error::DataOverflow)?;
	if n_chunks > chunk_limit {
		return Err(ser::Error::DataOverflow(format!(
			"BitmapSegment decoded {} chunks, PIBD limit is {}",
			n_chunks, chunk_limit
		)));
	}

	let segment_capacity = identifier.segment_capacity().map_err(|e| {
		ser::Error::CorruptedData(format!("Invalid bitmap segment identifier: {}", e))
	})?;
	if n_chunks as u64 > segment_capacity {
		return Err(ser::Error::DataOverflow(format!(
			"BitmapSegment decoded {} chunks, identifier limit is {}",
			n_chunks, segment_capacity
		)));
	}

	let leaf_offset = identifier.leaf_offset().map_err(|e| {
		ser::Error::CorruptedData(format!("Invalid bitmap segment identifier: {}", e))
	})?;
	for (chunk_idx, actual_pos) in leaf_pos.iter().copied().enumerate() {
		let chunk_idx_u64 = u64::try_from(chunk_idx).map_err(|_| {
			ser::Error::DataOverflow(format!("BitmapSegment::try_from, chunk_idx={}", chunk_idx))
		})?;
		let leaf_idx = leaf_offset.checked_add(chunk_idx_u64).ok_or_else(|| {
			ser::Error::DataOverflow(format!(
				"BitmapSegment::try_from, leaf_offset={} chunk_idx={}",
				leaf_offset, chunk_idx
			))
		})?;
		let expected_pos = pmmr::insertion_to_pmmr_index(leaf_idx).map_err(|e| {
			ser::Error::DataOverflow(format!(
				"BitmapSegment::try_from, leaf_idx={} error={}",
				leaf_idx, e
			))
		})?;
		if actual_pos != expected_pos {
			return Err(ser::Error::CorruptedData(format!(
				"BitmapSegment leaf position {} is {}, expected {}",
				chunk_idx, actual_pos, expected_pos
			)));
		}
	}

	Ok(())
}

// TODO: this can be sped up with some `unsafe` code
impl TryFrom<Segment<BitmapChunk>> for BitmapSegment {
	type Error = ser::Error;

	fn try_from(segment: Segment<BitmapChunk>) -> Result<Self, Self::Error> {
		let (identifier, hash_pos, hashes, leaf_pos, leaf_data, proof) = segment.parts();

		validate_bitmap_segment_parts_for_write(
			&identifier,
			&hash_pos,
			&hashes,
			&leaf_pos,
			leaf_data.len(),
		)?;

		let mut chunks_left = leaf_data.len();
		// Note: Real capacity is (chunks_left + BitmapBlock::NCHUNKS - 1) / BitmapBlock::NCHUNKS
		//   but that expression include unsafe operation. Instead we are using safe that can allocate
		//   one extra element in a worst case scenario.
		let mut blocks = Vec::with_capacity(chunks_left / BitmapBlock::NCHUNKS + 1);
		while chunks_left > 0 {
			let n_chunks = min(BitmapBlock::NCHUNKS, chunks_left);
			// Safe: n_chunks is capped at chunks_left above, so this cannot underflow.
			chunks_left -= n_chunks;
			blocks.push(BitmapBlock::new(n_chunks)?);
		}

		for (chunk_idx, chunk) in leaf_data.into_iter().enumerate() {
			if chunk.0.len() != BitmapChunk::LEN_BITS {
				return Err(ser::Error::CorruptedData(format!(
					"BitmapChunk expected {} bits, got {}",
					BitmapChunk::LEN_BITS,
					chunk.0.len()
				)));
			}
			let block = &mut blocks.get_mut(chunk_idx / BitmapBlock::NCHUNKS);

			if let Some(block) = block {
				// Safe: Data overflow can't happen here because all variables max values are limited by
				//  relatevly small constants.
				let offset = (chunk_idx % BitmapBlock::NCHUNKS) * BitmapChunk::LEN_BITS;
				for (i, _) in chunk.0.iter().enumerate().filter(|&(_, v)| v) {
					block.inner.set(offset + i, true);
				}
			}
		}

		Ok(Self {
			identifier,
			blocks,
			proof,
		})
	}
}

// TODO: this can be sped up with some `unsafe` code
impl TryFrom<BitmapSegment> for Segment<BitmapChunk> {
	type Error = Error;

	fn try_from(segment: BitmapSegment) -> Result<Self, Self::Error> {
		let BitmapSegment {
			identifier,
			blocks,
			proof,
		} = segment;

		let n_chunks = validate_bitmap_segment_layout(&identifier, &blocks)?;
		let mut leaf_pos = Vec::with_capacity(n_chunks);
		let mut chunks = Vec::with_capacity(n_chunks);
		let offset = identifier.leaf_offset()?;
		let n_chunks_u64 = u64::try_from(n_chunks).map_err(|_| {
			Error::DataOverflow(format!("BitmapSegment::try_from, n_chunks={}", n_chunks))
		})?;
		for i in 0..n_chunks_u64 {
			let leaf_idx = offset.checked_add(i).ok_or_else(|| {
				Error::DataOverflow(format!(
					"BitmapSegment::try_from, offset={} i={}",
					offset, i
				))
			})?;
			leaf_pos.push(pmmr::insertion_to_pmmr_index(leaf_idx)?);
			chunks.push(BitmapChunk::new());
		}

		for (block_idx, block) in blocks.into_iter().enumerate() {
			debug_assert!(block.inner.len() <= BitmapBlock::NBITS as usize);
			let offset = block_idx * BitmapBlock::NCHUNKS;
			for (i, _) in block.inner.iter().enumerate().filter(|&(_, v)| v) {
				if let Some(chunk) = chunks.get_mut(offset + i / BitmapChunk::LEN_BITS) {
					chunk.0.set(i % BitmapChunk::LEN_BITS, true);
				}
			}
		}

		Ok(Segment::from_parts(
			identifier,
			Vec::new(),
			Vec::new(),
			leaf_pos,
			chunks,
			proof,
		)?)
	}
}

/// A block of 2^16 bits that provides an efficient (de)serialization
/// depending on the bitmap occupancy.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BitmapBlock {
	inner: BitVec,
}

impl BitmapBlock {
	/// Maximum number of bits in a block
	const NBITS: u32 = 1 << 16;
	/// Maximum number of chunks in a block
	const NCHUNKS: usize = Self::NBITS as usize / BitmapChunk::LEN_BITS;

	fn new(n_chunks: usize) -> Result<Self, ser::Error> {
		if n_chunks > BitmapBlock::NCHUNKS {
			return Err(ser::Error::DataOverflow(format!(
				"BitmapBlock::new, n_chunks={} max_chunks={}",
				n_chunks,
				BitmapBlock::NCHUNKS
			)));
		}
		let n_bits = n_chunks.checked_mul(BitmapChunk::LEN_BITS).ok_or_else(|| {
			ser::Error::DataOverflow(format!(
				"BitmapBlock::new, n_chunks={} LEN_BITS={}",
				n_chunks,
				BitmapChunk::LEN_BITS
			))
		})?;
		Ok(Self {
			inner: BitVec::from_elem(n_bits, false),
		})
	}

	fn checked_n_chunks(&self) -> Result<usize, ser::Error> {
		let length = self.inner.len();
		if length > BitmapBlock::NBITS as usize {
			return Err(ser::Error::DataOverflow(format!(
				"BitmapBlock::checked_n_chunks, length={} max_bits={}",
				length,
				BitmapBlock::NBITS
			)));
		}
		if length % BitmapChunk::LEN_BITS != 0 {
			return Err(ser::Error::DataOverflow(format!(
				"BitmapBlock::checked_n_chunks, length={} chunk_bits={}",
				length,
				BitmapChunk::LEN_BITS
			)));
		}
		let n_chunks = length / BitmapChunk::LEN_BITS;
		if n_chunks > BitmapBlock::NCHUNKS {
			return Err(ser::Error::DataOverflow(format!(
				"BitmapBlock::checked_n_chunks, n_chunks={} max_chunks={}",
				n_chunks,
				BitmapBlock::NCHUNKS
			)));
		}
		Ok(n_chunks)
	}
}

impl Writeable for BitmapBlock {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let length = self.inner.len();
		// Safe on supported targets: NBITS is 2^16, and BitmapBlock::NCHUNKS
		// already relies on this constant fitting in usize.
		let max_bits = Self::NBITS as usize;
		if length > max_bits {
			return Err(ser::Error::DataOverflow(format!(
				"BitmapBlock::write, length={} max_bits={}",
				length, max_bits
			)));
		}
		if length % BitmapChunk::LEN_BITS != 0 {
			return Err(ser::Error::DataOverflow(format!(
				"BitmapBlock::write, length={} chunk_bits={}",
				length,
				BitmapChunk::LEN_BITS
			)));
		}
		let n_chunks = length / BitmapChunk::LEN_BITS;
		if n_chunks > Self::NCHUNKS {
			return Err(ser::Error::DataOverflow(format!(
				"BitmapBlock::write, n_chunks={} max_chunks={}",
				n_chunks,
				Self::NCHUNKS
			)));
		}

		// Safe after the invariant checks above: length is capped at 2^16 bits,
		// chunk-aligned, and BitmapChunk::LEN_BITS is non-zero. This means there
		// are at most 64 chunks and all bit counts fit u32.
		let n_chunks = n_chunks as u8;

		let count_pos = self.inner.iter().filter(|&v| v).count();
		let count_pos = count_pos as u32;

		// Negative count needs to be adjusted if the block is not full,
		// which affects the choice of serialization mode and size written
		let length = length as u32;
		let count_neg = length.checked_sub(count_pos).ok_or_else(|| {
			ser::Error::DataOverflow(format!(
				"BitmapBlock::write, length={} count_pos={}",
				length, count_pos
			))
		})?;

		writer.write_u8(n_chunks)?;
		let threshold = Self::NBITS / 16;
		if count_pos < threshold {
			// Write positive indices
			// Safe: sparse mode is selected only below threshold (4096), and the
			// validated block length limits bit indexes to 0..=65535.
			Writeable::write(&BitmapBlockSerialization::Positive, writer)?;
			writer.write_u16(count_pos as u16)?;
			for (i, _) in self.inner.iter().enumerate().filter(|&(_, v)| v) {
				writer.write_u16(i as u16)?;
			}
		} else if count_neg < threshold {
			// Write negative indices
			// Safe: sparse mode is selected only below threshold (4096), and the
			// validated block length limits bit indexes to 0..=65535.
			Writeable::write(&BitmapBlockSerialization::Negative, writer)?;
			writer.write_u16(count_neg as u16)?;
			for (i, _) in self.inner.iter().enumerate().filter(|&(_, v)| !v) {
				writer.write_u16(i as u16)?;
			}
		} else {
			// Write raw bytes
			Writeable::write(&BitmapBlockSerialization::Raw, writer)?;
			let bytes = self.inner.to_bytes();
			let max_bytes = max_bits / 8;
			if bytes.len() > max_bytes {
				return Err(ser::Error::DataOverflow(format!(
					"BitmapBlock::write, byte_len={} max_bytes={}",
					bytes.len(),
					max_bytes
				)));
			}
			writer.write_fixed_bytes(&bytes)?;
		}

		Ok(())
	}
}

impl Readable for BitmapBlock {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let n_chunks = reader.read_u8()?;
		if n_chunks as usize > BitmapBlock::NCHUNKS {
			return Err(ser::Error::TooLargeReadErr(format!(
				"Requested {} chunks, limit is {}",
				n_chunks,
				BitmapBlock::NCHUNKS
			)));
		}
		let n_bits = n_chunks as usize * BitmapChunk::LEN_BITS;

		let mode = Readable::read(reader)?;
		let inner = match mode {
			BitmapBlockSerialization::Raw => {
				// Raw bytes
				let bytes = reader.read_fixed_bytes(n_bits / 8)?;
				let inner = BitVec::from_bytes(&bytes);
				let threshold = BitmapBlock::NBITS as usize / 16;
				let count_pos = inner.iter().filter(|&v| v).count();
				let count_neg = n_bits.checked_sub(count_pos).ok_or_else(|| {
					ser::Error::CorruptedData(format!(
						"BitmapBlock raw positive count {} exceeds {} bits",
						count_pos, n_bits
					))
				})?;
				if count_pos < threshold || count_neg < threshold {
					return Err(ser::Error::CorruptedData(format!(
						"BitmapBlock raw encoding is non-canonical: positive count {}, negative count {}, threshold {}",
						count_pos, count_neg, threshold
					)));
				}
				inner
			}
			BitmapBlockSerialization::Positive => {
				// Positive indices
				let mut inner = BitVec::from_elem(n_bits, false);
				let n = reader.read_u16()?;
				let threshold = BitmapBlock::NBITS / 16;
				if u32::from(n) >= threshold {
					return Err(ser::Error::CorruptedData(format!(
						"BitmapBlock positive sparse count {} exceeds canonical limit {}",
						n,
						threshold - 1
					)));
				}
				if usize::from(n) > n_bits {
					return Err(ser::Error::CorruptedData(format!(
						"BitmapBlock positive sparse count {} exceeds {} bits",
						n, n_bits
					)));
				}
				let mut previous_index = None;
				for _ in 0..n {
					let index = reader.read_u16()? as usize;
					if index >= n_bits {
						return Err(ser::Error::CorruptedData(format!(
							"BitmapBlock positive index {} exceeds {} bits",
							index, n_bits
						)));
					}
					if previous_index.map(|prev| index <= prev).unwrap_or(false) {
						return Err(ser::Error::CorruptedData(format!(
							"BitmapBlock positive indexes are not strictly increasing: {} after {}",
							index,
							previous_index.unwrap()
						)));
					}
					previous_index = Some(index);
					inner.set(index, true);
				}
				inner
			}
			BitmapBlockSerialization::Negative => {
				// Negative indices
				let mut inner = BitVec::from_elem(n_bits, true);
				let n = reader.read_u16()?;
				let threshold = BitmapBlock::NBITS / 16;
				if u32::from(n) >= threshold {
					return Err(ser::Error::CorruptedData(format!(
						"BitmapBlock negative sparse count {} exceeds canonical limit {}",
						n,
						threshold - 1
					)));
				}
				if usize::from(n) > n_bits {
					return Err(ser::Error::CorruptedData(format!(
						"BitmapBlock negative sparse count {} exceeds {} bits",
						n, n_bits
					)));
				}
				let threshold = BitmapBlock::NBITS as usize / 16;
				let count_pos = n_bits - usize::from(n);
				if count_pos < threshold {
					return Err(ser::Error::CorruptedData(format!(
						"BitmapBlock negative sparse encoding is non-canonical: positive count {}, threshold {}",
						count_pos, threshold
					)));
				}
				let mut previous_index = None;
				for _ in 0..n {
					let index = reader.read_u16()? as usize;
					if index >= n_bits {
						return Err(ser::Error::CorruptedData(format!(
							"BitmapBlock negative index {} exceeds {} bits",
							index, n_bits
						)));
					}
					if previous_index.map(|prev| index <= prev).unwrap_or(false) {
						return Err(ser::Error::CorruptedData(format!(
							"BitmapBlock negative indexes are not strictly increasing: {} after {}",
							index,
							previous_index.unwrap()
						)));
					}
					previous_index = Some(index);
					inner.set(index, false);
				}
				inner
			}
		};

		Ok(BitmapBlock { inner })
	}
}

enum_from_primitive! {
	#[derive(Debug, Clone, Copy, PartialEq)]
	#[repr(u8)]
	enum BitmapBlockSerialization {
		Raw = 0,
		Positive = 1,
		Negative = 2,
	}
}

impl Writeable for BitmapBlockSerialization {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(*self as u8)
	}
}

impl Readable for BitmapBlockSerialization {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		Self::from_u8(reader.read_u8()?).ok_or(ser::Error::CorruptedData(format!(
			"Failed to read the next byte"
		)))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::ser::{BinReader, BinWriter, ProtocolVersion, Readable, Writeable};
	use mwc_crates::byteorder::ReadBytesExt;
	use mwc_crates::rand::rng;
	use mwc_crates::rand::RngExt;
	use std::io::Cursor;

	fn test_roundtrip(entries: usize, inverse: bool, encoding: u8, length: usize, n_blocks: usize) {
		let mut rng = rng();
		let mut block = BitmapBlock::new(n_blocks).unwrap();
		if inverse {
			block.inner.negate();
		}

		let range_size = n_blocks * BitmapChunk::LEN_BITS as usize;

		// Flip `entries` bits in random spots
		let mut count = 0;
		while count < entries {
			let idx = rng.random_range(0..range_size);
			if block.inner.get(idx).unwrap() == inverse {
				count += 1;
				block.inner.set(idx, !inverse);
			}
		}

		// Serialize
		let mut cursor = Cursor::new(Vec::<u8>::new());
		let mut writer = BinWriter::new(&mut cursor, ProtocolVersion(1), 0);
		Writeable::write(&block, &mut writer).unwrap();

		// Check encoding type and length
		cursor.set_position(1);
		assert_eq!(cursor.read_u8().unwrap(), encoding);
		let actual_length = cursor.get_ref().len();
		assert_eq!(actual_length, length);
		assert!(actual_length <= 2 + BitmapBlock::NBITS as usize / 8);

		// Deserialize
		cursor.set_position(0);
		let mut reader = BinReader::new(&mut cursor, ProtocolVersion(1), 0);
		let block2: BitmapBlock = Readable::read(&mut reader).unwrap();
		assert_eq!(block, block2);
	}

	fn serialized_bitmap_segment_prefix(identifier: SegmentIdentifier, n_blocks: u16) -> Vec<u8> {
		let mut cursor = Cursor::new(Vec::<u8>::new());
		let mut writer = BinWriter::new(&mut cursor, ProtocolVersion(1), 0);
		Writeable::write(&identifier, &mut writer).unwrap();
		writer.write_u16(n_blocks).unwrap();
		cursor.into_inner()
	}

	fn append_empty_bitmap_block(bytes: &mut Vec<u8>, n_chunks: u8) {
		let mut cursor = Cursor::new(bytes);
		cursor.set_position(cursor.get_ref().len() as u64);
		let mut writer = BinWriter::new(&mut cursor, ProtocolVersion(1), 0);
		writer.write_u8(n_chunks).unwrap();
		Writeable::write(&BitmapBlockSerialization::Positive, &mut writer).unwrap();
		writer.write_u16(0).unwrap();
	}

	fn append_empty_full_bitmap_block(bytes: &mut Vec<u8>) {
		append_empty_bitmap_block(bytes, BitmapBlock::NCHUNKS as u8);
	}

	fn append_empty_segment_proof(bytes: &mut Vec<u8>) {
		let mut cursor = Cursor::new(bytes);
		cursor.set_position(cursor.get_ref().len() as u64);
		let mut writer = BinWriter::new(&mut cursor, ProtocolVersion(1), 0);
		writer.write_u64(0).unwrap();
	}

	fn read_bitmap_segment(bytes: Vec<u8>) -> Result<BitmapSegment, ser::Error> {
		let mut cursor = Cursor::new(bytes);
		let mut reader = BinReader::new(&mut cursor, ProtocolVersion(1), 0);
		Readable::read(&mut reader)
	}

	fn empty_segment_proof() -> SegmentProof {
		let mut bytes = Vec::<u8>::new();
		append_empty_segment_proof(&mut bytes);
		let mut cursor = Cursor::new(bytes);
		let mut reader = BinReader::new(&mut cursor, ProtocolVersion(1), 0);
		Readable::read(&mut reader).unwrap()
	}

	fn bitmap_segment_from_blocks(
		identifier: SegmentIdentifier,
		blocks: Vec<BitmapBlock>,
	) -> BitmapSegment {
		BitmapSegment {
			identifier,
			blocks,
			proof: empty_segment_proof(),
		}
	}

	fn bitmap_chunk_segment(
		identifier: SegmentIdentifier,
		n_chunks: usize,
	) -> Segment<BitmapChunk> {
		let leaf_offset = identifier.leaf_offset().unwrap();
		Segment::from_parts(
			identifier,
			Vec::new(),
			Vec::new(),
			(0..n_chunks)
				.map(|idx| {
					let leaf_idx = leaf_offset.checked_add(idx as u64).unwrap();
					pmmr::insertion_to_pmmr_index(leaf_idx).unwrap()
				})
				.collect(),
			(0..n_chunks).map(|_| BitmapChunk::new()).collect(),
			empty_segment_proof(),
		)
		.unwrap()
	}

	#[test]
	fn block_ser_roundtrip() {
		let threshold = BitmapBlock::NBITS as usize / 16;
		let entries = rng().random_range(threshold..4 * threshold);
		test_roundtrip(entries, false, 0, 2 + BitmapBlock::NBITS as usize / 8, 64);
		test_roundtrip(entries, true, 0, 2 + BitmapBlock::NBITS as usize / 8, 64);
	}

	#[test]
	fn sparse_block_ser_roundtrip() {
		let entries = rng().random_range(BitmapChunk::LEN_BITS..BitmapBlock::NBITS as usize / 16);
		test_roundtrip(entries, false, 1, 4 + 2 * entries, 64);
	}

	#[test]
	fn sparse_unfull_block_ser_roundtrip() {
		let entries = rng().random_range(BitmapChunk::LEN_BITS..BitmapBlock::NBITS as usize / 16);
		test_roundtrip(entries, false, 1, 4 + 2 * entries, 61);
	}

	#[test]
	fn bitmap_chunk_ser_roundtrip_consumes_exact_bytes() {
		let mut chunk = BitmapChunk::new();
		chunk.set(0, true).unwrap();
		chunk.set(100, true).unwrap();
		chunk.set((BitmapChunk::LEN_BITS - 1) as u64, true).unwrap();

		let mut cursor = Cursor::new(Vec::<u8>::new());
		let mut writer = BinWriter::new(&mut cursor, ProtocolVersion(1), 0);
		Writeable::write(&chunk, &mut writer).unwrap();
		writer.write_u8(7).unwrap();

		assert_eq!(cursor.get_ref().len(), BitmapChunk::LEN_BYTES + 1);

		cursor.set_position(0);
		let mut reader = BinReader::new(&mut cursor, ProtocolVersion(1), 0);
		let chunk2: BitmapChunk = Readable::read(&mut reader).unwrap();
		assert_eq!(chunk, chunk2);
		assert_eq!(reader.read_u8().unwrap(), 7);
	}

	#[test]
	fn bitmap_block_new_rejects_too_many_chunks() {
		assert!(matches!(
			BitmapBlock::new(BitmapBlock::NCHUNKS + 1),
			Err(ser::Error::DataOverflow(_))
		));
	}

	#[test]
	fn bitmap_chunk_read_rejects_truncated_input() {
		let bytes = vec![0u8; BitmapChunk::LEN_BYTES - 1];
		let mut cursor = Cursor::new(bytes);
		let mut reader = BinReader::new(&mut cursor, ProtocolVersion(1), 0);

		assert!(Readable::read(&mut reader)
			.map(|_: BitmapChunk| ())
			.is_err());
	}

	#[test]
	fn bitmap_segment_read_rejects_block_count_above_identifier_capacity() {
		let bytes = serialized_bitmap_segment_prefix(SegmentIdentifier::new(0, 0), u16::MAX);

		assert!(matches!(
			read_bitmap_segment(bytes),
			Err(ser::Error::TooLargeReadErr(_))
		));
	}

	#[test]
	fn bitmap_segment_read_rejects_block_count_above_pibd_limit() {
		let block_limit = bitmap_segment_block_limit().unwrap();
		let bytes = serialized_bitmap_segment_prefix(
			SegmentIdentifier::new(20, 0),
			u16::try_from(block_limit + 1).unwrap(),
		);

		assert!(matches!(
			read_bitmap_segment(bytes),
			Err(ser::Error::TooLargeReadErr(_))
		));
	}

	#[test]
	fn bitmap_segment_read_rejects_decoded_chunks_above_identifier_capacity() {
		let mut bytes = serialized_bitmap_segment_prefix(SegmentIdentifier::new(5, 0), 1);
		append_empty_full_bitmap_block(&mut bytes);

		assert!(matches!(
			read_bitmap_segment(bytes),
			Err(ser::Error::TooLargeReadErr(_))
		));
	}

	#[test]
	fn bitmap_segment_read_rejects_empty_block() {
		let mut bytes = serialized_bitmap_segment_prefix(SegmentIdentifier::new(0, 0), 1);
		append_empty_bitmap_block(&mut bytes, 0);
		append_empty_segment_proof(&mut bytes);

		assert!(matches!(
			read_bitmap_segment(bytes),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn bitmap_segment_read_rejects_short_non_final_block() {
		let mut bytes = serialized_bitmap_segment_prefix(SegmentIdentifier::new(7, 0), 2);
		append_empty_bitmap_block(&mut bytes, 1);
		append_empty_bitmap_block(&mut bytes, 1);
		append_empty_segment_proof(&mut bytes);

		assert!(matches!(
			read_bitmap_segment(bytes),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn bitmap_segment_try_from_rejects_empty_block() {
		let segment = bitmap_segment_from_blocks(
			SegmentIdentifier::new(0, 0),
			vec![BitmapBlock::new(0).unwrap()],
		);

		assert!(matches!(
			Segment::<BitmapChunk>::try_from(segment),
			Err(Error::InvalidSegment(_))
		));
	}

	#[test]
	fn bitmap_segment_try_from_rejects_short_non_final_block() {
		let segment = bitmap_segment_from_blocks(
			SegmentIdentifier::new(7, 0),
			vec![BitmapBlock::new(1).unwrap(), BitmapBlock::new(1).unwrap()],
		);

		assert!(matches!(
			Segment::<BitmapChunk>::try_from(segment),
			Err(Error::InvalidSegment(_))
		));
	}

	#[test]
	fn bitmap_segment_try_from_rejects_chunks_above_pibd_limit() {
		let chunk_limit = bitmap_segment_chunk_limit().unwrap();
		let n_blocks = chunk_limit / BitmapBlock::NCHUNKS + 1;
		let blocks = (0..n_blocks)
			.map(|_| BitmapBlock::new(BitmapBlock::NCHUNKS).unwrap())
			.collect();
		let segment = bitmap_segment_from_blocks(SegmentIdentifier::new(20, 0), blocks);

		assert!(matches!(
			Segment::<BitmapChunk>::try_from(segment),
			Err(Error::InvalidSegment(_))
		));
	}

	#[test]
	fn bitmap_segment_from_segment_rejects_empty_leaf_data() {
		let segment = bitmap_chunk_segment(SegmentIdentifier::new(0, 0), 0);

		assert!(matches!(
			BitmapSegment::try_from(segment),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn bitmap_segment_from_segment_rejects_chunks_above_identifier_capacity() {
		let segment = bitmap_chunk_segment(SegmentIdentifier::new(0, 0), 2);

		assert!(matches!(
			BitmapSegment::try_from(segment),
			Err(ser::Error::DataOverflow(_))
		));
	}

	#[test]
	fn bitmap_segment_from_segment_rejects_chunks_above_pibd_limit() {
		let chunk_limit = bitmap_segment_chunk_limit().unwrap();
		let segment = bitmap_chunk_segment(SegmentIdentifier::new(20, 0), chunk_limit + 1);

		assert!(matches!(
			BitmapSegment::try_from(segment),
			Err(ser::Error::DataOverflow(_))
		));
	}

	#[test]
	fn bitmap_segment_from_segment_rejects_pruned_hash_data() {
		let segment = Segment::from_parts(
			SegmentIdentifier::new(1, 0),
			vec![2],
			vec![Hash::default()],
			vec![0],
			vec![BitmapChunk::new()],
			empty_segment_proof(),
		)
		.unwrap();

		assert!(matches!(
			BitmapSegment::try_from(segment),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn bitmap_segment_from_segment_rejects_non_contiguous_leaf_positions() {
		let segment = Segment::from_parts(
			SegmentIdentifier::new(2, 0),
			Vec::new(),
			Vec::new(),
			vec![0, 3],
			vec![BitmapChunk::new(), BitmapChunk::new()],
			empty_segment_proof(),
		)
		.unwrap();

		assert!(matches!(
			BitmapSegment::try_from(segment),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn bitmap_segment_try_from_allows_short_final_block() {
		let segment = bitmap_segment_from_blocks(
			SegmentIdentifier::new(7, 0),
			vec![
				BitmapBlock::new(BitmapBlock::NCHUNKS).unwrap(),
				BitmapBlock::new(1).unwrap(),
			],
		);

		let segment = Segment::<BitmapChunk>::try_from(segment).unwrap();

		assert_eq!(segment.leaf_iter().count(), BitmapBlock::NCHUNKS + 1);
	}

	fn write_block(block: &BitmapBlock) -> Result<(), ser::Error> {
		let mut bytes = Vec::<u8>::new();
		let mut writer = BinWriter::new(&mut bytes, ProtocolVersion(1), 0);
		Writeable::write(block, &mut writer)
	}

	#[test]
	fn block_write_rejects_unaligned_bit_length() {
		let block = BitmapBlock {
			inner: BitVec::from_elem(BitmapChunk::LEN_BITS - 1, false),
		};

		assert!(matches!(
			write_block(&block),
			Err(ser::Error::DataOverflow(_))
		));
	}

	#[test]
	fn block_write_rejects_overlong_bit_length() {
		let block = BitmapBlock {
			inner: BitVec::from_elem(BitmapBlock::NBITS as usize + BitmapChunk::LEN_BITS, false),
		};

		assert!(matches!(
			write_block(&block),
			Err(ser::Error::DataOverflow(_))
		));
	}

	#[test]
	fn abdundant_block_ser_roundtrip() {
		let entries = rng().random_range(BitmapChunk::LEN_BITS..BitmapBlock::NBITS as usize / 16);
		test_roundtrip(entries, true, 2, 4 + 2 * entries, 64);
	}

	#[test]
	fn abdundant_unfull_block_ser_roundtrip() {
		let entries = rng().random_range(BitmapChunk::LEN_BITS..BitmapBlock::NBITS as usize / 16);
		test_roundtrip(entries, true, 2, 4 + 2 * entries, 61);
	}

	#[test]
	fn apply_from_handles_final_u64_chunk_without_boundary_overflow() {
		let max_idx = u64::MAX - 1;
		let mut accumulator = BitmapAccumulator::new(0);

		accumulator
			.apply_from(vec![Ok(max_idx)], max_idx, u64::MAX)
			.unwrap();
	}

	#[test]
	fn init_resets_existing_accumulator_before_rebuild() {
		let mut accumulator = BitmapAccumulator::new(0);
		accumulator
			.init(vec![Ok(0)], BitmapAccumulator::NBITS)
			.unwrap();
		let initial_size = accumulator.backend.size();

		accumulator
			.init(vec![Ok(1)], BitmapAccumulator::NBITS)
			.unwrap();

		assert_eq!(accumulator.backend.size(), initial_size);
		let bitmap = accumulator.build_bitmap().unwrap();
		assert!(!bitmap.contains(0));
		assert!(bitmap.contains(1));
	}

	#[test]
	fn init_with_zero_size_clears_existing_accumulator() {
		let mut accumulator = BitmapAccumulator::new(0);
		accumulator
			.init(vec![Ok(0)], BitmapAccumulator::NBITS)
			.unwrap();

		accumulator.init(Vec::new(), 0).unwrap();

		assert_eq!(accumulator.backend.size(), 0);
		assert!(accumulator.build_bitmap().unwrap().is_empty());
	}

	#[test]
	fn append_chunk_preserves_pmmr_error_variant() {
		let mut accumulator = BitmapAccumulator::new(0);
		accumulator.backend.hashes.resize(2, None);

		let err = accumulator.append_chunk(BitmapChunk::new()).unwrap_err();

		assert!(matches!(
			err,
			Error::PMMRErr(mwc_core::core::pmmr::Error::DataCorruption(_))
		));
	}

	fn malformed_sparse_block(mode: BitmapBlockSerialization) -> Result<BitmapBlock, ser::Error> {
		read_sparse_bitmap_block(mode, 1, &[BitmapChunk::LEN_BITS as u16])
	}

	fn read_sparse_bitmap_block(
		mode: BitmapBlockSerialization,
		n_chunks: u8,
		indexes: &[u16],
	) -> Result<BitmapBlock, ser::Error> {
		let mut bytes = Vec::<u8>::new();
		let mut cursor = Cursor::new(&mut bytes);
		let mut writer = BinWriter::new(&mut cursor, ProtocolVersion(1), 0);
		writer.write_u8(n_chunks).unwrap();
		Writeable::write(&mode, &mut writer).unwrap();
		writer.write_u16(indexes.len() as u16).unwrap();
		for index in indexes {
			writer.write_u16(*index).unwrap();
		}
		drop(writer);
		drop(cursor);

		let mut cursor = Cursor::new(bytes);
		let mut reader = BinReader::new(&mut cursor, ProtocolVersion(1), 0);
		Readable::read(&mut reader)
	}

	fn read_sparse_bitmap_block_with_count(
		mode: BitmapBlockSerialization,
		n_chunks: u8,
		count: u16,
	) -> Result<BitmapBlock, ser::Error> {
		let mut bytes = Vec::<u8>::new();
		let mut cursor = Cursor::new(&mut bytes);
		let mut writer = BinWriter::new(&mut cursor, ProtocolVersion(1), 0);
		writer.write_u8(n_chunks).unwrap();
		Writeable::write(&mode, &mut writer).unwrap();
		writer.write_u16(count).unwrap();
		drop(writer);
		drop(cursor);

		let mut cursor = Cursor::new(bytes);
		let mut reader = BinReader::new(&mut cursor, ProtocolVersion(1), 0);
		Readable::read(&mut reader)
	}

	fn read_raw_bitmap_block(n_chunks: u8, bytes: &[u8]) -> Result<BitmapBlock, ser::Error> {
		let mut encoded = Vec::<u8>::new();
		let mut cursor = Cursor::new(&mut encoded);
		let mut writer = BinWriter::new(&mut cursor, ProtocolVersion(1), 0);
		writer.write_u8(n_chunks).unwrap();
		Writeable::write(&BitmapBlockSerialization::Raw, &mut writer).unwrap();
		writer.write_fixed_bytes(bytes).unwrap();
		drop(writer);
		drop(cursor);

		let mut cursor = Cursor::new(encoded);
		let mut reader = BinReader::new(&mut cursor, ProtocolVersion(1), 0);
		Readable::read(&mut reader)
	}

	#[test]
	fn sparse_block_rejects_positive_index_out_of_range() {
		assert!(matches!(
			malformed_sparse_block(BitmapBlockSerialization::Positive),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_negative_index_out_of_range() {
		assert!(matches!(
			malformed_sparse_block(BitmapBlockSerialization::Negative),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_positive_count_at_threshold() {
		let threshold = (BitmapBlock::NBITS / 16) as u16;
		assert!(matches!(
			read_sparse_bitmap_block_with_count(BitmapBlockSerialization::Positive, 64, threshold),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_negative_count_at_threshold() {
		let threshold = (BitmapBlock::NBITS / 16) as u16;
		assert!(matches!(
			read_sparse_bitmap_block_with_count(BitmapBlockSerialization::Negative, 64, threshold),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_positive_count_above_block_bits() {
		assert!(matches!(
			read_sparse_bitmap_block_with_count(
				BitmapBlockSerialization::Positive,
				1,
				BitmapChunk::LEN_BITS as u16 + 1
			),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_negative_count_above_block_bits() {
		assert!(matches!(
			read_sparse_bitmap_block_with_count(
				BitmapBlockSerialization::Negative,
				1,
				BitmapChunk::LEN_BITS as u16 + 1
			),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_negative_when_positive_is_canonical() {
		assert!(matches!(
			read_sparse_bitmap_block_with_count(BitmapBlockSerialization::Negative, 1, 0),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn raw_block_rejects_positive_sparse_canonical_encoding() {
		let bytes = vec![0u8; BitmapBlock::NBITS as usize / 8];

		assert!(matches!(
			read_raw_bitmap_block(BitmapBlock::NCHUNKS as u8, &bytes),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn raw_block_rejects_negative_sparse_canonical_encoding() {
		let bytes = vec![0xffu8; BitmapBlock::NBITS as usize / 8];

		assert!(matches!(
			read_raw_bitmap_block(BitmapBlock::NCHUNKS as u8, &bytes),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_duplicate_positive_indexes() {
		assert!(matches!(
			read_sparse_bitmap_block(BitmapBlockSerialization::Positive, 1, &[7, 7]),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_duplicate_negative_indexes() {
		assert!(matches!(
			read_sparse_bitmap_block(BitmapBlockSerialization::Negative, 1, &[7, 7]),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_out_of_order_positive_indexes() {
		assert!(matches!(
			read_sparse_bitmap_block(BitmapBlockSerialization::Positive, 1, &[9, 7]),
			Err(ser::Error::CorruptedData(_))
		));
	}

	#[test]
	fn sparse_block_rejects_out_of_order_negative_indexes() {
		assert!(matches!(
			read_sparse_bitmap_block(BitmapBlockSerialization::Negative, 1, &[9, 7]),
			Err(ser::Error::CorruptedData(_))
		));
	}
}
