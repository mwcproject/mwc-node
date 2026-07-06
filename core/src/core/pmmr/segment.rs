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

//! Segment of a PMMR.

use crate::core::hash::Hash;
use crate::core::pmmr::{self, Backend, ReadablePMMR, ReadonlyPMMR, VecBackend, PMMR};
use crate::ser::{
	Error, PMMRIndexHashable, PMMRable, Readable, Reader, Writeable, Writer, READ_VEC_SIZE_LIMIT,
};
use mwc_crates::croaring::Bitmap;
use std::cmp::min;
use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fmt;
use std::fmt::{Debug, Display};

const SEGMENT_POSITION_SIZE: usize = 8;
const SEGMENT_HASH_PAYLOAD_SIZE: usize = SEGMENT_POSITION_SIZE + Hash::LEN;
const MAX_SEGMENT_PROOF_HASHES: u64 = u64::BITS as u64 * 2 + 1;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
/// Possible segment types, according to this desegmenter
pub enum SegmentType {
	/// Output Bitmap
	Bitmap,
	/// Output
	Output,
	/// RangeProof
	RangeProof,
	/// Kernel
	Kernel,
}

/// Lumps possible types with segment ids to enable a unique identifier
/// for a segment with respect to a particular archive header
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SegmentTypeIdentifier {
	/// The type of this segment
	pub segment_type: SegmentType,
	/// The identfier itself
	pub identifier: SegmentIdentifier,
}

impl SegmentTypeIdentifier {
	/// Create
	pub fn new(segment_type: SegmentType, identifier: SegmentIdentifier) -> Self {
		Self {
			segment_type,
			identifier,
		}
	}
}

#[derive(Debug, thiserror::Error)]
/// Error related to segment creation or validation
pub enum SegmentError {
	/// An expected leaf was missing
	#[error("Missing leaf at pos {0}")]
	MissingLeaf(u64),
	/// An expected hash was missing
	#[error("Missing hash at pos {0}")]
	MissingHash(u64),
	/// The segment does not exist
	#[error("Segment does not exist")]
	NonExistent,
	/// Invalid MMR size
	#[error("Invalid MMR size {mmr_size}, incomplete subtree boundary at height {next_height}")]
	InvalidMMRSize {
		/// Invalid PMMR size.
		mmr_size: u64,
		/// Height of the incomplete subtree boundary.
		next_height: u64,
	},
	/// Mismatch between expected and actual root hash
	#[error("Root hash mismatch")]
	Mismatch,
	/// Too large segment size
	#[error("Segment is too large")]
	SegmentSizeAboveLimit,
	/// Generic internal error
	#[error("{0}")]
	GenericError(String),
	/// Underlying IO error.
	#[error("Segment IO error, {0}")]
	IO(#[from] std::io::Error),
	/// Data overflow error
	#[error("Segment data overflow error, {0}")]
	DataOverflow(String),
	/// PMMR Error
	#[error("PMMR Error, {0}")]
	PMMRError(crate::core::pmmr::Error),
}

impl From<crate::core::pmmr::Error> for SegmentError {
	fn from(source: crate::core::pmmr::Error) -> Self {
		match source {
			crate::core::pmmr::Error::DataOverflow(msg) => SegmentError::DataOverflow(msg),
			source => SegmentError::PMMRError(source),
		}
	}
}

/// Tuple that defines a segment of a given PMMR
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct SegmentIdentifier {
	/// Height of a segment
	pub height: u8,
	/// Zero-based index of the segment
	pub idx: u64,
}

impl Display for SegmentIdentifier {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		// Formater doesn't need to handle the errors. If error happens,
		let leaf_offset = match self.leaf_offset() {
			Ok(x) => x,
			Err(_) => {
				return write!(f, "(h:{}, idx:{}, Invalid offset)", self.height, self.idx);
			}
		};
		let segment_capacity = match self.segment_capacity() {
			Ok(x) => x,
			Err(_) => {
				return write!(f, "(h:{}, idx:{}, Invalid capacity)", self.height, self.idx);
			}
		};
		write!(
			f,
			"(h:{}, idx:{} offset:{:?} size:{:?})",
			self.height, self.idx, leaf_offset, segment_capacity
		)
	}
}

impl Readable for SegmentIdentifier {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
		let height = reader.read_u8()?;
		let idx = reader.read_u64()?;
		Ok(Self { height, idx })
	}
}

impl Writeable for SegmentIdentifier {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u8(self.height)?;
		writer.write_u64(self.idx)
	}
}

impl SegmentIdentifier {
	/// Create a new segment
	pub fn new(height: u8, idx: u64) -> Self {
		SegmentIdentifier { height, idx }
	}

	/// Maximum number of leaves in a segment, given by `2**height`
	pub fn segment_capacity_ex(height: u8) -> Result<u64, SegmentError> {
		// 1 << height
		1u64.checked_shl(u32::from(height)).ok_or_else(|| {
			SegmentError::DataOverflow(format!(
				"SegmentIdentifier::segment_capacity_ex, height={}",
				height
			))
		})
	}

	/// Maximum number of leaves in a segment, given by `2**height`
	pub fn segment_capacity(&self) -> Result<u64, SegmentError> {
		Self::segment_capacity_ex(self.height)
	}

	/// Offset (in leaf idx) of first leaf in the segment
	pub fn leaf_offset(&self) -> Result<u64, SegmentError> {
		let segment_capacity = self.segment_capacity()?;
		self.idx.checked_mul(segment_capacity).ok_or_else(|| {
			SegmentError::DataOverflow(format!(
				"SegmentIdentifier::leaf_offset, idx={} segment_capacity={}",
				self.idx, segment_capacity
			))
		})
	}

	fn validate_complete_mmr_size(mmr_size: u64) -> Result<(), SegmentError> {
		let (_, next_height) = pmmr::peak_sizes_height(mmr_size);
		if next_height != 0 {
			return Err(SegmentError::InvalidMMRSize {
				mmr_size,
				next_height,
			});
		}
		Ok(())
	}

	// Number of leaves in this segment. Equal to capacity except for the final segment, which can be smaller
	fn segment_unpruned_size(&self, mmr_size: u64) -> Result<u64, SegmentError> {
		Self::validate_complete_mmr_size(mmr_size)?;
		Ok(min(
			self.segment_capacity()?,
			pmmr::n_leaves(mmr_size)?.saturating_sub(self.leaf_offset()?),
		))
	}

	/// Inclusive (full) range of MMR positions for the segment that would be produced
	/// by this Identifier
	pub fn segment_pos_range(&self, mmr_size: u64) -> Result<(u64, u64), SegmentError> {
		let segment_size = self.segment_unpruned_size(mmr_size)?;
		if segment_size == 0 {
			return Err(SegmentError::NonExistent);
		}
		let leaf_offset = self.leaf_offset()?;
		let first = pmmr::insertion_to_pmmr_index(leaf_offset)?;
		let last = if self.full_segment(mmr_size)? {
			// pmmr::insertion_to_pmmr_index(leaf_offset + segment_size - 1) + (self.height as u64)
			let last_leaf_idx = leaf_offset
				.checked_add(segment_size)
				.and_then(|x| x.checked_sub(1))
				.ok_or_else(|| {
					SegmentError::DataOverflow(format!(
						"SegmentIdentifier::segment_pos_range, leaf_offset={} segment_size={}",
						leaf_offset, segment_size
					))
				})?;
			pmmr::insertion_to_pmmr_index(last_leaf_idx)?
				.checked_add(self.height as u64)
				.ok_or_else(|| {
					SegmentError::DataOverflow(format!(
						"SegmentIdentifier::segment_pos_range, last_leaf_idx={} height={}",
						last_leaf_idx, self.height
					))
				})?
		} else {
			mmr_size.checked_sub(1).ok_or_else(|| {
				SegmentError::DataOverflow(format!(
					"SegmentIdentifier::segment_pos_range, mmr_size={}",
					mmr_size
				))
			})?
		};
		Ok((first, last))
	}

	/// Whether the segment is full (segment size == capacity)
	fn full_segment(&self, mmr_size: u64) -> Result<bool, SegmentError> {
		Ok(self.segment_unpruned_size(mmr_size)? == self.segment_capacity()?)
	}
}

/// Segment of a PMMR: unpruned leaves and the necessary data to verify
/// segment membership in the original MMR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Segment<T> {
	identifier: SegmentIdentifier,
	hash_pos: Vec<u64>,
	hashes: Vec<Hash>,
	leaf_pos: Vec<u64>,
	leaf_data: Vec<T>,
	proof: SegmentProof,
}

#[derive(Default)]
struct ConsumedSegmentPositions {
	hash_pos: BTreeSet<u64>,
	leaf_pos: BTreeSet<u64>,
}

fn bitmap_keeps_leaf(pos0: u64, mmr_last_pos: u64, bitmap: &Bitmap) -> Result<bool, SegmentError> {
	let pos1 = pos0
		.checked_add(1)
		.ok_or_else(|| SegmentError::DataOverflow(format!("Segment leaf keep, pos0={}", pos0)))?;
	let idx_1 = pmmr::n_leaves(pos1)?
		.checked_sub(1)
		.ok_or_else(|| SegmentError::DataOverflow(format!("Segment leaf keep, pos1={}", pos1)))?;
	let idx_2 = if pmmr::is_left_sibling(pos0)? {
		idx_1.checked_add(1).ok_or_else(|| {
			SegmentError::DataOverflow(format!("Segment leaf keep, idx_1={}", idx_1))
		})?
	} else {
		idx_1.checked_sub(1).ok_or_else(|| {
			SegmentError::DataOverflow(format!("Segment leaf keep, idx_1={}", idx_1))
		})?
	};

	let idx_1 = u32::try_from(idx_1)
		.map_err(|_| SegmentError::DataOverflow(format!("Segment leaf keep, idx_1={}", idx_1)))?;
	let idx_2 = u32::try_from(idx_2)
		.map_err(|_| SegmentError::DataOverflow(format!("Segment leaf keep, idx_2={}", idx_2)))?;
	Ok(bitmap.contains(idx_1) || bitmap.contains(idx_2) || pos0 == mmr_last_pos)
}

fn check_segment_size_limit(
	segment_size: usize,
	segment_size_limit: usize,
) -> Result<(), SegmentError> {
	if segment_size > segment_size_limit {
		return Err(SegmentError::SegmentSizeAboveLimit);
	}
	Ok(())
}

fn add_segment_payload_size(
	segment_size: usize,
	payload_size: usize,
) -> Result<usize, SegmentError> {
	segment_size.checked_add(payload_size).ok_or_else(|| {
		SegmentError::DataOverflow(format!(
			"Segment::from_pmmr, segment_size={} payload_size={}",
			segment_size, payload_size
		))
	})
}

fn add_leaf_payload_size(segment_size: usize, leaf_size: usize) -> Result<usize, SegmentError> {
	segment_size
		.checked_add(SEGMENT_POSITION_SIZE)
		.and_then(|x| x.checked_add(leaf_size))
		.ok_or_else(|| {
			SegmentError::DataOverflow(format!(
				"Segment::from_pmmr, segment_size={} leaf_size={}",
				segment_size, leaf_size
			))
		})
}

impl<T> Segment<T> {
	/// Creates an empty segment
	fn empty(identifier: SegmentIdentifier) -> Self {
		Segment {
			identifier,
			hash_pos: Vec::new(),
			hashes: Vec::new(),
			leaf_pos: Vec::new(),
			leaf_data: Vec::new(),
			proof: SegmentProof::empty(),
		}
	}

	/// Maximum number of leaves in a segment, given by `2**height`
	fn _segment_capacity(&self) -> Result<u64, SegmentError> {
		self.identifier.segment_capacity()
	}

	/// Offset (in leaf idx) of first leaf in the segment
	pub fn leaf_offset(&self) -> Result<u64, SegmentError> {
		self.identifier.leaf_offset()
	}

	/// Check if it is not pruned segment (segment with leaves only, no hashes)
	pub fn is_no_prune(&self) -> bool {
		self.hashes.is_empty()
	}

	// Number of leaves in this segment. Equal to capacity except for the final segment, which can be smaller
	fn segment_unpruned_size(&self, mmr_size: u64) -> Result<u64, SegmentError> {
		self.identifier.segment_unpruned_size(mmr_size)
	}

	/// Whether the segment is full (segment size == capacity)
	fn full_segment(&self, mmr_size: u64) -> Result<bool, SegmentError> {
		self.identifier.full_segment(mmr_size)
	}

	/// Inclusive range of MMR positions for this segment
	pub fn segment_pos_range(&self, mmr_size: u64) -> Result<(u64, u64), SegmentError> {
		self.identifier.segment_pos_range(mmr_size)
	}

	fn get_hash_with_consumed(
		&self,
		pos0: u64,
		consumed: &mut ConsumedSegmentPositions,
	) -> Result<Hash, SegmentError> {
		let idx = self
			.hash_pos
			.binary_search(&pos0)
			.map_err(|_| SegmentError::MissingHash(pos0))?;
		consumed.hash_pos.insert(pos0);
		Ok(self.hashes[idx])
	}

	fn get_leaf_hash_with_consumed(
		&self,
		context_id: u32,
		pos0: u64,
		consumed: &mut ConsumedSegmentPositions,
	) -> Result<Hash, SegmentError>
	where
		T: PMMRIndexHashable,
	{
		let idx = self
			.leaf_pos
			.binary_search(&pos0)
			.map_err(|_| SegmentError::MissingLeaf(pos0))?;
		consumed.leaf_pos.insert(pos0);
		Ok(self.leaf_data[idx].hash_with_index(context_id, pos0)?)
	}

	/// Get the identifier associated with this segment
	pub fn identifier(&self) -> &SegmentIdentifier {
		&self.identifier
	}

	/// Consume the segment and return its parts
	pub fn parts(
		self,
	) -> (
		SegmentIdentifier,
		Vec<u64>,
		Vec<Hash>,
		Vec<u64>,
		Vec<T>,
		SegmentProof,
	) {
		(
			self.identifier,
			self.hash_pos,
			self.hashes,
			self.leaf_pos,
			self.leaf_data,
			self.proof,
		)
	}

	/// Construct a segment from its parts after validating parallel vector invariants.
	pub fn from_parts(
		identifier: SegmentIdentifier,
		hash_pos: Vec<u64>,
		hashes: Vec<Hash>,
		leaf_pos: Vec<u64>,
		leaf_data: Vec<T>,
		proof: SegmentProof,
	) -> Result<Self, SegmentError> {
		if hash_pos.len() != hashes.len() {
			return Err(SegmentError::GenericError(format!(
				"Segment hash position count {} does not match hash count {}",
				hash_pos.len(),
				hashes.len()
			)));
		}
		if !hash_pos.windows(2).all(|pos| pos[0] < pos[1]) {
			return Err(SegmentError::GenericError(
				"Segment hash positions are not strictly sorted".into(),
			));
		}
		if leaf_pos.len() != leaf_data.len() {
			return Err(SegmentError::GenericError(format!(
				"Segment leaf position count {} does not match leaf data count {}",
				leaf_pos.len(),
				leaf_data.len()
			)));
		}
		if !leaf_pos.windows(2).all(|pos| pos[0] < pos[1]) {
			return Err(SegmentError::GenericError(
				"Segment leaf positions are not strictly sorted".into(),
			));
		}

		Ok(Self {
			identifier,
			hash_pos,
			hashes,
			leaf_pos,
			leaf_data,
			proof,
		})
	}

	/// Iterator of all the leaves in the segment
	pub fn leaf_iter(&self) -> impl Iterator<Item = (u64, &T)> + '_ {
		self.leaf_pos.iter().map(|&p| p).zip(&self.leaf_data)
	}

	/// Iterator of all the hashes in the segment
	pub fn hash_iter(&self) -> impl Iterator<Item = (u64, Hash)> + '_ {
		self.hash_pos
			.iter()
			.zip(&self.hashes)
			.map(|(&p, &h)| (p, h))
	}

	/// Segment proof
	pub fn proof(&self) -> &SegmentProof {
		&self.proof
	}

	/// Segment identifier
	pub fn id(&self) -> &SegmentIdentifier {
		&self.identifier
	}
}

impl<T> Segment<T>
where
	T: Readable + Writeable + Debug + PMMRable + From<T::E> + Sync,
{
	/// Generate a segment from a PMMR, converting stored leaf elements into this segment type.
	pub fn from_pmmr<U, B>(
		segment_id: SegmentIdentifier,
		pmmr: &ReadonlyPMMR<'_, U, B>,
		bitmap: Option<&Bitmap>,
		leaf_size: usize,
		segment_size_limit: usize,
	) -> Result<Self, SegmentError>
	where
		U: PMMRable + Sync,
		T: From<U::E>,
		B: Backend<U>,
	{
		let mut segment = Segment::empty(segment_id);

		let mmr_size = pmmr.unpruned_size();
		if segment.segment_unpruned_size(mmr_size)? == 0 {
			return Err(SegmentError::NonExistent);
		}

		let (segment_first_pos, segment_last_pos) = segment.segment_pos_range(mmr_size)?;
		let mmr_last_pos = mmr_size.checked_sub(1).ok_or_else(|| {
			SegmentError::DataOverflow(format!("Segment::from_pmmr, mmr_size={}", mmr_size))
		})?;

		// Segment validity is defined by payload size, not by an independent
		// height/range cap. Large sparse bitmap segments are valid protocol data,
		// so keep segment_size_limit as the only size criterion here.
		if let Some(bitmap) = bitmap {
			// let's try to build the segment and prune it...
			let mut segm_copy_data: VecBackend<T> = VecBackend::new(pmmr.get_context_id());
			let mut segm_copy = PMMR::new(&mut segm_copy_data);
			segm_copy.update_index_offset(segment_first_pos);

			// constructin the segment in the memory.
			let mut prune_pos = Vec::new();
			let mut construction_size = 0usize;
			for pos0 in segment_first_pos..=segment_last_pos {
				check_segment_size_limit(construction_size, segment_size_limit)?;
				if pmmr::is_leaf(pos0) {
					let keeping = bitmap_keeps_leaf(pos0, mmr_last_pos, bitmap)?;
					match pmmr.get_data_from_file(pos0)? {
						Some(data) => {
							let data = T::from(data);
							construction_size =
								add_leaf_payload_size(construction_size, leaf_size)?;
							segm_copy.push(&data).map_err(|e| {
								SegmentError::GenericError(format!(
									"Unable to build a segment, {}",
									e
								))
							})?;

							if !keeping {
								prune_pos.push(pos0);
							}
							continue;
						}
						None if keeping => return Err(SegmentError::MissingLeaf(pos0)),
						None => {}
					}
				}
				if let Some(hash) = pmmr.get_from_file(pos0)? {
					let pos0_copy = pos0.checked_sub(segment_first_pos).ok_or_else(|| {
						SegmentError::DataOverflow(format!(
							"Segment::from_pmmr, pos0={} segment_first_pos={}",
							pos0, segment_first_pos
						))
					})?;
					if pos0_copy >= segm_copy.size() {
						construction_size =
							add_segment_payload_size(construction_size, SEGMENT_HASH_PAYLOAD_SIZE)?;
						segm_copy
							.push_pruned_subtree(hash, pos0_copy)
							.map_err(|e| {
								SegmentError::GenericError(format!(
									"push_pruned_subtree error, {}",
									e
								))
							})?;
					}
				}
			}

			// Pruning elements that wasn't in the bitmap. It is expected that some data might not be pruned
			// Note: we need to insert all data first and prune after. Also, there is no prpone at the end of PIBD download
			for ps in prune_pos {
				let prune_pos = ps.checked_sub(segment_first_pos).ok_or_else(|| {
					SegmentError::DataOverflow(format!(
						"Segment::from_pmmr, ps={} segment_first_pos={}",
						ps, segment_first_pos
					))
				})?;
				let res = segm_copy.prune(prune_pos).map_err(|e| {
					SegmentError::GenericError(format!("Unable to build a segment, {}", e))
				})?;
				if !res {
					return Err(SegmentError::GenericError(format!(
						"Unable to prune segment leaf {}",
						prune_pos
					)));
				}
			}

			let copy_size = segm_copy.unpruned_size();

			segm_copy_data.compact(true)?;

			let mut segm_copy = PMMR::at(&mut segm_copy_data, copy_size);
			segm_copy.update_index_offset(segment_first_pos);

			// Now we can retry to build the segment from this local copy of PMMR
			// Keep the legacy PIBD segment-size rule exactly as-is: check the accumulated
			// leaf/hash payload at the start of each iteration with `>`, before adding
			// the next item. This boundary behavior is part of consensus compatibility
			// for segment selection, so proof bytes and the item that crosses the limit
			// are intentionally not rejected here.
			let mut segment_size = 0;
			for pos0 in 0..=segm_copy.unpruned_size() {
				check_segment_size_limit(segment_size, segment_size_limit)?;
				if pmmr::is_leaf(pos0) {
					if let Some(data) = segm_copy.get_data(pos0)? {
						segment.leaf_data.push(T::from(data));
						segment
							.leaf_pos
							.push(pos0.checked_add(segment_first_pos).ok_or_else(|| {
								SegmentError::DataOverflow(format!(
									"Segment::from_pmmr, pos0={} segment_first_pos={}",
									pos0, segment_first_pos
								))
							})?);
						segment_size = add_leaf_payload_size(segment_size, leaf_size)?;
						continue;
					}
				}
				if let Some(hash) = segm_copy.get_from_file(pos0)? {
					segment.hashes.push(hash);
					segment
						.hash_pos
						.push(pos0.checked_add(segment_first_pos).ok_or_else(|| {
							SegmentError::DataOverflow(format!(
								"Segment::from_pmmr, pos0={} segment_first_pos={}",
								pos0, segment_first_pos
							))
						})?);
					segment_size =
						add_segment_payload_size(segment_size, SEGMENT_HASH_PAYLOAD_SIZE)?;
				}
			}
		} else {
			// Not prunable scenario
			// Keep the legacy PIBD segment-size rule exactly as-is; see the bitmap
			// branch above for why this is intentionally a pre-add `>` check.
			let mut segment_size = 0;
			for pos0 in segment_first_pos..=segment_last_pos {
				check_segment_size_limit(segment_size, segment_size_limit)?;
				if pmmr::is_leaf(pos0) {
					if let Some(data) = pmmr.get_data_from_file(pos0)? {
						segment.leaf_data.push(T::from(data));
						segment.leaf_pos.push(pos0);
						segment_size = add_leaf_payload_size(segment_size, leaf_size)?;
						continue;
					} else {
						return Err(SegmentError::MissingLeaf(pos0));
					}
				}
			}
		}

		let mut start_pos = None;
		// Fully pruned segment: only include a single hash, the first unpruned parent
		// This legacy fallback is also outside the size-limit accounting above.
		if segment.leaf_data.is_empty() && segment.hashes.is_empty() {
			let family_branch = pmmr::family_branch(segment_last_pos, mmr_size)?;
			for (pos0, _) in family_branch {
				if let Some(hash) = pmmr.get_from_file(pos0)? {
					segment.hashes.push(hash);
					segment.hash_pos.push(pos0);
					start_pos = Some(pos0.checked_add(1).ok_or_else(|| {
						SegmentError::DataOverflow(format!("Segment::from_pmmr, pos0={}", pos0))
					})?);
					break;
				}
			}
		}

		let mut consumed = ConsumedSegmentPositions::default();
		let _ = segment.first_unpruned_parent_with_consumed(
			pmmr.get_context_id(),
			mmr_size,
			bitmap,
			&mut consumed,
		)?;
		segment.validate_consumed_leaves(&consumed)?;
		segment.trim_unconsumed_hashes(&consumed);

		// Segment merkle proof
		segment.proof = SegmentProof::generate(
			pmmr,
			mmr_size,
			segment_first_pos.checked_add(1).ok_or_else(|| {
				SegmentError::DataOverflow(format!(
					"Segment::from_pmmr, segment_first_pos={}",
					segment_first_pos
				))
			})?,
			segment_last_pos.checked_add(1).ok_or_else(|| {
				SegmentError::DataOverflow(format!(
					"Segment::from_pmmr, segment_last_pos={}",
					segment_last_pos
				))
			})?,
			start_pos,
		)?;

		Ok(segment)
	}
}

impl<T> Segment<T>
where
	T: PMMRIndexHashable,
{
	/// Calculate root hash of this segment
	/// Returns `None` if the segment is full and completely pruned
	pub fn root(
		&self,
		context_id: u32,
		mmr_size: u64,
		bitmap: Option<&Bitmap>,
	) -> Result<Option<Hash>, SegmentError> {
		let mut consumed = ConsumedSegmentPositions::default();
		self.root_with_consumed(context_id, mmr_size, bitmap, &mut consumed)
	}

	fn root_with_consumed(
		&self,
		context_id: u32,
		mmr_size: u64,
		bitmap: Option<&Bitmap>,
		consumed: &mut ConsumedSegmentPositions,
	) -> Result<Option<Hash>, SegmentError> {
		if let Some(bitmap) = bitmap {
			return self.prunable_root_with_consumed(context_id, mmr_size, bitmap, consumed);
		}

		let (segment_first_pos, segment_last_pos) = self.segment_pos_range(mmr_size)?;
		// Safe because self.identifier.height is u8
		let mut hashes = Vec::<Option<Hash>>::with_capacity(2 * (self.identifier.height as usize));
		for pos0 in segment_first_pos..=segment_last_pos {
			let height = pmmr::bintree_postorder_height(pos0);
			let hash = if height == 0 {
				Some(self.get_leaf_hash_with_consumed(context_id, pos0, consumed)?)
			} else {
				let (left_child_pos0, right_child_pos0) =
					pmmr::children(pos0)?.ok_or_else(|| {
						SegmentError::GenericError(format!("Segment::root, pos0={}", pos0))
					})?;

				let right_child = hashes.pop().ok_or(SegmentError::GenericError(
					"Internal error, hashes are empty (right)".into(),
				))?;
				let left_child = hashes.pop().ok_or(SegmentError::GenericError(
					"Internal error, hashes are empty (left)".into(),
				))?;

				// Non-prunable MMR: require both children.
				Some(
					(
						left_child.ok_or_else(|| SegmentError::MissingHash(left_child_pos0 + 1))?,
						right_child
							.ok_or_else(|| SegmentError::MissingHash(right_child_pos0 + 1))?,
					)
						.hash_with_index(context_id, pos0)?,
				)
			};

			hashes.push(hash);
		}

		if self.full_segment(mmr_size)? {
			// Full segment: last position of segment is subtree root
			Ok(hashes.pop().ok_or(SegmentError::GenericError(
				"Internal error, hashes are empty (full_segment)".into(),
			))?)
		} else {
			// Not full (only final segment): peaks in segment, bag them together
			let peaks = pmmr::peaks(mmr_size)?;
			let peaks = peaks
				.into_iter()
				.filter(|&pos0| pos0 >= segment_first_pos && pos0 <= segment_last_pos)
				.rev();
			let mut hash = None;
			for pos0 in peaks {
				let lhash = hashes
					.pop()
					.ok_or_else(|| SegmentError::MissingHash(1 + pos0))?;
				let lhash = lhash.ok_or_else(|| SegmentError::MissingHash(1 + pos0))?;

				hash = match hash {
					None => Some(lhash),
					Some(rhash) => Some((lhash, rhash).hash_with_index(context_id, mmr_size)?),
				};
			}
			Ok(Some(hash.ok_or(SegmentError::GenericError(
				"Internal error, not found expected hash for a segment".into(),
			))?))
		}
	}

	fn subtree_leaf_range(pos0: u64, mmr_size: u64) -> Result<std::ops::Range<u32>, SegmentError> {
		let n_leaves = pmmr::n_leaves(mmr_size)?;
		let leftmost = pmmr::bintree_leftmost(pos0)?;
		let rightmost = pmmr::bintree_rightmost(pos0)?;
		let start = pmmr::pmmr_leaf_to_insertion_index(leftmost).ok_or_else(|| {
			SegmentError::GenericError(format!(
				"Segment::subtree_leaf_range, leftmost {} is not a leaf",
				leftmost
			))
		})?;
		let end = pmmr::pmmr_leaf_to_insertion_index(rightmost)
			.ok_or_else(|| {
				SegmentError::GenericError(format!(
					"Segment::subtree_leaf_range, rightmost {} is not a leaf",
					rightmost
				))
			})?
			.checked_add(1)
			.ok_or_else(|| {
				SegmentError::DataOverflow(format!(
					"Segment::subtree_leaf_range, rightmost={}",
					rightmost
				))
			})?;
		let end = min(end, n_leaves);
		let start = u32::try_from(start).map_err(|_| {
			SegmentError::DataOverflow(format!("Segment::subtree_leaf_range, start={}", start))
		})?;
		let end = u32::try_from(end).map_err(|_| {
			SegmentError::DataOverflow(format!("Segment::subtree_leaf_range, end={}", end))
		})?;
		Ok(start..end)
	}

	fn prunable_subtree_root_with_consumed(
		&self,
		context_id: u32,
		mmr_size: u64,
		bitmap: &Bitmap,
		pos0: u64,
		consumed: &mut ConsumedSegmentPositions,
	) -> Result<Option<Hash>, SegmentError> {
		if pmmr::is_leaf(pos0) {
			let mmr_last_pos = mmr_size.checked_sub(1).ok_or_else(|| {
				SegmentError::DataOverflow(format!("Segment::root, mmr_size={}", mmr_size))
			})?;
			if !bitmap_keeps_leaf(pos0, mmr_last_pos, bitmap)? {
				return Ok(None);
			}
			return self
				.get_leaf_hash_with_consumed(context_id, pos0, consumed)
				.map(Some);
		}

		if bitmap.range_cardinality(Self::subtree_leaf_range(pos0, mmr_size)?) == 0 {
			return Ok(None);
		}

		let (left_child_pos0, right_child_pos0) = pmmr::children(pos0)?
			.ok_or_else(|| SegmentError::GenericError(format!("Segment::root, pos0={}", pos0)))?;
		let left_child = self.prunable_subtree_root_with_consumed(
			context_id,
			mmr_size,
			bitmap,
			left_child_pos0,
			consumed,
		)?;
		let right_child = self.prunable_subtree_root_with_consumed(
			context_id,
			mmr_size,
			bitmap,
			right_child_pos0,
			consumed,
		)?;

		match (left_child, right_child) {
			(None, None) => Ok(None),
			(Some(l), Some(r)) => Ok(Some((l, r).hash_with_index(context_id, pos0)?)),
			(None, Some(r)) => {
				let l = self.get_hash_with_consumed(left_child_pos0, consumed)?;
				Ok(Some((l, r).hash_with_index(context_id, pos0)?))
			}
			(Some(l), None) => {
				let r = self.get_hash_with_consumed(right_child_pos0, consumed)?;
				Ok(Some((l, r).hash_with_index(context_id, pos0)?))
			}
		}
	}

	fn prunable_root_with_consumed(
		&self,
		context_id: u32,
		mmr_size: u64,
		bitmap: &Bitmap,
		consumed: &mut ConsumedSegmentPositions,
	) -> Result<Option<Hash>, SegmentError> {
		let (segment_first_pos, segment_last_pos) = self.segment_pos_range(mmr_size)?;
		if self.full_segment(mmr_size)? {
			return self.prunable_subtree_root_with_consumed(
				context_id,
				mmr_size,
				bitmap,
				segment_last_pos,
				consumed,
			);
		}

		let peaks = pmmr::peaks(mmr_size)?
			.into_iter()
			.filter(|&pos0| pos0 >= segment_first_pos && pos0 <= segment_last_pos)
			.rev();
		let mut hash = None;
		for pos0 in peaks {
			let mut lhash = self.prunable_subtree_root_with_consumed(
				context_id, mmr_size, bitmap, pos0, consumed,
			)?;
			if lhash.is_none() {
				lhash = Some(self.get_hash_with_consumed(pos0, consumed)?);
			}
			let lhash = lhash.ok_or_else(|| SegmentError::MissingHash(1 + pos0))?;

			hash = match hash {
				None => Some(lhash),
				Some(rhash) => Some((lhash, rhash).hash_with_index(context_id, mmr_size)?),
			};
		}
		Ok(Some(hash.ok_or(SegmentError::GenericError(
			"Internal error, not found expected hash for a segment".into(),
		))?))
	}

	/// Get the first 1-based (sucks) unpruned parent hash of this segment
	pub fn first_unpruned_parent(
		&self,
		context_id: u32,
		mmr_size: u64,
		bitmap: Option<&Bitmap>,
	) -> Result<(Hash, u64), SegmentError> {
		let mut consumed = ConsumedSegmentPositions::default();
		self.first_unpruned_parent_with_consumed(context_id, mmr_size, bitmap, &mut consumed)
	}

	fn first_unpruned_parent_with_consumed(
		&self,
		context_id: u32,
		mmr_size: u64,
		bitmap: Option<&Bitmap>,
		consumed: &mut ConsumedSegmentPositions,
	) -> Result<(Hash, u64), SegmentError> {
		let root = self.root_with_consumed(context_id, mmr_size, bitmap, consumed)?;
		let (_, last) = self.segment_pos_range(mmr_size)?;
		if let Some(root) = root {
			return Ok((
				root,
				last.checked_add(1).ok_or_else(|| {
					SegmentError::DataOverflow(format!(
						"Segment::first_unpruned_parent, last={}",
						last
					))
				})?,
			));
		}
		let bitmap = bitmap.ok_or(SegmentError::GenericError(
			"Internal error, first_unpruned_parent param bitmap is empty".into(),
		))?;
		let n_leaves = pmmr::n_leaves(mmr_size)?;

		let mut cardinality = 0;
		let mut pos0 = last;
		let mut hash = Err(SegmentError::MissingHash(last));
		let mut family_branch = pmmr::family_branch(last, mmr_size)?.into_iter();
		while cardinality == 0 {
			hash = self.get_hash_with_consumed(pos0, consumed).and_then(|h| {
				Ok((
					h,
					pos0.checked_add(1).ok_or_else(|| {
						SegmentError::DataOverflow(format!(
							"Segment::first_unpruned_parent, pos0={}",
							pos0
						))
					})?,
				))
			});
			if hash.is_ok() {
				// Return early in case a lower level hash is already present
				// This can occur if both child trees are pruned but compaction hasn't run yet
				return hash;
			}

			if let Some((p0, _)) = family_branch.next() {
				pos0 = p0;
				let leftmost = pmmr::bintree_leftmost(p0)?;
				let leftmost_pos1 = leftmost.checked_add(1).ok_or_else(|| {
					SegmentError::DataOverflow(format!(
						"Segment::first_unpruned_parent, leftmost={}",
						leftmost
					))
				})?;
				let range_start =
					pmmr::n_leaves(leftmost_pos1)?
						.checked_sub(1)
						.ok_or_else(|| {
							SegmentError::DataOverflow(format!(
								"Segment::first_unpruned_parent, leftmost_pos1={}",
								leftmost_pos1
							))
						})?;
				let rightmost = pmmr::bintree_rightmost(p0)?;
				let rightmost_pos1 = rightmost.checked_add(1).ok_or_else(|| {
					SegmentError::DataOverflow(format!(
						"Segment::first_unpruned_parent, rightmost={}",
						rightmost
					))
				})?;
				let range_end = min(pmmr::n_leaves(rightmost_pos1)?, n_leaves);
				let range_start = u32::try_from(range_start).map_err(|_| {
					SegmentError::DataOverflow(format!(
						"Segment::first_unpruned_parent, range_start={}",
						range_start
					))
				})?;
				let range_end = u32::try_from(range_end).map_err(|_| {
					SegmentError::DataOverflow(format!(
						"Segment::first_unpruned_parent, range_end={}",
						range_end
					))
				})?;
				let range = range_start..range_end;
				cardinality = bitmap.range_cardinality(range);
			} else {
				break;
			}
		}
		hash
	}

	fn validate_consumed_leaves(
		&self,
		consumed: &ConsumedSegmentPositions,
	) -> Result<(), SegmentError> {
		for pos0 in &self.leaf_pos {
			if !consumed.leaf_pos.contains(pos0) {
				return Err(SegmentError::GenericError(format!(
					"Segment contains unconsumed leaf position {}",
					pos0
				)));
			}
		}
		Ok(())
	}

	fn trim_unconsumed_hashes(&mut self, consumed: &ConsumedSegmentPositions) {
		let mut old_hash_pos = std::mem::take(&mut self.hash_pos);
		let mut old_hashes = std::mem::take(&mut self.hashes);
		for (pos0, hash) in old_hash_pos.drain(..).zip(old_hashes.drain(..)) {
			if consumed.hash_pos.contains(&pos0) {
				self.hash_pos.push(pos0);
				self.hashes.push(hash);
			}
		}
	}

	/// Validate the segment by calculating its root and validating the merkle proof.
	///
	/// Validation returns a sanitized segment because PIBD peers may send redundant
	/// hash entries. After proving the segment root, keep only the hashes consumed by
	/// that proof so applying the segment cannot write unproved hash data locally.
	pub fn validate(
		mut self,
		context_id: u32,
		mmr_size: u64,
		bitmap: Option<&Bitmap>,
		mmr_root: &Hash,
	) -> Result<Self, SegmentError> {
		let (first, last) = self.segment_pos_range(mmr_size)?;
		let mut consumed = ConsumedSegmentPositions::default();
		let (segment_root, segment_unpruned_pos) =
			self.first_unpruned_parent_with_consumed(context_id, mmr_size, bitmap, &mut consumed)?;
		self.validate_consumed_leaves(&consumed)?;
		self.proof.validate(
			context_id,
			mmr_size,
			mmr_root,
			first,
			last,
			segment_root,
			segment_unpruned_pos,
		)?;
		self.trim_unconsumed_hashes(&consumed);
		Ok(self)
	}
}

fn checked_read_count(context: &str, count: u64) -> Result<usize, Error> {
	if count > READ_VEC_SIZE_LIMIT {
		return Err(Error::TooLargeReadErr(format!(
			"{} count {} exceeds limit {}",
			context, count, READ_VEC_SIZE_LIMIT
		)));
	}
	usize::try_from(count).map_err(|_| Error::DataOverflow(format!("{} count {}", context, count)))
}

impl<T: Readable> Readable for Segment<T> {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
		let identifier = Readable::read(reader)?;

		let n_hashes_u64 = reader.read_u64()?;
		let n_hashes = checked_read_count("Segment::read n_hashes", n_hashes_u64)?;
		let mut hash_pos = Vec::with_capacity(n_hashes);
		let mut last_pos = 0;
		for _ in 0..n_hashes {
			let pos = reader.read_u64()?;
			if pos <= last_pos {
				return Err(Error::SortError);
			}
			last_pos = pos;
			hash_pos.push(
				pos.checked_sub(1).ok_or_else(|| {
					Error::DataOverflow(format!("Segment::read, hash_pos={}", pos))
				})?,
			);
		}

		let mut hashes = Vec::<Hash>::with_capacity(n_hashes);
		for _ in 0..n_hashes {
			hashes.push(Readable::read(reader)?);
		}

		let n_leaves_u64 = reader.read_u64()?;
		let n_leaves = checked_read_count("Segment::read n_leaves", n_leaves_u64)?;
		let mut leaf_pos = Vec::with_capacity(n_leaves);
		last_pos = 0;
		for _ in 0..n_leaves {
			let pos = reader.read_u64()?;
			if pos <= last_pos {
				return Err(Error::SortError);
			}
			last_pos = pos;
			leaf_pos.push(
				pos.checked_sub(1).ok_or_else(|| {
					Error::DataOverflow(format!("Segment::read, leaf_pos={}", pos))
				})?,
			);
		}

		let mut leaf_data = Vec::<T>::with_capacity(n_leaves);
		for _ in 0..n_leaves {
			leaf_data.push(Readable::read(reader)?);
		}

		let proof = Readable::read(reader)?;

		Ok(Self {
			identifier,
			hash_pos,
			hashes,
			leaf_pos,
			leaf_data,
			proof,
		})
	}
}

impl<T: Writeable> Writeable for Segment<T> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		Writeable::write(&self.identifier, writer)?;
		writer.write_u64(self.hashes.len() as u64)?;
		for &pos in &self.hash_pos {
			writer.write_u64(pos.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!("Segment::write, hash_pos={}", pos))
			})?)?;
		}
		for hash in &self.hashes {
			Writeable::write(hash, writer)?;
		}
		writer.write_u64(self.leaf_data.len() as u64)?;
		for &pos in &self.leaf_pos {
			writer.write_u64(pos.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!("Segment::write, leaf_pos={}", pos))
			})?)?;
		}
		for data in &self.leaf_data {
			Writeable::write(data, writer)?;
		}
		Writeable::write(&self.proof, writer)?;
		Ok(())
	}
}

/// Merkle proof of a segment
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SegmentProof {
	hashes: Vec<Hash>,
}

impl SegmentProof {
	fn empty() -> Self {
		Self { hashes: Vec::new() }
	}

	fn generate<U, B>(
		pmmr: &ReadonlyPMMR<'_, U, B>,
		last_pos: u64,
		segment_first_pos: u64,
		segment_last_pos: u64,
		start_pos: Option<u64>,
	) -> Result<Self, SegmentError>
	where
		U: PMMRable,
		B: Backend<U>,
	{
		let segment_last_pos0 = segment_last_pos.checked_sub(1).ok_or_else(|| {
			SegmentError::DataOverflow(format!(
				"SegmentProof::generate, segment_last_pos={}",
				segment_last_pos
			))
		})?;
		let family_branch = pmmr::family_branch(segment_last_pos0, last_pos)?;

		// 1. siblings along the path from the subtree root to the peak
		let hashes: Result<Vec<_>, _> = family_branch
			.iter()
			.filter(|&&(p0, _)| start_pos.map(|s| p0 >= s).unwrap_or(true))
			.map(|&(_, s0)| {
				pmmr.get_from_file(s0)?
					.ok_or_else(|| SegmentError::MissingHash(s0))
			})
			.collect();
		let mut proof = Self { hashes: hashes? };

		// 2. bagged peaks to the right
		let peak_pos = family_branch
			.last()
			.map(|&(p0, _)| p0)
			.unwrap_or(segment_last_pos0);
		if let Some(h) = pmmr.bag_the_rhs(peak_pos)? {
			proof.hashes.push(h);
		}

		// 3. peaks to the left
		let mut peaks = Vec::new();
		for pos0 in pmmr::peaks(last_pos)? {
			let pos1 = pos0.checked_add(1).ok_or_else(|| {
				SegmentError::DataOverflow(format!("SegmentProof::generate, pos0={}", pos0))
			})?;
			if pos1 < segment_first_pos {
				peaks.push(pos0);
			}
		}
		for pos0 in peaks.into_iter().rev() {
			proof.hashes.push(
				pmmr.get_peak_from_file(pos0)?
					.ok_or_else(|| SegmentError::MissingHash(pos0))?,
			);
		}

		Ok(proof)
	}

	/// Size of the proof in hashes.
	pub fn size(&self) -> usize {
		self.hashes.len()
	}

	/// Reconstruct PMMR root using this proof
	pub fn reconstruct_root(
		&self,
		context_id: u32,
		last_pos: u64,
		segment_first_pos0: u64,
		segment_last_pos0: u64,
		segment_root: Hash,
		segment_unpruned_pos: u64,
	) -> Result<Hash, SegmentError> {
		SegmentIdentifier::validate_complete_mmr_size(last_pos)?;

		let mut iter = self.hashes.iter();
		let family_branch = pmmr::family_branch(segment_last_pos0, last_pos)?;

		// 1. siblings along the path from the subtree root to the peak
		let mut root = segment_root;
		for &(p0, s0) in family_branch
			.iter()
			.filter(|&&(p0, _)| p0 >= segment_unpruned_pos)
		{
			let sibling_hash = iter
				.next()
				.ok_or_else(|| SegmentError::MissingHash(1 + s0))?;
			root = if pmmr::is_left_sibling(s0)? {
				(sibling_hash, root).hash_with_index(context_id, p0)?
			} else {
				(root, sibling_hash).hash_with_index(context_id, p0)?
			};
		}

		// 2. bagged peaks to the right
		let peak_pos0 = family_branch
			.last()
			.map(|&(p0, _)| p0)
			.unwrap_or(segment_last_pos0);

		let rhs = pmmr::peaks(last_pos)?
			.into_iter()
			.filter(|&x| x > peak_pos0)
			.next();

		if let Some(pos0) = rhs {
			root = (
				root,
				iter.next()
					.ok_or_else(|| SegmentError::MissingHash(1 + pos0))?,
			)
				.hash_with_index(context_id, last_pos)?
		}

		// 3. peaks to the left
		let peaks = pmmr::peaks(last_pos)?
			.into_iter()
			.filter(|&x| x < segment_first_pos0)
			.rev();
		for pos0 in peaks {
			root = (
				iter.next()
					.ok_or_else(|| SegmentError::MissingHash(1 + pos0))?,
				root,
			)
				.hash_with_index(context_id, last_pos)?;
		}

		if iter.next().is_some() {
			return Err(SegmentError::GenericError(
				"Segment proof contains trailing hash data".into(),
			));
		}

		Ok(root)
	}

	/// Check validity of the proof by equating the reconstructed root with the actual root
	pub fn validate(
		&self,
		context_id: u32,
		last_pos: u64,
		mmr_root: &Hash,
		segment_first_pos: u64,
		segment_last_pos: u64,
		segment_root: Hash,
		segment_unpruned_pos: u64,
	) -> Result<(), SegmentError> {
		let root = self.reconstruct_root(
			context_id,
			last_pos,
			segment_first_pos,
			segment_last_pos,
			segment_root,
			segment_unpruned_pos,
		)?;
		if root == *mmr_root {
			Ok(())
		} else {
			Err(SegmentError::Mismatch)
		}
	}
}

impl Readable for SegmentProof {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
		let n_hashes_u64 = reader.read_u64()?;
		if n_hashes_u64 > MAX_SEGMENT_PROOF_HASHES {
			return Err(Error::TooLargeReadErr(format!(
				"SegmentProof::read n_hashes count {} exceeds protocol limit {}",
				n_hashes_u64, MAX_SEGMENT_PROOF_HASHES
			)));
		}
		let n_hashes = checked_read_count("SegmentProof::read n_hashes", n_hashes_u64)?;
		let mut hashes = Vec::with_capacity(n_hashes);
		for _ in 0..n_hashes {
			let hash: Hash = Readable::read(reader)?;
			hashes.push(hash);
		}
		Ok(Self { hashes })
	}
}

impl Writeable for SegmentProof {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u64(self.hashes.len() as u64)?;
		for hash in &self.hashes {
			Writeable::write(hash, writer)?;
		}
		Ok(())
	}
}
