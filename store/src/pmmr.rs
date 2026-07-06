// Copyright 2019 The Grin Developers
// Copyright 2024 The MWC Developers
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

//! Implementation of the persistent Backend for the prunable MMR tree.

use std::fs;
use std::{io, time};

use crate::leaf_set::LeafSet;
use crate::prune_list::PruneList;
use crate::types::{AppendOnlyFile, DataFile, SizeEntry, SizeInfo, VariableSizeMetadataValidation};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::pmmr::{self, family, Backend, Error};
use mwc_core::core::BlockHeader;
use mwc_core::ser::{PMMRable, ProtocolVersion};
use mwc_crates::croaring::Bitmap;
use mwc_crates::log::{debug, info, warn};
use mwc_util::ToHex;
use std::convert::TryFrom;
use std::path::{Path, PathBuf};

const PMMR_HASH_FILE: &str = "pmmr_hash.bin";
const PMMR_DATA_FILE: &str = "pmmr_data.bin";
const PMMR_LEAF_FILE: &str = "pmmr_leaf.bin";
const PMMR_PRUN_FILE: &str = "pmmr_prun.bin";
const PMMR_SIZE_FILE: &str = "pmmr_size.bin";
const REWIND_FILE_CLEANUP_DURATION_SECONDS: u64 = 60 * 60 * 24; // 24 hours as seconds

/// The list of PMMR_Files for internal purposes
pub const PMMR_FILES: [&str; 4] = [
	PMMR_HASH_FILE,
	PMMR_DATA_FILE,
	PMMR_LEAF_FILE,
	PMMR_PRUN_FILE,
];

struct PMMRFileSet {
	hash: bool,
	data: bool,
	leaf: bool,
	prun: bool,
	size: bool,
}

impl PMMRFileSet {
	fn any(&self) -> bool {
		self.hash || self.data || self.leaf || self.prun || self.size
	}
}

/// PMMR persistent backend implementation. Relies on multiple facilities to
/// handle writing, reading and pruning.
///
/// * A main storage file appends Hash instances as they come.
/// This AppendOnlyFile is also backed by a mmap for reads.
/// * An in-memory backend buffers the latest batch of writes to ensure the
/// PMMR can always read recent values even if they haven't been flushed to
/// disk yet.
/// * A leaf_set tracks unpruned (unremoved) leaf positions in the MMR..
/// * A prune_list tracks the positions of pruned (and compacted) roots in the
/// MMR.
pub struct PMMRBackend<T: PMMRable> {
	data_dir: PathBuf,
	prunable: bool,
	context_id: u32,
	hash_file: DataFile<Hash>,
	data_file: DataFile<T::E>,
	leaf_set: LeafSet,
	prune_list: PruneList,
}

impl<T: PMMRable> Backend<T> for PMMRBackend<T> {
	fn get_context_id(&self) -> u32 {
		self.context_id
	}

	/// Append the provided data and hashes to the backend storage.
	/// Add the new leaf pos to our leaf_set if this is a prunable MMR.
	fn append(&mut self, data: &T, hashes: &[Hash]) -> Result<(), Error> {
		// Validate sizes before mutating so later append failures can roll back
		// to the exact buffered state we started from.
		let data = data.as_elmt().map_err(|e| {
			Error::SerializationError(format!("Failed to convert data to element, {}", e))
		})?;
		let data_size_before = self.data_file.size_unsync()?;
		let data_size = data_size_before
			.checked_add(1)
			.ok_or_else(|| Error::DataOverflow("PMMRBackend::append data size".into()))?;
		let hash_size_before = self.hash_file.size_unsync()?;
		let expected_hash_size = hash_size_before
			.checked_add(hashes.len() as u64)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"PMMRBackend::append hash size, hash_size={}, hashes_len={}",
					hash_size_before,
					hashes.len()
				))
			})?;

		let leaf_pos =
			if self.prunable {
				let total_leaf_shift = self.prune_list.get_total_leaf_shift()?;
				let nleaf0 = data_size
					.checked_add(total_leaf_shift)
					.and_then(|x| x.checked_sub(1))
					.ok_or_else(|| {
						Error::DataOverflow(format!(
							"PMMRBackend::append, size={} total_leaf_shift={}",
							data_size, total_leaf_shift
						))
					})?;

				let pos = pmmr::insertion_to_pmmr_index(nleaf0)?;
				// Checking u32 fit because of roaring bitmap, it works with u32
				u32::try_from(pos.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!("PMMRBackend::append, pos={}", pos))
				})?)
				.map_err(|_| Error::DataOverflow(format!("PMMRBackend::append, pos={}", pos)))?;
				Some(pos)
			} else {
				None
			};

		// So far counters are valid, so we can start buffering the append.
		let size = match self.data_file.append(&data) {
			Ok(size) => size,
			Err(e) => {
				let rollback_msg = self.rollback_append(data_size_before, hash_size_before);
				return Err(Error::SerializationError(format!(
					"Failed to append data to file. {}{}",
					e, rollback_msg
				)));
			}
		};
		if size != data_size {
			let rollback_msg = self.rollback_append(data_size_before, hash_size_before);
			return Err(Error::InvalidState(format!(
				"PMMRBackend::append data size mismatch, expected {}, got {}.{}",
				data_size, size, rollback_msg
			)));
		}

		let hash_size = match self.hash_file.extend_from_slice(hashes) {
			Ok(hash_size) => hash_size,
			Err(e) => {
				let rollback_msg = self.rollback_append(data_size_before, hash_size_before);
				return Err(Error::SerializationError(format!(
					"Failed to append hash to file. {}{}",
					e, rollback_msg
				)));
			}
		};
		if hash_size != expected_hash_size {
			let rollback_msg = self.rollback_append(data_size_before, hash_size_before);
			return Err(Error::InvalidState(format!(
				"PMMRBackend::append hash size mismatch, expected {}, got {}.{}",
				expected_hash_size, hash_size, rollback_msg
			)));
		}

		if let Some(pos) = leaf_pos {
			if let Err(e) = self.leaf_set.add(pos) {
				let rollback_msg = self.rollback_append(data_size_before, hash_size_before);
				if rollback_msg.is_empty() {
					return Err(e);
				}
				return Err(Error::InvalidState(format!(
					"PMMRBackend::append failed to update leaf set. {}{}",
					e, rollback_msg
				)));
			}
		}

		Ok(())
	}

	// Supports appending a pruned subtree root, plus any parent hashes needed to
	// connect it to immediately preceding peaks, to an existing hash file.
	fn append_pruned_subtree(&mut self, hash: Hash, pos0: u64) -> Result<(), Error> {
		self.append_pruned_subtree_hashes(hash, pos0, &[])
	}

	fn append_pruned_subtree_hashes(
		&mut self,
		hash: Hash,
		pos0: u64,
		hashes: &[Hash],
	) -> Result<(), Error> {
		if !self.prunable {
			return Err(Error::InvalidState(
				"Not prunable, cannot append pruned subtree.".into(),
			));
		}

		let range = pmmr::bintree_range(pos0)?;
		let current_size = self
			.hash_file
			.size_unsync()?
			.checked_add(self.prune_list.get_total_shift()?)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"PMMRBackend::append_pruned_subtree_hashes, pos0={}",
					pos0
				))
			})?;
		if range.start != current_size {
			return Err(Error::InvalidState(format!(
				"pruned subtree at position {} covers range {:?}, not contiguous with PMMR size {}",
				pos0, range, current_size
			)));
		}

		let hash_count = hashes.len().checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"PMMRBackend::append_pruned_subtree_hashes hashes len={}",
				hashes.len()
			))
		})?;
		let hash_size_before = self.hash_file.size_unsync()?;
		let expected_hash_size =
			hash_size_before
				.checked_add(hash_count as u64)
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"PMMRBackend::append_pruned_subtree_hashes hash_count={}",
						hash_count
					))
				})?;

		let mut all_hashes = Vec::with_capacity(hash_count);
		all_hashes.push(hash);
		all_hashes.extend_from_slice(hashes);

		let hash_size = match self.hash_file.extend_from_slice(&all_hashes) {
			Ok(hash_size) => hash_size,
			Err(e) => {
				let rollback_msg = self
					.hash_file
					.truncate_unsynced(hash_size_before)
					.err()
					.map(|err| format!(" Rollback failed. {}", err))
					.unwrap_or_default();
				return Err(Error::SerializationError(format!(
					"Failed to append subtree hash to file. {}{}",
					e, rollback_msg
				)));
			}
		};
		if hash_size != expected_hash_size {
			let rollback_msg = self
				.hash_file
				.truncate_unsynced(hash_size_before)
				.err()
				.map(|err| format!(" Rollback failed. {}", err))
				.unwrap_or_default();
			return Err(Error::InvalidState(format!(
				"PMMRBackend::append_pruned_subtree_hashes hash size mismatch, expected {}, got {}.{}",
				expected_hash_size, hash_size, rollback_msg
			)));
		}

		if let Err(e) = self.prune_list.append_exact(pos0) {
			let rollback_msg = self
				.hash_file
				.truncate_unsynced(hash_size_before)
				.err()
				.map(|err| format!(" Rollback failed. {}", err))
				.unwrap_or_default();
			if rollback_msg.is_empty() {
				return Err(e);
			}
			return Err(Error::InvalidState(format!(
				"PMMRBackend::append_pruned_subtree_hashes failed to update prune list. {}{}",
				e, rollback_msg
			)));
		}

		Ok(())
	}

	fn append_hash(&mut self, hash: Hash) -> Result<(), Error> {
		let hash_size_before = self.hash_file.size_unsync()?;
		let expected_hash_size = hash_size_before.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"PMMRBackend::append_hash hash size, hash_size={}",
				hash_size_before
			))
		})?;

		let hash_size = match self.hash_file.append(&hash) {
			Ok(hash_size) => hash_size,
			Err(e) => {
				let rollback_msg = self
					.hash_file
					.truncate_unsynced(hash_size_before)
					.err()
					.map(|err| format!(" Rollback failed. {}", err))
					.unwrap_or_default();
				return Err(Error::SerializationError(format!(
					"Failed to append hash to file. {}{}",
					e, rollback_msg
				)));
			}
		};
		if hash_size != expected_hash_size {
			let rollback_msg = self
				.hash_file
				.truncate_unsynced(hash_size_before)
				.err()
				.map(|err| format!(" Rollback failed. {}", err))
				.unwrap_or_default();
			return Err(Error::InvalidState(format!(
				"PMMRBackend::append_hash hash size mismatch, expected {}, got {}.{}",
				expected_hash_size, hash_size, rollback_msg
			)));
		}
		Ok(())
	}

	fn get_from_file(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		if !self.prunable {
			let position = Self::pos0_to_pos1(pos0, "PMMRBackend::get_from_file")?;
			if position > self.hash_file.size_unsync()? {
				return Ok(None);
			}
			let hash = self.hash_file.read(position)?.ok_or_else(|| {
				Error::DataCorruption(format!(
					"Missing PMMR hash at position {} and hash file position {}.",
					pos0, position
				))
			})?;
			return Ok(Some(hash));
		}

		let logical_size = self
			.hash_file
			.size_unsync()?
			.checked_add(self.prune_list.get_total_shift()?)
			.ok_or_else(|| {
				Error::DataOverflow(format!("PMMRBackend::get_from_file, pos0={}", pos0))
			})?;
		if pos0 >= logical_size {
			return Ok(None);
		}

		if self.is_compacted_impl(pos0)? {
			return Ok(None);
		}
		let shift = self.prune_list.get_shift(pos0)?;
		// 1 + pos0 - shift
		let position = 1u64
			.checked_add(pos0)
			.and_then(|x| x.checked_sub(shift))
			.ok_or(Error::DataOverflow(format!(
				"PMMRBackend::get_from_file, pos0={} shift={}",
				pos0, shift
			)))?;
		let hash = self.hash_file.read(position)?.ok_or_else(|| {
			Error::DataCorruption(format!(
				"Missing PMMR hash at position {} and hash file position {}.",
				pos0, position
			))
		})?;
		Ok(Some(hash))
	}

	fn is_compacted(&self, pos0: u64) -> Result<bool, Error> {
		self.is_compacted_impl(pos0)
	}

	fn get_peak_from_file(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		if !self.prunable {
			return Ok(self
				.hash_file
				.read(Self::pos0_to_pos1(pos0, "PMMRBackend::get_peak_from_file")?)?);
		}

		let shift = self.prune_list.get_shift(pos0)?;
		// 1 + pos0 - shift
		let position = 1u64
			.checked_add(pos0)
			.and_then(|x| x.checked_sub(shift))
			.ok_or(Error::DataOverflow(format!(
				"PMMRBackend::get_peak_from_file, pos0={} shift={}",
				pos0, shift
			)))?;
		Ok(self.hash_file.read(position)?)
	}

	fn get_data_from_file(&self, pos0: u64) -> Result<Option<T::E>, Error> {
		if !pmmr::is_leaf(pos0) {
			return Ok(None);
		}
		if !self.prunable {
			let pos0_plus1 = Self::pos0_to_pos1(pos0, "PMMRBackend::get_data_from_file")?;
			let data_pos = pmmr::n_leaves(pos0_plus1)?;
			let data = self.data_file.read(data_pos)?.ok_or_else(|| {
				Error::DataCorruption(format!(
					"Missing PMMR data for leaf at pos {} and data file position {}.",
					pos0, data_pos
				))
			})?;
			return Ok(Some(data));
		}

		if self.is_compacted(pos0)? {
			return Ok(None);
		}
		let pos0_plus1 = pos0.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("PMMRBackend::get_data_from_file, pos0={}", pos0))
		})?;
		let flatfile_pos = pmmr::n_leaves(pos0_plus1)?;
		let shift = self.prune_list.get_leaf_shift(pos0_plus1)?;
		let data_pos = flatfile_pos.checked_sub(shift).ok_or_else(|| {
			Error::DataOverflow(format!(
				"PMMRBackend::get_data_from_file, flatfile_pos={} shift={}",
				flatfile_pos, shift
			))
		})?;
		let data = self.data_file.read(data_pos)?.ok_or_else(|| {
			Error::DataCorruption(format!(
				"Missing PMMR data for leaf at pos {} and data file position {}.",
				pos0, data_pos
			))
		})?;
		Ok(Some(data))
	}

	/// Get the hash at pos.
	/// Return None if pos is a leaf and it has been removed (or pruned or
	/// compacted).
	fn get_hash(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		if self.prunable && pmmr::is_leaf(pos0) && !self.leaf_set.includes(pos0)? {
			return Ok(None);
		}
		Ok(self.get_from_file(pos0)?)
	}

	/// Get the data at pos.
	/// Return None if it has been removed or if pos is not a leaf node.
	fn get_data(&self, pos0: u64) -> Result<Option<T::E>, Error> {
		if !pmmr::is_leaf(pos0) {
			return Ok(None);
		}
		if self.prunable && !self.leaf_set.includes(pos0)? {
			return Ok(None);
		}
		self.get_data_from_file(pos0)
	}

	// Remove leaf from leaf set
	// DON'T USE IS, use prune instead
	/*fn remove_from_leaf_set(&mut self, pos0: u64) {
		self.leaf_set.remove(pos0);
	}*/

	/// Returns an iterator over all the leaf positions.
	/// for a prunable PMMR this is an iterator over the leaf_set bitmap.
	/// For a non-prunable PMMR this is *all* leaves.
	fn leaf_pos_iter(&self) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error> {
		if self.prunable {
			Ok(Box::new(self.leaf_set.iter().map(|x| {
				let pos0 = x
					.checked_sub(1)
					.ok_or_else(|| Error::DataOverflow("PMMRBackend::leaf_pos_iter".into()))?;
				if !pmmr::is_leaf(pos0) {
					return Err(Error::DataCorruption(format!(
						"Invalid leaf_set entry {}, PMMR position {} is not a leaf.",
						x, pos0
					)));
				}
				Ok(pos0)
			})))
		} else {
			let size = self.unpruned_size()?;
			Ok(Box::new(
				(0..size).filter(|pos0| pmmr::is_leaf(*pos0)).map(Ok),
			))
		}
	}

	fn leaf_pos_iter_from(
		&self,
		from_pos0: u64,
	) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error> {
		if self.prunable {
			Ok(Box::new(self.leaf_set.iter_from_pos0(from_pos0)?.map(
				|x| {
					let pos0 = x.checked_sub(1).ok_or_else(|| {
						Error::DataOverflow("PMMRBackend::leaf_pos_iter_from".into())
					})?;
					if !pmmr::is_leaf(pos0) {
						return Err(Error::DataCorruption(format!(
							"Invalid leaf_set entry {}, PMMR position {} is not a leaf.",
							x, pos0
						)));
					}
					Ok(pos0)
				},
			)))
		} else {
			let size = self.unpruned_size()?;
			Ok(Box::new(
				(from_pos0..size)
					.filter(|pos0| pmmr::is_leaf(*pos0))
					.map(Ok),
			))
		}
	}

	fn n_unpruned_leaves(&self) -> Result<u64, Error> {
		if self.prunable {
			Ok(self.leaf_set.len())
		} else {
			pmmr::n_leaves(self.unpruned_size()?)
		}
	}

	fn n_unpruned_leaves_to_index(&self, to_index: u64) -> Result<u64, Error> {
		if self.prunable {
			let to_pos1 = pmmr::insertion_to_pmmr_index(to_index)?
				.checked_add(1)
				.ok_or_else(|| {
					Error::DataOverflow(format!(
						"PMMRBackend::n_unpruned_leaves_to_index, to_index={}",
						to_index
					))
				})?;
			self.leaf_set.n_unpruned_leaves_to_index(to_pos1)
		} else {
			pmmr::n_leaves(pmmr::insertion_to_pmmr_index(to_index)?)
		}
	}

	/// Returns an iterator over all the leaf insertion indices (0-indexed).
	/// If our PMMR leaf positions are [0,1,3,4,7] then our insertion indices are [0,1,2,3,4]
	fn leaf_idx_iter(
		&self,
		from_idx: u64,
	) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error> {
		let from_pos = pmmr::insertion_to_pmmr_index(from_idx)?;
		Ok(Box::new(
			self.leaf_pos_iter()?
				.filter(move |pos| match pos {
					Ok(pos) => *pos >= from_pos,
					Err(_) => true,
				})
				.map(|pos| {
					let pos0 = pos?;
					let pos1 = pos0.checked_add(1).ok_or_else(|| {
						Error::DataOverflow(format!("PMMRBackend::leaf_idx_iter, pos0={}", pos0))
					})?;
					pmmr::n_leaves(pos1)?.checked_sub(1).ok_or_else(|| {
						Error::DataOverflow(format!("PMMRBackend::leaf_idx_iter, pos1={}", pos1))
					})
				}),
		))
	}

	/// Rewind the PMMR backend to the given position.
	fn rewind(&mut self, position: u64, rewind_rm_pos: &Bitmap) -> Result<(), Error> {
		let (hash_pos, data_pos) = if self.prunable {
			// Rewind the hash file accounting for pruned/compacted pos.
			let shift = if position == 0 {
				0
			} else {
				self.prune_list.get_shift(position - 1)?
			};
			let hash_pos = position.checked_sub(shift).ok_or_else(|| {
				Error::DataOverflow(format!(
					"PMMRBackend::rewind position={} shift={}",
					position, shift
				))
			})?;

			// Rewind the data file accounting for pruned/compacted pos.
			let flatfile_pos = pmmr::n_leaves(position)?;
			let leaf_shift = if position == 0 {
				0
			} else {
				self.prune_list.get_leaf_shift(position)?
			};
			let data_pos = flatfile_pos.checked_sub(leaf_shift).ok_or_else(|| {
				Error::DataOverflow(format!(
					"PMMRBackend::rewind flatfile_pos={} leaf_shift={}",
					flatfile_pos, leaf_shift
				))
			})?;
			(hash_pos, data_pos)
		} else {
			(position, pmmr::n_leaves(position)?)
		};

		let hash_size = self.hash_file.size_unsync()?;
		if hash_pos > hash_size {
			return Err(Error::InvalidState(format!(
				"cannot rewind hash file forward from {} to {}",
				hash_size, hash_pos
			)));
		}
		let data_size = self.data_file.size_unsync()?;
		if data_pos > data_size {
			return Err(Error::InvalidState(format!(
				"cannot rewind data file forward from {} to {}",
				data_size, data_pos
			)));
		}

		// Only mutate backend state after all fallible position calculations succeed.
		if self.prunable {
			self.leaf_set.rewind(position, rewind_rm_pos)?;
		}
		self.hash_file.rewind(hash_pos)?;
		self.data_file.rewind(data_pos)?;

		Ok(())
	}

	fn reset_prune_list(&mut self) -> Result<(), Error> {
		self.prune_list.restore(Bitmap::new())
	}

	/// Remove by insertion position.
	fn remove(&mut self, pos0: u64) -> Result<bool, Error> {
		if !self.prunable {
			return Err(Error::InvalidState("Remove on non-prunable MMR".into()));
		}
		Ok(self.leaf_set.remove(pos0)?)
	}

	/// Release underlying data files
	fn release_files(&mut self) {
		self.data_file.release();
		self.hash_file.release();
	}

	fn snapshot(&self, header: &BlockHeader) -> Result<(), Error> {
		self.leaf_set.snapshot(self.context_id, header)?;
		Ok(())
	}

	fn dump_stats(&self) {
		// We intentionally don't want return error, those errors will go into debug, so we could evaluate them
		debug!(
			"pmmr backend: unpruned: {:?}, hashes: {:?}, data: {:?}, leaf_set: {}, prune_list: {}",
			self.unpruned_size(),
			self.hash_size(),
			self.data_size(),
			self.leaf_set.len(),
			self.prune_list.len(),
		);
	}
}

impl<T: PMMRable> PMMRBackend<T> {
	/// Instantiates a new PMMR backend.
	/// If optional size is provided then treat as "fixed" size otherwise "variable" size backend.
	/// Use the provided dir to store its files.
	/// Instantiates a new PMMR backend with explicit variable-size metadata
	/// validation behavior.
	pub fn new<P: AsRef<Path>>(
		data_dir: P,
		prunable: bool,
		version: ProtocolVersion,
		context_id: u32,
		header: Option<&BlockHeader>,
		metadata_validation: VariableSizeMetadataValidation,
	) -> Result<PMMRBackend<T>, Error> {
		let data_dir = data_dir.as_ref();
		let leaf_set_path = data_dir.join(PMMR_LEAF_FILE);

		// If we received a rewound "snapshot" leaf_set file move it into
		// place before opening files below. Opening the append-only files can
		// create them, and snapshot failures should not leave a partial backend.
		if let Some(header) = header {
			let header_hash = header.hash(context_id)?;
			let leaf_snapshot_path = format!(
				"{}.{}",
				leaf_set_path.to_str().ok_or(io::Error::new(
					io::ErrorKind::Other,
					format!("Unable to build path to file {}", PMMR_LEAF_FILE)
				))?,
				header_hash.to_hex()
			);
			LeafSet::copy_snapshot(&leaf_set_path, &PathBuf::from(leaf_snapshot_path))?;
		}

		let existing_pmmr_files = Self::validate_pmmr_file_set(data_dir, prunable)?;

		// Are we dealing with "fixed size" data elements or "variable size" data elements
		// maintained in an associated size file?
		let size_info = if let Some(fixed_size) = T::elmt_size() {
			SizeInfo::FixedSize(fixed_size)
		} else {
			SizeInfo::VariableSize(Box::new(AppendOnlyFile::open(
				data_dir.join(PMMR_SIZE_FILE),
				SizeInfo::FixedSize(SizeEntry::LEN as u16),
				version,
				context_id,
				VariableSizeMetadataValidation::Full,
			)?))
		};

		// Hash file is always "fixed size" and we use 32 bytes per hash.
		let hash_size_info = SizeInfo::FixedSize(Hash::LEN as u16);

		let hash_file = DataFile::open(
			&data_dir.join(PMMR_HASH_FILE),
			hash_size_info,
			version,
			context_id,
			VariableSizeMetadataValidation::Full,
		)?;
		let data_file = DataFile::open(
			&data_dir.join(PMMR_DATA_FILE),
			size_info,
			version,
			context_id,
			metadata_validation,
		)?;

		let mut leaf_set = if prunable && existing_pmmr_files {
			LeafSet::open(&leaf_set_path)?
		} else {
			LeafSet::open_or_create(&leaf_set_path)?
		};
		let mut prune_list = PruneList::open(&data_dir.join(PMMR_PRUN_FILE))?;

		if prunable && !existing_pmmr_files {
			leaf_set.flush()?;
			prune_list.flush()?;
		}

		Ok(PMMRBackend {
			data_dir: data_dir.to_path_buf(),
			prunable,
			context_id,
			hash_file,
			data_file,
			leaf_set,
			prune_list,
		})
	}

	fn rollback_append(&mut self, data_size_before: u64, hash_size_before: u64) -> String {
		let mut errors = Vec::new();
		if let Err(e) = self.hash_file.truncate_unsynced(hash_size_before) {
			errors.push(format!("hash rollback failed: {}", e));
		}
		if let Err(e) = self.data_file.truncate_unsynced(data_size_before) {
			errors.push(format!("data rollback failed: {}", e));
		}
		if errors.is_empty() {
			String::new()
		} else {
			format!(" Rollback failed. {}", errors.join("; "))
		}
	}

	fn pmmr_file_set(data_dir: &Path) -> io::Result<PMMRFileSet> {
		Ok(PMMRFileSet {
			hash: Self::pmmr_regular_file_exists(data_dir, PMMR_HASH_FILE)?,
			data: Self::pmmr_regular_file_exists(data_dir, PMMR_DATA_FILE)?,
			leaf: Self::pmmr_regular_file_exists(data_dir, PMMR_LEAF_FILE)?,
			prun: Self::pmmr_regular_file_exists(data_dir, PMMR_PRUN_FILE)?,
			size: Self::pmmr_regular_file_exists(data_dir, PMMR_SIZE_FILE)?,
		})
	}

	fn pmmr_regular_file_exists(data_dir: &Path, file_name: &str) -> io::Result<bool> {
		let path = data_dir.join(file_name);
		match fs::symlink_metadata(&path) {
			Ok(metadata) => {
				let file_type = metadata.file_type();
				if file_type.is_symlink() {
					return Err(io::Error::new(
						io::ErrorKind::InvalidInput,
						format!("PMMR file {} must not be a symlink", path.display()),
					));
				}
				if !file_type.is_file() {
					return Err(io::Error::new(
						io::ErrorKind::InvalidInput,
						format!("PMMR file {} must be a regular file", path.display()),
					));
				}
				Ok(true)
			}
			Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
			Err(e) => Err(e),
		}
	}

	fn validate_pmmr_file_set(data_dir: &Path, prunable: bool) -> Result<bool, Error> {
		let files = Self::pmmr_file_set(data_dir)?;
		if !files.any() {
			return Ok(false);
		}

		if prunable {
			if files.leaf {
				LeafSet::open(data_dir.join(PMMR_LEAF_FILE))?;
			}

			if files.prun {
				PruneList::open(data_dir.join(PMMR_PRUN_FILE))?;
			}
		}

		if files.size && !files.data {
			return Err(Error::InvalidState(format!(
				"Partial PMMR file set in {}: {} exists without {}",
				data_dir.display(),
				PMMR_SIZE_FILE,
				PMMR_DATA_FILE
			)));
		}

		if files.hash != files.data {
			return Err(Error::InvalidState(format!(
				"Partial PMMR file set in {}: {} exists={}, {} exists={}",
				data_dir.display(),
				PMMR_HASH_FILE,
				files.hash,
				PMMR_DATA_FILE,
				files.data
			)));
		}

		if !files.hash {
			return Err(Error::InvalidState(format!(
				"Partial PMMR file set in {}: metadata files exist without hash/data files",
				data_dir.display()
			)));
		}

		if prunable && (!files.leaf || !files.prun) {
			return Err(Error::InvalidState(format!(
				"Partial PMMR file set in {}: prunable backend requires {}, {}, {}, and {}",
				data_dir.display(),
				PMMR_HASH_FILE,
				PMMR_DATA_FILE,
				PMMR_LEAF_FILE,
				PMMR_PRUN_FILE
			)));
		}

		Ok(true)
	}

	fn is_pruned(&self, pos0: u64) -> Result<bool, Error> {
		self.prune_list.is_pruned(pos0)
	}

	fn is_pruned_root(&self, pos0: u64) -> Result<bool, Error> {
		self.prune_list.is_pruned_root(pos0)
	}

	// Check if pos is pruned but not a pruned root itself.
	// Checking for pruned root is faster so we do this check first.
	// We can do a fast initial check as well -
	// if its in the current leaf_set then we know it is not compacted.
	fn is_compacted_impl(&self, pos0: u64) -> Result<bool, Error> {
		if !self.prunable {
			return Ok(false);
		}

		if self.leaf_set.includes(pos0)? {
			return Ok(false);
		}
		Ok(!self.is_pruned_root(pos0)? && self.is_pruned(pos0)?)
	}

	/// Number of hashes in the PMMR stored by this backend, including buffered
	/// in-memory changes that have not been synced to disk yet.
	pub fn unpruned_size(&self) -> Result<u64, Error> {
		let hash_size = self.hash_file.size_unsync()?;
		if !self.prunable {
			return Ok(hash_size);
		}

		hash_size
			.checked_add(self.prune_list.get_total_shift()?)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"PMMRBackend::unpruned_size, hash_size={}",
					hash_size
				))
			})
	}

	/// Number of elements in the underlying stored data. Extremely dependent on
	/// pruning and compaction.
	pub fn data_size(&self) -> Result<u64, Error> {
		Ok(self.data_file.size()?)
	}

	/// Size of the underlying hashed data. Extremely dependent on pruning
	/// and compaction.
	pub fn hash_size(&self) -> Result<u64, Error> {
		Ok(self.hash_file.size()?)
	}

	/// Syncs all files to disk. A call to sync is required to ensure all the
	/// data has been successfully written to disk.
	///
	/// PMMR state is persisted across multiple files. Making this flush fully
	/// transactional would require journaling or staging complete file sets,
	/// which would add significant overhead to the normal sync path. We flush
	/// each component directly and rely on PMMR consistency checks during later
	/// reads to detect any partial persistence caused by an I/O failure.
	pub fn sync(&mut self) -> io::Result<()> {
		self.hash_file.flush()?;
		self.data_file.flush()?;
		self.sync_leaf_set()?;
		self.prune_list.flush()?;
		Ok(())
	}

	// Sync the leaf_set if this is a prunable backend.
	fn sync_leaf_set(&mut self) -> io::Result<()> {
		if !self.prunable {
			return Ok(());
		}
		self.leaf_set.flush()
	}

	/// Discard the current, non synced state of the backend.
	pub fn discard(&mut self) -> Result<(), Error> {
		self.hash_file.discard();
		self.data_file.discard();
		self.leaf_set.discard();
		self.prune_list.discard()
	}

	/// Takes the leaf_set at a given cutoff_pos and generates an updated
	/// prune_list. Saves the updated prune_list to disk, compacts the hash
	/// and data files based on the prune_list and saves both to disk.
	///
	/// A cutoff position limits compaction on recent data.
	/// This will be the last position of a particular block to keep things
	/// aligned. The block_marker in the db/index for the particular block
	/// will have a suitable output_pos. This is used to enforce a horizon
	/// after which the local node should have all the data to allow rewinding.
	pub fn check_compact(
		&mut self,
		cutoff_pos: u64,
		rewind_rm_pos: &Bitmap,
	) -> Result<bool, Error> {
		if !self.prunable {
			return Err(Error::InvalidState(
				"Trying to compact a non-prunable PMMR".into(),
			));
		}
		self.sync()?;
		let current_size = self.unpruned_size()?;
		if cutoff_pos > current_size {
			return Err(Error::InvalidState(format!(
				"cannot compact beyond current PMMR size: cutoff_pos={}, unpruned_size={}",
				cutoff_pos, current_size
			)));
		}

		// Calculate the sets of leaf positions and node positions to remove based
		// on the cutoff_pos provided.
		let (leaves_removed, pos_to_rm) = self.pos_to_rm(cutoff_pos, rewind_rm_pos)?;

		// Save compact copy of the hash file, skipping removed data.
		{
			let pos_to_rm = pos_to_rm
				.iter()
				.map(|pos1| {
					let pos0 = u64::from(pos1).checked_sub(1).ok_or_else(|| {
						Error::DataOverflow(format!("PMMRBackend::check_compact, pos1={}", pos1))
					})?;
					let shift = self.prune_list.get_shift(pos0)?;
					u64::from(pos1).checked_sub(shift).ok_or_else(|| {
						Error::DataOverflow(format!(
							"PMMRBackend::check_compact pos1={} shift={}",
							pos1, shift
						))
					})
				})
				.collect::<Result<Vec<_>, Error>>()?;

			self.hash_file.write_tmp_pruned(&pos_to_rm)?;
		}

		// Save compact copy of the data file, skipping removed leaves.
		{
			let leaf_pos_to_rm = pos_to_rm
				.iter()
				.map(|x| {
					let pos = u64::from(x);
					let pos0 = pos.checked_sub(1).ok_or_else(|| {
						Error::DataOverflow(format!("PMMRBackend::check_compact, pos={}", pos))
					})?;
					if pmmr::is_leaf(pos0) {
						Ok(Some(pos))
					} else {
						Ok(None)
					}
				})
				.collect::<Result<Vec<_>, Error>>()?
				.into_iter()
				.flatten()
				.collect::<Vec<_>>();

			let pos_to_rm = leaf_pos_to_rm
				.iter()
				.map(|&pos| {
					let flat_pos = pmmr::n_leaves(pos)?;
					let shift = self.prune_list.get_leaf_shift(pos)?;
					flat_pos.checked_sub(shift).ok_or_else(|| {
						Error::DataOverflow(format!(
							"PMMRBackend::check_compact flat_pos={} shift={}",
							flat_pos, shift
						))
					})
				})
				.collect::<Result<Vec<_>, Error>>()?;

			self.data_file.write_tmp_pruned(&pos_to_rm)?;
		}

		// Compaction applies several persistent mutations below: hash/data file
		// replacement, prune-list flush, and leaf-set flush. These filesystem
		// operations are not transactional, so a crash or error after one step can
		// leave PMMR files inconsistent. This staged best-effort approach is what
		// we can support without a transaction layer for flat-file replacement.
		// Replace hash and data files with compact copies.
		// Rebuild and intialize from the new files.
		{
			debug!("compact: about to replace hash and data files and rebuild...");
			self.hash_file.replace_with_tmp()?;
			self.data_file.replace_with_tmp()?;
			debug!("compact: ...finished replacing and rebuilding");
		}

		// Update the prune list and write to disk.
		{
			let mut bitmap = self.prune_list.bitmap();
			bitmap.or_inplace(&leaves_removed);
			self.prune_list = PruneList::new(Some(self.data_dir.join(PMMR_PRUN_FILE)), bitmap)?;
			self.prune_list.flush()?;
		}

		// Write the leaf_set to disk.
		// Optimize the bitmap storage in the process.
		self.leaf_set.flush()?;

		let cleanup_stats = self.clean_rewind_files()?;
		if cleanup_stats.failed > 0 {
			warn!(
				"PMMR rewind file cleanup deleted {} files and reported {} failures",
				cleanup_stats.deleted, cleanup_stats.failed
			);
		} else if cleanup_stats.deleted > 0 {
			info!(
				"PMMR rewind file cleanup deleted {} files",
				cleanup_stats.deleted
			);
		}

		Ok(true)
	}

	fn clean_rewind_files(&self) -> io::Result<CleanupStats> {
		let data_dir = self.data_dir.clone();
		let pattern = format!("{}.", PMMR_LEAF_FILE);
		clean_files_by_prefix(data_dir, &pattern, REWIND_FILE_CLEANUP_DURATION_SECONDS)
	}

	fn pos_to_rm(
		&self,
		cutoff_pos: u64,
		rewind_rm_pos: &Bitmap,
	) -> Result<(Bitmap, Bitmap), Error> {
		let mut expanded = Bitmap::new();

		let leaf_pos_to_rm =
			self.leaf_set
				.removed_pre_cutoff(cutoff_pos, rewind_rm_pos, &self.prune_list)?;

		for x in leaf_pos_to_rm.iter() {
			expanded.add(x);
			let mut current = x;
			loop {
				let current0 = current.checked_sub(1).ok_or_else(|| {
					Error::DataOverflow(format!("PMMRBackend::pos_to_rm, current={}", current))
				})?;
				let (parent0, sibling0) = family(u64::from(current0))?;
				let sibling_pruned = self.is_pruned_root(sibling0)?;

				// if sibling previously pruned
				// push it back onto list of pos to remove
				// so we can remove it and traverse up to parent
				if sibling_pruned {
					expanded.add(Self::pos0_to_pos1_u32(
						sibling0,
						"PMMRBackend::pos_to_rm sibling0",
					)?);
				}

				if sibling_pruned
					|| expanded.contains(Self::pos0_to_pos1_u32(
						sibling0,
						"PMMRBackend::pos_to_rm sibling0",
					)?) {
					let parent1 =
						Self::pos0_to_pos1_u32(parent0, "PMMRBackend::pos_to_rm parent0")?;
					expanded.add(parent1);
					current = parent1;
				} else {
					break;
				}
			}
		}
		Ok((leaf_pos_to_rm, removed_excl_roots(&expanded)?))
	}

	fn pos0_to_pos1_u32(pos0: u64, context: &str) -> Result<u32, Error> {
		let pos1 = pos0
			.checked_add(1)
			.ok_or_else(|| Error::DataOverflow(format!("{}, pos0={}", context, pos0)))?;
		u32::try_from(pos1).map_err(|_| Error::DataOverflow(format!("{}, pos1={}", context, pos1)))
	}

	fn pos0_to_pos1(pos0: u64, context: &str) -> Result<u64, Error> {
		pos0.checked_add(1)
			.ok_or_else(|| Error::DataOverflow(format!("{}, pos0={}", context, pos0)))
	}
}

/// Filter remove list to exclude roots.
/// We want to keep roots around so we have hashes for Merkle proofs.
fn removed_excl_roots(removed: &Bitmap) -> Result<Bitmap, Error> {
	let mut bitmap = Bitmap::new();
	for pos in removed.iter() {
		let pos0 = u64::from(pos).checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!("store::removed_excl_roots, pos={}", pos))
		})?;
		let (parent_pos0, _) = family(pos0)?;
		// The remove bitmap stores PMMR positions as u32 values. Any parent position
		// outside that domain indicates a PMMR/compaction invariant bug and should be
		// reported instead of being treated as a normal "not contained" lookup.
		let parent_pos1 = parent_pos0
			.checked_add(1)
			.and_then(|pos1| u32::try_from(pos1).ok())
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"store::removed_excl_roots, parent_pos0={}",
					parent_pos0
				))
			})?;
		if removed.contains(parent_pos1) {
			bitmap.add(pos);
		}
	}
	Ok(bitmap)
}

/// Best-effort file cleanup statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CleanupStats {
	/// Number of files successfully deleted.
	pub deleted: u32,
	/// Number of per-entry cleanup failures.
	pub failed: u32,
}

/// Quietly clean a directory up based on a given prefix.
/// If the file was accessed within cleanup_duration_seconds from the beginning of
/// the function call, it will not be deleted. To delete all files, set cleanup_duration_seconds
/// to zero.
///
/// Precondition is that path points to a directory.
///
/// If you have files such as
/// ```text
/// foo
/// foo.1
/// foo.2
/// .
/// .
/// .
/// .
/// .
/// ```
///
/// call this function and you will get
///
/// ```text
/// foo
/// ```
///
/// in the directory
///
/// The return value reports the number of files that were deleted and the
/// number of per-entry cleanup failures. Cleanup remains best-effort, so
/// failures for individual entries are logged and counted without stopping
/// cleanup of later entries.
///
/// This function will return an error whenever the call to `std::fs::read_dir`
/// fails on the given path for any reason.
pub fn clean_files_by_prefix<P: AsRef<std::path::Path>>(
	path: P,
	prefix_to_delete: &str,
	cleanup_duration_seconds: u64,
) -> io::Result<CleanupStats> {
	let now = time::SystemTime::now();
	let cleanup_duration = time::Duration::from_secs(cleanup_duration_seconds);
	let mut stats = CleanupStats::default();

	for possible_dir_entry in fs::read_dir(&path)? {
		let dir_entry = match possible_dir_entry {
			Ok(dir_entry) => dir_entry,
			Err(e) => {
				stats.failed = stats.failed.saturating_add(1);
				warn!("Failed to inspect cleanup directory entry: {}", e);
				continue;
			}
		};

		let entry_path = dir_entry.path();
		let metadata = match dir_entry.metadata() {
			Ok(metadata) => metadata,
			Err(e) => {
				stats.failed = stats.failed.saturating_add(1);
				warn!(
					"Failed to read cleanup metadata for {}: {}",
					entry_path.display(),
					e
				);
				continue;
			}
		};

		if metadata.is_dir() {
			continue; // skip directories unconditionally
		}

		let accessed = match metadata.accessed() {
			Ok(accessed) => accessed,
			Err(e) => {
				stats.failed = stats.failed.saturating_add(1);
				warn!(
					"Failed to read cleanup access time for {}: {}",
					entry_path.display(),
					e
				);
				continue;
			}
		};

		let duration_since_accessed = match now.duration_since(accessed) {
			Ok(duration) => duration,
			Err(e) => {
				stats.failed = stats.failed.saturating_add(1);
				warn!(
					"Failed to compare cleanup access time for {}: {}",
					entry_path.display(),
					e
				);
				continue;
			}
		};

		if duration_since_accessed <= cleanup_duration {
			continue; // these files are still too new
		}

		let file_name = match dir_entry.file_name().into_string() {
			Ok(file_name) => file_name,
			Err(file_name) => {
				stats.failed = stats.failed.saturating_add(1);
				warn!(
					"Failed to convert cleanup filename {:?} into UTF-8",
					file_name
				);
				continue;
			}
		};

		// check to see if we want to delete this file?
		if file_name.starts_with(prefix_to_delete) && file_name.len() > prefix_to_delete.len() {
			// we want to delete it, try to do so
			match fs::remove_file(&entry_path) {
				Ok(()) => stats.deleted = stats.deleted.saturating_add(1),
				Err(e) => {
					stats.failed = stats.failed.saturating_add(1);
					warn!(
						"Failed to delete cleanup file {}: {}",
						entry_path.display(),
						e
					);
				}
			}
		}
	}

	Ok(stats)
}
