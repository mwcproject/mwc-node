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

//! The Mwc leaf_set implementation.
//! Compact (roaring) bitmap representing the set of leaf positions
//! that exist and are not currently pruned in the MMR.

use std::convert::TryFrom;
use std::path::{Path, PathBuf};

use mwc_crates::croaring::{Bitmap, Portable};

use crate::prune_list::PruneList;
use crate::{read_bitmap, save_via_temp_file};
use mwc_core::core::hash::Hashed;
use mwc_core::core::pmmr;
use mwc_core::core::pmmr::Error;
use mwc_core::core::BlockHeader;
use mwc_util::ToHex;

use mwc_crates::log::debug;
use std::io::{self, ErrorKind, Write};

/// Compact (roaring) bitmap representing the set of positions of
/// leaves that are currently unpruned in the MMR.
pub struct LeafSet {
	path: PathBuf,
	bitmap: Bitmap,
	bitmap_bak: Bitmap,
}

impl LeafSet {
	/// Open the remove log file.
	/// The content of the file will be read in memory for fast checking.
	pub fn open<P: AsRef<Path>>(path: P) -> io::Result<LeafSet> {
		Self::open_impl(path, false)
	}

	/// Open the remove log file, creating an empty in-memory leaf set if it does not exist.
	pub fn open_or_create<P: AsRef<Path>>(path: P) -> io::Result<LeafSet> {
		Self::open_impl(path, true)
	}

	fn open_impl<P: AsRef<Path>>(path: P, create_if_missing: bool) -> io::Result<LeafSet> {
		let file_path = path.as_ref();
		let bitmap = match read_bitmap(&file_path) {
			Ok(bitmap) => bitmap,
			Err(e) if e.kind() == io::ErrorKind::NotFound && create_if_missing => Bitmap::new(),
			Err(e) => return Err(e),
		};
		Self::validate_bitmap(&bitmap)?;

		if !bitmap.is_empty() {
			debug!(
				"bitmap {} pos ({} bytes)",
				bitmap.cardinality(),
				bitmap.get_serialized_size_in_bytes::<Portable>(),
			);
		}

		Ok(LeafSet {
			path: file_path.to_path_buf(),
			bitmap_bak: bitmap.clone(),
			bitmap,
		})
	}

	/// Copies a snapshot of the utxo file into the primary utxo file.
	pub fn copy_snapshot<P: AsRef<Path>>(path: P, cp_path: P) -> io::Result<()> {
		let cp_file_path = cp_path.as_ref();

		let bitmap = read_bitmap(&cp_file_path).map_err(|e| {
			if e.kind() == ErrorKind::NotFound {
				debug!(
					"leaf_set: rewound leaf file not found: {}",
					cp_file_path.display()
				);
				io::Error::new(
					ErrorKind::NotFound,
					format!("File {} not exits", cp_path.as_ref().to_string_lossy()),
				)
			} else {
				e
			}
		})?;
		Self::validate_bitmap(&bitmap)?;
		debug!(
			"leaf_set: copying rewound file {} to {}",
			cp_file_path.display(),
			path.as_ref().display()
		);

		let mut leaf_set = LeafSet {
			path: path.as_ref().to_path_buf(),
			bitmap_bak: bitmap.clone(),
			bitmap,
		};

		leaf_set.flush()?;
		Ok(())
	}

	/// Calculate the set of unpruned leaves
	/// up to and including the cutoff_pos.
	/// Only applicable for the output MMR.
	fn unpruned_pre_cutoff(
		&self,
		cutoff_pos: u64,
		prune_list: &PruneList,
	) -> Result<Bitmap, Error> {
		let cutoff_pos = u32::try_from(cutoff_pos).map_err(|_| {
			Error::DataOverflow(format!(
				"unpruned_pre_cutoff cutoff_pos is too large: {}",
				cutoff_pos
			))
		})?;

		let mut res_bitmap = Bitmap::new();
		for x in 1..=cutoff_pos {
			let pos0 = u64::from(x - 1);
			if pmmr::is_leaf(pos0) && !prune_list.is_pruned(pos0)? {
				res_bitmap.add(x);
			}
		}
		Ok(res_bitmap)
	}

	/// Calculate the set of pruned positions
	/// up to and including the cutoff_pos.
	/// Uses both the leaf_set and the prune_list to determine prunedness.
	pub fn removed_pre_cutoff(
		&self,
		cutoff_pos: u64,
		rewind_rm_pos: &Bitmap,
		prune_list: &PruneList,
	) -> Result<Bitmap, Error> {
		let mut bitmap = self.bitmap.clone();

		// First remove pos from leaf_set that were
		// added after the point we are rewinding to.
		let cutoff_plus_one_u32 =
			Self::u64_plus_one_u32(cutoff_pos, "removed_pre_cutoff", "cutoff_pos")?;
		let to_remove = cutoff_plus_one_u32..=bitmap.maximum().unwrap_or(0);
		bitmap.remove_range(to_remove);

		// Then add back output pos to the leaf_set
		// that were removed.
		bitmap.or_inplace(&rewind_rm_pos);

		// Invert bitmap for the leaf pos and return the resulting bitmap.
		Ok(bitmap
			.flip(1u32..cutoff_plus_one_u32)
			.and(&self.unpruned_pre_cutoff(cutoff_pos, prune_list)?))
	}

	/// Rewinds the leaf_set back to a previous state.
	/// Removes all pos after the cutoff.
	/// Adds back all pos in rewind_rm_pos.
	pub fn rewind(&mut self, cutoff_pos: u64, rewind_rm_pos: &Bitmap) -> Result<(), Error> {
		let cutoff_plus_one_u32 = Self::u64_plus_one_u32(cutoff_pos, "rewind", "cutoff_pos")?;
		let rewind_rm_pos = Self::filter_rewind_rm_pos(cutoff_plus_one_u32 - 1, rewind_rm_pos);

		// First remove pos from leaf_set that were
		// added after the point we are rewinding to.
		let to_remove = cutoff_plus_one_u32..=self.bitmap.maximum().unwrap_or(0);
		self.bitmap.remove_range(to_remove);

		// Then add back output pos to the leaf_set
		// that were removed.
		self.bitmap.or_inplace(&rewind_rm_pos);
		Ok(())
	}

	fn filter_rewind_rm_pos(cutoff_pos: u32, rewind_rm_pos: &Bitmap) -> Bitmap {
		let mut bitmap = Bitmap::new();
		for pos in rewind_rm_pos.iter() {
			if pos != 0 && pos <= cutoff_pos && pmmr::is_leaf(u64::from(pos - 1)) {
				bitmap.add(pos);
			}
		}
		bitmap
	}

	/// Append a new position to the leaf_set.
	pub fn add(&mut self, pos0: u64) -> Result<(), Error> {
		Self::validate_leaf_pos(pos0)?;
		let pos0_plus_1_u32 = Self::u64_plus_one_u32(pos0, "add", "pos0")?;
		Ok(self.bitmap.add(pos0_plus_1_u32))
	}

	/// Remove the provided position from the leaf_set.
	/// Returns true if the leaf was removed and false if it was not present.
	pub fn remove(&mut self, pos0: u64) -> Result<bool, Error> {
		Self::validate_leaf_pos(pos0)?;
		let pos0_plus_1_u32 = Self::u64_plus_one_u32(pos0, "remove", "pos0")?;
		if !self.bitmap.contains(pos0_plus_1_u32) {
			return Ok(false);
		}
		self.bitmap.remove(pos0_plus_1_u32);
		Ok(true)
	}

	/// Saves the utxo file tagged with block hash as filename suffix.
	/// Needed during fast-sync as the receiving node cannot rewind
	/// after receiving the txhashset zip file.
	pub fn snapshot(&self, context_id: u32, header: &BlockHeader) -> io::Result<()> {
		let mut cp_bitmap = self.bitmap.clone();
		cp_bitmap.run_optimize();

		let header_hash = header.hash(context_id)?;
		let cp_path = format!(
			"{}.{}",
			self.path.to_str().ok_or(io::Error::new(
				io::ErrorKind::Other,
				String::from("invalid path value at LeafSet::snapshot")
			))?,
			header_hash.to_hex()
		);
		save_via_temp_file(cp_path, ".tmp", |file| {
			file.write_all(&cp_bitmap.serialize::<Portable>())
		})?;
		Ok(())
	}

	/// Flush the leaf_set to file.
	pub fn flush(&mut self) -> io::Result<()> {
		// First run the optimization step on the bitmap.
		self.bitmap.run_optimize();

		// Write the updated bitmap file to disk.
		save_via_temp_file(&self.path, ".tmp", |file| {
			file.write_all(&self.bitmap.serialize::<Portable>())
		})?;

		// Make sure our backup in memory is up to date.
		self.bitmap_bak = self.bitmap.clone();

		Ok(())
	}

	/// Discard any pending changes.
	pub fn discard(&mut self) {
		self.bitmap = self.bitmap_bak.clone();
	}

	/// Whether the leaf_set includes the provided position.
	pub fn includes(&self, pos0: u64) -> Result<bool, Error> {
		let pos0_plus_1_u32 = Self::u64_plus_one_u32(pos0, "add", "pos0")?;
		Ok(self.bitmap.contains(pos0_plus_1_u32))
	}

	/// Number of positions stored in the leaf_set.
	pub fn len(&self) -> u64 {
		self.bitmap.cardinality()
	}

	/// Number of positions up to a 1-based PMMR position in the leaf set.
	pub fn n_unpruned_leaves_to_index(&self, to_index: u64) -> Result<u64, Error> {
		let to_index = u32::try_from(to_index).map_err(|_| {
			Error::DataOverflow(format!(
				"LeafSet::n_unpruned_leaves_to_index, to_index={}",
				to_index
			))
		})?;
		let mut count = 0;
		for pos1 in self.bitmap.iter() {
			if pos1 >= to_index {
				break;
			}
			let pos0 = pos1
				.checked_sub(1)
				.ok_or_else(|| Error::DataCorruption("Invalid zero leaf_set entry.".to_string()))?;
			if !pmmr::is_leaf(u64::from(pos0)) {
				return Err(Error::DataCorruption(format!(
					"Invalid leaf_set entry {}, PMMR position {} is not a leaf.",
					pos1, pos0
				)));
			}
			count += 1;
		}
		Ok(count)
	}

	/// Is the leaf_set empty.
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Iterator over positionns in the leaf_set (all leaf positions).
	pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
		self.bitmap.iter().map(u64::from)
	}

	/// Iterator over entries at or after the provided 0-based PMMR position.
	pub fn iter_from_pos0(&self, from_pos0: u64) -> Result<impl Iterator<Item = u64> + '_, Error> {
		let from_pos1 = Self::u64_plus_one_u32(from_pos0, "iter_from_pos0", "from_pos0")?;
		let mut iter = self.bitmap.iter();
		iter.reset_at_or_after(from_pos1);
		Ok(iter.map(u64::from))
	}

	#[inline]
	fn u64_plus_one_u32(x: u64, method_name: &str, var_name: &str) -> Result<u32, Error> {
		x.checked_add(1)
			.and_then(|x| u32::try_from(x).ok())
			.ok_or_else(|| {
				Error::DataOverflow(format!("LeafSet::{}, {}={}", method_name, var_name, x))
			})
	}

	fn validate_bitmap(bitmap: &Bitmap) -> io::Result<()> {
		for pos1 in bitmap.iter() {
			let pos0 = pos1.checked_sub(1).ok_or_else(|| {
				io::Error::new(
					ErrorKind::InvalidData,
					"Invalid zero leaf_set entry in persisted bitmap",
				)
			})?;
			if let Err(e) = Self::validate_leaf_pos(u64::from(pos0)) {
				return Err(io::Error::new(
					ErrorKind::InvalidData,
					format!("Invalid leaf_set entry {}, {}", pos1, e),
				));
			}
		}
		Ok(())
	}

	fn validate_leaf_pos(pos0: u64) -> Result<(), Error> {
		if !pmmr::is_leaf(pos0) {
			return Err(Error::DataCorruption(format!(
				"PMMR position {} is not a leaf",
				pos0
			)));
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;

	#[test]
	fn rewind_filters_invalid_restore_positions() {
		let mut leaf_set = LeafSet {
			path: PathBuf::new(),
			bitmap: Bitmap::of(&vec![1, 2, 4, 5, 8]),
			bitmap_bak: Bitmap::new(),
		};

		leaf_set
			.rewind(3, &Bitmap::of(&vec![0, 2, 3, 4, 6]))
			.unwrap();

		assert!(leaf_set.bitmap.contains(1));
		assert!(leaf_set.bitmap.contains(2));
		assert!(!leaf_set.bitmap.contains(0));
		assert!(!leaf_set.bitmap.contains(3));
		assert!(!leaf_set.bitmap.contains(4));
		assert!(!leaf_set.bitmap.contains(5));
		assert!(!leaf_set.bitmap.contains(6));
		assert!(!leaf_set.bitmap.contains(8));
	}

	#[test]
	fn add_rejects_non_leaf_position() {
		let mut leaf_set = LeafSet {
			path: PathBuf::new(),
			bitmap: Bitmap::new(),
			bitmap_bak: Bitmap::new(),
		};

		match leaf_set.add(2) {
			Err(Error::DataCorruption(msg)) => {
				assert!(msg.contains("is not a leaf"), "unexpected error: {}", msg);
			}
			other => panic!("expected non-leaf add rejection, got {:?}", other),
		}
		assert!(leaf_set.bitmap.is_empty());
	}

	#[test]
	fn remove_reports_removed_and_missing_leaf_positions() {
		let mut leaf_set = LeafSet {
			path: PathBuf::new(),
			bitmap: Bitmap::of(&[1]),
			bitmap_bak: Bitmap::new(),
		};

		assert!(leaf_set.remove(0).unwrap());
		assert!(!leaf_set.bitmap.contains(1));
		assert!(!leaf_set.remove(0).unwrap());

		match leaf_set.remove(2) {
			Err(Error::DataCorruption(msg)) => {
				assert!(msg.contains("is not a leaf"), "unexpected error: {}", msg);
			}
			other => panic!("expected non-leaf remove rejection, got {:?}", other),
		}
	}

	#[test]
	fn open_rejects_zero_leaf_set_entry() {
		let temp_dir = mwc_crates::tempfile::tempdir().unwrap();
		let path = temp_dir.path().join("leaf.bin");
		fs::write(&path, Bitmap::of(&[0]).serialize::<Portable>()).unwrap();

		let err = match LeafSet::open(&path) {
			Err(err) => err,
			Ok(_) => panic!("expected invalid zero leaf_set entry rejection"),
		};

		assert_eq!(err.kind(), ErrorKind::InvalidData);
		assert!(err.to_string().contains("zero leaf_set entry"));
	}

	#[test]
	fn open_rejects_non_leaf_leaf_set_entry() {
		let temp_dir = mwc_crates::tempfile::tempdir().unwrap();
		let path = temp_dir.path().join("leaf.bin");
		fs::write(&path, Bitmap::of(&[3]).serialize::<Portable>()).unwrap();

		let err = match LeafSet::open(&path) {
			Err(err) => err,
			Ok(_) => panic!("expected non-leaf leaf_set entry rejection"),
		};

		assert_eq!(err.kind(), ErrorKind::InvalidData);
		assert!(err.to_string().contains("is not a leaf"));
	}

	#[test]
	fn copy_snapshot_rejects_invalid_leaf_set_entry() {
		let temp_dir = mwc_crates::tempfile::tempdir().unwrap();
		let path = temp_dir.path().join("leaf.bin");
		let snapshot_path = temp_dir.path().join("leaf.bin.snapshot");
		fs::write(&snapshot_path, Bitmap::of(&[3]).serialize::<Portable>()).unwrap();

		let err = LeafSet::copy_snapshot(&path, &snapshot_path).unwrap_err();

		assert_eq!(err.kind(), ErrorKind::InvalidData);
		assert!(err.to_string().contains("is not a leaf"));
	}

	#[test]
	fn snapshot_uses_full_hash_hex_suffix() {
		mwc_core::global::set_local_chain_type(mwc_core::global::ChainTypes::AutomatedTesting);
		let temp_dir = mwc_crates::tempfile::tempdir().unwrap();
		let path = temp_dir.path().join("leaf.bin");
		let leaf_set = LeafSet {
			path: path.clone(),
			bitmap: Bitmap::new(),
			bitmap_bak: Bitmap::new(),
		};
		let header = BlockHeader::default(0);
		let full_hash = header.hash(0).unwrap().to_hex();

		leaf_set.snapshot(0, &header).unwrap();

		assert_eq!(full_hash.len(), 64);
		assert!(PathBuf::from(format!("{}.{}", path.display(), full_hash)).exists());
		assert!(!PathBuf::from(format!("{}.{}", path.display(), header.hash(0).unwrap())).exists());
	}
}
