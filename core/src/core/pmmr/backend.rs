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

use crate::core::hash::Hash;
use crate::core::BlockHeader;
use crate::ser::PMMRable;
use mwc_crates::croaring::Bitmap;

/// Errors for Backend and derivatives
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Couldn't find what we were looking for
	#[error("PMMR Serialization error, {0}")]
	SerializationError(String),
	/// PMMR State error
	#[error("PMMR state error, {0}")]
	InvalidState(String),
	/// Internal error
	#[error("PMMR internal error, {0}")]
	InternalError(String),
	/// Corrupted State
	#[error("PMMR data might be corrupted, {0}")]
	DataCorruption(String),
	/// Underlying IO error.
	#[error("PMMR IO error, {0}")]
	IOErr(#[from] std::io::Error),
	/// Data overflow error
	#[error("PMMR data overflow error, {0}")]
	DataOverflow(String),
	/// Not supported
	#[error("Not supported {0}")]
	NotSupported(String),
}

/// Storage backend for the MMR, just needs to be indexed by order of insertion.
/// The PMMR itself does not need the Backend to be accurate on the existence
/// of an element (i.e. remove could be a no-op) but layers above can
/// depend on an accurate Backend to check existence.
pub trait Backend<T: PMMRable> {
	/// Consensus context used for PMMR hash serialization.
	fn get_context_id(&self) -> u32;

	/// Append the provided Hashes to the backend storage, and optionally an
	/// associated data element to flatfile storage (for leaf nodes only). The
	/// position of the first element of the Vec in the MMR is provided to
	/// help the implementation.
	fn append(&mut self, data: &T, hashes: &[Hash]) -> Result<(), Error>;

	/// Rebuilding a PMMR locally from PIBD segments requires pruned subtree support.
	/// This allows us to append an existing pruned subtree directly without the underlying leaf nodes.
	fn append_pruned_subtree(&mut self, hash: Hash, pos0: u64) -> Result<(), Error>;

	/// Append a pruned subtree and any parent hashes built from preceding peaks.
	fn append_pruned_subtree_hashes(
		&mut self,
		hash: Hash,
		pos0: u64,
		hashes: &[Hash],
	) -> Result<(), Error>;

	/// Append a single hash to the pmmr
	fn append_hash(&mut self, hash: Hash) -> Result<(), Error>;

	/// Rewind the backend state to a previous position, as if all append
	/// operations after that had been canceled. Expects a position in the PMMR
	/// to rewind to as well as bitmaps representing the positions added and
	/// removed since the rewind position. These are what we will "undo"
	/// during the rewind.
	fn rewind(&mut self, pos1: u64, rewind_rm_pos: &Bitmap) -> Result<(), Error>;

	/// Get a Hash by insertion position.
	fn get_hash(&self, pos0: u64) -> Result<Option<Hash>, Error>;

	/// Get underlying data by insertion position.
	fn get_data(&self, pos0: u64) -> Result<Option<T::E>, Error>;

	/// Get a Hash  by original insertion position
	/// (ignoring the remove log).
	fn get_from_file(&self, pos0: u64) -> Result<Option<Hash>, Error>;

	/// Returns true when a hash missing at pos0 is expected because backend
	/// compaction intentionally removed it.
	fn is_compacted(&self, pos0: u64) -> Result<bool, Error>;

	/// Get hash for peak pos.
	/// Optimized for reading peak hashes rather than arbitrary pos hashes.
	/// Peaks can be assumed to not be compacted.
	fn get_peak_from_file(&self, pos0: u64) -> Result<Option<Hash>, Error>;

	/// Get a Data Element by original insertion position
	/// (ignoring the remove log).
	fn get_data_from_file(&self, pos0: u64) -> Result<Option<T::E>, Error>;

	/// Iterator over current (unpruned, unremoved) leaf positions.
	fn leaf_pos_iter(&self) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error>;

	/// Iterator over current (unpruned, unremoved) leaf positions at or after
	/// the provided 0-based PMMR position.
	fn leaf_pos_iter_from(
		&self,
		from_pos0: u64,
	) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error> {
		Ok(Box::new(self.leaf_pos_iter()?.filter(
			move |pos| match pos {
				Ok(pos) => *pos >= from_pos0,
				Err(_) => true,
			},
		)))
	}

	/// Number of leaves
	fn n_unpruned_leaves(&self) -> Result<u64, Error>;

	/// Number of leaves up to the given leaf index
	fn n_unpruned_leaves_to_index(&self, to_index: u64) -> Result<u64, Error>;

	/// Iterator over current (unpruned, unremoved) leaf insertion index.
	/// Note: This differs from underlying MMR pos - [0, 1, 2, 3, 4] vs. [1, 2, 4, 5, 8].
	fn leaf_idx_iter(
		&self,
		from_idx: u64,
	) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error>;

	/// Remove Hash by insertion position. An index is also provided so the
	/// underlying backend can implement some rollback of positions up to a
	/// given index (practically the index is the height of a block that
	/// triggered removal).
	fn remove(&mut self, position: u64) -> Result<bool, Error>;

	// Remove a leaf from the leaf set.
	// DON'T USE IS, use prune instead
	//fn remove_from_leaf_set(&mut self, pos0: u64);

	/// Release underlying datafiles and locks
	fn release_files(&mut self);

	/// Reset prune list, used when PIBD is reset
	fn reset_prune_list(&mut self) -> Result<(), Error>;

	/// Saves a snapshot of the rewound utxo file with the block hash as
	/// filename suffix. We need this when sending a txhashset zip file to a
	/// node for fast sync.
	fn snapshot(&self, header: &BlockHeader) -> Result<(), Error>;

	/// For debugging purposes so we can see how compaction is doing.
	fn dump_stats(&self);
}
