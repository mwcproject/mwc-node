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

//! The Mwc "Prune List" implementation.
//!
//! Maintains a set of pruned root node positions that define the pruned
//! and compacted "gaps" in the MMR data and hash files.
//! The root itself is maintained in the hash file, but all positions beneath
//! the root are compacted away. All positions to the right of a pruned node
//! must be shifted the appropriate amount when reading from the hash and data
//! files.

use std::path::{Path, PathBuf};
use std::{
	io::{self, Write},
	ops::Range,
};

use mwc_core::core::pmmr;
use mwc_crates::croaring::{Bitmap, Portable};

use crate::{read_bitmap, save_via_temp_file};
use mwc_core::core::pmmr::Error;
use mwc_core::core::pmmr::{bintree_leftmost, bintree_postorder_height, family};
use mwc_crates::log::debug;
use std::convert::TryFrom;

/// Maintains a list of previously pruned nodes in PMMR, compacting the list as
/// parents get pruned and allowing checking whether a leaf is pruned. Given
/// a node's position, computes how much it should get shifted given the
/// subtrees that have been pruned before.
///
/// The PruneList is useful when implementing compact backends for a PMMR (for
/// example a single large byte array or a file). As nodes get pruned and
/// removed from the backend to free space, the backend will get more compact
/// but positions of a node within the PMMR will not match positions in the
/// backend storage anymore. The PruneList accounts for that mismatch and does
/// the position translation.
#[derive(Debug)]
pub struct PruneList {
	path: Option<PathBuf>,
	/// Bitmap representing pruned root node positions.
	bitmap: Bitmap,
	bitmap_bak: Bitmap,
	// These caches are derived from the bitmap and are used by get_shift() and
	// get_leaf_shift() while translating logical PMMR positions to compacted
	// file positions. Scanning the full prune bitmap for every lookup is too
	// expensive on large PMMRs, so the prune list relies on these caches being
	// rebuilt or updated whenever the bitmap changes.
	shift_cache: Vec<u64>,
	leaf_shift_cache: Vec<u64>,
}

impl PruneList {
	/// Instantiate a new prune list from the provided path and 1-based bitmap.
	/// Note: Does not flush the bitmap to disk. Caller is responsible for doing this.
	pub fn new(path: Option<PathBuf>, bitmap: Bitmap) -> Result<PruneList, Error> {
		if bitmap.contains(0) {
			return Err(Error::InternalError("bitmap contains unexpected 0".into()));
		}
		let mut prune_list = PruneList {
			path,
			bitmap: Bitmap::new(),
			bitmap_bak: Bitmap::new(),
			shift_cache: vec![],
			leaf_shift_cache: vec![],
		};

		for pos1 in bitmap.iter() {
			// Safe: pos1 can't be 0 because bitmap.contains(0) is false.
			prune_list.append(u64::from(pos1 - 1))?
		}

		prune_list.bitmap.run_optimize();
		prune_list.bitmap_bak = prune_list.bitmap.clone();
		Ok(prune_list)
	}

	/// Instatiate a new empty prune list.
	pub fn empty() -> Result<PruneList, Error> {
		PruneList::new(None, Bitmap::new())
	}

	/// Open an existing prune_list or create a new one.
	/// Takes an optional bitmap of new pruned pos to be combined with existing pos.
	pub fn open<P: AsRef<Path>>(path: P) -> Result<PruneList, Error> {
		let file_path = PathBuf::from(path.as_ref());
		let bitmap = match read_bitmap(&file_path) {
			Ok(bitmap) => bitmap,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Bitmap::new(),
			Err(e) => return Err(e.into()),
		};
		if bitmap.contains(0) {
			return Err(Error::InternalError("bitmap contains unexpected 0".into()));
		}

		let mut prune_list = PruneList::new(Some(file_path), bitmap)?;

		// Now build the shift caches from the bitmap we read from disk
		prune_list.init_caches()?;

		if !prune_list.bitmap.is_empty() {
			debug!(
				"bitmap {} pos ({} bytes), shift_cache {}, leaf_shift_cache {}",
				prune_list.bitmap.cardinality(),
				prune_list.bitmap.get_serialized_size_in_bytes::<Portable>(),
				prune_list.shift_cache.len(),
				prune_list.leaf_shift_cache.len(),
			);
		}

		Ok(prune_list)
	}

	/// Init our internal shift caches.
	pub fn init_caches(&mut self) -> Result<(), Error> {
		self.build_shift_cache()?;
		self.build_leaf_shift_cache()?;
		Ok(())
	}

	/// Save the prune_list to disk.
	pub fn flush(&mut self) -> io::Result<()> {
		// Run the optimization step on the bitmap.
		self.bitmap.run_optimize();

		// Write the updated bitmap file to disk.
		if let Some(ref path) = self.path {
			save_via_temp_file(path, ".tmp", |file| {
				file.write_all(&self.bitmap.serialize::<Portable>())
			})?;
		}

		self.bitmap_bak = self.bitmap.clone();
		Ok(())
	}

	/// Discard in-memory changes since the last successful flush.
	pub fn discard(&mut self) -> Result<(), Error> {
		self.restore(self.bitmap_bak.clone())
	}

	/// Restore the prune list from a previously captured bitmap.
	pub(crate) fn restore(&mut self, bitmap: Bitmap) -> Result<(), Error> {
		if bitmap.contains(0) {
			return Err(Error::InternalError("bitmap contains unexpected 0".into()));
		}
		self.bitmap = bitmap;
		self.init_caches()
	}

	/// Return the total shift from all entries in the prune_list.
	/// This is the shift we need to account for when adding new entries to our PMMR.
	pub fn get_total_shift(&self) -> Result<u64, Error> {
		self.get_shift(self.get_last_bitmap_idx()?)
	}

	/// Return the total leaf_shift from all entries in the prune_list.
	/// This is the leaf_shift we need to account for when adding new entries to our PMMR.
	pub fn get_total_leaf_shift(&self) -> Result<u64, Error> {
		self.get_leaf_shift(self.get_last_bitmap_idx()?)
	}

	/// Computes by how many positions a node at pos should be shifted given the
	/// number of nodes that have already been pruned before it.
	/// Note: the node at pos may be pruned and may be compacted away itself and
	/// the caller needs to be aware of this.
	pub fn get_shift(&self, pos0: u64) -> Result<u64, Error> {
		let pos0plus = Self::calc_pos_plus(pos0, "get_shift", "pos0")?;

		let idx = self.bitmap.rank(pos0plus);
		if idx == 0 {
			return Ok(0);
		}

		Self::get_cache(&self.shift_cache, idx)
	}

	fn build_shift_cache(&mut self) -> Result<(), Error> {
		self.shift_cache.clear();
		for pos1 in self.bitmap.iter() {
			if pos1 == 0 {
				return Err(Error::InternalError("bitmap contains unexpected 0".into()));
			}
			// Safe: pos1 was checked to be non-zero before subtracting one.
			let pos0 = u64::from(pos1 - 1);
			let prev_shift = if pos0 == 0 {
				0
			} else {
				self.get_shift(pos0 - 1)?
			};

			let curr_shift = if self.is_pruned_root(pos0)? {
				let height = bintree_postorder_height(pos0);
				if height > 63 {
					return Err(Error::DataOverflow(format!(
						"PruneList::build_shift_cache, height={}",
						height
					)));
				}
				// Safe: height is checked above to be at most 63, so the shift,
				// subtract, and doubling stay within u64.
				2 * ((1u64 << height) - 1)
			} else {
				0
			};

			self.shift_cache
				.push(prev_shift.checked_add(curr_shift).ok_or_else(|| {
					Error::DataOverflow(format!(
						"PruneList::build_shift_cache, prev_shift={} curr_shift={}",
						prev_shift, curr_shift
					))
				})?);
		}
		Ok(())
	}

	/// As above, but only returning the number of leaf nodes to skip for a
	/// given leaf. Helpful if, for instance, data for each leaf is being stored
	/// separately in a continuous flat-file.
	pub fn get_leaf_shift(&self, pos0: u64) -> Result<u64, Error> {
		let pos0plus = Self::calc_pos_plus(pos0, "get_leaf_shift", "pos0")?;
		let idx = self.bitmap.rank(pos0plus);
		if idx == 0 {
			return Ok(0);
		}
		Self::get_cache(&self.leaf_shift_cache, idx)
	}

	fn build_leaf_shift_cache(&mut self) -> Result<(), Error> {
		self.leaf_shift_cache.clear();
		for pos1 in self.bitmap.iter() {
			if pos1 == 0 {
				return Err(Error::InternalError("bitmap contains unexpected 0".into()));
			}
			// Safe: pos1 was checked to be non-zero before subtracting one.
			let pos0 = u64::from(pos1 - 1);
			let prev_shift = if pos0 == 0 {
				0
			} else {
				self.get_leaf_shift(pos0 - 1)?
			};

			let curr_shift = Self::leaf_shift_for_pruned_root(pos0, "build_leaf_shift_cache")?;

			self.leaf_shift_cache
				.push(prev_shift.checked_add(curr_shift).ok_or_else(|| {
					Error::DataOverflow(format!(
						"PruneList::build_leaf_shift_cache, prev_shift={} curr_shift={}",
						prev_shift, curr_shift
					))
				})?);
		}
		Ok(())
	}

	fn shift_for_pruned_root(pos0: u64, method_name: &str) -> Result<u64, Error> {
		let height = bintree_postorder_height(pos0);
		if height > 63 {
			return Err(Error::DataOverflow(format!(
				"PruneList::{}, pos0={} height={}",
				method_name, pos0, height
			)));
		}
		// Safe: height is checked above to be at most 63, so the shift,
		// subtract, and doubling stay within u64.
		Ok(2 * ((1u64 << height) - 1))
	}

	fn leaf_shift_for_pruned_root(pos0: u64, method_name: &str) -> Result<u64, Error> {
		let height = bintree_postorder_height(pos0);
		if height > 63 {
			return Err(Error::DataOverflow(format!(
				"PruneList::{}, pos0={} height={}",
				method_name, pos0, height
			)));
		}
		if height == 0 {
			Ok(0)
		} else {
			// Safe: height is checked above to be in 1..=63.
			Ok(1u64 << height)
		}
	}

	// Plan removal of existing entries in shift_cache and leaf_shift_cache
	// for any pos contained in the subtree with provided root.
	fn cleanup_subtree_plan(&self, pos0: u64) -> Result<Option<(usize, u32, u32)>, Error> {
		let leftmost = bintree_leftmost(pos0)?;
		let lc0 = u32::try_from(leftmost).map_err(|_| {
			Error::DataOverflow(format!(
				"PruneList::cleanup_subtree_plan, pos0={} leftmost={}",
				pos0, leftmost
			))
		})?;

		let size = self.bitmap.maximum().unwrap_or(0);

		// If this subtree does not intersect with existing bitmap then nothing to cleanup.
		if lc0 >= size {
			return Ok(None);
		}

		// Note: We will treat this as a "closed range" below (croaring api weirdness).
		// Note: After croaring upgrade to 1.0.2 we provide an inclusive range directly
		let lc0plus1 = lc0.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("PruneList::cleanup_subtree_plan, lc0={}", lc0))
		})?;

		// Find point where we can truncate based on bitmap "rank" (index) of pos to the left of subtree.
		let idx = self.bitmap.rank(lc0);
		let idx = usize::try_from(idx).map_err(|_| {
			Error::DataOverflow(format!("PruneList::cleanup_subtree_plan, idx={}", idx))
		})?;
		Ok(Some((idx, lc0plus1, size)))
	}

	fn apply_cleanup_subtree(&mut self, cleanup: Option<(usize, u32, u32)>) {
		let Some((idx, start, end)) = cleanup else {
			return;
		};
		self.shift_cache.truncate(idx);
		self.leaf_shift_cache.truncate(idx);
		self.bitmap.remove_range(start..=end);
	}

	/// Push the node at the provided position in the prune list.
	/// Assumes rollup of siblings and children has already been handled.
	fn append_single_values(
		&self,
		pos0: u64,
		cleanup: Option<(usize, u32, u32)>,
	) -> Result<(u32, u64, u64), Error> {
		if pos0 < u64::from(self.bitmap.maximum().unwrap_or(0)) {
			return Err(Error::InternalError("prune list is append only".into()));
		}

		let pos0plus = Self::calc_pos_plus(pos0, "append_single", "pos0")?;
		let idx = cleanup
			.map(|(idx, _, _)| idx)
			.unwrap_or_else(|| self.shift_cache.len());
		let prev_shift = if idx == 0 {
			0
		} else {
			*self.shift_cache.get(idx - 1).ok_or_else(|| {
				Error::DataCorruption(format!("PruneList::append_single, shift idx={}", idx))
			})?
		};
		let prev_leaf_shift = if idx == 0 {
			0
		} else {
			*self.leaf_shift_cache.get(idx - 1).ok_or_else(|| {
				Error::DataCorruption(format!("PruneList::append_single, leaf shift idx={}", idx))
			})?
		};

		let shift = prev_shift
			.checked_add(Self::shift_for_pruned_root(pos0, "append_single")?)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"PruneList::append_single, pos0={} prev_shift={}",
					pos0, prev_shift
				))
			})?;
		let leaf_shift = prev_leaf_shift
			.checked_add(Self::leaf_shift_for_pruned_root(pos0, "append_single")?)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"PruneList::append_single, pos0={} prev_leaf_shift={}",
					pos0, prev_leaf_shift
				))
			})?;

		Ok((pos0plus, shift, leaf_shift))
	}

	fn append_single(&mut self, pos0plus: u32, shift: u64, leaf_shift: u64) {
		self.bitmap.add(pos0plus);
		self.shift_cache.push(shift);
		self.leaf_shift_cache.push(leaf_shift);
	}

	/// Push the node at the provided position in the prune list.
	/// Handles rollup of siblings and children as we go (relatively slow).
	/// Once we find a subtree root that can not be rolled up any further
	/// we cleanup everything beneath it and replace it with a single appended node.
	pub fn append(&mut self, pos0: u64) -> Result<(), Error> {
		let max = u64::from(self.bitmap.maximum().unwrap_or(0));
		if pos0 < max {
			return Err(Error::InternalError(format!(
				"prune list append only - pos={} bitmap.maximum={}",
				pos0, max
			)));
		}

		let (parent0, sibling0) = family(pos0)?;
		if self.is_pruned(sibling0)? {
			// Recursively append the parent (removing our sibling in the process).
			self.append(parent0)?
		} else {
			// Make sure we roll anything beneath this up into this higher level pruned subtree root.
			// We should have no nested entries in the prune_list.
			let cleanup = self.cleanup_subtree_plan(pos0)?;
			let (pos0plus, shift, leaf_shift) = self.append_single_values(pos0, cleanup)?;
			self.apply_cleanup_subtree(cleanup);
			self.append_single(pos0plus, shift, leaf_shift);
		}
		Ok(())
	}

	/// Push the exact node at the provided position in the prune list.
	/// Handles nested child cleanup, but does not roll up pruned siblings into
	/// an ancestor. This is used when the hash file already contains the exact
	/// physical hashes for an imported pruned subtree.
	pub(crate) fn append_exact(&mut self, pos0: u64) -> Result<(), Error> {
		let max = u64::from(self.bitmap.maximum().unwrap_or(0));
		if pos0 < max {
			return Err(Error::InternalError(format!(
				"prune list append only - pos={} bitmap.maximum={}",
				pos0, max
			)));
		}

		let cleanup = self.cleanup_subtree_plan(pos0)?;
		let (pos0plus, shift, leaf_shift) = self.append_single_values(pos0, cleanup)?;
		self.apply_cleanup_subtree(cleanup);
		self.append_single(pos0plus, shift, leaf_shift);
		Ok(())
	}

	/// Number of entries in the prune_list.
	pub fn len(&self) -> u64 {
		self.bitmap.cardinality()
	}

	/// Is the prune_list empty?
	pub fn is_empty(&self) -> bool {
		self.bitmap.is_empty()
	}

	/// A pos is pruned if it is a pruned root directly or if it is
	/// beneath the "next" pruned subtree.
	/// We only need to consider the "next" subtree due to the append-only MMR structure.
	pub fn is_pruned(&self, pos0: u64) -> Result<bool, Error> {
		if self.is_pruned_root(pos0)? {
			return Ok(true);
		}
		let pos_plus =
			u32::try_from(pos0.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!("PruneList::is_pruned, pos0={}", pos0))
			})?)
			.map_err(|_| Error::DataOverflow(format!("PruneList::is_pruned, pos0={}", pos0)))?;
		let rank = self.bitmap.rank(pos_plus);
		let rank = u32::try_from(rank)
			.map_err(|_| Error::DataOverflow(format!("PruneList::is_pruned, rank={}", rank)))?;
		if let Some(root) = self.bitmap.select(rank) {
			let root_minus_1 = u64::from(root).checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!("PruneList::is_pruned, root={}", root))
			})?;
			let range = pmmr::bintree_range(root_minus_1)?;
			Ok(range.contains(&pos0))
		} else {
			Ok(false)
		}
	}

	/// Convert the prune_list to a vec of pos.
	pub fn to_vec(&self) -> Vec<u64> {
		self.bitmap.iter().map(u64::from).collect()
	}

	/// Internal shift cache as slice.
	/// only used in store/tests/prune_list.rs tests
	pub fn shift_cache(&self) -> &[u64] {
		self.shift_cache.as_slice()
	}

	/// Internal leaf shift cache as slice.
	/// only used in store/tests/prune_list.rs tests
	pub fn leaf_shift_cache(&self) -> &[u64] {
		self.leaf_shift_cache.as_slice()
	}

	/// Is the specified position a root of a pruned subtree?
	pub fn is_pruned_root(&self, pos0: u64) -> Result<bool, Error> {
		let pos0plus = Self::calc_pos_plus(pos0, "is_pruned_root", "pos0")?;
		Ok(self.bitmap.contains(pos0plus))
	}

	/// Iterator over the entries in the prune list (pruned roots).
	pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
		self.bitmap.iter().map(u64::from)
	}

	/// Iterator over the pruned "bintree range" for each pruned root.
	pub fn pruned_bintree_range_iter(
		&self,
	) -> impl Iterator<Item = Result<Range<u64>, Error>> + '_ {
		self.iter().map(|x| {
			if x == 0 {
				return Err(Error::DataCorruption("pruned position is zero".into()));
			}
			let rng = pmmr::bintree_range(x - 1)?;
			let start = rng.start.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"PruneList::pruned_bintree_range_iter, range_start={}",
					rng.start
				))
			})?;
			let end = rng.end.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"PruneList::pruned_bintree_range_iter, range_end={}",
					rng.end
				))
			})?;
			Ok(start..end)
		})
	}

	/// Iterator over all pos that are *not* pruned based on current prune_list.
	pub fn unpruned_iter(&self, cutoff_pos: u64) -> Result<impl Iterator<Item = u64> + '_, Error> {
		let ranges: Vec<Range<u64>> = self
			.pruned_bintree_range_iter()
			.collect::<Result<Vec<Range<u64>>, Error>>()?;

		Ok(UnprunedIterator::new(ranges.into_iter()).take_while(move |x| *x <= cutoff_pos))
	}

	/// Iterator over all leaf pos that are *not* pruned based on current prune_list.
	/// Note this is not necessarily the same as the "leaf_set" as an output
	/// can be spent but not yet pruned.
	pub fn unpruned_leaf_iter(
		&self,
		cutoff_pos: u64,
	) -> Result<impl Iterator<Item = u64> + '_, Error> {
		Ok(self.unpruned_iter(cutoff_pos)?.filter(|x| {
			if *x == 0 {
				false
			} else {
				pmmr::is_leaf(*x - 1)
			}
		}))
	}

	/// Return a clone of our internal bitmap.
	pub fn bitmap(&self) -> Bitmap {
		self.bitmap.clone()
	}

	#[inline]
	fn calc_pos_plus(pos: u64, method_name: &str, var_name: &str) -> Result<u32, Error> {
		let pos = u32::try_from(pos).map_err(|_| {
			Error::DataOverflow(format!("PruneList::{}, {}={}", method_name, var_name, pos))
		})?;
		let pos_plus = pos.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("PruneList::{}, {}={}", method_name, var_name, pos))
		})?;
		Ok(pos_plus)
	}

	#[inline]
	fn get_cache(cache: &Vec<u64>, idx: u64) -> Result<u64, Error> {
		let idx: usize = usize::try_from(idx)
			.map_err(|_| Error::DataOverflow(format!("PruneList::get_cache, idx={}", idx)))?;
		if idx < 1 {
			return Err(Error::InternalError(
				"PruneList::get_cache invalid zero index".into(),
			));
		}
		if idx > cache.len() {
			return Err(Error::InternalError(format!(
				"PruneList::get_cache cache shorter than bitmap rank, idx={} cache_len={}",
				idx,
				cache.len()
			)));
		}
		Ok(cache[idx - 1])
	}

	#[inline]
	fn get_last_bitmap_idx(&self) -> Result<u64, Error> {
		let max = self.bitmap.maximum().unwrap_or(1);
		if max == 0 {
			return Err(Error::InternalError("bitmap contains unexpected 0".into()));
		}
		// Safe: max was checked to be non-zero before subtracting one.
		Ok(u64::from(max - 1))
	}
}

struct UnprunedIterator<I> {
	inner: I,
	current_excl_range: Option<Range<u64>>,
	current_pos: u64,
	done: bool,
}

impl<I: Iterator<Item = Range<u64>>> UnprunedIterator<I> {
	fn new(mut inner: I) -> UnprunedIterator<I> {
		let current_excl_range = inner.next();
		UnprunedIterator {
			inner,
			current_excl_range,
			current_pos: 1,
			done: false,
		}
	}
}

impl<I: Iterator<Item = Range<u64>>> Iterator for UnprunedIterator<I> {
	type Item = u64;

	fn next(&mut self) -> Option<Self::Item> {
		if self.done {
			return None;
		}

		loop {
			if let Some(range) = &self.current_excl_range {
				if self.current_pos < range.start {
					let next = self.current_pos;
					self.current_pos = match self.current_pos.checked_add(1) {
						Some(current_pos) => current_pos,
						None => {
							self.done = true;
							return Some(next);
						}
					};
					return Some(next);
				}

				// Skip excluded ranges iteratively. Consecutive excluded ranges can
				// be numerous, so recursive next() calls can exhaust the stack.
				if self.current_pos < range.end {
					self.current_pos = range.end;
				}
				self.current_excl_range = self.inner.next();
			} else {
				let next = self.current_pos;
				self.current_pos = match self.current_pos.checked_add(1) {
					Some(current_pos) => current_pos,
					None => {
						self.done = true;
						return Some(next);
					}
				};
				return Some(next);
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn get_cache_rejects_rank_beyond_cache_len() {
		match PruneList::get_cache(&vec![5], 2).unwrap_err() {
			Error::InternalError(msg) => assert!(msg.contains("cache shorter than bitmap rank")),
			other => panic!("expected InternalError, got {:?}", other),
		}
	}

	#[test]
	fn unpruned_iterator_skips_consecutive_ranges_iteratively() {
		let ranges = (1..20_000).map(|pos| pos..pos + 1).collect::<Vec<_>>();
		let mut iter = UnprunedIterator::new(ranges.into_iter());
		assert_eq!(iter.next(), Some(20_000));
		assert_eq!(iter.next(), Some(20_001));
	}
}
