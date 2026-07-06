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

//! Readonly view of a PMMR.

use std::convert::TryFrom;
use std::marker;

use crate::core::hash::Hash;
use crate::core::pmmr::pmmr::{bintree_rightmost, n_leaves, ReadablePMMR};
use crate::core::pmmr::{is_leaf, Backend, Error};
use crate::ser::PMMRable;

/// Readonly view of a PMMR.
pub struct ReadonlyPMMR<'a, T, B>
where
	T: PMMRable,
	B: Backend<T>,
{
	/// The last position in the PMMR
	size: u64,
	/// The backend for this readonly PMMR
	backend: &'a B,
	// only needed to parameterise Backend
	_marker: marker::PhantomData<T>,
}

impl<'a, T, B> ReadonlyPMMR<'a, T, B>
where
	T: PMMRable,
	B: 'a + Backend<T>,
{
	/// Build a new readonly PMMR.
	pub fn new(backend: &'a B) -> ReadonlyPMMR<'a, T, B> {
		ReadonlyPMMR {
			backend,
			size: 0,
			_marker: marker::PhantomData,
		}
	}

	/// Build a new readonly PMMR pre-initialized to
	/// size with the provided backend.
	pub fn at(backend: &'a B, size: u64) -> ReadonlyPMMR<'a, T, B> {
		ReadonlyPMMR {
			backend,
			size,
			_marker: marker::PhantomData,
		}
	}

	/// Helper function which returns un-pruned nodes from the insertion index
	/// forward. Each returned element is paired with its 1-based PMMR index.
	/// Returns the terminal PMMR scan index along with indexed data.
	pub fn elements_from_pmmr_index(
		&self,
		pmmr_index1: u64,
		max_count: u64,
		max_pmmr_pos1: Option<u64>,
	) -> Result<(u64, Vec<(u64, T::E)>), Error> {
		let mut return_vec = vec![];
		let size = max_pmmr_pos1.unwrap_or(self.size).min(self.size);
		let pmmr_index = pmmr_index1.checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"ReadonlyPMMR::elements_from_pmmr_index, pmmr_index1={}",
				pmmr_index1
			))
		})?;
		let max_count = usize::try_from(max_count).map_err(|_| {
			Error::DataOverflow(format!(
				"ReadonlyPMMR::elements_from_pmmr_index, max_count={}",
				max_count
			))
		})?;

		if max_count == 0 || pmmr_index >= size {
			return Ok((pmmr_index, return_vec));
		}

		for pos0 in self.backend.leaf_pos_iter_from(pmmr_index)? {
			let pos0 = pos0?;
			if pos0 >= size {
				break;
			}
			if let Some(t) = self.get_data(pos0)? {
				// Returned element indexes are 1-based PMMR indexes.
				let pos1 = pos0.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"ReadonlyPMMR::elements_from_pmmr_index, pmmr_index={}",
						pos0
					))
				})?;
				return_vec.push((pos1, t));
				if return_vec.len() == max_count {
					return Ok((pos1, return_vec));
				}
			}
		}
		Ok((size, return_vec))
	}

	/// Helper function to get up to n unpruned leaf entries by scanning
	/// backward along the bottom of the tree.
	/// Pruned/compacted leaves do not count toward n, so this may scan farther
	/// back than n historical insertions and may return entries older than the
	/// most recent n insertion positions.
	/// May return less than n items if the scan reaches the start of the MMR.
	/// NOTE This should just iterate over insertion indices
	/// to avoid the repeated calls to bintree_rightmost!
	pub fn get_last_n_insertions(&self, n: u64) -> Result<Vec<(Hash, T::E)>, Error> {
		let mut return_vec = vec![];
		let mut last_leaf = self.size;
		while (return_vec.len() as u64) < n && last_leaf > 0 {
			let prev_pos = last_leaf.checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"ReadonlyPMMR::get_last_n_insertions, last_leaf={}",
					last_leaf
				))
			})?;
			last_leaf = bintree_rightmost(prev_pos)?;

			if let Some(hash) = self.backend.get_hash(last_leaf)? {
				if let Some(data) = self.backend.get_data(last_leaf)? {
					return_vec.push((hash, data));
				}
			}
		}
		Ok(return_vec)
	}
}

impl<'a, T, B> ReadablePMMR for ReadonlyPMMR<'a, T, B>
where
	T: PMMRable,
	B: 'a + Backend<T>,
{
	type Item = T::E;

	fn get_context_id(&self) -> u32 {
		self.backend.get_context_id()
	}

	fn get_hash(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		if pos0 >= self.size {
			Ok(None)
		} else if is_leaf(pos0) {
			// If we are a leaf then get hash from the backend.
			self.backend.get_hash(pos0)
		} else {
			// If we are not a leaf get hash ignoring the remove log.
			match self.backend.get_from_file(pos0)? {
				Some(hash) => Ok(Some(hash)),
				None if self.backend.is_compacted(pos0)? => Ok(None),
				None => Err(Error::DataCorruption(format!(
					"Missing non-compacted PMMR hash at position {}.",
					pos0
				))),
			}
		}
	}

	fn get_data(&self, pos0: u64) -> Result<Option<Self::Item>, Error> {
		if pos0 >= self.size {
			// If we are beyond the rhs of the MMR return None.
			Ok(None)
		} else if is_leaf(pos0) {
			// If we are a leaf then get data from the backend.
			self.backend.get_data(pos0)
		} else {
			// If we are not a leaf then return None as only leaves have data.
			Ok(None)
		}
	}

	fn get_from_file(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		if pos0 >= self.size {
			Ok(None)
		} else {
			self.backend.get_from_file(pos0)
		}
	}

	fn get_peak_from_file(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		if pos0 >= self.size {
			Ok(None)
		} else {
			self.backend.get_peak_from_file(pos0)
		}
	}

	fn get_data_from_file(&self, pos0: u64) -> Result<Option<Self::Item>, Error> {
		if pos0 >= self.size {
			Ok(None)
		} else if !is_leaf(pos0) {
			Ok(None)
		} else {
			self.backend.get_data_from_file(pos0)
		}
	}

	fn unpruned_size(&self) -> u64 {
		self.size
	}

	fn leaf_pos_iter(&self) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error> {
		let size = self.size;
		Ok(Box::new(self.backend.leaf_pos_iter()?.filter(
			move |pos| match pos {
				Ok(pos) => *pos < size,
				Err(_) => true,
			},
		)))
	}

	fn n_unpruned_leaves_to_index(&self, to_index: u64) -> Result<u64, Error> {
		let to_index = to_index.min(n_leaves(self.size)?);
		self.backend.n_unpruned_leaves_to_index(to_index)
	}
}
