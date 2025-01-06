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

use std::collections::BTreeSet;
use std::convert::TryFrom;

use croaring::Bitmap;

use crate::core::hash::Hash;
use crate::core::pmmr::{self, Backend};
use crate::core::BlockHeader;
use crate::ser::PMMRable;

/// Simple/minimal/naive MMR backend implementation backed by Vec<T> and Vec<Hash>.
/// Removed pos are maintained in a HashSet<u64>.
#[derive(Clone, Debug)]
pub struct VecBackend<T: PMMRable> {
	/// Backend elements (optional, possible to just store hashes).
	pub data: Option<Vec<Option<T>>>,
	/// Vec of hashes for the PMMR (both leaves and parents).
	pub hashes: Vec<Option<Hash>>,
}

impl<T: PMMRable> Backend<T> for VecBackend<T> {
	fn append(&mut self, elmt: &T, hashes: &[Hash]) -> Result<(), String> {
		if let Some(data) = &mut self.data {
			data.push(Some(elmt.clone()));
		}
		for h in hashes {
			self.hashes.push(Some(h.clone()));
		}
		Ok(())
	}

	fn append_pruned_subtree(&mut self, hash: Hash, pos0: u64) -> Result<(), String> {
		let idx = usize::try_from(pos0).expect("usize from u64");

		if self.hashes.len() < idx {
			self.hashes.resize(idx + 1, None);
		}
		self.hashes[idx] = Some(hash);

		let leaves = pmmr::n_leaves(1 + pos0);
		if let Some(data) = &mut self.data {
			debug_assert!(data.len() < leaves as usize);
			if data.len() < leaves as usize {
				data.resize(leaves as usize, None);
			}
		}

		Ok(())
	}

	fn append_hash(&mut self, hash: Hash) -> Result<(), String> {
		self.hashes.push(Some(hash));

		Ok(())
	}

	fn get_hash(&self, pos0: u64) -> Option<Hash> {
		self.get_from_file(pos0)
	}

	fn get_data(&self, pos0: u64) -> Option<T::E> {
		self.get_data_from_file(pos0)
	}

	fn get_from_file(&self, pos0: u64) -> Option<Hash> {
		let idx = usize::try_from(pos0).expect("usize from u64");
		match self.hashes.get(idx) {
			Some(h) => h.clone(),
			None => None,
		}
	}

	fn get_peak_from_file(&self, pos0: u64) -> Option<Hash> {
		self.get_from_file(pos0)
	}

	fn get_data_from_file(&self, pos0: u64) -> Option<T::E> {
		if let Some(data) = &self.data {
			let idx = usize::try_from(pmmr::n_leaves(1 + pos0) - 1).expect("usize from u64");
			match data.get(idx) {
				Some(d) => d.clone().map(|x| x.as_elmt()),
				None => None,
			}
		} else {
			None
		}
	}

	/// Number of leaves in the MMR
	fn n_unpruned_leaves(&self) -> u64 {
		unimplemented!()
	}

	fn n_unpruned_leaves_to_index(&self, _to_index: u64) -> u64 {
		unimplemented!()
	}

	fn leaf_pos_iter(&self) -> Box<dyn Iterator<Item = u64> + '_> {
		Box::new(
			self.hashes
				.iter()
				.enumerate()
				.map(|(x, _)| x as u64)
				.filter(move |x| pmmr::is_leaf(*x)),
		)
	}

	/// NOTE this function is needlessly inefficient with repeated calls to n_leaves()
	fn leaf_idx_iter(&self, from_idx: u64) -> Box<dyn Iterator<Item = u64> + '_> {
		let from_pos = pmmr::insertion_to_pmmr_index(from_idx);
		Box::new(
			self.leaf_pos_iter()
				.skip_while(move |x| *x < from_pos)
				.map(|x| pmmr::n_leaves(x + 1) - 1),
		)
	}

	fn remove(&mut self, pos0: u64) -> Result<(), String> {
		if let Some(data) = &mut self.data {
			let idx = usize::try_from(pmmr::n_leaves(1 + pos0) - 1).expect("usize from u64");
			data[idx] = None;
		}
		Ok(())
	}

	//fn remove_from_leaf_set(&mut self, _pos0: u64) {
	//	unimplemented!()
	//}

	fn reset_prune_list(&mut self) {
		unimplemented!()
	}

	fn rewind(&mut self, position: u64, _rewind_rm_pos: &Bitmap) -> Result<(), String> {
		if let Some(data) = &mut self.data {
			let idx = pmmr::n_leaves(position);
			data.truncate(usize::try_from(idx).expect("usize from u64"));
		}
		self.hashes
			.truncate(usize::try_from(position).expect("usize from u64"));
		Ok(())
	}

	fn snapshot(&self, _header: &BlockHeader) -> Result<(), String> {
		Ok(())
	}

	fn release_files(&mut self) {}

	fn dump_stats(&self) {}
}

impl<T: PMMRable> VecBackend<T> {
	/// Instantiates a new empty vec backend.
	pub fn new() -> VecBackend<T> {
		VecBackend {
			data: Some(vec![]),
			hashes: vec![],
		}
	}

	/// Instantiate a new empty "hash only" vec backend.
	pub fn new_hash_only() -> VecBackend<T> {
		VecBackend {
			data: None,
			hashes: vec![],
		}
	}

	/// Size of this vec backend in hashes.
	pub fn size(&self) -> u64 {
		self.hashes.len() as u64
	}

	/// Reset backend data
	pub fn reset(&mut self) {
		if let Some(data) = self.data.as_mut() {
			data.clear();
		}
		self.hashes.clear();
	}

	///  It is expected that all needed leaves are pruned, now we need to update the hashes. Data is still expected to be in pairs because
	/// of overall node limitations.
	pub fn compact(&mut self, delete_buildable_hashes: bool) {
		if let Some(data) = self.data.as_mut() {
			if self.hashes.is_empty() {
				return;
			}

			let top_hash = self.hashes.last().expect("Segment can't be empty").clone();

			let mut leaves: BTreeSet<u64> = BTreeSet::new();
			for (pos, dt) in data.iter().enumerate() {
				if dt.is_some() {
					leaves.insert(pmmr::insertion_to_pmmr_index(pos as u64));
				}
			}

			let mut pos_with_data: BTreeSet<u64> = BTreeSet::new();
			for pos0 in 0..self.hashes.len() as u64 {
				let left_leaf = pmmr::bintree_leftmost(pos0);
				if leaves.range(left_leaf..=pos0).next().is_some() {
					pos_with_data.insert(pos0);
				}
			}

			// Now we need to keep all with parent that has a data
			for pos0 in 0..self.hashes.len() as u64 {
				if pos_with_data.contains(&pos0) {
					continue;
				}

				let (parent, _) = pmmr::family(pos0);
				// Top Hashes we want to keep in any case
				if pos_with_data.contains(&parent) || parent > self.hashes.len() as u64 {
					pos_with_data.insert(pos0);
				}
			}

			// Now we can delete all hashes that are not in the pos_with_data list
			for (pos, h) in &mut self.hashes.iter_mut().enumerate() {
				let pos = pos as u64;
				if !pos_with_data.contains(&pos) {
					*h = None;
				}
			}

			if pos_with_data.is_empty() {
				*self.hashes.last_mut().expect("Segment can't be empty") = top_hash;
			}

			if delete_buildable_hashes {
				for pos in 0..self.hashes.len() as u64 {
					if let Some((left_child, right_child)) = pmmr::children(pos) {
						let has_left_child = self
							.hashes
							.get(left_child as usize)
							.unwrap_or(&None)
							.is_some() || leaves.contains(&left_child);
						let has_right_child = self
							.hashes
							.get(right_child as usize)
							.unwrap_or(&None)
							.is_some() || leaves.contains(&right_child);

						if has_left_child && has_right_child {
							self.hashes[pos as usize] = None;
						}
					}
				}
			}
		}
	}
}
