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

use mwc_crates::croaring::Bitmap;
use mwc_crates::log::error;

use crate::core::hash::Hash;
use crate::core::pmmr::{self, Backend, Error};
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
	/// Positions where a missing hash is expected after local compaction.
	compacted: BTreeSet<u64>,
	/// Leaf positions removed from the logical PMMR view.
	removed: BTreeSet<u64>,
	context_id: u32,
}

/// Tail state split off from a VecBackend so callers can restore after a
/// fallible in-place rebuild.
pub struct VecBackendTail<T: PMMRable> {
	position: u64,
	hash_idx: usize,
	data_idx: Option<usize>,
	data: Option<Vec<Option<T>>>,
	hashes: Vec<Option<Hash>>,
	compacted: BTreeSet<u64>,
	removed: BTreeSet<u64>,
}

impl<T: PMMRable> Backend<T> for VecBackend<T> {
	fn get_context_id(&self) -> u32 {
		self.context_id
	}

	fn append(&mut self, elmt: &T, hashes: &[Hash]) -> Result<(), Error> {
		if let Some(data) = &mut self.data {
			data.push(Some(elmt.clone()));
		}
		for h in hashes {
			let pos0 = self.hashes.len() as u64;
			self.hashes.push(Some(h.clone()));
			self.compacted.remove(&pos0);
			self.removed.remove(&pos0);
		}
		Ok(())
	}

	fn append_pruned_subtree(&mut self, hash: Hash, pos0: u64) -> Result<(), Error> {
		let idx = usize::try_from(pos0).map_err(|_| {
			Error::DataOverflow(format!("VecBackend::append_pruned_subtree, pos0={}", pos0))
		})?;
		let len = idx.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("VecBackend::append_pruned_subtree, idx={}", idx))
		})?;
		let subtree_range = pmmr::bintree_range(pos0)?;
		let pos1 = pos0.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("VecBackend::append_pruned_subtree, pos0={}", pos0))
		})?;
		let leaves = pmmr::n_leaves(pos1)?;
		let data_leaves = if let Some(data) = self.data.as_ref() {
			let data_len = u64::try_from(data.len()).map_err(|_| {
				Error::DataOverflow(format!(
					"VecBackend::append_pruned_subtree, data_len={}",
					data.len()
				))
			})?;
			if data_len > leaves {
				return Err(Error::SerializationError(
					"VecBackend data is out of capacity".into(),
				));
			}
			Some(usize::try_from(leaves).map_err(|_| {
				Error::DataOverflow(format!(
					"VecBackend::append_pruned_subtree, leaves={}",
					leaves
				))
			})?)
		} else {
			None
		};

		if self.hashes.len() < len {
			self.hashes.resize(len, None);
		}
		self.hashes[idx] = Some(hash);
		self.compacted.remove(&pos0);
		self.removed.remove(&pos0);
		for pos in subtree_range {
			if pos != pos0 {
				self.compacted.insert(pos);
			}
		}

		if let (Some(data), Some(leaves)) = (&mut self.data, data_leaves) {
			if data.len() < leaves {
				data.resize(leaves, None);
			}
		}

		Ok(())
	}

	fn append_pruned_subtree_hashes(
		&mut self,
		hash: Hash,
		pos0: u64,
		hashes: &[Hash],
	) -> Result<(), Error> {
		let mut next = self.clone();
		next.append_pruned_subtree(hash, pos0)?;
		for hash in hashes {
			next.append_hash(*hash)?;
		}
		*self = next;
		Ok(())
	}

	fn append_hash(&mut self, hash: Hash) -> Result<(), Error> {
		let pos0 = self.hashes.len() as u64;
		self.hashes.push(Some(hash));
		self.compacted.remove(&pos0);
		self.removed.remove(&pos0);

		Ok(())
	}

	fn get_hash(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		if pmmr::is_leaf(pos0) {
			if self.removed.contains(&pos0) {
				return Ok(None);
			}
			if let Some(data) = &self.data {
				let pos1 = pos0.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!("VecBackend::get_hash, pos0={}", pos0))
				})?;
				let leaf_idx = pmmr::n_leaves(pos1)?.checked_sub(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"VecBackend::get_hash, pmmr::n_leaves for pos1={}",
						pos1
					))
				})?;
				let leaf_idx = usize::try_from(leaf_idx).map_err(|_| {
					Error::DataOverflow(format!("VecBackend::get_hash, leaf_idx={}", leaf_idx))
				})?;
				if !data.get(leaf_idx).map(|x| x.is_some()).unwrap_or(false) {
					return Ok(None);
				}
			} else if self.compacted.contains(&pos0) {
				return Ok(None);
			}
		}
		self.get_from_file(pos0)
	}

	fn get_data(&self, pos0: u64) -> Result<Option<T::E>, Error> {
		if pmmr::is_leaf(pos0) && self.removed.contains(&pos0) {
			return Ok(None);
		}
		self.get_data_from_file(pos0)
	}

	fn get_from_file(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		let idx = usize::try_from(pos0)
			.map_err(|_| Error::DataOverflow(format!("VecBackend::get_from_file pos0={}", pos0)))?;
		match self.hashes.get(idx) {
			Some(h) => Ok(h.clone()),
			None => Ok(None),
		}
	}

	fn is_compacted(&self, pos0: u64) -> Result<bool, Error> {
		Ok(self.compacted.contains(&pos0))
	}

	fn get_peak_from_file(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		self.get_from_file(pos0)
	}

	fn get_data_from_file(&self, pos0: u64) -> Result<Option<T::E>, Error> {
		if !pmmr::is_leaf(pos0) {
			return Ok(None);
		}
		if let Some(data) = &self.data {
			// idx = (pmmr::n_leaves(1 + pos0) - 1) as usize
			let pos1 = pos0.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!("VecBackend::get_data_from_file pos0={}", pos0))
			})?;
			let leaf_idx = pmmr::n_leaves(pos1)?.checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"VecBackend::get_data_from_file pmmr::n_leaves pos1={}",
					pos1
				))
			})?;
			let idx = usize::try_from(leaf_idx).map_err(|_| {
				Error::DataOverflow(format!(
					"VecBackend::get_data_from_file leaf_idx={}",
					leaf_idx
				))
			})?;
			match data.get(idx) {
				Some(d) => match d {
					Some(d) => match d.as_elmt() {
						Ok(d) => Ok(Some(d)),
						Err(e) => {
							error!("Data as_elmt conversion error: {}", e);
							return Err(Error::DataCorruption(format!(
								"Data as_elmt conversion error: {}",
								e
							)));
						}
					},
					None => Ok(None),
				},
				None => Ok(None),
			}
		} else {
			Ok(None)
		}
	}

	/// Number of leaves in the MMR
	fn n_unpruned_leaves(&self) -> Result<u64, Error> {
		Err(Error::InternalError(
			"n_unpruned_leaves is not implemented for VecBackend".into(),
		))
	}

	fn n_unpruned_leaves_to_index(&self, _to_index: u64) -> Result<u64, Error> {
		Err(Error::InternalError(
			"n_unpruned_leaves_to_index is not implemented for VecBackend".into(),
		))
	}

	fn leaf_pos_iter(&self) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error> {
		let mut leaf_pos = Vec::new();
		for (idx, hash) in self.hashes.iter().enumerate() {
			// Safe: in-memory vector indexes fit in u64 on supported targets.
			let pos0 = idx as u64;
			if !pmmr::is_leaf(pos0) {
				continue;
			}

			if let Some(data) = &self.data {
				let pos1 = pos0.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!("VecBackend::leaf_pos_iter, pos0={}", pos0))
				})?;
				let leaf_idx = pmmr::n_leaves(pos1)?.checked_sub(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"VecBackend::leaf_pos_iter, pmmr::n_leaves for pos1={}",
						pos1
					))
				})?;
				let leaf_idx = usize::try_from(leaf_idx).map_err(|_| {
					Error::DataOverflow(format!("VecBackend::leaf_pos_iter, leaf_idx={}", leaf_idx))
				})?;
				if data.get(leaf_idx).map(|x| x.is_some()).unwrap_or(false)
					&& !self.removed.contains(&pos0)
				{
					leaf_pos.push(Ok(pos0));
				}
			} else if hash.is_some()
				&& !self.compacted.contains(&pos0)
				&& !self.removed.contains(&pos0)
			{
				leaf_pos.push(Ok(pos0));
			}
		}
		Ok(Box::new(leaf_pos.into_iter()))
	}

	/// NOTE this function is needlessly inefficient with repeated calls to n_leaves()
	fn leaf_idx_iter(
		&self,
		from_idx: u64,
	) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error> {
		let from_pos = pmmr::insertion_to_pmmr_index(from_idx)?;
		Ok(Box::new(
			self.leaf_pos_iter()?
				.filter_map(move |pos| match pos {
					Ok(pos) => {
						if pos >= from_pos {
							Some(Ok(pos))
						} else {
							None
						}
					}
					Err(e) => Some(Err(e)),
				})
				.map(|pos| match pos {
					Ok(pos) => {
						let pos1 = pos.checked_add(1).ok_or_else(|| {
							Error::DataOverflow(format!("VecBackend::leaf_idx_iter, pos={}", pos))
						})?;
						pmmr::n_leaves(pos1)?.checked_sub(1).ok_or_else(|| {
							Error::DataOverflow(format!(
								"VecBackend::leaf_idx_iter, pmmr::n_leaves for pos1={}",
								pos1
							))
						})
					}
					Err(e) => Err(e),
				}),
		))
	}

	fn remove(&mut self, pos0: u64) -> Result<bool, Error> {
		if !pmmr::is_leaf(pos0) {
			return Err(Error::SerializationError(format!(
				"Node at {} is not a leaf, can't remove.",
				pos0
			)));
		}

		if self.get_hash(pos0)?.is_none() {
			return Ok(false);
		}

		Ok(self.removed.insert(pos0))
	}

	//fn remove_from_leaf_set(&mut self, _pos0: u64) {
	//	unimplemented!()
	//}

	fn reset_prune_list(&mut self) -> Result<(), Error> {
		Err(Error::InvalidState(
			"reset_prune_list is not supported by VecBackend".into(),
		))
	}

	fn rewind(&mut self, position: u64, rewind_rm_pos: &Bitmap) -> Result<(), Error> {
		self.detach_tail(position)?;
		for pos1 in rewind_rm_pos.iter() {
			if pos1 == 0 {
				continue;
			}
			let pos0 = u64::from(pos1 - 1);
			if pos0 < position && pmmr::is_leaf(pos0) {
				self.removed.remove(&pos0);
			}
		}
		Ok(())
	}

	fn snapshot(&self, _header: &BlockHeader) -> Result<(), Error> {
		Err(Error::NotSupported("VecBackend snapshot()".into()))
	}

	fn release_files(&mut self) {}

	fn dump_stats(&self) {}
}

impl<T: PMMRable> VecBackend<T> {
	/// Instantiates a new empty vec backend for a specific consensus context.
	pub fn new(context_id: u32) -> VecBackend<T> {
		VecBackend {
			data: Some(vec![]),
			hashes: vec![],
			compacted: BTreeSet::new(),
			removed: BTreeSet::new(),
			context_id,
		}
	}

	/// Instantiate a new empty "hash only" vec backend for a specific consensus context.
	pub fn new_hash_only(context_id: u32) -> VecBackend<T> {
		VecBackend {
			data: None,
			hashes: vec![],
			compacted: BTreeSet::new(),
			removed: BTreeSet::new(),
			context_id,
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
		self.compacted.clear();
		self.removed.clear();
	}

	fn rewind_indexes(&self, position: u64) -> Result<(usize, Option<usize>), Error> {
		let hash_size = self.hashes.len() as u64;
		if position > hash_size {
			return Err(Error::InvalidState(format!(
				"cannot rewind VecBackend hashes forward from {} to {}",
				hash_size, position
			)));
		}

		let data_idx = if let Some(data) = &self.data {
			let idx = pmmr::n_leaves(position)?;
			if idx > data.len() as u64 {
				return Err(Error::InvalidState(format!(
					"cannot rewind VecBackend data forward from {} to {}",
					data.len(),
					idx
				)));
			}
			Some(usize::try_from(idx).map_err(|_| {
				Error::SerializationError(format!("rewind invalid idx value: {}", idx))
			})?)
		} else {
			None
		};
		let hash_idx = usize::try_from(position).map_err(|_| {
			Error::SerializationError(format!("rewind invalid position value: {}", position))
		})?;

		Ok((hash_idx, data_idx))
	}

	/// Rewind to position, returning the detached suffix so it can be restored
	/// if a fallible rebuild fails after this point.
	pub fn detach_tail(&mut self, position: u64) -> Result<VecBackendTail<T>, Error> {
		let (hash_idx, data_idx) = self.rewind_indexes(position)?;
		let data = match (&mut self.data, data_idx) {
			(Some(data), Some(data_idx)) => Some(data.split_off(data_idx)),
			(None, None) => None,
			_ => {
				return Err(Error::InvalidState(
					"VecBackend data mode changed while detaching tail".into(),
				));
			}
		};
		let hashes = self.hashes.split_off(hash_idx);
		let compacted = self.compacted.split_off(&position);
		let removed = self.removed.split_off(&position);

		Ok(VecBackendTail {
			position,
			hash_idx,
			data_idx,
			data,
			hashes,
			compacted,
			removed,
		})
	}

	/// Restore a previously detached suffix, discarding anything appended after
	/// the detach point.
	pub fn restore_tail(&mut self, mut tail: VecBackendTail<T>) -> Result<(), Error> {
		if self.hashes.len() < tail.hash_idx {
			return Err(Error::InvalidState(format!(
				"cannot restore VecBackend hashes from {} to missing prefix {}",
				self.hashes.len(),
				tail.hash_idx
			)));
		}

		match (&self.data, &tail.data, tail.data_idx) {
			(Some(data), Some(_), Some(data_idx)) => {
				if data.len() < data_idx {
					return Err(Error::InvalidState(format!(
						"cannot restore VecBackend data from {} to missing prefix {}",
						data.len(),
						data_idx
					)));
				}
			}
			(None, None, None) => {}
			_ => {
				return Err(Error::InvalidState(
					"VecBackend data mode changed while restoring tail".into(),
				));
			}
		}

		match (&mut self.data, tail.data.take(), tail.data_idx) {
			(Some(data), Some(mut data_tail), Some(data_idx)) => {
				data.truncate(data_idx);
				data.append(&mut data_tail);
			}
			(None, None, None) => {}
			_ => {
				return Err(Error::InvalidState(
					"VecBackend data mode changed while restoring tail".into(),
				));
			}
		}
		self.hashes.truncate(tail.hash_idx);
		self.hashes.append(&mut tail.hashes);
		self.compacted.retain(|pos| *pos < tail.position);
		self.compacted.append(&mut tail.compacted);
		self.removed.retain(|pos| *pos < tail.position);
		self.removed.append(&mut tail.removed);

		Ok(())
	}

	///  It is expected that all needed leaves are pruned, now we need to update the hashes. Data is still expected to be in pairs because
	/// of overall node limitations.
	pub fn compact(&mut self, delete_buildable_hashes: bool) -> Result<(), Error> {
		if let Some(data) = self.data.as_ref() {
			if self.hashes.is_empty() {
				return Ok(());
			}

			let top_hash = match self.hashes.last() {
				Some(h) => h.clone(),
				None => return Ok(()),
			};

			let mut leaves: BTreeSet<u64> = BTreeSet::new();
			for (pos, dt) in data.iter().enumerate() {
				if dt.is_some() {
					let pos0 = pmmr::insertion_to_pmmr_index(pos as u64)?;
					if !self.removed.contains(&pos0) {
						leaves.insert(pos0);
					}
				}
			}

			let mut pos_with_data: BTreeSet<u64> = BTreeSet::new();
			let hashes_len = self.hashes.len() as u64;
			for pos0 in 0..hashes_len {
				let left_leaf = pmmr::bintree_leftmost(pos0)?;
				if leaves.range(left_leaf..=pos0).next().is_some() {
					pos_with_data.insert(pos0);
				}
			}

			// Now we need to keep all with parent that has a data
			for pos0 in 0..hashes_len {
				if pos_with_data.contains(&pos0) {
					continue;
				}

				let (parent, _) = pmmr::family(pos0)?;
				// Top Hashes we want to keep in any case
				if pos_with_data.contains(&parent) || parent > hashes_len {
					pos_with_data.insert(pos0);
				}
			}

			// Now we can delete all hashes that are not in the pos_with_data list
			for (pos, h) in &mut self.hashes.iter_mut().enumerate() {
				let pos = pos as u64;
				if !pos_with_data.contains(&pos) {
					*h = None;
					self.compacted.insert(pos);
				}
			}

			if pos_with_data.is_empty() {
				if let Some(h) = self.hashes.last_mut() {
					*h = top_hash;
					let pos = self.hashes.len().saturating_sub(1) as u64;
					self.compacted.remove(&pos);
				}
			}

			if delete_buildable_hashes {
				for pos in 0..hashes_len {
					if let Some((left_child, right_child)) = pmmr::children(pos)? {
						let left_child_idx = usize::try_from(left_child).map_err(|_| {
							Error::DataOverflow(format!(
								"VecBackend::compact, left_child={}",
								left_child
							))
						})?;
						let right_child_idx = usize::try_from(right_child).map_err(|_| {
							Error::DataOverflow(format!(
								"VecBackend::compact, right_child={}",
								right_child
							))
						})?;
						let has_left_child =
							self.hashes.get(left_child_idx).unwrap_or(&None).is_some()
								|| leaves.contains(&left_child);
						let has_right_child =
							self.hashes.get(right_child_idx).unwrap_or(&None).is_some()
								|| leaves.contains(&right_child);

						if has_left_child && has_right_child {
							let pos_idx = usize::try_from(pos).map_err(|_| {
								Error::DataOverflow(format!("VecBackend::compact, pos={}", pos))
							})?;
							self.hashes[pos_idx] = None;
							self.compacted.insert(pos);
						}
					}
				}
			}
		}
		Ok(())
	}
}
