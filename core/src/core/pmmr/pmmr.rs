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

use mwc_crates::crossbeam;
use mwc_crates::log::debug;
use mwc_crates::num_cpus;
use std::convert::TryFrom;
use std::{iter, marker, ops::Range, u64};

use mwc_crates::croaring::Bitmap;

use crate::core::hash::{Hash, ZERO_HASH};
use crate::core::merkle_proof::MerkleProof;
use crate::core::pmmr::{Backend, Error, ReadonlyPMMR};
use crate::core::BlockHeader;
use crate::ser::{PMMRIndexHashable, PMMRable};

/// Trait with common methods for reading from a PMMR
pub trait ReadablePMMR {
	/// Leaf type
	type Item;

	/// Consensus context used for PMMR hash serialization.
	fn get_context_id(&self) -> u32;

	/// Get the hash at provided position in the MMR.
	/// NOTE all positions are 0-based, so a size n MMR has nodes in positions 0 through n-1
	/// just like a Rust Range 0..n
	fn get_hash(&self, pos: u64) -> Result<Option<Hash>, Error>;

	/// Get the data element at provided position in the MMR.
	fn get_data(&self, pos: u64) -> Result<Option<Self::Item>, Error>;

	/// Get the hash from the underlying MMR file (ignores the remove log).
	fn get_from_file(&self, pos: u64) -> Result<Option<Hash>, Error>;

	/// Get the hash for the provided peak pos.
	/// Optimized for reading peak hashes rather than arbitrary pos hashes.
	/// Peaks can be assumed to not be compacted.
	fn get_peak_from_file(&self, pos: u64) -> Result<Option<Hash>, Error>;

	/// Get the data element at provided position in the MMR (ignores the remove log).
	fn get_data_from_file(&self, pos: u64) -> Result<Option<Self::Item>, Error>;

	/// Total size of the tree, including intermediary nodes and ignoring any pruning.
	fn unpruned_size(&self) -> u64;

	/// Iterator over current (unpruned, unremoved) leaf positions.
	fn leaf_pos_iter(&self) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error>;

	/// Iterator over current (unpruned, unremoved) leaf insertion indices.
	fn leaf_idx_iter(
		&self,
		from_idx: u64,
	) -> Result<Box<dyn Iterator<Item = Result<u64, Error>> + '_>, Error> {
		let from_pos = insertion_to_pmmr_index(from_idx)?;
		Ok(Box::new(
			self.leaf_pos_iter()?
				.filter(move |pos| match pos {
					Ok(pos) => *pos >= from_pos,
					Err(_) => true,
				})
				.map(|pos| {
					let pos0 = pos?;
					let pos1 = pos0.checked_add(1).ok_or_else(|| {
						Error::DataOverflow(format!("ReadablePMMR::leaf_idx_iter, pos0={}", pos0))
					})?;
					n_leaves(pos1)?.checked_sub(1).ok_or_else(|| {
						Error::DataOverflow(format!("ReadablePMMR::leaf_idx_iter, pos1={}", pos1))
					})
				}),
		))
	}

	/// Number of leaves in the MMR
	fn n_unpruned_leaves(&self) -> Result<u64, Error> {
		let mut leaves = self.leaf_pos_iter()?;
		leaves.try_fold(0u64, |count, pos| {
			pos?;
			count
				.checked_add(1)
				.ok_or_else(|| Error::DataOverflow("ReadablePMMR::n_unpruned_leaves".to_string()))
		})
	}

	/// Number of leaves in the MMR up to index
	fn n_unpruned_leaves_to_index(&self, to_index: u64) -> Result<u64, Error>;

	/// Is the MMR empty?
	fn is_empty(&self) -> bool {
		self.unpruned_size() == 0
	}

	/// Takes a single peak position and hashes together
	/// all the peaks to the right of this peak (if any).
	/// If this return a hash then this is our peaks sibling.
	/// If none then the sibling of our peak is the peak to the left.
	fn bag_the_rhs(&self, peak_pos0: u64) -> Result<Option<Hash>, Error> {
		let size = self.unpruned_size();
		let mut rhs: Vec<Hash> = Vec::new();

		for x in peaks(size)? {
			if x > peak_pos0 {
				let hash = self.get_peak_from_file(x)?.ok_or_else(|| {
					Error::DataCorruption(format!("Missing RHS PMMR peak hash at position {}", x))
				})?;
				rhs.push(hash);
			}
		}

		let mut res = None;
		let context_id = self.get_context_id();
		for peak in rhs.into_iter().rev() {
			res = match res {
				None => Some(peak),
				Some(rhash) => Some((peak, rhash).hash_with_index(context_id, size)?),
			}
		}
		Ok(res)
	}

	/// Returns a vec of the peaks of this MMR.
	fn peaks(&self) -> Result<Vec<Hash>, Error> {
		let mut hs: Vec<Hash> = Vec::new();
		for pi0 in peaks(self.unpruned_size())? {
			let h = self.get_peak_from_file(pi0)?.ok_or_else(|| {
				Error::DataCorruption(format!("Missing PMMR peak hash at position {}", pi0))
			})?;
			hs.push(h);
		}
		Ok(hs)
	}

	/// Hashes of the peaks excluding `peak_pos`, where the rhs is bagged together
	fn peak_path(&self, peak_pos0: u64) -> Result<Vec<Hash>, Error> {
		let rhs = self.bag_the_rhs(peak_pos0)?;

		let mut res = Vec::new();
		for x in peaks(self.unpruned_size())? {
			if x < peak_pos0 {
				let h = self.get_peak_from_file(x)?.ok_or_else(|| {
					Error::DataCorruption(format!("Missing left PMMR peak hash at position {}", x))
				})?;
				res.push(h);
			}
		}

		if let Some(rhs) = rhs {
			res.push(rhs);
		}
		res.reverse();

		Ok(res)
	}

	/// Computes the root of the MMR. Find all the peaks in the current
	/// tree and "bags" them to get a single peak.
	fn root(&self) -> Result<Hash, Error> {
		if self.is_empty() {
			return Ok(ZERO_HASH);
		}
		let mut res = None;
		let peaks = self.peaks()?;
		let mmr_size = self.unpruned_size();
		let context_id = self.get_context_id();
		for peak in peaks.into_iter().rev() {
			res = match res {
				None => Some(peak),
				Some(rhash) => Some((peak, rhash).hash_with_index(context_id, mmr_size)?),
			}
		}
		res.ok_or_else(|| Error::InvalidState("no root, invalid tree".to_owned()))
	}

	/// Build a Merkle proof for the element at the given position.
	fn merkle_proof(&self, pos0: u64) -> Result<MerkleProof, Error> {
		let size = self.unpruned_size();
		debug!("merkle_proof  {}, size {}", pos0, size);

		// check this pos is actually a leaf in the MMR
		if !is_leaf(pos0) {
			return Err(Error::SerializationError(format!(
				"not a mmr leaf at pos {}",
				pos0
			)));
		}

		// check we actually have a hash in the MMR at this pos
		self.get_hash(pos0)?
			.ok_or_else(|| Error::SerializationError(format!("no element at pos {}", pos0)))?;

		let family_branch = family_branch(pos0, size)?;

		let mut path = Vec::new();

		for x in &family_branch {
			let h = self.get_from_file(x.1)?.ok_or_else(|| {
				Error::DataCorruption(format!(
					"Missing PMMR branch sibling hash at position {}",
					x.1
				))
			})?;
			path.push(h);
		}

		let peak_pos = match family_branch.last() {
			Some(&(x, _)) => x,
			None => pos0,
		};

		path.append(&mut self.peak_path(peak_pos)?);

		Ok(MerkleProof {
			mmr_size: size,
			path,
		})
	}
}

/// Prunable Merkle Mountain Range implementation. All positions within the tree
/// start at 0 just like array indices.
///
/// Heavily relies on navigation operations within a binary tree. In particular,
/// all the implementation needs to keep track of the MMR structure is how far
/// we are in the sequence of nodes making up the MMR.
pub struct PMMR<'a, T, B>
where
	T: PMMRable + Sync,
	B: 'a + Backend<T> + Sync,
{
	/// Number of nodes in the PMMR
	size: u64,
	index_offset: u64, // Needed to be able to operate with segment of bigger PMMR
	backend: &'a mut B,
	// only needed to parameterise Backend
	_marker: marker::PhantomData<T>,
}

impl<'a, T, B> PMMR<'a, T, B>
where
	T: PMMRable + Sync,
	B: 'a + Backend<T> + Sync,
{
	/// Build a new prunable Merkle Mountain Range using the provided backend.
	pub fn new(backend: &'a mut B) -> PMMR<'a, T, B> {
		PMMR {
			backend,
			size: 0,
			index_offset: 0,
			_marker: marker::PhantomData,
		}
	}

	/// Build a new prunable Merkle Mountain Range pre-initialized until
	/// size with the provided backend.
	pub fn at(backend: &'a mut B, size: u64) -> PMMR<'a, T, B> {
		PMMR {
			backend,
			size,
			index_offset: 0,
			_marker: marker::PhantomData,
		}
	}

	/// Number of nodes in the PMMR.
	pub fn size(&self) -> u64 {
		self.size
	}

	/// Build a "readonly" view of this PMMR.
	pub fn readonly_pmmr(&self) -> ReadonlyPMMR<'_, T, B> {
		ReadonlyPMMR::at(&self.backend, self.size)
	}

	/// Setting up the index offset if we want to use this PMMR as a segment from the bigger one
	pub fn update_index_offset(&mut self, offset: u64) {
		self.index_offset = offset;
	}

	/// Push a new element into the MMR. Computes new related peaks at
	/// the same time if applicable.
	pub fn push(&mut self, leaf: &T) -> Result<u64, Error> {
		let leaf_pos = self.size;
		let context_id = self.get_context_id();
		let mut current_hash = leaf.hash_with_index(
			context_id,
			leaf_pos.checked_add(self.index_offset).ok_or_else(|| {
				Error::DataOverflow(format!(
					"PMMR::push, leaf_pos={} index_offset={}",
					leaf_pos, self.index_offset
				))
			})?,
		)?;

		let mut hashes = vec![current_hash];
		let mut pos = leaf_pos;

		let (peak_map, height) = peak_map_height(pos);
		if height != 0 {
			return Err(Error::DataCorruption(format!("bad mmr pos {}", pos)));
		}
		// hash with all immediately preceding peaks, as indicated by peak map
		let mut peak = 1u64;
		while (peak_map & peak) != 0 {
			let (parent, left_sibling) = family(pos)?;
			match self.backend.get_peak_from_file(left_sibling)? {
				Some(left_hash) => {
					peak = peak
						.checked_mul(2)
						.ok_or_else(|| Error::DataOverflow(format!("PMMR::push, peak={}", peak)))?;
					pos = parent;
					current_hash = (left_hash, current_hash).hash_with_index(
						context_id,
						pos.checked_add(self.index_offset).ok_or_else(|| {
							Error::DataOverflow(format!(
								"PMMR::push, pos={} index_offset={}",
								pos, self.index_offset
							))
						})?,
					)?;
					hashes.push(current_hash);
				}
				None => {
					return Err(Error::SerializationError(
						"missing left sibling in tree, should not have been pruned".into(),
					));
				}
			}
		}

		// append all the new nodes and update the MMR index
		let new_size = pos
			.checked_add(1)
			.ok_or_else(|| Error::DataOverflow(format!("PMMR::push, pos={}", pos)))?;
		self.backend.append(leaf, &hashes)?;
		self.size = new_size;
		Ok(leaf_pos)
	}

	/// Push a pruned subtree into the PMMR
	pub fn push_pruned_subtree(&mut self, hash: Hash, pos0: u64) -> Result<(), Error> {
		let range = bintree_range(pos0)?;
		if range.start != self.size {
			return Err(Error::InvalidState(format!(
				"pruned subtree at position {} covers range {:?}, not contiguous with PMMR size {}",
				pos0, range, self.size
			)));
		}

		let mut pos = pos0;
		let mut current_hash = hash;
		let context_id = self.get_context_id();
		let mut parent_hashes = Vec::new();

		let (peak_map, _) = peak_map_height(pos);

		// Then hash with all immediately preceding peaks, as indicated by peak map
		let mut peak = 1u64;
		while (peak_map & peak) != 0 {
			let (parent, sibling) = family(pos)?;
			peak = peak.checked_mul(2).ok_or_else(|| {
				Error::DataOverflow(format!("PMMR::push_pruned_subtree, peak={}", peak))
			})?;
			if sibling > pos {
				// is right sibling, we should be done
				continue;
			}
			match self.backend.get_from_file(sibling)? {
				Some(left_hash) => {
					pos = parent;
					current_hash = (left_hash, current_hash).hash_with_index(
						context_id,
						parent.checked_add(self.index_offset).ok_or_else(|| {
							Error::DataOverflow(format!(
								"PMMR::push_pruned_subtree, parent={} index_offset={}",
								parent, self.index_offset
							))
						})?,
					)?;
					parent_hashes.push(current_hash);
				}
				None => {
					return Err(Error::SerializationError(
						"missing left sibling in tree, should not have been pruned".into(),
					));
				}
			}
		}

		let new_size = pos.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("PMMR::push_pruned_subtree, pos={}", pos))
		})?;
		self.backend
			.append_pruned_subtree_hashes(hash, pos0, &parent_hashes)?;
		self.size = new_size;
		Ok(())
	}

	/// Reset prune list
	pub fn reset_prune_list(&mut self) -> Result<(), Error> {
		self.backend.reset_prune_list()
	}

	// Remove the specified position from the leaf set
	// DON'T USE IS, use prune instead
	/*pub fn remove_from_leaf_set(&mut self, pos0: u64) {
		self.backend.remove_from_leaf_set(pos0);
	}*/

	/// Saves a snapshot of the MMR tagged with the block hash.
	/// Specifically - snapshots the utxo file as we need this rewound before
	/// sending the txhashset zip file to another node for fast-sync.
	pub fn snapshot(&mut self, header: &BlockHeader) -> Result<(), Error> {
		self.backend.snapshot(header)?;
		Ok(())
	}

	/// Rewind the PMMR to a previous position, as if all push operations after
	/// that had been canceled. Expects a position in the PMMR to rewind and
	/// bitmaps representing the positions added and removed that we want to
	/// "undo".
	pub fn rewind(&mut self, position: u64, rewind_rm_pos: &Bitmap) -> Result<(), Error> {
		// Identify which actual position we should rewind to as the provided
		// position is a leaf. We traverse the MMR to include any parent(s) that
		// need to be included for the MMR to be valid.
		let leaf_pos = round_up_to_leaf_pos(position)?;
		if leaf_pos > self.size {
			return Err(Error::InvalidState(format!(
				"cannot rewind PMMR forward from {} to {}",
				self.size, leaf_pos
			)));
		}
		self.backend.rewind(leaf_pos, rewind_rm_pos)?;
		self.size = leaf_pos;
		Ok(())
	}

	/// Prunes (removes) the leaf from the MMR at the specified position.
	/// Returns an error if prune is called on a non-leaf position.
	/// Returns false if the leaf node has already been pruned.
	/// Returns true if pruning is successful.
	pub fn prune(&mut self, pos0: u64) -> Result<bool, Error> {
		if !is_leaf(pos0) {
			return Err(Error::SerializationError(format!(
				"Node at {} is not a leaf, can't prune.",
				pos0
			)));
		}

		if pos0 >= self.size {
			return Err(Error::InvalidState(format!(
				"cannot prune position {} outside PMMR size {}",
				pos0, self.size
			)));
		}

		if self.backend.get_hash(pos0)?.is_none() {
			return Ok(false);
		}

		let removed = self.backend.remove(pos0)?;
		Ok(removed)
	}

	/// Walks the MMR and validates parent hashes and stored leaf data hashes.
	pub fn validate(&self) -> Result<(), Error>
	where
		T::E: PMMRIndexHashable,
	{
		// next_height: the height of the next node that would be needed if the current size is sitting
		//     inside an incomplete subtree, so it must be 0 for complete PMMR
		let (_, next_height) = peak_sizes_height(self.size);
		if next_height != 0 {
			return Err(Error::DataCorruption(format!(
				"Invalid MMR size {}, incomplete subtree boundary at height {}.",
				self.size, next_height
			)));
		}

		for peak_pos in peaks(self.size)? {
			if self.get_peak_from_file(peak_pos)?.is_none() {
				return Err(Error::DataCorruption(format!(
					"Invalid MMR, missing peak hash at {}.",
					peak_pos + 1
				)));
			}
		}

		// Let's validate everything in multiple threads
		let num_cores_usize = num_cpus::get();
		let context_id = self.get_context_id();
		let num_cores = u64::try_from(num_cores_usize).map_err(|_| {
			Error::DataOverflow(format!("PMMR::validate, num_cores={}", num_cores_usize))
		})?;
		if num_cores == 0 {
			return Err(Error::InternalError(
				"PMMR::validate, num_cpus returned zero".to_string(),
			));
		}
		let validation_result = crossbeam::thread::scope(|s| {
			let mut handles = Vec::with_capacity(num_cores_usize);
			for thr_idx in 0..num_cores {
				let next_thr_idx = thr_idx.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!("PMMR::validate, thr_idx={}", thr_idx))
				})?;
				let idx1 = self.size.checked_mul(thr_idx).ok_or_else(|| {
					Error::DataOverflow(format!(
						"PMMR::validate, size={} thr_idx={}",
						self.size, thr_idx
					))
				})? / num_cores;
				let idx2 = self.size.checked_mul(next_thr_idx).ok_or_else(|| {
					Error::DataOverflow(format!(
						"PMMR::validate, size={} next_thr_idx={}",
						self.size, next_thr_idx
					))
				})? / num_cores;

				let handle = s.spawn(move |_| {
					for n in idx1..idx2 {
						let height = bintree_postorder_height(n);
						if height > 0 {
							let hash = match self.get_hash(n)? {
								Some(hash) => hash,
								None => {
									if self.backend.is_compacted(n)? {
										continue;
									}
									return Err(Error::DataCorruption(format!(
										"Invalid MMR, missing parent hash at {}.",
										n + 1
									)));
								}
							};

							let (left_pos, right_pos) = children(n)?.ok_or_else(|| {
								Error::DataOverflow(format!("PMMR::validate, n={}", n))
							})?;
							// using get_from_file here for the children (they may have been "removed")
							match (
								self.get_from_file(left_pos)?,
								self.get_from_file(right_pos)?,
							) {
								(Some(left_child_hs), Some(right_child_hs)) => {
									// hash the two child nodes together with parent_pos and compare
									if (left_child_hs, right_child_hs).hash_with_index(
										context_id,
										n.checked_add(self.index_offset).ok_or_else(|| {
											Error::DataOverflow(format!(
												"PMMR::validate, n={} index_offset={}",
												n, self.index_offset
											))
										})?,
									)? != hash
									{
										return Err(Error::DataCorruption(format!(
											"Invalid MMR, hash of parent at {} does not match children.",
											n + 1
										)));
									}
								}
								(None, None) => {
									if !self.backend.is_compacted(left_pos)?
										|| !self.backend.is_compacted(right_pos)?
									{
										return Err(Error::DataCorruption(format!(
											"Invalid MMR, parent at {} has two unexpectedly missing children.",
											n + 1
										)));
									}
								}
								_ => {
									return Err(Error::DataCorruption(format!(
										"Invalid MMR, parent at {} has exactly one missing child.",
										n + 1
									)));
								}
							}
						} else {
							let stored_hash = self.get_from_file(n)?;
							let stored_data = self.get_data_from_file(n)?;
							match (stored_hash, stored_data) {
								(Some(hash), Some(data)) => {
									let index =
										n.checked_add(self.index_offset).ok_or_else(|| {
											Error::DataOverflow(format!(
												"PMMR::validate, n={} index_offset={}",
												n, self.index_offset
											))
										})?;
									let data_hash = data.hash_with_index(context_id, index)?;
									if data_hash != hash {
										return Err(Error::DataCorruption(format!(
											"Invalid MMR leaf data at {}, data hash does not match stored hash.",
											n + 1
										)));
									}
								}
								(None, None) => {
									if !self.backend.is_compacted(n)? {
										return Err(Error::DataCorruption(format!(
											"Invalid MMR, missing non-compacted leaf hash and data at {}.",
											n + 1
										)));
									}
								}
								(Some(_), None) => {
									return Err(Error::DataCorruption(format!(
										"Invalid MMR, missing leaf data for hash at {}.",
										n + 1
									)));
								}
								(None, Some(_)) => {
									return Err(Error::DataCorruption(format!(
										"Invalid MMR, missing leaf hash for data at {}.",
										n + 1
									)));
								}
							}
						}
					}
					Ok(())
				});
				handles.push(handle);
			}
			for handle in handles {
				match handle.join().map_err(|_| {
					Error::InternalError("PMMR validate crossbeam runtime failure".to_string())
				})? {
					Ok(_) => {}
					Err(e) => return Err(e),
				}
			}
			Ok(())
		})
		.map_err(|_| Error::InternalError("PMMR validate crossbeam runtime failure".to_string()))?;
		validation_result
	}

	/// Debugging utility to print information about the MMRs. Short version
	/// only prints the last 8 nodes.
	pub fn dump(&self, short: bool) -> Result<(), Error> {
		let sz = self.unpruned_size();
		if sz > 2000 && !short {
			return Ok(());
		}
		let start = if short { sz / 8 } else { 0 };
		// Note,  sz/8 + 1 is safe, overflow is not possible
		for n in start..(sz / 8 + 1) {
			let mut idx = "".to_owned();
			let mut hashes = "".to_owned();
			// Note, even oveflow for (n + 1) * 8 is possible, it is a debug tool, chance of oveflow is acceptable
			for m in (n * 8)..(n + 1) * 8 {
				if m >= sz {
					break;
				}
				idx.push_str(&format!("{:>8} ", m));
				let ohs = self.get_hash(m)?;
				match ohs {
					Some(hs) => hashes.push_str(&format!("{} ", hs)),
					None => hashes.push_str(&format!("{:>8} ", "??")),
				}
			}
			debug!("{}", idx);
			debug!("{}", hashes);
		}
		Ok(())
	}

	/// Prints PMMR statistics to the logs, used for debugging.
	pub fn dump_stats(&self) {
		debug!("pmmr: unpruned - {}", self.unpruned_size());
		self.backend.dump_stats();
	}

	/// Debugging utility to print information about the MMRs. Short version
	/// only prints the last 8 nodes.
	/// Looks in the underlying hash file and so ignores the remove log.
	pub fn dump_from_file(&self, short: bool) -> Result<(), Error> {
		let sz = self.unpruned_size();
		if sz > 2000 && !short {
			return Ok(());
		}
		let start = if short { sz / 8 } else { 0 };
		// Note,  sz/8 + 1 is safe, overflow is not possible
		for n in start..(sz / 8 + 1) {
			let mut idx = "".to_owned();
			let mut hashes = "".to_owned();
			// Note, even oveflow for (n + 1) * 8 is possible, it is a debug tool, chance of oveflow is acceptable
			for m in (n * 8)..(n + 1) * 8 {
				if m >= sz {
					break;
				}
				idx.push_str(&format!("{:>8} ", m + 1));
				let ohs = self.get_from_file(m)?;
				match ohs {
					Some(hs) => hashes.push_str(&format!("{} ", hs)),
					None => hashes.push_str(&format!("{:>8} ", " .")),
				}
			}
			debug!("{}", idx);
			debug!("{}", hashes);
		}
		Ok(())
	}
}

impl<'a, T, B> ReadablePMMR for PMMR<'a, T, B>
where
	T: PMMRable + Sync,
	B: 'a + Backend<T> + Sync,
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

/// 64 bits all ones: 0b11111111...1
const ALL_ONES: u64 = u64::MAX;

/// peak bitmap and height of next node in mmr of given size
/// Example: on size 4 returns (0b11, 0) as mmr tree of size 4 is
///    2
///   / \
///  0   1   3
/// with 0b11 indicating the presence of peaks of height 0 and 1,
/// and 0 the height of the next node 4, which is a leaf
/// NOTE:
/// the peak map also encodes the path taken from the root to the added node
/// since the path turns left (resp. right) if-and-only-if
/// a peak at that height is absent (resp. present)
pub fn peak_map_height(mut size: u64) -> (u64, u64) {
	if size == 0 {
		// rust can't shift right by 64
		return (0, 0);
	}
	// Safe: size is non-zero, so leading_zeros() is in 0..=63 and the shift is valid.
	let mut peak_size = ALL_ONES >> size.leading_zeros();
	let mut peak_map = 0;
	while peak_size != 0 {
		// Safe: peak_map has at most one bit for each peak_size iteration,
		// and peak_size iterates over at most 64 bits.
		peak_map <<= 1;
		if size >= peak_size {
			// Safe: subtraction is guarded by the size >= peak_size check.
			size -= peak_size;
			peak_map |= 1;
		}
		// Safe: shifting right by one is always valid for u64.
		peak_size >>= 1;
	}
	(peak_map, size)
}

/// sizes of peaks and height of next node in mmr of given size
/// similar to peak_map_height but replacing bitmap by vector of sizes
/// Example: on input 5 returns ([3,1], 1) as mmr state before adding 5 was
///    2
///   / \
///  0   1   3   4
pub fn peak_sizes_height(mut size: u64) -> (Vec<u64>, u64) {
	if size == 0 {
		// rust can't shift right by 64
		return (vec![], 0);
	}
	// Safe: size is non-zero, so leading_zeros() is in 0..=63 and the shift is valid.
	let mut peak_size = ALL_ONES >> size.leading_zeros();
	let mut peak_sizes = vec![];
	while peak_size != 0 {
		if size >= peak_size {
			peak_sizes.push(peak_size);
			// Safe: subtraction is guarded by the size >= peak_size check.
			size -= peak_size;
		}
		// Safe: shifting right by one is always valid for u64.
		peak_size >>= 1;
	}
	(peak_sizes, size)
}

/// Gets the postorder traversal 0-based index of all peaks in a MMR given its size.
/// Starts with the top peak, which is always on the left
/// side of the range, and navigates toward lower siblings toward the right
/// of the range.
/// For some odd reason, return empty when next node is not a leaf
pub fn peaks(size: u64) -> Result<Vec<u64>, Error> {
	let (peak_sizes, height) = peak_sizes_height(size);
	if height == 0 {
		let mut acc = 0u64;
		let mut res = Vec::with_capacity(peak_sizes.len());
		for x in peak_sizes {
			acc = acc.checked_add(x).ok_or_else(|| {
				Error::DataOverflow(format!("pmmr::peaks, size={} acc={} x={}", size, acc, x))
			})?;
			res.push(acc.checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!("pmmr::peaks, size={} acc={}", size, acc))
			})?);
		}
		Ok(res)
	} else {
		Ok(vec![])
	}
}
/// The number of leaves in a MMR of the provided size.
pub fn n_leaves(size: u64) -> Result<u64, Error> {
	let (peak_map, height) = peak_map_height(size);
	if height == 0 {
		Ok(peak_map)
	} else {
		peak_map.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"pmmr::n_leaves, size={} peak_map={}",
				size, peak_map
			))
		})
	}
}

/// returns least position >= pos0 with height 0
pub fn round_up_to_leaf_pos(pos0: u64) -> Result<u64, Error> {
	let (insert_idx, height) = peak_map_height(pos0);
	let leaf_idx = if height == 0 {
		insert_idx
	} else {
		insert_idx.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"pmmr::round_up_to_leaf_pos, pos0={} insert_idx={}",
				pos0, insert_idx
			))
		})?
	};
	insertion_to_pmmr_index(leaf_idx)
}

/// Returns the 0-based pmmr index of 0-based leaf index n
pub fn insertion_to_pmmr_index(nleaf0: u64) -> Result<u64, Error> {
	// 2 * nleaf0 - nleaf0.count_ones() as u64
	let ones = u64::from(nleaf0.count_ones());
	nleaf0
		.checked_mul(2)
		.and_then(|x| x.checked_sub(ones))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"pmmr::insertion_to_pmmr_index, nleaf0={} ones={}",
				nleaf0, ones
			))
		})
}

/// Returns the insertion index of the given leaf index
pub fn pmmr_leaf_to_insertion_index(pos0: u64) -> Option<u64> {
	let (insert_idx, height) = peak_map_height(pos0);
	if height == 0 {
		Some(insert_idx)
	} else {
		None
	}
}

/// The height of a node in a full binary tree from its postorder traversal
/// index.
pub fn bintree_postorder_height(pos0: u64) -> u64 {
	peak_map_height(pos0).1
}

/// Is this position a leaf in the MMR?
/// We know the positions of all leaves based on the postorder height of an MMR
/// of any size (somewhat unintuitively but this is how the PMMR is "append
/// only").
pub fn is_leaf(pos0: u64) -> bool {
	bintree_postorder_height(pos0) == 0
}

/// Calculates the positions of the parent and sibling of the node at the
/// provided position.
pub fn family(pos0: u64) -> Result<(u64, u64), Error> {
	let (peak_map, height) = peak_map_height(pos0);
	//let peak = 1 << height;
	//if (peak_map & peak) != 0 {
	//	(pos0 + 1, pos0 + 1 - 2 * peak)
	//} else {
	//	(pos0 + 2 * peak, pos0 + 2 * peak - 1)
	//}

	let peak = 1u64
		.checked_shl(u32::try_from(height).map_err(|_| {
			Error::DataOverflow(format!("pmmr::family, pos0={} height={}", pos0, height))
		})?)
		.ok_or_else(|| {
			Error::DataOverflow(format!("pmmr::family, pos0={} height={}", pos0, height))
		})?;
	let double_peak = peak
		.checked_mul(2)
		.ok_or_else(|| Error::DataOverflow(format!("pmmr::family, pos0={} peak={}", pos0, peak)))?;
	if (peak_map & peak) != 0 {
		let parent = pos0
			.checked_add(1)
			.ok_or_else(|| Error::DataOverflow(format!("pmmr::family, pos0={}", pos0)))?;
		let sibling = parent.checked_sub(double_peak).ok_or_else(|| {
			Error::DataOverflow(format!(
				"pmmr::family, parent={} double_peak={}",
				parent, double_peak
			))
		})?;
		Ok((parent, sibling))
	} else {
		let parent = pos0.checked_add(double_peak).ok_or_else(|| {
			Error::DataOverflow(format!(
				"pmmr::family, pos0={} double_peak={}",
				pos0, double_peak
			))
		})?;
		let sibling = parent
			.checked_sub(1)
			.ok_or_else(|| Error::DataOverflow(format!("pmmr::family, parent={}", parent)))?;
		Ok((parent, sibling))
	}
}

/// positions of Left and right children. For leaf return None
pub fn children(pos0: u64) -> Result<Option<(u64, u64)>, Error> {
	let height = bintree_postorder_height(pos0);
	if height == 0 {
		return Ok(None); // It is a leaf, no children
	}
	// let left_pos = pos0 - (1 << height);
	// let right_pos = pos0 - 1;
	let left_offset = 1u64
		.checked_shl(u32::try_from(height).map_err(|_| {
			Error::DataOverflow(format!("pmmr::children, pos0={} height={}", pos0, height))
		})?)
		.ok_or_else(|| {
			Error::DataOverflow(format!("pmmr::children, pos0={} height={}", pos0, height))
		})?;
	let left_pos = pos0.checked_sub(left_offset).ok_or_else(|| {
		Error::DataOverflow(format!(
			"pmmr::children, pos0={} left_offset={}",
			pos0, left_offset
		))
	})?;
	let right_pos = pos0
		.checked_sub(1)
		.ok_or_else(|| Error::DataOverflow(format!("pmmr::children, pos0={}", pos0)))?;
	Ok(Some((left_pos, right_pos)))
}

/// Is the node at this pos the "left" sibling of its parent?
pub fn is_left_sibling(pos0: u64) -> Result<bool, Error> {
	let (peak_map, height) = peak_map_height(pos0);
	// let peak = 1 << height;
	let peak = 1u64
		.checked_shl(u32::try_from(height).map_err(|_| {
			Error::DataOverflow(format!(
				"pmmr::is_left_sibling, pos0={} height={}",
				pos0, height
			))
		})?)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"pmmr::is_left_sibling, pos0={} height={}",
				pos0, height
			))
		})?;
	Ok((peak_map & peak) == 0)
}

/// For a given starting position calculate the parent and sibling positions
/// for the branch/path from that position to the peak of the tree.
/// We will use the sibling positions to generate the "path" of a Merkle proof.
pub fn family_branch(pos0: u64, size: u64) -> Result<Vec<(u64, u64)>, Error> {
	if pos0 >= size {
		return Err(Error::InvalidState(format!(
			"family_branch position {} is outside PMMR size {}",
			pos0, size
		)));
	}

	// loop going up the tree, from node to parent, as long as we stay inside
	// the tree (as defined by size).
	let (peak_map, height) = peak_map_height(pos0);
	// let mut peak = 1 << height;
	let mut peak = 1u64
		.checked_shl(u32::try_from(height).map_err(|_| {
			Error::DataOverflow(format!(
				"pmmr::family_branch, pos0={} height={}",
				pos0, height
			))
		})?)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"pmmr::family_branch, pos0={} height={}",
				pos0, height
			))
		})?;
	let mut branch = vec![];
	let mut current = pos0;
	let mut sibling;
	while current.checked_add(1).ok_or_else(|| {
		Error::DataOverflow(format!(
			"pmmr::family_branch, current={} size={}",
			current, size
		))
	})? < size
	{
		let double_peak = peak.checked_mul(2).ok_or_else(|| {
			Error::DataOverflow(format!("pmmr::family_branch, pos0={} peak={}", pos0, peak))
		})?;
		if (peak_map & peak) != 0 {
			current = current.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!("pmmr::family_branch, current={}", current))
			})?;
			sibling = current.checked_sub(double_peak).ok_or_else(|| {
				Error::DataOverflow(format!(
					"pmmr::family_branch, current={} double_peak={}",
					current, double_peak
				))
			})?;
		} else {
			current = current.checked_add(double_peak).ok_or_else(|| {
				Error::DataOverflow(format!(
					"pmmr::family_branch, current={} double_peak={}",
					current, double_peak
				))
			})?;
			sibling = current.checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!("pmmr::family_branch, current={}", current))
			})?;
		};
		if current >= size {
			break;
		}
		branch.push((current, sibling));
		peak = double_peak;
	}
	Ok(branch)
}

/// Gets the position of the rightmost node (i.e. leaf) beneath the provided subtree root.
pub fn bintree_rightmost(pos0: u64) -> Result<u64, Error> {
	let height = bintree_postorder_height(pos0);
	pos0.checked_sub(height).ok_or_else(|| {
		Error::DataOverflow(format!(
			"pmmr::bintree_rightmost, pos0={} height={}",
			pos0, height
		))
	})
}

/// Gets the position of the leftmost node (i.e. leaf) beneath the provided subtree root.
pub fn bintree_leftmost(pos0: u64) -> Result<u64, Error> {
	let height = bintree_postorder_height(pos0);
	// pos0 + 2 - (2 << height)
	let subtree_width = 2u128
		.checked_shl(u32::try_from(height).map_err(|_| {
			Error::DataOverflow(format!(
				"pmmr::bintree_leftmost, pos0={} height={}",
				pos0, height
			))
		})?)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"pmmr::bintree_leftmost, pos0={} height={}",
				pos0, height
			))
		})?;
	let leftmost = u128::from(pos0)
		.checked_add(2)
		.and_then(|pos| pos.checked_sub(subtree_width))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"pmmr::bintree_leftmost, pos0={} subtree_width={}",
				pos0, subtree_width
			))
		})?;
	u64::try_from(leftmost).map_err(|_| {
		Error::DataOverflow(format!(
			"pmmr::bintree_leftmost, pos0={} leftmost={}",
			pos0, leftmost
		))
	})
}

/// Iterator over all leaf pos beneath the provided subtree root (including the root itself).
pub fn bintree_leaf_pos_iter(
	pos0: u64,
) -> Result<Box<dyn Iterator<Item = Result<u64, Error>>>, Error> {
	let leaf_start = pmmr_leaf_to_insertion_index(bintree_leftmost(pos0)?);
	let leaf_end = pmmr_leaf_to_insertion_index(bintree_rightmost(pos0)?);
	let leaf_start = match leaf_start {
		Some(l) => l,
		None => return Ok(Box::new(iter::empty::<Result<u64, Error>>())),
	};
	let leaf_end = match leaf_end {
		Some(l) => l,
		None => return Ok(Box::new(iter::empty::<Result<u64, Error>>())),
	};
	Ok(Box::new(
		(leaf_start..=leaf_end).map(|n| insertion_to_pmmr_index(n)),
	))
}

/// Iterator over all pos beneath the provided subtree root (including the root itself).
pub fn bintree_pos_iter(pos0: u64) -> Result<impl Iterator<Item = u64>, Error> {
	let leaf_start = bintree_leftmost(pos0)?;
	Ok((leaf_start..=pos0).into_iter())
}

/// All pos in the subtree beneath the provided root, including root itself.
pub fn bintree_range(pos0: u64) -> Result<Range<u64>, Error> {
	let leftmost = bintree_leftmost(pos0)?;
	let end = pos0
		.checked_add(1)
		.ok_or_else(|| Error::DataOverflow(format!("pmmr::bintree_range, pos0={}", pos0)))?;
	Ok(leftmost..end)
}
