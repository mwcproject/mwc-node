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

//! Utility structs to handle the 3 MMRs (output, rangeproof,
//! kernel) along the overall header MMR conveniently and transactionally.

use crate::error::Error;
use crate::linked_list::{ListIndex, PruneableListIndex, RewindableListIndex};
use crate::store::{self, Batch, ChainStore};
use crate::txhashset::{BitmapAccumulator, RewindableKernelView, UTXOView};
use crate::types::{
	CommitPos, HashHeight, KernelPos, SyncStatusUpdateThrottle, Tip, TxHashSetRoots,
	TxHashsetStateValidationStage, TXHASHSET_STATE_VALIDATION_STEPS,
};
use crate::{SyncState, SyncStatus};
use mwc_core::consensus::WEEK_HEIGHT;
use mwc_core::core::committed::{verify_kernel_sums_iter, Error as CommittedError};
use mwc_core::core::hash::{Hash, Hashed, ZERO_HASH};
use mwc_core::core::merkle_proof::MerkleProof;
use mwc_core::core::pmmr::{self, Backend, ReadablePMMR, ReadonlyPMMR, RewindablePMMR, PMMR};
use mwc_core::core::{
	Block, BlockHeader, KernelFeatures, Output, OutputIdentifier, Segment, TxKernel,
};
use mwc_core::global;
use mwc_core::ser::{self, PMMRable, ProtocolVersion};
use mwc_crates::croaring::Bitmap;
use mwc_crates::crossbeam;
use mwc_crates::crossbeam::thread::ScopedJoinHandle;
use mwc_crates::log::{debug, error, info, trace, warn};
use mwc_crates::num_cpus;
use mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_crates::secp::Secp256k1;
use mwc_store::pmmr::PMMRBackend;
use mwc_store::types::VariableSizeMetadataValidation;
use mwc_store::Error::NotFoundErr;
use mwc_util::{secp_static, StopState};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

const TXHASHSET_SUBDIR: &str = "txhashset";
const KERNEL_POS_INDEX_REBUILD_CHUNK_SIZE: usize = 10_000;
const COMMIT_SUM_BATCH_SIZE: usize = 10_000;
const INDEX_REBUILD_LOG_INTERVAL_SECS: u64 = 1;

const OUTPUT_SUBDIR: &str = "output";
const RANGE_PROOF_SUBDIR: &str = "rangeproof";
const KERNEL_SUBDIR: &str = "kernel";

/// Convenience enum to keep track of hash and leaf insertions when rebuilding an mmr
/// from segments
#[derive(Eq)]
pub enum OrderedHashLeafNode {
	/// index of data in hashes array, pmmr position
	Hash(usize, u64),
	/// index of data in leaf_data array, pmmr position
	Leaf(usize, u64),
}

impl PartialEq for OrderedHashLeafNode {
	fn eq(&self, other: &Self) -> bool {
		let a_val = match self {
			OrderedHashLeafNode::Hash(_, pos0) => pos0,
			OrderedHashLeafNode::Leaf(_, pos0) => pos0,
		};
		let b_val = match other {
			OrderedHashLeafNode::Hash(_, pos0) => pos0,
			OrderedHashLeafNode::Leaf(_, pos0) => pos0,
		};
		a_val == b_val
	}
}

impl Ord for OrderedHashLeafNode {
	fn cmp(&self, other: &Self) -> Ordering {
		let a_val = match self {
			OrderedHashLeafNode::Hash(_, pos0) => pos0,
			OrderedHashLeafNode::Leaf(_, pos0) => pos0,
		};
		let b_val = match other {
			OrderedHashLeafNode::Hash(_, pos0) => pos0,
			OrderedHashLeafNode::Leaf(_, pos0) => pos0,
		};
		a_val.cmp(&b_val)
	}
}

impl PartialOrd for OrderedHashLeafNode {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		let a_val = match self {
			OrderedHashLeafNode::Hash(_, pos0) => pos0,
			OrderedHashLeafNode::Leaf(_, pos0) => pos0,
		};
		let b_val = match other {
			OrderedHashLeafNode::Hash(_, pos0) => pos0,
			OrderedHashLeafNode::Leaf(_, pos0) => pos0,
		};
		Some(a_val.cmp(b_val))
	}
}

/// Convenience wrapper around a single prunable MMR backend.
pub struct PMMRHandle<T: PMMRable> {
	/// The backend storage for the MMR.
	pub backend: PMMRBackend<T>,
	/// The MMR size accessible via this handle (backend may continue out beyond this).
	pub size: u64,
}

impl<T: PMMRable> PMMRHandle<T> {
	/// Constructor to create a PMMR handle from an existing directory structure on disk.
	/// Creates the backend files as necessary if they do not already exist.
	pub fn new<P: AsRef<Path>>(
		path: P,
		prunable: bool,
		version: ProtocolVersion,
		context_id: u32,
		header: Option<&BlockHeader>,
		metadata_validation: VariableSizeMetadataValidation,
	) -> Result<PMMRHandle<T>, Error> {
		let path = path.as_ref();
		mwc_util::file::ensure_owner_only_dir_all(path)?;
		let backend = PMMRBackend::new(
			path,
			prunable,
			version,
			context_id,
			header,
			metadata_validation,
		)?;
		let size = backend.unpruned_size()?;
		Ok(PMMRHandle { backend, size })
	}
}

fn is_kernel_pmmr_version_probe_error(err: &Error) -> bool {
	let io_err = match err {
		Error::PMMRErr(pmmr::Error::IOErr(io_err)) => io_err,
		_ => return false,
	};

	match io_err.kind() {
		io::ErrorKind::Other | io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof => {}
		_ => return false,
	}

	let msg = io_err.to_string();
	msg.starts_with("Fail to read while validating variable-size file")
		|| msg.starts_with("Fail to read at rebuild_size_file")
		|| msg.starts_with("Fail to deserialize data")
}

impl PMMRHandle<BlockHeader> {
	/// Used during chain init to ensure the header PMMR is consistent with header_head in the db.
	pub fn init_head(&mut self, head: &Tip) -> Result<(), Error> {
		let head_hash = self.head_hash()?;
		let expected_hash = self.get_header_hash_by_height(head.height)?;
		let context_id = self.backend.get_context_id();
		let head_tip_hash = head.hash(context_id)?;
		if head_tip_hash != expected_hash {
			error!(
				"header PMMR inconsistent: {} vs {} at {}",
				expected_hash, head_tip_hash, head.height
			);
			return Err(Error::Other("header PMMR inconsistent".to_string()));
		}

		// use next header pos to find our size.
		let next_height = head.height.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("PMMRHandle::init_head, height={}", head.height))
		})?;
		let size = pmmr::insertion_to_pmmr_index(next_height)?;

		debug!(
			"init_head: header PMMR: current head {} at pos {}",
			head_hash, self.size
		);
		debug!(
			"init_head: header PMMR: resetting to {} at pos {} (height {})",
			head_tip_hash, size, head.height
		);

		self.size = size;
		Ok(())
	}

	/// Get the header hash at the specified height based on the current header MMR state.
	pub fn get_header_hash_by_height(&self, height: u64) -> Result<Hash, Error> {
		if height >= pmmr::n_leaves(self.size)? {
			return Err(Error::InvalidHeaderHeight(height));
		}
		let pos = pmmr::insertion_to_pmmr_index(height)?;
		let header_pmmr = ReadonlyPMMR::at(&self.backend, self.size);
		if let Some(entry) = header_pmmr.get_data(pos)? {
			Ok(entry.hash(self.backend.get_context_id())?)
		} else {
			Err(Error::Other(format!(
				"not found header hash for height {}",
				height
			)))
		}
	}

	/// Get the header hash for the head of the header chain based on current MMR state.
	/// Find the last leaf pos based on MMR size and return its header hash.
	pub fn head_hash(&self) -> Result<Hash, Error> {
		if self.size == 0 {
			return Err(Error::EmptyMMR);
		}
		let header_pmmr = ReadonlyPMMR::at(&self.backend, self.size);
		let leaf_pos = pmmr::bintree_rightmost(self.size.checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!("PMMRHandle::head_hash, size={}", self.size))
		})?)?;
		if let Some(entry) = header_pmmr.get_data(leaf_pos)? {
			Ok(entry.hash(self.backend.get_context_id())?)
		} else {
			Err(Error::Other("failed to find head hash".to_string()))
		}
	}
}

/// An easy to manipulate structure holding the 3 MMRs necessary to
/// validate blocks and capturing the output set, associated rangeproofs and the
/// kernels. Also handles the index of Commitments to positions in the
/// output and rangeproof MMRs.
///
/// Note that the index is never authoritative, only the trees are
/// guaranteed to indicate whether an output is spent or not. The index
/// may have commitments that have already been spent, even with
/// pruning enabled.
pub struct TxHashSet {
	output_pmmr_h: PMMRHandle<OutputIdentifier>,
	rproof_pmmr_h: PMMRHandle<RangeProof>,
	kernel_pmmr_h: PMMRHandle<TxKernel>,

	// chain store used as index of commitments to MMR positions
	commit_index: Arc<ChainStore>,
}

impl TxHashSet {
	/// Open an existing or new set of backends for the TxHashSet
	pub fn open(
		root_dir: String,
		commit_index: Arc<ChainStore>,
		header: Option<&BlockHeader>,
		secp: &Secp256k1,
	) -> Result<TxHashSet, Error> {
		let context_id = commit_index.get_context_id();
		let output_pmmr_h = PMMRHandle::new(
			Path::new(&root_dir)
				.join(TXHASHSET_SUBDIR)
				.join(OUTPUT_SUBDIR),
			true,
			ProtocolVersion(1),
			context_id,
			header,
			VariableSizeMetadataValidation::Full,
		)?;

		let rproof_pmmr_h = PMMRHandle::new(
			Path::new(&root_dir)
				.join(TXHASHSET_SUBDIR)
				.join(RANGE_PROOF_SUBDIR),
			true,
			ProtocolVersion(1),
			context_id,
			header,
			VariableSizeMetadataValidation::Full,
		)?;

		let mut maybe_kernel_handle: Option<PMMRHandle<TxKernel>> = None;
		let mut kernel_probe_errors: Vec<String> = vec![];
		let versions = vec![ProtocolVersion(2), ProtocolVersion(1)];
		for version in versions {
			// Using Fast validation because of node starting issue. Full validaiton takes too much time,
			// so we don't validate all commits and kernels internals
			let handle = match PMMRHandle::new(
				Path::new(&root_dir)
					.join(TXHASHSET_SUBDIR)
					.join(KERNEL_SUBDIR),
				false, // not prunable
				version,
				context_id,
				None,
				VariableSizeMetadataValidation::Fast,
			) {
				Ok(handle) => handle,
				Err(err) if is_kernel_pmmr_version_probe_error(&err) => {
					debug!(
						"attempting to open kernel PMMR using {:?} - FAIL ({})",
						version, err
					);
					kernel_probe_errors.push(format!("{}: {}", version, err));
					continue;
				}
				Err(err) => return Err(err),
			};
			if handle.size == 0 {
				debug!(
					"attempting to open (empty) kernel PMMR using {:?} - SUCCESS",
					version
				);
				maybe_kernel_handle = Some(handle);
				break;
			}
			let kernel: Option<TxKernel> = match ReadonlyPMMR::at(&handle.backend, 1).get_data(0) {
				Ok(kernel) => kernel,
				Err(err) => {
					let err = Error::from(err);
					if is_kernel_pmmr_version_probe_error(&err) {
						debug!(
							"attempting to open kernel PMMR using {:?} - FAIL ({})",
							version, err
						);
						kernel_probe_errors.push(format!("{}: {}", version, err));
						continue;
					}
					return Err(err);
				}
			};
			if let Some(kernel) = kernel {
				if kernel.verify(context_id, secp).is_ok() {
					debug!(
						"attempting to open kernel PMMR using {:?} - SUCCESS",
						version
					);
					maybe_kernel_handle = Some(handle);
					break;
				} else {
					debug!(
						"attempting to open kernel PMMR using {:?} - FAIL (verify failed)",
						version
					);
				}
			} else {
				debug!(
					"attempting to open kernel PMMR using {:?} - FAIL (read failed)",
					version
				);
			}
		}
		if let Some(kernel_pmmr_h) = maybe_kernel_handle {
			Ok(TxHashSet {
				output_pmmr_h,
				rproof_pmmr_h,
				kernel_pmmr_h,
				commit_index,
			})
		} else {
			let details = if kernel_probe_errors.is_empty() {
				String::new()
			} else {
				format!("; candidate errors: {}", kernel_probe_errors.join("; "))
			};
			Err(Error::TxHashSetErr(format!(
				"failed to open kernel PMMR{}",
				details
			)))
		}
	}

	/// Close all backend file handles
	pub fn release_backend_files(&mut self) {
		self.output_pmmr_h.backend.release_files();
		self.rproof_pmmr_h.backend.release_files();
		self.kernel_pmmr_h.backend.release_files();
	}

	/// Check if an output is unspent.
	/// We look in the index to find the output MMR pos.
	/// Then we check the entry in the output MMR and confirm the hash matches.
	pub fn get_unspent(
		&self,
		commit: Commitment,
	) -> Result<Option<(OutputIdentifier, CommitPos)>, Error> {
		match self.commit_index.get_output_pos_height(&commit) {
			Ok(Some(pos1)) => {
				let output_pmmr: ReadonlyPMMR<'_, OutputIdentifier, _> =
					ReadonlyPMMR::at(&self.output_pmmr_h.backend, self.output_pmmr_h.size);
				let pos0 = pos1.pos.checked_sub(1).ok_or_else(|| {
					mwc_store::Error::DataOverflow(format!(
						"TxHashSet::get_unspent pos1.pos={}",
						pos1.pos
					))
				})?;
				match output_pmmr.get_data(pos0)? {
					Some(out) if out.commitment() == commit => Ok(Some((out, pos1))),
					Some(out) => Err(Error::TxHashSetErr(format!(
						"output_pos index mismatch for commitment {:?}: index points to {:?} at pos {}",
						commit,
						out.commitment(),
						pos1.pos
					))),
					None => Err(Error::TxHashSetErr(format!(
						"output_pos index points to missing output at pos {} for commitment {:?}",
						pos1.pos, commit
					))),
				}
			}
			Ok(None) => Ok(None),
			Err(e) => Err(Error::StoreErr(e, "txhashset unspent check".to_string())),
		}
	}

	/// Returns up to distance unpruned nodes found by scanning backward along
	/// the bottom of the tree.
	/// Pruned/compacted leaves do not count toward distance, so results may
	/// include entries older than the most recent distance insertion positions.
	/// TODO: These need to return the actual data from the flat-files instead
	/// of hashes now
	pub fn last_n_output(&self, distance: u64) -> Result<Vec<(Hash, OutputIdentifier)>, Error> {
		Ok(
			ReadonlyPMMR::at(&self.output_pmmr_h.backend, self.output_pmmr_h.size)
				.get_last_n_insertions(distance)?,
		)
	}

	/// as above, for range proofs
	pub fn last_n_rangeproof(&self, distance: u64) -> Result<Vec<(Hash, RangeProof)>, Error> {
		let proofs = ReadonlyPMMR::at(&self.rproof_pmmr_h.backend, self.rproof_pmmr_h.size)
			.get_last_n_insertions(distance)?;
		Ok(proofs
			.into_iter()
			.map(|(hash, proof)| (hash, proof.into()))
			.collect())
	}

	/// as above, for kernels
	pub fn last_n_kernel(&self, distance: u64) -> Result<Vec<(Hash, TxKernel)>, Error> {
		Ok(
			ReadonlyPMMR::at(&self.kernel_pmmr_h.backend, self.kernel_pmmr_h.size)
				.get_last_n_insertions(distance)?,
		)
	}

	/// Get a kernel by 1-based kernel MMR position.
	pub fn get_kernel_by_mmr_index(&self, pos: u64) -> Result<Option<TxKernel>, Error> {
		if pos == 0 {
			return Err(Error::DataOverflow(
				"TxHashSet::get_kernel_by_mmr_index, pos=0".to_string(),
			));
		}
		if pos > self.kernel_pmmr_h.size {
			return Ok(None);
		}
		let pos0 = pos.checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!("TxHashSet::get_kernel_by_mmr_index, pos={}", pos))
		})?;
		Ok(
			ReadonlyPMMR::at(&self.kernel_pmmr_h.backend, self.kernel_pmmr_h.size)
				.get_data(pos0)?,
		)
	}

	/// Efficient view into the kernel PMMR based on size in header.
	pub fn kernel_pmmr_at(
		&'_ self,
		header: &BlockHeader,
	) -> ReadonlyPMMR<'_, TxKernel, PMMRBackend<TxKernel>> {
		ReadonlyPMMR::at(&self.kernel_pmmr_h.backend, header.kernel_mmr_size)
	}

	/// Efficient view into the output PMMR based on size in header.
	pub fn output_pmmr_at(
		&'_ self,
		header: &BlockHeader,
	) -> ReadonlyPMMR<'_, OutputIdentifier, PMMRBackend<OutputIdentifier>> {
		ReadonlyPMMR::at(&self.output_pmmr_h.backend, header.output_mmr_size)
	}

	/// Efficient view into the rangeproof PMMR based on size in header.
	pub fn rangeproof_pmmr_at(
		&'_ self,
		header: &BlockHeader,
	) -> ReadonlyPMMR<'_, RangeProof, PMMRBackend<RangeProof>> {
		ReadonlyPMMR::at(&self.rproof_pmmr_h.backend, header.output_mmr_size)
	}

	/// Convenience function to query the db for a header by its hash.
	pub fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, Error> {
		Ok(self.commit_index.get_block_header(&hash)?)
	}

	/// returns outputs from the given pmmr index up to the
	/// specified limit. Also returns the last index actually populated
	/// max index is the last PMMR index to consider, not leaf index
	/// Returned output PMMR indexes are 1-based.
	pub fn outputs_by_pmmr_index(
		&self,
		start_index: u64,
		max_count: u64,
		max_index: Option<u64>,
	) -> Result<(u64, Vec<(u64, OutputIdentifier)>), Error> {
		Ok(
			ReadonlyPMMR::at(&self.output_pmmr_h.backend, self.output_pmmr_h.size)
				.elements_from_pmmr_index(start_index, max_count, max_index)?,
		)
	}

	/// As above, for rangeproofs.
	/// Returned rangeproof PMMR indexes are 1-based.
	pub fn rangeproofs_by_pmmr_index(
		&self,
		start_index: u64,
		max_count: u64,
		max_index: Option<u64>,
	) -> Result<(u64, Vec<(u64, RangeProof)>), Error> {
		let (index, proofs) =
			ReadonlyPMMR::at(&self.rproof_pmmr_h.backend, self.rproof_pmmr_h.size)
				.elements_from_pmmr_index(start_index, max_count, max_index)?;
		Ok((
			index,
			proofs
				.into_iter()
				.map(|(pos, proof)| (pos, proof.into()))
				.collect(),
		))
	}

	/// size of output mmr
	pub fn output_mmr_size(&self) -> u64 {
		self.output_pmmr_h.size
	}

	/// size of kernel mmr
	pub fn kernel_mmr_size(&self) -> u64 {
		self.kernel_pmmr_h.size
	}

	/// size of rangeproof mmr (can differ from output mmr size during PIBD sync)
	pub fn rangeproof_mmr_size(&self) -> u64 {
		self.rproof_pmmr_h.size
	}

	/// Find a kernel with a given excess. Work backwards from `max_index` to `min_index`
	/// NOTE: this linear search over all kernel history can be VERY expensive
	/// public API access to this method should be limited
	pub fn find_kernel(
		&self,
		excess: &Commitment,
		min_index: Option<u64>,
		max_index: Option<u64>,
	) -> Result<Option<(TxKernel, u64)>, Error> {
		let min_index = min_index.unwrap_or(1);
		if min_index == 0 {
			return Err(Error::DataOverflow(
				"TxHashSet::find_kernel, min_index=0".to_string(),
			));
		}
		let max_index = max_index
			.unwrap_or(self.kernel_pmmr_h.size)
			.min(self.kernel_pmmr_h.size);
		if min_index > max_index {
			return Ok(None);
		}

		let pmmr = ReadonlyPMMR::at(&self.kernel_pmmr_h.backend, self.kernel_pmmr_h.size);
		let mut index = max_index.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("TxHashSet::find_kernel, max_index={}", max_index))
		})?;
		while index > min_index {
			// safe because index > min_index, so index>1
			index -= 1;
			// 'index-1' is safe because index>0 now
			if let Some(kernel) = pmmr.get_data(index - 1)? {
				if &kernel.excess == excess {
					return Ok(Some((kernel, index)));
				}
			}
		}
		Ok(None)
	}

	/// Get MMR roots.
	pub fn roots(&self) -> Result<TxHashSetRoots, Error> {
		debug!(
			"Generating MMR roots at sizes: Outputs: {}  Rangeproofs: {}  Kernels: {}",
			self.output_pmmr_h.size, self.rproof_pmmr_h.size, self.kernel_pmmr_h.size
		);
		let output_pmmr = ReadonlyPMMR::at(&self.output_pmmr_h.backend, self.output_pmmr_h.size);
		let rproof_pmmr = ReadonlyPMMR::at(&self.rproof_pmmr_h.backend, self.rproof_pmmr_h.size);
		let kernel_pmmr = ReadonlyPMMR::at(&self.kernel_pmmr_h.backend, self.kernel_pmmr_h.size);

		Ok(TxHashSetRoots {
			output_root: output_pmmr.root()?,
			output_mmr_size: self.output_pmmr_h.size,
			rproof_root: rproof_pmmr.root()?,
			rproof_mmr_size: self.rproof_pmmr_h.size,
			kernel_root: kernel_pmmr.root()?,
			kernel_mmr_size: self.kernel_pmmr_h.size,
		})
	}

	/// Return Commit's MMR position
	pub fn get_output_pos(&self, commit: &Commitment) -> Result<u64, Error> {
		let pos0 = self.commit_index.get_output_pos(commit)?;
		let output_pmmr = ReadonlyPMMR::at(&self.output_pmmr_h.backend, self.output_pmmr_h.size);
		match output_pmmr.get_data(pos0)? {
			Some(out) if out.commitment() == *commit => Ok(pos0),
			Some(out) => Err(Error::TxHashSetErr(format!(
				"output_pos index mismatch for commitment {:?}: index points to {:?} at pos {}",
				commit,
				out.commitment(),
				pos0 + 1 // pos0+1 is acceptable because it is an error message
			))),
			None => Err(Error::TxHashSetErr(format!(
				"output_pos index points to missing output at pos {} for commitment {:?}",
				pos0 + 1, // pos0+1 is acceptable because it is an error message
				commit
			))),
		}
	}

	/// build a new merkle proof for the given output commitment
	pub fn merkle_proof(&mut self, commit: Commitment) -> Result<MerkleProof, Error> {
		let pos0 = self.commit_index.get_output_pos(&commit)?;
		let output_pmmr = PMMR::at(&mut self.output_pmmr_h.backend, self.output_pmmr_h.size);
		match output_pmmr.get_data(pos0)? {
			Some(out) if out.commitment() == commit => {
				output_pmmr.merkle_proof(pos0).map_err(|e| {
					Error::MerkleProof(format!("Commit {:?}, pos {}, {}", commit, pos0, e))
				})
			}
			Some(out) => Err(Error::TxHashSetErr(format!(
				"output_pos index mismatch for commitment {:?}: index points to {:?} at pos {}",
				commit,
				out.commitment(),
				pos0 + 1 // pos0+1 os acceptable because it is a error message
			))),
			None => Err(Error::TxHashSetErr(format!(
				"output_pos index points to missing output at pos {} for commitment {:?}",
				pos0 + 1, // pos0+1 os acceptable because it is a error message
				commit
			))),
		}
	}

	/// Compact the MMR data files and flush the rm logs
	pub fn compact(
		&mut self,
		horizon_header: &BlockHeader,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		debug!("txhashset: starting compaction...");

		let head_header = batch.head_header()?;

		let rewind_rm_pos = input_pos_to_rewind(&horizon_header, &head_header, batch)?;

		debug!("txhashset: check_compact output mmr backend...");
		self.output_pmmr_h
			.backend
			.check_compact(horizon_header.output_mmr_size, &rewind_rm_pos)?;

		debug!("txhashset: check_compact rangeproof mmr backend...");
		self.rproof_pmmr_h
			.backend
			.check_compact(horizon_header.output_mmr_size, &rewind_rm_pos)?;

		debug!("txhashset: ... compaction finished");

		Ok(())
	}

	/// (Re)build the NRD kernel_pos index based on 2 weeks of recent kernel history.
	pub fn init_recent_kernel_pos_index(
		&self,
		header_pmmr: &PMMRHandle<BlockHeader>,
		batch: &Batch<'_>,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		let now = Instant::now();
		let head = batch.head()?;
		// Safe: WEEK_HEIGHT is a small fixed consensus constant.
		let cutoff = head.height.saturating_sub(WEEK_HEIGHT * 2);
		let cutoff_hash = header_pmmr.get_header_hash_by_height(cutoff)?;
		let cutoff_header = batch.get_block_header(&cutoff_hash)?;
		info!(
			"init_recent_kernel_pos_index: starting recent NRD kernel_pos index rebuild from height {} to {}",
			cutoff, head.height
		);
		self.verify_kernel_pos_index_with_status(
			&cutoff_header,
			header_pmmr,
			batch,
			status,
			stop_state,
			true,
		)?;
		info!(
			"init_recent_kernel_pos_index: finished recent NRD kernel_pos index rebuild, took {}s",
			now.elapsed().as_secs(),
		);
		Ok(())
	}

	fn update_output_pos_index_build_status(
		status: &Option<Arc<SyncState>>,
		status_throttle: &SyncStatusUpdateThrottle,
		outputs: u64,
		outputs_total: u64,
		force: bool,
	) {
		if let Some(status) = status {
			if status_throttle.should_update(force) {
				status.update(SyncStatus::TxHashsetOutputPosIndexBuild {
					outputs: outputs.min(outputs_total),
					outputs_total,
				});
			}
		}
	}

	fn update_kernel_pos_index_build_status(
		status: &Option<Arc<SyncState>>,
		status_throttle: &SyncStatusUpdateThrottle,
		kernels: u64,
		kernels_total: u64,
		force: bool,
	) {
		if let Some(status) = status {
			if status_throttle.should_update(force) {
				status.update(SyncStatus::TxHashsetKernelPosIndexBuild {
					kernels: kernels.min(kernels_total),
					kernels_total,
				});
			}
		}
	}

	fn should_log_index_rebuild_progress(last_log: &mut Instant, force: bool) -> bool {
		if force || last_log.elapsed().as_secs() >= INDEX_REBUILD_LOG_INTERVAL_SECS {
			*last_log = Instant::now();
			true
		} else {
			false
		}
	}

	fn check_stop_state(stop_state: &Option<Arc<StopState>>) -> Result<(), Error> {
		if let Some(stop_state) = stop_state {
			if stop_state.is_stopped() {
				return Err(Error::Stopped);
			}
		}
		Ok(())
	}

	/// (Re)build the full kernel excess index in committed chunks.
	pub fn init_kernel_pos_index_chunked(
		&self,
		store: &ChainStore,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		let now = Instant::now();
		let total_kernels = pmmr::n_leaves(self.kernel_pmmr_h.size)?;
		let status_throttle = SyncStatusUpdateThrottle::new();
		let mut last_progress_log = Instant::now();
		let cleared = Self::clear_kernel_pos_index_chunked(store, &stop_state)?;

		let context_id = self.commit_index.get_context_id();
		let kernel_pmmr = ReadonlyPMMR::at(&self.kernel_pmmr_h.backend, self.kernel_pmmr_h.size);
		let mut current = store.head_header()?;
		let mut batch = store.batch_write()?;
		let mut pending = 0usize;
		let mut total = 0usize;

		info!(
			"init_kernel_pos_index_chunked: starting full kernel_pos index rebuild, cleared {} entries, kernel_mmr_size {}, kernels {}, chunk size {}",
			cleared,
			self.kernel_pmmr_h.size,
			total_kernels,
			KERNEL_POS_INDEX_REBUILD_CHUNK_SIZE,
		);
		Self::update_kernel_pos_index_build_status(
			&status,
			&status_throttle,
			0,
			total_kernels,
			true,
		);

		loop {
			let prev_header = if current.height == 0 {
				None
			} else {
				Some(store.get_previous_header(&current)?)
			};
			let prev_kernel_mmr_size = prev_header
				.as_ref()
				.map(|header| header.kernel_mmr_size)
				.unwrap_or(0);
			if prev_kernel_mmr_size > current.kernel_mmr_size {
				return Err(Error::Other(format!(
					"init_kernel_pos_index_chunked found kernel MMR size regression at height {}: previous {}, current {}",
					current.height, prev_kernel_mmr_size, current.kernel_mmr_size
				)));
			}
			if current.kernel_mmr_size > self.kernel_pmmr_h.size {
				return Err(Error::InvalidHeaderHeight(current.height));
			}

			let start_pos = prev_kernel_mmr_size.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"TxHashSet::init_kernel_pos_index_chunked, prev_kernel_mmr_size={}",
					prev_kernel_mmr_size
				))
			})?;
			for pos in start_pos..=current.kernel_mmr_size {
				let pos0 = pos.checked_sub(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"TxHashSet::init_kernel_pos_index_chunked, pos={}",
						pos
					))
				})?;
				if !pmmr::is_leaf(pos0) {
					continue;
				}
				let kernel = kernel_pmmr.get_data(pos0)?.ok_or_else(|| {
					Error::TxHashSetErr(format!(
						"init_kernel_pos_index_chunked missing kernel PMMR data at pos {} for header {} at {}",
						pos,
						current.hash(context_id).unwrap_or(ZERO_HASH),
						current.height
					))
				})?;
				batch.save_kernel_pos(
					&kernel.excess(),
					KernelPos {
						pos,
						height: current.height,
					},
				)?;
				pending += 1;
				total += 1;

				if pending >= KERNEL_POS_INDEX_REBUILD_CHUNK_SIZE {
					batch.commit()?;
					Self::check_stop_state(&stop_state)?;
					batch = store.batch_write()?;
					pending = 0;
					let total_u64 = u64::try_from(total).unwrap_or(u64::MAX);
					Self::update_kernel_pos_index_build_status(
						&status,
						&status_throttle,
						total_u64,
						total_kernels,
						total_u64 == total_kernels,
					);
					if Self::should_log_index_rebuild_progress(&mut last_progress_log, false) {
						info!(
							"init_kernel_pos_index_chunked: rebuilt {} of {} kernel_pos entries",
							total_u64, total_kernels
						);
					}
				}
				Self::check_stop_state(&stop_state)?;
			}

			if let Some(prev_header) = prev_header {
				current = prev_header;
			} else {
				break;
			}
		}

		batch.set_kernel_pos_index_complete(true)?;
		batch.commit()?;

		let total_u64 = u64::try_from(total).unwrap_or(u64::MAX);
		Self::update_kernel_pos_index_build_status(
			&status,
			&status_throttle,
			total_u64,
			total_kernels,
			true,
		);
		info!(
			"init_kernel_pos_index_chunked: rebuilt {} entries after clearing {} entries, took {}s",
			total,
			cleared,
			now.elapsed().as_secs(),
		);
		Ok(())
	}

	fn clear_kernel_pos_index_chunked(
		store: &ChainStore,
		stop_state: &Option<Arc<StopState>>,
	) -> Result<usize, Error> {
		let mut total = 0usize;
		loop {
			let batch = store.batch_write()?;
			if total == 0 {
				batch.set_kernel_pos_index_complete(false)?;
			}
			let deleted =
				batch.clear_kernel_pos_index_chunk(KERNEL_POS_INDEX_REBUILD_CHUNK_SIZE)?;
			batch.commit()?;
			Self::check_stop_state(stop_state)?;
			total = total.saturating_add(deleted);
			if deleted < KERNEL_POS_INDEX_REBUILD_CHUNK_SIZE {
				break;
			}
		}
		Ok(total)
	}

	/// Verify and (re)build the NRD kernel_pos index from the provided header onwards.
	pub fn verify_kernel_pos_index(
		&self,
		from_header: &BlockHeader,
		header_pmmr: &PMMRHandle<BlockHeader>,
		batch: &Batch<'_>,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		self.verify_kernel_pos_index_with_status(
			from_header,
			header_pmmr,
			batch,
			status,
			stop_state,
			false,
		)
	}

	fn verify_kernel_pos_index_with_status(
		&self,
		from_header: &BlockHeader,
		header_pmmr: &PMMRHandle<BlockHeader>,
		batch: &Batch<'_>,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
		build_status: bool,
	) -> Result<(), Error> {
		let context_id = self.commit_index.get_context_id();
		if !global::is_nrd_enabled(context_id) {
			return Ok(());
		}

		let now = Instant::now();
		let kernel_index = store::nrd_recent_kernel_index();
		kernel_index.clear(batch)?;

		let prev_size = if from_header.height == 0 {
			0
		} else {
			let prev_header = batch.get_previous_header(&from_header)?;
			prev_header.kernel_mmr_size
		};

		debug!(
			"verify_kernel_pos_index: header: {} at {}, prev kernel_mmr_size: {}",
			from_header.hash(context_id)?,
			from_header.height,
			prev_size,
		);

		let kernel_pmmr = ReadonlyPMMR::at(&self.kernel_pmmr_h.backend, self.kernel_pmmr_h.size);

		let mut current_pos = prev_size.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"TxHashSet::verify_kernel_pos_index, prev_size={}",
				prev_size
			))
		})?;
		let mut current_header = from_header.clone();
		let mut count = 0u64;
		let total = pmmr::n_leaves(self.kernel_pmmr_h.size)?
			.checked_sub(pmmr::n_leaves(prev_size)?)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"TxHashSet::verify_kernel_pos_index, prev_size={}, kernel_pmmr_size={}",
					prev_size, self.kernel_pmmr_h.size
				))
			})?;
		let mut applied = 0u64;
		let status_throttle = SyncStatusUpdateThrottle::new();
		if let Some(ref s) = status {
			if build_status {
				s.update(SyncStatus::TxHashsetKernelPosIndexBuild {
					kernels: 0,
					kernels_total: total,
				});
			} else {
				s.update(SyncStatus::TxHashsetKernelsPosValidation {
					kernel_pos: 0,
					kernel_pos_total: total,
				});
			}
		}
		while current_pos <= self.kernel_pmmr_h.size {
			let current_pos0 = current_pos.checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"TxHashSet::verify_kernel_pos_index, current_pos={}",
					current_pos
				))
			})?;
			if pmmr::is_leaf(current_pos0) {
				if let Some(kernel) = kernel_pmmr.get_data(current_pos0)? {
					match kernel.features {
						KernelFeatures::NoRecentDuplicate { .. } => {
							while current_pos > current_header.kernel_mmr_size {
								let hash = header_pmmr.get_header_hash_by_height(
									current_header.height.checked_add(1).ok_or_else(|| {
										Error::DataOverflow(format!(
											"TxHashSet::verify_kernel_pos_index, current_header_height={}",
											current_header.height
										))
									})?,
								)?;
								current_header = batch.get_block_header(&hash)?;
							}
							let new_pos = CommitPos {
								pos: current_pos,
								height: current_header.height,
							};
							apply_kernel_rules(&kernel, new_pos, batch)?;
							// Count is used for debug purpose, data overflow is safe
							count += 1;
						}
						_ => {}
					}
				}
				// Applied is used for UI monitoring (value is less than total), data overflow is safe
				applied += 1;
				if let Some(ref s) = status {
					if status_throttle.should_update(applied == total) {
						if build_status {
							s.update(SyncStatus::TxHashsetKernelPosIndexBuild {
								kernels: applied,
								kernels_total: total,
							});
						} else {
							s.update(SyncStatus::TxHashsetKernelsPosValidation {
								kernel_pos: applied,
								kernel_pos_total: total,
							});
						}
					}
				}
			}
			if let Some(ref s) = stop_state {
				if s.is_stopped() {
					return Err(Error::Stopped);
				}
			}

			current_pos = current_pos.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"TxHashSet::verify_kernel_pos_index, current_pos={}",
					current_pos
				))
			})?;
		}

		if let Some(ref s) = status {
			if build_status {
				s.update(SyncStatus::TxHashsetKernelPosIndexBuild {
					kernels: applied,
					kernels_total: total,
				});
			} else {
				s.update(SyncStatus::TxHashsetKernelsPosValidation {
					kernel_pos: applied,
					kernel_pos_total: total,
				});
			}
		}
		debug!(
			"verify_kernel_pos_index: pushed {} entries to the index, took {}s",
			count,
			now.elapsed().as_secs(),
		);
		Ok(())
	}

	/// (Re)build the output_pos index to be consistent with the current UTXO set.
	/// Remove any "stale" index entries that do not correspond to outputs in the UTXO set.
	/// Add any missing index entries based on UTXO set.
	pub fn init_output_pos_index(
		&self,
		batch: &Batch<'_>,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		let now = Instant::now();

		let output_pmmr = ReadonlyPMMR::at(&self.output_pmmr_h.backend, self.output_pmmr_h.size);
		let total_utxos = output_pmmr.n_unpruned_leaves()?;
		let status_throttle = SyncStatusUpdateThrottle::new();
		let mut last_progress_log = Instant::now();

		info!(
			"init_output_pos_index: starting output_pos index rebuild, output_mmr_size {}, utxos {}",
			self.output_pmmr_h.size, total_utxos
		);
		Self::update_output_pos_index_build_status(&status, &status_throttle, 0, total_utxos, true);

		// Iterate over the current output_pos index, removing any entries that
		// do not point to to the expected output.
		let mut stale_keys = Vec::new();
		for item in batch.output_pos_iter()? {
			Self::check_stop_state(&stop_state)?;
			let (key, pos1) = item?;
			let pos0 = pos1.pos.checked_sub(1).ok_or_else(|| {
				mwc_store::Error::DataOverflow(format!(
					"TxHashSet::init_output_pos_index pos1.pos={}",
					pos1.pos
				))
			})?;
			let stale = if let Some(out) = output_pmmr.get_data(pos0)? {
				match batch.get_output_pos(&out.commitment()) {
					Ok(pos0_via_mmr) => {
						// If the pos matches and the index key matches the commitment
						// then keep the entry, otherwise we want to clean it up.
						!(pos0 == pos0_via_mmr
							&& batch.is_match_output_pos_key(&key, &out.commitment()))
					}
					Err(NotFoundErr(_)) => true,
					Err(e) => {
						return Err(Error::StoreErr(
							e,
							"init output_pos index lookup".to_owned(),
						));
					}
				}
			} else {
				true
			};
			if stale {
				stale_keys.push(key);
			}
		}
		let removed_count = stale_keys.len();
		for key in stale_keys {
			Self::check_stop_state(&stop_state)?;
			batch.delete(&key)?;
		}
		Self::check_stop_state(&stop_state)?;
		info!(
			"init_output_pos_index: removed {} stale index entries",
			removed_count
		);

		let mut output_ranges = Vec::new();
		let mut current = batch.head_header()?;
		loop {
			let prev_header = if current.height == 0 {
				None
			} else {
				Some(batch.get_previous_header(&current)?)
			};
			let prev_output_mmr_size = prev_header
				.as_ref()
				.map(|header| header.output_mmr_size)
				.unwrap_or(0);
			if prev_output_mmr_size > current.output_mmr_size {
				return Err(Error::Other(format!(
					"init_output_pos_index found output MMR size regression at height {}: previous {}, current {}",
					current.height, prev_output_mmr_size, current.output_mmr_size
				)));
			}
			if current.output_mmr_size > self.output_pmmr_h.size {
				return Err(Error::InvalidHeaderHeight(current.height));
			}
			if current.output_mmr_size > prev_output_mmr_size {
				output_ranges.push((current.output_mmr_size, current.height));
			}

			Self::check_stop_state(&stop_state)?;
			if let Some(prev_header) = prev_header {
				current = prev_header;
			} else {
				break;
			}
		}
		output_ranges.reverse();

		info!(
			"init_output_pos_index: streaming height mapping for {} utxos across {} output ranges",
			total_utxos,
			output_ranges.len()
		);

		let mut range_idx = 0usize;
		let mut processed_outputs = 0u64;
		let mut mapped_outputs = 0u64;
		let mut unmapped_outputs = 0u64;
		let mut updated_count = 0usize;
		for pos0 in output_pmmr.leaf_pos_iter()? {
			Self::check_stop_state(&stop_state)?;
			let pos0 = pos0?;
			if let Some(out) = output_pmmr.get_data(pos0)? {
				let pos1 = pos0.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!("TxHashSet::init_output_pos_index, pos0={}", pos0))
				})?;
				while range_idx < output_ranges.len() && pos1 > output_ranges[range_idx].0 {
					range_idx += 1;
				}
				if range_idx == output_ranges.len() {
					unmapped_outputs = unmapped_outputs.saturating_add(1);
				} else {
					let expected_pos = CommitPos {
						pos: pos1,
						height: output_ranges[range_idx].1,
					};
					match batch.get_output_pos_height(&out.commitment()) {
						Ok(Some(existing_pos)) if existing_pos == expected_pos => {}
						Ok(_) => {
							batch.save_output_pos_height(&out.commitment(), expected_pos)?;
							updated_count += 1;
						}
						Err(e) => {
							return Err(Error::StoreErr(
								e,
								"init output_pos index height lookup".to_owned(),
							));
						}
					}
					mapped_outputs = mapped_outputs.saturating_add(1);
				}
				processed_outputs = processed_outputs.saturating_add(1);
				Self::update_output_pos_index_build_status(
					&status,
					&status_throttle,
					processed_outputs,
					total_utxos,
					processed_outputs == total_utxos,
				);
				if Self::should_log_index_rebuild_progress(&mut last_progress_log, false) {
					info!(
						"init_output_pos_index: processed {} of {} utxos",
						processed_outputs, total_utxos
					);
				}
			}
		}

		if unmapped_outputs != 0 {
			return Err(Error::Other(format!(
				"init_output_pos_index failed to map {} of {} utxos to block heights",
				unmapped_outputs, processed_outputs
			)));
		}
		Self::check_stop_state(&stop_state)?;
		Self::update_output_pos_index_build_status(
			&status,
			&status_throttle,
			processed_outputs,
			total_utxos,
			true,
		);
		batch.set_output_pos_index_complete(true)?;
		info!(
			"init_output_pos_index: finished output_pos index rebuild, updated entries for {} of {} utxos, removed {} stale entries, took {}s",
			updated_count,
			mapped_outputs,
			removed_count,
			now.elapsed().as_secs(),
		);
		Ok(())
	}
}

fn record_discard_result<E>(first_err: &mut Option<Error>, result: Result<(), E>)
where
	E: Into<Error>,
{
	if let Err(e) = result {
		if first_err.is_none() {
			*first_err = Some(e.into());
		}
	}
}

fn discard_result(discard_err: Option<Error>) -> Result<(), Error> {
	discard_err.map_or(Ok(()), Err)
}

fn result_with_discard<T, E>(
	primary: Result<T, Error>,
	discard: Result<(), E>,
	context: &str,
) -> Result<T, Error>
where
	E: Into<Error>,
{
	let discard = discard.map_err(|e| e.into());
	match (primary, discard) {
		(Ok(r), Ok(())) => Ok(r),
		(Ok(_), Err(discard)) => Err(Error::TxHashSetDiscard {
			context: context.to_owned(),
			discard: Box::new(discard),
		}),
		(Err(e), Ok(())) => Err(e),
		(Err(primary), Err(discard)) => Err(Error::TxHashSetDiscardAfterError {
			context: context.to_owned(),
			primary: Box::new(primary),
			discard: Box::new(discard),
		}),
	}
}

fn discard_txhashset_backends(trees: &mut TxHashSet) -> Result<(), Error> {
	let mut first_err = None;
	record_discard_result(&mut first_err, trees.output_pmmr_h.backend.discard());
	record_discard_result(&mut first_err, trees.rproof_pmmr_h.backend.discard());
	record_discard_result(&mut first_err, trees.kernel_pmmr_h.backend.discard());
	discard_result(first_err)
}

/// Starts a new unit of work to extend (or rewind) the chain with additional
/// blocks. Accepts a closure that will operate within that unit of work.
/// The closure has access to an Extension object that allows the addition
/// of blocks to the txhashset and the checking of the current tree roots.
///
/// The unit of work is always discarded (always rollback) as this is read-only.
pub fn extending_readonly<F, T>(
	context_id: u32,
	handle: &mut PMMRHandle<BlockHeader>,
	trees: &mut TxHashSet,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&mut ExtensionPair<'_>, &Batch<'_>) -> Result<T, Error>,
{
	let commit_index = trees.commit_index.clone();
	let batch = commit_index.batch_write()?;

	trace!("Starting new txhashset (readonly) extension.");

	let head = batch.head()?;
	let header_head = batch.header_head()?;

	let res = {
		let header_pmmr = PMMR::at(&mut handle.backend, handle.size);
		let mut header_extension = HeaderExtension::new(header_pmmr, header_head);
		let mut extension = Extension::new(context_id, trees, head);
		let mut extension_pair = ExtensionPair {
			header_extension: &mut header_extension,
			extension: &mut extension,
		};
		inner(&mut extension_pair, &batch)
	};

	trace!("Rollbacking txhashset (readonly) extension.");

	let mut discard_err = None;
	record_discard_result(&mut discard_err, handle.backend.discard());
	record_discard_result(&mut discard_err, discard_txhashset_backends(trees));

	trace!("TxHashSet (readonly) extension done.");

	result_with_discard(res, discard_result(discard_err), "extending_readonly")
}

/// Readonly view on the UTXO set.
/// Based on the current txhashset output_pmmr.
pub fn utxo_view<F, T>(
	handle: &PMMRHandle<BlockHeader>,
	trees: &TxHashSet,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&UTXOView<'_>, &Batch<'_>) -> Result<T, Error>,
{
	let res: Result<T, Error>;
	{
		let header_pmmr = ReadonlyPMMR::at(&handle.backend, handle.size);
		let output_pmmr = ReadonlyPMMR::at(&trees.output_pmmr_h.backend, trees.output_pmmr_h.size);
		let rproof_pmmr = ReadonlyPMMR::at(&trees.rproof_pmmr_h.backend, trees.rproof_pmmr_h.size);

		// Create a new batch here to pass into the utxo_view.
		// Discard it (rollback) after we finish with the utxo_view.
		let batch = trees.commit_index.batch_read()?;
		let utxo = UTXOView::new(header_pmmr, output_pmmr, rproof_pmmr);
		res = inner(&utxo, &batch);
	}
	res
}

/// Rewindable (but still readonly) view on the kernel MMR.
/// The underlying backend is readonly. But we permit the PMMR to be "rewound"
/// via size.
/// We create a new db batch for this view and discard it (rollback)
/// when we are done with the view.
pub fn rewindable_kernel_view<F, T>(trees: &TxHashSet, inner: F) -> Result<T, Error>
where
	F: FnOnce(&mut RewindableKernelView<'_>, &Batch<'_>) -> Result<T, Error>,
{
	let res: Result<T, Error>;
	{
		let kernel_pmmr =
			RewindablePMMR::at(&trees.kernel_pmmr_h.backend, trees.kernel_pmmr_h.size);

		// Create a new batch here to pass into the kernel_view.
		// Discard it (rollback) after we finish with the kernel_view.
		let batch = trees.commit_index.batch_read()?;
		let header = batch.head_header()?;
		let mut view = RewindableKernelView::new(kernel_pmmr, header);
		res = inner(&mut view, &batch);
	}
	res
}

/// Starts a new unit of work to extend the chain with additional blocks,
/// accepting a closure that will work within that unit of work. The closure
/// has access to an Extension object that allows the addition of blocks to
/// the txhashset and the checking of the current tree roots.
///
/// If the closure returns an error, modifications are canceled and the unit
/// of work is abandoned. Otherwise, the unit of work is permanently applied.
pub fn extending<'a, F, T>(
	header_pmmr: &'a mut PMMRHandle<BlockHeader>,
	trees: &'a mut TxHashSet,
	batch: &'a mut Batch<'_>,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&mut ExtensionPair<'_>, &Batch<'_>) -> Result<T, Error>,
{
	let head = batch.head()?;
	extending_with_head(header_pmmr, trees, batch, head, inner)
}

/// Starts a new unit of work using an explicit body head for the extension.
///
/// This is for callers such as PIBD finalization where the txhashset PMMRs have
/// already been rebuilt to a known archive header, but the durable DB body head
/// must not be moved until validation succeeds.
pub fn extending_with_head<'a, F, T>(
	header_pmmr: &'a mut PMMRHandle<BlockHeader>,
	trees: &'a mut TxHashSet,
	batch: &'a mut Batch<'_>,
	head: Tip,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&mut ExtensionPair<'_>, &Batch<'_>) -> Result<T, Error>,
{
	let sizes: (u64, u64, u64);
	let res: Result<T, Error>;
	let rollback: bool;
	let context_id = batch.db.get_context_id();

	let header_head = batch.header_head()?;

	// create a child transaction so if the state is rolled back by itself, all
	// index saving can be undone
	let child_batch = batch.child()?;
	{
		trace!("Starting new txhashset extension.");

		let header_pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
		let mut header_extension = HeaderExtension::new(header_pmmr, header_head);
		let mut extension = Extension::new(context_id, trees, head);
		let mut extension_pair = ExtensionPair {
			header_extension: &mut header_extension,
			extension: &mut extension,
		};
		res = inner(&mut extension_pair, &child_batch);

		rollback = extension_pair.extension.rollback;
		sizes = extension_pair.extension.sizes();
	}

	// During an extension we do not want to modify the header_extension (and only read from it).
	// So make sure we discard any changes to the header MMR backed.
	let header_discard = header_pmmr.backend.discard();

	match res {
		Err(inner_err) => {
			debug!(
				"Error returned, discarding txhashset extension: {}",
				inner_err
			);
			let mut discard_err = None;
			record_discard_result(&mut discard_err, header_discard);
			record_discard_result(&mut discard_err, discard_txhashset_backends(trees));
			result_with_discard(Err(inner_err), discard_result(discard_err), "extending")
		}
		Ok(r) => {
			if rollback {
				trace!("Rollbacking txhashset extension. sizes {:?}", sizes);
				let mut discard_err = None;
				record_discard_result(&mut discard_err, header_discard);
				record_discard_result(&mut discard_err, discard_txhashset_backends(trees));
				result_with_discard(Ok(()), discard_result(discard_err), "extending rollback")?;
			} else {
				let mut discard_err = None;
				record_discard_result(&mut discard_err, header_discard);
				if discard_err.is_some() {
					record_discard_result(&mut discard_err, discard_txhashset_backends(trees));
					result_with_discard(
						Ok(()),
						discard_result(discard_err),
						"extending header discard",
					)?;
				}
				trace!("Committing txhashset extension. sizes {:?}", sizes);
				if let Err(e) = child_batch.commit() {
					let commit_err: Error = e.into();
					return result_with_discard(
						Err(commit_err),
						discard_txhashset_backends(trees),
						"extending commit",
					);
				}
				if let Err(e) = trees.output_pmmr_h.backend.sync() {
					let sync_err: Error = e.into();
					return result_with_discard(
						Err(sync_err),
						discard_txhashset_backends(trees),
						"extending output sync",
					);
				}
				if let Err(e) = trees.rproof_pmmr_h.backend.sync() {
					let sync_err: Error = e.into();
					return result_with_discard(
						Err(sync_err),
						discard_txhashset_backends(trees),
						"extending rangeproof sync",
					);
				}
				if let Err(e) = trees.kernel_pmmr_h.backend.sync() {
					let sync_err: Error = e.into();
					return result_with_discard(
						Err(sync_err),
						discard_txhashset_backends(trees),
						"extending kernel sync",
					);
				}
				trees.output_pmmr_h.size = sizes.0;
				trees.rproof_pmmr_h.size = sizes.1;
				trees.kernel_pmmr_h.size = sizes.2;
			}

			trace!("TxHashSet extension done.");
			Ok(r)
		}
	}
}

/// Start a new readonly header MMR extension.
/// This MMR can be extended individually beyond the other (output, rangeproof and kernel) MMRs
/// to allow headers to be validated before we receive the full block data.
pub fn header_extending_readonly<'a, F, T>(
	handle: &'a mut PMMRHandle<BlockHeader>,
	batch_read: Batch<'_>,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&mut HeaderExtension<'_>, &Batch<'_>) -> Result<T, Error>,
{
	let head = match handle.head_hash() {
		Ok(hash) => {
			let header = batch_read.get_block_header(&hash)?;
			Tip::try_from_header(&header)?
		}
		Err(Error::EmptyMMR) => Tip::default(),
		Err(err) => return Err(err),
	};

	let pmmr = PMMR::at(&mut handle.backend, handle.size);
	let mut extension = HeaderExtension::new(pmmr, head);
	let res = inner(&mut extension, &batch_read);

	result_with_discard(res, handle.backend.discard(), "header_extending_readonly")
}

/// Start a new header MMR unit of work.
/// This MMR can be extended individually beyond the other (output, rangeproof and kernel) MMRs
/// to allow headers to be validated before we receive the full block data.
pub fn header_extending<'a, F, T>(
	handle: &'a mut PMMRHandle<BlockHeader>,
	batch: &'a mut Batch<'_>,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&mut HeaderExtension<'_>, &Batch<'_>) -> Result<T, Error>,
{
	let size: u64;
	let res: Result<T, Error>;
	let rollback: bool;

	// create a child transaction so if the state is rolled back by itself, all
	// index saving can be undone
	let child_batch = batch.child()?;

	let head = match handle.head_hash() {
		Ok(hash) => {
			let header = child_batch.get_block_header(&hash)?;
			Tip::try_from_header(&header)?
		}
		Err(Error::EmptyMMR) => Tip::default(),
		Err(err) => return Err(err),
	};

	{
		let pmmr = PMMR::at(&mut handle.backend, handle.size);
		let mut extension = HeaderExtension::new(pmmr, head);
		res = inner(&mut extension, &child_batch);

		rollback = extension.rollback;
		size = extension.size();
	}

	match res {
		Err(e) => result_with_discard(Err(e), handle.backend.discard(), "header_extending"),
		Ok(r) => {
			if rollback {
				result_with_discard(Ok(r), handle.backend.discard(), "header_extending rollback")
			} else {
				if let Err(e) = child_batch.commit() {
					let commit_err: Error = e.into();
					return result_with_discard(
						Err(commit_err),
						handle.backend.discard(),
						"header_extending commit",
					);
				}
				if let Err(e) = handle.backend.sync() {
					let sync_err: Error = e.into();
					return result_with_discard(
						Err(sync_err),
						handle.backend.discard(),
						"header_extending sync",
					);
				}
				handle.size = size;
				Ok(r)
			}
		}
	}
}

/// A header extension to allow the header MMR to extend beyond the other MMRs individually.
/// This is to allow headers to be validated against the MMR before we have the full block data.
pub struct HeaderExtension<'a> {
	head: Tip,

	pmmr: PMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,

	/// Rollback flag.
	rollback: bool,
}

impl<'a> HeaderExtension<'a> {
	fn new(
		pmmr: PMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
		head: Tip,
	) -> HeaderExtension<'a> {
		HeaderExtension {
			head,
			pmmr,
			rollback: false,
		}
	}

	/// Get the header hash for the specified pos from the underlying MMR backend.
	fn get_header_hash(&self, pos0: u64) -> Result<Option<Hash>, Error> {
		match self.pmmr.get_data(pos0)? {
			None => Ok(None),
			Some(header) => Ok(Some(header.hash(self.pmmr.get_context_id())?)),
		}
	}

	/// The head representing the furthest extent of the current extension.
	pub fn head(&self) -> Tip {
		self.head.clone()
	}

	/// Get header hash by height.
	/// Based on current header MMR.
	pub fn get_header_hash_by_height(&self, height: u64) -> Result<Option<Hash>, Error> {
		let pos = pmmr::insertion_to_pmmr_index(height)?;
		self.get_header_hash(pos)
	}

	/// Get the header at the specified height based on the current state of the header extension.
	/// Derives the MMR pos from the height (insertion index) and retrieves the header hash.
	/// Looks the header up in the db by hash.
	pub fn get_header_by_height(
		&self,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<BlockHeader, Error> {
		if let Some(hash) = self.get_header_hash_by_height(height)? {
			Ok(batch.get_block_header(&hash)?)
		} else {
			Err(Error::Other(format!(
				"not found header for height {}",
				height
			)))
		}
	}

	/// Compares the provided header to the header in the header MMR at that height.
	/// If these match we know the header is on the current chain.
	pub fn is_on_current_chain(&self, t: Tip, batch: &Batch<'_>) -> Result<bool, Error> {
		if t.height > self.head.height {
			return Ok(false);
		}
		let chain_header = self.get_header_by_height(t.height, batch)?;
		let context_id = self.pmmr.get_context_id();
		Ok(chain_header.hash(context_id)? == t.hash(context_id)?)
	}

	/// Force the rollback of this extension, no matter the result.
	pub fn force_rollback(&mut self) {
		self.rollback = true;
	}

	/// Apply a new header to the header MMR extension.
	/// This may be either the header MMR or the sync MMR depending on the
	/// extension.
	pub fn apply_header(&mut self, header: &BlockHeader) -> Result<(), Error> {
		self.pmmr.push(header).map_err(|e| {
			Error::TxHashSetErr(format!(
				"Unable to apply header with height {}, {}",
				header.height, e
			))
		})?;
		self.head = Tip::try_from_header(header)?;
		Ok(())
	}

	/// Rewind the header extension to the specified header.
	/// Note the close relationship between header height and insertion index.
	pub fn rewind(&mut self, header: &BlockHeader) -> Result<(), Error> {
		let context_id = self.pmmr.get_context_id();
		debug!(
			"Rewind header extension to {} at {} from {} at {}",
			header.hash(context_id)?,
			header.height,
			self.head.hash(context_id)?,
			self.head.height,
		);

		let header_pos = pmmr::insertion_to_pmmr_index(header.height)?
			.checked_add(1)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"HeaderExtension::rewind, header_height={}",
					header.height
				))
			})?;
		self.pmmr.rewind(header_pos, &Bitmap::new()).map_err(|e| {
			Error::TxHashSetErr(format!("pmmr rewind for pos {}, {}", header_pos, e))
		})?;

		// Update our head to reflect the header we rewound to.
		self.head = Tip::try_from_header(header)?;

		Ok(())
	}

	/// The size of the header MMR.
	pub fn size(&self) -> u64 {
		self.pmmr.unpruned_size()
	}

	/// The root of the header MMR for convenience.
	pub fn root(&self) -> Result<Hash, Error> {
		Ok(self.pmmr.root()?)
	}

	/// Validate the prev_root of the header against the root of the current header MMR.
	pub fn validate_root(&self, header: &BlockHeader) -> Result<(), Error> {
		// If we are validating the genesis block then we have no prev_root.
		// So we are done here.
		if header.height == 0 {
			return Ok(());
		}
		let root = self.root()?;
		if root != header.prev_root {
			Err(Error::InvalidRoot(format!(
				"Unable to validate root, Expected header.prev_root {}, get {}",
				header.prev_root, root
			)))
		} else {
			Ok(())
		}
	}
}

/// An extension "pair" consisting of a txhashet extension (outputs, rangeproofs, kernels)
/// and the associated header extension.
pub struct ExtensionPair<'a> {
	/// The header extension.
	pub header_extension: &'a mut HeaderExtension<'a>,
	/// The txhashset extension.
	pub extension: &'a mut Extension<'a>,
}

/// Allows the application of new blocks on top of the txhashset in a
/// reversible manner within a unit of work provided by the `extending`
/// function.
pub struct Extension<'a> {
	head: Tip,

	output_pmmr: PMMR<'a, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
	rproof_pmmr: PMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
	kernel_pmmr: PMMR<'a, TxKernel, PMMRBackend<TxKernel>>,
	/// Rollback flag.
	rollback: bool,
	context_id: u32,
}

impl<'a> Extension<'a> {
	fn new(context_id: u32, trees: &'a mut TxHashSet, head: Tip) -> Extension<'a> {
		Extension {
			head,
			output_pmmr: PMMR::at(&mut trees.output_pmmr_h.backend, trees.output_pmmr_h.size),
			rproof_pmmr: PMMR::at(&mut trees.rproof_pmmr_h.backend, trees.rproof_pmmr_h.size),
			kernel_pmmr: PMMR::at(&mut trees.kernel_pmmr_h.backend, trees.kernel_pmmr_h.size),
			rollback: false,
			context_id,
		}
	}

	/// The head representing the furthest extent of the current extension.
	pub fn head(&self) -> Tip {
		self.head.clone()
	}

	/// Build a view of the current UTXO set based on the output PMMR
	/// and the provided header extension.
	pub fn utxo_view(&'a self, header_ext: &'a HeaderExtension<'a>) -> UTXOView<'a> {
		UTXOView::new(
			header_ext.pmmr.readonly_pmmr(),
			self.output_readonly_pmmr(),
			self.rproof_readonly_pmmr(),
		)
	}

	/// Readonly view of our output data.
	pub fn output_readonly_pmmr(
		&'_ self,
	) -> ReadonlyPMMR<'_, OutputIdentifier, PMMRBackend<OutputIdentifier>> {
		self.output_pmmr.readonly_pmmr()
	}

	/// Readonly view of our rangeproof data.
	pub fn rproof_readonly_pmmr(&'_ self) -> ReadonlyPMMR<'_, RangeProof, PMMRBackend<RangeProof>> {
		self.rproof_pmmr.readonly_pmmr()
	}

	/// Reset prune lists
	pub fn reset_prune_lists(&mut self) -> Result<(), Error> {
		self.output_pmmr.reset_prune_list()?;
		self.rproof_pmmr.reset_prune_list()?;
		Ok(())
	}

	/// Apply a new block to the current txhashet extension (output, rangeproof, kernel MMRs).
	/// Returns a vec of commit_pos representing the pos and height of the outputs spent
	/// by this block.
	pub fn apply_block(
		&mut self,
		b: &Block,
		header_ext: &HeaderExtension<'_>,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		let mut affected_pos = vec![];

		// Resolve spent outputs before adding any new outputs from this block.
		// Inputs must be validated against the pre-block UTXO set.
		let spent = self
			.utxo_view(header_ext)
			.validate_inputs(&b.inputs(), batch)?;
		let b_hash = b.hash(self.context_id)?;

		// Apply the output to the output and rangeproof MMRs.
		// Add pos to affected_pos to update the accumulator later on.
		// Add the new output to the output_pos index.
		for out in b.outputs() {
			let pos = self.apply_output(out, batch)?;
			affected_pos.push(pos);
			batch.save_output_pos_height(
				&out.commitment(),
				CommitPos {
					pos,
					height: b.header.height,
				},
			)?;
		}

		// Apply inputs to remove previously resolved spent outputs from the output and rangeproof MMRs.
		// Add spent_pos to affected_pos to update the accumulator later on.
		// Remove the spent outputs from the output_pos index.
		//save the spent commitment in the db for replay attack detection.
		for (out, pos) in &spent {
			self.apply_input(out.commitment(), *pos)?;
			affected_pos.push(pos.pos);
			batch.delete_output_pos_height(&out.commitment())?;
			//save the spent commitments.
			let hh = HashHeight {
				hash: b_hash,
				height: b.header.height.clone(),
			};
			batch.save_spent_commitments(&out.commitment().clone(), hh)?;
		}

		// Update the spent index with spent pos.
		let spent_pos: Vec<_> = spent.into_iter().map(|(_, pos)| pos).collect();
		batch.save_spent_index(&b_hash, &spent_pos)?;

		// Apply the kernels to the kernel MMR.
		// Note: This validates and NRD relative height locks via the "recent" kernel index.
		self.apply_kernels(b.kernels(), b.header.height, batch, true)?;

		// Update the head of the extension to reflect the block we just applied.
		self.head = Tip::try_from_header(&b.header)?;

		Ok(())
	}

	// Prune output and rangeproof PMMRs based on provided pos.
	// Input is not valid if we cannot prune successfully.
	fn apply_input(&mut self, commit: Commitment, pos: CommitPos) -> Result<(), Error> {
		let pos0 = pos.pos.checked_sub(1).ok_or_else(|| {
			mwc_store::Error::DataOverflow(format!("Extension::apply_input pos.pos={}", pos.pos))
		})?;
		match self.output_pmmr.prune(pos0)? {
			true => {
				let rproof_pruned = self
					.rproof_pmmr
					.prune(pos0)
					.map_err(|e| Error::TxHashSetErr(format!("pmmr prune error, {}", e)))?;
				if !rproof_pruned {
					return Err(Error::TxHashSetErr(format!(
						"rangeproof leaf for spent output {:?} at pos {} was already pruned or absent",
						commit, pos.pos
					)));
				}
				Ok(())
			}
			false => Err(Error::AlreadySpent(commit)),
		}
	}

	fn apply_output(&mut self, out: &Output, batch: &Batch<'_>) -> Result<u64, Error> {
		let commit = out.commitment();

		match batch.get_output_pos(&commit) {
			Ok(pos0) => match self.output_pmmr.get_data(pos0)? {
				Some(out_mmr) if out_mmr.commitment() == commit => {
					return Err(Error::DuplicateCommitment(commit));
				}
				Some(out_mmr) => {
					return Err(Error::TxHashSetErr(format!(
						"output_pos index mismatch for commitment {:?}: index points to {:?} at pos {}",
						commit,
						out_mmr.commitment(),
						pos0 + 1 // pos0+1 is acceptable because it is an error message
					)));
				}
				None => {
					return Err(Error::TxHashSetErr(format!(
						"output_pos index points to missing output at pos {} for commitment {:?}",
						pos0 + 1, // pos0+1 is acceptable because it is an error message
						commit
					)));
				}
			},
			Err(e) if e.store_error_is_not_found() => {}
			Err(e) => return Err(Error::StoreErr(e, "apply output get output pos".to_owned())),
		}
		// push the new output to the MMR.
		let output_pos = self
			.output_pmmr
			.push(&out.identifier())
			.map_err(|e| Error::TxHashSetErr(format!("pmmr output push error, {}", e)))?;

		// push the rangeproof to the MMR.
		let rproof_pos = self
			.rproof_pmmr
			.push(&out.proof())
			.map_err(|e| Error::TxHashSetErr(format!("pmmr proof push error, {}", e)))?;

		// The output and rproof MMRs should be exactly the same size
		// and we should have inserted to both in exactly the same pos.
		{
			if self.output_pmmr.unpruned_size() != self.rproof_pmmr.unpruned_size() {
				return Err(Error::Other(
					"output vs rproof MMRs different sizes".to_string(),
				));
			}

			if output_pos != rproof_pos {
				return Err(Error::Other(
					"output vs rproof MMRs different pos".to_string(),
				));
			}
		}
		output_pos.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Extension::apply_output, output_pos={}",
				output_pos
			))
		})
	}

	/// Once the PIBD set is downloaded, we need to ensure that the respective leaf sets
	/// match the bitmap (particularly in the case of outputs being spent after a PIBD catch-up)
	pub fn update_leaf_sets(&mut self, bitmap: &Bitmap) -> Result<(), Error> {
		let mut output_pos_to_prune = Vec::new();
		for pos0 in self.output_pmmr.leaf_pos_iter()? {
			let pos0 = pos0?;
			let leaf_idx = pmmr::pmmr_leaf_to_insertion_index(pos0).ok_or_else(|| {
				Error::Other(format!(
					"TxHashSet::update_leaf_sets, invalid output leaf pos {}",
					pos0
				))
			})?;
			let leaf_idx = u32::try_from(leaf_idx).map_err(|_| {
				Error::DataOverflow(format!(
					"TxHashSet::update_leaf_sets, output leaf_idx={}",
					leaf_idx
				))
			})?;
			if !bitmap.contains(leaf_idx) {
				output_pos_to_prune.push(pos0);
			}
		}
		for pos0 in output_pos_to_prune {
			if !self.output_pmmr.prune(pos0)? {
				return Err(Error::InvalidSegment(format!(
					"TxHashSet::update_leaf_sets, output leaf {} was already pruned",
					pos0
				)));
			}
		}

		let mut rproof_pos_to_prune = Vec::new();
		for pos0 in self.rproof_pmmr.leaf_pos_iter()? {
			let pos0 = pos0?;
			let leaf_idx = pmmr::pmmr_leaf_to_insertion_index(pos0).ok_or_else(|| {
				Error::Other(format!(
					"TxHashSet::update_leaf_sets, invalid rangeproof leaf pos {}",
					pos0
				))
			})?;
			let leaf_idx = u32::try_from(leaf_idx).map_err(|_| {
				Error::DataOverflow(format!(
					"TxHashSet::update_leaf_sets, rangeproof leaf_idx={}",
					leaf_idx
				))
			})?;
			if !bitmap.contains(leaf_idx) {
				rproof_pos_to_prune.push(pos0);
			}
		}
		for pos0 in rproof_pos_to_prune {
			if !self.rproof_pmmr.prune(pos0)? {
				return Err(Error::InvalidSegment(format!(
					"TxHashSet::update_leaf_sets, rangeproof leaf {} was already pruned",
					pos0
				)));
			}
		}
		Ok(())
	}

	/// Apply already-authenticated output segments to the output PMMR.
	/// Desegmenter validates peer segments before calling this so apply does not
	/// repeat Merkle proof/hash validation while holding txhashset locks.
	///
	/// Sort and apply hashes and leaves within a segment to output pmmr, skipping over
	/// genesis position.
	/// NB: Would like to make this more generic but the hard casting of pmmrs
	/// held by this struct makes it awkward to do so
	pub(super) fn apply_validated_output_segments(
		&mut self,
		segments: Vec<Segment<OutputIdentifier>>,
		bitmap: &Bitmap,
	) -> Result<(), Error> {
		for segm in segments {
			let (_sid, hash_pos, hashes, leaf_pos, leaf_data, _proof) = segm.parts();
			for &pos0 in &leaf_pos {
				if !pmmr::is_leaf(pos0) {
					return Err(Error::InvalidSegment(format!(
						"TxHashSet::apply_output_segments, output position {} is not a leaf",
						pos0
					)));
				}
			}
			let leaf_pos_copy = leaf_pos.clone();

			// insert either leaves or pruned subtrees as we go
			for insert in sort_pmmr_hashes_and_leaves(hash_pos, leaf_pos, Some(0)) {
				match insert {
					OrderedHashLeafNode::Hash(idx, pos0) => {
						if pos0 >= self.output_pmmr.size() {
							if self.output_pmmr.size() == 1 {
								// All initial outputs are spent up to this hash,
								// Roll back the genesis output
								self.output_pmmr.rewind(0, &Bitmap::new())?;
							}
							self.output_pmmr.push_pruned_subtree(hashes[idx], pos0)?;
						}
					}
					OrderedHashLeafNode::Leaf(idx, pos0) => {
						let current_size = self.output_pmmr.size();
						if pos0 == current_size {
							self.output_pmmr.push(&leaf_data[idx])?;
						} else if pos0 > current_size {
							return Err(Error::InvalidSegment(format!(
								"TxHashSet::apply_output_segments, output leaf {} exceeds current PMMR size {}",
								pos0, current_size
							)));
						}
						// Note, extra unproned segments will be upadted later
						// Prone will be due
					}
				}
			}
			// Pruning elements that wasn't in the bitmap. It is expected that some data might not be pruned
			// Note: we need to insert all data first and prune after. Also, there is no rpone at the end of PIBD download
			for pos0 in leaf_pos_copy {
				let pmmr_index = pmmr::pmmr_leaf_to_insertion_index(pos0);
				match pmmr_index {
					Some(i) => {
						let i = u32::try_from(i).map_err(|_| {
							Error::DataOverflow(format!(
								"TxHashSet::apply_output_segments, leaf_idx={}",
								i
							))
						})?;
						if !bitmap.contains(i) {
							if !self.output_pmmr.prune(pos0)? {
								return Err(Error::InvalidSegment(format!(
									"TxHashSet::apply_output_segments, output leaf {} was already pruned",
									pos0
								)));
							}
						}
					}
					None => {
						return Err(Error::InvalidSegment(format!(
							"TxHashSet::apply_output_segments, output position {} is not a leaf",
							pos0
						)));
					}
				};
			}
		}
		Ok(())
	}

	/// Apply already-authenticated rangeproof segments to the rangeproof PMMR.
	/// Desegmenter validates peer segments before calling this so apply does not
	/// repeat Merkle proof/hash validation while holding txhashset locks.
	///
	/// Sort and apply hashes and leaves within a segment to rangeproof pmmr, skipping over
	/// genesis position.
	pub(super) fn apply_validated_rangeproof_segments(
		&mut self,
		segments: Vec<Segment<RangeProof>>,
		bitmap: &Bitmap,
	) -> Result<(), Error> {
		for segm in segments {
			let (_sid, hash_pos, hashes, leaf_pos, leaf_data, _proof) = segm.parts();
			for &pos0 in &leaf_pos {
				if !pmmr::is_leaf(pos0) {
					return Err(Error::InvalidSegment(format!(
						"TxHashSet::apply_rangeproof_segments, rangeproof position {} is not a leaf",
						pos0
					)));
				}
			}
			let leaf_pos_copy = leaf_pos.clone();

			//info!("Adding proof segment {}, from mmr pos: {}  hashes sz: {}  leaf_data sz: {}  hash_pos: {:?}  hashes: {:?}   leaf_pos: {:?}  leaf_data: {:?}", sid.idx, self.rproof_pmmr.size(), hashes.len(), leaf_data.len(), hash_pos, hashes, leaf_pos, leaf_data );

			// insert either leaves or pruned subtrees as we go
			for insert in sort_pmmr_hashes_and_leaves(hash_pos, leaf_pos, Some(0)) {
				match insert {
					OrderedHashLeafNode::Hash(idx, pos0) => {
						if pos0 >= self.rproof_pmmr.size() {
							if self.rproof_pmmr.size() == 1 {
								// All initial outputs are spent up to this hash,
								// Roll back the genesis output
								self.rproof_pmmr.rewind(0, &Bitmap::new())?;
							}
							self.rproof_pmmr.push_pruned_subtree(hashes[idx], pos0)?;
						}
					}
					OrderedHashLeafNode::Leaf(idx, pos0) => {
						let current_size = self.rproof_pmmr.size();
						if pos0 == current_size {
							self.rproof_pmmr.push(&leaf_data[idx])?;
						} else if pos0 > current_size {
							return Err(Error::InvalidSegment(format!(
								"TxHashSet::apply_rangeproof_segments, rangeproof leaf {} exceeds current PMMR size {}",
								pos0, current_size
							)));
						}
						// Note, extra unproned segments will be upadted later
						// Prone will be due
					}
				}
			}

			// Pruning elements that wasn't in the bitmap. It is expecte dthat some data might not be pruned
			// Note: we need to insert all data first and prune after. Also, there is no rpone at the end of PIBD download
			for pos0 in leaf_pos_copy {
				let pmmr_index = pmmr::pmmr_leaf_to_insertion_index(pos0);
				match pmmr_index {
					Some(i) => {
						let i = u32::try_from(i).map_err(|_| {
							Error::DataOverflow(format!(
								"TxHashSet::apply_rangeproof_segments, leaf_idx={}",
								i
							))
						})?;
						if !bitmap.contains(i) {
							if !self.rproof_pmmr.prune(pos0)? {
								return Err(Error::InvalidSegment(format!(
									"TxHashSet::apply_rangeproof_segments, rangeproof leaf {} was already pruned",
									pos0
								)));
							}
						}
					}
					None => {
						return Err(Error::InvalidSegment(format!(
							"TxHashSet::apply_rangeproof_segments, rangeproof position {} is not a leaf",
							pos0
						)));
					}
				};
			}
		}
		Ok(())
	}

	/// Apply kernels to the kernel MMR.
	/// Validate any NRD relative height locks via the "recent" kernel index.
	/// Note: This is used for both block processing and tx validation.
	/// In the block processing case we use the block height.
	/// In the tx validation case we use the "next" block height based on current chain head.
	pub fn apply_kernels(
		&mut self,
		kernels: &[TxKernel],
		height: u64,
		batch: &Batch<'_>,
		update_kernel_index: bool,
	) -> Result<(), Error> {
		for kernel in kernels {
			let pos = self.apply_kernel(kernel)?;
			if update_kernel_index {
				batch.save_kernel_pos(&kernel.excess(), KernelPos { pos, height })?;
			}
			let commit_pos = CommitPos { pos, height };
			apply_kernel_rules(kernel, commit_pos, batch)?;
		}
		Ok(())
	}

	/// Apply already-authenticated kernel segments to the kernel PMMR.
	/// Desegmenter validates peer segments before calling this so apply does not
	/// repeat Merkle proof/hash validation while holding txhashset locks.
	pub(super) fn apply_validated_kernel_segments(
		&mut self,
		segments: Vec<Segment<TxKernel>>,
	) -> Result<(), Error> {
		for segm in segments {
			let (_sid, hash_pos, hashes, leaf_pos, leaf_data, _proof) = segm.parts();
			if !hash_pos.is_empty() || !hashes.is_empty() {
				return Err(Error::InvalidSegment(
					"Kernel PMMR is non-prunable, should not have hash data".to_string(),
				));
			}

			// Non prunable - insert only leaves (with genesis kernel removed)
			for insert in sort_pmmr_hashes_and_leaves(vec![], leaf_pos, Some(0)) {
				match insert {
					OrderedHashLeafNode::Hash(_, _) => {
						return Err(Error::InvalidSegment(
							"Kernel PMMR is non-prunable, should not have hash data".to_string(),
						));
					}
					OrderedHashLeafNode::Leaf(idx, pos0) => {
						let pmmr_size = self.kernel_pmmr.size();
						if pos0 != pmmr_size {
							return Err(Error::InvalidSegment(format!(
								"Kernel segment leaf position {} does not match kernel PMMR size {}",
								pos0, pmmr_size
							)));
						}
						self.kernel_pmmr.push(&leaf_data[idx])?;
					}
				}
			}
		}
		Ok(())
	}

	/// Push kernel onto MMR (hash and data files).
	fn apply_kernel(&mut self, kernel: &TxKernel) -> Result<u64, Error> {
		let pos = self.kernel_pmmr.push(kernel)?;
		pos.checked_add(1)
			.ok_or_else(|| Error::DataOverflow(format!("Extension::apply_kernel, pos={}", pos)))
	}

	/// Build a Merkle proof for the given output and the block
	/// this extension is currently referencing.
	/// Note: this relies on the MMR being stable even after pruning/compaction.
	/// We need the hash of each sibling pos from the pos up to the peak
	/// including the sibling leaf node which may have been removed.
	pub fn merkle_proof<T: AsRef<OutputIdentifier>>(
		&self,
		out_id: T,
		batch: &Batch<'_>,
	) -> Result<MerkleProof, Error> {
		let out_id = out_id.as_ref();
		debug!("txhashset: merkle_proof: output: {:?}", out_id.commit);
		// then calculate the Merkle Proof based on the known pos
		let pos0 = batch.get_output_pos(&out_id.commit)?;
		match self.output_pmmr.get_data(pos0)? {
			Some(out) if ser::hashes_equal(self.context_id, &out, out_id)? => {}
			Some(out) => {
				return Err(Error::TxHashSetErr(format!(
					"output_pos index mismatch for output {:?}: index points to {:?} at pos {}",
					out_id,
					out,
					pos0 + 1 // pos0+1 is acceptable because it is an error message
				)));
			}
			None => {
				return Err(Error::TxHashSetErr(format!(
					"output_pos index points to missing output at pos {} for output {:?}",
					pos0 + 1, // pos0+1 is acceptable because it is an error message
					out_id
				)));
			}
		}
		let merkle_proof = self.output_pmmr.merkle_proof(pos0)?;

		Ok(merkle_proof)
	}

	/// Saves a snapshot of the output and rangeproof MMRs to disk.
	/// Specifically - saves a snapshot of the utxo file, tagged with
	/// the block hash as filename suffix.
	/// Needed for fast-sync (utxo file needs to be rewound before sending
	/// across).
	pub fn snapshot(&mut self, batch: &Batch<'_>) -> Result<(), Error> {
		let header = batch.get_block_header(&self.head.last_block_h)?;
		self.output_pmmr
			.snapshot(&header)
			.map_err(|e| Error::Other(format!("pmmr snapshot error, {}", e)))?;
		self.rproof_pmmr
			.snapshot(&header)
			.map_err(|e| Error::Other(format!("pmmr snapshot error, {}", e)))?;
		Ok(())
	}

	/// Build a new bitmap accumulator for the provided output PMMR. Expected call for Segmenter only.
	pub fn build_bitmap_accumulator(&self) -> Result<BitmapAccumulator, Error> {
		let pmmr = self.output_pmmr.readonly_pmmr();
		let nbits = pmmr::n_leaves(pmmr.unpruned_size())?;
		let mut bitmap_accumulator = BitmapAccumulator::new(self.context_id);
		bitmap_accumulator.init(&mut pmmr.leaf_idx_iter(0)?, nbits)?;
		Ok(bitmap_accumulator)
	}

	/// Rewinds the MMRs to the provided block, rewinding to the last output pos
	/// and last kernel pos of that block. If `updated_bitmap` is supplied, the
	/// bitmap accumulator will be replaced with its contents
	pub fn rewind(
		&mut self,
		header: &BlockHeader,
		batch: &Batch<'_>,
		header_ext: &HeaderExtension<'_>,
		mut progress: Option<&mut dyn FnMut(u64, u64) -> Result<(), Error>>,
	) -> Result<(), Error> {
		let header_hash = header.hash(self.context_id)?;
		let head_hash = self.head.hash(self.context_id)?;
		debug!(
			"Rewind extension to {} at {} from {} at {}",
			header_hash, header.height, head_hash, self.head.height
		);

		// We need to build bitmaps of added and removed output positions
		// so we can correctly rewind all operations applied to the output MMR
		// after the position we are rewinding to (these operations will be
		// undone during rewind).
		// Rewound output pos will be removed from the MMR.
		// Rewound input (spent) pos will be added back to the MMR.
		let head_header = batch.get_block_header(&head_hash)?;

		if header.height > head_header.height {
			return Err(Error::TxHashSetErr(format!(
				"cannot rewind extension forward to {} at height {} from {} at height {}",
				header_hash, header.height, head_hash, head_header.height
			)));
		}

		let mut current = head_header;
		let mut rewind_hashes = vec![];
		while header.height < current.height {
			rewind_hashes.push(current.hash(self.context_id)?);
			let prev = batch.get_previous_header(&current)?;
			if prev.height >= current.height {
				return Err(Error::TxHashSetErr(format!(
					"cannot rewind through non-decreasing header heights {} -> {}",
					current.height, prev.height
				)));
			}
			current = prev;
		}

		let current_hash = current.hash(self.context_id)?;
		if current_hash != header_hash {
			return Err(Error::TxHashSetErr(format!(
				"rewind target {} at height {} is not on body chain ending at {} at height {}",
				header_hash, header.height, head_hash, self.head.height
			)));
		}
		if current != *header {
			return Err(Error::TxHashSetErr(format!(
				"rewind target {} at height {} does not match canonical body chain header",
				header_hash, header.height
			)));
		}

		let rewind_total = u64::try_from(rewind_hashes.len()).map_err(|_| {
			Error::DataOverflow(format!(
				"Extension::rewind, rewind_hashes.len={}",
				rewind_hashes.len()
			))
		})?;
		if let Some(ref mut progress) = progress {
			progress(0, rewind_total)?;
		}

		if rewind_hashes.is_empty() {
			// Nothing to rewind but we do want to truncate the MMRs at header for consistency.
			self.rewind_mmrs_to_pos(header.output_mmr_size, header.kernel_mmr_size, &[])?;
			if let Some(ref mut progress) = progress {
				progress(rewind_total, rewind_total)?;
			}
		} else {
			let mut rewound = 0u64;
			for hash in rewind_hashes {
				let block = batch.get_block(&hash)?;
				self.rewind_single_block(&block, batch, header_ext)?;
				rewound = rewound.checked_add(1).ok_or_else(|| {
					Error::DataOverflow("Extension::rewind, rewound overflow".into())
				})?;
				if let Some(ref mut progress) = progress {
					progress(rewound, rewind_total)?;
				}
			}
		}

		// Update our head to reflect the header we rewound to.
		self.head = Tip::try_from_header(header)?;

		Ok(())
	}

	// Rewind the MMRs and the output_pos index.
	// Returns a vec of "affected_pos" so we can apply the necessary updates to the bitmap
	// accumulator in a single pass for all rewound blocks.
	fn rewind_single_block(
		&mut self,
		block: &Block,
		batch: &Batch<'_>,
		header_ext: &HeaderExtension<'_>,
	) -> Result<(), Error> {
		let header = &block.header;
		let prev_header = batch.get_previous_header(&header)?;
		let header_hash = header.hash(self.context_id)?;

		// The spent index allows us to conveniently "unspend" everything in a block.
		let (spent_pos, spent_index): (Vec<u64>, Option<Vec<CommitPos>>) = match batch
			.get_spent_index(&header_hash)
		{
			Ok(spent) => {
				let spent_pos = spent.iter().map(|x| x.pos).collect();
				(spent_pos, Some(spent))
			}
			Err(e) if e.store_error_is_not_found() => {
				warn!(
					"rewind_single_block: fallback to legacy input bitmap for block {} at {}",
					header_hash, header.height
				);
				match batch.get_block_input_bitmap(&header_hash) {
					Ok(bitmap) => {
						let spent_pos = bitmap.iter().map(|x| x.into()).collect();
						(spent_pos, None)
					}
					Err(e) if e.store_error_is_not_found() => {
						warn!(
							"rewind_single_block: fallback to calculating inputs for block {} at {}",
							header_hash, header.height
						);
						let spent = self
							.utxo_view(header_ext)
							.validate_inputs(&block.inputs(), batch)?;
						let spent_index: Vec<_> = spent.into_iter().map(|(_, pos)| pos).collect();
						let spent_pos = spent_index.iter().map(|pos| pos.pos).collect();
						(spent_pos, Some(spent_index))
					}
					Err(e) => {
						return Err(Error::StoreErr(
							e,
							"rewind_single_block get legacy input bitmap".into(),
						));
					}
				}
			}
			Err(e) => {
				return Err(Error::StoreErr(
					e,
					"rewind_single_block get spent index".into(),
				));
			}
		};

		if header.height == 0 {
			self.rewind_mmrs_to_pos(0, 0, &spent_pos)?;
		} else {
			let prev = batch.get_previous_header(header)?;
			self.rewind_mmrs_to_pos(prev.output_mmr_size, prev.kernel_mmr_size, &spent_pos)?;
		}

		// Remove any entries from the output_pos created by the block being rewound.
		let mut missing_count = 0;
		for out in block.outputs() {
			match batch.delete_output_pos_height(&out.commitment()) {
				Ok(()) => {}
				Err(e) if e.store_error_is_not_found() => {
					missing_count += 1;
				}
				Err(e) => {
					return Err(Error::StoreErr(
						e,
						"rewind_single_block delete output_pos".into(),
					));
				}
			}
		}
		// Missing count is only logged becuase there is nothing elese what we can do. In case of
		// failure the data can be incomplete, so occasional missing is expected.
		if missing_count > 0 {
			warn!(
				"rewind_single_block: {} output_pos entries missing for: {} at {}",
				missing_count, header_hash, header.height,
			);
		}

		// Remove kernel_pos entries created by the block being rewound.
		let mut kernel_pos = Vec::new();
		let first_kernel_pos = prev_header.kernel_mmr_size.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Extension::rewind_single_block, prev_header.kernel_mmr_size={}",
				prev_header.kernel_mmr_size
			))
		})?;
		for pos in first_kernel_pos..=header.kernel_mmr_size {
			let pos0 = pos.checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!("Extension::rewind_single_block kernel pos={}", pos))
			})?;
			if pmmr::is_leaf(pos0) {
				kernel_pos.push(pos);
			}
		}
		if kernel_pos.len() != block.kernels().len() {
			return Err(Error::TxHashSetErr(format!(
				"rewind_single_block kernel position count mismatch for block {} at {}: positions {}, kernels {}",
				header_hash,
				header.height,
				kernel_pos.len(),
				block.kernels().len()
			)));
		}
		let mut missing_kernel_count = 0;
		for (kernel, pos) in block.kernels().iter().zip(kernel_pos) {
			match batch.delete_kernel_pos(&kernel.excess(), pos) {
				Ok(()) => {}
				Err(e) if e.store_error_is_not_found() => missing_kernel_count += 1,
				Err(e) => {
					return Err(Error::StoreErr(
						e,
						"rewind_single_block delete kernel_pos".into(),
					));
				}
			}
		}
		if missing_kernel_count > 0 {
			warn!(
				"rewind_single_block: {} kernel_pos entries missing for: {} at {}",
				missing_kernel_count, header_hash, header.height,
			);
		}

		// If NRD feature flag is enabled rewind the kernel_pos index
		// for any NRD kernels in the block being rewound.
		if global::is_nrd_enabled(self.context_id) {
			let kernel_index = store::nrd_recent_kernel_index();
			for kernel in block.kernels() {
				if let KernelFeatures::NoRecentDuplicate { .. } = kernel.features {
					kernel_index.rewind(batch, kernel.excess(), prev_header.kernel_mmr_size)?;
				}
			}
		}

		// Update output_pos based on "unspending" all spent pos from this block.
		// This is necessary to ensure the output_pos index correctly reflects a
		// reused output commitment. For example an output at pos 1, spent, reused at pos 2.
		// The output_pos index should be updated to reflect the old pos 1 when unspent.
		let spent_index = match spent_index {
			Some(spent) => spent,
			None => {
				let spent = self.reconstruct_spent_index(&spent_pos, &prev_header, batch)?;
				batch.save_spent_index(&header_hash, &spent)?;
				spent
			}
		};
		for pos1 in spent_index {
			let pos0 = pos1.pos.checked_sub(1).ok_or_else(|| {
				mwc_store::Error::DataOverflow(format!(
					"Extension::rewind_single_block pos1.pos={}",
					pos1.pos
				))
			})?;
			match self.output_pmmr.get_data(pos0)? {
				Some(out) => batch.save_output_pos_height(&out.commitment(), pos1)?,
				None => {
					return Err(Error::TxHashSetErr(format!(
						"rewind_single_block missing output PMMR data at pos {} while restoring output_pos for block {} at {}",
						pos1.pos, header_hash, header.height
					)));
				}
			}
		}

		Ok(())
	}

	fn reconstruct_spent_index(
		&self,
		spent_pos: &[u64],
		prev_header: &BlockHeader,
		batch: &Batch<'_>,
	) -> Result<Vec<CommitPos>, Error> {
		spent_pos
			.iter()
			.map(|pos| {
				Ok(CommitPos {
					pos: *pos,
					height: self.output_height_for_pos(*pos, prev_header, batch)?,
				})
			})
			.collect()
	}

	fn output_height_for_pos(
		&self,
		pos: u64,
		header: &BlockHeader,
		batch: &Batch<'_>,
	) -> Result<u64, Error> {
		if pos == 0 {
			return Err(Error::DataOverflow(
				"Extension::output_height_for_pos pos=0".into(),
			));
		}
		if pos > header.output_mmr_size {
			return Err(Error::TxHashSetErr(format!(
				"rewind_single_block cannot map output pos {} beyond rewind target output MMR size {}",
				pos, header.output_mmr_size
			)));
		}
		let pos0 = pos.checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!("Extension::output_height_for_pos pos={}", pos))
		})?;
		if !pmmr::is_leaf(pos0) {
			return Err(Error::TxHashSetErr(format!(
				"rewind_single_block cannot map non-leaf output PMMR pos {} to a block height",
				pos
			)));
		}

		let mut current = header.clone();
		loop {
			let prev = if current.height == 0 {
				None
			} else {
				Some(batch.get_previous_header(&current)?)
			};
			if let Some(prev_header) = &prev {
				if prev_header.height >= current.height {
					return Err(Error::TxHashSetErr(format!(
						"rewind_single_block cannot map output pos {} through non-decreasing header heights {} -> {}",
						pos, current.height, prev_header.height
					)));
				}
			}
			let prev_output_mmr_size = prev
				.as_ref()
				.map(|header| header.output_mmr_size)
				.unwrap_or(0);
			if prev_output_mmr_size > current.output_mmr_size {
				return Err(Error::TxHashSetErr(format!(
					"rewind_single_block found output MMR size regression at height {}: previous {}, current {}",
					current.height, prev_output_mmr_size, current.output_mmr_size
				)));
			}
			if pos > prev_output_mmr_size {
				return Ok(current.height);
			}
			match prev {
				Some(prev) => current = prev,
				None => {
					return Err(Error::TxHashSetErr(format!(
						"rewind_single_block cannot map output pos {} to a block height",
						pos
					)));
				}
			}
		}
	}

	/// Rewinds the MMRs to the provided positions, given the output and
	/// kernel pos we want to rewind to.
	fn rewind_mmrs_to_pos(
		&mut self,
		output_pos: u64,
		kernel_pos: u64,
		spent_pos: &[u64],
	) -> Result<(), Error> {
		let bitmap: Bitmap = spent_pos
			.iter()
			.map(|x| {
				u32::try_from(*x).map_err(|_| {
					Error::DataOverflow(format!("TxHashSet::rewind_mmrs_to_pos, spent_pos={}", x))
				})
			})
			.collect::<Result<Bitmap, Error>>()?;
		self.output_pmmr.rewind(output_pos, &bitmap)?;
		self.rproof_pmmr.rewind(output_pos, &bitmap)?;
		self.kernel_pmmr.rewind(kernel_pos, &Bitmap::new())?;
		Ok(())
	}

	/// Reset the body MMRs to empty and rebuild them from the hard-coded
	/// genesis block.
	pub fn rebuild_genesis(
		&mut self,
		genesis: &Block,
		header_ext: &HeaderExtension<'_>,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		if genesis.header.height != 0 {
			return Err(Error::InvalidGenesisHash);
		}
		self.rewind_mmrs_to_pos(0, 0, &[])?;
		for out in genesis.outputs() {
			match batch.delete_output_pos_height(&out.commitment()) {
				Ok(()) => {}
				Err(e) if e.store_error_is_not_found() => {}
				Err(e) => {
					return Err(Error::StoreErr(
						e,
						"rebuild_genesis delete output_pos".into(),
					));
				}
			}
		}
		self.apply_block(genesis, header_ext, batch)
	}

	/// Current root hashes and sums (if applicable) for the Output, range proof
	/// and kernel MMRs.
	pub fn roots(&self) -> Result<TxHashSetRoots, Error> {
		Ok(TxHashSetRoots {
			output_root: self.output_pmmr.root()?,
			output_mmr_size: self.output_pmmr.size(),
			rproof_root: self.rproof_pmmr.root()?,
			rproof_mmr_size: self.rproof_pmmr.size(),
			kernel_root: self.kernel_pmmr.root()?,
			kernel_mmr_size: self.kernel_pmmr.size(),
		})
	}

	fn header_has_mmr_data(header: &BlockHeader) -> bool {
		// Mainnet/floonet genesis headers include MMR entries; only empty
		// genesis headers can safely bypass root and size validation.
		header.output_mmr_size > 0 || header.kernel_mmr_size > 0
	}

	fn header_has_non_zero_mmr_roots(header: &BlockHeader) -> bool {
		header.output_root != ZERO_HASH
			|| header.range_proof_root != ZERO_HASH
			|| header.kernel_root != ZERO_HASH
	}

	fn can_skip_genesis_mmr_validation(&self, header: &BlockHeader) -> bool {
		header.height == 0
			&& !Self::header_has_mmr_data(header)
			&& !Self::header_has_non_zero_mmr_roots(header)
			&& self.sizes() == (0, 0, 0)
	}

	/// Validate the MMR (output, rangeproof, kernel) roots against the latest header.
	pub fn validate_roots(&self, header: &BlockHeader) -> Result<(), Error> {
		if header.height == 0 && !Self::header_has_mmr_data(header) {
			if Self::header_has_non_zero_mmr_roots(header) {
				return Err(Error::InvalidRoot(
					"empty genesis header has non-zero MMR roots".into(),
				));
			}
			if self.sizes() != (0, 0, 0) {
				return Err(Error::InvalidRoot(
					"empty genesis header does not match non-empty txhashset MMRs".into(),
				));
			}
			return Ok(());
		}
		self.roots()?.validate(header)
	}

	/// Validate the header, output and kernel MMR sizes against the block header.
	pub fn validate_sizes(&self, header: &BlockHeader) -> Result<(), Error> {
		if self.can_skip_genesis_mmr_validation(header) {
			return Ok(());
		}
		if (
			header.output_mmr_size,
			header.output_mmr_size,
			header.kernel_mmr_size,
		) != self.sizes()
		{
			Err(Error::InvalidMMRSize)
		} else {
			Ok(())
		}
	}

	fn validate_mmrs(&self) -> Result<(), Error> {
		let now = Instant::now();

		// validate all hashes and sums within the trees
		self.output_pmmr.validate()?;
		self.rproof_pmmr.validate()?;
		self.kernel_pmmr.validate()?;

		debug!(
			"txhashset: validated the output {}, rproof {}, kernel {} mmrs, took {}s",
			self.output_pmmr.unpruned_size(),
			self.rproof_pmmr.unpruned_size(),
			self.kernel_pmmr.unpruned_size(),
			now.elapsed().as_secs(),
		);

		Ok(())
	}

	fn update_kernel_sum_progress(
		status: &Option<Arc<SyncState>>,
		status_throttle: &SyncStatusUpdateThrottle,
		current: u64,
		total: u64,
		force: bool,
	) {
		if let Some(status) = status {
			if status_throttle.should_update(force) {
				status.update(SyncStatus::TxHashsetStateValidation {
					stage: TxHashsetStateValidationStage::ValidateKernelSums,
					current: current.min(total),
					total: total.max(1),
				});
			}
		}
	}

	fn check_stop_state(stop_state: &Option<Arc<StopState>>) -> Result<(), Error> {
		if let Some(stop_state) = stop_state {
			if stop_state.is_stopped() {
				return Err(Error::Stopped);
			}
		}
		Ok(())
	}

	fn output_commitments_iter(
		&self,
	) -> Result<Box<dyn Iterator<Item = Result<Commitment, Error>> + '_>, Error> {
		let output_positions = self.output_pmmr.leaf_pos_iter()?;
		Ok(Box::new(output_positions.map(move |pos0| {
			let pos0 = pos0?;
			let out = self.output_pmmr.get_data(pos0)?.ok_or_else(|| {
				Error::Committed(CommittedError::Other(format!(
					"Missing output PMMR data at leaf position {}",
					pos0
				)))
			})?;
			Ok(out.commit)
		})))
	}

	fn kernel_commitments_iter(&self) -> Box<dyn Iterator<Item = Result<Commitment, Error>> + '_> {
		Box::new(
			(0..self.kernel_pmmr.unpruned_size())
				.filter(|n| pmmr::is_leaf(*n))
				.map(move |pos0| {
					let kernel = self.kernel_pmmr.get_data(pos0)?.ok_or_else(|| {
						Error::Committed(CommittedError::Other(format!(
							"Missing kernel PMMR data at leaf position {}",
							pos0
						)))
					})?;
					Ok(kernel.excess())
				}),
		)
	}

	/// Validate full kernel sums against the provided header and unspent output bitmap
	/// (for overage and kernel_offset).
	/// This is an expensive operation as we need to retrieve all the UTXOs and kernels
	/// from the respective MMRs.
	/// For a significantly faster way of validating full kernel sums see BlockSums.
	pub fn validate_kernel_sums(
		&self,
		genesis: &BlockHeader,
		header: &BlockHeader,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
		secp: &Secp256k1,
	) -> Result<(Commitment, Commitment), Error> {
		let now = Instant::now();
		let total_outputs = self.output_pmmr.n_unpruned_leaves()?;
		let total_kernels = pmmr::n_leaves(self.kernel_pmmr.unpruned_size())?;
		let total_progress = total_outputs.saturating_add(total_kernels);
		let status_throttle = SyncStatusUpdateThrottle::new();
		Self::update_kernel_sum_progress(&status, &status_throttle, 0, total_progress, true);
		let overage = header.total_overage(self.context_id, genesis.kernel_mmr_size > 0)?;
		verify_kernel_sums_iter(
			self.output_commitments_iter()?,
			std::iter::empty::<Result<Commitment, Error>>(),
			self.kernel_commitments_iter(),
			overage,
			header.total_kernel_offset(),
			COMMIT_SUM_BATCH_SIZE,
			num_cpus::get().max(1),
			secp,
			|| Self::check_stop_state(&stop_state),
			|completed_items| {
				let progress = (completed_items as u64).min(total_progress);
				Self::update_kernel_sum_progress(
					&status,
					&status_throttle,
					progress,
					total_progress,
					progress == total_progress,
				);
				Ok(())
			},
		)
		.map(|(utxo_sum, kernel_sum)| {
			debug!(
				"txhashset: validated total kernel sums, took {}s",
				now.elapsed().as_secs(),
			);

			(utxo_sum, kernel_sum)
		})
	}

	/// Validate the txhashset state against the provided block header.
	/// A "fast validation" will skip rangeproof verification and kernel signature verification.
	pub fn validate(
		&self,
		genesis: &BlockHeader,
		fast_validation: bool,
		status: Option<Arc<SyncState>>,
		header: &BlockHeader,
		stop_state: Option<Arc<StopState>>,
		secp: &Secp256k1,
	) -> Result<(Commitment, Commitment), Error> {
		Self::update_state_validation_status(
			&status,
			TxHashsetStateValidationStage::ValidateMmrs,
			0,
		);
		self.validate_mmrs()?;
		Self::update_state_validation_status(
			&status,
			TxHashsetStateValidationStage::ValidateRoots,
			1,
		);
		self.validate_roots(header)?;
		Self::update_state_validation_status(
			&status,
			TxHashsetStateValidationStage::ValidateSizes,
			2,
		);
		self.validate_sizes(header)?;

		if self.can_skip_genesis_mmr_validation(header) && header.total_kernel_offset().is_zero() {
			if let Some(status) = &status {
				status.update(SyncStatus::TxHashsetStateValidation {
					stage: TxHashsetStateValidationStage::ValidateKernelSums,
					current: 1,
					total: 1,
				});
			}
			let zero_commit = secp_static::commit_to_zero_value();
			return Ok((zero_commit, zero_commit));
		}

		// The real magicking happens here. Sum of kernel excesses should equal
		// sum of unspent outputs minus total supply.
		let (output_sum, kernel_sum) =
			self.validate_kernel_sums(genesis, header, status.clone(), stop_state.clone(), secp)?;

		// These are expensive verification step (skipped for "fast validation").
		if !fast_validation {
			// Verify the rangeproof associated with each unspent output.
			self.verify_rangeproofs(status.clone(), None, stop_state.clone())?;
			if let Some(ref s) = stop_state {
				if s.is_stopped() {
					return Err(Error::Stopped.into());
				}
			}

			// Verify all the kernel signatures.
			self.verify_kernel_signatures(status, stop_state.clone())?;
			if let Some(ref s) = stop_state {
				if s.is_stopped() {
					return Err(Error::Stopped.into());
				}
			}
		}

		Ok((output_sum, kernel_sum))
	}

	fn update_state_validation_status(
		status: &Option<Arc<SyncState>>,
		stage: TxHashsetStateValidationStage,
		current: u64,
	) {
		if let Some(status) = status {
			status.update(SyncStatus::TxHashsetStateValidation {
				stage,
				current,
				total: TXHASHSET_STATE_VALIDATION_STEPS,
			});
		}
	}

	/// Force the rollback of this extension, no matter the result
	pub fn force_rollback(&mut self) {
		self.rollback = true;
	}

	/// Dumps the output MMR.
	/// We use this after compacting for visual confirmation that it worked.
	pub fn dump_output_pmmr(&self) -> Result<(), Error> {
		debug!("-- outputs --");
		self.output_pmmr.dump_from_file(false)?;
		debug!("--");
		self.output_pmmr.dump_stats();
		debug!("-- end of outputs --");
		Ok(())
	}

	/// Dumps the state of the 3 MMRs to stdout for debugging. Short
	/// version only prints the Output tree.
	pub fn dump(&self, short: bool) -> Result<(), Error> {
		debug!("-- outputs --");
		self.output_pmmr.dump(short)?;
		if !short {
			debug!("-- range proofs --");
			self.rproof_pmmr.dump(short)?;
			debug!("-- kernels --");
			self.kernel_pmmr.dump(short)?;
		}
		Ok(())
	}

	/// Sizes of each of the MMRs
	pub fn sizes(&self) -> (u64, u64, u64) {
		(
			self.output_pmmr.unpruned_size(),
			self.rproof_pmmr.unpruned_size(),
			self.kernel_pmmr.unpruned_size(),
		)
	}

	fn verify_kernel_signatures(
		&self,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		let now = Instant::now();
		const KERNEL_BATCH_SIZE: usize = 5_000;

		let verify_result = crossbeam::thread::scope(|s| {
			let mut kern_count = 0;
			let total_kernels = pmmr::n_leaves(self.kernel_pmmr.unpruned_size())?;

			let mut tx_kernels: Vec<TxKernel> = Vec::with_capacity(KERNEL_BATCH_SIZE);
			let num_cores = num_cpus::get();
			let mut running_threads: VecDeque<ScopedJoinHandle<Result<usize, Error>>> =
				VecDeque::with_capacity(num_cores * 2);
			let status_throttle = SyncStatusUpdateThrottle::new();
			let mut stopped = false;

			for n in 0..self.kernel_pmmr.unpruned_size() {
				if pmmr::is_leaf(n) {
					let kernel = self
						.kernel_pmmr
						.get_data(n)?
						.ok_or_else(|| Error::TxKernelNotFound)?;
					tx_kernels.push(kernel);
				}

				if tx_kernels.len() >= KERNEL_BATCH_SIZE
					|| n + 1 >= self.kernel_pmmr.unpruned_size()
				{
					Self::wait_for_kernel_tasks(
						num_cores,
						&mut running_threads,
						&status,
						&status_throttle,
						&mut kern_count,
						total_kernels,
					)?;

					if let Some(ref s) = stop_state {
						if s.is_stopped() {
							stopped = true;
							break;
						}
					}

					let mut tx_kernels2process = Vec::with_capacity(tx_kernels.len());
					tx_kernels2process.append(&mut tx_kernels);
					debug_assert!(tx_kernels.is_empty());
					let handle = s.spawn(move |_| {
						secp_static::with_verify_only(Error::from, |secp| {
							TxKernel::batch_sig_verify(self.context_id, &tx_kernels2process, secp)?;
							Ok(tx_kernels2process.len())
						})
					});
					running_threads.push_back(handle);
				}
			}

			// remaining part which not full of batch_size range proofs
			if !stopped && !tx_kernels.is_empty() {
				let handle = s.spawn(move |_| {
					secp_static::with_verify_only(Error::from, |secp| {
						TxKernel::batch_sig_verify(self.context_id, &tx_kernels, secp)?;
						Ok(tx_kernels.len())
					})
				});
				running_threads.push_back(handle);
			}

			// Waiting to the rest of tasks to finish
			while running_threads.len() > 0 {
				let len = running_threads.len();
				Self::wait_for_kernel_tasks(
					len,
					&mut running_threads,
					&status,
					&status_throttle,
					&mut kern_count,
					total_kernels,
				)?;
			}

			if stopped {
				return Err(Error::Stopped);
			}

			info!(
				"txhashset: verified {} kernel signatures, pmmr size {}, took {}s",
				kern_count,
				self.kernel_pmmr.unpruned_size(),
				now.elapsed().as_secs()
			);

			Ok(())
		});

		let verify_result =
			verify_result.map_err(|_| Error::Other("crossbeam runtime error".to_string()))?;
		verify_result
	}

	fn wait_for_kernel_tasks(
		num_cores: usize,
		running_tasks: &mut VecDeque<ScopedJoinHandle<Result<usize, Error>>>,
		status: &Option<Arc<SyncState>>,
		status_throttle: &SyncStatusUpdateThrottle,
		kern_count: &mut u64,
		total_kernels: u64,
	) -> Result<(), Error> {
		if running_tasks.len() < num_cores {
			return Ok(());
		}

		let handler = running_tasks.pop_front().ok_or(Error::Other(
			"wait_for_kernel_tasks internal error, no running task is available".into(),
		))?;
		let result = handler
			.join()
			.map_err(|_| Error::Other("crossbeam runtime error".to_string()))?;
		match result {
			Ok(size) => {
				let new_count = kern_count.checked_add(size as u64).ok_or_else(|| {
					Error::DataOverflow(format!(
						"wait_for_kernel_tasks verified kernel count overflow: current={}, size={}",
						*kern_count, size
					))
				})?;
				if new_count > total_kernels {
					return Err(Error::DataOverflow(format!(
						"wait_for_kernel_tasks verified kernel count {} exceeds total {}",
						new_count, total_kernels
					)));
				}
				*kern_count = new_count;
				if let Some(status) = status {
					if status_throttle.should_update(*kern_count == total_kernels) {
						status.update(SyncStatus::TxHashsetKernelsValidation {
							kernels: *kern_count,
							kernels_total: total_kernels,
						});
					}
				}
				// Expected by QT wallet
				info!(
					"txhashset: verify_kernel_signatures: verified {} signatures from {}",
					kern_count, total_kernels
				);
				Ok(())
			}
			Err(e) => Err(e),
		}
	}

	fn verify_rangeproofs(
		&self,
		status: Option<Arc<SyncState>>,
		batch_size: Option<usize>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		let now = Instant::now();

		let batch_size = batch_size.unwrap_or(1_000);

		let verify_result = crossbeam::thread::scope(|s| {
			let mut proof_count: u64 = 0;

			let total_rproofs = self.output_pmmr.n_unpruned_leaves()?;

			let num_cores = num_cpus::get();
			let mut commits: Vec<Commitment> = Vec::with_capacity(batch_size);
			let mut proofs: Vec<RangeProof> = Vec::with_capacity(batch_size);
			let mut running_threads: VecDeque<ScopedJoinHandle<Result<u64, Error>>> =
				VecDeque::with_capacity(num_cores * 2);
			let status_throttle = SyncStatusUpdateThrottle::new();
			let mut stopped = false;

			for pos0 in self.output_pmmr.leaf_pos_iter()? {
				let pos0 = pos0?;
				let output = self.output_pmmr.get_data(pos0)?;
				let proof = self.rproof_pmmr.get_data(pos0)?;

				// Output and corresponding rangeproof *must* exist.
				// It is invalid for either to be missing and we fail immediately in this case.
				match (output, proof) {
					(None, _) => {
						return Err(Error::OutputNotFound(format!(
							"at verify_rangeproofs for pos {}",
							pos0
						)));
					}
					(_, None) => {
						return Err(Error::RangeproofNotFound(format!(
							"at verify_rangeproofs for pos {}",
							pos0
						)));
					}
					(Some(output), Some(proof)) => {
						commits.push(output.commit);
						proofs.push(proof.into());
					}
				}

				proof_count += 1;

				if proofs.len() >= batch_size {
					Self::wait_for_rangeproofs_tasks(
						num_cores,
						&mut running_threads,
						total_rproofs,
						&status,
						&status_throttle,
					)?;

					if let Some(stop_state) = &stop_state {
						if stop_state.is_stopped() {
							stopped = true;
							break;
						}
					}

					// Macing copies for the spawn processing
					let proof_count = proof_count.clone();

					let mut commits2process = Vec::with_capacity(commits.len());
					commits2process.append(&mut commits);
					debug_assert!(commits.is_empty());

					let mut proofs2process = Vec::with_capacity(proofs.len());
					proofs2process.append(&mut proofs);
					debug_assert!(proofs.is_empty());

					let handle = s.spawn(move |_| {
						secp_static::with_verify_only_mut(Error::from, |secp| {
							Output::batch_verify_proofs(&commits2process, &proofs2process, secp)?;
							Ok(proof_count)
						})
					});
					running_threads.push_back(handle);
				}
			}

			// remaining part which not full of batch_size range proofs
			if !stopped && !proofs.is_empty() {
				let handle = s.spawn(move |_| {
					secp_static::with_verify_only_mut(Error::from, |secp| {
						Output::batch_verify_proofs(&commits, &proofs, secp)?;
						Ok(proof_count)
					})
				});
				running_threads.push_back(handle);
			}

			// Waiting to the rest of tasks to finish
			while running_threads.len() > 0 {
				let len = running_threads.len();
				Self::wait_for_rangeproofs_tasks(
					len,
					&mut running_threads,
					total_rproofs,
					&status,
					&status_throttle,
				)?;
			}

			if stopped {
				return Err(Error::Stopped);
			}

			debug!(
				"txhashset: verified {} rangeproofs, pmmr size {}, took {}s",
				proof_count,
				self.rproof_pmmr.unpruned_size(),
				now.elapsed().as_secs(),
			);
			Ok(())
		});

		let verify_result =
			verify_result.map_err(|_| Error::Other("crossbeam runtime error".to_string()))?;
		verify_result
	}

	// return pos0 value from the thread if want to exit with that
	fn wait_for_rangeproofs_tasks(
		num_cores: usize,
		running_tasks: &mut VecDeque<ScopedJoinHandle<Result<u64, Error>>>,
		total_rproofs: u64,
		status: &Option<Arc<SyncState>>,
		status_throttle: &SyncStatusUpdateThrottle,
	) -> Result<(), Error> {
		if running_tasks.len() < num_cores {
			return Ok(());
		}

		let handler = running_tasks.pop_front().ok_or(Error::Other(
			"wait_for_rangeproofs_tasks internal error, no running task is available".into(),
		))?;
		let result = handler
			.join()
			.map_err(|_| Error::Other("crossbeam runtime error".to_string()))?;
		match result {
			Ok(proof_count) => {
				// Expected by QT wallet
				info!(
					"txhashset: verify_rangeproofs: verified {} rangeproofs from {}",
					proof_count, total_rproofs
				);

				if let Some(s) = status {
					if status_throttle.should_update(proof_count == total_rproofs) {
						s.update(SyncStatus::TxHashsetRangeProofsValidation {
							rproofs: proof_count,
							rproofs_total: total_rproofs,
						});
					}
				}
				Ok(())
			}
			Err(e) => Err(e),
		}
	}
}

/// Result of replacing the txhashset directory on disk.
#[derive(Debug)]
pub enum TxHashSetReplaceResult {
	/// The replacement completed and the previous txhashset backup was removed.
	Replaced,
	/// The replacement completed, but removing the previous txhashset backup failed.
	ReplacedWithBackupCleanupFailure {
		/// Path to the leftover backup directory.
		backup_path: PathBuf,
		/// Error returned while trying to remove the backup directory.
		cleanup_error: io::Error,
	},
}

/// Overwrite txhashset folders in "to" folder with "from" folder.
pub fn txhashset_replace(from: PathBuf, to: PathBuf) -> Result<TxHashSetReplaceResult, Error> {
	debug!("txhashset_replace: move from {:?} to {:?}", from, to);

	let source_path = from.join(TXHASHSET_SUBDIR);
	let destination_path = to.join(TXHASHSET_SUBDIR);
	let backup_path = if destination_path.try_exists()? {
		let backup_path = txhashset_replace_backup_path(&to)?;
		fs::rename(&destination_path, &backup_path).map_err(|e| {
			error!(
				"txhashset_replace: failed to move existing {} from {:?} to {:?}. err: {}",
				TXHASHSET_SUBDIR, destination_path, backup_path, e
			);
			Error::IOErr(e)
		})?;
		Some(backup_path)
	} else {
		None
	};

	if let Err(e) = fs::rename(&source_path, &destination_path) {
		error!("hashset_replace fail on {}. err: {}", TXHASHSET_SUBDIR, e);
		if let Some(backup_path) = backup_path {
			if let Err(restore_err) = fs::rename(&backup_path, &destination_path) {
				error!(
					"txhashset_replace: failed to restore previous {} from {:?} to {:?}. err: {}",
					TXHASHSET_SUBDIR, backup_path, destination_path, restore_err
				);
				return Err(Error::TxHashSetErr(format!(
					"txhashset_replace: failed to move new {} from {:?} to {:?}. err: {}; \
					also failed to restore previous {} from {:?} to {:?}. err: {}",
					TXHASHSET_SUBDIR,
					source_path,
					destination_path,
					e,
					TXHASHSET_SUBDIR,
					backup_path,
					destination_path,
					restore_err,
				)));
			}
		}
		return Err(Error::IOErr(e));
	}

	if let Some(backup_path) = backup_path {
		if let Err(e) = fs::remove_dir_all(&backup_path) {
			return Ok(TxHashSetReplaceResult::ReplacedWithBackupCleanupFailure {
				backup_path,
				cleanup_error: e,
			});
		}
	}

	Ok(TxHashSetReplaceResult::Replaced)
}

fn txhashset_replace_backup_path(root_dir: &Path) -> Result<PathBuf, Error> {
	for idx in 0..1024 {
		let backup_path = root_dir.join(format!(
			".{}.replace_backup.{}.{}",
			TXHASHSET_SUBDIR,
			std::process::id(),
			idx
		));
		if !backup_path.try_exists()? {
			return Ok(backup_path);
		}
	}

	Err(Error::TxHashSetErr(format!(
		"unable to find a txhashset backup path in {:?}",
		root_dir
	)))
}

/// Clean the txhashset folder
pub fn clean_txhashset_folder(root_dir: &PathBuf) -> Result<(), Error> {
	let txhashset_path = root_dir.clone().join(TXHASHSET_SUBDIR);
	if txhashset_path.try_exists()? {
		fs::remove_dir_all(&txhashset_path)?;
	}
	Ok(())
}

/// Given a block header to rewind to and the block header at the
/// head of the current chain state, we need to calculate the positions
/// of all inputs (spent outputs) we need to "undo" during a rewind.
/// We do this by leveraging the "block_input_bitmap" cache and OR'ing
/// the set of bitmaps together for the set of blocks being rewound.
fn input_pos_to_rewind(
	block_header: &BlockHeader,
	head_header: &BlockHeader,
	batch: &Batch<'_>,
) -> Result<Bitmap, Error> {
	let mut bitmap = Bitmap::new();
	let context_id = batch.get_context_id();

	if block_header.height > head_header.height {
		return Err(Error::TxHashSetErr(format!(
			"input positions to rewind target {} at height {} is above body chain head {} at height {}",
			block_header.hash(context_id)?,
			block_header.height,
			head_header.hash(context_id)?,
			head_header.height
		)));
	}

	let mut current = head_header.clone();
	while current.height > block_header.height {
		let current_hash = current.hash(context_id)?;
		match batch.get_block_input_bitmap(&current_hash) {
			Ok(block_bitmap) => bitmap.or_inplace(&block_bitmap),
			Err(e) if e.store_error_is_not_found() => {
				return Err(Error::StoreErr(
					e,
					format!(
						"input positions to rewind missing block input bitmap for block {} at height {}",
						current_hash, current.height
					),
				));
			}
			Err(e) => {
				return Err(Error::StoreErr(
					e,
					"input positions to rewind get block input bitmap".to_owned(),
				));
			}
		}
		let prev = batch.get_previous_header(&current)?;
		if prev.height >= current.height {
			return Err(Error::TxHashSetErr(format!(
				"input positions to rewind encountered non-descending header ancestry: block {} at height {} has previous header {} at height {}",
				current_hash, current.height, current.prev_hash, prev.height
			)));
		}
		current = prev;
	}

	let current_hash = current.hash(context_id)?;
	let block_hash = block_header.hash(context_id)?;
	if current_hash != block_hash {
		return Err(Error::TxHashSetErr(format!(
			"input positions to rewind target {} at height {} is not on body chain ending at {} at height {}",
			block_hash,
			block_header.height,
			head_header.hash(context_id)?,
			head_header.height
		)));
	}
	if current != *block_header {
		return Err(Error::TxHashSetErr(format!(
			"input positions to rewind target {} at height {} does not match canonical body chain header",
			block_hash, block_header.height
		)));
	}
	Ok(bitmap)
}

/// If NRD enabled then enforce NRD relative height rules.
fn apply_kernel_rules(kernel: &TxKernel, pos: CommitPos, batch: &Batch<'_>) -> Result<(), Error> {
	if !global::is_nrd_enabled(batch.db.get_context_id()) {
		return Ok(());
	}
	match kernel.features {
		KernelFeatures::NoRecentDuplicate {
			relative_height, ..
		} => {
			let kernel_index = store::nrd_recent_kernel_index();
			debug!("checking NRD index: {:?}", kernel.excess());
			if let Some(prev) = kernel_index.peek_pos(batch, kernel.excess())? {
				let diff = pos.height.saturating_sub(prev.height);
				debug!(
					"NRD check: {}, {:?}, {:?}",
					pos.height, prev, relative_height
				);
				if diff < relative_height.into() {
					return Err(Error::NRDRelativeHeight);
				}
			}
			debug!(
				"pushing entry to NRD index: {:?}: {:?}",
				kernel.excess(),
				pos,
			);
			kernel_index.push_pos(batch, kernel.excess(), pos)?;
		}
		_ => {}
	}
	Ok(())
}

/// Order and sort output segments and hashes, returning an array
/// of elements that can be applied in order to a pmmr
pub fn sort_pmmr_hashes_and_leaves(
	hash_pos: Vec<u64>,
	leaf_pos: Vec<u64>,
	skip_leaf_position: Option<u64>,
) -> Vec<OrderedHashLeafNode> {
	// Merge and into single array and sort into insertion order
	let mut ordered_inserts = vec![];
	for (data_index, pos0) in leaf_pos.iter().enumerate() {
		// Don't re-push genesis output, basically
		if skip_leaf_position == Some(*pos0) {
			continue;
		}
		ordered_inserts.push(OrderedHashLeafNode::Leaf(data_index, *pos0));
	}
	for (data_index, pos0) in hash_pos.iter().enumerate() {
		ordered_inserts.push(OrderedHashLeafNode::Hash(data_index, *pos0));
	}
	ordered_inserts.sort();
	ordered_inserts
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::core::pmmr::segment::SegmentError;
	use mwc_core::core::{
		Input, Inputs, OutputFeatures, SegmentIdentifier, SegmentProof, TransactionBody,
	};
	use mwc_core::global::ChainTypes;
	use mwc_core::libtx::{reward, ProofBuilder};
	use mwc_crates::secp::ContextFlag;
	use mwc_keychain::{ExtKeychain, Keychain};
	use std::{fs, io};

	fn assert_data_overflow<T>(result: Result<T, Error>) {
		match result {
			Err(Error::DataOverflow(_)) => {}
			Err(other) => panic!("expected data overflow error, got {:?}", other),
			Ok(_) => panic!("expected data overflow error, got Ok"),
		}
	}

	#[test]
	fn wait_for_kernel_tasks_rejects_progress_count_overflow() {
		let (result, kern_count) = crossbeam::thread::scope(|scope| {
			let mut running_tasks = VecDeque::new();
			running_tasks.push_back(scope.spawn(|_| Ok(1usize)));
			let mut kern_count = u64::MAX;
			let result = Extension::wait_for_kernel_tasks(
				1,
				&mut running_tasks,
				&None,
				&SyncStatusUpdateThrottle::new(),
				&mut kern_count,
				u64::MAX,
			);
			(result, kern_count)
		})
		.unwrap();

		assert_data_overflow(result);
		assert_eq!(kern_count, u64::MAX);
	}

	#[test]
	fn wait_for_kernel_tasks_rejects_progress_count_above_total() {
		let (result, kern_count) = crossbeam::thread::scope(|scope| {
			let mut running_tasks = VecDeque::new();
			running_tasks.push_back(scope.spawn(|_| Ok(1usize)));
			let mut kern_count = 5;
			let result = Extension::wait_for_kernel_tasks(
				1,
				&mut running_tasks,
				&None,
				&SyncStatusUpdateThrottle::new(),
				&mut kern_count,
				5,
			);
			(result, kern_count)
		})
		.unwrap();

		assert_data_overflow(result);
		assert_eq!(kern_count, 5);
	}

	fn empty_segment_proof() -> SegmentProof {
		let mut proof_bytes = [0u8; 8].as_ref();
		mwc_core::ser::deserialize_default(0, &mut proof_bytes).unwrap()
	}

	fn reward_kernel(secp: &mut Secp256k1, child: u32) -> TxKernel {
		let keychain = ExtKeychain::from_seed(secp, &[0; 32], false).unwrap();
		let proof_builder = ProofBuilder::new(secp, &keychain).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, child, 0, 0, 0).unwrap();
		let (_, kernel) =
			reward::output(0, &keychain, &proof_builder, &key_id, 0, false, 1, secp).unwrap();
		kernel
	}

	fn save_block_headers(store: &ChainStore, headers: &[&BlockHeader]) {
		let batch = store.batch_write().unwrap();
		for header in headers {
			batch.save_block_header(header).unwrap();
		}
		batch.commit().unwrap();
	}

	fn assert_rewind_target_error(err: Error) {
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("rewind"), "{}", msg);
			}
			other => panic!("expected rewind target error, got {:?}", other),
		}
	}

	#[test]
	fn txhashset_replace_swaps_in_new_txhashset() {
		let root_dir = PathBuf::from("target/txhashset_replace_swaps_in_new_txhashset");
		let from = root_dir.join("from");
		let to = root_dir.join("to");
		let source_path = from.join(TXHASHSET_SUBDIR);
		let destination_path = to.join(TXHASHSET_SUBDIR);

		let _ = fs::remove_dir_all(&root_dir);
		fs::create_dir_all(&source_path).unwrap();
		fs::write(source_path.join("state"), b"new").unwrap();
		fs::create_dir_all(&destination_path).unwrap();
		fs::write(destination_path.join("state"), b"old").unwrap();

		assert!(matches!(
			txhashset_replace(from.clone(), to.clone()).unwrap(),
			TxHashSetReplaceResult::Replaced
		));

		assert_eq!(
			fs::read(to.join(TXHASHSET_SUBDIR).join("state")).unwrap(),
			b"new".to_vec()
		);
		assert!(!from.join(TXHASHSET_SUBDIR).try_exists().unwrap());
		assert_eq!(fs::read_dir(&to).unwrap().count(), 1);

		let _ = fs::remove_dir_all(&root_dir);
	}

	#[test]
	fn txhashset_replace_restores_existing_txhashset_on_rename_error() {
		let root_dir =
			PathBuf::from("target/txhashset_replace_restores_existing_txhashset_on_rename_error");
		let from = root_dir.join("from");
		let to = root_dir.join("to");
		let destination_path = to.join(TXHASHSET_SUBDIR);

		let _ = fs::remove_dir_all(&root_dir);
		fs::create_dir_all(&from).unwrap();
		fs::create_dir_all(&destination_path).unwrap();
		fs::write(destination_path.join("state"), b"old").unwrap();

		let err = txhashset_replace(from, to.clone()).unwrap_err();
		match err {
			Error::IOErr(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
			other => panic!("expected io error, got {:?}", other),
		}

		assert_eq!(
			fs::read(to.join(TXHASHSET_SUBDIR).join("state")).unwrap(),
			b"old".to_vec()
		);
		assert_eq!(fs::read_dir(&to).unwrap().count(), 1);

		let _ = fs::remove_dir_all(&root_dir);
	}

	#[cfg(unix)]
	#[test]
	fn txhashset_replace_reports_backup_cleanup_failure_after_replacement() {
		use std::os::unix::fs::PermissionsExt;

		let root_dir = PathBuf::from(
			"target/txhashset_replace_reports_backup_cleanup_failure_after_replacement",
		);
		let from = root_dir.join("from");
		let to = root_dir.join("to");
		let source_path = from.join(TXHASHSET_SUBDIR);
		let destination_path = to.join(TXHASHSET_SUBDIR);
		let protected_path = destination_path.join("protected");

		let _ = fs::remove_dir_all(&root_dir);
		fs::create_dir_all(&source_path).unwrap();
		fs::write(source_path.join("state"), b"new").unwrap();
		fs::create_dir_all(&protected_path).unwrap();
		fs::write(protected_path.join("state"), b"old").unwrap();
		fs::set_permissions(&protected_path, fs::Permissions::from_mode(0o500)).unwrap();

		let expected_backup_path = txhashset_replace_backup_path(&to).unwrap();
		let actual_backup_path = match txhashset_replace(from.clone(), to.clone()).unwrap() {
			TxHashSetReplaceResult::ReplacedWithBackupCleanupFailure {
				backup_path,
				cleanup_error: _,
			} => {
				assert_eq!(backup_path, expected_backup_path);
				backup_path
			}
			other => panic!("expected backup cleanup failure status, got {:?}", other),
		};

		assert_eq!(
			fs::read(to.join(TXHASHSET_SUBDIR).join("state")).unwrap(),
			b"new".to_vec()
		);
		assert!(!from.join(TXHASHSET_SUBDIR).try_exists().unwrap());
		assert!(actual_backup_path.try_exists().unwrap());

		fs::set_permissions(
			actual_backup_path.join("protected"),
			fs::Permissions::from_mode(0o700),
		)
		.unwrap();
		let _ = fs::remove_dir_all(&root_dir);
	}

	#[test]
	fn kernel_pmmr_probe_error_classifier_only_retries_version_reads() {
		let retry = Error::PMMRErr(pmmr::Error::IOErr(io::Error::new(
			io::ErrorKind::Other,
			"Fail to deserialize data, unexpected end of input",
		)));
		assert!(is_kernel_pmmr_version_probe_error(&retry));

		let fatal_state = Error::PMMRErr(pmmr::Error::InvalidState(
			"partial PMMR file set".to_string(),
		));
		assert!(!is_kernel_pmmr_version_probe_error(&fatal_state));

		let fatal_io = Error::PMMRErr(pmmr::Error::IOErr(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"permission denied",
		)));
		assert!(!is_kernel_pmmr_version_probe_error(&fatal_io));
	}

	#[test]
	fn open_falls_back_to_v1_kernel_pmmr_after_v2_probe_fails() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/open_falls_back_to_v1_kernel_pmmr_after_v2_probe_fails";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[0; 32], false).unwrap();
		let proof_builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let (_, kernel) = reward::output(
			0,
			&keychain,
			&proof_builder,
			&key_id,
			0,
			false,
			1,
			&mut secp,
		)
		.unwrap();
		kernel.verify(0, &secp).unwrap();

		let kernel_dir = Path::new(chain_dir)
			.join(TXHASHSET_SUBDIR)
			.join(KERNEL_SUBDIR);
		mwc_util::file::ensure_owner_only_dir_all(&kernel_dir).unwrap();
		{
			let mut backend = PMMRBackend::<TxKernel>::new(
				&kernel_dir,
				false,
				ProtocolVersion(1),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			{
				let mut pmmr = PMMR::new(&mut backend);
				assert_eq!(pmmr.push(&kernel).unwrap(), 0);
			}
			backend.sync().unwrap();
		}

		let txhashset = TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		assert_eq!(txhashset.kernel_pmmr_h.size, 1);
		let read_kernel = ReadonlyPMMR::at(
			&txhashset.kernel_pmmr_h.backend,
			txhashset.kernel_pmmr_h.size,
		)
		.get_data(0)
		.unwrap()
		.unwrap();
		read_kernel.verify(0, &secp).unwrap();

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_roots_rejects_empty_genesis_header_with_nonzero_roots() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_roots_rejects_empty_genesis_header_with_nonzero_roots";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let mut header = BlockHeader::default(0);
		header.output_root = Hash::from_vec(&[42]);

		{
			let extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&header).unwrap());
			let err = extension.validate_roots(&header).unwrap_err();
			match err {
				Error::InvalidRoot(msg) => {
					assert!(msg.contains("empty genesis header"), "{}", msg);
					assert!(msg.contains("non-zero MMR roots"), "{}", msg);
				}
				other => panic!("expected invalid root error, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_roots_rejects_empty_genesis_header_with_populated_mmrs() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_roots_rejects_empty_genesis_header_with_populated_mmrs";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let header = BlockHeader::default(0);

		{
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&header).unwrap());
			let commit = secp.commit_value(1).unwrap();
			let output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit);
			let proof = RangeProof::zero();
			let kernel = reward_kernel(&mut secp, 1);

			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 0);
			assert_eq!(extension.rproof_pmmr.push(&proof).unwrap(), 0);
			assert_eq!(extension.kernel_pmmr.push(&kernel).unwrap(), 0);

			let err = extension.validate_roots(&header).unwrap_err();
			match err {
				Error::InvalidRoot(msg) => {
					assert!(msg.contains("empty genesis header"), "{}", msg);
					assert!(msg.contains("non-empty txhashset MMRs"), "{}", msg);
				}
				other => panic!("expected invalid root error, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn get_output_pos_rejects_stale_output_pos_index_entry() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/get_output_pos_rejects_stale_output_pos_index_entry";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let commit_a = secp.commit_value(1).unwrap();
		let commit_b = secp.commit_value(2).unwrap();
		let output_a = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit_a);
		let output_b = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit_b);
		let pos_b = {
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			assert_eq!(output_pmmr.push(&output_a).unwrap(), 0);
			let pos_b = output_pmmr.push(&output_b).unwrap();
			txhashset.output_pmmr_h.size = output_pmmr.size();
			pos_b
		};
		let pos_b1 = pos_b.checked_add(1).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch
				.save_output_pos_height(
					&commit_b,
					CommitPos {
						pos: pos_b1,
						height: 0,
					},
				)
				.unwrap();
			batch
				.save_output_pos_height(
					&commit_a,
					CommitPos {
						pos: pos_b1,
						height: 0,
					},
				)
				.unwrap();
			batch.commit().unwrap();
		}

		assert_eq!(txhashset.get_output_pos(&commit_b).unwrap(), pos_b);
		let err = txhashset.get_output_pos(&commit_a).unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("output_pos index mismatch"), "{}", msg);
			}
			other => panic!("expected output_pos mismatch error, got {:?}", other),
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn get_output_pos_rejects_output_pos_index_missing_mmr_data() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/get_output_pos_rejects_output_pos_index_missing_mmr_data";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let txhashset = TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let commit = secp.commit_value(1).unwrap();
		{
			let batch = store.batch_write().unwrap();
			batch
				.save_output_pos_height(&commit, CommitPos { pos: 1, height: 0 })
				.unwrap();
			batch.commit().unwrap();
		}

		let err = txhashset.get_output_pos(&commit).unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(
					msg.contains("output_pos index points to missing output"),
					"{}",
					msg
				);
			}
			other => panic!("expected missing output_pos target error, got {:?}", other),
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn merkle_proof_rejects_stale_output_pos_index_entry() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/merkle_proof_rejects_stale_output_pos_index_entry";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let commit_a = secp.commit_value(1).unwrap();
		let commit_b = secp.commit_value(2).unwrap();
		let output_a = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit_a);
		let output_b = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit_b);
		let pos_b = {
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			assert_eq!(output_pmmr.push(&output_a).unwrap(), 0);
			let pos_b = output_pmmr.push(&output_b).unwrap();
			txhashset.output_pmmr_h.size = output_pmmr.size();
			pos_b
		};
		let pos_b1 = pos_b.checked_add(1).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch
				.save_output_pos_height(
					&commit_b,
					CommitPos {
						pos: pos_b1,
						height: 0,
					},
				)
				.unwrap();
			batch
				.save_output_pos_height(
					&commit_a,
					CommitPos {
						pos: pos_b1,
						height: 0,
					},
				)
				.unwrap();
			batch.commit().unwrap();
		}

		txhashset.merkle_proof(commit_b).unwrap();
		let err = txhashset.merkle_proof(commit_a).unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("output_pos index mismatch"), "{}", msg);
			}
			other => panic!("expected output_pos mismatch error, got {:?}", other),
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extension_merkle_proof_rejects_output_pos_index_identifier_mismatch() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/extension_merkle_proof_rejects_output_pos_index_identifier_mismatch";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let commit = secp.commit_value(1).unwrap();
		let plain_output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit);
		let coinbase_output =
			OutputIdentifier::new(mwc_core::core::OutputFeatures::Coinbase, &commit);
		let pos_coinbase = {
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			assert_eq!(output_pmmr.push(&plain_output).unwrap(), 0);
			let pos_coinbase = output_pmmr.push(&coinbase_output).unwrap();
			txhashset.output_pmmr_h.size = output_pmmr.size();
			pos_coinbase
		};
		let pos_coinbase1 = pos_coinbase.checked_add(1).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch
				.save_output_pos_height(
					&commit,
					CommitPos {
						pos: pos_coinbase1,
						height: 0,
					},
				)
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_write().unwrap();
			let extension = Extension::new(0, &mut txhashset, Tip::default());

			extension.merkle_proof(coinbase_output, &batch).unwrap();
			let err = extension.merkle_proof(plain_output, &batch).unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("output_pos index mismatch"), "{}", msg);
				}
				other => panic!("expected output_pos mismatch error, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn apply_output_rejects_output_pos_index_commitment_mismatch() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/apply_output_rejects_output_pos_index_commitment_mismatch";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let indexed_commit = secp.commit_value(1).unwrap();
		let mmr_commit = secp.commit_value(2).unwrap();
		let mmr_output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &mmr_commit);
		let pos = {
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			let pos = output_pmmr.push(&mmr_output).unwrap();
			txhashset.output_pmmr_h.size = output_pmmr.size();
			pos
		};

		{
			let batch = store.batch_write().unwrap();
			batch
				.save_output_pos_height(
					&indexed_commit,
					CommitPos {
						pos: pos.checked_add(1).unwrap(),
						height: 0,
					},
				)
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let output = Output::new(
				mwc_core::core::OutputFeatures::Plain,
				indexed_commit,
				RangeProof::zero(),
			);

			let err = extension.apply_output(&output, &batch).unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("output_pos index mismatch"), "{}", msg);
				}
				other => panic!("expected output_pos mismatch error, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn apply_output_rejects_output_pos_index_missing_mmr_data() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/apply_output_rejects_output_pos_index_missing_mmr_data";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let commit = secp.commit_value(1).unwrap();
		{
			let batch = store.batch_write().unwrap();
			batch
				.save_output_pos_height(&commit, CommitPos { pos: 1, height: 0 })
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let output = Output::new(
				mwc_core::core::OutputFeatures::Plain,
				commit,
				RangeProof::zero(),
			);

			let err = extension.apply_output(&output, &batch).unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(
						msg.contains("output_pos index points to missing output"),
						"{}",
						msg
					);
				}
				other => panic!("expected missing output_pos target error, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn apply_block_resolves_inputs_before_indexing_new_outputs() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/apply_block_resolves_inputs_before_indexing_new_outputs";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let commit = secp.commit_value(1).unwrap();
		let output = Output::new(OutputFeatures::Plain, commit, RangeProof::zero());
		let input = Input::new(OutputFeatures::Plain, commit);
		let kernel = reward_kernel(&mut secp, 1);
		let mut header = BlockHeader::default(0);
		header.height = 1;
		let body = TransactionBody::init(
			0,
			Inputs::from([input].as_slice()),
			&[output],
			&[kernel],
			false,
		)
		.unwrap();
		let block = Block { header, body };

		{
			let batch = store.batch_write().unwrap();
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			let header_ext = HeaderExtension::new(pmmr, Tip::default());

			let err = extension
				.apply_block(&block, &header_ext, &batch)
				.unwrap_err();
			match err {
				Error::AlreadySpent(c) => assert_eq!(c, commit),
				other => panic!("expected missing pre-block input, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extension_rewind_rejects_forward_target_header() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/extension_rewind_rejects_forward_target_header";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let mut head = BlockHeader::default(0);
		head.height = 1;
		let head_hash = head.hash(0).unwrap();
		save_block_headers(&store, &[&head]);

		let mut target = BlockHeader::default(0);
		target.height = 2;
		target.prev_hash = head_hash;

		{
			let batch = store.batch_read().unwrap();
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&head).unwrap());
			let pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			let header_ext = HeaderExtension::new(pmmr, Tip::default());

			let err = extension
				.rewind(&target, &batch, &header_ext, None)
				.unwrap_err();
			assert_rewind_target_error(err);
			assert_eq!(extension.head().last_block_h, head_hash);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extension_rewind_rejects_same_height_fork_header() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/extension_rewind_rejects_same_height_fork_header";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let mut head = BlockHeader::default(0);
		head.height = 1;
		let head_hash = head.hash(0).unwrap();
		save_block_headers(&store, &[&head]);

		let mut fork = head.clone();
		fork.pow.proof.nonces[0] = 1;
		assert_ne!(fork.hash(0).unwrap(), head_hash);

		{
			let batch = store.batch_read().unwrap();
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&head).unwrap());
			let pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			let header_ext = HeaderExtension::new(pmmr, Tip::default());

			let err = extension
				.rewind(&fork, &batch, &header_ext, None)
				.unwrap_err();
			assert_rewind_target_error(err);
			assert_eq!(extension.head().last_block_h, head_hash);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extension_rewind_rejects_same_hash_altered_header_fields() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/extension_rewind_rejects_same_hash_altered_header_fields";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let mut head = BlockHeader::default(0);
		head.height = 1;
		head.output_mmr_size = 1;
		let head_hash = head.hash(0).unwrap();
		save_block_headers(&store, &[&head]);

		let mut altered = head.clone();
		altered.output_mmr_size = 0;
		assert_eq!(altered.hash(0).unwrap(), head_hash);
		assert_ne!(altered, head);

		{
			let batch = store.batch_read().unwrap();
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&head).unwrap());
			let commit = secp.commit_value(1).unwrap();
			let output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit);
			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 0);
			let pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			let header_ext = HeaderExtension::new(pmmr, Tip::default());

			let err = extension
				.rewind(&altered, &batch, &header_ext, None)
				.unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("does not match canonical"), "{}", msg);
				}
				other => panic!("expected canonical header mismatch, got {:?}", other),
			}
			assert_eq!(extension.output_pmmr.size(), 1);
			assert_eq!(extension.head().last_block_h, head_hash);
		}

		drop(header_pmmr);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extension_rewind_rejects_lower_fork_header_before_applying_blocks() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/extension_rewind_rejects_lower_fork_header_before_applying_blocks";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let mut ancestor = BlockHeader::default(0);
		ancestor.height = 1;
		ancestor.pow.proof.nonces[0] = 1;
		let ancestor_hash = ancestor.hash(0).unwrap();

		let mut head = BlockHeader::default(0);
		head.height = 2;
		head.prev_hash = ancestor_hash;
		head.pow.proof.nonces[0] = 2;
		let head_hash = head.hash(0).unwrap();

		let mut fork = ancestor.clone();
		fork.pow.proof.nonces[0] = 3;
		assert_ne!(fork.hash(0).unwrap(), ancestor_hash);

		save_block_headers(&store, &[&ancestor, &head]);

		{
			let batch = store.batch_read().unwrap();
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&head).unwrap());
			let pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			let header_ext = HeaderExtension::new(pmmr, Tip::default());

			let err = extension
				.rewind(&fork, &batch, &header_ext, None)
				.unwrap_err();
			assert_rewind_target_error(err);
			assert_eq!(extension.head().last_block_h, head_hash);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn rewind_single_block_errors_if_spent_output_data_missing() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/rewind_single_block_errors_if_spent_output_data_missing";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let prev = BlockHeader::default(0);
		let prev_hash = prev.hash(0).unwrap();
		let mut header = BlockHeader::default(0);
		header.height = 1;
		header.prev_hash = prev_hash;
		let header_hash = header.hash(0).unwrap();
		save_block_headers(&store, &[&prev]);

		{
			let batch = store.batch_write().unwrap();
			batch
				.save_spent_index(&header_hash, &[CommitPos { pos: 1, height: 0 }])
				.unwrap();
			batch.commit().unwrap();
		}

		let mut block = Block::default(0);
		block.header = header.clone();

		{
			let batch = store.batch_write().unwrap();
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&header).unwrap());
			let pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			let header_ext = HeaderExtension::new(pmmr, Tip::default());

			let err = extension
				.rewind_single_block(&block, &batch, &header_ext)
				.unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("missing output PMMR data"), "{}", msg);
					assert!(msg.contains("restoring output_pos"), "{}", msg);
				}
				other => panic!("expected missing output PMMR data error, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn reconstruct_spent_index_maps_output_positions_to_heights() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/reconstruct_spent_index_maps_output_positions_to_heights";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let genesis = BlockHeader::default(0);
		let genesis_hash = genesis.hash(0).unwrap();
		let mut header_1 = BlockHeader::default(0);
		header_1.height = 1;
		header_1.prev_hash = genesis_hash;
		header_1.output_mmr_size = 1;
		header_1.pow.proof.nonces[0] = 1;
		let header_1_hash = header_1.hash(0).unwrap();
		let mut header_2 = BlockHeader::default(0);
		header_2.height = 2;
		header_2.prev_hash = header_1_hash;
		header_2.output_mmr_size = 3;
		header_2.pow.proof.nonces[0] = 2;
		save_block_headers(&store, &[&genesis, &header_1]);

		let batch = store.batch_read().unwrap();
		let extension = Extension::new(0, &mut txhashset, Tip::try_from_header(&header_2).unwrap());
		assert_eq!(
			extension
				.reconstruct_spent_index(&[1, 2], &header_2, &batch)
				.unwrap(),
			vec![
				CommitPos { pos: 1, height: 1 },
				CommitPos { pos: 2, height: 2 },
			]
		);

		drop(extension);
		drop(batch);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn reconstruct_spent_index_rejects_internal_output_pmmr_node() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/reconstruct_spent_index_rejects_internal_output_pmmr_node";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let genesis = BlockHeader::default(0);
		let genesis_hash = genesis.hash(0).unwrap();
		let mut header_1 = BlockHeader::default(0);
		header_1.height = 1;
		header_1.prev_hash = genesis_hash;
		header_1.output_mmr_size = 1;
		header_1.pow.proof.nonces[0] = 1;
		let header_1_hash = header_1.hash(0).unwrap();
		let mut header_2 = BlockHeader::default(0);
		header_2.height = 2;
		header_2.prev_hash = header_1_hash;
		header_2.output_mmr_size = 3;
		header_2.pow.proof.nonces[0] = 2;
		save_block_headers(&store, &[&genesis, &header_1]);

		let batch = store.batch_read().unwrap();
		let extension = Extension::new(0, &mut txhashset, Tip::try_from_header(&header_2).unwrap());
		let err = extension
			.reconstruct_spent_index(&[3], &header_2, &batch)
			.unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("non-leaf output PMMR pos 3"), "{}", msg);
			}
			other => panic!("expected non-leaf output PMMR pos error, got {:?}", other),
		}

		drop(extension);
		drop(batch);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn reconstruct_spent_index_rejects_output_mmr_size_regression() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/reconstruct_spent_index_rejects_output_mmr_size_regression";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let genesis = BlockHeader::default(0);
		let genesis_hash = genesis.hash(0).unwrap();
		let mut header_1 = BlockHeader::default(0);
		header_1.height = 1;
		header_1.prev_hash = genesis_hash;
		header_1.output_mmr_size = 5;
		header_1.pow.proof.nonces[0] = 1;
		let header_1_hash = header_1.hash(0).unwrap();
		let mut header_2 = BlockHeader::default(0);
		header_2.height = 2;
		header_2.prev_hash = header_1_hash;
		header_2.output_mmr_size = 3;
		header_2.pow.proof.nonces[0] = 2;
		save_block_headers(&store, &[&genesis, &header_1]);

		let batch = store.batch_read().unwrap();
		let extension = Extension::new(0, &mut txhashset, Tip::try_from_header(&header_2).unwrap());
		let err = extension
			.reconstruct_spent_index(&[2], &header_2, &batch)
			.unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("output MMR size regression"), "{}", msg);
				assert!(msg.contains("previous 5, current 3"), "{}", msg);
			}
			other => panic!("expected output MMR size regression error, got {:?}", other),
		}

		drop(extension);
		drop(batch);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn header_hash_by_height_rejects_height_above_leaf_count() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/header_hash_by_height_rejects_height_above_leaf_count";
		let _ = fs::remove_dir_all(chain_dir);
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		header_pmmr.size = pmmr::insertion_to_pmmr_index(4).unwrap();
		let err = header_pmmr.get_header_hash_by_height(4).unwrap_err();

		assert!(matches!(err, Error::InvalidHeaderHeight(4)));
		drop(header_pmmr);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn input_pos_to_rewind_errors_if_block_input_bitmap_missing() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/input_pos_to_rewind_errors_if_block_input_bitmap_missing";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let horizon = BlockHeader::default(0);
		let mut head = BlockHeader::default(0);
		head.height = horizon.height + 1;
		head.prev_hash = horizon.hash(0).unwrap();

		let batch = store.batch_read().unwrap();
		let err = input_pos_to_rewind(&horizon, &head, &batch).unwrap_err();
		match err {
			Error::StoreErr(store_err, msg) => {
				assert!(store_err.store_error_is_not_found(), "{:?}", store_err);
				assert!(msg.contains("missing block input bitmap"), "{}", msg);
			}
			other => panic!("expected missing bitmap store error, got {:?}", other),
		}
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn input_pos_to_rewind_errors_if_previous_header_height_does_not_decrease() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/input_pos_to_rewind_errors_if_previous_header_height_does_not_decrease";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let horizon = BlockHeader::default(0);
		let mut prev = BlockHeader::default(0);
		prev.height = 1;
		let prev_hash = prev.hash(0).unwrap();

		let mut head = BlockHeader::default(0);
		head.height = 1;
		head.prev_hash = prev_hash;
		let head_hash = head.hash(0).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&prev).unwrap();
			batch.save_spent_index(&head_hash, &[]).unwrap();
			batch.commit().unwrap();
		}

		let batch = store.batch_read().unwrap();
		let err = input_pos_to_rewind(&horizon, &head, &batch).unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("non-descending header ancestry"), "{}", msg);
			}
			other => panic!("expected non-descending ancestry error, got {:?}", other),
		}
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn input_pos_to_rewind_errors_if_target_hash_not_on_body_chain() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/input_pos_to_rewind_errors_if_target_hash_not_on_body_chain";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let mut horizon = BlockHeader::default(0);
		horizon.height = 42;
		let mut head = BlockHeader::default(0);
		head.height = horizon.height;
		head.pow.proof.nonces[0] = 1;

		let batch = store.batch_read().unwrap();
		let err = input_pos_to_rewind(&horizon, &head, &batch).unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("is not on body chain"), "{}", msg);
			}
			other => panic!("expected body chain mismatch error, got {:?}", other),
		}
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn input_pos_to_rewind_errors_if_target_height_above_head() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/input_pos_to_rewind_errors_if_target_height_above_head";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let mut head = BlockHeader::default(0);
		head.height = 1;
		let mut target = head.clone();
		target.height = 2;
		assert_eq!(target.hash(0).unwrap(), head.hash(0).unwrap());

		let batch = store.batch_read().unwrap();
		let err = input_pos_to_rewind(&target, &head, &batch).unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("above body chain head"), "{}", msg);
			}
			other => panic!("expected forward rewind target error, got {:?}", other),
		}
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn input_pos_to_rewind_errors_if_same_hash_target_header_fields_differ() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/input_pos_to_rewind_errors_if_same_hash_target_header_fields_differ";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let mut head = BlockHeader::default(0);
		head.height = 1;
		head.output_mmr_size = 1;
		let head_hash = head.hash(0).unwrap();

		let mut target = head.clone();
		target.output_mmr_size = 0;
		assert_eq!(target.hash(0).unwrap(), head_hash);
		assert_ne!(target, head);

		let batch = store.batch_read().unwrap();
		let err = input_pos_to_rewind(&target, &head, &batch).unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("does not match canonical"), "{}", msg);
			}
			other => panic!("expected canonical header mismatch, got {:?}", other),
		}
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn find_kernel_rejects_zero_min_and_clamps_max_bound() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/find_kernel_rejects_zero_min_and_clamps_max_bound";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let txhashset = TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let excess = secp_static::commit_to_zero_value();

		assert_data_overflow(txhashset.find_kernel(&excess, Some(0), Some(1)));
		assert!(txhashset
			.find_kernel(&excess, Some(1), Some(u64::MAX))
			.unwrap()
			.is_none());

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn update_leaf_sets_prunes_leaves_absent_from_bitmap() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/update_leaf_sets_prunes_leaves_absent_from_bitmap";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		{
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let commit = secp.commit_value(1).unwrap();
			let output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit);
			let proof = RangeProof::zero();

			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 0);
			assert_eq!(extension.rproof_pmmr.push(&proof).unwrap(), 0);
			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 1);
			assert_eq!(extension.rproof_pmmr.push(&proof).unwrap(), 1);

			let mut bitmap = Bitmap::new();
			bitmap.add(0);
			extension.update_leaf_sets(&bitmap).unwrap();

			assert!(extension.output_pmmr.get_data(0).unwrap().is_some());
			assert!(extension.rproof_pmmr.get_data(0).unwrap().is_some());
			assert!(extension.output_pmmr.get_data(1).unwrap().is_none());
			assert!(extension.rproof_pmmr.get_data(1).unwrap().is_none());
			assert_eq!(extension.output_pmmr.n_unpruned_leaves().unwrap(), 1);
			assert_eq!(extension.rproof_pmmr.n_unpruned_leaves().unwrap(), 1);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn verify_rangeproofs_returns_stopped_at_batch_boundary() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/verify_rangeproofs_returns_stopped_at_batch_boundary";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		{
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let commit = secp.commit_value(1).unwrap();
			let output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit);
			let proof = RangeProof::zero();
			let stop_state = Arc::new(StopState::new());
			stop_state.stop();

			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 0);
			assert_eq!(extension.rproof_pmmr.push(&proof).unwrap(), 0);
			assert!(matches!(
				extension.verify_rangeproofs(None, Some(1), Some(stop_state)),
				Err(Error::Stopped)
			));
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn genesis_validation_skip_requires_empty_extension_mmrs() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/genesis_validation_skip_requires_empty_extension_mmrs";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[0; 32], false).unwrap();
		let proof_builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let reward = reward::output(
			0,
			&keychain,
			&proof_builder,
			&key_id,
			0,
			false,
			0,
			&mut secp,
		)
		.unwrap();
		let genesis = Block::default(0).with_reward(reward.0, reward.1).unwrap();
		assert_eq!(genesis.header.output_mmr_size, 0);
		assert_eq!(genesis.header.kernel_mmr_size, 0);
		assert_eq!(genesis.header.output_root, ZERO_HASH);
		assert_eq!(genesis.header.range_proof_root, ZERO_HASH);
		assert_eq!(genesis.header.kernel_root, ZERO_HASH);

		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		{
			let batch = store.batch_write().unwrap();
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			let header_ext = HeaderExtension::new(pmmr, Tip::default());

			let mut non_zero_root_header = genesis.header.clone();
			non_zero_root_header.output_root = Hash::from_vec(&[1]);
			assert!(matches!(
				extension.validate_roots(&non_zero_root_header),
				Err(Error::InvalidRoot(_))
			));

			extension
				.rebuild_genesis(&genesis, &header_ext, &batch)
				.unwrap();
			assert_eq!(extension.sizes(), (1, 1, 1));

			match extension.validate_roots(&genesis.header).unwrap_err() {
				Error::InvalidRoot(msg) => {
					assert!(msg.contains("empty genesis header"), "{}", msg);
					assert!(msg.contains("non-empty txhashset MMRs"), "{}", msg);
				}
				other => panic!("expected invalid genesis MMR root, got {:?}", other),
			}
			assert!(matches!(
				extension.validate_sizes(&genesis.header),
				Err(Error::InvalidMMRSize)
			));
		}

		drop(header_pmmr);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_empty_genesis_shortcut_requires_zero_kernel_offset() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_empty_genesis_shortcut_requires_zero_kernel_offset";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let header = BlockHeader::default(0);
		let extension = Extension::new(0, &mut txhashset, Tip::default());
		let zero_commit = secp_static::commit_to_zero_value();
		assert_eq!(
			extension
				.validate(&header, true, None, &header, None, &secp)
				.unwrap(),
			(zero_commit, zero_commit)
		);

		drop(extension);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_empty_genesis_rejects_nonzero_kernel_offset() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_empty_genesis_rejects_nonzero_kernel_offset";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let mut header = BlockHeader::default(0);
		header.total_kernel_offset = mwc_keychain::BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000001",
		)
		.unwrap();

		let extension = Extension::new(0, &mut txhashset, Tip::default());
		match extension
			.validate(&header, true, None, &header, None, &secp)
			.unwrap_err()
		{
			Error::Committed(_) => {}
			other => panic!("expected committed sum error, got {:?}", other),
		}

		drop(extension);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_populated_genesis_runs_kernel_sum_validation() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/validate_populated_genesis_runs_kernel_sum_validation";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[0; 32], false).unwrap();
		let proof_builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let reward = reward::output(
			0,
			&keychain,
			&proof_builder,
			&key_id,
			0,
			false,
			0,
			&mut secp,
		)
		.unwrap();
		let mut genesis = Block::default(0).with_reward(reward.0, reward.1).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		{
			let batch = store.batch_write().unwrap();
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			let header_ext = HeaderExtension::new(pmmr, Tip::default());
			extension
				.apply_block(&genesis, &header_ext, &batch)
				.unwrap();
			let roots = extension.roots().unwrap();
			let sizes = extension.sizes();
			genesis.header.output_mmr_size = sizes.0;
			genesis.header.kernel_mmr_size = sizes.2;
			genesis.header.output_root = roots.output_root;
			genesis.header.range_proof_root = roots.rproof_root;
			genesis.header.kernel_root = roots.kernel_root;

			let (output_sum, kernel_sum) = extension
				.validate(&genesis.header, false, None, &genesis.header, None, &secp)
				.unwrap();
			let zero_commit = secp_static::commit_to_zero_value();
			assert_ne!(output_sum, zero_commit);
			assert_ne!(kernel_sum, zero_commit);
		}

		drop(header_pmmr);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn apply_segments_reject_non_leaf_positions() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/apply_segments_reject_non_leaf_positions";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		{
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let commit = secp.commit_value(1).unwrap();
			let output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit);
			let output_segment = Segment::from_parts(
				SegmentIdentifier::new(0, 0),
				Vec::new(),
				Vec::new(),
				vec![2],
				vec![output],
				empty_segment_proof(),
			)
			.unwrap();

			let output_err = extension
				.apply_validated_output_segments(vec![output_segment], &Bitmap::new())
				.unwrap_err();
			match output_err {
				Error::InvalidSegment(msg) => {
					assert!(msg.contains("output position 2 is not a leaf"), "{}", msg);
				}
				other => panic!("expected invalid output segment, got {:?}", other),
			}

			let rproof_segment = Segment::from_parts(
				SegmentIdentifier::new(0, 0),
				Vec::new(),
				Vec::new(),
				vec![2],
				vec![RangeProof::zero()],
				empty_segment_proof(),
			)
			.unwrap();

			let rproof_err = extension
				.apply_validated_rangeproof_segments(vec![rproof_segment], &Bitmap::new())
				.unwrap_err();
			match rproof_err {
				Error::InvalidSegment(msg) => {
					assert!(
						msg.contains("rangeproof position 2 is not a leaf"),
						"{}",
						msg
					);
				}
				other => panic!("expected invalid rangeproof segment, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn segment_validate_rejects_unauthenticated_output_data() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		let forged_commit = secp.commit_value(2).unwrap();
		let forged_output =
			OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &forged_commit);
		let segment = Segment::from_parts(
			SegmentIdentifier::new(0, 1),
			Vec::new(),
			Vec::new(),
			vec![1],
			vec![forged_output],
			empty_segment_proof(),
		)
		.unwrap();
		let mut bitmap = Bitmap::new();
		bitmap.add(1);
		let expected_root = Hash::from_vec(&[1]);

		let err = segment
			.validate(0, 3, Some(&bitmap), &expected_root)
			.unwrap_err();
		match err {
			SegmentError::MissingHash(_) | SegmentError::Mismatch => {}
			other => panic!("expected segment proof validation error, got {:?}", other),
		}
	}

	#[test]
	fn segment_validate_rejects_unauthenticated_rangeproof_data() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let segment = Segment::from_parts(
			SegmentIdentifier::new(0, 1),
			Vec::new(),
			Vec::new(),
			vec![1],
			vec![RangeProof::zero()],
			empty_segment_proof(),
		)
		.unwrap();
		let mut bitmap = Bitmap::new();
		bitmap.add(1);
		let expected_root = Hash::from_vec(&[1]);

		let err = segment
			.validate(0, 3, Some(&bitmap), &expected_root)
			.unwrap_err();
		match err {
			SegmentError::MissingHash(_) | SegmentError::Mismatch => {}
			other => panic!("expected segment proof validation error, got {:?}", other),
		}
	}

	#[test]
	fn apply_output_segments_rejects_future_leaf_position() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/apply_output_segments_rejects_future_leaf_position";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		{
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let future_leaf = 1;
			let commit = secp.commit_value(1).unwrap();
			let output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit);
			let segment = Segment::from_parts(
				SegmentIdentifier::new(0, 0),
				Vec::new(),
				Vec::new(),
				vec![future_leaf],
				vec![output],
				empty_segment_proof(),
			)
			.unwrap();
			let mut bitmap = Bitmap::new();
			bitmap.add(
				u32::try_from(pmmr::pmmr_leaf_to_insertion_index(future_leaf).unwrap()).unwrap(),
			);

			let err = extension
				.apply_validated_output_segments(vec![segment], &bitmap)
				.unwrap_err();
			match err {
				Error::InvalidSegment(msg) => {
					assert!(msg.contains("output leaf 1"), "{}", msg);
					assert!(msg.contains("current PMMR size 0"), "{}", msg);
				}
				other => panic!("expected invalid output segment, got {:?}", other),
			}
			assert_eq!(extension.output_pmmr.size(), 0);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn apply_rangeproof_segments_rejects_future_leaf_position() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/apply_rangeproof_segments_rejects_future_leaf_position";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		{
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let future_leaf = 1;
			let segment = Segment::from_parts(
				SegmentIdentifier::new(0, 0),
				Vec::new(),
				Vec::new(),
				vec![future_leaf],
				vec![RangeProof::zero()],
				empty_segment_proof(),
			)
			.unwrap();
			let mut bitmap = Bitmap::new();
			bitmap.add(
				u32::try_from(pmmr::pmmr_leaf_to_insertion_index(future_leaf).unwrap()).unwrap(),
			);

			let err = extension
				.apply_validated_rangeproof_segments(vec![segment], &bitmap)
				.unwrap_err();
			match err {
				Error::InvalidSegment(msg) => {
					assert!(msg.contains("rangeproof leaf 1"), "{}", msg);
					assert!(msg.contains("current PMMR size 0"), "{}", msg);
				}
				other => panic!("expected invalid rangeproof segment, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn apply_validated_kernel_segments_rejects_hash_data() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/apply_validated_kernel_segments_rejects_hash_data";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		{
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let kernel_segment: Segment<TxKernel> = Segment::from_parts(
				SegmentIdentifier::new(0, 0),
				vec![0],
				vec![Hash::default()],
				Vec::new(),
				Vec::new(),
				empty_segment_proof(),
			)
			.unwrap();

			let err = extension
				.apply_validated_kernel_segments(vec![kernel_segment])
				.unwrap_err();
			match err {
				Error::InvalidSegment(msg) => {
					assert!(msg.contains("non-prunable"), "{}", msg);
					assert!(msg.contains("hash data"), "{}", msg);
				}
				other => panic!("expected invalid kernel segment, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn segment_validate_rejects_unauthenticated_kernel_data() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		let forged_kernel = reward_kernel(&mut secp, 2);
		let segment = Segment::from_parts(
			SegmentIdentifier::new(0, 1),
			Vec::new(),
			Vec::new(),
			vec![1],
			vec![forged_kernel],
			empty_segment_proof(),
		)
		.unwrap();
		let expected_root = Hash::from_vec(&[1]);

		let err = segment.validate(0, 3, None, &expected_root).unwrap_err();
		match err {
			SegmentError::MissingHash(_) | SegmentError::Mismatch => {}
			other => panic!("expected segment proof validation error, got {:?}", other),
		}
	}

	#[test]
	fn apply_input_rejects_missing_rangeproof_leaf() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/apply_input_rejects_missing_rangeproof_leaf";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		{
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let commit = secp.commit_value(1).unwrap();
			let output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit);
			let proof = RangeProof::zero();

			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 0);
			assert_eq!(extension.rproof_pmmr.push(&proof).unwrap(), 0);
			assert!(extension.rproof_pmmr.prune(0).unwrap());

			let err = extension
				.apply_input(commit, CommitPos { pos: 1, height: 0 })
				.unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("rangeproof leaf"), "{}", msg);
					assert!(msg.contains("already pruned or absent"), "{}", msg);
				}
				other => panic!("expected rangeproof prune error, got {:?}", other),
			}
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extending_propagates_rangeproof_prune_error_and_discards() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/extending_propagates_rangeproof_prune_error_and_discards";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let tip = Tip::default();
		{
			let batch = store.batch_write().unwrap();
			batch.save_body_head(&tip).unwrap();
			batch.save_header_head(&tip).unwrap();
			batch.commit().unwrap();
		}

		let commit = secp.commit_value(1).unwrap();
		let mut batch = store.batch_write().unwrap();
		let err = extending(&mut header_pmmr, &mut txhashset, &mut batch, |ext, _| {
			let output = OutputIdentifier::new(mwc_core::core::OutputFeatures::Plain, &commit);
			let proof = RangeProof::zero();

			assert_eq!(ext.extension.output_pmmr.push(&output).unwrap(), 0);
			assert_eq!(ext.extension.rproof_pmmr.push(&proof).unwrap(), 0);
			assert!(ext.extension.rproof_pmmr.prune(0).unwrap());

			ext.extension
				.apply_input(commit, CommitPos { pos: 1, height: 0 })
		})
		.unwrap_err();

		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("rangeproof leaf"), "{}", msg);
				assert!(msg.contains("already pruned or absent"), "{}", msg);
			}
			other => panic!(
				"expected propagated rangeproof prune error, got {:?}",
				other
			),
		}
		assert_eq!(txhashset.output_pmmr_h.size, 0);
		assert_eq!(txhashset.rproof_pmmr_h.size, 0);

		drop(batch);
		drop(txhashset);
		drop(header_pmmr);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extending_with_head_rewinds_to_archive_header_when_body_head_is_genesis() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/extending_with_head_rewinds_to_archive_header_when_body_head_is_genesis";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let genesis_tip = Tip::default();
		let mut archive_header = BlockHeader::default(0);
		archive_header.height = 1;
		let archive_tip = Tip::try_from_header(&archive_header).unwrap();
		{
			let batch = store.batch_write().unwrap();
			batch.save_body_head(&genesis_tip).unwrap();
			batch.save_header_head(&genesis_tip).unwrap();
			batch.save_block_header(&archive_header).unwrap();
			batch.commit().unwrap();
		}

		let mut batch = store.batch_write().unwrap();
		extending_with_head(
			&mut header_pmmr,
			&mut txhashset,
			&mut batch,
			archive_tip.clone(),
			|ext, batch| {
				assert_eq!(ext.extension.head().height, archive_tip.height);
				assert_eq!(ext.extension.head().last_block_h, archive_tip.last_block_h);
				ext.extension
					.rewind(&archive_header, batch, ext.header_extension, None)
			},
		)
		.unwrap();

		drop(batch);
		drop(txhashset);
		drop(header_pmmr);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_non_genesis_header_does_not_shortcut_on_zero_extension_head() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/validate_non_genesis_header_does_not_shortcut_on_zero_extension_head";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let roots = txhashset.roots().unwrap();
		let genesis = BlockHeader::default(0);
		let mut header = BlockHeader::default(0);
		header.height = 1;
		header.output_root = roots.output_root;
		header.range_proof_root = roots.rproof_root;
		header.kernel_root = roots.kernel_root;
		header.output_mmr_size = roots.output_mmr_size;
		header.kernel_mmr_size = roots.kernel_mmr_size;

		let extension = Extension::new(0, &mut txhashset, Tip::default());
		extension
			.validate(&genesis, true, None, &header, None, &secp)
			.unwrap_err();

		drop(extension);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}
}
