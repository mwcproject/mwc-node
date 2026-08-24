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
	CommitPos, HashHeight, KernelPos, SpentCommitmentRecord, SpentOutput, SyncStatusUpdateThrottle,
	Tip, TxHashSetRoots, TxHashsetStateValidationStage, TXHASHSET_STATE_VALIDATION_STEPS,
};
use crate::{SyncState, SyncStatus};
use mwc_core::consensus::WEEK_HEIGHT;
use mwc_core::core::block::{verify_kernel_lock_height, verify_nrd_kernel_for_header_version};
use mwc_core::core::committed::{verify_kernel_sums_iter, Error as CommittedError};
use mwc_core::core::hash::{Hash, Hashed, ZERO_HASH};
use mwc_core::core::merkle_proof::MerkleProof;
use mwc_core::core::pmmr::{self, Backend, ReadablePMMR, ReadonlyPMMR, RewindablePMMR, PMMR};
use mwc_core::core::{
	amount_to_hr_string, Block, BlockHeader, Inputs, KernelFeatures, Output, OutputIdentifier,
	Segment, TxKernel,
};
use mwc_core::global;
use mwc_core::ser::{self, PMMRIndexHashable, PMMRable, ProtocolVersion};
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
use std::collections::{HashMap, HashSet, VecDeque};
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
const PERSISTED_ANCESTRY_LOG_INTERVAL_SECS: u64 = 5;
const KERNEL_SUM_PROGRESS_LOG_INTERVAL_SECS: u64 = 5;
const OUTPUT_POS_VALIDATION_PROGRESS_LOG_INTERVAL_SECS: u64 = 5;

const OUTPUT_SUBDIR: &str = "output";
const RANGE_PROOF_SUBDIR: &str = "rangeproof";
const KERNEL_SUBDIR: &str = "kernel";

/// Authenticate cached spent-output positions against the persisted block body
/// and the raw output/rangeproof PMMR data. The output and rangeproof roots do
/// not commit to prunable leaf membership, so callers must perform this check
/// before a cache is allowed to restore leaves during rewind or preserve them
/// during compaction. Returned entries use the exact spent-record positions and
/// are ordered to match the persisted block inputs.
fn validate_block_spent_positions<FO, FR, FS>(
	operation: &str,
	block: &Block,
	previous_header: &BlockHeader,
	positions: &[u64],
	output_mmr_size: u64,
	rproof_mmr_size: u64,
	mut output_at: FO,
	mut rangeproof_exists_at: FR,
	mut spent_record: FS,
) -> Result<Vec<SpentOutput>, Error>
where
	FO: FnMut(u64) -> Result<Option<OutputIdentifier>, Error>,
	FR: FnMut(u64) -> Result<bool, Error>,
	FS: FnMut(&Commitment) -> Result<SpentCommitmentRecord, Error>,
{
	let inputs = block.inputs();
	if positions.len() != inputs.len() {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} for block at height {} contains {} positions for {} inputs",
			operation,
			block.header.height,
			positions.len(),
			inputs.len()
		)));
	}

	let mut cached_outputs = HashMap::with_capacity(positions.len());
	let mut unique_positions = HashSet::with_capacity(positions.len());
	for pos1 in positions {
		let pos0 = pos1.checked_sub(1).ok_or_else(|| {
			Error::InvalidPersistedChainState(format!(
				"{} for block at height {} contains zero position",
				operation, block.header.height
			))
		})?;
		if !unique_positions.insert(*pos1) {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} for block at height {} contains duplicate position {}",
				operation, block.header.height, pos1
			)));
		}
		if !pmmr::is_leaf(pos0) {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} for block at height {} contains non-leaf PMMR position {}",
				operation, block.header.height, pos1
			)));
		}
		if *pos1 > previous_header.output_mmr_size {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} for block at height {} contains position {} beyond predecessor output MMR size {}",
				operation, block.header.height, pos1, previous_header.output_mmr_size
			)));
		}
		if pos0 >= output_mmr_size || pos0 >= rproof_mmr_size {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} for block at height {} contains position {} beyond current output/rangeproof PMMR sizes {}/{}",
				operation, block.header.height, pos1, output_mmr_size, rproof_mmr_size
			)));
		}

		let output = output_at(pos0)?.ok_or_else(|| {
			Error::InvalidPersistedChainState(format!(
				"{} for block at height {} points to missing output data at position {}",
				operation, block.header.height, pos1
			))
		})?;
		if !rangeproof_exists_at(pos0)? {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} for block at height {} points to missing rangeproof data at position {}",
				operation, block.header.height, pos1
			)));
		}
		let commitment = output.commitment();
		if let Some((other_pos, _)) = cached_outputs.insert(commitment, (*pos1, output)) {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} for block at height {} points to duplicate output commitment {:?} at positions {} and {}",
				operation, block.header.height, commitment, other_pos, pos1
			)));
		}
	}

	let mut validate_spent_record = |commitment: &Commitment,
	                                 pos1: u64|
	 -> Result<SpentOutput, Error> {
		let record = spent_record(commitment)?;
		if record.spending_block.height != block.header.height {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} for block at height {} has spent commitment record height {} for commitment {:?}",
				operation, block.header.height, record.spending_block.height, commitment
			)));
		}
		if record.spent_output.pos != pos1 {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} for block at height {} records input commitment {:?} at position {}, but the authenticated spent commitment record identifies position {} at height {}",
				operation,
				block.header.height,
				commitment,
				pos1,
				record.spent_output.pos,
				record.spent_output.height
			)));
		}
		if record.spent_output.height > previous_header.height {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} for block at height {} records input commitment {:?} from future output height {} above predecessor height {}",
				operation,
				block.header.height,
				commitment,
				record.spent_output.height,
				previous_header.height
			)));
		}
		// The complete exact-spend index is populated from validated UTXO
		// transitions and is authoritative for the output creation height. Preserve
		// that authenticated record instead of reconstructing its height by walking
		// header ancestry on every use.
		Ok(SpentOutput {
			commitment: *commitment,
			position: record.spent_output,
		})
	};

	let mut authenticated_spent = Vec::with_capacity(positions.len());
	match inputs {
		Inputs::CommitOnly(inputs) => {
			for input in inputs {
				let commitment = input.commitment();
				let (pos1, _) = cached_outputs.remove(&commitment).ok_or_else(|| {
					Error::InvalidPersistedChainState(format!(
						"{} for block at height {} has no output matching input commitment {:?}",
						operation, block.header.height, commitment
					))
				})?;
				authenticated_spent.push(validate_spent_record(&commitment, pos1)?);
			}
		}
		Inputs::FeaturesAndCommit(inputs) => {
			for input in inputs {
				let commitment = input.commitment();
				let (pos1, output) = cached_outputs.remove(&commitment).ok_or_else(|| {
					Error::InvalidPersistedChainState(format!(
						"{} for block at height {} has no output matching input {:?}",
						operation, block.header.height, input
					))
				})?;
				if output.features != input.features {
					return Err(Error::InvalidPersistedChainState(format!(
						"{} for block at height {} points to output features {:?} for input features {:?} with commitment {:?}",
						operation,
						block.header.height,
						output.features,
						input.features,
						input.commitment()
					)));
				}
				authenticated_spent.push(validate_spent_record(&commitment, pos1)?);
			}
		}
	}

	if !cached_outputs.is_empty() {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} for block at height {} contains unmatched output positions {:?}",
			operation,
			block.header.height,
			cached_outputs
				.iter()
				.map(|(_, (pos, _))| *pos)
				.collect::<Vec<_>>()
		)));
	}

	Ok(authenticated_spent)
}

fn checked_bitmap_positions_for_inputs(
	operation: &str,
	block: &Block,
	block_bitmap: &Bitmap,
) -> Result<Vec<u64>, Error> {
	let input_count = u64::try_from(block.inputs().len()).map_err(|_| {
		Error::DataOverflow(format!(
			"{} input count does not fit u64 for block at height {}",
			operation, block.header.height
		))
	})?;
	let position_count = block_bitmap.cardinality();
	if position_count != input_count {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} for block at height {} contains {} positions for {} inputs",
			operation, block.header.height, position_count, input_count
		)));
	}

	Ok(block_bitmap.iter().map(u64::from).collect())
}

fn require_spent_commitment_record_index(operation: &str, batch: &Batch<'_>) -> Result<(), Error> {
	if !batch.is_spent_commitment_record_index_complete()? {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} requires a complete exact spent commitment record index",
			operation
		)));
	}
	Ok(())
}

fn spent_commitment_record_for_block(
	operation: &str,
	commitment: &Commitment,
	spending_block: HashHeight,
	batch: &Batch<'_>,
) -> Result<SpentCommitmentRecord, Error> {
	let records = batch.get_spent_commitments(commitment)?.ok_or_else(|| {
		Error::InvalidPersistedChainState(format!(
			"{} has no spent commitment records for input {:?} in block {} at height {}",
			operation, commitment, spending_block.hash, spending_block.height
		))
	})?;
	let mut matching = records
		.into_iter()
		.filter(|record| record.spending_block.hash == spending_block.hash);
	let record = matching.next().ok_or_else(|| {
		Error::InvalidPersistedChainState(format!(
			"{} has no spent commitment record for input {:?} in block {} at height {}",
			operation, commitment, spending_block.hash, spending_block.height
		))
	})?;
	if matching.next().is_some() {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} has conflicting spent commitment records for input {:?} in block {} at height {}",
			operation, commitment, spending_block.hash, spending_block.height
		)));
	}
	if record.spending_block != spending_block {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} spent commitment record for input {:?} identifies block {} at height {}, expected {} at height {}",
			operation,
			commitment,
			record.spending_block.hash,
			record.spending_block.height,
			spending_block.hash,
			spending_block.height
		)));
	}
	Ok(record)
}

#[derive(Clone, Copy)]
struct KernelHeaderBoundary {
	height: u64,
	version: mwc_core::core::HeaderVersion,
	kernel_mmr_size: u64,
}

impl From<&BlockHeader> for KernelHeaderBoundary {
	fn from(header: &BlockHeader) -> Self {
		Self {
			height: header.height,
			version: header.version,
			kernel_mmr_size: header.kernel_mmr_size,
		}
	}
}

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

	/// Authenticate a loaded header against both projections retained by the
	/// header PMMR at `height`.
	///
	/// `HeaderEntry` and the indexed PMMR leaf hash are stored in separate files.
	/// Checking both prevents a stale or corrupted data entry from redirecting a
	/// height lookup to another header that happens to exist in the block-header
	/// database.
	///
	/// This authenticates the two PMMR projections; it deliberately does not
	/// reverify the complete header's PoW. Callers used by API reads rely on PoW
	/// validation at admission plus persisted-ancestry validation at
	/// startup/recovery. Adding Cuckoo verification here would turn inexpensive,
	/// attacker-selectable lookups into a CPU-amplification DoS primitive.
	pub(crate) fn authenticate_header_at_height(
		&self,
		height: u64,
		header: &BlockHeader,
	) -> Result<(), Error> {
		if header.height != height {
			return Err(Error::InvalidPersistedChainState(format!(
				"header PMMR lookup for height {} loaded header at height {}",
				height, header.height
			)));
		}

		let pos0 = pmmr::insertion_to_pmmr_index(height)?;
		if pos0 >= self.size {
			return Err(Error::InvalidPersistedChainState(format!(
				"header PMMR is missing leaf position {} for height {}",
				pos0, height
			)));
		}

		let header_pmmr = ReadonlyPMMR::at(&self.backend, self.size);
		let stored_entry = header_pmmr.get_data(pos0)?.ok_or_else(|| {
			Error::InvalidPersistedChainState(format!(
				"header PMMR is missing data at leaf position {} for height {}",
				pos0, height
			))
		})?;
		let expected_entry = header.as_elmt()?;
		if stored_entry != expected_entry {
			return Err(Error::InvalidPersistedChainState(format!(
				"header PMMR data at leaf position {} does not match loaded header at height {}",
				pos0, height
			)));
		}

		let stored_leaf_hash = header_pmmr.get_hash(pos0)?.ok_or_else(|| {
			Error::InvalidPersistedChainState(format!(
				"header PMMR is missing hash at leaf position {} for height {}",
				pos0, height
			))
		})?;
		let context_id = self.backend.get_context_id();
		let expected_leaf_hash = header.hash_with_index(context_id, pos0)?;
		if stored_leaf_hash != expected_leaf_hash {
			return Err(Error::InvalidPersistedChainState(format!(
				"header PMMR hash at leaf position {} does not authenticate loaded header at height {}",
				pos0, height
			)));
		}

		Ok(())
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
			// Open the kernel PMMR with Fast validation for performance reasons.
			// Kernels are not prunable, so the data volume is high and keeps
			// growing. Full validation would deserialize the entire data file on
			// every node start, which takes too much time and is not worth it;
			// the Fast structural check (size file covers the data file) is
			// sufficient here because these locally maintained, append-only
			// files are never compacted.
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
				match kernel.verify(context_id, secp) {
					Ok(()) => {
						debug!(
							"attempting to open kernel PMMR using {:?} - SUCCESS",
							version
						);
						maybe_kernel_handle = Some(handle);
						break;
					}
					Err(err) => {
						debug!(
							"attempting to open kernel PMMR using {:?} - FAIL (kernel verification failed: {})",
							version, err
						);
						kernel_probe_errors
							.push(format!("{}: kernel verification failed: {}", version, err));
					}
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
		let pos = self
			.commit_index
			.get_output_pos_height(&commit)
			.map_err(|e| Error::StoreErr(e, "txhashset unspent check".to_string()))?;
		self.get_unspent_with_position(commit, pos)
	}

	/// Check an output-position entry supplied by a caller that owns the
	/// corresponding database snapshot.
	pub(crate) fn get_unspent_with_position(
		&self,
		commit: Commitment,
		pos: Option<CommitPos>,
	) -> Result<Option<(OutputIdentifier, CommitPos)>, Error> {
		let Some(pos1) = pos else {
			return Ok(None);
		};
		let output_pmmr: ReadonlyPMMR<'_, OutputIdentifier, _> =
			ReadonlyPMMR::at(&self.output_pmmr_h.backend, self.output_pmmr_h.size);
		let pos0 = pos1.pos.checked_sub(1).ok_or_else(|| {
			mwc_store::Error::DataOverflow(format!("TxHashSet::get_unspent pos1.pos={}", pos1.pos))
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

	/// Validate that every body PMMR can reach the durable recovery target.
	///
	/// Each backend performs its own prune-aware check because compacted file
	/// lengths cannot be compared directly with the logical sizes in a header.
	/// The first missing component is enough to make reconciliation impossible;
	/// no PMMR has been mutated when this method returns an error.
	pub(crate) fn validate_recovery_rewind_targets(
		&self,
		head: &Tip,
		header: &BlockHeader,
	) -> Result<(), Error> {
		self.validate_recovery_rewind_targets_for("durable HEAD", head, header)
	}

	/// Validate every body PMMR against a named durable selector.
	///
	/// Compaction recovery uses this for BODY_TAIL in addition to the normal
	/// HEAD reconciliation preflight above.
	pub(crate) fn validate_recovery_rewind_targets_for(
		&self,
		selector: &str,
		tip: &Tip,
		header: &BlockHeader,
	) -> Result<(), Error> {
		for (component, position, result) in [
			(
				"output",
				header.output_mmr_size,
				self.output_pmmr_h
					.backend
					.validate_rewind_target(header.output_mmr_size),
			),
			(
				"rangeproof",
				header.output_mmr_size,
				self.rproof_pmmr_h
					.backend
					.validate_rewind_target(header.output_mmr_size),
			),
			(
				"kernel",
				header.kernel_mmr_size,
				self.kernel_pmmr_h
					.backend
					.validate_rewind_target(header.kernel_mmr_size),
			),
		] {
			match result {
				Ok(()) => {}
				Err(pmmr::Error::InvalidState(reason)) => {
					return Err(Error::PmmrRecoveryRequired(format!(
						"{} {} at height {} requires {} PMMR position {}, but the current backend cannot represent that rewind target: {}",
						selector, tip.last_block_h, tip.height, component, position, reason
					)));
				}
				Err(err) => return Err(err.into()),
			}
		}
		Ok(())
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

	/// Build a Merkle proof for an unspent output against the current output
	/// PMMR state.
	///
	/// This deliberately uses `self.output_pmmr_h.size`. Do not overlay an older
	/// header size here: compaction guarantees the current peaks and maximal
	/// pruned-subtree roots, but it does not preserve every node that happened to
	/// be a peak at an earlier size. The returned `mmr_size` tells callers which
	/// output-root state must be used for verification.
	pub fn merkle_proof(&self, commit: Commitment) -> Result<MerkleProof, Error> {
		let pos0 = self.commit_index.get_output_pos(&commit)?;
		let output_pmmr = ReadonlyPMMR::at(&self.output_pmmr_h.backend, self.output_pmmr_h.size);
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

		let rewind_rm_pos = input_pos_to_rewind(self, &horizon_header, &head_header, batch)?;

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

	/// Authenticate one block's cached spent positions before compaction relies on
	/// them to preserve rewind data. A well-formed but incomplete cache would
	/// otherwise make check_compact permanently remove an output and rangeproof
	/// that a supported rewind needs to restore.
	fn validate_compact_block_input_bitmap(
		&self,
		block: &Block,
		previous_header: &BlockHeader,
		block_bitmap: &Bitmap,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		require_spent_commitment_record_index("compact input bitmap", batch)?;
		let spending_block = HashHeight {
			hash: block.hash(batch.get_context_id())?,
			height: block.header.height,
		};
		let positions =
			checked_bitmap_positions_for_inputs("compact input bitmap", block, block_bitmap)?;
		validate_block_spent_positions(
			"compact input bitmap",
			block,
			previous_header,
			&positions,
			self.output_pmmr_h.size,
			self.rproof_pmmr_h.size,
			|pos0| Ok(self.output_pmmr_h.backend.get_data_from_file(pos0)?),
			|pos0| {
				Ok(self
					.rproof_pmmr_h
					.backend
					.get_data_from_file(pos0)?
					.is_some())
			},
			|commitment| {
				spent_commitment_record_for_block(
					"compact input bitmap",
					commitment,
					spending_block,
					batch,
				)
			},
		)?;
		Ok(())
	}

	/// Commitment of the output leaf data retained at the 1-based MMR position
	/// `pos1`, read directly from the data file regardless of prune state.
	/// Returns None when no data is retained at the position.
	pub fn output_commitment_at_pos(&self, pos1: u64) -> Result<Option<Commitment>, Error> {
		let pos0 = pos1
			.checked_sub(1)
			.ok_or_else(|| Error::Other("output commitment lookup at zero MMR position".into()))?;
		let data = self.output_pmmr_h.backend.get_data_from_file(pos0)?;
		Ok(data.map(|output| output.commitment()))
	}

	/// (Re)build the NRD kernel_pos index based on 2 weeks of recent kernel history.
	pub fn init_recent_kernel_pos_index(
		&self,
		batch: &Batch<'_>,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		if !global::is_nrd_enabled(self.commit_index.get_context_id()) {
			return Ok(());
		}
		let now = Instant::now();
		let head = batch.head()?;
		let context_id = self.commit_index.get_context_id();
		let head_header = batch.get_block_header(&head.last_block_h)?;
		let head_header_hash = head_header.hash(context_id)?;
		if head_header.height != head.height || head_header_hash != head.last_block_h {
			return Err(Error::TxHashSetErr(format!(
				"init_recent_kernel_pos_index body HEAD {} at {} does not match stored header {} at {}",
				head.last_block_h, head.height, head_header_hash, head_header.height
			)));
		}
		if head_header.kernel_mmr_size != self.kernel_pmmr_h.size {
			return Err(Error::TxHashSetErr(format!(
				"init_recent_kernel_pos_index body HEAD kernel MMR size {} does not match txhashset size {}",
				head_header.kernel_mmr_size, self.kernel_pmmr_h.size
			)));
		}

		// Body rewinds are bounded to one cut-through horizon from the current
		// head. On production networks that horizon is WEEK_HEIGHT, so retaining
		// two weeks covers both the deepest supported rewind and the maximum NRD
		// relative height.
		// Safe: WEEK_HEIGHT is a small fixed consensus constant.
		let cutoff = head.height.saturating_sub(WEEK_HEIGHT * 2);
		let ancestry_links = head.height.saturating_sub(cutoff);
		let ancestry_boundaries = ancestry_links.saturating_add(1);
		info!(
			"init_recent_kernel_pos_index: starting recent NRD kernel_pos index rebuild from height {} to {}; collecting {} body header boundaries",
			cutoff, head.height, ancestry_boundaries
		);

		// HEAD and the kernel PMMR describe the validated body chain. The header
		// PMMR may legally be ahead on a different fork, so recover every kernel
		// boundary from HEAD's prev_hash ancestry instead of looking it up by
		// height in the header PMMR.
		let mut current_header = head_header.clone();
		let mut boundaries = Vec::new();
		let mut visited = HashSet::new();
		let ancestry_started = Instant::now();
		let mut last_ancestry_log = Instant::now();
		while current_header.height > cutoff {
			Self::check_stop_state(&stop_state)?;
			boundaries.push(KernelHeaderBoundary::from(&current_header));

			let prev_header = crate::checked_previous_header(
				context_id,
				&current_header,
				&mut visited,
				"init_recent_kernel_pos_index ancestry",
				|hash| batch.get_block_header(hash),
			)?;
			if prev_header.kernel_mmr_size > current_header.kernel_mmr_size {
				return Err(Error::TxHashSetErr(format!(
					"init_recent_kernel_pos_index kernel MMR size regression from {} at {} to {} at {}",
					prev_header.kernel_mmr_size,
					prev_header.height,
					current_header.kernel_mmr_size,
					current_header.height
				)));
			}
			current_header = prev_header;
			if last_ancestry_log.elapsed().as_secs() >= PERSISTED_ANCESTRY_LOG_INTERVAL_SECS {
				let traversed = head.height.saturating_sub(current_header.height);
				info!(
					"init_recent_kernel_pos_index: body ancestry progress {}/{} ({}%), reached height {}",
					traversed,
					ancestry_links,
					traversed.saturating_mul(100) / ancestry_links.max(1),
					current_header.height
				);
				last_ancestry_log = Instant::now();
			}
		}
		if current_header.height != cutoff {
			return Err(Error::TxHashSetErr(format!(
				"init_recent_kernel_pos_index body ancestry stopped at {}, expected cutoff {}",
				current_header.height, cutoff
			)));
		}
		let cutoff_header = current_header;
		boundaries.push(KernelHeaderBoundary::from(&cutoff_header));
		boundaries.reverse();

		let prev_size = if cutoff_header.height == 0 {
			0
		} else {
			let prev_header = crate::checked_previous_header(
				context_id,
				&cutoff_header,
				&mut visited,
				"init_recent_kernel_pos_index cutoff ancestry",
				|hash| batch.get_block_header(hash),
			)?;
			if prev_header.kernel_mmr_size > cutoff_header.kernel_mmr_size {
				return Err(Error::TxHashSetErr(format!(
					"init_recent_kernel_pos_index kernel MMR size regression from {} at {} to {} at {}",
					prev_header.kernel_mmr_size,
					prev_header.height,
					cutoff_header.kernel_mmr_size,
					cutoff_header.height
				)));
			}
			prev_header.kernel_mmr_size
		};

		info!(
			"init_recent_kernel_pos_index: collected {} body header boundaries in {}s; starting recent kernel scan",
			boundaries.len(),
			ancestry_started.elapsed().as_secs()
		);
		self.verify_kernel_pos_index_with_status(
			&cutoff_header,
			&head_header,
			prev_size,
			batch,
			status,
			stop_state,
			true,
			|height| {
				let offset = height.checked_sub(cutoff).ok_or_else(|| {
					Error::DataOverflow(format!(
						"TxHashSet::init_recent_kernel_pos_index, height={}, cutoff={}",
						height, cutoff
					))
				})?;
				let idx = usize::try_from(offset).map_err(|_| {
					Error::DataOverflow(format!(
						"TxHashSet::init_recent_kernel_pos_index, boundary offset={}",
						offset
					))
				})?;
				boundaries.get(idx).copied().ok_or_else(|| {
					Error::TxHashSetErr(format!(
						"init_recent_kernel_pos_index missing body boundary at height {}",
						height
					))
				})
			},
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
		let context_id = self.commit_index.get_context_id();
		let mut current = store.head_header()?;
		if current.kernel_mmr_size != self.kernel_pmmr_h.size {
			return Err(Error::TxHashSetErr(format!(
				"init_kernel_pos_index_chunked body HEAD kernel MMR size {} does not match txhashset size {}",
				current.kernel_mmr_size, self.kernel_pmmr_h.size
			)));
		}
		let total_kernels = pmmr::n_leaves(self.kernel_pmmr_h.size)?;
		let status_throttle = SyncStatusUpdateThrottle::new();
		let mut last_progress_log = Instant::now();
		let cleared = Self::clear_kernel_pos_index_chunked(store, &stop_state)?;

		let kernel_pmmr = ReadonlyPMMR::at(&self.kernel_pmmr_h.backend, self.kernel_pmmr_h.size);
		let mut batch = store.batch_write()?;
		let mut pending = 0usize;
		let mut total = 0u64;
		let mut visited = HashSet::new();

		info!(
			"init_kernel_pos_index_chunked: starting full kernel_pos index rebuild, cleared {} entries, kernel_mmr_size {}, kernels {}, chunk size {}",
			cleared, self.kernel_pmmr_h.size, total_kernels, KERNEL_POS_INDEX_REBUILD_CHUNK_SIZE,
		);
		Self::update_kernel_pos_index_build_status(
			&status,
			&status_throttle,
			0,
			total_kernels,
			true,
		);

		loop {
			Self::check_stop_state(&stop_state)?;
			let prev_header = if current.height == 0 {
				None
			} else {
				Some(crate::checked_previous_header(
					context_id,
					&current,
					&mut visited,
					"init_kernel_pos_index_chunked",
					|hash| store.get_block_header(hash),
				)?)
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
			let current_hash = current.hash(context_id)?;
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
						pos, current_hash, current.height
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
				total = total.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"TxHashSet::init_kernel_pos_index_chunked, total={}",
						total
					))
				})?;

				if pending >= KERNEL_POS_INDEX_REBUILD_CHUNK_SIZE {
					batch.commit()?;
					Self::check_stop_state(&stop_state)?;
					batch = store.batch_write()?;
					pending = 0;
					Self::update_kernel_pos_index_build_status(
						&status,
						&status_throttle,
						total,
						total_kernels,
						total == total_kernels,
					);
					if Self::should_log_index_rebuild_progress(&mut last_progress_log, false) {
						info!(
							"init_kernel_pos_index_chunked: rebuilt {} of {} kernel_pos entries",
							total, total_kernels
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

		if total != total_kernels {
			return Err(Error::TxHashSetErr(format!(
				"init_kernel_pos_index_chunked rebuilt {} kernel_pos entries, expected {}",
				total, total_kernels
			)));
		}
		batch.set_kernel_pos_index_complete(true)?;
		batch.commit()?;

		Self::update_kernel_pos_index_build_status(
			&status,
			&status_throttle,
			total,
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

	/// Verify contextual kernel inclusion rules and (re)build the NRD kernel_pos
	/// index over the provided header range. The terminal header anchors the
	/// header PMMR ancestry and the kernel PMMR state before any index mutation.
	pub fn verify_kernel_pos_index(
		&self,
		from_header: &BlockHeader,
		to_header: &BlockHeader,
		header_pmmr: &PMMRHandle<BlockHeader>,
		batch: &Batch<'_>,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		let context_id = self.commit_index.get_context_id();
		let load_pmmr_header = |height: u64| -> Result<(Hash, BlockHeader), Error> {
			let pmmr_hash = header_pmmr.get_header_hash_by_height(height)?;
			let header = batch.get_block_header(&pmmr_hash)?;
			let header_hash = header.hash(context_id)?;
			if header.height != height || header_hash != pmmr_hash {
				return Err(Error::TxHashSetErr(format!(
					"verify_kernel_pos_index header PMMR entry {} resolves to persisted header {} at {}",
					height, header_hash, header.height
				)));
			}
			Ok((pmmr_hash, header))
		};

		// Normal PoW validation binds the complete header to its proof-derived hash.
		// This maintenance path does not repeat PoW, so resolve each endpoint
		// through the header PMMR and require full persisted-header equality before
		// trusting contextual fields.
		let (pmmr_from_hash, persisted_from) = load_pmmr_header(from_header.height)?;
		if persisted_from != *from_header {
			return Err(Error::TxHashSetErr(format!(
				"verify_kernel_pos_index start header {} at {} does not match persisted header selected by the header PMMR",
				pmmr_from_hash, from_header.height
			)));
		}

		let (pmmr_to_hash, persisted_to) = load_pmmr_header(to_header.height)?;
		if persisted_to != *to_header {
			return Err(Error::TxHashSetErr(format!(
				"verify_kernel_pos_index terminal header {} at {} does not match persisted header selected by the header PMMR",
				pmmr_to_hash, to_header.height
			)));
		}

		if persisted_from.height > persisted_to.height {
			return Err(Error::TxHashSetErr(format!(
				"verify_kernel_pos_index invalid header range {}..{}",
				persisted_from.height, persisted_to.height
			)));
		}

		let prev_size = if persisted_from.height == 0 {
			0
		} else {
			let prev_height = persisted_from.height.checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"TxHashSet::verify_kernel_pos_index, from_height={}",
					persisted_from.height
				))
			})?;
			let (pmmr_prev_hash, prev_header) = load_pmmr_header(prev_height)?;
			if persisted_from.prev_hash != pmmr_prev_hash {
				return Err(Error::TxHashSetErr(format!(
					"verify_kernel_pos_index start header {} at {} has predecessor {}, but header PMMR ancestry has {} at {}",
					pmmr_from_hash,
					persisted_from.height,
					persisted_from.prev_hash,
					pmmr_prev_hash,
					prev_height
				)));
			}
			prev_header.kernel_mmr_size
		};

		// The PMMR fixes a header hash at each height, but it does not by itself
		// prove that the persisted headers selected by adjacent leaves link to one
		// another. Validate the complete range before
		// verify_kernel_pos_index_with_status clears or updates the NRD index. This
		// intentionally runs even across kernel-free spans that the boundary
		// callback below would never visit.
		let mut ancestry_hash = pmmr_from_hash;
		let mut ancestry_header = persisted_from.clone();
		while ancestry_header.height < persisted_to.height {
			Self::check_stop_state(&stop_state)?;
			let next_height = ancestry_header.height.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"TxHashSet::verify_kernel_pos_index, ancestry_height={}",
					ancestry_header.height
				))
			})?;
			let (next_hash, next_header) = load_pmmr_header(next_height)?;
			if next_header.prev_hash != ancestry_hash {
				return Err(Error::TxHashSetErr(format!(
					"verify_kernel_pos_index disconnected header PMMR ancestry: header {} at {} has predecessor {}, expected {} at {}",
					next_hash,
					next_header.height,
					next_header.prev_hash,
					ancestry_hash,
					ancestry_header.height
				)));
			}
			if next_header.kernel_mmr_size < ancestry_header.kernel_mmr_size
				|| next_header.kernel_mmr_size > persisted_to.kernel_mmr_size
			{
				return Err(Error::TxHashSetErr(format!(
					"verify_kernel_pos_index invalid kernel MMR boundary {} at {} after {} at {}",
					next_header.kernel_mmr_size,
					next_header.height,
					ancestry_header.kernel_mmr_size,
					ancestry_header.height
				)));
			}
			ancestry_hash = next_hash;
			ancestry_header = next_header;
		}
		if ancestry_hash != pmmr_to_hash || ancestry_header != persisted_to {
			return Err(Error::TxHashSetErr(format!(
				"verify_kernel_pos_index header PMMR ancestry terminated at {} at {}, expected {} at {}",
				ancestry_hash, ancestry_header.height, pmmr_to_hash, persisted_to.height
			)));
		}

		self.verify_kernel_pos_index_with_status(
			&persisted_from,
			&persisted_to,
			prev_size,
			batch,
			status,
			stop_state,
			false,
			|height| {
				let (_, header) = load_pmmr_header(height)?;
				Ok(KernelHeaderBoundary::from(&header))
			},
		)
	}

	fn verify_kernel_pos_index_with_status<F>(
		&self,
		from_header: &BlockHeader,
		to_header: &BlockHeader,
		prev_size: u64,
		batch: &Batch<'_>,
		status: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
		build_status: bool,
		mut boundary_at_height: F,
	) -> Result<(), Error>
	where
		F: FnMut(u64) -> Result<KernelHeaderBoundary, Error>,
	{
		let context_id = self.commit_index.get_context_id();

		let now = Instant::now();
		let from_boundary = KernelHeaderBoundary::from(from_header);
		let to_boundary = KernelHeaderBoundary::from(to_header);
		if from_boundary.height > to_boundary.height {
			return Err(Error::TxHashSetErr(format!(
				"verify_kernel_pos_index invalid boundary range {}..{}",
				from_boundary.height, to_boundary.height
			)));
		}
		if to_boundary.kernel_mmr_size != self.kernel_pmmr_h.size {
			return Err(Error::TxHashSetErr(format!(
				"verify_kernel_pos_index terminal header kernel MMR size {} does not match txhashset size {}",
				to_boundary.kernel_mmr_size, self.kernel_pmmr_h.size
			)));
		}
		if prev_size > from_boundary.kernel_mmr_size
			|| from_boundary.kernel_mmr_size > to_boundary.kernel_mmr_size
		{
			return Err(Error::TxHashSetErr(format!(
				"verify_kernel_pos_index invalid kernel MMR boundaries: previous {}, start {}, terminal {}",
				prev_size, from_boundary.kernel_mmr_size, to_boundary.kernel_mmr_size
			)));
		}

		let total = pmmr::n_leaves(self.kernel_pmmr_h.size)?
			.checked_sub(pmmr::n_leaves(prev_size)?)
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"TxHashSet::verify_kernel_pos_index, prev_size={}, kernel_pmmr_size={}",
					prev_size, self.kernel_pmmr_h.size
				))
			})?;

		// Do not clear the authoritative recent index until the header source and
		// terminal kernel PMMR state have passed all preflight consistency checks.
		let kernel_index = store::nrd_recent_kernel_index();
		kernel_index.clear(batch)?;

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
		let mut current_header = from_boundary;
		let mut count = 0u64;
		let mut applied = 0u64;
		let status_throttle = SyncStatusUpdateThrottle::new();
		let mut last_progress_log = Instant::now();
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
					// Kernel MMR sizes are authenticated boundaries for each block.
					// Use the caller's already-anchored ancestry to recover the block
					// that first included this kernel.
					while current_pos > current_header.kernel_mmr_size {
						let next_height =
							current_header.height.checked_add(1).ok_or_else(|| {
								Error::DataOverflow(format!(
									"TxHashSet::verify_kernel_pos_index, current_header_height={}",
									current_header.height
								))
							})?;
						if next_height > to_boundary.height {
							return Err(Error::TxHashSetErr(format!(
								"verify_kernel_pos_index kernel position {} exceeds terminal boundary {} at {}",
								current_pos, to_boundary.kernel_mmr_size, to_boundary.height
							)));
						}
						let next_header = boundary_at_height(next_height)?;
						if next_header.height != next_height {
							return Err(Error::TxHashSetErr(format!(
								"verify_kernel_pos_index expected boundary at {}, got {}",
								next_height, next_header.height
							)));
						}
						if next_header.kernel_mmr_size < current_header.kernel_mmr_size
							|| next_header.kernel_mmr_size > to_boundary.kernel_mmr_size
						{
							return Err(Error::TxHashSetErr(format!(
								"verify_kernel_pos_index invalid kernel MMR boundary {} at {} after {} at {}",
								next_header.kernel_mmr_size,
								next_header.height,
								current_header.kernel_mmr_size,
								current_header.height
							)));
						}
						current_header = next_header;
					}

					verify_kernel_lock_height(&kernel, current_header.height)?;
					verify_nrd_kernel_for_header_version(
						&kernel,
						current_header.version,
						context_id,
					)?;

					match kernel.features {
						KernelFeatures::NoRecentDuplicate { .. } => {
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
				if Self::should_log_index_rebuild_progress(&mut last_progress_log, false) {
					info!(
						"verify_kernel_pos_index: {} progress {}/{} kernels ({}%)",
						if build_status {
							"rebuild"
						} else {
							"validation"
						},
						applied,
						total,
						applied.saturating_mul(100) / total.max(1)
					);
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
		let context_id = batch.get_context_id();
		let mut visited = HashSet::new();
		loop {
			let prev_header = if current.height == 0 {
				None
			} else {
				Some(crate::checked_previous_header(
					context_id,
					&current,
					&mut visited,
					"init_output_pos_index",
					|hash| batch.get_block_header(hash),
				)?)
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
/// of work is abandoned. Otherwise, PMMR changes are synced and index changes
/// are merged into the caller's batch. The caller must still commit that outer
/// batch; PMMR files and the database are separate durability domains.
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
					let sync_err = Error::PmmrSyncStateUncertain {
						context: "extending output sync".to_owned(),
						source: e,
					};
					return result_with_discard(
						Err(sync_err),
						discard_txhashset_backends(trees),
						"extending output sync",
					);
				}
				if let Err(e) = trees.rproof_pmmr_h.backend.sync() {
					let sync_err = Error::PmmrSyncStateUncertain {
						context: "extending rangeproof sync".to_owned(),
						source: e,
					};
					return result_with_discard(
						Err(sync_err),
						discard_txhashset_backends(trees),
						"extending rangeproof sync",
					);
				}
				if let Err(e) = trees.kernel_pmmr_h.backend.sync() {
					let sync_err = Error::PmmrSyncStateUncertain {
						context: "extending kernel sync".to_owned(),
						source: e,
					};
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
	header_extending_with_head(handle, batch, None, inner)
}

/// Start a header MMR unit of work with an explicit logical head.
///
/// Normal header extensions derive their head from the PMMR's final leaf and
/// require the corresponding BlockHeader to be visible in the enclosing DB
/// batch. Recovery cannot make that assumption: the PMMR files are synced
/// before the enclosing batch commits, so an interrupted operation can leave a
/// valid speculative PMMR suffix whose header records were rolled back. Passing
/// the durable DB-selected head lets recovery enter the extension and rewind
/// that suffix without first resolving its speculative final leaf through the
/// DB.
pub(crate) fn header_extending_with_explicit_head<'a, F, T>(
	handle: &'a mut PMMRHandle<BlockHeader>,
	batch: &'a mut Batch<'_>,
	head: Tip,
	inner: F,
) -> Result<T, Error>
where
	F: FnOnce(&mut HeaderExtension<'_>, &Batch<'_>) -> Result<T, Error>,
{
	header_extending_with_head(handle, batch, Some(head), inner)
}

fn header_extending_with_head<'a, F, T>(
	handle: &'a mut PMMRHandle<BlockHeader>,
	batch: &'a mut Batch<'_>,
	explicit_head: Option<Tip>,
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

	let head = match explicit_head {
		Some(head) => head,
		None => match handle.head_hash() {
			Ok(hash) => {
				let header = child_batch.get_block_header(&hash)?;
				Tip::try_from_header(&header)?
			}
			Err(Error::EmptyMMR) => Tip::default(),
			Err(err) => return Err(err),
		},
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
					let sync_err = Error::PmmrSyncStateUncertain {
						context: "header_extending sync".to_owned(),
						source: e,
					};
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

	/// Compare a complete header with the persisted header on the current chain.
	///
	/// This persisted-state membership check uses full equality because it does
	/// not repeat the PoW validation that originally bound the complete header to
	/// its proof-derived hash.
	pub fn is_header_on_current_chain(
		&self,
		header: &BlockHeader,
		batch: &Batch<'_>,
	) -> Result<bool, Error> {
		if header.height > self.head.height {
			return Ok(false);
		}
		Ok(self.get_header_by_height(header.height, batch)? == *header)
	}

	/// Compare an authoritative persisted header directly with the PMMR entry at
	/// the same height, without resolving the PMMR entry's block hash through the
	/// database.
	///
	/// Recovery uses this while the PMMR may contain a valid speculative suffix
	/// whose enclosing DB transaction was rolled back. A different embedded block
	/// hash denotes a fork and is safe to rewind. Once the embedded hash matches,
	/// however, both the cached HeaderEntry metadata and the indexed PMMR leaf hash
	/// must authenticate the complete authoritative header; a mismatch then is
	/// corruption rather than an alternate fork. This method only compares the
	/// PMMR projection; its recovery caller must authenticate the complete header
	/// first because neither stored value commits to every BlockHeader field.
	pub(crate) fn is_persisted_header_on_current_chain(
		&self,
		header: &BlockHeader,
	) -> Result<bool, Error> {
		let pos0 = pmmr::insertion_to_pmmr_index(header.height)?;
		if pos0 >= self.size() {
			return Ok(false);
		}

		let stored_entry = self.pmmr.get_data_from_file(pos0)?.ok_or_else(|| {
			Error::InvalidPersistedChainState(format!(
				"header PMMR is missing data at leaf position {} for height {}",
				pos0, header.height
			))
		})?;
		let expected_entry = header.as_elmt()?;
		if stored_entry.hash != expected_entry.hash {
			return Ok(false);
		}
		if stored_entry != expected_entry {
			return Err(Error::InvalidPersistedChainState(format!(
				"header PMMR data at leaf position {} does not match authoritative header at height {}",
				pos0, header.height
			)));
		}

		let stored_hash = self.pmmr.get_from_file(pos0)?.ok_or_else(|| {
			Error::InvalidPersistedChainState(format!(
				"header PMMR is missing hash at leaf position {} for height {}",
				pos0, header.height
			))
		})?;
		let context_id = self.pmmr.get_context_id();
		let expected_hash = header.hash_with_index(context_id, pos0)?;
		if stored_hash != expected_hash {
			return Err(Error::InvalidPersistedChainState(format!(
				"header PMMR hash at leaf position {} does not authenticate authoritative header at height {}",
				pos0, header.height
			)));
		}

		Ok(true)
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
		let header_hash = header.hash(context_id)?;
		let current_head_hash = self.head.hash(context_id)?;
		let new_head = Tip::try_from_header(header)?;
		debug!(
			"Rewind header extension to {} at {} from {} at {}",
			header_hash, header.height, current_head_hash, self.head.height,
		);

		let next_height = header.height.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"HeaderExtension::rewind, header_height={}",
				header.height
			))
		})?;
		let header_pos = pmmr::insertion_to_pmmr_index(next_height)?;
		self.pmmr.rewind(header_pos, &Bitmap::new()).map_err(|e| {
			Error::TxHashSetErr(format!("pmmr rewind for pos {}, {}", header_pos, e))
		})?;

		// Update our head to reflect the header we rewound to.
		self.head = new_head;

		Ok(())
	}

	/// Verify that the retained header PMMR is an exact projection of the
	/// authoritative header ancestry stored in the database.
	///
	/// HeaderEntry intentionally stores only a proof-derived block hash plus a
	/// small metadata cache. It cannot independently reproduce the PMMR leaf hash,
	/// so generic PMMR validation is insufficient for this backend. Validate each
	/// complete persisted non-genesis header, including its PoW, before
	/// authenticating its database key, ancestry, and PMMR projection. Genesis is
	/// validated separately before storage is opened by `Chain::init`.
	pub(crate) fn validate_persisted_ancestry(
		&self,
		header: &BlockHeader,
		batch: &Batch<'_>,
		pow_verifier: fn(u32, &BlockHeader) -> Result<(), mwc_core::pow::Error>,
		stop_state: Option<&StopState>,
	) -> Result<(), Error> {
		let started = Instant::now();
		info!(
			"validate_persisted_ancestry: started, target height {}, PMMR size {}",
			header.height,
			self.size()
		);
		let result = self.validate_persisted_ancestry_inner(
			header,
			batch,
			pow_verifier,
			stop_state,
			&started,
		);
		match &result {
			Ok(()) => info!(
				"validate_persisted_ancestry: finished successfully in {}s",
				started.elapsed().as_secs()
			),
			Err(err) => error!(
				"validate_persisted_ancestry: stopped with error after {}s: {:?}",
				started.elapsed().as_secs(),
				err
			),
		}
		result
	}

	fn validate_persisted_ancestry_inner(
		&self,
		header: &BlockHeader,
		batch: &Batch<'_>,
		pow_verifier: fn(u32, &BlockHeader) -> Result<(), mwc_core::pow::Error>,
		stop_state: Option<&StopState>,
		started: &Instant,
	) -> Result<(), Error> {
		if stop_state.map(StopState::is_stopped).unwrap_or(false) {
			return Err(Error::Stopped);
		}
		let context_id = self.pmmr.get_context_id();
		let expected_head = Tip::try_from_header(header)?;
		if self.head != expected_head {
			return Err(Error::InvalidPersistedChainState(format!(
				"header PMMR head {:?} does not match authoritative target {:?}",
				self.head, expected_head
			)));
		}

		let next_height = header.height.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"HeaderExtension::validate_persisted_ancestry, height={}",
				header.height
			))
		})?;
		let expected_size = pmmr::insertion_to_pmmr_index(next_height)?;
		if self.size() != expected_size {
			return Err(Error::InvalidPersistedChainState(format!(
				"header PMMR size {} does not match target height {} expected size {}",
				self.size(),
				header.height,
				expected_size
			)));
		}

		let leaf_capacity = usize::try_from(next_height).map_err(|_| {
			Error::DataOverflow(format!(
				"HeaderExtension::validate_persisted_ancestry leaf count, height={}",
				header.height
			))
		})?;
		let mut persisted_leaf_hashes = Vec::with_capacity(leaf_capacity);
		let mut current = header.clone();
		let mut expected_current_hash = expected_head.last_block_h;
		let mut last_progress_log = Instant::now();
		loop {
			if stop_state.map(StopState::is_stopped).unwrap_or(false) {
				return Err(Error::Stopped);
			}
			crate::pipe::validate_header_context_id(context_id, &current).map_err(|e| {
				Error::InvalidPersistedChainState(format!(
					"persisted header at height {} failed context validation: {}",
					current.height, e
				))
			})?;
			if current.height != 0
				&& !current.pow.is_primary(context_id)
				&& !current.pow.is_secondary()
			{
				return Err(Error::InvalidPersistedChainState(format!(
					"persisted header at height {} has invalid proof edge bits",
					current.height
				)));
			}
			// Chain::init validates genesis separately. In particular, the exact
			// hardcoded Mainnet and Floonet genesis identities retain a documented
			// compatibility exception for their historical proofs.
			if current.height != 0 {
				pow_verifier(context_id, &current).map_err(|e| {
					Error::InvalidPersistedChainState(format!(
						"persisted header at height {} failed PoW validation: {}",
						current.height, e
					))
				})?;
			}

			let pos0 = pmmr::insertion_to_pmmr_index(current.height)?;
			let stored_entry = self.pmmr.get_data_from_file(pos0)?.ok_or_else(|| {
				Error::InvalidPersistedChainState(format!(
					"header PMMR is missing data at leaf position {} for height {}",
					pos0, current.height
				))
			})?;
			let expected_entry = current.as_elmt()?;
			if expected_entry.hash != expected_current_hash {
				return Err(Error::InvalidPersistedChainState(format!(
					"header PMMR persisted ancestry loaded header {} from key {} at height {}",
					expected_entry.hash, expected_current_hash, current.height
				)));
			}
			if stored_entry != expected_entry {
				return Err(Error::InvalidPersistedChainState(format!(
					"header PMMR data at leaf position {} does not match authoritative header at height {}",
					pos0, current.height
				)));
			}

			let stored_hash = self.pmmr.get_from_file(pos0)?.ok_or_else(|| {
				Error::InvalidPersistedChainState(format!(
					"header PMMR is missing hash at leaf position {} for height {}",
					pos0, current.height
				))
			})?;
			let expected_hash = current.hash_with_index(context_id, pos0)?;
			if stored_hash != expected_hash {
				return Err(Error::InvalidPersistedChainState(format!(
					"header PMMR hash at leaf position {} does not authenticate authoritative header at height {}",
					pos0, current.height
				)));
			}
			persisted_leaf_hashes.push(stored_hash);

			let completed = next_height.saturating_sub(current.height);
			if last_progress_log.elapsed().as_secs() >= PERSISTED_ANCESTRY_LOG_INTERVAL_SECS {
				info!(
					"validate_persisted_ancestry: header ancestry {}/{} ({}%), current height {}",
					completed,
					next_height,
					completed.saturating_mul(100) / next_height,
					current.height
				);
				last_progress_log = Instant::now();
			}

			if current.height == 0 {
				break;
			}

			let expected_height = current.height.checked_sub(1).ok_or_else(|| {
				Error::InvalidPersistedChainState(format!(
					"header PMMR persisted ancestry attempted to traverse before height {}",
					current.height
				))
			})?;
			let previous_key = current.prev_hash;
			let previous = batch.get_block_header(&previous_key).map_err(|e| {
				Error::StoreErr(
					e,
					format!(
						"header PMMR persisted ancestry load previous header {} for {} at height {}",
						previous_key, expected_current_hash, current.height
					),
				)
			})?;
			if previous.height != expected_height {
				return Err(Error::InvalidPersistedChainState(format!(
					"header PMMR persisted ancestry expected predecessor {} at height {}, found height {}",
					previous_key, expected_height, previous.height
				)));
			}
			current = previous;
			expected_current_hash = previous_key;
		}

		info!(
			"validate_persisted_ancestry: header ancestry complete; validating {} PMMR positions",
			expected_size
		);

		// Header PMMRs are non-prunable, so every retained parent must be
		// reproducible directly from its two persisted child hashes. The ancestry
		// pass above already loaded every leaf. A postorder stack lets us read each
		// parent once instead of rereading both children for every parent.
		let mut leaf_hashes = persisted_leaf_hashes.into_iter().rev();
		let mut node_stack: Vec<(u64, Hash)> = Vec::new();
		last_progress_log = Instant::now();
		for pos0 in 0..expected_size {
			if stop_state.map(StopState::is_stopped).unwrap_or(false) {
				return Err(Error::Stopped);
			}
			let height = pmmr::bintree_postorder_height(pos0);
			if height == 0 {
				let leaf_hash = leaf_hashes.next().ok_or_else(|| {
					Error::InvalidPersistedChainState(format!(
						"header PMMR has more leaf positions than persisted ancestry at position {}",
						pos0
					))
				})?;
				node_stack.push((0, leaf_hash));
			} else {
				let (right_height, right_hash) = node_stack.pop().ok_or_else(|| {
					Error::InvalidPersistedChainState(format!(
						"header PMMR parent {} has no right child in postorder traversal",
						pos0
					))
				})?;
				let (left_height, left_hash) = node_stack.pop().ok_or_else(|| {
					Error::InvalidPersistedChainState(format!(
						"header PMMR parent {} has no left child in postorder traversal",
						pos0
					))
				})?;
				let child_height = height.checked_sub(1).ok_or_else(|| {
					Error::DataOverflow(format!("header PMMR parent height at position {}", pos0))
				})?;
				if left_height != child_height || right_height != child_height {
					return Err(Error::InvalidPersistedChainState(format!(
						"header PMMR parent {} at height {} has child heights {} and {}",
						pos0, height, left_height, right_height
					)));
				}
				let stored_hash = self.pmmr.get_from_file(pos0)?.ok_or_else(|| {
					Error::InvalidPersistedChainState(format!(
						"header PMMR is missing parent hash at position {}",
						pos0
					))
				})?;
				let expected_hash = (left_hash, right_hash).hash_with_index(context_id, pos0)?;
				if stored_hash != expected_hash {
					return Err(Error::InvalidPersistedChainState(format!(
						"header PMMR parent hash at position {} does not match its children",
						pos0
					)));
				}
				node_stack.push((height, stored_hash));
			}

			if last_progress_log.elapsed().as_secs() >= PERSISTED_ANCESTRY_LOG_INTERVAL_SECS {
				let completed = pos0.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"header PMMR validation progress at position {}",
						pos0
					))
				})?;
				info!(
					"validate_persisted_ancestry: PMMR positions {}/{} ({}%), elapsed {}s",
					completed,
					expected_size,
					completed.saturating_mul(100) / expected_size,
					started.elapsed().as_secs()
				);
				last_progress_log = Instant::now();
			}
		}
		if leaf_hashes.next().is_some() {
			return Err(Error::InvalidPersistedChainState(
				"persisted header ancestry contains more leaves than the header PMMR".into(),
			));
		}

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

#[derive(Debug)]
struct RewindBlockPlan {
	block: Block,
	previous_header: BlockHeader,
	spent_outputs: Vec<SpentOutput>,
	persist_spent_index: bool,
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
	/// Returns the exact spent-commitment records produced by this block. The
	/// caller may persist these in an outer batch when a fully validated block is
	/// retained on a currently losing fork and this extension is rolled back.
	pub fn apply_block(
		&mut self,
		b: &Block,
		header_ext: &HeaderExtension<'_>,
		batch: &Batch<'_>,
	) -> Result<Vec<(Commitment, SpentCommitmentRecord)>, Error> {
		let mut affected_pos = vec![];

		// Resolve spent outputs before adding any new outputs from this block.
		// Inputs must be validated against the pre-block UTXO set.
		let spent = self
			.utxo_view(header_ext)
			.validate_inputs(&b.inputs(), batch)?;
		let mut spent_records = Vec::with_capacity(spent.len());
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
			let record = SpentCommitmentRecord {
				spending_block: HashHeight {
					hash: b_hash,
					height: b.header.height,
				},
				spent_output: *pos,
			};
			batch.save_spent_commitments(&out.commitment(), record)?;
			spent_records.push((out.commitment(), record));
		}

		// Preserve the commitment-to-occurrence association established by PMMR
		// validation. Input serialization order may change between protocol versions,
		// so a position-only vector cannot safely be paired with a reloaded block.
		let spent_index: Vec<_> = spent_records
			.iter()
			.map(|(commitment, record)| SpentOutput {
				commitment: *commitment,
				position: record.spent_output,
			})
			.collect();
		batch.save_spent_index(&b_hash, &spent_index)?;

		// Apply the kernels to the kernel MMR.
		// Note: This validates and NRD relative height locks via the "recent" kernel index.
		self.apply_kernels(b.kernels(), b.header.height, batch, true)?;

		// Update the head of the extension to reflect the block we just applied.
		self.head = Tip::try_from_header(&b.header)?;

		Ok(spent_records)
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

	/// Rewinds the MMRs to the provided block's last output and kernel positions.
	/// All blocks and spent-position metadata are authenticated before mutation.
	pub fn rewind(
		&mut self,
		header: &BlockHeader,
		batch: &Batch<'_>,
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
		let loaded_head_hash = head_header.hash(self.context_id)?;
		if loaded_head_hash != head_hash {
			return Err(Error::InvalidPersistedChainState(format!(
				"Extension::rewind head header key/hash mismatch: selected {}, header hashes to {}",
				head_hash, loaded_head_hash
			)));
		}

		// Bound supported body reorgs from the authenticated current head rather
		// than BODY_TAIL or retained full blocks. Archive retention must not allow
		// a deeper rewind than a pruned node can perform.
		let minimum_height = head_header
			.height
			.saturating_sub(u64::from(global::cut_through_horizon(self.context_id)));
		if header.height < minimum_height {
			return Err(Error::RewindBeyondHorizon {
				head_height: head_header.height,
				target_height: header.height,
				minimum_height,
			});
		}

		if header.height > head_header.height {
			return Err(Error::TxHashSetErr(format!(
				"cannot rewind extension forward to {} at height {} from {} at height {}",
				header_hash, header.height, head_hash, head_header.height
			)));
		}

		let mut current = head_header;
		let mut rewind_headers = vec![];
		let mut visited = HashSet::new();
		while header.height < current.height {
			rewind_headers.push(current.clone());
			current = crate::checked_previous_header(
				self.context_id,
				&current,
				&mut visited,
				"Extension::rewind ancestry",
				|hash| batch.get_block_header(hash),
			)?;
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

		let rewind_total = u64::try_from(rewind_headers.len()).map_err(|_| {
			Error::DataOverflow(format!(
				"Extension::rewind, rewind_headers.len={}",
				rewind_headers.len()
			))
		})?;

		// Verify every full block and authenticate its spent-position cache before
		// the first rewind mutation. PMMR roots do not authenticate prunable leaf
		// membership, so accepting an incorrect cache here could manufacture an
		// unspent output that later UTXO validation would trust.
		//
		// `progress` is intentionally not called during this preflight. A cancellation
		// request communicated through that callback is therefore observed only at the
		// checkpoint below, before the first mutation. The preflight is bounded by the
		// cut-through horizon and does not rescan chain ancestry for every block, so
		// this delayed progress/cancellation response is an accepted tradeoff.
		let mut rewind_blocks = Vec::with_capacity(rewind_headers.len());
		for expected_header in &rewind_headers {
			let block = crate::checked_block_for_header(
				self.context_id,
				expected_header,
				"Extension::rewind preflight",
				|hash| batch.get_block(hash),
			)?;
			let previous_header = crate::checked_previous_header(
				self.context_id,
				&block.header,
				&mut HashSet::new(),
				"prepare_authenticated_rewind_block predecessor",
				|hash| batch.get_block_header(hash),
			)?;
			rewind_blocks.push((block, previous_header));
		}
		let mut rewind_plans = Vec::with_capacity(rewind_blocks.len());
		for (block, previous_header) in rewind_blocks {
			rewind_plans.push(self.prepare_authenticated_rewind_block(
				block,
				previous_header,
				batch,
			)?);
		}

		if let Some(ref mut progress) = progress {
			progress(0, rewind_total)?;
		}

		if rewind_plans.is_empty() {
			// Nothing to rewind but we do want to truncate the MMRs at header for consistency.
			// An empty restore bitmap cannot recover older leaves removed by an interrupted,
			// uncommitted extension. Recovery callers must authenticate the resulting leaf
			// membership against independently committed state before accepting it.
			self.rewind_mmrs_to_pos(header.output_mmr_size, header.kernel_mmr_size, &[])?;
			if let Some(ref mut progress) = progress {
				progress(rewind_total, rewind_total)?;
			}
		} else {
			let mut rewound = 0u64;
			for plan in rewind_plans {
				self.apply_rewind_block(plan, batch)?;
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

	fn prepare_authenticated_rewind_block(
		&self,
		block: Block,
		previous_header: BlockHeader,
		batch: &Batch<'_>,
	) -> Result<RewindBlockPlan, Error> {
		let header = &block.header;
		let header_hash = header.hash(self.context_id)?;

		// The spent index allows us to conveniently "unspend" everything in a
		// block, but it is derived state and must be authenticated before use.
		let (positions, cached_spent_index, persist_spent_index, operation) =
			match batch.get_spent_index(&header_hash) {
				Ok(spent) => {
					let positions = spent.iter().map(|entry| entry.position.pos).collect();
					(positions, Some(spent), false, "rewind spent index")
				}
				Err(e) if e.store_error_is_not_found() => {
					warn!(
						"prepare_authenticated_rewind_block: fallback to legacy input bitmap for block {} at {}",
						header_hash, header.height
					);
					match batch.get_block_input_bitmap(&header_hash) {
						Ok(bitmap) => {
							let positions = bitmap.iter().map(u64::from).collect();
							(positions, None, true, "rewind legacy input bitmap")
						}
						Err(e) if e.store_error_is_not_found() => {
							if block.inputs().is_empty() {
								(Vec::new(), None, true, "rewind missing empty spent index")
							} else {
								let msg = format!(
									"rewind block {} at height {} has neither a spent index nor a legacy input bitmap",
									header_hash, header.height
								);
								return Err(Error::InvalidPersistedChainState(msg));
							}
						}
						Err(e) => {
							return Err(Error::StoreErr(
								e,
								"prepare_authenticated_rewind_block get legacy input bitmap".into(),
							));
						}
					}
				}
				Err(e) => {
					return Err(Error::StoreErr(
						e,
						"prepare_authenticated_rewind_block get spent index".into(),
					));
				}
			};

		let spent_outputs = self.authenticate_rewind_spent_index(
			operation,
			&block,
			&previous_header,
			&positions,
			cached_spent_index.as_deref(),
			batch,
		)?;

		Ok(RewindBlockPlan {
			block,
			previous_header,
			spent_outputs,
			persist_spent_index,
		})
	}

	fn authenticate_rewind_spent_index(
		&self,
		operation: &str,
		block: &Block,
		previous_header: &BlockHeader,
		positions: &[u64],
		cached_spent_index: Option<&[SpentOutput]>,
		batch: &Batch<'_>,
	) -> Result<Vec<SpentOutput>, Error> {
		require_spent_commitment_record_index(operation, batch)?;
		let spending_block = HashHeight {
			hash: block.hash(self.context_id)?,
			height: block.header.height,
		};
		let spent_outputs = validate_block_spent_positions(
			operation,
			block,
			previous_header,
			positions,
			self.output_pmmr.size(),
			self.rproof_pmmr.size(),
			|pos0| Ok(self.output_pmmr.get_data_from_file(pos0)?),
			|pos0| Ok(self.rproof_pmmr.get_data_from_file(pos0)?.is_some()),
			|commitment| {
				spent_commitment_record_for_block(operation, commitment, spending_block, batch)
			},
		)?;

		if let Some(cached) = cached_spent_index {
			if cached.len() != spent_outputs.len() {
				return Err(Error::InvalidPersistedChainState(format!(
					"{} for block at height {} contains {} cached occurrences for {} authenticated inputs",
					operation,
					block.header.height,
					cached.len(),
					spent_outputs.len()
				)));
			}
			let mut authenticated_by_commitment = HashMap::with_capacity(spent_outputs.len());
			for expected in &spent_outputs {
				if authenticated_by_commitment
					.insert(expected.commitment, expected.position)
					.is_some()
				{
					return Err(Error::InvalidPersistedChainState(format!(
						"{} authenticates duplicate input commitment {:?} for block at height {}",
						operation, expected.commitment, block.header.height
					)));
				}
			}
			let mut cached_commitments = HashSet::with_capacity(cached.len());
			for cached in cached {
				let commitment = cached.commitment;
				let cached_position = cached.position;
				if cached_position.height > previous_header.height {
					return Err(Error::InvalidPersistedChainState(format!(
						"{} for block at height {} records output position {} at height {} above predecessor height {}",
						operation,
						block.header.height,
						cached_position.pos,
						cached_position.height,
						previous_header.height
					)));
				}
				if !cached_commitments.insert(commitment) {
					return Err(Error::InvalidPersistedChainState(format!(
						"{} for block at height {} contains duplicate cached commitment {:?}",
						operation, block.header.height, commitment
					)));
				}
				let expected = authenticated_by_commitment
					.get(&commitment)
					.ok_or_else(|| {
						Error::InvalidPersistedChainState(format!(
							"{} for block at height {} caches commitment {:?} that is not an input",
							operation, block.header.height, commitment
						))
					})?;
				if cached_position != *expected {
					return Err(Error::InvalidPersistedChainState(format!(
						"{} for block at height {} records commitment {:?} at output position {} and height {}, but the authenticated spent commitment record identifies position {} and height {}",
						operation,
						block.header.height,
						commitment,
						cached_position.pos,
						cached_position.height,
						expected.pos,
						expected.height
					)));
				}
			}
		}
		Ok(spent_outputs)
	}

	fn apply_rewind_block(
		&mut self,
		plan: RewindBlockPlan,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		let RewindBlockPlan {
			block,
			previous_header: prev_header,
			spent_outputs,
			persist_spent_index,
		} = plan;
		let header = &block.header;
		let header_hash = header.hash(self.context_id)?;
		let spent_pos = spent_outputs
			.iter()
			.map(|entry| entry.position.pos)
			.collect::<Vec<_>>();

		if header.height == 0 {
			self.rewind_mmrs_to_pos(0, 0, &spent_pos)?;
		} else {
			self.rewind_mmrs_to_pos(
				prev_header.output_mmr_size,
				prev_header.kernel_mmr_size,
				&spent_pos,
			)?;
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
		let mut exact_spent_index = Vec::with_capacity(spent_outputs.len());
		for spent_output in spent_outputs {
			let pos1 = spent_output.position;
			let pos0 = pos1.pos.checked_sub(1).ok_or_else(|| {
				mwc_store::Error::DataOverflow(format!(
					"Extension::rewind_single_block pos1.pos={}",
					pos1.pos
				))
			})?;
			match self.output_pmmr.get_data(pos0)? {
				Some(out) => {
					if out.commitment() != spent_output.commitment {
						return Err(Error::InvalidPersistedChainState(format!(
							"rewind_single_block restored output commitment {:?} at position {}, expected {:?}",
							out.commitment(), pos1.pos, spent_output.commitment
						)));
					}
					batch.save_output_pos_height(&spent_output.commitment, pos1)?;
					exact_spent_index.push(spent_output);
				}
				None => {
					return Err(Error::TxHashSetErr(format!(
						"rewind_single_block missing output PMMR data at pos {} while restoring output_pos for block {} at {}",
						pos1.pos, header_hash, header.height
					)));
				}
			}
		}
		if persist_spent_index {
			batch.save_spent_index(&header_hash, &exact_spent_index)?;
		}

		Ok(())
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
		// The full kernel_pos index is derived from the kernel PMMR. Rewinding
		// directly to genesis bypasses the per-block index cleanup, so make any
		// surviving entries non-authoritative in the same batch as the reset.
		batch.set_kernel_pos_index_complete(false)?;
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
		self.apply_block(genesis, header_ext, batch).map(|_| ())
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

		info!("Starting PMMR validation");
		// validate all hashes and sums within the trees
		self.output_pmmr.validate()?;
		info!("Finish outputs PMMR validation");
		self.rproof_pmmr.validate()?;
		info!("Finish rangeproofs PMMR validation");
		self.kernel_pmmr.validate()?;
		info!("Finish Kernels PMMR validation");

		info!(
			"txhashset: validated PMMR: the output {}, rproof {}, kernel {} mmrs, took {}s",
			self.output_pmmr.unpruned_size(),
			self.rproof_pmmr.unpruned_size(),
			self.kernel_pmmr.unpruned_size(),
			now.elapsed().as_secs(),
		);

		Ok(())
	}

	fn validate_output_rangeproof_leaf_sets(&self) -> Result<(), Error> {
		let mut output_positions = self.output_pmmr.leaf_pos_iter()?;
		let mut rangeproof_positions = self.rproof_pmmr.leaf_pos_iter()?;

		loop {
			match (output_positions.next(), rangeproof_positions.next()) {
				(None, None) => return Ok(()),
				(Some(output_pos), Some(rangeproof_pos)) => {
					let output_pos = output_pos?;
					let rangeproof_pos = rangeproof_pos?;
					if output_pos != rangeproof_pos {
						return Err(Error::InvalidPersistedChainState(format!(
							"output leaf position {} does not match rangeproof leaf position {}",
							output_pos, rangeproof_pos
						)));
					}
				}
				(Some(output_pos), None) => {
					return Err(Error::InvalidPersistedChainState(format!(
						"output leaf position {} has no matching rangeproof leaf",
						output_pos?
					)));
				}
				(None, Some(rangeproof_pos)) => {
					return Err(Error::InvalidPersistedChainState(format!(
						"rangeproof leaf position {} has no matching output leaf",
						rangeproof_pos?
					)));
				}
			}
		}
	}

	/// Validate exact UTXO leaf membership against the transactionally committed
	/// output-position index.
	///
	/// PMMR roots authenticate append history, not the prunable leaf bitmap, and
	/// output/rangeproof leaf-set equality only proves that the two bitmaps agree
	/// with each other. Recovery therefore needs this independent, bidirectional
	/// check before it can accept a leaf set produced by a zero-step rewind.
	pub(crate) fn validate_output_pos_index(
		&self,
		batch: &Batch<'_>,
		header: &BlockHeader,
	) -> Result<(), Error> {
		let index_complete = batch.is_output_pos_index_complete().map_err(|e| {
			Error::StoreErr(
				e,
				"validate output_pos index completeness during recovery".into(),
			)
		})?;
		if !index_complete {
			return Err(Error::InvalidPersistedChainState(
				"cannot authenticate UTXO leaf membership: output_pos index is incomplete".into(),
			));
		}

		let now = Instant::now();
		let total_outputs = self.output_pmmr.n_unpruned_leaves()?;
		info!(
			"validate_output_pos_index: starting bidirectional output_pos validation at height {}, output_mmr_size {}, utxos {}",
			header.height, header.output_mmr_size, total_outputs
		);
		let index_pass_started = Instant::now();
		let mut last_progress_log = Instant::now();
		let mut indexed_outputs = 0u64;
		let output_pos_iter = batch
			.output_pos_iter()
			.map_err(|e| Error::StoreErr(e, "iterate output_pos index during recovery".into()))?;
		for entry in output_pos_iter {
			let (key, pos1) = entry
				.map_err(|e| Error::StoreErr(e, "read output_pos entry during recovery".into()))?;
			let pos0 = pos1.pos.checked_sub(1).ok_or_else(|| {
				Error::InvalidPersistedChainState(
					"output_pos index contains invalid position 0".into(),
				)
			})?;
			if pos1.pos > header.output_mmr_size || !pmmr::is_leaf(pos0) {
				return Err(Error::InvalidPersistedChainState(format!(
					"output_pos index contains invalid position {} for recovered output MMR size {}",
					pos1.pos, header.output_mmr_size
				)));
			}

			let output = self.output_pmmr.get_data(pos0)?.ok_or_else(|| {
				Error::InvalidPersistedChainState(format!(
					"committed output_pos entry points to missing UTXO leaf at position {}",
					pos1.pos
				))
			})?;
			if !batch.is_match_output_pos_key(&key, &output.commitment()) {
				return Err(Error::InvalidPersistedChainState(format!(
					"committed output_pos key does not match output commitment at position {}",
					pos1.pos
				)));
			}
			if self.rproof_pmmr.get_data(pos0)?.is_none() {
				return Err(Error::InvalidPersistedChainState(format!(
					"committed output_pos entry has no rangeproof leaf at position {}",
					pos1.pos
				)));
			}

			indexed_outputs = indexed_outputs.checked_add(1).ok_or_else(|| {
				Error::DataOverflow("validate_output_pos_index indexed output count".into())
			})?;
			if last_progress_log.elapsed().as_secs()
				>= OUTPUT_POS_VALIDATION_PROGRESS_LOG_INTERVAL_SECS
			{
				info!(
					"validate_output_pos_index: index-to-UTXO progress {}/{} entries ({}%)",
					indexed_outputs,
					total_outputs,
					(indexed_outputs.saturating_mul(100) / total_outputs.max(1)).min(100)
				);
				last_progress_log = Instant::now();
			}
		}
		info!(
			"validate_output_pos_index: index-to-UTXO pass finished, checked {} entries in {}s; starting UTXO-to-index pass",
			indexed_outputs,
			index_pass_started.elapsed().as_secs()
		);

		let utxo_pass_started = Instant::now();
		last_progress_log = Instant::now();
		let mut output_leaves = 0u64;
		for pos0 in self.output_pmmr.leaf_pos_iter()? {
			let pos0 = pos0?;
			let pos1 = pos0.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"validate_output_pos_index output position {}",
					pos0
				))
			})?;
			if pos1 > header.output_mmr_size {
				return Err(Error::InvalidPersistedChainState(format!(
					"UTXO leaf position {} exceeds recovered output MMR size {}",
					pos1, header.output_mmr_size
				)));
			}
			let output = self.output_pmmr.get_data(pos0)?.ok_or_else(|| {
				Error::InvalidPersistedChainState(format!(
					"output leaf iterator returned missing UTXO data at position {}",
					pos1
				))
			})?;
			let indexed_pos = batch
				.get_output_pos_height(&output.commitment())
				.map_err(|e| {
					Error::StoreErr(e, "look up output_pos entry during recovery".into())
				})?;
			match indexed_pos {
				Some(indexed_pos) if indexed_pos.pos == pos1 => {}
				Some(indexed_pos) => {
					return Err(Error::InvalidPersistedChainState(format!(
						"UTXO leaf at position {} is indexed at position {}",
						pos1, indexed_pos.pos
					)));
				}
				None => {
					return Err(Error::InvalidPersistedChainState(format!(
						"UTXO leaf at position {} has no committed output_pos entry",
						pos1
					)));
				}
			}

			output_leaves = output_leaves.checked_add(1).ok_or_else(|| {
				Error::DataOverflow("validate_output_pos_index output leaf count".into())
			})?;
			if last_progress_log.elapsed().as_secs()
				>= OUTPUT_POS_VALIDATION_PROGRESS_LOG_INTERVAL_SECS
			{
				info!(
					"validate_output_pos_index: UTXO-to-index progress {}/{} outputs ({}%)",
					output_leaves,
					total_outputs,
					(output_leaves.saturating_mul(100) / total_outputs.max(1)).min(100)
				);
				last_progress_log = Instant::now();
			}
		}

		if indexed_outputs != output_leaves {
			return Err(Error::InvalidPersistedChainState(format!(
				"output_pos index count {} does not match UTXO leaf count {}",
				indexed_outputs, output_leaves
			)));
		}

		info!(
			"validate_output_pos_index: finished successfully, checked {} entries and {} UTXOs in {}s (UTXO-to-index pass {}s)",
			indexed_outputs,
			output_leaves,
			now.elapsed().as_secs(),
			utxo_pass_started.elapsed().as_secs()
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
		info!(
			"validate_kernel_sums: started at height {}, outputs {}, kernels {}, total commitments {}",
			header.height, total_outputs, total_kernels, total_progress
		);
		let status_throttle = SyncStatusUpdateThrottle::new();
		Self::update_kernel_sum_progress(&status, &status_throttle, 0, total_progress, true);
		let mut last_progress_log = Instant::now();
		let result = (|| {
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
					if last_progress_log.elapsed().as_secs()
						>= KERNEL_SUM_PROGRESS_LOG_INTERVAL_SECS
					{
						let outputs_done = progress.min(total_outputs);
						let kernels_done =
							progress.saturating_sub(total_outputs).min(total_kernels);
						info!(
							"validate_kernel_sums: progress {}/{} ({}%), outputs {}/{}, kernels {}/{}",
							progress,
							total_progress,
							progress.saturating_mul(100) / total_progress.max(1),
							outputs_done,
							total_outputs,
							kernels_done,
							total_kernels
						);
						last_progress_log = Instant::now();
					}
					Ok(())
				},
			)
		})();

		match &result {
			Ok(_) => info!(
				"validate_kernel_sums: finished successfully in {}s; total circulating balance {} MWC checked at height {}",
				now.elapsed().as_secs(),
				amount_to_hr_string(
					header
						.total_overage(self.context_id, genesis.kernel_mmr_size > 0)?
						.unsigned_abs(),
					true,
				),
				header.height
			),
			Err(err) => error!(
				"validate_kernel_sums: stopped with error after {}s: {}",
				now.elapsed().as_secs(),
				err
			),
		}
		result
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
		self.validate_output_rangeproof_leaf_sets()?;

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
	txhashset: &TxHashSet,
	block_header: &BlockHeader,
	head_header: &BlockHeader,
	batch: &Batch<'_>,
) -> Result<Bitmap, Error> {
	// Rewinding blocks one by one instead load all rewind positions in the RAM. That allow us save memory (unwind can be up to a WEEK).
	walk_input_pos_to_rewind(
		block_header,
		head_header,
		batch,
		|current, previous, block_bitmap| {
			let block = crate::checked_block_for_header(
				batch.get_context_id(),
				current,
				"compact input bitmap preflight",
				|hash| batch.get_block(hash),
			)?;
			txhashset.validate_compact_block_input_bitmap(&block, previous, block_bitmap, batch)
		},
	)
}

fn walk_input_pos_to_rewind<F>(
	block_header: &BlockHeader,
	head_header: &BlockHeader,
	batch: &Batch<'_>,
	mut validate_block_bitmap: F,
) -> Result<Bitmap, Error>
where
	F: FnMut(&BlockHeader, &BlockHeader, &Bitmap) -> Result<(), Error>,
{
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
	let mut visited = HashSet::new();
	while current.height > block_header.height {
		let current_hash = current.hash(context_id)?;
		let block_bitmap = match batch.get_block_input_bitmap(&current_hash) {
			Ok(block_bitmap) => block_bitmap,
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
		};
		let previous = crate::checked_previous_header(
			context_id,
			&current,
			&mut visited,
			"input positions to rewind ancestry",
			|hash| batch.get_block_header(hash),
		)?;
		validate_block_bitmap(&current, &previous, &block_bitmap)?;
		bitmap.or_inplace(&block_bitmap);
		current = previous;
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
		block, HeaderVersion, Input, NRDRelativeHeight, OutputFeatures, SegmentIdentifier,
		SegmentProof, TransactionBody,
	};
	use mwc_core::global::ChainTypes;
	use mwc_core::libtx::{reward, ProofBuilder};
	use mwc_crates::secp::ContextFlag;
	use mwc_keychain::{ExtKeychain, Keychain};
	use std::{fs, io};

	fn spent_cache_entry(commitment: Commitment, pos: u64, height: u64) -> SpentOutput {
		SpentOutput {
			commitment,
			position: CommitPos { pos, height },
		}
	}

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

	fn save_empty_body_chain(store: &ChainStore, height: u64) -> Vec<BlockHeader> {
		let mut headers = vec![BlockHeader::default(0)];
		for next_height in 1..=height {
			let mut header = BlockHeader::default(0);
			header.height = next_height;
			header.prev_hash = headers.last().unwrap().hash(0).unwrap();
			header.pow.proof.nonces[0] = next_height;
			headers.push(header);
		}

		let batch = store.batch_write().unwrap();
		batch
			.set_spent_commitment_record_index_complete(true)
			.unwrap();
		for header in &headers {
			batch.save_block_header(header).unwrap();
			if header.height > 0 {
				let mut block = Block::default(0);
				block.header = header.clone();
				batch.save_block(&block).unwrap();
				batch
					.save_spent_index(&header.hash(0).unwrap(), &[])
					.unwrap();
			}
		}
		batch.commit().unwrap();

		headers
	}

	#[test]
	fn init_kernel_pos_index_chunked_rejects_short_head_before_clear() {
		let chain_dir = "target/init_kernel_pos_index_chunked_rejects_short_head_before_clear";
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let _ = fs::remove_dir_all(chain_dir);

		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let kernel = reward_kernel(&mut secp, 1);
		let kernel_mmr_size = {
			let mut kernel_pmmr = PMMR::at(
				&mut txhashset.kernel_pmmr_h.backend,
				txhashset.kernel_pmmr_h.size,
			);
			kernel_pmmr.push(&kernel).unwrap();
			kernel_pmmr.size()
		};
		txhashset.kernel_pmmr_h.size = kernel_mmr_size;

		let head = BlockHeader::default(0);
		save_block_headers(&store, &[&head]);
		{
			let batch = store.batch_write().unwrap();
			batch
				.save_body_head(&Tip::try_from_header(&head).unwrap())
				.unwrap();
			batch
				.save_kernel_pos(&kernel.excess(), KernelPos { pos: 1, height: 0 })
				.unwrap();
			batch.set_kernel_pos_index_complete(false).unwrap();
			batch.commit().unwrap();
		}

		let err = txhashset
			.init_kernel_pos_index_chunked(&store, None, None)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::TxHashSetErr(msg)
				if msg.contains("body HEAD kernel MMR size")
					&& msg.contains("does not match txhashset size")
		));

		let batch = store.batch_read().unwrap();
		assert!(!batch.is_kernel_pos_index_complete().unwrap());
		let entries = batch
			.kernel_pos_iter(&kernel.excess())
			.unwrap()
			.collect::<Result<Vec<_>, _>>()
			.unwrap();
		assert_eq!(entries, vec![KernelPos { pos: 1, height: 0 }]);
		drop(batch);

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	fn verify_test_kernel_history(
		chain_dir: &str,
		kernels: &[TxKernel],
		inclusion_height: u64,
		inclusion_version: HeaderVersion,
		nrd_enabled: bool,
	) -> Result<(), Error> {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(nrd_enabled);
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let kernel_mmr_size = {
			let mut kernel_pmmr = PMMR::at(
				&mut txhashset.kernel_pmmr_h.backend,
				txhashset.kernel_pmmr_h.size,
			);
			for kernel in kernels {
				kernel_pmmr.push(kernel).unwrap();
			}
			kernel_pmmr.size()
		};
		txhashset.kernel_pmmr_h.size = kernel_mmr_size;

		let mut headers = vec![BlockHeader::default(0)];
		for height in 1..=inclusion_height {
			let mut header = BlockHeader::default(0);
			header.height = height;
			header.prev_hash = headers.last().unwrap().hash(0).unwrap();
			header.pow.proof.nonces[0] = height;
			if height == inclusion_height {
				header.version = inclusion_version;
				header.kernel_mmr_size = kernel_mmr_size;
			}
			headers.push(header);
		}

		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		header_pmmr.size = {
			let mut pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			for header in &headers {
				pmmr.push(header).unwrap();
			}
			pmmr.size()
		};

		{
			let batch = store.batch_write().unwrap();
			for header in &headers {
				batch.save_block_header(header).unwrap();
			}
			batch.commit().unwrap();
		}

		let result = {
			let batch = store.batch_write().unwrap();
			txhashset.verify_kernel_pos_index(
				&headers[0],
				headers.last().unwrap(),
				&header_pmmr,
				&batch,
				None,
				None,
			)
		};

		drop(header_pmmr);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
		result
	}

	#[test]
	fn recent_kernel_index_uses_body_ancestry_across_header_fork() {
		let chain_dir = "target/recent_kernel_index_uses_body_ancestry_across_header_fork";
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(true);
		let _ = fs::remove_dir_all(chain_dir);

		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 1u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(2).unwrap(),
		})
		.unwrap();
		let kernel_mmr_size = {
			let mut kernel_pmmr = PMMR::at(
				&mut txhashset.kernel_pmmr_h.backend,
				txhashset.kernel_pmmr_h.size,
			);
			kernel_pmmr.push(&kernel).unwrap();
			kernel_pmmr.size()
		};
		txhashset.kernel_pmmr_h.size = kernel_mmr_size;

		let genesis = BlockHeader::default(0);
		let genesis_hash = genesis.hash(0).unwrap();
		let mut body_1 = BlockHeader::default(0);
		body_1.height = 1;
		body_1.version = HeaderVersion(4);
		body_1.prev_hash = genesis_hash;
		body_1.pow.proof.nonces[0] = 1;
		let mut body_2 = BlockHeader::default(0);
		body_2.height = 2;
		body_2.version = HeaderVersion(4);
		body_2.prev_hash = body_1.hash(0).unwrap();
		body_2.pow.proof.nonces[0] = 2;
		body_2.kernel_mmr_size = kernel_mmr_size;

		// The header-only fork reaches the same kernel boundary one block earlier.
		// Using these boundaries for the body PMMR would record the kernel at 1
		// instead of 2 and permit a duplicate at height 3.
		let mut header_fork_1 = BlockHeader::default(0);
		header_fork_1.height = 1;
		header_fork_1.version = HeaderVersion(4);
		header_fork_1.prev_hash = genesis_hash;
		header_fork_1.pow.proof.nonces[0] = 11;
		header_fork_1.kernel_mmr_size = kernel_mmr_size;
		let mut header_fork_2 = BlockHeader::default(0);
		header_fork_2.height = 2;
		header_fork_2.version = HeaderVersion(4);
		header_fork_2.prev_hash = header_fork_1.hash(0).unwrap();
		header_fork_2.pow.proof.nonces[0] = 12;
		header_fork_2.kernel_mmr_size = kernel_mmr_size;

		save_block_headers(
			&store,
			&[&genesis, &body_1, &body_2, &header_fork_1, &header_fork_2],
		);
		{
			let batch = store.batch_write().unwrap();
			batch
				.save_body_head(&Tip::try_from_header(&body_2).unwrap())
				.unwrap();
			batch.commit().unwrap();
		}

		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		header_pmmr.size = {
			let mut pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			for header in [&genesis, &header_fork_1, &header_fork_2] {
				pmmr.push(header).unwrap();
			}
			pmmr.size()
		};

		let kernel_index = store::nrd_recent_kernel_index();
		{
			let batch = store.batch_write().unwrap();
			txhashset
				.init_recent_kernel_pos_index(&batch, None, None)
				.unwrap();
			let stored = kernel_index
				.peek_pos(&batch, kernel.excess())
				.unwrap()
				.unwrap();
			assert_eq!(stored.height, body_2.height);
			assert!(matches!(
				apply_kernel_rules(
					&kernel,
					CommitPos {
						pos: kernel_mmr_size + 1,
						height: 3,
					},
					&batch,
				),
				Err(Error::NRDRelativeHeight)
			));
			batch.commit().unwrap();
		}

		// The full-history PMMR path must reject a foreign terminal header before
		// clearing the already-correct recent index.
		{
			let batch = store.batch_write().unwrap();
			let err = txhashset
				.verify_kernel_pos_index(&genesis, &body_2, &header_pmmr, &batch, None, None)
				.unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => assert!(msg.contains("terminal header"), "{}", msg),
				other => panic!("expected terminal header mismatch, got {:?}", other),
			}
			assert_eq!(
				kernel_index
					.peek_pos(&batch, kernel.excess())
					.unwrap()
					.unwrap()
					.height,
				body_2.height
			);
			batch.commit().unwrap();
		}

		// Deliberately model an invalid/corrupt same-key header with forged starting
		// boundaries. Normal PoW validation would reject it; this maintenance path
		// must reject it before clearing the recent index without repeating PoW.
		{
			let mut altered_start = header_fork_1.clone();
			altered_start.prev_hash = header_fork_2.hash(0).unwrap();
			assert_eq!(
				altered_start.hash(0).unwrap(),
				header_fork_1.hash(0).unwrap()
			);
			assert_ne!(altered_start, header_fork_1);

			let batch = store.batch_write().unwrap();
			let err = txhashset
				.verify_kernel_pos_index(
					&altered_start,
					&header_fork_2,
					&header_pmmr,
					&batch,
					None,
					None,
				)
				.unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("start header"), "{}", msg);
					assert!(msg.contains("does not match persisted"), "{}", msg);
				}
				other => panic!("expected complete start header mismatch, got {:?}", other),
			}
			assert_eq!(
				kernel_index
					.peek_pos(&batch, kernel.excess())
					.unwrap()
					.unwrap()
					.height,
				body_2.height
			);
			batch.commit().unwrap();
		}

		// The terminal endpoint is subject to the same complete-header check.
		{
			let mut altered_terminal = header_fork_2.clone();
			altered_terminal.version = HeaderVersion(3);
			assert_eq!(
				altered_terminal.hash(0).unwrap(),
				header_fork_2.hash(0).unwrap()
			);
			assert_ne!(altered_terminal, header_fork_2);

			let batch = store.batch_write().unwrap();
			let err = txhashset
				.verify_kernel_pos_index(
					&genesis,
					&altered_terminal,
					&header_pmmr,
					&batch,
					None,
					None,
				)
				.unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("terminal header"), "{}", msg);
					assert!(msg.contains("does not match persisted"), "{}", msg);
				}
				other => panic!(
					"expected complete terminal header mismatch, got {:?}",
					other
				),
			}
			assert_eq!(
				kernel_index
					.peek_pos(&batch, kernel.excess())
					.unwrap()
					.unwrap()
					.height,
				body_2.height
			);
			batch.commit().unwrap();
		}

		drop(header_pmmr);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn verify_kernel_pos_index_rejects_invalid_start_predecessor_before_clear() {
		let chain_dir =
			"target/verify_kernel_pos_index_rejects_invalid_start_predecessor_before_clear";
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(true);
		let _ = fs::remove_dir_all(chain_dir);

		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let txhashset = TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let genesis = BlockHeader::default(0);
		let mut off_pmmr_predecessor = BlockHeader::default(0);
		off_pmmr_predecessor.pow.proof.nonces[0] = 9;

		let mut start = BlockHeader::default(0);
		start.height = 1;
		start.version = HeaderVersion(4);
		start.prev_hash = off_pmmr_predecessor.hash(0).unwrap();
		start.pow.proof.nonces[0] = 1;

		let mut terminal = BlockHeader::default(0);
		terminal.height = 2;
		terminal.version = HeaderVersion(4);
		terminal.prev_hash = start.hash(0).unwrap();
		terminal.pow.proof.nonces[0] = 2;

		save_block_headers(
			&store,
			&[&genesis, &off_pmmr_predecessor, &start, &terminal],
		);

		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		header_pmmr.size = {
			let mut pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			for header in [&genesis, &start, &terminal] {
				pmmr.push(header).unwrap();
			}
			pmmr.size()
		};

		let kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 1u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(2).unwrap(),
		})
		.unwrap();
		let kernel_index = store::nrd_recent_kernel_index();
		let sentinel = CommitPos { pos: 1, height: 42 };
		{
			let batch = store.batch_write().unwrap();
			kernel_index
				.push_pos(&batch, kernel.excess(), sentinel)
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_write().unwrap();
			let err = txhashset
				.verify_kernel_pos_index(&start, &terminal, &header_pmmr, &batch, None, None)
				.unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("predecessor"), "{}", msg);
					assert!(msg.contains("header PMMR ancestry"), "{}", msg);
				}
				other => panic!("expected start predecessor mismatch, got {:?}", other),
			}
			let stored = kernel_index
				.peek_pos(&batch, kernel.excess())
				.unwrap()
				.unwrap();
			assert_eq!(stored.pos, sentinel.pos);
			assert_eq!(stored.height, sentinel.height);
			batch.commit().unwrap();
		}

		// Also reject a PMMR-selected predecessor whose persisted height does not
		// match the height implied by the starting endpoint.
		let mut wrong_height_predecessor = BlockHeader::default(0);
		wrong_height_predecessor.height = 7;
		wrong_height_predecessor.pow.proof.nonces[0] = 10;

		let mut wrong_height_start = BlockHeader::default(0);
		wrong_height_start.height = 1;
		wrong_height_start.version = HeaderVersion(4);
		wrong_height_start.prev_hash = wrong_height_predecessor.hash(0).unwrap();
		wrong_height_start.pow.proof.nonces[0] = 3;

		let mut wrong_height_terminal = BlockHeader::default(0);
		wrong_height_terminal.height = 2;
		wrong_height_terminal.version = HeaderVersion(4);
		wrong_height_terminal.prev_hash = wrong_height_start.hash(0).unwrap();
		wrong_height_terminal.pow.proof.nonces[0] = 4;

		save_block_headers(
			&store,
			&[
				&wrong_height_predecessor,
				&wrong_height_start,
				&wrong_height_terminal,
			],
		);
		let mut wrong_height_header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir)
				.join("wrong_height_header")
				.join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		wrong_height_header_pmmr.size = {
			let mut pmmr = PMMR::at(
				&mut wrong_height_header_pmmr.backend,
				wrong_height_header_pmmr.size,
			);
			for header in [
				&wrong_height_predecessor,
				&wrong_height_start,
				&wrong_height_terminal,
			] {
				pmmr.push(header).unwrap();
			}
			pmmr.size()
		};

		{
			let batch = store.batch_write().unwrap();
			let err = txhashset
				.verify_kernel_pos_index(
					&wrong_height_start,
					&wrong_height_terminal,
					&wrong_height_header_pmmr,
					&batch,
					None,
					None,
				)
				.unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("header PMMR entry 0"), "{}", msg);
					assert!(msg.contains("at 7"), "{}", msg);
				}
				other => panic!("expected predecessor height mismatch, got {:?}", other),
			}
			let stored = kernel_index
				.peek_pos(&batch, kernel.excess())
				.unwrap()
				.unwrap();
			assert_eq!(stored.pos, sentinel.pos);
			assert_eq!(stored.height, sentinel.height);
			batch.commit().unwrap();
		}

		drop(wrong_height_header_pmmr);
		drop(header_pmmr);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn verify_kernel_pos_index_rejects_disconnected_range_before_clear() {
		let chain_dir = "target/verify_kernel_pos_index_rejects_disconnected_range_before_clear";
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(true);
		let _ = fs::remove_dir_all(chain_dir);

		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let txhashset = TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let genesis = BlockHeader::default(0);
		let genesis_hash = genesis.hash(0).unwrap();

		let mut pmmr_height_one = BlockHeader::default(0);
		pmmr_height_one.height = 1;
		pmmr_height_one.version = HeaderVersion(4);
		pmmr_height_one.prev_hash = genesis_hash;
		pmmr_height_one.pow.proof.nonces[0] = 1;

		let mut off_pmmr_height_one = BlockHeader::default(0);
		off_pmmr_height_one.height = 1;
		off_pmmr_height_one.version = HeaderVersion(4);
		off_pmmr_height_one.prev_hash = genesis_hash;
		off_pmmr_height_one.pow.proof.nonces[0] = 9;

		// The terminal is individually selected by the PMMR and is a valid child
		// of a persisted header, but not of the preceding PMMR leaf.
		let mut terminal = BlockHeader::default(0);
		terminal.height = 2;
		terminal.version = HeaderVersion(4);
		terminal.prev_hash = off_pmmr_height_one.hash(0).unwrap();
		terminal.pow.proof.nonces[0] = 2;

		save_block_headers(
			&store,
			&[&genesis, &pmmr_height_one, &off_pmmr_height_one, &terminal],
		);

		let mut header_pmmr = PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		header_pmmr.size = {
			let mut pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			for header in [&genesis, &pmmr_height_one, &terminal] {
				pmmr.push(header).unwrap();
			}
			pmmr.size()
		};

		let kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 1u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(2).unwrap(),
		})
		.unwrap();
		let kernel_index = store::nrd_recent_kernel_index();
		let sentinel = CommitPos { pos: 1, height: 42 };
		{
			let batch = store.batch_write().unwrap();
			kernel_index
				.push_pos(&batch, kernel.excess(), sentinel)
				.unwrap();
			batch.commit().unwrap();
		}

		// Every header has an empty kernel boundary. This ensures ancestry is
		// checked independently of the kernel-driven boundary callback.
		{
			let batch = store.batch_write().unwrap();
			let err = txhashset
				.verify_kernel_pos_index(&genesis, &terminal, &header_pmmr, &batch, None, None)
				.unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("disconnected header PMMR ancestry"), "{}", msg);
				}
				other => panic!("expected disconnected header ancestry, got {:?}", other),
			}
			let stored = kernel_index
				.peek_pos(&batch, kernel.excess())
				.unwrap()
				.unwrap();
			assert_eq!(stored.pos, sentinel.pos);
			assert_eq!(stored.height, sentinel.height);
			batch.commit().unwrap();
		}

		drop(header_pmmr);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn verify_kernel_history_rejects_premature_height_locked_kernel() {
		let kernel = TxKernel::with_features(KernelFeatures::HeightLocked {
			fee: 1u32.try_into().unwrap(),
			lock_height: 2,
		})
		.unwrap();
		let err = verify_test_kernel_history(
			"target/verify_kernel_history_rejects_premature_height_locked_kernel",
			&[kernel],
			1,
			HeaderVersion(4),
			true,
		)
		.unwrap_err();

		assert!(matches!(
			err,
			Error::Block(block::Error::KernelLockHeight(2, 1))
		));
	}

	#[test]
	fn verify_kernel_history_rejects_nrd_kernel_before_header_v4() {
		let kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 1u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(2).unwrap(),
		})
		.unwrap();
		let err = verify_test_kernel_history(
			"target/verify_kernel_history_rejects_nrd_kernel_before_header_v4",
			&[kernel],
			1,
			HeaderVersion(3),
			true,
		)
		.unwrap_err();

		assert!(matches!(err, Error::Block(block::Error::NRDKernelPreHF3)));
	}

	#[test]
	fn verify_kernel_history_rejects_nrd_kernel_when_disabled() {
		let kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 1u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(2).unwrap(),
		})
		.unwrap();
		let err = verify_test_kernel_history(
			"target/verify_kernel_history_rejects_nrd_kernel_when_disabled",
			&[kernel],
			1,
			HeaderVersion(4),
			false,
		)
		.unwrap_err();

		match err {
			Error::Block(block::Error::NRDKernelNotEnabled) => {}
			Error::PMMRErr(err) => {
				assert!(err.to_string().contains("NRD is disabled"), "{}", err);
			}
			other => panic!("expected disabled NRD rejection, got {:?}", other),
		}
	}

	#[test]
	fn verify_kernel_history_accepts_contextually_valid_kernels_after_empty_block() {
		let height_locked = TxKernel::with_features(KernelFeatures::HeightLocked {
			fee: 1u32.try_into().unwrap(),
			lock_height: 2,
		})
		.unwrap();
		let nrd = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 1u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(2).unwrap(),
		})
		.unwrap();

		verify_test_kernel_history(
			"target/verify_kernel_history_accepts_contextually_valid_kernels_after_empty_block",
			&[height_locked, nrd],
			2,
			HeaderVersion(4),
			true,
		)
		.unwrap();
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
	fn validate_output_pos_index_accepts_exact_utxo_membership() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_output_pos_index_accepts_exact_utxo_membership";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header = BlockHeader::default(0);
		header.output_mmr_size = 1;
		let commit = secp.commit_value(1).unwrap();
		let output = OutputIdentifier::new(OutputFeatures::Plain, &commit);
		let batch = store.batch_write().unwrap();
		batch
			.save_output_pos_height(&commit, CommitPos { pos: 1, height: 0 })
			.unwrap();
		batch.set_output_pos_index_complete(true).unwrap();

		{
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&header).unwrap());
			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 0);
			assert_eq!(extension.rproof_pmmr.push(&RangeProof::zero()).unwrap(), 0);
			extension
				.validate_output_pos_index(&batch, &header)
				.unwrap();
		}

		drop(batch);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_output_pos_index_rejects_indexed_output_missing_from_leaf_sets() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/validate_output_pos_index_rejects_indexed_output_missing_from_leaf_sets";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header = BlockHeader::default(0);
		header.output_mmr_size = 1;
		let commit = secp.commit_value(1).unwrap();
		let output = OutputIdentifier::new(OutputFeatures::Plain, &commit);
		let batch = store.batch_write().unwrap();
		batch
			.save_output_pos_height(&commit, CommitPos { pos: 1, height: 0 })
			.unwrap();
		batch.set_output_pos_index_complete(true).unwrap();

		{
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&header).unwrap());
			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 0);
			assert_eq!(extension.rproof_pmmr.push(&RangeProof::zero()).unwrap(), 0);
			assert!(extension.output_pmmr.prune(0).unwrap());
			assert!(extension.rproof_pmmr.prune(0).unwrap());

			let err = extension
				.validate_output_pos_index(&batch, &header)
				.unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("committed output_pos entry points to missing UTXO leaf")
			));
		}

		drop(batch);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_output_pos_index_rejects_unindexed_utxo_leaf() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = "target/validate_output_pos_index_rejects_unindexed_utxo_leaf";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();
		let mut header = BlockHeader::default(0);
		header.output_mmr_size = 1;
		let commit = secp.commit_value(1).unwrap();
		let output = OutputIdentifier::new(OutputFeatures::Plain, &commit);
		let batch = store.batch_write().unwrap();
		batch.set_output_pos_index_complete(true).unwrap();

		{
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&header).unwrap());
			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 0);
			assert_eq!(extension.rproof_pmmr.push(&RangeProof::zero()).unwrap(), 0);

			let err = extension
				.validate_output_pos_index(&batch, &header)
				.unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("has no committed output_pos entry")
			));
		}

		drop(batch);
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
	fn current_merkle_proof_survives_unrelated_output_compaction() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir = format!(
			"target/current_merkle_proof_survives_unrelated_output_compaction_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = Arc::new(ChainStore::new(0, &chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset = TxHashSet::open(chain_dir.clone(), store.clone(), None, &secp).unwrap();

		let target =
			OutputIdentifier::new(OutputFeatures::Coinbase, &secp.commit_value(1).unwrap());
		let left_sibling =
			OutputIdentifier::new(OutputFeatures::Plain, &secp.commit_value(2).unwrap());
		let historical_right =
			OutputIdentifier::new(OutputFeatures::Plain, &secp.commit_value(3).unwrap());
		let later = OutputIdentifier::new(OutputFeatures::Plain, &secp.commit_value(4).unwrap());

		let target_pos0;
		let historical_right_pos0;
		let historical_size;
		let historical_root;
		{
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			target_pos0 = output_pmmr.push(&target).unwrap();
			assert_eq!(output_pmmr.push(&left_sibling).unwrap(), 1);
			historical_right_pos0 = output_pmmr.push(&historical_right).unwrap();
			assert_eq!(historical_right_pos0, 3);
			historical_size = output_pmmr.size();
			assert_eq!(historical_size, 4);
			historical_root = output_pmmr.root().unwrap();
		}
		txhashset.output_pmmr_h.size = historical_size;
		{
			let batch = store.batch_write().unwrap();
			batch
				.save_output_pos_height(
					&target.commitment(),
					CommitPos {
						pos: target_pos0 + 1,
						height: 0,
					},
				)
				.unwrap();
			batch.commit().unwrap();
		}

		let current_root;
		let later_pos0;
		{
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			later_pos0 = output_pmmr.push(&later).unwrap();
			assert_eq!(later_pos0, 4);
			txhashset.output_pmmr_h.size = output_pmmr.size();
			current_root = output_pmmr.root().unwrap();
		}
		assert_eq!(txhashset.output_pmmr_h.size, 7);

		// The right peak at pos 3 and the later leaf at pos 4 are spent together.
		// Compaction rolls them into their parent at pos 5 and physically removes
		// the children. Current-state proofs remain supported because they use
		// the retained parent. Proofs against the earlier size/root are
		// intentionally outside the API contract.
		{
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			output_pmmr.prune(historical_right_pos0).unwrap();
			output_pmmr.prune(later_pos0).unwrap();
		}
		txhashset.output_pmmr_h.backend.sync().unwrap();
		txhashset
			.output_pmmr_h
			.backend
			.check_compact(txhashset.output_pmmr_h.size, &Bitmap::new())
			.unwrap();
		txhashset.output_pmmr_h.backend.sync().unwrap();
		assert_eq!(
			txhashset
				.output_pmmr_h
				.backend
				.get_from_file(historical_right_pos0)
				.unwrap(),
			None
		);

		let proof = txhashset.merkle_proof(target.commitment()).unwrap();
		assert_eq!(proof.mmr_size, txhashset.output_pmmr_h.size);
		proof.verify(0, current_root, &target, target_pos0).unwrap();
		assert!(proof
			.verify(0, historical_root, &target, target_pos0)
			.is_err());

		// The compacted backend must continue serving the same current-state proof
		// after reopening; no per-header historical peak archive is involved.
		drop(txhashset);
		drop(store);
		let store = Arc::new(ChainStore::new(0, &chain_dir).unwrap());
		let txhashset = TxHashSet::open(chain_dir.clone(), store.clone(), None, &secp).unwrap();
		let reopened_proof = txhashset.merkle_proof(target.commitment()).unwrap();
		assert_eq!(reopened_proof, proof);

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
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
	fn extension_rewind_allows_exact_horizon_boundary() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/extension_rewind_allows_exact_horizon_boundary";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let horizon = u64::from(global::cut_through_horizon(0));
		let headers = save_empty_body_chain(&store, horizon);
		let target = headers.first().unwrap();
		let head = headers.last().unwrap();
		assert_eq!(target.height, head.height.saturating_sub(horizon));

		{
			let batch = store.batch_read().unwrap();
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(head).unwrap());

			extension.rewind(target, &batch, None).unwrap();
			assert_eq!(extension.head(), Tip::try_from_header(target).unwrap());
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extension_rewind_rejects_target_below_horizon_before_mutation() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/extension_rewind_rejects_target_below_horizon_before_mutation";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let horizon = u64::from(global::cut_through_horizon(0));
		let headers = save_empty_body_chain(&store, horizon + 1);
		let target = headers.first().unwrap();
		let head = headers.last().unwrap();
		let head_tip = Tip::try_from_header(head).unwrap();

		{
			let batch = store.batch_read().unwrap();
			let mut extension = Extension::new(0, &mut txhashset, head_tip.clone());
			let output =
				OutputIdentifier::new(OutputFeatures::Plain, &secp.commit_value(1).unwrap());
			extension.output_pmmr.push(&output).unwrap();
			extension.rproof_pmmr.push(&RangeProof::zero()).unwrap();
			let original_sizes = extension.sizes();
			let progress_calls = std::cell::Cell::new(0u64);
			let mut progress = |_, _| {
				progress_calls.set(progress_calls.get() + 1);
				Ok(())
			};

			let err = extension
				.rewind(target, &batch, Some(&mut progress))
				.unwrap_err();
			assert!(matches!(
				&err,
				Error::RewindBeyondHorizon {
					head_height,
					target_height,
					minimum_height,
				} if *head_height == horizon + 1
					&& *target_height == 0
					&& *minimum_height == 1
			));
			assert!(!err.is_bad_data());
			assert_eq!(progress_calls.get(), 0);
			assert_eq!(extension.sizes(), original_sizes);
			assert_eq!(extension.head(), head_tip);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extension_rewind_allows_genesis_before_chain_reaches_horizon() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/extension_rewind_allows_genesis_before_chain_reaches_horizon";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let headers = save_empty_body_chain(&store, 1);
		let target = headers.first().unwrap();
		let head = headers.last().unwrap();
		assert!(head.height < u64::from(global::cut_through_horizon(0)));

		{
			let batch = store.batch_read().unwrap();
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(head).unwrap());

			extension.rewind(target, &batch, None).unwrap();
			assert_eq!(extension.head(), Tip::try_from_header(target).unwrap());
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

			let err = extension.rewind(&target, &batch, None).unwrap_err();
			assert_rewind_target_error(err);
			assert_eq!(extension.head().last_block_h, head_hash);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extension_rewind_rejects_misindexed_head_header_before_preflight() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/extension_rewind_rejects_misindexed_head_header_before_preflight";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let target = BlockHeader::default(0);
		let target_hash = target.hash(0).unwrap();
		let mut selected_head = BlockHeader::default(0);
		selected_head.height = 1;
		selected_head.prev_hash = target_hash;
		selected_head.pow.proof.nonces[0] = 1;
		let selected_hash = selected_head.hash(0).unwrap();
		let mut substituted_head = selected_head.clone();
		substituted_head.pow.proof.nonces[0] = 2;
		let substituted_hash = substituted_head.hash(0).unwrap();
		assert_ne!(selected_hash, substituted_hash);

		let mut substituted_block = Block::default(0);
		substituted_block.header = substituted_head.clone();
		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&target).unwrap();
			batch.save_block_header(&selected_head).unwrap();
			batch.save_block_header(&substituted_head).unwrap();
			batch.save_block(&substituted_block).unwrap();
			batch.save_spent_index(&substituted_hash, &[]).unwrap();
			// Bypass the normal key/hash invariant to model a misindexed record.
			batch
				.db
				.put_ser(&mwc_store::to_key(b'h', selected_hash), &substituted_head)
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			let mut extension = Extension::new(
				0,
				&mut txhashset,
				Tip::try_from_header(&selected_head).unwrap(),
			);
			let progress_calls = std::cell::Cell::new(0u64);
			let mut progress = |_, _| {
				progress_calls.set(progress_calls.get() + 1);
				Ok(())
			};

			let err = extension
				.rewind(&target, &batch, Some(&mut progress))
				.unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("Extension::rewind head header key/hash mismatch")
						&& msg.contains(&selected_hash.to_string())
						&& msg.contains(&substituted_hash.to_string())
			));
			assert_eq!(progress_calls.get(), 0);
			assert_eq!(extension.head().last_block_h, selected_hash);
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

			let err = extension.rewind(&fork, &batch, None).unwrap_err();
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

			let err = extension.rewind(&altered, &batch, None).unwrap_err();
			match err {
				Error::TxHashSetErr(msg) => {
					assert!(msg.contains("does not match canonical"), "{}", msg);
				}
				other => panic!("expected canonical header mismatch, got {:?}", other),
			}
			assert_eq!(extension.output_pmmr.size(), 1);
			assert_eq!(extension.head().last_block_h, head_hash);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn extension_rewind_preflights_same_hash_block_headers_before_mutation() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/extension_rewind_preflights_same_hash_block_headers_before_mutation";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let target = BlockHeader::default(0);
		let target_hash = target.hash(0).unwrap();

		let mut intermediate = BlockHeader::default(0);
		intermediate.height = 1;
		intermediate.prev_hash = target_hash;
		intermediate.pow.proof.nonces[0] = 1;
		let intermediate_hash = intermediate.hash(0).unwrap();

		let mut head = BlockHeader::default(0);
		head.height = 2;
		head.prev_hash = intermediate_hash;
		head.pow.proof.nonces[0] = 2;
		let head_hash = head.hash(0).unwrap();

		let mut altered_intermediate_block = Block::default(0);
		altered_intermediate_block.header = intermediate.clone();
		altered_intermediate_block.header.height = 99;
		assert_eq!(
			altered_intermediate_block.hash(0).unwrap(),
			intermediate_hash
		);
		assert_ne!(altered_intermediate_block.header, intermediate);

		let mut head_block = Block::default(0);
		head_block.header = head.clone();
		{
			// Deliberately bypass both normal ingestion and the ChainStore write
			// invariant to model raw database corruption under the proof-derived key.
			let batch = store.batch_write().unwrap();
			for header in [&target, &intermediate, &head] {
				batch.save_block_header(header).unwrap();
			}
			batch
				.db
				.put_ser(
					&mwc_store::to_key(b'b', intermediate_hash),
					&altered_intermediate_block,
				)
				.unwrap();
			batch.save_block(&head_block).unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			let mut extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&head).unwrap());
			let progress_calls = std::cell::Cell::new(0u64);
			let mut progress = |_, _| {
				progress_calls.set(progress_calls.get() + 1);
				Ok(())
			};

			let err = extension
				.rewind(&target, &batch, Some(&mut progress))
				.unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("Extension::rewind preflight")
						&& msg.contains("does not exactly match persisted ancestry header")
			));
			assert_eq!(progress_calls.get(), 0);
			assert_eq!(extension.head().last_block_h, head_hash);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn rewind_and_apply_fork_rejects_same_hash_block_header_before_body_rewind() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/rewind_and_apply_fork_rejects_same_hash_block_header_before_body_rewind";
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

		let fork_point = BlockHeader::default(0);
		let fork_point_tip = Tip::try_from_header(&fork_point).unwrap();
		let mut fork_header = BlockHeader::default(0);
		fork_header.height = 1;
		fork_header.prev_hash = fork_point.hash(0).unwrap();
		fork_header.pow.proof.nonces[0] = 1;

		header_pmmr.size = {
			let mut pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			pmmr.push(&fork_point).unwrap();
			pmmr.push(&fork_header).unwrap();
			pmmr.size()
		};

		let mut altered_fork_block = Block::default(0);
		altered_fork_block.header = fork_header.clone();
		altered_fork_block.header.prev_hash = Hash::from_vec(&[7; Hash::LEN]);
		assert_eq!(
			altered_fork_block.hash(0).unwrap(),
			fork_header.hash(0).unwrap()
		);
		assert_ne!(altered_fork_block.header, fork_header);

		{
			// Deliberately bypass both normal ingestion and the ChainStore write
			// invariant to model raw database corruption under the proof-derived key.
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&fork_point).unwrap();
			batch.save_block_header(&fork_header).unwrap();
			batch
				.db
				.put_ser(
					&mwc_store::to_key(b'b', fork_header.hash(0).unwrap()),
					&altered_fork_block,
				)
				.unwrap();
			batch.save_body_head(&fork_point_tip).unwrap();
			batch
				.save_header_head(&Tip::try_from_header(&fork_header).unwrap())
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			let mut extension = Extension::new(0, &mut txhashset, fork_point_tip);
			let pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			let mut header_extension =
				HeaderExtension::new(pmmr, Tip::try_from_header(&fork_header).unwrap());
			let mut pair = ExtensionPair {
				header_extension: &mut header_extension,
				extension: &mut extension,
			};

			let err = crate::pipe::rewind_and_apply_fork(0, &fork_header, &mut pair, &batch, &secp)
				.unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("rewind_and_apply_fork preflight")
						&& msg.contains("does not exactly match persisted ancestry header")
			));
			assert_eq!(pair.extension.head(), fork_point_tip);
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

			let err = extension.rewind(&fork, &batch, None).unwrap_err();
			assert_rewind_target_error(err);
			assert_eq!(extension.head().last_block_h, head_hash);
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn rewind_preflight_rejects_spent_cache_count_mismatch() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/rewind_preflight_rejects_spent_cache_count_mismatch";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let prev = BlockHeader::default(0);
		let prev_hash = prev.hash(0).unwrap();
		let mut header = BlockHeader::default(0);
		header.height = 1;
		header.prev_hash = prev_hash;
		header.pow.proof.nonces[0] = 1;
		let header_hash = header.hash(0).unwrap();
		save_block_headers(&store, &[&prev]);

		{
			let batch = store.batch_write().unwrap();
			batch
				.set_spent_commitment_record_index_complete(true)
				.unwrap();
			batch
				.save_spent_index(
					&header_hash,
					&[spent_cache_entry(secp.commit_value(1).unwrap(), 1, 0)],
				)
				.unwrap();
			batch.commit().unwrap();
		}

		let mut block = Block::default(0);
		block.header = header.clone();

		{
			let batch = store.batch_write().unwrap();
			let extension =
				Extension::new(0, &mut txhashset, Tip::try_from_header(&header).unwrap());
			let err = extension
				.prepare_authenticated_rewind_block(block, prev, &batch)
				.unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("rewind spent index")
						&& msg.contains("contains 1 positions for 0 inputs")
			));
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn rewind_preflight_authenticates_spent_index_position_and_height() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/rewind_preflight_authenticates_spent_index_position_and_height";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let spent_commit = secp.commit_value(1).unwrap();
		let other_commit = secp.commit_value(2).unwrap();
		let spent_output = OutputIdentifier::new(OutputFeatures::Plain, &spent_commit);
		let other_output = OutputIdentifier::new(OutputFeatures::Plain, &other_commit);
		let output_size = {
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			assert_eq!(output_pmmr.push(&spent_output).unwrap(), 0);
			assert_eq!(output_pmmr.push(&other_output).unwrap(), 1);
			output_pmmr.size()
		};
		txhashset.output_pmmr_h.size = output_size;
		let rproof_size = {
			let mut rproof_pmmr = PMMR::at(
				&mut txhashset.rproof_pmmr_h.backend,
				txhashset.rproof_pmmr_h.size,
			);
			assert_eq!(rproof_pmmr.push(&RangeProof::zero()).unwrap(), 0);
			assert_eq!(rproof_pmmr.push(&RangeProof::zero()).unwrap(), 1);
			rproof_pmmr.size()
		};
		txhashset.rproof_pmmr_h.size = rproof_size;
		assert_eq!(output_size, rproof_size);
		txhashset.output_pmmr_h.backend.sync().unwrap();
		txhashset.rproof_pmmr_h.backend.sync().unwrap();

		let genesis = BlockHeader::default(0);
		let genesis_hash = genesis.hash(0).unwrap();
		let mut output_one_header = BlockHeader::default(0);
		output_one_header.height = 1;
		output_one_header.prev_hash = genesis_hash;
		output_one_header.output_mmr_size = 1;
		output_one_header.pow.proof.nonces[0] = 1;
		let output_one_hash = output_one_header.hash(0).unwrap();
		let mut previous_header = BlockHeader::default(0);
		previous_header.height = 2;
		previous_header.prev_hash = output_one_hash;
		previous_header.output_mmr_size = output_size;
		previous_header.pow.proof.nonces[0] = 2;
		let previous_hash = previous_header.hash(0).unwrap();
		let mut header = BlockHeader::default(0);
		header.height = 3;
		header.prev_hash = previous_hash;
		header.output_mmr_size = output_size;
		header.pow.proof.nonces[0] = 3;
		let header_hash = header.hash(0).unwrap();
		let mut block = Block::default(0);
		block.header = header.clone();
		block.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, spent_commit)]);
		// Only the direct predecessor is needed. Authentication uses the exact spent
		// record and must not walk old header ancestry to reconstruct output heights.
		save_block_headers(&store, &[&previous_header]);

		let batch = store.batch_write().unwrap();
		let extension = Extension::new(0, &mut txhashset, Tip::try_from_header(&header).unwrap());
		batch
			.set_spent_commitment_record_index_complete(true)
			.unwrap();
		batch
			.save_spent_commitments(
				&spent_commit,
				SpentCommitmentRecord {
					spending_block: HashHeight {
						hash: header_hash,
						height: header.height,
					},
					spent_output: CommitPos { pos: 1, height: 1 },
				},
			)
			.unwrap();
		batch
			.save_spent_commitments(
				&other_commit,
				SpentCommitmentRecord {
					spending_block: HashHeight {
						hash: header_hash,
						height: header.height,
					},
					spent_output: CommitPos { pos: 2, height: 2 },
				},
			)
			.unwrap();

		batch
			.save_spent_index(&header_hash, &[spent_cache_entry(spent_commit, 2, 0)])
			.unwrap();
		let err = extension
			.prepare_authenticated_rewind_block(block.clone(), previous_header.clone(), &batch)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("has no output matching input")
		));

		batch
			.save_spent_index(&header_hash, &[spent_cache_entry(spent_commit, 1, 7)])
			.unwrap();
		let err = extension
			.prepare_authenticated_rewind_block(block.clone(), previous_header.clone(), &batch)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("records output position 1 at height 7 above predecessor height 2")
		));

		batch
			.save_spent_index(&header_hash, &[spent_cache_entry(spent_commit, 1, 0)])
			.unwrap();
		let err = extension
			.prepare_authenticated_rewind_block(block.clone(), previous_header.clone(), &batch)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("records commitment")
					&& msg.contains("at output position 1 and height 0")
					&& msg.contains("authenticated spent commitment record identifies position 1 and height 1")
		));

		batch
			.save_spent_index(&header_hash, &[spent_cache_entry(spent_commit, 1, 1)])
			.unwrap();
		let plan = extension
			.prepare_authenticated_rewind_block(block.clone(), previous_header.clone(), &batch)
			.unwrap();
		assert_eq!(
			plan.spent_outputs,
			vec![spent_cache_entry(spent_commit, 1, 1)]
		);
		assert!(!plan.persist_spent_index);

		block.body.inputs = Inputs::FeaturesAndCommit(vec![
			Input::new(OutputFeatures::Plain, spent_commit),
			Input::new(OutputFeatures::Plain, other_commit),
		]);
		batch
			.save_spent_index(
				&header_hash,
				&[
					spent_cache_entry(spent_commit, 1, 2),
					spent_cache_entry(other_commit, 2, 1),
				],
			)
			.unwrap();
		let err = extension
			.prepare_authenticated_rewind_block(block, previous_header, &batch)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("records commitment")
					&& msg.contains("at output position 1 and height 2")
					&& msg.contains("authenticated spent commitment record identifies position 1 and height 1")
		));

		drop(extension);
		drop(batch);
		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn rewind_preflight_rejects_older_reused_commitment_occurrence() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/rewind_preflight_rejects_older_reused_commitment_occurrence";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let reused_commit = secp.commit_value(1).unwrap();
		let reused_output = OutputIdentifier::new(OutputFeatures::Plain, &reused_commit);
		let output_size = {
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			assert_eq!(output_pmmr.push(&reused_output).unwrap(), 0);
			assert_eq!(output_pmmr.push(&reused_output).unwrap(), 1);
			output_pmmr.size()
		};
		txhashset.output_pmmr_h.size = output_size;
		let rproof_size = {
			let mut rproof_pmmr = PMMR::at(
				&mut txhashset.rproof_pmmr_h.backend,
				txhashset.rproof_pmmr_h.size,
			);
			assert_eq!(rproof_pmmr.push(&RangeProof::zero()).unwrap(), 0);
			assert_eq!(rproof_pmmr.push(&RangeProof::zero()).unwrap(), 1);
			rproof_pmmr.size()
		};
		txhashset.rproof_pmmr_h.size = rproof_size;
		assert_eq!(output_size, rproof_size);
		txhashset.output_pmmr_h.backend.sync().unwrap();
		txhashset.rproof_pmmr_h.backend.sync().unwrap();

		let genesis = BlockHeader::default(0);
		let genesis_hash = genesis.hash(0).unwrap();
		let mut previous_header = BlockHeader::default(0);
		previous_header.height = 1;
		previous_header.prev_hash = genesis_hash;
		previous_header.output_mmr_size = output_size;
		previous_header.pow.proof.nonces[0] = 1;
		let previous_hash = previous_header.hash(0).unwrap();
		let mut header = BlockHeader::default(0);
		header.height = 2;
		header.prev_hash = previous_hash;
		header.output_mmr_size = output_size;
		header.pow.proof.nonces[0] = 2;
		let header_hash = header.hash(0).unwrap();
		let mut block = Block::default(0);
		block.header = header.clone();
		block.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, reused_commit)]);
		save_block_headers(&store, &[&genesis, &previous_header]);

		let batch = store.batch_write().unwrap();
		let extension = Extension::new(0, &mut txhashset, Tip::try_from_header(&header).unwrap());
		batch
			.set_spent_commitment_record_index_complete(true)
			.unwrap();
		batch
			.save_spent_commitments(
				&reused_commit,
				SpentCommitmentRecord {
					spending_block: HashHeight {
						hash: header_hash,
						height: header.height,
					},
					spent_output: CommitPos { pos: 2, height: 1 },
				},
			)
			.unwrap();
		batch
			.save_spent_index(&header_hash, &[spent_cache_entry(reused_commit, 1, 0)])
			.unwrap();
		let err = extension
			.prepare_authenticated_rewind_block(block.clone(), previous_header.clone(), &batch)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("records input commitment")
					&& msg.contains("at position 1")
					&& msg.contains("authenticated spent commitment record identifies position 2")
		));

		batch
			.save_spent_index(&header_hash, &[spent_cache_entry(reused_commit, 2, 1)])
			.unwrap();
		let plan = extension
			.prepare_authenticated_rewind_block(block, previous_header, &batch)
			.unwrap();
		assert_eq!(
			plan.spent_outputs,
			vec![spent_cache_entry(reused_commit, 2, 1)]
		);

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
	fn compact_bitmap_rejects_large_cardinality_before_expansion() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let block = Block::default(0);
		let mut bitmap = Bitmap::new();
		bitmap.add_range(..=u32::MAX);
		assert_eq!(bitmap.cardinality(), 1u64 << 32);

		let err = checked_bitmap_positions_for_inputs("compact input bitmap", &block, &bitmap)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(ref msg)
				if msg.contains("contains 4294967296 positions for 0 inputs")
		));
	}

	#[test]
	fn compact_rejects_incomplete_or_incorrect_spent_index_before_rewriting_pmmrs() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/compact_rejects_incomplete_or_incorrect_spent_index_before_rewriting_pmmrs";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		let spent_commit = secp.commit_value(1).unwrap();
		let other_commit = secp.commit_value(2).unwrap();
		let spent_output = OutputIdentifier::new(OutputFeatures::Plain, &spent_commit);
		let other_output = OutputIdentifier::new(OutputFeatures::Plain, &other_commit);
		let output_size = {
			let mut output_pmmr = PMMR::at(
				&mut txhashset.output_pmmr_h.backend,
				txhashset.output_pmmr_h.size,
			);
			assert_eq!(output_pmmr.push(&spent_output).unwrap(), 0);
			assert_eq!(output_pmmr.push(&other_output).unwrap(), 1);
			output_pmmr.size()
		};
		txhashset.output_pmmr_h.size = output_size;
		let rproof_size = {
			let mut rproof_pmmr = PMMR::at(
				&mut txhashset.rproof_pmmr_h.backend,
				txhashset.rproof_pmmr_h.size,
			);
			assert_eq!(rproof_pmmr.push(&RangeProof::zero()).unwrap(), 0);
			assert_eq!(rproof_pmmr.push(&RangeProof::zero()).unwrap(), 1);
			rproof_pmmr.size()
		};
		txhashset.rproof_pmmr_h.size = rproof_size;
		assert_eq!(output_size, rproof_size);
		txhashset.output_pmmr_h.backend.sync().unwrap();
		txhashset.rproof_pmmr_h.backend.sync().unwrap();

		let mut horizon = BlockHeader::default(0);
		horizon.output_mmr_size = output_size;
		let horizon_hash = horizon.hash(0).unwrap();
		let mut head = horizon.clone();
		head.height = 1;
		head.prev_hash = horizon_hash;
		head.pow.proof.nonces[0] = head.pow.proof.nonces[0].wrapping_add(1);
		let head_hash = head.hash(0).unwrap();
		assert_ne!(head_hash, horizon_hash);

		let mut head_block = Block::default(0);
		head_block.header = head.clone();
		head_block.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, spent_commit)]);
		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&horizon).unwrap();
			batch.save_block_header(&head).unwrap();
			batch.save_block(&head_block).unwrap();
			batch
				.set_spent_commitment_record_index_complete(true)
				.unwrap();
			batch
				.save_spent_commitments(
					&spent_commit,
					SpentCommitmentRecord {
						spending_block: HashHeight {
							hash: head_hash,
							height: head.height,
						},
						spent_output: CommitPos { pos: 1, height: 0 },
					},
				)
				.unwrap();
			batch
				.save_body_head(&Tip::try_from_header(&head).unwrap())
				.unwrap();
			// This is syntactically valid cache data, but it omits the block's input.
			batch.save_spent_index(&head_hash, &[]).unwrap();
			batch.commit().unwrap();
		}

		let output_data_size = txhashset.output_pmmr_h.backend.data_size().unwrap();
		let rproof_data_size = txhashset.rproof_pmmr_h.backend.data_size().unwrap();
		let batch = store.batch_read().unwrap();
		let err = txhashset.compact(&horizon, &batch).unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(ref msg)
				if msg.contains("contains 0 positions for 1 inputs")
		));
		assert_eq!(
			txhashset.output_pmmr_h.backend.data_size().unwrap(),
			output_data_size
		);
		assert_eq!(
			txhashset.rproof_pmmr_h.backend.data_size().unwrap(),
			rproof_data_size
		);

		drop(batch);
		{
			let batch = store.batch_write().unwrap();
			// The count is now correct, but position 2 is the other output and does
			// not match the input spent by this block.
			batch
				.save_spent_index(&head_hash, &[spent_cache_entry(spent_commit, 2, 0)])
				.unwrap();
			batch.commit().unwrap();
		}
		let batch = store.batch_read().unwrap();
		let err = txhashset.compact(&horizon, &batch).unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(ref msg)
				if msg.contains("has no output matching input")
		));
		assert_eq!(
			txhashset.output_pmmr_h.backend.data_size().unwrap(),
			output_data_size
		);
		assert_eq!(
			txhashset.rproof_pmmr_h.backend.data_size().unwrap(),
			rproof_data_size
		);

		drop(batch);
		drop(txhashset);
		drop(store);
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
		let err = walk_input_pos_to_rewind(&horizon, &head, &batch, |_, _, _| Ok(())).unwrap_err();
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
		head.pow.proof.nonces[0] = 1;
		let head_hash = head.hash(0).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&prev).unwrap();
			batch.save_spent_index(&head_hash, &[]).unwrap();
			batch.commit().unwrap();
		}

		let batch = store.batch_read().unwrap();
		let err = walk_input_pos_to_rewind(&horizon, &head, &batch, |_, _, _| Ok(())).unwrap_err();
		match err {
			Error::InvalidPersistedChainState(msg) => {
				assert!(
					msg.contains("input positions to rewind ancestry"),
					"{}",
					msg
				);
				assert!(msg.contains("at height 0, found height 1"), "{}", msg);
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
		let err = walk_input_pos_to_rewind(&horizon, &head, &batch, |_, _, _| Ok(())).unwrap_err();
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
		let err = walk_input_pos_to_rewind(&target, &head, &batch, |_, _, _| Ok(())).unwrap_err();
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
		let err = walk_input_pos_to_rewind(&target, &head, &batch, |_, _, _| Ok(())).unwrap_err();
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
	fn validate_rejects_output_rangeproof_leaf_set_divergence() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/validate_rejects_output_rangeproof_leaf_set_divergence";
		let _ = fs::remove_dir_all(chain_dir);
		let store = Arc::new(ChainStore::new(0, chain_dir).unwrap());
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut txhashset =
			TxHashSet::open(chain_dir.to_string(), store.clone(), None, &secp).unwrap();

		{
			let mut extension = Extension::new(0, &mut txhashset, Tip::default());
			let commit = secp.commit_value(1).unwrap();
			let output = OutputIdentifier::new(OutputFeatures::Plain, &commit);
			let proof = RangeProof::zero();
			assert_eq!(extension.output_pmmr.push(&output).unwrap(), 0);
			assert_eq!(extension.rproof_pmmr.push(&proof).unwrap(), 0);

			let roots = extension.roots().unwrap();
			let mut header = BlockHeader::default(0);
			header.output_mmr_size = roots.output_mmr_size;
			header.kernel_mmr_size = roots.kernel_mmr_size;
			header.output_root = roots.output_root;
			header.range_proof_root = roots.rproof_root;
			header.kernel_root = roots.kernel_root;

			assert!(extension.rproof_pmmr.prune(0).unwrap());
			assert!(extension.validate_roots(&header).is_ok());
			assert!(extension.validate_sizes(&header).is_ok());

			let err = extension
				.validate(&header, true, None, &header, None, &secp)
				.unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("no matching rangeproof leaf")
			));
		}

		drop(txhashset);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn validate_kernel_sums_rejects_matching_missing_utxo_leaves() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = "target/validate_kernel_sums_rejects_matching_missing_utxo_leaves";
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

			extension
				.validate(&genesis.header, true, None, &genesis.header, None, &secp)
				.unwrap();
			assert!(extension.output_pmmr.prune(0).unwrap());
			assert!(extension.rproof_pmmr.prune(0).unwrap());
			assert!(extension.validate_roots(&genesis.header).is_ok());
			assert!(extension.validate_sizes(&genesis.header).is_ok());

			let err = extension
				.validate(&genesis.header, true, None, &genesis.header, None, &secp)
				.unwrap_err();
			assert!(matches!(err, Error::Committed(_)));
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
				ext.extension.rewind(&archive_header, batch, None)
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
