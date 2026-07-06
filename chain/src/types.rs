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

//! Base types that the block chain pipeline requires.

use mwc_crates::bitflags::bitflags;
use mwc_crates::serde::{self, Deserialize, Serialize};

use crate::error::Error;
use mwc_core::core::hash::{Hash, Hashed, ZERO_HASH};
use mwc_core::core::{Block, BlockHeader};
use mwc_core::pow::Difficulty;
use mwc_core::ser::{self, Readable, Reader, Writeable, Writer};
use mwc_crates::log::{debug, info};
use mwc_crates::parking_lot::{RwLock, RwLockWriteGuard};
use mwc_crates::secp::Secp256k1;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

bitflags! {
	/// Options for block validation
	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
	pub struct Options: u32 {
		/// No flags
		const NONE = 0b0000_0000;
		/// Runs without checking the Proof of Work.
		/// This is accepted only for cfg(test) builds or non-production chain modes.
		#[cfg(test)]
		const SKIP_POW = 0b0000_0001;
		/// Adds block while in syncing mode.
		const SYNC = 0b0000_0010;
		/// Block validation on a block we mined ourselves
		const MINE = 0b0000_0100;
	}
}

/// We receive 512 headers from a peer in a batch. Let's use it for planning.
pub const HEADERS_PER_BATCH: u32 = 512;
pub(crate) const SYNC_STATUS_UPDATE_INTERVAL_MS: u64 = 200;

/// Helper for sync phases that can produce progress faster than the UI can use.
/// Using throttle to minimize unneeded updates
pub(crate) struct SyncStatusUpdateThrottle {
	start: Instant,
	next_update_ms: AtomicU64,
}

impl SyncStatusUpdateThrottle {
	pub(crate) fn new() -> SyncStatusUpdateThrottle {
		SyncStatusUpdateThrottle {
			start: Instant::now(),
			next_update_ms: AtomicU64::new(SYNC_STATUS_UPDATE_INTERVAL_MS),
		}
	}

	pub(crate) fn should_update(&self, force: bool) -> bool {
		if force {
			return true;
		}

		let elapsed_ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
		let mut next_update_ms = self.next_update_ms.load(Ordering::Relaxed);
		loop {
			if elapsed_ms < next_update_ms {
				return false;
			}

			match self.next_update_ms.compare_exchange_weak(
				next_update_ms,
				elapsed_ms.saturating_add(SYNC_STATUS_UPDATE_INTERVAL_MS),
				Ordering::Relaxed,
				Ordering::Relaxed,
			) {
				Ok(_) => return true,
				Err(current) => next_update_ms = current,
			}
		}
	}
}

/// Progress steps for txhashset state validation before full rangeproof and
/// kernel signature checks take over.
pub const TXHASHSET_STATE_VALIDATION_STEPS: u64 = 4;

/// The txhashset state validation sub-stage currently running.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(crate = "serde")]
pub enum TxHashsetStateValidationStage {
	/// Rewinding the writeable txhashset extension to the PIBD archive header.
	Rewind,
	/// Validating internal MMR hashes and sums.
	ValidateMmrs,
	/// Validating MMR roots against the archive header.
	ValidateRoots,
	/// Validating MMR sizes against the archive header.
	ValidateSizes,
	/// Validating the txhashset kernel sums.
	ValidateKernelSums,
}

impl TxHashsetStateValidationStage {
	/// Stable status name for API consumers.
	pub fn api_name(self) -> &'static str {
		match self {
			TxHashsetStateValidationStage::Rewind => "rewind",
			TxHashsetStateValidationStage::ValidateMmrs => "validate_mmrs",
			TxHashsetStateValidationStage::ValidateRoots => "validate_roots",
			TxHashsetStateValidationStage::ValidateSizes => "validate_sizes",
			TxHashsetStateValidationStage::ValidateKernelSums => "validate_kernel_sums",
		}
	}

	/// Human-readable label for local status displays.
	pub fn display_name(self) -> &'static str {
		match self {
			TxHashsetStateValidationStage::Rewind => "writeable rewind",
			TxHashsetStateValidationStage::ValidateMmrs => "MMR validation",
			TxHashsetStateValidationStage::ValidateRoots => "root validation",
			TxHashsetStateValidationStage::ValidateSizes => "size validation",
			TxHashsetStateValidationStage::ValidateKernelSums => "kernel sums",
		}
	}

	/// Unit name used by status displays for the progress counters.
	pub fn progress_unit(self) -> &'static str {
		match self {
			TxHashsetStateValidationStage::Rewind => "blocks",
			TxHashsetStateValidationStage::ValidateKernelSums => "commitments",
			_ => "steps",
		}
	}
}

/// Various status sync can be in, whether it's fast sync or archival.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(crate = "serde")]
pub enum SyncStatus {
	/// Initial State (we do not yet know if we are/should be syncing)
	Initial,
	/// Not syncing
	NoSync,
	/// Not enough peers to do anything yet, boolean indicates whether
	/// we should wait at all or ignore and start ASAP
	AwaitingPeers,
	/// Downloading block header hashes
	HeaderHashSync {
		/// total number of blocks
		completed_blocks: usize,
		/// total number of leaves required by archive header
		total_blocks: usize,
	},
	/// Downloading block headers below archive height
	HeaderSync {
		/// current sync head
		current_height: u64,
		/// height of the most advanced peer
		archive_height: u64,
	},
	/// Performing PIBD reconstruction of txhashset
	/// If PIBD syncer determines there's not enough
	/// PIBD peers to continue, then move on to TxHashsetDownload state
	TxHashsetPibd {
		/// total number of recieved segments
		recieved_segments: usize,
		/// total number of segments required
		total_segments: usize,
	},
	/// Validating kernels history
	ValidatingKernelsHistory {
		/// number of headers for which kernel history has been checked
		headers: u64,
		/// headers total
		headers_total: u64,
	},
	/// Kernels position validation phase
	TxHashsetKernelsPosValidation {
		/// kernel position portion
		kernel_pos: u64,
		/// total kernel position
		kernel_pos_total: u64,
	},
	/// Building the output commitment to position/height index.
	TxHashsetOutputPosIndexBuild {
		/// outputs processed
		outputs: u64,
		/// outputs in total
		outputs_total: u64,
	},
	/// Building the kernel excess to position/height index.
	TxHashsetKernelPosIndexBuild {
		/// kernels processed
		kernels: u64,
		/// kernels in total
		kernels_total: u64,
	},
	/// Validating txhashset state before full rangeproof and kernel checks.
	TxHashsetStateValidation {
		/// current validation sub-stage
		stage: TxHashsetStateValidationStage,
		/// current progress within the sub-stage
		current: u64,
		/// total progress within the sub-stage
		total: u64,
	},
	/// Validating the range proofs
	TxHashsetRangeProofsValidation {
		/// range proofs validated
		rproofs: u64,
		/// range proofs in total
		rproofs_total: u64,
	},
	/// Validating the kernels
	TxHashsetKernelsValidation {
		/// kernels validated
		kernels: u64,
		/// kernels in total
		kernels_total: u64,
	},
	/// Downloading blocks above the archive (horizon) height
	BodySync {
		/// Archive header height. Starting height to download the blocks (if running in archive_mode, must be 0)
		archive_height: u64,
		/// current node height
		current_height: u64,
		/// height of the most advanced peer
		highest_height: u64,
	},
	/// Shutdown
	Shutdown,
}

/// Current sync state. Encapsulates the current SyncStatus.
pub struct SyncState {
	current: RwLock<SyncStatus>,
}

impl SyncState {
	/// Return a new SyncState initialize to NoSync
	pub fn new() -> SyncState {
		SyncState {
			current: RwLock::new(SyncStatus::Initial),
		}
	}

	/// Reset sync status to NoSync.
	pub fn reset(&self) {
		self.update(SyncStatus::NoSync);
	}

	/// Whether the current state matches any active syncing operation.
	/// Note: This includes our "initial" state.
	pub fn is_syncing(&self) -> bool {
		match *self.current.read_recursive() {
			SyncStatus::NoSync => false,
			SyncStatus::BodySync {
				archive_height: _,
				current_height,
				highest_height,
			} => highest_height.saturating_sub(current_height) > 10,
			_ => true,
		}
	}

	/// Check if headers download process is done. In this case it make sense to request more top headers
	pub fn are_headers_done(&self) -> bool {
		match *self.current.read_recursive() {
			SyncStatus::Initial => false,
			SyncStatus::HeaderHashSync {
				completed_blocks: _,
				total_blocks: _,
			} => false,
			SyncStatus::HeaderSync {
				current_height: _,
				archive_height: _,
			} => false,
			_ => true,
		}
	}

	/// Whether the node is in a long txhashset/header PMMR validation phase.
	pub fn is_txhashset_validation(&self) -> bool {
		matches!(
			*self.current.read_recursive(),
			SyncStatus::ValidatingKernelsHistory { .. }
				| SyncStatus::TxHashsetKernelsPosValidation { .. }
				| SyncStatus::TxHashsetOutputPosIndexBuild { .. }
				| SyncStatus::TxHashsetKernelPosIndexBuild { .. }
				| SyncStatus::TxHashsetStateValidation { .. }
				| SyncStatus::TxHashsetRangeProofsValidation { .. }
				| SyncStatus::TxHashsetKernelsValidation { .. }
		)
	}

	/// Current syncing status
	pub fn status(&self) -> SyncStatus {
		*self.current.read_recursive()
	}

	/// Update the syncing status
	pub fn update(&self, new_status: SyncStatus) -> bool {
		let status = self.current.write();
		self.update_with_guard(new_status, status)
	}

	fn update_with_guard(
		&self,
		new_status: SyncStatus,
		mut status: RwLockWriteGuard<SyncStatus>,
	) -> bool {
		if *status == new_status {
			return false;
		}
		// Sync status is needed for QT wallet sync tracking. Please keep this message as info
		info!("mwc-node sync status: {:?}", new_status);
		*status = new_status;
		true
	}

	/// Update the syncing status if predicate f is satisfied
	pub fn update_if<F>(&self, new_status: SyncStatus, f: F) -> bool
	where
		F: Fn(SyncStatus) -> bool,
	{
		let status = self.current.write();
		if f(*status) {
			self.update_with_guard(new_status, status)
		} else {
			false
		}
	}
}

/// A helper for the various txhashset MMR roots.
#[derive(Debug)]
pub struct TxHashSetRoots {
	/// Output roots
	pub output_root: Hash,
	/// Output mmr size
	pub output_mmr_size: u64,
	/// Range Proof root
	pub rproof_root: Hash,
	/// Range Proof mmr size
	pub rproof_mmr_size: u64,
	/// Kernel root
	pub kernel_root: Hash,
	/// Kernel mmr size
	pub kernel_mmr_size: u64,
}

impl TxHashSetRoots {
	/// Validate roots against the provided block header.
	pub fn validate(&self, header: &BlockHeader) -> Result<(), Error> {
		let validate_info = self.get_validate_info_str(header)?;
		debug!("{}", validate_info);

		if header.output_root != self.output_root {
			Err(Error::InvalidRoot(format!(
				"Failed Output root validation. {}",
				validate_info
			)))
		} else if header.range_proof_root != self.rproof_root {
			Err(Error::InvalidRoot(format!(
				"Failed Range Proof root validation. {}",
				validate_info
			)))
		} else if header.kernel_root != self.kernel_root {
			Err(Error::InvalidRoot(format!(
				"Failed Kernel root validation. {}",
				validate_info
			)))
		} else {
			Ok(())
		}
	}

	fn get_validate_info_str(&self, header: &BlockHeader) -> Result<String, Error> {
		Ok(format!(
			"Validating at height {}. Output MMR size: {}  Kernel MMR size: {}  .validate roots: {} at {}, Outputs roots {} vs. {}, sz {} vs {}, Range Proof roots {} vs {}, sz {} vs {}, Kernel Roots {} vs {}, sz {} vs {}",
			header.height,
			header.output_mmr_size,
			header.kernel_mmr_size,
			header.hash(header.pow.proof.context_id)?,
			header.height,
			header.output_root,
			self.output_root,
			header.output_mmr_size,
			self.output_mmr_size,
			header.range_proof_root,
			self.rproof_root,
			header.output_mmr_size,
			self.rproof_mmr_size,
			header.kernel_root,
			self.kernel_root,
			header.kernel_mmr_size,
			self.kernel_mmr_size,
		))
	}
}

/// Minimal struct representing a known MMR position and associated block height.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CommitPos {
	/// MMR position
	pub pos: u64,
	/// Block height
	pub height: u64,
}

impl Readable for CommitPos {
	fn read<R: Reader>(reader: &mut R) -> Result<CommitPos, ser::Error> {
		let pos = reader.read_u64()?;
		let height = reader.read_u64()?;
		Ok(CommitPos { pos, height })
	}
}

impl Writeable for CommitPos {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.pos)?;
		writer.write_u64(self.height)?;
		Ok(())
	}
}

/// Minimal struct representing a known kernel MMR position and associated block height.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct KernelPos {
	/// Kernel MMR position
	pub pos: u64,
	/// Block height
	pub height: u64,
}

impl Readable for KernelPos {
	fn read<R: Reader>(reader: &mut R) -> Result<KernelPos, ser::Error> {
		let pos = reader.read_u64()?;
		let height = reader.read_u64()?;
		Ok(KernelPos { pos, height })
	}
}

impl Writeable for KernelPos {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.pos)?;
		writer.write_u64(self.height)?;
		Ok(())
	}
}

/// Minimal struct representing a block header hash and height
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HashHeight {
	/// hasher
	pub hash: Hash,
	/// Block height
	pub height: u64,
}

impl Readable for HashHeight {
	fn read<R: Reader>(reader: &mut R) -> Result<HashHeight, ser::Error> {
		let hash = Hash::read(reader)?;
		let height = reader.read_u64()?;

		Ok(HashHeight { hash, height })
	}
}

impl Writeable for HashHeight {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.hash.write(writer)?;
		writer.write_u64(self.height)?;
		Ok(())
	}
}

/// The tip of a fork. A handle to the fork ancestry from its leaf in the
/// blockchain tree. References the max height and the latest and previous
/// blocks
/// for convenience and the total difficulty.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(crate = "serde")]
pub struct Tip {
	/// Height of the tip (max height of the fork)
	pub height: u64,
	/// Last block pushed to the fork
	pub last_block_h: Hash,
	/// Previous block
	pub prev_block_h: Hash,
	/// Total difficulty accumulated on that fork
	pub total_difficulty: Difficulty,
}

impl Tip {
	/// Creates a new tip based on provided header, propagating hash errors.
	pub fn try_from_header(header: &BlockHeader) -> Result<Tip, Error> {
		Ok(Tip {
			height: header.height,
			last_block_h: header.hash(header.pow.proof.context_id)?,
			prev_block_h: header.prev_hash,
			total_difficulty: header.total_difficulty(),
		})
	}
}

impl Hashed for Tip {
	/// The hash of the underlying block.
	fn hash(&self, _context_id: u32) -> Result<Hash, std::io::Error> {
		Ok(self.last_block_h)
	}
}

impl Default for Tip {
	fn default() -> Self {
		Tip {
			height: 0,
			last_block_h: ZERO_HASH,
			prev_block_h: ZERO_HASH,
			total_difficulty: Difficulty::min(),
		}
	}
}

/// Serialization of a tip, required to save to datastore.
impl ser::Writeable for Tip {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.height)?;
		writer.write_fixed_bytes(&self.last_block_h)?;
		writer.write_fixed_bytes(&self.prev_block_h)?;
		self.total_difficulty.write(writer)
	}
}

impl ser::Readable for Tip {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Tip, ser::Error> {
		let height = reader.read_u64()?;
		let last = Hash::read(reader)?;
		let prev = Hash::read(reader)?;
		let diff = Difficulty::read(reader)?;
		Ok(Tip {
			height: height,
			last_block_h: last,
			prev_block_h: prev,
			total_difficulty: diff,
		})
	}
}

/// Bridge between the chain pipeline and the rest of the system. Handles
/// downstream processing of valid blocks by the rest of the system, most
/// importantly the broadcasting of blocks to our peers.
pub trait ChainAdapter {
	/// The blockchain pipeline has accepted this block as valid and added
	/// it to our chain.
	fn block_accepted(
		&self,
		secp: &mut Secp256k1,
		block: &Block,
		status: BlockStatus,
		opts: Options,
	);

	/// A sourced block failed validation. The source peers are string encoded
	/// to avoid coupling chain internals to p2p address types.
	fn block_rejected(&self, _hash: &Hash, _source_peers: &HashSet<String>, _err: &Error) {}
}

/// Dummy adapter used as a placeholder for real implementations
pub struct NoopAdapter {}

impl ChainAdapter for NoopAdapter {
	fn block_accepted(
		&self,
		_secp: &mut Secp256k1,
		_b: &Block,
		_status: BlockStatus,
		_opts: Options,
	) {
	}
}

/// Status of an accepted block.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BlockStatus {
	/// Block is the "next" block, updating the chain head.
	Next {
		/// Previous block (previous chain head).
		prev: Tip,
	},
	/// Block does not update the chain head and is a fork.
	Fork {
		/// Previous block on this fork.
		prev: Tip,
		/// Current chain head.
		head: Tip,
		/// Fork point for rewind.
		fork_point: Tip,
	},
	/// Block updates the chain head via a (potentially disruptive) "reorg".
	/// Previous block was not our previous chain head.
	Reorg {
		/// Previous block on this fork.
		prev: Tip,
		/// Previous chain head.
		prev_head: Tip,
		/// Fork point for rewind.
		fork_point: Tip,
	},
}

impl BlockStatus {
	/// Is this the "next" block?
	pub fn is_next(&self) -> bool {
		match *self {
			BlockStatus::Next { .. } => true,
			_ => false,
		}
	}

	/// Is this block a "reorg"?
	pub fn is_reorg(&self) -> bool {
		match *self {
			BlockStatus::Reorg { .. } => true,
			_ => false,
		}
	}
}
