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

use chrono::prelude::{DateTime, Utc};

use crate::core::core::hash::{Hash, Hashed, ZERO_HASH};
use crate::core::core::{Block, BlockHeader};
use crate::core::pow::Difficulty;
use crate::core::ser::{self, Readable, Reader, Writeable, Writer};
use crate::error::Error;
use crate::util::{RwLock, RwLockWriteGuard};

bitflags! {
/// Options for block validation
	pub struct Options: u32 {
		/// No flags
		const NONE = 0b0000_0000;
		/// Runs without checking the Proof of Work, mostly to make testing easier.
		const SKIP_POW = 0b0000_0001;
		/// Adds block while in syncing mode.
		const SYNC = 0b0000_0010;
		/// Block validation on a block we mined ourselves
		const MINE = 0b0000_0100;
	}
}

/// We receive 512 headers from a peer in a batch. Let's use it for planning.
pub const HEADERS_PER_BATCH: u32 = 512;

/// Various status sync can be in, whether it's fast sync or archival.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
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
	ValidatingKernelsHistory,
	/// Setting up before validation
	TxHashsetHeadersValidation {
		/// number of 'headers' for which kernels have been checked
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

/// Stats for TxHashsetDownload stage
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
pub struct TxHashsetDownloadStats {
	/// when download started
	pub start_time: DateTime<Utc>,
	/// time of the previous update
	pub prev_update_time: DateTime<Utc>,
	/// time of the latest update
	pub update_time: DateTime<Utc>,
	/// size of the previous chunk
	pub prev_downloaded_size: u64,
	/// size of the the latest chunk
	pub downloaded_size: u64,
	/// downloaded since the start
	pub total_size: u64,
}

impl Default for TxHashsetDownloadStats {
	fn default() -> Self {
		TxHashsetDownloadStats {
			start_time: Utc::now(),
			update_time: Utc::now(),
			prev_update_time: Utc::now(),
			prev_downloaded_size: 0,
			downloaded_size: 0,
			total_size: 0,
		}
	}
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
		match *self.current.read() {
			SyncStatus::NoSync => false,
			SyncStatus::BodySync {
				archive_height: _,
				current_height,
				highest_height,
			} => current_height + 10 < highest_height,
			_ => true,
		}
	}

	/// Check if headers download process is done. In this case it make sense to request more top headers
	pub fn are_headers_done(&self) -> bool {
		match *self.current.read() {
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

	/// Current syncing status
	pub fn status(&self) -> SyncStatus {
		*self.current.read()
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
		debug!("{}", self.get_validate_info_str(header));

		if header.output_root != self.output_root {
			Err(Error::InvalidRoot(format!(
				"Failed Output root validation. {}",
				self.get_validate_info_str(header)
			)))
		} else if header.range_proof_root != self.rproof_root {
			Err(Error::InvalidRoot(format!(
				"Failed Range Proof root validation. {}",
				self.get_validate_info_str(header)
			)))
		} else if header.kernel_root != self.kernel_root {
			Err(Error::InvalidRoot(format!(
				"Failed Kernel root validation. {}",
				self.get_validate_info_str(header)
			)))
		} else {
			Ok(())
		}
	}

	fn get_validate_info_str(&self, header: &BlockHeader) -> String {
		format!("Validating at height {}. Output MMR size: {}  Kernel MMR size: {}  .validate roots: {} at {}, Outputs roots {} vs. {}, sz {} vs {}, Range Proof roots {} vs {}, sz {} vs {}, Kernel Roots {} vs {}, sz {} vs {}",
				header.height, header.output_mmr_size, header.kernel_mmr_size,
				header.hash(),
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
		)
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
	/// Creates a new tip based on provided header.
	pub fn from_header(header: &BlockHeader) -> Tip {
		header.into()
	}
}

impl From<BlockHeader> for Tip {
	fn from(header: BlockHeader) -> Self {
		Self::from(&header)
	}
}

impl From<&BlockHeader> for Tip {
	fn from(header: &BlockHeader) -> Self {
		Tip {
			height: header.height,
			last_block_h: header.hash(),
			prev_block_h: header.prev_hash,
			total_difficulty: header.total_difficulty(),
		}
	}
}

impl Hashed for Tip {
	/// The hash of the underlying block.
	fn hash(&self) -> Hash {
		self.last_block_h
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
	fn block_accepted(&self, block: &Block, status: BlockStatus, opts: Options);
}

/// Dummy adapter used as a placeholder for real implementations
pub struct NoopAdapter {}

impl ChainAdapter for NoopAdapter {
	fn block_accepted(&self, _b: &Block, _status: BlockStatus, _opts: Options) {}
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
