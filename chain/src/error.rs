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

//! Error types for chain
use mwc_core::core;
use mwc_core::core::hash::Hash;
use mwc_core::core::pmmr::segment;
use mwc_core::core::{block, committed, transaction};
use mwc_core::ser;
use mwc_core::{consensus, pow};
use mwc_crates::secp;
use mwc_crates::secp::pedersen::Commitment;
use std::io;

/// Chain error definitions
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// The block doesn't fit anywhere in our chain
	#[error("Block is unfit: {0}")]
	Unfit(String),
	/// Special case of orphan blocks
	#[error("Orphan, {0}")]
	Orphan(String),
	/// Difficulty is too low either compared to ours or the block PoW hash
	#[error("Difficulty is too low compared to ours or the block PoW hash")]
	DifficultyTooLow,
	/// Addition of difficulties on all previous block is wrong
	#[error("Addition of difficulties on all previous blocks is wrong")]
	WrongTotalDifficulty,
	/// Block header edge_bits is lower than our min
	#[error("Cuckoo Size too small")]
	LowEdgebits,
	/// Block header invalid hash, explicitly rejected
	#[error("Block hash explicitly rejected by chain")]
	InvalidHash,
	/// Scaling factor between primary and secondary PoW is invalid
	#[error("Wrong scaling factor")]
	InvalidScaling,
	/// The proof of work is invalid
	#[error("Invalid PoW")]
	InvalidPow,
	/// The proof context does not match the chain context.
	#[error("Block header proof context mismatch: expected {expected}, got {actual}")]
	InvalidHeaderContext {
		/// Context assigned to the chain store.
		expected: u32,
		/// Context embedded in the supplied proof.
		actual: u32,
	},
	/// Peer abusively sending us an old block we already have
	#[error("Old Block")]
	OldBlock,
	/// Block time is too old
	#[error("Invalid Block Time")]
	InvalidBlockTime,
	/// Block height is invalid (not previous + 1)
	#[error("Invalid Block Height")]
	InvalidBlockHeight,
	/// One of the root hashes in the block is invalid
	#[error("Invalid Root, {0}")]
	InvalidRoot(String),
	/// One of the MMR sizes in the block header is invalid
	#[error("Invalid MMR Size")]
	InvalidMMRSize,
	/// Error from underlying keychain impl
	#[error("Keychain Error, {0}")]
	Keychain(#[from] mwc_keychain::Error),
	/// Error from underlying secp lib
	#[error("Secp Lib Error, {0}")]
	Secp(secp::Error),
	/// One of the inputs in the block has already been spent
	#[error("Already Spent: {0:?}")]
	AlreadySpent(Commitment),
	/// Input commitment exists but the full input identifier does not match.
	#[error("Input Mismatch: {0:?}")]
	InputMismatch(Commitment),
	/// An output with that commitment already exists (should be unique)
	#[error("Duplicate Commitment: {0:?}")]
	DuplicateCommitment(Commitment),
	/// An output reuses a previously spent commitment on the retained chain.
	#[error("Replay attack detected. Commit {0:?} observed at height {1} and {2}")]
	ReplayAttack(Commitment, u64, u64),
	/// Attempt to spend a coinbase output before it sufficiently matures.
	#[error("Attempt to spend immature coinbase")]
	ImmatureCoinbase,
	/// Error validating a Merkle proof (coinbase output)
	#[error("Error validating merkle proof, {0}")]
	MerkleProof(String),
	/// Output not found
	#[error("Output not found, {0}")]
	OutputNotFound(String),
	/// Rangeproof not found
	#[error("Rangeproof not found, {0}")]
	RangeproofNotFound(String),
	/// Tx kernel not found
	#[error("Tx kernel not found")]
	TxKernelNotFound,
	/// The full kernel excess index is not complete enough to serve lookups.
	#[error("Kernel position index is incomplete")]
	KernelPosIndexIncomplete,
	/// The retained spent commitment replay index is not complete enough to serve lookups.
	#[error("Retained spent commitment index is incomplete")]
	SpentCommitmentIndexIncomplete,
	/// output spent
	#[error("Output is spent")]
	OutputSpent,
	/// Invalid block version, either a mistake or outdated software
	#[error("Invalid Block Version: {0:?}")]
	InvalidBlockVersion(block::HeaderVersion),
	/// We've been provided a bad txhashset
	#[error("Invalid TxHashSet: {0}")]
	InvalidTxHashSet(String),
	/// Internal issue when trying to save or load data from store
	#[error("Chain Store Error: {1}, reason: {0}")]
	StoreErr(mwc_store::Error, String),
	/// Internal issue when trying to save or load data from append only files
	#[error("Chain File Read Error: {0}")]
	FileReadErr(String),
	/// IO error
	#[error("Chain IO Error, {0}")]
	IOErr(#[from] io::Error),
	/// Error serializing or deserializing a type
	#[error("Chain Serialization Error, {0}")]
	SerErr(#[from] ser::Error),
	/// Error migrating a persisted full-block record between protocol versions.
	#[error("Unable to migrate block record {key:?}; v3 error: {v3_err}; v2 error: {v2_err}")]
	BlockMigration {
		/// Raw database key for the block record.
		key: Vec<u8>,
		/// Error observed when reading the record as v3.
		v3_err: ser::Error,
		/// Error observed when reading the record as v2.
		v2_err: ser::Error,
	},
	/// Error with the txhashset
	#[error("TxHashSetErr: {0}")]
	TxHashSetErr(String),
	/// A PMMR sync failed after durable persistence may already have begun.
	#[error("{context}: PMMR sync failed after persistence may have begun: {source}")]
	PmmrSyncStateUncertain {
		/// Sync stage for diagnostics.
		context: String,
		/// Underlying I/O failure.
		#[source]
		source: io::Error,
	},
	/// A readonly or rollback txhashset/header PMMR operation failed to discard changes.
	#[error("{context}: failed to discard txhashset/header PMMR changes: {discard}")]
	TxHashSetDiscard {
		/// Operation context for diagnostics.
		context: String,
		/// Discard/cleanup error.
		discard: Box<Error>,
	},
	/// The primary operation failed and the follow-up discard also failed.
	#[error("{context}: primary error: {primary}; additionally failed to discard txhashset/header PMMR changes: {discard}")]
	TxHashSetDiscardAfterError {
		/// Operation context for diagnostics.
		context: String,
		/// Primary operation error.
		primary: Box<Error>,
		/// Discard/cleanup error.
		discard: Box<Error>,
	},
	/// PMMR error
	#[error("PMMR Error, {0}")]
	PMMRErr(#[from] mwc_core::core::pmmr::Error),
	/// Tx not valid based on lock_height.
	#[error("Invalid Transaction Lock Height")]
	TxLockHeight,
	/// Tx is not valid due to NRD relative_height restriction.
	#[error("NRD Relative Height")]
	NRDRelativeHeight,
	/// A body rewind target is older than the locally supported horizon.
	#[error(
		"Cannot rewind body from head height {head_height} to target height {target_height}: minimum supported height is {minimum_height}"
	)]
	RewindBeyondHorizon {
		/// Height of the authenticated body head.
		head_height: u64,
		/// Requested rewind target height.
		target_height: u64,
		/// Oldest height to which this body head may rewind.
		minimum_height: u64,
	},
	/// No chain exists and genesis block is required
	#[error("Genesis Block Required")]
	GenesisBlockRequired,
	/// Error from underlying tx handling
	#[error("Transaction Validation Error: {0}")]
	Transaction(#[from] transaction::Error),
	/// Error from underlying block handling
	#[error("Block Validation Error: {0}")]
	Block(#[from] block::Error),
	/// Attempt to retrieve a header at a height greater than
	/// the max allowed by u64 limits
	#[error("Invalid Header Height: {0}")]
	InvalidHeaderHeight(u64),
	/// Anything else
	#[error("Chain other Error: {0}")]
	Other(String),
	/// Chain restart required
	#[error("Data corruption is detected, mwc-node needs to be restarted")]
	ChainRestartRequired,
	/// Data overflow error
	#[error("Chain data overflow error, {0}")]
	DataOverflow(String),
	/// Error from summing and verifying kernel sums via committed trait.
	#[error("Committed Trait: Error summing and verifying kernel sums, {0}")]
	Committed(#[from] committed::Error),
	/// We cannot process data once the Mwc server has been stopped.
	#[error("Stopped (MWC Shutting Down)")]
	Stopped,
	/// Internal Roaring Bitmap error
	#[error("Roaring Bitmap error")]
	Bitmap,
	/// Error during chain sync
	#[error("Sync error")]
	SyncError(String),
	/// PIBD segment related error
	#[error("Segment error, {0}")]
	SegmentError(#[from] segment::SegmentError),
	/// We've decided to halt the PIBD process due to lack of supporting peers or
	/// otherwise failing to progress for a certain amount of time
	#[error("Aborting PIBD error")]
	AbortingPIBDError,
	/// The segmenter is associated to a different block header
	#[error("Segmenter header mismatch, available {0} at height {1}")]
	SegmenterHeaderMismatch(Hash, u64),
	/// Segment height not within allowed range
	#[error("Invalid segment height")]
	InvalidSegmentHeight,
	/// Error from the core calls
	#[error("Core error, {0}")]
	CoreErr(#[from] core::Error),
	/// Other issue with segment
	#[error("Invalid segment: {0}")]
	InvalidSegment(String),
	/// The blockchain is in sync process, not all data is available
	#[error("Chain is syncing, data is not complete")]
	ChainInSyncing(String),
	/// Invalid bitmap root hash. Probably old traffic or somebody attacking as
	#[error("Invalid bitmap root hash")]
	InvalidBitmapRoot,
	/// Outputs bitmaps is not ready
	#[error("Outputs bitmap is not build yet")]
	BitmapNotReady,
	/// Invalid headers root hash. Probably old traffic or somebody attacking as
	#[error("Invalid headers root hash")]
	InvalidHeadersRoot,
	/// Invalid prune segment state. Expected that segment is not pruned, but it does
	#[error("Not expected segment pruned state")]
	InvalidPruneState,
	/// Invalid segment id (such segment was never requested).
	#[error("Invalid segment id")]
	InvalidSegmentId,
	/// Invalid genesis hash.
	#[error("Invalid genesis hash")]
	InvalidGenesisHash,
	/// Persisted chain metadata or header ancestry is internally inconsistent.
	#[error("Invalid persisted chain state: {0}")]
	InvalidPersistedChainState(String),
	/// A durable database head requires PMMR entries no longer present in the backend files.
	///
	/// Rewind-only reconciliation cannot manufacture the missing entries. Startup
	/// must stop with the pending operation marker intact so an operator can reset
	/// or resynchronize chain state explicitly.
	#[error(
		"Automatic PMMR recovery stopped before mutation: {0}. The pending chain-operation marker was retained; reset or resynchronize chain state before restarting"
	)]
	PmmrRecoveryRequired(String),
	/// Durable chain state was committed, but the follow-up recovery failed.
	///
	/// The nested error describes a node-local post-commit failure and must not
	/// be used to attribute bad data to the peer that supplied the accepted data.
	#[error("{context}: chain state was committed, but recovery failed: {source}")]
	CommittedRecoveryFailed {
		/// Operation whose durable commit preceded the recovery failure.
		context: String,
		/// Underlying recovery failure, retained for diagnostics.
		#[source]
		source: Box<Error>,
	},
	/// Desegmenter creation error
	#[error("Unable to create desegmenter, {0}")]
	DesegmenterCreationError(String),
	/// Invalid series of blocks.
	#[error("Invalid series of blocks, {0}")]
	InvalidBlocksSeries(String),
	/// Chain is in sync mode
	#[error("Chain is in sync mode")]
	ChainInSync,
	/// Empty MMR
	#[error("Empty MMR")]
	EmptyMMR,
}

impl Error {
	/// Preserve the post-commit phase when exposing a recovery failure through
	/// the public chain error type.
	pub(crate) fn committed_recovery_failed(context: impl Into<String>, source: Error) -> Self {
		Self::CommittedRecoveryFailed {
			context: context.into(),
			source: Box::new(source),
		}
	}

	/// Whether the error is due to a block that was intrinsically wrong
	pub fn is_bad_data(&self) -> bool {
		match self {
			// Remote data failed consensus or structural validation. Callers may
			// use these errors as peer-scoring or banning signals.
			Error::DifficultyTooLow
			| Error::WrongTotalDifficulty
			| Error::LowEdgebits
			| Error::InvalidHash
			| Error::InvalidScaling
			| Error::InvalidPow
			| Error::InvalidHeaderContext { .. }
			| Error::OldBlock
			| Error::InvalidBlockTime
			| Error::InvalidBlockHeight
			| Error::InvalidRoot(_)
			| Error::InvalidMMRSize
			| Error::Secp(_)
			| Error::AlreadySpent(_)
			| Error::InputMismatch(_)
			| Error::DuplicateCommitment(_)
			| Error::ReplayAttack(_,_,_)
			| Error::ImmatureCoinbase
			| Error::MerkleProof(_)
			| Error::OutputNotFound(_)
			| Error::RangeproofNotFound(_)
			| Error::TxKernelNotFound
			| Error::OutputSpent
			| Error::InvalidBlockVersion(_)
			| Error::InvalidTxHashSet(_)
			| Error::TxLockHeight
			| Error::NRDRelativeHeight
			// These wrapped error enums can include both consensus failures and
			// internal/local failures. We classify them broadly because callers
			// use this in peer reject/scoring paths, where we prefer being
			// conservative over a false negative that lets bad remote data pass.
			| Error::Transaction(_)
			| Error::Block(_)
			| Error::InvalidHeaderHeight(_)
			| Error::DataOverflow(_)
			| Error::Committed(_)
			| Error::SegmentError(_)
			| Error::InvalidSegmentHeight
			| Error::CoreErr(_)
			| Error::InvalidSegment(_)
			| Error::InvalidBitmapRoot
			| Error::InvalidHeadersRoot
			| Error::InvalidPruneState
			| Error::InvalidSegmentId
			| Error::InvalidGenesisHash
			| Error::InvalidBlocksSeries(_) => true,

			// Local state, storage, lifecycle, missing-context, and sync-progress
			// failures are not evidence that a peer sent bad data.
			Error::Unfit(_)
			| Error::Orphan(_)
			| Error::Keychain(_)
			| Error::StoreErr(_, _)
			| Error::InvalidPersistedChainState(_)
			| Error::PmmrRecoveryRequired(_)
			| Error::CommittedRecoveryFailed { .. }
			| Error::FileReadErr(_)
			| Error::IOErr(_)
			| Error::SerErr(_)
			| Error::BlockMigration { .. }
			| Error::KernelPosIndexIncomplete
			| Error::SpentCommitmentIndexIncomplete
			| Error::TxHashSetErr(_)
			| Error::PmmrSyncStateUncertain { .. }
			| Error::TxHashSetDiscard { .. }
			| Error::PMMRErr(_)
			| Error::RewindBeyondHorizon { .. }
			| Error::GenesisBlockRequired
			| Error::Other(_)
			| Error::ChainRestartRequired
			| Error::Stopped
			| Error::Bitmap
			| Error::SyncError(_)
			| Error::AbortingPIBDError
			| Error::SegmenterHeaderMismatch(_, _)
			| Error::ChainInSyncing(_)
			| Error::BitmapNotReady
			| Error::DesegmenterCreationError(_)
			| Error::ChainInSync
			| Error::EmptyMMR => false,

			Error::TxHashSetDiscardAfterError { primary, .. } => primary.is_bad_data(),
		}
	}

	/// Whether this error only reports that the full block is already known.
	///
	/// Body sync intentionally issues redundant requests, so these outcomes can
	/// be produced by a normal race between two valid peer responses.
	pub fn is_known_block(&self) -> bool {
		match self {
			Error::OldBlock => true,
			Error::Unfit(msg) => matches!(
				msg.as_str(),
				"already known in head" | "already known in store" | "duplicate block"
			),
			_ => false,
		}
	}

	/// Whether the error means PMMR rollback/discard cleanup failed.
	pub fn is_txhashset_discard_failure(&self) -> bool {
		matches!(
			self,
			Error::TxHashSetDiscard { .. } | Error::TxHashSetDiscardAfterError { .. }
		)
	}

	/// Whether a pending chain-operation marker must be retained for recovery.
	pub fn requires_chain_recovery(&self) -> bool {
		matches!(
			self,
			Error::PmmrSyncStateUncertain { .. } | Error::CommittedRecoveryFailed { .. }
		) || self.is_txhashset_discard_failure()
	}

	/// Whether this error represents missing chain data.
	pub fn is_not_found(&self) -> bool {
		matches!(
			self,
			Error::StoreErr(mwc_store::Error::NotFoundErr(_), _)
				| Error::OutputNotFound(_)
				| Error::RangeproofNotFound(_)
				| Error::TxKernelNotFound
		)
	}
}

impl From<secp::Error> for Error {
	fn from(err: secp::Error) -> Self {
		Error::Secp(err)
	}
}

impl From<mwc_store::Error> for Error {
	fn from(error: mwc_store::Error) -> Error {
		Error::StoreErr(error, "NA".into())
	}
}

impl From<pow::Error> for Error {
	fn from(e: pow::Error) -> Error {
		match e {
			pow::Error::PrePowError(_)
			| pow::Error::Verification(_)
			| pow::Error::EdgeAddition
			| pow::Error::Path
			| pow::Error::InvalidCycle(_)
			| pow::Error::NoCycle
			| pow::Error::NoSolution
			| pow::Error::InvalidConfiguration(_) => Error::InvalidPow,
			pow::Error::IOError { source } => Error::IOErr(source),
			pow::Error::DataOverflow(msg) => Error::DataOverflow(msg),
			pow::Error::SysRndError => Error::Other("PoW error, SysRnd failure".into()),
			pow::Error::NotImplemented(msg) => {
				Error::Other(format!("PoW operation is not implemented: {}", msg))
			}
			pow::Error::ConsensusError(e) => match e {
				consensus::Error::DataOverflow(msg) => Error::DataOverflow(msg),
				consensus::Error::InvalidEdgeBits(_) => Error::InvalidPow,
				e @ (consensus::Error::HistoryTooShort
				| consensus::Error::HeaderIO(_)
				| consensus::Error::AlreadyInitialized(_)
				| consensus::Error::InvalidParameter(_)) => Error::Other(format!("PoW consensus error, {}", e)),
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn is_bad_data_returns_false_for_local_internal_errors() {
		let local_errors = vec![
			Error::FileReadErr("append-only file read failed".into()),
			Error::PmmrRecoveryRequired("durable HEAD is ahead of output PMMR".into()),
			Error::ChainRestartRequired,
			Error::Stopped,
			Error::Bitmap,
			Error::KernelPosIndexIncomplete,
			Error::RewindBeyondHorizon {
				head_height: 100,
				target_height: 29,
				minimum_height: 30,
			},
			Error::Other("generic local failure".into()),
			Error::PmmrSyncStateUncertain {
				context: "header_extending sync".into(),
				source: io::Error::new(io::ErrorKind::Other, "forced sync failure"),
			},
			Error::SyncError("sync state unavailable".into()),
			Error::AbortingPIBDError,
			Error::ChainInSyncing("headers are still syncing".into()),
			Error::BitmapNotReady,
			Error::ChainInSync,
			Error::EmptyMMR,
			Error::SegmenterHeaderMismatch(Hash::from_vec(&[1]), 42),
			Error::DesegmenterCreationError("missing local state".into()),
		];

		for err in local_errors {
			assert!(!err.is_bad_data(), "{:?}", err);
		}
	}

	#[test]
	fn is_bad_data_returns_true_for_explicit_bad_remote_data() {
		let bad_data_errors = vec![
			Error::InvalidPow,
			Error::InvalidHeaderContext {
				expected: 7,
				actual: 11,
			},
			Error::InputMismatch(Commitment::from_vec([1; 33].to_vec()).unwrap()),
			Error::ReplayAttack(Commitment::from_vec([2; 33].to_vec()).unwrap(), 10, 20),
			Error::InvalidRoot("output root mismatch".into()),
			Error::InvalidBitmapRoot,
			Error::InvalidHeadersRoot,
			Error::InvalidSegment("segment root mismatch".into()),
			Error::InvalidBlocksSeries("non-contiguous blocks".into()),
		];

		for err in bad_data_errors {
			assert!(err.is_bad_data(), "{:?}", err);
		}
	}

	#[test]
	fn committed_recovery_failure_is_never_bad_peer_data() {
		let err = Error::committed_recovery_failed(
			"process_block_header committed marker cleanup",
			Error::InvalidRoot("forced local recovery mismatch".into()),
		);

		assert!(!err.is_bad_data(), "{:?}", err);
		assert!(err.requires_chain_recovery());
		assert!(matches!(
			&err,
			Error::CommittedRecoveryFailed { context, source }
				if context == "process_block_header committed marker cleanup"
					&& matches!(source.as_ref(), Error::InvalidRoot(_))
		));
	}

	#[test]
	fn known_block_errors_are_classified_separately() {
		assert!(Error::OldBlock.is_known_block());
		assert!(Error::Unfit("already known in head".into()).is_known_block());
		assert!(Error::Unfit("already known in store".into()).is_known_block());
		assert!(Error::Unfit("duplicate block".into()).is_known_block());

		assert!(!Error::Unfit("conflicting orphan body".into()).is_known_block());
		assert!(!Error::InvalidPow.is_known_block());
	}

	#[test]
	fn txhashset_discard_after_error_preserves_primary_bad_data_classification() {
		let err = Error::TxHashSetDiscardAfterError {
			context: "applying block".into(),
			primary: Box::new(Error::InvalidPow),
			discard: Box::new(Error::TxHashSetErr("discard failed".into())),
		};

		assert!(err.is_bad_data(), "{:?}", err);
	}

	#[test]
	fn uncertain_pmmr_sync_and_discard_failures_require_chain_recovery() {
		let sync_err = Error::PmmrSyncStateUncertain {
			context: "header_extending sync".into(),
			source: io::Error::new(io::ErrorKind::Other, "forced sync failure"),
		};
		assert!(sync_err.requires_chain_recovery());

		let discard_err = Error::TxHashSetDiscard {
			context: "header_extending rollback".into(),
			discard: Box::new(Error::TxHashSetErr("forced discard failure".into())),
		};
		assert!(discard_err.requires_chain_recovery());

		assert!(!Error::InvalidRoot("pre-sync validation failure".into()).requires_chain_recovery());
	}

	#[test]
	fn pow_consensus_data_overflow_converts_to_chain_data_overflow() {
		let err = Error::from(pow::Error::ConsensusError(consensus::Error::DataOverflow(
			"graph_weight edge_bits=64".into(),
		)));

		assert!(matches!(err, Error::DataOverflow(_)), "{:?}", err);
		assert!(err.is_bad_data());
	}

	#[test]
	fn pow_invalid_configuration_converts_to_bad_pow() {
		let err = Error::from(pow::Error::InvalidConfiguration(
			"Invalid edge_bits 34".into(),
		));

		assert!(matches!(err, Error::InvalidPow), "{:?}", err);
		assert!(err.is_bad_data());
	}
}
