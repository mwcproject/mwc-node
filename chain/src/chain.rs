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

//! Facade and handler for the rest of the blockchain implementation
//! and mostly the chain pipeline.

use crate::error::Error;
use crate::pibd_params::PibdParams;
use crate::pipe;
use crate::store;
use crate::store::{ChainOperationKind, PendingChainOperation, PendingChainOperationGuard};
use crate::txhashset;
use crate::txhashset::{Desegmenter, PMMRHandle, Segmenter, TxHashSet};
use crate::types::{
	BlockStatus, ChainAdapter, CommitPos, HashHeight, Options, SpentCommitmentRecord, SpentOutput,
	SyncState, SyncStatus, SyncStatusUpdateThrottle, Tip, HEADERS_PER_BATCH,
};
use crate::ChainStore;
use crate::{
	store::Batch,
	txhashset::{ExtensionPair, HeaderExtension},
};
use mwc_core::consensus;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::merkle_proof::MerkleProof;
use mwc_core::core::pmmr::{self, ReadablePMMR, VecBackend, PMMR};
use mwc_core::core::{
	Block, BlockHeader, BlockSums, Committed, Inputs, KernelFeatures, Output, OutputIdentifier,
	Transaction, TransactionBody, TxKernel,
};
use mwc_core::difficulty_cache::DifficultyCache;
use mwc_core::pow;
use mwc_core::ser;
use mwc_core::ser::ProtocolVersion;
use mwc_core::{genesis, global};
use mwc_crates::log::{debug, error, info, trace, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_store::types::VariableSizeMetadataValidation;
use mwc_store::Error::NotFoundErr;
use mwc_util::{StopState, ToHex};
use std::cmp::min;
use std::collections::HashSet;
#[cfg(test)]
use std::convert::TryFrom;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};
use std::{collections::HashMap, io::Cursor};

/// When evicting, very old orphans are evicted first
const MAX_ORPHAN_AGE_SECS: u64 = 3000;
/// Peer attribution is best-effort metadata and must remain bounded per orphan.
const MAX_ORPHAN_SOURCE_PEERS: usize = 6;
const SPENT_COMMITMENT_INDEX_CLEAR_CHUNK_SIZE: usize = 10_000;
const SPENT_COMMITMENT_INDEX_REBUILD_CHUNK_SIZE: usize = 1_000;
const HISTORICAL_BLOCK_DELETE_CHUNK: usize = 100;

#[derive(Debug, Clone)]
pub struct Orphan {
	pub block: Block,
	pub opts: Options,
	pub source_peers: HashSet<String>,
	added: Instant,
}

pub struct OrphanBlockPool {
	// blocks indexed by their hash
	orphans: RwLock<HashMap<Hash, Orphan>>,
	// additional index of height -> hash
	// so we can efficiently identify a child block (ex-orphan) after processing a block
	height_idx: RwLock<HashMap<u64, Vec<Hash>>>,
	// accumulated number of evicted block because of MAX_ORPHAN_SIZE limitation
	evicted: AtomicUsize,
	pibd_params: Arc<PibdParams>,
}

/// Result of finalizing the recovery marker for an operation whose successful
/// value is produced only after its durable database batch has committed.
enum PendingChainOperationCompletion<T> {
	Complete(T),
	CommittedNeedsRecovery { value: T, marker_error: Error },
}

/// Internal block-processing error classification.
///
/// Only `NotCommitted` is safe for the batch caller to retry one block at a
/// time. Once the block batch committed, a recovery failure must be surfaced
/// without reclassifying the accepted block as a validation failure.
enum BlockProcessingError {
	NotCommitted(Error),
	CommittedRecoveryFailed(Error),
}

#[cfg(test)]
struct RewindBadBlockAfterBodySyncHook {
	reached: mpsc::SyncSender<()>,
	resume: Mutex<mpsc::Receiver<()>>,
}

impl From<Error> for BlockProcessingError {
	fn from(error: Error) -> Self {
		Self::NotCommitted(error)
	}
}

/// Compare the portions of two block bodies committed by the header MMR roots.
///
/// Inputs are intentionally excluded because a block header does not commit
/// their individual identities. Outputs include their rangeproofs in the full
/// encoding, and kernels include their excess signatures.
pub(crate) fn bodies_equal_header_committed(
	context_id: u32,
	lhs: &TransactionBody,
	rhs: &TransactionBody,
) -> Result<bool, Error> {
	let version = ProtocolVersion::local();
	Ok(ser::ser_vec(context_id, &lhs.outputs, version)?
		== ser::ser_vec(context_id, &rhs.outputs, version)?
		&& ser::ser_vec(context_id, &lhs.kernels, version)?
			== ser::ser_vec(context_id, &rhs.kernels, version)?)
}

/// Lossless comparison of unvalidated block bodies.
///
/// Full-data serialization cannot be used for inputs: at protocol versions
/// >= 3, `Inputs::write` converts `FeaturesAndCommit` inputs into sorted
/// commit-only values, discarding the variant and consensus-relevant input
/// features. Outputs and kernels do not have this lossy protocol conversion,
/// so their full-data encodings retain rangeproofs and excess signatures.
fn bodies_equal_lossless(
	context_id: u32,
	lhs: &TransactionBody,
	rhs: &TransactionBody,
) -> Result<bool, Error> {
	if !lhs.inputs.eq_by_hash(context_id, &rhs.inputs)? {
		return Ok(false);
	}
	bodies_equal_header_committed(context_id, lhs, rhs)
}

/// Compare a candidate block with a trusted stored block across the v2 wire and
/// v3 database representations.
///
/// # Why this deliberately differs from `blocks_equal_lossless`
///
/// Protocol v0-v2 carries `(features, commitment)` for every input, while the
/// v3 database format stores only the commitment. Consequently, the same valid
/// block is `FeaturesAndCommit` on a legacy connection and `CommitOnly` after it
/// is stored. `Inputs::eq_by_hash` correctly treats nonempty cross-representation
/// inputs as unequal: for two unvalidated bodies, the missing feature cannot be
/// proven without the parent UTXO state. Using that strict comparison here,
/// however, lets a legacy replay of an already stored block miss the duplicate
/// filter and repeat the expensive block-processing path.
///
/// This helper is the narrow known-block exception. `stored` must be the already
/// validated block loaded from the block store. Serializing both complete bodies
/// as v3 removes legacy input features and orders those inputs by commitment,
/// while still comparing every input commitment, output and rangeproof, kernel
/// and signature, plus the exact header. It requires no parent or UTXO lookup.
///
/// If the caller classifies an equal candidate as known, it is discarded and
/// the stored block remains authoritative, so a wrong legacy feature cannot
/// affect chain state. The deliberate tradeoff is that such a feature-only
/// mutation is suppressed as a duplicate instead of being used to ban a peer.
/// Callers still let a stored higher-work block continue to normal UTXO
/// validation when it needs reapplication.
///
/// Never use this for orphan deduplication or between two unvalidated bodies;
/// those paths must retain and compare input features with
/// `blocks_equal_lossless`/`bodies_equal_lossless`.
pub(crate) fn blocks_equal_as_v3(
	context_id: u32,
	stored: &Block,
	candidate: &Block,
) -> Result<bool, Error> {
	Ok(store::blocks_equal_as_v3(context_id, stored, candidate)?)
}

impl OrphanBlockPool {
	fn new(pibd_params: Arc<PibdParams>) -> OrphanBlockPool {
		OrphanBlockPool {
			orphans: RwLock::new(HashMap::new()),
			height_idx: RwLock::new(HashMap::new()),
			evicted: AtomicUsize::new(0),
			pibd_params,
		}
	}

	fn len(&self) -> usize {
		let orphans = self.orphans.read_recursive();
		orphans.len()
	}

	fn len_evicted(&self) -> usize {
		self.evicted.load(Ordering::Relaxed)
	}

	fn extend_source_peers_capped(source_peers: &mut HashSet<String>, incoming: HashSet<String>) {
		for source_peer in incoming {
			if source_peers.len() >= MAX_ORPHAN_SOURCE_PEERS {
				break;
			}
			source_peers.insert(source_peer);
		}
	}

	/// Add an unvalidated orphan, deduplicating bodies losslessly.
	///
	/// Why this is needed: the orphan pool is keyed by the block hash, which
	/// is the header hash only, while orphan bodies have not yet been
	/// validated against the roots committed to by that header. Deduplication
	/// (discarding a newly arrived body and merging its `source_peers` into
	/// the cached entry) is therefore only sound if the two bodies are
	/// losslessly identical. Any field the comparison fails to cover becomes
	/// a cache-poisoning and peer-misattribution vector.
	///
	/// Attack vector with a lossy comparison:
	/// 1. A malicious peer sends an orphan with the valid header and valid
	///    commitments but corrupted input features. It is cached with the
	///    attacker in `source_peers`.
	/// 2. An honest peer later sends the valid body for the same header. If
	///    the comparison cannot see the corrupted field, the valid body is
	///    discarded as a "duplicate" and the honest peer's address is merged
	///    into the poisoned entry's `source_peers`.
	/// 3. Once the parent arrives, the cached (poisoned) body is processed
	///    and deferred validation fails with a bad-data error (e.g.
	///    `InputMismatch`). `process_block` then reports *every* merged
	///    source peer via `block_rejected`, so the honest peer is banned
	///    alongside the attacker. This gives an attacker cheap, repeatable
	///    ban amplification against honest peers.
	///
	/// How the comparison is made lossless:
	/// - Inputs use the variant-aware hash comparison, which preserves the
	///   `Inputs` variant, input feature bytes and ordering. Full-data
	///   serialization cannot be used for inputs: at protocol versions >= 3,
	///   `Inputs::write` converts `FeaturesAndCommit` inputs into
	///   `CommitWrapper` values (and sorts them), discarding the
	///   consensus-relevant `Input::features` bytes — the exact gap that
	///   made the attack above possible.
	/// - Outputs (including rangeproofs) and kernels (including excess
	///   signatures) serialize losslessly in full-data mode at any supported
	///   protocol version, so their bytes are compared directly.
	fn add(&self, context_id: u32, mut orphan: Orphan) -> Result<(), Error> {
		// Enforce the per-orphan bound for every caller, including an oversized
		// source set supplied with the first insertion.
		let incoming = std::mem::take(&mut orphan.source_peers);
		Self::extend_source_peers_capped(&mut orphan.source_peers, incoming);

		let mut orphans = self.orphans.write();
		let mut height_idx = self.height_idx.write();
		{
			let height = orphan.block.header.height;
			let hash = orphan.block.hash(context_id)?;
			// The block hash is the header hash. Orphan bodies have not yet been
			// validated against the roots committed to by that header, so only
			// losslessly identical orphan blocks can safely be deduplicated.
			// Anything less lets a poisoned body absorb the source peers of a
			// later valid body, misattributing its validation failure and
			// banning honest peers; see bodies_equal_lossless for the attack
			// walkthrough. The source_peers merge below must stay behind this
			// equality check.
			if let Some(existing) = orphans.get_mut(&hash) {
				if !bodies_equal_lossless(context_id, &existing.block.body, &orphan.block.body)? {
					return Err(Error::Unfit(
						"conflicting orphan body for header".to_owned(),
					));
				}

				Self::extend_source_peers_capped(&mut existing.source_peers, orphan.source_peers);
			} else {
				orphans.insert(hash.clone(), orphan);
				let height_hashes = height_idx.entry(height).or_insert_with(|| vec![]);
				height_hashes.push(hash);
			}
		}

		let orphans_num_limit = self.pibd_params.get_orphans_num_limit();
		if orphans.len() > orphans_num_limit {
			let old_len = orphans.len();

			// evict too old
			orphans.retain(|_, ref mut x| {
				x.added.elapsed() < Duration::from_secs(MAX_ORPHAN_AGE_SECS)
			});
			// Evict too far ahead by whole height buckets. This is a hot
			// in-memory cache path, and height buckets are the optimal unit for
			// orphan lookup and cleanup after a parent block is accepted.
			let mut heights = height_idx.keys().cloned().collect::<Vec<u64>>();
			heights.sort_unstable();
			for h in heights.iter().rev() {
				if let Some(hs) = height_idx.remove(h) {
					for h in hs {
						let _ = orphans.remove(&h);
					}
				}
				// We intentionally evict until we are below the limit, not
				// exactly at it. The extra headroom delays the next eviction
				// pass and keeps this cache path cheaper under load.
				if orphans.len() < orphans_num_limit {
					break;
				}
			}
			// Cleanup index buckets cheaply. Mixed buckets may keep stale
			// hashes; later removals filter through `orphans`, and avoiding a
			// full rebuild keeps this cache path fast.
			height_idx.retain(|_, ref mut xs| xs.iter().any(|x| orphans.contains_key(&x)));

			self.evicted
				.fetch_add(old_len - orphans.len(), Ordering::Relaxed);
		}
		Ok(())
	}

	/// Get an orphan from the pool indexed by the hash of its parent, removing
	/// it at the same time, preventing clone
	fn remove_by_height(&self, height: u64) -> Option<Vec<Orphan>> {
		let mut orphans = self.orphans.write();
		let mut height_idx = self.height_idx.write();
		height_idx
			.remove(&height)
			.map(|hs| hs.iter().filter_map(|h| orphans.remove(h)).collect())
	}

	fn remove_by_height_header_hash(&self, height: u64, header_hash: &Hash) -> Option<Orphan> {
		let mut orphans = self.orphans.write();
		let mut height_idx = self.height_idx.write();

		if !orphans.contains_key(header_hash) {
			return None;
		}

		if let Some(mut hash_by_height) = height_idx.remove(&height) {
			hash_by_height.retain(|&hash| hash != *header_hash);
			if !hash_by_height.is_empty() {
				height_idx.insert(height.clone(), hash_by_height);
			}
		}

		return orphans.remove(&header_hash);
	}

	/// Get list of ophan's hashes
	pub fn get_orphan_list(&self) -> HashSet<Hash> {
		self.orphans
			.read_recursive()
			.iter()
			.map(|(k, _v)| k.clone())
			.collect()
	}

	/// Check if orphans is in the list
	pub fn contains(&self, hash: &Hash) -> bool {
		self.orphans.read_recursive().contains_key(hash)
	}

	/// Request orphan by hash
	pub fn get_orphan(&self, hash: &Hash) -> Option<Orphan> {
		self.orphans.read_recursive().get(hash).map(|o| o.clone())
	}

	/// Request orphan height and prev block hash. Alternative to get_orphan without much data copy
	pub fn get_orphan_height_prev_hash(&self, hash: &Hash) -> Option<(Hash, u64)> {
		self.orphans
			.read_recursive()
			.get(hash)
			.map(|o| (o.block.header.prev_hash.clone(), o.block.header.height))
	}
}

/// Facade to the blockchain block processing pipeline and storage. Provides
/// the current view of the TxHashSet according to the chain state. Also
/// maintains locking for the pipeline to avoid conflicting processing.
pub struct Chain {
	db_root: String,
	store: Arc<store::ChainStore>, // Lock order (with childrer):   3
	adapter: Arc<dyn ChainAdapter + Send + Sync>,
	orphans: Arc<OrphanBlockPool>,
	txhashset: Arc<RwLock<txhashset::TxHashSet>>, // Lock order (with childrer):   2
	header_pmmr: Arc<RwLock<txhashset::PMMRHandle<BlockHeader>>>, // Lock order  (with childrer):  1
	pibd_segmenter: Arc<RwLock<Option<Segmenter>>>,
	// POW verification function
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	archive_mode: bool,
	genesis: Block,
	cache_header_difficulty: Arc<RwLock<DifficultyCache>>,
	pibd_params: Arc<PibdParams>,
	stop_state: Option<Arc<StopState>>,
	requires_init_recovery: Arc<AtomicBool>,
	pibd_state_generation: Arc<AtomicU64>,
	#[cfg(test)]
	fail_next_process_block_marker_clear: AtomicBool,
	#[cfg(test)]
	fail_next_process_block_header_marker_clear: AtomicBool,
	#[cfg(test)]
	fail_next_committed_recovery_with_bad_data: AtomicBool,
	#[cfg(test)]
	process_block_batch_safety_depth: AtomicU64,
	#[cfg(test)]
	rewind_bad_block_after_body_sync_hook: RwLock<Option<Arc<RewindBadBlockAfterBodySyncHook>>>,
}

/// A coherent read-only view of the header PMMR, body PMMRs, and chain store.
///
/// Instances exist only for the duration of [`Chain::with_output_read_snapshot`].
/// Chain writers cannot change or reorganize the viewed state while the snapshot
/// is in use.
pub struct OutputReadSnapshot<'a> {
	chain: &'a Chain,
	header_pmmr: &'a PMMRHandle<BlockHeader>,
	txhashset: &'a TxHashSet,
	batch: Batch<'a>,
}

impl OutputReadSnapshot<'_> {
	/// Context id associated with this chain snapshot.
	pub fn get_context_id(&self) -> u32 {
		self.batch.get_context_id()
	}

	/// Return the earliest retained block tip from this snapshot.
	pub fn get_tail(&self) -> Result<Tip, Error> {
		self.batch
			.tail()
			.map_err(|e| Error::StoreErr(e, "output snapshot get tail".to_owned()))
	}

	/// Load a block header by hash from this snapshot and verify its store key.
	pub fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, Error> {
		crate::checked_header_by_hash(
			self.get_context_id(),
			hash,
			"output snapshot get header by hash",
			|hash| self.batch.get_block_header(hash),
		)
	}

	/// Return unspent outputs by insertion index from this snapshot.
	pub fn unspent_outputs_by_pmmr_index(
		&self,
		start_index: u64,
		max_count: u64,
		max_pmmr_index: Option<u64>,
	) -> Result<(u64, u64, Vec<Output>), Error> {
		let output_mmr_size = self.txhashset.output_mmr_size();
		let last_index = match max_pmmr_index {
			Some(index) => min(index, output_mmr_size),
			None => output_mmr_size,
		};
		let outputs =
			self.txhashset
				.outputs_by_pmmr_index(start_index, max_count, max_pmmr_index)?;
		let rangeproofs =
			self.txhashset
				.rangeproofs_by_pmmr_index(start_index, max_count, max_pmmr_index)?;
		let (index, output_vec) = combine_positioned_outputs_and_rangeproofs(outputs, rangeproofs)?;
		Ok((index, last_index, output_vec))
	}

	/// Return the header selected by the header PMMR at `height`.
	///
	/// This is a request-driven read path, not a PoW validation boundary. Normal
	/// writes validate headers before persistence, and startup/recovery validates
	/// persisted ancestry. Revalidating Cuckoo PoW here would let API clients turn
	/// cheap height lookups into expensive CPU work and create a DoS surface.
	/// The checks below intentionally provide inexpensive store/PMMR consistency
	/// checks only; raw local database modification is outside this threat model.
	pub fn get_header_by_height(&self, height: u64) -> Result<BlockHeader, Error> {
		let hash = self.header_pmmr.get_header_hash_by_height(height)?;
		let header = self
			.batch
			.get_block_header(&hash)
			.map_err(|e| Error::StoreErr(e, format!("output snapshot get header {}", hash)))?;
		let actual_hash = header.hash(self.get_context_id())?;
		if header.height != height || actual_hash != hash {
			return Err(Error::InvalidPersistedChainState(format!(
				"output snapshot header entry {} at height {} resolved to header {} at height {}",
				hash, height, actual_hash, header.height
			)));
		}
		self.header_pmmr
			.authenticate_header_at_height(height, &header)?;
		Ok(header)
	}

	/// Load the full block whose complete header must equal `expected`.
	pub fn get_block_for_header(&self, expected: &BlockHeader) -> Result<Block, Error> {
		let expected_hash = expected.hash(self.get_context_id())?;
		let stored_header = crate::checked_header_by_hash(
			self.get_context_id(),
			&expected_hash,
			"output snapshot get block for header",
			|hash| self.batch.get_block_header(hash),
		)?;
		if stored_header != *expected {
			return Err(Error::InvalidPersistedChainState(format!(
				"output snapshot stored header {} does not exactly match the requested header",
				expected_hash
			)));
		}
		crate::checked_block_for_header(
			self.get_context_id(),
			expected,
			"output snapshot",
			|hash| self.batch.get_block(hash),
		)
	}

	fn get_unspent_entry(
		&self,
		commit: Commitment,
	) -> Result<Option<(OutputIdentifier, CommitPos)>, Error> {
		let indexed_pos = self
			.batch
			.get_output_pos_height(&commit)
			.map_err(|e| Error::StoreErr(e, "output snapshot get output position".to_owned()))?;
		let Some((output, pos)) = self
			.txhashset
			.get_unspent_with_position(commit, indexed_pos)?
		else {
			return Ok(None);
		};
		let body_head = self
			.batch
			.head()
			.map_err(|e| Error::StoreErr(e, "output snapshot get body head".to_owned()))?;
		if self
			.chain
			.body_chain_header_for_output_pos(self.header_pmmr, &self.batch, &body_head, pos)?
			.is_none()
		{
			return Err(Error::InvalidPersistedChainState(format!(
				"output position index entry for commitment {} has invalid position {} or height {}",
				commit.to_hex(),
				pos.pos,
				pos.height
			)));
		}
		Ok(Some((output, pos)))
	}

	/// Return an unspent output identifier and its one-based PMMR position from
	/// this snapshot without loading its rangeproof.
	pub fn get_unspent_output_position(
		&self,
		commit: Commitment,
	) -> Result<Option<(OutputIdentifier, CommitPos)>, Error> {
		self.get_unspent_entry(commit)
	}

	fn get_merkle_proof(
		&self,
		output: &OutputIdentifier,
		pos: CommitPos,
	) -> Result<MerkleProof, Error> {
		let pos0 = pos.pos.checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"OutputReadSnapshot::get_merkle_proof pos={}",
				pos.pos
			))
		})?;
		let indexed_pos0 = self.txhashset.get_output_pos(&output.commitment())?;
		if indexed_pos0 != pos0 {
			return Err(Error::InvalidPersistedChainState(format!(
				"output position changed inside snapshot for commitment {}: {} versus {}",
				output.commitment().to_hex(),
				pos0,
				indexed_pos0
			)));
		}
		let proof = self.txhashset.merkle_proof(output.commitment())?;
		if proof.mmr_size != self.txhashset.output_mmr_size() {
			return Err(Error::InvalidPersistedChainState(format!(
				"merkle proof MMR size {} does not match output PMMR size {}",
				proof.mmr_size,
				self.txhashset.output_mmr_size()
			)));
		}
		Ok(proof)
	}

	/// Return the zero-based PMMR position and current-state Merkle proof for an
	/// unspent commitment from this snapshot.
	pub fn get_output_pos_and_merkle_proof(
		&self,
		commit: Commitment,
	) -> Result<(u64, MerkleProof), Error> {
		let Some((output, pos)) = self.get_unspent_entry(commit)? else {
			return Err(Error::OutputNotFound(commit.to_hex()));
		};
		let pos0 = pos.pos.checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"OutputReadSnapshot::get_output_pos_and_merkle_proof pos={}",
				pos.pos
			))
		})?;
		let proof = self.get_merkle_proof(&output, pos)?;
		Ok((pos0, proof))
	}

	/// Read an output's unspent position and optional current-state Merkle proof
	/// from this snapshot.
	pub fn get_output_status(
		&self,
		expected: &OutputIdentifier,
		include_merkle_proof: bool,
	) -> Result<(Option<CommitPos>, Option<MerkleProof>), Error> {
		let Some((stored, pos)) = self.get_unspent_entry(expected.commitment())? else {
			return Ok((None, None));
		};
		if !ser::hashes_equal(self.get_context_id(), &stored, expected)? {
			return Err(Error::TxHashSetErr(format!(
				"unspent output identifier mismatch for commitment {}",
				expected.commitment().to_hex()
			)));
		}
		let merkle_proof = if include_merkle_proof && expected.is_coinbase() {
			Some(self.get_merkle_proof(&stored, pos)?)
		} else {
			None
		};
		Ok((Some(pos), merkle_proof))
	}

	/// Read a complete unspent output and its optional current-state Merkle proof
	/// from this snapshot.
	pub fn get_unspent_output(
		&self,
		commit: Commitment,
		include_merkle_proof: bool,
	) -> Result<Option<(Output, OutputIdentifier, CommitPos, Option<MerkleProof>)>, Error> {
		let Some((stored, pos)) = self.get_unspent_entry(commit)? else {
			return Ok(None);
		};
		let pos0 = pos.pos.checked_sub(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"OutputReadSnapshot::get_unspent_output pos={}",
				pos.pos
			))
		})?;
		let output = txhashset::utxo_view(self.header_pmmr, self.txhashset, |utxo, _| {
			utxo.get_unspent_output_at(pos0)
		})?;
		if !ser::hashes_equal(self.get_context_id(), &output.identifier(), &stored)? {
			return Err(Error::InvalidPersistedChainState(format!(
				"output data at position {} does not match commitment {}",
				pos.pos,
				commit.to_hex()
			)));
		}
		let merkle_proof = if include_merkle_proof && stored.is_coinbase() {
			Some(self.get_merkle_proof(&stored, pos)?)
		} else {
			None
		};
		Ok(Some((output, stored, pos, merkle_proof)))
	}
}

impl Chain {
	fn ensure_chain_robust(&self) -> Result<(), Error> {
		if self.requires_init_recovery.load(Ordering::SeqCst) {
			warn!("chain marked as requiring init recovery; attempting recovery before continuing");
			self.recover_pending_chain_operation_checked("ensure_chain_robust")?;
		}
		Ok(())
	}

	fn with_robust_header_pmmr_read<T, F>(&self, f: F) -> Result<T, Error>
	where
		F: Fn(&PMMRHandle<BlockHeader>) -> Result<T, Error>,
	{
		self.ensure_chain_robust()?;
		loop {
			let header_pmmr = self.header_pmmr.read_recursive();
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}
			return f(&header_pmmr);
		}
	}

	fn with_robust_chain_read<T, F>(&self, f: F) -> Result<T, Error>
	where
		F: Fn(&PMMRHandle<BlockHeader>, &TxHashSet) -> Result<T, Error>,
	{
		self.ensure_chain_robust()?;
		loop {
			let header_pmmr = self.header_pmmr.read_recursive();
			let txhashset = self.txhashset.read_recursive();
			// A writer may have failed while this reader was waiting for locks.
			// Do not read txhashset/header state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}
			return f(&header_pmmr, &txhashset);
		}
	}

	/// Execute output-related reads against one coherent chain snapshot.
	///
	/// The supplied closure must not attempt a chain write. Header and body PMMR
	/// read locks, together with one database read transaction, remain held until
	/// the closure returns.
	pub fn with_output_read_snapshot<T, E, F>(&self, f: F) -> Result<T, E>
	where
		E: From<Error>,
		F: Fn(&OutputReadSnapshot<'_>) -> Result<T, E>,
	{
		let result = self
			.with_robust_chain_read(|header_pmmr, txhashset| {
				let batch = self
					.store
					.batch_read()
					.map_err(|e| Error::StoreErr(e, "create output read snapshot".to_owned()))?;
				let snapshot = OutputReadSnapshot {
					chain: self,
					header_pmmr,
					txhashset,
					batch,
				};
				Ok(f(&snapshot))
			})
			.map_err(E::from)?;
		result
	}

	fn ensure_header_pmmr_locked_for_marker(&self, op_name: &str) -> Result<(), Error> {
		// Defensive invariant check: parking_lot does not expose lock ownership,
		// so this proves only that the lock is not currently free.
		if let Some(header_pmmr) = self.header_pmmr.try_write() {
			drop(header_pmmr);
			return Err(Error::Other(format!(
				"{} attempted to set a chain operation marker without holding header_pmmr lock",
				op_name
			)));
		}
		Ok(())
	}

	fn set_pending_chain_operation_checked(
		&self,
		op: &PendingChainOperation,
	) -> Result<PendingChainOperationGuard, Error> {
		self.ensure_header_pmmr_locked_for_marker("set_pending_chain_operation")?;
		match self.store.set_pending_chain_operation_if_absent(op) {
			Ok(true) => Ok(PendingChainOperationGuard::new(
				self.requires_init_recovery.clone(),
			)),
			Ok(false) => {
				self.requires_init_recovery.store(true, Ordering::SeqCst);
				Err(Error::Other(
					"pending chain operation requires chain init recovery".into(),
				))
			}
			Err(e) => {
				// A failed durable commit can have an uncertain outcome. Fail closed so
				// the next top-level chain access checks for and recovers any marker.
				self.requires_init_recovery.store(true, Ordering::SeqCst);
				Err(e.into())
			}
		}
	}

	fn clear_pending_chain_operation_checked(&self) -> Result<(), Error> {
		match self.store.clear_pending_chain_operation() {
			Ok(()) => Ok(()),
			Err(e) => {
				self.requires_init_recovery.store(true, Ordering::SeqCst);
				Err(e.into())
			}
		}
	}

	#[cfg(test)]
	fn should_fail_process_marker_clear(&self, op_name: &str) -> bool {
		match op_name {
			"process_block_single" | "process_block_multiple" => self
				.fail_next_process_block_marker_clear
				.swap(false, Ordering::SeqCst),
			"process_block_header" => self
				.fail_next_process_block_header_marker_clear
				.swap(false, Ordering::SeqCst),
			_ => false,
		}
	}

	/// Invalidate every PIBD producer or consumer derived from the current PMMR state.
	///
	/// Callers that can invalidate a PIBD session's PMMR snapshot must advance this
	/// generation while holding the PMMR locks. Do not take `pibd_segmenter`
	/// here: `segmenter()` takes the cache lock before the PMMR locks, so doing so
	/// would invert the lock order.
	///
	/// Exhaustion fails closed instead of wrapping to a value held by an old
	/// Segmenter or Desegmenter. A process restart safely resets the generation
	/// because no in-memory PIBD objects survive it.
	fn advance_pibd_state_generation(&self) -> Result<(), Error> {
		self.pibd_state_generation
			.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |generation| {
				generation.checked_add(1)
			})
			.map(|_| ())
			.map_err(|_| {
				self.requires_init_recovery.store(true, Ordering::SeqCst);
				Error::DataOverflow("PIBD state generation exhausted; restart is required".into())
			})
	}

	#[cfg(test)]
	fn wait_after_rewind_bad_block_body_sync(&self) {
		let hook = self
			.rewind_bad_block_after_body_sync_hook
			.read_recursive()
			.clone();
		if let Some(hook) = hook {
			hook.reached
				.send(())
				.expect("rewind_bad_block body-sync test receiver dropped");
			hook.resume
				.lock()
				.expect("rewind_bad_block body-sync test mutex poisoned")
				.recv()
				.expect("rewind_bad_block body-sync test sender dropped");
		}
	}

	fn recover_pending_chain_operation_checked(&self, recovery_context: &str) -> Result<(), Error> {
		warn!("attempting recovery: {}", recovery_context);
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		// Reserve a non-repeating generation before recovery can clear its durable
		// marker. On exhaustion, leave both the marker and in-memory recovery latch
		// installed so no old PIBD object can become current again.
		self.advance_pibd_state_generation()?;
		#[cfg(test)]
		if self
			.fail_next_committed_recovery_with_bad_data
			.swap(false, Ordering::SeqCst)
		{
			self.requires_init_recovery.store(true, Ordering::SeqCst);
			return Err(Error::InvalidRoot(
				"forced local committed-recovery failure".into(),
			));
		}
		match recover_pending_chain_operation(
			&self.genesis,
			&self.store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
			self.pow_verifier,
			self.stop_state.clone(),
		) {
			Ok(()) => {
				self.requires_init_recovery.store(false, Ordering::SeqCst);
				Ok(())
			}
			Err(e) => {
				error!(
					"{} failed to recover pending chain operation: {}",
					recovery_context, e
				);
				Err(e)
			}
		}
	}

	fn handle_failed_pending_chain_operation(
		&self,
		op_name: &str,
		e: &Error,
		marker_guard: &mut PendingChainOperationGuard,
	) {
		warn!(
			"{} failed after marker was set; will attempt recovery: {}",
			op_name, e
		);
		marker_guard.require_recovery();
	}

	fn set_readonly_pmmr_discard_marker(
		&self,
		op_name: &str,
	) -> Result<PendingChainOperationGuard, Error> {
		match self.store.pending_chain_operation() {
			Ok(None) => {}
			Ok(Some(existing_op)) => {
				self.requires_init_recovery.store(true, Ordering::SeqCst);
				warn!(
					"{} found existing pending {:?} marker; chain init recovery is required before readonly PMMR access",
					op_name,
					existing_op.kind()
				);
				return Err(Error::Other(
					"pending chain operation requires chain init recovery".into(),
				));
			}
			Err(e) => {
				// An unreadable marker means we cannot prove that no interrupted
				// operation requires recovery. Keep all later chain access fail-closed.
				self.requires_init_recovery.store(true, Ordering::SeqCst);
				return Err(e.into());
			}
		}

		let op = prepare_reconcile_heads_operation(
			&self.store,
			ChainOperationKind::ReadonlyPmmrDiscard,
		)?;
		// This fails closed and latches recovery if another marker wins the
		// conditional insert or if the durable commit has an uncertain outcome.
		let marker_guard = self.set_pending_chain_operation_checked(&op)?;
		trace!(
			"{} set readonly PMMR discard recovery marker before operation",
			op_name
		);
		Ok(marker_guard)
	}

	fn finish_readonly_pmmr_discard_marker<T>(
		&self,
		op_name: &str,
		res: Result<T, Error>,
		mut marker_guard: PendingChainOperationGuard,
	) -> Result<T, Error> {
		match res {
			Ok(res) => {
				if self.requires_init_recovery.load(Ordering::SeqCst) {
					warn!(
						"{} completed while chain init recovery was required; retaining readonly PMMR recovery marker",
						op_name
					);
					marker_guard.require_recovery();
					return Err(Error::Other(
						"pending chain operation requires chain init recovery".into(),
					));
				}
				self.clear_pending_chain_operation_checked()?;
				// A non-PMMR path can latch recovery while the durable marker is
				// being cleared. Never publish a successful result in that case.
				if self.requires_init_recovery.load(Ordering::SeqCst) {
					marker_guard.require_recovery();
					return Err(Error::Other(
						"pending chain operation requires chain init recovery".into(),
					));
				}
				marker_guard.disarm();
				Ok(res)
			}
			Err(e) => {
				if e.is_txhashset_discard_failure() {
					error!(
						"{} failed to discard txhashset/header PMMR changes; chain marked for recovery: {}",
						op_name, e
					);
					marker_guard.require_recovery();
					Err(e)
				} else {
					match self.clear_pending_chain_operation_checked() {
						Ok(()) => {
							marker_guard.disarm();
							Err(e)
						}
						Err(clear_err) => {
							error!(
								"{} failed before readonly PMMR state changed: {}; additionally failed to clear readonly PMMR discard recovery marker: {}",
								op_name, e, clear_err
							);
							// Keep the primary operation error as the caller-visible result.
							// clear_pending_chain_operation_checked() marks init recovery on failure;
							// the clear failure is logged here for diagnostics.
							Err(e)
						}
					}
				}
			}
		}
	}

	// Caller must hold the PMMR lock(s) for the readonly operation before
	// setting this marker. This keeps marker lifetime serialized with the
	// operation that can fail to discard PMMR state.
	fn with_locked_readonly_pmmr_discard_marker<T, F>(
		&self,
		op_name: &str,
		f: F,
	) -> Result<T, Error>
	where
		F: FnOnce() -> Result<T, Error>,
	{
		self.ensure_header_pmmr_locked_for_marker(op_name)?;
		// Recovery takes the PMMR locks itself, so it cannot be performed here.
		// Reject the operation instead, ensuring no caller can run the closure
		// against state that a preceding writer left marked as uncertain.
		if self.requires_init_recovery.load(Ordering::SeqCst) {
			warn!(
				"{} refused readonly PMMR access because chain init recovery is required",
				op_name
			);
			return Err(Error::Other(
				"pending chain operation requires chain init recovery".into(),
			));
		}

		let marker_guard = self.set_readonly_pmmr_discard_marker(op_name)?;
		let res = f();
		self.finish_readonly_pmmr_discard_marker(op_name, res, marker_guard)
	}

	fn finish_pending_chain_operation<T>(
		&self,
		op_name: &str,
		res: Result<T, Error>,
		state_may_have_changed: bool,
		mut marker_guard: PendingChainOperationGuard,
	) -> Result<PendingChainOperationCompletion<T>, Error> {
		match res {
			Ok(res) => {
				#[cfg(test)]
				let clear_res = if self.should_fail_process_marker_clear(op_name) {
					self.requires_init_recovery.store(true, Ordering::SeqCst);
					Err(Error::Other(format!(
						"forced pending marker clear failure for {}",
						op_name
					)))
				} else {
					self.clear_pending_chain_operation_checked()
				};
				#[cfg(not(test))]
				let clear_res = self.clear_pending_chain_operation_checked();

				match clear_res {
					Ok(()) => {
						marker_guard.disarm();
						Ok(PendingChainOperationCompletion::Complete(res))
					}
					Err(marker_error) => {
						// The operation's batch is already committed. Retain its value
						// while recovery reconciles PMMR state and clears the marker.
						marker_guard.require_recovery();
						Ok(PendingChainOperationCompletion::CommittedNeedsRecovery {
							value: res,
							marker_error,
						})
					}
				}
			}
			Err(e) => {
				if state_may_have_changed || e.requires_chain_recovery() {
					self.handle_failed_pending_chain_operation(op_name, &e, &mut marker_guard);
					Err(e)
				} else {
					match self.clear_pending_chain_operation_checked() {
						Ok(()) => {
							marker_guard.disarm();
							Err(e)
						}
						Err(clear_err) => {
							error!(
								"{} failed before chain state changed: {}; additionally failed to clear pending chain operation marker: {}",
								op_name, e, clear_err
							);
							// Returning original error, clear error doesn't matter for caller
							Err(e)
						}
					}
				}
			}
		}
	}

	/// Initializes the blockchain and returns a new Chain instance. Does a
	/// check on the current chain head to make sure it exists and creates one
	/// based on the genesis block if necessary. Routine persisted blockchain
	/// validation can be skipped, but genesis validation and incomplete-operation
	/// recovery remain mandatory initialization safety checks.
	pub fn init(
		secp: &Secp256k1,
		context_id: u32,
		db_root: String,
		adapter: Arc<dyn ChainAdapter + Send + Sync>,
		genesis: Block,
		pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
		archive_mode: bool,
		invalid_blocks: HashSet<Hash>,
		sync_state: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
		skip_start_blockchain_validation: bool,
	) -> Result<Chain, Error> {
		validate_genesis_for_init(secp, context_id, &genesis, pow_verifier)?;
		if skip_start_blockchain_validation {
			warn!("init: skipping startup blockchain data validation");
		} else {
			println!(
				"Starting blockchain data validation. It might take few minutes, please wait..."
			);
		}

		let store = Arc::new(store::ChainStore::new(context_id, &db_root)?);

		let pibd_params = Arc::new(PibdParams::new());

		// DB migrations to be run prior to the chain being used.
		// Migrate full blocks to protocol version v3.
		Chain::migrate_db_v2_v3(&store)?;

		// open the txhashset, creating a new one if necessary
		let mut txhashset =
			txhashset::TxHashSet::open(db_root.clone(), store.clone(), None, &secp)?;

		let mut header_pmmr = PMMRHandle::new(
			Path::new(&db_root).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			context_id,
			None,
			VariableSizeMetadataValidation::Full,
		)?;

		// Migrate legacy positions-only per-block spent indexes to the exact
		// occurrence format before recovery can rewind blocks that carry them.
		// The output PMMR is open at this point, so the migration resolves each
		// active-window legacy position's commitment from retained leaf data.
		Chain::migrate_spent_index(&store, &txhashset, stop_state.clone())?;

		// The spent-occurrence index must be complete before recovery runs:
		// rewind and reconciliation paths consume it. An index left incomplete
		// by a crash or an older version is rebuilt from the retained full
		// blocks here.
		Chain::init_spent_commitment_index(&store, stop_state.clone())?;

		mark_interrupted_pibd_for_recovery(&genesis, &store, &txhashset)?;

		recover_pending_chain_operation(
			&genesis,
			&store,
			&mut header_pmmr,
			&mut txhashset,
			secp,
			pow_verifier,
			stop_state.clone(),
		)?;

		setup_head(
			&genesis,
			&store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
			pow_verifier,
			stop_state.clone(),
			skip_start_blockchain_validation,
			None,
		)?;

		// Initialize the output_pos index based on UTXO set
		// and NRD kernel_pos index based recent kernel history.
		let kernel_pos_index_complete = {
			let batch = store.batch_write()?;
			if batch.is_output_pos_index_complete()? {
				debug!("init: output_pos index is complete, skipping rebuild");
			} else {
				txhashset.init_output_pos_index(&batch, sync_state.clone(), stop_state.clone())?;
			}
			txhashset.init_recent_kernel_pos_index(
				&batch,
				sync_state.clone(),
				stop_state.clone(),
			)?;
			let complete = batch.is_kernel_pos_index_complete()?;
			batch.commit()?;
			complete
		};
		if !kernel_pos_index_complete {
			txhashset.init_kernel_pos_index_chunked(
				&store,
				sync_state.clone(),
				stop_state.clone(),
			)?;
		}
		// Re-check after recovery and head setup: on a fresh DB the head did not
		// exist at the first call, and recovery may have reset chain state.
		// No-op if the index is already complete.
		Chain::init_spent_commitment_index(&store, stop_state.clone())?;

		let chain = Chain {
			db_root,
			store,
			adapter,
			orphans: Arc::new(OrphanBlockPool::new(pibd_params.clone())),
			txhashset: Arc::new(RwLock::new(txhashset)),
			header_pmmr: Arc::new(RwLock::new(header_pmmr)),
			pibd_segmenter: Arc::new(RwLock::new(None)),
			pow_verifier,
			archive_mode,
			genesis: genesis,
			cache_header_difficulty: Arc::new(RwLock::new(DifficultyCache::new())),
			pibd_params,
			stop_state,
			requires_init_recovery: Arc::new(AtomicBool::new(false)),
			pibd_state_generation: Arc::new(AtomicU64::new(0)),
			#[cfg(test)]
			fail_next_process_block_marker_clear: AtomicBool::new(false),
			#[cfg(test)]
			fail_next_process_block_header_marker_clear: AtomicBool::new(false),
			#[cfg(test)]
			fail_next_committed_recovery_with_bad_data: AtomicBool::new(false),
			#[cfg(test)]
			process_block_batch_safety_depth: AtomicU64::new(100),
			#[cfg(test)]
			rewind_bad_block_after_body_sync_hook: RwLock::new(None),
		};

		chain.apply_invalid_blocks(secp, invalid_blocks)?;

		Ok(chain)
	}

	/// Apply and set invalid blocks data.
	pub fn apply_invalid_blocks(
		&self,
		secp: &Secp256k1,
		invalid_blocks: HashSet<Hash>,
	) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		// Publish the denylist before rewinding so concurrent block/header
		// processing cannot re-accept the denied hash after the rewind.
		pipe::init_invalid_block_hashes(self.get_context_id(), invalid_blocks.clone());
		self.rewind_bad_block(secp, &invalid_blocks)?;
		self.log_heads()?;
		Ok(())
	}

	/// Pibd params with envoronment monitoring
	pub fn get_pibd_params(&self) -> &Arc<PibdParams> {
		&self.pibd_params
	}

	/// Reset chain to be ready to download data with PIBD
	pub fn reset_pibd_chain(&self) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;

		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		let mut marker_guard =
			self.set_pending_chain_operation_checked(&PendingChainOperation::PibdReset)?;
		let res = reset_pibd_chain_state(
			&self.genesis,
			&self.store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
			self.pow_verifier,
			self.stop_state.clone(),
		);

		match res {
			Ok(()) => {
				self.advance_pibd_state_generation()?;
				self.clear_pending_chain_operation_checked()?;
				marker_guard.disarm();
				Ok(())
			}
			Err(e) => {
				self.handle_failed_pending_chain_operation(
					"reset_pibd_chain",
					&e,
					&mut marker_guard,
				);
				Err(e)
			}
		}
	}

	/// Reset both head and header_head to the provided header.
	/// Handles simple rewind and more complex fork scenarios.
	/// Used by the reset_chain_head owner api endpoint.
	/// Caller can choose not to rewind headers, which can be used
	/// during PIBD scenarios where it's desirable to restart the PIBD process
	/// without re-downloading the header chain
	pub fn reset_chain_head(
		&self,
		secp: &Secp256k1,
		header: &BlockHeader,
		rewind_headers: bool,
	) -> Result<(), Error> {
		self.ensure_chain_robust()?;

		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		let op = prepare_reset_chain_head_operation(&self.store, header, rewind_headers)?;
		let mut marker_guard = self.set_pending_chain_operation_checked(&op)?;
		let res = reset_chain_head_state(
			&self.store,
			&mut header_pmmr,
			&mut txhashset,
			secp,
			header,
			rewind_headers,
		);

		match res {
			Ok(()) => {
				self.advance_pibd_state_generation()?;
				self.clear_pending_chain_operation_checked()?;
				marker_guard.disarm();
				Ok(())
			}
			Err(e) => {
				self.handle_failed_pending_chain_operation(
					"reset_chain_head",
					&e,
					&mut marker_guard,
				);
				Err(e)
			}
		}
	}

	/// wipes the chain head down to genesis, without attempting to rewind
	/// Used upon PIBD failure, where we want to keep the header chain but
	/// restart the output PMMRs from scratch
	pub fn reset_chain_head_to_genesis(&self) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		let mut marker_guard =
			self.set_pending_chain_operation_checked(&PendingChainOperation::ResetToGenesis)?;
		let res = reset_chain_head_to_genesis_state(
			&self.genesis,
			&self.store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
			self.pow_verifier,
			self.stop_state.clone(),
			true,
		);
		match res {
			Ok(()) => {
				self.advance_pibd_state_generation()?;
				self.clear_pending_chain_operation_checked()?;
				marker_guard.disarm();
				Ok(())
			}
			Err(e) => {
				self.handle_failed_pending_chain_operation(
					"reset_chain_head_to_genesis",
					&e,
					&mut marker_guard,
				);
				Err(e)
			}
		}
	}

	/// Are we running with archive_mode enabled?
	pub fn archive_mode(&self) -> bool {
		self.archive_mode
	}

	/// Return our shared header MMR handle.
	/// Note, caller is responsible for locking in correct order. See the comment at declaration
	#[cfg(test)]
	pub fn get_header_pmmr_for_test(&self) -> Arc<RwLock<PMMRHandle<BlockHeader>>> {
		self.header_pmmr.clone()
	}

	/// Return our shared txhashset instance.
	/// Note, caller is responsible for locking in correct order. See the comment at declaration
	#[cfg(test)]
	pub fn get_txhashset_for_test(&self) -> Arc<RwLock<TxHashSet>> {
		self.txhashset.clone()
	}

	/// return genesis header
	pub fn genesis(&self) -> BlockHeader {
		self.genesis.header.clone()
	}

	/// Shared store instance.
	/// Note, caller is responsible for locking in correct order. See the comment at declaration
	#[cfg(test)]
	pub fn get_store_for_tests(&self) -> Arc<store::ChainStore> {
		self.store.clone()
	}

	/// Known bad block that we must rewind prior to if seen on "current chain".
	///
	/// Missing denylisted headers are intentionally skipped without an active-chain
	/// membership check. This feature blocks known headers or blocks present in a
	/// healthy database; database corruption is explicitly outside its threat model
	/// and must be handled separately.
	pub fn rewind_bad_block(
		&self,
		secp: &Secp256k1,
		invalid_blocks: &HashSet<Hash>,
	) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		for hash in invalid_blocks {
			let header = match self.get_block_header(hash) {
				Ok(header) => header,
				Err(Error::StoreErr(NotFoundErr(_), _)) => continue,
				Err(e) => return Err(e),
			};

			let header_hash = header.hash(context_id)?;
			if header_hash != *hash {
				return Err(Error::InvalidPersistedChainState(format!(
					"rewind_bad_block loaded header {} from denylisted key {}",
					header_hash, hash
				)));
			}

			loop {
				self.ensure_chain_robust()?;
				let mut header_pmmr = self.header_pmmr.write();
				// A writer may have marked recovery while this call was waiting
				// for header_pmmr. Drop the lock before attempting recovery.
				if self.requires_init_recovery.load(Ordering::SeqCst) {
					drop(header_pmmr);
					continue;
				}

				let read_batch = self.store.batch_read()?;
				let persisted_header_head = read_batch
					.header_head()
					.map_err(|e| Error::StoreErr(e, "header head".to_owned()))?;
				// `last_block_h` is the authoritative HEADER_HEAD selector. Rebuild
				// the redundant Tip fields before using its cached height to bound a
				// PMMR membership check.
				let (old_header_head_header, old_header_head) = canonical_tip_header(
					"rewind_bad_block HEADER_HEAD",
					&persisted_header_head,
					&read_batch,
				)?;
				let old_body_head = read_batch
					.head()
					.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))?;

				// Establish whether the initially loaded denied header is relevant
				// before following its prev_hash. Canonical cleanup may retain an
				// off-chain child after deleting its formerly canonical parent; that
				// detached child must not turn an otherwise successful denylist pass
				// into a persistent missing-header error.
				let mut rewind_headers = self.is_on_current_chain_with_header_pmmr(
					&header_pmmr,
					Tip::try_from_header(&header)?,
					old_header_head.clone(),
				)?;
				let mut rewind_body =
					self.is_on_body_chain_with_batch(&read_batch, &header, &old_body_head)?;
				if !rewind_headers && !rewind_body {
					break;
				}

				// The header is active on at least one durable chain. Missing or
				// malformed ancestry from this point is active-chain corruption and
				// must remain fatal.
				let mut ancestry_visited = HashSet::new();
				let mut prev_header = crate::checked_previous_header(
					context_id,
					&header,
					&mut ancestry_visited,
					"rewind_bad_block ancestry",
					|hash| read_batch.get_block_header(hash),
				)?;
				let mut denied_headers = vec![header.clone()];
				// A stronger implementation could batch all denied current-chain
				// blocks into one atomic rewind, but validation is expected to
				// report a single bad block in normal operation. Keep this per-hash
				// path, but do not choose a rewind target that is also denied if a
				// HashSet happens to visit adjacent bad blocks descendant-first.
				while invalid_blocks.contains(&prev_header.hash(context_id)?) {
					denied_headers.push(prev_header.clone());
					prev_header = crate::checked_previous_header(
						context_id,
						&prev_header,
						&mut ancestry_visited,
						"rewind_bad_block denied ancestry",
						|hash| read_batch.get_block_header(hash),
					)?;
				}
				let new_head = Tip::try_from_header(&prev_header)?;

				// HEADER_HEAD and BODY_HEAD may legitimately be on competing forks.
				// Determine membership independently, considering every adjacent denied
				// ancestor that the rewind target skips.
				for denied_header in denied_headers.iter().skip(1) {
					if rewind_headers {
						break;
					}
					if self.is_on_current_chain_with_header_pmmr(
						&header_pmmr,
						Tip::try_from_header(denied_header)?,
						old_header_head.clone(),
					)? {
						rewind_headers = true;
						break;
					}
				}

				for denied_header in denied_headers.iter().skip(1) {
					if rewind_body {
						break;
					}
					if self.is_on_body_chain_with_batch(
						&read_batch,
						denied_header,
						&old_body_head,
					)? {
						rewind_body = true;
						break;
					}
				}
				debug!(
					"rewind_bad_block: found denied header {} at {}; rewind_headers={}, rewind_body={}",
					header_hash, header.height, rewind_headers, rewind_body
				);

				// Preflight the complete body cleanup path before mutating a PMMR or
				// setting the durable recovery marker. Rewinding below BODY_TAIL would
				// leave the tail above HEAD and pointing at a deleted full block.
				let mut body_cleanup_headers = Vec::new();
				if rewind_body {
					let body_tail = read_batch
						.tail()
						.map_err(|e| Error::StoreErr(e, "body tail".to_owned()))?;
					if body_tail.height > old_body_head.height {
						return Err(Error::InvalidPersistedChainState(format!(
							"rewind_bad_block BODY_TAIL height {} is above BODY_HEAD height {}",
							body_tail.height, old_body_head.height
						)));
					}
					let canonical_tail = self.body_chain_header_at_height(
						&read_batch,
						&old_body_head,
						body_tail.height,
					)?;
					let canonical_tail_hash = canonical_tail.hash(context_id)?;
					let body_tail_hash = body_tail.hash(context_id)?;
					if canonical_tail_hash != body_tail_hash {
						return Err(Error::InvalidPersistedChainState(format!(
							"rewind_bad_block BODY_TAIL {} at height {} is not on the body chain; found {}",
							body_tail_hash, body_tail.height, canonical_tail_hash
						)));
					}
					if new_head.height < body_tail.height {
						return Err(Error::Other(format!(
							"rewind_bad_block cannot rewind BODY_HEAD to {} at height {} below BODY_TAIL {} at height {}; a full chain-state reset is required",
							new_head.hash(context_id)?,
							new_head.height,
							body_tail_hash,
							body_tail.height
						)));
					}

					let old_body_hash = old_body_head.hash(context_id)?;
					let mut current = read_batch.get_block_header(&old_body_hash)?;
					let computed_body_hash = current.hash(context_id)?;
					if computed_body_hash != old_body_hash {
						return Err(Error::InvalidPersistedChainState(format!(
							"rewind_bad_block BODY_HEAD selected {}, header hashes to {}",
							old_body_hash, computed_body_hash
						)));
					}
					let mut cleanup_visited = HashSet::new();
					while current.height > new_head.height {
						crate::checked_block_for_header(
							context_id,
							&current,
							"rewind_bad_block body cleanup preflight",
							|hash| read_batch.get_block(hash),
						)?;
						let previous = crate::checked_previous_header(
							context_id,
							&current,
							&mut cleanup_visited,
							"rewind_bad_block body cleanup ancestry",
							|hash| read_batch.get_block_header(hash),
						)?;
						body_cleanup_headers.push(current);
						current = previous;
					}
					if current != prev_header {
						return Err(Error::InvalidPersistedChainState(format!(
							"rewind_bad_block body cleanup reached {} at height {}, expected {} at height {}",
							current.hash(context_id)?,
							current.height,
							prev_header.hash(context_id)?,
							prev_header.height
						)));
					}
					// The loop above authenticates only descendants that will be
					// deleted. The target remains in the retained body window and
					// becomes BODY_HEAD, so require its exact full-block record too.
					crate::checked_block_for_header(
						context_id,
						&prev_header,
						"rewind_bad_block body target preflight",
						|hash| read_batch.get_block(hash),
					)?;
				}

				// Preflight the header cleanup path and every optional full block.
				// A full block must remain paired with its header until delete_block()
				// has removed its dependent records.
				let mut header_cleanup_headers = Vec::new();
				if rewind_headers {
					let mut current = old_header_head_header.clone();
					let mut cleanup_visited = HashSet::new();
					while current.height > new_head.height {
						let current_hash = current.hash(context_id)?;
						if read_batch.block_exists(&current_hash)? {
							crate::checked_block_for_header(
								context_id,
								&current,
								"rewind_bad_block header cleanup preflight",
								|hash| read_batch.get_block(hash),
							)?;
						}
						let previous = crate::checked_previous_header(
							context_id,
							&current,
							&mut cleanup_visited,
							"rewind_bad_block header cleanup ancestry",
							|hash| read_batch.get_block_header(hash),
						)?;
						header_cleanup_headers.push(current);
						current = previous;
					}
					if current != prev_header {
						return Err(Error::InvalidPersistedChainState(format!(
							"rewind_bad_block header cleanup reached {} at height {}, expected {} at height {}",
							current.hash(context_id)?,
							current.height,
							prev_header.hash(context_id)?,
							prev_header.height
						)));
					}
				}
				drop(read_batch);

				// A body rewind needs both PMMR locks and an LMDB writer. Acquire
				// them in the documented header_pmmr -> txhashset -> store order.
				// Keep the optional body guard alive until the marker is finalized so
				// readers cannot pair speculative PMMR sizes with old database heads.
				let mut body_txhashset = if rewind_body {
					Some(self.txhashset.write())
				} else {
					None
				};
				let op = prepare_reconcile_heads_operation(
					&self.store,
					ChainOperationKind::RewindBadBlock,
				)?;
				let mut marker_guard = self.set_pending_chain_operation_checked(&op)?;
				let res = (|| {
					let mut batch = self.store.batch_write()?;

					if let Some(txhashset) = body_txhashset.as_deref_mut() {
						debug!(
							"rewind_bad_block: rewinding BODY_HEAD to {} at {}",
							prev_header.hash(context_id)?,
							prev_header.height
						);

						txhashset::extending(
							&mut header_pmmr,
							txhashset,
							&mut batch,
							|ext, batch| {
								self.rewind_and_apply_fork(secp, &prev_header, ext, batch)?;
								ext.extension.validate_roots(&prev_header)?;
								ext.extension.validate_sizes(&prev_header)?;
								// HEADER_HEAD is independent and may be on a competing fork.
								batch.save_body_head(&new_head)?;
								Ok(())
							},
						)?;

						for removed_header in &body_cleanup_headers {
							batch.delete_block(&removed_header.hash(context_id)?)?;
						}
					}
					#[cfg(test)]
					if rewind_body {
						self.wait_after_rewind_bad_block_body_sync();
					}

					if rewind_headers {
						debug!(
							"rewind_bad_block: rewinding HEADER_HEAD to {} at {}",
							prev_header.hash(context_id)?,
							prev_header.height
						);
						txhashset::header_extending(&mut header_pmmr, &mut batch, |ext, batch| {
							self.rewind_and_apply_header_fork(&prev_header, ext, batch)?;
							batch.save_header_head(&new_head)?;
							Ok(())
						})?;

						for removed_header in &header_cleanup_headers {
							let removed_hash = removed_header.hash(context_id)?;
							// delete_block() requires the separately stored header, so the
							// full block and its dependent indices must be removed first.
							if batch.block_exists(&removed_hash)? {
								batch.delete_block(&removed_hash)?;
							}
							batch.delete_block_header(&removed_hash)?;
						}
					}

					batch.commit()?;
					// The committed rewind invalidates every PIBD snapshot derived from
					// the previous PMMR state. Advance the generation before clearing the
					// marker and while the affected PMMR write guards remain held.
					self.advance_pibd_state_generation()?;

					Ok(())
				})();
				match res {
					Ok(()) => {
						self.clear_pending_chain_operation_checked()?;
						marker_guard.disarm();
					}
					Err(e) => {
						self.handle_failed_pending_chain_operation(
							"rewind_bad_block",
							&e,
							&mut marker_guard,
						);
						return Err(e);
					}
				}
				break;
			}
		}

		Ok(())
	}

	fn log_heads(&self) -> Result<(), Error> {
		let log_head = |name, head: Tip| -> Result<(), Error> {
			debug!(
				"{}: {} @ {} [{}]",
				name,
				head.total_difficulty.to_num(),
				head.height,
				head.hash(self.store.get_context_id())?,
			);
			Ok(())
		};
		log_head("head", self.head()?)?;
		let sync_head = self.header_head()?;
		log_head("header_head", sync_head)?;

		// Needed for Node State tracking...
		info!(
			"init: sync_head: {} @ {} [{}]",
			sync_head.total_difficulty.to_num(),
			sync_head.height,
			sync_head.last_block_h,
		);

		Ok(())
	}

	/// Processes a single block, then checks for orphans, processing
	/// those as well if they're found
	pub fn process_block(
		&self,
		secp: &mut Secp256k1,
		b: Block,
		opts: Options,
		source_peers: HashSet<String>,
	) -> Result<Option<Tip>, Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		pipe::validate_header_context_id(context_id, &b.header)?;
		let block_hash = b.hash(context_id)?;
		let report_peers = source_peers.clone();

		// Check if block can be processed now. Overwise add it to orphans and returns error
		if let Err(e) = self.check_block(&b, opts, source_peers) {
			// OldBlock is also a known-block outcome. Exact stored duplicates must
			// never be attributed to their source peers as invalid remote data.
			if e.is_bad_data() && !e.is_known_block() && !report_peers.is_empty() {
				self.adapter.block_rejected(&block_hash, &report_peers, &e);
			}
			return Err(e);
		}

		// block is not orphnan and it is great
		// Let's try to add several blocks from the current active branch. Adding many in a single
		// transaction is good for performance.
		let mut blocks: Vec<Block> = vec![];

		// We can't process as multiple during sync because it is slow.
		// But also we better to process blocks one by one when node running because of possible reorg.
		// Reord requires to roll back single block, not a whole package.
		#[cfg(test)]
		let batch_safety_depth = self.process_block_batch_safety_depth.load(Ordering::SeqCst);
		#[cfg(not(test))]
		let batch_safety_depth = 100;
		let multiple_processing_height_limit = self
			.header_head()?
			.height
			.saturating_sub(batch_safety_depth);
		if b.header.height < multiple_processing_height_limit {
			// if it is a block on the chain, let's try to add many of them
			match self.get_header_by_height(b.header.height) {
				Ok(header) => {
					let context_id = self.store.get_context_id();
					// this block is expected to be from the main chain, we are expecting approve long sequence, not a short branch
					if header.hash(context_id)? == b.hash(context_id)? {
						blocks.push(b.clone());
						loop {
							let last_block = blocks.last().ok_or(Error::Other(
								"Internal error, no blocks at process_block".into(),
							))?;
							let next_hegiht =
								last_block.header.height.checked_add(1).ok_or_else(|| {
									Error::DataOverflow(format!(
										"Chain::process_block, last_block.header.height={}",
										last_block.header.height
									))
								})?;
							match self.get_header_by_height(next_hegiht) {
								Ok(header) => {
									if let Some(orphan) =
										self.orphans.get_orphan(&header.hash(context_id)?)
									{
										blocks.push(orphan.block);
										continue; // can process the next block
									}
								}
								Err(e) if e.is_not_found() => {}
								Err(e) => return Err(e),
							}
							break;
						}
						if blocks
							.last()
							.ok_or(Error::Other(
								"Process block internal error, collection was empty".into(),
							))?
							.header
							.height < multiple_processing_height_limit
						{
							// good, we can process multiple blocks, it should be faster than one by one
							let mut block_hashes: Vec<(u64, Hash)> = Vec::new();
							for b in &blocks {
								block_hashes.push((b.header.height, b.hash(context_id)?));
							}
							match self.process_block_multiple(secp, &blocks, opts) {
								Ok(tip) => {
									info!(
										"Accepted multiple blocks from {} to {}",
										blocks.first().map(|b| b.header.height).unwrap_or(0),
										blocks.last().map(|b| b.header.height).unwrap_or(0)
									);
									// We are good, let's clean up the orphans
									for (height, hash) in block_hashes {
										let _ = self
											.orphans
											.remove_by_height_header_hash(height, &hash);
									}
									return Ok(tip); // Done with success
								}
								Err(BlockProcessingError::NotCommitted(e)) => {
									self.ensure_chain_robust()?;
									if e.is_bad_data() {
										info!(
											"Failed to process multiple blocks, will try process one by one. {}",
											e
										);
									} else {
										debug!(
											"Failed to process multiple blocks, will try process one by one. {}",
											e
										);
									}
								}
								Err(BlockProcessingError::CommittedRecoveryFailed(e)) => {
									error!(
										"Committed block batch could not complete chain recovery: {}",
										e
									);
									return Err(Error::committed_recovery_failed(
										"process_block_multiple committed marker cleanup",
										e,
									));
								}
							}
						}
					}
				}
				Err(e) if e.is_not_found() => {}
				Err(e) => return Err(e),
			}
		}

		// Processing blocks one by one. It is slower, but any possible error will be caught on block level.
		let height = b.header.height;
		match self.process_block_single(secp, b, opts) {
			Ok(tip) => {
				let next_height = height.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!("Chain::process_block, height={}", height))
				})?;
				self.check_orphans(secp, next_height)?;
				return Ok(tip);
			}
			Err(BlockProcessingError::NotCommitted(e)) => {
				// A duplicate can pass the initial unlocked known-block check and
				// then lose a race to another peer response before the pipeline
				// acquires its write locks. The block is valid and already stored,
				// so this is normal sync control flow rather than a rejection.
				if e.is_known_block() {
					debug!(
						"process_block_single found block already known after a concurrent update: {}",
						e
					);
				} else if e.is_bad_data() {
					error!("process_block_single failed with error: {}", e);
					if !report_peers.is_empty() {
						self.adapter.block_rejected(&block_hash, &report_peers, &e);
					}
				} else {
					debug!("process_block_single failed with error: {}", e);
				}
				return Err(e);
			}
			Err(BlockProcessingError::CommittedRecoveryFailed(e)) => {
				error!(
					"Committed single block could not complete chain recovery: {}",
					e
				);
				return Err(Error::committed_recovery_failed(
					"process_block_single committed marker cleanup",
					e,
				));
			}
		}
	}

	/// We plan to support receiving blocks with CommitOnly inputs.
	/// We also need to support relaying blocks with FeaturesAndCommit inputs to peers.
	/// So we need a way to convert blocks from CommitOnly to FeaturesAndCommit.
	/// Validating the inputs against the utxo_view allows us to look the outputs up.
	pub fn convert_block_v2(&self, secp: &Secp256k1, block: Block) -> Result<Block, Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		debug!(
			"convert_block_v2: {} at {} ({} -> v2)",
			block.header.hash(context_id)?,
			block.header.height,
			block.inputs().version_str(),
		);

		if block.inputs().is_empty() {
			return Ok(Block {
				header: block.header,
				body: block
					.body
					.replace_inputs(self.get_context_id(), Inputs::FeaturesAndCommit(vec![]))?,
			});
		}

		let inputs: Vec<_> = loop {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();

			// A writer may have failed while this thread was waiting for locks.
			// Do not convert against PMMR/txhashset state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			break self.with_locked_readonly_pmmr_discard_marker("convert_block_v2", || {
				txhashset::extending_readonly(
					self.store.get_context_id(),
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						let previous_header = crate::checked_previous_header(
							context_id,
							&block.header,
							&mut HashSet::new(),
							"convert_block_v2 predecessor",
							|hash| batch.get_block_header(hash),
						)?;
						self.rewind_and_apply_fork(secp, &previous_header, ext, batch)?;
						ext.extension
							.utxo_view(ext.header_extension)
							.validate_inputs(&block.inputs(), batch)
							.map(|outputs| outputs.into_iter().map(|(out, _)| out).collect())
					},
				)
			});
		}?;
		let inputs = Inputs::from_output_identifiers(context_id, inputs.as_slice())?;
		Ok(Block {
			header: block.header,
			body: block.body.replace_inputs(self.get_context_id(), inputs)?,
		})
	}

	fn determine_status(
		&self,
		head: Option<Tip>,
		prev: Tip,
		prev_head: Tip,
		fork_point: Tip,
	) -> BlockStatus {
		// If head is updated then we are either "next" block or we just experienced a "reorg" to new head.
		// Otherwise this is a "fork" off the main chain.
		if head.is_some() {
			let fork_point_is_prev_head = fork_point.height == prev_head.height
				&& fork_point.last_block_h == prev_head.last_block_h;

			if fork_point_is_prev_head {
				BlockStatus::Next { prev }
			} else {
				BlockStatus::Reorg {
					prev,
					prev_head,
					fork_point,
				}
			}
		} else {
			BlockStatus::Fork {
				prev,
				head: prev_head,
				fork_point,
			}
		}
	}

	/// Quick check for "known" duplicate block up to and including current chain head.
	/// Returns an error if this block is "known".
	pub fn is_known(&self, header: &BlockHeader) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		let head = self.head()?;
		let header_hash = header.hash(context_id)?;
		if head.hash(context_id)? == header_hash {
			return Err(Error::Unfit("duplicate block".into()));
		}
		if header.total_difficulty() <= head.total_difficulty {
			if self.block_exists(&header_hash)? {
				return Err(Error::Unfit("duplicate block".into()));
			}
		}
		Ok(())
	}

	fn check_exact_known_block(&self, b: &Block) -> Result<(), Error> {
		let context_id = self.store.get_context_id();
		let bh = b.hash(context_id)?;
		let existing = match self.store.get_block(&bh) {
			Ok(existing) => existing,
			Err(NotFoundErr(_)) => return Ok(()),
			Err(e) => return Err(Error::StoreErr(e, "chain get exact known block".to_owned())),
		};

		// The store side is already validated v3 data. Normalize the legacy
		// candidate only for this known-block decision; see blocks_equal_as_v3.
		if !blocks_equal_as_v3(context_id, &existing, b)? {
			return Ok(());
		}

		let head = self.head()?;
		if bh == head.last_block_h || bh == head.prev_block_h {
			Err(Error::Unfit("already known in head".into()))
		} else if b.header.total_difficulty() > head.total_difficulty {
			// Stored blocks with more work may need to be applied again after a
			// reset or when a fork becomes the active body chain.
			Ok(())
		} else if b.header.height < head.height.saturating_sub(50) {
			Err(Error::OldBlock)
		} else {
			Err(Error::Unfit("already known in store".into()))
		}
	}

	// Check if the provided block is an orphan.
	// If block is an orphan add it to our orphan block pool for deferred processing.
	// If this is the "next" block immediately following current head then not an orphan.
	// Or if we have the previous full block then not an orphan.
	fn check_orphan(
		&self,
		block: &Block,
		opts: Options,
		source_peers: HashSet<String>,
	) -> Result<(), Error> {
		let head = self.head()?;
		let is_next = block.header.prev_hash == head.last_block_h;
		if is_next || self.block_exists(&block.header.prev_hash)? {
			return Ok(());
		}

		let context_id = self.store.get_context_id();
		let block_hash = block.hash(context_id)?;
		let orphan = Orphan {
			block: block.clone(),
			opts,
			source_peers,
			added: Instant::now(),
		};
		self.orphans.add(context_id, orphan)?;

		debug!(
			"is_orphan: {:?}, # orphans {}{}",
			block_hash,
			self.orphans.len(),
			if self.orphans.len_evicted() > 0 {
				format!(", # evicted {}", self.orphans.len_evicted())
			} else {
				String::new()
			},
		);

		Err(Error::Orphan(String::new()))
	}

	// Check block is starting routine from process_block_single.
	// It is separated because we are using it to deted if block is orphan
	fn check_block(
		&self,
		b: &Block,
		opts: Options,
		source_peers: HashSet<String>,
	) -> Result<(), Error> {
		// Process the header first.
		// If invalid then fail early.
		// If valid then continue with block processing with header_head committed to db etc.
		self.process_block_header(&b.header, opts)?;

		// Header processing above has already validated PoW and exact stored-header
		// identity. Only an exact full-block duplicate is known here; a different
		// body under the same validated header must continue through body/state
		// validation rather than being misclassified as a duplicate.
		self.check_exact_known_block(b)?;

		// Check if this block is an orphan.
		// Only do this once we know the header PoW is valid.
		self.check_orphan(b, opts, source_peers)?;

		Ok(())
	}

	/// Attempt to add a new block to the chain.
	/// Returns true if it has been added to the longest chain
	/// or false if it has added to a fork (or orphan?).
	fn process_block_single(
		&self,
		secp: &mut Secp256k1,
		b: Block,
		opts: Options,
	) -> Result<Option<Tip>, BlockProcessingError> {
		let mut state_may_have_changed = false;
		let completion = {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let op =
				prepare_reconcile_heads_operation(&self.store, ChainOperationKind::ProcessBlock)?;
			let marker_guard = self.set_pending_chain_operation_checked(&op)?;
			let res = (|| {
				let context_id = self.store.get_context_id();
				let batch = self.store.batch_write()?;
				let prev_head = batch.head()?;
				let mut ctx = self.new_ctx(opts, batch, &mut header_pmmr, &mut txhashset)?;

				let bv = vec![b.clone()];
				let (head, fork_point) = pipe::process_blocks_series(
					self.store.get_context_id(),
					&bv,
					&mut ctx,
					&mut state_may_have_changed,
					secp,
				)?;

				// Prepare every fallible input to the acceptance callback before the
				// durable commit. A successful commit must leave only marker recovery
				// and infallible publication work.
				let prev = ctx.batch.get_previous_header(&b.header).map_err(|e| {
					Error::StoreErr(e, "process_block_single get previous header".into())
				})?;
				let status = self.determine_status(
					head,
					Tip::try_from_header(&prev)?,
					prev_head,
					Tip::try_from_header(&fork_point)?,
				);
				let block_hash = b.hash(context_id)?;
				ctx.batch.commit()?;

				Ok((head, status, block_hash))
			})();
			self.finish_pending_chain_operation(
				"process_block_single",
				res,
				state_may_have_changed,
				marker_guard,
			)
		}?;

		let (head, status, block_hash) = match completion {
			PendingChainOperationCompletion::Complete(value) => value,
			PendingChainOperationCompletion::CommittedNeedsRecovery {
				value,
				marker_error,
			} => {
				warn!(
					"process_block_single committed its block but failed to clear the recovery marker; recovering before publishing acceptance: {}",
					marker_error
				);
				self.recover_pending_chain_operation_checked(
					"process_block_single committed marker cleanup",
				)
				.map_err(BlockProcessingError::CommittedRecoveryFailed)?;
				value
			}
		};

		info!(
			"Accepted single block {} for height {}",
			block_hash, b.header.height
		);
		// notifying other parts of the system of the update
		self.adapter.block_accepted(secp, &b, status, opts);

		Ok(head)
	}

	// attempt to add multiple blocks that came in the sequence from 0 first to last
	// Note, it is expected that check_block was called for all blocks at 'blocks'.
	// Since they are orphans - check_block was called to them when they were added to orphan pool.
	fn process_block_multiple(
		&self,
		secp: &mut Secp256k1,
		blocks: &Vec<Block>,
		opts: Options,
	) -> Result<Option<Tip>, BlockProcessingError> {
		let first_height = blocks
			.first()
			.ok_or_else(|| {
				Error::Other("Internal error, empty blocks at process_block_multiple".into())
			})?
			.header
			.height;
		let last_block = blocks.last().ok_or_else(|| {
			Error::Other("Internal error, empty blocks at process_block_multiple".into())
		})?;
		let last_height = last_block.header.height;
		let mut state_may_have_changed = false;
		let completion = {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let op =
				prepare_reconcile_heads_operation(&self.store, ChainOperationKind::ProcessBlock)?;
			let marker_guard = self.set_pending_chain_operation_checked(&op)?;
			let res = (|| {
				let batch = self.store.batch_write()?;
				let prev_head = batch.head()?;
				let mut ctx = self.new_ctx(opts, batch, &mut header_pmmr, &mut txhashset)?;

				let (head, fork_point) = pipe::process_blocks_series(
					self.store.get_context_id(),
					&blocks,
					&mut ctx,
					&mut state_may_have_changed,
					secp,
				)?;

				// The predecessor of the final block may have been written earlier in
				// this same batch, so read it from the batch before committing.
				let prev = ctx
					.batch
					.get_previous_header(&last_block.header)
					.map_err(|e| {
						Error::StoreErr(e, "process_block_multiple get previous header".into())
					})?;
				let status = self.determine_status(
					head,
					Tip::try_from_header(&prev)?,
					prev_head,
					Tip::try_from_header(&fork_point)?,
				);
				ctx.batch.commit()?;

				Ok((head, status))
			})();
			self.finish_pending_chain_operation(
				"process_block_multiple",
				res,
				state_may_have_changed,
				marker_guard,
			)
		}?;

		let (head, status) = match completion {
			PendingChainOperationCompletion::Complete(value) => value,
			PendingChainOperationCompletion::CommittedNeedsRecovery {
				value,
				marker_error,
			} => {
				warn!(
					"process_block_multiple committed its block batch but failed to clear the recovery marker; recovering before publishing acceptance: {}",
					marker_error
				);
				self.recover_pending_chain_operation_checked(
					"process_block_multiple committed marker cleanup",
				)
				.map_err(BlockProcessingError::CommittedRecoveryFailed)?;
				value
			}
		};

		debug!(
			"Accepted multiple {} block from height {} to {}",
			blocks.len(),
			first_height,
			last_height
		);

		// Notify other parts of the system of the update.
		//
		// Known limitation: status is computed once for the whole batch, from the
		// final block, and then reused for each block notification. That means
		// prev/fork/reorg metadata is exact only for the final block in the batch.
		// Processing the batch one block at a time would avoid this, but is too
		// slow for the deep catch-up path this optimization targets.
		//
		// This path is intentionally limited by depth: process_block()
		// only calls process_block_multiple() when the final batch block is below
		// header_head - 100, so the batch tail is at least 101 blocks behind the
		// current header head. This depth guard, not the SYNC option, is what
		// makes the reused status metadata acceptable here.
		for b in blocks {
			self.adapter.block_accepted(secp, b, status, opts);
		}

		Ok(head)
	}

	/// Process a block header received during "header first" propagation.
	/// Note: This will update header MMR and corresponding header_head
	/// if total work increases (on the header chain).
	pub fn process_block_header(&self, bh: &BlockHeader, opts: Options) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		pipe::validate_header_context_id(context_id, bh)?;
		pipe::validate_header_hash(context_id, &bh.hash(context_id)?)?;
		// Most propagated headers are repeats. Check an exact stored header in a
		// read-only snapshot before taking the two global write locks or creating
		// the durable operation marker. The header_pmmr read lock serializes this
		// check against header-state writers (e.g. reset_chain_head): without it a
		// downward transition could commit a lower HEADER_HEAD concurrently, and a
		// header classified as non-improving against the old head would be skipped
		// even though it must now be reapplied. The check inside the locked
		// pipeline stays authoritative for stored headers that now need reapplying.
		let is_known = self.with_robust_header_pmmr_read(|_| {
			let batch = self.store.batch_read()?;
			let header_head = batch.header_head()?;
			pipe::is_exact_known_header(context_id, bh, &header_head, &batch)
		})?;
		if is_known {
			return Ok(());
		}
		let mut state_may_have_changed = false;
		let completion = {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let op =
				prepare_reconcile_heads_operation(&self.store, ChainOperationKind::ProcessHeader)?;
			let marker_guard = self.set_pending_chain_operation_checked(&op)?;
			let res = (|| {
				let batch = self.store.batch_write()?;
				let mut ctx = self.new_ctx(opts, batch, &mut header_pmmr, &mut txhashset)?;
				pipe::process_block_header(context_id, bh, &mut ctx, &mut state_may_have_changed)?;
				ctx.batch.commit()?;
				Ok(())
			})();
			self.finish_pending_chain_operation(
				"process_block_header",
				res,
				state_may_have_changed,
				marker_guard,
			)
		}?;

		match completion {
			PendingChainOperationCompletion::Complete(()) => Ok(()),
			PendingChainOperationCompletion::CommittedNeedsRecovery {
				value: (),
				marker_error,
			} => {
				warn!(
					"process_block_header committed its header but failed to clear the recovery marker; recovering before returning success: {}",
					marker_error
				);
				self.recover_pending_chain_operation_checked(
					"process_block_header committed marker cleanup",
				)
				.map_err(|e| {
					Error::committed_recovery_failed(
						"process_block_header committed marker cleanup",
						e,
					)
				})
			}
		}
	}

	/// Attempt to add new headers to the header chain (or fork).
	/// This is only ever used during sync and is based on sync_head.
	/// We update header_head here if our total work increases.
	/// Returns the new sync_head (may temporarily diverge from header_head when syncing a long fork).
	pub fn sync_block_headers(
		&self,
		headers: &[BlockHeader],
		sync_head: Tip,
		opts: Options,
	) -> Result<Option<Tip>, Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		for header in headers {
			pipe::validate_header_context_id(context_id, header)?;
		}
		{
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let op =
				prepare_reconcile_heads_operation(&self.store, ChainOperationKind::SyncHeaders)?;
			// Set the recovery marker before validation and deliberately treat any
			// later error as recovery-worthy. Some current errors can happen before
			// PMMR or batch state changes, but this path is storage-recovery
			// sensitive: future validation changes may move mutations earlier, and
			// misclassifying a partial mutation as harmless is worse than doing an
			// unnecessary recovery pass.
			let mut marker_guard = self.set_pending_chain_operation_checked(&op)?;
			let res = (|| {
				let batch = self.store.batch_write()?;

				// Sync the chunk of block headers, updating header_head if total work increases.
				let mut ctx = self.new_ctx(opts, batch, &mut header_pmmr, &mut txhashset)?;
				let sync_head =
					pipe::process_block_headers(context_id, headers, sync_head, &mut ctx)?;
				ctx.batch.commit()?;

				Ok(sync_head)
			})();
			match res {
				Ok(sync_head) => {
					self.clear_pending_chain_operation_checked()?;
					marker_guard.disarm();
					Ok(sync_head)
				}
				Err(e) => {
					self.handle_failed_pending_chain_operation(
						"sync_block_headers",
						&e,
						&mut marker_guard,
					);
					Err(e)
				}
			}
		}
	}

	/// Build a new block processing context.
	pub fn new_ctx<'a>(
		&'a self,
		opts: Options,
		batch: store::Batch<'a>,
		header_pmmr: &'a mut txhashset::PMMRHandle<BlockHeader>,
		txhashset: &'a mut txhashset::TxHashSet,
	) -> Result<pipe::BlockContext<'a>, Error> {
		Ok(pipe::BlockContext {
			opts,
			pow_verifier: self.pow_verifier,
			header_pmmr,
			txhashset,
			batch,
			difficulty_cache: self.cache_header_difficulty.write(),
		})
	}

	/// Access to orphan pool
	pub fn get_orphans_pool(&self) -> &Arc<OrphanBlockPool> {
		&self.orphans
	}

	/// Check if hash is for a known orphan.
	pub fn is_orphan(&self, hash: &Hash) -> bool {
		self.orphans.contains(hash)
	}

	/// Get orphan data.
	pub fn get_orphan(&self, hash: &Hash) -> Option<Orphan> {
		self.orphans.get_orphan(hash)
	}

	/// Remove orphan data.
	pub fn remove_orphan(&self, height: u64, hash: &Hash) -> Option<Orphan> {
		self.orphans.remove_by_height_header_hash(height, hash)
	}

	/// Get the OrphanBlockPool accumulated evicted number of blocks
	pub fn orphans_evicted_len(&self) -> usize {
		self.orphans.len_evicted()
	}

	/// Check for orphans, once a block is successfully added
	fn check_orphans(&self, secp: &mut Secp256k1, mut height: u64) -> Result<(), Error> {
		let initial_height = height;

		// Is there an orphan in our orphans that we can now process?
		loop {
			trace!(
				"check_orphans: at {}, # orphans {}",
				height,
				self.orphans.len(),
			);

			let mut orphan_accepted = false;
			let mut height_accepted = height;

			// The orphan pool is a recoverable in-memory cache, and draining it is
			// intentionally best-effort. Many entries are expected to be stale,
			// invalid, or otherwise rejected when retried. We preserve bad-data
			// failures for peer attribution and propagate failures after durable child
			// state was committed, but do not let an ordinary child orphan failure make
			// the already-accepted parent block fail. If a still-valid orphan is dropped
			// because of a validation, storage, or txhashset processing error, normal
			// sync will request the missing block again when it is needed.
			if let Some(orphans) = self.orphans.remove_by_height(height) {
				let orphans_len = orphans.len();
				for (i, orphan) in orphans.into_iter().enumerate() {
					let context_id = self.store.get_context_id();
					let block_hash = orphan.block.hash(context_id)?;
					let source_peers = orphan.source_peers.clone();
					debug!(
						"check_orphans: get block {} at {}{}",
						block_hash,
						height,
						if orphans_len > 1 {
							format!(", no.{} of {} orphans", i, orphans_len)
						} else {
							String::new()
						},
					);
					let height = orphan.block.header.height;
					let res = match self.check_block(
						&orphan.block,
						orphan.opts.clone(),
						source_peers.clone(),
					) {
						Ok(()) => self.process_block_single(secp, orphan.block, orphan.opts),
						// Header processing can commit before marker cleanup and recovery
						// fail. Preserve that post-commit phase instead of treating it as
						// an ordinary best-effort orphan rejection.
						Err(e @ Error::CommittedRecoveryFailed { .. }) => return Err(e),
						Err(e) => Err(BlockProcessingError::NotCommitted(e)),
					};
					match res {
						Ok(_) => {
							orphan_accepted = true;
							height_accepted = height;
						}
						Err(BlockProcessingError::NotCommitted(e)) => {
							// A concurrent response can make a drained orphan an exact
							// known duplicate before it is retried here.
							if e.is_bad_data() && !e.is_known_block() && !source_peers.is_empty() {
								self.adapter.block_rejected(&block_hash, &source_peers, &e);
							}
						}
						Err(BlockProcessingError::CommittedRecoveryFailed(e)) => {
							return Err(Error::committed_recovery_failed(
								"check_orphans committed block recovery",
								e,
							));
						}
					}
				}

				if orphan_accepted {
					// We accepted a block, so see if we can accept any orphans
					height = height_accepted.checked_add(1).ok_or_else(|| {
						Error::DataOverflow(format!(
							"Chain::check_orphans height_accepted={}",
							height_accepted
						))
					})?;
					continue;
				}
			}
			break;
		}

		if initial_height != height {
			debug!(
				"check_orphans: {} blocks accepted since height {}, remaining # orphans {}",
				height - initial_height,
				initial_height,
				self.orphans.len(),
			);
		}

		Ok(())
	}

	/// Returns Ok(Some((out, pos))) if output is unspent.
	/// Returns Ok(None) if output is spent.
	/// Returns Err if something went wrong beyond not finding the output.
	pub fn get_unspent(
		&self,
		commit: Commitment,
	) -> Result<Option<(OutputIdentifier, CommitPos)>, Error> {
		Ok(self
			.get_unspent_with_validated_height(commit)?
			.map(|(out, pos, _)| (out, pos)))
	}

	fn get_unspent_with_validated_height(
		&self,
		commit: Commitment,
	) -> Result<Option<(OutputIdentifier, CommitPos, BlockHeader)>, Error> {
		let mut attempted_repair = false;
		loop {
			let read_res = self.with_robust_chain_read(|header_pmmr, txhashset| {
				let batch = self
					.store
					.batch_read()
					.map_err(|e| Error::StoreErr(e, "chain get unspent batch".to_owned()))?;
				match txhashset.get_unspent(commit)? {
					Some((out, pos)) => {
						let body_head = batch
							.head()
							.map_err(|e| Error::StoreErr(e, "chain get unspent head".to_owned()))?;
						match self.body_chain_header_for_output_pos(
							header_pmmr,
							&batch,
							&body_head,
							pos,
						)? {
							Some(header) => Ok(Ok(Some((out, pos, header)))),
							None => Ok(Err(pos)),
						}
					}
					None => Ok(Ok(None)),
				}
			})?;

			let invalid_pos = match read_res {
				Ok(Some(output)) => return Ok(Some(output)),
				Ok(None) => {
					if attempted_repair {
						return Err(Error::Other(format!(
							"output_pos index entry missing for commit {} after rebuild",
							commit.to_hex(),
						)));
					}
					return Ok(None);
				}
				Err(invalid_pos) => invalid_pos,
			};

			if attempted_repair {
				return Err(Error::Other(format!(
					"output_pos index height remains invalid for commit {} at pos {} height {} after rebuild",
					commit.to_hex(),
					invalid_pos.pos,
					invalid_pos.height,
				)));
			}

			warn!(
				"output_pos index height invalid for commit {} at pos {} height {}; rebuilding output_pos index",
				commit.to_hex(),
				invalid_pos.pos,
				invalid_pos.height,
			);
			self.rebuild_output_pos_index(&commit, invalid_pos)?;
			attempted_repair = true;
		}
	}

	fn body_chain_header_for_output_pos(
		&self,
		header_pmmr: &PMMRHandle<BlockHeader>,
		batch: &Batch<'_>,
		body_head: &Tip,
		pos: CommitPos,
	) -> Result<Option<BlockHeader>, Error> {
		// `body_head.height` is a redundant cache, so let the lookup canonicalize
		// `last_block_h` before treating a position above the body head as absent.
		let header = match self.body_chain_header_at_height_maybe_fast(
			header_pmmr,
			batch,
			body_head,
			pos.height,
		) {
			Ok(header) => header,
			Err(Error::ChainInSyncing(_)) => return Ok(None),
			Err(err) => return Err(err),
		};
		let prev_output_mmr_size = if pos.height == 0 {
			0
		} else {
			crate::checked_previous_header(
				self.store.get_context_id(),
				&header,
				&mut HashSet::new(),
				"body_chain_header_for_output_pos predecessor",
				|hash| batch.get_block_header(hash),
			)?
			.output_mmr_size
		};

		if pos.pos > prev_output_mmr_size && pos.pos <= header.output_mmr_size {
			Ok(Some(header))
		} else {
			Ok(None)
		}
	}

	/// Retrieves an unspent output using its PMMR position
	pub fn get_unspent_output_at(&self, pos0: u64) -> Result<Output, Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			txhashset::utxo_view(header_pmmr, txhashset, |utxo, _| {
				utxo.get_unspent_output_at(pos0)
			})
		})
	}

	/// Validate the tx against the current UTXO set and recent kernels (NRD relative lock heights).
	pub fn validate_tx(&self, tx: &Transaction) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		self.validate_tx_against_utxo(tx)?;
		self.validate_tx_kernels(tx)?;
		Ok(())
	}

	/// Validate candidate outputs against the current UTXO set without checking
	/// transaction inputs or kernels.
	pub fn validate_outputs(&self, outputs: &[Output]) -> Result<(), Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			txhashset::utxo_view(header_pmmr, txhashset, |utxo, batch| {
				utxo.validate_outputs(outputs, batch)
			})
		})
	}

	/// Validates NRD relative height locks against "recent" kernel history.
	/// Applies the kernels to the current kernel MMR in a readonly extension.
	/// The extension and the db batch are discarded.
	/// The batch ensures duplicate NRD kernels within the tx are handled correctly.
	fn validate_tx_kernels(&self, tx: &Transaction) -> Result<(), Error> {
		let has_nrd_kernel = tx.kernels().iter().any(|k| match k.features {
			KernelFeatures::NoRecentDuplicate { .. } => true,
			_ => false,
		});
		if !has_nrd_kernel {
			return Ok(());
		}

		self.ensure_chain_robust()?;
		loop {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();

			// A writer may have failed while this thread was waiting for locks.
			// Do not validate NRD kernels against state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			return self.with_locked_readonly_pmmr_discard_marker("validate_tx_kernels", || {
				txhashset::extending_readonly(
					self.store.get_context_id(),
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						// Do not call next_block_height() here. We already hold the
						// header_pmmr and txhashset write locks, and that public path can
						// trigger init recovery which needs the same locks.
						let head = batch.head()?;
						let next_block_height = head.height.checked_add(1).ok_or_else(|| {
							Error::DataOverflow(format!(
								"Chain::validate_tx_kernels, head.height={}",
								head.height
							))
						})?;
						ext.extension
							.apply_kernels(tx.kernels(), next_block_height, batch, false)
					},
				)
			});
		}
	}

	fn validate_tx_against_utxo(
		&self,
		tx: &Transaction,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			txhashset::utxo_view(header_pmmr, txhashset, |utxo, batch| {
				utxo.validate_tx(tx, batch)
			})
		})
	}

	/// Validates inputs against the current utxo.
	/// Each input must spend an unspent output.
	/// Returns the vec of output identifiers and their pos of the outputs
	/// that would be spent by the inputs.
	pub fn validate_inputs(
		&self,
		inputs: &Inputs,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			txhashset::utxo_view(header_pmmr, txhashset, |utxo, batch| {
				utxo.validate_inputs(inputs, batch)
			})
		})
	}

	fn next_block_height(&self) -> Result<u64, Error> {
		let bh = self.head_header()?;
		bh.height.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("Chain::next_block_height, bh.height={}", bh.height))
		})
	}

	/// Verify we are not attempting to spend a coinbase output
	/// that has not yet sufficiently matured.
	pub fn verify_coinbase_maturity(&self, inputs: &Inputs) -> Result<(), Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			txhashset::utxo_view(header_pmmr, txhashset, |utxo, batch| {
				let head = batch
					.head()
					.map_err(|e| Error::StoreErr(e, "coinbase maturity head".to_owned()))?;
				let height = head.height.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Chain::verify_coinbase_maturity, head.height={}",
						head.height
					))
				})?;
				utxo.verify_coinbase_maturity(self.store.get_context_id(), inputs, height, batch)?;
				Ok(())
			})
		})
	}

	/// Verify that the tx has a lock_height that is less than or equal to
	/// the height of the next block.
	pub fn verify_tx_lock_height(&self, tx: &Transaction) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let height = self.next_block_height()?;
		if tx.lock_height() <= height {
			Ok(())
		} else {
			Err(Error::TxLockHeight)
		}
	}

	/// replay attack  check
	/// when the pipe adds the block the chain, it will also do this check based on the block headerversion
	/// (need to be version 3 or bigger)
	/// Do we need to do the check here? we are doing check for every tx regardless of the kernel version.
	pub fn replay_attack_check(&self, tx: &Transaction) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		loop {
			let mut header_pmmr = self.header_pmmr.write();

			// A writer may have failed while this thread was waiting for the lock.
			// Do not validate replay state against PMMR/DB state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			return self.with_locked_readonly_pmmr_discard_marker("replay_attack_check", || {
				let batch_read = self.store.batch_read()?;
				txhashset::header_extending_readonly(&mut header_pmmr, batch_read, |ext, batch| {
					let body_header = batch.head_header()?;
					self.rewind_and_apply_header_fork(&body_header, ext, batch)?;
					pipe::check_against_spent_output(
						&tx.body,
						body_header.height,
						None,
						None,
						ext,
						batch,
					)?;
					Ok(())
				})
			});
		}
	}

	/// Validate the current chain state.
	pub fn validate(&self, secp: &Secp256k1, fast_validation: bool) -> Result<(), Error> {
		self.ensure_chain_robust()?;

		loop {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();

			// A writer may have failed while this thread was waiting for locks.
			// Do not validate PMMR/txhashset state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			return self.with_locked_readonly_pmmr_discard_marker("validate", || {
				// We want to lock first and read the header next. Otherwise after the lock header might be different
				let header = self.store.head_header()?;

				// Now create an extension from the txhashset and validate against the
				// latest block header. Rewind the extension to the specified header to
				// ensure the view is consistent.
				txhashset::extending_readonly(
					self.store.get_context_id(),
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						self.rewind_and_apply_fork(secp, &header, ext, batch)?;
						ext.extension.validate(
							&self.genesis.header,
							fast_validation,
							None,
							&header,
							None,
							secp,
						)?;
						Ok(())
					},
				)
			});
		}
	}

	/// Sets prev_root on a brand new block header by applying the previous header to the header MMR.
	pub fn set_prev_root_only(&self, header: &mut BlockHeader) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let prev_root = loop {
			let mut header_pmmr = self.header_pmmr.write();

			// A writer may have failed while this thread was waiting for the lock.
			// Recovery acquires header_pmmr itself, so release it before retrying.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			break self.with_locked_readonly_pmmr_discard_marker("set_prev_root_only", || {
				let batch_read = self.store.batch_read()?;
				txhashset::header_extending_readonly(&mut header_pmmr, batch_read, |ext, batch| {
					let prev_header = crate::checked_previous_header(
						self.store.get_context_id(),
						header,
						&mut HashSet::new(),
						"set_prev_root_only predecessor",
						|hash| batch.get_block_header(hash),
					)?;
					self.rewind_and_apply_header_fork(&prev_header, ext, batch)?;
					ext.root()
				})
			});
		}?;

		// Set the prev_root on the header.
		header.prev_root = prev_root;

		Ok(())
	}

	/// Sets the txhashset roots on a brand new block by applying the block on
	/// the current txhashset state.
	pub fn set_txhashset_roots(&self, secp: &Secp256k1, b: &mut Block) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let (prev_root, roots, sizes) = loop {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();

			// A writer may have failed while this thread was waiting for locks.
			// Do not calculate roots from PMMR/txhashset state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			break self.with_locked_readonly_pmmr_discard_marker("set_txhashset_roots", || {
				txhashset::extending_readonly(
					self.store.get_context_id(),
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						let previous_header = crate::checked_previous_header(
							self.store.get_context_id(),
							&b.header,
							&mut HashSet::new(),
							"set_txhashset_roots predecessor",
							|hash| batch.get_block_header(hash),
						)?;
						self.rewind_and_apply_fork(secp, &previous_header, ext, batch)?;

						// rewind_and_apply_fork validates roots/sizes only for fork blocks it
						// reapplies; when previous_header is already on the current body chain
						// that list is empty and rewind only truncates to header-declared
						// positions. Verify the parent state before deriving new consensus roots.
						ext.extension.validate_roots(&previous_header)?;
						ext.extension.validate_sizes(&previous_header)?;

						let extension = &mut ext.extension;
						let header_extension = &mut ext.header_extension;

						// Retrieve the header root before we apply the new block
						let prev_root = header_extension.root()?;

						// Apply the latest block to the chain state via the extension.
						extension.apply_block(b, header_extension, batch)?;

						Ok((prev_root, extension.roots()?, extension.sizes()))
					},
				)
			});
		}?;

		// Set the output and kernel MMR sizes.
		// Note: We need to do this *before* calculating the roots as the output_root
		// depends on the output_mmr_size
		{
			// Carefully destructure these correctly...
			let (output_mmr_size, _, kernel_mmr_size) = sizes;
			b.header.output_mmr_size = output_mmr_size;
			b.header.kernel_mmr_size = kernel_mmr_size;
		}

		// Set the prev_root on the header.
		b.header.prev_root = prev_root;

		// Set the output, rangeproof and kernel MMR roots.
		b.header.output_root = roots.output_root;
		b.header.range_proof_root = roots.rproof_root;
		b.header.kernel_root = roots.kernel_root;

		Ok(())
	}

	/// Return a Merkle proof for the given unspent output against the current
	/// output PMMR state.
	///
	/// Historical/origin-header proofs are intentionally not supported. PMMR
	/// compaction preserves the roots needed for proofs at the current MMR size,
	/// but may roll an old peak into a larger pruned-subtree root. Supporting
	/// arbitrary old headers would therefore require retaining additional state
	/// for every historical header. Callers must verify the returned proof against
	/// an output root whose MMR size equals `proof.mmr_size`, normally the current
	/// head observed for this request.
	pub fn get_merkle_proof<T: AsRef<OutputIdentifier>>(
		&self,
		out_id: T,
	) -> Result<MerkleProof, Error> {
		let out_id = out_id.as_ref();
		let commit = out_id.commitment();
		let context_id = self.store.get_context_id();
		self.with_robust_chain_read(|_, txhashset| {
			let Some((stored_out, _)) = txhashset.get_unspent(commit)? else {
				return Err(Error::OutputSpent);
			};
			if !ser::hashes_equal(context_id, &stored_out, out_id)? {
				return Err(Error::TxHashSetErr(format!(
					"unspent output identifier mismatch for commitment {}",
					commit.to_hex()
				)));
			}
			txhashset.merkle_proof(commit)
		})
	}

	/// Return a Merkle proof valid for the current output PMMR state for a
	/// commitment looked up through the output-position index.
	///
	/// This is the commitment-only variant used by the legacy txhashset API. It
	/// has the same current-state-only contract as [`Chain::get_merkle_proof`].
	pub fn get_merkle_proof_for_pos(&self, commit: Commitment) -> Result<MerkleProof, Error> {
		self.with_robust_chain_read(|_, txhashset| txhashset.merkle_proof(commit))
	}

	/// Rewind and apply fork with the chain specific header validation (denylist) rules.
	/// If we rewind and re-apply a "denied" block then validation will fail.
	fn rewind_and_apply_fork(
		&self,
		secp: &Secp256k1,
		header: &BlockHeader,
		ext: &mut ExtensionPair,
		batch: &Batch,
	) -> Result<BlockHeader, Error> {
		let (header, _) =
			pipe::rewind_and_apply_fork(self.store.get_context_id(), header, ext, batch, secp)?;
		Ok(header)
	}

	/// Rewind and apply fork with the chain specific header validation (denylist) rules.
	/// If we rewind and re-apply a "denied" header then validation will fail.
	fn rewind_and_apply_header_fork(
		&self,
		header: &BlockHeader,
		ext: &mut HeaderExtension,
		batch: &Batch,
	) -> Result<(), Error> {
		pipe::rewind_and_apply_header_fork(self.store.get_context_id(), header, ext, batch)
	}

	/// The segmenter is responsible for generation PIBD segments.
	/// We cache a segmenter instance based on the current archve period (new period every 12 hours).
	/// This allows us to efficiently generate bitmap segments for the current archive period.
	///
	/// It is a relatively expensive operation to initializa and cache a new segmenter instance
	/// as this involves rewinding the txhashet by approx 720 blocks (12 hours).
	///
	/// Caller is responsible for only doing this when required.
	/// Caller should verify a peer segment request is valid before calling this for example.
	///
	pub fn segmenter(&self) -> Result<Segmenter, Error> {
		loop {
			self.ensure_chain_robust()?;
			// The archive header corresponds to the data we will segment.
			let archive_header = self.txhashset_archive_header()?;

			// Use the cached segmenter only if it was built after the most recent
			// recovery and recovery has not been latched again.
			if let Some(x) = self.pibd_segmenter.read_recursive().as_ref() {
				if x.header() == &archive_header && x.is_current() {
					return Ok(x.clone());
				}
			}

			// We have no current cached segmenter. Take the write lock before
			// initializing so concurrent callers do not all run the expensive path.
			let mut cache = self.pibd_segmenter.write();
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(cache);
				continue;
			}
			if let Some(x) = cache.as_ref() {
				if x.header() == &archive_header && x.is_current() {
					return Ok(x.clone());
				}
			}

			let segmenter = match self.init_segmenter(&archive_header) {
				Ok(segmenter) => segmenter,
				Err(_) if self.requires_init_recovery.load(Ordering::SeqCst) => {
					drop(cache);
					self.ensure_chain_robust()?;
					continue;
				}
				Err(e) => return Err(e),
			};
			if !segmenter.is_current() {
				drop(cache);
				continue;
			}

			*cache = Some(segmenter.clone());
			// Close the window between construction and cache publication. An old
			// entry is harmless because Segmenter also guards every data method,
			// but remove it eagerly so the next request rebuilds immediately.
			if !segmenter.is_current() {
				*cache = None;
				drop(cache);
				continue;
			}
			return Ok(segmenter);
		}
	}

	/// Root hash for the header hashes MMR at the provided txhashset archive header.
	pub fn header_hashes_root(&self, header: &BlockHeader) -> Result<Hash, Error> {
		let context_id = self.store.get_context_id();
		let header_hash = header.hash(context_id)?;
		self.with_robust_header_pmmr_read(|header_pmmr| {
			let current_header_hash = header_pmmr.get_header_hash_by_height(header.height)?;
			if current_header_hash != header_hash {
				return Err(Error::ChainInSyncing(format!(
					"archive header {} at {} no longer matches current header {}",
					header_hash, header.height, current_header_hash
				)));
			}

			let mut segm_header_pmmr_backend: VecBackend<Hash> = VecBackend::new(context_id);
			let mut segm_header_pmmr = PMMR::new(&mut segm_header_pmmr_backend);
			let hash_num = txhashset::calc_header_hashes_from_target_height(header.height);
			for i in 0..hash_num {
				let data = header_pmmr
					.get_header_hash_by_height(i * HEADERS_PER_BATCH as u64)
					.map_err(|e| {
						Error::Other(format!(
							"header_hashes_root internal error, header data is expected below horizon, {}",
							e
						))
					})?;
				segm_header_pmmr.push(&data).map_err(|s| {
					Error::SyncError(format!("Unable to create Headers hash MMR, {}", s))
				})?;
			}
			Ok(segm_header_pmmr.root()?)
		})
	}

	/// This is an expensive rewind to recreate bitmap state but we only need to do this once.
	/// Caller is responsible for "caching" the segmenter (per archive period) for reuse.
	fn init_segmenter(&self, header: &BlockHeader) -> Result<Segmenter, Error> {
		let now = Instant::now();
		let context_id = self.store.get_context_id();
		let header_hash = header.hash(context_id)?;
		debug!(
			"init_segmenter: initializing new segmenter for {} at {}",
			header_hash, header.height
		);

		let (bitmap_snapshot, segm_header_pmmr_backend, state_generation) = loop {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();

			// A writer may have failed while segmenter initialization was waiting
			// for the PMMR locks. Recover before deriving or caching any segment data.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			break self.with_locked_readonly_pmmr_discard_marker("init_segmenter", || {
				// `last_block_h` is the authoritative HEAD selector. Rebuild the
				// redundant Tip fields from its selected header in one DB snapshot
				// before deriving the archive period. In particular, a stale cached
				// height must not make an older, otherwise valid archive acceptable.
				let archive_height = {
					let batch = self.store.batch_read()?;
					let persisted_body_head = batch
						.head()
						.map_err(|e| Error::StoreErr(e, "init_segmenter HEAD".to_owned()))?;
					let (_, canonical_body_head) = canonical_tip_header(
						"init_segmenter HEAD",
						&persisted_body_head,
						&batch,
					)?;
					Self::height_2_archive_height(context_id, canonical_body_head.height)
				};
				if header.height != archive_height {
					return Err(Error::ChainInSyncing(format!(
						"archive header {} at {} no longer matches current archive height {}",
						header_hash, header.height, archive_height
					)));
				}

				let current_header_hash = header_pmmr.get_header_hash_by_height(archive_height)?;
				if current_header_hash != header_hash {
					return Err(Error::ChainInSyncing(format!(
						"archive header {} at {} no longer matches current header {}",
						header_hash, header.height, current_header_hash
					)));
				}
				let local_output_mmr_size = txhashset.output_mmr_size();
				let local_kernel_mmr_size = txhashset.kernel_mmr_size();
				let local_rangeproof_mmr_size = txhashset.rangeproof_mmr_size();

				if header.output_mmr_size > local_output_mmr_size
					|| header.kernel_mmr_size > local_kernel_mmr_size
					|| header.output_mmr_size > local_rangeproof_mmr_size
				{
					return Err(Error::ChainInSyncing(format!("Header expected mmr size: output:{} kernel:{}.  Chains mmr size: output:{} kernel:{} rangeproof:{}",
														 header.output_mmr_size, header.kernel_mmr_size, local_output_mmr_size, local_kernel_mmr_size, local_rangeproof_mmr_size)));
				}

				txhashset::extending_readonly(
					context_id,
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						let extension = &mut ext.extension;
						extension.rewind(header, batch, None)?;
						Ok(extension.build_bitmap_accumulator()?)
					},
				)
				.and_then(|bitmap_snapshot| {
					// Creating headers hashes PIBD data. With that we can download headers in parallel.
					let mut segm_header_pmmr_backend: VecBackend<Hash> = VecBackend::new(context_id);
					{
						let mut segm_header_pmmr = PMMR::new(&mut segm_header_pmmr_backend);

						let hash_num = txhashset::calc_header_hashes_from_target_height(header.height);
						for i in 0..hash_num {
							let data = header_pmmr
								.get_header_hash_by_height(i * HEADERS_PER_BATCH as u64)
								.map_err(|e| {
									Error::Other(format!(
										"init_segmenter internal error, header data is expected below horizon, {}",
										e
									))
								})?;
							segm_header_pmmr.push(&data).map_err(|s| {
								Error::SyncError(format!("Unable to create Headers hash MMR, {}", s))
							})?;
						}
					}

					// Validate the live PMMR roots while the same locks and recovery
					// marker still protect the snapshot. A separate read here would
					// reopen a wait-then-read race with a failing writer.
					let output_pmmr = txhashset.output_pmmr_at(header);
					let output_pmmr_root = output_pmmr
						.root()
						.map_err(|e| Error::Other(format!("Invalid output_pmmr, {}", e)))?;
					if header.output_root != output_pmmr_root {
						return Err(Error::InvalidRoot("output PMMR root mismatch".into()));
					}

					let rangeproof_pmmr = txhashset.rangeproof_pmmr_at(header);
					let rangeproof_pmmr_root = rangeproof_pmmr
						.root()
						.map_err(|e| Error::Other(format!("Invalid rangeproof_pmmr, {}", e)))?;
					if header.range_proof_root != rangeproof_pmmr_root {
						return Err(Error::InvalidRoot(
							"rangeproof PMMR root mismatch".into(),
						));
					}

					let kernel_pmmr = txhashset.kernel_pmmr_at(header);
					let kernel_pmmr_root = kernel_pmmr
						.root()
						.map_err(|e| Error::Other(format!("Invalid kernel_pmmr, {}", e)))?;
					if header.kernel_root != kernel_pmmr_root {
						return Err(Error::InvalidRoot("kernel PMMR root mismatch".into()));
					}

					Ok((
						bitmap_snapshot,
						segm_header_pmmr_backend,
						self.pibd_state_generation.load(Ordering::SeqCst),
					))
				})
			});
		}?;

		debug!("init_segmenter: done, took {}ms", now.elapsed().as_millis());

		Segmenter::new_guarded(
			Arc::new(RwLock::new(segm_header_pmmr_backend)),
			self.txhashset.clone(),
			bitmap_snapshot,
			header.clone(),
			self.requires_init_recovery.clone(),
			self.pibd_state_generation.clone(),
			state_generation,
		)
	}

	/// initialize a desegmenter, which is capable of extending the hashset by appending
	/// PIBD segments of the three PMMR trees + Bitmap PMMR
	/// header should be the same header as selected for the txhashset.zip archive
	pub fn init_desegmenter(
		&self,
		archive_header_hegiht: u64,
		bitmap_root_hash: Hash,
	) -> Result<Desegmenter, Error> {
		loop {
			self.ensure_chain_robust()?;
			let state_generation = self.pibd_state_generation.load(Ordering::SeqCst);
			// Even if not all headers are uploaded, headers through the archive height
			// must be present so PIBD can request segments for this exact header.
			let archive_header = self.get_header_by_height(archive_header_hegiht)?;
			debug!(
				"init_desegmenter: initializing new desegmenter for {} at {}",
				archive_header.hash(self.store.get_context_id())?,
				archive_header.height
			);

			let desegmenter = Desegmenter::new_guarded(
				self.txhashset.clone(),
				self.header_pmmr.clone(),
				archive_header,
				bitmap_root_hash,
				self.genesis.header.clone(),
				self.store.clone(),
				self.pibd_params.clone(),
				self.requires_init_recovery.clone(),
				self.pibd_state_generation.clone(),
				state_generation,
			)?;
			// Close the construction race with recovery. Every operation repeats this
			// check, so recovery starting after this point still makes the returned
			// instance permanently stale.
			if desegmenter.is_current() {
				return Ok(desegmenter);
			}
		}
	}

	/// Static method to convert height to archive height. Used in chain and also in Sync process
	pub fn height_2_archive_height(context_id: u32, height: u64) -> u64 {
		let sync_threshold = u64::from(global::state_sync_threshold(context_id));
		let archive_interval = global::txhashset_archive_interval(context_id);
		let mut archive_height = height.saturating_sub(sync_threshold);
		archive_height = archive_height.saturating_sub(archive_height % archive_interval);
		archive_height
	}

	/// To support the ability to download the txhashset from multiple peers in parallel,
	/// the peers must all agree on the exact binary representation of the txhashset.
	/// This means compacting and rewinding to the exact same header.
	/// Since compaction is a heavy operation, peers can agree to compact every 12 hours,
	/// and no longer support requesting arbitrary txhashsets.
	/// Here we return the header of the txhashset we are currently offering to peers.
	pub fn txhashset_archive_header(&self) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		// Derive the archive period from the header selected by HEAD rather than
		// trusting its redundant cached height. Keep the selector and selected
		// header in one LMDB snapshot.
		let body_head = {
			let batch = self.store.batch_read()?;
			let persisted_body_head = batch
				.head()
				.map_err(|e| Error::StoreErr(e, "txhashset archive HEAD".to_owned()))?;
			let (_, canonical_body_head) =
				canonical_tip_header("txhashset archive HEAD", &persisted_body_head, &batch)?;
			canonical_body_head
		};
		let txhashset_height = Self::height_2_archive_height(context_id, body_head.height);

		debug!(
			"txhashset_archive_header: body_head - {}, {}, txhashset height - {}",
			body_head.last_block_h, body_head.height, txhashset_height,
		);

		let archive_header = self.get_header_by_height(txhashset_height)?;
		if !self.is_on_body_chain(&archive_header, body_head.clone())? {
			return Err(Error::ChainInSyncing(format!(
				"archive header {} at {} is not on body chain ending at {} at {}",
				archive_header.hash(context_id)?,
				archive_header.height,
				body_head.last_block_h,
				body_head.height,
			)));
		}

		Ok(archive_header)
	}

	/// Return the Block Header at the txhashset horizon, considering only the
	/// contents of the header PMMR
	pub fn txhashset_archive_header_header_only(&self) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		let header_head = self.header_head()?;
		let txhashset_height =
			Self::height_2_archive_height(self.store.get_context_id(), header_head.height);
		self.get_header_by_height(txhashset_height)
	}

	/// Special handling to make sure the whole kernel set matches each of its
	/// roots in each block header, without truncation. We go back header by
	/// header, rewind and check each root. This fixes a potential weakness in
	/// fast sync where a reorg past the horizon could allow a whole rewrite of
	/// the kernel set.
	pub fn validate_kernel_history(
		header: &BlockHeader,
		txhashset: &txhashset::TxHashSet,
		status: Option<&SyncState>,
		stop_state: Option<&StopState>,
	) -> Result<(), Error> {
		debug!("validate_kernel_history: rewinding and validating kernel history (readonly)");

		let mut count: u64 = 0;
		let total = header.height;
		let mut current = header.clone();
		let mut visited = HashSet::new();
		if let Some(status) = status {
			status.update(SyncStatus::ValidatingKernelsHistory {
				headers: 0,
				headers_total: total,
			});
		}
		txhashset::rewindable_kernel_view(&txhashset, |view, batch| {
			let context_id = batch.get_context_id();
			let status_throttle = SyncStatusUpdateThrottle::new();
			while current.height > 0 {
				if let Some(stop_state) = stop_state {
					if stop_state.is_stopped() {
						return Err(Error::Stopped);
					}
				}
				view.rewind(&current)?;
				view.validate_root()?;
				current = crate::checked_previous_header(
					context_id,
					&current,
					&mut visited,
					"validate_kernel_history ancestry",
					|hash| batch.get_block_header(hash),
				)?;
				// Increment is safe because if can't begger that the number of the blocks. Also
				//  count used for logging, any failure will not be critical
				count += 1;
				if let Some(status) = status {
					if status_throttle.should_update(count == total) {
						status.update(SyncStatus::ValidatingKernelsHistory {
							headers: count,
							headers_total: total,
						});
					}
				}
			}
			Ok(())
		})?;

		debug!(
			"validate_kernel_history: validated kernel root on {} headers",
			count,
		);

		Ok(())
	}

	/// Finds the "fork point" where header chain diverges from full block chain.
	/// If we are syncing this will correspond to the last full block where
	/// the next header is known but we do not yet have the full block.
	/// i.e. This is the last known full block and all subsequent blocks are missing.
	pub fn fork_point(&self) -> Result<BlockHeader, Error> {
		// Preserve lock order: header_pmmr (1) before store (3). A store batch retains
		// the LMDB resize read lock and must not be live while acquiring header_pmmr.
		self.with_robust_header_pmmr_read(|header_pmmr| {
			let context_id = self.store.get_context_id();
			let batch = self.store.batch_read()?;
			let stored_body_head = batch.head()?;
			let stored_header_head = batch.header_head()?;
			// Verify the header stored under the HEAD selector hashes back to it,
			// and rebuild the Tip from the header so `height` is not a stale cache.
			let (mut current, _) = canonical_tip_header("HEAD", &stored_body_head, &batch)?;
			// Header-chain membership is bounded by HEADER_HEAD, not the body HEAD.
			// A higher-work header fork may legitimately end below the body HEAD.
			let (_, header_head) =
				canonical_tip_header("HEADER_HEAD", &stored_header_head, &batch)?;
			let mut visited = HashSet::new();
			while !self.is_on_current_chain_with_header_pmmr(
				header_pmmr,
				Tip::try_from_header(&current)?,
				header_head,
			)? {
				current = crate::checked_previous_header(
					context_id,
					&current,
					&mut visited,
					"fork_point body ancestry",
					|hash| batch.get_block_header(hash),
				)?;
			}
			Ok(current)
		})
	}

	/// Clean the temporary sandbox folder
	pub fn clean_txhashset_sandbox(&self) -> Result<(), Error> {
		txhashset::clean_txhashset_folder(&self.get_tmp_dir())
	}

	/// Specific tmp dir.
	/// Normally it's ~/.mwc/main/tmp for mainnet
	/// or ~/.mwc/floo/tmp for floonet
	pub fn get_tmp_dir(&self) -> PathBuf {
		let mut tmp_dir = PathBuf::from(self.db_root.clone());
		tmp_dir = match tmp_dir.parent() {
			Some(parent) => parent.to_path_buf(),
			None => tmp_dir,
		};
		tmp_dir.push("tmp");
		tmp_dir
	}

	fn validate_tmpfile_name(tmpfile_name: &str) -> Result<(), Error> {
		if tmpfile_name.is_empty() || tmpfile_name.contains('/') || tmpfile_name.contains('\\') {
			return Err(Error::Other(format!(
				"Invalid tmp file name: {}",
				tmpfile_name
			)));
		}

		let mut components = Path::new(tmpfile_name).components();
		match (components.next(), components.next()) {
			(Some(Component::Normal(_)), None) => Ok(()),
			_ => Err(Error::Other(format!(
				"Invalid tmp file name: {}",
				tmpfile_name
			))),
		}
	}

	/// Get a tmp file path in above specific tmp dir (create tmp dir if not exist)
	/// Delete file if tmp file already exists
	pub fn get_tmpfile_pathname(&self, tmpfile_name: String) -> Result<PathBuf, Error> {
		Self::validate_tmpfile_name(&tmpfile_name)?;

		let mut tmp = self.get_tmp_dir();
		mwc_util::file::ensure_owner_only_dir_all(&tmp)?;
		tmp.push(tmpfile_name);
		match fs::remove_file(&tmp) {
			Ok(()) => {}
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
			Err(e) => return Err(e.into()),
		}
		Ok(tmp)
	}

	/// Writes a reading view on a txhashset state that's been provided to us.
	/// If we're willing to accept that new state, the data stream will be
	/// read as a zip file, unzipped and the resulting state files should be
	/// rewound to the provided indexes.
	//  Note, if there are updates in this code, please check Sync code, probably it needs to be updates as well
	/*	pub fn txhashset_write(
		&self,
		h: Hash,
		txhashset_data: File,
		status: &dyn TxHashsetWriteStatus,
	) -> Result<bool, Error> {
		status.on_setup(None, None, None, None);

		// Initial check whether this txhashset is needed or not
		let fork_point = self.fork_point()?;
		if !self.check_txhashset_needed(&fork_point)? {
			warn!("txhashset_write: txhashset received but it's not needed! ignored.");
			return Err(Error::InvalidTxHashSet("not needed".to_owned()));
		}

		let header = match self.get_block_header(&h) {
			Ok(header) => header,
			Err(e) if e.is_not_found() => {
				warn!("txhashset_write: cannot find block header, {}", e);
				// This is a bannable reason
				return Ok(true);
			}
			Err(e) => return Err(e),
		};

		// Write txhashset to sandbox (in the Mwc specific tmp dir)
		let sandbox_dir = self.get_tmp_dir();
		txhashset::clean_txhashset_folder(&sandbox_dir)?;
		txhashset::zip_write(sandbox_dir.clone(), txhashset_data.try_clone()?, &header)?;

		let mut txhashset = txhashset::TxHashSet::open(
			sandbox_dir
				.to_str()
				.ok_or_else(|| Error::Other("invalid sandbox folder".into()))?
				.to_owned(),
			self.store.clone(),
			Some(&header),
			&self.secp,
		)?;

		// Validate the full kernel history.
		// Check kernel MMR root for every block header.
		// Check NRD relative height rules for full kernel history.
		{
			self.validate_kernel_history(&header, &txhashset)?;

			let header_pmmr = self.header_pmmr.read_recursive();
			let batch = self.store.batch_write()?;
			txhashset.verify_kernel_pos_index(
				&self.genesis.header,
				&header,
				&header_pmmr,
				&batch,
				None,
				None,
			)?;
		}

		// all good, prepare a new batch and update all the required records
		debug!("txhashset_write: rewinding a 2nd time (writeable)");

		let mut header_pmmr = self.header_pmmr.write();
		let mut batch = self.store.batch_write()?;
		txhashset::extending(
			&mut header_pmmr,
			&mut txhashset,
			&mut batch,
			|ext, batch| {
				let extension = &mut ext.extension;
				extension.rewind(&header, batch)?;

				// Validate the extension, generating the utxo_sum and kernel_sum.
				// Full validation, including rangeproofs and kernel signature verification.
				let (utxo_sum, kernel_sum) = extension.validate(
					&self.genesis.header,
					false,
					status,
					None,
					None,
					&header,
					None,
					self.secp(),
				)?;

					// Save the block_sums (utxo_sum, kernel_sum) to the db for use later.
					batch.save_block_sums(
						&header.hash(self.store.get_context_id())?,
						BlockSums::new(utxo_sum, kernel_sum),
					)?;

				Ok(())
			},
		)?;

		debug!("txhashset_write: finished validating and rebuilding");

		status.on_save();

		// Save the new head to the db and rebuild the header by height index.
		{
			let tip = Tip::try_from_header(&header)?;
			batch.save_body_head(&tip)?;

			// Reset the body tail to the body head after a txhashset write
			batch.save_body_tail(&tip)?;
		}

		// Rebuild our output_pos index in the db based on fresh UTXO set.
		txhashset.init_output_pos_index(&batch)?;

		// Rebuild our NRD kernel_pos index based on recent kernel history.
		txhashset.init_recent_kernel_pos_index(&batch)?;

		// Rebuild the full kernel excess index based on fresh kernel history.
		txhashset.init_kernel_pos_index(&batch)?;
		batch.set_kernel_pos_index_complete(true)?;

		// Commit all the changes to the db.
		batch.commit()?;

		debug!("txhashset_write: finished committing the batch (head etc.)");

		// Sandbox full validation ok, go to overwrite txhashset on db root
		{
			let mut txhashset_ref = self.txhashset.write();

			// Before overwriting, drop file handlers in underlying txhashset
			txhashset_ref.release_backend_files();

			// Move sandbox to overwrite
			txhashset.release_backend_files();
			match txhashset::txhashset_replace(sandbox_dir, PathBuf::from(self.db_root.clone()))? {
				txhashset::TxHashSetReplaceResult::Replaced => {}
				txhashset::TxHashSetReplaceResult::ReplacedWithBackupCleanupFailure {
					backup_path,
					cleanup_error,
				} => {
					warn!(
						"txhashset_write: replaced txhashset but failed to remove backup {:?}. err: {}",
						backup_path, cleanup_error
					);
				}
			}

			// Re-open on db root dir
			txhashset = txhashset::TxHashSet::open(
				self.db_root.clone(),
				self.store.clone(),
				Some(&header),
				&self.secp,
			)?;

			// Replace the chain txhashset with the newly built one.
			*txhashset_ref = txhashset;
		}

		debug!("txhashset_write: replaced our txhashset with the new one");

		status.on_done();

		Ok(false)
	}*/

	/// Cleanup old blocks from the db.
	/// Determine the cutoff height from the horizon and the current block height.
	/// *Only* runs if we are not in archive mode.
	fn remove_historical_blocks(
		&self,
		new_tail: &BlockHeader,
		stop_state: &StopState,
	) -> Result<(), Error> {
		if self.archive_mode() {
			return Ok(());
		}
		if stop_state.is_stopped() {
			return Err(Error::Stopped);
		}

		debug!(
			"remove_historical_blocks: new_tail height: {}",
			new_tail.height
		);

		let hashes_to_delete = {
			let batch = self.store.batch_read()?;
			let mut hashes_to_delete: Vec<(Hash, u64)> = Vec::new();
			let context_id = self.store.get_context_id();
			// Remove old blocks (including short lived fork blocks) which height < tail.height
			for block in batch.blocks_iter()? {
				if stop_state.is_stopped() {
					return Err(Error::Stopped);
				}
				let block = block?;
				let block_hash = block.hash(context_id)?;
				let expected_header = batch.get_block_header(&block_hash).map_err(|e| {
					Error::StoreErr(
						e,
						format!("historical block cleanup load header {}", block_hash),
					)
				})?;
				if block.header != expected_header {
					return Err(Error::InvalidPersistedChainState(format!(
						"historical block cleanup full block {} does not exactly match its separately stored header",
						block_hash
					)));
				}
				if block.header.height < new_tail.height {
					hashes_to_delete.push((block_hash, block.header.height));
				}
			}
			hashes_to_delete
		};
		let mut count = 0;
		for hashes in hashes_to_delete.chunks(HISTORICAL_BLOCK_DELETE_CHUNK) {
			if stop_state.is_stopped() {
				return Err(Error::Stopped);
			}
			let batch = self.store.batch_write()?;
			// Re-read BODY_TAIL in the same transaction as the deletes. A
			// concurrent reset_pibd_chain / reset_chain_head_to_genesis may
			// have lowered the tail to genesis and recreated blocks below our
			// stale cutoff; those blocks are required chain state again and
			// must not be deleted.
			let stored_current_tail = batch
				.tail()
				.map_err(|e| Error::StoreErr(e, "historical block cleanup load tail".to_owned()))?;
			let (current_tail_header, current_tail) = canonical_tip_header(
				"historical block cleanup BODY_TAIL",
				&stored_current_tail,
				&batch,
			)?;
			if current_tail.height < new_tail.height {
				// Tail moved backward under us (chain reset). The cutoff this
				// cleanup was started with is void; abort and let a later
				// compaction re-derive a correct one.
				return Err(Error::InvalidPersistedChainState(format!(
					"historical block cleanup tail moved backward: started at {}, now {}",
					new_tail.height, current_tail.height
				)));
			}
			let new_tail_on_current_chain = body_chain_ancestor_at_height(
				self.store.get_context_id(),
				&batch,
				&current_tail_header,
				new_tail.height,
				"historical block cleanup BODY_TAIL ancestry",
			)?;
			if new_tail_on_current_chain != *new_tail {
				return Err(Error::InvalidPersistedChainState(format!(
					"historical block cleanup cutoff {} at height {} is not an ancestor of current BODY_TAIL {} at height {}",
					new_tail.hash(self.store.get_context_id())?,
					new_tail.height,
					current_tail.last_block_h,
					current_tail.height
				)));
			}
			for (hash, height) in hashes {
				if stop_state.is_stopped() {
					return Err(Error::Stopped);
				}
				// Skip candidates no longer below the current tail.
				if *height >= current_tail.height {
					continue;
				}
				// The full block may already have been removed after the read
				// pass. Only that initial absence is benign; failures after
				// loading the block, such as a missing separately stored
				// header, must abort. Note the reverse direction — a block
				// recreated by a concurrent reset — is not benign either and
				// is handled by the tail revalidation above.
				if batch.delete_block_if_exists(hash)? {
					count += 1;
				}
			}
			if stop_state.is_stopped() {
				return Err(Error::Stopped);
			}
			batch.commit()?;
		}
		debug!(
			"remove_historical_blocks: removed {} blocks in chunks of {}. tail height: {}",
			count, HISTORICAL_BLOCK_DELETE_CHUNK, new_tail.height
		);
		Ok(())
	}

	fn compact_eligibility_for_heights(
		context_id: u32,
		tail_height: u64,
		head_height: u64,
	) -> Result<(bool, u64), Error> {
		let horizon = u64::from(global::cut_through_horizon(context_id));
		let threshold = horizon + horizon / 10;
		let next_compact = tail_height.checked_add(threshold).ok_or_else(|| {
			Error::DataOverflow(format!(
				"compact eligibility height overflow: tail_height={}, threshold={}",
				tail_height, threshold
			))
		})?;
		Ok((next_compact <= head_height, next_compact))
	}

	fn validate_compact_tail_ancestry(
		context_id: u32,
		batch: &Batch<'_>,
		body_chain_anchor: &BlockHeader,
		body_tail_header: &BlockHeader,
		body_tail: &Tip,
		operation: &str,
	) -> Result<(), Error> {
		let tail_on_body_chain = body_chain_ancestor_at_height(
			context_id,
			batch,
			body_chain_anchor,
			body_tail.height,
			operation,
		)?;
		if tail_on_body_chain != *body_tail_header {
			return Err(Error::InvalidPersistedChainState(format!(
				"{} BODY_TAIL {} at height {} is not on the durable body chain",
				operation, body_tail.last_block_h, body_tail.height
			)));
		}
		Ok(())
	}

	fn compact_eligibility(&self) -> Result<(bool, u64), Error> {
		// `last_block_h` is the authoritative selector for both tips. Derive the
		// heights from the selected headers in one snapshot instead of trusting
		// their redundant persisted height fields.
		let batch = self.store.batch_read()?;
		let stored_tail = batch
			.tail()
			.map_err(|e| Error::StoreErr(e, "compact eligibility BODY_TAIL".to_owned()))?;
		let (tail_header, tail) =
			canonical_tip_header("compact eligibility BODY_TAIL", &stored_tail, &batch)?;
		let stored_head = batch
			.head()
			.map_err(|e| Error::StoreErr(e, "compact eligibility HEAD".to_owned()))?;
		let (head_header, head) =
			canonical_tip_header("compact eligibility HEAD", &stored_head, &batch)?;
		if tail.height > head.height {
			return Err(Error::InvalidPersistedChainState(format!(
				"compact eligibility BODY_TAIL height {} is above HEAD height {}",
				tail.height, head.height
			)));
		}
		let context_id = self.store.get_context_id();
		let eligibility =
			Self::compact_eligibility_for_heights(context_id, tail.height, head.height)?;
		// If compaction is skipped, no later planning pass will authenticate the
		// relationship between these individually valid selectors. The ineligible
		// interval is bounded by the compact threshold, so this traversal is short.
		if !eligibility.0 {
			Self::validate_compact_tail_ancestry(
				context_id,
				&batch,
				&head_header,
				&tail_header,
				&tail,
				"compact eligibility",
			)?;
		}
		Ok(eligibility)
	}

	/// Triggers chain compaction.
	///
	/// * compacts the txhashset based on current prune_list
	/// * removes historical blocks and associated data from the db (unless archive mode)
	///
	pub fn compact(
		&self,
		sync_state: Option<Arc<SyncState>>,
		stop_state: Arc<StopState>,
	) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		if stop_state.is_stopped() {
			return Err(Error::Stopped);
		}
		// A node may be restarted multiple times in a short period of time.
		// We compact at most once per 60 blocks in this situation by comparing
		// current "head" and "tail" height to our cut-through horizon and
		// allowing an additional 60 blocks in height before allowing a further compaction.
		let (should_compact, next_compact) = self.compact_eligibility()?;
		if !should_compact {
			debug!(
				"compact: skipping startup compaction (next at {})",
				next_compact
			);
			return Ok(());
		}

		let context_id = self.store.get_context_id();

		let cleanup_tail = {
			// Take a write lock on the txhashet and start a new writeable db batch.
			let header_pmmr = self.header_pmmr.read_recursive();
			let mut txhashset = self.txhashset.write();
			if stop_state.is_stopped() {
				return Err(Error::Stopped);
			}
			// Select and authenticate the exact compact horizon before installing
			// the marker. Once installed, this target lets recovery publish the
			// matching BODY_TAIL even if the PMMR file replacements reached disk but
			// the enclosing LMDB batch did not.
			let (
				op,
				planned_body_head,
				planned_header_head,
				planned_body_tail,
				horizon_header,
				target_body_tail,
			) = {
				let batch = self.store.batch_read()?;
				let stored_body_head = batch.head()?;
				let (body_head_header, body_head) =
					canonical_tip_header("compact HEAD", &stored_body_head, &batch)?;
				let stored_header_head = batch.header_head()?;
				let (_, header_head) =
					canonical_tip_header("compact HEADER_HEAD", &stored_header_head, &batch)?;
				let stored_body_tail = batch.tail()?;
				let (body_tail_header, body_tail) =
					canonical_tip_header("compact BODY_TAIL", &stored_body_tail, &batch)?;

				if body_tail.height > body_head.height {
					return Err(Error::InvalidPersistedChainState(format!(
						"compact BODY_TAIL height {} is above HEAD height {}",
						body_tail.height, body_head.height
					)));
				}
				// A queued compact call may have become ineligible while waiting.
				// Repeat the decision from these canonical tips in this same snapshot.
				let (should_compact, next_compact) = Self::compact_eligibility_for_heights(
					context_id,
					body_tail.height,
					body_head.height,
				)?;
				if !should_compact {
					Self::validate_compact_tail_ancestry(
						context_id,
						&batch,
						&body_head_header,
						&body_tail_header,
						&body_tail,
						"compact queued eligibility",
					)?;
					debug!(
						"compact: skipping queued compaction (next at {})",
						next_compact
					);
					return Ok(());
				}

				let horizon_height = body_head
					.height
					.saturating_sub(global::cut_through_horizon(context_id) as u64);
				let horizon_header =
					self.body_chain_header_at_height(&batch, &body_head, horizon_height)?;
				let horizon_hash = horizon_header.hash(context_id)?;
				let header_pmmr_hash = header_pmmr.get_header_hash_by_height(horizon_height)?;
				if header_pmmr_hash != horizon_hash {
					return Err(Error::ChainInSyncing(format!(
						"compact horizon {} at {} is not on current header chain",
						horizon_hash, horizon_height
					)));
				}
				let body_head_hash = body_head.hash(context_id)?;
				let header_pmmr_body_hash =
					header_pmmr.get_header_hash_by_height(body_head.height)?;
				if header_pmmr_body_hash != body_head_hash {
					return Err(Error::ChainInSyncing(format!(
						"compact body head {} at {} is not on current header chain",
						body_head_hash, body_head.height
					)));
				}

				let target_body_tail = Tip::try_from_header(&horizon_header)?;
				if target_body_tail.height < body_tail.height {
					return Err(Error::InvalidPersistedChainState(format!(
						"compact target BODY_TAIL height {} is below current BODY_TAIL height {}",
						target_body_tail.height, body_tail.height
					)));
				}
				// The target is on the body chain and is now known to be at or above
				// BODY_TAIL, so validate the current tail by traversing only the short
				// interval between them instead of walking down from HEAD a second time.
				Self::validate_compact_tail_ancestry(
					context_id,
					&batch,
					&horizon_header,
					&body_tail_header,
					&body_tail,
					"compact BODY_TAIL ancestry",
				)?;
				// Recovery requires this exact retained full-block record. Establish
				// that precondition before the durable marker or any PMMR mutation.
				crate::checked_block_for_header(
					context_id,
					&horizon_header,
					"compact target BODY_TAIL preflight",
					|hash| batch.get_block(hash),
				)?;

				let op = PendingChainOperation::Compact {
					original_body_head: body_head,
					original_header_head: header_head,
					target_body_tail,
				};
				(
					op,
					body_head,
					header_head,
					body_tail,
					horizon_header,
					target_body_tail,
				)
			};
			let mut marker_guard = self.set_pending_chain_operation_checked(&op)?;
			let res = (|| {
				let batch = self.store.batch_write()?;

				// The PMMR locks make this stable in normal operation. Recheck after
				// the marker commit so an unexpected out-of-band selector change cannot
				// apply a horizon planned for a different chain.
				let stored_body_head = batch.head()?;
				let (_, current_body_head) =
					canonical_tip_header("compact current HEAD", &stored_body_head, &batch)?;
				let stored_header_head = batch.header_head()?;
				let (_, current_header_head) = canonical_tip_header(
					"compact current HEADER_HEAD",
					&stored_header_head,
					&batch,
				)?;
				let stored_body_tail = batch.tail()?;
				let (_, current_body_tail) =
					canonical_tip_header("compact current BODY_TAIL", &stored_body_tail, &batch)?;
				if current_body_head != planned_body_head
					|| current_header_head != planned_header_head
					|| current_body_tail != planned_body_tail
				{
					return Err(Error::ChainInSyncing(
						"compact chain selectors changed after planning the durable horizon".into(),
					));
				}
				if target_body_tail.height < current_body_tail.height {
					return Err(Error::InvalidPersistedChainState(format!(
						"compact target BODY_TAIL height {} is below current BODY_TAIL height {} after marker installation",
						target_body_tail.height, current_body_tail.height
					)));
				}

				// Compact the txhashset itself (rewriting the pruned backend files).

				txhashset.compact(&horizon_header, &batch)?;
				if stop_state.is_stopped() {
					return Err(Error::Stopped);
				}

				// NOTE:  Compaction selects a different horizon
				// block from txhashset horizon/PIBD segmenter. That block is allways above or equal
				// It is expected, we don't want all nodes go into compaction at the same time becase
				// it might take a while on slow hardware.

				// Archive is 2 days + 12 hours.  horizon is a week. Guaranteed that archive_header.height is larger than horizon height
				debug_assert!(
					Self::height_2_archive_height(context_id, planned_body_head.height)
						> horizon_header.height
				);

				batch.save_body_tail(&target_body_tail)?;

				// Make sure our output_pos index is consistent with the UTXO set.
				// Normal block processing maintains this index incrementally, so
				// avoid the full historical header scan unless a recovery path
				// explicitly marked the index incomplete.
				if batch.is_output_pos_index_complete()? {
					debug!("compact: output_pos index is complete, skipping rebuild");
				} else {
					txhashset.init_output_pos_index(
						&batch,
						sync_state.clone(),
						Some(stop_state.clone()),
					)?;
				}

				// TODO - Why is this part of chain compaction?
				// Rebuild our NRD kernel_pos index based on recent kernel history.
				txhashset.init_recent_kernel_pos_index(
					&batch,
					sync_state.clone(),
					Some(stop_state.clone()),
				)?;

				// Commit all the above db changes.
				batch.commit()?;
				Ok(horizon_header)
			})();
			match res {
				Ok(horizon_header) => {
					self.clear_pending_chain_operation_checked()?;
					marker_guard.disarm();
					Ok(Some(horizon_header))
				}
				Err(e) => {
					self.handle_failed_pending_chain_operation("compact", &e, &mut marker_guard);
					Err(e)
				}
			}
		}?;

		if let Some(cleanup_tail) = cleanup_tail {
			self.remove_historical_blocks(&cleanup_tail, stop_state.as_ref())?;
		}
		Ok(())
	}

	/// Returns up to distance unpruned outputs found by scanning backward in
	/// the output sum tree. Pruned outputs do not count toward distance.
	pub fn get_last_n_output(&self, distance: u64) -> Result<Vec<(Hash, OutputIdentifier)>, Error> {
		self.with_robust_chain_read(|_, txhashset| Ok(txhashset.last_n_output(distance)?))
	}

	/// As above, for rangeproofs.
	pub fn get_last_n_rangeproof(&self, distance: u64) -> Result<Vec<(Hash, RangeProof)>, Error> {
		self.with_robust_chain_read(|_, txhashset| Ok(txhashset.last_n_rangeproof(distance)?))
	}

	/// As above, for kernels.
	pub fn get_last_n_kernel(&self, distance: u64) -> Result<Vec<(Hash, TxKernel)>, Error> {
		self.with_robust_chain_read(|_, txhashset| Ok(txhashset.last_n_kernel(distance)?))
	}

	/// Return Commit's MMR position
	pub fn get_output_pos(&self, commit: &Commitment) -> Result<u64, Error> {
		self.with_robust_chain_read(|_, txhashset| Ok(txhashset.get_output_pos(commit)?))
	}

	/// outputs by insertion index
	pub fn unspent_outputs_by_pmmr_index(
		&self,
		start_index: u64,
		max_count: u64,
		max_pmmr_index: Option<u64>,
	) -> Result<(u64, u64, Vec<Output>), Error> {
		self.with_output_read_snapshot(|snapshot| {
			snapshot.unspent_outputs_by_pmmr_index(start_index, max_count, max_pmmr_index)
		})
	}

	/// Return unspent outputs as above, but bounded between a particular range of blocks
	pub fn block_height_range_to_pmmr_indices(
		&self,
		start_block_height: u64,
		end_block_height: Option<u64>,
	) -> Result<(u64, u64), Error> {
		self.with_robust_header_pmmr_read(|header_pmmr| {
			let batch = self
				.store
				.batch_read()
				.map_err(|e| Error::StoreErr(e, "block height range read batch".to_owned()))?;
			let body_head = batch
				.head()
				.map_err(|e| Error::StoreErr(e, "block height range body head".to_owned()))?;
			let end_block_height = match end_block_height {
				Some(h) => h.min(body_head.height),
				None => body_head.height,
			};
			if start_block_height > end_block_height {
				return Err(Error::Other(format!(
					"Invalid block height range: start_block_height={} is greater than end_block_height={}",
					start_block_height, end_block_height
				)));
			}

			// Resolve bounds from the fully validated body chain. The header PMMR can
			// be ahead of, or forked away from, the body head during header-first sync.
			let start_mmr_size = if start_block_height == 0 {
				// Note PMMR are 1 based, for the first PMMR index is 1.
				1
			} else {
				let start_header = self.body_chain_header_at_height_maybe_fast(
					header_pmmr,
					&batch,
					&body_head,
					start_block_height - 1,
				)?;
				start_header.output_mmr_size.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Chain::block_height_range_to_pmmr_indices, start_header.output_mmr_size={}",
						start_header.output_mmr_size
					))
				})?
			};
			let end_header = self.body_chain_header_at_height_maybe_fast(
				header_pmmr,
				&batch,
				&body_head,
				end_block_height,
			)?;
			let end_mmr_size = end_header.output_mmr_size;
			Ok((start_mmr_size, end_mmr_size))
		})
	}

	/// Orphans pool size
	pub fn orphans_len(&self) -> usize {
		self.orphans.len()
	}

	/// Tip (head) of the block chain.
	pub fn head(&self) -> Result<Tip, Error> {
		self.ensure_chain_robust()?;
		self.store
			.head()
			.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))
	}

	/// Tail of the block chain in this node after compact (cross-block cut-through)
	pub fn tail(&self) -> Result<Tip, Error> {
		self.ensure_chain_robust()?;
		self.store
			.tail()
			.map_err(|e| Error::StoreErr(e, "chain tail".to_owned()))
	}

	/// Tip (head) of the header chain.
	pub fn header_head(&self) -> Result<Tip, Error> {
		self.ensure_chain_robust()?;
		self.store
			.header_head()
			.map_err(|e| Error::StoreErr(e, "header head".to_owned()))
	}

	/// Block header for the chain head
	pub fn head_header(&self) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		self.store
			.head_header()
			.map_err(|e| Error::StoreErr(e, "chain head header".to_owned()))
	}

	/// Load a full block and require its complete header to equal `expected`.
	pub fn get_block_for_header(&self, expected: &BlockHeader) -> Result<Block, Error> {
		self.with_robust_chain_read(|_, _| {
			let batch = self
				.store
				.batch_read()
				.map_err(|e| Error::StoreErr(e, "chain get block for header batch".to_owned()))?;
			let expected_hash = expected.hash(self.store.get_context_id())?;
			let stored_header = crate::checked_header_by_hash(
				self.store.get_context_id(),
				&expected_hash,
				"chain get block for header",
				|hash| batch.get_block_header(hash),
			)?;
			if stored_header != *expected {
				return Err(Error::InvalidPersistedChainState(format!(
					"chain get block for header stored header {} does not exactly match the requested header",
					expected_hash
				)));
			}
			crate::checked_block_for_header(
				self.store.get_context_id(),
				expected,
				"chain get block for header",
				|hash| batch.get_block(hash),
			)
		})
	}

	/// Gets the earliest stored block (tail)
	pub fn get_tail(&self) -> Result<Tip, Error> {
		self.ensure_chain_robust()?;
		self.store
			.tail()
			.map_err(|e| Error::StoreErr(e, "chain get tail".to_owned()))
	}

	/// Gets a block header by hash
	pub fn get_block_header(&self, h: &Hash) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		crate::checked_header_by_hash(self.store.get_context_id(), h, "chain get header", |hash| {
			self.store.get_block_header(hash)
		})
	}

	/// Get previous block header.
	pub fn get_previous_header(&self, header: &BlockHeader) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		self.store
			.get_previous_header(header)
			.map_err(|e| Error::StoreErr(e, "chain get previous header".to_owned()))
	}

	/// Get block_sums by header hash.
	pub fn get_block_sums(&self, h: &Hash) -> Result<BlockSums, Error> {
		self.ensure_chain_robust()?;
		self.store
			.get_block_sums(h)
			.map_err(|e| Error::StoreErr(e, "chain get block_sums".to_owned()))
	}

	/// Gets the block header at the provided height.
	/// Note: Takes a read lock on the header_pmmr.
	///
	/// Do not add PoW verification to this request-reachable getter. Header PoW is
	/// authenticated during admission and controlled startup/recovery. Repeating
	/// Cuckoo verification per lookup would expose attacker-controlled CPU work;
	/// this method deliberately performs only cheap persisted-state consistency
	/// checks and trusts those validation boundaries.
	pub fn get_header_by_height(&self, height: u64) -> Result<BlockHeader, Error> {
		self.with_robust_header_pmmr_read(|header_pmmr| {
			let hash = header_pmmr.get_header_hash_by_height(height)?;
			let batch = self
				.store
				.batch_read()
				.map_err(|e| Error::StoreErr(e, "chain get header by height batch".to_owned()))?;
			let header = batch
				.get_block_header(&hash)
				.map_err(|e| Error::StoreErr(e, format!("chain get header by height {}", hash)))?;
			let actual_hash = header.hash(self.store.get_context_id())?;
			if header.height != height || actual_hash != hash {
				return Err(Error::InvalidPersistedChainState(format!(
					"header PMMR entry {} at height {} resolved to header {} at height {}",
					hash, height, actual_hash, header.height
				)));
			}
			header_pmmr.authenticate_header_at_height(height, &header)?;
			Ok(header)
		})
	}

	/// Migrate our local db from v2 to v3.
	/// "commit only" inputs.
	fn migrate_db_v2_v3(store: &ChainStore) -> Result<(), Error> {
		if store.batch_read()?.is_blocks_v3_migrated()? {
			// Previously migrated so skipping.
			debug!("migrate_db_v2_v3: previously migrated, skipping");
			return Ok(());
		}
		let mut total = 0u64;
		let mut keys_to_migrate = vec![];
		let context_id = store.get_context_id();
		for item in store.batch_read()?.blocks_raw_iter()? {
			let (k, v) = item?;
			// Increment is safe because total is used for logging only
			total += 1;

			// We want to migrate all blocks that cannot be read via v3 protocol version.
			let block_v3: Result<Block, _> =
				ser::deserialize_strict(&mut Cursor::new(&v), ProtocolVersion(3), context_id);
			if let Err(v3_err) = block_v3 {
				let block_v2: Result<Block, _> =
					ser::deserialize_strict(&mut Cursor::new(&v), ProtocolVersion(2), context_id);
				match block_v2 {
					Ok(_) => keys_to_migrate.push(k),
					Err(v2_err) => {
						return Err(Error::BlockMigration {
							key: k,
							v3_err,
							v2_err,
						});
					}
				}
			}
		}
		debug!(
			"migrate_db_v2_v3: {} (of {}) blocks to migrate",
			keys_to_migrate.len(),
			total,
		);
		let mut count = 0u64;
		keys_to_migrate
			.chunks(100)
			.try_for_each(|keys| {
				let batch = store.batch_write()?;
				for key in keys {
					batch.migrate_block(&key, ProtocolVersion(2), ProtocolVersion(3))?;
					// Increment is safe because count is used for logging only
					count += 1;
				}
				batch.commit()?;
				debug!("migrate_db_v2_v3: successfully migrated {} blocks", count);
				Ok(())
			})
			.and_then(|_| {
				// Set flag to indicate we have migrated all blocks in the db.
				// We will skip migration in the future.
				let batch = store.batch_write()?;
				batch.set_blocks_v3_migrated(true)?;
				batch.commit()?;
				Ok(())
			})
	}

	fn set_spent_commitment_record_index_complete(
		store: &ChainStore,
		complete: bool,
	) -> Result<(), Error> {
		let batch = store.batch_write().map_err(|e| {
			Error::StoreErr(
				e,
				"spent commitment index completeness write batch".to_owned(),
			)
		})?;
		batch.set_spent_commitment_record_index_complete(complete)?;
		batch.commit().map_err(|e| {
			Error::StoreErr(e, "spent commitment index completeness commit".to_owned())
		})
	}

	fn clear_spent_commitment_index(store: &ChainStore) -> Result<(), Error> {
		loop {
			let batch = store.batch_write().map_err(|e| {
				Error::StoreErr(e, "clear spent commitment index write batch".to_owned())
			})?;
			let deleted = batch
				.clear_spent_commitment_index_chunk(SPENT_COMMITMENT_INDEX_CLEAR_CHUNK_SIZE)?;
			batch.commit().map_err(|e| {
				Error::StoreErr(e, "clear spent commitment index commit".to_owned())
			})?;
			if deleted == 0 {
				return Ok(());
			}
		}
	}

	/// Resolve the persisted body HEAD and walk its canonical ancestry to the
	/// cut-through horizon boundary. The returned headers are strictly above the
	/// boundary: rewinding to `window_start` undoes only those blocks, and PMMR
	/// compaction does not preserve leaf data spent by the boundary block itself.
	/// Callers pass the body `HEAD` selector, never `HEADER_HEAD`.
	fn canonical_body_headers_in_horizon(
		context_id: u32,
		persisted_body_head: &Tip,
		batch: &Batch<'_>,
		operation: &str,
	) -> Result<(BlockHeader, Tip, u64, Vec<BlockHeader>), Error> {
		let (mut body_head, canonical_head) =
			canonical_tip_header(operation, persisted_body_head, batch)?;
		let selected_body_head = body_head.clone();
		let window_start = canonical_head
			.height
			.saturating_sub(u64::from(global::cut_through_horizon(context_id)));

		let mut headers = Vec::new();
		let mut visited = HashSet::new();
		while body_head.height > window_start {
			let current_hash = body_head.hash(context_id)?;
			let current_height = body_head.height;
			let previous_hash = body_head.prev_hash;
			headers.push(body_head.clone());
			body_head = crate::checked_previous_header(
				context_id,
				&body_head,
				&mut visited,
				operation,
				|hash| batch.get_block_header(hash),
			)
			.map_err(|e| match e {
				Error::StoreErr(store_err, _) if store_err.store_error_is_not_found() => {
					Error::InvalidPersistedChainState(format!(
						"{}: canonical body block {} at height {} is missing predecessor {}",
						operation, current_hash, current_height, previous_hash
					))
				}
				other => other,
			})?;
		}
		Ok((selected_body_head, canonical_head, window_start, headers))
	}

	pub(crate) fn init_spent_commitment_index(
		store: &ChainStore,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		let batch = store
			.batch_read()
			.map_err(|e| Error::StoreErr(e, "spent occurrence index read batch".into()))?;
		let complete = batch.is_spent_commitment_record_index_complete()?;
		let head = match batch.head() {
			Ok(head) => head,
			Err(e) if e.store_error_is_not_found() => return Ok(()),
			Err(e) => {
				return Err(Error::StoreErr(
					e,
					"spent occurrence index read head".into(),
				));
			}
		};

		if complete {
			return Ok(());
		}

		// `last_block_h` is the authoritative body HEAD selector; use its selected
		// header rather than the redundant persisted Tip height. The same helper
		// supplies the canonical body window to both rebuild and migration.
		let (header, canonical_head, window_start, canonical_headers) =
			Self::canonical_body_headers_in_horizon(
				store.get_context_id(),
				&head,
				&batch,
				"spent occurrence index HEAD",
			)?;
		if canonical_head.height != 0 {
			// An incomplete index left by a crash or an older version is rebuilt
			// from canonical body blocks strictly above the horizon boundary. Every
			// consumer is bounded by one cut-through horizon from the head: the replay
			// check ignores spends below half the horizon, rewinds beyond one horizon
			// are rejected with RewindBeyondHorizon, and compaction authenticates only
			// blocks in the compact window. Walking body HEAD ancestry avoids archive
			// history and retained bodies on competing forks.
			info!(
				"Rebuilding spent occurrence index from canonical body blocks at HEAD {} height {} (window start {})",
				canonical_head.last_block_h, canonical_head.height, window_start
			);
			drop(batch);
			return Self::rebuild_spent_commitment_index(
				store,
				window_start,
				canonical_headers,
				stop_state,
			);
		}

		// Genesis has no inputs, so an empty index can be established without
		// trusting any persisted spent-position cache.
		let block = crate::checked_block_for_header(
			store.get_context_id(),
			&header,
			"spent occurrence index genesis",
			|hash| batch.get_block(hash),
		)?;
		if !block.inputs().is_empty() {
			return Err(Error::InvalidPersistedChainState(
				"genesis block contains inputs while initializing spent occurrence index".into(),
			));
		}
		drop(batch);
		Self::init_empty_spent_commitment_record_index(store)
	}

	/// One-time migration of per-block spent indexes written before the exact
	/// occurrence format (positions only) to the current `SpentOutput` format.
	///
	/// Iterates the raw `BLOCK_SPENT_PREFIX` records keyed by block hash. A
	/// record is migrated only when the header stored under its key exists,
	/// verifiably belongs to the canonical chain, and sits strictly above the
	/// cut-through horizon boundary. Records at or below the boundary are deleted:
	/// they are derived caches that are not needed to rewind to the boundary.
	/// Archive mode retains historical full blocks, not these inactive indexes.
	/// Dangling records and active-window fork records are also deleted.
	///
	/// Positions come from the legacy entry. The commitment at each position is
	/// resolved authoritatively from the output MMR leaf data, which compaction
	/// deliberately preserves for every in-window spend. No full block or input
	/// ordering is needed: each position identifies its exact output occurrence,
	/// so duplicated commitments migrate exactly. The output creation height is
	/// carried over from the legacy entry; it is not independently verified.
	pub(crate) fn migrate_spent_index(
		store: &ChainStore,
		txhashset: &TxHashSet,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		let now = Instant::now();
		let context_id = store.get_context_id();
		let (window_start, canonical_hashes) = {
			let batch = store
				.batch_read()
				.map_err(|e| Error::StoreErr(e, "spent index migration read batch".into()))?;
			if batch.is_spent_index_migrated()? {
				return Ok(());
			}
			let head = match batch.head() {
				Ok(head) => head,
				Err(e) if e.store_error_is_not_found() => {
					// Fresh DB before head setup: no blocks to migrate yet. The
					// flag is set on a later start, once a head exists.
					return Ok(());
				}
				Err(e) => return Err(Error::StoreErr(e, "spent index migration read head".into())),
			};
			info!("Migrating spent index, might take some time...");
			let (_, _, window_start, canonical_headers) = Self::canonical_body_headers_in_horizon(
				context_id,
				&head,
				&batch,
				"spent index migration HEAD",
			)?;
			// The migration must inspect every spent-index record so it can delete
			// stale and fork entries. Membership in this bounded body-HEAD ancestry
			// distinguishes the canonical records without consulting HEADER_HEAD.
			let mut canonical_hashes = HashSet::with_capacity(canonical_headers.len());
			for header in canonical_headers {
				canonical_hashes.insert(header.hash(context_id)?);
			}
			(window_start, canonical_hashes)
		};

		let mut processed = 0u64;
		let mut migrated = 0u64;
		let mut deleted = 0u64;
		let mut last_key: Option<Vec<u8>> = None;
		loop {
			if let Some(stop_state) = stop_state.as_ref() {
				if stop_state.is_stopped() {
					return Err(Error::Stopped);
				}
			}
			// Use a fresh read transaction for each chunk and release it before
			// opening the write batch. Besides avoiding a long-lived LMDB snapshot,
			// this permits batch_write() to resize the map as migrated values grow.
			let chunk = {
				let read_batch = store
					.batch_read()
					.map_err(|e| Error::StoreErr(e, "spent index migration read batch".into()))?;
				let start = last_key.as_deref().unwrap_or(&[]);
				let mut keys = read_batch
					.spent_index_key_iter_from(start)
					.map_err(|e| Error::StoreErr(e, "spent index migration records iter".into()))?;
				let mut chunk = Vec::with_capacity(SPENT_COMMITMENT_INDEX_REBUILD_CHUNK_SIZE);
				while chunk.len() < SPENT_COMMITMENT_INDEX_REBUILD_CHUNK_SIZE {
					let Some(key) = keys.next() else {
						break;
					};
					let key = key.map_err(|e| {
						Error::StoreErr(e, "spent index migration load record key".into())
					})?;
					// iter_from() is inclusive. Skip the last committed key when it
					// survived the preceding chunk as a migrated/current record.
					if last_key.as_deref() == Some(key.as_slice()) {
						continue;
					}
					chunk.push(key);
				}
				chunk
			};
			if chunk.is_empty() {
				break;
			}
			if let Some(first) = chunk.first() {
				info!(
					"Migrating spent index, processing {} records, starting from hash {}",
					chunk.len(),
					Self::spent_index_key_hash(first)?
				);
			}
			let batch = store
				.batch_write()
				.map_err(|e| Error::StoreErr(e, "spent index migration write batch".into()))?;
			for key in &chunk {
				let block_hash = Self::spent_index_key_hash(key)?;
				let header = match batch.get_block_header(&block_hash) {
					Ok(header) => header,
					Err(e) if e.store_error_is_not_found() => {
						debug!(
							"spent index migration: deleting record for {} with no stored header",
							block_hash
						);
						batch.delete(key).map_err(|e| {
							Error::StoreErr(e, "spent index migration delete record".into())
						})?;
						deleted += 1;
						continue;
					}
					Err(e) => {
						return Err(Error::StoreErr(
							e,
							format!("spent index migration load header {}", block_hash),
						));
					}
				};
				let stored_hash = header.hash(context_id)?;
				if stored_hash != block_hash {
					return Err(Error::InvalidPersistedChainState(format!(
						"spent index migration: header stored under {} hashes to {}",
						block_hash, stored_hash
					)));
				}
				if header.height <= window_start {
					debug!(
						"spent index migration: deleting inactive record for block {} at height {} at or below window start {}",
						block_hash, header.height, window_start
					);
					batch.delete(key).map_err(|e| {
						Error::StoreErr(e, "spent index migration delete record".into())
					})?;
					deleted += 1;
					continue;
				}
				if !canonical_hashes.contains(&block_hash) {
					debug!(
						"spent index migration: deleting record for non-canonical block {} at height {}",
						block_hash, header.height
					);
					batch.delete(key).map_err(|e| {
						Error::StoreErr(e, "spent index migration delete record".into())
					})?;
					deleted += 1;
					continue;
				}
				match batch.get_spent_index(&block_hash) {
					// Already in the exact occurrence format.
					Ok(_) => {}
					Err(current_err) => {
						let legacy = match batch.get_spent_index_legacy(&block_hash) {
							Ok(legacy) => legacy,
							Err(_) => {
								// The legacy read is only a compatibility
								// fallback. Report the original current-format
								// error, which describes the entry as it is
								// expected to be.
								return Err(Error::StoreErr(
									current_err,
									format!(
										"spent index migration load spent index {}",
										block_hash
									),
								));
							}
						};
						let mut entries = Vec::with_capacity(legacy.len());
						for position in &legacy {
							if position.height >= header.height {
								return Err(Error::InvalidPersistedChainState(format!(
									"spent index migration: legacy spent index of block {} at height {} pairs an input with an output created at height {}",
									block_hash, header.height, position.height
								)));
							}
							let commitment = txhashset
								.output_commitment_at_pos(position.pos)?
								.ok_or_else(|| {
									Error::InvalidPersistedChainState(format!(
										"spent index migration: no retained output data at position {} spent by block {} at height {}",
										position.pos, block_hash, header.height
									))
								})?;
							entries.push(SpentOutput {
								commitment,
								position: *position,
							});
						}
						batch.save_spent_index(&block_hash, &entries).map_err(|e| {
							Error::StoreErr(
								e,
								format!("spent index migration save spent index {}", block_hash),
							)
						})?;
						migrated += 1;
					}
				}
			}
			let committed_last_key = chunk.last().cloned();
			processed += chunk.len() as u64;
			batch
				.commit()
				.map_err(|e| Error::StoreErr(e, "spent index migration commit".into()))?;
			last_key = committed_last_key;
		}
		{
			let batch = store
				.batch_write()
				.map_err(|e| Error::StoreErr(e, "spent index migration marker batch".into()))?;
			batch.set_spent_index_migrated(true)?;
			batch
				.commit()
				.map_err(|e| Error::StoreErr(e, "spent index migration marker commit".into()))?;
		}
		info!(
			"Spent index migration: {} entries migrated, {} deleted ({} records scanned, window start {}) in {}s",
			migrated,
			deleted,
			processed,
			window_start,
			now.elapsed().as_secs()
		);
		Ok(())
	}

	/// Extract the block hash from a raw `BLOCK_SPENT_PREFIX` record key.
	fn spent_index_key_hash(key: &[u8]) -> Result<Hash, Error> {
		if key.len() != 2 + Hash::LEN {
			return Err(Error::InvalidPersistedChainState(format!(
				"spent index migration: malformed spent index key {:?}",
				key
			)));
		}
		Ok(Hash::from_vec(&key[2..]))
	}

	/// Rebuild the exact spent-occurrence index from canonical full blocks
	/// strictly above `window_start`.
	///
	/// `canonical_headers` is the bounded ancestry selected by the persisted body
	/// HEAD. Only those exact block hashes are loaded, so archive history at or
	/// below the horizon and retained bodies from other forks are never scanned.
	/// Each loaded body must match its separately stored canonical header. Exact output
	/// positions come from the per-block spent index cache, whose commitment
	/// multiset is cross-checked against the body inputs before use.
	///
	/// The replay check ignores spends older than half the horizon, rewinds beyond
	/// one horizon are rejected, and compaction only authenticates this body-chain
	/// window. Older and noncanonical records are therefore not rebuild inputs.
	fn rebuild_spent_commitment_index(
		store: &ChainStore,
		window_start: u64,
		mut canonical_headers: Vec<BlockHeader>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<(), Error> {
		let now = Instant::now();
		let context_id = store.get_context_id();
		Self::set_spent_commitment_record_index_complete(store, false)?;
		Self::clear_spent_commitment_index(store)?;

		// The ancestry walk returns HEAD first. Rebuild oldest-to-newest so records
		// for a reused commitment have stable body-chain order.
		canonical_headers.reverse();
		let mut processed = 0u64;
		for chunk in canonical_headers.chunks(SPENT_COMMITMENT_INDEX_REBUILD_CHUNK_SIZE) {
			if let Some(stop_state) = stop_state.as_ref() {
				if stop_state.is_stopped() {
					return Err(Error::Stopped);
				}
			}
			if let Some(first) = chunk.first() {
				info!(
					"Building spent commitment index, processing {} canonical blocks from height {}, starting from hash {}",
					chunk.len(),
					first.height,
					first.hash(context_id)?
				);
			}
			let batch = store.batch_write().map_err(|e| {
				Error::StoreErr(e, "spent occurrence index rebuild write batch".into())
			})?;
			for header in chunk {
				if header.height <= window_start {
					return Err(Error::InvalidPersistedChainState(format!(
						"spent occurrence index rebuild: canonical header at height {} is not above window start {}",
						header.height, window_start
					)));
				}
				let block_hash = header.hash(context_id)?;
				let block = crate::checked_block_for_header(
					context_id,
					header,
					"spent occurrence index rebuild canonical body",
					|hash| batch.get_block(hash),
				)?;
				let spent = Self::load_spent_index_for_rebuild(&batch, block_hash, &block)?;
				for (commitment, position) in &spent {
					batch
						.save_spent_commitments(
							commitment,
							SpentCommitmentRecord {
								spending_block: HashHeight {
									hash: block_hash,
									height: header.height,
								},
								spent_output: *position,
							},
						)
						.map_err(|e| {
							Error::StoreErr(
								e,
								format!(
									"spent occurrence index rebuild save record for {}",
									block_hash
								),
							)
						})?;
				}
			}
			processed += chunk.len() as u64;
			batch
				.commit()
				.map_err(|e| Error::StoreErr(e, "spent occurrence index rebuild commit".into()))?;
			debug!(
				"spent occurrence index rebuild: processed {} canonical blocks",
				processed
			);
		}
		Self::set_spent_commitment_record_index_complete(store, true)?;
		info!(
			"Rebuilt spent occurrence index from {} canonical blocks above height {} in {}s",
			processed,
			window_start,
			now.elapsed().as_secs()
		);
		Ok(())
	}

	fn block_input_commitments(block: &Block) -> Vec<Commitment> {
		match block.inputs() {
			Inputs::CommitOnly(inputs) => inputs.iter().map(|input| input.commitment()).collect(),
			Inputs::FeaturesAndCommit(inputs) => {
				inputs.iter().map(|input| input.commitment()).collect()
			}
		}
	}

	/// Load one retained block's spent occurrences for the rebuild as
	/// (commitment, position) pairs.
	///
	/// Entries are expected in the exact `SpentOutput` format; legacy
	/// positions-only entries are converted by
	/// `migrate_spent_index` before the rebuild runs. The
	/// commitment multiset is cross-checked against the authenticated body
	/// inputs before any position is used.
	///
	/// `BLOCK_SPENT_PREFIX` is trusted local derived state, not peer-supplied
	/// position data. Production entries are written from the exact `CommitPos`
	/// values returned by UTXO validation when the block is applied. Migrated
	/// entries retain those previously validated positions and additionally
	/// resolve their commitments from the raw output PMMR. This rebuild therefore
	/// deliberately preserves each cached position after authenticating the full
	/// block against its canonical header and checking the commitment multiset.
	/// Re-resolving an occurrence from the commitment alone would be incorrect
	/// because a commitment can be reused after its earlier occurrence is spent.
	fn load_spent_index_for_rebuild(
		batch: &Batch<'_>,
		block_hash: Hash,
		block: &Block,
	) -> Result<Vec<(Commitment, CommitPos)>, Error> {
		let spent_index = match batch.get_spent_index(&block_hash) {
			Ok(spent_index) => spent_index,
			Err(e)
				if e.store_error_is_not_found()
					&& Self::block_input_commitments(block).is_empty() =>
			{
				// Inputless blocks (notably genesis) may have no entry.
				return Ok(Vec::new());
			}
			Err(e) if e.store_error_is_not_found() => {
				return Err(Error::InvalidPersistedChainState(format!(
					"spent occurrence index rebuild: retained full block {} at height {} has no spent index",
					block_hash, block.header.height
				)));
			}
			Err(e) => {
				return Err(Error::StoreErr(
					e,
					format!(
						"spent occurrence index rebuild load spent index {}",
						block_hash
					),
				));
			}
		};
		Self::validate_spent_index_against_body(block_hash, block, &spent_index)?;
		Ok(spent_index
			.iter()
			.map(|spent| (spent.commitment, spent.position))
			.collect())
	}

	/// Cross-check a retained block's spent index cache against its
	/// authenticated body. The cache supplies exact output positions only; the
	/// multiset of spent commitments must match the body inputs exactly.
	fn validate_spent_index_against_body(
		block_hash: Hash,
		block: &Block,
		spent_index: &[SpentOutput],
	) -> Result<(), Error> {
		let input_commitments = Self::block_input_commitments(block);
		let mut counts: HashMap<Commitment, u64> = HashMap::with_capacity(input_commitments.len());
		for commitment in input_commitments {
			*counts.entry(commitment).or_insert(0) += 1;
		}
		for spent in spent_index {
			let count = counts.get_mut(&spent.commitment).ok_or_else(|| {
				Error::InvalidPersistedChainState(format!(
					"spent occurrence index rebuild: spent index of block {} contains commitment {:?} that is not a body input",
					block_hash, spent.commitment
				))
			})?;
			*count -= 1;
			if *count == 0 {
				counts.remove(&spent.commitment);
			}
		}
		if !counts.is_empty() {
			return Err(Error::InvalidPersistedChainState(format!(
				"spent occurrence index rebuild: body inputs of block {} are missing from its spent index",
				block_hash
			)));
		}
		Ok(())
	}

	pub(crate) fn init_empty_spent_commitment_record_index(
		store: &ChainStore,
	) -> Result<(), Error> {
		// PIBD restores state, not old block bodies. Replay protection is
		// intentionally best effort after that point: this empty index describes
		// the locally retained post-snapshot block window and is populated as body
		// sync validates subsequent blocks. It must not be used as a reason to
		// reset the chain during PIBD, reorg, or recovery.
		info!("Initializing empty spent commitment replay index for PIBD state");
		Self::set_spent_commitment_record_index_complete(store, false)?;
		Self::clear_spent_commitment_index(store)?;
		Self::set_spent_commitment_record_index_complete(store, true)?;
		Ok(())
	}

	/// Gets the block header in which a given output appears in the txhashset.
	pub fn get_header_for_output(&self, commit: Commitment) -> Result<BlockHeader, Error> {
		match self.get_unspent_with_validated_height(commit)? {
			Some((_, _, header)) => Ok(header),
			None => Err(Error::OutputNotFound(format!(
				"Not found commit {}",
				commit.to_hex()
			))),
		}
	}

	fn rebuild_output_pos_index(
		&self,
		commit: &Commitment,
		invalid_pos: CommitPos,
	) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		loop {
			let txhashset = self.txhashset.read_recursive();
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				self.ensure_chain_robust()?;
				continue;
			}

			let batch = self.store.batch_write().map_err(|e| {
				Error::StoreErr(e, "rebuild output_pos index write batch".to_owned())
			})?;

			match batch.get_output_pos_height(commit)? {
				Some(current_pos) if current_pos == invalid_pos => {
					batch.delete_output_pos_height(commit)?;
				}
				_ => {}
			}

			txhashset.init_output_pos_index(&batch, None, None)?;
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(batch);
				drop(txhashset);
				self.ensure_chain_robust()?;
				continue;
			}

			return batch
				.commit()
				.map_err(|e| Error::StoreErr(e, "rebuild output_pos index commit".to_owned()));
		}
	}

	/// Gets the kernel with a given excess and the block height it is included in.
	pub fn get_kernel_height(
		&self,
		excess: &Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			let batch = self
				.store
				.batch_read()
				.map_err(|e| Error::StoreErr(e, "chain kernel_pos read batch".to_owned()))?;
			let head = batch
				.head()
				.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))?;

			if let (Some(min), Some(max)) = (min_height, max_height) {
				if min > max {
					return Ok(None);
				}
			}
			let min_height = min_height.unwrap_or(0);
			if min_height > head.height {
				return Ok(None);
			}
			let max_height = max_height
				.filter(|h| *h <= head.height)
				.unwrap_or(head.height);

			// Chunked rebuild commits partial kernel_pos entries while this flag is false.
			// A missing entry is not a reliable cache miss until the full index is complete.
			if !batch.is_kernel_pos_index_complete()? {
				return Err(Error::KernelPosIndexIncomplete);
			}

			let mut found = None;
			for pos in batch.kernel_pos_iter(excess)? {
				let kernel_pos = pos?;
				let kernel = txhashset
					.get_kernel_by_mmr_index(kernel_pos.pos)?
					.ok_or_else(|| {
						Error::TxHashSetErr(format!(
							"kernel_pos index points to missing kernel at pos {} for excess {:?}",
							kernel_pos.pos, excess
						))
					})?;
				if kernel.excess() != *excess {
					return Err(Error::TxHashSetErr(format!(
						"kernel_pos index mismatch for excess {:?}: index points to {:?} at pos {}",
						excess,
						kernel.excess(),
						kernel_pos.pos
					)));
				}

				let header = self.get_header_for_kernel_index_with_header_pmmr(
					header_pmmr,
					kernel_pos.pos,
					Some(0),
					Some(head.height),
				)?;
				let height = header.height;
				if height != kernel_pos.height {
					return Err(Error::TxHashSetErr(format!(
						"kernel_pos index height mismatch for excess {:?}: pos {} indexed at height {}, actual height {}",
						excess, kernel_pos.pos, kernel_pos.height, height
					)));
				}

				if height < min_height {
					continue;
				}
				if height > max_height {
					break;
				}
				found = Some((kernel, height, kernel_pos.pos));
			}

			Ok(found)
		})
	}
	/// Gets the block header in which a given kernel mmr index appears in the txhashset.
	pub fn get_header_for_kernel_index(
		&self,
		kernel_mmr_index: u64,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<BlockHeader, Error> {
		self.with_robust_header_pmmr_read(|header_pmmr| {
			self.get_header_for_kernel_index_with_header_pmmr(
				header_pmmr,
				kernel_mmr_index,
				min_height,
				max_height,
			)
		})
	}

	fn get_header_for_kernel_index_with_header_pmmr(
		&self,
		header_pmmr: &PMMRHandle<BlockHeader>,
		kernel_mmr_index: u64,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<BlockHeader, Error> {
		let batch = self
			.store
			.batch_read()
			.map_err(|e| Error::StoreErr(e, "chain kernel header read batch".to_owned()))?;
		let body_head = batch
			.head()
			.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))?;
		let get_body_header = |height| {
			self.body_chain_header_at_height_maybe_fast(header_pmmr, &batch, &body_head, height)
		};

		let min_height = min_height.unwrap_or(0);
		let head_height = body_head.height;
		let max_height = max_height.unwrap_or(head_height);

		if kernel_mmr_index == 0 {
			return Err(Error::DataOverflow(
				"Chain::get_header_for_kernel_index, kernel_mmr_index=0".to_string(),
			));
		}
		if min_height > max_height {
			return Err(Error::DataOverflow(format!(
				"Chain::get_header_for_kernel_index, min_height={}, max_height={}",
				min_height, max_height
			)));
		}
		if max_height > head_height {
			return Err(Error::InvalidHeaderHeight(max_height));
		}

		let min_prev_kernel_mmr_size = if min_height == 0 {
			0
		} else {
			// min_height - 1 is safe because min_height>0
			let prev_height = min_height - 1;
			get_body_header(prev_height)?.kernel_mmr_size
		};
		let max_header = get_body_header(max_height)?;
		if kernel_mmr_index <= min_prev_kernel_mmr_size
			|| kernel_mmr_index > max_header.kernel_mmr_size
		{
			return Err(Error::DataOverflow(format!(
				"Chain::get_header_for_kernel_index, kernel_mmr_index={}, min_height={}, max_height={}",
				kernel_mmr_index, min_height, max_height
			)));
		}

		let mut min = min_height;
		let mut max = max_height;
		while min < max {
			// All operations are safe because min/max and result less or equal to max
			let search_height = min + (max - min) / 2;
			let h = get_body_header(search_height)?;
			if kernel_mmr_index <= h.kernel_mmr_size {
				max = search_height;
			} else {
				min = search_height.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Chain::get_header_for_kernel_index, search_height={}",
						search_height
					))
				})?;
			}
		}

		let header = get_body_header(min)?;
		let prev_kernel_mmr_size = if min == 0 {
			0
		} else {
			// safe because min>0
			let prev_height = min - 1;
			get_body_header(prev_height)?.kernel_mmr_size
		};
		if kernel_mmr_index <= prev_kernel_mmr_size || kernel_mmr_index > header.kernel_mmr_size {
			return Err(Error::DataOverflow(format!(
				"Chain::get_header_for_kernel_index, kernel_mmr_index={}, height={}",
				kernel_mmr_index, header.height
			)));
		}
		Ok(header)
	}

	fn is_on_current_chain_with_header_pmmr(
		&self,
		header_pmmr: &PMMRHandle<BlockHeader>,
		x: Tip,
		header_head: Tip,
	) -> Result<bool, Error> {
		if x.height > header_head.height {
			return Ok(false);
		}

		if x.hash(self.store.get_context_id())?
			== header_pmmr.get_header_hash_by_height(x.height)?
		{
			Ok(true)
		} else {
			Ok(false)
		}
	}

	fn body_chain_header_at_height(
		&self,
		batch: &Batch<'_>,
		body_head: &Tip,
		height: u64,
	) -> Result<BlockHeader, Error> {
		// Treat last_block_h as the authoritative selector. Verify the header
		// stored under it hashes back to that selector and rebuild the redundant
		// Tip fields before consulting the cached height.
		let (mut current, canonical_head) = canonical_tip_header("BODY_HEAD", body_head, batch)?;
		if height > canonical_head.height {
			return Err(Error::ChainInSyncing(format!(
				"body chain head is at {}, below requested height {}",
				canonical_head.height, height
			)));
		}

		let context_id = self.store.get_context_id();
		let mut visited = HashSet::new();
		while current.height > height {
			current = crate::checked_previous_header(
				context_id,
				&current,
				&mut visited,
				"body_chain_header_at_height ancestry",
				|hash| batch.get_block_header(hash),
			)?;
		}
		if current.height != height {
			return Err(Error::Other(format!(
				"body chain header traversal stopped at height {}, below requested height {}",
				current.height, height
			)));
		}
		Ok(current)
	}

	fn body_chain_header_at_height_maybe_fast(
		&self,
		header_pmmr: &PMMRHandle<BlockHeader>,
		batch: &Batch<'_>,
		body_head: &Tip,
		height: u64,
	) -> Result<BlockHeader, Error> {
		// Canonicalize the body-chain anchor before using either its height or
		// its selected header. This also protects the zero-step fast return.
		let (mut current, canonical_head) = canonical_tip_header("BODY_HEAD", body_head, batch)?;
		if height > canonical_head.height {
			return Err(Error::ChainInSyncing(format!(
				"body chain head is at {}, below requested height {}",
				canonical_head.height, height
			)));
		}

		let context_id = self.store.get_context_id();
		let stored_header_head = batch.header_head().map_err(|e| {
			Error::StoreErr(e, "body chain header fast path header head".to_owned())
		})?;
		// HEADER_HEAD.height is another redundant cache. Verify the selected
		// header and derive the PMMR fast-path bound from that header instead.
		let (_, canonical_header_head) =
			canonical_tip_header("HEADER_HEAD", &stored_header_head, batch)?;
		let header_head_height = canonical_header_head.height;
		let mut visited = HashSet::new();

		loop {
			if current.height == height {
				return Ok(current);
			}
			if current.height < height {
				return Err(Error::Other(format!(
					"body chain header traversal stopped at height {}, below requested height {}",
					current.height, height
				)));
			}

			if current.height <= header_head_height {
				let header_pmmr_hash = header_pmmr.get_header_hash_by_height(current.height)?;
				if current.hash(context_id)? == header_pmmr_hash {
					header_pmmr.authenticate_header_at_height(current.height, &current)?;
					let hash = header_pmmr.get_header_hash_by_height(height)?;
					let header = batch.get_block_header(&hash).map_err(|e| {
						Error::StoreErr(e, "body chain header fast path get header".to_owned())
					})?;
					if header.height != height || header.hash(context_id)? != hash {
						return Err(Error::InvalidPersistedChainState(format!(
							"body chain header fast path entry {} at height {} resolved to header {} at height {}",
							hash,
							height,
							header.hash(context_id)?,
							header.height
						)));
					}
					header_pmmr.authenticate_header_at_height(height, &header)?;
					return Ok(header);
				}
			}

			current = crate::checked_previous_header(
				context_id,
				&current,
				&mut visited,
				"body_chain_header_at_height_maybe_fast ancestry",
				|hash| batch.get_block_header(hash),
			)?;
		}
	}

	fn is_on_body_chain(&self, header: &BlockHeader, body_head: Tip) -> Result<bool, Error> {
		let batch = self.store.batch_read()?;
		let (mut current, canonical_head) = canonical_tip_header("BODY_HEAD", &body_head, &batch)?;
		if header.height > canonical_head.height {
			return Ok(false);
		}

		let context_id = self.store.get_context_id();
		let mut visited = HashSet::new();
		while current.height > header.height {
			current = crate::checked_previous_header(
				context_id,
				&current,
				&mut visited,
				"is_on_body_chain ancestry",
				|hash| batch.get_block_header(hash),
			)?;
		}

		Ok(current == *header)
	}

	fn is_on_body_chain_with_batch(
		&self,
		batch: &Batch<'_>,
		header: &BlockHeader,
		body_head: &Tip,
	) -> Result<bool, Error> {
		let (_, canonical_head) = canonical_tip_header("BODY_HEAD", body_head, batch)?;
		if header.height > canonical_head.height {
			return Ok(false);
		}

		let current = self.body_chain_header_at_height(batch, &canonical_head, header.height)?;

		Ok(current == *header)
	}

	/// Gets multiple headers at the provided heights.
	/// Note: Uses the sync pmmr, not the header pmmr.
	/// Note: This is based on the provided sync_head to support syncing against a fork.
	pub fn get_locator_hashes(&self, sync_head: Tip, heights: &[u64]) -> Result<Vec<Hash>, Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		let sync_head_hash = sync_head.hash(context_id)?;

		loop {
			let mut header_pmmr = self.header_pmmr.write();
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			return self.with_locked_readonly_pmmr_discard_marker("get_locator_hashes", || {
				let batch_read = self.store.batch_read()?;
				txhashset::header_extending_readonly(&mut header_pmmr, batch_read, |ext, batch| {
					let header = batch.get_block_header(&sync_head_hash)?;
					self.rewind_and_apply_header_fork(&header, ext, batch)?;

					let mut hashes = Vec::with_capacity(heights.len());

					for h in heights {
						if *h > sync_head.height {
							return Err(Error::InvalidHeaderHeight(*h));
						}

						let hash = ext.get_header_hash_by_height(*h)?.ok_or_else(|| {
							Error::Other(format!(
								"missing header PMMR entry for locator height {} after rewinding to sync head {} at height {}",
								h, sync_head_hash, sync_head.height
							))
						})?;
						hashes.push(hash);
					}

					Ok(hashes)
				})
			});
		}
	}

	/// Builds an iterator on blocks starting from the current chain head and
	/// running backward. Specialized to return information pertaining to block
	/// difficulty calculation (timestamp and previous difficulties).
	pub fn difficulty_iter(&self) -> Result<store::DifficultyIter<'_>, Error> {
		self.ensure_chain_robust()?;
		let head = self.head()?;
		self.difficulty_iter_from(head.last_block_h)
	}

	/// Builds an iterator on blocks starting from the provided block hash and
	/// running backward. Specialized to return information pertaining to block
	/// difficulty calculation (timestamp and previous difficulties).
	pub fn difficulty_iter_from(&self, start: Hash) -> Result<store::DifficultyIter<'_>, Error> {
		self.ensure_chain_robust()?;
		Ok(store::DifficultyIter::from(start, self.store.clone()))
	}

	/// Check whether we have a block without reading it
	pub fn block_exists(&self, h: &Hash) -> Result<bool, Error> {
		self.ensure_chain_robust()?;
		self.store
			.block_exists(h)
			.map_err(|e| Error::StoreErr(e, "chain block exists".to_owned()))
	}

	/// Locate headers from the main chain.
	pub fn locate_headers(
		&self,
		locator: &[Hash],
		block_header_num: u32,
	) -> Result<Vec<mwc_core::core::BlockHeader>, crate::Error> {
		self.ensure_chain_robust()?;
		debug!("locator: {:?}", locator);

		let header = match self.find_common_header(locator)? {
			Some(header) => header,
			None => return Ok(vec![]),
		};

		// looks like we know one, getting as many following headers as allowed
		let hh = header.height;
		let start_height = hh.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("Chain::locate_headers, start height hh={}", hh))
		})?;
		let end_height = hh.checked_add(block_header_num as u64).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Chain::locate_headers, end height hh={} block_header_num={}",
				hh, block_header_num
			))
		})?;
		let header_hashes = self.with_robust_header_pmmr_read(|header_pmmr| {
			// Do not call self.header_head() while holding header_pmmr. It can
			// trigger init recovery, which needs header_pmmr.write().
			let max_height = self
				.store
				.header_head()
				.map_err(|e| Error::StoreErr(e, "locate headers header head".to_owned()))?
				.height;
			let mut header_hashes = vec![];
			for h in start_height..=end_height {
				if h > max_height {
					break;
				}

				header_hashes.push(header_pmmr.get_header_hash_by_height(h)?);
			}
			Ok(header_hashes)
		})?;

		let mut headers = Vec::with_capacity(header_hashes.len());
		for hash in header_hashes {
			let header = self.get_block_header(&hash)?;
			headers.push(header);
		}
		debug!("returning headers: {}", headers.len());
		Ok(headers)
	}

	// Find the first locator hash that refers to a known header on our main chain.
	fn find_common_header(&self, locator: &[Hash]) -> Result<Option<BlockHeader>, Error> {
		self.with_robust_header_pmmr_read(|header_pmmr| {
			let header_head_height = self
				.store
				.header_head()
				.map_err(|e| Error::StoreErr(e, "chain header head".to_owned()))?
				.height;
			let context_id = self.store.get_context_id();
			let get_block_header = |hash: &Hash| {
				self.store
					.get_block_header(hash)
					.map_err(|e| Error::StoreErr(e, "chain get header".to_owned()))
			};
			for hash in locator {
				let header = match get_block_header(hash) {
					Ok(header) => header,
					Err(Error::StoreErr(NotFoundErr(_), _)) => continue,
					Err(e) => return Err(e),
				};
				if header.height > header_head_height {
					continue;
				}
				let hash_at_height = header_pmmr.get_header_hash_by_height(header.height)?;
				let header_at_height = get_block_header(&hash_at_height)?;
				if header.hash(context_id)? == header_at_height.hash(context_id)? {
					return Ok(Some(header));
				}
			}
			Ok(None)
		})
	}

	/// App sesion id, defines network
	pub fn get_context_id(&self) -> u32 {
		self.store.get_context_id()
	}
}

fn mark_interrupted_pibd_for_recovery(
	genesis: &Block,
	store: &store::ChainStore,
	txhashset: &TxHashSet,
) -> Result<(), Error> {
	if store.pending_chain_operation()?.is_some() {
		return Ok(());
	}

	let batch = store.batch_read()?;
	let stored_head = match batch.head() {
		Ok(head) => head,
		Err(NotFoundErr(_)) => return Ok(()),
		Err(e) => return Err(Error::StoreErr(e, "interrupted PIBD load HEAD".into())),
	};
	let (_, head) = canonical_tip_header("HEAD", &stored_head, &batch)?;
	let genesis_head = Tip::try_from_header(&genesis.header)?;
	if head != genesis_head {
		return Ok(());
	}

	let expected_sizes = (
		genesis.header.output_mmr_size,
		genesis.header.output_mmr_size,
		genesis.header.kernel_mmr_size,
	);
	let actual_sizes = (
		txhashset.output_mmr_size(),
		txhashset.rangeproof_mmr_size(),
		txhashset.kernel_mmr_size(),
	);
	if actual_sizes == expected_sizes {
		return Ok(());
	}
	drop(batch);

	warn!(
		"Detected interrupted PIBD body state at genesis: output/rangeproof/kernel PMMR sizes are {}/{}/{}, expected {}/{}/{}. Scheduling a full PIBD body reset while preserving HEADER_HEAD",
		actual_sizes.0,
		actual_sizes.1,
		actual_sizes.2,
		expected_sizes.0,
		expected_sizes.1,
		expected_sizes.2,
	);
	if !store.set_pending_chain_operation_if_absent(&PendingChainOperation::PibdReset)? {
		warn!("A pending chain operation was installed while scheduling interrupted PIBD recovery");
	}
	Ok(())
}

fn reset_pibd_chain_state(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
) -> Result<(), Error> {
	reset_chain_head_to_genesis_state(
		genesis,
		store,
		header_pmmr,
		txhashset,
		secp,
		pow_verifier,
		stop_state,
		false,
	)?;
	Ok(())
}

fn prepare_reset_chain_head_operation(
	store: &store::ChainStore,
	header: &BlockHeader,
	rewind_headers: bool,
) -> Result<PendingChainOperation, Error> {
	pipe::validate_header_context_id(store.get_context_id(), header)?;
	let batch = store.batch_read()?;
	let original_body_head = batch.head()?;
	let original_header_head = batch.header_head()?;
	let requested_target = Tip::try_from_header(header)?;
	let (_, target_body_head) = canonical_tip_header("reset target", &requested_target, &batch)?;
	let target_header_head = if rewind_headers {
		target_body_head
	} else {
		original_header_head
	};
	Ok(PendingChainOperation::ResetChainHead {
		original_body_head,
		original_header_head,
		target_body_head,
		target_header_head,
		rewind_headers,
	})
}

fn prepare_reconcile_heads_operation(
	store: &store::ChainStore,
	kind: ChainOperationKind,
) -> Result<PendingChainOperation, Error> {
	let batch = store.batch_read()?;
	Ok(PendingChainOperation::ReconcileHeads {
		kind,
		original_body_head: batch.head()?,
		original_header_head: batch.header_head()?,
	})
}

fn recover_pending_chain_operation(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
) -> Result<(), Error> {
	let op = match store.pending_chain_operation()? {
		None => return Ok(()),
		Some(op) => op,
	};

	warn!("Detected incomplete chain operation: {:?}", op.kind());
	recover_marked_chain_operation(
		genesis,
		store,
		header_pmmr,
		txhashset,
		secp,
		pow_verifier,
		stop_state,
		&op,
	)
}

fn recover_marked_chain_operation(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
	op: &PendingChainOperation,
) -> Result<(), Error> {
	let res = match op {
		PendingChainOperation::PibdReset => reset_pibd_chain_state(
			genesis,
			store,
			header_pmmr,
			txhashset,
			secp,
			pow_verifier,
			stop_state.clone(),
		),
		PendingChainOperation::ResetToGenesis => reset_chain_head_to_genesis_state(
			genesis,
			store,
			header_pmmr,
			txhashset,
			secp,
			pow_verifier,
			stop_state.clone(),
			true,
		),
		PendingChainOperation::Compact {
			original_body_head,
			original_header_head,
			target_body_tail,
		} => recover_compact_chain_operation(
			genesis,
			store,
			header_pmmr,
			txhashset,
			secp,
			pow_verifier,
			stop_state.clone(),
			original_body_head,
			original_header_head,
			target_body_tail,
		),
		PendingChainOperation::ReconcileHeads {
			kind: ChainOperationKind::Compact,
			original_body_head,
			original_header_head,
		} => recover_legacy_compact_chain_operation(
			genesis,
			store,
			header_pmmr,
			txhashset,
			secp,
			pow_verifier,
			stop_state.clone(),
			original_body_head,
			original_header_head,
		),
		PendingChainOperation::ResetChainHead { .. }
		| PendingChainOperation::ReconcileHeads { .. } => reconcile_pmmrs_to_db_heads(
			genesis,
			store,
			header_pmmr,
			txhashset,
			secp,
			pow_verifier,
			stop_state,
		),
	};

	match res {
		Ok(()) => {
			store.clear_pending_chain_operation()?;
			Ok(())
		}
		Err(e) => {
			// A marked-operation recovery failure means the code cannot prove that
			// the durable DB selectors and PMMR files describe one state. Do not hide
			// that failure by silently rebuilding the body at genesis. Keep the marker
			// so every restart fails closed until the operator has investigated and
			// explicitly cleaned, reset, or resynchronized the chain data.
			error!(
				"Failed to recover pending {:?}: {}. Automatic fallback reset is disabled; the pending marker is retained. Inspect the chain data and explicitly clean or reset it before restarting",
				op.kind(),
				e
			);
			Err(e)
		}
	}
}

/// Recover a compact marker written before the marker carried an explicit
/// BODY_TAIL. The old operation selected its horizon deterministically from
/// the recorded body head, so derive that target and then apply the same full
/// validation as a new marker. If configuration changed incompatibly, the
/// PMMR rewind-target checks fail closed and leave the marker installed.
fn recover_legacy_compact_chain_operation(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
	original_body_head: &Tip,
	original_header_head: &Tip,
) -> Result<(), Error> {
	let batch = store.batch_read()?;
	let (body_head_header, canonical_body_head) = canonical_tip_header(
		"legacy compact marker original HEAD",
		original_body_head,
		&batch,
	)?;
	let (_, canonical_header_head) = canonical_tip_header(
		"legacy compact marker original HEADER_HEAD",
		original_header_head,
		&batch,
	)?;
	let horizon_height =
		canonical_body_head
			.height
			.saturating_sub(u64::from(global::cut_through_horizon(
				store.get_context_id(),
			)));
	let horizon_header = body_chain_ancestor_at_height(
		store.get_context_id(),
		&batch,
		&body_head_header,
		horizon_height,
		"legacy compact marker horizon ancestry",
	)?;
	let target_body_tail = Tip::try_from_header(&horizon_header)?;
	drop(batch);

	warn!(
		"Recovering legacy compact marker by deriving BODY_TAIL {} at height {} from recorded HEAD",
		target_body_tail.last_block_h, target_body_tail.height
	);
	recover_compact_chain_operation(
		genesis,
		store,
		header_pmmr,
		txhashset,
		secp,
		pow_verifier,
		stop_state,
		&canonical_body_head,
		&canonical_header_head,
		&target_body_tail,
	)
}

/// Recover the cross-durability boundary changed by chain compaction.
///
/// PMMR compaction replaces files before the LMDB batch containing BODY_TAIL
/// commits. The marker's target tail is therefore the authoritative minimum
/// rewind horizon if recovery observes the compacted files with an older DB
/// tail. Validate it against both the durable body chain and every body PMMR
/// before publishing it.
fn recover_compact_chain_operation(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
	original_body_head: &Tip,
	original_header_head: &Tip,
	target_body_tail: &Tip,
) -> Result<(), Error> {
	let context_id = store.get_context_id();
	let batch = store.batch_read()?;
	let stored_body_head = batch.head()?;
	let (body_head_header, body_head) =
		canonical_tip_header("compact recovery HEAD", &stored_body_head, &batch)?;
	let stored_header_head = batch.header_head()?;
	let (_, header_head) =
		canonical_tip_header("compact recovery HEADER_HEAD", &stored_header_head, &batch)?;
	let (_, marker_body_head) =
		canonical_tip_header("compact marker original HEAD", original_body_head, &batch)?;
	let (_, marker_header_head) = canonical_tip_header(
		"compact marker original HEADER_HEAD",
		original_header_head,
		&batch,
	)?;
	if marker_body_head != *original_body_head || marker_header_head != *original_header_head {
		return Err(Error::InvalidPersistedChainState(
			"compact recovery marker contains non-canonical original chain heads".into(),
		));
	}
	if body_head != marker_body_head || header_head != marker_header_head {
		return Err(Error::InvalidPersistedChainState(format!(
			"compact recovery chain heads changed after the horizon was selected: marker HEAD {:?}, current HEAD {:?}, marker HEADER_HEAD {:?}, current HEADER_HEAD {:?}",
			marker_body_head, body_head, marker_header_head, header_head
		)));
	}

	let (target_header, canonical_target_tail) =
		canonical_tip_header("compact marker target BODY_TAIL", target_body_tail, &batch)?;
	if canonical_target_tail != *target_body_tail {
		return Err(Error::InvalidPersistedChainState(format!(
			"compact recovery marker target BODY_TAIL {:?} is not canonical {:?}",
			target_body_tail, canonical_target_tail
		)));
	}
	if canonical_target_tail.height > body_head.height {
		return Err(Error::InvalidPersistedChainState(format!(
			"compact recovery target BODY_TAIL height {} is above HEAD height {}",
			canonical_target_tail.height, body_head.height
		)));
	}
	let target_on_body_chain = body_chain_ancestor_at_height(
		context_id,
		&batch,
		&body_head_header,
		canonical_target_tail.height,
		"compact recovery target BODY_TAIL ancestry",
	)?;
	if target_on_body_chain != target_header {
		return Err(Error::InvalidPersistedChainState(format!(
			"compact recovery target BODY_TAIL {} at height {} is not on durable body chain",
			canonical_target_tail.last_block_h, canonical_target_tail.height
		)));
	}
	crate::checked_block_for_header(
		context_id,
		&target_header,
		"compact recovery target BODY_TAIL preflight",
		|hash| batch.get_block(hash),
	)?;
	txhashset.validate_recovery_rewind_targets_for(
		"compact target BODY_TAIL",
		&canonical_target_tail,
		&target_header,
	)?;
	drop(batch);

	// Compaction does not intentionally change either head, but its marker also
	// protects against unrelated speculative PMMR writes. Repair those first.
	reconcile_pmmrs_to_db_heads(
		genesis,
		store,
		header_pmmr,
		txhashset,
		secp,
		pow_verifier,
		stop_state,
	)?;

	let batch = store.batch_read()?;
	let stored_body_head = batch.head()?;
	let (body_head_header, body_head) =
		canonical_tip_header("compact recovery repaired HEAD", &stored_body_head, &batch)?;
	if body_head != marker_body_head {
		return Err(Error::InvalidPersistedChainState(format!(
			"compact recovery HEAD changed while repairing PMMRs: marker {:?}, current {:?}",
			marker_body_head, body_head
		)));
	}

	let repaired_tail = match batch.tail() {
		Ok(stored_tail) => {
			let (tail_header, tail) =
				canonical_tip_header("compact recovery current BODY_TAIL", &stored_tail, &batch)?;
			if tail.height > body_head.height {
				return Err(Error::InvalidPersistedChainState(format!(
					"compact recovery current BODY_TAIL height {} is above HEAD height {}",
					tail.height, body_head.height
				)));
			}
			if tail.height >= canonical_target_tail.height {
				let tail_on_body_chain = body_chain_ancestor_at_height(
					context_id,
					&batch,
					&body_head_header,
					tail.height,
					"compact recovery current BODY_TAIL ancestry",
				)?;
				if tail_on_body_chain != tail_header {
					return Err(Error::InvalidPersistedChainState(format!(
						"compact recovery current BODY_TAIL {} at height {} is not on durable body chain",
						tail.last_block_h, tail.height
					)));
				}
				crate::checked_block_for_header(
					context_id,
					&tail_header,
					"compact recovery current BODY_TAIL preflight",
					|hash| batch.get_block(hash),
				)?;
				txhashset.validate_recovery_rewind_targets_for(
					"current BODY_TAIL",
					&tail,
					&tail_header,
				)?;
				tail
			} else {
				canonical_target_tail
			}
		}
		Err(NotFoundErr(_)) => canonical_target_tail,
		Err(e) => {
			return Err(Error::StoreErr(e, "compact recovery load BODY_TAIL".into()));
		}
	};
	drop(batch);

	let batch = store.batch_write()?;
	batch.save_body_tail(&repaired_tail)?;
	batch.commit()?;
	Ok(())
}

fn body_chain_ancestor_at_height(
	context_id: u32,
	batch: &store::Batch<'_>,
	body_head: &BlockHeader,
	height: u64,
	operation: &str,
) -> Result<BlockHeader, Error> {
	if height > body_head.height {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} requested height {} above body head height {}",
			operation, height, body_head.height
		)));
	}

	let mut current = body_head.clone();
	let mut visited = HashSet::new();
	while current.height > height {
		current = crate::checked_previous_header(
			context_id,
			&current,
			&mut visited,
			operation,
			|hash| batch.get_block_header(hash),
		)?;
	}
	if current.height != height {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} stopped at height {}, below requested height {}",
			operation, current.height, height
		)));
	}
	Ok(current)
}

/// Refuse rewind-only recovery when a durable DB head is ahead of a PMMR file.
///
/// PMMR extensions sync their files before their caller commits the enclosing
/// LMDB batch. A crash or failed outer commit after a rewind can therefore leave
/// a completely valid but shorter PMMR on disk while HEAD or HEADER_HEAD still
/// selects the previous, higher state. This is an expected cross-durability-
/// domain failure mode; it does not imply that either individual store is
/// internally corrupt.
///
/// The normal reconciliation code cannot repair that direction of mismatch. It
/// initializes Extension and HeaderExtension from the durable DB tips and then
/// uses rewind operations. If the files are shorter, the extensions incorrectly
/// appear to be at the requested heads and eventually ask PMMRBackend::rewind to
/// move a hash or data file forward. Rewind correctly rejects that request and
/// cannot recreate the missing headers, outputs, rangeproofs, or kernels.
///
/// Validate the targets before mutating any PMMR. Returning a dedicated error on
/// the first missing component makes node initialization fail with an actionable
/// reason, bypasses the unsuitable body-only fallback, and preserves the pending-
/// operation marker for an explicit reset or resynchronization.
fn preflight_reconciliation_pmmr_capacity(
	body_head: &Tip,
	body_header: &BlockHeader,
	header_head: &Tip,
	header_header: &BlockHeader,
	header_pmmr: &PMMRHandle<BlockHeader>,
	txhashset: &TxHashSet,
) -> Result<(), Error> {
	let header_leaf_count = header_header.height.checked_add(1).ok_or_else(|| {
		Error::DataOverflow(format!(
			"recovery HEADER_HEAD height overflow: {}",
			header_header.height
		))
	})?;
	let header_position = pmmr::insertion_to_pmmr_index(header_leaf_count)?;

	match header_pmmr.backend.validate_rewind_target(header_position) {
		Ok(()) => {}
		Err(pmmr::Error::InvalidState(reason)) => {
			return Err(Error::PmmrRecoveryRequired(format!(
				"durable HEADER_HEAD {} at height {} requires header PMMR position {}, but the current backend files are shorter: {}",
				header_head.last_block_h, header_head.height, header_position, reason
			)));
		}
		Err(err) => return Err(err.into()),
	}
	txhashset.validate_recovery_rewind_targets(body_head, body_header)
}

/// Authenticate the complete persisted header before recovery trusts the
/// proof-derived identity stored in the header PMMR.
///
/// The fixed production genesis proofs predate the current runtime verifier,
/// so height zero is authenticated by exact equality with the configured
/// genesis header. Every later header must pass the verifier configured for
/// this Chain instance.
fn authenticate_persisted_header_for_recovery(
	context_id: u32,
	genesis: &BlockHeader,
	header: &BlockHeader,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
) -> Result<(), Error> {
	pipe::validate_header_context_id(context_id, header).map_err(|e| {
		Error::InvalidPersistedChainState(format!(
			"persisted header at height {} failed context authentication: {}",
			header.height, e
		))
	})?;

	if header.height == 0 {
		if header != genesis {
			return Err(Error::InvalidPersistedChainState(
				"persisted height-zero header does not exactly match configured genesis".into(),
			));
		}
		return Ok(());
	}

	if !header.pow.is_primary(context_id) && !header.pow.is_secondary() {
		return Err(Error::InvalidPersistedChainState(format!(
			"persisted header at height {} has invalid proof edge bits",
			header.height
		)));
	}

	pow_verifier(context_id, header).map_err(|e| {
		Error::InvalidPersistedChainState(format!(
			"persisted header at height {} failed PoW authentication: {}",
			header.height, e
		))
	})
}

fn reconcile_pmmrs_to_db_heads(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
) -> Result<(), Error> {
	// Reconciliation repairs PMMRs to the durable DB-selected heads. It
	// intentionally does not apply INVALID_BLOCK_HASHES to ancestry already
	// represented by those heads: denylist checks belong to normal header/block
	// admission and explicit rewind_bad_block handling, not this durability-repair
	// path.
	let batch = store.batch_read()?;
	let body_head = batch.head()?;
	let header_head = batch.header_head()?;
	// Canonicalize both tips: each selected header must hash back to its
	// persisted selector before any PMMR is mutated toward it.
	let (body_header, canonical_body_head) = canonical_tip_header("HEAD", &body_head, &batch)?;
	let (header_header, canonical_header_head) =
		canonical_tip_header("HEADER_HEAD", &header_head, &batch)?;
	preflight_reconciliation_pmmr_capacity(
		&canonical_body_head,
		&body_header,
		&canonical_header_head,
		&header_header,
		header_pmmr,
		txhashset,
	)?;
	crate::checked_block_for_header(
		store.get_context_id(),
		&body_header,
		"reconcile_pmmrs_to_db_heads HEAD preflight",
		|hash| batch.get_block(hash),
	)?;
	drop(batch);

	// Repair the header PMMR first. Body reconciliation uses it as a temporary
	// fork index, so it must no longer expose speculative entries whose DB records
	// were rolled back with an interrupted outer batch.
	reconcile_header_pmmr_to_header(
		&genesis.header,
		store,
		header_pmmr,
		&header_header,
		pow_verifier,
		stop_state.clone(),
	)?;
	reconcile_body_pmmr_to_header(
		&genesis.header,
		store,
		header_pmmr,
		txhashset,
		secp,
		&body_header,
		pow_verifier,
		stop_state,
	)?;

	// Publish both repaired caches only after both PMMRs authenticate. Keeping
	// these writes in one final batch prevents recovery from exposing one
	// canonical Tip while leaving the other stale.
	let batch = store.batch_write()?;
	batch.save_body_head(&canonical_body_head)?;
	batch.save_header_head(&canonical_header_head)?;
	batch.commit()?;
	Ok(())
}

fn reconcile_body_pmmr_to_header(
	genesis: &BlockHeader,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	header: &BlockHeader,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
) -> Result<(), Error> {
	let context_id = store.get_context_id();
	let authenticate_header = |candidate: &BlockHeader| {
		if stop_state
			.as_ref()
			.map(|state| state.is_stopped())
			.unwrap_or(false)
		{
			return Err(Error::Stopped);
		}
		authenticate_persisted_header_for_recovery(context_id, genesis, candidate, pow_verifier)
	};
	let mut batch = store.batch_write()?;
	txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
		pipe::rewind_and_apply_fork_for_recovery(
			context_id,
			header,
			ext,
			batch,
			secp,
			&authenticate_header,
		)?;
		// A same-head rewind truncates appended PMMR data but has no block-derived
		// spend bitmap with which to restore leaves removed by an interrupted,
		// uncommitted extension. Roots and kernel sums do not authenticate exact
		// leaf membership, so require a bidirectional match with the committed
		// output-position index before recovery can clear its marker.
		ext.extension.validate_output_pos_index(batch, header)?;
		ext.extension
			.validate(genesis, true, None, header, stop_state.clone(), secp)?;
		Ok(())
	})?;
	batch.commit()?;
	Ok(())
}

fn reconcile_header_pmmr_to_header(
	genesis: &BlockHeader,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	header: &BlockHeader,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
) -> Result<(), Error> {
	let context_id = store.get_context_id();
	let authenticate_header = |candidate: &BlockHeader| {
		if stop_state
			.as_ref()
			.map(|state| state.is_stopped())
			.unwrap_or(false)
		{
			return Err(Error::Stopped);
		}
		authenticate_persisted_header_for_recovery(context_id, genesis, candidate, pow_verifier)
	};
	let mut batch = store.batch_write()?;
	let durable_head = Tip::try_from_header(header)?;
	txhashset::header_extending_with_explicit_head(
		header_pmmr,
		&mut batch,
		durable_head,
		|ext, batch| {
			pipe::rewind_and_apply_header_fork_for_recovery(
				context_id,
				header,
				ext,
				batch,
				&authenticate_header,
			)?;
			ext.validate_persisted_ancestry(header, batch, pow_verifier, stop_state.as_deref())
		},
	)?;
	batch.commit()?;
	Ok(())
}

fn reset_chain_head_state(
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	header: &BlockHeader,
	rewind_headers: bool,
) -> Result<(), Error> {
	let context_id = store.get_context_id();
	pipe::validate_header_context_id(context_id, header)?;
	let requested_target = Tip::try_from_header(header)?;
	let mut batch = store.batch_write()?;
	let (header, head) = canonical_tip_header("reset target", &requested_target, &batch)?;

	// A zero-step reset and a rewind to an existing ancestor do not otherwise
	// load the target block.
	crate::checked_block_for_header(
		context_id,
		&header,
		"reset_chain_head target preflight",
		|hash| batch.get_block(hash),
	)?;

	let (tail_header, tail) = match batch.tail() {
		Ok(stored_tail) => canonical_tip_header("BODY_TAIL", &stored_tail, &batch)?,
		Err(NotFoundErr(_)) => {
			let stored_head = batch.head()?;
			let (head_header, canonical_head) = canonical_tip_header("HEAD", &stored_head, &batch)?;
			if canonical_head.height != 0 {
				return Err(Error::InvalidPersistedChainState(format!(
					"reset_chain_head BODY_TAIL is missing for HEAD at height {}",
					canonical_head.height
				)));
			}
			(head_header, canonical_head)
		}
		Err(e) => return Err(Error::StoreErr(e, "reset_chain_head load BODY_TAIL".into())),
	};
	if head.height < tail.height {
		return Err(Error::Other(format!(
			"reset_chain_head cannot reset HEAD to height {} below BODY_TAIL at height {}",
			head.height, tail.height
		)));
	}
	let mut target_at_tail = header.clone();
	let mut visited = HashSet::new();
	while target_at_tail.height > tail.height {
		target_at_tail = crate::checked_previous_header(
			context_id,
			&target_at_tail,
			&mut visited,
			"reset_chain_head target ancestry",
			|hash| batch.get_block_header(hash),
		)?;
	}
	if target_at_tail != tail_header {
		return Err(Error::Other(format!(
			"reset_chain_head target ancestry does not contain BODY_TAIL {} at height {}",
			tail.last_block_h, tail.height
		)));
	}

	// Rewind and reapply blocks to reset the output/rangeproof/kernel MMR.
	txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
		pipe::rewind_and_apply_fork(context_id, &header, ext, batch, secp)?;
		ext.extension.validate_roots(&header)?;
		ext.extension.validate_sizes(&header)?;
		batch.save_body_tail(&tail)?;
		batch.save_body_head(&head)?;
		Ok(())
	})?;

	if rewind_headers {
		// If the rewind of full blocks was successful then we can rewind the header MMR.
		// Rewind and reapply headers to reset the header MMR.
		txhashset::header_extending(header_pmmr, &mut batch, |ext, batch| {
			pipe::rewind_and_apply_header_fork(context_id, &header, ext, batch)?;
			batch.save_header_head(&head)?;
			Ok(())
		})?;
	}

	batch.commit()?;
	Ok(())
}

fn combine_positioned_outputs_and_rangeproofs(
	outputs: (u64, Vec<(u64, OutputIdentifier)>),
	rangeproofs: (u64, Vec<(u64, RangeProof)>),
) -> Result<(u64, Vec<Output>), Error> {
	if outputs.0 != rangeproofs.0 || outputs.1.len() != rangeproofs.1.len() {
		return Err(Error::TxHashSetErr(String::from(
			"Output and rangeproof sets don't match",
		)));
	}

	let index = outputs.0;
	let mut output_vec = Vec::with_capacity(outputs.1.len());
	for ((output_pos, output), (rangeproof_pos, rangeproof)) in
		outputs.1.into_iter().zip(rangeproofs.1.into_iter())
	{
		// output_pos and rangeproof_pos are 1-based PMMR indexes.
		if output_pos != rangeproof_pos {
			return Err(Error::TxHashSetErr(format!(
				"Output and rangeproof PMMR positions don't match: output position {}, rangeproof position {}",
				output_pos, rangeproof_pos
			)));
		}
		output_vec.push(Output::new(
			output.features,
			output.commitment(),
			rangeproof,
		));
	}
	Ok((index, output_vec))
}

fn reset_chain_head_to_genesis_state(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
	validate_retained_headers: bool,
) -> Result<(), Error> {
	validate_genesis_context_id(genesis, store.get_context_id())?;
	let head = Tip::try_from_header(&genesis.header)?;
	// Header sync authenticates every header before storing it. A PIBD body reset
	// intentionally preserves that chain, so it must not turn into another full
	// persisted-ancestry validation while holding both PMMR write locks.
	setup_head(
		genesis,
		store,
		header_pmmr,
		txhashset,
		secp,
		pow_verifier,
		stop_state.clone(),
		!validate_retained_headers,
		Some(head),
	)?;

	if !validate_retained_headers {
		return Ok(());
	}

	// Preserve the original reset ordering and validation boundaries: setup the
	// genesis body state first, then reconcile the retained header PMMR to its
	// durable HEADER_HEAD.
	let batch = store.batch_read()?;
	let stored_header_head = batch.header_head()?;
	let (header, _) = canonical_tip_header("HEADER_HEAD", &stored_header_head, &batch)?;
	drop(batch);
	reconcile_header_pmmr_to_header(
		&genesis.header,
		store,
		header_pmmr,
		&header,
		pow_verifier,
		stop_state,
	)
}

fn validate_genesis_context_id(genesis: &Block, context_id: u32) -> Result<(), Error> {
	let genesis_context_id = genesis.header.pow.proof.context_id;
	if genesis_context_id != context_id {
		error!(
			"genesis proof context_id mismatch: expected {}, got {}",
			context_id, genesis_context_id
		);
		return Err(Error::InvalidGenesisHash);
	}
	Ok(())
}

fn validate_genesis_for_init(
	secp: &Secp256k1,
	context_id: u32,
	genesis: &Block,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
) -> Result<(), Error> {
	validate_genesis_context_id(genesis, context_id)?;

	if genesis.header.height != 0 {
		return Err(Error::InvalidGenesisHash);
	}

	if !consensus::valid_header_version(context_id, genesis.header.height, genesis.header.version) {
		return Err(Error::InvalidBlockVersion(genesis.header.version));
	}

	if !genesis.header.pow.is_primary(context_id) && !genesis.header.pow.is_secondary() {
		return Err(Error::LowEdgebits);
	}

	// Mainnet and Floonet genesis blocks are fixed consensus identities. Their
	// historical Cuckarood29 proofs do not pass the current runtime verifier:
	// the verifier now requires a 42-edge proof to be parity-balanced, while
	// both hardcoded genesis proofs are 23 even / 19 odd. Re-mining or editing
	// those proofs would change the genesis hash, so accept only the exact
	// hardcoded genesis block by canonical serialization. Testing chain types
	// may still rely on the supplied PoW verifier for custom genesis blocks.
	match global::get_chain_type(context_id) {
		global::ChainTypes::Floonet | global::ChainTypes::Mainnet => {
			if is_known_hardcoded_genesis(secp, context_id, genesis)? {
				return Ok(());
			}
			return Err(Error::InvalidGenesisHash);
		}
		global::ChainTypes::AutomatedTesting | global::ChainTypes::UserTesting => {
			// Accepted risk: custom testing genesis blocks are intentionally
			// validated only far enough to initialize local test chain state.
			// We validate the context/header/PoW here, and setup_head later
			// checks kernel sums plus PMMR roots and sizes, but we do not run
			// the normal Block::validate/TransactionBody::validate checks for
			// rangeproofs, kernel signatures, coinbase rules, lock heights, or
			// NRD feature rules. These chain types are for synthetic test
			// chains, so custom testing genesis blocks do not need the full
			// production body validation required by Mainnet/Floonet genesis.
		}
	}

	match pow_verifier(context_id, &genesis.header) {
		Ok(()) => Ok(()),
		Err(pow::Error::Verification(e)) => {
			debug!(
				"init: invalid PoW for genesis header with cuckoo edge_bits {}: {}",
				genesis.header.pow.edge_bits(),
				e
			);
			Err(Error::InvalidPow)
		}
		Err(e) => {
			debug!(
				"init: PoW verifier failed for genesis header with cuckoo edge_bits {}: {}",
				genesis.header.pow.edge_bits(),
				e
			);
			Err(e.into())
		}
	}
}

fn is_known_hardcoded_genesis(
	secp: &Secp256k1,
	context_id: u32,
	genesis: &Block,
) -> Result<bool, Error> {
	match global::get_chain_type(context_id) {
		global::ChainTypes::Floonet => is_exact_genesis_match(
			context_id,
			genesis,
			&genesis::genesis_floo(secp, context_id),
		),
		global::ChainTypes::Mainnet => is_exact_genesis_match(
			context_id,
			genesis,
			&genesis::genesis_main(secp, context_id),
		),
		global::ChainTypes::AutomatedTesting | global::ChainTypes::UserTesting => Ok(false),
	}
}

fn is_exact_genesis_match(
	context_id: u32,
	genesis: &Block,
	expected_genesis: &Block,
) -> Result<bool, Error> {
	let mut genesis_bytes = Vec::new();
	ser::serialize_default(context_id, &mut genesis_bytes, genesis)?;

	let mut expected_bytes = Vec::new();
	ser::serialize_default(context_id, &mut expected_bytes, expected_genesis)?;

	Ok(genesis_bytes == expected_bytes)
}

fn validate_genesis_matches_header_pmmr(
	genesis_hash: &Hash,
	header_pmmr: &txhashset::PMMRHandle<BlockHeader>,
) -> Result<(), Error> {
	if header_pmmr.size == 0 {
		return Ok(());
	}

	let stored_genesis_hash = header_pmmr.get_header_hash_by_height(0)?;
	if stored_genesis_hash != *genesis_hash {
		error!(
			"genesis hash mismatch: expected {}, got {}",
			stored_genesis_hash, genesis_hash
		);
		return Err(Error::InvalidGenesisHash);
	}
	Ok(())
}

fn genesis_block_sums(
	genesis: &Block,
	context_id: u32,
	secp: &Secp256k1,
) -> Result<BlockSums, Error> {
	if genesis.inputs().is_empty() && genesis.outputs().is_empty() && genesis.kernels().is_empty() {
		if !genesis.header.total_kernel_offset().is_zero() {
			return Err(Error::Committed(
				mwc_core::core::committed::Error::KernelSumMismatch,
			));
		}
		return Ok(BlockSums::empty());
	}

	let (utxo_sum, kernel_sum) = (BlockSums::empty(), genesis as &dyn Committed)
		.verify_kernel_sums(
			genesis.header.overage(context_id)?,
			genesis.header.total_kernel_offset(),
			secp,
		)?;
	Ok(BlockSums::new(utxo_sum, kernel_sum))
}

fn save_genesis_block_metadata(
	genesis: &Block,
	genesis_hash: &Hash,
	batch: &store::Batch<'_>,
	secp: &Secp256k1,
	context_id: u32,
) -> Result<(), Error> {
	batch.save_block(genesis)?;
	batch.save_spent_index(genesis_hash, &[])?;
	batch.save_block_sums(genesis_hash, genesis_block_sums(genesis, context_id, secp)?)?;
	Ok(())
}

/// Rebuild the redundant fields of a persisted chain-tip cache from the
/// trusted block-header store.
///
/// Trust policy: `persisted.last_block_h` is the authoritative head selector,
/// and the header stored under that key is authoritative after its recomputed
/// hash has been verified against the selector. The remaining Tip fields
/// (`height`, `prev_block_h`, and `total_difficulty`) are cached copies that may
/// be repaired from the header. Header validity, PoW, and selection of the
/// winning fork have already been established before data reaches this store
/// and are intentionally not revalidated here.
fn canonical_tip_header(
	name: &str,
	persisted: &Tip,
	batch: &store::Batch<'_>,
) -> Result<(BlockHeader, Tip), Error> {
	let header = batch
		.get_block_header(&persisted.last_block_h)
		.map_err(|e| {
			Error::StoreErr(
				e,
				format!("chain init load {} header {}", name, persisted.last_block_h),
			)
		})?;
	let canonical = Tip::try_from_header(&header)?;
	if canonical.last_block_h != persisted.last_block_h {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} header key/hash mismatch: selected {}, header hashes to {}",
			name, persisted.last_block_h, canonical.last_block_h
		)));
	}
	Ok((header, canonical))
}

/// Permit implicit genesis initialization only for an empty chain store.
///
/// A missing HEAD is normal on the first startup, but it is also possible after
/// local database damage. Treating every missing selector as a fresh node would
/// silently replace an existing body chain with genesis. Normal startup must
/// therefore fail closed if any authoritative DB selector, PMMR content, header,
/// or full block proves that this store was already used. The operator can then
/// investigate and explicitly clean or reset the node data. Explicit reset/PIBD
/// paths pass a body-head override and intentionally do not use this preflight.
///
/// This also covers an intentionally fail-closed first-run failure mode. The
/// PMMR extension helpers sync their files before setup_head() commits its outer
/// LMDB batch. A process exit or propagated error in that interval can therefore
/// leave genesis PMMR data on disk without a durable HEAD. There is deliberately
/// no automatic recovery for that unmarked state: on the next startup it is
/// indistinguishable from loss of HEAD in a previously used store. The node must
/// report the inconsistency and require the operator to inspect and explicitly
/// clean or reset the chain data instead of implicitly deleting or rebuilding it.
fn ensure_missing_head_is_fresh(
	batch: &store::Batch<'_>,
	header_pmmr: &PMMRHandle<BlockHeader>,
	txhashset: &TxHashSet,
) -> Result<(), Error> {
	match batch.head() {
		Ok(_) => return Ok(()),
		Err(NotFoundErr(_)) => {}
		Err(e) => return Err(Error::StoreErr(e, "fresh-chain preflight HEAD".into())),
	}

	let mut existing_state = Vec::new();
	match batch.header_head() {
		Ok(head) => existing_state.push(format!(
			"HEADER_HEAD {} at height {}",
			head.last_block_h, head.height
		)),
		Err(NotFoundErr(_)) => {}
		Err(e) => {
			return Err(Error::StoreErr(
				e,
				"fresh-chain preflight HEADER_HEAD".into(),
			));
		}
	}
	match batch.tail() {
		Ok(tail) => existing_state.push(format!(
			"BODY_TAIL {} at height {}",
			tail.last_block_h, tail.height
		)),
		Err(NotFoundErr(_)) => {}
		Err(e) => return Err(Error::StoreErr(e, "fresh-chain preflight BODY_TAIL".into())),
	}

	if header_pmmr.size != 0 {
		existing_state.push(format!("header PMMR size {}", header_pmmr.size));
	}
	let body_sizes = (
		txhashset.output_mmr_size(),
		txhashset.rangeproof_mmr_size(),
		txhashset.kernel_mmr_size(),
	);
	if body_sizes != (0, 0, 0) {
		existing_state.push(format!(
			"body PMMR sizes output/rangeproof/kernel {}/{}/{}",
			body_sizes.0, body_sizes.1, body_sizes.2
		));
	}
	if batch
		.has_any_block_headers()
		.map_err(|e| Error::StoreErr(e, "fresh-chain preflight block-header records".into()))?
	{
		existing_state.push("persisted block-header records".into());
	}
	if batch
		.has_any_full_blocks()
		.map_err(|e| Error::StoreErr(e, "fresh-chain preflight full-block records".into()))?
	{
		existing_state.push("persisted full-block records".into());
	}
	if batch
		.has_any_auxiliary_chain_state()
		.map_err(|e| Error::StoreErr(e, "fresh-chain preflight auxiliary records".into()))?
	{
		existing_state.push("persisted auxiliary chain records or cache flags".into());
	}

	if existing_state.is_empty() {
		return Ok(());
	}

	let msg = format!(
		"HEAD is missing from non-fresh chain state ({}). Automatic genesis rebuild is disabled; inspect the chain data and explicitly clean or reset it before restarting",
		existing_state.join(", ")
	);
	error!("{}", msg);
	Err(Error::InvalidPersistedChainState(msg))
}

fn setup_head(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut txhashset::PMMRHandle<BlockHeader>,
	txhashset: &mut txhashset::TxHashSet,
	secp: &Secp256k1,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	stop_state: Option<Arc<StopState>>,
	skip_start_blockchain_validation: bool,
	body_head_override: Option<Tip>,
) -> Result<(), Error> {
	let context_id = store.get_context_id();
	validate_genesis_context_id(genesis, context_id)?;

	let mut batch = store.batch_write()?;
	if body_head_override.is_none() {
		ensure_missing_head_is_fresh(&batch, header_pmmr, txhashset)?;
	}
	let genesis_hash = genesis.hash(context_id)?;
	validate_genesis_matches_header_pmmr(&genesis_hash, header_pmmr)?;
	// Durability policy: header_extending() and extending() sync PMMR files
	// before the enclosing LMDB batch below is committed. If initialization
	// terminates after either sync, the PMMR data may survive while all staged
	// genesis records, including HEAD, are rolled back. We intentionally leave
	// that state for explicit operator investigation/cleanup rather than infer
	// that a missing HEAD authorizes automatic PMMR deletion or genesis rebuild.
	// ensure_missing_head_is_fresh() enforces this fail-closed policy on restart.
	// Apply the genesis header to header and sync MMRs.
	{
		match batch.get_block_header(&genesis_hash) {
			Ok(stored) => {
				if stored != genesis.header {
					return Err(Error::InvalidPersistedChainState(format!(
						"stored genesis header {} does not exactly match configured genesis",
						genesis_hash
					)));
				}
			}
			Err(NotFoundErr(_)) => {
				batch.save_block_header(&genesis.header)?;
			}
			Err(e) => return Err(Error::StoreErr(e, "chain init load genesis header".into())),
		}

		if header_pmmr.size == 0 {
			txhashset::header_extending(header_pmmr, &mut batch, |ext, _| {
				ext.apply_header(&genesis.header)
			})?;
		}
	}

	// Make sure our header PMMR is consistent with header_head from db if it exists.
	// If header_head is missing in db then use head of header PMMR.
	match batch.header_head() {
		Ok(stored_head) => {
			let (header, head) = canonical_tip_header("HEADER_HEAD", &stored_head, &batch)?;
			header_pmmr.init_head(&head)?;
			txhashset::header_extending(header_pmmr, &mut batch, |ext, batch| {
				ext.rewind(&header)?;
				if skip_start_blockchain_validation {
					Ok(())
				} else {
					ext.validate_persisted_ancestry(
						&header,
						batch,
						pow_verifier,
						stop_state.as_deref(),
					)
				}
			})?;
			if stored_head != head {
				warn!(
					"Repairing inconsistent HEADER_HEAD cache: stored {:?}, canonical {:?}",
					stored_head, head
				);
				batch.save_header_head(&head)?;
			}
		}
		Err(NotFoundErr(_)) => {
			let hash = header_pmmr.head_hash()?;
			let header = batch.get_block_header(&hash)?;
			let head = Tip::try_from_header(&header)?;
			if !skip_start_blockchain_validation {
				txhashset::header_extending(header_pmmr, &mut batch, |ext, batch| {
					ext.validate_persisted_ancestry(
						&header,
						batch,
						pow_verifier,
						stop_state.as_deref(),
					)
				})?;
			}
			batch.save_header_head(&head)?;
		}
		Err(e) => return Err(Error::StoreErr(e, "chain init load header head".to_owned())),
	}

	if let Some(stored_head) = body_head_override {
		let (_, head) = canonical_tip_header("HEAD override", &stored_head, &batch)?;
		if stored_head != head {
			return Err(Error::InvalidPersistedChainState(format!(
				"HEAD override {:?} does not match canonical {:?}",
				stored_head, head
			)));
		}
		// Stage intentional HEAD resets in the same batch as the rewind and
		// validation below. Committing HEAD first can leave durable chain
		// metadata reset even if setup_head later fails while syncing or
		// rewinding PMMR state.
		if head.height == 0 && head.last_block_h == genesis_hash {
			// Recreate metadata normally created by the missing-head genesis
			// init branch, then rebuild the body MMRs from genesis instead of
			// only rewinding to the sizes committed in the genesis header.
			save_genesis_block_metadata(genesis, &genesis_hash, &batch, secp, context_id)?;

			txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
				ext.extension.reset_prune_lists()?;
				ext.extension
					.rebuild_genesis(genesis, ext.header_extension, batch)?;
				ext.extension.validate_roots(&genesis.header)?;
				ext.extension.validate_sizes(&genesis.header)?;
				batch.save_body_tail(&head)?;
				batch.save_body_head(&head)?;
				Ok(())
			})?;

			txhashset.init_output_pos_index(&batch, None, stop_state.clone())?;
			txhashset.init_recent_kernel_pos_index(&batch, None, stop_state.clone())?;
			batch.commit()?;

			// Clear any full kernel_pos entries left above genesis and rebuild the
			// complete index before the reset operation reports success.
			txhashset.init_kernel_pos_index_chunked(store, None, stop_state.clone())?;
			return Ok(());
		}
		batch.save_body_head(&head)?;
	}

	// check if we have a head in store, otherwise the genesis block is it
	let head_res = batch.head();
	let head: Tip;
	match head_res {
		Ok(stored_head) => {
			let (_, canonical_head) = canonical_tip_header("HEAD", &stored_head, &batch)?;
			head = canonical_head;
			if stored_head != head {
				warn!(
					"Repairing inconsistent HEAD cache: stored {:?}, canonical {:?}",
					stored_head, head
				);
				batch.save_body_head(&head)?;
			}
			// Reconcile the PMMRs to the durable HEAD. Unless explicitly disabled,
			// validate the selected block and all authenticated chain state exactly
			// once; startup does not select an older block and retry after failure.
			{
				// Use current chain tip if we have one.
				// Note: We are rewinding and validating against a writeable extension.
				// If validation is successful we will truncate the backend files
				// to match the provided block header.
				let header = batch.get_block_header(&head.last_block_h)?;
				if !skip_start_blockchain_validation {
					crate::checked_block_for_header(
						context_id,
						&header,
						"setup_head durable HEAD preflight",
						|hash| batch.get_block(hash),
					)?;
				}
				let output_mmr_size_before = txhashset.output_mmr_size();
				let kernel_mmr_size_before = txhashset.kernel_mmr_size();
				let body_pmmr_rewind_expected = output_mmr_size_before > header.output_mmr_size
					|| kernel_mmr_size_before > header.kernel_mmr_size;

				let res = txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
					pipe::rewind_and_apply_fork(store.get_context_id(), &header, ext, batch, secp)?;

					if skip_start_blockchain_validation {
						debug!(
							"init: rewound without startup blockchain validation... {} at {}",
							header.hash(context_id)?,
							header.height,
						);
						return Ok(());
					}

					let extension = &mut ext.extension;
					// Authenticate persisted PMMR data against its hash trees and the
					// selected header before trusting or rebuilding any derived cache.
					// Fast validation still verifies the MMRs, roots, sizes, leaf-set
					// pairing, and kernel sums; it skips only rangeproof and kernel
					// signature verification.
					let (utxo_sum, kernel_sum) = extension.validate(
						&genesis.header,
						true,
						None,
						&header,
						stop_state.clone(),
						secp,
					)?;
					// PMMR roots authenticate append history, but not the exact
					// membership of the prunable output/rangeproof leaf sets. For a
					// zero-step startup rewind, bind those leaf sets to the independently
					// committed output_pos index before accepting the durable HEAD or
					// rebuilding derived caches.
					//
					// If the backend is actually being rewound, output_pos still describes
					// the pre-rewind state and is not a valid authentication anchor. The
					// success path below marks it incomplete so Chain::init rebuilds it.
					if !body_pmmr_rewind_expected {
						extension.validate_output_pos_index(batch, &header)?;
					}

					let header_hash = header.hash(context_id)?;
					let block_sums = if header.height == 0 {
						genesis_block_sums(genesis, context_id, secp)?
					} else {
						BlockSums::new(utxo_sum, kernel_sum)
					};
					// BlockSums is a derived acceleration cache. Replace it from the
					// validated txhashset rather than accepting any persisted value.
					batch.save_block_sums(&header_hash, block_sums)?;
					info!(
						"setup_head: startup txhashset validation finished at height {}; synchronizing PMMR backends",
						header.height
					);

					debug!(
						"init: rewinding and validating before we start... {} at {}",
						header.hash(context_id)?,
						header.height,
					);
					Ok(())
				});

				match res {
					Ok(()) => {
						info!(
							"setup_head: PMMR backend synchronization finished at height {}",
							header.height
						);
						let output_mmr_size_after = txhashset.output_mmr_size();
						let kernel_mmr_size_after = txhashset.kernel_mmr_size();
						let output_mmr_rewound = output_mmr_size_before > output_mmr_size_after;
						let kernel_mmr_rewound = kernel_mmr_size_before > kernel_mmr_size_after;
						if output_mmr_rewound {
							debug!(
								"init: output PMMR rewound from {} to {}; marking output_pos index incomplete",
								output_mmr_size_before, output_mmr_size_after
							);
							batch.set_output_pos_index_complete(false)?;
						}
						if kernel_mmr_rewound {
							debug!(
								"init: kernel PMMR rewound from {} to {}; marking kernel_pos index incomplete",
								kernel_mmr_size_before, kernel_mmr_size_after
							);
							batch.set_kernel_pos_index_complete(false)?;
						}
					}
					Err(e) => {
						if matches!(
							&e,
							Error::PMMRErr(mwc_core::core::pmmr::Error::DataCorruption(_))
						) {
							// The durable HEAD is operator-visible chain state. Do not
							// silently select its parent and delete the corresponding block
							// merely because local PMMR validation failed. The extension has
							// already discarded its tentative changes; return the original
							// corruption error and leave HEAD untouched so the operator can
							// investigate and explicitly clean or reset the node data.
							error!(
								"PMMR corruption while validating durable HEAD {} at height {}: {}. Automatic block rollback is disabled; inspect the chain data and explicitly clean or reset it before restarting",
								head.last_block_h, head.height, e
							);
						}
						return Err(e);
					}
				}
			}
		}
		Err(NotFoundErr(_)) => {
			// Normal startup reaches this branch only after
			// ensure_missing_head_is_fresh() proved that no prior chain state exists.
			// A missing HEAD in a used store is reported above instead of being
			// converted into an implicit reset. Explicit PIBD/reset callers supply an
			// override and intentionally retain their existing behavior.
			// Save the genesis header with a "zero" header_root.
			// We will update this later once we have the correct header_root.
			// Keep every derived index explicitly non-authoritative until the
			// post-setup initialization below has rebuilt and verified it.
			batch.set_output_pos_index_complete(false)?;
			batch.set_kernel_pos_index_complete(false)?;
			batch.set_spent_commitment_record_index_complete(false)?;
			save_genesis_block_metadata(genesis, &genesis_hash, &batch, secp, context_id)?;
			batch.save_body_head(&Tip::try_from_header(&genesis.header)?)?;

			txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
				ext.extension.reset_prune_lists()?;
				ext.extension
					.rebuild_genesis(genesis, ext.header_extension, batch)?;
				ext.extension.validate_roots(&genesis.header)?;
				ext.extension.validate_sizes(&genesis.header)?;
				Ok(())
			})?;

			info!("init: saved genesis: {}", genesis_hash);
		}
		Err(e) => return Err(Error::StoreErr(e, "chain init load head".to_owned())),
	};
	batch.commit()?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tests::chain_test_helper::{clean_output_dir, genesis_block, mine_chain};
	use crate::types::SpentOutput;
	use mwc_core::core::pmmr::Backend;
	use mwc_core::core::{CommitWrapper, Input, OutputFeatures};
	use mwc_core::libtx::{aggsig, proof::ProofBuilder, reward as reward_builder};
	use mwc_core::ser::PMMRIndexHashable;
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::secp::constants::MAX_PROOF_SIZE;
	use mwc_crates::secp::SecretKey;
	use mwc_keychain::{ExtKeychain, Keychain};
	use std::fs::OpenOptions;
	use std::io::{Seek, SeekFrom, Write};

	fn reject_pow(_: u32, _: &BlockHeader) -> Result<(), pow::Error> {
		Err(pow::Error::Verification(
			"forced genesis PoW failure".into(),
		))
	}

	fn reject_non_genesis_pow(_: u32, header: &BlockHeader) -> Result<(), pow::Error> {
		if header.height == 0 {
			Ok(())
		} else {
			Err(pow::Error::Verification(
				"forced non-genesis PoW failure".into(),
			))
		}
	}

	fn test_output_identifier() -> OutputIdentifier {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(1).unwrap();
		OutputIdentifier::new(OutputFeatures::Plain, &commit)
	}

	fn test_rangeproof() -> RangeProof {
		RangeProof {
			plen: 0,
			proof: [0; MAX_PROOF_SIZE],
		}
	}

	fn test_input(features: OutputFeatures) -> Input {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(1).unwrap();
		Input::new(features, commit)
	}

	#[derive(Default)]
	struct RecordingAdapter {
		accepted: RwLock<Vec<(Hash, BlockStatus)>>,
		rejected: RwLock<Vec<(Hash, HashSet<String>)>>,
	}

	impl ChainAdapter for RecordingAdapter {
		fn block_accepted(
			&self,
			_secp: &mut Secp256k1,
			block: &Block,
			status: BlockStatus,
			_opts: Options,
		) {
			let context_id = block.header.pow.proof.context_id;
			self.accepted
				.write()
				.push((block.hash(context_id).unwrap(), status));
		}

		fn block_rejected(&self, hash: &Hash, source_peers: &HashSet<String>, _err: &Error) {
			self.rejected
				.write()
				.push((hash.clone(), source_peers.clone()));
		}
	}

	fn init_chain_with_recording_adapter(
		chain_dir: &str,
		secp: &Secp256k1,
		genesis: Block,
		adapter: Arc<RecordingAdapter>,
	) -> Chain {
		Chain::init(
			secp,
			0,
			chain_dir.to_owned(),
			adapter,
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap()
	}

	#[test]
	fn startup_validates_persisted_pow_unless_explicitly_skipped() {
		let chain_dir = format!("target/startup_pow_validation_{}", std::process::id());
		clean_output_dir(&chain_dir);
		let chain = mine_chain(&chain_dir, 2);
		let genesis = chain.genesis.clone();
		let expected_head = chain.head().unwrap();
		drop(chain);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let err = match Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis.clone(),
			reject_non_genesis_pow,
			false,
			HashSet::new(),
			None,
			None,
			false,
		) {
			Ok(_) => panic!("startup accepted persisted PoW rejected by its verifier"),
			Err(err) => err,
		};
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("persisted header at height 1 failed PoW validation")
		));

		let restarted = Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis,
			reject_non_genesis_pow,
			false,
			HashSet::new(),
			None,
			None,
			true,
		)
		.unwrap();
		assert_eq!(restarted.head().unwrap(), expected_head);

		drop(restarted);
		clean_output_dir(&chain_dir);
	}

	fn assert_committed_recovery_failure(err: &Error, expected_context: &str) {
		assert!(!err.is_bad_data(), "{:?}", err);
		assert!(err.requires_chain_recovery(), "{:?}", err);
		assert!(matches!(
			err,
			Error::CommittedRecoveryFailed { context, source }
				if context == expected_context && matches!(source.as_ref(), Error::InvalidRoot(_))
		));
	}

	#[test]
	fn output_read_snapshot_holds_chain_state_and_returns_matching_proof() {
		let chain_dir = format!("target/output_read_snapshot_{}", std::process::id());
		clean_output_dir(&chain_dir);
		let chain = mine_chain(&chain_dir, 1);

		let result: Result<(), Error> = chain.with_output_read_snapshot(|snapshot| {
			assert!(chain.header_pmmr.try_write().is_none());
			assert!(chain.txhashset.try_write().is_none());

			let header = snapshot.get_header_by_height(0)?;
			let header_hash = header.hash(snapshot.get_context_id())?;
			assert_eq!(snapshot.get_block_header(&header_hash)?, header);
			let block = snapshot.get_block_for_header(&header)?;
			let output = block.outputs().first().expect("genesis output");
			let (last_index, highest_index, outputs) =
				snapshot.unspent_outputs_by_pmmr_index(1, 10_000, None)?;
			assert_eq!(last_index, header.output_mmr_size);
			assert_eq!(highest_index, header.output_mmr_size);
			assert!(outputs.contains(output));
			let (stored_output, stored_pos) = snapshot
				.get_unspent_output_position(output.commitment())?
				.expect("unspent genesis output position");
			assert!(ser::hashes_equal(
				snapshot.get_context_id(),
				&stored_output,
				&output.identifier()
			)?);
			let (legacy_pos0, legacy_proof) =
				snapshot.get_output_pos_and_merkle_proof(output.commitment())?;
			assert_eq!(
				legacy_pos0,
				stored_pos.pos.checked_sub(1).expect("one-based position")
			);
			assert_eq!(legacy_proof.mmr_size, header.output_mmr_size);
			let (pos, proof) = snapshot.get_output_status(&output.identifier(), true)?;
			let pos0 = pos
				.expect("unspent genesis output")
				.pos
				.checked_sub(1)
				.expect("one-based output position");
			let proof = proof.expect("coinbase merkle proof");
			assert_eq!(proof.mmr_size, header.output_mmr_size);
			proof
				.verify(
					snapshot.get_context_id(),
					header.output_root,
					&output.identifier(),
					pos0,
				)
				.unwrap();
			Ok(())
		});
		result.unwrap();

		drop(chain);
		clean_output_dir(&chain_dir);
	}

	#[test]
	fn output_read_snapshot_uses_held_batch_for_output_position() {
		let chain_dir = format!(
			"target/output_read_snapshot_position_batch_{}",
			std::process::id()
		);
		clean_output_dir(&chain_dir);
		let chain = mine_chain(&chain_dir, 1);
		let commit = chain.genesis.outputs()[0].commitment();
		let expected_pos = chain
			.store
			.get_output_pos_height(&commit)
			.unwrap()
			.expect("genesis output position");

		let writer_store = chain.store.clone();
		let result: Result<(), Error> = chain.with_output_read_snapshot(|snapshot| {
			// Model a cache-only repair committing after this snapshot's LMDB read
			// transaction began. PMMR read locks intentionally do not block it.
			let writer_store = writer_store.clone();
			std::thread::spawn(move || {
				let batch = writer_store.batch_write().unwrap();
				batch
					.save_output_pos_height(
						&commit,
						CommitPos {
							pos: 0,
							height: expected_pos.height,
						},
					)
					.unwrap();
				batch.commit().unwrap();
			})
			.join()
			.unwrap();

			let (_, observed_pos) = snapshot
				.get_unspent_output_position(commit)?
				.expect("snapshot retains its original output position");
			assert_eq!(observed_pos, expected_pos);
			Ok(())
		});

		// Restore the cache so normal Chain teardown sees a valid index even if
		// the assertion above failed by returning an error.
		let batch = chain.store.batch_write().unwrap();
		batch.save_output_pos_height(&commit, expected_pos).unwrap();
		batch.commit().unwrap();
		result.unwrap();

		drop(chain);
		clean_output_dir(&chain_dir);
	}

	#[test]
	fn output_read_snapshot_rejects_header_pmmr_hash_data_split() {
		let chain_dir = format!(
			"target/output_read_snapshot_header_split_{}",
			std::process::id()
		);
		let corrupt_header_dir = format!("{}_corrupt_header", chain_dir);
		clean_output_dir(&chain_dir);
		let _ = fs::remove_dir_all(&corrupt_header_dir);
		let chain = mine_chain(&chain_dir, 1);

		let canonical = chain.genesis.header.clone();
		let redirected = retained_test_block(0, canonical.prev_hash, 1).header;
		let redirected_hash = redirected.hash(0).unwrap();
		assert_ne!(redirected_hash, canonical.hash(0).unwrap());
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_block_header(&redirected).unwrap();
			batch.commit().unwrap();
		}

		// The data file redirects height zero to `redirected`, while the hash
		// file retains the indexed leaf hash for the canonical header.
		let mut corrupt_header_pmmr = recovery_header_pmmr(&corrupt_header_dir);
		let canonical_leaf_hash = canonical.hash_with_index(0, 0).unwrap();
		corrupt_header_pmmr
			.backend
			.append(&redirected, &[canonical_leaf_hash])
			.unwrap();
		corrupt_header_pmmr.backend.sync().unwrap();
		corrupt_header_pmmr.size = 1;
		assert_eq!(
			corrupt_header_pmmr.get_header_hash_by_height(0).unwrap(),
			redirected_hash
		);

		let txhashset = chain.txhashset.read();
		let batch = chain.store.batch_read().unwrap();
		let snapshot = OutputReadSnapshot {
			chain: &chain,
			header_pmmr: &corrupt_header_pmmr,
			txhashset: &txhashset,
			batch,
		};
		let err = snapshot.get_header_by_height(0).unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("does not authenticate loaded header")
		));

		drop(snapshot);
		drop(txhashset);
		drop(corrupt_header_pmmr);
		drop(chain);
		clean_output_dir(&chain_dir);
		let _ = fs::remove_dir_all(&corrupt_header_dir);
	}

	#[test]
	fn get_block_for_header_rejects_same_hash_header_mismatch() {
		let chain_dir = format!("target/get_block_for_header_{}", std::process::id());
		clean_output_dir(&chain_dir);
		let chain = mine_chain(&chain_dir, 1);

		let original = chain.get_header_by_height(0).unwrap();
		let mut altered = original.clone();
		altered.prev_root = Hash::from_vec(&[42; Hash::LEN]);
		assert_ne!(altered, original);
		assert_eq!(altered.hash(0).unwrap(), original.hash(0).unwrap());

		let err = chain.get_block_for_header(&altered).unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("does not exactly match the requested header")
		));

		drop(chain);
		clean_output_dir(&chain_dir);
	}

	#[test]
	fn get_block_for_header_rejects_block_without_stored_header() {
		let chain_dir = format!(
			"target/get_block_for_header_missing_header_{}",
			std::process::id()
		);
		clean_output_dir(&chain_dir);
		let chain = mine_chain(&chain_dir, 1);

		let header = chain.head_header().unwrap();
		let hash = header.hash(chain.get_context_id()).unwrap();
		assert!(chain.store.get_block(&hash).is_ok());
		{
			let batch = chain.store.batch_write().unwrap();
			batch.delete_block_header(&hash).unwrap();
			batch.commit().unwrap();
		}
		assert!(chain.store.get_block(&hash).is_ok());

		let err = chain.get_block_for_header(&header).unwrap_err();
		assert!(matches!(
			err,
			Error::StoreErr(NotFoundErr(_), context)
				if context.contains("chain get block for header load header")
		));

		drop(chain);
		clean_output_dir(&chain_dir);
	}

	#[test]
	fn single_block_marker_clear_failure_preserves_acceptance() {
		let source_dir = format!(
			"target/single_block_marker_clear_source_{}",
			std::process::id()
		);
		let target_dir = format!(
			"target/single_block_marker_clear_target_{}",
			std::process::id()
		);
		clean_output_dir(&source_dir);
		clean_output_dir(&target_dir);

		let source = mine_chain(&source_dir, 2);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let header = source.get_header_by_height(1).unwrap();
		let block_hash = header.hash(0).unwrap();
		let block = source.get_block_for_header(&header).unwrap();
		let adapter = Arc::new(RecordingAdapter::default());
		let chain = init_chain_with_recording_adapter(
			&target_dir,
			&secp,
			source.genesis.clone(),
			adapter.clone(),
		);

		chain
			.fail_next_process_block_marker_clear
			.store(true, Ordering::SeqCst);
		let tip = chain
			.process_block(&mut secp, block.clone(), Options::SKIP_POW, HashSet::new())
			.unwrap()
			.unwrap();

		assert_eq!(tip.height, 1);
		assert_eq!(tip.last_block_h, block_hash);
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		let accepted = adapter.accepted.read_recursive();
		assert_eq!(accepted.len(), 1);
		assert_eq!(accepted[0].0, block_hash);
		assert!(accepted[0].1.is_next());
		drop(accepted);

		let retry = chain.process_block(&mut secp, block, Options::SKIP_POW, HashSet::new());
		assert!(matches!(retry, Err(ref e) if e.is_known_block()));
		assert_eq!(adapter.accepted.read_recursive().len(), 1);

		drop(chain);
		drop(source);
		clean_output_dir(&target_dir);
		clean_output_dir(&source_dir);
	}

	#[test]
	fn old_known_block_does_not_reject_source_peer() {
		let chain_dir = format!(
			"target/old_known_block_no_peer_rejection_{}",
			std::process::id()
		);
		clean_output_dir(&chain_dir);

		// A height-1 block is classified as OldBlock once the head reaches 52.
		let source = mine_chain(&chain_dir, 53);
		let genesis = source.genesis.clone();
		let old_header = source.get_header_by_height(1).unwrap();
		let old_block = source.get_block_for_header(&old_header).unwrap();
		assert_eq!(source.head().unwrap().height, 52);
		drop(source);

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let adapter = Arc::new(RecordingAdapter::default());
		let chain = init_chain_with_recording_adapter(&chain_dir, &secp, genesis, adapter.clone());
		let err = chain
			.process_block(
				&mut secp,
				old_block,
				Options::SKIP_POW,
				std::iter::once("honest-source-peer".to_owned()).collect(),
			)
			.unwrap_err();

		assert!(matches!(err, Error::OldBlock));
		assert!(err.is_bad_data());
		assert!(err.is_known_block());
		assert!(adapter.rejected.read_recursive().is_empty());

		drop(chain);
		clean_output_dir(&chain_dir);
	}

	#[test]
	fn known_block_with_valid_alternate_kernel_signature_rejects_source_peer() {
		let chain_dir = format!(
			"target/known_block_alternate_signature_{}",
			std::process::id()
		);
		clean_output_dir(&chain_dir);
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let genesis = genesis_block(&mut secp, &keychain);
		let adapter = Arc::new(RecordingAdapter::default());
		let chain = init_chain_with_recording_adapter(&chain_dir, &secp, genesis, adapter.clone());

		let prev = chain.head_header().unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
		let reward = reward_builder::output(
			0,
			&keychain,
			&ProofBuilder::new(&secp, &keychain).unwrap(),
			&key_id,
			0,
			false,
			1,
			&mut secp,
		)
		.unwrap();
		let mut stored = Block::new(
			0,
			&prev,
			&[],
			mwc_core::pow::Difficulty::min(),
			reward,
			&secp,
		)
		.unwrap();
		stored.header.timestamp = prev.timestamp + mwc_crates::chrono::Duration::seconds(60);
		chain.set_txhashset_roots(&secp, &mut stored).unwrap();
		let block_hash = stored.hash(0).unwrap();
		chain
			.process_block(&mut secp, stored.clone(), Options::SKIP_POW, HashSet::new())
			.unwrap();

		// Re-sign the same valid coinbase kernel with a different nonce. Internal
		// block cryptography still validates, but the new signature changes the
		// kernel MMR leaf and therefore cannot match the stored header root.
		let mut candidate = stored.clone();
		let kernel = candidate
			.body
			.kernels
			.first_mut()
			.expect("reward block has one kernel");
		let original_signature = kernel.excess_sig;
		let message = kernel.msg_to_sign(0).unwrap();
		let public_key = kernel.excess.to_pubkey(&secp).unwrap();
		let alternate_nonce = SecretKey::from_slice(&secp, &[2; 32]).unwrap();
		kernel.excess_sig = aggsig::sign_from_key_id(
			&secp,
			&keychain,
			&message,
			consensus::reward(0, 0, 1).unwrap(),
			&key_id,
			Some(&alternate_nonce),
			&public_key,
		)
		.unwrap();
		assert_ne!(kernel.excess_sig, original_signature);
		kernel.verify(0, &secp).unwrap();
		candidate
			.validate(0, &prev.total_kernel_offset, &mut secp)
			.unwrap();
		assert_eq!(candidate.hash(0).unwrap(), block_hash);

		let source_peers: HashSet<_> =
			std::iter::once("alternate-signature-peer".to_owned()).collect();
		let err = chain
			.process_block(
				&mut secp,
				candidate,
				Options::SKIP_POW,
				source_peers.clone(),
			)
			.unwrap_err();
		assert!(
			matches!(&err, Error::InvalidRoot(msg) if msg.contains("header-committed body conflicts")),
			"{:?}",
			err
		);
		assert!(err.is_bad_data());
		assert!(!err.is_known_block());

		let rejected = adapter.rejected.read_recursive();
		assert_eq!(rejected.as_slice(), &[(block_hash, source_peers)]);
		drop(rejected);

		drop(chain);
		clean_output_dir(&chain_dir);
	}

	#[test]
	fn committed_single_block_recovery_failure_stays_non_bad_data() {
		let source_dir = format!(
			"target/committed_single_recovery_source_{}",
			std::process::id()
		);
		let target_dir = format!(
			"target/committed_single_recovery_target_{}",
			std::process::id()
		);
		clean_output_dir(&source_dir);
		clean_output_dir(&target_dir);

		let source = mine_chain(&source_dir, 2);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let header = source.get_header_by_height(1).unwrap();
		let block_hash = header.hash(0).unwrap();
		let block = source.get_block_for_header(&header).unwrap();
		let adapter = Arc::new(RecordingAdapter::default());
		let chain = init_chain_with_recording_adapter(
			&target_dir,
			&secp,
			source.genesis.clone(),
			adapter.clone(),
		);

		chain
			.fail_next_process_block_marker_clear
			.store(true, Ordering::SeqCst);
		chain
			.fail_next_committed_recovery_with_bad_data
			.store(true, Ordering::SeqCst);
		let err = chain
			.process_block(
				&mut secp,
				block,
				Options::SKIP_POW,
				std::iter::once("single-source-peer".to_owned()).collect(),
			)
			.unwrap_err();

		assert_committed_recovery_failure(&err, "process_block_single committed marker cleanup");
		assert_eq!(chain.store.head().unwrap().last_block_h, block_hash);
		assert!(chain.store.pending_chain_operation().unwrap().is_some());
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(adapter.accepted.read_recursive().is_empty());
		assert!(adapter.rejected.read_recursive().is_empty());

		chain.ensure_chain_robust().unwrap();
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		drop(source);
		clean_output_dir(&target_dir);
		clean_output_dir(&source_dir);
	}

	#[test]
	fn committed_header_recovery_failure_does_not_reject_source_peer() {
		let source_dir = format!(
			"target/committed_header_recovery_source_{}",
			std::process::id()
		);
		let target_dir = format!(
			"target/committed_header_recovery_target_{}",
			std::process::id()
		);
		clean_output_dir(&source_dir);
		clean_output_dir(&target_dir);

		let source = mine_chain(&source_dir, 2);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let header = source.get_header_by_height(1).unwrap();
		let block_hash = header.hash(0).unwrap();
		let block = source.get_block_for_header(&header).unwrap();
		let adapter = Arc::new(RecordingAdapter::default());
		let chain = init_chain_with_recording_adapter(
			&target_dir,
			&secp,
			source.genesis.clone(),
			adapter.clone(),
		);

		chain
			.fail_next_process_block_header_marker_clear
			.store(true, Ordering::SeqCst);
		chain
			.fail_next_committed_recovery_with_bad_data
			.store(true, Ordering::SeqCst);
		let err = chain
			.process_block(
				&mut secp,
				block,
				Options::SKIP_POW,
				std::iter::once("header-source-peer".to_owned()).collect(),
			)
			.unwrap_err();

		assert_committed_recovery_failure(&err, "process_block_header committed marker cleanup");
		assert_eq!(chain.store.header_head().unwrap().last_block_h, block_hash);
		assert_eq!(chain.store.head().unwrap().height, 0);
		assert!(chain.store.pending_chain_operation().unwrap().is_some());
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(adapter.accepted.read_recursive().is_empty());
		assert!(adapter.rejected.read_recursive().is_empty());

		chain.ensure_chain_robust().unwrap();
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		drop(source);
		clean_output_dir(&target_dir);
		clean_output_dir(&source_dir);
	}

	#[test]
	fn orphan_header_committed_recovery_failure_is_propagated() {
		let source_dir = format!(
			"target/orphan_header_recovery_source_{}",
			std::process::id()
		);
		let target_dir = format!(
			"target/orphan_header_recovery_target_{}",
			std::process::id()
		);
		clean_output_dir(&source_dir);
		clean_output_dir(&target_dir);

		let source = mine_chain(&source_dir, 3);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let header_one = source.get_header_by_height(1).unwrap();
		let header_two = source.get_header_by_height(2).unwrap();
		let block_one = source.get_block_for_header(&header_one).unwrap();
		let block_two = source.get_block_for_header(&header_two).unwrap();
		let block_two_hash = block_two.hash(0).unwrap();
		let adapter = Arc::new(RecordingAdapter::default());
		let chain = init_chain_with_recording_adapter(
			&target_dir,
			&secp,
			source.genesis.clone(),
			adapter.clone(),
		);

		// Cache block two while its full parent is unavailable. Its header is
		// already known, as required by the orphan admission path.
		chain
			.process_block_header(&header_one, Options::SKIP_POW)
			.unwrap();
		chain
			.process_block_header(&header_two, Options::SKIP_POW)
			.unwrap();
		let orphan_result = chain.process_block(
			&mut secp,
			block_two,
			Options::SKIP_POW,
			std::iter::once("orphan-source-peer".to_owned()).collect(),
		);
		assert!(matches!(orphan_result, Err(Error::Orphan(_))));
		assert!(chain.is_orphan(&block_two_hash));

		// Rewind the header chain, then restore only header one. Retrying the
		// orphan must now reapply and commit header two.
		chain
			.reset_chain_head(&secp, &source.genesis.header, true)
			.unwrap();
		chain
			.process_block_header(&header_one, Options::SKIP_POW)
			.unwrap();

		chain
			.fail_next_process_block_header_marker_clear
			.store(true, Ordering::SeqCst);
		chain
			.fail_next_committed_recovery_with_bad_data
			.store(true, Ordering::SeqCst);
		let err = chain
			.process_block(&mut secp, block_one, Options::SKIP_POW, HashSet::new())
			.unwrap_err();

		assert_committed_recovery_failure(&err, "process_block_header committed marker cleanup");
		assert_eq!(chain.store.head().unwrap().height, 1);
		assert_eq!(
			chain.store.header_head().unwrap().last_block_h,
			block_two_hash
		);
		assert!(chain.store.pending_chain_operation().unwrap().is_some());
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(!chain.is_orphan(&block_two_hash));
		assert_eq!(adapter.accepted.read_recursive().len(), 1);
		assert!(adapter.rejected.read_recursive().is_empty());

		chain.ensure_chain_robust().unwrap();
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		drop(source);
		clean_output_dir(&target_dir);
		clean_output_dir(&source_dir);
	}

	#[test]
	fn block_batch_marker_clear_failure_notifies_and_cleans_orphans() {
		let source_dir = format!(
			"target/block_batch_marker_clear_source_{}",
			std::process::id()
		);
		let target_dir = format!(
			"target/block_batch_marker_clear_target_{}",
			std::process::id()
		);
		clean_output_dir(&source_dir);
		clean_output_dir(&target_dir);

		let source = mine_chain(&source_dir, 4);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut source_blocks = Vec::new();
		for height in 1..=3 {
			let header = source.get_header_by_height(height).unwrap();
			source_blocks.push(source.get_block_for_header(&header).unwrap());
		}
		let block_one = source_blocks[0].clone();
		let block_two = source_blocks[1].clone();
		let block_one_hash = block_one.hash(0).unwrap();
		let block_two_hash = block_two.hash(0).unwrap();

		let adapter = Arc::new(RecordingAdapter::default());
		let chain = init_chain_with_recording_adapter(
			&target_dir,
			&secp,
			source.genesis.clone(),
			adapter.clone(),
		);
		for block in &source_blocks {
			chain
				.process_block_header(&block.header, Options::SKIP_POW)
				.unwrap();
		}

		let orphan_result = chain.process_block(
			&mut secp,
			block_two.clone(),
			Options::SKIP_POW,
			HashSet::new(),
		);
		assert!(matches!(orphan_result, Err(Error::Orphan(_))));
		assert!(chain.is_orphan(&block_two_hash));
		assert!(!chain.store.block_exists(&block_two_hash).unwrap());
		assert!(chain
			.store
			.batch_read()
			.unwrap()
			.get_spent_index(&block_two_hash)
			.is_err());

		// Exercise the production batch branch with a short chain. The production
		// default remains 100; only this Chain instance uses a zero-depth guard.
		chain
			.process_block_batch_safety_depth
			.store(0, Ordering::SeqCst);
		chain
			.fail_next_process_block_marker_clear
			.store(true, Ordering::SeqCst);
		let tip = chain
			.process_block(
				&mut secp,
				block_one.clone(),
				Options::SKIP_POW,
				HashSet::new(),
			)
			.unwrap()
			.unwrap();

		assert_eq!(tip.height, 2);
		assert_eq!(tip.last_block_h, block_two_hash);
		assert!(!chain.is_orphan(&block_two_hash));
		assert!(chain.store.block_exists(&block_two_hash).unwrap());
		assert!(chain
			.store
			.batch_read()
			.unwrap()
			.get_spent_index(&block_two_hash)
			.is_ok());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		let accepted = adapter.accepted.read_recursive();
		assert_eq!(accepted.len(), 2);
		assert_eq!(accepted[0].0, block_one_hash);
		assert_eq!(accepted[1].0, block_two_hash);
		assert!(accepted.iter().all(|(_, status)| status.is_next()));
		drop(accepted);

		let retry = chain.process_block(&mut secp, block_one, Options::SKIP_POW, HashSet::new());
		assert!(matches!(retry, Err(ref e) if e.is_known_block()));
		assert_eq!(adapter.accepted.read_recursive().len(), 2);

		drop(chain);
		drop(source);
		clean_output_dir(&target_dir);
		clean_output_dir(&source_dir);
	}

	#[test]
	fn committed_block_batch_recovery_failure_stays_non_bad_data() {
		let source_dir = format!(
			"target/committed_batch_recovery_source_{}",
			std::process::id()
		);
		let target_dir = format!(
			"target/committed_batch_recovery_target_{}",
			std::process::id()
		);
		clean_output_dir(&source_dir);
		clean_output_dir(&target_dir);

		let source = mine_chain(&source_dir, 4);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut source_blocks = Vec::new();
		for height in 1..=3 {
			let header = source.get_header_by_height(height).unwrap();
			source_blocks.push(source.get_block_for_header(&header).unwrap());
		}
		let block_one = source_blocks[0].clone();
		let block_two = source_blocks[1].clone();
		let block_two_hash = block_two.hash(0).unwrap();

		let adapter = Arc::new(RecordingAdapter::default());
		let chain = init_chain_with_recording_adapter(
			&target_dir,
			&secp,
			source.genesis.clone(),
			adapter.clone(),
		);
		for block in &source_blocks {
			chain
				.process_block_header(&block.header, Options::SKIP_POW)
				.unwrap();
		}

		let orphan_result =
			chain.process_block(&mut secp, block_two, Options::SKIP_POW, HashSet::new());
		assert!(matches!(orphan_result, Err(Error::Orphan(_))));

		chain
			.process_block_batch_safety_depth
			.store(0, Ordering::SeqCst);
		chain
			.fail_next_process_block_marker_clear
			.store(true, Ordering::SeqCst);
		chain
			.fail_next_committed_recovery_with_bad_data
			.store(true, Ordering::SeqCst);
		let err = chain
			.process_block(
				&mut secp,
				block_one,
				Options::SKIP_POW,
				std::iter::once("batch-source-peer".to_owned()).collect(),
			)
			.unwrap_err();

		assert_committed_recovery_failure(&err, "process_block_multiple committed marker cleanup");
		assert_eq!(chain.store.head().unwrap().last_block_h, block_two_hash);
		assert!(chain.store.pending_chain_operation().unwrap().is_some());
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(adapter.accepted.read_recursive().is_empty());
		assert!(adapter.rejected.read_recursive().is_empty());

		chain.ensure_chain_robust().unwrap();
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		drop(source);
		clean_output_dir(&target_dir);
		clean_output_dir(&source_dir);
	}

	#[test]
	fn block_comparisons_keep_untrusted_features_but_normalize_known_blocks() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let mut plain = Block::default(0);
		plain.body.inputs = Inputs::FeaturesAndCommit(vec![test_input(OutputFeatures::Plain)]);

		let mut coinbase = plain.clone();
		coinbase.body.inputs =
			Inputs::FeaturesAndCommit(vec![test_input(OutputFeatures::Coinbase)]);

		// Protocol v3+ full-data serialization normalizes both inputs to the
		// same commit-only representation, despite their different features.
		assert_eq!(
			ser::ser_vec(0, &plain, ProtocolVersion::local()).unwrap(),
			ser::ser_vec(0, &coinbase, ProtocolVersion::local()).unwrap()
		);
		assert!(blocks_equal_as_v3(0, &plain, &coinbase).unwrap());

		let mut commit_only = plain.clone();
		commit_only.body.inputs = Inputs::CommitOnly(vec![CommitWrapper::from(
			test_input(OutputFeatures::Plain).commitment(),
		)]);
		assert_eq!(
			ser::ser_vec(0, &plain, ProtocolVersion::local()).unwrap(),
			ser::ser_vec(0, &commit_only, ProtocolVersion::local()).unwrap()
		);
		assert!(blocks_equal_as_v3(0, &plain, &commit_only).unwrap());

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut different_commit = commit_only.clone();
		different_commit.body.inputs =
			Inputs::CommitOnly(vec![CommitWrapper::from(secp.commit_value(2).unwrap())]);
		assert!(!blocks_equal_as_v3(0, &commit_only, &different_commit).unwrap());

		let mut first_proof = test_rangeproof();
		first_proof.plen = 1;
		first_proof.proof[0] = 1;
		let mut second_proof = first_proof;
		second_proof.proof[0] = 2;
		let mut first_output = Block::default(0);
		first_output.body.outputs.push(Output {
			identifier: test_output_identifier(),
			proof: first_proof,
		});
		let mut second_output = first_output.clone();
		second_output.body.outputs[0].proof = second_proof;
		assert!(!blocks_equal_as_v3(0, &first_output, &second_output).unwrap());

		let mut different_header = plain.clone();
		different_header.header.height = different_header.header.height.saturating_add(1);
		assert_eq!(different_header.hash(0).unwrap(), plain.hash(0).unwrap());
		assert!(!blocks_equal_as_v3(0, &plain, &different_header).unwrap());
	}

	#[test]
	fn exact_known_header_readonly_check_is_collision_and_work_safe() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = format!(
			"target/exact_known_header_readonly_check_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();

		let mut header = BlockHeader::default(0);
		header.pow.total_difficulty = mwc_core::pow::Difficulty::from_num(10);
		let mut header_head = Tip::try_from_header(&header).unwrap();
		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&header).unwrap();
			batch.save_header_head(&header_head).unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			assert!(pipe::is_exact_known_header(0, &header, &header_head, &batch).unwrap());

			let mut collision = header.clone();
			collision.height = collision.height.saturating_add(1);
			assert_eq!(collision.hash(0).unwrap(), header.hash(0).unwrap());
			assert!(matches!(
				pipe::is_exact_known_header(0, &collision, &header_head, &batch),
				Err(Error::Block(mwc_core::core::block::Error::Other(ref msg)))
					if msg == "known header hash matches a different header"
			));
		}

		// A stored header above the current header head must go through the
		// locked pipeline so it can be reapplied after a reset.
		header_head.total_difficulty = mwc_core::pow::Difficulty::from_num(9);
		{
			let batch = store.batch_read().unwrap();
			assert!(!pipe::is_exact_known_header(0, &header, &header_head, &batch).unwrap());
		}

		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn denylisted_known_header_fast_paths_return_invalid_hash() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/denylisted_known_header_fast_paths_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let context_id = chain.get_context_id();

		// Persist a full block under a distinct proof-derived hash without making
		// it current. Both the read-only Chain shortcut and pipe's known-store
		// shortcut would previously accept this exact header without consulting
		// the denylist.
		let genesis_header = chain.genesis();
		let genesis_hash = genesis_header.hash(context_id).unwrap();
		let mut known_block = chain.get_block_for_header(&genesis_header).unwrap();
		let last_nonce = known_block
			.header
			.pow
			.proof
			.nonces
			.last_mut()
			.expect("automated-test genesis proof has at least one nonce");
		*last_nonce = (*last_nonce).wrapping_add(1);
		let known_hash = known_block.hash(context_id).unwrap();
		assert_ne!(known_hash, genesis_hash);
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_block_header(&known_block.header).unwrap();
			batch.save_block(&known_block).unwrap();
			batch.commit().unwrap();
		}

		let mut denied = HashSet::new();
		denied.insert(known_hash);
		pipe::init_invalid_block_hashes(context_id, denied);

		let chain_err = chain
			.process_block_header(&known_block.header, Options::SKIP_POW)
			.unwrap_err();
		assert!(matches!(chain_err, Error::InvalidHash));
		assert!(chain_err.is_bad_data());

		let pipe_err = {
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			let batch = chain.store.batch_write().unwrap();
			let mut ctx = chain
				.new_ctx(Options::SKIP_POW, batch, &mut header_pmmr, &mut txhashset)
				.unwrap();
			let mut state_may_have_changed = false;
			let err = pipe::process_block_header(
				context_id,
				&known_block.header,
				&mut ctx,
				&mut state_may_have_changed,
			)
			.unwrap_err();
			assert!(!state_may_have_changed);
			err
		};
		assert!(matches!(pipe_err, Error::InvalidHash));

		pipe::release_context_data(context_id);
		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn pending_chain_operation_guard_marks_recovery_during_unwind() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/pending_chain_operation_unwind_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::SyncHeaders)
			.unwrap();

		let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			let _header_pmmr = chain.header_pmmr.write();
			let _txhashset = chain.txhashset.write();
			let _marker_guard = chain.set_pending_chain_operation_checked(&op).unwrap();
			panic!("forced unwind after installing pending-operation marker");
		}));

		assert!(result.is_err());
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert_eq!(chain.store.pending_chain_operation().unwrap(), Some(op));

		chain.ensure_chain_robust().unwrap();
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn unreadable_readonly_pmmr_marker_latches_recovery() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/unreadable_readonly_pmmr_marker_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);

		// Corrupt the durable marker version so reading PendingChainOperation fails.
		let batch = chain.store.batch_write().unwrap();
		batch
			.db
			.put(&mwc_store::to_key(b'O', "last_chain_operation"), &[u8::MAX])
			.unwrap();
		batch.commit().unwrap();

		let mut operation_ran = false;
		{
			let _header_pmmr = chain.header_pmmr.write();
			let _txhashset = chain.txhashset.write();
			let result =
				chain.with_locked_readonly_pmmr_discard_marker("unreadable_marker_test", || {
					operation_ran = true;
					Ok(())
				});
			assert!(result.is_err());
		}

		assert!(!operation_ran);
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(chain.store.pending_chain_operation().is_err());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn existing_marker_aborts_readonly_pmmr_operation() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/existing_readonly_pmmr_marker_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let stale_op =
			prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::SyncHeaders)
				.unwrap();
		chain.store.set_pending_chain_operation(&stale_op).unwrap();

		let mut operation_ran = false;
		{
			let _header_pmmr = chain.header_pmmr.write();
			let _txhashset = chain.txhashset.write();
			let result =
				chain.with_locked_readonly_pmmr_discard_marker("existing_marker_test", || {
					operation_ran = true;
					Ok(())
				});
			assert!(matches!(
				result,
				Err(Error::Other(ref msg))
					if msg == "pending chain operation requires chain init recovery"
			));
		}

		assert!(!operation_ran);
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert_eq!(
			chain.store.pending_chain_operation().unwrap(),
			Some(stale_op)
		);

		chain.ensure_chain_robust().unwrap();
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_segmenter_rechecks_recovery_after_acquiring_pmmr_locks() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_segmenter_rechecks_recovery_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		chain.requires_init_recovery.store(true, Ordering::SeqCst);

		let result = chain.init_segmenter(&chain.genesis());
		if let Err(e) = result {
			panic!("segmenter initialization failed after recovery: {}", e);
		}
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn segmenter_archive_height_uses_header_selected_by_head() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/segmenter_canonical_head_height_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);

		// Put the canonical head exactly on an archive-period transition. Moving
		// only the redundant cached height down by one then selects the preceding
		// archive period if a caller trusts Tip.height directly.
		let head_height =
			u64::from(global::state_sync_threshold(0)) + global::txhashset_archive_interval(0);
		let chain = mine_chain(&chain_dir, head_height + 1);
		let canonical_head = chain.store.head().unwrap();
		assert_eq!(canonical_head.height, head_height);
		let canonical_archive_height = Chain::height_2_archive_height(0, canonical_head.height);

		let mut stale_head = canonical_head;
		stale_head.height = stale_head.height.checked_sub(1).unwrap();
		let stale_archive_height = Chain::height_2_archive_height(0, stale_head.height);
		assert_ne!(stale_archive_height, canonical_archive_height);
		let stale_archive_header = chain.get_header_by_height(stale_archive_height).unwrap();
		let canonical_archive_header = chain
			.get_header_by_height(canonical_archive_height)
			.unwrap();

		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_body_head(&stale_head).unwrap();
			batch.commit().unwrap();
		}
		assert_eq!(chain.head().unwrap(), stale_head);

		let err = match chain.init_segmenter(&stale_archive_header) {
			Ok(_) => panic!("stale archive header unexpectedly initialized a segmenter"),
			Err(err) => err,
		};
		assert!(matches!(
			err,
			Error::ChainInSyncing(ref msg)
				if msg.contains(&format!("current archive height {}", canonical_archive_height))
		));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		// The public selector must also use the canonicalized height so callers
		// propose the candidate that init_segmenter will accept.
		assert_eq!(
			chain.txhashset_archive_header().unwrap(),
			canonical_archive_header
		);
		let segmenter = chain.segmenter().unwrap();
		assert_eq!(segmenter.header(), &canonical_archive_header);
		assert!(segmenter.is_current());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn readonly_pmmr_helper_rejects_latched_recovery() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/readonly_pmmr_helper_rejects_recovery_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		chain.requires_init_recovery.store(true, Ordering::SeqCst);

		let mut operation_ran = false;
		{
			let _header_pmmr = chain.header_pmmr.write();
			let _txhashset = chain.txhashset.write();
			let result =
				chain.with_locked_readonly_pmmr_discard_marker("latched_recovery_test", || {
					operation_ran = true;
					Ok(())
				});
			assert!(matches!(
				result,
				Err(Error::Other(ref msg))
					if msg == "pending chain operation requires chain init recovery"
			));
		}

		assert!(!operation_ran);
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		chain.ensure_chain_robust().unwrap();
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn readonly_pmmr_success_is_rejected_if_recovery_latches_during_operation() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/readonly_pmmr_success_recovery_gate_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);

		let result = {
			let _header_pmmr = chain.header_pmmr.write();
			let _txhashset = chain.txhashset.write();
			chain.with_locked_readonly_pmmr_discard_marker("success_recovery_gate_test", || {
				chain.requires_init_recovery.store(true, Ordering::SeqCst);
				Ok(42_u64)
			})
		};

		assert!(matches!(
			result,
			Err(Error::Other(ref msg))
				if msg == "pending chain operation requires chain init recovery"
		));
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		let marker = chain.store.pending_chain_operation().unwrap().unwrap();
		assert_eq!(marker.kind(), ChainOperationKind::ReadonlyPmmrDiscard);

		chain.ensure_chain_robust().unwrap();
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn recovery_invalidates_cached_and_cloned_segmenters() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/recovery_invalidates_segmenters_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);

		let old_segmenter = chain.segmenter().unwrap();
		assert!(old_segmenter.is_current());
		assert!(old_segmenter.bitmap_root().is_ok());
		let generation_before = chain.pibd_state_generation.load(Ordering::SeqCst);

		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::SyncHeaders)
			.unwrap();
		chain.store.set_pending_chain_operation(&op).unwrap();
		chain.requires_init_recovery.store(true, Ordering::SeqCst);

		assert!(!old_segmenter.is_current());
		assert!(old_segmenter.bitmap_root().is_err());
		chain.ensure_chain_robust().unwrap();
		assert_eq!(
			chain.pibd_state_generation.load(Ordering::SeqCst),
			generation_before + 1
		);
		assert!(!old_segmenter.is_current());
		assert!(old_segmenter.bitmap_root().is_err());

		let fresh_segmenter = chain.segmenter().unwrap();
		assert!(fresh_segmenter.is_current());
		assert!(fresh_segmenter.bitmap_root().is_ok());
		assert!(chain
			.pibd_segmenter
			.read_recursive()
			.as_ref()
			.unwrap()
			.is_current());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn pibd_state_generation_exhaustion_fails_closed() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/pibd_state_generation_exhaustion_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let old_segmenter = chain.segmenter().unwrap();
		assert!(old_segmenter.is_current());

		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::SyncHeaders)
			.unwrap();
		chain.store.set_pending_chain_operation(&op).unwrap();
		chain
			.pibd_state_generation
			.store(u64::MAX, Ordering::SeqCst);
		chain.requires_init_recovery.store(true, Ordering::SeqCst);

		let err = chain.ensure_chain_robust().unwrap_err();
		assert!(matches!(
			err,
			Error::DataOverflow(ref msg) if msg.contains("PIBD state generation exhausted")
		));
		assert_eq!(chain.pibd_state_generation.load(Ordering::SeqCst), u64::MAX);
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert_eq!(chain.store.pending_chain_operation().unwrap(), Some(op));
		assert!(!old_segmenter.is_current());
		assert!(old_segmenter.bitmap_root().is_err());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn rewind_bad_block_skips_detached_denied_child_after_parent_cleanup() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/rewind_bad_block_detached_child_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = mine_chain(&chain_dir, 4);

		let denied_parent = chain.get_header_by_height(2).unwrap();
		let denied_parent_hash = denied_parent.hash(0).unwrap();
		let rewind_target = chain.get_header_by_height(1).unwrap();
		let rewind_target_tip = Tip::try_from_header(&rewind_target).unwrap();
		let detached_child = recovery_test_header(3, denied_parent_hash, 901);
		let detached_child_hash = detached_child.hash(0).unwrap();
		assert_ne!(
			detached_child_hash,
			chain.head_header().unwrap().hash(0).unwrap()
		);

		// Keep an off-chain child of the denied canonical parent. Rewinding the
		// parent removes its canonical header but intentionally does not scan and
		// delete arbitrary off-chain descendants.
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_block_header(&detached_child).unwrap();
			batch
				.save_body_tail(&Tip::try_from_header(&chain.genesis()).unwrap())
				.unwrap();
			batch.commit().unwrap();
		}

		chain
			.rewind_bad_block(&secp, &std::iter::once(denied_parent_hash).collect())
			.unwrap();
		assert_eq!(chain.head().unwrap(), rewind_target_tip);
		assert_eq!(chain.header_head().unwrap(), rewind_target_tip);
		assert!(chain.get_block_header(&denied_parent_hash).is_err());
		assert_eq!(
			chain.get_block_header(&detached_child_hash).unwrap(),
			detached_child
		);

		// The retained child now has a missing parent, but it is above and off both
		// active chains. It must be skipped without dereferencing prev_hash.
		chain
			.rewind_bad_block(&secp, &std::iter::once(detached_child_hash).collect())
			.unwrap();
		assert_eq!(chain.head().unwrap(), rewind_target_tip);
		assert_eq!(chain.header_head().unwrap(), rewind_target_tip);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn rewind_bad_block_keeps_missing_active_ancestry_fatal() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/rewind_bad_block_missing_active_parent_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = mine_chain(&chain_dir, 3);
		let denied_header = chain.head_header().unwrap();
		let denied_hash = denied_header.hash(0).unwrap();
		let parent_hash = denied_header.prev_hash;
		let body_head_before = chain.head().unwrap();
		let header_head_before = chain.header_head().unwrap();

		{
			let batch = chain.store.batch_write().unwrap();
			batch.delete_block_header(&parent_hash).unwrap();
			batch.commit().unwrap();
		}

		let err = chain
			.rewind_bad_block(&secp, &std::iter::once(denied_hash).collect())
			.unwrap_err();
		assert!(matches!(
			err,
			Error::StoreErr(NotFoundErr(_), ref context)
				if context.contains("rewind_bad_block ancestry")
		));
		assert_eq!(chain.head().unwrap(), body_head_before);
		assert_eq!(chain.header_head().unwrap(), header_head_before);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn rewind_bad_block_rejects_missing_retained_target_before_marker() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/rewind_bad_block_missing_retained_target_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = mine_chain(&chain_dir, 3);
		let denied_header = chain.head_header().unwrap();
		let denied_hash = denied_header.hash(0).unwrap();
		let target_header = chain
			.get_header_by_height(denied_header.height - 1)
			.unwrap();
		let target_hash = target_header.hash(0).unwrap();
		let body_head_before = chain.head().unwrap();
		let header_head_before = chain.header_head().unwrap();
		let body_tail = Tip::try_from_header(&chain.genesis()).unwrap();

		// Automated-testing compaction keeps BODY_TAIL at HEAD. Retain the
		// target, then model raw loss of its full-block record.
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_body_tail(&body_tail).unwrap();
			batch.delete(&mwc_store::to_key(b'b', target_hash)).unwrap();
			batch.commit().unwrap();
		}

		let err = chain
			.rewind_bad_block(&secp, &std::iter::once(denied_hash).collect())
			.unwrap_err();
		assert!(matches!(
			err,
			Error::StoreErr(NotFoundErr(_), ref context)
				if context.contains("rewind_bad_block body target preflight load full block")
		));
		assert_eq!(chain.head().unwrap(), body_head_before);
		assert_eq!(chain.header_head().unwrap(), header_head_before);
		assert_eq!(chain.tail().unwrap(), body_tail);
		assert_eq!(chain.get_block_header(&target_hash).unwrap(), target_header);
		assert!(chain.get_block_for_header(&denied_header).is_ok());
		assert!(chain.get_block_header(&denied_hash).is_ok());
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn rewind_bad_block_rejects_mismatched_retained_target_before_marker() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/rewind_bad_block_mismatched_retained_target_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = mine_chain(&chain_dir, 3);
		let denied_header = chain.head_header().unwrap();
		let denied_hash = denied_header.hash(0).unwrap();
		let target_header = chain
			.get_header_by_height(denied_header.height - 1)
			.unwrap();
		let target_hash = target_header.hash(0).unwrap();
		let mut corrupted_target = chain.get_block_for_header(&target_header).unwrap();
		corrupted_target.header.height = corrupted_target.header.height.saturating_add(100);
		assert_eq!(corrupted_target.hash(0).unwrap(), target_hash);
		assert_ne!(corrupted_target.header, target_header);
		let body_head_before = chain.head().unwrap();
		let header_head_before = chain.header_head().unwrap();
		let body_tail = Tip::try_from_header(&chain.genesis()).unwrap();

		// Bypass normal block-write validation to model a legacy or raw-corruption
		// record stored under the target hash with a different complete header.
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_body_tail(&body_tail).unwrap();
			batch
				.db
				.put_ser(&mwc_store::to_key(b'b', target_hash), &corrupted_target)
				.unwrap();
			batch.commit().unwrap();
		}

		let err = chain
			.rewind_bad_block(&secp, &std::iter::once(denied_hash).collect())
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(ref msg)
				if msg.contains("rewind_bad_block body target preflight")
					&& msg.contains("does not exactly match persisted ancestry header")
		));
		assert_eq!(chain.head().unwrap(), body_head_before);
		assert_eq!(chain.header_head().unwrap(), header_head_before);
		assert_eq!(chain.tail().unwrap(), body_tail);
		assert_eq!(chain.get_block_header(&target_hash).unwrap(), target_header);
		assert_eq!(
			chain.store.get_block(&target_hash).unwrap().header,
			corrupted_target.header
		);
		assert!(chain.get_block_for_header(&denied_header).is_ok());
		assert!(chain.get_block_header(&denied_hash).is_ok());
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn rewind_bad_block_holds_body_lock_until_finalization() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!("target/rewind_bad_block_body_lock_{}", std::process::id());
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = Arc::new(mine_chain(&chain_dir, 3));
		let denied_header = chain.head_header().unwrap();
		let denied_hash = denied_header.hash(0).unwrap();
		let parent = chain
			.get_header_by_height(denied_header.height - 1)
			.unwrap();
		let parent_tip = Tip::try_from_header(&parent).unwrap();

		// Automated-testing compaction keeps BODY_TAIL at HEAD. Move the tail back
		// to genesis so this test can exercise a real body rewind.
		{
			let batch = chain.store.batch_write().unwrap();
			batch
				.save_body_tail(&Tip::try_from_header(&chain.genesis()).unwrap())
				.unwrap();
			batch.commit().unwrap();
		}

		let (reached_tx, reached_rx) = mpsc::sync_channel(1);
		let (resume_tx, resume_rx) = mpsc::sync_channel(1);
		*chain.rewind_bad_block_after_body_sync_hook.write() =
			Some(Arc::new(RewindBadBlockAfterBodySyncHook {
				reached: reached_tx,
				resume: Mutex::new(resume_rx),
			}));

		let worker_chain = chain.clone();
		let worker = std::thread::spawn(move || {
			global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
			global::set_local_nrd_enabled(false);
			let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			worker_chain.apply_invalid_blocks(&secp, std::iter::once(denied_hash).collect())
		});

		let reached = reached_rx.recv_timeout(Duration::from_secs(30));
		if let Err(e) = reached {
			let _ = resume_tx.send(());
			if worker.is_finished() {
				match worker.join() {
					Ok(Ok(())) => panic!(
						"rewind completed without reaching the post-body-sync hook: {}",
						e
					),
					Ok(Err(worker_err)) => panic!(
						"rewind failed before the post-body-sync hook: {}; {}",
						e, worker_err
					),
					Err(_) => panic!("rewind panicked before the post-body-sync hook: {}", e),
				}
			}
			panic!("rewind timed out before the post-body-sync hook: {}", e);
		}
		let body_lock_was_held = chain.txhashset.try_read().is_none();
		resume_tx.send(()).unwrap();
		worker.join().unwrap().unwrap();
		*chain.rewind_bad_block_after_body_sync_hook.write() = None;

		assert!(
			body_lock_was_held,
			"txhashset became readable after PMMR sync but before database and marker finalization"
		);
		assert_eq!(chain.head().unwrap(), parent_tip);
		assert_eq!(chain.header_head().unwrap(), parent_tip);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		pipe::release_context_data(chain.get_context_id());
		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn rewind_bad_block_generation_exhaustion_retains_recovery_marker() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/rewind_bad_block_generation_exhaustion_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = mine_chain(&chain_dir, 3);
		let denied_header = chain.head_header().unwrap();
		let denied_hash = denied_header.hash(0).unwrap();
		let parent = chain
			.get_header_by_height(denied_header.height - 1)
			.unwrap();
		let parent_tip = Tip::try_from_header(&parent).unwrap();

		{
			let batch = chain.store.batch_write().unwrap();
			batch
				.save_body_tail(&Tip::try_from_header(&chain.genesis()).unwrap())
				.unwrap();
			batch.commit().unwrap();
		}
		chain
			.pibd_state_generation
			.store(u64::MAX, Ordering::SeqCst);

		let err = chain
			.apply_invalid_blocks(&secp, std::iter::once(denied_hash).collect())
			.unwrap_err();
		assert!(matches!(
			err,
			Error::DataOverflow(ref msg) if msg.contains("PIBD state generation exhausted")
		));
		assert_eq!(chain.store.head().unwrap(), parent_tip);
		assert_eq!(chain.store.header_head().unwrap(), parent_tip);
		assert_eq!(chain.pibd_state_generation.load(Ordering::SeqCst), u64::MAX);
		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert_eq!(
			chain
				.store
				.pending_chain_operation()
				.unwrap()
				.unwrap()
				.kind(),
			ChainOperationKind::RewindBadBlock
		);

		pipe::release_context_data(chain.get_context_id());
		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn recovery_invalidates_marked_and_markerless_desegmenters() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/recovery_invalidates_desegmenters_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);

		let marked_desegmenter = chain.init_desegmenter(0, Hash::default()).unwrap();
		assert!(marked_desegmenter.is_current());
		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::SyncHeaders)
			.unwrap();
		chain.store.set_pending_chain_operation(&op).unwrap();
		chain.requires_init_recovery.store(true, Ordering::SeqCst);
		chain.ensure_chain_robust().unwrap();
		assert!(!marked_desegmenter.is_current());
		assert!(matches!(
			marked_desegmenter.check_update_leaf_set_state(),
			Err(Error::ChainRestartRequired)
		));

		let markerless_desegmenter = chain.init_desegmenter(0, Hash::default()).unwrap();
		assert!(markerless_desegmenter.is_current());
		// Bitmap-accumulator failures latch recovery without a durable marker. The
		// no-marker recovery path must still invalidate the partially mutated object.
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		chain.requires_init_recovery.store(true, Ordering::SeqCst);
		chain.ensure_chain_robust().unwrap();
		assert!(!markerless_desegmenter.is_current());
		assert!(matches!(
			markerless_desegmenter.check_update_leaf_set_state(),
			Err(Error::ChainRestartRequired)
		));

		let fresh_desegmenter = chain.init_desegmenter(0, Hash::default()).unwrap();
		assert!(fresh_desegmenter.is_current());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	fn assert_successful_reset_invalidates_segmenters<F>(chain: &Chain, reset: F)
	where
		F: FnOnce() -> Result<(), Error>,
	{
		let old_segmenter = chain.segmenter().unwrap();
		assert!(old_segmenter.is_current());
		assert!(old_segmenter.bitmap_root().is_ok());
		let generation_before = chain.pibd_state_generation.load(Ordering::SeqCst);

		reset().unwrap();

		assert_eq!(
			chain.pibd_state_generation.load(Ordering::SeqCst),
			generation_before + 1
		);
		assert!(!old_segmenter.is_current());
		assert!(old_segmenter.bitmap_root().is_err());
		assert!(!chain
			.pibd_segmenter
			.read_recursive()
			.as_ref()
			.unwrap()
			.is_current());

		let fresh_segmenter = chain.segmenter().unwrap();
		assert!(fresh_segmenter.is_current());
		assert!(fresh_segmenter.bitmap_root().is_ok());
	}

	#[test]
	fn successful_resets_invalidate_cached_and_cloned_segmenters() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/successful_resets_invalidate_segmenters_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis();

		assert_successful_reset_invalidates_segmenters(&chain, || {
			chain.reset_chain_head(&secp, &genesis, true)
		});
		assert_successful_reset_invalidates_segmenters(&chain, || chain.reset_pibd_chain());
		assert_successful_reset_invalidates_segmenters(&chain, || {
			chain.reset_chain_head_to_genesis()
		});

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn pibd_reset_skips_but_explicit_reset_validates_retained_headers() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/pibd_reset_skips_retained_header_validation_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let genesis = global::get_genesis_block(&secp, 0).unwrap();
		let chain = Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis.clone(),
			reject_non_genesis_pow,
			false,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap();

		let header = recovery_test_header(1, genesis.hash(0).unwrap(), 1);
		let header_tip = Tip::try_from_header(&header).unwrap();
		{
			let mut header_pmmr = chain.header_pmmr.write();
			let mut batch = chain.store.batch_write().unwrap();
			txhashset::header_extending(&mut header_pmmr, &mut batch, |ext, batch| {
				ext.apply_header(&header)?;
				batch.save_block_header(&header)?;
				batch.save_header_head(&header_tip)?;
				Ok(())
			})
			.unwrap();
			batch.commit().unwrap();
		}

		// The configured verifier rejects this non-genesis header. Both the live
		// PIBD reset and recovery from its durable marker must still preserve it.
		chain.reset_pibd_chain().unwrap();
		assert_eq!(chain.header_head().unwrap(), header_tip);

		chain
			.store
			.set_pending_chain_operation(&PendingChainOperation::PibdReset)
			.unwrap();
		chain.requires_init_recovery.store(true, Ordering::SeqCst);
		chain.ensure_chain_robust().unwrap();
		assert_eq!(chain.header_head().unwrap(), header_tip);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		let err = chain.reset_chain_head_to_genesis().unwrap_err();
		assert!(
			matches!(
				&err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("forced non-genesis PoW failure")
			),
			"unexpected explicit reset error: {:?}",
			err
		);
		assert_eq!(
			chain
				.store
				.pending_chain_operation()
				.unwrap()
				.unwrap()
				.kind(),
			ChainOperationKind::ResetToGenesis
		);

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn existing_pending_chain_operation_marks_recovery_required() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/existing_pending_chain_operation_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let stale_op =
			prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::SyncHeaders)
				.unwrap();
		chain.store.set_pending_chain_operation(&stale_op).unwrap();

		{
			let _header_pmmr = chain.header_pmmr.write();
			let result = chain.set_pending_chain_operation_checked(&stale_op);
			assert!(matches!(
				result,
				Err(Error::Other(ref msg))
					if msg == "pending chain operation requires chain init recovery"
			));
		}

		assert!(chain.requires_init_recovery.load(Ordering::SeqCst));
		assert_eq!(
			chain.store.pending_chain_operation().unwrap(),
			Some(stale_op)
		);

		chain.ensure_chain_robust().unwrap();
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn legacy_compact_marker_derives_and_recovers_body_tail() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!("target/legacy_compact_marker_{}", std::process::id());
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let expected_tail = Tip::try_from_header(&chain.genesis()).unwrap();
		let op =
			prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::Compact).unwrap();
		chain.store.set_pending_chain_operation(&op).unwrap();
		chain.requires_init_recovery.store(true, Ordering::SeqCst);

		chain.ensure_chain_robust().unwrap();

		assert_eq!(chain.tail().unwrap(), expected_tail);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn process_block_header_rejects_mismatched_context_before_hashing() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/process_block_header_context_mismatch_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let header_head_before = chain.header_head().unwrap();
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		let mut header = chain.genesis();
		header.pow.proof.context_id = u32::MAX;
		let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			chain.process_block_header(&header, Options::SKIP_POW)
		}));
		let err = result
			.expect("context mismatch must return an error instead of panicking")
			.unwrap_err();
		assert!(err.is_bad_data());
		match err {
			Error::InvalidHeaderContext { expected, actual } => {
				assert_eq!(expected, chain.get_context_id());
				assert_eq!(actual, u32::MAX);
			}
			other => panic!("unexpected context mismatch error: {:?}", other),
		}
		assert_eq!(chain.header_head().unwrap(), header_head_before);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn missing_parent_header_validates_pow_before_returning_orphan() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/missing_parent_header_pow_validation_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			global::get_genesis_block(&secp, 0).unwrap(),
			reject_non_genesis_pow,
			false,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap();

		let mut header = BlockHeader::default(0);
		header.height = 1;
		header.prev_hash = Hash::from_vec(&[0xa5; Hash::LEN]);
		*header
			.pow
			.proof
			.nonces
			.last_mut()
			.expect("automated-test proof has at least one nonce") = 1;
		assert_ne!(header.hash(0).unwrap(), chain.head().unwrap().last_block_h);

		let err = chain
			.process_block_header(&header, Options::NONE)
			.unwrap_err();
		assert!(matches!(err, Error::InvalidPow));
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn reset_chain_head_rejects_mismatched_context_before_hashing() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/reset_chain_head_context_mismatch_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let body_head_before = chain.head().unwrap();
		let header_head_before = chain.header_head().unwrap();
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		let mut header = chain.genesis();
		header.pow.proof.context_id = u32::MAX;
		let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			chain.reset_chain_head(&secp, &header, true)
		}));
		let err = result
			.expect("context mismatch must return an error instead of panicking")
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidHeaderContext { expected, actual }
				if expected == chain.get_context_id() && actual == u32::MAX
		));

		// Keep the state helper safe if a future internal caller bypasses operation
		// preparation and invokes it directly.
		let state_result = {
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				reset_chain_head_state(
					&chain.store,
					&mut header_pmmr,
					&mut txhashset,
					&secp,
					&header,
					true,
				)
			}))
		};
		let err = state_result
			.expect("state context mismatch must return an error instead of panicking")
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidHeaderContext { expected, actual }
				if expected == chain.get_context_id() && actual == u32::MAX
		));

		assert_eq!(chain.head().unwrap(), body_head_before);
		assert_eq!(chain.header_head().unwrap(), header_head_before);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	fn retained_test_block(height: u64, prev_hash: Hash, proof_nonce: u64) -> Block {
		let mut block = Block::default(0);
		block.header.height = height;
		block.header.prev_hash = prev_hash;
		if let Some(last_nonce) = block.header.pow.proof.nonces.last_mut() {
			*last_nonce = proof_nonce;
		}
		block
	}

	fn init_automated_test_chain(chain_dir: &str, secp: &Secp256k1) -> Chain {
		Chain::init(
			secp,
			0,
			chain_dir.to_owned(),
			Arc::new(crate::types::NoopAdapter {}),
			global::get_genesis_block(secp, 0).unwrap(),
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap()
	}

	fn recovery_test_header(height: u64, prev_hash: Hash, proof_nonce: u64) -> BlockHeader {
		let mut header = BlockHeader::default(0);
		header.height = height;
		header.prev_hash = prev_hash;
		header.pow.proof.nonces[0] = proof_nonce;
		header
	}

	fn accept_recovery_test_pow(_context_id: u32, _header: &BlockHeader) -> Result<(), pow::Error> {
		Ok(())
	}

	fn recovery_header_pmmr(chain_dir: &str) -> PMMRHandle<BlockHeader> {
		PMMRHandle::<BlockHeader>::new(
			Path::new(chain_dir).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap()
	}

	#[test]
	fn startup_recovers_speculative_header_pmmr_suffix_missing_from_db() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/recovery_speculative_header_suffix_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		let genesis_tip = Tip::try_from_header(&genesis.header).unwrap();
		let genesis_hash = genesis.hash(0).unwrap();
		let genesis_root = {
			let mut header_pmmr = chain.header_pmmr.write();
			let size = header_pmmr.size;
			PMMR::at(&mut header_pmmr.backend, size).root().unwrap()
		};

		let mut speculative = recovery_test_header(1, genesis_hash, 801);
		speculative.prev_root = genesis_root;
		let speculative_hash = speculative.hash(0).unwrap();
		let speculative_tip = Tip::try_from_header(&speculative).unwrap();
		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::ProcessHeader)
			.unwrap();
		chain.store.set_pending_chain_operation(&op).unwrap();

		{
			let mut header_pmmr = chain.header_pmmr.write();
			let mut batch = chain.store.batch_write().unwrap();
			txhashset::header_extending(&mut header_pmmr, &mut batch, |ext, _| {
				ext.validate_root(&speculative)?;
				ext.apply_header(&speculative)
			})
			.unwrap();

			// Model process_block_header's writes after the PMMR sync, then abort
			// the enclosing LMDB transaction as a crash or failed commit would.
			batch.save_block_header(&speculative).unwrap();
			batch.save_header_head(&speculative_tip).unwrap();
			drop(batch);
			assert_eq!(header_pmmr.head_hash().unwrap(), speculative_hash);
		}

		assert_eq!(chain.store.header_head().unwrap(), genesis_tip);
		assert!(chain.store.get_block_header(&speculative_hash).is_err());
		assert_eq!(
			chain.store.pending_chain_operation().unwrap(),
			Some(op.clone())
		);

		drop(chain);
		let restarted = Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap();

		assert_eq!(restarted.header_head().unwrap(), genesis_tip);
		assert_eq!(restarted.header_pmmr.read().size, 1);
		assert_eq!(
			restarted.header_pmmr.read().head_hash().unwrap(),
			genesis_hash
		);
		assert!(restarted.store.pending_chain_operation().unwrap().is_none());
		assert!(restarted.store.get_block_header(&speculative_hash).is_err());

		drop(restarted);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn startup_recovers_speculative_header_pmmr_fork_missing_from_db() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/recovery_speculative_header_fork_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		let genesis_hash = genesis.hash(0).unwrap();
		let genesis_root = {
			let mut header_pmmr = chain.header_pmmr.write();
			let size = header_pmmr.size;
			PMMR::at(&mut header_pmmr.backend, size).root().unwrap()
		};

		let mut durable = recovery_test_header(1, genesis_hash, 811);
		durable.prev_root = genesis_root;
		let durable_hash = durable.hash(0).unwrap();
		let durable_tip = Tip::try_from_header(&durable).unwrap();
		let mut speculative = recovery_test_header(1, genesis_hash, 812);
		speculative.prev_root = genesis_root;
		let speculative_hash = speculative.hash(0).unwrap();
		let speculative_tip = Tip::try_from_header(&speculative).unwrap();
		assert_ne!(durable_hash, speculative_hash);

		// Establish a fully durable header branch first.
		{
			let mut header_pmmr = chain.header_pmmr.write();
			let mut batch = chain.store.batch_write().unwrap();
			txhashset::header_extending(&mut header_pmmr, &mut batch, |ext, _| {
				ext.validate_root(&durable)?;
				ext.apply_header(&durable)
			})
			.unwrap();
			batch.save_block_header(&durable).unwrap();
			batch.save_header_head(&durable_tip).unwrap();
			batch.commit().unwrap();
		}

		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::SyncHeaders)
			.unwrap();
		chain.store.set_pending_chain_operation(&op).unwrap();

		{
			let mut header_pmmr = chain.header_pmmr.write();
			let mut batch = chain.store.batch_write().unwrap();
			txhashset::header_extending(&mut header_pmmr, &mut batch, |ext, _| {
				ext.rewind(&genesis.header)?;
				ext.validate_root(&speculative)?;
				ext.apply_header(&speculative)
			})
			.unwrap();

			// The PMMR fork is durable, but these enclosing DB writes are not.
			batch.save_block_header(&speculative).unwrap();
			batch.save_header_head(&speculative_tip).unwrap();
			drop(batch);
			assert_eq!(header_pmmr.head_hash().unwrap(), speculative_hash);
		}

		assert_eq!(chain.store.header_head().unwrap(), durable_tip);
		assert_eq!(
			chain.store.get_block_header(&durable_hash).unwrap(),
			durable
		);
		assert!(chain.store.get_block_header(&speculative_hash).is_err());
		drop(chain);

		let restarted = Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis,
			accept_recovery_test_pow,
			false,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap();

		assert_eq!(restarted.header_head().unwrap(), durable_tip);
		assert_eq!(restarted.header_pmmr.read().size, 3);
		assert_eq!(
			restarted.header_pmmr.read().head_hash().unwrap(),
			durable_hash
		);
		assert!(restarted.store.pending_chain_operation().unwrap().is_none());
		assert!(restarted.store.get_block_header(&speculative_hash).is_err());

		drop(restarted);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn reset_chain_head_requires_target_full_block() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!("target/reset_target_block_{}", std::process::id());
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		let genesis_hash = genesis.hash(0).unwrap();
		{
			let batch = chain.store.batch_write().unwrap();
			batch
				.delete(&mwc_store::to_key(b'b', genesis_hash))
				.unwrap();
			batch.commit().unwrap();
		}

		let mut header_pmmr = chain.header_pmmr.write();
		let mut txhashset = chain.txhashset.write();
		let err = reset_chain_head_state(
			&chain.store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
			&genesis.header,
			true,
		)
		.unwrap_err();
		assert!(matches!(
			err,
			Error::StoreErr(_, context)
				if context.contains("reset_chain_head target preflight load full block")
		));

		drop(txhashset);
		drop(header_pmmr);
		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn reset_chain_head_preserves_body_tail_ancestry() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!("target/reset_body_tail_{}", std::process::id());
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		let main_1 = retained_test_block(1, genesis.hash(0).unwrap(), 601);
		let main_2 = retained_test_block(2, main_1.hash(0).unwrap(), 602);
		let fork_1 = retained_test_block(1, genesis.hash(0).unwrap(), 701);
		let fork_2 = retained_test_block(2, fork_1.hash(0).unwrap(), 702);
		let body_head = Tip::try_from_header(&main_2.header).unwrap();
		let body_tail = Tip::try_from_header(&main_1.header).unwrap();
		{
			let batch = chain.store.batch_write().unwrap();
			for block in [&main_1, &main_2, &fork_1, &fork_2] {
				batch.save_block_header(&block.header).unwrap();
				batch.save_block(block).unwrap();
			}
			batch.save_body_head(&body_head).unwrap();
			batch.save_body_tail(&body_tail).unwrap();
			batch.commit().unwrap();
		}

		let mut header_pmmr = chain.header_pmmr.write();
		let mut txhashset = chain.txhashset.write();
		let below_tail = reset_chain_head_state(
			&chain.store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
			&genesis.header,
			true,
		)
		.unwrap_err();
		assert!(matches!(below_tail, Error::Other(msg) if msg.contains("below BODY_TAIL")));

		let wrong_fork = reset_chain_head_state(
			&chain.store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
			&fork_2.header,
			true,
		)
		.unwrap_err();
		assert!(matches!(
			wrong_fork,
			Error::Other(msg) if msg.contains("does not contain BODY_TAIL")
		));

		drop(txhashset);
		drop(header_pmmr);
		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn header_recovery_preserves_complete_odd_height_pmmr_size() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = format!(
			"target/header_recovery_odd_height_size_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let genesis = BlockHeader::default(0);
		let header = recovery_test_header(1, genesis.hash(0).unwrap(), 1);
		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&genesis).unwrap();
			batch.save_block_header(&header).unwrap();
			batch.commit().unwrap();
		}

		let mut header_pmmr = recovery_header_pmmr(&chain_dir);
		header_pmmr.size = {
			let mut pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			pmmr.push(&genesis).unwrap();
			pmmr.push(&header).unwrap();
			pmmr.size()
		};
		assert_eq!(header_pmmr.size, 3);

		reconcile_header_pmmr_to_header(
			&genesis,
			&store,
			&mut header_pmmr,
			&header,
			accept_recovery_test_pow,
			None,
		)
		.unwrap();
		assert_eq!(header_pmmr.size, 3);

		drop(header_pmmr);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn header_recovery_rejects_hash_data_split() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = format!(
			"target/header_recovery_hash_data_split_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let genesis = BlockHeader::default(0);
		let old_header = recovery_test_header(1, genesis.hash(0).unwrap(), 1);
		let new_header = recovery_test_header(1, genesis.hash(0).unwrap(), 2);
		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&genesis).unwrap();
			batch.save_block_header(&old_header).unwrap();
			batch.commit().unwrap();
		}

		// Model a crash after the new-fork hash file flush but before the data
		// file flush: hashes describe the new fork while HeaderEntry data still
		// describes the old durable HEADER_HEAD fork.
		let mut header_pmmr = recovery_header_pmmr(&chain_dir);
		let genesis_hash = genesis.hash_with_index(0, 0).unwrap();
		let new_leaf_hash = new_header.hash_with_index(0, 1).unwrap();
		let new_parent_hash = (genesis_hash, new_leaf_hash).hash_with_index(0, 2).unwrap();
		header_pmmr
			.backend
			.append(&genesis, &[genesis_hash])
			.unwrap();
		header_pmmr
			.backend
			.append(&old_header, &[new_leaf_hash, new_parent_hash])
			.unwrap();
		header_pmmr.size = 3;

		let err = reconcile_header_pmmr_to_header(
			&genesis,
			&store,
			&mut header_pmmr,
			&old_header,
			accept_recovery_test_pow,
			None,
		)
		.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("does not authenticate authoritative header")
		));

		drop(header_pmmr);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn header_recovery_rejects_same_hash_cached_metadata_mismatch() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = format!(
			"target/header_recovery_cached_metadata_mismatch_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let genesis = BlockHeader::default(0);
		let cached_header = recovery_test_header(1, genesis.hash(0).unwrap(), 1);
		let mut authoritative_header = cached_header.clone();
		authoritative_header.pow.total_difficulty = mwc_core::pow::Difficulty::from_num(
			cached_header.total_difficulty().to_num().saturating_add(1),
		);
		assert_eq!(
			cached_header.hash(0).unwrap(),
			authoritative_header.hash(0).unwrap()
		);
		assert_ne!(cached_header, authoritative_header);
		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&genesis).unwrap();
			batch.save_block_header(&authoritative_header).unwrap();
			batch.commit().unwrap();
		}

		let mut header_pmmr = recovery_header_pmmr(&chain_dir);
		header_pmmr.size = {
			let mut pmmr = PMMR::at(&mut header_pmmr.backend, header_pmmr.size);
			pmmr.push(&genesis).unwrap();
			pmmr.push(&cached_header).unwrap();
			pmmr.size()
		};

		let err = reconcile_header_pmmr_to_header(
			&genesis,
			&store,
			&mut header_pmmr,
			&authoritative_header,
			accept_recovery_test_pow,
			None,
		)
		.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("does not match authoritative header")
		));

		drop(header_pmmr);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn header_recovery_rejects_same_hash_header_with_invalid_pow_binding() {
		let chain_dir = format!(
			"target/header_recovery_invalid_pow_binding_{}",
			std::process::id()
		);
		clean_output_dir(&chain_dir);
		let chain = mine_chain(&chain_dir, 2);
		let genesis = chain.genesis.clone();
		let selected_hash = chain.header_head().unwrap().last_block_h;
		let original = chain.store.get_block_header(&selected_hash).unwrap();
		assert_eq!(original.height, 1);
		pow::verify_size(0, &original).unwrap();

		let mut altered = original.clone();
		altered.prev_root = Hash::from_vec(&[42; Hash::LEN]);
		assert_ne!(altered, original);
		assert_eq!(altered.hash(0).unwrap(), selected_hash);
		let pos0 = pmmr::insertion_to_pmmr_index(altered.height).unwrap();
		assert_eq!(
			altered.hash_with_index(0, pos0).unwrap(),
			original.hash_with_index(0, pos0).unwrap()
		);
		assert!(pow::verify_size(0, &altered).is_err());

		{
			let batch = chain.store.batch_write().unwrap();
			// Bypass the normal overwrite guard to model a persisted header whose
			// noncached fields changed while its proof-derived key stayed the same.
			batch
				.db
				.put_ser(&mwc_store::to_key(b'h', selected_hash), &altered)
				.unwrap();
			batch.commit().unwrap();
		}

		let mut header_pmmr = chain.header_pmmr.write();
		let size_before = header_pmmr.size;
		let head_before = header_pmmr.head_hash().unwrap();
		let err = reconcile_header_pmmr_to_header(
			&genesis.header,
			&chain.store,
			&mut header_pmmr,
			&altered,
			pow::verify_size,
			None,
		)
		.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("failed PoW authentication")
		));
		assert_eq!(header_pmmr.size, size_before);
		assert_eq!(header_pmmr.head_hash().unwrap(), head_before);

		drop(header_pmmr);
		drop(chain);
		clean_output_dir(&chain_dir);
	}

	#[test]
	fn marked_recovery_failure_does_not_rebuild_body_at_genesis() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/marked_recovery_no_genesis_fallback_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		let genesis_hash = genesis.hash(0).unwrap();
		let original_body_head = chain.head().unwrap();
		let original_header_head = chain.header_head().unwrap();
		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::ProcessBlock)
			.unwrap();
		chain.store.set_pending_chain_operation(&op).unwrap();
		{
			let batch = chain.store.batch_write().unwrap();
			batch
				.delete(&mwc_store::to_key(b'b', genesis_hash))
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			let header_size_before = header_pmmr.size;
			let body_sizes_before = (
				txhashset.output_mmr_size(),
				txhashset.rangeproof_mmr_size(),
				txhashset.kernel_mmr_size(),
			);
			let err = recover_pending_chain_operation(
				&genesis,
				&chain.store,
				&mut header_pmmr,
				&mut txhashset,
				&secp,
				pow::verify_size,
				None,
			)
			.unwrap_err();
			assert!(matches!(
				err,
				Error::StoreErr(_, context)
					if context.contains("reconcile_pmmrs_to_db_heads HEAD preflight")
			));
			assert_eq!(header_pmmr.size, header_size_before);
			assert_eq!(
				(
					txhashset.output_mmr_size(),
					txhashset.rangeproof_mmr_size(),
					txhashset.kernel_mmr_size(),
				),
				body_sizes_before
			);
		}
		assert_eq!(
			chain.store.pending_chain_operation().unwrap(),
			Some(op.clone())
		);
		assert_eq!(chain.head().unwrap(), original_body_head);
		assert_eq!(chain.header_head().unwrap(), original_header_head);
		assert!(!chain.store.block_exists(&genesis_hash).unwrap());

		drop(chain);
		let restart_err = match Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		) {
			Ok(_) => panic!("startup silently rebuilt the body at genesis"),
			Err(err) => err,
		};
		assert!(matches!(
			restart_err,
			Error::StoreErr(_, context)
				if context.contains("reconcile_pmmrs_to_db_heads HEAD preflight")
		));
		let store = ChainStore::new(0, &chain_dir).unwrap();
		assert_eq!(store.pending_chain_operation().unwrap(), Some(op));
		assert_eq!(store.head().unwrap(), original_body_head);
		assert_eq!(store.header_head().unwrap(), original_header_head);
		assert!(!store.block_exists(&genesis_hash).unwrap());
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn marked_recovery_reports_short_header_pmmr_and_startup_stops() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!("target/recovery_short_header_pmmr_{}", std::process::id());
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		let original_body_head = chain.head().unwrap();
		let target_header = recovery_test_header(1, genesis.hash(0).unwrap(), 41);
		let target_header_head = Tip::try_from_header(&target_header).unwrap();
		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::ProcessHeader)
			.unwrap();

		// Model the restart-visible result of a rewind that reached the PMMR
		// durability domain without the matching LMDB transition: HEADER_HEAD
		// requires two header leaves, while the file still contains only genesis.
		chain.store.set_pending_chain_operation(&op).unwrap();
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_block_header(&target_header).unwrap();
			batch.save_header_head(&target_header_head).unwrap();
			batch.commit().unwrap();
		}

		{
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			let header_size_before = header_pmmr.size;
			let body_sizes_before = (
				txhashset.output_mmr_size(),
				txhashset.rangeproof_mmr_size(),
				txhashset.kernel_mmr_size(),
			);
			let err = recover_pending_chain_operation(
				&genesis,
				&chain.store,
				&mut header_pmmr,
				&mut txhashset,
				&secp,
				pow::verify_size,
				None,
			)
			.unwrap_err();
			let details = match err {
				Error::PmmrRecoveryRequired(details) => details,
				other => panic!("unexpected short-header recovery error: {:?}", other),
			};
			assert!(details.contains("durable HEADER_HEAD"), "{}", details);
			assert!(details.contains("header PMMR position 3"), "{}", details);
			assert_eq!(header_pmmr.size, header_size_before);
			assert_eq!(
				(
					txhashset.output_mmr_size(),
					txhashset.rangeproof_mmr_size(),
					txhashset.kernel_mmr_size(),
				),
				body_sizes_before
			);
		}
		assert_eq!(
			chain.store.pending_chain_operation().unwrap(),
			Some(op.clone())
		);
		assert_eq!(chain.head().unwrap(), original_body_head);
		assert_eq!(chain.header_head().unwrap(), target_header_head);

		// Chain::init invokes marked-operation recovery before setup_head. The same
		// typed error therefore aborts node initialization instead of entering the
		// body-only genesis fallback or clearing the marker.
		drop(chain);
		let restart_err = match Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		) {
			Ok(_) => panic!("startup accepted a durable head beyond the header PMMR"),
			Err(err) => err,
		};
		assert!(matches!(
			restart_err,
			Error::PmmrRecoveryRequired(ref details)
				if details.contains("durable HEADER_HEAD")
		));

		let store = ChainStore::new(0, &chain_dir).unwrap();
		assert_eq!(store.pending_chain_operation().unwrap(), Some(op));
		assert_eq!(store.head().unwrap(), original_body_head);
		assert_eq!(store.header_head().unwrap(), target_header_head);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn marked_recovery_reports_short_body_pmmr_before_mutation() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!("target/recovery_short_body_pmmrs_{}", std::process::id());
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		let original_header_head = chain.header_head().unwrap();
		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::ProcessBlock)
			.unwrap();

		let body_sizes_before = {
			let txhashset = chain.txhashset.read();
			(
				txhashset.output_mmr_size(),
				txhashset.rangeproof_mmr_size(),
				txhashset.kernel_mmr_size(),
			)
		};
		let output_leaf_count = pmmr::n_leaves(body_sizes_before.0).unwrap();
		let target_output_size = pmmr::insertion_to_pmmr_index(output_leaf_count + 1).unwrap();
		assert!(target_output_size > body_sizes_before.0);

		let mut target_block = retained_test_block(1, genesis.hash(0).unwrap(), 42);
		target_block.header.output_mmr_size = target_output_size;
		target_block.header.kernel_mmr_size = body_sizes_before.2;
		let target_body_head = Tip::try_from_header(&target_block.header).unwrap();

		chain.store.set_pending_chain_operation(&op).unwrap();
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_block_header(&target_block.header).unwrap();
			batch.save_block(&target_block).unwrap();
			batch.save_body_head(&target_body_head).unwrap();
			batch.commit().unwrap();
		}

		{
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			let header_size_before = header_pmmr.size;
			let err = recover_pending_chain_operation(
				&genesis,
				&chain.store,
				&mut header_pmmr,
				&mut txhashset,
				&secp,
				pow::verify_size,
				None,
			)
			.unwrap_err();
			let details = match err {
				Error::PmmrRecoveryRequired(details) => details,
				other => panic!("unexpected short-body recovery error: {:?}", other),
			};
			assert!(details.contains("durable HEAD"), "{}", details);
			assert!(details.contains("output PMMR"), "{}", details);
			assert_eq!(header_pmmr.size, header_size_before);
			assert_eq!(
				(
					txhashset.output_mmr_size(),
					txhashset.rangeproof_mmr_size(),
					txhashset.kernel_mmr_size(),
				),
				body_sizes_before
			);
		}

		assert_eq!(chain.store.pending_chain_operation().unwrap(), Some(op));
		assert_eq!(chain.head().unwrap(), target_body_head);
		assert_eq!(chain.header_head().unwrap(), original_header_head);
		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn body_reconciliation_requires_complete_output_pos_index() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/body_reconciliation_requires_complete_output_pos_index_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		{
			let batch = chain.store.batch_write().unwrap();
			batch.set_output_pos_index_complete(false).unwrap();
			batch.commit().unwrap();
		}

		{
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			let err = reconcile_body_pmmr_to_header(
				&genesis.header,
				&chain.store,
				&mut header_pmmr,
				&mut txhashset,
				&secp,
				&genesis.header,
				pow::verify_size,
				None,
			)
			.unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("output_pos index is incomplete")
			));
		}

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn marked_recovery_failure_retains_marker_without_genesis_fallback() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/marked_recovery_retains_marker_{}",
			std::process::id()
		);
		let corrupt_header_dir = format!("{}_corrupt_header", chain_dir);
		let _ = fs::remove_dir_all(&chain_dir);
		let _ = fs::remove_dir_all(&corrupt_header_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();

		// Preserve the authoritative HeaderEntry while corrupting its PMMR leaf
		// hash. init_head() and a same-size rewind accept this split state because
		// they derive the block hash from HeaderEntry rather than the hash file.
		let mut corrupt_header_pmmr = recovery_header_pmmr(&corrupt_header_dir);
		let expected_leaf_hash = genesis.header.hash_with_index(0, 0).unwrap();
		let corrupt_leaf_hash = Hash::from_vec(&[42; Hash::LEN]);
		assert_ne!(corrupt_leaf_hash, expected_leaf_hash);
		corrupt_header_pmmr
			.backend
			.append(&genesis.header, &[corrupt_leaf_hash])
			.unwrap();
		corrupt_header_pmmr.backend.sync().unwrap();
		corrupt_header_pmmr.size = 1;
		assert_eq!(
			corrupt_header_pmmr.get_header_hash_by_height(0).unwrap(),
			genesis.hash(0).unwrap()
		);

		let op = prepare_reconcile_heads_operation(&chain.store, ChainOperationKind::ProcessHeader)
			.unwrap();
		chain.store.set_pending_chain_operation(&op).unwrap();
		{
			let mut txhashset = chain.txhashset.write();
			let err = recover_marked_chain_operation(
				&genesis,
				&chain.store,
				&mut corrupt_header_pmmr,
				&mut txhashset,
				&secp,
				pow::verify_size,
				None,
				&op,
			)
			.unwrap_err();
			assert!(
				matches!(
					&err,
					Error::InvalidPersistedChainState(msg)
						if msg.contains("does not authenticate authoritative header")
				),
				"unexpected recovery error: {:?}",
				err
			);
		}

		// Recovery must not convert this validation failure into a body reset. The
		// marker tells every restart to stop until the operator investigates and
		// explicitly repairs or cleans the state.
		assert_eq!(chain.store.pending_chain_operation().unwrap(), Some(op));

		drop(corrupt_header_pmmr);
		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
		let _ = fs::remove_dir_all(&corrupt_header_dir);
	}

	#[test]
	fn reconciliation_persists_both_canonical_tip_caches() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/reconciliation_persists_canonical_tips_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let canonical = Tip::try_from_header(&chain.genesis.header).unwrap();

		let mut stale_body_head = canonical;
		stale_body_head.height = 41;
		stale_body_head.prev_block_h = Hash::from_vec(&[1; Hash::LEN]);
		stale_body_head.total_difficulty = mwc_core::pow::Difficulty::from_num(101);
		let mut stale_header_head = canonical;
		stale_header_head.height = 73;
		stale_header_head.prev_block_h = Hash::from_vec(&[2; Hash::LEN]);
		stale_header_head.total_difficulty = mwc_core::pow::Difficulty::from_num(202);
		assert_ne!(stale_body_head, canonical);
		assert_ne!(stale_header_head, canonical);
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_body_head(&stale_body_head).unwrap();
			batch.save_header_head(&stale_header_head).unwrap();
			batch.commit().unwrap();
		}

		{
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			reconcile_pmmrs_to_db_heads(
				&chain.genesis,
				&chain.store,
				&mut header_pmmr,
				&mut txhashset,
				&secp,
				pow::verify_size,
				None,
			)
			.unwrap();
		}

		let batch = chain.store.batch_read().unwrap();
		assert_eq!(batch.head().unwrap(), canonical);
		assert_eq!(batch.header_head().unwrap(), canonical);
		drop(batch);

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn remove_historical_blocks_aborts_when_tail_moved_backward() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/remove_historical_blocks_stale_tail_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let store = chain.get_store_for_tests();
		let genesis_header = chain.genesis();
		let genesis_hash = genesis_header.hash(0).unwrap();

		// Persist headers and full blocks above genesis as cleanup candidates.
		let mut blocks = Vec::new();
		{
			let batch = store.batch_write().unwrap();
			let mut prev_hash = genesis_hash;
			for n in 1..=5u64 {
				let block = retained_test_block(n, prev_hash, n);
				prev_hash = block.hash(0).unwrap();
				batch.save_block_header(&block.header).unwrap();
				batch.save_block(&block).unwrap();
				blocks.push(block);
			}
			// Tail as captured by a completed compaction at height 3.
			let stale_tail = Tip::try_from_header(&blocks[2].header).unwrap();
			batch.save_body_tail(&stale_tail).unwrap();
			batch.commit().unwrap();
		}
		let stale_tail_header = blocks[2].header.clone();

		// Simulate a concurrent reset_pibd_chain/reset_chain_head_to_genesis
		// landing between compaction and cleanup: BODY_TAIL drops to genesis.
		{
			let batch = store.batch_write().unwrap();
			batch
				.save_body_tail(&Tip::try_from_header(&genesis_header).unwrap())
				.unwrap();
			batch.commit().unwrap();
		}

		let stop_state = StopState::new();
		let err = chain
			.remove_historical_blocks(&stale_tail_header, &stop_state)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(ref msg) if msg.contains("tail moved backward")
		));

		// Nothing may have been deleted: the genesis block and the candidates
		// below the stale cutoff are required chain state again.
		chain.get_block_for_header(&genesis_header).unwrap();
		for block in &blocks {
			chain.get_block_for_header(&block.header).unwrap();
		}

		// The selector is authoritative and the height is only a cache. A
		// reset with a stale high cached height must still be recognized as a
		// backward move and must not authorize deletion below that cache.
		{
			let mut reset_tail = Tip::try_from_header(&genesis_header).unwrap();
			reset_tail.height = stale_tail_header.height;
			let batch = store.batch_write().unwrap();
			batch.save_body_tail(&reset_tail).unwrap();
			batch.commit().unwrap();
		}
		let err = chain
			.remove_historical_blocks(&stale_tail_header, &stop_state)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(ref msg) if msg.contains("tail moved backward")
		));
		chain.get_block_for_header(&genesis_header).unwrap();
		for block in &blocks {
			chain.get_block_for_header(&block.header).unwrap();
		}

		// With the tail restored at the cutoff, cleanup proceeds normally.
		{
			let batch = store.batch_write().unwrap();
			batch
				.save_body_tail(&Tip::try_from_header(&stale_tail_header).unwrap())
				.unwrap();
			batch.commit().unwrap();
		}
		chain
			.remove_historical_blocks(&stale_tail_header, &stop_state)
			.unwrap();
		assert!(chain.get_block_for_header(&genesis_header).is_err());
		for block in &blocks[..2] {
			assert!(chain.get_block_for_header(&block.header).is_err());
		}
		for block in &blocks[2..] {
			chain.get_block_for_header(&block.header).unwrap();
		}

		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn remove_historical_blocks_rejects_cutoff_off_current_tail_chain() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/remove_historical_blocks_off_chain_tail_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let store = chain.get_store_for_tests();
		let genesis_hash = chain.genesis().hash(0).unwrap();

		let main_1 = retained_test_block(1, genesis_hash, 101);
		let main_2 = retained_test_block(2, main_1.hash(0).unwrap(), 102);
		let main_3 = retained_test_block(3, main_2.hash(0).unwrap(), 103);
		let fork_1 = retained_test_block(1, genesis_hash, 201);
		let fork_2 = retained_test_block(2, fork_1.hash(0).unwrap(), 202);
		let fork_3 = retained_test_block(3, fork_2.hash(0).unwrap(), 203);
		let blocks = [&main_1, &main_2, &main_3, &fork_1, &fork_2, &fork_3];
		{
			let batch = store.batch_write().unwrap();
			for block in blocks {
				batch.save_block_header(&block.header).unwrap();
				batch.save_block(block).unwrap();
			}
			batch
				.save_body_tail(&Tip::try_from_header(&fork_3.header).unwrap())
				.unwrap();
			batch.commit().unwrap();
		}

		let stop_state = StopState::new();
		let err = chain
			.remove_historical_blocks(&main_3.header, &stop_state)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(ref msg) if msg.contains("is not an ancestor")
		));

		chain.get_block_for_header(&chain.genesis()).unwrap();
		for block in blocks {
			chain.get_block_for_header(&block.header).unwrap();
		}

		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn canonical_tip_header_rejects_misindexed_header() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/canonical_tip_header_rejects_misindexed_header_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let header = BlockHeader::default(0);
		let actual_hash = header.hash(0).unwrap();
		let selected_hash = Hash::from_vec(&[7; Hash::LEN]);
		assert_ne!(selected_hash, actual_hash);

		let mut persisted = Tip::try_from_header(&header).unwrap();
		persisted.last_block_h = selected_hash;
		{
			let batch = store.batch_write().unwrap();
			batch
				.db
				.put_ser(&mwc_store::to_key(b'h', selected_hash), &header)
				.unwrap();
			batch.commit().unwrap();
		}

		let batch = store.batch_read().unwrap();
		let err = canonical_tip_header("HEAD", &persisted, &batch).unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("HEAD header key/hash mismatch")
					&& msg.contains(&selected_hash.to_string())
					&& msg.contains(&actual_hash.to_string())
		));

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn body_chain_lookups_reject_misindexed_anchor_without_traversal() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!("target/body_chain_misindexed_anchor_{}", std::process::id());
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let store = chain.get_store_for_tests();

		let header = retained_test_block(5, Hash::from_vec(&[1; Hash::LEN]), 17).header;
		let actual_hash = header.hash(0).unwrap();
		let selected_hash = Hash::from_vec(&[7; Hash::LEN]);
		assert_ne!(selected_hash, actual_hash);
		let mut body_head = Tip::try_from_header(&header).unwrap();
		body_head.last_block_h = selected_hash;

		{
			let batch = store.batch_write().unwrap();
			// Bypass the normal header write invariant to model a misindexed
			// persisted record selected by BODY_HEAD.
			batch
				.db
				.put_ser(&mwc_store::to_key(b'h', selected_hash), &header)
				.unwrap();
			batch.commit().unwrap();
		}

		let header_pmmr_handle = chain.get_header_pmmr_for_test();
		let header_pmmr = header_pmmr_handle.read();
		let batch = store.batch_read().unwrap();
		let slow_err = chain
			.body_chain_header_at_height(&batch, &body_head, header.height)
			.unwrap_err();
		let fast_err = chain
			.body_chain_header_at_height_maybe_fast(&header_pmmr, &batch, &body_head, header.height)
			.unwrap_err();
		let batched_membership_err = chain
			.is_on_body_chain_with_batch(&batch, &header, &body_head)
			.unwrap_err();

		for err in [slow_err, fast_err, batched_membership_err] {
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("BODY_HEAD header key/hash mismatch")
						&& msg.contains(&selected_hash.to_string())
						&& msg.contains(&actual_hash.to_string())
			));
		}
		drop(batch);
		drop(header_pmmr);
		drop(header_pmmr_handle);

		let membership_err = chain.is_on_body_chain(&header, body_head).unwrap_err();
		assert!(matches!(
		membership_err,
		Error::InvalidPersistedChainState(msg)
			if msg.contains("BODY_HEAD header key/hash mismatch")
		));

		drop(chain);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn body_chain_fast_lookup_rejects_misindexed_header_head_before_zero_step() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/body_chain_misindexed_header_head_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let store = chain.get_store_for_tests();
		let body_head = chain.head().unwrap();
		let header = chain.genesis();
		let actual_hash = header.hash(0).unwrap();
		let selected_hash = Hash::from_vec(&[7; Hash::LEN]);
		assert_ne!(selected_hash, actual_hash);
		let mut header_head = Tip::try_from_header(&header).unwrap();
		header_head.last_block_h = selected_hash;

		{
			let batch = store.batch_write().unwrap();
			// Bypass the normal header write invariant to model a misindexed
			// persisted record selected by HEADER_HEAD.
			batch
				.db
				.put_ser(&mwc_store::to_key(b'h', selected_hash), &header)
				.unwrap();
			batch.save_header_head(&header_head).unwrap();
			batch.commit().unwrap();
		}

		let header_pmmr_handle = chain.get_header_pmmr_for_test();
		let header_pmmr = header_pmmr_handle.read();
		let batch = store.batch_read().unwrap();
		let err = chain
			.body_chain_header_at_height_maybe_fast(
				&header_pmmr,
				&batch,
				&body_head,
				body_head.height,
			)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("HEADER_HEAD header key/hash mismatch")
					&& msg.contains(&selected_hash.to_string())
					&& msg.contains(&actual_hash.to_string())
		));

		drop(batch);
		drop(header_pmmr);
		drop(header_pmmr_handle);
		drop(chain);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn body_chain_fast_lookup_uses_canonical_header_head_height() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/body_chain_canonical_header_head_height_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let store = chain.get_store_for_tests();
		let genesis = chain.genesis();
		let genesis_hash = genesis.hash(0).unwrap();
		let body_header = retained_test_block(1, genesis_hash, 23).header;
		let body_head = Tip::try_from_header(&body_header).unwrap();
		let mut stale_header_head = Tip::try_from_header(&genesis).unwrap();
		stale_header_head.height = body_header.height;

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&body_header).unwrap();
			batch.save_header_head(&stale_header_head).unwrap();
			batch.commit().unwrap();
		}

		let header_pmmr_handle = chain.get_header_pmmr_for_test();
		let header_pmmr = header_pmmr_handle.read();
		let batch = store.batch_read().unwrap();
		let resolved = chain
			.body_chain_header_at_height_maybe_fast(&header_pmmr, &batch, &body_head, 0)
			.unwrap();
		assert_eq!(resolved, genesis);

		drop(batch);
		drop(header_pmmr);
		drop(header_pmmr_handle);
		drop(chain);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn body_chain_fast_lookup_rejects_target_header_hash_data_split() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/body_chain_fast_target_header_split_{}",
			std::process::id()
		);
		let corrupt_header_dir = format!("{}_corrupt_header", chain_dir);
		let _ = fs::remove_dir_all(&chain_dir);
		let _ = fs::remove_dir_all(&corrupt_header_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let store = chain.get_store_for_tests();
		let context_id = chain.get_context_id();
		let genesis = chain.genesis();
		let genesis_hash = genesis.hash(context_id).unwrap();
		let canonical_target = recovery_test_header(1, genesis_hash, 31);
		let redirected_target = recovery_test_header(1, genesis_hash, 32);
		let body_header = recovery_test_header(2, canonical_target.hash(context_id).unwrap(), 33);
		assert_ne!(
			canonical_target.hash(context_id).unwrap(),
			redirected_target.hash(context_id).unwrap()
		);

		let body_head = Tip::try_from_header(&body_header).unwrap();
		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&canonical_target).unwrap();
			batch.save_block_header(&redirected_target).unwrap();
			batch.save_block_header(&body_header).unwrap();
			batch.save_body_head(&body_head).unwrap();
			batch.save_header_head(&body_head).unwrap();
			batch.commit().unwrap();
		}

		// Keep the canonical leaf hash at height one while redirecting its
		// independently stored HeaderEntry to another same-height header.
		let mut corrupt_header_pmmr = recovery_header_pmmr(&corrupt_header_dir);
		let genesis_leaf_hash = genesis.hash_with_index(context_id, 0).unwrap();
		let canonical_target_leaf_hash = canonical_target.hash_with_index(context_id, 1).unwrap();
		let parent_hash = (genesis_leaf_hash, canonical_target_leaf_hash)
			.hash_with_index(context_id, 2)
			.unwrap();
		let body_leaf_hash = body_header.hash_with_index(context_id, 3).unwrap();
		corrupt_header_pmmr
			.backend
			.append(&genesis, &[genesis_leaf_hash])
			.unwrap();
		corrupt_header_pmmr
			.backend
			.append(
				&redirected_target,
				&[canonical_target_leaf_hash, parent_hash],
			)
			.unwrap();
		corrupt_header_pmmr
			.backend
			.append(&body_header, &[body_leaf_hash])
			.unwrap();
		corrupt_header_pmmr.backend.sync().unwrap();
		corrupt_header_pmmr.size = 4;

		let batch = store.batch_read().unwrap();
		let err = chain
			.body_chain_header_at_height_maybe_fast(
				&corrupt_header_pmmr,
				&batch,
				&body_head,
				canonical_target.height,
			)
			.unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("does not authenticate loaded header")
		));

		drop(batch);
		drop(corrupt_header_pmmr);
		drop(chain);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
		let _ = fs::remove_dir_all(&corrupt_header_dir);
	}

	#[test]
	fn body_chain_lookups_use_canonical_anchor_height() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/body_chain_canonical_anchor_height_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let store = chain.get_store_for_tests();

		let mut predecessor = retained_test_block(4, Hash::from_vec(&[1; Hash::LEN]), 18).header;
		predecessor.output_mmr_size = 10;
		let predecessor_hash = predecessor.hash(chain.get_context_id()).unwrap();
		let mut header = retained_test_block(5, predecessor_hash, 19).header;
		header.output_mmr_size = 12;
		let canonical_head = Tip::try_from_header(&header).unwrap();
		let mut stale_low = canonical_head;
		stale_low.height = header.height - 1;
		let mut stale_high = canonical_head;
		stale_high.height = header.height + 1;
		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&predecessor).unwrap();
			batch.save_block_header(&header).unwrap();
			batch.commit().unwrap();
		}

		assert!(chain.is_on_body_chain(&header, stale_low).unwrap());

		let header_pmmr_handle = chain.get_header_pmmr_for_test();
		let header_pmmr = header_pmmr_handle.read();
		let batch = store.batch_read().unwrap();
		assert_eq!(
			chain
				.body_chain_header_at_height(&batch, &stale_low, header.height)
				.unwrap(),
			header
		);
		assert_eq!(
			chain
				.body_chain_header_at_height_maybe_fast(
					&header_pmmr,
					&batch,
					&stale_low,
					header.height,
				)
				.unwrap(),
			header
		);
		assert!(chain
			.is_on_body_chain_with_batch(&batch, &header, &stale_low)
			.unwrap());
		assert_eq!(
			chain
				.body_chain_header_for_output_pos(
					&header_pmmr,
					&batch,
					&stale_low,
					CommitPos {
						pos: 11,
						height: header.height,
					},
				)
				.unwrap(),
			Some(header.clone())
		);
		assert_eq!(
			chain
				.body_chain_header_for_output_pos(
					&header_pmmr,
					&batch,
					&stale_high,
					CommitPos {
						pos: 13,
						height: header.height + 1,
					},
				)
				.unwrap(),
			None
		);

		let slow_err = chain
			.body_chain_header_at_height(&batch, &stale_high, header.height + 1)
			.unwrap_err();
		let fast_err = chain
			.body_chain_header_at_height_maybe_fast(
				&header_pmmr,
				&batch,
				&stale_high,
				header.height + 1,
			)
			.unwrap_err();
		for err in [slow_err, fast_err] {
			assert!(matches!(
				err,
				Error::ChainInSyncing(msg)
					if msg.contains("body chain head is at 5, below requested height 6")
			));
		}

		drop(batch);
		drop(header_pmmr);
		drop(header_pmmr_handle);
		drop(chain);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn missing_head_freshness_rejects_auxiliary_cache_state() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/missing_head_auxiliary_cache_state_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = Arc::new(ChainStore::new(0, &chain_dir).unwrap());

		// The block migration runs before setup_head and writes this flag even for
		// a genuinely unused database, so it must remain an allowed fresh state.
		{
			let batch = store.batch_write().unwrap();
			batch.set_blocks_v3_migrated(true).unwrap();
			batch.commit().unwrap();
		}
		let header_pmmr = recovery_header_pmmr(&chain_dir);
		let txhashset = TxHashSet::open(chain_dir.clone(), store.clone(), None, &secp).unwrap();
		{
			let batch = store.batch_read().unwrap();
			ensure_missing_head_is_fresh(&batch, &header_pmmr, &txhashset).unwrap();
		}

		// A derived index record proves prior chain use even if its completeness
		// flag is absent and all authoritative selectors have been lost.
		let stale_commit = secp.commit_value(42).unwrap();
		{
			let batch = store.batch_write().unwrap();
			batch
				.save_output_pos_height(&stale_commit, CommitPos { pos: 1, height: 1 })
				.unwrap();
			batch.commit().unwrap();
		}
		{
			let batch = store.batch_read().unwrap();
			let err = ensure_missing_head_is_fresh(&batch, &header_pmmr, &txhashset).unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(ref msg)
					if msg.contains("persisted auxiliary chain records or cache flags")
			));
		}

		// The existence of a completeness flag is itself evidence, including a
		// false value that would otherwise decode to the default fresh value.
		{
			let batch = store.batch_write().unwrap();
			batch.delete_output_pos_height(&stale_commit).unwrap();
			batch.set_output_pos_index_complete(false).unwrap();
			batch.commit().unwrap();
		}
		{
			let batch = store.batch_read().unwrap();
			let err = ensure_missing_head_is_fresh(&batch, &header_pmmr, &txhashset).unwrap_err();
			assert!(matches!(
				err,
				Error::InvalidPersistedChainState(ref msg)
					if msg.contains("persisted auxiliary chain records or cache flags")
			));
		}

		drop(txhashset);
		drop(header_pmmr);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn setup_head_rejects_missing_head_in_used_store_without_resetting() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!("target/setup_head_missing_used_head_{}", std::process::id());
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		let genesis_hash = genesis.hash(0).unwrap();
		let original_header_head = chain.header_head().unwrap();
		let header_size_before = chain.header_pmmr.read().size;
		let body_sizes_before = {
			let txhashset = chain.txhashset.read();
			(
				txhashset.output_mmr_size(),
				txhashset.rangeproof_mmr_size(),
				txhashset.kernel_mmr_size(),
			)
		};

		// Model loss of the authoritative HEAD selector in an otherwise used
		// store. This must not be mistaken for first-run initialization.
		{
			let batch = chain.store.batch_write().unwrap();
			batch.delete(&[b'H']).unwrap();
			batch.commit().unwrap();
		}
		drop(chain);

		let restart_err = match Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		) {
			Ok(_) => panic!("startup treated a used store with missing HEAD as fresh"),
			Err(err) => err,
		};
		assert!(matches!(
			&restart_err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("HEAD is missing from non-fresh chain state")
					&& msg.contains("Automatic genesis rebuild is disabled")
		));

		let store = Arc::new(ChainStore::new(0, &chain_dir).unwrap());
		assert!(matches!(store.head(), Err(NotFoundErr(_))));
		assert_eq!(store.header_head().unwrap(), original_header_head);
		assert!(store.block_exists(&genesis_hash).unwrap());
		assert!(store.pending_chain_operation().unwrap().is_none());
		let header_pmmr = recovery_header_pmmr(&chain_dir);
		let txhashset = TxHashSet::open(chain_dir.clone(), store.clone(), None, &secp).unwrap();
		assert_eq!(header_pmmr.size, header_size_before);
		assert_eq!(
			(
				txhashset.output_mmr_size(),
				txhashset.rangeproof_mmr_size(),
				txhashset.kernel_mmr_size(),
			),
			body_sizes_before
		);

		drop(txhashset);
		drop(header_pmmr);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn setup_head_rejects_header_pmmr_hash_data_split() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/setup_head_header_hash_data_split_{}",
			std::process::id()
		);
		let corrupt_header_dir = format!("{}_corrupt_header", chain_dir);
		let _ = fs::remove_dir_all(&chain_dir);
		let _ = fs::remove_dir_all(&corrupt_header_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();

		// Keep the proof-derived HeaderEntry valid while storing a different PMMR
		// leaf hash. The lightweight head checks accept this split representation;
		// persisted-ancestry validation must reject it during ordinary startup.
		let mut corrupt_header_pmmr = recovery_header_pmmr(&corrupt_header_dir);
		let expected_leaf_hash = genesis.header.hash_with_index(0, 0).unwrap();
		let corrupt_leaf_hash = Hash::from_vec(&[42; Hash::LEN]);
		assert_ne!(corrupt_leaf_hash, expected_leaf_hash);
		corrupt_header_pmmr
			.backend
			.append(&genesis.header, &[corrupt_leaf_hash])
			.unwrap();
		corrupt_header_pmmr.backend.sync().unwrap();
		corrupt_header_pmmr.size = 1;

		let err = {
			let mut txhashset = chain.txhashset.write();
			setup_head(
				&genesis,
				&chain.store,
				&mut corrupt_header_pmmr,
				&mut txhashset,
				&secp,
				pow::verify_size,
				None,
				false,
				None,
			)
			.unwrap_err()
		};
		assert!(
			matches!(
				&err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("does not authenticate authoritative header")
			),
			"unexpected startup error: {:?}",
			err
		);

		drop(corrupt_header_pmmr);
		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
		let _ = fs::remove_dir_all(&corrupt_header_dir);
	}

	#[test]
	fn setup_head_persisted_ancestry_validation_honors_stop_state() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/setup_head_stopped_ancestry_validation_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let stop_state = Arc::new(StopState::new());
		stop_state.stop();

		let err = {
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			setup_head(
				&chain.genesis,
				&chain.store,
				&mut header_pmmr,
				&mut txhashset,
				&secp,
				pow::verify_size,
				Some(stop_state),
				false,
				None,
			)
			.unwrap_err()
		};
		assert!(matches!(err, Error::Stopped));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn setup_head_requires_durable_head_full_block() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/setup_head_requires_durable_head_block_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let genesis = chain.genesis.clone();
		let genesis_hash = genesis.hash(0).unwrap();
		{
			let batch = chain.store.batch_write().unwrap();
			batch
				.delete(&mwc_store::to_key(b'b', genesis_hash))
				.unwrap();
			batch.commit().unwrap();
		}

		let err = {
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			setup_head(
				&genesis,
				&chain.store,
				&mut header_pmmr,
				&mut txhashset,
				&secp,
				pow::verify_size,
				None,
				false,
				None,
			)
			.unwrap_err()
		};
		assert!(matches!(
			err,
			Error::StoreErr(_, context)
				if context.contains("setup_head durable HEAD preflight load full block")
		));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn startup_body_validation_rejects_corruption_unless_skipped() {
		let chain_dir = format!(
			"target/setup_head_body_hash_data_split_{}",
			std::process::id()
		);
		clean_output_dir(&chain_dir);
		let chain = mine_chain(&chain_dir, 1);
		let genesis = chain.genesis.clone();
		let head_hash = chain.head().unwrap().last_block_h;
		assert!(chain.store.get_block_sums(&head_hash).is_ok());
		drop(chain);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let replacement_commit = secp.commit_value(42).unwrap();
		let replacement_output = OutputIdentifier::new(
			genesis.outputs()[0].identifier().features,
			&replacement_commit,
		);
		let mut replacement_bytes = Vec::new();
		ser::serialize(
			&mut replacement_bytes,
			ProtocolVersion(1),
			0,
			&replacement_output,
		)
		.unwrap();
		let output_data_path = Path::new(&chain_dir)
			.join("txhashset")
			.join("output")
			.join("pmmr_data.bin");
		let mut output_data = OpenOptions::new()
			.write(true)
			.open(&output_data_path)
			.unwrap();
		assert_eq!(
			output_data.metadata().unwrap().len(),
			u64::try_from(replacement_bytes.len()).unwrap()
		);
		output_data.seek(SeekFrom::Start(0)).unwrap();
		output_data.write_all(&replacement_bytes).unwrap();
		output_data.sync_all().unwrap();
		drop(output_data);

		let err = match Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis.clone(),
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		) {
			Ok(_) => panic!("startup accepted split body PMMR data and hashes"),
			Err(err) => err,
		};
		assert!(
			matches!(
				&err,
				Error::PMMRErr(pmmr::Error::DataCorruption(msg))
					if msg.contains("leaf data") && msg.contains("stored hash")
			),
			"unexpected body PMMR validation error: {:?}",
			err
		);

		let restarted = Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			true,
		)
		.unwrap();
		assert_eq!(restarted.head().unwrap().last_block_h, head_hash);
		drop(restarted);

		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn setup_head_rejects_complete_output_pos_index_missing_utxo() {
		let chain_dir = format!(
			"target/setup_head_missing_complete_output_pos_{}",
			std::process::id()
		);
		clean_output_dir(&chain_dir);
		let chain = mine_chain(&chain_dir, 1);
		let genesis = chain.genesis.clone();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let genesis_commit = genesis.outputs()[0].commitment();

		{
			let batch = chain.store.batch_write().unwrap();
			batch.delete_output_pos_height(&genesis_commit).unwrap();
			// Model a corrupted cache whose durable completeness assertion was
			// left intact. Startup must not trust the flag without checking the
			// index bidirectionally against the UTXO leaf set.
			batch.set_output_pos_index_complete(true).unwrap();
			batch.commit().unwrap();
		}

		let err = {
			let mut header_pmmr = chain.header_pmmr.write();
			let mut txhashset = chain.txhashset.write();
			setup_head(
				&genesis,
				&chain.store,
				&mut header_pmmr,
				&mut txhashset,
				&secp,
				pow::verify_size,
				None,
				false,
				None,
			)
			.unwrap_err()
		};
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("UTXO leaf") && msg.contains("has no committed output_pos entry")
		));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn setup_head_rebuilds_existing_block_sums_from_validated_txhashset() {
		let chain_dir = format!(
			"target/setup_head_rebuilds_block_sums_{}",
			std::process::id()
		);
		clean_output_dir(&chain_dir);
		let chain = mine_chain(&chain_dir, 1);
		let genesis = chain.genesis.clone();
		let head_hash = chain.head().unwrap().last_block_h;
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let expected = genesis_block_sums(&genesis, 0, &secp).unwrap();
		let corrupt = BlockSums::new(
			secp.commit_value(41).unwrap(),
			secp.commit_value(42).unwrap(),
		);
		let mut expected_bytes = Vec::new();
		ser::serialize_default(0, &mut expected_bytes, &expected).unwrap();
		let mut corrupt_bytes = Vec::new();
		ser::serialize_default(0, &mut corrupt_bytes, &corrupt).unwrap();
		assert_ne!(corrupt_bytes, expected_bytes);
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_block_sums(&head_hash, corrupt).unwrap();
			batch.commit().unwrap();
		}
		drop(chain);

		let restarted = Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap();
		let rebuilt = restarted.store.get_block_sums(&head_hash).unwrap();
		let mut rebuilt_bytes = Vec::new();
		ser::serialize_default(0, &mut rebuilt_bytes, &rebuilt).unwrap();
		assert_eq!(rebuilt_bytes, expected_bytes);

		drop(restarted);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn setup_head_rejects_same_hash_altered_stored_genesis_header() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/setup_head_rejects_altered_genesis_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let genesis = global::get_genesis_block(&secp, 0).unwrap();
		let genesis_hash = genesis.hash(0).unwrap();
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let store = chain.get_store_for_tests();
		let mut altered = genesis.header.clone();
		altered.height = 1;
		assert_eq!(altered.hash(0).unwrap(), genesis_hash);
		assert_ne!(altered, genesis.header);

		{
			let batch = store.batch_write().unwrap();
			// Bypass the ChainStore overwrite guard to model raw persisted-state
			// corruption discovered during initialization.
			batch
				.db
				.put_ser(&mwc_store::to_key(b'h', genesis_hash), &altered)
				.unwrap();
			batch.commit().unwrap();
		}
		drop(chain);
		drop(store);

		let err = match Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		) {
			Ok(_) => panic!("altered stored genesis header was accepted"),
			Err(err) => err,
		};
		// The rejection point depends on init ordering: canonical spent-index
		// traversal can reject the impossible height-one genesis ancestry before
		// setup_head compares the stored header against configured genesis.
		assert!(
			matches!(
				&err,
				Error::InvalidPersistedChainState(msg)
					if msg.contains("does not exactly match configured genesis")
						|| msg.contains("header differs from the separately stored header")
						|| msg.contains("is missing predecessor")
			),
			"unexpected error: {:?}",
			err
		);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn setup_head_repairs_header_and_body_tip_caches_from_headers() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/setup_head_repairs_tip_caches_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = init_automated_test_chain(&chain_dir, &secp);
		let expected_header_head = chain.header_head().unwrap();
		let expected_body_head = chain.head().unwrap();
		let store = chain.get_store_for_tests();
		let corrupt_prev = Hash::from_vec(&[7; Hash::LEN]);

		{
			let batch = store.batch_write().unwrap();
			let mut header_head = expected_header_head;
			header_head.prev_block_h = corrupt_prev;
			header_head.total_difficulty = mwc_core::pow::Difficulty::from_num(
				header_head.total_difficulty.to_num().saturating_add(1),
			);
			let mut body_head = expected_body_head;
			body_head.prev_block_h = corrupt_prev;
			body_head.total_difficulty = mwc_core::pow::Difficulty::from_num(
				body_head.total_difficulty.to_num().saturating_add(1),
			);
			batch.save_header_head(&header_head).unwrap();
			batch.save_body_head(&body_head).unwrap();
			batch.commit().unwrap();
		}
		drop(chain);
		drop(store);

		let restarted = init_automated_test_chain(&chain_dir, &secp);
		assert_eq!(restarted.header_head().unwrap(), expected_header_head);
		assert_eq!(restarted.head().unwrap(), expected_body_head);

		drop(restarted);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	fn test_spent_commitment_record(hash: Hash, height: u64) -> SpentCommitmentRecord {
		SpentCommitmentRecord {
			spending_block: HashHeight { hash, height },
			spent_output: CommitPos { pos: 1, height: 0 },
		}
	}

	#[test]
	fn init_spent_commitment_index_rebuilds_from_retained_blocks() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_spent_commitment_index_rebuilds_from_retained_blocks_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let reused_commitment = secp.commit_value(17).unwrap();

		let genesis = Block::default(0);
		let mut block = retained_test_block(1, genesis.hash(0).unwrap(), 2);
		block.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, reused_commitment)]);
		let block_hash = block.hash(0).unwrap();
		let cached_old_occurrence = CommitPos { pos: 1, height: 0 };

		{
			let batch = store.batch_write().unwrap();
			for canonical_block in [&genesis, &block] {
				batch.save_block_header(&canonical_block.header).unwrap();
				batch.save_block(canonical_block).unwrap();
			}
			batch
				.save_body_head(&Tip::try_from_header(&block.header).unwrap())
				.unwrap();
			batch
				.save_body_tail(&Tip::try_from_header(&block.header).unwrap())
				.unwrap();
			// The per-block spent index is the position source for the rebuild.
			batch
				.save_spent_index(
					&block_hash,
					&[SpentOutput {
						commitment: reused_commitment,
						position: cached_old_occurrence,
					}],
				)
				.unwrap();
			// A stale conflicting record must be cleared before the rebuild
			// rewrites the exact occurrence from the retained block.
			batch
				.save_spent_commitments(
					&reused_commitment,
					SpentCommitmentRecord {
						spending_block: HashHeight {
							hash: block_hash,
							height: block.header.height,
						},
						spent_output: CommitPos { pos: 99, height: 5 },
					},
				)
				.unwrap();
			// The completeness flag is unset, e.g. after a crash or an upgrade
			// from a version without the index.
			batch.commit().unwrap();
		}

		Chain::init_spent_commitment_index(&store, None).unwrap();
		let batch = store.batch_read().unwrap();
		assert!(batch.is_spent_commitment_record_index_complete().unwrap());
		assert_eq!(
			batch.get_spent_commitments(&reused_commitment).unwrap(),
			Some(vec![SpentCommitmentRecord {
				spending_block: HashHeight {
					hash: block_hash,
					height: block.header.height,
				},
				spent_output: cached_old_occurrence,
			}])
		);

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rebuild_uses_body_chain_only() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_spent_commitment_index_rebuild_uses_body_chain_only_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let canonical_commitment = secp.commit_value(61).unwrap();
		let fork_commitment = secp.commit_value(62).unwrap();

		let genesis = Block::default(0);
		let genesis_hash = genesis.hash(0).unwrap();
		let mut canonical_1 = retained_test_block(1, genesis_hash, 61);
		canonical_1.body.inputs = Inputs::FeaturesAndCommit(vec![Input::new(
			OutputFeatures::Plain,
			canonical_commitment,
		)]);
		let canonical_1_hash = canonical_1.hash(0).unwrap();
		let canonical_2 = retained_test_block(2, canonical_1_hash, 63);

		let mut header_fork_1 = retained_test_block(1, genesis_hash, 71);
		header_fork_1.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, fork_commitment)]);
		let header_fork_2 = retained_test_block(2, header_fork_1.hash(0).unwrap(), 72);

		{
			let batch = store.batch_write().unwrap();
			for block in [
				&genesis,
				&canonical_1,
				&canonical_2,
				&header_fork_1,
				&header_fork_2,
			] {
				batch.save_block_header(&block.header).unwrap();
				batch.save_block(block).unwrap();
			}
			batch
				.save_body_head(&Tip::try_from_header(&canonical_2.header).unwrap())
				.unwrap();
			// Deliberately select the competing branch as HEADER_HEAD. Rebuild
			// canonicality must still come exclusively from body HEAD ancestry.
			batch
				.save_header_head(&Tip::try_from_header(&header_fork_2.header).unwrap())
				.unwrap();
			batch
				.save_spent_index(
					&canonical_1_hash,
					&[SpentOutput {
						commitment: canonical_commitment,
						position: CommitPos { pos: 1, height: 0 },
					}],
				)
				.unwrap();
			// No spent index is saved for header_fork_1. Scanning all retained
			// bodies would fail here; a body-chain-only rebuild never loads it.
			batch.commit().unwrap();
		}

		Chain::init_spent_commitment_index(&store, None).unwrap();
		let batch = store.batch_read().unwrap();
		assert!(batch.is_spent_commitment_record_index_complete().unwrap());
		assert!(batch
			.get_spent_commitments(&canonical_commitment)
			.unwrap()
			.is_some());
		assert_eq!(batch.get_spent_commitments(&fork_commitment).unwrap(), None);

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rebuild_uses_canonical_head_height() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_spent_commitment_index_rebuild_uses_canonical_head_height_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let spent_commitment = secp.commit_value(29).unwrap();
		let genesis = Block::default(0);
		let mut block = retained_test_block(1, genesis.hash(0).unwrap(), 29);
		block.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, spent_commitment)]);
		let block_hash = block.hash(0).unwrap();
		let spent_output = CommitPos { pos: 1, height: 0 };

		{
			let batch = store.batch_write().unwrap();
			for canonical_block in [&genesis, &block] {
				batch.save_block_header(&canonical_block.header).unwrap();
				batch.save_block(canonical_block).unwrap();
			}
			let mut cached_head = Tip::try_from_header(&block.header).unwrap();
			cached_head.height = 0;
			batch.save_body_head(&cached_head).unwrap();
			batch
				.save_spent_index(
					&block_hash,
					&[SpentOutput {
						commitment: spent_commitment,
						position: spent_output,
					}],
				)
				.unwrap();
			// Stale record with a corrupted height; the rebuild clears it and
			// recreates the record from the retained block.
			batch
				.save_spent_commitments(
					&spent_commitment,
					test_spent_commitment_record(block_hash, 0),
				)
				.unwrap();
			batch.commit().unwrap();
		}

		// The persisted Tip height is corrupted to 0. The canonical head is
		// selected by `last_block_h`, so its real height drives a rebuild rather
		// than the genesis empty-index path.
		Chain::init_spent_commitment_index(&store, None).unwrap();
		let batch = store.batch_read().unwrap();
		assert!(batch.is_spent_commitment_record_index_complete().unwrap());
		assert_eq!(
			batch.get_spent_commitments(&spent_commitment).unwrap(),
			Some(vec![SpentCommitmentRecord {
				spending_block: HashHeight {
					hash: block_hash,
					height: block.header.height,
				},
				spent_output,
			}])
		);

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rebuild_rejects_spent_index_body_mismatch() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_spent_commitment_index_rebuild_rejects_spent_index_body_mismatch_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let body_commitment = secp.commit_value(31).unwrap();
		let cached_commitment = secp.commit_value(32).unwrap();

		let genesis = Block::default(0);
		let mut block = retained_test_block(1, genesis.hash(0).unwrap(), 31);
		block.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, body_commitment)]);
		let block_hash = block.hash(0).unwrap();

		{
			let batch = store.batch_write().unwrap();
			for canonical_block in [&genesis, &block] {
				batch.save_block_header(&canonical_block.header).unwrap();
				batch.save_block(canonical_block).unwrap();
			}
			batch
				.save_body_head(&Tip::try_from_header(&block.header).unwrap())
				.unwrap();
			// The cached spent index disagrees with the authenticated body.
			// Local corruption must abort the rebuild instead of being promoted
			// into the trusted index.
			batch
				.save_spent_index(
					&block_hash,
					&[SpentOutput {
						commitment: cached_commitment,
						position: CommitPos { pos: 1, height: 0 },
					}],
				)
				.unwrap();
			batch.commit().unwrap();
		}

		let err = Chain::init_spent_commitment_index(&store, None).unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("contains commitment") && msg.contains("not a body input")
		));
		let batch = store.batch_read().unwrap();
		assert!(!batch.is_spent_commitment_record_index_complete().unwrap());

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rebuild_skips_blocks_below_horizon_window() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_spent_commitment_index_rebuild_skips_blocks_below_horizon_window_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let old_commitment = secp.commit_value(41).unwrap();
		let recent_commitment = secp.commit_value(42).unwrap();

		// The testing horizon is 70 blocks. With the head at height 100 the
		// rebuild window starts at height 30. Retain the complete body history to
		// model an archive node; the rebuild must load only heights 31 through 100.
		let mut canonical_blocks = vec![Block::default(0)];
		let mut prev_hash = canonical_blocks[0].hash(0).unwrap();
		for height in 1..=100 {
			let mut block = retained_test_block(height, prev_hash, 100 + height);
			if height == 2 {
				block.body.inputs = Inputs::FeaturesAndCommit(vec![Input::new(
					OutputFeatures::Plain,
					old_commitment,
				)]);
			} else if height == 50 {
				block.body.inputs = Inputs::FeaturesAndCommit(vec![Input::new(
					OutputFeatures::Plain,
					recent_commitment,
				)]);
			}
			prev_hash = block.hash(0).unwrap();
			canonical_blocks.push(block);
		}
		let old_block = &canonical_blocks[2];
		let old_hash = old_block.hash(0).unwrap();
		let recent_block = &canonical_blocks[50];
		let recent_hash = recent_block.hash(0).unwrap();
		let head_block = &canonical_blocks[100];
		let head_hash = head_block.hash(0).unwrap();

		{
			let batch = store.batch_write().unwrap();
			for block in &canonical_blocks {
				batch.save_block_header(&block.header).unwrap();
				batch.save_block(block).unwrap();
			}
			// Make one archived body below the horizon unreadable. A global
			// BLOCK_PREFIX iterator would deserialize it and fail; a bounded body
			// ancestry rebuild never touches the record.
			batch
				.db
				.put(&mwc_store::to_key(b'b', old_hash), &[1])
				.unwrap();
			batch
				.save_spent_index(
					&old_hash,
					&[SpentOutput {
						commitment: old_commitment,
						position: CommitPos { pos: 1, height: 0 },
					}],
				)
				.unwrap();
			batch
				.save_spent_index(
					&recent_hash,
					&[SpentOutput {
						commitment: recent_commitment,
						position: CommitPos { pos: 2, height: 1 },
					}],
				)
				.unwrap();
			batch.save_spent_index(&head_hash, &[]).unwrap();
			batch
				.save_body_head(&Tip::try_from_header(&head_block.header).unwrap())
				.unwrap();
			batch.commit().unwrap();
		}

		Chain::init_spent_commitment_index(&store, None).unwrap();
		let batch = store.batch_read().unwrap();
		assert!(batch.is_spent_commitment_record_index_complete().unwrap());
		// Below the window: no record is rebuilt even though the block and its
		// spent index are still retained (archive-node behavior).
		assert_eq!(batch.get_spent_commitments(&old_commitment).unwrap(), None);
		// Inside the window: the record is rebuilt from the retained block.
		assert_eq!(
			batch.get_spent_commitments(&recent_commitment).unwrap(),
			Some(vec![SpentCommitmentRecord {
				spending_block: HashHeight {
					hash: recent_hash,
					height: recent_block.header.height,
				},
				spent_output: CommitPos { pos: 2, height: 1 },
			}])
		);

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rebuild_rejects_legacy_spent_index() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_spent_commitment_index_rebuild_rejects_legacy_spent_index_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();

		let genesis = Block::default(0);
		let mut block = retained_test_block(1, genesis.hash(0).unwrap(), 51);
		block.body.inputs = Inputs::FeaturesAndCommit(vec![
			Input::new(OutputFeatures::Plain, secp.commit_value(51).unwrap()),
			Input::new(OutputFeatures::Plain, secp.commit_value(52).unwrap()),
		]);
		let block_hash = block.hash(0).unwrap();

		{
			let batch = store.batch_write().unwrap();
			for canonical_block in [&genesis, &block] {
				batch.save_block_header(&canonical_block.header).unwrap();
				batch.save_block(canonical_block).unwrap();
			}
			batch
				.save_body_head(&Tip::try_from_header(&block.header).unwrap())
				.unwrap();
			// Positions-only entry written by a pre-upgrade version. The rebuild
			// must fail loudly; migrate_spent_index converts
			// these entries before the rebuild runs.
			batch
				.save_spent_index_legacy(
					&block_hash,
					&[
						CommitPos { pos: 1, height: 0 },
						CommitPos { pos: 2, height: 0 },
					],
				)
				.unwrap();
			batch.commit().unwrap();
		}

		let err = Chain::init_spent_commitment_index(&store, None).unwrap_err();
		assert!(matches!(err, Error::StoreErr(..)));
		let batch = store.batch_read().unwrap();
		assert!(!batch.is_spent_commitment_record_index_complete().unwrap());

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn replay_attack_check_fails_when_spent_commitment_index_incomplete() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/replay_attack_check_fails_when_spent_commitment_index_incomplete_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			global::get_genesis_block(&secp, 0).unwrap(),
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap();

		{
			let store = chain.get_store_for_tests();
			let batch = store.batch_write().unwrap();
			batch
				.set_spent_commitment_record_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		let err = chain
			.replay_attack_check(&Transaction::empty())
			.unwrap_err();
		assert!(matches!(err, Error::SpentCommitmentIndexIncomplete));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_empty_spent_commitment_record_index_clears_stale_entries_without_body_tail() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_empty_spent_commitment_record_index_clears_stale_entries_without_body_tail_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let stale_commit = secp.commit_value(8).unwrap();
		let block = retained_test_block(9, Hash::from_vec(&[1; Hash::LEN]), 1);
		let tip = Tip::try_from_header(&block.header).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&block.header).unwrap();
			batch.save_body_head(&tip).unwrap();
			batch
				.save_spent_commitments(
					&stale_commit,
					test_spent_commitment_record(Hash::from_vec(&[9; Hash::LEN]), 99),
				)
				.unwrap();
			batch
				.set_spent_commitment_record_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		Chain::init_empty_spent_commitment_record_index(&store).unwrap();

		let batch = store.batch_read().unwrap();
		assert!(batch.tail().is_err());
		assert!(batch.is_spent_commitment_record_index_complete().unwrap());
		assert!(batch
			.get_spent_commitments(&stale_commit)
			.unwrap()
			.is_none());

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn orphan_pool_merges_source_peers_for_duplicate_block() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let pool = OrphanBlockPool::new(Arc::new(PibdParams::new()));
		let block = Block::default(0);
		let hash = block.hash(0).unwrap();

		let mut first_peers = HashSet::new();
		first_peers.insert("127.0.0.1:3414".to_string());
		pool.add(
			0,
			Orphan {
				block: block.clone(),
				opts: Options::NONE,
				source_peers: first_peers,
				added: Instant::now(),
			},
		)
		.unwrap();

		let mut second_peers = HashSet::new();
		second_peers.insert("127.0.0.2:3414".to_string());
		pool.add(
			0,
			Orphan {
				block,
				opts: Options::NONE,
				source_peers: second_peers,
				added: Instant::now(),
			},
		)
		.unwrap();

		let orphan = pool.get_orphan(&hash).unwrap();
		assert_eq!(orphan.source_peers.len(), 2);
		assert!(orphan.source_peers.contains("127.0.0.1:3414"));
		assert!(orphan.source_peers.contains("127.0.0.2:3414"));

		let orphans = pool.remove_by_height(orphan.block.header.height).unwrap();
		assert_eq!(orphans.len(), 1);
	}

	#[test]
	fn orphan_pool_caps_source_peers_on_first_insert() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let pool = OrphanBlockPool::new(Arc::new(PibdParams::new()));
		let block = Block::default(0);
		let hash = block.hash(0).unwrap();
		let source_peers = (0..MAX_ORPHAN_SOURCE_PEERS + 2)
			.map(|idx| format!("peer-{}", idx))
			.collect();

		pool.add(
			0,
			Orphan {
				block,
				opts: Options::NONE,
				source_peers,
				added: Instant::now(),
			},
		)
		.unwrap();

		let orphan = pool.get_orphan(&hash).unwrap();
		assert_eq!(orphan.source_peers.len(), MAX_ORPHAN_SOURCE_PEERS);
	}

	#[test]
	fn orphan_pool_caps_source_peers_for_duplicate_block() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let pool = OrphanBlockPool::new(Arc::new(PibdParams::new()));
		let block = Block::default(0);
		let hash = block.hash(0).unwrap();

		for idx in 0..MAX_ORPHAN_SOURCE_PEERS + 2 {
			let source_peer = format!("peer-{}", idx);
			pool.add(
				0,
				Orphan {
					block: block.clone(),
					opts: Options::NONE,
					source_peers: std::iter::once(source_peer).collect(),
					added: Instant::now(),
				},
			)
			.unwrap();
		}

		let orphan = pool.get_orphan(&hash).unwrap();
		assert_eq!(orphan.source_peers.len(), MAX_ORPHAN_SOURCE_PEERS);
		for idx in 0..MAX_ORPHAN_SOURCE_PEERS {
			assert!(orphan.source_peers.contains(&format!("peer-{}", idx)));
		}
		assert!(!orphan
			.source_peers
			.contains(&format!("peer-{}", MAX_ORPHAN_SOURCE_PEERS)));
	}

	#[test]
	fn orphan_pool_rejects_conflicting_body_for_same_header_hash() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let pool = OrphanBlockPool::new(Arc::new(PibdParams::new()));
		let block = Block::default(0);
		let hash = block.hash(0).unwrap();

		let mut first_peers = HashSet::new();
		first_peers.insert("127.0.0.1:3414".to_string());
		pool.add(
			0,
			Orphan {
				block,
				opts: Options::NONE,
				source_peers: first_peers,
				added: Instant::now(),
			},
		)
		.unwrap();

		let mut conflicting_block = Block::default(0);
		conflicting_block.body.outputs.push(Output {
			identifier: test_output_identifier(),
			proof: test_rangeproof(),
		});

		let mut second_peers = HashSet::new();
		second_peers.insert("127.0.0.2:3414".to_string());
		let err = pool
			.add(
				0,
				Orphan {
					block: conflicting_block,
					opts: Options::NONE,
					source_peers: second_peers,
					added: Instant::now(),
				},
			)
			.unwrap_err();

		match err {
			Error::Unfit(msg) => {
				assert_eq!(msg, "conflicting orphan body for header");
			}
			e => panic!("expected conflicting orphan body error, got {:?}", e),
		}

		let orphan = pool.get_orphan(&hash).unwrap();
		assert_eq!(orphan.source_peers.len(), 1);
		assert!(orphan.source_peers.contains("127.0.0.1:3414"));
		assert!(orphan.block.body.outputs.is_empty());
	}

	#[test]
	fn orphan_pool_rejects_conflicting_input_features_for_same_header_hash() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let pool = OrphanBlockPool::new(Arc::new(PibdParams::new()));
		let mut block = Block::default(0);
		block.body.inputs = Inputs::FeaturesAndCommit(vec![test_input(OutputFeatures::Plain)]);
		let hash = block.hash(0).unwrap();

		let mut first_peers = HashSet::new();
		first_peers.insert("127.0.0.1:3414".to_string());
		pool.add(
			0,
			Orphan {
				block,
				opts: Options::NONE,
				source_peers: first_peers,
				added: Instant::now(),
			},
		)
		.unwrap();

		// Same header and same input commitment, but different input features.
		// Full-data serialization at the local protocol version converts
		// feature-bearing inputs into commit-only wrappers and would treat
		// this body as a duplicate, merging the honest sender into the
		// poisoned entry's source_peers. When the poisoned body later fails
		// validation as bad data, every merged source peer is reported via
		// block_rejected and banned.
		let mut conflicting_block = Block::default(0);
		conflicting_block.body.inputs =
			Inputs::FeaturesAndCommit(vec![test_input(OutputFeatures::Coinbase)]);

		let mut second_peers = HashSet::new();
		second_peers.insert("127.0.0.2:3414".to_string());
		let err = pool
			.add(
				0,
				Orphan {
					block: conflicting_block,
					opts: Options::NONE,
					source_peers: second_peers,
					added: Instant::now(),
				},
			)
			.unwrap_err();

		match err {
			Error::Unfit(msg) => {
				assert_eq!(msg, "conflicting orphan body for header");
			}
			e => panic!("expected conflicting orphan body error, got {:?}", e),
		}

		let orphan = pool.get_orphan(&hash).unwrap();
		assert_eq!(orphan.source_peers.len(), 1);
		assert!(orphan.source_peers.contains("127.0.0.1:3414"));
		match &orphan.block.body.inputs {
			Inputs::FeaturesAndCommit(inputs) => {
				assert_eq!(inputs.len(), 1);
				assert!(inputs[0].is_plain());
			}
			_ => panic!("expected feature-bearing inputs"),
		}
	}

	#[test]
	fn orphan_pool_rejects_mismatched_inputs_variant_for_same_header_hash() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let pool = OrphanBlockPool::new(Arc::new(PibdParams::new()));
		let mut block = Block::default(0);
		block.body.inputs = Inputs::CommitOnly(vec![CommitWrapper::from(
			test_input(OutputFeatures::Plain).commitment(),
		)]);
		let hash = block.hash(0).unwrap();

		let mut first_peers = HashSet::new();
		first_peers.insert("127.0.0.1:3414".to_string());
		pool.add(
			0,
			Orphan {
				block,
				opts: Options::NONE,
				source_peers: first_peers,
				added: Instant::now(),
			},
		)
		.unwrap();

		// Same header and same input commitment, but the feature-bearing
		// variant. Commit-only and feature-bearing inputs must never be
		// deduplicated against each other: the lossy protocol-versioned
		// serialization erases the variant distinction, opening the same
		// source-peer misattribution vector as an input-features mismatch.
		let mut conflicting_block = Block::default(0);
		conflicting_block.body.inputs =
			Inputs::FeaturesAndCommit(vec![test_input(OutputFeatures::Plain)]);

		let mut second_peers = HashSet::new();
		second_peers.insert("127.0.0.2:3414".to_string());
		let err = pool
			.add(
				0,
				Orphan {
					block: conflicting_block,
					opts: Options::NONE,
					source_peers: second_peers,
					added: Instant::now(),
				},
			)
			.unwrap_err();

		match err {
			Error::Unfit(msg) => {
				assert_eq!(msg, "conflicting orphan body for header");
			}
			e => panic!("expected conflicting orphan body error, got {:?}", e),
		}

		let orphan = pool.get_orphan(&hash).unwrap();
		assert_eq!(orphan.source_peers.len(), 1);
		assert!(orphan.source_peers.contains("127.0.0.1:3414"));
		match &orphan.block.body.inputs {
			Inputs::CommitOnly(inputs) => assert_eq!(inputs.len(), 1),
			_ => panic!("expected commit-only inputs"),
		}
	}

	#[test]
	fn compact_eligibility_uses_tail_head_threshold() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let context_id = 0;
		let tail_height = 100;
		let horizon = global::cut_through_horizon(context_id) as u64;
		let next_compact = tail_height + horizon + horizon / 10;

		assert_eq!(
			Chain::compact_eligibility_for_heights(context_id, tail_height, next_compact - 1)
				.unwrap(),
			(false, next_compact)
		);
		assert_eq!(
			Chain::compact_eligibility_for_heights(context_id, tail_height, next_compact).unwrap(),
			(true, next_compact)
		);
	}

	#[test]
	fn compact_eligibility_uses_headers_selected_by_head_and_tail() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/compact_eligibility_canonical_tips_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = mine_chain(&chain_dir, 78);

		let canonical_head = chain.store.head().unwrap();
		let horizon = u64::from(global::cut_through_horizon(0));
		let target_height = canonical_head.height.saturating_sub(horizon);
		let canonical_tail_header = chain.get_header_by_height(target_height + 1).unwrap();
		let canonical_tail = Tip::try_from_header(&canonical_tail_header).unwrap();
		assert!(target_height < canonical_tail.height);

		// Corrupt only the redundant cached heights. The selected headers remain
		// authoritative. The old raw-height calculation deemed this eligible and
		// selected a target below the header selected by BODY_TAIL.
		let mut stale_head = canonical_head;
		stale_head.height = u64::MAX;
		let mut stale_tail = canonical_tail;
		stale_tail.height = 0;
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_body_head(&stale_head).unwrap();
			batch.save_body_tail(&stale_tail).unwrap();
			batch.commit().unwrap();
		}

		let next_compact = canonical_tail
			.height
			.saturating_add(horizon.saturating_add(horizon / 10));
		assert_eq!(chain.compact_eligibility().unwrap(), (false, next_compact));
		chain.compact(None, Arc::new(StopState::new())).unwrap();
		assert_eq!(chain.store.head().unwrap(), stale_head);
		assert_eq!(chain.store.tail().unwrap(), stale_tail);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn compact_rejects_off_chain_tail_when_ineligible() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/compact_ineligible_off_chain_tail_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = mine_chain(&chain_dir, 4);
		let context_id = chain.get_context_id();
		let body_head_header = chain.head_header().unwrap();
		let off_chain_tail_header = recovery_test_header(
			body_head_header.height,
			chain.genesis().hash(context_id).unwrap(),
			901,
		);
		assert_ne!(
			off_chain_tail_header.hash(context_id).unwrap(),
			body_head_header.hash(context_id).unwrap()
		);
		let off_chain_tail = Tip::try_from_header(&off_chain_tail_header).unwrap();

		// Both selectors are individually canonical and height-ordered, but the
		// tail is not the body-chain header at its selected height. Its height makes
		// compaction ineligible, so the early-return path must still reject it.
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_block_header(&off_chain_tail_header).unwrap();
			batch.save_body_tail(&off_chain_tail).unwrap();
			batch.commit().unwrap();
		}

		let err = chain.compact(None, Arc::new(StopState::new())).unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(ref msg)
				if msg.contains("compact eligibility BODY_TAIL")
					&& msg.contains("is not on the durable body chain")
		));
		assert_eq!(chain.store.tail().unwrap(), off_chain_tail);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn compact_rejects_unusable_target_block_before_marker() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/compact_target_block_preflight_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = mine_chain(&chain_dir, 78);
		let context_id = chain.get_context_id();
		// Automated-testing block processing advances BODY_TAIL with each batch.
		// Move it back to genesis so this test exercises an eligible compaction.
		let genesis_tail = Tip::try_from_header(&chain.genesis()).unwrap();
		{
			let batch = chain.store.batch_write().unwrap();
			batch.save_body_tail(&genesis_tail).unwrap();
			batch.commit().unwrap();
		}
		let original_tail = chain.store.tail().unwrap();
		let head = chain.store.head().unwrap();
		let horizon = u64::from(global::cut_through_horizon(context_id));
		let target_height = head.height.saturating_sub(horizon);
		let target_header = chain.get_header_by_height(target_height).unwrap();
		let target_hash = target_header.hash(context_id).unwrap();
		let target_block = chain.get_block_for_header(&target_header).unwrap();

		// Raw loss of the retained full-block record must be detected before a
		// durable Compact marker is installed.
		{
			let batch = chain.store.batch_write().unwrap();
			batch.delete(&mwc_store::to_key(b'b', target_hash)).unwrap();
			batch.commit().unwrap();
		}
		let err = chain.compact(None, Arc::new(StopState::new())).unwrap_err();
		assert!(matches!(
			err,
			Error::StoreErr(NotFoundErr(_), ref context)
				if context.contains("compact target BODY_TAIL preflight load full block")
		));
		assert_eq!(chain.store.tail().unwrap(), original_tail);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		// Restore the record, then model a same-key record whose complete header
		// differs from the separately stored canonical ancestry header.
		let mut corrupted_target = target_block.clone();
		corrupted_target.header.height = corrupted_target.header.height.saturating_add(100);
		assert_eq!(corrupted_target.hash(context_id).unwrap(), target_hash);
		assert_ne!(corrupted_target.header, target_header);
		{
			let batch = chain.store.batch_write().unwrap();
			batch
				.db
				.put_ser(&mwc_store::to_key(b'b', target_hash), &corrupted_target)
				.unwrap();
			batch.commit().unwrap();
		}
		let err = chain.compact(None, Arc::new(StopState::new())).unwrap_err();
		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(ref msg)
				if msg.contains("compact target BODY_TAIL preflight")
					&& msg.contains("does not exactly match persisted ancestry header")
		));
		assert_eq!(chain.store.tail().unwrap(), original_tail);
		assert!(chain.store.pending_chain_operation().unwrap().is_none());
		assert!(!chain.requires_init_recovery.load(Ordering::SeqCst));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn combine_positioned_outputs_and_rangeproofs_rejects_position_mismatch() {
		let outputs = (10, vec![(1, test_output_identifier())]);
		let rangeproofs = (10, vec![(2, test_rangeproof())]);

		let err = combine_positioned_outputs_and_rangeproofs(outputs, rangeproofs).unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("PMMR positions don't match"), "{}", msg);
			}
			other => panic!("expected position mismatch error, got {:?}", other),
		}
	}

	#[test]
	fn validate_tmpfile_name_accepts_single_normal_component() {
		assert!(Chain::validate_tmpfile_name("txhashset.zip").is_ok());
		assert!(Chain::validate_tmpfile_name("snapshot.tmp").is_ok());
	}

	#[test]
	fn validate_tmpfile_name_rejects_paths_and_empty_names() {
		for tmpfile_name in [
			"",
			".",
			"..",
			"txhashset/zip",
			"txhashset/",
			"/txhashset",
			"../txhashset",
			"txhashset/../zip",
			"txhashset\\zip",
			"\\txhashset",
			"C:\\txhashset",
		] {
			assert!(
				Chain::validate_tmpfile_name(tmpfile_name).is_err(),
				"accepted invalid tmpfile name: {}",
				tmpfile_name
			);
		}
	}

	#[test]
	fn exact_hardcoded_genesis_bypasses_runtime_pow_verifier() {
		global::set_local_chain_type(global::ChainTypes::Floonet);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let genesis = genesis::genesis_floo(&secp, 0);

		assert!(validate_genesis_for_init(&secp, 0, &genesis, reject_pow).is_ok());
	}

	#[test]
	fn production_genesis_requires_full_canonical_match() {
		global::set_local_chain_type(global::ChainTypes::Floonet);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut genesis = genesis::genesis_floo(&secp, 0);
		let canonical_hash = genesis.hash(0).unwrap();
		genesis.header.pow.nonce += 1;

		assert_eq!(genesis.hash(0).unwrap(), canonical_hash);
		assert!(matches!(
			validate_genesis_for_init(&secp, 0, &genesis, reject_pow),
			Err(Error::InvalidGenesisHash)
		));
	}

	#[test]
	fn testing_genesis_uses_supplied_pow_verifier() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let genesis = Block::default(0);

		assert!(matches!(
			validate_genesis_for_init(&secp, 0, &genesis, reject_pow),
			Err(Error::InvalidPow)
		));
	}

	#[test]
	fn genesis_block_sums_allows_empty_genesis_body() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let genesis = Block::default(0);

		assert!(matches!(
			genesis_block_sums(&genesis, 0, &secp),
			Ok(BlockSums::Empty)
		));
	}

	#[test]
	fn genesis_block_sums_rejects_empty_genesis_with_kernel_offset() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut genesis = Block::default(0);
		genesis.header.total_kernel_offset = mwc_keychain::BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000001",
		)
		.unwrap();

		let res = genesis_block_sums(&genesis, 0, &secp);
		assert!(matches!(res, Err(Error::Committed(_))), "got {:?}", res);
	}

	#[test]
	fn genesis_block_sums_rejects_output_only_genesis_body() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut genesis = Block::default(0);
		let output_value = consensus::calc_mwc_block_reward(0, 0) + 1;
		let output = Output::new(
			OutputFeatures::Plain,
			secp.commit_value(output_value).unwrap(),
			test_rangeproof(),
		);
		genesis.body.outputs.push(output);

		let res = genesis_block_sums(&genesis, 0, &secp);
		assert!(matches!(res, Err(Error::Committed(_))), "got {:?}", res);
	}
}
