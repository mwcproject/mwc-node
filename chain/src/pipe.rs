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

//! Implementation of the chain block acceptance (or refusal) pipeline.

use crate::error::Error;
use crate::store;
use crate::txhashset;
use crate::types::{CommitPos, Options, Tip};
use mwc_core::consensus;
use mwc_core::consensus::HeaderDifficultyInfo;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::Committed;
use mwc_core::core::Transaction;
use mwc_core::core::{
	block, Block, BlockHeader, BlockSums, HeaderVersion, OutputIdentifier, TransactionBody,
};
use mwc_core::difficulty_cache::DifficultyCache;
use mwc_core::global;
use mwc_core::pow;
use mwc_core::ser::{self, ProtocolVersion};
use mwc_crates::crossbeam;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::log::{debug, error, info};
use mwc_crates::num_cpus;
use mwc_crates::parking_lot::{RwLock, RwLockWriteGuard};
use mwc_crates::secp::Secp256k1;
use mwc_store::Error::NotFoundErr;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::iter::FromIterator;

/// Contextual information required to process a new block and either reject or
/// accept it.
pub struct BlockContext<'a> {
	/// The options
	pub opts: Options,
	/// The pow verifier to use when processing a block.
	pub pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	/// The active txhashset (rewindable MMRs) to use for block processing.
	pub txhashset: &'a mut txhashset::TxHashSet,
	/// The active header MMR handle.
	pub header_pmmr: &'a mut txhashset::PMMRHandle<BlockHeader>,
	/// The active batch to use for block processing.
	pub batch: store::Batch<'a>,
	pub(crate) difficulty_cache: RwLockWriteGuard<'a, DifficultyCache>,
}

impl<'a> BlockContext<'a> {
	fn skip_pow(&self) -> bool {
		#[cfg(test)]
		{
			self.opts.contains(Options::SKIP_POW)
		}
		#[cfg(not(test))]
		{
			let _ = self;
			false
		}
	}
}

lazy_static! {
	static ref INVALID_BLOCK_HASHES: RwLock<HashMap<u32, HashSet<Hash>>> =
		RwLock::new(HashMap::new());
}

// Known/duplicate blocks are normal control-flow outcomes for header processing.
// Store or serialization failures still propagate as Error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KnownStatus {
	Unknown,
	KnownInHead,
	KnownInStore,
	OldBlock,
}

impl KnownStatus {
	fn is_known(self) -> bool {
		self != KnownStatus::Unknown
	}

	fn into_error(self) -> Option<Error> {
		match self {
			KnownStatus::Unknown => None,
			KnownStatus::KnownInHead => Some(Error::Unfit("already known in head".to_string())),
			KnownStatus::KnownInStore => Some(Error::Unfit("already known in store".to_string())),
			KnownStatus::OldBlock => Some(Error::OldBlock),
		}
	}
}

/// Release Context related data
pub fn release_context_data(context_id: u32) {
	INVALID_BLOCK_HASHES.write().remove(&context_id);
}

/// Setup the banned header hashes defined at the config.
pub fn init_invalid_block_hashes(context_id: u32, hashes: HashSet<Hash>) {
	INVALID_BLOCK_HASHES
		.write()
		.entry(context_id)
		.or_default()
		.extend(hashes);
}

/// Validate the block hash, check if it is banned
pub fn validate_header_hash(context_id: u32, hash: &Hash) -> Result<(), Error> {
	let hashes = INVALID_BLOCK_HASHES.read_recursive();
	if let Some(blocked_hashes) = hashes.get(&context_id) {
		if blocked_hashes.contains(&hash) {
			error!("Invalid header found: {}. Rejecting it!", hash);
			return Err(Error::InvalidHash.into());
		}
	}
	Ok(())
}

// If this block has greater total difficulty than treat as unknown in current context.
// If it matches current chain head (latest or previous hash) then we know about it.
// If it exists in the local db then we know about it.
fn check_known(
	context_id: u32,
	header: &BlockHeader,
	head: &Tip,
	ctx: &BlockContext<'_>,
) -> Result<KnownStatus, Error> {
	if header.total_difficulty() <= head.total_difficulty {
		let status = check_known_head(context_id, header, head, ctx)?;
		if status.is_known() {
			return Ok(status);
		}
		return check_known_store(context_id, header, head, ctx);
	}
	Ok(KnownStatus::Unknown)
}

///check the outputs of this block against the spent output in the lmdb within the horizon.
///beyond that, the blocks are compacted.
pub fn check_against_spent_output(
	tx: &TransactionBody,
	fork_point_height: Option<u64>,
	local_branch_blocks: Option<&Vec<Hash>>,
	header_extension: &txhashset::HeaderExtension<'_>,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	let output_commits = tx.outputs.iter().map(|output| output.identifier.commit);
	let tip = batch
		.head()
		.map_err(|e| Error::Other(format!("Unable to get a head from batch, {}", e)))?;
	let fork_height = fork_point_height.unwrap_or(tip.height);
	//convert the list of local branch bocks header hashes to a hash set for quick search
	let empty_vec = Vec::new();
	let local_branch_blocks_list = local_branch_blocks.unwrap_or(&empty_vec);
	let local_branch_blocks_set = HashSet::<&Hash>::from_iter(local_branch_blocks_list.iter());

	if !batch.is_retained_spent_commitment_index_complete()? {
		return Err(Error::SpentCommitmentIndexIncomplete);
	}

	for commit in output_commits {
		let commit_hash = batch.get_spent_commitments(&commit)?; // check to see if this commitment is in the spent records in db
		if let Some(c_hash) = commit_hash {
			for hash_val in c_hash {
				let header = batch.get_block_header(&hash_val.hash)?;
				if header.height != hash_val.height {
					return Err(Error::TxHashSetErr(format!(
						"spent commitment index height mismatch for block {}: index height {}, header height {}",
						hash_val.hash, hash_val.height, header.height
					)));
				}

				//first check the local branch.
				if header.height > fork_height && local_branch_blocks_set.contains(&hash_val.hash) {
					//first check the local branch.
					error!(
						"output contains spent commtiment:{:?} from local branch",
						commit
					);
					return Err(Error::ReplayAttack(commit));
				} else if header.height <= fork_height {
					if header_extension
						.is_on_current_chain(Tip::try_from_header(&header)?, batch)?
					{
						error!(
							"output contains spent commtiment:{:?} from the main chain",
							commit
						);
						return Err(Error::ReplayAttack(commit));
					}
				}
			}
		}
	}

	Ok(())
}

// Validate only the proof of work in a block header.
// Used to cheaply validate pow before checking if orphan or continuing block validation.
fn validate_pow_only(
	context_id: u32,
	header: &BlockHeader,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	skip_pow: bool,
) -> Result<(), Error> {
	// Some of our tests require this check to be skipped (we should revisit this).
	if skip_pow {
		return Ok(());
	}
	if !header.pow.is_primary(context_id) && !header.pow.is_secondary() {
		return Err(Error::LowEdgebits);
	}
	match pow_verifier(context_id, header) {
		Ok(()) => {}
		Err(pow::Error::Verification(e)) => {
			debug!(
				"pipe: invalid PoW for header with cuckoo edge_bits {}: {}",
				header.pow.edge_bits(),
				e
			);
			return Err(Error::InvalidPow);
		}
		Err(e) => {
			debug!(
				"pipe: PoW verifier failed for header with cuckoo edge_bits {}: {}",
				header.pow.edge_bits(),
				e
			);
			return Err(e.into());
		}
	}
	Ok(())
}

fn validate_pow_batch_parallel(
	context_id: u32,
	headers: &[BlockHeader],
	ctx: &BlockContext<'_>,
) -> Result<(), Error> {
	let skip_pow = ctx.skip_pow();

	if skip_pow || headers.len() <= 32 {
		for header in headers {
			validate_pow_only(context_id, header, ctx.pow_verifier, skip_pow)?;
		}
		return Ok(());
	}

	let worker_count = num_cpus::get().max(1).min(headers.len());
	let chunk_size = (headers.len() + worker_count - 1) / worker_count;
	let pow_verifier = ctx.pow_verifier;

	let verify_result = crossbeam::thread::scope(|s| {
		let mut handles = Vec::with_capacity(worker_count);
		for chunk in headers.chunks(chunk_size) {
			handles.push(s.spawn(move |_| {
				for header in chunk {
					validate_pow_only(context_id, header, pow_verifier, false)?;
				}
				Ok::<(), Error>(())
			}));
		}

		for handle in handles {
			let result = handle
				.join()
				.map_err(|_| Error::Other("header PoW crossbeam runtime failure".into()))?;
			result?;
		}

		Ok::<(), Error>(())
	})
	.map_err(|_| Error::Other("header PoW crossbeam runtime failure".into()))?;
	verify_result
}

fn validate_header_against_prev(
	context_id: u32,
	header: &BlockHeader,
	prev: &BlockHeader,
) -> Result<(), Error> {
	// This header height must increase the height from the previous header by exactly 1.
	let expected_height = prev.height.checked_add(1).ok_or_else(|| {
		Error::DataOverflow(format!("validate_header, prev.height={}", prev.height))
	})?;
	if header.height != expected_height {
		return Err(Error::InvalidBlockHeight);
	}

	// This header must have a valid header version for its height.
	if !consensus::valid_header_version(context_id, header.height, header.version) {
		return Err(Error::InvalidBlockVersion(header.version));
	}

	// Consensus validation only requires strict timestamp progression. The
	// max-future timestamp check is local wall-clock based, so it belongs in
	// UntrustedBlockHeader::read as a peer-broadcast admission rule instead of
	// here in deterministic chain validation.
	if header.timestamp <= prev.timestamp {
		// prevent time warp attacks and some timestamp manipulations by forcing strict
		// time progression
		return Err(Error::InvalidBlockTime);
	}

	txhashset::ensure_complete_pmmr_size(header.output_mmr_size)?;
	txhashset::ensure_complete_pmmr_size(header.kernel_mmr_size)?;

	// We can determine output and kernel counts for this block based on mmr sizes from previous header.
	// Assume 0 inputs and estimate a lower bound on the full block weight.
	let num_outputs = header
		.output_mmr_count()?
		.saturating_sub(prev.output_mmr_count()?);
	let num_kernels = header
		.kernel_mmr_count()?
		.saturating_sub(prev.kernel_mmr_count()?);

	// Each block must contain at least 1 kernel and 1 output for the block reward.
	if num_outputs == 0 || num_kernels == 0 {
		return Err(Error::InvalidMMRSize);
	}

	// Block header is invalid (and block is invalid) if this lower bound is too heavy for a full block.
	let weight = Transaction::weight_for_size(0, num_outputs, num_kernels)?;
	if weight > global::max_block_weight(context_id) {
		return Err(Error::Block(block::Error::TooHeavy));
	}

	Ok(())
}

fn validate_header_difficulty(
	context_id: u32,
	header: &BlockHeader,
	prev: &BlockHeader,
	next_header_info: &HeaderDifficultyInfo,
) -> Result<pow::Difficulty, Error> {
	if header.total_difficulty() <= prev.total_difficulty() {
		return Err(Error::DifficultyTooLow);
	}

	let target_difficulty = (header.total_difficulty() - prev.total_difficulty())?;

	if header.pow.to_difficulty(context_id, header.height)? < target_difficulty {
		return Err(Error::DifficultyTooLow);
	}

	// explicit check to ensure total_difficulty has increased by exactly
	// the _network_ difficulty of the previous block
	// (during testnet1 we use _block_ difficulty here)
	if target_difficulty != next_header_info.difficulty {
		info!(
			"validate_header: header target difficulty {} != {}",
			target_difficulty.to_num(),
			next_header_info.difficulty.to_num()
		);
		return Err(Error::WrongTotalDifficulty);
	}
	// check the secondary PoW scaling factor if applicable
	if header.pow.secondary_scaling != next_header_info.secondary_scaling {
		info!(
			"validate_header: header secondary scaling {} != {}",
			header.pow.secondary_scaling, next_header_info.secondary_scaling
		);
		return Err(Error::InvalidScaling);
	}

	Ok(target_difficulty)
}

/// Runs the block processing pipeline, including validation and finding a
/// place for the new block in the chain.
/// Returns new head if chain head updated and the "fork point" rewound to when processing the new block.
pub fn process_blocks_series(
	context_id: u32,
	blocks: &Vec<Block>,
	ctx: &mut BlockContext<'_>,
	state_may_have_changed: &mut bool,
	secp: &mut Secp256k1,
) -> Result<(Option<Tip>, BlockHeader), Error> {
	debug_assert!(!blocks.is_empty());
	let first_block = blocks.first().ok_or(Error::Other(
		"Invalid process_blocks_series param blocks - it is empty".into(),
	))?;
	debug!(
		"pipe: process_blocks_series {} at {}, blocks in series: {}",
		first_block.hash(context_id)?,
		first_block.header.height,
		blocks.len()
	);

	// let's validate if series is correct
	for i in 1..blocks.len() {
		let b1 = &blocks[i - 1];
		let b2 = &blocks[i];
		let b1_hash = b1.hash(context_id)?;
		let expected_height = b1.header.height.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"process_blocks_series, b1.header.height={}",
				b1.header.height
			))
		})?;
		if expected_height != b2.header.height
			|| b1_hash != b2.header.prev_hash
			|| b1.header.pow.total_difficulty >= b2.header.pow.total_difficulty
		{
			return Err(Error::InvalidBlocksSeries(format!(
				"Headers: {} vs {}, hashes: {} vs {},  Difficulties: {} vs {}",
				b1.header.height,
				b2.header.height,
				b1_hash,
				b2.header.prev_hash,
				b1.header.pow.total_difficulty,
				b2.header.pow.total_difficulty
			)));
		}
	}

	// Read current chain head from db via the batch.
	// We use this for various operations later.
	let head = ctx.batch.head()?;
	let last_block = blocks.last().ok_or(Error::Other(
		"process_blocks_series blocks are empty".into(),
	))?;
	let series_has_more_work = has_more_work(&last_block.header, &head);
	let skip_pow = ctx.skip_pow();

	for b in blocks {
		// Validate block for deny list, just in case
		validate_header_hash(context_id, &b.header.hash(context_id)?)?;

		// Quick pow validation. No point proceeding if this is invalid.
		// We want to do this before we add the block to the orphan pool so we
		// want to do this now and not later during header validation.
		validate_pow_only(context_id, &b.header, ctx.pow_verifier, skip_pow)?;

		// Process the header for the block.
		// Note: We still want to process the full block if we have seen this header before
		// as we may have processed it "header first" and not yet processed the full block.
		process_block_header(context_id, &b.header, ctx, state_may_have_changed)?;

		// Validate the block itself, make sure it is internally consistent.
		// Use the verifier_cache for verifying rangeproofs and kernel signatures.
		validate_block(context_id, b, ctx, secp)?;
	}

	// Treat a known full block as duplicate only after the incoming block has
	// passed PoW and internal block validation. Before that, the proof-derived
	// header hash alone is not a safe identity for peer-supplied full blocks.
	if let Some(e) = check_known_exact_full_block(context_id, first_block, &head, ctx)?.into_error()
	{
		return Err(e);
	}

	// Get previous header from the db.
	let prev = prev_header_store(&first_block.header, &mut ctx.batch)?;

	// Start a chain extension unit of work dependent on the success of the
	// internal validation and saving operations
	let header_pmmr = &mut ctx.header_pmmr;
	let txhashset = &mut ctx.txhashset;
	let batch = &mut ctx.batch;
	let fork_point = txhashset::extending(header_pmmr, txhashset, batch, |ext, batch| {
		*state_may_have_changed = true;
		let fork_point_local_blocks = rewind_and_apply_fork(context_id, &prev, ext, batch, secp)?;

		let fork_point = fork_point_local_blocks.0;
		let mut local_branch_blocks = fork_point_local_blocks.1;

		for b in blocks {
			replay_attack_check(b, fork_point.height, &local_branch_blocks, ext, batch)?;

			// Check any coinbase being spent have matured sufficiently.
			// This needs to be done within the context of a potentially
			// rewound txhashset extension to reflect chain state prior
			// to applying the new block.
			verify_coinbase_maturity(context_id, b, ext, batch)?;

			// Validate the block against the UTXO set.
			validate_utxo(b, ext, batch)?;

			// Using block_sums (utxo_sum, kernel_sum) for the previous block from the db
			// we can verify_kernel_sums across the full UTXO sum and full kernel sum
			// accounting for inputs/outputs/kernels in this new block.
			// We know there are no double-spends etc. if this verifies successfully.
			verify_block_sums(context_id, b, batch, secp)?;

			// Apply the block to the txhashset state.
			// Validate the txhashset roots and sizes against the block header.
			// Block is invalid if there are any discrepencies.
			apply_block_to_txhashset(b, ext, batch)?;

			local_branch_blocks.push(b.hash(context_id)?); // appending processed block to the local branch
		}

		// The txhashset extension and the later BODY_HEAD update must make the
		// same commit/rollback decision for the whole series. Intermediate fork
		// blocks can be lower work than the old head while the last block wins.
		if !series_has_more_work {
			ext.extension.force_rollback();
		}

		Ok(fork_point)
	})?;

	// Add the validated block to the db.
	// Note we do this in the outer batch, not the child batch from the extension
	// as we only commit the child batch if the extension increases total work.
	// We want to save the block to the db regardless.
	for b in blocks {
		add_block(b, &ctx.batch)?;
	}

	// If we have no "tail" then set it now.
	match ctx.batch.tail() {
		Ok(_) => {}
		Err(NotFoundErr(_)) => {
			update_body_tail(&first_block.header, &ctx.batch)?;
		}
		Err(e) => return Err(Error::StoreErr(e, "pipe read body tail".to_owned())),
	}

	let res = if series_has_more_work {
		let head = Tip::try_from_header(&last_block.header)?;
		update_head(&head, &mut ctx.batch)?;
		Ok((Some(head), fork_point))
	} else {
		Ok((None, fork_point))
	};
	res
}

///
pub fn replay_attack_check(
	b: &Block,
	fork_point_height: u64,
	local_branch_blocks: &Vec<Hash>,
	ext: &txhashset::ExtensionPair<'_>,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	// Replay protection is a consensus rule, so HeaderVersion is the visible
	// hard-fork signal for enabling this block-level check. Keep this gate in
	// sync with consensus::valid_header_version(): production networks must
	// accept HeaderVersion(3) at the activation height before this runs for
	// normal Mainnet/Floonet blocks. If replay protection is required for an
	// earlier production version, this gate must be updated to cover it.
	if b.header.version >= HeaderVersion(3) {
		check_against_spent_output(
			&b.body,
			Some(fork_point_height),
			Some(local_branch_blocks),
			ext.header_extension,
			batch,
		)?;
	}
	Ok(())
}

/// Process a batch of sequential block headers.
/// This is only used during header sync.
/// Will update header_head locally if this batch of headers increases total work.
/// Returns the updated sync_head, which may be on a fork.
pub fn process_block_headers(
	context_id: u32,
	headers: &[BlockHeader],
	sync_head: Tip,
	ctx: &mut BlockContext<'_>,
) -> Result<Option<Tip>, Error> {
	if headers.is_empty() {
		return Ok(None);
	}
	let last_header = headers.last().ok_or(Error::Other(
		"process_block_headers internal error, headers param is empty".into(),
	))?;

	validate_header_batch_contiguous(context_id, headers)?;

	let head = ctx.batch.header_head()?;
	let first_header = headers.first().ok_or(Error::Other(
		"process_block_headers internal error, headers param is empty".into(),
	))?;
	let mut prev = prev_header_store(first_header, &ctx.batch)?;
	let skip_pow = ctx.skip_pow();
	let mut batch_difficulty_cache = DifficultyCache::new();
	if !skip_pow {
		batch_difficulty_cache
			.reset_rolling(store::DifficultyIter::from_batch(
				prev.hash(context_id)?,
				&ctx.batch,
			))
			.map_err(|e| Error::Other(format!("Difficulty calculation error, {}", e)))?;
	}

	// Validate each header in the chunk before mutating storage. The sequence is
	// contiguous, so after the first db header the previous header comes from the
	// incoming batch and the difficulty window can be advanced in memory.
	// Note: This batch may be rolled back later if the MMR does not validate successfully.
	// Note: This batch may later be committed even if the MMR itself is rollbacked.
	for header in headers {
		let header_hash = header.hash(context_id)?;
		match ctx.batch.get_block_header(&header_hash) {
			Ok(existing) if existing != *header => {
				return Err(Error::Block(block::Error::Other(
					"known header hash matches a different header".into(),
				)));
			}
			Ok(_) => {}
			Err(NotFoundErr(_)) => {}
			Err(e) => return Err(Error::StoreErr(e, "pipe check existing header".to_owned())),
		}

		// Apply any ctx specific header validation (denylist) rules.
		validate_header_hash(context_id, &header_hash)?;

		validate_header_against_prev(context_id, header, &prev)?;

		if !skip_pow {
			let next_header_info = batch_difficulty_cache
				.next_rolling_difficulty(context_id, header.height)
				.map_err(|e| Error::Other(format!("Difficulty calculation error, {}", e)))?;

			let target_difficulty =
				validate_header_difficulty(context_id, header, &prev, &next_header_info)?;

			let timestamp = u64::try_from(header.timestamp.timestamp()).map_err(|_| {
				Error::DataOverflow(format!(
					"process_block_headers, timestamp={}",
					header.timestamp.timestamp()
				))
			})?;
			// Keep the just-validated header in the rolling cache so the next
			// header in this contiguous batch does not re-read the same
			// previous-header window from LMDB.
			batch_difficulty_cache
				.push_rolling_header(HeaderDifficultyInfo::new(
					header.height,
					Some(header_hash),
					timestamp,
					target_difficulty,
					header.pow.secondary_scaling,
					header.pow.is_secondary(),
				))
				.map_err(|e| Error::Other(format!("Difficulty calculation error, {}", e)))?;
		}

		prev = header.clone();
	}

	validate_pow_batch_parallel(context_id, headers, ctx)?;

	for header in headers {
		add_block_header(header, &ctx.batch)?;
	}

	// Now apply this entire chunk of headers to the header MMR.
	txhashset::header_extending(&mut ctx.header_pmmr, &mut ctx.batch, |ext, batch| {
		rewind_and_apply_header_fork(context_id, &last_header, ext, batch)?;

		// If previous sync_head is not on the "current" chain then
		// these headers are on an alternative fork to sync_head.
		let alt_fork = !ext.is_on_current_chain(sync_head, batch)?;

		// Update our "header_head" if this batch results in an increase in total work.
		// Otherwise rollback this header extension.
		// Note the outer batch may still be committed to db assuming no errors occur in the extension.
		let last_tip = Tip::try_from_header(last_header)?;
		if has_more_work(last_header, &head) {
			update_header_head(&last_tip, &batch)?;
		} else {
			ext.force_rollback();
		};

		if alt_fork || has_more_work(last_header, &sync_head) {
			Ok(Some(last_tip))
		} else {
			Ok(None)
		}
	})
}

fn validate_header_batch_contiguous(context_id: u32, headers: &[BlockHeader]) -> Result<(), Error> {
	for pair in headers.windows(2) {
		let prev = &pair[0];
		let next = &pair[1];
		let expected_height = prev.height.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"validate_header_batch_contiguous, prev.height={}",
				prev.height
			))
		})?;
		let prev_hash = prev.hash(context_id)?;

		if next.height != expected_height || next.prev_hash != prev_hash {
			return Err(Error::InvalidBlocksSeries(format!(
				"non-contiguous header batch: header {} at height {} does not follow header {} at height {}",
				next.hash(context_id)?,
				next.height,
				prev_hash,
				prev.height
			)));
		}
	}

	Ok(())
}

/// Process a block header. Update the header MMR and corresponding header_head if this header
/// increases the total work relative to header_head.
/// Note: In contrast to processing a full block we treat "already known" as success
/// to allow processing to continue (for header itself).
pub fn process_block_header(
	context_id: u32,
	header: &BlockHeader,
	ctx: &mut BlockContext<'_>,
	state_may_have_changed: &mut bool,
) -> Result<(), Error> {
	// If we have already processed the full block for this header then done.
	// Note: "already known" in this context is success so subsequent processing can continue.
	{
		let head = ctx.batch.head()?;
		if check_known(context_id, header, &head, ctx)?.is_known() {
			return Ok(());
		}
	}

	// Check this header is not an orphan, we must know about the previous header to continue.
	let prev_header = prev_header_store(header, &ctx.batch)?;

	// If we have not yet seen the full block then check if we have seen this header.
	// If it does not increase total_difficulty beyond our current header_head
	// then we can (re)accept this header and process the full block (or request it).
	// This header is on a fork and we should still accept it as the fork may eventually win.
	let header_head = ctx.batch.header_head()?;
	match ctx.batch.get_block_header(&header.hash(context_id)?) {
		Ok(existing) => {
			if existing != *header {
				return Err(Error::Block(block::Error::Other(
					"known header hash matches a different header".into(),
				)));
			}
			if !has_more_work(&existing, &header_head) {
				return Ok(());
			}
		}
		Err(NotFoundErr(_)) => {}
		Err(e) => return Err(Error::StoreErr(e, "pipe check existing header".to_owned())),
	}

	// We want to validate this individual header before applying it to our header PMMR.
	validate_header(context_id, header, ctx)?;

	// Apply the header to the header PMMR, making sure we put the extension in the correct state
	// based on previous header first.
	txhashset::header_extending(&mut ctx.header_pmmr, &mut ctx.batch, |ext, batch| {
		*state_may_have_changed = true;
		rewind_and_apply_header_fork(context_id, &prev_header, ext, batch)?;
		ext.validate_root(header)?;
		ext.apply_header(header)?;
		if !has_more_work(&header, &header_head) {
			ext.force_rollback();
		}
		Ok(())
	})?;

	// Add this new block header to the db.
	add_block_header(header, &ctx.batch)?;

	if has_more_work(header, &header_head) {
		update_header_head(&Tip::try_from_header(header)?, &mut ctx.batch)?;
	}

	Ok(())
}

/// Quick check to reject recently handled blocks.
/// Checks against last_block_h and prev_block_h of the chain head.
fn check_known_head(
	context_id: u32,
	header: &BlockHeader,
	head: &Tip,
	ctx: &BlockContext<'_>,
) -> Result<KnownStatus, Error> {
	let bh = header.hash(context_id)?;
	if bh == head.last_block_h || bh == head.prev_block_h {
		let existing = ctx
			.batch
			.get_block_header(&bh)
			.map_err(|e| Error::StoreErr(e, "pipe get known head header".to_owned()))?;
		// Before PoW validation, the header hash is not enough to identify the full header.
		if existing != *header {
			return Err(Error::Block(block::Error::Other(
				"known header hash matches a different header".into(),
			)));
		}
		return Ok(KnownStatus::KnownInHead);
	}
	Ok(KnownStatus::Unknown)
}

// Check if this block is in the store already.
fn check_known_store(
	context_id: u32,
	header: &BlockHeader,
	head: &Tip,
	ctx: &BlockContext<'_>,
) -> Result<KnownStatus, Error> {
	let bh = header.hash(context_id)?;
	match ctx.batch.block_exists(&bh) {
		Ok(true) => {
			let existing = ctx
				.batch
				.get_block_header(&bh)
				.map_err(|e| Error::StoreErr(e, "pipe get known store header".to_owned()))?;
			// Before PoW validation, the header hash is not enough to identify the full header.
			if existing != *header {
				return Err(Error::Block(block::Error::Other(
					"known header hash matches a different header".into(),
				)));
			}
			if header.height < head.height.saturating_sub(50) {
				// TODO - we flag this as an "abusive peer" but only in the case
				// where we have the full block in our store.
				// So this is not a particularly exhaustive check.
				Ok(KnownStatus::OldBlock)
			} else {
				Ok(KnownStatus::KnownInStore)
			}
		}
		Ok(false) => {
			// Not yet processed this block, we can proceed.
			Ok(KnownStatus::Unknown)
		}
		Err(e) => Err(Error::StoreErr(e, "pipe get this block".to_owned())),
	}
}

fn check_known_exact_full_block(
	context_id: u32,
	block: &Block,
	head: &Tip,
	ctx: &BlockContext<'_>,
) -> Result<KnownStatus, Error> {
	let bh = block.hash(context_id)?;
	let existing = match ctx.batch.get_block(&bh) {
		Ok(existing) => existing,
		Err(NotFoundErr(_)) => return Ok(KnownStatus::Unknown),
		Err(e) => return Err(Error::StoreErr(e, "pipe get known full block".to_owned())),
	};

	let existing_bytes = ser::ser_vec(context_id, &existing, ProtocolVersion::local())?;
	let incoming_bytes = ser::ser_vec(context_id, block, ProtocolVersion::local())?;
	if existing_bytes != incoming_bytes {
		return Ok(KnownStatus::Unknown);
	}

	if bh == head.last_block_h || bh == head.prev_block_h {
		Ok(KnownStatus::KnownInHead)
	} else if has_more_work(&block.header, head) {
		// The block is already stored, but it may need to be applied again after
		// a reset or as part of a higher-work fork becoming the active body chain.
		Ok(KnownStatus::Unknown)
	} else if block.header.height < head.height.saturating_sub(50) {
		Ok(KnownStatus::OldBlock)
	} else {
		Ok(KnownStatus::KnownInStore)
	}
}

// Find the previous header from the store.
// Return an Orphan error if we cannot find the previous header.
fn prev_header_store(header: &BlockHeader, batch: &store::Batch<'_>) -> Result<BlockHeader, Error> {
	match batch.get_previous_header(header) {
		Ok(prev) => Ok(prev),
		Err(NotFoundErr(_)) => Err(Error::Orphan(format!(
			"previous header {} not found",
			header.prev_hash
		))),
		Err(e) => Err(Error::StoreErr(e, "pipe get previous header".to_owned())),
	}
}

/// First level of block validation that only needs to act on the block header
/// to make it as cheap as possible. The different validations are also
/// arranged by order of cost to have as little DoS surface as possible.
fn validate_header(
	context_id: u32,
	header: &BlockHeader,
	ctx: &mut BlockContext<'_>,
) -> Result<(), Error> {
	let header_hash = header.hash(context_id)?;

	// First I/O cost, delayed as late as possible.
	let prev = prev_header_store(header, &ctx.batch)?;
	// Apply any ctx specific header validation (denylist) rules.
	validate_header_hash(context_id, &header_hash)?;

	validate_header_against_prev(context_id, header, &prev)?;

	// verify the proof of work and related parameters
	// at this point we have a previous block header
	// we know the height increased by one
	// so now we can check the total_difficulty increase is also valid
	// check the pow hash shows a difficulty at least as large
	// as the target difficulty
	let skipping_pow = ctx.skip_pow();
	if !skipping_pow {
		// Quick check of this header in isolation. No point proceeding if this fails.
		// We can do this without needing to iterate over previous headers.
		validate_pow_only(context_id, header, ctx.pow_verifier, false)?;

		let diff_iter = store::DifficultyIter::from_batch(prev.hash(context_id)?, &ctx.batch);
		let next_header_info = consensus::next_difficulty(
			context_id,
			header.height,
			diff_iter,
			&mut *ctx.difficulty_cache,
		)
		.map_err(|e| Error::Other(format!("Difficulty calculation error, {}", e)))?;

		validate_header_difficulty(context_id, header, &prev, &next_header_info)?;
	}

	Ok(())
}

fn validate_block(
	context_id: u32,
	block: &Block,
	ctx: &mut BlockContext<'_>,
	secp: &mut Secp256k1,
) -> Result<(), Error> {
	let prev = prev_header_store(&block.header, &ctx.batch)?;
	block
		.validate(context_id, &prev.total_kernel_offset, secp)
		.map_err(|e| Error::Block(e))?;
	Ok(())
}

/// Verify the block is not spending coinbase outputs before they have sufficiently matured.
fn verify_coinbase_maturity(
	context_id: u32,
	block: &Block,
	ext: &txhashset::ExtensionPair<'_>,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	let extension = &ext.extension;
	let header_extension = &ext.header_extension;
	extension
		.utxo_view(header_extension)
		.verify_coinbase_maturity(context_id, &block.inputs(), block.header.height, batch)
}

/// Verify kernel sums across the full utxo and kernel sets based on block_sums
/// of previous block accounting for the inputs|outputs|kernels of the new block.
/// Saves the new block_sums to the db via the current batch if successful.
fn verify_block_sums(
	context_id: u32,
	b: &Block,
	batch: &store::Batch<'_>,
	secp: &Secp256k1,
) -> Result<(), Error> {
	// Retrieve the block_sums for the previous block.
	let block_sums = batch.get_block_sums(&b.header.prev_hash)?;

	// Overage is based purely on the new block.
	// Previous block_sums have taken all previous overage into account.
	let overage = b.header.overage(context_id).map_err(Error::Block)?;

	// Offset on the other hand is the total kernel offset from the new block.
	let offset = b.header.total_kernel_offset();

	// Verify the kernel sums for the block_sums with the new block applied.
	let (utxo_sum, kernel_sum) =
		(block_sums, b as &dyn Committed).verify_kernel_sums(overage, offset, secp)?;

	batch.save_block_sums(&b.hash(context_id)?, BlockSums::new(utxo_sum, kernel_sum))?;

	Ok(())
}

/// Fully validate the block by applying it to the txhashset extension.
/// Check both the txhashset roots and sizes are correct after applying the block.
fn apply_block_to_txhashset(
	block: &Block,
	ext: &mut txhashset::ExtensionPair<'_>,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	ext.extension
		.apply_block(block, ext.header_extension, batch)?;
	ext.extension.validate_roots(&block.header)?;
	ext.extension.validate_sizes(&block.header)?;
	Ok(())
}

/// Officially adds the block to our chain (possibly on a losing fork).
/// Header must be added separately (assume this has been done previously).
fn add_block(b: &Block, batch: &store::Batch<'_>) -> Result<(), Error> {
	batch.save_block(b)?;
	Ok(())
}

/// Update the block chain tail so we can know the exact tail of full blocks in this node
fn update_body_tail(bh: &BlockHeader, batch: &store::Batch<'_>) -> Result<(), Error> {
	let tip = Tip::try_from_header(bh)?;
	batch
		.save_body_tail(&tip)
		.map_err(|e| Error::StoreErr(e, "pipe save body tail".to_owned()))?;
	debug!("body tail {} @ {}", tip.last_block_h, bh.height);
	Ok(())
}

/// Officially adds the block header to our header chain.
fn add_block_header(bh: &BlockHeader, batch: &store::Batch<'_>) -> Result<(), Error> {
	batch
		.save_block_header(bh)
		.map_err(|e| Error::StoreErr(e, "pipe save header".to_owned()))?;
	Ok(())
}

fn update_header_head(head: &Tip, batch: &store::Batch<'_>) -> Result<(), Error> {
	batch
		.save_header_head(&head)
		.map_err(|e| Error::StoreErr(e, "pipe save header head".to_owned()))?;

	debug!(
		"header head updated to {} at {}",
		head.last_block_h, head.height
	);

	Ok(())
}

fn update_head(head: &Tip, batch: &store::Batch<'_>) -> Result<(), Error> {
	batch
		.save_body_head(&head)
		.map_err(|e| Error::StoreErr(e, "pipe save body".to_owned()))?;

	debug!("head updated to {} at {}", head.last_block_h, head.height);

	Ok(())
}

// Whether the provided block totals more work than the chain tip
fn has_more_work(header: &BlockHeader, head: &Tip) -> bool {
	header.total_difficulty() > head.total_difficulty
}

/// Rewind the header chain and reapply headers on a fork.
pub fn rewind_and_apply_header_fork(
	context_id: u32,
	header: &BlockHeader,
	ext: &mut txhashset::HeaderExtension<'_>,
	batch: &store::Batch<'_>,
) -> Result<(), Error> {
	let mut fork_hashes = vec![];
	let mut current = header.clone();
	while current.height > 0 {
		let current_tip = Tip::try_from_header(&current)?;
		if ext.is_on_current_chain(current_tip, batch)? {
			break;
		}
		fork_hashes.push(current_tip.last_block_h);
		current = batch.get_previous_header(&current)?;
	}
	fork_hashes.reverse();

	let forked_header = current;

	// Rewind the txhashset state back to the block where we forked from the most work chain.
	ext.rewind(&forked_header)?;

	let invalid_block_hashes = {
		let invalid_hashes = INVALID_BLOCK_HASHES.read_recursive();
		if let Some(blocked_hashes) = invalid_hashes.get(&context_id) {
			blocked_hashes.clone()
		} else {
			HashSet::new()
		}
	};

	// Re-apply all headers on this fork.
	for h in fork_hashes {
		let header = batch
			.get_block_header(&h)
			.map_err(|e| Error::StoreErr(e, "getting forked headers".to_string()))?;

		// Re-validate every header being re-applied.
		// This makes it possible to check all header hashes against the ctx specific "denylist".
		let header_hash = header.hash(context_id)?;
		if invalid_block_hashes.contains(&header_hash) {
			return Err(Error::Block(block::Error::Other(
				"header hash denied".into(),
			)));
		}

		ext.validate_root(&header)?;
		ext.apply_header(&header)?;
	}

	Ok(())
}

/// Utility function to handle forks. From the forked block, jump backward
/// to find to fork point. Rewind the txhashset to the fork point and apply all
/// necessary blocks prior to the one being processed to set the txhashset in
/// the expected state.
/// Returns the "fork point" that we rewound to.
pub fn rewind_and_apply_fork(
	context_id: u32,
	header: &BlockHeader,
	ext: &mut txhashset::ExtensionPair<'_>,
	batch: &store::Batch<'_>,
	secp: &Secp256k1,
) -> Result<(BlockHeader, Vec<Hash>), Error> {
	let extension = &mut ext.extension;
	let header_extension = &mut ext.header_extension;

	// Prepare the header MMR.
	rewind_and_apply_header_fork(context_id, header, header_extension, batch)?;

	// Rewind the txhashset extension back to common ancestor based on header MMR.
	let mut current = batch.head_header()?;
	while current.height > 0
		&& !header_extension.is_on_current_chain(Tip::try_from_header(&current)?, batch)?
	{
		current = batch.get_previous_header(&current)?;
	}
	let fork_point = current;
	extension.rewind(&fork_point, batch, header_extension, None)?;

	// Then apply all full blocks since this common ancestor
	// to put txhashet extension in a state to accept the new block.
	let mut fork_hashes = vec![];
	let mut current = header.clone();
	while current.height > fork_point.height {
		fork_hashes.push(current.hash(context_id)?);
		current = batch.get_previous_header(&current)?;
	}
	fork_hashes.reverse();

	for h in &fork_hashes {
		let fb = match batch
			.get_block(&h)
			.map_err(|e| Error::StoreErr(e, "getting forked blocks".to_string()))
		{
			Ok(fb) => fb,
			Err(e) => return Err(e),
		};

		// Re-verify coinbase maturity along this fork.
		verify_coinbase_maturity(context_id, &fb, ext, batch)?;
		// Validate the block against the UTXO set.
		validate_utxo(&fb, ext, batch)?;
		// Re-verify block_sums to set the block_sums up on this fork correctly.
		verify_block_sums(context_id, &fb, batch, secp)?;
		// Re-apply the blocks.
		apply_block_to_txhashset(&fb, ext, batch)?;
	}

	Ok((fork_point, fork_hashes)) //change the signature so we can have the local branch information.
}

/// Validate block inputs and outputs against utxo.
/// Every input must spend an unspent output.
/// No duplicate outputs created.
fn validate_utxo(
	block: &Block,
	ext: &mut txhashset::ExtensionPair<'_>,
	batch: &store::Batch<'_>,
) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
	let extension = &ext.extension;
	let header_extension = &ext.header_extension;
	extension
		.utxo_view(header_extension)
		.validate_block(block, batch)
}
