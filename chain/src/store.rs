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

//! Implements storage primitives required by the chain

use crate::linked_list::MultiIndex;
use crate::types::{CommitPos, KernelPos, SpentCommitmentRecord, SpentOutput, Tip};
use mwc_core::consensus::{self, HeaderDifficultyInfo};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::{Block, BlockHeader, BlockSums, Inputs};
use mwc_core::pow::Difficulty;
use mwc_core::ser;
use mwc_core::ser::{ProtocolVersion, Readable, Writeable};
use mwc_crates::croaring;
use mwc_crates::croaring::Bitmap;
use mwc_crates::log::debug;
use mwc_crates::secp::pedersen::Commitment;
use mwc_store::{option_to_not_found, to_key, to_key_u64, Error};
use std::convert::{TryFrom, TryInto};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const STORE_SUBPATH: &str = "chain";

const BLOCK_HEADER_PREFIX: u8 = b'h';
const BLOCK_PREFIX: u8 = b'b';
const HEAD_PREFIX: u8 = b'H';
const TAIL_PREFIX: u8 = b'T';
const HEADER_HEAD_PREFIX: u8 = b'G';
const OUTPUT_POS_PREFIX: u8 = b'p';
const KERNEL_POS_PREFIX: u8 = b'X';

/// Prefix for NRD kernel pos index lists.
pub const NRD_KERNEL_LIST_PREFIX: u8 = b'K';
/// Prefix for NRD kernel pos index entries.
pub const NRD_KERNEL_ENTRY_PREFIX: u8 = b'k';

const BLOCK_INPUT_BITMAP_PREFIX: u8 = b'B';
const BLOCK_SUMS_PREFIX: u8 = b'M';
const BLOCK_SPENT_PREFIX: u8 = b'S';
/// Replay and spent-occurrence index keyed by output commitment. Values identify
/// both the retained block that spent the commitment and the exact output PMMR
/// occurrence it consumed. On normal nodes this is not an all-history set
/// because compacted block bodies are pruned and their entries are deleted with
/// them.
const BLOCK_SPENT_COMMITMENT_PREFIX: u8 = b'C';

/// Prefix for various boolean flags stored in the db.
const BOOL_FLAG_PREFIX: u8 = b'F';
/// Prefix for named chain operation markers stored in the db.
const CHAIN_MARKER_PREFIX: u8 = b'O';
/// Boolean flag for v3 migration.
const BLOCKS_V3_MIGRATED: &str = "blocks_v3_migrated";
/// Boolean flag for full kernel excess index migration.
const KERNEL_POS_INDEX_COMPLETE: &str = "kernel_pos_index_complete";
/// Boolean flag for output_pos index completeness.
const OUTPUT_POS_INDEX_COMPLETE: &str = "output_pos_index_complete";
/// Boolean marker that the spent commitment index contains a complete baseline
/// for canonical body blocks within one cut-through horizon of the head.
/// Subsequent validation may add records for locally processed forks.
const SPENT_COMMITMENT_RECORD_INDEX_COMPLETE: &str = "spent_commitment_record_index_complete";
/// Boolean marker that legacy positions-only per-block spent indexes have been
/// migrated to the exact `SpentOutput` occurrence format.
const SPENT_INDEX_MIGRATED: &str = "spent_index_migrated";

/// Compare a trusted stored block with a candidate using the canonical v3
/// database representation. V3 intentionally normalizes legacy
/// feature-bearing inputs to commitment-only inputs.
pub(crate) fn blocks_equal_as_v3(
	context_id: u32,
	stored: &Block,
	candidate: &Block,
) -> Result<bool, ser::Error> {
	if stored.header != candidate.header {
		return Ok(false);
	}

	let version = ProtocolVersion(3);
	Ok(ser::ser_vec(context_id, &stored.body, version)?
		== ser::ser_vec(context_id, &candidate.body, version)?)
}

/// All chain-related database operations
pub struct ChainStore {
	db: mwc_store::Store,
}

impl ChainStore {
	/// Create new chain store
	pub fn new(context_id: u32, db_root: &str) -> Result<ChainStore, Error> {
		let db = mwc_store::Store::new(context_id, db_root, None, Some(STORE_SUBPATH), None)?;
		Ok(ChainStore { db })
	}

	/// The current chain head.
	pub fn head(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[HEAD_PREFIX]), || "HEAD".to_owned())
	}

	/// The current header head (may differ from chain head).
	pub fn header_head(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[HEADER_HEAD_PREFIX]), || {
			"HEADER_HEAD".to_owned()
		})
	}

	/// The current chain "tail" (earliest block in the store).
	pub fn tail(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[TAIL_PREFIX]), || "TAIL".to_owned())
	}

	/// Header of the block at the head of the block chain (not the same thing as header_head).
	pub fn head_header(&self) -> Result<BlockHeader, Error> {
		self.get_block_header(&self.head()?.last_block_h)
	}

	/// Get full block.
	pub fn get_block(&self, h: &Hash) -> Result<Block, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_PREFIX, h)), || {
			format!("BLOCK: {}", h)
		})
	}

	/// Does this full block exist?
	pub fn block_exists(&self, h: &Hash) -> Result<bool, Error> {
		self.db.exists(&to_key(BLOCK_PREFIX, h))
	}

	/// Get block_sums for the block hash.
	pub fn get_block_sums(&self, h: &Hash) -> Result<BlockSums, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_SUMS_PREFIX, h)), || {
			format!("Block sums for block: {}", h)
		})
	}

	/// Get previous header.
	pub fn get_previous_header(&self, header: &BlockHeader) -> Result<BlockHeader, Error> {
		self.get_block_header(&header.prev_hash)
	}

	/// Get block header.
	pub fn get_block_header(&self, h: &Hash) -> Result<BlockHeader, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_HEADER_PREFIX, h)), || {
			format!("BLOCK HEADER: {}", h)
		})
	}

	/// Get PMMR pos for the given output commitment.
	pub fn get_output_pos(&self, commit: &Commitment) -> Result<u64, Error> {
		match self.get_output_pos_height(commit)? {
			Some(pos) => pos
				.pos
				.checked_sub(1)
				.ok_or_else(|| Error::DataOverflow(format!("get_output_pos pos.pos={}", pos.pos))),
			None => Err(Error::NotFoundErr(format!(
				"Output position for: {:?}",
				commit
			))),
		}
	}

	/// Get PMMR pos and block height for the given output commitment.
	pub fn get_output_pos_height(&self, commit: &Commitment) -> Result<Option<CommitPos>, Error> {
		self.db.get_ser(&to_key(OUTPUT_POS_PREFIX, commit))
	}

	/// Builds a new batch for read only access with this store.
	pub fn batch_read(&self) -> Result<Batch<'_>, Error> {
		Ok(Batch {
			db: self.db.batch_read()?,
		})
	}

	/// Builds a new batch for write access to be used with this store.
	pub fn batch_write(&self) -> Result<Batch<'_>, Error> {
		Ok(Batch {
			db: self.db.batch_write()?,
		})
	}

	/// Context id assigned to this store
	pub fn get_context_id(&self) -> u32 {
		self.db.get_context_id()
	}

	/// Read the durable pending chain operation marker.
	pub fn pending_chain_operation(&self) -> Result<Option<PendingChainOperation>, Error> {
		self.batch_read()?
			.get_chain_marker(ChainMarker::LastChainOperation)
	}

	/// Set the durable pending chain operation marker.
	pub fn set_pending_chain_operation(&self, op: &PendingChainOperation) -> Result<(), Error> {
		if self.set_pending_chain_operation_if_absent(op)? {
			Ok(())
		} else {
			Err(Error::OtherErr(
				"pending chain operation requires chain init recovery".into(),
			))
		}
	}

	/// Set the durable pending chain operation marker if no marker exists.
	/// Returns true when this call wrote the marker.
	pub fn set_pending_chain_operation_if_absent(
		&self,
		op: &PendingChainOperation,
	) -> Result<bool, Error> {
		let batch = self.batch_write()?;
		if batch
			.get_chain_marker::<PendingChainOperation>(ChainMarker::LastChainOperation)?
			.is_some()
		{
			return Ok(false);
		}
		batch.set_chain_marker(ChainMarker::LastChainOperation, op)?;
		batch.commit()?;
		Ok(true)
	}

	/// Clear the durable pending chain operation marker.
	pub fn clear_pending_chain_operation(&self) -> Result<(), Error> {
		let batch = self.batch_write()?;
		batch.delete_chain_marker(ChainMarker::LastChainOperation)?;
		batch.commit()?;
		Ok(())
	}
}

/// An atomic batch in which all changes can be committed all at once or
/// discarded on error.
pub struct Batch<'a> {
	/// The underlying db instance.
	pub db: mwc_store::Batch<'a>,
}

impl<'a> Batch<'a> {
	fn ignore_not_found(result: Result<(), Error>) -> Result<(), Error> {
		match result {
			Ok(()) => Ok(()),
			Err(e) if e.store_error_is_not_found() => Ok(()),
			Err(e) => Err(e),
		}
	}

	/// Context id assigned to this store batch.
	pub fn get_context_id(&self) -> u32 {
		self.db.get_context_id()
	}

	/// The head.
	pub fn head(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[HEAD_PREFIX]), || "HEAD".to_owned())
	}

	/// The tail.
	pub fn tail(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[TAIL_PREFIX]), || "TAIL".to_owned())
	}

	/// The current header head (may differ from chain head).
	pub fn header_head(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[HEADER_HEAD_PREFIX]), || {
			"HEADER_HEAD".to_owned()
		})
	}

	/// Header of the block at the head of the block chain (not the same thing as header_head).
	pub fn head_header(&self) -> Result<BlockHeader, Error> {
		self.get_block_header(&self.head()?.last_block_h)
	}

	/// Save body head to db.
	pub fn save_body_head(&self, t: &Tip) -> Result<(), Error> {
		self.db.put_ser(&[HEAD_PREFIX], t)
	}

	/// Save body "tail" to db.
	pub fn save_body_tail(&self, t: &Tip) -> Result<(), Error> {
		self.db.put_ser(&[TAIL_PREFIX], t)
	}

	/// Delete body "tail" from db.
	pub fn delete_body_tail(&self) -> Result<(), Error> {
		Self::ignore_not_found(self.db.delete(&[TAIL_PREFIX]))
	}

	/// Save header head to db.
	pub fn save_header_head(&self, t: &Tip) -> Result<(), Error> {
		self.db.put_ser(&[HEADER_HEAD_PREFIX], t)
	}

	/// get block
	pub fn get_block(&self, h: &Hash) -> Result<Block, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_PREFIX, h)), || {
			format!("Block with hash: {}", h)
		})
	}

	/// Does the block exist?
	pub fn block_exists(&self, h: &Hash) -> Result<bool, Error> {
		self.db.exists(&to_key(BLOCK_PREFIX, h))
	}

	/// Whether any persisted block-header records exist.
	pub(crate) fn has_any_block_headers(&self) -> Result<bool, Error> {
		self.has_any_prefixed_records(BLOCK_HEADER_PREFIX)
	}

	/// Whether any persisted full-block records exist.
	pub(crate) fn has_any_full_blocks(&self) -> Result<bool, Error> {
		self.has_any_prefixed_records(BLOCK_PREFIX)
	}

	fn has_any_prefixed_records(&self, record_prefix: u8) -> Result<bool, Error> {
		let prefix = to_key(record_prefix, "");
		let mut entries = self.db.iter(&prefix, |_, _| Ok(()))?;
		match entries.next() {
			Some(entry) => {
				entry?;
				Ok(true)
			}
			None => Ok(false),
		}
	}

	/// Whether any persisted chain records exist that cannot be created by the
	/// pre-setup migration of an otherwise fresh database.
	///
	/// `BLOCKS_V3_MIGRATED` is deliberately excluded because startup writes it
	/// before `setup_head()` even when the chain database has never held a block.
	pub(crate) fn has_any_auxiliary_chain_state(&self) -> Result<bool, Error> {
		for prefix in [
			OUTPUT_POS_PREFIX,
			KERNEL_POS_PREFIX,
			NRD_KERNEL_LIST_PREFIX,
			NRD_KERNEL_ENTRY_PREFIX,
			BLOCK_INPUT_BITMAP_PREFIX,
			BLOCK_SUMS_PREFIX,
			BLOCK_SPENT_PREFIX,
			BLOCK_SPENT_COMMITMENT_PREFIX,
			CHAIN_MARKER_PREFIX,
		] {
			if self.has_any_prefixed_records(prefix)? {
				return Ok(true);
			}
		}

		// Existence, rather than the decoded boolean value, is the freshness
		// signal. A persisted false completeness flag still proves that setup or
		// recovery previously reached this database.
		for flag in [
			KERNEL_POS_INDEX_COMPLETE,
			OUTPUT_POS_INDEX_COMPLETE,
			SPENT_COMMITMENT_RECORD_INDEX_COMPLETE,
		] {
			if self.db.exists(&to_key(BOOL_FLAG_PREFIX, flag))? {
				return Ok(true);
			}
		}

		Ok(false)
	}

	/// Save the block to the db.
	/// Note: the block header is not saved to the db here, assumes this has already been done.
	/// This is a low-level persistence primitive: it does not validate PoW or the
	/// body, so production callers must perform consensus validation first. It
	/// enforces exact identity with the separately stored complete header and
	/// preserves any canonical full body already stored under the block hash.
	pub fn save_block(&self, b: &Block) -> Result<(), Error> {
		let block_hash = b.hash(self.get_context_id())?;
		let stored_header = self.get_block_header(&block_hash)?;
		if stored_header != b.header {
			return Err(Error::OtherErr(format!(
				"refusing to save full block {} with a header that differs from the separately stored header",
				block_hash
			)));
		}

		match self.get_block(&block_hash) {
			Ok(existing) if blocks_equal_as_v3(self.get_context_id(), &existing, b)? => {
				// Preserve the validated body that first claimed this header. This is
				// also the idempotent path for equivalent v2/v3 input encodings.
				return Ok(());
			}
			Ok(_) => {
				return Err(Error::OtherErr(format!(
					"refusing to overwrite full block {} with a different body for the same header",
					block_hash
				)));
			}
			Err(e) if e.store_error_is_not_found() => {}
			Err(e) => return Err(e),
		}

		debug!(
			"save_block: {} at {} ({} -> v{})",
			block_hash,
			b.header.height,
			b.inputs().version_str(),
			self.db.protocol_version(),
		);
		self.db.put_ser(&to_key(BLOCK_PREFIX, block_hash)[..], b)?;
		Ok(())
	}

	/// Maintain the exact outputs spent by each full block so `output_pos` can be
	/// restored during rewind. Each PMMR position remains paired with the
	/// commitment authenticated at that position during block validation; callers
	/// must not reconstruct this association from block input order.
	pub fn save_spent_index(&self, h: &Hash, spent: &[SpentOutput]) -> Result<(), Error> {
		self.db
			.put_ser(&to_key(BLOCK_SPENT_PREFIX, h)[..], &spent.to_vec())?;
		Ok(())
	}

	/// Record that `spent` was consumed by a retained full block.
	///
	/// This feeds the replay-protection index under BLOCK_SPENT_COMMITMENT_PREFIX.
	/// The index contains commitments spent by retained block bodies only. Normal
	/// nodes delete older full blocks during compaction, and delete these entries
	/// at the same time, so callers must not treat this as all historical spends.
	pub fn save_spent_commitments(
		&self,
		spent: &Commitment,
		record: SpentCommitmentRecord,
	) -> Result<(), Error> {
		let records = self
			.db
			.get_ser(&to_key(BLOCK_SPENT_COMMITMENT_PREFIX, spent))?;
		let mut spent_list = records.unwrap_or_default();

		if !Self::append_spent_commitment(&mut spent_list, record)? {
			return Ok(());
		}
		self.db.put_ser(
			&to_key(BLOCK_SPENT_COMMITMENT_PREFIX, spent)[..],
			&spent_list.to_vec(),
		)?;
		Ok(())
	}

	fn append_spent_commitment(
		spent_list: &mut Vec<SpentCommitmentRecord>,
		record: SpentCommitmentRecord,
	) -> Result<bool, Error> {
		if let Some(existing) = spent_list
			.iter()
			.find(|existing| existing.spending_block.hash == record.spending_block.hash)
		{
			if existing == &record {
				return Ok(false);
			}
			return Err(Error::OtherErr(format!(
				"conflicting spent commitment records for spending block {}: existing {:?}, new {:?}",
				record.spending_block.hash, existing, record
			)));
		}
		let spent_count = u64::try_from(spent_list.len()).map_err(|_| {
			Error::DataOverflow(format!(
				"spent commitment list length does not fit u64: {}",
				spent_list.len()
			))
		})?;
		if spent_count >= ser::READ_VEC_SIZE_LIMIT {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"spent commitment list length exceeds {} entries",
				ser::READ_VEC_SIZE_LIMIT
			))
			.into());
		}
		spent_list.push(record);
		Ok(true)
	}

	/// Return retained-block spends recorded for `spent`.
	///
	/// `None` means no retained indexed block is known to have spent this
	/// commitment. It is only safe to interpret this as a replay-check miss after
	/// `is_spent_commitment_record_index_complete()` has returned true.
	pub fn get_spent_commitments(
		&self,
		spent: &Commitment,
	) -> Result<Option<Vec<SpentCommitmentRecord>>, Error> {
		self.db
			.get_ser(&to_key(BLOCK_SPENT_COMMITMENT_PREFIX, spent))
	}

	// /// An iterator to all "spent" commit in db
	// pub fn spent_commitment_iter(&self) -> Result<SerIterator<Vec<Commitment>>, Error> {
	// 	let key = to_key(BLOCK_SPENT_COMMITMENT_PREFIX, "");
	// 	self.db.iter(&key)
	// }

	/// DB flag representing full migration of blocks to v3 version.
	/// Default to false if flag not present.
	pub fn is_blocks_v3_migrated(&self) -> Result<bool, Error> {
		self.get_bool_flag(BLOCKS_V3_MIGRATED)
	}

	/// Set DB flag representing full migration of blocks to v3 version.
	pub fn set_blocks_v3_migrated(&self, migrated: bool) -> Result<(), Error> {
		self.set_bool_flag(BLOCKS_V3_MIGRATED, migrated)
	}

	/// DB flag representing a complete kernel excess index.
	/// Default to false if flag not present.
	pub fn is_kernel_pos_index_complete(&self) -> Result<bool, Error> {
		self.get_bool_flag(KERNEL_POS_INDEX_COMPLETE)
	}

	/// Set DB flag representing a complete kernel excess index.
	pub fn set_kernel_pos_index_complete(&self, complete: bool) -> Result<(), Error> {
		self.set_bool_flag(KERNEL_POS_INDEX_COMPLETE, complete)
	}

	/// DB flag representing a complete output_pos index.
	/// Default to false if flag not present.
	pub fn is_output_pos_index_complete(&self) -> Result<bool, Error> {
		self.get_bool_flag(OUTPUT_POS_INDEX_COMPLETE)
	}

	/// Set DB flag representing a complete output_pos index.
	pub fn set_output_pos_index_complete(&self, complete: bool) -> Result<(), Error> {
		self.set_bool_flag(OUTPUT_POS_INDEX_COMPLETE, complete)
	}

	/// Whether BLOCK_SPENT_COMMITMENT_PREFIX is complete and all values use
	/// `SpentCommitmentRecord`. Production code establishes this at an empty trusted
	/// boundary, maintains it through validated UTXO transitions, or rebuilds it
	/// from the local per-block spent index. That per-block index is admissible for
	/// rebuild because its exact positions were produced by UTXO validation (with
	/// migrated commitments additionally resolved from the raw output PMMR), and
	/// rebuild rechecks the corresponding canonical block bodies. This marker must
	/// not be established from peer-supplied or otherwise unauthenticated positions.
	pub fn is_spent_commitment_record_index_complete(&self) -> Result<bool, Error> {
		self.get_bool_flag(SPENT_COMMITMENT_RECORD_INDEX_COMPLETE)
	}

	/// Set the exact spent-occurrence index trust/completeness marker.
	pub fn set_spent_commitment_record_index_complete(&self, complete: bool) -> Result<(), Error> {
		self.set_bool_flag(SPENT_COMMITMENT_RECORD_INDEX_COMPLETE, complete)
	}

	/// Check whether legacy positions-only per-block spent indexes in the active
	/// rewind window have been migrated to the exact `SpentOutput` format.
	pub fn is_spent_index_migrated(&self) -> Result<bool, Error> {
		self.get_bool_flag(SPENT_INDEX_MIGRATED)
	}

	/// Set the spent index migration marker.
	pub fn set_spent_index_migrated(&self, migrated: bool) -> Result<(), Error> {
		self.set_bool_flag(SPENT_INDEX_MIGRATED, migrated)
	}

	/// Read a named DB boolean flag.
	/// Default to false if flag not present.
	pub fn get_bool_flag(&self, flag: &str) -> Result<bool, Error> {
		let value: Option<BoolFlag> = self.db.get_ser(&to_key(BOOL_FLAG_PREFIX, flag))?;
		match value {
			None => Ok(false),
			Some(x) => Ok(x.into()),
		}
	}

	/// Set a named DB boolean flag.
	pub fn set_bool_flag(&self, flag: &str, value: bool) -> Result<(), Error> {
		self.db
			.put_ser(&to_key(BOOL_FLAG_PREFIX, flag)[..], &BoolFlag(value))?;
		Ok(())
	}

	/// Delete a named DB boolean flag.
	pub fn delete_bool_flag(&self, flag: &str) -> Result<(), Error> {
		self.db.delete(&to_key(BOOL_FLAG_PREFIX, flag))
	}

	/// Read a named chain marker.
	pub fn get_chain_marker<T: Readable>(&self, marker: ChainMarker) -> Result<Option<T>, Error> {
		self.db.get_ser(&to_key(CHAIN_MARKER_PREFIX, marker.name()))
	}

	/// Set a named chain marker.
	pub fn set_chain_marker<T: Writeable>(
		&self,
		marker: ChainMarker,
		value: &T,
	) -> Result<(), Error> {
		self.db
			.put_ser(&to_key(CHAIN_MARKER_PREFIX, marker.name())[..], value)
	}

	/// Delete a named chain marker.
	pub fn delete_chain_marker(&self, marker: ChainMarker) -> Result<(), Error> {
		self.db.delete(&to_key(CHAIN_MARKER_PREFIX, marker.name()))
	}

	/// Migrate a block stored in the db reading from one protocol version and writing
	/// with new protocol version.
	pub fn migrate_block(
		&self,
		key: &[u8],
		from_version: ProtocolVersion,
		to_version: ProtocolVersion,
	) -> Result<(), Error> {
		let context_id = self.db.get_context_id();
		let block: Block = option_to_not_found(
			self.db.get_with(key, move |_, mut v| {
				ser::deserialize_strict(&mut v, from_version, context_id).map_err(From::from)
			}),
			|| format!("BLOCK: {:?}", key),
		)?;
		self.db.put_ser_with_version(key, &block, to_version)?;
		Ok(())
	}

	/// Low level function to delete directly by raw key.
	pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
		self.db.delete(key)
	}

	/// Delete a full block. Does not delete any record associated with a block
	/// header. Verify the full-block key and complete header before trusting its
	/// inputs to remove secondary spent-commitment entries.
	pub fn delete_block(&self, bh: &Hash) -> Result<(), Error> {
		let block = self.get_block(bh)?;
		self.delete_block_with_body(bh, block)
	}

	/// Delete a full block if its canonical record still exists.
	///
	/// Returns `false` only when the initial full-block lookup is missing. Once
	/// the block has been loaded, all subsequent errors (including a missing
	/// separately stored header) are propagated as persisted-state failures.
	pub fn delete_block_if_exists(&self, bh: &Hash) -> Result<bool, Error> {
		let block = match self.get_block(bh) {
			Ok(block) => block,
			Err(e) if e.store_error_is_not_found() => return Ok(false),
			Err(e) => return Err(e),
		};
		self.delete_block_with_body(bh, block)?;
		Ok(true)
	}

	fn delete_block_with_body(&self, bh: &Hash, block: Block) -> Result<(), Error> {
		let block_hash = block.hash(self.get_context_id())?;
		if block_hash != *bh {
			return Err(Error::OtherErr(format!(
				"refusing to delete full block loaded from key {} with computed hash {}",
				bh, block_hash
			)));
		}
		let stored_header = self.get_block_header(bh)?;
		if block.header != stored_header {
			return Err(Error::OtherErr(format!(
				"refusing to delete full block {} with a header that differs from the separately stored header",
				bh
			)));
		}
		let inputs = block.inputs();
		match inputs {
			// Missing records are acceptable during idempotent cleanup.
			Inputs::CommitOnly(inputs) => {
				for input in inputs {
					Self::ignore_not_found(self.delete_spent_commitments(&input.commitment(), bh))?;
				}
			}
			Inputs::FeaturesAndCommit(inputs) => {
				for input in inputs {
					Self::ignore_not_found(self.delete_spent_commitments(&input.commitment(), bh))?;
				}
			}
		}

		self.db.delete(&to_key(BLOCK_PREFIX, bh)[..])?;

		Self::ignore_not_found(self.delete_block_sums(bh))?;
		Self::ignore_not_found(self.delete_spent_index(bh))?;

		Ok(())
	}

	/// Delete a block header.
	pub fn delete_block_header(&self, h: &Hash) -> Result<(), Error> {
		self.db.delete(&to_key(BLOCK_HEADER_PREFIX, h)[..])
	}

	/// Save block header to db.
	pub fn save_block_header(&self, header: &BlockHeader) -> Result<(), Error> {
		let hash = header.hash(self.get_context_id())?;
		// Defense in depth for local persistence. This is not a cryptographic
		// collision check: normal PoW validation is what binds the complete header
		// to this proof-derived key.
		match self.get_block_header(&hash) {
			Ok(stored) if stored != *header => {
				return Err(Error::OtherErr(format!(
					"refusing to overwrite header key {} with a different complete header",
					hash
				)));
			}
			Ok(_) => return Ok(()),
			Err(e) if e.store_error_is_not_found() => {}
			Err(e) => return Err(e),
		}

		// Store the header itself indexed by hash.
		self.db
			.put_ser(&to_key(BLOCK_HEADER_PREFIX, hash)[..], header)?;

		Ok(())
	}

	/// Save output_pos and block height to index.
	pub fn save_output_pos_height(&self, commit: &Commitment, pos: CommitPos) -> Result<(), Error> {
		self.db
			.put_ser(&to_key(OUTPUT_POS_PREFIX, commit)[..], &pos)
	}

	fn kernel_pos_key(excess: &Commitment, pos: u64) -> Result<Vec<u8>, Error> {
		to_key_u64(KERNEL_POS_PREFIX, excess, pos)
	}

	fn kernel_pos_prefix(excess: &Commitment) -> Vec<u8> {
		to_key(KERNEL_POS_PREFIX, excess)
	}

	/// Save kernel_pos and block height to index.
	pub fn save_kernel_pos(&self, excess: &Commitment, pos: KernelPos) -> Result<(), Error> {
		self.db
			.put_ser(&Self::kernel_pos_key(excess, pos.pos)?[..], &pos)
	}

	/// Delete a kernel_pos index entry.
	pub fn delete_kernel_pos(&self, excess: &Commitment, pos: u64) -> Result<(), Error> {
		self.db.delete(&Self::kernel_pos_key(excess, pos)?)
	}

	/// Iterator over kernel_pos entries for a specific kernel excess.
	pub fn kernel_pos_iter(
		&self,
		excess: &Commitment,
	) -> Result<impl Iterator<Item = Result<KernelPos, Error>> + '_, Error> {
		let key = Self::kernel_pos_prefix(excess);
		let protocol_version = self.db.protocol_version();
		let context_id = self.db.get_context_id();
		self.db.iter(&key, move |_, mut v| {
			ser::deserialize_strict(&mut v, protocol_version, context_id).map_err(From::from)
		})
	}

	/// Clear the full kernel_pos index.
	pub fn clear_kernel_pos_index(&self) -> Result<(), Error> {
		let prefix = to_key(KERNEL_POS_PREFIX, "");
		let keys = self
			.db
			.iter(&prefix, |k, _| Ok(k.to_vec()))?
			.collect::<Result<Vec<_>, Error>>()?;
		for key in keys {
			self.db.delete(&key)?;
		}
		Ok(())
	}

	/// Clear up to `limit` full kernel_pos index entries.
	pub fn clear_kernel_pos_index_chunk(&self, limit: usize) -> Result<usize, Error> {
		let prefix = to_key(KERNEL_POS_PREFIX, "");
		let keys = self
			.db
			.iter(&prefix, |k, _| Ok(k.to_vec()))?
			.take(limit)
			.collect::<Result<Vec<_>, Error>>()?;
		let deleted = keys.len();
		for key in keys {
			self.db.delete(&key)?;
		}
		Ok(deleted)
	}

	/// Clear up to `limit` retained spent commitment replay index entries.
	pub fn clear_spent_commitment_index_chunk(&self, limit: usize) -> Result<usize, Error> {
		let prefix = to_key(BLOCK_SPENT_COMMITMENT_PREFIX, "");
		let keys = self
			.db
			.iter(&prefix, |k, _| Ok(k.to_vec()))?
			.take(limit)
			.collect::<Result<Vec<_>, Error>>()?;
		let deleted = keys.len();
		for key in keys {
			self.db.delete(&key)?;
		}
		Ok(deleted)
	}

	/// Delete the output_pos index entry for a spent output.
	pub fn delete_output_pos_height(&self, commit: &Commitment) -> Result<(), Error> {
		self.db.delete(&to_key(OUTPUT_POS_PREFIX, commit))
	}

	/// Delete the retained-block spend record for `spent` in block `hash`.
	///
	/// Called when a retained full block is deleted during compaction or cleanup.
	/// This keeps the replay index scoped to locally retained full block bodies.
	pub fn delete_spent_commitments(&self, spent: &Commitment, hash: &Hash) -> Result<(), Error> {
		let records = self.get_spent_commitments(spent)?.unwrap_or_default();
		let filtered_list: Vec<SpentCommitmentRecord> = records
			.into_iter()
			.filter(|record| record.spending_block.hash != *hash)
			.collect();

		if !filtered_list.is_empty() {
			self.db.put_ser(
				&to_key(BLOCK_SPENT_COMMITMENT_PREFIX, spent)[..],
				&filtered_list,
			)?;
		} else {
			self.db
				.delete(&to_key(BLOCK_SPENT_COMMITMENT_PREFIX, spent))?;
		}

		Ok(())
	}

	/// When using the output_pos iterator we have access to the index keys but not the
	/// original commitment that the key is constructed from. So we need a way of comparing
	/// a key with another commitment without reconstructing the commitment from the key bytes.
	pub fn is_match_output_pos_key(&self, key: &[u8], commit: &Commitment) -> bool {
		let commit_key = to_key(OUTPUT_POS_PREFIX, commit);
		commit_key == key
	}

	/// Iterator over the output_pos index.
	pub fn output_pos_iter(
		&self,
	) -> Result<impl Iterator<Item = Result<(Vec<u8>, CommitPos), Error>> + '_, Error> {
		let key = to_key(OUTPUT_POS_PREFIX, "");
		let protocol_version = self.db.protocol_version();
		let context_id = self.db.get_context_id();
		self.db.iter(&key, move |k, mut v| {
			ser::deserialize_strict(&mut v, protocol_version, context_id)
				.map(|pos| (k.to_vec(), pos))
				.map_err(From::from)
		})
	}

	/// Get output_pos from index.
	pub fn get_output_pos(&self, commit: &Commitment) -> Result<u64, Error> {
		match self.get_output_pos_height(commit)? {
			Some(pos) => pos
				.pos
				.checked_sub(1)
				.ok_or_else(|| Error::DataOverflow(format!("get_output_pos pos.pos={}", pos.pos))),
			None => Err(Error::NotFoundErr(format!(
				"Output position for: {:?}",
				commit
			))),
		}
	}

	/// Get output_pos and block height from index.
	pub fn get_output_pos_height(&self, commit: &Commitment) -> Result<Option<CommitPos>, Error> {
		self.db.get_ser(&to_key(OUTPUT_POS_PREFIX, commit))
	}

	/// Get the previous header.
	pub fn get_previous_header(&self, header: &BlockHeader) -> Result<BlockHeader, Error> {
		self.get_block_header(&header.prev_hash)
	}

	/// Get block header.
	pub fn get_block_header(&self, h: &Hash) -> Result<BlockHeader, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_HEADER_PREFIX, h)), || {
			format!("BLOCK HEADER: {}", h)
		})
	}

	/// Delete the block spent index.
	fn delete_spent_index(&self, bh: &Hash) -> Result<(), Error> {
		// Clean up the legacy input bitmap as well.
		Self::ignore_not_found(self.db.delete(&to_key(BLOCK_INPUT_BITMAP_PREFIX, bh)))?;

		// Tolerate a missing record: the spent index migration deletes
		// entries outside the supported rewind window before their blocks
		// are cleaned up.
		Self::ignore_not_found(self.db.delete(&to_key(BLOCK_SPENT_PREFIX, bh)))
	}

	/// Save block_sums for the block.
	pub fn save_block_sums(&self, h: &Hash, sums: BlockSums) -> Result<(), Error> {
		self.db.put_ser(&to_key(BLOCK_SUMS_PREFIX, h)[..], &sums)
	}

	/// Get block_sums for the block.
	pub fn get_block_sums(&self, h: &Hash) -> Result<BlockSums, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_SUMS_PREFIX, h)), || {
			format!("Block sums for block: {}", h)
		})
	}

	/// Delete the block_sums for the block.
	fn delete_block_sums(&self, bh: &Hash) -> Result<(), Error> {
		self.db.delete(&to_key(BLOCK_SUMS_PREFIX, bh))
	}

	/// Get the block input bitmap based on our spent index.
	/// Fallback to legacy block input bitmap from the db.
	pub fn get_block_input_bitmap(&self, bh: &Hash) -> Result<Bitmap, Error> {
		match self.get_spent_index(bh) {
			Ok(spent) => {
				let mut bitmap = Bitmap::new();
				for spent_output in spent {
					let pos = spent_output.position.pos.try_into().map_err(|e| {
						Error::OtherErr(format!(
							"Invalid commit pos, spent index value {:?}, {}",
							spent_output, e
						))
					})?;
					bitmap.add(pos);
				}
				Ok(bitmap)
			}
			Err(e) if e.store_error_is_not_found() => self.get_legacy_input_bitmap(bh),
			Err(e) => Err(e),
		}
	}

	fn get_legacy_input_bitmap(&self, bh: &Hash) -> Result<Bitmap, Error> {
		option_to_not_found(
			self.db
				.get_with(&to_key(BLOCK_INPUT_BITMAP_PREFIX, bh), move |_, data| {
					let bitmap =
						Bitmap::try_deserialize::<croaring::Portable>(data).ok_or_else(|| {
							Error::OtherErr(format!(
								"Invalid legacy block input bitmap for block {}",
								bh
							))
						})?;
					if bitmap.get_serialized_size_in_bytes::<croaring::Portable>() != data.len() {
						return Err(Error::OtherErr(format!(
							"Invalid legacy block input bitmap for block {}",
							bh
						)));
					}
					Ok(bitmap)
				}),
			|| "legacy block input bitmap".to_string(),
		)
	}

	/// Get the exact commitment-to-occurrence index for the specified block.
	/// If we rewind the block, the positions are used to unspend its inputs.
	pub fn get_spent_index(&self, bh: &Hash) -> Result<Vec<SpentOutput>, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_SPENT_PREFIX, bh)), || {
			format!("spent index: {}", bh)
		})
	}

	/// Read a spent index entry written before the exact-occurrence format:
	/// positions only, paired positionally with the block's inputs.
	pub fn get_spent_index_legacy(&self, bh: &Hash) -> Result<Vec<CommitPos>, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_SPENT_PREFIX, bh)), || {
			format!("legacy spent index: {}", bh)
		})
	}

	/// Write a legacy-format (positions only) spent index entry. Exists so
	/// tests can model databases written before the exact-occurrence format.
	#[cfg(test)]
	pub fn save_spent_index_legacy(&self, h: &Hash, spent: &[CommitPos]) -> Result<(), Error> {
		self.db
			.put_ser(&to_key(BLOCK_SPENT_PREFIX, h)[..], &spent.to_vec())?;
		Ok(())
	}

	/// Iterator over raw per-block spent index keys starting at `start`.
	///
	/// Values are deliberately not loaded: the spent index migration reads
	/// each entry through the typed accessors after inspecting the record key.
	/// The first key is greater than or equal to `start`, allowing the migration
	/// to release its read transaction between write chunks.
	pub fn spent_index_key_iter_from(
		&self,
		start: &[u8],
	) -> Result<impl Iterator<Item = Result<Vec<u8>, Error>> + '_, Error> {
		let prefix = to_key(BLOCK_SPENT_PREFIX, "");
		self.db.iter_from(&prefix, start, |key, _| Ok(key.to_vec()))
	}

	/// Commits this batch. If it's a child batch, it will be merged with the
	/// parent, otherwise the batch is written to db.
	pub fn commit(self) -> Result<(), Error> {
		self.db.commit()
	}

	/// Creates a child of this batch. It will be merged with its parent on
	/// commit, abandoned otherwise.
	pub fn child(&mut self) -> Result<Batch<'_>, Error> {
		Ok(Batch {
			db: self.db.child()?,
		})
	}

	/// Iterator over all full blocks in the db.
	/// Uses default db serialization strategy via db protocol version.
	pub fn blocks_iter(&self) -> Result<impl Iterator<Item = Result<Block, Error>> + '_, Error> {
		let key = to_key(BLOCK_PREFIX, "");
		let protocol_version = self.db.protocol_version();
		let context_id = self.db.get_context_id();
		self.db.iter(&key, move |raw_key, mut v| {
			let block: Block = ser::deserialize_strict(&mut v, protocol_version, context_id)?;
			let block_hash = block.hash(context_id)?;
			let expected_key = to_key(BLOCK_PREFIX, block_hash);
			if raw_key != expected_key.as_slice() {
				return Err(Error::OtherErr(format!(
					"full block {} is stored under noncanonical key {:?}",
					block_hash, raw_key
				)));
			}
			Ok(block)
		})
	}

	/// Iterator over raw data for full blocks in the db.
	/// Used during block migration (we need flexibility around deserialization).
	pub fn blocks_raw_iter(
		&self,
	) -> Result<impl Iterator<Item = Result<(Vec<u8>, Vec<u8>), Error>> + '_, Error> {
		let key = to_key(BLOCK_PREFIX, "");
		self.db.iter(&key, |k, v| Ok((k.to_vec(), v.to_vec())))
	}

	/// Protocol version of our underlying db.
	pub fn protocol_version(&self) -> ProtocolVersion {
		self.db.protocol_version()
	}
}

/// An iterator on blocks, from latest to earliest, specialized to return
/// information pertaining to block difficulty calculation (timestamp and
/// previous difficulties). Mostly used by the consensus next difficulty
/// calculation.
pub struct DifficultyIter<'a> {
	start: Hash,
	store: Option<Arc<ChainStore>>,
	batch: Option<&'a Batch<'a>>,

	// maintain state for both the "next" header in this iteration
	// and its previous header in the chain ("next next" in the iteration)
	// so we effectively read-ahead as we iterate through the chain back
	// toward the genesis block (while maintaining current state)
	header: Option<BlockHeader>,
	prev_header: Option<BlockHeader>,
	prev_header_hash: Option<Hash>,
}

impl<'a> DifficultyIter<'a> {
	/// Build a new iterator using the provided chain store and starting from
	/// the provided block hash.
	pub fn from<'b>(start: Hash, store: Arc<ChainStore>) -> DifficultyIter<'b> {
		DifficultyIter {
			start,
			store: Some(store),
			batch: None,
			header: None,
			prev_header: None,
			prev_header_hash: None,
		}
	}

	/// Build a new iterator using the provided chain store batch and starting from
	/// the provided block hash.
	pub fn from_batch(start: Hash, batch: &'a Batch<'a>) -> DifficultyIter<'a> {
		DifficultyIter {
			start,
			store: None,
			batch: Some(batch),
			header: None,
			prev_header: None,
			prev_header_hash: None,
		}
	}
}

impl<'a> Iterator for DifficultyIter<'a> {
	type Item = Result<HeaderDifficultyInfo, consensus::Error>;

	fn next(&mut self) -> Option<Self::Item> {
		// Get both header and previous_header if this is the initial iteration.
		// Otherwise move prev_header to header and get the next prev_header.
		let mut read_error: Option<mwc_store::lmdb::Error> = None;

		let (cur_header, cur_header_hash) = if self.header.is_none() {
			if let Some(ref batch) = self.batch {
				(
					batch
						.get_block_header(&self.start)
						.map_err(|e| read_error = Some(e))
						.ok(),
					Some(self.start),
				)
			} else if let Some(ref store) = self.store {
				(
					store
						.get_block_header(&self.start)
						.map_err(|e| read_error = Some(e))
						.ok(),
					Some(self.start),
				)
			} else {
				(None, None)
			}
		} else {
			(self.prev_header.clone(), self.prev_header_hash)
		};

		self.header = cur_header;
		if self.header.is_none() {
			if let Some(err) = read_error {
				return Some(Err(mwc_core::consensus::Error::HeaderIO(err.to_string())));
			}
		}

		// If we have a header we can do this iteration.
		// Otherwise we are done.
		if let Some(header) = self.header.clone() {
			if header.height == 0 {
				// Genesis has no previous header; avoid masking any storage error as an
				// expected missing previous header.
				self.prev_header = None;
			} else if let Some(ref batch) = self.batch {
				self.prev_header = batch
					.get_previous_header(&header)
					.map_err(|e| read_error = Some(e))
					.ok();
			} else if let Some(ref store) = self.store {
				self.prev_header = store
					.get_previous_header(&header)
					.map_err(|e| read_error = Some(e))
					.ok();
			} else {
				self.prev_header = None;
			}

			self.prev_header_hash = Some(header.prev_hash);

			let prev_difficulty = match &self.prev_header {
				Some(h) => h.total_difficulty().clone(),
				None => {
					if header.height == 0 {
						Difficulty::zero()
					} else {
						// Note, Not enough history data can be triggered by data storage failure or data corruption.
						match read_error {
							Some(err) => {
								return Some(Err(mwc_core::consensus::Error::HeaderIO(
									err.to_string(),
								)))
							}
							None => return Some(Err(mwc_core::consensus::Error::HistoryTooShort)),
						}
					}
				}
			};

			let difficulty = match header.total_difficulty() - prev_difficulty {
				Ok(diff) => diff,
				Err(e) => {
					return Some(Err(consensus::Error::DataOverflow(format!(
						"DifficultyIter::next, {}",
						e.to_string()
					))))
				}
			};

			let scaling = header.pow.secondary_scaling;
			let timestamp = match u64::try_from(header.timestamp.timestamp()) {
				Ok(timestamp) => timestamp,
				Err(_) => {
					return Some(Err(consensus::Error::DataOverflow(format!(
						"DifficultyIter::next, timestamp={}",
						header.timestamp.timestamp()
					))));
				}
			};

			Some(Ok(HeaderDifficultyInfo::new(
				header.height,
				cur_header_hash,
				timestamp,
				difficulty,
				scaling,
				header.pow.is_secondary(),
			)))
		} else {
			match read_error {
				Some(err) => Some(Err(mwc_core::consensus::Error::HeaderIO(err.to_string()))),
				None => None,
			}
		}
	}
}

/// Init the NRD "recent history" kernel index backed by the underlying db.
/// List index supports multiple entries per key, maintaining insertion order.
/// Allows for fast lookup of the most recent entry per excess commitment.
pub fn nrd_recent_kernel_index() -> MultiIndex<CommitPos> {
	MultiIndex::init(NRD_KERNEL_LIST_PREFIX, NRD_KERNEL_ENTRY_PREFIX)
}

/// Named chain markers stored in the chain DB.
#[derive(Debug, Clone, Copy)]
pub enum ChainMarker {
	/// The last chain operation that crossed the LMDB/PMMR boundary.
	LastChainOperation,
}

impl ChainMarker {
	fn name(self) -> &'static str {
		match self {
			ChainMarker::LastChainOperation => "last_chain_operation",
		}
	}
}

/// Chain operation kind recorded in a pending operation marker.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChainOperationKind {
	/// PIBD reset.
	PibdReset,
	/// Reset chain head owner API operation.
	ResetChainHead,
	/// Reset body/header state to genesis.
	ResetToGenesis,
	/// Rewind triggered by a known bad block.
	RewindBadBlock,
	/// Full block processing.
	ProcessBlock,
	/// Single header processing.
	ProcessHeader,
	/// Header sync processing.
	SyncHeaders,
	/// Chain compaction.
	Compact,
	/// Readonly PMMR extension discard failed.
	ReadonlyPmmrDiscard,
}

impl ChainOperationKind {
	fn from_u8(value: u8) -> Option<Self> {
		match value {
			0 => Some(ChainOperationKind::PibdReset),
			1 => Some(ChainOperationKind::ResetChainHead),
			2 => Some(ChainOperationKind::ResetToGenesis),
			3 => Some(ChainOperationKind::RewindBadBlock),
			4 => Some(ChainOperationKind::ProcessBlock),
			5 => Some(ChainOperationKind::ProcessHeader),
			6 => Some(ChainOperationKind::SyncHeaders),
			7 => Some(ChainOperationKind::Compact),
			8 => Some(ChainOperationKind::ReadonlyPmmrDiscard),
			_ => None,
		}
	}
}

impl Writeable for ChainOperationKind {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let value = match self {
			ChainOperationKind::PibdReset => 0,
			ChainOperationKind::ResetChainHead => 1,
			ChainOperationKind::ResetToGenesis => 2,
			ChainOperationKind::RewindBadBlock => 3,
			ChainOperationKind::ProcessBlock => 4,
			ChainOperationKind::ProcessHeader => 5,
			ChainOperationKind::SyncHeaders => 6,
			ChainOperationKind::Compact => 7,
			ChainOperationKind::ReadonlyPmmrDiscard => 8,
		};
		writer.write_u8(value)
	}
}

impl Readable for ChainOperationKind {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let value = reader.read_u8()?;
		Self::from_u8(value).ok_or(ser::Error::CorruptedData(format!(
			"Invalid chain operation kind {}",
			value
		)))
	}
}

/// Durable payload for an interrupted chain operation.
#[derive(Debug, Clone, PartialEq)]
pub enum PendingChainOperation {
	/// PIBD reset was interrupted.
	PibdReset,
	/// Reset to genesis was interrupted.
	ResetToGenesis,
	/// Chain-head reset was interrupted.
	ResetChainHead {
		/// Body head before the operation started.
		original_body_head: Tip,
		/// Header head before the operation started.
		original_header_head: Tip,
		/// Intended body head after the reset.
		target_body_head: Tip,
		/// Intended header head after the reset.
		target_header_head: Tip,
		/// Whether the operation intended to rewind header PMMR state.
		rewind_headers: bool,
	},
	/// Generic operation that should recover by reconciling PMMRs to durable DB heads.
	ReconcileHeads {
		/// Operation kind.
		kind: ChainOperationKind,
		/// Body head before the operation started.
		original_body_head: Tip,
		/// Header head before the operation started.
		original_header_head: Tip,
	},
	/// Chain compaction was interrupted after selecting a durable rewind horizon.
	Compact {
		/// Body head from which the compact horizon was selected.
		original_body_head: Tip,
		/// Header head before the operation started.
		original_header_head: Tip,
		/// Oldest body-chain state that must remain rewindable after compaction.
		target_body_tail: Tip,
	},
}

/// Keeps the in-memory recovery signal consistent with an installed durable
/// pending-operation marker when control leaves an operation unexpectedly.
///
/// The marker owner must disarm the guard only after either clearing the marker
/// or explicitly setting the recovery signal on a handled failure. In
/// particular, dropping an armed guard during panic unwinding leaves the
/// durable marker intact and makes the next chain access initiate recovery.
#[must_use = "an installed pending chain operation must remain guarded until it is finalized"]
pub(crate) struct PendingChainOperationGuard {
	requires_init_recovery: Arc<AtomicBool>,
	armed: bool,
}

impl PendingChainOperationGuard {
	pub(crate) fn new(requires_init_recovery: Arc<AtomicBool>) -> Self {
		Self {
			requires_init_recovery,
			armed: true,
		}
	}

	pub(crate) fn disarm(&mut self) {
		self.armed = false;
	}

	pub(crate) fn require_recovery(&mut self) {
		self.requires_init_recovery.store(true, Ordering::SeqCst);
		self.disarm();
	}
}

impl Drop for PendingChainOperationGuard {
	fn drop(&mut self) {
		if self.armed {
			self.requires_init_recovery.store(true, Ordering::SeqCst);
		}
	}
}

impl PendingChainOperation {
	/// Operation kind for logging and recovery decisions.
	pub fn kind(&self) -> ChainOperationKind {
		match self {
			PendingChainOperation::PibdReset => ChainOperationKind::PibdReset,
			PendingChainOperation::ResetToGenesis => ChainOperationKind::ResetToGenesis,
			PendingChainOperation::ResetChainHead { .. } => ChainOperationKind::ResetChainHead,
			PendingChainOperation::ReconcileHeads { kind, .. } => *kind,
			PendingChainOperation::Compact { .. } => ChainOperationKind::Compact,
		}
	}
}

impl Writeable for PendingChainOperation {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(1)?;
		match self {
			PendingChainOperation::PibdReset => writer.write_u8(0),
			PendingChainOperation::ResetToGenesis => writer.write_u8(1),
			PendingChainOperation::ResetChainHead {
				original_body_head,
				original_header_head,
				target_body_head,
				target_header_head,
				rewind_headers,
			} => {
				writer.write_u8(2)?;
				original_body_head.write(writer)?;
				original_header_head.write(writer)?;
				target_body_head.write(writer)?;
				target_header_head.write(writer)?;
				writer.write_u8((*rewind_headers).into())
			}
			PendingChainOperation::ReconcileHeads {
				kind,
				original_body_head,
				original_header_head,
			} => {
				writer.write_u8(3)?;
				kind.write(writer)?;
				original_body_head.write(writer)?;
				original_header_head.write(writer)
			}
			PendingChainOperation::Compact {
				original_body_head,
				original_header_head,
				target_body_tail,
			} => {
				writer.write_u8(4)?;
				original_body_head.write(writer)?;
				original_header_head.write(writer)?;
				target_body_tail.write(writer)
			}
		}
	}
}

impl Readable for PendingChainOperation {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let version = reader.read_u8()?;
		if version != 1 {
			return Err(ser::Error::CorruptedData(format!(
				"Invalid pending chain operation version {}",
				version
			)));
		}

		let variant = reader.read_u8()?;
		match variant {
			0 => Ok(PendingChainOperation::PibdReset),
			1 => Ok(PendingChainOperation::ResetToGenesis),
			2 => {
				let original_body_head = Tip::read(reader)?;
				let original_header_head = Tip::read(reader)?;
				let target_body_head = Tip::read(reader)?;
				let target_header_head = Tip::read(reader)?;
				let rewind_headers = match reader.read_u8()? {
					0 => false,
					1 => true,
					x => {
						return Err(ser::Error::CorruptedData(format!(
							"Invalid pending chain operation rewind_headers value {}",
							x
						)))
					}
				};
				Ok(PendingChainOperation::ResetChainHead {
					original_body_head,
					original_header_head,
					target_body_head,
					target_header_head,
					rewind_headers,
				})
			}
			3 => {
				let kind = ChainOperationKind::read(reader)?;
				let original_body_head = Tip::read(reader)?;
				let original_header_head = Tip::read(reader)?;
				Ok(PendingChainOperation::ReconcileHeads {
					kind,
					original_body_head,
					original_header_head,
				})
			}
			4 => Ok(PendingChainOperation::Compact {
				original_body_head: Tip::read(reader)?,
				original_header_head: Tip::read(reader)?,
				target_body_tail: Tip::read(reader)?,
			}),
			x => Err(ser::Error::CorruptedData(format!(
				"Invalid pending chain operation variant {}",
				x
			))),
		}
	}
}

#[derive(Debug)]
struct BoolFlag(bool);

impl From<BoolFlag> for bool {
	fn from(b: BoolFlag) -> Self {
		b.0
	}
}

impl Readable for BoolFlag {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let x = reader.read_u8()?;
		match x {
			0 => Ok(BoolFlag(false)),
			1 => Ok(BoolFlag(true)),
			_ => Err(ser::Error::CorruptedData(format!(
				"Invalid boolean flag value {}",
				x
			))),
		}
	}
}

impl Writeable for BoolFlag {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.0.into())?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::core::{CommitWrapper, Input, OutputFeatures};
	use mwc_core::global;
	use mwc_core::ser::{BinReader, ProtocolVersion};
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use std::fs;

	fn read_bool_flag(bytes: &[u8]) -> Result<BoolFlag, ser::Error> {
		let mut source = bytes;
		let mut reader = BinReader::new(&mut source, ProtocolVersion::local(), 0);
		BoolFlag::read(&mut reader)
	}

	#[test]
	fn block_writes_require_exact_separately_stored_header() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/block_writes_require_exact_separately_stored_header";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		let mut expected_block = Block::default(0);
		expected_block.header.height = 1;
		expected_block.header.pow.proof.nonces[0] = 1;
		let expected_hash = expected_block.hash(0).unwrap();
		let mut altered_block = expected_block.clone();
		altered_block.header.height = 99;
		assert_eq!(altered_block.hash(0).unwrap(), expected_hash);
		assert_ne!(altered_block.header, expected_block.header);

		let batch = store.batch_write().unwrap();
		batch.save_block_header(&expected_block.header).unwrap();
		batch.save_block(&expected_block).unwrap();
		match batch.save_block(&altered_block).unwrap_err() {
			Error::OtherErr(msg) => assert!(msg.contains("separately stored header"), "{}", msg),
			other => panic!("expected full-block header mismatch, got {:?}", other),
		}
		match batch.save_block_header(&altered_block.header).unwrap_err() {
			Error::OtherErr(msg) => assert!(msg.contains("different complete header"), "{}", msg),
			other => panic!(
				"expected stored-header overwrite rejection, got {:?}",
				other
			),
		}
		assert_eq!(
			batch.get_block_header(&expected_hash).unwrap(),
			expected_block.header
		);

		// The delete path also consumes body data to clean secondary indexes, so
		// model raw corruption and require the same complete-header invariant.
		batch
			.db
			.put_ser(&to_key(BLOCK_PREFIX, expected_hash), &altered_block)
			.unwrap();
		match batch.delete_block(&expected_hash).unwrap_err() {
			Error::OtherErr(msg) => assert!(msg.contains("separately stored header"), "{}", msg),
			other => panic!("expected delete header mismatch, got {:?}", other),
		}

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn block_writes_preserve_existing_canonical_body() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = format!(
			"target/block_writes_preserve_existing_canonical_body_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		let stored_commit = secp.commit_value(1).unwrap();
		let conflicting_commit = secp.commit_value(2).unwrap();
		let mut stored = Block::default(0);
		stored.header.height = 1;
		stored.header.pow.proof.nonces[0] = 1;
		stored.body.inputs = Inputs::CommitOnly(vec![CommitWrapper::from(stored_commit)]);

		// Feature-bearing legacy inputs and commitment-only v3 inputs are the
		// same canonical database body and must remain idempotent.
		let mut equivalent = stored.clone();
		equivalent.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, stored_commit)]);
		assert!(blocks_equal_as_v3(0, &stored, &equivalent).unwrap());

		let mut conflicting = stored.clone();
		conflicting.body.inputs = Inputs::CommitOnly(vec![CommitWrapper::from(conflicting_commit)]);
		assert_eq!(stored.hash(0).unwrap(), conflicting.hash(0).unwrap());
		assert!(!blocks_equal_as_v3(0, &stored, &conflicting).unwrap());

		let block_hash = stored.hash(0).unwrap();
		let batch = store.batch_write().unwrap();
		batch.save_block_header(&stored.header).unwrap();
		batch.save_block(&stored).unwrap();
		batch.save_block(&equivalent).unwrap();
		match batch.save_block(&conflicting).unwrap_err() {
			Error::OtherErr(msg) => assert!(msg.contains("different body"), "{}", msg),
			other => panic!("expected full-block overwrite rejection, got {:?}", other),
		}

		let persisted = batch.get_block(&block_hash).unwrap();
		assert!(blocks_equal_as_v3(0, &persisted, &stored).unwrap());
		assert!(!blocks_equal_as_v3(0, &persisted, &conflicting).unwrap());

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn delete_block_if_exists_only_ignores_an_initially_missing_block() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = format!(
			"target/delete_block_if_exists_only_ignores_missing_block_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();

		let mut block = Block::default(0);
		block.header.height = 1;
		block.header.pow.proof.nonces[0] = 1;
		let block_hash = block.hash(0).unwrap();

		{
			let batch = store.batch_write().unwrap();
			assert!(!batch.delete_block_if_exists(&block_hash).unwrap());
			batch.save_block_header(&block.header).unwrap();
			batch.save_block(&block).unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_write().unwrap();
			batch.delete_block_header(&block_hash).unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_write().unwrap();
			assert!(batch.block_exists(&block_hash).unwrap());
			match batch.delete_block_if_exists(&block_hash).unwrap_err() {
				Error::NotFoundErr(msg) => assert!(msg.contains("BLOCK HEADER"), "{}", msg),
				other => panic!("expected missing-header error, got {:?}", other),
			}
		}

		assert!(store.block_exists(&block_hash).unwrap());
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn delete_block_removes_only_its_spent_commitment_occurrence_record() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = format!(
			"target/delete_block_removes_only_its_spent_record_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commitment = secp.commit_value(11).unwrap();
		let mut block = Block::default(0);
		block.header.height = 2;
		block.header.pow.proof.nonces[0] = 1;
		block.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, commitment)]);
		let block_hash = block.hash(0).unwrap();
		let other_hash = Hash::from_vec(&[8; Hash::LEN]);
		let block_record = SpentCommitmentRecord {
			spending_block: crate::types::HashHeight {
				hash: block_hash,
				height: 2,
			},
			spent_output: CommitPos { pos: 1, height: 0 },
		};
		let other_record = SpentCommitmentRecord {
			spending_block: crate::types::HashHeight {
				hash: other_hash,
				height: 2,
			},
			spent_output: CommitPos { pos: 1, height: 0 },
		};

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&block.header).unwrap();
			batch.save_block(&block).unwrap();
			batch
				.save_spent_index(
					&block_hash,
					&[SpentOutput {
						commitment,
						position: block_record.spent_output,
					}],
				)
				.unwrap();
			batch
				.save_spent_commitments(&commitment, block_record)
				.unwrap();
			batch
				.save_spent_commitments(&commitment, other_record)
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_write().unwrap();
			batch.delete_block(&block_hash).unwrap();
			batch.commit().unwrap();
		}
		let batch = store.batch_read().unwrap();
		assert_eq!(
			batch.get_spent_commitments(&commitment).unwrap(),
			Some(vec![other_record])
		);
		assert!(batch.get_spent_index(&block_hash).is_err());

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn blocks_iter_rejects_noncanonical_full_block_keys() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		for malformed_key_kind in ["wrong_hash", "extra_suffix"] {
			let chain_dir = format!(
				"target/blocks_iter_rejects_{}_{}",
				malformed_key_kind,
				std::process::id()
			);
			let _ = fs::remove_dir_all(&chain_dir);
			let store = ChainStore::new(0, &chain_dir).unwrap();

			let mut block = Block::default(0);
			block.header.height = 1;
			block.header.pow.proof.nonces[0] = 1;
			let block_hash = block.hash(0).unwrap();
			let mut malformed_key = to_key(BLOCK_PREFIX, block_hash);
			match malformed_key_kind {
				"wrong_hash" => malformed_key[2] ^= 1,
				"extra_suffix" => malformed_key.push(0),
				_ => unreachable!(),
			}

			{
				let batch = store.batch_write().unwrap();
				batch.db.put_ser(&malformed_key, &block).unwrap();
				batch.commit().unwrap();
			}

			{
				let batch = store.batch_read().unwrap();
				let err = batch
					.blocks_iter()
					.unwrap()
					.next()
					.expect("malformed full-block record must be scanned")
					.unwrap_err();
				match err {
					Error::OtherErr(msg) => {
						assert!(msg.contains("noncanonical key"), "{}", msg)
					}
					other => panic!("expected noncanonical-key error, got {:?}", other),
				}
				assert!(batch.db.exists(&malformed_key).unwrap());
			}

			drop(store);
			let _ = fs::remove_dir_all(&chain_dir);
		}
	}

	#[test]
	fn bool_flag_rejects_noncanonical_values() {
		assert!(!bool::from(read_bool_flag(&[0]).unwrap()));
		assert!(bool::from(read_bool_flag(&[1]).unwrap()));

		for value in [2u8, 3u8, u8::MAX] {
			match read_bool_flag(&[value]) {
				Err(ser::Error::CorruptedData(msg)) => {
					assert!(msg.contains("Invalid boolean flag value"), "{}", msg);
				}
				other => panic!(
					"expected noncanonical boolean flag rejection, got {:?}",
					other
				),
			}
		}
	}

	#[test]
	fn kernel_pos_iter_filters_excess_and_orders_by_pos() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/kernel_pos_iter_filters_excess_and_orders_by_pos";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let excess = Commitment::from_vec(vec![1; 33]).unwrap();
		let other_excess = Commitment::from_vec(vec![2; 33]).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch
				.save_kernel_pos(&excess, KernelPos { pos: 9, height: 4 })
				.unwrap();
			batch
				.save_kernel_pos(&other_excess, KernelPos { pos: 1, height: 1 })
				.unwrap();
			batch
				.save_kernel_pos(&excess, KernelPos { pos: 3, height: 2 })
				.unwrap();
			batch.set_kernel_pos_index_complete(true).unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			assert!(batch.is_kernel_pos_index_complete().unwrap());
			let positions = batch
				.kernel_pos_iter(&excess)
				.unwrap()
				.collect::<Result<Vec<_>, _>>()
				.unwrap();
			assert_eq!(
				positions,
				vec![
					KernelPos { pos: 3, height: 2 },
					KernelPos { pos: 9, height: 4 },
				]
			);
		}

		{
			let batch = store.batch_write().unwrap();
			batch.delete_kernel_pos(&excess, 3).unwrap();
			batch.commit().unwrap();
		}

		let batch = store.batch_read().unwrap();
		let positions = batch
			.kernel_pos_iter(&excess)
			.unwrap()
			.collect::<Result<Vec<_>, _>>()
			.unwrap();
		assert_eq!(positions, vec![KernelPos { pos: 9, height: 4 }]);
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn clear_kernel_pos_index_chunk_deletes_bounded_batches() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/clear_kernel_pos_index_chunk_deletes_bounded_batches";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let excess = Commitment::from_vec(vec![3; 33]).unwrap();
		let other_excess = Commitment::from_vec(vec![4; 33]).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch
				.save_kernel_pos(&excess, KernelPos { pos: 1, height: 1 })
				.unwrap();
			batch
				.save_kernel_pos(&excess, KernelPos { pos: 3, height: 2 })
				.unwrap();
			batch
				.save_kernel_pos(&other_excess, KernelPos { pos: 5, height: 3 })
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_write().unwrap();
			assert_eq!(batch.clear_kernel_pos_index_chunk(2).unwrap(), 2);
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			let remaining = batch
				.kernel_pos_iter(&excess)
				.unwrap()
				.chain(batch.kernel_pos_iter(&other_excess).unwrap())
				.collect::<Result<Vec<_>, _>>()
				.unwrap();
			assert_eq!(remaining.len(), 1);
		}

		{
			let batch = store.batch_write().unwrap();
			assert_eq!(batch.clear_kernel_pos_index_chunk(2).unwrap(), 1);
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			let remaining = batch
				.kernel_pos_iter(&excess)
				.unwrap()
				.chain(batch.kernel_pos_iter(&other_excess).unwrap())
				.collect::<Result<Vec<_>, _>>()
				.unwrap();
			assert!(remaining.is_empty());
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn spent_commitment_record_index_complete_flag_defaults_false_and_roundtrips() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/spent_commitment_record_index_complete_flag_roundtrips";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();

		{
			let batch = store.batch_read().unwrap();
			assert!(!batch.is_spent_commitment_record_index_complete().unwrap());
		}

		{
			let batch = store.batch_write().unwrap();
			batch
				.set_spent_commitment_record_index_complete(true)
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			assert!(batch.is_spent_commitment_record_index_complete().unwrap());
		}

		{
			let batch = store.batch_write().unwrap();
			batch
				.set_spent_commitment_record_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			assert!(!batch.is_spent_commitment_record_index_complete().unwrap());
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn clear_spent_commitment_index_chunk_deletes_bounded_batches() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/clear_spent_commitment_index_chunk_deletes_bounded_batches";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let first_commit = Commitment::from_vec(vec![5; 33]).unwrap();
		let second_commit = Commitment::from_vec(vec![6; 33]).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch
				.save_spent_commitments(&first_commit, test_spent_record(1))
				.unwrap();
			batch
				.save_spent_commitments(&second_commit, test_spent_record(2))
				.unwrap();
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_write().unwrap();
			assert_eq!(batch.clear_spent_commitment_index_chunk(1).unwrap(), 1);
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_write().unwrap();
			assert_eq!(batch.clear_spent_commitment_index_chunk(10).unwrap(), 1);
			batch.commit().unwrap();
		}

		{
			let batch = store.batch_read().unwrap();
			assert!(batch
				.get_spent_commitments(&first_commit)
				.unwrap()
				.is_none());
			assert!(batch
				.get_spent_commitments(&second_commit)
				.unwrap()
				.is_none());
		}

		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn block_input_bitmap_falls_back_to_legacy_only_when_spent_index_missing() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir =
			"target/block_input_bitmap_falls_back_to_legacy_only_when_spent_index_missing";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let block_hash = Hash::from_vec(&[42; Hash::LEN]);
		let legacy_bitmap = Bitmap::of(&[7]);

		{
			let batch = store.batch_write().unwrap();
			batch
				.db
				.put(
					&to_key(BLOCK_INPUT_BITMAP_PREFIX, &block_hash),
					&legacy_bitmap.serialize::<croaring::Portable>(),
				)
				.unwrap();
			batch.commit().unwrap();
		}

		let batch = store.batch_read().unwrap();
		let bitmap = batch.get_block_input_bitmap(&block_hash).unwrap();
		assert!(bitmap.contains(7));
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn block_input_bitmap_propagates_corrupt_spent_index() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/block_input_bitmap_propagates_corrupt_spent_index";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let block_hash = Hash::from_vec(&[43; Hash::LEN]);
		let legacy_bitmap = Bitmap::of(&[8]);

		{
			let batch = store.batch_write().unwrap();
			batch
				.db
				.put(&to_key(BLOCK_SPENT_PREFIX, &block_hash), &[1])
				.unwrap();
			batch
				.db
				.put(
					&to_key(BLOCK_INPUT_BITMAP_PREFIX, &block_hash),
					&legacy_bitmap.serialize::<croaring::Portable>(),
				)
				.unwrap();
			batch.commit().unwrap();
		}

		let batch = store.batch_read().unwrap();
		let err = batch.get_block_input_bitmap(&block_hash).unwrap_err();
		assert!(!err.store_error_is_not_found(), "{:?}", err);
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn block_input_bitmap_rejects_corrupt_legacy_bitmap() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/block_input_bitmap_rejects_corrupt_legacy_bitmap";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let block_hash = Hash::from_vec(&[44; Hash::LEN]);

		{
			let batch = store.batch_write().unwrap();
			batch
				.db
				.put(&to_key(BLOCK_INPUT_BITMAP_PREFIX, &block_hash), &[3])
				.unwrap();
			batch.commit().unwrap();
		}

		let batch = store.batch_read().unwrap();
		match batch.get_block_input_bitmap(&block_hash).unwrap_err() {
			Error::OtherErr(msg) => {
				assert!(msg.contains("Invalid legacy block input bitmap"), "{}", msg)
			}
			other => panic!("expected corrupt legacy bitmap error, got {:?}", other),
		}
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	#[test]
	fn block_input_bitmap_rejects_legacy_bitmap_trailing_data() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let chain_dir = "target/block_input_bitmap_rejects_legacy_bitmap_trailing_data";
		let _ = fs::remove_dir_all(chain_dir);
		let store = ChainStore::new(0, chain_dir).unwrap();
		let block_hash = Hash::from_vec(&[45; Hash::LEN]);
		let legacy_bitmap = Bitmap::of(&[9]);
		let mut serialized = legacy_bitmap.serialize::<croaring::Portable>();
		serialized.push(0xff);

		{
			let batch = store.batch_write().unwrap();
			batch
				.db
				.put(&to_key(BLOCK_INPUT_BITMAP_PREFIX, &block_hash), &serialized)
				.unwrap();
			batch.commit().unwrap();
		}

		let batch = store.batch_read().unwrap();
		match batch.get_block_input_bitmap(&block_hash).unwrap_err() {
			Error::OtherErr(msg) => {
				assert!(msg.contains("Invalid legacy block input bitmap"), "{}", msg)
			}
			other => panic!("expected corrupt legacy bitmap error, got {:?}", other),
		}
		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(chain_dir);
	}

	fn test_spent_record(height: u64) -> SpentCommitmentRecord {
		SpentCommitmentRecord {
			spending_block: crate::types::HashHeight {
				hash: Hash::from_vec(&height.to_le_bytes()),
				height,
			},
			spent_output: CommitPos {
				pos: height.saturating_mul(2).saturating_add(1),
				height,
			},
		}
	}

	#[test]
	fn spent_commitment_append_rejects_unreadable_list_growth() {
		let max_spent_list: Vec<SpentCommitmentRecord> = (0..ser::READ_VEC_SIZE_LIMIT)
			.map(test_spent_record)
			.collect();
		let mut duplicate_list = max_spent_list.clone();
		let mut overflow_list = max_spent_list;

		assert!(
			!Batch::append_spent_commitment(&mut duplicate_list, test_spent_record(0)).unwrap()
		);
		assert_eq!(duplicate_list.len(), ser::READ_VEC_SIZE_LIMIT as usize);

		let err = Batch::append_spent_commitment(
			&mut overflow_list,
			test_spent_record(ser::READ_VEC_SIZE_LIMIT),
		)
		.unwrap_err();
		match err {
			Error::SerErr(ser::Error::TooLargeWriteErr(msg)) => {
				assert!(msg.contains("spent commitment list length"), "{}", msg);
			}
			other => panic!("expected TooLargeWriteErr, got {:?}", other),
		}
		assert_eq!(overflow_list.len(), ser::READ_VEC_SIZE_LIMIT as usize);
	}

	#[test]
	fn spent_commitment_append_rejects_conflicting_record_for_same_block() {
		let original = test_spent_record(7);
		let mut conflicting = original;
		conflicting.spent_output.pos = conflicting.spent_output.pos.saturating_add(2);
		let mut records = vec![original];

		let err = Batch::append_spent_commitment(&mut records, conflicting).unwrap_err();
		assert!(matches!(
			err,
			Error::OtherErr(msg) if msg.contains("conflicting spent commitment records")
		));
		assert_eq!(records, vec![original]);
	}
}
