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

use crate::core::consensus::HeaderDifficultyInfo;
use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::{Block, BlockHeader, BlockSums, Inputs};
use crate::core::pow::Difficulty;
use crate::core::ser::{DeserializationMode, ProtocolVersion, Readable, Writeable};
use crate::linked_list::MultiIndex;
use crate::types::{CommitPos, HashHeight, Tip};
use crate::util::secp::pedersen::Commitment;
use croaring::Bitmap;
use mwc_core::ser;
use mwc_store as store;
use mwc_store::{option_to_not_found, to_key, Error};
use std::convert::TryInto;
use std::sync::Arc;

const STORE_SUBPATH: &str = "chain";

const BLOCK_HEADER_PREFIX: u8 = b'h';
const BLOCK_PREFIX: u8 = b'b';
const HEAD_PREFIX: u8 = b'H';
const TAIL_PREFIX: u8 = b'T';
const HEADER_HEAD_PREFIX: u8 = b'G';
const OUTPUT_POS_PREFIX: u8 = b'p';

/// Prefix for NRD kernel pos index lists.
pub const NRD_KERNEL_LIST_PREFIX: u8 = b'K';
/// Prefix for NRD kernel pos index entries.
pub const NRD_KERNEL_ENTRY_PREFIX: u8 = b'k';

const BLOCK_INPUT_BITMAP_PREFIX: u8 = b'B';
const BLOCK_SUMS_PREFIX: u8 = b'M';
const BLOCK_SPENT_PREFIX: u8 = b'S';
const BLOCK_SPENT_COMMITMENT_PREFIX: u8 = b'C';

/// Prefix for various boolean flags stored in the db.
const BOOL_FLAG_PREFIX: u8 = b'F';
/// Boolean flag for v3 migration.
const BLOCKS_V3_MIGRATED: &str = "blocks_v3_migrated";

/// All chain-related database operations
pub struct ChainStore {
	db: store::Store,
}

impl ChainStore {
	/// Create new chain store
	pub fn new(db_root: &str) -> Result<ChainStore, Error> {
		let db = store::Store::new(db_root, None, Some(STORE_SUBPATH), None)?;
		Ok(ChainStore { db })
	}

	/// The current chain head.
	pub fn head(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[HEAD_PREFIX], None), || "HEAD".to_owned())
	}

	/// The current header head (may differ from chain head).
	pub fn header_head(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[HEADER_HEAD_PREFIX], None), || {
			"HEADER_HEAD".to_owned()
		})
	}

	/// The current chain "tail" (earliest block in the store).
	pub fn tail(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[TAIL_PREFIX], None), || "TAIL".to_owned())
	}

	/// Header of the block at the head of the block chain (not the same thing as header_head).
	pub fn head_header(&self) -> Result<BlockHeader, Error> {
		self.get_block_header(&self.head()?.last_block_h)
	}

	/// Get full block.
	pub fn get_block(&self, h: &Hash) -> Result<Block, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_PREFIX, h), None), || {
			format!("BLOCK: {}", h)
		})
	}

	/// Does this full block exist?
	pub fn block_exists(&self, h: &Hash) -> Result<bool, Error> {
		self.db.exists(&to_key(BLOCK_PREFIX, h))
	}

	/// Get block_sums for the block hash.
	pub fn get_block_sums(&self, h: &Hash) -> Result<BlockSums, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_SUMS_PREFIX, h), None), || {
			format!("Block sums for block: {}", h)
		})
	}

	/// Get previous header.
	pub fn get_previous_header(&self, header: &BlockHeader) -> Result<BlockHeader, Error> {
		self.get_block_header(&header.prev_hash)
	}

	/// Get previous header without deserializing the proof nonces
	pub fn get_previous_header_skip_proof(
		&self,
		header: &BlockHeader,
	) -> Result<BlockHeader, Error> {
		self.get_block_header_skip_proof(&header.prev_hash)
	}

	/// Get block header.
	pub fn get_block_header(&self, h: &Hash) -> Result<BlockHeader, Error> {
		option_to_not_found(
			self.db.get_ser(&to_key(BLOCK_HEADER_PREFIX, h), None),
			|| format!("BLOCK HEADER: {}", h),
		)
	}

	/// Get block header without deserializing the full PoW Proof; currently used
	/// for difficulty iterator which is called many times but doesn't need the proof
	pub fn get_block_header_skip_proof(&self, h: &Hash) -> Result<BlockHeader, Error> {
		option_to_not_found(
			self.db.get_ser(
				&to_key(BLOCK_HEADER_PREFIX, h),
				Some(ser::DeserializationMode::SkipPow),
			),
			|| format!("BLOCK HEADER: {}", h),
		)
	}

	/// Get PMMR pos for the given output commitment.
	pub fn get_output_pos(&self, commit: &Commitment) -> Result<u64, Error> {
		match self.get_output_pos_height(commit)? {
			Some(pos) => Ok(pos.pos - 1),
			None => Err(Error::NotFoundErr(format!(
				"Output position for: {:?}",
				commit
			))),
		}
	}

	/// Get PMMR pos and block height for the given output commitment.
	pub fn get_output_pos_height(&self, commit: &Commitment) -> Result<Option<CommitPos>, Error> {
		self.db.get_ser(&to_key(OUTPUT_POS_PREFIX, commit), None)
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
}

/// An atomic batch in which all changes can be committed all at once or
/// discarded on error.
pub struct Batch<'a> {
	/// The underlying db instance.
	pub db: store::Batch<'a>,
}

impl<'a> Batch<'a> {
	/// The head.
	pub fn head(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[HEAD_PREFIX], None), || "HEAD".to_owned())
	}

	/// The tail.
	pub fn tail(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[TAIL_PREFIX], None), || "TAIL".to_owned())
	}

	/// The current header head (may differ from chain head).
	pub fn header_head(&self) -> Result<Tip, Error> {
		option_to_not_found(self.db.get_ser(&[HEADER_HEAD_PREFIX], None), || {
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

	/// Save header head to db.
	pub fn save_header_head(&self, t: &Tip) -> Result<(), Error> {
		self.db.put_ser(&[HEADER_HEAD_PREFIX], t)
	}

	/// get block
	pub fn get_block(&self, h: &Hash) -> Result<Block, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_PREFIX, h), None), || {
			format!("Block with hash: {}", h)
		})
	}

	/// Does the block exist?
	pub fn block_exists(&self, h: &Hash) -> Result<bool, Error> {
		self.db.exists(&to_key(BLOCK_PREFIX, h))
	}

	/// Save the block to the db.
	/// Note: the block header is not saved to the db here, assumes this has already been done.
	pub fn save_block(&self, b: &Block) -> Result<(), Error> {
		debug!(
			"save_block: {} at {} ({} -> v{})",
			b.header.hash(),
			b.header.height,
			b.inputs().version_str(),
			self.db.protocol_version(),
		);
		self.db.put_ser(&to_key(BLOCK_PREFIX, b.hash())[..], b)?;
		Ok(())
	}

	/// We maintain a "spent" index for each full block to allow the output_pos
	/// to be easily reverted during rewind.
	pub fn save_spent_index(&self, h: &Hash, spent: &[CommitPos]) -> Result<(), Error> {
		self.db
			.put_ser(&to_key(BLOCK_SPENT_PREFIX, h)[..], &spent.to_vec())?;
		Ok(())
	}

	/// We maintain a "spent" commitments for each full block to allow validation of input against spent output
	/// for blocks within the horizon. These data will be deleted when chain is compact.
	pub fn save_spent_commitments(&self, spent: &Commitment, hh: HashHeight) -> Result<(), Error> {
		let hash_list = self
			.db
			.get_ser(&to_key(BLOCK_SPENT_COMMITMENT_PREFIX, spent), None)?;
		let mut spent_list;
		if let Some(list) = hash_list {
			spent_list = list;
		} else {
			spent_list = Vec::new();
		}
		spent_list.push(hh);
		self.db.put_ser(
			&to_key(BLOCK_SPENT_COMMITMENT_PREFIX, spent)[..],
			&spent_list.to_vec(),
		)?;
		Ok(())
	}

	/// get spent commitment
	pub fn get_spent_commitments(
		&self,
		spent: &Commitment,
	) -> Result<Option<Vec<HashHeight>>, Error> {
		self.db
			.get_ser(&to_key(BLOCK_SPENT_COMMITMENT_PREFIX, spent), None)
	}

	// /// An iterator to all "spent" commit in db
	// pub fn spent_commitment_iter(&self) -> Result<SerIterator<Vec<Commitment>>, Error> {
	// 	let key = to_key(BLOCK_SPENT_COMMITMENT_PREFIX, "");
	// 	self.db.iter(&key)
	// }

	/// DB flag representing full migration of blocks to v3 version.
	/// Default to false if flag not present.
	pub fn is_blocks_v3_migrated(&self) -> Result<bool, Error> {
		let migrated: Option<BoolFlag> = self
			.db
			.get_ser(&to_key(BOOL_FLAG_PREFIX, BLOCKS_V3_MIGRATED), None)?;
		match migrated {
			None => Ok(false),
			Some(x) => Ok(x.into()),
		}
	}

	/// Set DB flag representing full migration of blocks to v3 version.
	pub fn set_blocks_v3_migrated(&self, migrated: bool) -> Result<(), Error> {
		self.db.put_ser(
			&to_key(BOOL_FLAG_PREFIX, BLOCKS_V3_MIGRATED)[..],
			&BoolFlag(migrated),
		)?;
		Ok(())
	}

	/// Migrate a block stored in the db reading from one protocol version and writing
	/// with new protocol version.
	pub fn migrate_block(
		&self,
		key: &[u8],
		from_version: ProtocolVersion,
		to_version: ProtocolVersion,
	) -> Result<(), Error> {
		let block: Option<Block> = self.db.get_with(key, move |_, mut v| {
			ser::deserialize(&mut v, from_version, ser::DeserializationMode::default())
				.map_err(From::from)
		})?;
		if let Some(block) = block {
			self.db.put_ser_with_version(key, &block, to_version)?;
		}
		Ok(())
	}

	/// Low level function to delete directly by raw key.
	pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
		self.db.delete(key)
	}

	/// Delete a full block. Does not delete any record associated with a block
	/// header.
	pub fn delete_block(&self, bh: &Hash) -> Result<(), Error> {
		let block = self.get_block(bh)?;
		let inputs = block.inputs();
		match inputs {
			Inputs::CommitOnly(inputs) => {
				for input in inputs {
					let _ = self.delete_spent_commitments(&input.commitment(), bh);
				}
			}
			Inputs::FeaturesAndCommit(inputs) => {
				for input in inputs {
					let _ = self.delete_spent_commitments(&input.commitment(), bh);
				}
			}
		}

		self.db.delete(&to_key(BLOCK_PREFIX, bh)[..])?;

		// Best effort at deleting associated data for this block.
		// Not an error if these fail.
		{
			let _ = self.delete_block_sums(bh);
			let _ = self.delete_spent_index(bh);
		}

		Ok(())
	}

	/// Delete a block header.
	pub fn delete_block_header(&self, h: &Hash) -> Result<(), Error> {
		self.db.delete(&to_key(BLOCK_HEADER_PREFIX, h)[..])
	}

	/// Save block header to db.
	pub fn save_block_header(&self, header: &BlockHeader) -> Result<(), Error> {
		let hash = header.hash();

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

	/// Delete the output_pos index entry for a spent output.
	pub fn delete_output_pos_height(&self, commit: &Commitment) -> Result<(), Error> {
		self.db.delete(&to_key(OUTPUT_POS_PREFIX, commit))
	}

	/// Delete the commitment for a spent output.
	pub fn delete_spent_commitments(&self, spent: &Commitment, hash: &Hash) -> Result<(), Error> {
		let hash_list = self.get_spent_commitments(spent)?;
		let hash_list_unwrap = hash_list.unwrap_or(vec![]);
		let filtered_list: Vec<&HashHeight> = hash_list_unwrap
			.iter()
			.filter(|hash_height| hash_height.hash != *hash)
			.collect();

		if filtered_list.len() != 0 {
			self.db.put_ser(
				&to_key(BLOCK_SPENT_COMMITMENT_PREFIX, spent)[..],
				&filtered_list.to_vec(),
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
	pub fn output_pos_iter(&self) -> Result<impl Iterator<Item = (Vec<u8>, CommitPos)>, Error> {
		let key = to_key(OUTPUT_POS_PREFIX, "");
		let protocol_version = self.db.protocol_version();
		self.db.iter(&key, move |k, mut v| {
			ser::deserialize(&mut v, protocol_version, DeserializationMode::default())
				.map(|pos| (k.to_vec(), pos))
				.map_err(From::from)
		})
	}

	/// Get output_pos from index.
	pub fn get_output_pos(&self, commit: &Commitment) -> Result<u64, Error> {
		match self.get_output_pos_height(commit)? {
			Some(pos) => Ok(pos.pos - 1),
			None => Err(Error::NotFoundErr(format!(
				"Output position for: {:?}",
				commit
			))),
		}
	}

	/// Get output_pos and block height from index.
	pub fn get_output_pos_height(&self, commit: &Commitment) -> Result<Option<CommitPos>, Error> {
		self.db.get_ser(&to_key(OUTPUT_POS_PREFIX, commit), None)
	}

	/// Get the previous header.
	pub fn get_previous_header(&self, header: &BlockHeader) -> Result<BlockHeader, Error> {
		self.get_block_header(&header.prev_hash)
	}

	/// Get the previous header, without deserializing the full PoW Proof (or the ability to derive the
	/// block hash, this is used for the difficulty iterator).
	pub fn get_previous_header_skip_proof(
		&self,
		header: &BlockHeader,
	) -> Result<BlockHeader, Error> {
		self.get_block_header_skip_proof(&header.prev_hash)
	}

	/// Get block header.
	pub fn get_block_header(&self, h: &Hash) -> Result<BlockHeader, Error> {
		option_to_not_found(
			self.db.get_ser(&to_key(BLOCK_HEADER_PREFIX, h), None),
			|| format!("BLOCK HEADER: {}", h),
		)
	}

	/// Get block header without deserializing the full PoW Proof; currently used
	/// for difficulty iterator which is called many times but doesn't need the proof
	pub fn get_block_header_skip_proof(&self, h: &Hash) -> Result<BlockHeader, Error> {
		option_to_not_found(
			self.db.get_ser(
				&to_key(BLOCK_HEADER_PREFIX, h),
				Some(ser::DeserializationMode::SkipPow),
			),
			|| format!("BLOCK HEADER: {}", h),
		)
	}

	/// Delete the block spent index.
	fn delete_spent_index(&self, bh: &Hash) -> Result<(), Error> {
		// Clean up the legacy input bitmap as well.
		let _ = self.db.delete(&to_key(BLOCK_INPUT_BITMAP_PREFIX, bh));

		self.db.delete(&to_key(BLOCK_SPENT_PREFIX, bh))
	}

	/// Save block_sums for the block.
	pub fn save_block_sums(&self, h: &Hash, sums: BlockSums) -> Result<(), Error> {
		self.db.put_ser(&to_key(BLOCK_SUMS_PREFIX, h)[..], &sums)
	}

	/// Get block_sums for the block.
	pub fn get_block_sums(&self, h: &Hash) -> Result<BlockSums, Error> {
		option_to_not_found(self.db.get_ser(&to_key(BLOCK_SUMS_PREFIX, h), None), || {
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
		if let Ok(spent) = self.get_spent_index(bh) {
			let bitmap = spent
				.into_iter()
				.map(|x| x.pos.try_into().unwrap())
				.collect();
			Ok(bitmap)
		} else {
			self.get_legacy_input_bitmap(bh)
		}
	}

	fn get_legacy_input_bitmap(&self, bh: &Hash) -> Result<Bitmap, Error> {
		option_to_not_found(
			self.db
				.get_with(&to_key(BLOCK_INPUT_BITMAP_PREFIX, bh), move |_, data| {
					Ok(Bitmap::deserialize::<croaring::Portable>(data))
				}),
			|| "legacy block input bitmap".to_string(),
		)
	}

	/// Get the "spent index" from the db for the specified block.
	/// If we need to rewind a block then we use this to "unspend" the spent outputs.
	pub fn get_spent_index(&self, bh: &Hash) -> Result<Vec<CommitPos>, Error> {
		option_to_not_found(
			self.db.get_ser(&to_key(BLOCK_SPENT_PREFIX, bh), None),
			|| format!("spent index: {}", bh),
		)
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
	pub fn blocks_iter(&self) -> Result<impl Iterator<Item = Block>, Error> {
		let key = to_key(BLOCK_PREFIX, "");
		let protocol_version = self.db.protocol_version();
		self.db.iter(&key, move |_, mut v| {
			ser::deserialize(&mut v, protocol_version, DeserializationMode::default())
				.map_err(From::from)
		})
	}

	/// Iterator over raw data for full blocks in the db.
	/// Used during block migration (we need flexibility around deserialization).
	pub fn blocks_raw_iter(&self) -> Result<impl Iterator<Item = (Vec<u8>, Vec<u8>)>, Error> {
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
	type Item = HeaderDifficultyInfo;

	fn next(&mut self) -> Option<Self::Item> {
		// Get both header and previous_header if this is the initial iteration.
		// Otherwise move prev_header to header and get the next prev_header.
		// Note that due to optimizations being called in `get_block_header_skip_proof`,
		// Items returned by this iterator cannot be expected to correctly
		// calculate their own hash - This iterator is purely for iterating through
		// difficulty information
		let (cur_header, cur_header_hash) = if self.header.is_none() {
			if let Some(ref batch) = self.batch {
				(
					batch.get_block_header_skip_proof(&self.start).ok(),
					Some(self.start),
				)
			} else if let Some(ref store) = self.store {
				(
					store.get_block_header_skip_proof(&self.start).ok(),
					Some(self.start),
				)
			} else {
				(None, None)
			}
		} else {
			(self.prev_header.clone(), self.prev_header_hash)
		};

		self.header = cur_header;

		// If we have a header we can do this iteration.
		// Otherwise we are done.
		if let Some(header) = self.header.clone() {
			if let Some(ref batch) = self.batch {
				self.prev_header = batch.get_previous_header_skip_proof(&header).ok();
			} else if let Some(ref store) = self.store {
				self.prev_header = store.get_previous_header_skip_proof(&header).ok();
			} else {
				self.prev_header = None;
			}

			self.prev_header_hash = Some(header.prev_hash);

			let prev_difficulty = self
				.prev_header
				.clone()
				.map_or(Difficulty::zero(), |x| x.total_difficulty());
			let difficulty = header.total_difficulty() - prev_difficulty;
			let scaling = header.pow.secondary_scaling;

			Some(HeaderDifficultyInfo::new(
				header.height,
				cur_header_hash,
				header.timestamp.timestamp() as u64,
				difficulty,
				scaling,
				header.pow.is_secondary(),
			))
		} else {
			None
		}
	}
}

/// Init the NRD "recent history" kernel index backed by the underlying db.
/// List index supports multiple entries per key, maintaining insertion order.
/// Allows for fast lookup of the most recent entry per excess commitment.
pub fn nrd_recent_kernel_index() -> MultiIndex<CommitPos> {
	MultiIndex::init(NRD_KERNEL_LIST_PREFIX, NRD_KERNEL_ENTRY_PREFIX)
}

struct BoolFlag(bool);

impl From<BoolFlag> for bool {
	fn from(b: BoolFlag) -> Self {
		b.0
	}
}

impl Readable for BoolFlag {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let x = reader.read_u8()?;
		Ok(BoolFlag(1 & x == 1))
	}
}

impl Writeable for BoolFlag {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.0.into())?;
		Ok(())
	}
}
