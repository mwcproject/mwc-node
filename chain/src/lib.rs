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

//! The block chain itself, validates and accepts new blocks, handles reorgs.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#[cfg(test)]
extern crate self as mwc_chain;

mod chain;
mod error;
pub mod linked_list;
pub mod pibd_params;
pub mod pipe;
pub mod store;
pub mod txhashset;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export the base interface

pub use crate::chain::{Chain, OutputReadSnapshot};
pub use crate::error::Error;
pub use crate::store::ChainStore;
pub use crate::types::{
	BlockStatus, ChainAdapter, Options, SyncState, SyncStatus, Tip, TxHashsetStateValidationStage,
};

use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::{Block, BlockHeader};
use std::collections::HashSet;

/// Load a persisted header by hash and require the record to hash back to its key.
pub(crate) fn checked_header_by_hash<F>(
	context_id: u32,
	expected_hash: &Hash,
	operation: &str,
	load: F,
) -> Result<BlockHeader, Error>
where
	F: FnOnce(&Hash) -> Result<BlockHeader, mwc_store::Error>,
{
	let header = load(expected_hash)
		.map_err(|e| Error::StoreErr(e, format!("{} load header {}", operation, expected_hash)))?;
	let loaded_hash = header.hash(context_id)?;
	if loaded_hash != *expected_hash {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} header key/hash mismatch: requested {}, loaded {}",
			operation, expected_hash, loaded_hash
		)));
	}
	Ok(header)
}

/// Load a persisted full block selected by an already-traversed complete header.
///
/// Hash serialization identifies the packed PoW proof rather than the complete
/// header. Normal block ingestion makes that a safe identity by validating PoW
/// and the body commitments. State-maintenance paths do not repeat those
/// expensive checks, so a loaded record must retain the exact validated header.
///
/// This is a persisted-state invariant check, not an assumption that a peer can
/// cheaply produce two different consensus-valid headers with the same hash.
/// A mismatch means the independently stored header and full-block records are
/// inconsistent, for example after corruption or an unvalidated local write.
/// This checks cross-record header identity only; it does not independently
/// revalidate the block body against the header's cumulative MMR commitments.
pub(crate) fn checked_block_for_header<F>(
	context_id: u32,
	expected: &BlockHeader,
	operation: &str,
	load: F,
) -> Result<Block, Error>
where
	F: FnOnce(&Hash) -> Result<Block, mwc_store::Error>,
{
	let expected_hash = expected.hash(context_id)?;
	let block = load(&expected_hash).map_err(|e| {
		Error::StoreErr(
			e,
			format!("{} load full block {}", operation, expected_hash),
		)
	})?;
	let loaded_hash = block.header.hash(context_id)?;
	if loaded_hash != expected_hash {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} loaded full block {} from key {}",
			operation, loaded_hash, expected_hash
		)));
	}
	if block.header != *expected {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} full block {} header at height {} does not exactly match persisted ancestry header at height {}",
			operation, expected_hash, block.header.height, expected.height
		)));
	}

	Ok(block)
}

/// Load and validate one step through persisted block-header ancestry.
///
/// Normal PoW validation binds the complete header to the proof-derived hash.
/// This maintenance helper does not repeat PoW, so it verifies key/hash and
/// structural ancestry invariants while trusting persisted headers.
pub(crate) fn checked_previous_header<F>(
	context_id: u32,
	current: &BlockHeader,
	visited: &mut HashSet<Hash>,
	operation: &str,
	load: F,
) -> Result<BlockHeader, Error>
where
	F: FnOnce(&Hash) -> Result<BlockHeader, mwc_store::Error>,
{
	let current_hash = current.hash(context_id)?;
	if !visited.insert(current_hash) {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} encountered repeated header {} at height {}",
			operation, current_hash, current.height
		)));
	}

	let expected_height = current.height.checked_sub(1).ok_or_else(|| {
		Error::InvalidPersistedChainState(format!(
			"{} attempted to traverse before genesis header {}",
			operation, current_hash
		))
	})?;

	if visited.contains(&current.prev_hash) {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} encountered header ancestry cycle from {} at height {} to {}",
			operation, current_hash, current.height, current.prev_hash
		)));
	}

	let previous = load(&current.prev_hash).map_err(|e| {
		Error::StoreErr(
			e,
			format!(
				"{} load previous header {} for {} at height {}",
				operation, current.prev_hash, current_hash, current.height
			),
		)
	})?;
	let previous_hash = previous.hash(context_id)?;
	if previous_hash != current.prev_hash {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} loaded header {} from key {} while traversing {} at height {}",
			operation, previous_hash, current.prev_hash, current_hash, current.height
		)));
	}
	if previous.height != expected_height {
		return Err(Error::InvalidPersistedChainState(format!(
			"{} expected predecessor {} at height {}, found height {}",
			operation, previous_hash, expected_height, previous.height
		)));
	}

	Ok(previous)
}

#[cfg(test)]
mod checked_ancestry_tests {
	use super::*;
	use mwc_core::global::{self, ChainTypes};

	fn header(height: u64, proof_nonce: u64) -> BlockHeader {
		let mut header = BlockHeader::default(0);
		header.height = height;
		if let Some(nonce) = header.pow.proof.nonces.last_mut() {
			*nonce = proof_nonce;
		}
		header
	}

	#[test]
	fn checked_block_for_header_rejects_same_hash_different_header() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let expected = header(1, 1);
		let mut altered_block = Block::default(0);
		altered_block.header = expected.clone();
		altered_block.header.height = 42;
		altered_block.header.prev_hash = Hash::from_vec(&[7; Hash::LEN]);

		// This deliberately models corrupt persisted state, not two
		// consensus-valid blocks. No collision search is needed because these
		// fields are absent from hash serialization; normal PoW validation would
		// reject the altered header.
		assert_eq!(altered_block.hash(0).unwrap(), expected.hash(0).unwrap());
		assert_ne!(altered_block.header, expected);

		let err =
			checked_block_for_header(
				0,
				&expected,
				"same-hash test",
				|_| Ok(altered_block.clone()),
			)
			.unwrap_err();

		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("does not exactly match persisted ancestry header")
		));
	}

	#[test]
	fn checked_previous_header_rejects_self_cycle() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let mut current = header(1, 1);
		current.prev_hash = current.hash(0).unwrap();
		let mut visited = HashSet::new();

		let err = checked_previous_header(0, &current, &mut visited, "self-cycle test", |_| {
			Ok(current.clone())
		})
		.unwrap_err();

		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg) if msg.contains("cycle")
		));
	}

	#[test]
	fn checked_previous_header_rejects_two_header_cycle() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let mut previous = header(1, 2);
		let mut current = header(2, 1);
		current.prev_hash = previous.hash(0).unwrap();
		previous.prev_hash = current.hash(0).unwrap();
		let mut visited = HashSet::new();

		let loaded =
			checked_previous_header(0, &current, &mut visited, "two-header cycle test", |_| {
				Ok(previous.clone())
			})
			.unwrap();
		let err =
			checked_previous_header(0, &loaded, &mut visited, "two-header cycle test", |_| {
				Ok(current.clone())
			})
			.unwrap_err();

		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg) if msg.contains("cycle")
		));
	}

	#[test]
	fn checked_previous_header_rejects_height_gap() {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let previous = header(1, 2);
		let mut current = header(3, 1);
		current.prev_hash = previous.hash(0).unwrap();
		let mut visited = HashSet::new();

		let err = checked_previous_header(0, &current, &mut visited, "height-gap test", |_| {
			Ok(previous.clone())
		})
		.unwrap_err();

		assert!(matches!(
			err,
			Error::InvalidPersistedChainState(msg)
				if msg.contains("expected predecessor") && msg.contains("height 2")
		));
	}
}
