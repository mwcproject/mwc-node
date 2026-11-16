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
use super::utils::{get_output, w};
use crate::rest::*;
use crate::types::*;
use mwc_core::core::hash::Hash;
use mwc_core::core::hash::Hashed;
use mwc_core::core::BlockHeader;
use std::sync::Weak;

/// Maximum number of full blocks returned by a single get_blocks request.
/// Kept small because every returned block is fully materialized in memory,
/// performs per-output UTXO/proof lookups, and is hex-expanded when proofs
/// are requested, so the response cost scales with both block count and block
/// contents. Callers can paginate via `last_retrieved_height`.
pub const BLOCK_TRANSFER_LIMIT: u64 = 10;
/// Gets block headers given either a hash or height or an output commit.
///
pub struct HeaderHandler {
	pub chain: Weak<mwc_chain::Chain>,
}

impl HeaderHandler {
	pub fn get_header_v2(&self, h: &Hash) -> Result<BlockHeaderPrintable, Error> {
		let chain = w(&self.chain)?;
		let header = chain.get_block_header(h).map_err(|e| {
			let msg = format!("Block header for hash {}, {}", h, e);
			Error::chain_read_error(e, msg)
		})?;
		let actual_hash = header.hash(chain.get_context_id())?;
		if actual_hash != *h {
			return Err(mwc_chain::Error::InvalidPersistedChainState(format!(
				"block header record key/hash mismatch: requested {}, loaded {}",
				h, actual_hash
			))
			.into());
		}
		Ok(BlockHeaderPrintable::from_header(&header)?)
	}

	// Try to get hash from height, hash or output commit
	pub fn parse_inputs(
		&self,
		height: Option<u64>,
		hash: Option<Hash>,
		commit: Option<String>,
	) -> Result<Hash, Error> {
		if let Some(height) = height {
			match w(&self.chain)?.get_body_header_by_height(height) {
				Ok(header) => return Ok(header.hash(w(&self.chain)?.get_context_id())?),
				Err(e) => {
					let msg = format!("Header for height {}, {}", height, e);
					return Err(Error::chain_read_error(e, msg));
				}
			}
		}
		if let Some(hash) = hash {
			return Ok(hash);
		}
		if let Some(commit) = commit {
			let oid = match get_output(&self.chain, &commit)? {
				Some((_, o)) => o,
				None => return Err(Error::NotFound("Output not found".to_string())),
			};
			match w(&self.chain)?.get_header_for_output(oid.commitment()) {
				Ok(header) => return Ok(header.hash(w(&self.chain)?.get_context_id())?),
				Err(e) => {
					let msg = format!("Header for output {:?}, {}", oid, e);
					return Err(Error::chain_read_error(e, msg));
				}
			}
		}
		Err(Error::Argument(format!(
			"not a valid hash {:?}, height {:?} or output commit {:?}",
			hash, height, commit
		)))
	}
}

/// Get block details. Included proofs describe the node's current output PMMR state. For a
/// historical block response they do not verify against the block header in
/// that response; consumers must use a root matching each proof's `mmr_size`.
pub struct BlockHandler {
	pub chain: Weak<mwc_chain::Chain>,
}

impl BlockHandler {
	fn is_unavailable_block_error(error: &Error) -> bool {
		matches!(
			error,
			Error::NotFound(_) | Error::Chain(mwc_chain::Error::InvalidHeaderHeight(_))
		)
	}

	pub fn get_block(
		&self,
		h: &Hash,
		include_proof: bool,
		include_merkle_proof: bool,
	) -> Result<BlockPrintable, Error> {
		let chain = w(&self.chain)?;
		chain.with_output_read_snapshot(|snapshot| {
			let header = snapshot.get_block_header(h).map_err(|e| {
				let msg = format!("Block header for hash {}, {}", h, e);
				Error::chain_read_error(e, msg)
			})?;
			self.get_block_for_header(snapshot, &header, include_proof, include_merkle_proof)
		})
	}

	fn get_block_for_header(
		&self,
		snapshot: &mwc_chain::OutputReadSnapshot<'_>,
		header: &BlockHeader,
		include_proof: bool,
		include_merkle_proof: bool,
	) -> Result<BlockPrintable, Error> {
		let h = header.hash(snapshot.get_context_id())?;
		let block = snapshot.get_block_for_header(header).map_err(|e| {
			let msg = format!("Block for hash {}, {}", h, e);
			Error::chain_read_error(e, msg)
		})?;
		BlockPrintable::from_block_snapshot(&block, snapshot, include_proof, include_merkle_proof)
			.map_err(|e| {
				Error::Internal(format!("chain error, broken block for hash {}. {}", h, e))
			})
	}

	pub fn get_blocks(
		&self,
		start_height: u64,
		end_height: u64,
		mut max: u64,
		include_proof: Option<bool>,
	) -> Result<BlockListing, Error> {
		if max == 0 {
			return Err(Error::Argument("max must be greater than 0".to_string()));
		}
		// set a limit here
		if max > BLOCK_TRANSFER_LIMIT {
			max = BLOCK_TRANSFER_LIMIT;
		}
		let chain = w(&self.chain)?;
		chain.with_output_read_snapshot(|snapshot| {
			let mut start_height = start_height;
			let tail_height = snapshot
				.get_tail()
				.map_err(|e| Error::chain_read_error(e, "Tail not found".to_string()))?
				.height;
			let orig_start_height = start_height;
			if start_height < tail_height {
				start_height = tail_height;
			}

			// In full archive node, tail will be set to 1, so include genesis block as well
			// for consistency
			if start_height == 1 && orig_start_height == 0 {
				start_height = 0;
			}

			let mut result_set = BlockListing {
				last_retrieved_height: 0,
				blocks: vec![],
			};
			let mut block_count = 0;
			for h in start_height..=end_height {
				let header = match snapshot.get_body_header_by_height(h).map_err(|e| {
					let msg = format!("Header for height {}, {}", h, e);
					Error::chain_read_error(e, msg)
				}) {
					Err(e) => {
						if Self::is_unavailable_block_error(&e) {
							break;
						} else {
							return Err(e);
						}
					}
					Ok(header) => header,
				};

				let block_res = self.get_block_for_header(
					snapshot,
					&header,
					include_proof == Some(true),
					false,
				);

				match block_res {
					Err(e) => {
						if Self::is_unavailable_block_error(&e) {
							break;
						} else {
							return Err(e);
						}
					}
					Ok(b) => {
						block_count += 1;
						result_set.blocks.push(b);
						result_set.last_retrieved_height = h;
					}
				}
				if block_count >= max {
					break;
				}
			}
			Ok(result_set)
		})
	}

	// Try to get hash from height, hash or output commit
	pub fn parse_inputs(
		&self,
		height: Option<u64>,
		hash: Option<Hash>,
		commit: Option<String>,
	) -> Result<Hash, Error> {
		if let Some(height) = height {
			match w(&self.chain)?.get_body_header_by_height(height) {
				Ok(header) => return Ok(header.hash(w(&self.chain)?.get_context_id())?),
				Err(e) => {
					let msg = format!("Header for height {}, {}", height, e);
					return Err(Error::chain_read_error(e, msg));
				}
			}
		}
		if let Some(hash) = hash {
			return Ok(hash);
		}
		if let Some(commit) = commit {
			let oid = match get_output(&self.chain, &commit)? {
				Some((_, o)) => o,
				None => return Err(Error::NotFound("Output not found".to_string())),
			};
			match w(&self.chain)?.get_header_for_output(oid.commitment()) {
				Ok(header) => return Ok(header.hash(w(&self.chain)?.get_context_id())?),
				Err(e) => {
					let msg = format!("Header for output {:?}, {}", oid, e);
					return Err(Error::chain_read_error(e, msg));
				}
			}
		}
		Err(Error::Argument(format!(
			"not a valid hash {:?}, height {:?} or output commit {:?}",
			hash, height, commit
		)))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_util::ToHex;
	use std::fs;
	use std::sync::Arc;
	use std::time::{SystemTime, UNIX_EPOCH};

	fn unique_test_dir(test_name: &str) -> String {
		let unique = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		std::env::temp_dir()
			.join(format!(
				"mwc_api_{}_{}_{}",
				test_name,
				std::process::id(),
				unique
			))
			.to_string_lossy()
			.into_owned()
	}

	#[cfg(feature = "test-support")]
	#[test]
	fn height_queries_follow_body_head_during_header_sync_and_reorg() {
		use super::super::chain_api::OutputHandler;
		use mwc_chain::Options;
		use mwc_core::core::{transaction, Block};
		use mwc_core::libtx::{reward, ProofBuilder};
		use mwc_core::{consensus, global, pow};
		use mwc_crates::chrono::Duration;
		use mwc_keychain::{ExtKeychain, Keychain};
		use std::collections::HashSet;

		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = unique_test_dir("height_queries_body_head");
		let chain = Arc::new(
			mwc_chain::Chain::init(
				&secp,
				0,
				chain_dir.clone(),
				Arc::new(mwc_chain::types::NoopAdapter {}),
				global::get_genesis_block(&secp, 0).unwrap(),
				pow::verify_size,
				false,
				HashSet::new(),
				None,
				None,
				false,
			)
			.unwrap(),
		);
		let keychain = ExtKeychain::from_seed(&secp, &[42; 32], false).unwrap();
		let make_block = |secp: &mut Secp256k1, prev: &BlockHeader, work: u32| {
			let key = ExtKeychain::derive_key_id(1, work, 0, 0, 0).unwrap();
			let txs = transaction::aggregate(0, &[], secp).unwrap();
			let binding = chain
				.coinbase_binding_for_template(secp, prev, &txs.body)
				.unwrap();
			let (output, kernel, opening) = reward::output_s2c(
				0,
				&keychain,
				&ProofBuilder::new(secp, &keychain).unwrap(),
				&key,
				0,
				prev.height + 1,
				secp,
				binding.digest().unwrap(),
			)
			.unwrap();
			let mut block = Block::new(
				0,
				prev,
				&[],
				pow::Difficulty::from_num(u64::from(work)),
				(output, kernel),
				secp,
			)
			.unwrap();
			block.coinbase_opening =
				consensus::is_coinbase_binding_enabled(0, block.header.height).then_some(opening);
			block.header.timestamp = prev.timestamp + Duration::seconds(60);
			block.header.pow.proof = pow::Proof::random(0, global::proofsize(0)).unwrap();
			chain.set_txhashset_roots(secp, &mut block).unwrap();
			block
		};

		// Apply A -> B, then learn header C without its body. Height-based API
		// queries must still stop at B, while internal header sync can see C.
		let a = make_block(&mut secp, &chain.head_header().unwrap(), 1);
		chain
			.process_block(&mut secp, a.clone(), Options::SKIP_POW, HashSet::new())
			.unwrap();
		let b = make_block(&mut secp, &a.header, 2);
		chain
			.process_block(&mut secp, b.clone(), Options::SKIP_POW, HashSet::new())
			.unwrap();
		let c = make_block(&mut secp, &b.header, 3);
		chain
			.process_block_header(&c.header, Options::SKIP_POW)
			.unwrap();
		let headers = HeaderHandler {
			chain: Arc::downgrade(&chain),
		};
		let blocks = BlockHandler {
			chain: Arc::downgrade(&chain),
		};
		let outputs = OutputHandler {
			chain: Arc::downgrade(&chain),
		};
		assert_eq!(chain.get_header_by_height(3).unwrap(), c.header);
		assert!(matches!(
			headers.parse_inputs(Some(3), None, None),
			Err(Error::NotFound(_))
		));
		assert!(matches!(
			blocks.parse_inputs(Some(3), None, None),
			Err(Error::NotFound(_))
		));
		assert!(matches!(
			outputs.get_outputs_v2(None, Some(3), Some(3), None, None),
			Err(Error::NotFound(_))
		));
		let listing = blocks.get_blocks(1, 10, 10, None).unwrap();
		assert_eq!(listing.last_retrieved_height, 2);
		assert_eq!(listing.blocks.len(), 2);
		assert!(blocks
			.get_blocks(3, 10, 10, None)
			.unwrap()
			.blocks
			.is_empty());

		// A higher-work header B' switches the header PMMR to A -> B'. The body
		// head remains B. RPC height selectors, ranges, and outputs must
		// keep returning B and its unspent outputs, rather than the header-only fork.
		let fork = make_block(&mut secp, &a.header, 10);
		chain
			.process_block_header(&fork.header, Options::SKIP_POW)
			.unwrap();
		let b_hash = b.hash(0).unwrap();
		assert_eq!(chain.head().unwrap().last_block_h, b_hash);
		assert_eq!(
			chain.header_head().unwrap().last_block_h,
			fork.hash(0).unwrap()
		);
		assert_eq!(
			headers
				.get_header_v2(&headers.parse_inputs(Some(2), None, None).unwrap())
				.unwrap()
				.hash,
			b_hash.to_hex()
		);
		assert_eq!(headers.parse_inputs(Some(2), None, None).unwrap(), b_hash);
		assert_eq!(blocks.parse_inputs(Some(2), None, None).unwrap(), b_hash);
		let listing = blocks.get_blocks(1, 10, 10, None).unwrap();
		assert_eq!(listing.last_retrieved_height, 2);
		assert_eq!(listing.blocks.len(), 2);
		assert_eq!(listing.blocks[0].header.hash, a.hash(0).unwrap().to_hex());
		assert_eq!(listing.blocks[1].header.hash, b_hash.to_hex());
		let body_outputs = outputs
			.get_outputs_v2(None, Some(2), Some(2), Some(false), Some(false))
			.unwrap();
		assert_eq!(body_outputs.len(), b.outputs().len());
		assert_eq!(body_outputs[0].commit, b.outputs()[0].commitment());
		assert!(!body_outputs[0].spent);

		// Explicit hash requests still allow inspection of the competing header.
		assert_eq!(
			headers.get_header_v2(&fork.hash(0).unwrap()).unwrap().hash,
			fork.hash(0).unwrap().to_hex()
		);
		drop(chain);
		mwc_chain::pipe::release_context_data(0);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn full_blocks_build_output_metadata_from_snapshot() {
		mwc_core::global::set_local_chain_type(mwc_core::global::ChainTypes::Floonet);
		mwc_core::global::set_local_nrd_enabled(false);
		let chain_dir = unique_test_dir("block_response_snapshot");
		let _ = fs::remove_dir_all(&chain_dir);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let genesis = mwc_core::genesis::genesis_floo(&secp, 0);
		let output = *genesis.outputs().first().expect("genesis output");
		let block_hash = genesis.hash(0).unwrap();
		let output_root = genesis.header.output_root;
		let output_mmr_size = genesis.header.output_mmr_size;
		let chain = Arc::new(
			mwc_chain::Chain::init(
				&secp,
				0,
				chain_dir.clone(),
				Arc::new(mwc_chain::types::NoopAdapter {}),
				genesis,
				mwc_core::pow::verify_size,
				false,
				std::collections::HashSet::new(),
				None,
				None,
				false,
			)
			.unwrap(),
		);
		let handler = BlockHandler {
			chain: Arc::downgrade(&chain),
		};

		let printable = handler.get_block(&block_hash, true, true).unwrap();
		let printable_output = printable
			.outputs
			.iter()
			.find(|printable| printable.commit == output.commitment())
			.expect("genesis output in printable block");
		let proof = printable_output
			.merkle_proof
			.as_ref()
			.expect("coinbase merkle proof");
		let pos0 = printable_output
			.mmr_index
			.checked_sub(1)
			.expect("one-based output position");
		assert_eq!(proof.mmr_size, output_mmr_size);
		proof
			.verify(0, output_root, &output.identifier(), pos0)
			.unwrap();

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn unavailable_block_errors_include_heights_above_header_pmmr() {
		assert!(BlockHandler::is_unavailable_block_error(&Error::NotFound(
			"missing block".to_owned()
		)));
		assert!(BlockHandler::is_unavailable_block_error(&Error::Chain(
			mwc_chain::Error::InvalidHeaderHeight(42)
		)));
		assert!(!BlockHandler::is_unavailable_block_error(&Error::Argument(
			"bad request".to_owned()
		)));
	}

	#[test]
	fn header_commitment_lookup_propagates_internal_errors() {
		let handler = HeaderHandler { chain: Weak::new() };

		match handler.parse_inputs(None, None, Some("a".repeat(Hash::LEN * 2 + 2))) {
			Err(Error::Internal(msg)) => {
				assert!(msg.contains("failed to upgrade weak reference"));
			}
			Err(e) => panic!("expected internal weak-reference error, got {:?}", e),
			Ok(_) => panic!("expected internal weak-reference error"),
		}
	}

	#[test]
	fn get_header_v2_rejects_misindexed_record() {
		mwc_core::global::set_local_chain_type(mwc_core::global::ChainTypes::Floonet);
		mwc_core::global::set_local_nrd_enabled(false);
		let chain_dir = unique_test_dir("misindexed_header_record");
		let _ = fs::remove_dir_all(&chain_dir);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain = mwc_chain::Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(mwc_chain::types::NoopAdapter {}),
			mwc_core::genesis::genesis_floo(&secp, 0),
			mwc_core::pow::verify_size,
			false,
			std::collections::HashSet::new(),
			None,
			None,
			false,
		)
		.unwrap();
		let header = chain.genesis();
		let actual_hash = header.hash(chain.get_context_id()).unwrap();

		let mut wrong_hash_bytes = actual_hash.to_vec();
		wrong_hash_bytes[0] ^= 1;
		let wrong_hash = Hash::from_vec(&wrong_hash_bytes);
		drop(chain);
		mwc_chain::pipe::release_context_data(0);

		let store = mwc_chain::ChainStore::new(0, &chain_dir).unwrap();
		let batch = store.batch_write().unwrap();
		let mut wrong_key = Vec::with_capacity(Hash::LEN + 2);
		wrong_key.extend_from_slice(b"h:");
		wrong_key.extend_from_slice(wrong_hash.as_bytes());
		batch.db.put_ser(&wrong_key, &header).unwrap();
		batch.commit().unwrap();
		drop(store);

		let chain = Arc::new(
			mwc_chain::Chain::init(
				&secp,
				0,
				chain_dir.clone(),
				Arc::new(mwc_chain::types::NoopAdapter {}),
				mwc_core::genesis::genesis_floo(&secp, 0),
				mwc_core::pow::verify_size,
				false,
				std::collections::HashSet::new(),
				None,
				None,
				false,
			)
			.unwrap(),
		);
		let handler = HeaderHandler {
			chain: Arc::downgrade(&chain),
		};
		let result = handler.get_header_v2(&wrong_hash);

		drop(handler);
		drop(chain);
		mwc_chain::pipe::release_context_data(0);
		let _ = fs::remove_dir_all(&chain_dir);

		match result {
			Err(Error::Chain(mwc_chain::Error::InvalidPersistedChainState(msg))) => {
				assert!(msg.contains("key/hash mismatch"), "{}", msg);
				assert!(msg.contains(&wrong_hash.to_string()), "{}", msg);
				assert!(msg.contains(&actual_hash.to_string()), "{}", msg);
			}
			other => panic!("expected persisted-chain-state error, got {:?}", other),
		}
	}

	#[test]
	fn header_commitment_lookup_returns_not_found_for_missing_output() {
		mwc_core::global::set_local_chain_type(mwc_core::global::ChainTypes::Floonet);
		mwc_core::global::set_local_nrd_enabled(false);
		let chain_dir = unique_test_dir("missing_output_header_probe");
		let _ = fs::remove_dir_all(&chain_dir);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		let result = {
			let chain = Arc::new(
				mwc_chain::Chain::init(
					&secp,
					0,
					chain_dir.clone(),
					Arc::new(mwc_chain::types::NoopAdapter {}),
					mwc_core::genesis::genesis_floo(&secp, 0),
					mwc_core::pow::verify_size,
					false,
					std::collections::HashSet::new(),
					None,
					None,
					false,
				)
				.unwrap(),
			);
			let handler = HeaderHandler {
				chain: Arc::downgrade(&chain),
			};
			handler.parse_inputs(None, None, Some(secp.commit_value(42).unwrap().to_hex()))
		};

		let _ = fs::remove_dir_all(&chain_dir);

		match result {
			Err(Error::NotFound(_)) => {}
			other => panic!("expected missing output probe, got {:?}", other),
		}
	}
}
