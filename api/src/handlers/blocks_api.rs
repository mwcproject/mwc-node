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
use crate::router::{Handler, ResponseFuture};
use crate::types::*;
use crate::web::*;
use mwc_core::core::hash::Hash;
use mwc_core::core::hash::Hashed;
use mwc_core::core::BlockHeader;
use mwc_crates::bytes::Bytes;
use mwc_crates::hyper::{Request, StatusCode};
use std::sync::Weak;

/// Maximum number of full blocks returned by a single get_blocks request.
/// Kept small because every returned block is fully materialized in memory,
/// performs per-output UTXO/proof lookups, and is hex-expanded when proofs
/// are requested, so the response cost scales with both block count and block
/// contents. Callers can paginate via `last_retrieved_height`.
pub const BLOCK_TRANSFER_LIMIT: u64 = 10;
const MAX_U64_DECIMAL_LEN: usize = 20;
const INVALID_INPUT_PREVIEW_CHARS: usize = 80;

#[derive(Debug, PartialEq, Eq)]
struct BlockQueryOptions {
	compact: bool,
	include_proof: bool,
	include_merkle_proof: bool,
}

impl Default for BlockQueryOptions {
	fn default() -> Self {
		BlockQueryOptions {
			compact: false,
			include_proof: false,
			include_merkle_proof: true,
		}
	}
}

fn parse_canonical_height(input: &str) -> Option<u64> {
	if input == "0"
		|| (input.len() <= MAX_U64_DECIMAL_LEN
			&& !input.starts_with('0')
			&& input.bytes().all(|b| b.is_ascii_digit()))
	{
		input.parse().ok()
	} else {
		None
	}
}

fn invalid_hash_or_height(input: &str, err: impl std::fmt::Display) -> Error {
	let mut chars = input.chars();
	let preview = chars
		.by_ref()
		.take(INVALID_INPUT_PREVIEW_CHARS)
		.collect::<String>();
	let truncated = if chars.next().is_some() {
		" (truncated)"
	} else {
		""
	};

	Error::Argument(format!(
		"Not a valid hash or height value (len {}, preview {:?}{}), {}",
		input.len(),
		preview,
		truncated,
		err
	))
}

fn parse_block_query(params: Option<&str>) -> Result<BlockQueryOptions, Error> {
	let mut options = BlockQueryOptions::default();
	let query = QueryParams::from_query(params)?;

	for param in query.names() {
		match param {
			"compact" => options.compact = true,
			"no_merkle_proof" => options.include_merkle_proof = false,
			"include_proof" => options.include_proof = true,
			_ => {
				return Err(Error::RequestError(format!(
					"unsupported query parameter: {}",
					param
				)));
			}
		}
	}

	Ok(options)
}

/// Gets block headers given either a hash or height or an output commit.
/// GET /v1/headers/<hash>
/// GET /v1/headers/<height>
/// GET /v1/headers/<output commit>
///
pub struct HeaderHandler {
	pub chain: Weak<mwc_chain::Chain>,
}

impl HeaderHandler {
	fn get_header(&self, input: String) -> Result<BlockHeaderPrintable, Error> {
		// will fail quick if the provided isn't a commitment
		match self.get_header_for_output(input.clone()) {
			Ok(Some(h)) => return Ok(h),
			Ok(None) => {}
			// Expected commitment probe failures. Continue parsing the input as
			// a height or hash, but do not hide internal or chain-read errors.
			Err(Error::Argument(_)) | Err(Error::SecpError(_)) => {}
			Err(e) => return Err(e),
		}
		if let Some(height) = parse_canonical_height(&input) {
			match w(&self.chain)?.get_header_by_height(height) {
				Ok(header) => return Ok(BlockHeaderPrintable::from_header(&header)?),
				Err(e) => {
					let msg = format!("Header for height {}, {}", height, e);
					return Err(Error::chain_read_error(e, msg));
				}
			}
		}
		let h = Hash::from_hex(&input).map_err(|e| invalid_hash_or_height(&input, e))?;
		let chain = w(&self.chain)?;
		let header = chain.get_block_header(&h).map_err(|e| {
			let msg = format!("Block header for hash {}, {}", h, e);
			Error::chain_read_error(e, msg)
		})?;
		let actual_hash = header.hash(chain.get_context_id())?;
		if actual_hash != h {
			return Err(mwc_chain::Error::InvalidPersistedChainState(format!(
				"block header record key/hash mismatch: requested {}, loaded {}",
				h, actual_hash
			))
			.into());
		}
		Ok(BlockHeaderPrintable::from_header(&header)?)
	}

	fn get_header_for_output(
		&self,
		commit_id: String,
	) -> Result<Option<BlockHeaderPrintable>, Error> {
		let oid = match get_output(&self.chain, &commit_id)? {
			Some((_, o)) => o,
			None => return Ok(None),
		};
		match w(&self.chain)?.get_header_for_output(oid.commitment()) {
			Ok(header) => Ok(Some(BlockHeaderPrintable::from_header(&header)?)),
			Err(e) => {
				let msg = format!("Header for output {}, {}", commit_id, e);
				Err(Error::chain_read_error(e, msg))
			}
		}
	}

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
			match w(&self.chain)?.get_header_by_height(height) {
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

impl Handler for HeaderHandler {
	fn get(&self, req: Request<Bytes>) -> ResponseFuture {
		let el = right_path_element!(req);
		result_to_response(self.get_header(el.to_string()))
	}
}

/// Gets block details given either a hash or an unspent commit
/// GET /v1/blocks/<hash>
/// GET /v1/blocks/<height>
/// GET /v1/blocks/<commit>
///
/// Optionally return results as "compact blocks" by passing "?compact" query
/// param GET /v1/blocks/<hash>?compact
///
/// Optionally turn off the Merkle proof extraction by passing "?no_merkle_proof" query
/// param GET /v1/blocks/<hash>?no_merkle_proof
///
/// Included proofs describe the node's current output PMMR state. For a
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
				let header = match snapshot.get_header_by_height(h).map_err(|e| {
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

	fn get_compact_block(
		&self,
		h: &Hash,
		include_merkle_proof: bool,
	) -> Result<CompactBlockPrintable, Error> {
		let chain = w(&self.chain)?;
		chain.with_output_read_snapshot(|snapshot| {
			let header = snapshot.get_block_header(h).map_err(|e| {
				let msg = format!("Block header for hash {}, {}", h, e);
				Error::chain_read_error(e, msg)
			})?;
			let block = snapshot.get_block_for_header(&header).map_err(|e| {
				let msg = format!("Block for hash {}, {}", h, e);
				Error::chain_read_error(e, msg)
			})?;
			CompactBlockPrintable::from_compact_block_snapshot(
				&mwc_core::core::CompactBlock::from(block).map_err(|e| {
					Error::Internal(format!("Unable to build a CompactBlock, {}", e))
				})?,
				snapshot,
				include_merkle_proof,
			)
			.map_err(|e| {
				Error::Internal(format!(
					"chain error, broken compact block for hash {}, {}",
					h, e
				))
			})
		})
	}

	// Try to decode the string as a height or a hash.
	fn parse_input(&self, input: String) -> Result<Hash, Error> {
		if let Some(height) = parse_canonical_height(&input) {
			match w(&self.chain)?.get_header_by_height(height) {
				Ok(header) => return Ok(header.hash(w(&self.chain)?.get_context_id())?),
				Err(e) => {
					let msg = format!("Header for height {}, {}", height, e);
					return Err(Error::chain_read_error(e, msg));
				}
			}
		}
		Hash::from_hex(&input).map_err(|e| invalid_hash_or_height(&input, e))
	}

	// Try to get hash from height, hash or output commit
	pub fn parse_inputs(
		&self,
		height: Option<u64>,
		hash: Option<Hash>,
		commit: Option<String>,
	) -> Result<Hash, Error> {
		if let Some(height) = height {
			match w(&self.chain)?.get_header_by_height(height) {
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

impl Handler for BlockHandler {
	fn get(&self, req: Request<Bytes>) -> ResponseFuture {
		let el = right_path_element!(req);
		let h = match self.parse_input(el.to_string()) {
			Err(e @ Error::Argument(_)) => {
				return response(
					StatusCode::BAD_REQUEST,
					format!("failed to parse input: {}", e),
				);
			}
			Err(e) => return result_to_response::<()>(Err(e)),
			Ok(h) => h,
		};

		let options = match parse_block_query(req.uri().query()) {
			Ok(options) => options,
			Err(e) => return result_to_response::<()>(Err(e)),
		};

		if options.compact {
			return result_to_response(self.get_compact_block(&h, options.include_merkle_proof));
		}

		result_to_response(self.get_block(&h, options.include_proof, options.include_merkle_proof))
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

	#[test]
	fn full_and_compact_blocks_build_output_metadata_from_snapshot() {
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
		let source_compact =
			mwc_core::core::CompactBlock::from(genesis.clone()).expect("compact genesis block");
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

		let compact = handler.get_compact_block(&block_hash, true).unwrap();
		let converted_compact =
			CompactBlockPrintable::from_compact_block(&source_compact, &chain, true)
				.expect("printable compact genesis block");
		assert_eq!(converted_compact.nonce, source_compact.nonce);
		let serialized_compact =
			mwc_crates::serde_json::to_value(&converted_compact).expect("serialize compact block");
		assert_eq!(
			serialized_compact
				.get("nonce")
				.and_then(|nonce| nonce.as_u64()),
			Some(source_compact.nonce)
		);
		let compact_output = compact
			.out_full
			.iter()
			.find(|printable| printable.commit == output.commitment())
			.expect("genesis output in printable compact block");
		assert_eq!(compact_output.context_id, printable_output.context_id);
		assert_eq!(
			compact_output
				.merkle_proof
				.as_ref()
				.map(|proof| proof.mmr_size),
			Some(output_mmr_size)
		);

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
	fn parse_input_rejects_overlong_hashes() {
		let handler = BlockHandler { chain: Weak::new() };
		let overlong_hash = format!("{}00", "a".repeat(Hash::LEN * 2));
		assert!(handler.parse_input(overlong_hash).is_err());
	}

	#[test]
	fn parse_input_rejects_very_overlong_hashes_with_bounded_error() {
		let handler = BlockHandler { chain: Weak::new() };
		let overlong_hash = "a".repeat(INVALID_INPUT_PREVIEW_CHARS + 512);
		let err = handler.parse_input(overlong_hash.clone()).unwrap_err();

		match err {
			Error::Argument(msg) => {
				assert!(
					msg.contains(&format!("len {}", overlong_hash.len())),
					"{}",
					msg
				);
				assert!(
					msg.contains(&"a".repeat(INVALID_INPUT_PREVIEW_CHARS)),
					"{}",
					msg
				);
				assert!(msg.contains("truncated"), "{}", msg);
				assert!(!msg.contains(&overlong_hash), "{}", msg);
				assert!(msg.len() < 256, "{}", msg);
			}
			other => panic!("expected argument error, got {:?}", other),
		}
	}

	#[test]
	fn parse_input_rejects_noncanonical_numeric_heights_before_chain_lookup() {
		let handler = BlockHandler { chain: Weak::new() };
		let overlong_zero_height = "0".repeat(Hash::LEN * 2 + 3);

		for input in ["00", "01", &overlong_zero_height] {
			match handler.parse_input(input.to_owned()) {
				Err(Error::Argument(_)) => {}
				other => panic!("expected argument error for {:?}, got {:?}", input, other),
			}
		}
	}

	#[test]
	fn parse_canonical_height_accepts_only_canonical_decimal_strings() {
		assert_eq!(parse_canonical_height("0"), Some(0));
		assert_eq!(parse_canonical_height("1"), Some(1));
		assert_eq!(
			parse_canonical_height(&u64::MAX.to_string()),
			Some(u64::MAX)
		);

		assert_eq!(parse_canonical_height(""), None);
		assert_eq!(parse_canonical_height("00"), None);
		assert_eq!(parse_canonical_height("01"), None);
		assert_eq!(parse_canonical_height("18446744073709551616"), None);
		assert_eq!(parse_canonical_height(&"0".repeat(Hash::LEN * 2 + 3)), None);
	}

	#[test]
	fn parse_block_query_accepts_supported_flags() {
		let options = parse_block_query(Some("compact&no_merkle_proof&include_proof=1")).unwrap();

		assert!(options.compact);
		assert!(options.include_proof);
		assert!(!options.include_merkle_proof);
	}

	#[test]
	fn parse_block_query_rejects_percent_decoded_invalid_utf8() {
		match parse_block_query(Some("compact=%FF")) {
			Ok(_) => panic!("expected invalid UTF-8 to be rejected"),
			Err(Error::RequestError(msg)) => {
				assert!(msg.contains("invalid UTF-8 in query string"), "{}", msg);
			}
			Err(other) => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn get_preserves_internal_parse_input_errors() {
		let handler = BlockHandler { chain: Weak::new() };
		let req = Request::builder()
			.uri("/v1/blocks/1")
			.body(Bytes::new())
			.unwrap();

		let response = mwc_crates::futures::executor::block_on(handler.get(req)).unwrap();

		assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
	}

	#[test]
	fn get_header_propagates_internal_commitment_probe_errors() {
		let handler = HeaderHandler { chain: Weak::new() };

		match handler.get_header("a".repeat(Hash::LEN * 2 + 2)) {
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
	fn get_header_for_output_returns_none_for_missing_output_probe() {
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
			handler.get_header_for_output(secp.commit_value(42).unwrap().to_hex())
		};

		let _ = fs::remove_dir_all(&chain_dir);

		match result {
			Ok(None) => {}
			other => panic!("expected missing output probe, got {:?}", other),
		}
	}
}
