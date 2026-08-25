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

use super::utils::{parse_commitment, w};
use crate::rest::*;
use crate::router::{Handler, ResponseFuture};
use crate::types::*;
use crate::web::*;
use mwc_crates::bytes::Bytes;
use mwc_crates::hyper::{Request, StatusCode};
use mwc_util::{secp_static, ToHex};
use std::sync::Weak;
// Sum tree handler. Retrieve the roots:
// GET /v1/txhashset/roots
//
// Last inserted nodes, using legacy semantics that skip pruned entries::
// GET /v1/txhashset/lastoutputs (gets up to 10 unpruned entries)
// GET /v1/txhashset/lastoutputs?n=5
// GET /v1/txhashset/lastrangeproofs
// GET /v1/txhashset/lastkernels

// UTXO traversal::
// GET /v1/txhashset/outputs?start_index=1&max=100
// GET /v1/txhashset/heightstopmmr?start_height=1&end_height=1000
//
// Build a Merkle proof for a currently unspent output. The proof targets the
// node's current output PMMR state, not the output's origin header.
// GET /v1/txhashset/merkleproof?n=1

const MAX_LAST_TXHASHSET_INSERTIONS: u64 = 10_000;

pub struct TxHashSetHandler {
	pub chain: Weak<mwc_chain::Chain>,
}

impl TxHashSetHandler {
	// gets roots
	fn get_roots(&self) -> Result<TxHashSet, Error> {
		let chain = w(&self.chain)?;
		TxHashSet::from_head(&chain)
			.map_err(|e| Error::Internal(format!("failed to read roots from txhashset: {}", e)))
	}

	// Gets up to distance unpruned outputs by scanning backward in the tree.
	fn get_last_n_output(&self, distance: u64) -> Result<Vec<TxHashSetNode>, Error> {
		let distance = validate_last_txhashset_insertions(distance)?;
		let chain = w(&self.chain)?;
		Ok(TxHashSetNode::get_last_n_output(&chain, distance)?)
	}

	// Gets up to distance unpruned rangeproofs by scanning backward in the tree.
	fn get_last_n_rangeproof(&self, distance: u64) -> Result<Vec<TxHashSetNode>, Error> {
		let distance = validate_last_txhashset_insertions(distance)?;
		let chain = w(&self.chain)?;
		Ok(TxHashSetNode::get_last_n_rangeproof(&chain, distance)?)
	}

	// Gets up to distance unpruned kernels by scanning backward in the tree.
	fn get_last_n_kernel(&self, distance: u64) -> Result<Vec<TxHashSetNode>, Error> {
		let distance = validate_last_txhashset_insertions(distance)?;
		let chain = w(&self.chain)?;
		Ok(TxHashSetNode::get_last_n_kernel(&chain, distance)?)
	}

	// allows traversal of utxo set
	fn outputs(
		&self,
		start_index: u64,
		end_index: Option<u64>,
		mut max: u64,
	) -> Result<OutputListing, Error> {
		//set a limit here
		if max > 10_000 {
			max = 10_000;
		}
		let chain = w(&self.chain)?;
		chain.with_output_read_snapshot(|snapshot| {
			let outputs = snapshot
				.unspent_outputs_by_pmmr_index(start_index, max, end_index)
				.map_err(|e| {
					let msg = format!(
						"Unspent output for PMMR {}-{:?}, {}",
						start_index, end_index, e
					);
					Error::chain_read_error(e, msg)
				})?;
			let printable_outputs = outputs
				.2
				.iter()
				.map(|output| {
					// These are current-state proofs. An origin header is intentionally
					// not fetched because it is not a valid verification target.
					let (pos, merkle_proof) = snapshot
						.get_output_status(&output.identifier(), true)
						.map_err(|e| Error::Internal(format!("chain error: {}", e)))?;
					OutputPrintable::from_output_snapshot(
						output,
						pos,
						merkle_proof,
						snapshot.get_context_id(),
						None,
						true,
					)
					.map_err(|e| Error::Internal(format!("chain error: {}", e)))
				})
				.collect::<Result<Vec<_>, _>>()?;
			Ok(OutputListing {
				last_retrieved_index: outputs.0,
				highest_index: outputs.1,
				outputs: printable_outputs,
			})
		})
	}

	// allows traversal of utxo set bounded within a block range
	pub fn block_height_range_to_pmmr_indices(
		&self,
		start_block_height: u64,
		end_block_height: Option<u64>,
	) -> Result<OutputListing, Error> {
		let chain = w(&self.chain)?;
		let range = chain
			.block_height_range_to_pmmr_indices(start_block_height, end_block_height)
			.map_err(|e| {
				let msg = format!(
					"Block PMMR range for heights {}-{:?}, {}",
					start_block_height, end_block_height, e
				);
				Error::chain_read_error(e, msg)
			})?;
		let out = OutputListing {
			last_retrieved_index: range.0,
			highest_index: range.1,
			outputs: vec![],
		};
		Ok(out)
	}

	// Return a dummy output carrying a current-state Merkle proof (to avoid
	// introducing another legacy response type). The proof's `mmr_size`, not an
	// origin block, identifies the output-root state used for verification.
	fn get_merkle_proof_for_output(&self, id: &str) -> Result<OutputPrintable, Error> {
		let commit = parse_commitment(id)?;
		let commit_hex = commit.to_hex();
		let chain = w(&self.chain)?;
		chain.with_output_read_snapshot(|snapshot| {
			let (output_pos, merkle_proof) = snapshot
				.get_output_pos_and_merkle_proof(commit)
				.map_err(|e| {
					let msg = format!(
						"Unable to get a MMR position and merkle proof for commit {}, {}",
						commit_hex, e
					);
					Error::chain_read_error(e, msg)
				})?;
			Ok(OutputPrintable {
				output_type: OutputType::Coinbase,
				commit: secp_static::commit_to_zero_value(),
				spent: false,
				proof: None,
				proof_hash: "".to_string(),
				block_height: None,
				merkle_proof: Some(merkle_proof),
				mmr_index: output_pos,
				context_id: snapshot.get_context_id(),
			})
		})
	}
}

// Caps the requested number of returned unpruned entries. This is not a bound
// on historical insertion positions scanned by the legacy last-n helpers.
fn validate_last_txhashset_insertions(n: u64) -> Result<u64, Error> {
	if n > MAX_LAST_TXHASHSET_INSERTIONS {
		return Err(Error::RequestError(format!(
			"parameter n exceeds maximum of {}",
			MAX_LAST_TXHASHSET_INSERTIONS
		)));
	}
	Ok(n)
}

impl Handler for TxHashSetHandler {
	fn get(&self, req: Request<Bytes>) -> ResponseFuture {
		let response = (|| -> Result<ResponseFuture, Error> {
			let params = QueryParams::from_query(req.uri().query())?;
			let last_n = parse_param!(params, "n", 10);
			let start_index = parse_param!(params, "start_index", 1);
			let end_index = match parse_param!(params, "end_index", 0) {
				0 => None,
				i => Some(i),
			};
			let max = parse_param!(params, "max", 100);
			let id = parse_param!(params, "id", "".to_owned());
			let start_height = parse_param!(params, "start_height", 1);
			let end_height = match parse_param!(params, "end_height", 0) {
				0 => None,
				h => Some(h),
			};
			let path_element = match req.uri().path().trim_end_matches('/').rsplit('/').next() {
				Some(el) => el,
				None => return Ok(response(StatusCode::BAD_REQUEST, "invalid url")),
			};

			Ok(match path_element {
				"roots" => result_to_response(self.get_roots()),
				"lastoutputs" => result_to_response(self.get_last_n_output(last_n)),
				"lastrangeproofs" => result_to_response(self.get_last_n_rangeproof(last_n)),
				"lastkernels" => result_to_response(self.get_last_n_kernel(last_n)),
				"outputs" => result_to_response(self.outputs(start_index, end_index, max)),
				"heightstopmmr" => result_to_response(
					self.block_height_range_to_pmmr_indices(start_height, end_height),
				),
				"merkleproof" => result_to_response(self.get_merkle_proof_for_output(&id)),
				_ => response(StatusCode::BAD_REQUEST, ""),
			})
		})();

		match response {
			Ok(response) => response,
			Err(e) => result_to_response(Err::<(), Error>(e)),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::secp::constants::PEDERSEN_COMMITMENT_SIZE;
	use mwc_crates::secp::{ContextFlag, Secp256k1};
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
	fn legacy_output_listing_and_proof_use_matching_snapshot_data() {
		mwc_core::global::set_local_chain_type(mwc_core::global::ChainTypes::Floonet);
		mwc_core::global::set_local_nrd_enabled(false);
		let chain_dir = unique_test_dir("legacy_output_snapshot");
		let _ = fs::remove_dir_all(&chain_dir);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let genesis = mwc_core::genesis::genesis_floo(&secp, 0);
		let output = *genesis.outputs().first().expect("genesis output");
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
		let handler = TxHashSetHandler {
			chain: Arc::downgrade(&chain),
		};

		let listing = handler.outputs(1, None, 100).unwrap();
		let listed = listing
			.outputs
			.iter()
			.find(|listed| listed.commit == output.commitment())
			.expect("genesis output in listing");
		let proof_output = handler
			.get_merkle_proof_for_output(&output.commitment().to_hex())
			.unwrap();
		let proof = proof_output
			.merkle_proof
			.as_ref()
			.expect("current-state merkle proof");
		let head = chain.head_header().unwrap();

		assert_eq!(listing.highest_index, head.output_mmr_size);
		assert_eq!(listed.context_id, proof_output.context_id);
		assert_eq!(
			listed.mmr_index.checked_sub(1),
			Some(proof_output.mmr_index)
		);
		assert_eq!(proof.mmr_size, head.output_mmr_size);
		proof
			.verify(
				proof_output.context_id,
				head.output_root,
				&output.identifier(),
				proof_output.mmr_index,
			)
			.unwrap();

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn get_merkle_proof_rejects_overlong_commitment_with_bounded_error() {
		let handler = TxHashSetHandler { chain: Weak::new() };
		let id = "00".repeat(PEDERSEN_COMMITMENT_SIZE + 1024);

		let err = match handler.get_merkle_proof_for_output(&id) {
			Err(err) => err,
			Ok(_) => panic!("expected oversized commitment to be rejected"),
		};

		match err {
			Error::Argument(msg) => {
				assert!(msg.contains("invalid commitment hex length"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected argument error, got {:?}", other),
		}
	}

	#[test]
	fn validate_last_txhashset_insertions_rejects_oversized_n() {
		assert_eq!(
			validate_last_txhashset_insertions(MAX_LAST_TXHASHSET_INSERTIONS).unwrap(),
			MAX_LAST_TXHASHSET_INSERTIONS
		);

		let err = validate_last_txhashset_insertions(MAX_LAST_TXHASHSET_INSERTIONS + 1)
			.expect_err("expected oversized n to be rejected");

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("parameter n exceeds maximum"), "{}", msg);
				assert!(
					msg.contains(&MAX_LAST_TXHASHSET_INSERTIONS.to_string()),
					"{}",
					msg
				);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn get_last_n_kernel_rejects_oversized_distance_before_chain_access() {
		let handler = TxHashSetHandler { chain: Weak::new() };

		let err = handler
			.get_last_n_kernel(MAX_LAST_TXHASHSET_INSERTIONS + 1)
			.expect_err("expected oversized n to be rejected");

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("parameter n exceeds maximum"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}
}
