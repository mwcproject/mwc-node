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
use mwc_crates::secp::Secp256k1;
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
// Build a merkle proof for a given pos
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
		secp: &Secp256k1,
		start_index: u64,
		end_index: Option<u64>,
		mut max: u64,
	) -> Result<OutputListing, Error> {
		//set a limit here
		if max > 10_000 {
			max = 10_000;
		}
		let chain = w(&self.chain)?;
		let outputs = chain
			.unspent_outputs_by_pmmr_index(start_index, max, end_index)
			.map_err(|e| {
				let msg = format!(
					"Unspent output for PMMR {}-{:?}, {}",
					start_index, end_index, e
				);
				Error::chain_read_error(e, msg)
			})?;
		let out = OutputListing {
			last_retrieved_index: outputs.0,
			highest_index: outputs.1,
			outputs: outputs
				.2
				.iter()
				.map(|x| {
					// Requesting headers for voinbase only. Reson for that is:
					// when include_merkle_proof is true, it only builds a
					//   Merkle proof for unspent coinbase outputs. That proof needs the block
					//   header so the chain can rewind the PMMR to the correct block state.
					let header = if x.is_coinbase() {
						Some(chain.get_header_for_output(x.commitment()).map_err(|e| {
							let msg = format!(
								"Header for output commitment {}, {}",
								x.commitment().to_hex(),
								e
							);
							Error::chain_read_error(e, msg)
						})?)
					} else {
						None
					};

					OutputPrintable::from_output(secp, x, &chain, header.as_ref(), true, true)
						.map_err(|e| Error::Internal(format!("chain error: {}", e)))
				})
				.collect::<Result<Vec<_>, _>>()?,
		};
		Ok(out)
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

	// return a dummy output with merkle proof for position filled out
	// (to avoid having to create a new type to pass around)
	fn get_merkle_proof_for_output(
		&self,
		context_id: u32,
		id: &str,
	) -> Result<OutputPrintable, Error> {
		let commit = parse_commitment(id)?;
		let commit_hex = commit.to_hex();
		let chain = w(&self.chain)?;
		let output_pos = chain.get_output_pos(&commit).map_err(|e| {
			let msg = format!(
				"Unable to get a MMR position for commit {}, {}",
				commit_hex, e
			);
			Error::chain_read_error(e, msg)
		})?;
		let merkle_proof =
			mwc_chain::Chain::get_merkle_proof_for_pos(&chain, commit).map_err(|e| {
				let msg = format!(
					"Unable to get a merkle proof for commit {}, {}",
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
			context_id,
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
				"outputs" => result_to_response(secp_static::with_verify_only(
					|e| Error::Internal(format!("failed to create secp instance: {}", e)),
					|secp| self.outputs(secp, start_index, end_index, max),
				)),
				"heightstopmmr" => result_to_response(
					self.block_height_range_to_pmmr_indices(start_height, end_height),
				),
				"merkleproof" => result_to_response((|| {
					let context_id = w(&self.chain)?.get_context_id();
					self.get_merkle_proof_for_output(context_id, &id)
				})()),
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

	#[test]
	fn get_merkle_proof_rejects_overlong_commitment_with_bounded_error() {
		let handler = TxHashSetHandler { chain: Weak::new() };
		let id = "00".repeat(PEDERSEN_COMMITMENT_SIZE + 1024);

		let err = match handler.get_merkle_proof_for_output(0, &id) {
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
