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

use super::utils::{get_output, get_output_v2, w};
use crate::rest::*;
use crate::router::{Handler, ResponseFuture};
use crate::types::*;
use crate::web::*;
use mwc_core::core::hash::Hashed;
use mwc_core::libtx::secp_ser;
use mwc_crates::bytes::Bytes;
use mwc_crates::hyper::{Request, StatusCode};
use mwc_crates::log::{debug, error};
use mwc_crates::secp::constants::PEDERSEN_COMMITMENT_SIZE;
use mwc_crates::secp::pedersen::Commitment;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_crates::serde::de::IntoDeserializer;
use mwc_util::secp_static;
use mwc_util::StopState;
use std::sync::{Arc, Weak};

const MAX_GET_OUTPUTS_COMMITS: usize = 1_000;
const MAX_OUTPUTS_BY_HEIGHT_RANGE: u64 = 100;

/// Chain handler. Get the head details.
/// GET /v1/chain
pub struct ChainHandler {
	pub chain: Weak<mwc_chain::Chain>,
}

impl ChainHandler {
	pub fn get_tip(&self) -> Result<Tip, Error> {
		let head = w(&self.chain)?
			.head()
			.map_err(|e| Error::Internal(format!("can't get head: {}", e)))?;
		Ok(Tip::from_tip(head))
	}
}

impl Handler for ChainHandler {
	fn get(&self, _req: Request<Bytes>) -> ResponseFuture {
		result_to_response(self.get_tip())
	}
}

/// Chain validation handler.
/// GET /v1/chain/validate?fast=true
///
/// This is an owner/admin API. Full validation (`fast=false`) is intentionally
/// expensive: it validates the txhashset, verifies rangeproofs and kernel
/// signatures, and holds chain/PMMR locks while it runs. Operators enabling
/// this endpoint must protect it from unauthorized access and understand that
/// calling it can temporarily degrade node and API availability.
pub struct ChainValidationHandler {
	pub chain: Weak<mwc_chain::Chain>,
}

impl ChainValidationHandler {
	fn fast_validation(req: &Request<Bytes>) -> Result<bool, Error> {
		let params = QueryParams::from_query(req.uri().query())?;
		match params.get("fast")? {
			None => Ok(true),
			Some(val) => val
				.parse()
				.map_err(|_| Error::RequestError("invalid value of parameter fast".to_string())),
		}
	}

	pub fn validate_chain(&self, secp: &Secp256k1, fast_validation: bool) -> Result<(), Error> {
		w(&self.chain)?
			.validate(secp, fast_validation)
			.map_err(|e| {
				Error::Internal(format!(
					"chain fast validation ({}) error: {}",
					fast_validation, e
				))
			})
	}
}

impl Handler for ChainValidationHandler {
	fn get(&self, req: Request<Bytes>) -> ResponseFuture {
		let fast_validation = match Self::fast_validation(&req) {
			Ok(fast_validation) => fast_validation,
			Err(e) => return result_to_response::<()>(Err(e)),
		};
		let secp = match Secp256k1::with_caps(ContextFlag::Commit) {
			Ok(s) => s,
			Err(e) => {
				return response(
					StatusCode::INTERNAL_SERVER_ERROR,
					format!("Secp error, {}", e),
				);
			}
		};
		match self.validate_chain(&secp, fast_validation) {
			Ok(_) => response(StatusCode::OK, "{}"),
			Err(e) => response(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("chain validation is failed, {}", e),
			),
		}
	}
}

/// Chain compaction handler. Trigger a compaction of the chain state to regain
/// storage space.
/// POST /v1/chain/compact
pub struct ChainCompactHandler {
	pub chain: Weak<mwc_chain::Chain>,
	pub stop_state: Arc<StopState>,
}

impl ChainCompactHandler {
	pub fn compact_chain(&self) -> Result<(), Error> {
		w(&self.chain)?
			.compact(self.stop_state.clone())
			.map_err(|e| Error::Internal(format!("compact chain error {}", e)))
	}
}

impl Handler for ChainCompactHandler {
	fn post(&self, _req: Request<Bytes>) -> ResponseFuture {
		match self.compact_chain() {
			Ok(_) => response(StatusCode::OK, "{}"),
			Err(e) => response(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("chain compact failed: {}", e),
			),
		}
	}
}

// Supports retrieval of multiple outputs in a single request -
// GET /v1/chain/outputs/byids?id=xxx,yyy,zzz
// GET /v1/chain/outputs/byids?id=xxx&id=yyy&id=zzz
// GET /v1/chain/outputs/byheight?start_height=101&end_height=200
pub struct OutputHandler {
	pub chain: Weak<mwc_chain::Chain>,
}

impl OutputHandler {
	pub fn get_outputs_v2(
		&self,
		secp: &Secp256k1,
		commits: Vec<String>,
		include_proof: Option<bool>,
		include_merkle_proof: Option<bool>,
	) -> Result<Vec<OutputPrintable>, Error> {
		if commits.len() > MAX_GET_OUTPUTS_COMMITS {
			return Err(Error::RequestError(format!(
				"too many output commitments requested: {}, max {}",
				commits.len(),
				MAX_GET_OUTPUTS_COMMITS
			)));
		}

		let mut outputs: Vec<OutputPrintable> = Vec::with_capacity(commits.len());
		// First check the commits length
		for commit in &commits {
			if commit.len() != 66 {
				return Err(Error::RequestError(format!(
					"invalid commit length {}, expected length 66",
					commit.len()
				)));
			}
		}
		for commit in commits {
			match get_output_v2(
				secp,
				&self.chain,
				&commit,
				include_proof.unwrap_or(false),
				include_merkle_proof.unwrap_or(false),
			) {
				Ok(Some((output, _))) => outputs.push(output),
				Ok(None) => {
					// Ignore outputs that are not found
				}
				Err(e) => {
					error!(
						"Failure to get output for commitment {} with error {}",
						commit, e
					);
					return Err(e);
				}
			};
		}
		Ok(outputs)
	}

	// allows traversal of utxo set
	pub fn get_unspent_outputs(
		&self,
		secp: &Secp256k1,
		start_index: u64,
		end_index: Option<u64>,
		mut max: u64,
		include_proof: Option<bool>,
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
					"Unspent outputs for PMMR {}-{:?}, {}",
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
					OutputPrintable::from_output(
						secp,
						x,
						&chain,
						None,
						include_proof.unwrap_or(false),
						false,
					)
				})
				.collect::<Result<Vec<_>, _>>()
				.map_err(|e| Error::Internal(format!("chain error, {}", e)))?,
		};
		Ok(out)
	}

	fn outputs_by_ids(&self, req: &Request<Bytes>) -> Result<Vec<Output>, Error> {
		let mut commitments: Vec<String> = vec![];

		let query = must_get_query!(req);
		let params = QueryParams::from_query_str(query)?;
		params.process_multival_param("id", |id| push_output_id_param(&mut commitments, id))?;

		let mut outputs: Vec<Output> = vec![];
		for x in commitments {
			match get_output(&self.chain, &x) {
				Ok(Some((output, _))) => outputs.push(output),
				Ok(None) => {
					// Ignore outputs that are not found
				}
				Err(e) => {
					error!(
						"Failure to get output for commitment {} with error {}",
						x, e
					);
					return Err(e);
				}
			};
		}
		Ok(outputs)
	}

	fn outputs_at_height(
		&self,
		secp: &Secp256k1,
		block_height: u64,
		commitments: &[Commitment],
		include_proof: bool,
	) -> Result<BlockOutputs, Error> {
		let header = w(&self.chain)?
			.get_header_by_height(block_height)
			.map_err(|e| {
				let msg = format!("Header at height {}, {}", block_height, e);
				Error::chain_read_error(e, msg)
			})?;

		// TODO - possible to compact away blocks we care about
		// in the period between accepting the block and refreshing the wallet
		let chain = w(&self.chain)?;
		let context_id = chain.get_context_id();
		let header_hash = header.hash(context_id)?;
		let block = chain.get_block(&header_hash).map_err(|e| {
			let msg = format!(
				"Block at height {} for hash {}, {}",
				block_height, header_hash, e
			);
			Error::chain_read_error(e, msg)
		})?;
		let outputs = block
			.outputs()
			.iter()
			.filter(|output| commitments.is_empty() || commitments.contains(&output.commitment()))
			.map(|output| {
				OutputPrintable::from_output(
					secp,
					output,
					&chain,
					Some(&header),
					include_proof,
					true,
				)
			})
			.collect::<Result<Vec<_>, _>>()
			.map_err(|e| Error::Internal(format!("chain read outputs from block error, {}", e)))?;

		Ok(BlockOutputs {
			header: BlockHeaderDifficultyInfo::from_header(&header)?,
			outputs: outputs,
		})
	}

	// returns outputs for a specified range of blocks
	fn outputs_block_batch(
		&self,
		secp: &Secp256k1,
		req: &Request<Bytes>,
	) -> Result<Vec<BlockOutputs>, Error> {
		let mut commitments: Vec<Commitment> = vec![];

		let query = must_get_query!(req);
		let params = QueryParams::from_query_str(query)?;
		params.process_multival_param("id", |id| {
			push_output_commitment_param(&mut commitments, id)
		})?;
		let start_height: u64 = parse_param!(params, "start_height", 1);
		let end_height: u64 = parse_param!(params, "end_height", 1);
		let height_count = end_height
			.checked_sub(start_height)
			.and_then(|span| span.checked_add(1))
			.ok_or_else(|| {
				Error::RequestError(format!(
					"invalid block height range: {}-{}",
					start_height, end_height
				))
			})?;
		if height_count > MAX_OUTPUTS_BY_HEIGHT_RANGE {
			return Err(Error::RequestError(format!(
				"too many block heights requested: {}, max {}",
				height_count, MAX_OUTPUTS_BY_HEIGHT_RANGE
			)));
		}
		let include_rp = params.get("include_rp")?.is_some();

		debug!(
			"outputs_block_batch: {}-{}, {:?}, {:?}",
			start_height, end_height, commitments, include_rp,
		);

		let mut return_vec = vec![];
		for i in (start_height..=end_height).rev() {
			match self.outputs_at_height(secp, i, &commitments, include_rp) {
				Ok(res) => {
					if !res.outputs.is_empty() {
						return_vec.push(res);
					}
				}
				Err(e) => return Err(e),
			}
		}

		Ok(return_vec)
	}
}

fn push_output_id_param(commitments: &mut Vec<String>, id: &str) -> Result<(), Error> {
	if commitments.len() >= MAX_GET_OUTPUTS_COMMITS {
		return Err(Error::RequestError(format!(
			"too many output commitments requested: {}, max {}",
			commitments.len() + 1,
			MAX_GET_OUTPUTS_COMMITS
		)));
	}

	let id_hex = id.trim();
	let id_hex = id_hex.strip_prefix("0x").unwrap_or(id_hex);
	let expected_hex_len = PEDERSEN_COMMITMENT_SIZE * 2;
	if id_hex.len() != expected_hex_len {
		return Err(Error::RequestError(format!(
			"invalid commit length {}, expected length {}",
			id_hex.len(),
			expected_hex_len
		)));
	}

	commitments.push(id.to_owned());
	Ok(())
}

fn push_output_commitment_param(commitments: &mut Vec<Commitment>, id: &str) -> Result<(), Error> {
	if commitments.len() >= MAX_GET_OUTPUTS_COMMITS {
		return Err(Error::RequestError(format!(
			"too many output commitments requested: {}, max {}",
			commitments.len() + 1,
			MAX_GET_OUTPUTS_COMMITS
		)));
	}

	let id_hex = id.strip_prefix("0x").unwrap_or(id);
	let expected_hex_len = PEDERSEN_COMMITMENT_SIZE * 2;
	if id_hex.len() != expected_hex_len {
		return Err(Error::RequestError(format!(
			"invalid commit length {}, expected length {}",
			id_hex.len(),
			expected_hex_len
		)));
	}

	let deserializer: mwc_crates::serde::de::value::StrDeserializer<
		mwc_crates::serde::de::value::Error,
	> = id_hex.into_deserializer();
	// Expected behavior: this endpoint treats the path element as caller-supplied
	// commitment text and exposes a single "not a valid commitment" request error
	// for parse failures from this boundary. The API deliberately does not add
	// special-case plumbing for rare secp context setup failures here.
	let commit = secp_ser::commitment_from_hex(deserializer).map_err(|_| {
		Error::RequestError(format!("Invalid block id {}, not a valid commitment", id))
	})?;
	commitments.push(commit);
	Ok(())
}

impl Handler for OutputHandler {
	fn get(&self, req: Request<Bytes>) -> ResponseFuture {
		match right_path_element!(req) {
			"byids" => result_to_response(self.outputs_by_ids(&req)),
			"byheight" => result_to_response(secp_static::with_verify_only(
				|e| Error::Internal(format!("failed to create secp instance: {}", e)),
				|secp| self.outputs_block_batch(secp, &req),
			)),
			_ => response(StatusCode::BAD_REQUEST, ""),
		}
	}
}

/// Kernel handler, search for a kernel by excess commitment
/// GET /v1/chain/kernels/XXX?min_height=YYY&max_height=ZZZ
/// The `min_height` and `max_height` parameters are optional
pub struct KernelHandler {
	pub chain: Weak<mwc_chain::Chain>,
}

fn parse_kernel_excess(excess_s: &str) -> Result<Commitment, Error> {
	let excess_hex = excess_s.trim();
	let excess_hex = excess_hex.strip_prefix("0x").unwrap_or(excess_hex);
	let expected_hex_len = PEDERSEN_COMMITMENT_SIZE * 2;
	if excess_hex.len() != expected_hex_len {
		return Err(Error::RequestError(format!(
			"invalid excess hex length {}, expected {}",
			excess_hex.len(),
			expected_hex_len
		)));
	}
	let deserializer: mwc_crates::serde::de::value::StrDeserializer<
		mwc_crates::serde::de::value::Error,
	> = excess_hex.into_deserializer();
	// Expected behavior: kernel excess is supplied as request path text, and this
	// boundary intentionally reports commitment parse failures as a bounded bad
	// request. Rare secp context setup failures are not distinguished here to keep
	// this input validation path simple and consistent with other commitment APIs.
	secp_ser::commitment_from_hex(deserializer)
		.map_err(|_| Error::RequestError("invalid excess commitment".to_string()))
}

impl KernelHandler {
	fn get_kernel(&self, req: Request<Bytes>) -> Result<LocatedTxKernel, Error> {
		let excess_s = req
			.uri()
			.path()
			.trim_end_matches('/')
			.rsplit('/')
			.next()
			.ok_or_else(|| Error::RequestError("missing excess".into()))?;
		let excess = parse_kernel_excess(excess_s)?;

		let chain = w(&self.chain)?;

		let mut min_height: Option<u64> = None;
		let mut max_height: Option<u64> = None;

		// Check query parameters for minimum and maximum search height
		if let Some(q) = req.uri().query() {
			let params = QueryParams::from_query_str(q)?;
			if let Some(hs) = params.get("min_height")? {
				let h = hs.parse().map_err(|e| {
					Error::RequestError(format!(
						"invalid parameter 'min_height' value {}, {}",
						hs, e
					))
				})?;
				// Default is genesis
				min_height = if h == 0 { None } else { Some(h) };
			}
			if let Some(hs) = params.get("max_height")? {
				let h = hs.parse().map_err(|e| {
					Error::RequestError(format!(
						"invalid parameter 'max_height' value {}, {}",
						hs, e
					))
				})?;
				// If omitted, max_height defaults to the current head inside
				// get_kernel_height. If supplied, keep the caller's explicit bound
				// and let get_kernel_height clamp it against the current head at lookup time.
				max_height = Some(h);
			}
		}

		let kernel = chain
			.get_kernel_height(&excess, min_height, max_height)
			.map_err(|e| {
				Error::Internal(format!(
					"Unable to get a height for the requested excess, {}",
					e
				))
			})?
			.map(|(tx_kernel, height, mmr_index)| LocatedTxKernel {
				tx_kernel,
				height,
				mmr_index,
			});
		kernel.ok_or_else(|| Error::NotFound("kernel value for requested excess".to_string()))
	}

	pub fn get_kernel_v2(
		&self,
		excess_s: String,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<LocatedTxKernel, Error> {
		let excess = parse_kernel_excess(&excess_s)?;

		let chain = w(&self.chain)?;
		let kernel = chain
			.get_kernel_height(&excess, min_height, max_height)
			.map_err(|e| {
				Error::Internal(format!(
					"Unable to get a height for the requested excess, {}",
					e
				))
			})?
			.map(|(tx_kernel, height, mmr_index)| LocatedTxKernel {
				tx_kernel,
				height,
				mmr_index,
			});
		kernel.ok_or_else(|| Error::NotFound("kernel value for requested excess".to_string()))
	}
}

impl Handler for KernelHandler {
	fn get(&self, req: Request<Bytes>) -> ResponseFuture {
		result_to_response(self.get_kernel(req))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_util::ToHex;
	use std::fs;
	use std::sync::{Arc, Weak};
	use std::time::{SystemTime, UNIX_EPOCH};

	const VALID_COMMIT: &str = "083eafae5d61a85ab07b12e1a51b3918d8e6de11fc6cde641d54af53608aa77b9f";

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
	fn chain_validate_defaults_to_fast_validation() {
		let req = Request::builder()
			.uri("/v1/chain/validate")
			.body(Bytes::new())
			.unwrap();

		assert!(ChainValidationHandler::fast_validation(&req).unwrap());
	}

	#[test]
	fn chain_validate_accepts_explicit_fast_validation() {
		let req = Request::builder()
			.uri("/v1/chain/validate?fast=true")
			.body(Bytes::new())
			.unwrap();

		assert!(ChainValidationHandler::fast_validation(&req).unwrap());
	}

	#[test]
	fn chain_validate_accepts_full_validation() {
		let req = Request::builder()
			.uri("/v1/chain/validate?fast=false")
			.body(Bytes::new())
			.unwrap();

		assert!(!ChainValidationHandler::fast_validation(&req).unwrap());
	}

	#[test]
	fn chain_validate_rejects_invalid_fast_validation() {
		let req = Request::builder()
			.uri("/v1/chain/validate?fast=yes")
			.body(Bytes::new())
			.unwrap();

		let err = ChainValidationHandler::fast_validation(&req).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("invalid value of parameter fast"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn parse_kernel_excess_accepts_normalized_commitment_hex() {
		parse_kernel_excess(&format!("  0x{}  ", VALID_COMMIT)).unwrap();
	}

	#[test]
	fn parse_kernel_excess_rejects_invalid_commitment() {
		let excess = "00".repeat(PEDERSEN_COMMITMENT_SIZE);
		let err = parse_kernel_excess(&excess).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("invalid excess commitment"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn parse_kernel_excess_rejects_overlong_hex_with_bounded_error() {
		let excess = "00".repeat(PEDERSEN_COMMITMENT_SIZE + 1);
		let err = parse_kernel_excess(&excess).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("invalid excess hex length"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn parse_kernel_excess_rejects_invalid_hex_with_bounded_error() {
		let excess = "zz".repeat(PEDERSEN_COMMITMENT_SIZE);
		let err = parse_kernel_excess(&excess).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("invalid excess commitment"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn parse_kernel_excess_rejects_nested_prefix_as_request_error() {
		let excess = format!("0x0x{}", "00".repeat(PEDERSEN_COMMITMENT_SIZE - 1));
		let err = parse_kernel_excess(&excess).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("invalid excess commitment"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn push_output_commitment_param_rejects_invalid_commitment() {
		let mut commitments = Vec::new();
		let commit = "00".repeat(PEDERSEN_COMMITMENT_SIZE);
		let err = push_output_commitment_param(&mut commitments, &commit).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("Invalid block id"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
		assert!(commitments.is_empty());
	}

	#[test]
	fn get_kernel_rest_maps_lookup_miss_to_not_found() {
		mwc_core::global::set_local_chain_type(mwc_core::global::ChainTypes::Floonet);
		mwc_core::global::set_local_nrd_enabled(false);
		let chain_dir = unique_test_dir("kernel_missing");
		let _ = fs::remove_dir_all(&chain_dir);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		let err = {
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
				)
				.unwrap(),
			);
			let kernel_handler = KernelHandler {
				chain: Arc::downgrade(&chain),
			};
			let excess = secp.commit_value(42).unwrap().to_hex();
			let req = Request::builder()
				.uri(format!(
					"/v1/chain/kernels/{}?min_height=2&max_height=1",
					excess
				))
				.body(Bytes::new())
				.unwrap();

			kernel_handler.get_kernel(req).unwrap_err()
		};

		let _ = fs::remove_dir_all(&chain_dir);

		match err {
			Error::NotFound(msg) => {
				assert_eq!(msg, "kernel value for requested excess");
			}
			other => panic!("expected not found error, got {:?}", other),
		}
	}

	#[test]
	fn get_outputs_v2_rejects_commit_lists_above_limit() {
		let output_handler = OutputHandler { chain: Weak::new() };
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commits = vec!["00".repeat(33); MAX_GET_OUTPUTS_COMMITS + 1];

		let err = output_handler
			.get_outputs_v2(&secp, commits, None, None)
			.unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(
					msg.contains("too many output commitments requested"),
					"{}",
					msg
				);
				assert!(msg.contains("max 1000"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn get_outputs_v2_allows_commit_lists_at_limit() {
		let output_handler = OutputHandler { chain: Weak::new() };
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commits = vec![VALID_COMMIT.to_string(); MAX_GET_OUTPUTS_COMMITS];

		let err = output_handler
			.get_outputs_v2(&secp, commits, None, None)
			.unwrap_err();

		match err {
			Error::Internal(msg) => {
				assert!(msg.contains("failed to upgrade weak reference"), "{}", msg);
			}
			other => panic!("expected internal weak reference error, got {:?}", other),
		}
	}

	#[test]
	fn outputs_by_ids_rejects_commit_lists_above_limit() {
		let mut commitments = Vec::new();
		for _ in 0..MAX_GET_OUTPUTS_COMMITS {
			push_output_id_param(&mut commitments, VALID_COMMIT).unwrap();
		}
		let err = push_output_id_param(&mut commitments, VALID_COMMIT).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(
					msg.contains("too many output commitments requested"),
					"{}",
					msg
				);
				assert!(msg.contains("max 1000"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn outputs_by_ids_rejects_invalid_commit_length_before_decode() {
		let output_handler = OutputHandler { chain: Weak::new() };
		let commit = "00".repeat(PEDERSEN_COMMITMENT_SIZE + 1);
		let req = Request::builder()
			.uri(format!("/v1/chain/outputs/byids?id={}", commit))
			.body(Bytes::new())
			.unwrap();

		let err = output_handler.outputs_by_ids(&req).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("invalid commit length"), "{}", msg);
				assert!(msg.contains("expected length 66"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn outputs_block_batch_rejects_height_ranges_above_limit() {
		let output_handler = OutputHandler { chain: Weak::new() };
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let req = Request::builder()
			.uri(format!(
				"/v1/chain/outputs/byheight?start_height=1&end_height={}",
				MAX_OUTPUTS_BY_HEIGHT_RANGE + 1
			))
			.body(Bytes::new())
			.unwrap();

		let err = output_handler.outputs_block_batch(&secp, &req).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("too many block heights requested"), "{}", msg);
				assert!(msg.contains("max 100"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn outputs_block_batch_propagates_missing_requested_heights() {
		mwc_core::global::set_local_chain_type(mwc_core::global::ChainTypes::Floonet);
		mwc_core::global::set_local_nrd_enabled(false);
		let chain_dir = unique_test_dir("outputs_missing_height");
		let _ = fs::remove_dir_all(&chain_dir);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		let err = {
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
				)
				.unwrap(),
			);
			let output_handler = OutputHandler {
				chain: Arc::downgrade(&chain),
			};
			let req = Request::builder()
				.uri("/v1/chain/outputs/byheight?start_height=1&end_height=1")
				.body(Bytes::new())
				.unwrap();

			output_handler.outputs_block_batch(&secp, &req).unwrap_err()
		};

		let _ = fs::remove_dir_all(&chain_dir);

		match err {
			Error::NotFound(msg) => {
				assert!(msg.contains("Header at height 1"), "{}", msg);
			}
			other => panic!("expected not found error, got {:?}", other),
		}
	}

	#[test]
	fn outputs_block_batch_rejects_commit_lists_above_limit() {
		let mut commitments = Vec::new();
		let commit = VALID_COMMIT.to_string();

		for _ in 0..MAX_GET_OUTPUTS_COMMITS {
			push_output_commitment_param(&mut commitments, &commit).unwrap();
		}
		let err = push_output_commitment_param(&mut commitments, &commit).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(
					msg.contains("too many output commitments requested"),
					"{}",
					msg
				);
				assert!(msg.contains("max 1000"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn outputs_block_batch_rejects_invalid_commit_length_before_decode() {
		let output_handler = OutputHandler { chain: Weak::new() };
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let req = Request::builder()
			.uri("/v1/chain/outputs/byheight?start_height=1&end_height=1&id=00")
			.body(Bytes::new())
			.unwrap();

		let err = output_handler.outputs_block_batch(&secp, &req).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("invalid commit length"), "{}", msg);
				assert!(msg.contains("expected length 66"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}
}
