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

//! Build a block to mine: gathers transactions from the pool, assembles
//! them into a block and returns it.

use crate::common::types::Error;
use crate::ServerTxPool;
use mwc_api::client::HttpClient;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::{Output, TxKernel};
use mwc_core::libtx::coinbase_binding::{verify_coinbase_binding_digest, CoinbaseBindingContext};
use mwc_core::libtx::secp_ser;
use mwc_core::libtx::ProofBuilder;
use mwc_core::{consensus, core, global};
use mwc_crates::chrono::prelude::{DateTime, Utc};
use mwc_crates::log::{debug, error, trace, warn};
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::rand::{rng, RngExt};
use mwc_crates::secp::s2c::Opening;
use mwc_crates::secp::{Secp256k1, SecretKey};
use mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_crates::serde_json;
use mwc_crates::serde_json::json;
use mwc_keychain::{ExtKeychain, Identifier, Keychain};
use mwc_util::{StopState, ToHex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Internal block-template fee, height, and reward-key metadata.
/// The node adds the binding digest when constructing the wallet RPC request.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct BlockFees {
	/// fees
	#[serde(with = "secp_ser::string_or_u64")]
	pub fees: u64,
	/// height
	#[serde(with = "secp_ser::string_or_u64")]
	pub height: u64,
	/// key id
	pub key_id: Option<Identifier>,
}

impl BlockFees {
	/// return key id
	pub fn key_id(&self) -> Option<Identifier> {
		self.key_id.clone()
	}
}

pub struct BuiltBlock {
	pub block: core::Block,
	pub fees: BlockFees,
	pub parent_header: core::BlockHeader,
	pub parent_hash: Hash,
}

enum BuildBlockResult {
	Ready(BuiltBlock),
	ChainHeadChanged,
}

/// Response to build a coinbase output.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct CbData {
	/// Output
	pub output: Output,
	/// Kernel
	pub kernel: TxKernel,
	/// Key Id
	pub key_id: Option<Identifier>,
	/// Required for every mining RPC response, including before activation.
	pub coinbase_opening: Opening,
}

// Ensure a block suitable for mining is built and returned
// If a wallet listener URL is not provided the reward will be "burnt"
// Warning: This call does not return until/unless a new block can be built
pub fn get_block(
	secp: &mut Secp256k1,
	chain: &Arc<mwc_chain::Chain>,
	tx_pool: &ServerTxPool,
	key_id: Option<Identifier>,
	wallet_listener_url: Option<String>,
	client: &HttpClient,
	stop_state: &Arc<StopState>,
) -> Result<BuiltBlock, Error> {
	let wallet_retry_interval_sec = 1;
	// get the latest chain state and build a block on top of it
	let mut new_key_id = key_id.to_owned();
	loop {
		if stop_state.is_stopped() {
			return Err(Error::General("Interrupted".into()));
		}

		match build_block(
			secp,
			chain,
			tx_pool,
			new_key_id.clone(),
			wallet_listener_url.clone(),
			client,
		) {
			Ok(BuildBlockResult::Ready(built_block)) => return Ok(built_block),
			Ok(BuildBlockResult::ChainHeadChanged) => continue,
			Err(e) => {
				// Retry transient template, chain, and communication failures.
				// A wallet that cannot construct a valid bound reward requires
				// operator intervention, so report that error to the caller.
				// stop_state interrupts the retry loop.
				match e {
					self::Error::WalletBinding(_) => return Err(e),
					self::Error::Chain(c) => match c {
						mwc_chain::Error::DuplicateCommitment(_) => {
							debug!(
								"Duplicate commit for potential coinbase detected. Trying next derivation."
							);
							// use the next available key to generate a different coinbase commitment
							new_key_id = None;
						}
						_ => {
							error!("Chain Error: {}", c);
						}
					},
					self::Error::WalletComm(msg) => {
						error!(
							"Error building new block: Can't connect to wallet listener at {:?}; {}, will retry",
							wallet_listener_url.as_ref().unwrap_or(&"BROKEN_URL".to_string()), msg
						);
						thread::sleep(Duration::from_secs(wallet_retry_interval_sec));
					}
					ae => {
						warn!("Error building new block: {:?}. Retrying.", ae);
					}
				}

				// only wait if we are still using the same key: a different coinbase commitment is unlikely
				// to have duplication
				if new_key_id.is_some() {
					thread::sleep(Duration::from_millis(100));
				}
			}
		}
	}
}

/// Builds a new block with the chain head as previous and eligible
/// transactions from the pool.
fn build_block(
	secp: &mut Secp256k1,
	chain: &Arc<mwc_chain::Chain>,
	tx_pool: &ServerTxPool,
	key_id: Option<Identifier>,
	wallet_listener_url: Option<String>,
	client: &HttpClient,
) -> Result<BuildBlockResult, Error> {
	let context_id = chain.get_context_id();
	let head = chain.head_header()?;
	let head_hash = head.hash(context_id)?;

	// prepare the block header timestamp
	let mut now_sec = Utc::now().timestamp();
	let head_sec = head.timestamp.timestamp();
	if now_sec <= head_sec {
		now_sec = head_sec.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"mine_block::build_block, head_timestamp={}",
				head_sec
			))
		})?;
	}
	let height = head.height.checked_add(1).ok_or_else(|| {
		Error::DataOverflow(format!(
			"mine_block::build_block, head_height={}",
			head.height
		))
	})?;

	// Determine the difficulty our block should be at.
	// Note: do not keep the difficulty_iter in scope (it has an active batch).
	let mut cache_values = consensus::DifficultyCache::new();
	let difficulty = consensus::next_difficulty(
		context_id,
		height,
		chain.difficulty_iter_from(head_hash)?,
		&mut cache_values,
	)?;

	// Extract current "mineable" transactions from the pool.
	// If this fails for *any* reason then fallback to an empty vec of txs.
	// This will allow us to mine an "empty" block if the txpool is in an
	// invalid (and unexpected) state.
	let txs = match tx_pool.read_recursive().prepare_mineable_transactions(secp) {
		Ok(txs) => txs,
		Err(e) => {
			error!(
				"build_block: Failed to prepare mineable txs from txpool: {:?}",
				e
			);
			warn!("build_block: Falling back to mining empty block.");
			vec![]
		}
	};

	// build the coinbase and the block itself
	let fees = txs.iter().try_fold(0u64, |sum, tx| {
		let fee = tx.fee()?;
		sum.checked_add(fee).ok_or_else(|| {
			core::transaction::Error::DataOverflow(format!(
				"mine_block::build_block, sum={} fee={}",
				sum, fee
			))
		})
	})?;
	let block_fees = BlockFees {
		fees,
		key_id,
		height,
	};

	// The binding covers the final cut-through input set. A concatenation of
	// the pool transactions can include outputs spent by another selected tx.
	// Mining uses S2C at every height so node/wallet compatibility is checked
	// before consensus activation. Only block inclusion is height-dependent.
	let aggregate = core::transaction::aggregate(context_id, &txs, secp)?;
	let binding = chain.coinbase_binding_for_template(secp, &head, &aggregate.body)?;
	let (output, kernel, block_fees, opening) = get_coinbase(
		context_id,
		client,
		wallet_listener_url,
		block_fees,
		&binding,
		secp,
	)?;
	verify_bound_coinbase_response(context_id, secp, &output, &kernel, &opening, &binding)?;
	let mut b = core::Block::from_reward(
		context_id,
		&head,
		&txs,
		output,
		kernel,
		difficulty.difficulty,
		secp,
	)?;

	if consensus::is_coinbase_binding_enabled(context_id, height) {
		b.coinbase_opening = Some(opening);
	}

	// making sure we're not spending time mining a useless block
	b.validate(context_id, &head.total_kernel_offset, secp)?;

	b.header.pow.nonce = rng().random();
	b.header.pow.secondary_scaling = difficulty.secondary_scaling;
	let ts = DateTime::from_timestamp(now_sec, 0)
		.ok_or(Error::General("Utc::now into timestamp".into()))?;
	b.header.timestamp = ts.to_utc();

	debug!(
		"Built new block with {} inputs and {} outputs, block difficulty: {}, cumulative difficulty {}",
		b.inputs().len(),
		b.outputs().len(),
		difficulty.difficulty,
		b.header.total_difficulty().to_num(),
	);

	// Now set txhashset roots and sizes on the header of the block being built.
	match chain.set_txhashset_roots(secp, &mut b) {
		Ok(_) => {
			let current_head = chain.head_header()?;
			let current_head_hash = current_head.hash(context_id)?;
			if current_head_hash != head_hash {
				debug!(
					"Chain head changed while building block template from {} to {}; retrying.",
					head_hash, current_head_hash,
				);
				Ok(BuildBlockResult::ChainHeadChanged)
			} else {
				Ok(BuildBlockResult::Ready(BuiltBlock {
					block: b,
					fees: block_fees,
					parent_header: head,
					parent_hash: head_hash,
				}))
			}
		}
		Err(e) => {
			match e {
				// If this is a duplicate commitment then likely trying to use
				// a key that hass already been derived but not in the wallet
				// for some reason, allow caller to retry.
				mwc_chain::Error::DuplicateCommitment(e) => {
					Err(Error::Chain(mwc_chain::Error::DuplicateCommitment(e)))
				}

				// Some other issue, possibly duplicate kernel
				_ => {
					error!("Error setting txhashset root to build a block: {:?}", e);
					Err(Error::Chain(mwc_chain::Error::Other(format!(
						"Error setting txhashset root to build a block: {:?}",
						e
					))))
				}
			}
		}
	}
}

///
/// Probably only want to do this when testing.
///
fn burn_reward(
	context_id: u32,
	block_fees: BlockFees,
	binding: &CoinbaseBindingContext,
	secp: &mut Secp256k1,
) -> Result<(core::Output, core::TxKernel, BlockFees, Opening), Error> {
	warn!("Burning block fees: {:?}", block_fees);
	let secret_key = SecretKey::new(&secp, &mut SysRng)
		.map_err(|e| Error::General(format!("Unable to create reward secret key: {}", e)))?;
	let keychain = ExtKeychain::from_seed(&secp, &secret_key.0, global::is_floonet(context_id))?;
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0)?;
	let builder = ProofBuilder::new(secp, &keychain)?;
	let (out, kernel, opening) = mwc_core::libtx::reward::output_s2c(
		context_id,
		&keychain,
		&builder,
		&key_id,
		block_fees.fees,
		block_fees.height,
		secp,
		binding.digest()?,
	)?;
	Ok((out, kernel, block_fees, opening))
}

// Connect to the wallet listener and get coinbase.
// Warning: If a wallet listener URL is not provided the reward will be "burnt"
fn get_coinbase(
	context_id: u32,
	client: &HttpClient,
	wallet_listener_url: Option<String>,
	block_fees: BlockFees,
	binding: &CoinbaseBindingContext,
	secp: &mut Secp256k1,
) -> Result<(core::Output, core::TxKernel, BlockFees, Opening), Error> {
	match wallet_listener_url {
		None => {
			// Burn it
			return burn_reward(context_id, block_fees, binding, secp);
		}
		Some(wallet_listener_url) => {
			let res = create_coinbase(client, &wallet_listener_url, &block_fees, binding)?;
			let output = res.output;
			let kernel = res.kernel;
			let key_id = res.key_id;
			let block_fees = BlockFees {
				key_id: key_id,
				..block_fees
			};

			debug!("get_coinbase: {:?}", block_fees);
			return Ok((output, kernel, block_fees, res.coinbase_opening));
		}
	}
}

/// Call the wallet API to create a coinbase output for the given block_fees.
/// Communication failures may be retried. Rejected or malformed bound responses
/// require operator intervention and stop mining.
fn create_coinbase(
	client: &HttpClient,
	dest: &str,
	block_fees: &BlockFees,
	binding: &CoinbaseBindingContext,
) -> Result<CbData, Error> {
	let url = format!("{}/v2/foreign", dest);
	static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);
	let request_id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
	let req_body = coinbase_request(block_fees, binding, request_id)?;

	trace!("Sending build_coinbase request: {}", req_body);
	let res = client.post_request(&url, &req_body).map_err(|e| {
		let report = format!(
			"Failed to get coinbase from {}. Is the wallet listening? {}",
			dest, e
		);
		error!("{}", report);
		if matches!(e, mwc_api::Error::ResponseError(_)) {
			Error::WalletBinding(format!(
				"Invalid wallet response; upgrade or repair the mining wallet. {}",
				report
			))
		} else {
			Error::WalletComm(report)
		}
	})?;

	parse_coinbase_response(dest, request_id, res)
}

fn parse_coinbase_response(
	dest: &str,
	request_id: u64,
	res: serde_json::Value,
) -> Result<CbData, Error> {
	trace!("Response: {}", res);
	if res["id"].as_u64() != Some(request_id) {
		return Err(Error::WalletBinding(format!(
			"Invalid coinbase response ID from {}: expected {}, received {}",
			dest, request_id, res["id"]
		)));
	}
	if res["error"] != json!(null) {
		return Err(Error::WalletBinding(format!(
			"Coinbase binding not supported or rejected; upgrade the mining wallet. \
			Failed to get coinbase from {}: Error: {}, Message: {}",
			dest, res["error"]["code"], res["error"]["message"]
		)));
	}
	if res["result"]["Err"] != json!(null) {
		return Err(Error::WalletBinding(format!(
			"Bound coinbase request rejected: {}",
			res["result"]["Err"]
		)));
	}

	let cb_data = res["result"]["Ok"].clone();
	trace!("cb_data: {}", cb_data);
	serde_json::from_value::<CbData>(cb_data).map_err(|e| {
		Error::WalletBinding(format!(
			"Invalid bound coinbase response; upgrade or repair the mining wallet: {}",
			e
		))
	})
}

/// Check the complete returned reward before pool validation, so a broken
/// wallet kernel is reported as an operator error instead of retried forever.
fn verify_bound_coinbase_response(
	context_id: u32,
	secp: &mut Secp256k1,
	output: &Output,
	kernel: &TxKernel,
	opening: &Opening,
	binding: &CoinbaseBindingContext,
) -> Result<(), Error> {
	let invalid = |message: String| {
		Error::WalletBinding(format!(
			"Invalid bound coinbase; upgrade or repair the mining wallet: {}",
			message
		))
	};
	if !output.is_coinbase() {
		return Err(invalid("wallet returned a non-Coinbase output".into()));
	}
	mwc_core::libtx::proof::verify(secp, output.commitment(), output.proof, None)
		.map_err(|e| invalid(e.to_string()))?;
	verify_coinbase_binding_digest(context_id, secp, kernel, opening, binding.digest()?)
		.map_err(|e| invalid(e.to_string()))?;
	let over_commit = secp
		.commit_value(binding.reward)
		.map_err(|e| invalid(e.to_string()))?;
	let excess = secp
		.commit_sum(vec![output.commitment()], vec![over_commit])
		.map_err(|e| invalid(e.to_string()))?;
	if excess != kernel.excess {
		return Err(invalid(
			"coinbase output and kernel reward do not balance".into(),
		));
	}
	Ok(())
}

/// Always send the binding digest, and require the wallet response to include
/// an opening so an old wallet cannot silently return an unbound reward.
fn coinbase_request(
	fees: &BlockFees,
	binding: &CoinbaseBindingContext,
	request_id: u64,
) -> Result<serde_json::Value, Error> {
	let mut params = serde_json::to_value(fees)
		.map_err(|e| Error::General(format!("Coinbase request serialization: {}", e)))?;
	params["binding_digest"] = json!(binding.digest()?.to_hex());
	Ok(
		json!({"jsonrpc": "2.0", "method": "build_coinbase", "id": request_id,
		"params": {"block_fees": params}}),
	)
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::libtx::reward;
	use mwc_crates::secp::ContextFlag;

	fn binding_context() -> CoinbaseBindingContext {
		CoinbaseBindingContext {
			genesis_hash: Hash::from_vec(&[1; 32]),
			prev_hash: Hash::from_vec(&[2; 32]),
			height: 4,
			input_hash: Hash::from_vec(&[3; 32]),
			bitmap_hash: Hash::from_vec(&[4; 32]),
			output_leaf_count: 1,
			reward: consensus::reward(0, 0, 4).unwrap(),
		}
	}

	#[test]
	fn coinbase_request_requires_s2c_before_and_after_activation() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for height in [1, 3, 4] {
			let fees = BlockFees {
				fees: 0,
				height,
				key_id: None,
			};
			let mut context = binding_context();
			context.height = height;
			context.reward = consensus::reward(0, 0, height).unwrap();
			let request = coinbase_request(&fees, &context, 100 + height).unwrap();
			assert_eq!(request["id"], 100 + height);
			assert_eq!(request["method"], "build_coinbase");
			assert!(request["params"]["block_fees"]
				.get("binding_version")
				.is_none());
			assert_eq!(
				request["params"]["block_fees"]["binding_digest"],
				json!(context.digest().unwrap().to_hex())
			);
		}
	}

	#[test]
	fn bound_coinbase_rejections_stop_mining() {
		for response in [
			json!({"id": 1, "error": {"code": -32601, "message": "Method not found"}}),
			json!({"id": 1, "result": {"Err": "Coinbase binding not supported"}}),
			json!({"id": 1, "result": {"Ok": {"output": "malformed"}}}),
			json!({"id": 1}),
		] {
			assert!(matches!(
				parse_coinbase_response("wallet", 1, response),
				Err(Error::WalletBinding(_))
			));
		}
	}

	#[test]
	fn coinbase_response_requires_matching_request_id() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let data = test_cb_data(&mut secp);
		let response = json!({"jsonrpc": "2.0", "id": 42, "result": {"Ok": data}});
		parse_coinbase_response("wallet", 42, response.clone()).unwrap();
		for id in [json!(41), json!(43), json!(null), json!("42"), json!(42.0)] {
			let mut invalid = response.clone();
			invalid["id"] = id;
			assert!(matches!(
				parse_coinbase_response("wallet", 42, invalid),
				Err(Error::WalletBinding(_))
			));
		}
		let mut missing = response;
		missing.as_object_mut().unwrap().remove("id");
		assert!(matches!(
			parse_coinbase_response("wallet", 42, missing),
			Err(Error::WalletBinding(_))
		));
	}

	#[test]
	fn bound_coinbase_malformed_http_body_stops_mining() {
		use std::io::{BufRead, BufReader, Read, Write};
		use std::net::TcpListener;
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		let server = std::thread::spawn(move || {
			let mut request_ids = Vec::new();
			for _ in 0..2 {
				let (mut stream, _) = listener.accept().unwrap();
				stream
					.set_read_timeout(Some(Duration::from_secs(5)))
					.unwrap();
				let mut reader = BufReader::new(&mut stream);
				let mut content_length = 0;
				loop {
					let mut line = String::new();
					assert!(reader.read_line(&mut line).unwrap() > 0);
					if line == "\r\n" {
						break;
					}
					if let Some((name, value)) = line.split_once(':') {
						if name.eq_ignore_ascii_case("content-length") {
							content_length = value.trim().parse::<usize>().unwrap();
						}
					}
				}
				let mut body = vec![0; content_length];
				reader.read_exact(&mut body).unwrap();
				let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
				request_ids.push(request["id"].as_u64().unwrap());
				assert_eq!(request["method"], "build_coinbase");
				assert_eq!(
					request["params"]["block_fees"]["binding_digest"]
						.as_str()
						.unwrap()
						.len(),
					64
				);
				drop(reader);
				stream
				.write_all(
					b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nnot json",
				)
				.unwrap();
			}
			assert!(request_ids[1] > request_ids[0]);
		});
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let client = HttpClient::new(0, Duration::from_secs(5), None);
		for _ in 0..2 {
			let result = create_coinbase(
				&client,
				&format!("http://{}", address),
				&BlockFees {
					fees: 0,
					height: 4,
					key_id: None,
				},
				&binding_context(),
			);
			assert!(matches!(result, Err(Error::WalletBinding(_))));
		}
		server.join().unwrap();
	}

	#[test]
	fn preactivation_burn_rewards_already_use_s2c() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		for height in [1, 3] {
			let mut context = binding_context();
			context.height = height;
			context.reward = consensus::reward(0, 0, height).unwrap();
			let (output, kernel, _, opening) = burn_reward(
				0,
				BlockFees {
					fees: 0,
					height,
					key_id: None,
				},
				&context,
				&mut secp,
			)
			.unwrap();
			kernel.verify(0, &secp).unwrap();
			verify_bound_coinbase_response(0, &mut secp, &output, &kernel, &opening, &context)
				.unwrap();
		}
	}

	#[test]
	fn bound_burn_reward_matches_requested_binding() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let context = binding_context();
		let (output, kernel, _, opening) = burn_reward(
			0,
			BlockFees {
				fees: 0,
				height: 4,
				key_id: None,
			},
			&context,
			&mut secp,
		)
		.unwrap();
		verify_bound_coinbase_response(0, &mut secp, &output, &kernel, &opening, &context).unwrap();
		// A different, otherwise valid reward kernel must stop mining too.
		let other_kernel = test_cb_data(&mut secp).kernel;
		assert!(matches!(
			verify_bound_coinbase_response(
				0,
				&mut secp,
				&output,
				&other_kernel,
				&opening,
				&context
			),
			Err(Error::WalletBinding(_))
		));
		let mut wrong_feature = kernel.clone();
		wrong_feature.features = core::KernelFeatures::Plain {
			fee: core::FeeFields::zero(),
		};
		assert!(matches!(
			verify_bound_coinbase_response(
				0,
				&mut secp,
				&output,
				&wrong_feature,
				&opening,
				&context
			),
			Err(Error::WalletBinding(_))
		));
		verify_coinbase_binding_digest(0, &secp, &kernel, &opening, context.digest().unwrap())
			.unwrap();
		let mut other = context.clone();
		other.input_hash = Hash::from_vec(&[5; 32]);
		assert!(verify_coinbase_binding_digest(
			0,
			&secp,
			&kernel,
			&opening,
			other.digest().unwrap(),
		)
		.is_err());
	}

	fn test_cb_data(secp: &mut Secp256k1) -> CbData {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);

		let keychain = ExtKeychain::from_seed(secp, &[0; 32], false).unwrap();
		let builder = ProofBuilder::new(secp, &keychain).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let context = binding_context();
		let (output, kernel, opening) = reward::output_s2c(
			0,
			&keychain,
			&builder,
			&key_id,
			0,
			context.height,
			secp,
			context.digest().unwrap(),
		)
		.unwrap();

		CbData {
			output,
			kernel,
			key_id: Some(key_id),
			coinbase_opening: opening,
		}
	}

	#[test]
	fn bound_coinbase_response_requires_a_valid_opening() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		for height in [3, 4] {
			let mut context = binding_context();
			context.height = height;
			context.reward = consensus::reward(0, 0, height).unwrap();
			let (output, kernel, fees, opening) = burn_reward(
				0,
				BlockFees {
					fees: 0,
					height,
					key_id: None,
				},
				&context,
				&mut secp,
			)
			.unwrap();
			let data = CbData {
				output,
				kernel,
				key_id: fees.key_id,
				coinbase_opening: opening,
			};
			let encoded = serde_json::to_value(data).unwrap();
			let decoded = parse_coinbase_response(
				"wallet",
				1,
				json!({"id": 1, "result": {"Ok": encoded.clone()}}),
			)
			.unwrap();
			assert_eq!(decoded.coinbase_opening, opening);
			for invalid in [
				json!(null),
				json!("00".repeat(33)),
				json!("02"),
				json!("gg".repeat(33)),
			] {
				let mut bad = encoded.clone();
				bad["coinbase_opening"] = invalid;
				assert!(matches!(
					parse_coinbase_response("wallet", 1, json!({"id": 1, "result": {"Ok": bad}})),
					Err(Error::WalletBinding(_))
				));
			}
			let mut legacy = encoded;
			legacy.as_object_mut().unwrap().remove("coinbase_opening");
			assert!(matches!(
				parse_coinbase_response("wallet", 1, json!({"id": 1, "result": {"Ok": legacy}})),
				Err(Error::WalletBinding(message)) if message.contains("upgrade")
			));
		}
	}

	#[test]
	fn deserialize_cb_data_accepts_compact_wallet_signature() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let cb_data = test_cb_data(&mut secp);
		let compact_sig = cb_data.kernel.excess_sig.serialize_compact(&secp).unwrap();
		let cb_data_json = serde_json::to_value(&cb_data).unwrap();
		assert_eq!(
			cb_data_json["kernel"]["excess_sig"],
			json!(mwc_util::to_hex(&compact_sig))
		);

		let parsed: CbData = serde_json::from_value(cb_data_json).unwrap();

		parsed.kernel.verify(0, &secp).unwrap();
		assert_eq!(parsed.kernel.excess_sig, cb_data.kernel.excess_sig);
	}
}
