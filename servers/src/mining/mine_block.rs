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

use crate::chain;
use crate::common::types::Error;
use crate::core::core::{Output, TxKernel};
use crate::core::libtx::secp_ser;
use crate::core::libtx::ProofBuilder;
use crate::core::{consensus, core, global};
use crate::keychain::{ExtKeychain, Identifier, Keychain};
use crate::ServerTxPool;
use chrono::prelude::{DateTime, Utc};
use mwc_api::client::HttpClient;
use mwc_util::secp::Secp256k1;
use rand::{thread_rng, Rng};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Fees in block to use for coinbase amount calculation
/// (Duplicated from Mwc wallet project)
#[derive(Serialize, Deserialize, Debug, Clone)]
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

/// Response to build a coinbase output.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CbData {
	/// Output
	pub output: Output,
	/// Kernel
	pub kernel: TxKernel,
	/// Key Id
	pub key_id: Option<Identifier>,
}

// Ensure a block suitable for mining is built and returned
// If a wallet listener URL is not provided the reward will be "burnt"
// Warning: This call does not return until/unless a new block can be built
pub fn get_block(
	chain: &Arc<chain::Chain>,
	tx_pool: &ServerTxPool,
	key_id: Option<Identifier>,
	wallet_listener_url: Option<String>,
	client: &HttpClient,
) -> (core::Block, BlockFees) {
	let wallet_retry_interval = 5;
	// get the latest chain state and build a block on top of it
	loop {
		match build_block(
			chain,
			tx_pool,
			key_id.clone(),
			wallet_listener_url.clone(),
			client,
		) {
			Ok((block, fees)) => {
				return (block, fees);
			}
			Err(e) => {
				// On error report the problem and keep trying forever
				let mut new_key_id = key_id.to_owned();
				match e {
					self::Error::Chain(c) => match c {
						chain::Error::DuplicateCommitment(_) => {
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
						thread::sleep(Duration::from_secs(wallet_retry_interval));
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
	chain: &Arc<chain::Chain>,
	tx_pool: &ServerTxPool,
	key_id: Option<Identifier>,
	wallet_listener_url: Option<String>,
	client: &HttpClient,
) -> Result<(core::Block, BlockFees), Error> {
	let head = chain.head_header()?;

	// prepare the block header timestamp
	let mut now_sec = Utc::now().timestamp();
	let head_sec = head.timestamp.timestamp();
	if now_sec <= head_sec {
		now_sec = head_sec + 1;
	}

	// Determine the difficulty our block should be at.
	// Note: do not keep the difficulty_iter in scope (it has an active batch).
	let mut cache_values = VecDeque::new();
	let difficulty = consensus::next_difficulty(
		chain.get_context_id(),
		head.height + 1,
		chain.difficulty_iter()?,
		&mut cache_values,
	);

	// Extract current "mineable" transactions from the pool.
	// If this fails for *any* reason then fallback to an empty vec of txs.
	// This will allow us to mine an "empty" block if the txpool is in an
	// invalid (and unexpected) state.
	let txs = match tx_pool
		.read()
		.unwrap_or_else(|e| e.into_inner())
		.prepare_mineable_transactions(chain.secp())
	{
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
	let fees = txs.iter().map(|tx| tx.fee()).sum();
	let height = head.height + 1;
	let block_fees = BlockFees {
		fees,
		key_id,
		height,
	};

	let (output, kernel, block_fees) = get_coinbase(
		chain.get_context_id(),
		client,
		wallet_listener_url,
		block_fees,
		chain.secp(),
	)?;
	let mut b = core::Block::from_reward(
		chain.get_context_id(),
		&head,
		&txs,
		output,
		kernel,
		difficulty.difficulty,
		chain.secp(),
	)?;

	// making sure we're not spending time mining a useless block
	b.validate(
		chain.get_context_id(),
		&head.total_kernel_offset,
		chain.secp(),
	)?;

	b.header.pow.nonce = thread_rng().gen();
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
	match chain.set_txhashset_roots(&mut b) {
		Ok(_) => Ok((b, block_fees)),
		Err(e) => {
			match e {
				// If this is a duplicate commitment then likely trying to use
				// a key that hass already been derived but not in the wallet
				// for some reason, allow caller to retry.
				chain::Error::DuplicateCommitment(e) => {
					Err(Error::Chain(chain::Error::DuplicateCommitment(e)))
				}

				// Some other issue, possibly duplicate kernel
				_ => {
					error!("Error setting txhashset root to build a block: {:?}", e);
					Err(Error::Chain(chain::Error::Other(format!(
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
	secp: &Secp256k1,
) -> Result<(core::Output, core::TxKernel, BlockFees), Error> {
	warn!("Burning block fees: {:?}", block_fees);
	let keychain = ExtKeychain::from_random_seed(global::is_floonet(context_id))?;
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0)?;
	let (out, kernel) = crate::core::libtx::reward::output(
		context_id,
		&keychain,
		&ProofBuilder::new(&keychain)?,
		&key_id,
		block_fees.fees,
		false,
		block_fees.height,
		secp,
	)?;
	Ok((out, kernel, block_fees))
}

// Connect to the wallet listener and get coinbase.
// Warning: If a wallet listener URL is not provided the reward will be "burnt"
fn get_coinbase(
	context_id: u32,
	client: &HttpClient,
	wallet_listener_url: Option<String>,
	block_fees: BlockFees,
	secp: &Secp256k1,
) -> Result<(core::Output, core::TxKernel, BlockFees), Error> {
	match wallet_listener_url {
		None => {
			// Burn it
			return burn_reward(context_id, block_fees, secp);
		}
		Some(wallet_listener_url) => {
			let res = create_coinbase(client, &wallet_listener_url, &block_fees)?;
			let output = res.output;
			let kernel = res.kernel;
			let key_id = res.key_id;
			let block_fees = BlockFees {
				key_id: key_id,
				..block_fees
			};

			debug!("get_coinbase: {:?}", block_fees);
			return Ok((output, kernel, block_fees));
		}
	}
}

/// Call the wallet API to create a coinbase output for the given block_fees.
/// Will retry based on default "retry forever with backoff" behavior.
fn create_coinbase(
	client: &HttpClient,
	dest: &str,
	block_fees: &BlockFees,
) -> Result<CbData, Error> {
	let url = format!("{}/v2/foreign", dest);
	let req_body = json!({
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"id": 1,
		"params": {
			"block_fees": block_fees
		}
	});

	trace!("Sending build_coinbase request: {}", req_body);
	let res = client.post_request(&url, &req_body).map_err(|e| {
		let report = format!(
			"Failed to get coinbase from {}. Is the wallet listening? {}",
			dest, e
		);
		error!("{}", report);
		Error::WalletComm(report)
	})?;

	trace!("Response: {}", res);
	if res["error"] != json!(null) {
		let report = format!(
			"Failed to get coinbase from {}: Error: {}, Message: {}",
			dest, res["error"]["code"], res["error"]["message"]
		);
		error!("{}", report);
		return Err(Error::WalletComm(report));
	}

	let cb_data = res["result"]["Ok"].clone();
	trace!("cb_data: {}", cb_data);
	let ret_val = match serde_json::from_value::<CbData>(cb_data) {
		Ok(r) => r,
		Err(e) => {
			let report = format!("Couldn't deserialize CbData: {}", e);
			error!("{}", report);
			return Err(Error::WalletComm(report));
		}
	};

	Ok(ret_val)
}
