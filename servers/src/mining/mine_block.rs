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
use mwc_core::libtx::secp_ser;
use mwc_core::libtx::ProofBuilder;
use mwc_core::{consensus, core, global};
use mwc_crates::chrono::prelude::{DateTime, Utc};
use mwc_crates::log::{debug, error, trace, warn};
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::rand::{rng, RngExt};
use mwc_crates::secp::{Secp256k1, SecretKey};
use mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_crates::serde_json;
use mwc_crates::serde_json::json;
use mwc_keychain::{ExtKeychain, Identifier, Keychain};
use mwc_util::StopState;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Fees in block to use for coinbase amount calculation
/// (Duplicated from Mwc wallet project)
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
				// Best-effort miner strategy: build_block may return both transient
				// errors and deeper validation/storage errors. We intentionally log
				// and retry instead of returning these errors to the caller because
				// keeping the miner alive is preferable; stop_state is the supported
				// way to interrupt this loop.
				match e {
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

	let (output, kernel, block_fees) =
		get_coinbase(context_id, client, wallet_listener_url, block_fees, secp)?;
	let mut b = core::Block::from_reward(
		context_id,
		&head,
		&txs,
		output,
		kernel,
		difficulty.difficulty,
		secp,
	)?;

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
	secp: &mut Secp256k1,
) -> Result<(core::Output, core::TxKernel, BlockFees), Error> {
	warn!("Burning block fees: {:?}", block_fees);
	let secret_key = SecretKey::new(&secp, &mut SysRng)
		.map_err(|e| Error::General(format!("Unable to create reward secret key: {}", e)))?;
	let keychain = ExtKeychain::from_seed(&secp, &secret_key.0, global::is_floonet(context_id))?;
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0)?;
	let (out, kernel) = mwc_core::libtx::reward::output(
		context_id,
		&keychain,
		&ProofBuilder::new(secp, &keychain)?,
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
	secp: &mut Secp256k1,
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

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::libtx::reward;
	use mwc_crates::secp::ContextFlag;

	fn test_cb_data(secp: &mut Secp256k1) -> CbData {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);

		let keychain = ExtKeychain::from_seed(secp, &[0; 32], false).unwrap();
		let builder = ProofBuilder::new(secp, &keychain).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let (output, kernel) =
			reward::output(0, &keychain, &builder, &key_id, 0, false, 1, secp).unwrap();

		CbData {
			output,
			kernel,
			key_id: Some(key_id),
		}
	}

	#[test]
	fn deserialize_cb_data_accepts_legacy_compact_wallet_signature() {
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
