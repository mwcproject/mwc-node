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

use super::utils::w;
use crate::rest::*;
use crate::router::{Handler, ResponseFuture};
use crate::types::*;
use crate::web::*;
use mwc_core::core::hash::Hashed;
use mwc_core::core::Transaction;
use mwc_core::ser::{self, ProtocolVersion};
use mwc_crates::bytes::Bytes;
use mwc_crates::hyper::{Request, StatusCode};
use mwc_crates::log::{error, info};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_pool::{self, BlockChain, PoolAdapter};
use std::sync::Weak;

pub const MAX_UNCONFIRMED_TRANSACTIONS: usize = 1_000;

/// Get basic information about the transaction pool.
/// GET /v1/pool
pub struct PoolInfoHandler<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	pub tx_pool: Weak<RwLock<mwc_pool::TransactionPool<B, P>>>,
}

impl<B, P> Handler for PoolInfoHandler<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	fn get(&self, _req: Request<Bytes>) -> ResponseFuture {
		let pool_arc = w_fut!(&self.tx_pool);
		let pool = pool_arc.read_recursive();

		json_response(&PoolInfo {
			pool_size: pool.total_size(),
		})
	}
}

pub struct PoolHandler<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	pub tx_pool: Weak<RwLock<mwc_pool::TransactionPool<B, P>>>,
}

impl<B, P> PoolHandler<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	pub fn get_pool_size(&self) -> Result<usize, Error> {
		let pool_arc = w(&self.tx_pool)?;
		let pool = pool_arc.read_recursive();
		Ok(pool.total_size())
	}
	pub fn get_unconfirmed_transactions(&self) -> Result<Vec<Transaction>, Error> {
		// Return a bounded snapshot of the txpool.
		let pool_arc = w(&self.tx_pool)?;
		let txpool = pool_arc.read_recursive();
		Ok(txpool
			.txpool
			.ordered_entry_refs()
			.take(MAX_UNCONFIRMED_TRANSACTIONS)
			.map(|entry| entry.tx.clone())
			.collect())
	}
	pub fn push_transaction(
		&self,
		tx: Transaction,
		fluff: Option<bool>,
		secp: &mut Secp256k1,
	) -> Result<(), Error> {
		let pool_arc = w(&self.tx_pool)?;
		let context_id = pool_arc.read_recursive().get_context_id();
		let source = mwc_pool::TxSource::PushApi;
		let tx_hash = tx.hash(context_id)?;
		info!(
			"Pushing transaction {} to pool (inputs: {}, outputs: {}, kernels: {}, fluff: {:?})",
			tx_hash,
			tx.inputs().len(),
			tx.outputs().len(),
			tx.kernels().len(),
			fluff,
		);

		//  Push to tx pool.
		let mut tx_pool = pool_arc.write();
		let header = tx_pool
			.blockchain
			.chain_head()
			.map_err(|e| Error::Internal(format!("Failed to get chain head, {}", e)))?;
		tx_pool
			.add_to_pool(source, tx, !fluff.unwrap_or(false), &header, secp)
			.map_err(pool_error_to_api_error)?;

		info!("transaction {} was added to the pool", tx_hash);

		Ok(())
	}
}
/// Dummy wrapper for the hex-encoded serialized transaction.
#[derive(Serialize, Deserialize)]
#[serde(crate = "serde")]
struct TxWrapper {
	tx_hex: String,
}

fn pool_error_to_api_error(e: mwc_pool::PoolError) -> Error {
	use mwc_pool::PoolError::*;

	match e {
		InvalidTx(_)
		| ImmatureTransaction
		| ImmatureCoinbase
		| OverCapacity
		| LowFeeTransaction(_)
		| DuplicateCommitment
		| DuplicateKernelOrDuplicateSpent(_)
		| DuplicateTx
		| NRDKernelPreHF3
		| NRDKernelNotEnabled
		| NRDKernelRelativeHeight => Error::RequestError(format!("Transaction rejected: {}", e)),
		internal_error @ (InvalidBlock(_) | Keychain(_) | Committed(_) | Serialization(_)
		| IO(_) | DandelionError | Other(_)) => {
			error!("Failed to update pool: {}", internal_error);
			Error::Internal("Failed to update pool".to_string())
		}
	}
}

/// Push new transaction to our local transaction pool.
///
/// Network relay is best-effort after local acceptance. Adapter failures are
/// logged by the pool and are not returned from this endpoint.
/// POST /v1/pool/push_tx
pub struct PoolPushHandler<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	pub tx_pool: Weak<RwLock<mwc_pool::TransactionPool<B, P>>>,
}

fn parse_fluff_param(params: &QueryParams) -> Result<bool, Error> {
	match params.get("fluff")?.map(|v| v.as_str()) {
		None => Ok(false),
		Some("") | Some("true") | Some("1") => Ok(true),
		Some("false") | Some("0") => Ok(false),
		Some(_) => Err(Error::RequestError(
			"invalid value of parameter fluff".to_string(),
		)),
	}
}

async fn update_pool<B, P>(
	pool: Weak<RwLock<mwc_pool::TransactionPool<B, P>>>,
	req: Request<Bytes>,
) -> Result<(), Error>
where
	B: BlockChain,
	P: PoolAdapter,
{
	let pool = w(&pool)?;
	let params = QueryParams::from_query(req.uri().query())?;
	let fluff = parse_fluff_param(&params)?;

	let wrapper: TxWrapper = parse_body(req).await?;
	let tx_hex_len = wrapper.tx_hex.len();
	let tx_bin = mwc_util::from_hex(&wrapper.tx_hex).map_err(|e| {
		Error::RequestError(format!(
			"Unable to decode transaction hex of length {}, {}",
			tx_hex_len, e
		))
	})?;

	// All wallet api interaction explicitly uses protocol version 1 for now.
	let version = ProtocolVersion(1);
	let context_id = pool.read_recursive().get_context_id();
	let tx_bin_len = tx_bin.len();
	let tx: Transaction =
		ser::deserialize_strict(&mut &tx_bin[..], version, context_id).map_err(|e| {
			Error::RequestError(format!(
				"Unable to deserialize transaction binary of length {}, {}",
				tx_bin_len, e
			))
		})?;

	let source = mwc_pool::TxSource::PushApi;
	info!(
		"Pushing transaction {} to pool (inputs: {}, outputs: {}, kernels: {})",
		tx.hash(context_id)?,
		tx.inputs().len(),
		tx.outputs().len(),
		tx.kernels().len(),
	);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit)?;

	//  Push to tx pool.
	let mut tx_pool = pool.write();
	let header = tx_pool
		.blockchain
		.chain_head()
		.map_err(|e| Error::Internal(format!("Failed to get chain head: {}", e)))?;
	tx_pool
		.add_to_pool(source, tx, !fluff, &header, &mut secp)
		.map_err(pool_error_to_api_error)?;
	Ok(())
}

impl<B, P> Handler for PoolPushHandler<B, P>
where
	B: BlockChain + 'static,
	P: PoolAdapter + 'static,
{
	fn post(&self, req: Request<Bytes>) -> ResponseFuture {
		let pool = self.tx_pool.clone();
		Box::pin(async move {
			let res = match update_pool(pool, req).await {
				Ok(_) => just_response(StatusCode::OK, ""),
				Err(e) => return result_to_response(Err::<(), Error>(e)).await,
			};
			Ok(res)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse_fluff(query: Option<&str>) -> Result<bool, Error> {
		let params = QueryParams::from_query(query)?;
		parse_fluff_param(&params)
	}

	#[test]
	fn push_tx_fluff_defaults_to_stem_phase() {
		assert!(!parse_fluff(None).unwrap());
	}

	#[test]
	fn push_tx_fluff_accepts_presence_flag() {
		assert!(parse_fluff(Some("fluff")).unwrap());
		assert!(parse_fluff(Some("fluff=")).unwrap());
	}

	#[test]
	fn push_tx_fluff_accepts_boolean_values() {
		assert!(parse_fluff(Some("fluff=true")).unwrap());
		assert!(parse_fluff(Some("fluff=1")).unwrap());
		assert!(!parse_fluff(Some("fluff=false")).unwrap());
		assert!(!parse_fluff(Some("fluff=0")).unwrap());
	}

	#[test]
	fn push_tx_fluff_rejects_invalid_values() {
		let err = parse_fluff(Some("fluff=garbage")).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("invalid value of parameter fluff"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn push_tx_fluff_rejects_duplicate_values() {
		let err = parse_fluff(Some("fluff=true&fluff=false")).unwrap_err();

		match err {
			Error::RequestError(msg) => {
				assert!(msg.contains("duplicate query parameter fluff"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn pool_internal_errors_return_generic_api_message() {
		let err = pool_error_to_api_error(mwc_pool::PoolError::Other(
			"backend detail should stay server-side".into(),
		));

		match err {
			Error::Internal(msg) => {
				assert_eq!(msg, "Failed to update pool");
				assert!(!msg.contains("backend detail"));
			}
			other => panic!("expected internal error, got {:?}", other),
		}
	}
}
