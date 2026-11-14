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
use mwc_core::core::hash::Hash;
use mwc_core::core::Transaction;
use mwc_crates::log::{error, info};
use mwc_crates::parking_lot::RecursiveRwLock;
use mwc_crates::secp::Secp256k1;
use mwc_pool::{self, BlockChain, PoolAdapter};
use std::sync::Weak;

pub const MAX_UNCONFIRMED_TRANSACTIONS: usize = 1_000;

pub struct PoolHandler<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	pub tx_pool: Weak<RecursiveRwLock<mwc_pool::TransactionPool<B, P>>>,
}

impl<B, P> PoolHandler<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	pub fn get_pool_size(&self) -> Result<usize, Error> {
		let pool_arc = w(&self.tx_pool)?;
		let pool = pool_arc.read();
		Ok(pool.total_size())
	}
	pub fn get_unconfirmed_transactions(&self) -> Result<Vec<Transaction>, Error> {
		// Return a bounded snapshot of the txpool.
		let pool_arc = w(&self.tx_pool)?;
		let txpool = pool_arc.read();
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
		tx_hash: Hash,
		fluff: Option<bool>,
		secp: &mut Secp256k1,
	) -> Result<(), Error> {
		let pool_arc = w(&self.tx_pool)?;
		let source = mwc_pool::TxSource::PushApi;
		info!(
			"Pushing transaction {} to pool (inputs: {}, outputs: {}, kernels: {}, fluff: {:?})",
			tx_hash,
			tx.inputs().len(),
			tx.outputs().len(),
			tx.kernels().len(),
			fluff,
		);

		let blockchain = {
			let tx_pool = pool_arc.read();
			tx_pool.blockchain.clone()
		};
		let header = blockchain
			.chain_head()
			.map_err(|e| Error::Internal(format!("Failed to get chain head, {}", e)))?;
		mwc_pool::TransactionPool::submit_to_pool(
			pool_arc.as_ref(),
			source,
			tx,
			!fluff.unwrap_or(false),
			&header,
			secp,
		)
		.map_err(pool_error_to_api_error)?;

		info!("transaction {} was added to the pool", tx_hash);

		Ok(())
	}
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
		| TransactionAlreadyConfirmed
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn mined_transaction_returns_confirmed_request_error() {
		let err = pool_error_to_api_error(mwc_pool::PoolError::TransactionAlreadyConfirmed);
		match err {
			Error::RequestError(message) => {
				assert_eq!(
					message,
					"Transaction rejected: Transaction already confirmed on the current chain"
				);
			}
			other => panic!("expected confirmed transaction rejection, got {:?}", other),
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
