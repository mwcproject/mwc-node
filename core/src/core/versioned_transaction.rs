//! Versioned Transactions.

use crate::core::committed::Committed;
use crate::core::hash::DefaultHashable;
use crate::core::transaction::{
	self, Error, Inputs, Output, Transaction, TransactionBody, TxBodyImpl, TxImpl, TxKernel,
	Weighting,
};
use crate::core::transaction_v2::{self, OutputWithRnp, TransactionBodyV2, TransactionV2};
use crate::core::verifier_cache::VerifierCache;
use crate::ser::{self, Writeable, Writer};
use enum_dispatch::enum_dispatch;
use keychain::{self, BlindingFactor};
use std::convert::TryFrom;
use std::sync::Arc;
use util;
use util::secp::pedersen::Commitment;
use util::RwLock;

/// Enum of various flavors/versions of TransactionBody.
#[enum_dispatch(Committed, TxBodyImpl)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VersionedTransactionBody {
	/// The version before HF2, which support interactive tx only.
	V1(TransactionBody),
	/// The version after HF2, which support both non-interactive tx and interactive tx
	V2(TransactionBodyV2),
}

impl From<Transaction> for VersionedTransactionBody {
	fn from(tx: Transaction) -> Self {
		VersionedTransactionBody::V1(tx.body)
	}
}

impl From<TransactionV2> for VersionedTransactionBody {
	fn from(tx: TransactionV2) -> Self {
		VersionedTransactionBody::V2(tx.body)
	}
}

impl VersionedTransactionBody {
	/// Get inner vector of inputs w/ sig
	pub fn inputs_with_sig(&self) -> Option<Inputs> {
		match self {
			VersionedTransactionBody::V1(body) => None,
			VersionedTransactionBody::V2(body) => Some(body.inputs_with_sig()),
		}
	}

	/// Transaction outputs w/ R&P'.
	pub fn outputs_with_rnp(&self) -> Option<&[OutputWithRnp]> {
		match self {
			VersionedTransactionBody::V1(body) => None,
			VersionedTransactionBody::V2(body) => Some(body.outputs_with_rnp()),
		}
	}
}

/// Enum of various flavors/versions of Transaction.
#[enum_dispatch(Committed, TxImpl)]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum VersionedTransaction {
	/// The version before HF2, which support interactive tx only.
	V1(Transaction),
	/// The version after HF2, which support both non-interactive tx and interactive tx
	V2(TransactionV2),
}

/// Implementation of Writeable.
/// No version flag, so it's not readable.
impl Writeable for VersionedTransaction {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			VersionedTransaction::V1(tx) => tx.write(writer)?,
			VersionedTransaction::V2(tx) => tx.write(writer)?,
		}
		Ok(())
	}
}

impl DefaultHashable for VersionedTransaction {}

// impl TryFrom<VersionedTransaction> for Transaction {
// 	type Error = &'static str;
// 	fn try_from(tx_ex: VersionedTransaction) -> Result<Self, Self::Error> {
// 		match tx_ex {
// 			VersionedTransaction::V1(tx) => Ok(tx),
// 			VersionedTransaction::V2(tx) => Transaction::try_from(tx),
// 		}
// 	}
// }
//
// impl From<VersionedTransaction> for TransactionV2 {
// 	fn from(tx_ex: VersionedTransaction) -> Self {
// 		match tx_ex {
// 			VersionedTransaction::V1(tx) => TransactionV2::from(tx),
// 			VersionedTransaction::V2(tx) => tx,
// 		}
// 	}
// }

impl VersionedTransaction {
	/// Is it the version after HF2?
	pub fn not_v1_version(&self) -> bool {
		match self {
			VersionedTransaction::V1(tx) => false,
			VersionedTransaction::V2(tx) => true,
		}
	}

	/// Fully replace inputs (note: inputs w/o signature).
	pub fn replace_inputs(mut self, inputs: Inputs) -> VersionedTransaction {
		match self {
			VersionedTransaction::V1(tx) => tx.body.replace_inputs(inputs),
			VersionedTransaction::V2(tx) => tx.body.replace_inputs(inputs),
		}
		self.clone()
	}

	/// Get inputs w/ signature
	pub fn inputs_with_sig(&self) -> Option<Inputs> {
		match self {
			VersionedTransaction::V1(tx) => None,
			VersionedTransaction::V2(tx) => Some(tx.body.inputs_with_sig()),
		}
	}

	/// Get outputs w/ R&P'
	pub fn outputs_with_rnp(&self) -> Option<&[OutputWithRnp]> {
		match self {
			VersionedTransaction::V1(tx) => None,
			VersionedTransaction::V2(tx) => Some(tx.body.outputs_with_rnp()),
		}
	}
}

/// Aggregate a vec of txs into a multi-kernel tx with cut_through.
pub fn aggregate(txs: &[VersionedTransaction]) -> Result<VersionedTransaction, Error> {
	let not_v1 = txs.iter().any(|tx| tx.not_v1_version());
	if !not_v1 {
		// Backward compatibility to support Pre-HF2
		let txs_v1 = txs
			.iter()
			.map(|tx| Transaction::try_from(tx.clone())?)
			.collect::<Vec<Transaction>>();
		Ok(VersionedTransaction::from(transaction::aggregate(&txs_v1)?))
	} else {
		let txs_v2 = txs
			.iter()
			.map(|tx| TransactionV2::from(tx.clone()))
			.collect::<Vec<TransactionV2>>();
		Ok(VersionedTransaction::from(transaction_v2::aggregate(
			&txs_v2,
		)?))
	}
}

/// Attempt to deaggregate a multi-kernel transaction based on multiple transactions.
pub fn deaggregate(
	mk_tx: VersionedTransaction,
	txs: &[VersionedTransaction],
) -> Result<VersionedTransaction, Error> {
	if !txs.iter().any(|tx| tx.not_v1_version()) && !mk_tx.not_v1_version() {
		// Backward compatibility to support Pre-HF2
		let txs_v1 = txs
			.iter()
			.map(|tx| Transaction::try_from(tx.clone())?)
			.collect::<Vec<Transaction>>();
		Ok(VersionedTransaction::from(transaction::deaggregate(
			Transaction::try_from(mk_tx)?,
			&txs_v1,
		)?))
	} else {
		let txs_v2 = txs
			.iter()
			.map(|tx| TransactionV2::from(tx.clone()))
			.collect::<Vec<TransactionV2>>();
		Ok(VersionedTransaction::from(transaction_v2::deaggregate(
			TransactionV2::from(mk_tx),
			&txs_v2,
		)?))
	}
}
