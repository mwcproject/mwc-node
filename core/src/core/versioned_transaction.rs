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

impl From<VersionedTransaction> for VersionedTransactionBody {
	fn from(tx: VersionedTransaction) -> Self {
		tx.body()
	}
}

/// Implementation of Writeable, defines how to write the transaction body as binary.
impl Writeable for VersionedTransactionBody {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			VersionedTransactionBody::V1(body) => body.write(writer)?,
			VersionedTransactionBody::V2(body) => body.write(writer)?,
		}
		Ok(())
	}
}

impl VersionedTransactionBody {
	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(self, output: Output) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V1(tx) => {
				VersionedTransactionBody::V1(tx.with_output(output))
			}
			VersionedTransactionBody::V2(tx) => {
				VersionedTransactionBody::V2(tx.with_output(output))
			}
		}
	}

	/// Builds a new transaction with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(self, kernel: TxKernel) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V1(tx) => {
				VersionedTransactionBody::V1(tx.with_kernel(kernel))
			}
			VersionedTransactionBody::V2(tx) => {
				VersionedTransactionBody::V2(tx.with_kernel(kernel))
			}
		}
	}

	/// Fully replace inputs (note: inputs w/o signature).
	pub fn replace_inputs(mut self, inputs: Inputs) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V1(body) => {
				self = VersionedTransactionBody::V1(body.replace_inputs(inputs))
			}
			VersionedTransactionBody::V2(body) => {
				self = VersionedTransactionBody::V2(body.replace_inputs(inputs))
			}
		};
		self
	}

	/// Fully replace outputs.
	pub fn replace_outputs(mut self, outputs: &[Output]) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V1(body) => {
				self = VersionedTransactionBody::V1(body.replace_outputs(outputs))
			}
			VersionedTransactionBody::V2(body) => {
				self = VersionedTransactionBody::V2(body.replace_outputs(outputs))
			}
		};
		self
	}

	/// Builds a new TransactionBodyV2 replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(mut self, kernel: TxKernel) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V1(body) => {
				self = VersionedTransactionBody::V1(body.replace_kernel(kernel))
			}
			VersionedTransactionBody::V2(body) => {
				self = VersionedTransactionBody::V2(body.replace_kernel(kernel))
			}
		};
		self
	}

	/// Get inner vector of inputs w/ sig
	pub fn inputs_with_sig(&self) -> Option<Inputs> {
		match self {
			VersionedTransactionBody::V1(_body) => None,
			VersionedTransactionBody::V2(body) => Some(body.inputs_with_sig()),
		}
	}

	/// Transaction outputs w/o R&P'.
	pub fn outputs(&self) -> &[Output] {
		match self {
			VersionedTransactionBody::V1(body) => body.outputs(),
			VersionedTransactionBody::V2(body) => body.outputs(),
		}
	}

	/// Transaction outputs w/ R&P'.
	pub fn outputs_with_rnp(&self) -> Option<&[OutputWithRnp]> {
		match self {
			VersionedTransactionBody::V1(_body) => None,
			VersionedTransactionBody::V2(body) => Some(body.outputs_with_rnp()),
		}
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification
	/// * kernel signature verification
	pub fn validate_read(&self, weighting: Weighting) -> Result<(), Error> {
		match self {
			VersionedTransactionBody::V1(body) => body.validate_read(weighting),
			VersionedTransactionBody::V2(body) => body.validate_read(weighting),
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

impl VersionedTransaction {
	/// Is it the version after HF2?
	pub fn not_v1_version(&self) -> bool {
		match self {
			VersionedTransaction::V1(_tx) => false,
			VersionedTransaction::V2(_tx) => true,
		}
	}

	/// Body
	pub fn body(&self) -> VersionedTransactionBody {
		match self {
			VersionedTransaction::V1(tx) => VersionedTransactionBody::V1(tx.body.clone()),
			VersionedTransaction::V2(tx) => VersionedTransactionBody::V2(tx.body.clone()),
		}
	}

	/// Offset
	pub fn offset(&self) -> &BlindingFactor {
		match self {
			VersionedTransaction::V1(tx) => &tx.offset,
			VersionedTransaction::V2(tx) => &tx.offset,
		}
	}

	/// Because of conflict with enum_dispatch, we can not implement our own 'from'/'into'.
	pub fn to_v1(&self) -> Result<Transaction, Error> {
		match self {
			VersionedTransaction::V1(tx) => Ok(tx.clone()),
			VersionedTransaction::V2(tx) => {
				Transaction::try_from(tx.clone()).map_err(|e| Error::Generic(e.to_string()))
			}
		}
	}

	/// Because of conflict with enum_dispatch, we can not implement our own 'from'/'into'.
	pub fn to_v2(&self) -> TransactionV2 {
		match self {
			VersionedTransaction::V1(tx) => TransactionV2::from(tx.clone()),
			VersionedTransaction::V2(tx) => tx.clone(),
		}
	}

	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(self, output: Output) -> VersionedTransaction {
		match self {
			VersionedTransaction::V1(tx) => VersionedTransaction::V1(tx.with_output(output)),
			VersionedTransaction::V2(tx) => VersionedTransaction::V2(tx.with_output(output)),
		}
	}

	/// Builds a new transaction with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(self, kernel: TxKernel) -> VersionedTransaction {
		match self {
			VersionedTransaction::V1(tx) => VersionedTransaction::V1(tx.with_kernel(kernel)),
			VersionedTransaction::V2(tx) => VersionedTransaction::V2(tx.with_kernel(kernel)),
		}
	}

	/// Fully replace inputs (note: inputs w/o signature).
	pub fn replace_inputs(mut self, inputs: Inputs) -> VersionedTransaction {
		match self {
			VersionedTransaction::V1(tx) => {
				self = VersionedTransaction::V1(tx.replace_inputs(inputs))
			}
			VersionedTransaction::V2(tx) => {
				self = VersionedTransaction::V2(tx.replace_inputs(inputs))
			}
		};
		self
	}

	/// Get inputs w/ signature
	pub fn inputs_with_sig(&self) -> Option<Inputs> {
		match self {
			VersionedTransaction::V1(_tx) => None,
			VersionedTransaction::V2(tx) => Some(tx.body.inputs_with_sig()),
		}
	}

	/// Get outputs w/ R&P'
	pub fn outputs_with_rnp(&self) -> Option<&[OutputWithRnp]> {
		match self {
			VersionedTransaction::V1(_tx) => None,
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
			.map(|tx| tx.to_v1().unwrap())
			.collect::<Vec<Transaction>>();
		Ok(transaction::aggregate(&txs_v1)?.into())
	} else {
		let txs_v2 = txs
			.iter()
			.map(|tx| tx.to_v2())
			.collect::<Vec<TransactionV2>>();
		Ok(transaction_v2::aggregate(&txs_v2)?.into())
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
			.map(|tx| tx.to_v1().unwrap())
			.collect::<Vec<Transaction>>();
		Ok(transaction::deaggregate(mk_tx.to_v1()?, &txs_v1)?.into())
	} else {
		let txs_v2 = txs
			.iter()
			.map(|tx| tx.to_v2())
			.collect::<Vec<TransactionV2>>();
		Ok(transaction_v2::deaggregate(mk_tx.to_v2(), &txs_v2)?.into())
	}
}
