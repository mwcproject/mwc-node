//! Versioned Transactions.

use crate::core::committed::Committed;
use crate::core::hash::DefaultHashable;
use crate::core::transaction::{
	self, Error, Inputs, Output, Transaction, TransactionBody, TxBodyImpl, TxImpl, TxKernel,
	Weighting,
};
use crate::core::transaction_v4::{self, OutputWithRnp, TransactionBodyV4, TransactionV4};
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
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum VersionedTransactionBody {
	/// The version before HF2, which support interactive tx only.
	V3(TransactionBody),
	/// The version after HF2, which support both non-interactive tx and interactive tx
	V4(TransactionBodyV4),
}

impl From<Transaction> for VersionedTransactionBody {
	fn from(tx: Transaction) -> Self {
		VersionedTransactionBody::V3(tx.body)
	}
}

impl From<TransactionV4> for VersionedTransactionBody {
	fn from(tx: TransactionV4) -> Self {
		VersionedTransactionBody::V4(tx.body)
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
			VersionedTransactionBody::V3(body) => body.write(writer)?,
			VersionedTransactionBody::V4(body) => body.write(writer)?,
		}
		Ok(())
	}
}

impl VersionedTransactionBody {
	/// Is it the version after HF2?
	pub fn not_v3_version(&self) -> bool {
		match self {
			VersionedTransactionBody::V3(_body) => false,
			VersionedTransactionBody::V4(_body) => true,
		}
	}

	/// Because of conflict with enum_dispatch, we can not implement our own 'from'/'into'.
	pub fn to_v3(&self) -> Result<TransactionBody, Error> {
		match self {
			VersionedTransactionBody::V3(body) => Ok(body.clone()),
			VersionedTransactionBody::V4(body) => {
				TransactionBody::try_from(body.clone()).map_err(|e| Error::Generic(e.to_string()))
			}
		}
	}

	/// Because of conflict with enum_dispatch, we can not implement our own 'from'/'into'.
	pub fn to_v4(&self) -> TransactionBodyV4 {
		match self {
			VersionedTransactionBody::V3(body) => TransactionBodyV4::from(body.clone()),
			VersionedTransactionBody::V4(body) => body.clone(),
		}
	}

	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(self, output: Output) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V3(body) => {
				VersionedTransactionBody::V3(body.with_output(output))
			}
			VersionedTransactionBody::V4(body) => {
				VersionedTransactionBody::V4(body.with_output(output))
			}
		}
	}

	/// Builds a new transaction with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(self, kernel: TxKernel) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V3(body) => {
				VersionedTransactionBody::V3(body.with_kernel(kernel))
			}
			VersionedTransactionBody::V4(body) => {
				VersionedTransactionBody::V4(body.with_kernel(kernel))
			}
		}
	}

	/// Fully replace inputs (note: inputs w/o signature).
	pub fn replace_inputs(mut self, inputs: Inputs) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V3(body) => {
				self = VersionedTransactionBody::V3(body.replace_inputs(inputs))
			}
			VersionedTransactionBody::V4(body) => {
				self = VersionedTransactionBody::V4(body.replace_inputs(inputs))
			}
		};
		self
	}

	/// Fully replace outputs.
	pub fn replace_outputs(mut self, outputs: &[Output]) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V3(body) => {
				self = VersionedTransactionBody::V3(body.replace_outputs(outputs))
			}
			VersionedTransactionBody::V4(body) => {
				self = VersionedTransactionBody::V4(body.replace_outputs(outputs))
			}
		};
		self
	}

	/// Builds a new TransactionBodyV4 replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(mut self, kernel: TxKernel) -> VersionedTransactionBody {
		match self {
			VersionedTransactionBody::V3(body) => {
				self = VersionedTransactionBody::V3(body.replace_kernel(kernel))
			}
			VersionedTransactionBody::V4(body) => {
				self = VersionedTransactionBody::V4(body.replace_kernel(kernel))
			}
		};
		self
	}

	/// Get inner vector of inputs w/ sig
	pub fn inputs_with_sig(&self) -> Option<Inputs> {
		match self {
			VersionedTransactionBody::V3(_body) => None,
			VersionedTransactionBody::V4(body) => Some(body.inputs_with_sig()),
		}
	}

	/// Transaction outputs w/o R&P'.
	pub fn outputs(&self) -> &[Output] {
		match self {
			VersionedTransactionBody::V3(body) => body.outputs(),
			VersionedTransactionBody::V4(body) => body.outputs(),
		}
	}

	/// Transaction outputs w/ R&P'.
	pub fn outputs_with_rnp(&self) -> Option<&[OutputWithRnp]> {
		match self {
			VersionedTransactionBody::V3(_body) => None,
			VersionedTransactionBody::V4(body) => Some(body.outputs_with_rnp()),
		}
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification
	/// * kernel signature verification
	pub fn validate_read(&self, weighting: Weighting) -> Result<(), Error> {
		match self {
			VersionedTransactionBody::V3(body) => body.validate_read(weighting),
			VersionedTransactionBody::V4(body) => body.validate_read(weighting),
		}
	}
}

/// Enum of various flavors/versions of Transaction.
#[enum_dispatch(Committed, TxImpl)]
#[derive(Serialize, Debug, Clone, PartialEq)]
pub enum VersionedTransaction {
	/// The version before HF2, which support interactive tx only.
	V3(Transaction),
	/// The version after HF2, which support both non-interactive tx and interactive tx
	V4(TransactionV4),
}

/// Implementation of Writeable.
/// No version flag, so it's not readable.
impl Writeable for VersionedTransaction {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			VersionedTransaction::V3(tx) => tx.write(writer)?,
			VersionedTransaction::V4(tx) => tx.write(writer)?,
		}
		Ok(())
	}
}

impl DefaultHashable for VersionedTransaction {}

impl VersionedTransaction {
	/// Is it the version after HF2?
	pub fn not_v3_version(&self) -> bool {
		match self {
			VersionedTransaction::V3(_tx) => false,
			VersionedTransaction::V4(_tx) => true,
		}
	}

	/// Body
	pub fn body(&self) -> VersionedTransactionBody {
		match self {
			VersionedTransaction::V3(tx) => VersionedTransactionBody::V3(tx.body.clone()),
			VersionedTransaction::V4(tx) => VersionedTransactionBody::V4(tx.body.clone()),
		}
	}

	/// Offset
	pub fn offset(&self) -> &BlindingFactor {
		match self {
			VersionedTransaction::V3(tx) => &tx.offset,
			VersionedTransaction::V4(tx) => &tx.offset,
		}
	}

	/// Because of conflict with enum_dispatch, we can not implement our own 'from'/'into'.
	pub fn to_v3(&self) -> Result<Transaction, Error> {
		match self {
			VersionedTransaction::V3(tx) => Ok(tx.clone()),
			VersionedTransaction::V4(tx) => {
				Transaction::try_from(tx.clone()).map_err(|e| Error::Generic(e.to_string()))
			}
		}
	}

	/// Because of conflict with enum_dispatch, we can not implement our own 'from'/'into'.
	pub fn to_v4(&self) -> TransactionV4 {
		match self {
			VersionedTransaction::V3(tx) => TransactionV4::from(tx.clone()),
			VersionedTransaction::V4(tx) => tx.clone(),
		}
	}

	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(self, output: Output) -> VersionedTransaction {
		match self {
			VersionedTransaction::V3(tx) => VersionedTransaction::V3(tx.with_output(output)),
			VersionedTransaction::V4(tx) => VersionedTransaction::V4(tx.with_output(output)),
		}
	}

	/// Builds a new transaction with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(self, kernel: TxKernel) -> VersionedTransaction {
		match self {
			VersionedTransaction::V3(tx) => VersionedTransaction::V3(tx.with_kernel(kernel)),
			VersionedTransaction::V4(tx) => VersionedTransaction::V4(tx.with_kernel(kernel)),
		}
	}

	/// Fully replace inputs (note: inputs w/o signature).
	pub fn replace_inputs(mut self, inputs: Inputs) -> VersionedTransaction {
		match self {
			VersionedTransaction::V3(tx) => {
				self = VersionedTransaction::V3(tx.replace_inputs(inputs))
			}
			VersionedTransaction::V4(tx) => {
				self = VersionedTransaction::V4(tx.replace_inputs(inputs))
			}
		};
		self
	}

	/// Get inputs w/ signature
	pub fn inputs_with_sig(&self) -> Option<Inputs> {
		match self {
			VersionedTransaction::V3(_tx) => None,
			VersionedTransaction::V4(tx) => Some(tx.body.inputs_with_sig()),
		}
	}

	/// Get outputs w/ R&P'
	pub fn outputs_with_rnp(&self) -> Option<&[OutputWithRnp]> {
		match self {
			VersionedTransaction::V3(_tx) => None,
			VersionedTransaction::V4(tx) => Some(tx.body.outputs_with_rnp()),
		}
	}
}

/// Aggregate a vec of txs into a multi-kernel tx with cut_through.
pub fn aggregate(txs: &[VersionedTransaction]) -> Result<VersionedTransaction, Error> {
	let not_v3 = txs.iter().any(|tx| tx.not_v3_version());
	if !not_v3 {
		// Backward compatibility to support Pre-HF2
		let txs_v3 = txs
			.iter()
			.map(|tx| tx.to_v3().unwrap())
			.collect::<Vec<Transaction>>();
		Ok(transaction::aggregate(&txs_v3)?.into())
	} else {
		let txs_v4 = txs
			.iter()
			.map(|tx| tx.to_v4())
			.collect::<Vec<TransactionV4>>();
		Ok(transaction_v4::aggregate(&txs_v4)?.into())
	}
}

/// Attempt to deaggregate a multi-kernel transaction based on multiple transactions.
pub fn deaggregate(
	mk_tx: VersionedTransaction,
	txs: &[VersionedTransaction],
) -> Result<VersionedTransaction, Error> {
	if !txs.iter().any(|tx| tx.not_v3_version()) && !mk_tx.not_v3_version() {
		// Backward compatibility to support Pre-HF2
		let txs_v3 = txs
			.iter()
			.map(|tx| tx.to_v3().unwrap())
			.collect::<Vec<Transaction>>();
		Ok(transaction::deaggregate(mk_tx.to_v3()?, &txs_v3)?.into())
	} else {
		let txs_v4 = txs
			.iter()
			.map(|tx| tx.to_v4())
			.collect::<Vec<TransactionV4>>();
		Ok(transaction_v4::deaggregate(mk_tx.to_v4(), &txs_v4)?.into())
	}
}
