//! Versioned Transactions.

use crate::core::committed;
use crate::core::hash::{DefaultHashable, Hashed};
use crate::core::transaction::{
	self, Commit, CommitWrapper, Error, Input, Inputs, KernelFeatures, Output, OutputFeatures,
	OutputIdentifier, Transaction, TransactionBody, TxKernel, Weighting,
};
use crate::core::transaction_v2::{
	self, IdentifierWithRnp, OutputWithRnp, TransactionBodyV2, TransactionV2,
};
use crate::core::verifier_cache::VerifierCache;
use crate::libtx::{aggsig, secp_ser};
use crate::ser::{
	self, read_multi, PMMRable, ProtocolVersion, Readable, Reader, VerifySortedAndUnique,
	Writeable, Writer,
};
use crate::{consensus, global};
use enum_primitive::FromPrimitive;
use keychain::{self, BlindingFactor};
use std::cmp::Ordering;
use std::cmp::{max, min};
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use util;
use util::secp;
use util::secp::key::PublicKey;
use util::secp::pedersen::{Commitment, RangeProof};
use util::static_secp_instance;
use util::RwLock;
use util::ToHex;

/// Enum of various flavors/versions of TransactionBody.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum VersionedTransactionBody {
	/// The version before HF2, which support interactive tx only.
	V1 {
		/// Structure TransactionBody
		#[serde(flatten)]
		body: TransactionBody,
	},
	/// The version after HF2, which support both non-interactive tx and interactive tx
	V2 {
		/// Structure TransactionBodyV2
		#[serde(flatten)]
		body: TransactionBodyV2,
	},
}

impl From<Transaction> for VersionedTransactionBody {
	fn from(tx: Transaction) -> Self {
		VersionedTransactionBody::V1 { body: tx.body }
	}
}

impl From<TransactionV2> for VersionedTransactionBody {
	fn from(tx: TransactionV2) -> Self {
		VersionedTransactionBody::V2 { body: tx.body }
	}
}

impl committed::Committed for VersionedTransactionBody {
	fn inputs_committed(&self) -> Vec<Commitment> {
		match self {
			VersionedTransactionBody::V1 { body } => body.inputs_committed(),
			VersionedTransactionBody::V2 { body } => body.inputs_committed(),
		}
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		match self {
			VersionedTransactionBody::V1 { body } => body.outputs_committed(),
			VersionedTransactionBody::V2 { body } => body.outputs_committed(),
		}
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		match self {
			VersionedTransactionBody::V1 { body } => body.kernels_committed(),
			VersionedTransactionBody::V2 { body } => body.kernels_committed(),
		}
	}
}

impl VersionedTransactionBody {
	/// Transaction inputs.
	pub fn inputs(&self) -> Inputs {
		match self {
			VersionedTransactionBody::V1 { body } => body.inputs(),
			VersionedTransactionBody::V2 { body } => body.inputs(),
		}
	}

	/// Get inner vector of inputs w/ sig
	pub fn inputs_with_sig(&self) -> Option<Inputs> {
		match self {
			VersionedTransactionBody::V1 { body } => None,
			VersionedTransactionBody::V2 { body } => Some(body.inputs_with_sig()),
		}
	}

	/// Transaction outputs w/o R&P'.
	pub fn outputs(&self) -> &[Output] {
		match self {
			VersionedTransactionBody::V1 { body } => body.outputs(),
			VersionedTransactionBody::V2 { body } => body.outputs(),
		}
	}

	/// Transaction outputs w/ R&P'.
	pub fn outputs_with_rnp(&self) -> Option<&[OutputWithRnp]> {
		match self {
			VersionedTransactionBody::V1 { body } => None,
			VersionedTransactionBody::V2 { body } => Some(body.outputs_with_rnp()),
		}
	}

	/// Transaction kernels.
	pub fn kernels(&self) -> &[TxKernel] {
		match self {
			VersionedTransactionBody::V1 { body } => body.kernels(),
			VersionedTransactionBody::V2 { body } => body.kernels(),
		}
	}

	/// Total fee for a TransactionBody is the sum of fees of all fee carrying kernels.
	pub fn fee(&self) -> u64 {
		match self {
			VersionedTransactionBody::V1 { body } => body.fee(),
			VersionedTransactionBody::V2 { body } => body.fee(),
		}
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification
	/// * kernel signature verification
	pub fn validate_read(&self, weighting: Weighting) -> Result<(), Error> {
		match self {
			VersionedTransactionBody::V1 { body } => body.validate_read(weighting),
			VersionedTransactionBody::V2 { body } => body.validate_read(weighting),
		}
	}

	/// Validates all relevant parts of a transaction body. Checks the
	/// excess value against the signature as well as range proofs for each
	/// output.
	pub fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
	) -> Result<(), Error> {
		match self {
			VersionedTransactionBody::V1 { body } => body.validate(weighting, verifier),
			VersionedTransactionBody::V2 { body } => body.validate(weighting, verifier),
		}
	}
}

/// Enum of various flavors/versions of Transaction.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum VersionedTransaction {
	/// The version before HF2, which support interactive tx only.
	#[serde(flatten)]
	V1 {
		/// Structure Transaction
		tx: Transaction,
	},
	/// The version after HF2, which support both non-interactive tx and interactive tx
	#[serde(flatten)]
	V2 {
		/// Structure TransactionV2
		tx: TransactionV2,
	},
}

/// Implementation of Writeable.
/// No version flag, so it's not readable.
impl Writeable for VersionedTransaction {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			VersionedTransaction::V1 { tx } => tx.write(writer)?,
			VersionedTransaction::V2 { tx } => tx.write(writer)?,
		}
		Ok(())
	}
}

impl DefaultHashable for VersionedTransaction {}

impl From<Transaction> for VersionedTransaction {
	fn from(tx: Transaction) -> Self {
		VersionedTransaction::V1 { tx }
	}
}

impl From<TransactionV2> for VersionedTransaction {
	fn from(tx: TransactionV2) -> Self {
		VersionedTransaction::V2 { tx }
	}
}

impl TryFrom<VersionedTransaction> for Transaction {
	type Error = &'static str;
	fn try_from(tx_ex: VersionedTransaction) -> Result<Self, Self::Error> {
		match tx_ex {
			VersionedTransaction::V1 { tx } => Ok(tx),
			VersionedTransaction::V2 { tx } => Transaction::try_from(tx),
		}
	}
}

impl From<VersionedTransaction> for TransactionV2 {
	fn from(tx: VersionedTransaction) -> Self {
		match tx_ex {
			VersionedTransaction::V1 { tx } => TransactionV2::from(tx),
			VersionedTransaction::V2 { tx } => tx,
		}
	}
}

impl committed::Committed for VersionedTransaction {
	fn inputs_committed(&self) -> Vec<Commitment> {
		match self {
			VersionedTransaction::V1 { tx } => tx.body.inputs_committed(),
			VersionedTransaction::V2 { tx } => tx.body.inputs_committed(),
		}
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		match self {
			VersionedTransaction::V1 { tx } => tx.body.outputs_committed(),
			VersionedTransaction::V2 { tx } => tx.body.outputs_committed(),
		}
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		match self {
			VersionedTransaction::V1 { tx } => tx.body.kernels_committed(),
			VersionedTransaction::V2 { tx } => tx.body.kernels_committed(),
		}
	}
}

impl VersionedTransaction {
	/// Is it the version after HF2?
	pub fn not_v1_version(&self) -> bool {
		match self {
			VersionedTransaction::V1 { tx } => false,
			VersionedTransaction::V2 { tx } => true,
		}
	}

	/// Get inputs w/o signature
	pub fn inputs(&self) -> Inputs {
		match self {
			VersionedTransaction::V1 { tx } => tx.body.inputs(),
			VersionedTransaction::V2 { tx } => tx.body.inputs(),
		}
	}

	/// Get inputs w/ signature
	pub fn inputs_with_sig(&self) -> Option<Inputs> {
		match self {
			VersionedTransaction::V1 { tx } => None,
			VersionedTransaction::V2 { tx } => Some(tx.body.inputs_with_sig()),
		}
	}

	/// Get outputs w/o R&P'
	pub fn outputs(&self) -> &[Output] {
		match self {
			VersionedTransaction::V1 { tx } => tx.body.outputs(),
			VersionedTransaction::V2 { tx } => tx.body.outputs(),
		}
	}

	/// Get outputs w/ R&P'
	pub fn outputs_with_rnp(&self) -> Option<&[OutputWithRnp]> {
		match self {
			VersionedTransaction::V1 { tx } => None,
			VersionedTransaction::V2 { tx } => Some(tx.body.outputs_with_rnp()),
		}
	}

	/// Get kernels
	pub fn kernels(&self) -> &[TxKernel] {
		match self {
			VersionedTransaction::V1 { tx } => tx.kernels(),
			VersionedTransaction::V2 { tx } => tx.kernels(),
		}
	}

	/// Can be used to compare txs by their fee/weight ratio.
	/// Don't use these values for anything else though due to precision multiplier.
	pub fn fee_to_weight(&self) -> u64 {
		match self {
			VersionedTransaction::V1 { tx } => tx.fee_to_weight(),
			VersionedTransaction::V2 { tx } => tx.fee_to_weight(),
		}
	}

	/// Validates all relevant parts of a fully built transaction. Checks the
	/// excess value against the signature as well as range proofs for each
	/// output.
	pub fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
	) -> Result<(), Error> {
		match self {
			VersionedTransaction::V1 { tx } => tx.validate(weighting, verifier_cache),
			VersionedTransaction::V2 { tx } => tx.validate(weighting, verifier_cache),
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
