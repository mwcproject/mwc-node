// Copyright 2026 The MWC Developers
// Licensed under the Apache License, Version 2.0.

//! A deliberately non-publishable description of a transaction. Neither this
//! request nor its nested types can carry signatures, nonces or rangeproofs.

use crate::core::hash::{Hash, Hashed};
use crate::core::{
	CommitWrapper, Committed, Inputs, KernelFeatures, Output, OutputFeatures, OutputIdentifier,
	Transaction, TxKernel,
};
use crate::libtx::secp_ser;
use keychain::BlindingFactor;
use mwc_crates::secp::{
	pedersen::{Commitment, RangeProof},
	Secp256k1,
};
use mwc_crates::serde::{self, Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use util::ToHex;

/// Input commitment and, when carried by the slate, its asserted feature.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct PreflightInput {
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	/// Pedersen commitment; never a rangeproof.
	pub commitment: Commitment,
	/// Consensus feature metadata.
	pub features: Option<OutputFeatures>,
}

/// Output metadata. Its proof is deliberately absent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct PreflightOutput {
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	/// Pedersen commitment; never a rangeproof.
	pub commitment: Commitment,
	/// Consensus feature metadata.
	pub features: OutputFeatures,
}

/// Kernel metadata. A partial request can omit an unfinished excess.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct PreflightKernel {
	/// Consensus feature metadata.
	pub features: KernelFeatures,
	#[serde(default, with = "secp_ser::option_commitment_serde")]
	/// Aggregate public excess commitment, when known.
	pub excess: Option<Commitment>,
	/// Optional opaque identifier for exact public-pool duplicate detection.
	/// Hashing a completed kernel does not disclose its signature.
	pub kernel_hash: Option<Hash>,
}

/// One unsigned transaction. Partial success never implies balance.
/// Only complete, successful parents provide outputs to later transactions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct PreflightTransaction {
	/// Whether all transaction components are present and balance must be checked.
	pub is_complete: bool,
	/// Available input commitments and optional asserted features.
	pub inputs: Vec<PreflightInput>,
	/// Available output commitments and features.
	pub outputs: Vec<PreflightOutput>,
	/// Available unsigned kernel metadata.
	pub kernels: Vec<PreflightKernel>,
	/// Aggregate transaction offset, hex encoded; no participant secrets.
	pub offset: Option<String>,
	/// Permit a future absolute kernel lock height. All other checks use current
	/// chain state; success does not predict future input availability.
	#[serde(default)]
	pub allow_future_height: bool,
}

/// Ordered unsigned transactions checked against one chain/public-pool snapshot.
/// Parents must precede children. No signatures or proofs are representable.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct MempoolAcceptRequest {
	/// One or more transactions, each with its own validation scope.
	pub transactions: Vec<PreflightTransaction>,
	/// Optional current body-chain tip or ancestor. Validation uses current state.
	pub expected_tip: Option<Hash>,
}

impl MempoolAcceptRequest {
	/// Check one transaction without a chain anchor.
	pub fn single(transaction: PreflightTransaction) -> Self {
		Self {
			transactions: vec![transaction],
			expected_tip: None,
		}
	}

	/// Bound the whole request before collecting pool state or validating curves.
	pub fn validate_size(&self) -> Result<(), String> {
		if self.transactions.is_empty() || self.transactions.len() > 100 {
			return Err("Preflight must contain 1..=100 transactions".into());
		}
		let count = self.transactions.iter().fold(0usize, |count, tx| {
			count
				.saturating_add(tx.inputs.len())
				.saturating_add(tx.outputs.len())
				.saturating_add(tx.kernels.len())
		});
		if count == 0 || count > 10_000 {
			return Err("Preflight must contain 1..=10000 components in total".into());
		}
		Ok(())
	}
}

/// Results in request order. This never attests signatures or rangeproofs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct MempoolAcceptResponse {
	/// True only if every transaction passed its requested checks.
	pub checks_passed: bool,
	/// Body-chain tip used for every transaction in this response.
	pub checked_tip: Hash,
	/// Height of that body-chain tip.
	pub checked_height: u64,
	/// One result per requested transaction, preserving request order.
	pub transactions: Vec<PreflightTransactionResult>,
}

impl MempoolAcceptResponse {
	/// Start the results for one immutable snapshot.
	pub fn new(request: &MempoolAcceptRequest, tip: Hash, height: u64) -> Self {
		Self {
			checks_passed: true,
			checked_tip: tip,
			checked_height: height,
			transactions: request
				.transactions
				.iter()
				.map(PreflightTransactionResult::new)
				.collect(),
		}
	}

	/// Reject the entire request, for example when its chain anchor was removed.
	pub fn reject(&mut self, check: &str, reason: String) {
		self.checks_passed = false;
		for result in &mut self.transactions {
			result.reject(check, reason.clone());
		}
	}

	/// Set the overall verdict after checking each transaction.
	pub fn finish(mut self) -> Self {
		self.checks_passed = self.transactions.iter().all(|result| result.checks_passed);
		self
	}
}

/// Trusted state collected from the locked public pool, never from RPC input.
#[derive(Default)]
pub struct PreflightPoolState {
	/// The same complete unsigned transaction is already public.
	pub already_known: bool,
	/// Outputs of already validated public-pool transactions.
	pub available_inputs: Vec<OutputIdentifier>,
	/// Conflicts with other public-pool transactions.
	pub conflicts: Vec<String>,
}

/// Temporary dependency view. Nothing is written to the chain or pool.
#[derive(Default)]
pub struct PreflightDependencies {
	outputs: BTreeMap<Commitment, (OutputIdentifier, u64)>,
	spent: BTreeSet<Commitment>,
	created: BTreeSet<Commitment>,
	kernel_hashes: BTreeSet<Hash>,
	nrd_excesses: BTreeSet<Commitment>,
}

impl PreflightDependencies {
	/// Check conflicts within the request and resolve successful complete parents.
	pub fn check(
		&mut self,
		request: &PreflightTransaction,
		result: &mut PreflightTransactionResult,
	) -> Vec<OutputIdentifier> {
		let mut available = Vec::new();
		for input in &request.inputs {
			if !self.spent.insert(input.commitment) {
				result.reject(
					"inputs",
					"Input is spent by another requested transaction".into(),
				);
			}
			if let Some((output, height)) = self.outputs.get(&input.commitment) {
				available.push(*output);
				result.valid_from_height = result.valid_from_height.max(*height);
			}
		}
		for output in &request.outputs {
			if !self.created.insert(output.commitment) || self.spent.contains(&output.commitment) {
				result.reject("outputs", "Output is reused within the request".into());
			}
		}
		for kernel in &request.kernels {
			if kernel
				.kernel_hash
				.is_some_and(|hash| !self.kernel_hashes.insert(hash))
			{
				result.reject("kernels", "Kernel is repeated within the request".into());
			}
			if matches!(kernel.features, KernelFeatures::NoRecentDuplicate { .. }) {
				if kernel
					.excess
					.is_some_and(|excess| !self.nrd_excesses.insert(excess))
				{
					result.reject(
						"kernels",
						"NRD excess is repeated within the request".into(),
					);
				}
			}
		}
		available
	}

	/// Only a complete parent whose checks all passed can fund a child.
	pub fn remember(
		&mut self,
		request: &PreflightTransaction,
		result: &PreflightTransactionResult,
	) {
		if request.is_complete && result.checks_passed && result.balance_checked {
			for output in &request.outputs {
				self.outputs.insert(
					output.commitment,
					(
						OutputIdentifier::new(output.features, &output.commitment),
						result.valid_from_height,
					),
				);
			}
		}
	}
}

/// A failed check, separate from other checks which may still have passed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct PreflightFailure {
	/// Stable category of the failed check.
	pub check: String,
	/// Human-readable failure details.
	pub reason: String,
}

/// Snapshot result. This never attests signatures or rangeproofs.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde", deny_unknown_fields)]
pub struct PreflightTransactionResult {
	/// Whether all transaction components are present and balance must be checked.
	pub is_complete: bool,
	/// True only when the failures list is empty; not proof/signature validation.
	pub checks_passed: bool,
	/// True only when the complete balance equation was evaluated.
	pub balance_checked: bool,
	/// Earliest height required by this transaction and its supplied ancestors.
	/// Does not predict future input availability.
	pub valid_from_height: u64,
	/// The same complete unsigned description is already in the public pool.
	pub already_known: bool,
	/// Independent failed checks; partial success is not transaction acceptance.
	pub failures: Vec<PreflightFailure>,
}

impl PreflightTransactionResult {
	/// Start a result for one immutable chain snapshot.
	pub fn new(request: &PreflightTransaction) -> Self {
		Self {
			is_complete: request.is_complete,
			checks_passed: true,
			balance_checked: false,
			valid_from_height: 0,
			already_known: false,
			failures: vec![],
		}
	}

	/// Record an independent validation failure without skipping other checks.
	pub fn record<E: std::fmt::Display>(&mut self, check: &str, result: Result<(), E>) {
		if let Err(error) = result {
			self.reject(check, error.to_string());
		}
	}

	/// Add a failure and clear the success flag.
	pub fn reject(&mut self, check: &str, reason: String) {
		self.checks_passed = false;
		self.failures.push(PreflightFailure {
			check: check.to_owned(),
			reason,
		});
	}
}

impl PreflightTransaction {
	/// Copy only the explicitly permitted fields. Never serialize a slate or a
	/// Transaction and then redact its JSON.
	pub fn from_transaction(
		context_id: u32,
		tx: &Transaction,
		is_complete: bool,
	) -> Result<Self, crate::core::transaction::Error> {
		let inputs = match &tx.body.inputs {
			Inputs::FeaturesAndCommit(inputs) => inputs
				.iter()
				.map(|i| PreflightInput {
					commitment: i.commitment(),
					features: Some(i.features),
				})
				.collect(),
			Inputs::CommitOnly(inputs) => inputs
				.iter()
				.map(|i| PreflightInput {
					commitment: i.commitment(),
					features: None,
				})
				.collect(),
		};
		let kernels = tx
			.kernels()
			.iter()
			.map(|k| {
				let excess = if k.excess.as_ref().iter().all(|b| *b == 0) {
					None
				} else {
					Some(k.excess)
				};
				let kernel_hash = if k.excess_sig.as_ref().iter().all(|b| *b == 0) {
					None
				} else {
					Some(k.hash(context_id)?)
				};
				Ok(PreflightKernel {
					features: k.features,
					excess,
					kernel_hash,
				})
			})
			.collect::<Result<Vec<_>, crate::core::transaction::Error>>()?;
		Ok(Self {
			is_complete,
			inputs,
			outputs: tx
				.outputs()
				.iter()
				.map(|o| PreflightOutput {
					commitment: o.commitment(),
					features: o.features(),
				})
				.collect(),
			kernels,
			offset: Some(tx.offset.to_hex()),
			allow_future_height: false,
		})
	}

	/// Materialize an unsigned, proofless object only to reuse core/state
	/// validation. It must never be passed to transaction submission.
	pub fn validation_transaction(
		&self,
		context_id: u32,
		secp: &Secp256k1,
	) -> Result<Transaction, String> {
		let count = self
			.inputs
			.len()
			.saturating_add(self.outputs.len())
			.saturating_add(self.kernels.len());
		if count == 0 || count > 10_000 {
			return Err("Preflight must contain 1..=10000 components".into());
		}
		if self.is_complete
			&& (self.inputs.is_empty()
				|| self.outputs.is_empty()
				|| self.kernels.is_empty()
				|| self.offset.is_none()
				|| self.kernels.iter().any(|k| k.excess.is_none()))
		{
			return Err(
				"Complete preflight requires inputs, outputs, kernel excesses and offset".into(),
			);
		}
		let mut inputs = BTreeSet::new();
		for input in &self.inputs {
			secp.validate_commitment(&input.commitment)
				.map_err(|e| e.to_string())?;
			if !inputs.insert(input.commitment) {
				return Err("Duplicate input commitment".into());
			}
		}
		let mut outputs = BTreeSet::new();
		for output in &self.outputs {
			secp.validate_commitment(&output.commitment)
				.map_err(|e| e.to_string())?;
			if !outputs.insert(output.commitment) {
				return Err("Duplicate output commitment".into());
			}
			if inputs.contains(&output.commitment) {
				return Err("Input/output overlap".into());
			}
		}
		let kernels = self
			.kernels
			.iter()
			.map(|k| {
				k.features
					.kernel_sig_msg(context_id)
					.map_err(|e| e.to_string())?;
				let mut kernel = TxKernel::with_features(k.features).map_err(|e| e.to_string())?;
				if let Some(excess) = k.excess {
					excess.to_pubkey(secp).map_err(|e| e.to_string())?;
					kernel.excess = excess;
				} else if matches!(k.features, KernelFeatures::NoRecentDuplicate { .. }) {
					return Err("NRD preflight requires the kernel excess".into());
				}
				Ok(kernel)
			})
			.collect::<Result<Vec<_>, String>>()?;
		let outputs = self
			.outputs
			.iter()
			.map(|o| Output::new(o.features, o.commitment, RangeProof::zero()))
			.collect::<Vec<_>>();
		let offset = match &self.offset {
			Some(hex) => BlindingFactor::from_hex(hex).map_err(|e| e.to_string())?,
			None => BlindingFactor::zero(),
		};
		if offset != BlindingFactor::zero() {
			offset.secret_key(secp).map_err(|e| e.to_string())?;
		}
		let tx = Transaction::new(
			context_id,
			Inputs::CommitOnly(
				self.inputs
					.iter()
					.map(|i| CommitWrapper::from(i.commitment))
					.collect(),
			),
			&outputs,
			&kernels,
		)
		.map_err(|e| e.to_string())?
		.with_offset(offset);
		tx.validate_read(context_id).map_err(|e| e.to_string())?;
		Ok(tx)
	}

	/// Balance is independent of UTXO existence and height eligibility, allowing
	/// callers to inspect a complete future refund without declaring it spendable.
	pub fn check_balance(
		&self,
		tx: &Transaction,
		secp: &Secp256k1,
		result: &mut PreflightTransactionResult,
	) {
		if self.is_complete {
			result.balance_checked = true;
			result.record(
				"balance",
				tx.overage().map_err(|e| e.to_string()).and_then(|fee| {
					tx.verify_kernel_sums(fee, tx.offset.clone(), secp)
						.map(|_| ())
						.map_err(|e| e.to_string())
				}),
			);
		}
	}

	/// Equality of the public transaction description, ignoring an optional
	/// signature hash and the caller's validation scope.
	pub fn same_transaction(&self, other: &Self) -> bool {
		self.inputs.len() == other.inputs.len()
			&& self
				.inputs
				.iter()
				.zip(&other.inputs)
				.all(|(a, b)| a.commitment == b.commitment)
			&& self.outputs == other.outputs
			&& self.offset == other.offset
			&& self.kernels.len() == other.kernels.len()
			&& self
				.kernels
				.iter()
				.zip(&other.kernels)
				.all(|(a, b)| a.features == b.features && a.excess == b.excess)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::global::{self, ChainTypes};
	use mwc_crates::{
		secp::{ContextFlag, SecretKey},
		serde_json,
	};

	fn balanced_request(secp: &Secp256k1) -> PreflightTransaction {
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let key = |n| {
			let mut bytes = [0; 32];
			bytes[31] = n;
			SecretKey::from_slice(secp, &bytes).unwrap()
		};
		PreflightTransaction {
			is_complete: true,
			inputs: vec![PreflightInput {
				commitment: secp.commit(100, key(1)).unwrap(),
				features: None,
			}],
			outputs: vec![PreflightOutput {
				commitment: secp.commit(90, key(3)).unwrap(),
				features: OutputFeatures::Plain,
			}],
			kernels: vec![PreflightKernel {
				features: KernelFeatures::Plain {
					fee: crate::core::FeeFields::new(10).unwrap(),
				},
				excess: Some(secp.commit(0, key(1)).unwrap()),
				kernel_hash: None,
			}],
			offset: Some(BlindingFactor::from_secret_key(key(1)).to_hex()),
			allow_future_height: false,
		}
	}

	#[test]
	fn preflight_balance_requires_complete_scope_and_correct_offset() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut request = balanced_request(&secp);
		let tx = request.validation_transaction(0, &secp).unwrap();
		let mut result = PreflightTransactionResult::new(&request);
		request.check_balance(&tx, &secp, &mut result);
		assert!(result.balance_checked && result.checks_passed);
		request.offset = Some(BlindingFactor::zero().to_hex());
		let tx = request.validation_transaction(0, &secp).unwrap();
		let mut result = PreflightTransactionResult::new(&request);
		request.check_balance(&tx, &secp, &mut result);
		assert!(result.balance_checked && !result.checks_passed);
		assert_eq!(result.failures[0].check, "balance");
		request.is_complete = false;
		request.inputs.clear();
		request.kernels.clear();
		request.offset = None;
		let tx = request.validation_transaction(0, &secp).unwrap();
		let mut result = PreflightTransactionResult::new(&request);
		request.check_balance(&tx, &secp, &mut result);
		assert!(!result.balance_checked && result.checks_passed);
	}

	#[test]
	fn preflight_wire_format_cannot_carry_signatures_or_proofs() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let request = balanced_request(&secp);
		let tx = request.validation_transaction(0, &secp).unwrap();
		let copied = PreflightTransaction::from_transaction(0, &tx, true).unwrap();
		let value = serde_json::to_value(MempoolAcceptRequest {
			transactions: vec![copied.clone(), copied],
			expected_tip: None,
		})
		.unwrap();
		for index in 0..2 {
			let transaction = &value["transactions"][index];
			assert_eq!(transaction["outputs"][0].as_object().unwrap().len(), 2);
			assert_eq!(transaction["kernels"][0].as_object().unwrap().len(), 3);
			for (section, field) in [
				("outputs", "proof"),
				("kernels", "excess_sig"),
				("inputs", "signature"),
			] {
				let mut bad = value.clone();
				bad["transactions"][index][section][0][field] = serde_json::json!("forbidden");
				assert!(serde_json::from_value::<MempoolAcceptRequest>(bad).is_err());
			}
			let mut missing_scope = value.clone();
			missing_scope["transactions"][index]
				.as_object_mut()
				.unwrap()
				.remove("is_complete");
			assert!(serde_json::from_value::<MempoolAcceptRequest>(missing_scope).is_err());
		}
		let mut unknown = value.clone();
		unknown["parent_outputs"] = serde_json::json!([]);
		assert!(serde_json::from_value::<MempoolAcceptRequest>(unknown).is_err());
		let mut default_height = value;
		default_height["transactions"][0]
			.as_object_mut()
			.unwrap()
			.remove("allow_future_height");
		let decoded: MempoolAcceptRequest = serde_json::from_value(default_height).unwrap();
		assert!(!decoded.transactions[0].allow_future_height);
	}

	#[test]
	fn preflight_rejects_duplicate_commitments_coinbase_outputs_and_missing_excess() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let request = balanced_request(&secp);
		let mut duplicate = request.clone();
		duplicate.inputs.push(duplicate.inputs[0].clone());
		assert!(duplicate.validation_transaction(0, &secp).is_err());
		let mut coinbase = request.clone();
		coinbase.outputs[0].features = OutputFeatures::Coinbase;
		assert!(coinbase.validation_transaction(0, &secp).is_err());
		let mut missing = request;
		missing.kernels[0].excess = None;
		assert!(missing.validation_transaction(0, &secp).is_err());
		missing.is_complete = false;
		assert!(missing.validation_transaction(0, &secp).is_ok());
	}
}
