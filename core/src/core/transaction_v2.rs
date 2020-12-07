// Copyright 2020 The Grin Developers
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

//! Transactions V2. To support NIT(Non-Interactive Transaction) feature.

use crate::core::committed::{self, Committed};
use crate::core::hash::{DefaultHashable, Hashed};
use crate::core::transaction::{
	Commit, CommitWrapper, Error, Input, Inputs, KernelFeatures, Output, OutputFeatures,
	OutputIdentifier, Transaction, TransactionBody, TxBodyImpl, TxImpl, TxKernel, Weighting,
};
use crate::core::verifier_cache::VerifierCache;
use crate::libtx::{aggsig, secp_ser};
use crate::ser::{
	self, read_multi, PMMRable, Readable, Reader, VerifySortedAndUnique, Writeable, Writer,
};
use crate::{consensus, global};
use keychain::{self, BlindingFactor};
use std::cmp::Ordering;
use std::cmp::{max, min};
use std::convert::{TryFrom, TryInto};
use std::sync::Arc;
use util;
use util::secp::key::PublicKey;
use util::secp::pedersen::{Commitment, RangeProof};
use util::secp::{self, Secp256k1};
use util::static_secp_instance;
use util::RwLock;

/// TransactionBodyV2 is a common abstraction for transaction and block.
/// Not a perfect and clean structure design here, 2 inputs vectors and 2 outputs vectors in one structure,
/// but it is for implementing a mixing of NIT and IT schemes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransactionBodyV2 {
	/// List of inputs (w/o signature) spent by the transaction.
	pub inputs: Inputs,
	/// List of inputs (w/ signature) spent by the transaction.
	pub inputs_with_sig: Inputs,
	/// List of outputs w/o R&P' that the transaction produces.
	pub outputs: Vec<Output>,
	/// List of outputs w/ R&P' that the transaction produces.
	pub outputs_with_rnp: Vec<OutputWithRnp>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernel>,
}

// V1 to V2 conversion
impl From<TransactionBody> for TransactionBodyV2 {
	fn from(body: TransactionBody) -> Self {
		TransactionBodyV2 {
			inputs: body.inputs(),
			inputs_with_sig: Inputs::CommitsWithSig(vec![]),
			outputs: body.outputs().to_vec(),
			outputs_with_rnp: vec![],
			kernels: body.kernels().to_vec(),
		}
	}
}

// V2 to V1 conversion
impl TryFrom<TransactionBodyV2> for TransactionBody {
	type Error = &'static str;
	fn try_from(body: TransactionBodyV2) -> Result<Self, Self::Error> {
		if body.is_v1_compatible() {
			Ok(TransactionBody {
				inputs: body.inputs(),
				outputs: body.outputs().to_vec(),
				kernels: body.kernels().to_vec(),
			})
		} else {
			Err("some v2 transaction body contents can not convert to v1")
		}
	}
}

/// Implementation of Writeable for a body, defines how to
/// write the body as binary.
impl Writeable for TransactionBodyV2 {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.inputs.len() > ser::READ_VEC_SIZE_LIMIT as usize
			|| self.inputs_with_sig.len() > ser::READ_VEC_SIZE_LIMIT as usize
			|| self.outputs.len() > ser::READ_VEC_SIZE_LIMIT as usize
			|| self.outputs_with_rnp.len() > ser::READ_VEC_SIZE_LIMIT as usize
			|| self.kernels.len() > ser::READ_VEC_SIZE_LIMIT as usize
		{
			return Err(ser::Error::TooLargeWriteErr(format!(
                "Transaction has impossibly many items: inputs {}, inputs_with_sig {}, outputs {}, outputs_with_rnp {}, kerners {}",
                self.inputs.len(),
                self.inputs_with_sig.len(),
                self.outputs.len(),
                self.outputs_with_rnp.len(),
                self.kernels.len()
            )));
		}

		ser_multiwrite!(
			writer,
			[write_u64, self.inputs.len() as u64],
			[write_u64, self.inputs_with_sig.len() as u64],
			[write_u64, self.outputs.len() as u64],
			[write_u64, self.outputs_with_rnp.len() as u64],
			[write_u64, self.kernels.len() as u64]
		);

		self.inputs.write(writer)?;
		self.inputs_with_sig.write(writer)?;
		self.outputs.write(writer)?;
		self.outputs_with_rnp.write(writer)?;
		self.kernels.write(writer)?;

		Ok(())
	}
}

/// Implementation of Readable for a body, defines how to read a
/// body from a binary stream.
impl Readable for TransactionBodyV2 {
	fn read<R: Reader>(reader: &mut R) -> Result<TransactionBodyV2, ser::Error> {
		let (num_inputs, num_inputs_with_sig, num_outputs, num_outputs_with_rnp, num_kernels) =
			ser_multiread!(reader, read_u64, read_u64, read_u64, read_u64, read_u64);

		// Quick block weight check before proceeding.
		// Note: We use weight_as_block here (inputs have weight).
		let tx_block_weight = TransactionBodyV2::weight_as_block(
			num_inputs,
			num_inputs_with_sig,
			num_outputs,
			num_outputs_with_rnp,
			num_kernels,
		);

		if num_inputs > ser::READ_VEC_SIZE_LIMIT
			|| num_inputs_with_sig > ser::READ_VEC_SIZE_LIMIT
			|| num_outputs > ser::READ_VEC_SIZE_LIMIT
			|| num_outputs_with_rnp > ser::READ_VEC_SIZE_LIMIT
			|| num_kernels > ser::READ_VEC_SIZE_LIMIT
		{
			return Err(ser::Error::TooLargeReadErr(format!(
                "Transaction has impossibly many items: inputs {}, inputs_with_sig {}, outputs {}, outputs_with_rnp {}, kerners {}",
                num_inputs, num_inputs_with_sig, num_outputs, num_outputs_with_rnp, num_kernels
            )));
		}

		if tx_block_weight > global::max_block_weight() {
			return Err(ser::Error::TooLargeReadErr(format!(
				"Tx body weight {} is too heavy. Limit value {}",
				tx_block_weight,
				global::max_block_weight()
			)));
		}

		// Read protocol version specific inputs.
		let inputs = match reader.protocol_version().value() {
			0..=999 => {
				return Err(ser::Error::UnsupportedProtocolVersion(format!(
					"get version {}, expecting version >=1000",
					reader.protocol_version().value()
				)))
			}
			1_000..=ser::ProtocolVersion::MAX => {
				let inputs: Vec<CommitWrapper> = read_multi(reader, num_inputs)?;
				Inputs::from(inputs.as_slice())
			}
		};

		// Read protocol version specific inputs_with_sig.
		let inputs_with_sig = match reader.protocol_version().value() {
			0..=999 => {
				return Err(ser::Error::UnsupportedProtocolVersion(format!(
					"get version {}, expecting version >=1000",
					reader.protocol_version().value()
				)))
			}
			1_000..=ser::ProtocolVersion::MAX => {
				let inputs_with_sig: Vec<CommitWithSig> = read_multi(reader, num_inputs_with_sig)?;
				Inputs::from(inputs_with_sig.as_slice())
			}
		};

		let outputs = read_multi(reader, num_outputs)?;
		let outputs_with_rnp = read_multi(reader, num_outputs_with_rnp)?;
		let kernels = read_multi(reader, num_kernels)?;

		// Initialize tx body and verify everything is sorted.
		let body = TransactionBodyV2::init(
			inputs,
			inputs_with_sig,
			&outputs,
			&outputs_with_rnp,
			&kernels,
			true,
		)
		.map_err(|e| ser::Error::CorruptedData(format!("Fail to read transaction, {}", e)))?;

		Ok(body)
	}
}

impl Committed for TransactionBodyV2 {
	fn inputs_committed(&self) -> Vec<Commitment> {
		let inputs: Vec<_> = self.inputs().into();
		let mut commits: Vec<Commitment> = inputs.iter().map(|x| x.commitment()).collect();

		let inputs_with_sig: Vec<_> = self.inputs_with_sig().into();
		let commits_part2: Vec<Commitment> =
			inputs_with_sig.iter().map(|x| x.commitment()).collect();
		commits.extend(commits_part2);
		commits
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		let mut commits: Vec<Commitment> = self.outputs().iter().map(|x| x.commitment()).collect();
		let commits_part2: Vec<Commitment> = self
			.outputs_with_rnp()
			.iter()
			.map(|x| x.commitment())
			.collect();
		commits.extend(commits_part2);
		commits
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		self.kernels().iter().map(|x| x.excess()).collect()
	}
}

impl Default for TransactionBodyV2 {
	fn default() -> TransactionBodyV2 {
		TransactionBodyV2::empty()
	}
}

impl TxBodyImpl for TransactionBodyV2 {
	fn sort(&mut self) {
		self.inputs.sort_unstable();
		self.inputs_with_sig.sort_unstable();
		self.outputs.sort_unstable();
		self.outputs_with_rnp.sort_unstable();
		self.kernels.sort_unstable();
	}

	fn inputs(&self) -> Inputs {
		self.inputs.clone()
	}

	fn outputs(&self) -> &[Output] {
		&self.outputs
	}

	fn kernels(&self) -> &[TxKernel] {
		&self.kernels
	}

	fn fee(&self) -> u64 {
		self.kernels
			.iter()
			.filter_map(|k| match k.features {
				KernelFeatures::Coinbase => None,
				KernelFeatures::Plain { fee } => Some(fee),
				KernelFeatures::HeightLocked { fee, .. } => Some(fee),
				KernelFeatures::NoRecentDuplicate { fee, .. } => Some(fee),
			})
			.fold(0, |acc, fee| acc.saturating_add(fee))
	}

	fn overage(&self) -> i64 {
		self.fee() as i64
	}

	fn body_weight(&self) -> u64 {
		TransactionBodyV2::weight(
			(self.inputs.len() as u64).saturating_add(self.inputs_with_sig.len() as u64),
			(self.outputs.len() as u64).saturating_add(self.outputs_with_rnp.len() as u64),
			self.kernels.len() as u64,
		)
	}

	fn body_weight_as_block(&self) -> u64 {
		TransactionBodyV2::weight_as_block(
			self.inputs.len() as u64,
			self.inputs_with_sig.len() as u64,
			self.outputs.len() as u64,
			self.outputs_with_rnp.len() as u64,
			self.kernels.len() as u64,
		)
	}

	fn lock_height(&self) -> u64 {
		self.kernels
			.iter()
			.filter_map(|x| match x.features {
				KernelFeatures::HeightLocked { lock_height, .. } => Some(lock_height),
				_ => None,
			})
			.max()
			.unwrap_or(0)
	}

	fn verify_weight(&self, weighting: Weighting) -> Result<(), Error> {
		// A coinbase reward is a single output and a single kernel (for now).
		// We need to account for this when verifying max tx weights.
		let coinbase_weight = consensus::BLOCK_OUTPUT_WEIGHT + consensus::BLOCK_KERNEL_WEIGHT;

		// If "tx" body then remember to reduce the max_block_weight by the weight of a kernel.
		// If "limited tx" then compare against the provided max_weight.
		// If "block" body then verify weight based on full set of inputs|outputs|kernels.
		// If "pool" body then skip weight verification (pool can be larger than single block).
		//
		// Note: Taking a max tx and building a block from it we need to allow room
		// for the additional coinbase reward (1 output + 1 kernel).
		//
		let max_weight = match weighting {
			Weighting::AsTransaction => global::max_block_weight().saturating_sub(coinbase_weight),
			Weighting::AsLimitedTransaction(max_weight) => {
				min(global::max_block_weight(), max_weight).saturating_sub(coinbase_weight)
			}
			Weighting::AsBlock => global::max_block_weight(),
			Weighting::NoLimit => {
				// We do not verify "tx as pool" weight so we are done here.
				return Ok(());
			}
		};

		if self.body_weight_as_block() > max_weight {
			return Err(Error::TooHeavy);
		}
		Ok(())
	}

	fn verify_no_nrd_duplicates(&self) -> Result<(), Error> {
		if !global::is_nrd_enabled() {
			return Ok(());
		}

		let mut nrd_excess: Vec<Commitment> = self
			.kernels
			.iter()
			.filter(|x| match x.features {
				KernelFeatures::NoRecentDuplicate { .. } => true,
				_ => false,
			})
			.map(|x| x.excess())
			.collect();

		// Sort and dedup and compare length to look for duplicates.
		nrd_excess.sort();
		let original_count = nrd_excess.len();
		nrd_excess.dedup();
		let dedup_count = nrd_excess.len();
		if original_count == dedup_count {
			Ok(())
		} else {
			Err(Error::InvalidNRDRelativeHeight)
		}
	}

	fn verify_sorted(&self) -> Result<(), Error> {
		self.inputs.verify_sorted_and_unique()?;
		self.inputs_with_sig.verify_sorted_and_unique()?;
		self.outputs.verify_sorted_and_unique()?;
		self.outputs_with_rnp.verify_sorted_and_unique()?;
		self.kernels.verify_sorted_and_unique()?;
		Ok(())
	}

	fn inputs_outputs_committed(&self) -> Vec<Commitment> {
		let mut commits = self.inputs_committed();
		commits.extend_from_slice(self.outputs_committed().as_slice());
		commits.sort_unstable();
		commits
	}

	fn verify_cut_through(&self) -> Result<(), Error> {
		let commits = self.inputs_outputs_committed();
		for pair in commits.windows(2) {
			if pair[0] == pair[1] {
				return Err(Error::CutThrough);
			}
		}
		Ok(())
	}

	fn verify_features(&self) -> Result<(), Error> {
		self.verify_output_features()?;
		self.verify_kernel_features()?;
		Ok(())
	}

	fn verify_output_features(&self) -> Result<(), Error> {
		if self.outputs.iter().any(|x| x.is_coinbase()) {
			return Err(Error::InvalidOutputFeatures);
		}
		if self
			.outputs_with_rnp
			.iter()
			.any(|x| x.is_coinbase() || x.is_plain())
		{
			return Err(Error::InvalidOutputFeatures);
		}
		Ok(())
	}

	fn verify_kernel_features(&self) -> Result<(), Error> {
		if self.kernels.iter().any(|x| x.is_coinbase()) {
			return Err(Error::InvalidKernelFeatures);
		}
		Ok(())
	}

	fn validate_read(&self, weighting: Weighting) -> Result<(), Error> {
		self.verify_weight(weighting)?;
		self.verify_no_nrd_duplicates()?;
		self.verify_sorted()?;
		Ok(())
	}

	fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
	) -> Result<(), Error> {
		self.validate_read(weighting)?;

		// Find all the outputs that have not had their rangeproofs verified.
		let outputs = {
			let mut verifier = verifier.write();
			verifier.filter_rangeproof_unverified(&self.outputs)
		};

		// Now batch verify all those unverified rangeproofs
		if !outputs.is_empty() {
			let mut commits = vec![];
			let mut proofs = vec![];
			for x in &outputs {
				commits.push(x.commitment());
				proofs.push(x.proof);
			}
			Output::batch_verify_proofs(&commits, &proofs)?;
		}

		// rangeproofs verification for outputs_with_rnp
		let outputs_with_rnp = {
			let mut verifier = verifier.write();
			verifier.filter_rangeproof_unverified_v2(&self.outputs_with_rnp)
		};
		if !outputs_with_rnp.is_empty() {
			let mut commits = vec![];
			let mut extra_commits_data: Vec<Vec<u8>> = vec![];
			let mut proofs = vec![];
			for x in &outputs_with_rnp {
				commits.push(x.commitment());
				proofs.push(x.proof);
				extra_commits_data.push(x.extra_commit_data());
			}
			OutputWithRnp::batch_verify_proofs(&commits, extra_commits_data, &proofs)?;
		}

		// Find all the kernels that have not yet been verified.
		let kernels = {
			let mut verifier = verifier.write();
			verifier.filter_kernel_sig_unverified(&self.kernels)
		};

		// Verify the unverified tx kernels.
		TxKernel::batch_sig_verify(&kernels)?;

		// Cache the successful verification results for the new outputs and kernels.
		{
			let mut verifier = verifier.write();
			verifier.add_rangeproof_verified(outputs);
			verifier.add_rangeproof_verified_v2(outputs_with_rnp);
			verifier.add_kernel_sig_verified(kernels);
		}
		Ok(())
	}
}

impl TransactionBodyV2 {
	/// Whether it is v1 compatible
	pub fn is_v1_compatible(&self) -> bool {
		if self.inputs_with_sig.is_empty() && self.outputs_with_rnp.is_empty() {
			true
		} else {
			false
		}
	}

	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> TransactionBodyV2 {
		TransactionBodyV2 {
			inputs: Inputs::default(),
			inputs_with_sig: Inputs::CommitsWithSig(vec![]),
			outputs: vec![],
			outputs_with_rnp: vec![],
			kernels: vec![],
		}
	}

	/// Creates a new transaction body initialized with
	/// the provided inputs, outputs and kernels.
	/// Guarantees inputs, outputs, kernels are sorted lexicographically.
	pub fn init(
		inputs: Inputs,
		inputs_with_sig: Inputs,
		outputs: &[Output],
		outputs_with_rnp: &[OutputWithRnp],
		kernels: &[TxKernel],
		verify_sorted: bool,
	) -> Result<TransactionBodyV2, Error> {
		let mut body = TransactionBodyV2 {
			inputs,
			inputs_with_sig,
			outputs: outputs.to_vec(),
			outputs_with_rnp: outputs_with_rnp.to_vec(),
			kernels: kernels.to_vec(),
		};

		if verify_sorted {
			// If we are verifying sort order then verify and
			// return an error if not sorted lexicographically.
			body.verify_sorted()?;
		} else {
			// If we are not verifying sort order then sort in place and return.
			body.sort();
		}
		Ok(body)
	}

	/// Transaction inputs w/ signature.
	pub fn inputs_with_sig(&self) -> Inputs {
		self.inputs_with_sig.clone()
	}

	/// Transaction outputs w/ R&P'.
	pub fn outputs_with_rnp(&self) -> &[OutputWithRnp] {
		&self.outputs_with_rnp
	}

	/// Builds a new body with the provided inputs (w/o signature) added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(mut self, input: Input) -> TransactionBodyV2 {
		match &mut self.inputs {
			Inputs::CommitOnly(inputs) => {
				let commit = input.into();
				if let Err(e) = inputs.binary_search(&commit) {
					inputs.insert(e, commit)
				};
			}
			Inputs::FeaturesAndCommit(inputs) => {
				if let Err(e) = inputs.binary_search(&input) {
					inputs.insert(e, input)
				};
			}
			Inputs::CommitsWithSig(_) => {
				panic!(
					"with_input failed at impossible case that self.inputs is CommitsWithSig type."
				);
			}
		};
		self
	}

	/// Builds a new body with the provided inputs (w/ signature) added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input_wsig(mut self, input_with_sig: CommitWithSig) -> TransactionBodyV2 {
		match &mut self.inputs_with_sig {
			Inputs::FeaturesAndCommit(_) | Inputs::CommitOnly(_) => {
				panic!(
					"with_input_wsig failed at impossible case that wrong self.inputs_with_sig type."
				);
			}
			Inputs::CommitsWithSig(inputs) => {
				if let Err(e) = inputs.binary_search(&input_with_sig) {
					inputs.insert(e, input_with_sig)
				};
			}
		};
		self
	}

	/// Fully replace inputs (w/o signature).
	pub fn replace_inputs(mut self, inputs: Inputs) -> TransactionBodyV2 {
		self.inputs = inputs;
		self
	}

	/// Fully replace inputs (w/ signature).
	pub fn replace_inputs_wsig(mut self, inputs_with_sig: Inputs) -> TransactionBodyV2 {
		self.inputs_with_sig = inputs_with_sig;
		self
	}

	/// Builds a new TransactionBodyV2 with the provided output (w/o R&P') added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(mut self, output: Output) -> TransactionBodyV2 {
		if let Err(e) = self.outputs.binary_search(&output) {
			self.outputs.insert(e, output)
		};
		self
	}

	/// Builds a new TransactionBodyV2 with the provided output (w/o R&P') added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output_wrnp(mut self, output_with_rnp: OutputWithRnp) -> TransactionBodyV2 {
		if let Err(e) = self.outputs_with_rnp.binary_search(&output_with_rnp) {
			self.outputs_with_rnp.insert(e, output_with_rnp)
		};
		self
	}

	/// Fully replace outputs (w/o R&P').
	pub fn replace_outputs(mut self, outputs: &[Output]) -> TransactionBodyV2 {
		self.outputs = outputs.to_vec();
		self
	}

	/// Fully replace outputs (w/ R&P').
	pub fn replace_outputs_wrnp(mut self, outputs_with_rnp: &[OutputWithRnp]) -> TransactionBodyV2 {
		self.outputs_with_rnp = outputs_with_rnp.to_vec();
		self
	}

	/// Builds a new TransactionBodyV2 with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(mut self, kernel: TxKernel) -> TransactionBodyV2 {
		if let Err(e) = self.kernels.binary_search(&kernel) {
			self.kernels.insert(e, kernel)
		};
		self
	}

	/// Builds a new TransactionBodyV2 replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(mut self, kernel: TxKernel) -> TransactionBodyV2 {
		self.kernels.clear();
		self.kernels.push(kernel);
		self
	}

	/// Calculate transaction weight from transaction details. This is non
	/// consensus critical and compared to block weight, incentivizes spending
	/// more outputs (to lower the fee).
	pub fn weight(num_inputs: u64, num_outputs: u64, num_kernels: u64) -> u64 {
		let body_weight = num_outputs
			.saturating_mul(4)
			.saturating_add(num_kernels)
			.saturating_sub(num_inputs);
		max(body_weight, 1)
	}

	/// Calculate transaction weight using block weighing from transaction
	/// details. Consensus critical and uses consensus weight values.
	fn weight_as_block(
		num_inputs: u64,
		num_inputs_with_sig: u64,
		num_outputs: u64,
		num_outputs_with_rnp: u64,
		num_kernels: u64,
	) -> u64 {
		let body_weight = num_inputs
			.saturating_mul(consensus::BLOCK_INPUT_WEIGHT as u64)
			.saturating_add(num_outputs.saturating_mul(consensus::BLOCK_OUTPUT_WEIGHT as u64))
			.saturating_add(num_kernels.saturating_mul(consensus::BLOCK_KERNEL_WEIGHT as u64));

		num_inputs_with_sig
			.saturating_mul(consensus::BLOCK_INPUT_WITH_SIG_WEIGHT as u64)
			.saturating_add(
				num_outputs_with_rnp.saturating_mul(consensus::BLOCK_OUTPUT_WITH_RNP_WEIGHT as u64),
			)
			.saturating_add(body_weight)
	}
}

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionV2 {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBodyV2,
}

// V1 to V2 conversion
impl From<Transaction> for TransactionV2 {
	fn from(tx: Transaction) -> Self {
		TransactionV2 {
			offset: tx.offset,
			body: TransactionBodyV2::from(tx.body),
		}
	}
}

// V2 to V1 conversion
impl TryFrom<TransactionV2> for Transaction {
	type Error = &'static str;
	fn try_from(tx: TransactionV2) -> Result<Self, Self::Error> {
		Ok(Transaction {
			offset: tx.offset,
			body: TransactionBody::try_from(tx.body)?,
		})
	}
}

impl DefaultHashable for TransactionV2 {}

/// PartialEq
impl PartialEq for TransactionV2 {
	fn eq(&self, tx: &TransactionV2) -> bool {
		self.body == tx.body && self.offset == tx.offset
	}
}

/// Implementation of Writeable for a fully blinded transaction, defines how to
/// write the transaction as binary.
impl Writeable for TransactionV2 {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.offset.write(writer)?;
		self.body.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction, defines how to read a full
/// transaction from a binary stream.
impl Readable for TransactionV2 {
	fn read<R: Reader>(reader: &mut R) -> Result<TransactionV2, ser::Error> {
		let offset = BlindingFactor::read(reader)?;
		let body = TransactionBodyV2::read(reader)?;
		let tx = TransactionV2 { offset, body };

		// Now "lightweight" validation of the tx.
		// Treat any validation issues as data corruption.
		// An example of this would be reading a tx
		// that exceeded the allowed number of inputs.
		tx.validate_read()
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read Tx, {}", e)))?;

		Ok(tx)
	}
}

impl Committed for TransactionV2 {
	fn inputs_committed(&self) -> Vec<Commitment> {
		self.body.inputs_committed()
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		self.body.outputs_committed()
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		self.body.kernels_committed()
	}
}

impl Default for TransactionV2 {
	fn default() -> TransactionV2 {
		TransactionV2::empty()
	}
}

impl TxImpl for TransactionV2 {
	fn inputs(&self) -> Inputs {
		self.body.inputs()
	}

	fn outputs(&self) -> &[Output] {
		&self.body.outputs()
	}

	fn kernels(&self) -> &[TxKernel] {
		&self.body.kernels()
	}

	fn fee(&self) -> u64 {
		self.body.fee()
	}

	fn overage(&self) -> i64 {
		self.body.overage()
	}

	fn lock_height(&self) -> u64 {
		self.body.lock_height()
	}

	fn validate_read(&self) -> Result<(), Error> {
		self.body.validate_read(Weighting::AsTransaction)?;
		self.body.verify_features()?;
		Ok(())
	}

	fn validate(
		&self,
		weighting: Weighting,
		verifier: Arc<RwLock<dyn VerifierCache>>,
	) -> Result<(), Error> {
		self.body.verify_features()?;
		self.body.validate(weighting, verifier)?;
		self.verify_kernel_sums(self.overage(), self.offset.clone())?;
		Ok(())
	}

	fn fee_to_weight(&self) -> u64 {
		self.fee() * 1_000 / self.tx_weight() as u64
	}

	fn tx_weight(&self) -> u64 {
		self.body.body_weight()
	}

	fn tx_weight_as_block(&self) -> u64 {
		self.body.body_weight_as_block()
	}
}

impl TransactionV2 {
	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> TransactionV2 {
		TransactionV2 {
			offset: BlindingFactor::zero(),
			body: Default::default(),
		}
	}

	/// Creates a new transaction initialized with
	/// the provided inputs, outputs, kernels
	pub fn new(
		inputs: Inputs,
		inputs_with_sig: Inputs,
		outputs: &[Output],
		outputs_with_rnp: &[OutputWithRnp],
		kernels: &[TxKernel],
	) -> TransactionV2 {
		// Initialize a new tx body and sort everything.
		let body = TransactionBodyV2::init(
			inputs,
			inputs_with_sig,
			outputs,
			outputs_with_rnp,
			kernels,
			false,
		)
		.expect("sorting, not verifying");

		TransactionV2 {
			offset: BlindingFactor::zero(),
			body,
		}
	}

	/// Creates a new transaction using this transaction as a template
	/// and with the specified offset.
	pub fn with_offset(self, offset: BlindingFactor) -> TransactionV2 {
		TransactionV2 { offset, ..self }
	}

	/// Builds a new transaction with the provided inputs (w/o signature) added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(self, input: Input) -> TransactionV2 {
		TransactionV2 {
			body: self.body.with_input(input),
			..self
		}
	}

	/// Builds a new transaction with the provided inputs (w/ signature) added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input_wsig(self, input_with_sig: CommitWithSig) -> TransactionV2 {
		TransactionV2 {
			body: self.body.with_input_wsig(input_with_sig),
			..self
		}
	}

	/// Builds a new transaction with the provided output (w/o R&P') added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(self, output: Output) -> TransactionV2 {
		TransactionV2 {
			body: self.body.with_output(output),
			..self
		}
	}

	/// Builds a new transaction with the provided output (w/ R&P') added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output_wrnp(self, output_with_rnp: OutputWithRnp) -> TransactionV2 {
		TransactionV2 {
			body: self.body.with_output_wrnp(output_with_rnp),
			..self
		}
	}

	/// Builds a new transaction with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(self, kernel: TxKernel) -> TransactionV2 {
		TransactionV2 {
			body: self.body.with_kernel(kernel),
			..self
		}
	}

	/// Fully replace inputs.
	pub fn replace_inputs(mut self, inputs: Inputs) -> TransactionV2 {
		self.body = self.body.replace_inputs(inputs);
		self
	}

	/// Builds a new transaction replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(self, kernel: TxKernel) -> TransactionV2 {
		TransactionV2 {
			body: self.body.replace_kernel(kernel),
			..self
		}
	}

	/// Get inputs w/ signature
	pub fn inputs_with_sig(&self) -> Inputs {
		self.body.inputs_with_sig()
	}

	/// Get outputs w/ R&P'
	pub fn outputs_with_rnp(&self) -> &[OutputWithRnp] {
		&self.body.outputs_with_rnp()
	}

	/// Calculate transaction weight from transaction details
	pub fn weight(num_inputs: u64, num_outputs: u64, num_kernels: u64) -> u64 {
		TransactionBodyV2::weight(num_inputs, num_outputs, num_kernels)
	}
}

/// Aggregate a vec of txs into a multi-kernel tx.
pub fn aggregate(txs: &[TransactionV2]) -> Result<TransactionV2, Error> {
	// convenience short-circuiting
	if txs.is_empty() {
		return Ok(TransactionV2::empty());
	} else if txs.len() == 1 {
		return Ok(txs[0].clone());
	}

	let (n_inputs, n_inputs_with_sig, n_outputs, n_outputs_with_rnp, n_kernels) =
		txs.iter().fold((0, 0, 0, 0, 0), |(i1, i2, o1, o2, k), tx| {
			(
				i1 + tx.inputs().len(),
				i2 + tx.inputs_with_sig().len(),
				o1 + tx.outputs().len(),
				o2 + tx.outputs_with_rnp().len(),
				k + tx.kernels().len(),
			)
		});
	let mut inputs: Vec<CommitWrapper> = Vec::with_capacity(n_inputs);
	let mut inputs_with_sig: Vec<CommitWithSig> = Vec::with_capacity(n_inputs_with_sig);
	let mut outputs: Vec<Output> = Vec::with_capacity(n_outputs);
	let mut outputs_with_rnp: Vec<OutputWithRnp> = Vec::with_capacity(n_outputs_with_rnp);
	let mut kernels: Vec<TxKernel> = Vec::with_capacity(n_kernels);

	// we will sum these together at the end to give us the overall offset for the
	// transaction
	let mut kernel_offsets: Vec<BlindingFactor> = Vec::with_capacity(txs.len());
	for tx in txs {
		// we will sum these later to give a single aggregate offset
		kernel_offsets.push(tx.offset.clone());

		let tx_inputs: Vec<_> = tx.inputs().into();
		inputs.extend_from_slice(&tx_inputs);
		inputs_with_sig.extend_from_slice(&tx.inputs_with_sig().inputs_with_sig());
		outputs.extend_from_slice(tx.outputs());
		outputs_with_rnp.extend_from_slice(tx.outputs_with_rnp());
		kernels.extend_from_slice(tx.kernels());
	}

	// now sum the kernel_offsets up to give us an aggregate offset for the
	// transaction
	let total_kernel_offset = committed::sum_kernel_offsets(kernel_offsets, vec![])?;

	// build a new aggregate tx from the following -
	//   * all inputs
	//   * all outputs
	//   * full set of tx kernels
	//   * sum of all kernel offsets
	// Note: We sort input/outputs/kernels when building the transaction body internally.
	let tx = TransactionV2::new(
		Inputs::from(inputs.as_slice()),
		Inputs::from(inputs_with_sig.as_slice()),
		&outputs,
		&outputs_with_rnp,
		&kernels,
	)
	.with_offset(total_kernel_offset);

	Ok(tx)
}

/// Attempt to deaggregate a multi-kernel transaction based on multiple
/// transactions
pub fn deaggregate(mk_tx: TransactionV2, txs: &[TransactionV2]) -> Result<TransactionV2, Error> {
	let mut inputs: Vec<CommitWrapper> = vec![];
	let mut inputs_with_sig: Vec<CommitWithSig> = vec![];
	let mut outputs: Vec<Output> = vec![];
	let mut outputs_with_rnp: Vec<OutputWithRnp> = vec![];
	let mut kernels: Vec<TxKernel> = vec![];

	// we will subtract these at the end to give us the overall offset for the
	// transaction
	let mut kernel_offsets = vec![];

	let tx = aggregate(txs)?;

	// find all inputs which is not included in txs
	{
		let mk_inputs: Vec<_> = mk_tx.inputs().into();
		let tx_inputs: Vec<_> = tx.inputs().into();
		for mk_input in mk_inputs {
			if !tx_inputs.contains(&mk_input) && !inputs.contains(&mk_input) {
				inputs.push(mk_input);
			}
		}
	}
	// find all inputs_with_sig which is not included in txs
	{
		let mk_inputs: Vec<_> = mk_tx.inputs_with_sig().inputs_with_sig();
		let tx_inputs: Vec<_> = tx.inputs_with_sig().inputs_with_sig();
		for mk_input in mk_inputs {
			if !tx_inputs.contains(&mk_input) && !inputs_with_sig.contains(&mk_input) {
				inputs_with_sig.push(mk_input);
			}
		}
	}
	// find all outputs which is not included in txs
	for mk_output in mk_tx.outputs() {
		if !tx.outputs().contains(&mk_output) && !outputs.contains(mk_output) {
			outputs.push(*mk_output);
		}
	}
	// find all outputs_with_rnp which is not included in txs
	for mk_output in mk_tx.outputs_with_rnp() {
		if !tx.outputs_with_rnp().contains(&mk_output) && !outputs_with_rnp.contains(mk_output) {
			outputs_with_rnp.push(*mk_output);
		}
	}
	// find all kernels which is not included in txs
	for mk_kernel in mk_tx.kernels() {
		if !tx.kernels().contains(&mk_kernel) && !kernels.contains(mk_kernel) {
			kernels.push(*mk_kernel);
		}
	}

	kernel_offsets.push(tx.offset);

	// now compute the total kernel offset
	let total_kernel_offset = {
		let positive_key = vec![mk_tx.offset]
			.into_iter()
			.filter(|x| *x != BlindingFactor::zero())
			.filter_map(|x| x.secret_key().ok())
			.collect::<Vec<_>>();
		let negative_keys = kernel_offsets
			.into_iter()
			.filter(|x| *x != BlindingFactor::zero())
			.filter_map(|x| x.secret_key().ok())
			.collect::<Vec<_>>();

		if positive_key.is_empty() && negative_keys.is_empty() {
			BlindingFactor::zero()
		} else {
			let sum = Secp256k1::blind_sum(positive_key, negative_keys)?;
			BlindingFactor::from_secret_key(sum)
		}
	};

	// Sorting them lexicographically
	inputs.sort_unstable();
	inputs_with_sig.sort_unstable();
	outputs.sort_unstable();
	outputs_with_rnp.sort_unstable();
	kernels.sort_unstable();

	// Build a new tx from the above data.
	Ok(TransactionV2::new(
		Inputs::from(inputs.as_slice()),
		Inputs::from(inputs_with_sig.as_slice()),
		&outputs,
		&outputs_with_rnp,
		&kernels,
	)
	.with_offset(total_kernel_offset))
}

/// The Input with signature in a transaction when spending an output w/ R&P'.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct CommitWithSig {
	/// The commitment of Input.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
	/// The signature for the spending output P'.
	#[serde(with = "secp_ser::sig_serde")]
	pub sig: secp::Signature,
}

impl DefaultHashable for CommitWithSig {}
hashable_ord!(CommitWithSig);

/// Implementation of Writeable for a transaction Input, defines how to write
/// an Input as binary.
impl Writeable for CommitWithSig {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.commit.write(writer)?;
		self.sig.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Input, defines how to read
/// an Input from a binary stream.
impl Readable for CommitWithSig {
	fn read<R: Reader>(reader: &mut R) -> Result<CommitWithSig, ser::Error> {
		let commit = Commitment::read(reader)?;
		let sig = secp::Signature::read(reader)?;
		Ok(CommitWithSig { commit, sig })
	}
}

impl CommitWithSig {
	/// Wrapped commitment.
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Batch signature verification.
	/// Because of VerifierCache, it's not a requirement here that both vectors has same size,
	/// but they must be in same order, and each input commit must be included in the accomplished_inputs vector.
	pub fn batch_sig_verify(
		inputs_with_sig: &[CommitWithSig],
		accomplished_inputs: &[IdentifierWithRnp],
	) -> Result<(), Error> {
		let len = inputs_with_sig.len();
		let mut sigs = Vec::with_capacity(len);
		let mut pubkeys = Vec::with_capacity(len);
		let mut msgs = Vec::with_capacity(len);

		let mut rnp_iter = accomplished_inputs.iter();
		for input_with_sig in inputs_with_sig {
			sigs.push(input_with_sig.sig.clone());
			loop {
				let rnp = rnp_iter.next().ok_or(Error::IncorrectSignature)?;
				if rnp.commitment() == input_with_sig.commit {
					pubkeys.push(rnp.onetime_pubkey.clone());
					msgs.push(
						secp::Message::from_slice(rnp.extra_commit_data().as_slice()).unwrap(),
					);
					break;
				}
			}
		}

		let secp = static_secp_instance();
		let secp = secp.lock();

		if !aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys) {
			return Err(Error::IncorrectSignature);
		}

		Ok(())
	}
}

/// IdentifierWithRnp w/ R&P' for a transaction, a new type for non-interactive transaction feature, used by OutputWithRnp.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct IdentifierWithRnp {
	/// Output identifier (features and commitment).
	#[serde(flatten)]
	pub identifier: OutputIdentifier,
	/// Public nonce R for generating Ephemeral key.
	#[serde(with = "secp_ser::pubkey_serde")]
	pub nonce: PublicKey,
	/// One-time public key P' which is calculated by H(A')*G+B
	#[serde(with = "secp_ser::pubkey_serde")]
	pub onetime_pubkey: PublicKey,
}
impl DefaultHashable for IdentifierWithRnp {}

impl Ord for IdentifierWithRnp {
	fn cmp(&self, other: &Self) -> Ordering {
		self.identifier.cmp(&other.identifier)
	}
}

impl PartialOrd for IdentifierWithRnp {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl PartialEq for IdentifierWithRnp {
	fn eq(&self, other: &Self) -> bool {
		self.identifier == other.identifier
	}
}

impl Eq for IdentifierWithRnp {}

impl AsRef<Commitment> for IdentifierWithRnp {
	fn as_ref(&self) -> &Commitment {
		&self.identifier.commit
	}
}

/// Implementation of Writeable for it, defines how to write it as binary.
impl Writeable for IdentifierWithRnp {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.identifier.write(writer)?;
		self.nonce.write(writer)?;
		self.onetime_pubkey.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for it, defines how to read it from a binary stream.
impl Readable for IdentifierWithRnp {
	fn read<R: Reader>(reader: &mut R) -> Result<IdentifierWithRnp, ser::Error> {
		Ok(IdentifierWithRnp {
			identifier: OutputIdentifier::read(reader)?,
			nonce: PublicKey::read(reader)?,
			onetime_pubkey: PublicKey::read(reader)?,
		})
	}
}

impl PMMRable for IdentifierWithRnp {
	type E = Self;

	fn as_elmt(&self) -> IdentifierWithRnp {
		*self
	}

	fn elmt_size() -> Option<u16> {
		Some(
			(1 + secp::constants::PEDERSEN_COMMITMENT_SIZE
				+ 2 * secp::constants::COMPRESSED_PUBLIC_KEY_SIZE)
				.try_into()
				.unwrap(),
		)
	}
}

impl IdentifierWithRnp {
	/// Create with the provided features, commitment, R, P'.
	pub fn new(
		features: OutputFeatures,
		commit: Commitment,
		nonce: PublicKey,
		onetime_pubkey: PublicKey,
	) -> IdentifierWithRnp {
		IdentifierWithRnp {
			identifier: OutputIdentifier { features, commit },
			nonce,
			onetime_pubkey,
		}
	}

	/// Output identifier.
	pub fn identifier(&self) -> OutputIdentifier {
		self.identifier
	}

	/// Commitment for the output
	pub fn commitment(&self) -> Commitment {
		self.identifier.commitment()
	}

	/// Extra commit data for bullet proof. ExtraCommit = Hash(R || P' || OutputFeatures).
	/// This data is also used for input signing message.
	pub fn extra_commit_data(&self) -> Vec<u8> {
		let extra_commit_data = (
			self.nonce.serialize_vec(true).as_ref().to_vec(),
			self.onetime_pubkey.serialize_vec(true).as_ref().to_vec(),
			self.identifier.features as u8,
		)
			.hash();
		extra_commit_data.to_vec()
	}

	/// Output features.
	pub fn features(&self) -> OutputFeatures {
		self.identifier.features
	}

	/// Is this a coinbase output?
	pub fn is_coinbase(&self) -> bool {
		self.identifier.is_coinbase()
	}

	/// Is this a plain output?
	pub fn is_plain(&self) -> bool {
		self.identifier.is_plain()
	}
}

/// Output w/ R&P' for a transaction, a new type of output for non-interactive transaction feature.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct OutputWithRnp {
	/// Output identifier (features and commitment) with R and P'.
	#[serde(flatten)]
	pub identifier_with_rnp: IdentifierWithRnp,
	/// Rangeproof associated with the commitment.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::rangeproof_from_hex"
	)]
	pub proof: RangeProof,
}

impl Ord for OutputWithRnp {
	fn cmp(&self, other: &Self) -> Ordering {
		self.identifier_with_rnp.cmp(&other.identifier_with_rnp)
	}
}

impl PartialOrd for OutputWithRnp {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl PartialEq for OutputWithRnp {
	fn eq(&self, other: &Self) -> bool {
		self.identifier_with_rnp == other.identifier_with_rnp
	}
}

impl Eq for OutputWithRnp {}

impl AsRef<Commitment> for OutputWithRnp {
	fn as_ref(&self) -> &Commitment {
		self.identifier_with_rnp.as_ref()
	}
}

/// Implementation of Writeable for a transaction Output, defines how to write
/// an Output as binary.
impl Writeable for OutputWithRnp {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.identifier_with_rnp.write(writer)?;
		self.proof.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Output, defines how to read
/// an Output from a binary stream.
impl Readable for OutputWithRnp {
	fn read<R: Reader>(reader: &mut R) -> Result<OutputWithRnp, ser::Error> {
		Ok(OutputWithRnp {
			identifier_with_rnp: IdentifierWithRnp::read(reader)?,
			proof: RangeProof::read(reader)?,
		})
	}
}

impl Commit for OutputWithRnp {
	/// Commitment for the output
	fn commitment(&self) -> Commitment {
		self.identifier_with_rnp.commitment()
	}
}
impl OutputWithRnp {
	/// Create a new output with the provided features, commitment, R, P' and rangeproof.
	pub fn new(
		features: OutputFeatures,
		commit: Commitment,
		nonce: PublicKey,
		onetime_pubkey: PublicKey,
		proof: RangeProof,
	) -> OutputWithRnp {
		OutputWithRnp {
			identifier_with_rnp: IdentifierWithRnp::new(features, commit, nonce, onetime_pubkey),
			proof,
		}
	}

	/// Output identifier.
	pub fn identifier(&self) -> OutputIdentifier {
		self.identifier_with_rnp.identifier()
	}

	/// Extra commit data for bullet proof. ExtraCommit = Hash(R || P' || OutputFeatures)
	pub fn extra_commit_data(&self) -> Vec<u8> {
		self.identifier_with_rnp.extra_commit_data()
	}

	/// Output features.
	pub fn features(&self) -> OutputFeatures {
		self.identifier_with_rnp.features()
	}

	/// Is this a coinbase output?
	pub fn is_coinbase(&self) -> bool {
		self.identifier_with_rnp.is_coinbase()
	}

	/// Is this a plain output?
	pub fn is_plain(&self) -> bool {
		self.identifier_with_rnp.is_plain()
	}

	/// Range proof for the output
	pub fn proof(&self) -> RangeProof {
		self.proof
	}

	/// Get range proof as byte slice
	pub fn proof_bytes(&self) -> &[u8] {
		&self.proof.proof[..]
	}

	/// Validates the range proof using the commitment and extra_commit_data
	pub fn verify_proof(&self) -> Result<(), Error> {
		let extra_commit_data = self.extra_commit_data();
		let secp = static_secp_instance();
		secp.lock()
			.verify_bullet_proof(self.commitment(), self.proof, Some(extra_commit_data))?;
		Ok(())
	}

	/// Batch validates the range proofs using the commitments
	pub fn batch_verify_proofs(
		commits: &[Commitment],
		extra_commits_data: Vec<Vec<u8>>,
		proofs: &[RangeProof],
	) -> Result<(), Error> {
		let secp = static_secp_instance();
		secp.lock().verify_bullet_proof_multi(
			commits.to_vec(),
			proofs.to_vec(),
			Some(extra_commits_data),
		)?;
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hash;
	use crate::core::id::{ShortId, ShortIdentifiable};
	use keychain::{ExtKeychain, Keychain, SwitchCommitmentType};

	#[test]
	fn input_short_id() {
		let keychain = ExtKeychain::from_seed(&[0; 32], false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0);
		let commit = keychain
			.commit(5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		let input = Input {
			features: OutputFeatures::Plain,
			commit,
		};

		let block_hash =
			Hash::from_hex("3a42e66e46dd7633b57d1f921780a1ac715e6b93c19ee52ab714178eb3a9f673")
				.unwrap();

		let nonce = 0;

		let short_id = input.short_id(&block_hash, nonce);
		assert_eq!(short_id, ShortId::from_hex("c4b05f2ba649").unwrap());

		// now generate the short_id for a *very* similar output (single feature flag
		// different) and check it generates a different short_id
		let input = Input {
			features: OutputFeatures::Coinbase,
			commit,
		};

		let short_id = input.short_id(&block_hash, nonce);
		assert_eq!(short_id, ShortId::from_hex("3f0377c624e9").unwrap());
	}
}
