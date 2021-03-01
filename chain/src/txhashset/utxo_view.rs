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

//! Lightweight readonly view into output MMR for convenience.

use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::pmmr::{self, ReadonlyPMMR};
use crate::core::core::verifier_cache::VerifierCache;
use crate::core::core::{
	Block, BlockHeader, Commit, CommitWithSig, IdentifierWithRnp, Inputs, Output, OutputFeatures,
	OutputIdentifier, TxImpl, VersionedTransaction,
};
use crate::core::global;
use crate::error::{Error, ErrorKind};
use crate::store::Batch;
use crate::types::CommitPos;
use crate::util::secp::pedersen::{Commitment, RangeProof};
use grin_core::core::OutputWithRnp;
use grin_store::pmmr::PMMRBackend;
use grin_util::RwLock;
use std::sync::Arc;

/// Readonly view of the UTXO set (based on output MMR).
pub struct UTXOView<'a> {
	header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
	output_pmmr: ReadonlyPMMR<'a, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
	output_wrnp_pmmr: ReadonlyPMMR<'a, IdentifierWithRnp, PMMRBackend<IdentifierWithRnp>>,
	rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
	rproof_wrnp_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
}

impl<'a> UTXOView<'a> {
	/// Build a new UTXO view.
	pub fn new(
		header_pmmr: ReadonlyPMMR<'a, BlockHeader, PMMRBackend<BlockHeader>>,
		output_pmmr: ReadonlyPMMR<'a, OutputIdentifier, PMMRBackend<OutputIdentifier>>,
		output_wrnp_pmmr: ReadonlyPMMR<'a, IdentifierWithRnp, PMMRBackend<IdentifierWithRnp>>,
		rproof_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
		rproof_wrnp_pmmr: ReadonlyPMMR<'a, RangeProof, PMMRBackend<RangeProof>>,
	) -> UTXOView<'a> {
		UTXOView {
			header_pmmr,
			output_pmmr,
			output_wrnp_pmmr,
			rproof_pmmr,
			rproof_wrnp_pmmr,
		}
	}

	/// Validate a block against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_block(
		&self,
		block: &Block,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		for output in block.outputs() {
			self.validate_output(output, batch)?;
		}
		self.validate_inputs(&block.inputs(), batch)
	}

	/// Validate a transaction against the current UTXO set.
	/// Every input must spend an output that currently exists in the UTXO set.
	/// No duplicate outputs.
	pub fn validate_tx(
		&self,
		tx: &VersionedTransaction,
		batch: &Batch<'_>,
		verifier_cache: Arc<RwLock<dyn VerifierCache>>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		for output in tx.outputs() {
			self.validate_output(output, batch)?;
		}
		let mut res: Vec<(OutputIdentifier, CommitPos)> =
			self.validate_inputs(&tx.inputs(), batch)?;

		if let Some(outputs) = tx.outputs_with_rnp() {
			for output in outputs {
				self.validate_output(output, batch)?;
			}
			if let Some(inputs) = tx.inputs_with_sig() {
				let res2: Vec<(IdentifierWithRnp, CommitPos)> =
					self.validate_inputs_with_sig(&inputs, verifier_cache, batch)?;
				res.extend(
					res2.iter()
						.map(|r| (r.0.identifier(), r.1))
						.collect::<Vec<(OutputIdentifier, CommitPos)>>(),
				);
			}
		}
		Ok(res)
	}

	/// Validate the provided inputs (w/o signature).
	/// Returns a vec of output identifiers corresponding to outputs
	/// that would be spent by the provided inputs.
	pub fn validate_inputs(
		&self,
		inputs: &Inputs,
		batch: &Batch<'_>,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		match inputs {
			Inputs::CommitOnly(inputs) => {
				let outputs_spent: Result<Vec<_>, Error> = inputs
					.iter()
					.map(|input| {
						self.validate_input(input.commitment(), batch)
							.and_then(|(out, pos)| Ok((out, pos)))
					})
					.collect();
				outputs_spent
			}
			Inputs::FeaturesAndCommit(inputs) => {
				let outputs_spent: Result<Vec<_>, Error> = inputs
					.iter()
					.map(|input| {
						self.validate_input(input.commitment(), batch)
							.and_then(|(out, pos)| {
								// Unspent output found.
								// Check input matches full output identifier.
								if out == input.into() {
									Ok((out, pos))
								} else {
									error!("input mismatch: {:?}, {:?}, {:?}", out, pos, input);
									Err(ErrorKind::Other("input mismatch".into()).into())
								}
							})
					})
					.collect();
				outputs_spent
			}
			Inputs::CommitsWithSig(_) => Err(ErrorKind::Other(
				"wrong function called. use validate_inputs_with_sig instead.".into(),
			)
			.into()),
		}
	}

	/// Validate the provided inputs (w/ signature).
	/// Returns a vec of output IdentifierWithRnp corresponding to outputs
	/// that would be spent by the provided inputs.
	/// Note: inputs signature validation is here.
	pub fn validate_inputs_with_sig(
		&self,
		inputs: &Inputs,
		verifier: Arc<RwLock<dyn VerifierCache>>,
		batch: &Batch<'_>,
	) -> Result<Vec<(IdentifierWithRnp, CommitPos)>, Error> {
		match inputs {
			Inputs::CommitOnly(_) | Inputs::FeaturesAndCommit(_) => Err(ErrorKind::Other(
				"wrong function called. use validate_inputs instead.".into(),
			)
			.into()),
			Inputs::CommitsWithSig(inputs) => {
				let mut outputs_spent = vec![];
				for input in inputs {
					outputs_spent.push(self.validate_input_with_sig(input.commitment(), batch)?);
				}

				// Signature validation
				let inputs_with_sig = {
					let mut verifier = verifier.write();
					verifier.filter_input_with_sig_unverified(inputs)
				};

				// Get Vec<IdentifierWithRnp> only
				let rnps = outputs_spent
					.iter()
					.map(|o| (o.0, o.1))
					.collect::<Vec<(IdentifierWithRnp, Hash)>>();

				// Verify the unverified inputs signatures.
				// Signature verification need public key (i.e. that P' in this context), the P' has to be queried from chain UTXOs set.
				CommitWithSig::batch_sig_verify(&inputs_with_sig, &rnps)?;
				Ok(outputs_spent
					.iter()
					.map(|o| (o.0, o.2))
					.collect::<Vec<(IdentifierWithRnp, CommitPos)>>())
			}
		}
	}

	// Input is valid if it is spending an (unspent) output
	// that currently exists in the output MMR.
	// Note: We lookup by commitment. Caller must compare the full input as necessary.
	fn validate_input(
		&self,
		input: Commitment,
		batch: &Batch<'_>,
	) -> Result<(OutputIdentifier, CommitPos), Error> {
		let pos = batch.get_output_pos_height(&input)?;
		if let Some(pos) = pos {
			if let Some(out) = self.output_pmmr.get_data(pos.pos) {
				if out.commitment() == input {
					return Ok((out, pos));
				} else {
					error!("input mismatch: {:?}, {:?}, {:?}", out, pos, input);
					return Err(ErrorKind::Other(
						"input mismatch (output_pos index mismatch?)".into(),
					)
					.into());
				}
			}
		}
		Err(ErrorKind::AlreadySpent(input).into())
	}

	// Input is valid if it is spending an (unspent) output which currently exists in the output MMR.
	// Note: (1) We lookup by commitment. Caller must compare the full input as necessary.
	//       (2) It's caller's responsibility to validate the input signature.
	fn validate_input_with_sig(
		&self,
		input: Commitment,
		batch: &Batch<'_>,
	) -> Result<(IdentifierWithRnp, Hash, CommitPos), Error> {
		let commit_pos = batch.get_output_pos_height(&input)?;
		if let Some(cp) = commit_pos {
			if let Some(out) = self.output_wrnp_pmmr.get_data(cp.pos) {
				return if out.commitment() == input {
					if let Some(h) = self.rproof_wrnp_pmmr.get_hash(cp.pos) {
						Ok((out, h, cp))
					} else {
						error!("rproof not exist: {:?}, {:?}, {:?}", out, cp, input);
						Err(ErrorKind::Other("rproof not exist".into()).into())
					}
				} else {
					error!("input mismatch: {:?}, {:?}, {:?}", out, cp, input);
					Err(
						ErrorKind::Other("input mismatch (output_pos index mismatch?)".into())
							.into(),
					)
				};
			}
		}
		Err(ErrorKind::AlreadySpent(input).into())
	}

	// Output is valid if it would not result in a duplicate commitment in the output MMR.
	fn validate_output(&self, output: &dyn Commit, batch: &Batch<'_>) -> Result<(), Error> {
		if let Ok(commit_pos) = batch.get_output_pos_height(&output.commitment()) {
			if let Some(cp) = commit_pos {
				match cp.features {
					OutputFeatures::PlainWrnp => {
						if let Some(out_mmr) = self.output_wrnp_pmmr.get_data(cp.pos) {
							if out_mmr.commitment() == output.commitment() {
								return Err(
									ErrorKind::DuplicateCommitment(output.commitment()).into()
								);
							}
						}
					}
					_ => {
						if let Some(out_mmr) = self.output_pmmr.get_data(cp.pos) {
							if out_mmr.commitment() == output.commitment() {
								return Err(
									ErrorKind::DuplicateCommitment(output.commitment()).into()
								);
							}
						}
					}
				}
			}
		}
		Ok(())
	}

	/// Retrieves an unspent output (w/o R&P') using its PMMR position
	pub fn get_unspent_output_at(&self, pos: u64) -> Result<Output, Error> {
		match self.output_pmmr.get_data(pos) {
			Some(output_id) => match self.rproof_pmmr.get_data(pos) {
				Some(rproof) => Ok(output_id.into_output(rproof)),
				None => Err(ErrorKind::RangeproofNotFound(format!("at position {}", pos)).into()),
			},
			None => Err(ErrorKind::OutputNotFound(format!("at position {}", pos)).into()),
		}
	}

	/// Retrieves an unspent output (w/ R&P') using its PMMR position
	pub fn get_unspent_output_wrnp_at(&self, pos: u64) -> Result<OutputWithRnp, Error> {
		match self.output_wrnp_pmmr.get_data(pos) {
			Some(output_id) => match self.rproof_wrnp_pmmr.get_data(pos) {
				Some(rproof) => Ok(output_id.into_output(rproof)),
				None => Err(ErrorKind::RangeproofNotFound(format!("at position {}", pos)).into()),
			},
			None => Err(ErrorKind::OutputNotFound(format!("at position {}", pos)).into()),
		}
	}

	/// Verify we are not attempting to spend any coinbase outputs
	/// that have not sufficiently matured.
	pub fn verify_coinbase_maturity(
		&self,
		inputs: &Inputs,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<(), Error> {
		let inputs: Vec<_> = inputs.into();

		// Lookup the outputs being spent.
		let spent: Result<Vec<_>, _> = inputs
			.iter()
			.map(|x| self.validate_input(x.commitment(), batch))
			.collect();

		// Find the max pos of any coinbase being spent.
		let pos = spent?
			.iter()
			.filter_map(|(out, pos)| {
				if out.features.is_coinbase() {
					Some(pos.pos)
				} else {
					None
				}
			})
			.max();

		if let Some(pos) = pos {
			// If we have not yet reached 1440 blocks then
			// we can fail immediately as coinbase cannot be mature.
			if height < global::coinbase_maturity() {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}

			// Find the "cutoff" pos in the output MMR based on the
			// header from 1,000 blocks ago.
			let cutoff_height = height.saturating_sub(global::coinbase_maturity());
			let cutoff_header = self.get_header_by_height(cutoff_height, batch)?;
			let cutoff_pos = cutoff_header.output_mmr_size;

			// If any output pos exceed the cutoff_pos
			// we know they have not yet sufficiently matured.
			if pos > cutoff_pos {
				return Err(ErrorKind::ImmatureCoinbase.into());
			}
		}

		Ok(())
	}

	/// Get the header hash for the specified pos from the underlying MMR backend.
	fn get_header_hash(&self, pos: u64) -> Option<Hash> {
		self.header_pmmr.get_data(pos).map(|x| x.hash())
	}

	/// Get the header at the specified height based on the current state of the extension.
	/// Derives the MMR pos from the height (insertion index) and retrieves the header hash.
	/// Looks the header up in the db by hash.
	pub fn get_header_by_height(
		&self,
		height: u64,
		batch: &Batch<'_>,
	) -> Result<BlockHeader, Error> {
		let pos = pmmr::insertion_to_pmmr_index(height + 1);
		if let Some(hash) = self.get_header_hash(pos) {
			let header = batch.get_block_header(&hash)?;
			Ok(header)
		} else {
			Err(ErrorKind::Other(format!("get header for height {}", height)).into())
		}
	}
}
