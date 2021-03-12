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

//! The Committed trait and associated errors.

use crate::core::OutputIds;
use enum_dispatch::enum_dispatch;
use failure::Fail;
use keychain;
use keychain::BlindingFactor;
use util::secp::key::SecretKey;
use util::secp::pedersen::Commitment;
use util::{secp, secp_static, static_secp_instance};

/// Errors from summing and verifying kernel excesses via committed trait.
#[derive(Debug, Clone, PartialEq, Eq, Fail, Serialize, Deserialize)]
pub enum Error {
	/// Keychain related error.
	#[fail(display = "Keychain error {}", _0)]
	Keychain(keychain::Error),
	/// Secp related error.
	#[fail(display = "Secp error {}", _0)]
	Secp(secp::Error),
	/// Kernel sums do not equal output sums.
	#[fail(display = "Kernel sum mismatch")]
	KernelSumMismatch,
	/// Kernel sums do not equal output R and input P' sums.
	#[fail(display = "Kernel sum eqn2 mismatch")]
	KernelSumEqn2Mismatch,
	/// Committed overage (fee or reward) is invalid
	#[fail(display = "Invalid value")]
	InvalidValue,
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(e)
	}
}

impl From<keychain::Error> for Error {
	fn from(e: keychain::Error) -> Error {
		Error::Keychain(e)
	}
}

/// Implemented by types that hold inputs and outputs (and kernels)
/// containing Pedersen commitments.
/// Handles the collection of the commitments as well as their
/// summing, taking potential explicit overages of fees into account.
#[enum_dispatch]
pub trait Committed {
	/// Gather the kernel excesses and sum them.
	fn sum_kernel_excesses(
		&self,
		offset: &BlindingFactor,
	) -> Result<(Commitment, Commitment), crate::core::committed::Error> {
		// then gather the kernel excess commitments
		let kernel_commits = self.kernels_committed();

		// sum the commitments
		let kernel_sum = sum_commits(kernel_commits, vec![])?;

		// sum the commitments along with the
		// commit to zero built from the offset
		let kernel_sum_plus_offset = {
			let secp = static_secp_instance();
			let secp = secp.lock();
			let mut commits = vec![kernel_sum];
			if *offset != BlindingFactor::zero() {
				let key = offset.secret_key()?;
				let offset_commit = secp.commit(0, key)?;
				commits.push(offset_commit);
			}
			secp::Secp256k1::commit_sum(commits, vec![])?
		};

		Ok((kernel_sum, kernel_sum_plus_offset))
	}

	/// Gathers commitments and sum them.
	fn sum_commitments(&self, overage: i64) -> Result<Commitment, crate::core::committed::Error> {
		// gather the commitments
		let mut input_commits = self.inputs_committed();
		let mut output_commits = self.outputs_committed();

		// add the overage as output commitment if positive,
		// or as an input commitment if negative
		if overage != 0 {
			let over_commit = {
				let secp = static_secp_instance();
				let secp = secp.lock();
				let overage_abs = overage.checked_abs().ok_or_else(|| Error::InvalidValue)? as u64;
				secp.commit_value(overage_abs)?
			};
			if overage < 0 {
				input_commits.push(over_commit);
			} else {
				output_commits.push(over_commit);
			}
		}

		sum_commits(output_commits, input_commits)
	}

	/// Gathers commitments and sum them.
	/// Sum all Input P' and Output R.
	fn sum_eqn2_commitments(
		&self,
		total_spent_rmp: Option<Commitment>,
		inputs_p_committed: &[Commitment],
	) -> Result<Commitment, crate::core::committed::Error> {
		// gather the commitments
		let input_commits = inputs_p_committed.to_vec();
		let mut output_commits = self.outputs_r_committed();
		if let Some(rmp) = total_spent_rmp {
			output_commits.push(rmp);
		}
		sum_commits(output_commits, input_commits)
	}

	/// Vector of output R commitments to verify.
	fn outputs_r_committed(&self) -> Vec<Commitment>;

	/// Vector of input commitments to verify.
	fn inputs_committed(&self) -> Vec<Commitment>;

	/// Vector of output commitments to verify.
	fn outputs_committed(&self) -> Vec<Commitment>;

	/// Vector of kernel excesses to verify.
	fn kernels_committed(&self) -> Vec<Commitment>;

	/// Verify the sum of the kernel excesses equals the
	/// sum of the outputs, taking into account both
	/// the kernel_offset and overage.
	fn verify_kernel_sums(
		&self,
		overage: i64,
		kernel_offset: BlindingFactor,
	) -> Result<(Commitment, Commitment), crate::core::committed::Error> {
		// Sum all input|output|overage commitments.
		let utxo_sum = self.sum_commitments(overage)?;

		// Sum the kernel excesses accounting for the kernel offset.
		let (kernel_sum, kernel_sum_plus_offset) = self.sum_kernel_excesses(&kernel_offset)?;

		if utxo_sum != kernel_sum_plus_offset {
			return Err(Error::KernelSumMismatch);
		}

		Ok((utxo_sum, kernel_sum))
	}

	/// Verify the equation (2) sum of the kernel excesses equals the
	/// sum of the Outputs R, taking into account the kernel_offset and Inputs P'.
	/// Note:
	/// - as the input parameter, the "total_spent_rmp" is the from the previous block header.
	/// - parameter "spending_output_ids" should be empty for chain validation.
	fn verify_kernel_sums_eqn2(
		&self,
		kernel_offset: BlindingFactor,
		kernel_sum: Commitment,
		total_spent_rmp: Option<Commitment>,
		spending_output_ids: &[OutputIds],
	) -> Result<Commitment, crate::core::committed::Error> {
		// Sum all Input P' and Output R.
		let inputs_p_committed = spending_output_ids
			.iter()
			.filter(|id| id.is_id_with_rnp())
			.map(|id| {
				Commitment::from_pubkey(&id.identifier_with_rnp().unwrap().onetime_pubkey)
					.unwrap_or(secp_static::commit_to_zero_value())
			})
			.collect::<Vec<Commitment>>();
		let rmp_sum = self.sum_eqn2_commitments(total_spent_rmp, &inputs_p_committed)?;

		// Sum the kernel excesses accounting for the kernel offset.
		let kernel_sum_plus_offset = commit_add_offset(kernel_sum, kernel_offset)?;

		if rmp_sum != kernel_sum_plus_offset {
			return Err(Error::KernelSumEqn2Mismatch);
		}

		Ok(rmp_sum)
	}
}

/// Utility to sum positive and negative commitments, eliminating zero values
pub fn sum_commits(
	mut positive: Vec<Commitment>,
	mut negative: Vec<Commitment>,
) -> Result<Commitment, Error> {
	let zero_commit = secp_static::commit_to_zero_value();
	positive.retain(|x| *x != zero_commit);
	negative.retain(|x| *x != zero_commit);
	Ok(secp::Secp256k1::commit_sum(positive, negative)?)
}

/// Utility function to take sets of positive and negative kernel offsets as
/// blinding factors, convert them to private key filtering zero values and
/// summing all of them. Useful to build blocks.
pub fn sum_kernel_offsets(
	positive: Vec<BlindingFactor>,
	negative: Vec<BlindingFactor>,
) -> Result<BlindingFactor, Error> {
	let positive = to_secrets(positive);
	let negative = to_secrets(negative);

	if positive.is_empty() {
		Ok(BlindingFactor::zero())
	} else {
		let sum = secp::Secp256k1::blind_sum(positive, negative)?;
		Ok(BlindingFactor::from_secret_key(sum))
	}
}

fn to_secrets(bf: Vec<BlindingFactor>) -> Vec<SecretKey> {
	bf.into_iter()
		.filter(|x| *x != BlindingFactor::zero())
		.filter_map(|x| x.secret_key().ok())
		.collect::<Vec<_>>()
}

/// Util for adding an offset on a commitment.
pub fn commit_add_offset(
	sum: Commitment,
	offset: BlindingFactor,
) -> Result<Commitment, crate::core::committed::Error> {
	let secp = static_secp_instance();
	let secp = secp.lock();
	let mut commits = vec![sum];
	if offset != BlindingFactor::zero() {
		let offset_commit = secp.commit(0, offset.secret_key()?)?;
		commits.push(offset_commit);
	}
	Ok(secp::Secp256k1::commit_sum(commits, vec![])?)
}
