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

//! The Committed trait and associated errors.

use keychain::BlindingFactor;
use std::cmp;
use std::sync::Arc;
use util::secp::key::SecretKey;
use util::secp::pedersen::Commitment;
use util::secp::Secp256k1;
use util::{secp, secp_static};

/// Errors from summing and verifying kernel excesses via committed trait.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum Error {
	/// Keychain related error.
	#[error("Keychain error {0}")]
	Keychain(keychain::Error),
	/// Secp related error.
	#[error("Secp error {0}")]
	Secp(secp::Error),
	/// Kernel sums do not equal output sums.
	#[error("Kernel sum mismatch")]
	KernelSumMismatch,
	/// Committed overage (fee or reward) is invalid
	#[error("Invalid value")]
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
pub trait Committed {
	/// Gather the kernel excesses and sum them.
	fn sum_kernel_excesses(
		&self,
		offset: &BlindingFactor,
		secp: &Secp256k1,
	) -> Result<(Commitment, Commitment), Error> {
		// then gather the kernel excess commitments
		let kernel_commits = self.kernels_committed();

		// sum the commitments
		let kernel_sum = sum_commits(kernel_commits, vec![], secp)?;

		// sum the commitments along with the
		// commit to zero built from the offset
		let kernel_sum_plus_offset = {
			let mut commits = vec![kernel_sum];
			if *offset != BlindingFactor::zero() {
				let key = offset.secret_key(&secp)?;
				let offset_commit = secp.commit(0, key)?;
				commits.push(offset_commit);
			}
			secp.commit_sum(commits, vec![])?
		};

		Ok((kernel_sum, kernel_sum_plus_offset))
	}

	/// Gathers commitments and sum them.
	fn sum_commitments(&self, overage: i64, secp: &Secp256k1) -> Result<Commitment, Error> {
		// gather the commitments
		let mut input_commits = self.inputs_committed();
		let mut output_commits = self.outputs_committed();

		// add the overage as output commitment if positive,
		// or as an input commitment if negative
		if overage != 0 {
			let over_commit = {
				let overage_abs = overage.checked_abs().ok_or_else(|| Error::InvalidValue)? as u64;
				secp.commit_value(overage_abs)?
			};
			if overage < 0 {
				input_commits.push(over_commit);
			} else {
				output_commits.push(over_commit);
			}
		}

		sum_commits(output_commits, input_commits, secp)
	}

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
		secp: &Secp256k1,
	) -> Result<(Commitment, Commitment), Error> {
		// Sum all input|output|overage commitments.
		let utxo_sum = self.sum_commitments(overage, secp)?;

		// Sum the kernel excesses accounting for the kernel offset.
		let (kernel_sum, kernel_sum_plus_offset) =
			self.sum_kernel_excesses(&kernel_offset, secp)?;

		if utxo_sum != kernel_sum_plus_offset {
			return Err(Error::KernelSumMismatch);
		}

		Ok((utxo_sum, kernel_sum))
	}
}

/// Utility to sum positive and negative commitments, eliminating zero values
pub fn sum_commits(
	mut positive: Vec<Commitment>,
	mut negative: Vec<Commitment>,
	secp: &Secp256k1,
) -> Result<Commitment, Error> {
	let zero_commit = secp_static::commit_to_zero_value();
	positive.retain(|x| *x != zero_commit);
	negative.retain(|x| *x != zero_commit);

	// We can process in parallell if there are a lot of data...
	if positive.len() + negative.len() < 100 {
		// can process in a singe thread (creating threads is overhead)
		Ok(secp.commit_sum(positive, negative)?)
	} else {
		// many items we better to process in multiple threads.
		let num_cores = num_cpus::get();
		let secp = Arc::new(secp);

		let sum_result = crossbeam::thread::scope(|s| {
			const COMMITS_PER_THREAD_LIMIT: usize = 20;

			let mut pos_handles = Vec::with_capacity(num_cores);
			if !positive.is_empty() {
				let pos_thr_num = cmp::max(
					1,
					cmp::min(num_cores, positive.len() / COMMITS_PER_THREAD_LIMIT),
				);
				for thr_idx in 0..pos_thr_num {
					let idx1 = positive.len() * thr_idx / pos_thr_num;
					let idx2 = positive.len() * (thr_idx + 1) / pos_thr_num;
					let secp = secp.clone();
					let pos_chunk: Vec<Commitment> = positive[idx1..idx2].to_vec();
					let handle = s.spawn(move |_| secp.commit_sum(pos_chunk, vec![]));
					pos_handles.push(handle);
				}
			}

			// let's start negative processing...
			let mut neg_handles = Vec::with_capacity(num_cores);
			if !negative.is_empty() {
				let neg_thr_num = cmp::max(
					1,
					cmp::min(num_cores, negative.len() / COMMITS_PER_THREAD_LIMIT),
				);
				for thr_idx in 0..neg_thr_num {
					let idx1 = negative.len() * thr_idx / neg_thr_num;
					let idx2 = negative.len() * (thr_idx + 1) / neg_thr_num;

					let secp = secp.clone();
					let neg_chunk: Vec<Commitment> = negative[idx1..idx2].to_vec();
					let handle = s.spawn(move |_| {
						// note, processing negative with positive sign, because we will subtrucat them at the final step
						secp.commit_sum(neg_chunk, vec![])
					});
					neg_handles.push(handle);
				}
			}

			// now let's collect the data from the worker threads
			let mut pos_sum: Vec<Commitment> = Vec::new();
			for handle in pos_handles {
				match handle.join().expect("Crossbeam runtime failure") {
					Ok(com) => pos_sum.push(com),
					Err(e) => return Err(e),
				}
			}

			let mut neg_sum: Vec<Commitment> = Vec::new();
			for handle in neg_handles {
				match handle.join().expect("Crossbeam runtime failure") {
					Ok(com) => neg_sum.push(com),
					Err(e) => return Err(e),
				}
			}
			// here eevry sum goes with intended sign
			Ok(secp.commit_sum(pos_sum, neg_sum)?)
		})
		.expect("Crossbeam runtime failure");
		Ok(sum_result?)
	}
}

/// Utility function to take sets of positive and negative kernel offsets as
/// blinding factors, convert them to private key filtering zero values and
/// summing all of them. Useful to build blocks.
pub fn sum_kernel_offsets(
	positive: Vec<BlindingFactor>,
	negative: Vec<BlindingFactor>,
	secp: &Secp256k1,
) -> Result<BlindingFactor, Error> {
	let positive = to_secrets(positive, &secp);
	let negative = to_secrets(negative, &secp);

	if positive.is_empty() {
		Ok(BlindingFactor::zero())
	} else {
		let sum = secp.blind_sum(positive, negative)?;
		Ok(BlindingFactor::from_secret_key(sum))
	}
}

fn to_secrets(bf: Vec<BlindingFactor>, secp: &secp::Secp256k1) -> Vec<SecretKey> {
	bf.into_iter()
		.filter(|x| *x != BlindingFactor::zero())
		.filter_map(|x| x.secret_key(secp).ok())
		.collect::<Vec<_>>()
}
