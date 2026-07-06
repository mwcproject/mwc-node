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
use mwc_crates::crossbeam;
use mwc_crates::crossbeam::thread::ScopedJoinHandle;
use mwc_crates::num_cpus;
use mwc_crates::secp;
use mwc_crates::secp::key::SecretKey;
use mwc_crates::secp::pedersen::Commitment;
use mwc_crates::secp::Secp256k1;
use mwc_crates::serde::{self, Deserialize, Serialize};
use std::collections::VecDeque;
use util::secp_static;

const COMMITS_BATCH_SIZE: usize = 5000;

enum CommitSumChunk {
	/// Most chunks can be compressed into one partial commitment and later
	/// combined by the parent thread.
	Sum(Commitment),
	/// If a chunk sum is zero, secp cannot serialize it as a Commitment, so we
	/// carry the original commits forward into the final sum.
	Raw(Vec<Commitment>),
}

impl CommitSumChunk {
	fn from_commits(commits: Vec<Commitment>) -> Result<CommitSumChunk, Error> {
		secp_static::with_none(Error::from, |secp| {
			match secp.commit_sum(commits.clone(), vec![]) {
				Ok(sum) => Ok(CommitSumChunk::Sum(sum)),
				Err(secp::Error::IncorrectCommitSum) => Ok(CommitSumChunk::Raw(commits)),
				Err(err) => Err(Error::from(err)),
			}
		})
	}

	fn append_to(self, commits: &mut Vec<Commitment>) {
		match self {
			CommitSumChunk::Sum(sum) => commits.push(sum),
			CommitSumChunk::Raw(raw_commits) => commits.extend(raw_commits),
		}
	}
}

fn wait_for_commit_sum_task<E, F>(
	min_running_tasks: usize,
	running_tasks: &mut VecDeque<ScopedJoinHandle<Result<(CommitSumChunk, usize), Error>>>,
	partial_sums: &mut Vec<Commitment>,
	on_progress: &mut F,
) -> Result<(), E>
where
	E: From<Error>,
	F: FnMut(usize) -> Result<(), E>,
{
	if running_tasks.len() < min_running_tasks {
		return Ok(());
	}

	let handle = running_tasks.pop_front().ok_or_else(|| {
		E::from(Error::Other(
			"wait_for_commit_sum_task internal error, no running task".into(),
		))
	})?;
	let result = handle
		.join()
		.map_err(|_| E::from(Error::Other("commit sum crossbeam runtime failure".into())))?;
	let (sum, items) = result.map_err(E::from)?;
	sum.append_to(partial_sums);
	on_progress(items)?;
	Ok(())
}

fn collect_commitment_partials<I, E, C, F>(
	commits: I,
	batch_size: usize,
	max_workers: usize,
	check_state: &mut C,
	on_progress: &mut F,
) -> Result<Vec<Commitment>, E>
where
	I: Iterator<Item = Result<Commitment, E>>,
	E: From<Error>,
	C: FnMut() -> Result<(), E>,
	F: FnMut(usize) -> Result<(), E>,
{
	let batch_size = batch_size.max(1);
	let max_workers = max_workers.max(1);
	let mut partial_sums = Vec::new();

	let scope_result = crossbeam::thread::scope(|s| {
		let mut running_tasks: VecDeque<ScopedJoinHandle<Result<(CommitSumChunk, usize), Error>>> =
			VecDeque::with_capacity(max_workers);
		let mut chunk = Vec::with_capacity(batch_size);

		for commit in commits {
			check_state()?;
			chunk.push(commit?);
			if chunk.len() < batch_size {
				continue;
			}

			let chunk_to_sum = std::mem::replace(&mut chunk, Vec::with_capacity(batch_size));
			running_tasks.push_back(s.spawn(move |_| {
				let chunk_len = chunk_to_sum.len();
				let sum = CommitSumChunk::from_commits(chunk_to_sum)?;
				Ok((sum, chunk_len))
			}));
			wait_for_commit_sum_task(
				max_workers,
				&mut running_tasks,
				&mut partial_sums,
				on_progress,
			)?;
		}

		if !chunk.is_empty() {
			let chunk_len = chunk.len();
			partial_sums.extend(chunk);
			on_progress(chunk_len)?;
		}

		while !running_tasks.is_empty() {
			let wait_until = running_tasks.len();
			wait_for_commit_sum_task(
				wait_until,
				&mut running_tasks,
				&mut partial_sums,
				on_progress,
			)?;
		}

		Ok::<(), E>(())
	})
	.map_err(|_| E::from(Error::Other("commit sum crossbeam runtime failure".into())))?;
	scope_result?;

	Ok(partial_sums)
}

/// Sum positive and negative commitment streams by compacting large chunks in
/// parallel, carrying raw chunks forward if a zero partial cannot be serialized.
pub fn sum_commitments_parallel<I, J, E, C, F>(
	positive: I,
	negative: J,
	positive_tail: &[Commitment],
	negative_tail: &[Commitment],
	batch_size: usize,
	max_workers: usize,
	secp: &Secp256k1,
	mut check_state: C,
	mut on_progress: F,
) -> Result<Commitment, E>
where
	I: Iterator<Item = Result<Commitment, E>>,
	J: Iterator<Item = Result<Commitment, E>>,
	E: From<Error>,
	C: FnMut() -> Result<(), E>,
	F: FnMut(usize) -> Result<(), E>,
{
	let mut completed_items: usize = 0;
	let mut update_completed = |items| {
		completed_items = completed_items.saturating_add(items);
		on_progress(completed_items)
	};

	// Successful chunks become one partial commitment. Chunks whose sum is zero
	// remain raw because secp cannot serialize a zero partial as a Commitment.
	let mut pos_sum = collect_commitment_partials(
		positive,
		batch_size,
		max_workers,
		&mut check_state,
		&mut update_completed,
	)?;
	let mut neg_sum = collect_commitment_partials(
		negative,
		batch_size,
		max_workers,
		&mut check_state,
		&mut update_completed,
	)?;

	// The final secp sum validates compact partial sums, raw chunks, and any
	// caller-provided tail commitments as one equivalent commitment sum.
	pos_sum.extend_from_slice(positive_tail);
	neg_sum.extend_from_slice(negative_tail);
	if pos_sum.is_empty() && neg_sum.is_empty() {
		return Err(E::from(Error::Secp(secp::Error::IncorrectCommitSum)));
	}

	secp.commit_sum(pos_sum, neg_sum)
		.map_err(Error::from)
		.map_err(E::from)
}

/// Verify output/input/overage commitments against kernel excesses and kernel offset.
pub fn verify_kernel_sums_iter<I, J, K, E, C, F>(
	outputs: I,
	inputs: J,
	kernels: K,
	overage: i64,
	kernel_offset: BlindingFactor,
	batch_size: usize,
	max_workers: usize,
	secp: &Secp256k1,
	mut check_state: C,
	mut on_progress: F,
) -> Result<(Commitment, Commitment), E>
where
	I: Iterator<Item = Result<Commitment, E>>,
	J: Iterator<Item = Result<Commitment, E>>,
	K: Iterator<Item = Result<Commitment, E>>,
	E: From<Error>,
	C: FnMut() -> Result<(), E>,
	F: FnMut(usize) -> Result<(), E>,
{
	let mut input_tail = vec![];
	let mut output_tail = vec![];
	if overage != 0 {
		let overage_abs = overage.checked_abs().ok_or(Error::InvalidValue)? as u64;
		let over_commit = secp.commit_value(overage_abs).map_err(Error::from)?;
		if overage < 0 {
			input_tail.push(over_commit);
		} else {
			output_tail.push(over_commit);
		}
	}

	let mut completed_items = 0usize;
	let mut output_completed = 0usize;
	let utxo_sum = sum_commitments_parallel(
		outputs,
		inputs,
		&output_tail,
		&input_tail,
		batch_size,
		max_workers,
		secp,
		&mut check_state,
		|completed| {
			let delta = completed.saturating_sub(output_completed);
			output_completed = completed;
			completed_items = completed_items.saturating_add(delta);
			on_progress(completed_items)
		},
	)?;

	check_state()?;

	let mut kernel_completed = 0usize;
	let kernel_sum = sum_commitments_parallel(
		kernels,
		std::iter::empty::<Result<Commitment, E>>(),
		&[],
		&[],
		batch_size,
		max_workers,
		secp,
		&mut check_state,
		|completed| {
			let delta = completed.saturating_sub(kernel_completed);
			kernel_completed = completed;
			completed_items = completed_items.saturating_add(delta);
			on_progress(completed_items)
		},
	)?;

	check_state()?;

	let kernel_sum_plus_offset = {
		let mut commits = vec![kernel_sum];
		if kernel_offset != BlindingFactor::zero() {
			let key = kernel_offset.secret_key(secp).map_err(Error::from)?;
			let offset_commit = secp.commit(0, key).map_err(Error::from)?;
			commits.push(offset_commit);
		}
		secp.commit_sum(commits, vec![]).map_err(Error::from)?
	};

	if utxo_sum != kernel_sum_plus_offset {
		return Err(E::from(Error::KernelSumMismatch));
	}

	Ok((utxo_sum, kernel_sum))
}

/// Errors from summing and verifying kernel excesses via committed trait.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum Error {
	/// Keychain related error.
	#[error("Keychain error {0}")]
	Keychain(#[from] keychain::Error),
	/// Secp related error.
	#[error("Secp error {0}")]
	Secp(secp::Error),
	/// Kernel sums do not equal output sums.
	#[error("Kernel sum mismatch")]
	KernelSumMismatch,
	/// Committed overage (fee or reward) is invalid
	#[error("Invalid value")]
	InvalidValue,
	/// Some other/internal generic error
	#[error("{0}")]
	Other(String),
	/// PMMR Error
	#[error("PMMR Error, {0}")]
	PMMRError(String),
}

impl From<crate::core::pmmr::Error> for Error {
	fn from(e: crate::core::pmmr::Error) -> Error {
		Error::PMMRError(e.to_string())
	}
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(e)
	}
}

/// Iterator over commitments used by sum validation.
pub type CommitmentIterator<'a> = Box<dyn Iterator<Item = Result<Commitment, Error>> + 'a>;

/// Implemented by types that hold inputs and outputs (and kernels)
/// containing Pedersen commitments.
/// Handles the collection of the commitments as well as their
/// summing, taking potential explicit overages of fees into account.
pub trait Committed {
	/// Input commitments to verify.
	fn inputs_committed(&self) -> Result<CommitmentIterator<'_>, Error>;

	/// Output commitments to verify.
	fn outputs_committed(&self) -> Result<CommitmentIterator<'_>, Error>;

	/// Kernel excess commitments to verify.
	fn kernels_committed(&self) -> Result<CommitmentIterator<'_>, Error>;

	/// Verify the sum of the kernel excesses equals the
	/// sum of the outputs, taking into account both
	/// the kernel_offset and overage.
	fn verify_kernel_sums(
		&self,
		overage: i64,
		kernel_offset: BlindingFactor,
		secp: &Secp256k1,
	) -> Result<(Commitment, Commitment), Error> {
		verify_kernel_sums_iter(
			self.outputs_committed()?,
			self.inputs_committed()?,
			self.kernels_committed()?,
			overage,
			kernel_offset,
			COMMITS_BATCH_SIZE,
			num_cpus::get().max(1),
			secp,
			|| Ok::<(), Error>(()),
			|_| Ok::<(), Error>(()),
		)
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
	let positive = to_secrets(positive, &secp)?;
	let negative = to_secrets(negative, &secp)?;

	if positive.is_empty() && negative.is_empty() {
		Ok(BlindingFactor::zero())
	} else {
		match secp.blind_sum(positive, negative) {
			Ok(sum) => Ok(BlindingFactor::from_secret_key(sum)),
			Err(secp::Error::ZeroSecretKey) => Ok(BlindingFactor::zero()),
			Err(e) => Err(e.into()),
		}
	}
}

fn to_secrets(bf: Vec<BlindingFactor>, secp: &secp::Secp256k1) -> Result<Vec<SecretKey>, Error> {
	let mut res: Vec<SecretKey> = Vec::with_capacity(bf.len());

	for x in &bf {
		if *x != BlindingFactor::zero() {
			res.push(
				x.secret_key(secp)
					.map_err(|e| Error::Other(format!("Invalid blind value, {}", e)))?,
			);
		}
	}
	Ok(res)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn commit_values(secp: &Secp256k1, values: &[u64]) -> Vec<Commitment> {
		values
			.iter()
			.map(|value| secp.commit_value(*value).unwrap())
			.collect()
	}

	fn commitment_iter(
		commits: Vec<Commitment>,
	) -> impl Iterator<Item = Result<Commitment, Error>> {
		commits.into_iter().map(Ok::<Commitment, Error>)
	}

	#[test]
	fn sum_commitments_parallel_iterators_match_direct_sum() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let positive_values: Vec<_> = (1..=220).collect();
		let negative_values: Vec<_> = (1..=20).collect();
		let positive = commit_values(&secp, &positive_values);
		let negative = commit_values(&secp, &negative_values);

		let expected = secp.commit_sum(positive.clone(), negative.clone()).unwrap();
		let actual = sum_commitments_parallel(
			commitment_iter(positive),
			commitment_iter(negative),
			&[],
			&[],
			25,
			4,
			&secp,
			|| Ok::<(), Error>(()),
			|_| Ok::<(), Error>(()),
		)
		.unwrap();

		assert_eq!(actual, expected);
	}

	#[test]
	fn sum_commitments_parallel_iterators_carry_zero_partial_chunk_as_raw_commits() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(10).unwrap();
		let negative_commit = secp.commit_sum(vec![], vec![commit]).unwrap();
		let mut positive = Vec::with_capacity(200);
		for _ in 0..50 {
			positive.push(commit);
			positive.push(negative_commit);
		}
		for value in 1..=100 {
			positive.push(secp.commit_value(value).unwrap());
		}

		let expected = secp.commit_sum(positive.clone(), vec![]).unwrap();
		let actual = sum_commitments_parallel(
			commitment_iter(positive),
			std::iter::empty::<Result<Commitment, Error>>(),
			&[],
			&[],
			100,
			4,
			&secp,
			|| Ok::<(), Error>(()),
			|_| Ok::<(), Error>(()),
		)
		.unwrap();

		assert_eq!(actual, expected);
	}
}
