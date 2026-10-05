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

//! Utility functions to build Mwc transactions. Handles the blinding of
//! inputs and outputs, maintaining the sum of blinding factors, producing
//! the excess signature, etc.
//!
//! Each building function is a combinator that produces a function taking
//! a transaction a sum of blinding factors, to return another transaction
//! and sum. Combinators can then be chained and executed using the
//! _transaction_ function.
//!
//! Example:
//! build::transaction(
//!   KernelFeatures::Plain{ fee: 2.try_into().unwrap() },
//!   vec![
//!     input_rand(75),
//!     output_rand(42),
//!     output_rand(32),
//!   ]
//! )

use crate::core::{Input, Inputs, KernelFeatures, Output, OutputFeatures, Transaction, TxKernel};
use crate::libtx::proof;
use crate::libtx::proof::ProofBuild;
use crate::libtx::{aggsig, Error};
use keychain::{BlindSum, BlindingFactor, Identifier, Keychain, SwitchCommitmentType};
use mwc_crates::secp::Secp256k1;

/// Context information available to transaction combinators.
pub struct Context<'a, K, B>
where
	K: Keychain,
	B: ProofBuild,
{
	/// The keychain used for key derivation
	pub keychain: &'a K,
	/// The bulletproof builder
	pub builder: &'a B,
	/// secp instance
	pub secp: &'a mut Secp256k1,
	/// Consensus context used for serialization, hashing and ordering.
	pub context_id: u32,
}

/// Function type returned by the transaction combinators. Transforms a
/// (Transaction, BlindSum) tuple into another, given the provided context.
/// Will return an Err if seomthing went wrong at any point during transaction building.
pub type Append<K, B> = dyn for<'a> Fn(
	&'a mut Context<'_, K, B>,
	Result<(Transaction, BlindSum), Error>,
) -> Result<(Transaction, BlindSum), Error>;

/// Build a feature-preserving transaction input.
///
/// Core wire transactions use commit-only inputs at the current protocol
/// version, but V2/V3 slates explicitly exchange input features. Wallet slate
/// construction must retain that metadata until the transaction is serialized
/// for the node. The transaction must use `Inputs::FeaturesAndCommit`.
pub fn feature_input<K, B>(
	value: u64,
	features: OutputFeatures,
	key_id: Identifier,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(move |build, acc| -> Result<(_, BlindSum), Error> {
		let (tx, sum) = acc?;
		let commit =
			build
				.keychain
				.commit(build.secp, value, &key_id, SwitchCommitmentType::Regular)?;
		let input = Input::new(features, commit);
		let value_path = key_id.to_value_path(value).map_err(|e| {
			Error::Other(format!(
				"Unable to build a feature-preserving input key: {}",
				e
			))
		})?;
		Ok((
			tx.with_input(build.context_id, input)?,
			sum.sub_key_id(value_path),
		))
	})
}

/// Build an output whose proof message carries the historical anti-replay
/// height without making that height part of the BIP32 derivation path.
pub fn height_tagged_output<K, B>(value: u64, key_id: Identifier, height: u64) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(move |build, acc| {
		let (tx, sum) = acc?;
		let (commit, rangeproof) = proof::height_tagged_rangeproof(
			build.secp,
			build.keychain,
			build.builder,
			value,
			&key_id,
			height,
		)?;

		Ok((
			tx.with_output(
				build.context_id,
				Output::new(OutputFeatures::Plain, commit, rangeproof),
			)?,
			sum.add_key_id(key_id.to_value_path(value)?),
		))
	})
}

/// Adds a known excess value on the transaction being built. Usually used in
/// combination with the initial_tx function when a new transaction is built
/// by adding to a pre-existing one.
pub fn with_excess<K, B>(excess: BlindingFactor) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, acc| -> Result<(Transaction, BlindSum), Error> {
			acc.map(|(tx, sum)| (tx, sum.add_blinding_factor(excess.clone())))
		},
	)
}

/// Sets an initial transaction to add to when building a new transaction.
pub fn initial_tx<K, B>(tx: Transaction) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, acc| -> Result<(Transaction, BlindSum), Error> {
			acc.map(|(_, sum)| (tx.clone(), sum))
		},
	)
}

/// Takes an existing transaction and partially builds on it.
///
/// Example:
/// let (tx, sum) = build::transaction(tx, vec![input_rand(4), output_rand(1))], keychain)?;
///
pub fn partial_transaction<K, B>(
	context_id: u32,
	secp: &mut Secp256k1,
	tx: Transaction,
	elems: &[Box<Append<K, B>>],
	keychain: &K,
	builder: &B,
) -> Result<(Transaction, BlindingFactor), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context {
		keychain,
		builder,
		secp,
		context_id,
	};
	let (tx, sum) = elems
		.iter()
		.fold(Ok((tx, BlindSum::new())), |acc, elem| elem(&mut ctx, acc))?;
	let blind_sum = ctx.keychain.blind_sum(ctx.secp, &sum)?;

	// Zero blinding sum is not accepted by consensus and safety rules
	if blind_sum.is_zero() {
		return Err(Error::ZeroBlindingSum);
	}

	Ok((tx, blind_sum))
}

/// Builds a complete transaction.
/// NOTE: We only use this in tests (for convenience).
/// In the real world we use signature aggregation across multiple participants.
pub fn transaction<K, B>(
	context_id: u32,
	secp: &mut Secp256k1,
	features: KernelFeatures,
	elems: &[Box<Append<K, B>>],
	keychain: &K,
	builder: &B,
) -> Result<Transaction, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut kernel = TxKernel::with_features(features)?;

	// Construct the message to be signed.
	let msg = kernel.msg_to_sign(context_id)?;

	// Generate kernel public excess and associated signature.
	let excess = BlindingFactor::rand(secp)?;
	let skey = excess.secret_key(secp)?;
	kernel.excess = secp.commit(0, skey)?;
	let pubkey = &kernel.excess.to_pubkey(secp)?;
	kernel.excess_sig = aggsig::sign_with_blinding(secp, &msg, &excess, &pubkey)?;
	kernel.verify(context_id, secp)?;
	transaction_with_kernel(context_id, secp, elems, kernel, excess, keychain, builder)
}

/// Build a complete transaction with the provided kernel and corresponding private excess.
/// NOTE: Only used in tests (for convenience).
/// Cannot recommend passing private excess around like this in the real world.
pub fn transaction_with_kernel<K, B>(
	context_id: u32,
	secp: &mut Secp256k1,
	elems: &[Box<Append<K, B>>],
	kernel: TxKernel,
	excess: BlindingFactor,
	keychain: &K,
	builder: &B,
) -> Result<Transaction, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context {
		keychain,
		builder,
		secp,
		context_id,
	};
	let mut tx = Transaction::empty();
	// Keep input features while building, as wallet slates do. Wire
	// serialization can explicitly convert to commitment-only inputs later.
	tx.body.inputs = Inputs::FeaturesAndCommit(vec![]);
	let (tx, sum) = elems
		.iter()
		.fold(Ok((tx, BlindSum::new())), |acc, elem| elem(&mut ctx, acc))?;
	let blind_sum = ctx.keychain.blind_sum(ctx.secp, &sum)?;
	// Zero blinding sum is not accepted by consensus and safety rules
	if blind_sum.is_zero() {
		return Err(Error::ZeroBlindingSum);
	}

	// Update tx with new kernel and offset.
	let mut tx = tx.replace_kernel(kernel);
	tx.offset = blind_sum.split(&excess, secp)?;
	Ok(tx)
}

// Just a simple test, most exhaustive tests in the core.
#[cfg(test)]
mod test {
	use super::*;
	use crate::core::transaction::Weighting;
	use crate::global;
	use crate::libtx::ProofBuilder;
	use keychain::{ExtKeychain, ExtKeychainPath};
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::secp::{ContextFlag, SecretKey};
	use std::convert::TryInto;

	#[test]
	fn blind_simple_tx() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = ProofBuilder::new(&mut secp, &keychain).unwrap();
		let key_id1 = ExtKeychainPath::new(3, 0, 0, 1, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id2 = ExtKeychainPath::new(3, 0, 0, 2, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id3 = ExtKeychainPath::new(3, 0, 0, 3, 0)
			.unwrap()
			.to_identifier()
			.unwrap();

		let tx = transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 2u32.try_into().unwrap(),
			},
			&[
				feature_input(10, OutputFeatures::Plain, key_id1),
				feature_input(12, OutputFeatures::Plain, key_id2),
				height_tagged_output(20, key_id3, 1),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(0, Weighting::AsTransaction, &mut secp).unwrap();
	}

	#[test]
	fn blind_simple_tx_with_offset() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let key_id1 = ExtKeychainPath::new(3, 0, 0, 1, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id2 = ExtKeychainPath::new(3, 0, 0, 2, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id3 = ExtKeychainPath::new(3, 0, 0, 3, 0)
			.unwrap()
			.to_identifier()
			.unwrap();

		let tx = transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 2u32.try_into().unwrap(),
			},
			&[
				feature_input(10, OutputFeatures::Plain, key_id1),
				feature_input(12, OutputFeatures::Plain, key_id2),
				height_tagged_output(20, key_id3, 1),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(0, Weighting::AsTransaction, &mut secp).unwrap();
	}

	#[test]
	fn blind_simpler_tx() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let key_id1 = ExtKeychainPath::new(3, 0, 0, 1, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let key_id2 = ExtKeychainPath::new(3, 0, 0, 2, 0)
			.unwrap()
			.to_identifier()
			.unwrap();

		let tx = transaction(
			0,
			&mut secp,
			KernelFeatures::Plain {
				fee: 4u32.try_into().unwrap(),
			},
			&[
				feature_input(6, OutputFeatures::Plain, key_id1),
				height_tagged_output(2, key_id2, 1),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(0, Weighting::AsTransaction, &mut secp).unwrap();
	}
}
