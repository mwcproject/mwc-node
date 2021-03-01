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

//! Utility functions to build non-interactive transactions. Handles the blinding of
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
//!   KernelFeatures::Plain{ fee: 2 },
//!   vec![
//!     input_rand(75),
//!     output_rand(42),
//!     output_rand(32),
//!   ]
//! )

use crate::address::Address;
use crate::core::{
	IdentifierWithRnp, Input, KernelFeatures, Output, OutputFeatures, OutputWithRnp, TransactionV4,
	TxKernel,
};
use crate::libtx::build::Context;
use crate::libtx::proof::{self, PaymentId, ProofBuild};
use crate::libtx::{aggsig, Error};
use keychain::{BlindSum, BlindingFactor, Identifier, Keychain, SwitchCommitmentType};
use util::secp::{PublicKey, SecretKey};

/// Function type returned by the transaction combinators. Transforms a
/// (TransactionV4, BlindSum) tuple into another, given the provided context.
/// Will return an Err if something went wrong at any point during transaction building.
pub type AppendV4<K, B> = dyn for<'a> Fn(
	&'a mut Context<'_, K, B>,
	Result<(TransactionV4, BlindSum), Error>,
) -> Result<(TransactionV4, BlindSum), Error>;

/// Adds an input with the provided value and blinding key to the transaction
/// being built.
fn build_input<K, B>(
	value: u64,
	features: OutputFeatures,
	key_id: Identifier,
) -> Box<AppendV4<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(TransactionV4, BlindSum), Error> {
			if let Ok((tx, sum)) = acc {
				let commit =
					build
						.keychain
						.commit(value, &key_id, SwitchCommitmentType::Regular)?;
				let input = Input::new(features, commit);
				Ok((
					tx.with_input(input),
					sum.sub_key_id(key_id.to_value_path(value)),
				))
			} else {
				acc
			}
		},
	)
}

/// Adds an input with the provided value and blinding key to the transaction
/// being built.
pub fn input<K, B>(value: u64, key_id: Identifier) -> Box<AppendV4<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	debug!(
		"Building input (spending regular output): {}, {}",
		value, key_id
	);
	build_input(value, OutputFeatures::Plain, key_id)
}

/// Adds a coinbase input spending a coinbase output.
pub fn coinbase_input<K, B>(value: u64, key_id: Identifier) -> Box<AppendV4<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	debug!("Building input (spending coinbase): {}, {}", value, key_id);
	build_input(value, OutputFeatures::Coinbase, key_id)
}

/// Adds an output (w/o R&P') with the provided value and key identifier from the
/// keychain.
pub fn output<K, B>(value: u64, key_id: Identifier) -> Box<AppendV4<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(TransactionV4, BlindSum), Error> {
			let (tx, sum) = acc?;

			let switch = SwitchCommitmentType::Regular;

			let commit = build.keychain.commit(value, &key_id, switch)?;

			debug!("Building output: {}, {:?}", value, commit);

			let proof = proof::create(
				build.keychain,
				build.builder,
				value,
				&key_id,
				switch,
				commit,
				None,
			)?;

			Ok((
				tx.with_output(Output::new(OutputFeatures::Plain, commit, proof)),
				sum.add_key_id(key_id.to_value_path(value)),
			))
		},
	)
}

/// Adds a NIT output (w/ R&P') with the provided value and key identifier from the keychain.
pub fn output_wrnp<K, B>(
	value: u64,
	private_nonce: SecretKey,
	recipient_address: Address,
	payment_id: PaymentId,
	timestamp: u64,
) -> Box<AppendV4<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(TransactionV4, BlindSum), Error> {
			let (tx, sum) = acc?;
			let switch = SwitchCommitmentType::Regular;
			let public_nonce = PublicKey::from_secret_key(build.keychain.secp(), &private_nonce)?;

			let (ephemeral_key_q, pp_apos) = recipient_address
				.get_ephemeral_key_for_tx(build.keychain.secp(), &private_nonce)?;
			let view_tag =
				recipient_address.get_view_tag_for_tx(build.keychain.secp(), &private_nonce)?;
			let commit = build
				.keychain
				.commit_with_key(value, ephemeral_key_q.clone(), switch)?;

			debug!(
				"Building NIT output: {}, {:?} for recipient: {}",
				value,
				commit,
				recipient_address.to_string()
			);

			let proof = proof::nit_create(
				build.keychain,
				build.builder,
				value,
				ephemeral_key_q.clone(),
				switch,
				commit,
				payment_id,
				timestamp,
				None,
			)?;

			// Calculate the actual blinding factor for commitment type of SwitchCommitmentType::Regular.
			let blind = match switch {
				SwitchCommitmentType::Regular => {
					build.keychain.secp().blind_switch(value, ephemeral_key_q)?
				}
				SwitchCommitmentType::None => ephemeral_key_q,
			};

			Ok((
				tx.with_output_wrnp(OutputWithRnp::new(
					IdentifierWithRnp::new(
						OutputFeatures::PlainWrnp,
						commit,
						public_nonce,
						pp_apos,
						view_tag,
					),
					proof,
				)),
				sum.add_blinding_factor(BlindingFactor::from_secret_key(blind)),
			))
		},
	)
}

/// Adds a known excess value on the transaction being built. Usually used in
/// combination with the initial_tx function when a new transaction is built
/// by adding to a pre-existing one.
pub fn with_excess<K, B>(excess: BlindingFactor) -> Box<AppendV4<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, acc| -> Result<(TransactionV4, BlindSum), Error> {
			acc.map(|(tx, sum)| (tx, sum.add_blinding_factor(excess.clone())))
		},
	)
}

/// Sets an initial transaction to add to when building a new transaction.
pub fn initial_tx<K, B>(tx: TransactionV4) -> Box<AppendV4<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |_build, acc| -> Result<(TransactionV4, BlindSum), Error> {
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
	tx: TransactionV4,
	elems: &[Box<AppendV4<K, B>>],
	keychain: &K,
	builder: &B,
) -> Result<(TransactionV4, BlindingFactor), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context { keychain, builder };
	let (tx, sum) = elems
		.iter()
		.fold(Ok((tx, BlindSum::new())), |acc, elem| elem(&mut ctx, acc))?;
	let blind_sum = ctx.keychain.blind_sum(&sum)?;
	Ok((tx, blind_sum))
}

/// Builds a complete transaction.
/// NOTE: We only use this in tests (for convenience).
/// In the real world we use signature aggregation across multiple participants.
pub fn transaction<K, B>(
	features: KernelFeatures,
	elems: &[Box<AppendV4<K, B>>],
	keychain: &K,
	builder: &B,
) -> Result<TransactionV4, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut kernel = TxKernel::with_features(features);

	// Construct the message to be signed.
	let msg = kernel.msg_to_sign()?;

	// Generate kernel public excess and associated signature.
	let excess = BlindingFactor::rand();
	let skey = excess.secret_key()?;
	kernel.excess = keychain.secp().commit(0, skey)?;
	let pubkey = &kernel.excess.to_pubkey()?;
	kernel.excess_sig = aggsig::sign_with_blinding(&keychain.secp(), &msg, &excess, Some(&pubkey))?;
	kernel.verify()?;
	transaction_with_kernel(elems, kernel, excess, keychain, builder)
}

/// Build a complete transaction with the provided kernel and corresponding private excess.
/// NOTE: Only used in tests (for convenience).
/// Cannot recommend passing private excess around like this in the real world.
pub fn transaction_with_kernel<K, B>(
	elems: &[Box<AppendV4<K, B>>],
	kernel: TxKernel,
	excess: BlindingFactor,
	keychain: &K,
	builder: &B,
) -> Result<TransactionV4, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut ctx = Context { keychain, builder };
	let (tx, sum) = elems.iter().fold(
		Ok((TransactionV4::empty(), BlindSum::new())),
		|acc, elem| elem(&mut ctx, acc),
	)?;
	let blind_sum = ctx.keychain.blind_sum(&sum)?;

	// Update tx with new kernel and offset.
	let mut tx = tx.replace_kernel(kernel);
	tx.offset = blind_sum.split(&excess)?;
	Ok(tx)
}

// Just a simple test, most exhaustive tests in the core.
#[cfg(test)]
mod test {
	use rand::thread_rng;
	use std::sync::Arc;
	use util::RwLock;

	use super::*;
	use crate::core::transaction::Weighting;
	use crate::core::verifier_cache::{LruVerifierCache, VerifierCache};
	use crate::core::TxImpl;
	use crate::global;
	use crate::libtx::ProofBuilder;
	use keychain::{ExtKeychain, ExtKeychainPath};

	fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
		Arc::new(RwLock::new(LruVerifierCache::new()))
	}

	#[test]
	fn it_2i1o() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
		let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

		let vc = verifier_cache();

		let tx = transaction(
			KernelFeatures::Plain { fee: 2 },
			&[input(10, key_id1), input(12, key_id2), output(20, key_id3)],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();
	}

	#[test]
	fn it_1i1o() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();

		let vc = verifier_cache();

		let tx = transaction(
			KernelFeatures::Plain { fee: 4 },
			&[input(6, key_id1), output(2, key_id2)],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();
	}

	#[test]
	fn nit_2i1o() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
		let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();

		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let payment_id = PaymentId::new();

		let (pri_nonce, _pub_nonce) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

		let vc = verifier_cache();

		let tx = transaction(
			KernelFeatures::Plain { fee: 2 },
			&[
				input(10, key_id1),
				input(12, key_id2),
				output(4, key_id3),
				output_wrnp(16, pri_nonce, recipient_addr, payment_id, 1),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();
	}

	#[test]
	fn nit_1i1o() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();

		let (_pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
		let recipient_addr =
			Address::from_one_pubkey(&pub_view, global::ChainTypes::AutomatedTesting);
		let payment_id = PaymentId::new();

		let (pri_nonce, _pub_nonce) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

		let vc = verifier_cache();

		let tx = transaction(
			KernelFeatures::Plain { fee: 2 },
			&[
				input(10, key_id1),
				output_wrnp(8, pri_nonce, recipient_addr, payment_id, 1),
			],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();
	}
}