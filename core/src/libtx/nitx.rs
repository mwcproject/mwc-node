//! Utility functions to build non-interactive transactions. Handles the blinding of
//! inputs and outputs, maintaining the sum of blinding factors, producing
//! the excess signature, etc.
//!
//! Example:
//! nitx::transaction(
//!   KernelFeatures::Plain{ fee: 2 },
//!   vec![
//!     input_rand(75),
//!     output_rand(42),
//!     output_rand(32),
//!   ],
//!   keychain,
//!   builder
//! )

use crate::core::hash::{Hash, Hashed};
use crate::core::{
	Input, InputProof, KernelFeatures, KernelProof, Output, OutputFeatures, Transaction, TxKernel,
};
use crate::libtx::proof::ProofBuild;
use crate::libtx::{aggsig, Error};
use keychain::{stealth, BlindSum, BlindingFactor, Identifier, Keychain, SwitchCommitmentType};
use stealth::StealthAddress;
use util::secp;
use util::secp::{Message, PublicKey, SecretKey};

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
}

/// Function type returned by the transaction combinators. Transforms a
/// (Transaction, BlindSum, BlindSum) tuple into another, given the provided context.
/// Will return an Err if something went wrong at any point during transaction building.
type Append<K, B> = dyn for<'a> Fn(
	&'a mut Context<'_, K, B>,
	Result<(Transaction, BlindSum, BlindSum), Error>,
) -> Result<(Transaction, BlindSum, BlindSum), Error>;

/// Adds an input with the provided value, excess key, and doubling key to the transaction
/// being built.
pub fn input<K, B>(
	output_id: Hash,
	value: u64,
	features: OutputFeatures,
	excess_key_id: Identifier,
	doubling_key_id: Identifier,
	spend_key: Option<SecretKey>,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum, BlindSum), Error> {
			if let Ok((tx, sum_excess, sum_stealth)) = acc {
				let doubling_key = build.keychain.derive_key(
					value,
					&doubling_key_id,
					SwitchCommitmentType::None,
				)?;
				let commit =
					build
						.keychain
						.commit(value, &excess_key_id, SwitchCommitmentType::Regular)?;
				let input_proof = if let Some(spend_key) = spend_key.as_ref() {
					let sig = aggsig::sign_dual_key(
						build.keychain.secp(),
						&Message::from_slice(output_id.to_vec().as_slice())?,
						&spend_key,
						&doubling_key,
					)?;
					Some(InputProof::new(
						output_id.clone(),
						PublicKey::from_secret_key(build.keychain.secp(), &spend_key)?,
						PublicKey::from_secret_key(build.keychain.secp(), &doubling_key)?,
						sig,
					))
				} else {
					None
				};

				let input = Input::new(features, commit, input_proof);
				Ok((
					tx.with_input(input),
					sum_excess.sub_key_id(excess_key_id.to_value_path(value)),
					sum_stealth.sub_blinding_factor(BlindingFactor::from_secret_key(doubling_key)),
				))
			} else {
				acc
			}
		},
	)
}

/// Adds an output for the provided receiver with the value and blinding key to the transaction
/// being built.
#[allow(non_snake_case)]
pub fn output<K, B>(
	value: u64,
	key_id: Identifier,
	receiver_addr: StealthAddress,
) -> Box<Append<K, B>>
where
	K: Keychain,
	B: ProofBuild,
{
	Box::new(
		move |build, acc| -> Result<(Transaction, BlindSum, BlindSum), Error> {
			let (tx, sum, stealth_sum) = acc?;

			let secp = build.keychain.secp();

			let r = build
				.keychain
				.derive_key(value, &key_id, SwitchCommitmentType::None)?;
			let ephemeral_pk = PublicKey::from_secret_key(secp, &r)?;

			// Calculate shared secrets (k,q)
			let (k, q) = receiver_addr.calc_shared_secrets(secp, &r)?;

			let blind = secp.blind_switch(value, q)?;
			let commit = secp.commit(value, blind.clone())?;

			debug!("Building output: {}, {:?}", value, commit);

			// Build rangeproof
			let rewind_nonce = build.builder.rewind_nonce(secp, &commit)?;
			let private_nonce = build.builder.private_nonce(secp, &commit)?;
			let message =
				build
					.builder
					.proof_message(secp, &key_id, SwitchCommitmentType::Regular)?;
			let proof = secp.bullet_proof(
				value,
				blind.clone(),
				rewind_nonce,
				private_nonce,
				None,
				Some(message),
			);

			let mut output_pk = receiver_addr.B;
			output_pk.add_exp_assign(secp, &k)?;

			// Sign (commit||proof||output_pk)
			let msg_hash = (commit, proof, output_pk.serialize_vec(true).to_vec()).hash();
			let msg = secp::Message::from_slice(&msg_hash.as_bytes())?;
			let sig = aggsig::sign_single(secp, &msg, &r, None, None)?;

			Ok((
				tx.with_output(Output::new_nitx(
					OutputFeatures::Plain,
					commit,
					proof,
					ephemeral_pk,
					output_pk,
					sig,
				)),
				sum.add_blinding_factor(BlindingFactor::from_secret_key(blind)),
				stealth_sum.add_blinding_factor(BlindingFactor::from_secret_key(r)),
			))
		},
	)
}

/// Builds a complete non-interactive transaction.
pub fn transaction<K, B>(
	features: KernelFeatures,
	elems: &[Box<Append<K, B>>],
	keychain: &K,
	builder: &B,
) -> Result<Transaction, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let mut kernel = TxKernel::with_features(features);

	// Construct the message to be signed.
	let msg = kernel.msg_to_sign()?;

	let mut ctx = Context { keychain, builder };
	let (tx, sum_excess, sum_stealth) = elems.iter().fold(
		Ok((Transaction::empty(), BlindSum::new(), BlindSum::new())),
		|acc, elem| elem(&mut ctx, acc),
	)?;

	let offset = BlindingFactor::rand();
	let stealth_offset = BlindingFactor::rand();

	// Generate kernel public excess and associated signature.
	let total_excess = keychain.blind_sum(&sum_excess)?;
	let kern_excess = total_excess.split(&offset)?;
	let key = kern_excess.secret_key()?;
	kernel.excess = keychain.secp().commit(0, key.clone())?;

	let total_stealth_excess = keychain.blind_sum(&sum_stealth)?;
	let kern_stealth_excess = total_stealth_excess.split(&stealth_offset)?;
	let stealth_key = kern_stealth_excess.secret_key()?;

	kernel.proof = KernelProof::NonInteractive {
		stealth_excess: keychain.secp().commit(0, stealth_key.clone())?,
		signature: aggsig::sign_dual_key(&keychain.secp(), &msg, &key, &stealth_key)?,
	};
	kernel.verify()?;

	// Update tx with new kernel and offset.
	let mut tx = tx.replace_kernel(kernel);
	tx.offset = offset;
	tx.stealth_offset = Some(stealth_offset);
	Ok(tx)
}

// Just a simple test, most exhaustive tests in the core.
#[cfg(test)]
mod test {
	use rand::distributions::Alphanumeric;
	use rand::{thread_rng, Rng};
	use std::sync::Arc;
	use util::RwLock;

	use super::*;
	use crate::core::hash::Hash;
	use crate::core::transaction::Weighting;
	use crate::core::verifier_cache::{LruVerifierCache, VerifierCache};
	use crate::global;
	use crate::libtx::ProofBuilder;
	use keychain::{ExtKeychain, ExtKeychainPath};

	fn verifier_cache() -> Arc<RwLock<dyn VerifierCache>> {
		Arc::new(RwLock::new(LruVerifierCache::new()))
	}

	fn rand_hash() -> Hash {
		let rnd: String = thread_rng().sample_iter(&Alphanumeric).take(32).collect();
		Hash::from_vec(rnd.as_bytes())
	}

	fn rand_sk() -> SecretKey {
		SecretKey::from_slice(rand_hash().as_bytes()).unwrap()
	}

	fn rand_pk() -> PublicKey {
		PublicKey::from_secret_key(&secp::Secp256k1::new(), &rand_sk()).unwrap()
	}

	#[test]
	fn build_simple_nitx() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let keychain = ExtKeychain::from_random_seed(false).unwrap();
		let builder = ProofBuilder::new(&keychain);
		let key_id1 = ExtKeychainPath::new(1, 1, 0, 0, 0).to_identifier();
		let key_id2 = ExtKeychainPath::new(1, 2, 0, 0, 0).to_identifier();
		let key_id3 = ExtKeychainPath::new(1, 3, 0, 0, 0).to_identifier();
		let key_id4 = ExtKeychainPath::new(1, 4, 0, 0, 0).to_identifier();
		let key_id5 = ExtKeychainPath::new(1, 5, 0, 0, 0).to_identifier();

		let vc = verifier_cache();

		let input1 = input(
			rand_hash(),
			10,
			OutputFeatures::Plain,
			key_id1,
			key_id2,
			Some(rand_sk()),
		);

		let input2 = input(
			rand_hash(),
			12,
			OutputFeatures::Plain,
			key_id3,
			key_id4,
			Some(rand_sk()),
		);

		let receiver_addr1 = StealthAddress {
			A: rand_pk(),
			B: rand_pk(),
		};
		let output1 = output(20, key_id5, receiver_addr1);

		let tx = transaction(
			KernelFeatures::Plain { fee: 2 },
			&[input1, input2, output1],
			&keychain,
			&builder,
		)
		.unwrap();

		tx.validate(Weighting::AsTransaction, vc.clone()).unwrap();
	}
}
