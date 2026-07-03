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

//! Aggregated Signature functions used in the creation of Mwc transactions.
//! This module interfaces into the underlying
//! [Rust Aggsig library](https://github.com/mimblewimble/rust-secp256k1-zkp/blob/master/src/aggsig.rs)

use crate::libtx::error::Error;
use keychain::{BlindingFactor, Identifier, Keychain, SwitchCommitmentType};
use mwc_crates::blake2_rfc::blake2b::Blake2b;
use mwc_crates::secp;
use mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_crates::secp::pedersen::Commitment;
use mwc_crates::secp::{aggsig, AggSigSignature, Message, Secp256k1};

/// Creates a new secure nonce (as a SecretKey), guaranteed to be usable during
/// aggsig creation.
///
/// # Arguments
///
/// * `secp` - A Secp256k1 Context initialized for Signing
///
/// # Example
///
/// ```
/// # extern crate mwc_core as core;
/// use core::libtx::aggsig;
/// use mwc_crates::secp::{ContextFlag, Secp256k1};
/// let secp = Secp256k1::with_caps(ContextFlag::SignOnly).unwrap();
/// let secret_nonce = aggsig::create_secnonce(&secp).unwrap();
/// ```
/// # Remarks
///
/// The resulting SecretKey is guaranteed to have Jacobi symbol 1.

pub fn create_secnonce(secp: &Secp256k1) -> Result<SecretKey, Error> {
	let nonce = aggsig::export_secnonce_single(secp)?;
	Ok(nonce)
}

/// Calculates a partial signature given the signer's secure key,
/// the sum of all public nonces and (optionally) the sum of all public keys.
///
/// # Arguments
///
/// * `secp` - A Secp256k1 Context initialized for Signing
/// * `sec_key` - The signer's secret key
/// * `sec_nonce` - The signer's secret nonce (the public version of which
/// was added to the `nonce_sum` total)
/// * `nonce_sum` - The sum of the public nonces of all signers participating
/// in the full signature. This value is encoded in e.
/// * `pubkey_sum` - The sum of the public keys of all signers participating
/// in the full signature. This value is encoded in e.
/// * `msg` - The message to sign.
///
/// # Example
///
/// ```
/// # extern crate mwc_core as core;
/// use core::libtx::aggsig;
/// use mwc_crates::rand::rng;
/// use mwc_crates::rand::rngs::SysRng;
/// use mwc_crates::secp::key::{PublicKey, SecretKey};
/// use mwc_crates::secp::{ContextFlag, Message, Secp256k1};
///
/// let secp = Secp256k1::with_caps(ContextFlag::SignOnly).unwrap();
/// let secret_nonce = aggsig::create_secnonce(&secp).unwrap();
/// let secret_key = SecretKey::new(&secp, &mut SysRng).unwrap();
/// let pub_nonce_sum = PublicKey::from_secret_key(&secp, &secret_nonce).unwrap();
/// // ... Add all other participating nonces
/// let pub_key_sum = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
/// // ... Add all other participating keys
/// let mut msg_bytes = [0; 32];
/// // ... Encode message
/// let message = Message::from_slice(&msg_bytes).unwrap();
/// let sig_part = aggsig::calculate_partial_sig(
///     &secp,
///     &secret_key,
///     &secret_nonce,
///     &pub_nonce_sum,
///     &pub_key_sum,
///     &message,
///).unwrap();
/// ```

pub fn calculate_partial_sig(
	secp: &Secp256k1,
	sec_key: &SecretKey,
	sec_nonce: &SecretKey,
	nonce_sum: &PublicKey,
	pubkey_sum: &PublicKey,
	msg: &secp::Message,
) -> Result<AggSigSignature, Error> {
	//Now calculate signature using message M=fee, nonce in e=nonce_sum
	let sig = aggsig::sign_single(
		secp,
		&msg,
		sec_key,
		Some(sec_nonce),
		None,
		Some(nonce_sum),
		pubkey_sum,
		Some(nonce_sum),
	)?;
	Ok(sig)
}

/// Verifies a partial signature from a public key. All nonce and public
/// key sum values must be identical to those provided in the call to
/// [`calculate_partial_sig`](fn.calculate_partial_sig.html). Returns
/// `Result::Ok` if the signature is valid, or a Signature
/// [ErrorKind](../enum.ErrorKind.html) otherwise
///
/// # Arguments
///
/// * `secp` - A Secp256k1 Context initialized for Validation
/// * `sig` - The signature to validate, created via a call to
/// [`calculate_partial_sig`](fn.calculate_partial_sig.html)
/// * `pub_nonce_sum` - The sum of the public nonces of all signers participating
/// in the full signature. This value is encoded in e.
/// * `pub_nonce` - The signer's individual public nonce contribution.
/// * `pubkey` - Corresponding Public Key of the private key used to sign the message.
/// * `pubkey_sum` - (Optional) The sum of the public keys of all signers participating
/// in the full signature. If included, this value is encoded in e.
/// * `msg` - The message to verify.
///
/// # Example
///
/// ```
/// # extern crate mwc_core as core;
/// use core::libtx::aggsig;
/// use mwc_crates::rand::rng;
/// use mwc_crates::rand::rngs::SysRng;
/// use mwc_crates::secp::key::{PublicKey, SecretKey};
/// use mwc_crates::secp::{ContextFlag, Message, Secp256k1};
///
/// let secp = Secp256k1::with_caps(ContextFlag::Full).unwrap();
/// let secret_nonce = aggsig::create_secnonce(&secp).unwrap();
/// let secret_key = SecretKey::new(&secp, &mut SysRng).unwrap();
/// let pub_nonce = PublicKey::from_secret_key(&secp, &secret_nonce).unwrap();
/// let pub_nonce_sum = pub_nonce.clone();
/// // ... Add all other participating nonces
/// let pub_key_sum = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
/// // ... Add all other participating keys
/// let mut msg_bytes = [0; 32];
/// // ... Encode message
/// let message = Message::from_slice(&msg_bytes).unwrap();
/// let sig_part = aggsig::calculate_partial_sig(
///     &secp,
///     &secret_key,
///     &secret_nonce,
///     &pub_nonce_sum,
///     &pub_key_sum,
///     &message,
///).unwrap();
///
/// // Now verify the signature, ensuring the same values used to create
/// // the signature are provided:
/// let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
///
/// let result = aggsig::verify_partial_sig(
///     &secp,
///     &sig_part,
///     &pub_nonce_sum,
///     &pub_nonce,
///     &public_key,
///     &pub_key_sum,
///     &message,
///);
/// ```

pub fn verify_partial_sig(
	secp: &Secp256k1,
	sig: &AggSigSignature,
	pub_nonce_sum: &PublicKey,
	pub_nonce: &PublicKey,
	pubkey: &PublicKey,
	pubkey_sum: &PublicKey,
	msg: &secp::Message,
) -> Result<(), Error> {
	let pub_nonce = pub_nonce.serialize_vec(secp, true)?;
	if sig.as_ref()[..32] != pub_nonce[1..33] {
		return Err(Error::Signature(
			"Signature public nonce does not match signer nonce".to_string(),
		));
	}

	if !verify_single(
		secp,
		sig,
		&msg,
		Some(&pub_nonce_sum),
		pubkey,
		pubkey_sum,
		true,
	)? {
		return Err(Error::Signature("Signature validation error".to_string()));
	}
	Ok(())
}

/// Creates a single-signer aggsig signature from a key id. Generally,
/// this function is used to create transaction kernel signatures for
/// coinbase outputs.
/// Returns `Ok(Signature)` if the signature is valid, or a Signature
/// [ErrorKind](../enum.ErrorKind.html) otherwise
///
/// # Arguments
///
/// * `secp` - A Secp256k1 Context initialized for Signing
/// * `k` - The Keychain implementation being used
/// * `msg` - The message to sign (fee|lockheight).
/// * `key_id` - The keychain key id corresponding to the private key
/// with which to sign the message
/// * `blind_sum` - (Optional) The sum of all blinding factors in the transaction
/// in the case of a coinbase transaction this will simply be the corresponding
/// public key.
///
/// # Example
///
/// ```
/// # extern crate mwc_core as core;
/// use core::consensus::reward;
/// use mwc_crates::secp::key::{PublicKey, SecretKey};
/// use mwc_crates::secp::{ContextFlag, Secp256k1};
/// use core::libtx::{aggsig, proof};
/// use core::core::transaction::KernelFeatures;
/// use core::core::{Output, OutputFeatures};
/// use keychain::{Keychain, ExtKeychain, SwitchCommitmentType};
/// use std::convert::TryInto;
/// use core::global;
/// use mwc_crates::rand::rngs::SysRng;
///
/// global::set_local_chain_type(global::ChainTypes::Floonet);
/// global::set_local_nrd_enabled(false);
/// let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
/// let keychain = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false).unwrap();
/// let fees = 10_000;
/// let value = reward(0, fees, 1).unwrap();
/// let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
/// let switch = SwitchCommitmentType::Regular;
/// let commit = keychain.commit(&secp, value, &key_id, switch).unwrap();
/// let builder = proof::ProofBuilder::new(&secp, &keychain).unwrap();
/// let proof = proof::create(&mut secp, &keychain, &builder, value, &key_id, switch, commit, None).unwrap();
/// let output = Output::new(OutputFeatures::Coinbase, commit, proof);
/// let height = 20;
/// let over_commit = secp.commit_value(reward(0, fees, height).unwrap()).unwrap();
/// let out_commit = output.commitment();
/// let features = KernelFeatures::HeightLocked{fee: 1u32.try_into().unwrap(), lock_height: height};
/// let msg = features.kernel_sig_msg(0).unwrap();
/// let excess = secp.commit_sum(vec![out_commit], vec![over_commit]).unwrap();
/// let pubkey = excess.to_pubkey(&secp).unwrap();
/// let sig = aggsig::sign_from_key_id(&secp, &keychain, &msg, value, &key_id, None, &pubkey).unwrap();
/// ```

pub fn sign_from_key_id<K>(
	secp: &Secp256k1,
	k: &K,
	msg: &Message,
	value: u64,
	key_id: &Identifier,
	s_nonce: Option<&SecretKey>,
	blind_sum: &PublicKey,
) -> Result<AggSigSignature, Error>
where
	K: Keychain,
{
	let skey = k.derive_key(secp, value, key_id, SwitchCommitmentType::Regular)?; // TODO: proper support for different switch commitment schemes
	let sig = aggsig::sign_single(secp, &msg, &skey, s_nonce, None, None, blind_sum, None)?;
	Ok(sig)
}

/// Simple verification a single signature from a commitment. The public
/// key used to verify the signature is derived from the commit.
/// Returns `Ok(())` if the signature is valid, or a Signature
/// [ErrorKind](../enum.ErrorKind.html) otherwise
///
/// # Arguments
///
/// * `secp` - A Secp256k1 Context initialized for Verification
/// * `sig` - The Signature to verify
/// * `msg` - The message to sign (fee|lockheight).
/// * `commit` - The commitment to verify. The actual public key used
/// during verification is derived from this commit.
///
/// # Example
///
/// ```
/// # extern crate mwc_core as core;
/// use core::consensus::reward;
/// use core::libtx::{aggsig, proof};
/// use mwc_crates::secp::key::{PublicKey, SecretKey};
/// use mwc_crates::secp::{ContextFlag, Secp256k1};
/// use core::core::transaction::KernelFeatures;
/// use core::core::{Output, OutputFeatures};
/// use keychain::{Keychain, ExtKeychain, SwitchCommitmentType};
/// use std::convert::TryInto;
/// use core::global;
/// use mwc_crates::rand::rngs::SysRng;
///
/// // Create signature
/// global::set_local_chain_type(global::ChainTypes::Floonet);
/// global::set_local_nrd_enabled(false);
/// let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
/// let keychain = ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false).unwrap();
/// let fees = 10_000;
/// let value = reward(0, fees, 1).unwrap();
/// let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
/// let switch = SwitchCommitmentType::Regular;
/// let commit = keychain.commit(&secp, value, &key_id, switch).unwrap();
/// let builder = proof::ProofBuilder::new(&secp, &keychain).unwrap();
/// let proof = proof::create(&mut secp, &keychain, &builder, value, &key_id, switch, commit, None).unwrap();
/// let output = Output::new(OutputFeatures::Coinbase, commit, proof);
/// let height = 20;
/// let over_commit = secp.commit_value(reward(0, fees, height).unwrap()).unwrap();
/// let out_commit = output.commitment();
/// let features = KernelFeatures::HeightLocked{fee: 1u32.try_into().unwrap(), lock_height: height};
/// let msg = features.kernel_sig_msg(0).unwrap();
/// let excess = secp.commit_sum(vec![out_commit], vec![over_commit]).unwrap();
/// let pubkey = excess.to_pubkey(&secp).unwrap();
/// let sig = aggsig::sign_from_key_id(&secp, &keychain, &msg, value, &key_id, None, &pubkey).unwrap();
///
/// // Verify the signature from the excess commit
/// let sig_verifies =
///     aggsig::verify_single_from_commit(&secp, &sig, &msg, &excess);
/// assert!(!sig_verifies.is_err());
/// ```

pub fn verify_single_from_commit(
	secp: &Secp256k1,
	sig: &AggSigSignature,
	msg: &Message,
	commit: &Commitment,
) -> Result<(), Error> {
	let pubkey = commit.to_pubkey(secp)?;
	if !verify_single(secp, sig, msg, None, &pubkey, &pubkey, false)? {
		return Err(Error::Signature("Signature validation error".to_string()));
	}
	Ok(())
}

/// Verifies a completed (summed) signature, which must include the message
/// and pubkey sum values that are used during signature creation time
/// to create 'e'
/// Returns `Ok(())` if the signature is valid, or a Signature
/// [ErrorKind](../enum.ErrorKind.html) otherwise
///
/// # Arguments
///
/// * `secp` - A Secp256k1 Context initialized for Verification
/// * `sig` - The Signature to verify
/// * `pubkey` - Corresponding Public Key of the private key used to sign the message.
/// * `pubkey_sum` - The sum of the public keys of all signers participating
/// in the full signature. This value is encoded in e and must be the same
/// value as when the signature was created to verify correctly. For single-key
/// signatures, this is the corresponding public key.
/// * `msg` - The message to verify (fee|lockheight).
///
/// # Example
///
/// ```
/// # extern crate mwc_core as core;
/// use core::libtx::aggsig;
/// use mwc_crates::rand::rng;
/// use mwc_crates::rand::rngs::SysRng;
/// use mwc_crates::secp::key::{PublicKey, SecretKey};
/// use mwc_crates::secp::{ContextFlag, Message, Secp256k1};
///
/// let secp = Secp256k1::with_caps(ContextFlag::Full).unwrap();
/// let secret_nonce = aggsig::create_secnonce(&secp).unwrap();
/// let secret_key = SecretKey::new(&secp, &mut SysRng).unwrap();
/// let pub_nonce_sum = PublicKey::from_secret_key(&secp, &secret_nonce).unwrap();
/// // ... Add all other participating nonces
/// let pub_key_sum = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
/// // ... Add all other participating keys
/// let mut msg_bytes = [0; 32];
/// // ... Encode message
/// let message = Message::from_slice(&msg_bytes).unwrap();
/// let sig_part = aggsig::calculate_partial_sig(
///     &secp,
///     &secret_key,
///     &secret_nonce,
///     &pub_nonce_sum,
///     &pub_key_sum,
///     &message,
/// ).unwrap();
/// // ... Verify above, once all signatures have been added together
/// let sig_verifies = aggsig::verify_completed_sig(
///     &secp,
///     &sig_part,
///     &pub_key_sum,
///     &pub_key_sum,
///     &message,
///     );
/// assert!(!sig_verifies.is_err());
/// ```

pub fn verify_completed_sig(
	secp: &Secp256k1,
	sig: &AggSigSignature,
	pubkey: &PublicKey,
	pubkey_sum: &PublicKey,
	msg: &secp::Message,
) -> Result<(), Error> {
	if !verify_single(secp, sig, msg, None, pubkey, pubkey_sum, false)? {
		return Err(Error::Signature("Signature validation error".to_string()));
	}
	Ok(())
}

/// Adds signatures
pub fn add_signatures(
	secp: &Secp256k1,
	part_sigs: Vec<&AggSigSignature>,
	nonce_sum: &PublicKey,
) -> Result<AggSigSignature, Error> {
	// Add public nonces kR*G + kS*G
	let sig = aggsig::add_signatures_single(&secp, part_sigs, &nonce_sum)?;
	Ok(sig)
}

/// Subtract a partial signature from a completed signature
/// see https://github.com/mimblewimble/rust-secp256k1-zkp/blob/e9e4f09bd0c85da914774a52219457ba10ac3e57/src/aggsig.rs#L267
pub fn subtract_signature(
	secp: &Secp256k1,
	sig: &AggSigSignature,
	partial_sig: &AggSigSignature,
) -> Result<(AggSigSignature, Option<AggSigSignature>), Error> {
	let sig = aggsig::subtract_partial_signature(secp, sig, partial_sig)?;
	Ok(sig)
}
/// Just a simple sig, creates its own nonce if not provided.
///
/// `pubkey_sum` is always included in the Schnorr challenge. For single-key
/// signatures this is the public key corresponding to `skey`; for aggregate
/// signatures this is the aggregate public key.
pub fn sign_single(
	secp: &Secp256k1,
	msg: &Message,
	skey: &SecretKey,
	snonce: Option<&SecretKey>,
	pubkey_sum: &PublicKey,
) -> Result<AggSigSignature, Error> {
	let sig = aggsig::sign_single(secp, &msg, skey, snonce, None, None, pubkey_sum, None)?;
	Ok(sig)
}

/// Verifies an aggsig signature
pub fn verify_single(
	secp: &Secp256k1,
	sig: &AggSigSignature,
	msg: &Message,
	pubnonce: Option<&PublicKey>,
	pubkey: &PublicKey,
	pubkey_sum: &PublicKey,
	is_partial: bool,
) -> Result<bool, Error> {
	Ok(aggsig::verify_single(
		secp, sig, msg, pubnonce, pubkey, pubkey_sum, None, is_partial,
	)?)
}

/// Verify a batch of signatures.
pub fn verify_batch(
	secp: &Secp256k1,
	sigs: &Vec<AggSigSignature>,
	msgs: &Vec<Message>,
	pubkeys: &Vec<PublicKey>,
) -> Result<bool, Error> {
	Ok(aggsig::verify_batch(secp, sigs, msgs, pubkeys)?)
}

/// Just a simple sig, creates its own nonce, etc
pub fn sign_with_blinding(
	secp: &Secp256k1,
	msg: &Message,
	blinding: &BlindingFactor,
	pubkey_sum: &PublicKey,
) -> Result<AggSigSignature, Error> {
	if blinding.is_zero() {
		return Err(Error::Signature(
			"Cannot sign with zero blinding factor".to_string(),
		));
	}
	let skey = &blinding.secret_key(secp)?;
	let sig = aggsig::sign_single(secp, &msg, skey, None, None, None, pubkey_sum, None)?;
	Ok(sig)
}

/// A dual-key "batch" Schnorr signature.
pub struct BatchSignature(AggSigSignature);

fn dual_key_coefficient(
	secp: &Secp256k1,
	pk1: &PublicKey,
	pk2: &PublicKey,
) -> Result<SecretKey, Error> {
	let mut hasher = Blake2b::new(32);
	let pk1 = pk1.serialize_vec(secp, true)?;
	let pk2 = pk2.serialize_vec(secp, true)?;
	hasher.update(pk1.as_ref());
	hasher.update(pk2.as_ref());
	Ok(SecretKey::from_slice(secp, hasher.finalize().as_bytes())?)
}

/// Creates a "batch" Schnorr signature for two secret keys (sk1, sk2)
/// These are nothing more than regular schnorr signatures using a single
/// key (sk) that's calculated from sk1 and sk2 using the formula:
///
/// sk = sk1 + sk2 * blake2b(ser(pk1)||ser(pk2))
pub fn sign_dual_key(
	secp: &Secp256k1,
	msg: &Message,
	sk1: &SecretKey,
	sk2: &SecretKey,
) -> Result<BatchSignature, Error> {
	let pk1 = PublicKey::from_secret_key(&secp, &sk1)?;
	let pk2 = PublicKey::from_secret_key(&secp, &sk2)?;

	let mut sk = dual_key_coefficient(secp, &pk1, &pk2)?;
	sk.mul_assign(secp, &sk2)?;
	sk.add_assign(secp, &sk1)?;

	let pubkey = PublicKey::from_secret_key(&secp, &sk)?;
	let sig = sign_single(&secp, &msg, &sk, None, &pubkey)?;

	Ok(BatchSignature(sig))
}

/// Combines the two public keys of a "batch" signature into the composite
/// public key that the signature is verifiable against.
///
/// Returns pk = pk1 + pk2 * blake2b(ser(pk1)||ser(pk2))
pub fn build_composite_pubkey(
	secp: &Secp256k1,
	pk1: &PublicKey,
	pk2: &PublicKey,
) -> Result<PublicKey, Error> {
	let sk = dual_key_coefficient(secp, pk1, pk2)?;
	let mut pk = pk2.clone();
	pk.mul_assign(secp, &sk)?;
	let pubkey = PublicKey::from_combination(secp, vec![&pk1, &pk])?;

	Ok(pubkey)
}

/// Verifies a two-key "batch" Schnorr signature.
pub fn verify_dual_key(
	secp: &Secp256k1,
	msg: &Message,
	sig: &BatchSignature,
	pk1: &PublicKey,
	pk2: &PublicKey,
) -> Result<(), Error> {
	let pubkey = build_composite_pubkey(&secp, &pk1, &pk2)?;

	verify_completed_sig(&secp, &sig.0, &pubkey, &pubkey, &msg)
}

#[cfg(test)]
mod test {
	use super::*;
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::rand::TryRng;

	#[test]
	fn batch_signature() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();

		let mut msg_bytes = [0; 32];
		SysRng.try_fill_bytes(&mut msg_bytes).unwrap();
		let msg = Message::from_slice(&msg_bytes).unwrap();

		let sk1 = SecretKey::new(&secp, &mut SysRng).unwrap();
		let sk2 = SecretKey::new(&secp, &mut SysRng).unwrap();
		let batch_sig = sign_dual_key(&secp, &msg, &sk1, &sk2).unwrap();

		let pk1 = PublicKey::from_secret_key(&secp, &sk1).unwrap();
		let pk2 = PublicKey::from_secret_key(&secp, &sk2).unwrap();
		verify_dual_key(&secp, &msg, &batch_sig, &pk1, &pk2).unwrap();
	}

	#[test]
	fn composite_pubkey_uses_canonical_key_serialization() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Commit).unwrap();
		let sk1 = SecretKey::new(&secp, &mut SysRng).unwrap();
		let sk2 = SecretKey::new(&secp, &mut SysRng).unwrap();
		let pk1 = PublicKey::from_secret_key(&secp, &sk1).unwrap();
		let pk2 = PublicKey::from_secret_key(&secp, &sk2).unwrap();

		let pk1_ser = pk1.serialize_vec(&secp, true).unwrap();
		let pk2_ser = pk2.serialize_vec(&secp, true).unwrap();
		let mut hasher = Blake2b::new(32);
		hasher.update(pk1_ser.as_ref());
		hasher.update(pk2_ser.as_ref());
		let coeff = SecretKey::from_slice(&secp, hasher.finalize().as_bytes()).unwrap();
		let mut scaled_pk2 = pk2.clone();
		scaled_pk2.mul_assign(&secp, &coeff).unwrap();
		let expected = PublicKey::from_combination(&secp, vec![&pk1, &scaled_pk2]).unwrap();

		let actual = build_composite_pubkey(&secp, &pk1, &pk2).unwrap();

		assert_eq!(
			actual.serialize_vec(&secp, true).unwrap(),
			expected.serialize_vec(&secp, true).unwrap()
		);
	}

	#[test]
	fn sign_single_binds_public_key() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Full).unwrap();

		let mut msg_bytes = [0; 32];
		SysRng.try_fill_bytes(&mut msg_bytes).unwrap();
		let msg = Message::from_slice(&msg_bytes).unwrap();

		let secret_key = SecretKey::new(&secp, &mut SysRng).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		let sig = sign_single(&secp, &msg, &secret_key, None, &public_key).unwrap();

		verify_completed_sig(&secp, &sig, &public_key, &public_key, &msg).unwrap();
	}

	#[test]
	fn sign_with_blinding_rejects_zero_blinding_factor() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Full).unwrap();

		let mut msg_bytes = [0; 32];
		SysRng.try_fill_bytes(&mut msg_bytes).unwrap();
		let msg = Message::from_slice(&msg_bytes).unwrap();

		let secret_key = SecretKey::new(&secp, &mut SysRng).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();

		match sign_with_blinding(&secp, &msg, &BlindingFactor::zero(), &public_key) {
			Err(Error::Signature(msg)) => {
				assert!(msg.contains("zero blinding factor"));
			}
			other => panic!(
				"expected zero blinding factor signature error, got {:?}",
				other
			),
		}
	}

	#[test]
	fn verify_partial_sig_accepts_matching_signer_nonce() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Full).unwrap();

		let mut msg_bytes = [0; 32];
		SysRng.try_fill_bytes(&mut msg_bytes).unwrap();
		let msg = Message::from_slice(&msg_bytes).unwrap();

		let secret_key = SecretKey::new(&secp, &mut SysRng).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		let secret_nonce = create_secnonce(&secp).unwrap();
		let public_nonce = PublicKey::from_secret_key(&secp, &secret_nonce).unwrap();

		let sig = calculate_partial_sig(
			&secp,
			&secret_key,
			&secret_nonce,
			&public_nonce,
			&public_key,
			&msg,
		)
		.unwrap();

		verify_partial_sig(
			&secp,
			&sig,
			&public_nonce,
			&public_nonce,
			&public_key,
			&public_key,
			&msg,
		)
		.unwrap();
	}

	#[test]
	fn verify_partial_sig_rejects_mismatched_signer_nonce() {
		let secp = Secp256k1::with_caps(secp::ContextFlag::Full).unwrap();

		let mut msg_bytes = [0; 32];
		SysRng.try_fill_bytes(&mut msg_bytes).unwrap();
		let msg = Message::from_slice(&msg_bytes).unwrap();

		let secret_key = SecretKey::new(&secp, &mut SysRng).unwrap();
		let public_key = PublicKey::from_secret_key(&secp, &secret_key).unwrap();
		let advertised_secret_nonce = create_secnonce(&secp).unwrap();
		let advertised_public_nonce =
			PublicKey::from_secret_key(&secp, &advertised_secret_nonce).unwrap();
		let signing_secret_nonce = create_secnonce(&secp).unwrap();

		let sig = calculate_partial_sig(
			&secp,
			&secret_key,
			&signing_secret_nonce,
			&advertised_public_nonce,
			&public_key,
			&msg,
		)
		.unwrap();

		assert!(verify_single(
			&secp,
			&sig,
			&msg,
			Some(&advertised_public_nonce),
			&public_key,
			&public_key,
			true,
		)
		.unwrap());
		assert!(verify_partial_sig(
			&secp,
			&sig,
			&advertised_public_nonce,
			&advertised_public_nonce,
			&public_key,
			&public_key,
			&msg,
		)
		.is_err());
	}
}
