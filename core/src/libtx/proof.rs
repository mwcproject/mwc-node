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

//! Rangeproof library functions

use crate::libtx::error::Error;
use crate::libtx::zeroizing_blake2b::zeroizing_blake2b;
use keychain::extkey_bip32::BIP32MwcHasher;
use keychain::{Identifier, Keychain, SwitchCommitmentType, ViewKey};
use mwc_crates::secp;
use mwc_crates::secp::key::SecretKey;
use mwc_crates::secp::pedersen::{Commitment, ProofMessage, RangeProof};
use mwc_crates::secp::Secp256k1;
use mwc_crates::zeroize::{Zeroize, Zeroizing};
use std::convert::TryFrom;

/// Create a bulletproof
pub fn create<K, B>(
	secp: &mut Secp256k1,
	k: &K,
	b: &B,
	amount: u64,
	key_id: &Identifier,
	switch: SwitchCommitmentType,
	commit: Commitment,
	extra_data: Option<Vec<u8>>,
) -> Result<RangeProof, Error>
where
	K: Keychain,
	B: ProofBuild,
{
	// TODO: proper support for different switch commitment schemes
	// The new bulletproof scheme encodes and decodes it, but
	// it is not supported at the wallet level (yet).
	let expected_commit = k.commit(secp, amount, key_id, switch)?;
	if commit != expected_commit {
		return Err(Error::RangeProof(format!(
			"Supplied commitment {:?} does not match computed commitment {:?}",
			commit, expected_commit
		)));
	}
	let skey = k.derive_key(secp, amount, key_id, switch)?;
	let rewind_nonce = b.rewind_nonce(secp, &commit)?;
	let private_nonce = b.private_nonce(secp, &commit)?;
	let message = b.proof_message(secp, key_id, switch)?;
	Ok(secp.bullet_proof(
		amount,
		skey,
		rewind_nonce,
		private_nonce,
		extra_data,
		Some(message),
	)?)
}

/// Verify a proof
pub fn verify(
	secp: &mut Secp256k1,
	commit: Commitment,
	proof: RangeProof,
	extra_data: Option<Vec<u8>>,
) -> Result<(), secp::Error> {
	let result = secp.verify_bullet_proof(commit, proof, extra_data);
	result.map(|_| ())
}

/// Rewind a rangeproof to retrieve the amount, derivation path and switch commitment type
pub fn rewind<B>(
	secp: &mut Secp256k1,
	b: &B,
	commit: Commitment,
	extra_data: Option<Vec<u8>>,
	proof: RangeProof,
) -> Result<Option<(u64, Identifier, SwitchCommitmentType)>, Error>
where
	B: ProofBuild,
{
	verify(secp, commit, proof, extra_data.clone())?;

	let nonce = b
		.rewind_nonce(secp, &commit)
		.map_err(|e| Error::RangeProof(format!("Unable rewind for commit {:?}, {}", commit, e)))?;
	let info = secp.rewind_bullet_proof(commit, nonce, None, extra_data, proof);
	let info = match info {
		Ok(i) => i,
		Err(secp::Error::InvalidRangeProof) => return Ok(None),
		Err(e) => return Err(e.into()),
	};
	let amount = info.value;
	let check = b
		.check_output(secp, &commit, amount, info.message)
		.map_err(|e| {
			Error::RangeProof(format!("Unable to check output for {:?}, {}", commit, e))
		})?;

	Ok(check.map(|(id, switch)| (amount, id, switch)))
}

/// Used for building proofs and checking if the output belongs to the wallet
pub trait ProofBuild {
	/// Create a BP nonce that will allow to rewind the derivation path and flags
	fn rewind_nonce(&self, secp: &Secp256k1, commit: &Commitment) -> Result<SecretKey, Error>;

	/// Create a BP nonce that blinds the private key
	fn private_nonce(&self, secp: &Secp256k1, commit: &Commitment) -> Result<SecretKey, Error>;

	/// Create a BP message
	fn proof_message(
		&self,
		secp: &Secp256k1,
		id: &Identifier,
		switch: SwitchCommitmentType,
	) -> Result<ProofMessage, Error>;

	/// Check if the output belongs to this keychain
	fn check_output(
		&self,
		secp: &Secp256k1,
		commit: &Commitment,
		amount: u64,
		message: ProofMessage,
	) -> Result<Option<(Identifier, SwitchCommitmentType)>, Error>;
}

/// The new, more flexible proof builder
pub struct ProofBuilder<'a, K>
where
	K: Keychain,
{
	keychain: &'a K,
	rewind_hash: Zeroizing<Vec<u8>>,
	private_hash: Zeroizing<Vec<u8>>,
}

impl<'a, K> ProofBuilder<'a, K>
where
	K: Keychain,
{
	/// Creates a new instance of this proof builder
	pub fn new(secp: &Secp256k1, keychain: &'a K) -> Result<Self, Error> {
		let private_root_key = keychain.derive_key(
			secp,
			0,
			&K::root_key_id().map_err(|e| Error::Other(format!("Unable to build a key, {}", e)))?,
			SwitchCommitmentType::None,
		)?;

		let private_hash = zeroizing_blake2b(32, &[], &private_root_key.0);

		let public_root_key = keychain
			.public_root_key(secp)
			.map_err(|e| Error::Other(format!("Unable to build a key, {}", e)))?
			.serialize_vec(secp, true)?;
		let rewind_hash = zeroizing_blake2b(32, &[], &public_root_key[..]);

		Ok(Self {
			keychain,
			rewind_hash,
			private_hash,
		})
	}

	fn nonce(
		&self,
		secp: &Secp256k1,
		commit: &Commitment,
		private: bool,
	) -> Result<SecretKey, Error> {
		let hash = if private {
			&self.private_hash
		} else {
			&self.rewind_hash
		};
		let nonce_bytes = zeroizing_blake2b(32, &commit.0, hash);
		SecretKey::from_slice(secp, nonce_bytes.as_slice()).map_err(|e| {
			Error::RangeProof(format!(
				"Unable to extract nonce from commit {:?}, {}",
				commit, e
			))
		})
	}
}

impl<'a, K> ProofBuild for ProofBuilder<'a, K>
where
	K: Keychain,
{
	fn rewind_nonce(&self, secp: &Secp256k1, commit: &Commitment) -> Result<SecretKey, Error> {
		self.nonce(secp, commit, false)
	}

	fn private_nonce(&self, secp: &Secp256k1, commit: &Commitment) -> Result<SecretKey, Error> {
		self.nonce(secp, commit, true)
	}

	/// Message bytes:
	///     0: reserved for future use
	///     1: wallet type (0 for standard)
	///     2: switch commitment type
	///     3: path depth
	///  4-19: derivation path
	fn proof_message(
		&self,
		_secp: &Secp256k1,
		id: &Identifier,
		switch: SwitchCommitmentType,
	) -> Result<ProofMessage, Error> {
		let mut msg = [0; 20];
		msg[2] = u8::from(switch);
		let id_bytes = id.to_bytes();
		msg[3..20].clone_from_slice(&id_bytes[..17]);
		Ok(ProofMessage::from_bytes(&msg)?)
	}

	fn check_output(
		&self,
		secp: &Secp256k1,
		commit: &Commitment,
		amount: u64,
		message: ProofMessage,
	) -> Result<Option<(Identifier, SwitchCommitmentType)>, Error> {
		if message.len() != 20 {
			return Ok(None);
		}
		let msg = message.as_bytes();
		let exp: [u8; 2] = [0; 2];
		if msg[..2] != exp {
			return Ok(None);
		}
		let switch = match SwitchCommitmentType::try_from(msg[2]) {
			Ok(s) => s,
			Err(_) => return Ok(None),
		};
		let depth = msg[3];
		if depth > 4 {
			return Ok(None);
		}
		let id = Identifier::from_serialized_path(depth, &msg[4..])?;

		let commit_exp = self.keychain.commit(secp, amount, &id, switch)?;
		if commit == &commit_exp {
			Ok(Some((id, switch)))
		} else {
			Ok(None)
		}
	}
}

impl<'a, K> Zeroize for ProofBuilder<'a, K>
where
	K: Keychain,
{
	fn zeroize(&mut self) {
		self.rewind_hash.zeroize();
		self.private_hash.zeroize();
	}
}

impl<'a, K> Drop for ProofBuilder<'a, K>
where
	K: Keychain,
{
	fn drop(&mut self) {
		self.zeroize();
	}
}

/// The legacy proof builder, used before the first hard fork
pub struct LegacyProofBuilder<'a, K>
where
	K: Keychain,
{
	keychain: &'a K,
	root_hash: Vec<u8>,
}

impl<'a, K> LegacyProofBuilder<'a, K>
where
	K: Keychain,
{
	/// Creates a new instance of this proof builder
	pub fn new(secp: &Secp256k1, keychain: &'a K) -> Result<Self, Error> {
		Ok(Self {
			keychain,
			root_hash: keychain
				.derive_key(
					secp,
					0,
					&K::root_key_id()
						.map_err(|e| Error::Other(format!("Unable to build a key, {}", e)))?,
					SwitchCommitmentType::Regular,
				)?
				.0
				.to_vec(),
		})
	}

	fn nonce(&self, secp: &Secp256k1, commit: &Commitment) -> Result<SecretKey, Error> {
		let nonce_bytes = zeroizing_blake2b(32, &commit.0, &self.root_hash);
		SecretKey::from_slice(secp, nonce_bytes.as_slice()).map_err(|e| {
			Error::RangeProof(format!(
				"Unable to extract nonce from commit {:?}, {}",
				commit, e
			))
		})
	}
}

impl<'a, K> ProofBuild for LegacyProofBuilder<'a, K>
where
	K: Keychain,
{
	fn rewind_nonce(&self, secp: &Secp256k1, commit: &Commitment) -> Result<SecretKey, Error> {
		self.nonce(secp, commit)
	}

	fn private_nonce(&self, secp: &Secp256k1, commit: &Commitment) -> Result<SecretKey, Error> {
		// Legacy proofs used the same nonce for rewind and private nonce. Keep this
		// behavior for compatibility with old pre-hard-fork outputs that wallets may
		// still need to scan and rewind; new outputs should use ProofBuilder.
		self.nonce(secp, commit)
	}

	/// Message bytes:
	///   0-3: 0
	///  4-19: derivation path
	/// All outputs with this scheme are assumed to use regular switch commitments
	fn proof_message(
		&self,
		_secp: &Secp256k1,
		id: &Identifier,
		_switch: SwitchCommitmentType,
	) -> Result<ProofMessage, Error> {
		let path = id.to_path()?;
		if path.depth != 3 {
			return Err(Error::RangeProof(format!(
				"Legacy rangeproof messages only support depth 3 identifiers, got depth {}",
				path.depth
			)));
		}

		let mut msg = [0; 20];
		let id_ser = id.serialize_path();
		msg[4..20].clone_from_slice(&id_ser[..16]);
		Ok(ProofMessage::from_bytes(&msg)?)
	}

	fn check_output(
		&self,
		secp: &Secp256k1,
		commit: &Commitment,
		amount: u64,
		message: ProofMessage,
	) -> Result<Option<(Identifier, SwitchCommitmentType)>, Error> {
		if message.len() != 20 {
			return Ok(None);
		}

		let msg = message.as_bytes();
		let exp: [u8; 4] = [0; 4];
		if msg[..4] != exp {
			return Ok(None);
		}

		let id = Identifier::from_serialized_path(3, &msg[4..])?;
		let commit_exp = self
			.keychain
			.commit(secp, amount, &id, SwitchCommitmentType::Regular)?;
		if commit == &commit_exp {
			Ok(Some((id, SwitchCommitmentType::Regular)))
		} else {
			Ok(None)
		}
	}
}

impl<'a, K> Zeroize for LegacyProofBuilder<'a, K>
where
	K: Keychain,
{
	fn zeroize(&mut self) {
		self.root_hash.zeroize();
	}
}

impl<'a, K> Drop for LegacyProofBuilder<'a, K>
where
	K: Keychain,
{
	fn drop(&mut self) {
		self.zeroize();
	}
}

impl ProofBuild for ViewKey {
	fn rewind_nonce(&self, secp: &Secp256k1, commit: &Commitment) -> Result<SecretKey, Error> {
		let nonce_bytes = zeroizing_blake2b(32, &commit.0, &self.rewind_hash);
		SecretKey::from_slice(secp, nonce_bytes.as_slice()).map_err(|e| {
			Error::RangeProof(format!(
				"Unable to rewind nonce for commit {:?}, {}",
				commit, e
			))
		})
	}

	fn private_nonce(&self, _secp: &Secp256k1, _commit: &Commitment) -> Result<SecretKey, Error> {
		Err(Error::RangeProof(
			"ViewKey cannot create private rangeproof nonces".into(),
		))
	}

	fn proof_message(
		&self,
		_secp: &Secp256k1,
		_id: &Identifier,
		_switch: SwitchCommitmentType,
	) -> Result<ProofMessage, Error> {
		Err(Error::RangeProof(
			"ViewKey cannot create rangeproof messages".into(),
		))
	}

	fn check_output(
		&self,
		secp: &Secp256k1,
		commit: &Commitment,
		amount: u64,
		message: ProofMessage,
	) -> Result<Option<(Identifier, SwitchCommitmentType)>, Error> {
		if message.len() != 20 {
			return Ok(None);
		}
		let msg = message.as_bytes();
		let exp: [u8; 2] = [0; 2];
		if msg[..2] != exp {
			return Ok(None);
		}
		let switch = match SwitchCommitmentType::try_from(msg[2]) {
			Ok(s) => s,
			Err(_) => return Ok(None),
		};
		let depth = msg[3];
		if depth > 4 {
			return Ok(None);
		}
		let id = match Identifier::from_serialized_path(depth, &msg[4..]) {
			Ok(id) => id,
			Err(_) => return Ok(None),
		};

		let path = match id.to_path() {
			Ok(path) => path,
			Err(_) => return Ok(None),
		};
		if self.depth() > path.depth {
			return Ok(None);
		}

		for (idx, child_number) in self.path().iter().enumerate() {
			if path.path[idx] != *child_number {
				return Ok(None);
			}
		}

		let mut key = self.clone();
		let mut hasher = BIP32MwcHasher::new(self.is_floo);
		for i in self.depth()..path.depth {
			let child_number = path.path[i as usize];
			if child_number.is_hardened() {
				return Ok(None);
			}
			key = key.ckd_pub(secp, &mut hasher, child_number)?;
		}
		let pub_key = key.commit(secp, amount, switch)?;
		if commit.to_pubkey(secp)? == pub_key {
			Ok(Some((id, switch)))
		} else {
			Ok(None)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use keychain::ChildNumber;
	use keychain::ExtKeychain;
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::rand::{rng, RngExt};
	use mwc_crates::secp::ContextFlag;

	fn proof_message_for(id: &Identifier, switch: SwitchCommitmentType) -> ProofMessage {
		let mut msg = [0; 20];
		msg[2] = switch as u8;
		let id_bytes = id.to_bytes();
		msg[3..20].clone_from_slice(&id_bytes[..17]);
		ProofMessage::from_bytes(&msg).unwrap()
	}

	#[test]
	fn legacy_builder() {
		let rng = &mut rng();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = LegacyProofBuilder::new(&secp, &keychain).unwrap();
		let amount = rng.random();
		let id =
			ExtKeychain::derive_key_id(3, rng.random(), rng.random(), rng.random(), 0).unwrap();
		let switch = SwitchCommitmentType::Regular;
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();
		let proof = create(
			&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
		)
		.unwrap();
		assert!(verify(&mut secp, commit, proof, None).is_ok());
		let rewind = rewind(&mut secp, &builder, commit, None, proof).unwrap();
		assert!(rewind.is_some());
		let (r_amount, r_id, r_switch) = rewind.unwrap();
		assert_eq!(r_amount, amount);
		assert_eq!(r_id, id);
		assert_eq!(r_switch, switch);
	}

	#[test]
	fn legacy_check_output_rejects_non_legacy_header_before_path_decode() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = LegacyProofBuilder::new(&secp, &keychain).unwrap();
		let amount = 5;
		let id = ExtKeychain::derive_key_id(3, 1, 2, 3, 0).unwrap();
		let commit = keychain
			.commit(&secp, amount, &id, SwitchCommitmentType::Regular)
			.unwrap();
		let mut msg = [0xff; 20];
		msg[..4].copy_from_slice(&[1, 2, 3, 4]);
		let message = ProofMessage::from_bytes(&msg).unwrap();

		let check = builder.check_output(&secp, &commit, amount, message);

		assert!(matches!(check, Ok(None)));
	}

	#[test]
	fn legacy_builder_rejects_non_depth_3_identifier() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = LegacyProofBuilder::new(&secp, &keychain).unwrap();
		let amount = 5;
		let id = ExtKeychain::derive_key_id(2, 1, 2, 0, 0).unwrap();
		let switch = SwitchCommitmentType::Regular;
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();

		let res = create(
			&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
		);

		assert!(matches!(
			res,
			Err(Error::RangeProof(msg)) if msg.contains("only support depth 3 identifiers")
		));
	}

	#[test]
	fn create_rejects_mismatched_commitment() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let amount = 5;
		let id = ExtKeychain::derive_key_id(3, 1, 2, 3, 0).unwrap();
		let switch = SwitchCommitmentType::Regular;
		let wrong_commit = keychain.commit(&secp, amount + 1, &id, switch).unwrap();

		let res = create(
			&mut secp,
			&keychain,
			&builder,
			amount,
			&id,
			switch,
			wrong_commit,
			None,
		);

		assert!(matches!(
			res,
			Err(Error::RangeProof(msg)) if msg.contains("does not match computed commitment")
		));
	}

	#[test]
	fn rewind_rejects_invalid_rangeproof() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let amount = 5;
		let id = ExtKeychain::derive_key_id(3, 1, 2, 3, 0).unwrap();
		let switch = SwitchCommitmentType::Regular;
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();

		let res = rewind(&mut secp, &builder, commit, None, RangeProof::zero());

		assert!(matches!(
			res,
			Err(Error::Secp(secp::Error::InvalidRangeProof))
		));
	}

	#[test]
	fn rewind_returns_none_for_valid_unowned_rangeproof() {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let other_keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let other_builder = ProofBuilder::new(&secp, &other_keychain).unwrap();
		let amount = 5;
		let id = ExtKeychain::derive_key_id(3, 1, 2, 3, 0).unwrap();
		let switch = SwitchCommitmentType::Regular;
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();
		let proof = create(
			&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
		)
		.unwrap();

		let rewind = rewind(&mut secp, &other_builder, commit, None, proof).unwrap();

		assert!(rewind.is_none());
	}

	#[test]
	fn check_output_rejects_invalid_path_depth() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let mut hasher = keychain.hasher();
		let view_key =
			ViewKey::create(&secp, keychain.master_key().unwrap(), &mut hasher, false).unwrap();
		let amount = 5;
		let id = ExtKeychain::derive_key_id(4, 1, 2, 3, 4).unwrap();
		let switch = SwitchCommitmentType::None;
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();
		let mut msg = [0; 20];
		msg[2] = switch as u8;
		let id_bytes = id.to_bytes();
		msg[3..20].clone_from_slice(&id_bytes[..17]);
		msg[3] = 5;
		let message = ProofMessage::from_bytes(&msg).unwrap();

		let builder_check = builder
			.check_output(&secp, &commit, amount, message.clone())
			.unwrap();
		let view_key_check = view_key
			.check_output(&secp, &commit, amount, message)
			.unwrap();

		assert!(builder_check.is_none());
		assert!(view_key_check.is_none());
	}

	#[test]
	fn view_key_check_output_rejects_malformed_path_data() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let mut hasher = keychain.hasher();
		let view_key =
			ViewKey::create(&secp, keychain.master_key().unwrap(), &mut hasher, false).unwrap();
		let amount = 5;
		let id = ExtKeychain::derive_key_id(2, 1, 2, 0, 0).unwrap();
		let switch = SwitchCommitmentType::None;
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();
		let mut message = proof_message_for(&id, switch).as_bytes().to_vec();
		message[12] = 1;
		let message = ProofMessage::from_bytes(&message).unwrap();

		let check = view_key
			.check_output(&secp, &commit, amount, message)
			.unwrap();

		assert!(check.is_none());
	}

	#[test]
	fn view_key_check_output_validates_full_prefix() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let mut hasher = keychain.hasher();
		let view_key = ViewKey::create(&secp, keychain.master_key().unwrap(), &mut hasher, false)
			.unwrap()
			.ckd_pub(
				&secp,
				&mut hasher,
				ChildNumber::from_normal_idx(10).unwrap(),
			)
			.unwrap()
			.ckd_pub(
				&secp,
				&mut hasher,
				ChildNumber::from_normal_idx(20).unwrap(),
			)
			.unwrap();
		let amount = 5;
		let switch = SwitchCommitmentType::None;
		let id = ExtKeychain::derive_key_id(3, 10, 20, 30, 0).unwrap();
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();

		let check = view_key
			.check_output(&secp, &commit, amount, proof_message_for(&id, switch))
			.unwrap();
		assert!(check.is_some());

		let id_with_wrong_ancestor = ExtKeychain::derive_key_id(3, 11, 20, 30, 0).unwrap();
		let check = view_key
			.check_output(
				&secp,
				&commit,
				amount,
				proof_message_for(&id_with_wrong_ancestor, switch),
			)
			.unwrap();

		assert!(check.is_none());
	}

	#[test]
	fn builder() {
		let rng = &mut rng();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let amount = rng.random();
		let id =
			ExtKeychain::derive_key_id(3, rng.random(), rng.random(), rng.random(), 0).unwrap();
		// With switch commitment
		let commit_a = {
			let switch = SwitchCommitmentType::Regular;
			let commit = keychain.commit(&secp, amount, &id, switch).unwrap();
			let proof = create(
				&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
			)
			.unwrap();
			assert!(verify(&mut secp, commit, proof, None).is_ok());
			let rewind = rewind(&mut secp, &builder, commit, None, proof).unwrap();
			assert!(rewind.is_some());
			let (r_amount, r_id, r_switch) = rewind.unwrap();
			assert_eq!(r_amount, amount);
			assert_eq!(r_id, id);
			assert_eq!(r_switch, switch);
			commit
		};
		// Without switch commitment
		let commit_b = {
			let switch = SwitchCommitmentType::None;
			let commit = keychain.commit(&secp, amount, &id, switch).unwrap();
			let proof = create(
				&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
			)
			.unwrap();
			assert!(verify(&mut secp, commit, proof, None).is_ok());
			let rewind = rewind(&mut secp, &builder, commit, None, proof).unwrap();
			assert!(rewind.is_some());
			let (r_amount, r_id, r_switch) = rewind.unwrap();
			assert_eq!(r_amount, amount);
			assert_eq!(r_id, id);
			assert_eq!(r_switch, switch);
			commit
		};
		// The resulting pedersen commitments should be different
		assert_ne!(commit_a, commit_b);
	}

	#[test]
	fn view_key_regular_switch() {
		let rng = &mut rng();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();

		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let mut hasher = keychain.hasher();
		let view_key =
			ViewKey::create(&secp, keychain.master_key().unwrap(), &mut hasher, false).unwrap();
		assert_eq!(builder.rewind_hash, view_key.rewind_hash);

		let amount = rng.random();
		let id = ExtKeychain::derive_key_id(
			3,
			rng.random::<u16>() as u32,
			rng.random::<u16>() as u32,
			rng.random::<u16>() as u32,
			0,
		)
		.unwrap();
		let switch = SwitchCommitmentType::Regular;
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();

		// Generate proof with ProofBuilder..
		let proof = create(
			&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
		)
		.unwrap();
		// ..and rewind with ViewKey
		let rewind = rewind(&mut secp, &view_key, commit, None, proof);

		assert!(rewind.is_ok());
		let rewind = rewind.unwrap();
		assert!(rewind.is_some());
		let (r_amount, r_id, r_switch) = rewind.unwrap();
		assert_eq!(r_amount, amount);
		assert_eq!(r_id, id);
		assert_eq!(r_switch, switch);
	}

	#[test]
	fn view_key_no_switch() {
		let rng = &mut rng();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();

		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let mut hasher = keychain.hasher();
		let view_key =
			ViewKey::create(&secp, keychain.master_key().unwrap(), &mut hasher, false).unwrap();
		assert_eq!(builder.rewind_hash, view_key.rewind_hash);

		let amount = rng.random();
		let id = ExtKeychain::derive_key_id(
			3,
			rng.random::<u16>() as u32,
			rng.random::<u16>() as u32,
			rng.random::<u16>() as u32,
			0,
		)
		.unwrap();
		let switch = SwitchCommitmentType::None;
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();

		// Generate proof with ProofBuilder..
		let proof = create(
			&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
		)
		.unwrap();
		// ..and rewind with ViewKey
		let rewind = rewind(&mut secp, &view_key, commit, None, proof);

		assert!(rewind.is_ok());
		let rewind = rewind.unwrap();
		assert!(rewind.is_some());
		let (r_amount, r_id, r_switch) = rewind.unwrap();
		assert_eq!(r_amount, amount);
		assert_eq!(r_id, id);
		assert_eq!(r_switch, switch);
	}

	#[test]
	fn view_key_hardened() {
		let rng = &mut rng();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();

		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let mut hasher = keychain.hasher();
		let view_key =
			ViewKey::create(&secp, keychain.master_key().unwrap(), &mut hasher, false).unwrap();
		assert_eq!(builder.rewind_hash, view_key.rewind_hash);

		let amount = rng.random();
		let id = ExtKeychain::derive_key_id(
			3,
			rng.random::<u16>() as u32,
			u32::max_value() - 2,
			rng.random::<u16>() as u32,
			0,
		)
		.unwrap();
		let switch = SwitchCommitmentType::None;
		let commit = keychain.commit(&secp, amount, &id, switch).unwrap();

		// Generate proof with ProofBuilder..
		let proof = create(
			&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
		)
		.unwrap();
		// ..and rewind with ViewKey
		let rewind = rewind(&mut secp, &view_key, commit, None, proof);

		assert!(rewind.is_ok());
		let rewind = rewind.unwrap();
		assert!(rewind.is_none());
	}

	#[test]
	fn view_key_child() {
		let rng = &mut rng();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();

		let builder = ProofBuilder::new(&secp, &keychain).unwrap();
		let mut hasher = keychain.hasher();
		let view_key =
			ViewKey::create(&secp, keychain.master_key().unwrap(), &mut hasher, false).unwrap();
		assert_eq!(builder.rewind_hash, view_key.rewind_hash);

		// Same child
		{
			let child_view_key = view_key
				.ckd_pub(
					&secp,
					&mut hasher,
					ChildNumber::from_normal_idx(10).unwrap(),
				)
				.unwrap();
			assert_eq!(child_view_key.depth(), 1);

			let amount = rng.random();
			let id = ExtKeychain::derive_key_id(
				3,
				10,
				rng.random::<u16>() as u32,
				rng.random::<u16>() as u32,
				0,
			)
			.unwrap();
			let switch = SwitchCommitmentType::None;
			let commit = keychain.commit(&secp, amount, &id, switch).unwrap();

			// Generate proof with ProofBuilder..
			let proof = create(
				&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
			)
			.unwrap();
			// ..and rewind with child ViewKey
			let rewind = rewind(&mut secp, &child_view_key, commit, None, proof);

			assert!(rewind.is_ok());
			let rewind = rewind.unwrap();
			assert!(rewind.is_some());
			let (r_amount, r_id, r_switch) = rewind.unwrap();
			assert_eq!(r_amount, amount);
			assert_eq!(r_id, id);
			assert_eq!(r_switch, switch);
		}

		// Different child
		{
			let child_view_key = view_key
				.ckd_pub(
					&secp,
					&mut hasher,
					ChildNumber::from_normal_idx(11).unwrap(),
				)
				.unwrap();
			assert_eq!(child_view_key.depth(), 1);

			let amount = rng.random();
			let id = ExtKeychain::derive_key_id(
				3,
				10,
				rng.random::<u16>() as u32,
				rng.random::<u16>() as u32,
				0,
			)
			.unwrap();
			let switch = SwitchCommitmentType::None;
			let commit = keychain.commit(&secp, amount, &id, switch).unwrap();

			// Generate proof with ProofBuilder..
			let proof = create(
				&mut secp, &keychain, &builder, amount, &id, switch, commit, None,
			)
			.unwrap();
			// ..and rewind with child ViewKey
			let rewind = rewind(&mut secp, &child_view_key, commit, None, proof);

			assert!(rewind.is_ok());
			let rewind = rewind.unwrap();
			assert!(rewind.is_none());
		}
	}
}
