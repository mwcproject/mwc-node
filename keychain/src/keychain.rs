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

/// Implementation of the Keychain trait based on an extended key derivation
/// scheme.
use mwc_crates::blake2_rfc::blake2b::blake2b;

use crate::extkey_bip32::{
	BIP32MwcHasher, ChainCode, ExtendedPrivKey, ExtendedPubKey, Fingerprint,
};
use crate::types::{
	BlindSum, BlindingFactor, Error, ExtKeychainPath, Identifier, Keychain, SwitchCommitmentType,
};
use mwc_crates::secp;
use mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_crates::secp::pedersen::Commitment;
use mwc_crates::secp::{EcdsaSignature, Message, Secp256k1};
use mwc_crates::zeroize::Zeroizing;
use mwc_util::secp_static;
use std::convert::TryFrom;
use std::fmt;

#[derive(Clone)]
struct MaskedMasterKey {
	network: [u8; 4],
	depth: u8,
	parent_fingerprint: Fingerprint,
	child_number: crate::extkey_bip32::ChildNumber,
	chain_code: ChainCode,
	secret_key: Zeroizing<[u8; secp::constants::SECRET_KEY_SIZE]>,
	integrity_tag: [u8; 32],
}

impl MaskedMasterKey {
	fn from_master(master: &ExtendedPrivKey, mask: &SecretKey) -> Result<Self, Error> {
		Ok(Self {
			network: master.network,
			depth: master.depth,
			parent_fingerprint: master.parent_fingerprint,
			child_number: master.child_number,
			chain_code: master.chain_code,
			secret_key: Zeroizing::new(xor_secret_key_bytes(&master.secret_key.0, mask)),
			integrity_tag: master_key_integrity_tag(
				master.network,
				master.depth,
				master.parent_fingerprint,
				master.child_number,
				master.chain_code,
				&master.secret_key.0,
			)?,
		})
	}

	fn unmask(&self, secp: &Secp256k1, mask: &SecretKey) -> Result<ExtendedPrivKey, Error> {
		let unmasked_secret_key = xor_secret_key_bytes(self.secret_key.as_ref(), mask);
		let integrity_tag = master_key_integrity_tag(
			self.network,
			self.depth,
			self.parent_fingerprint,
			self.child_number,
			self.chain_code,
			&unmasked_secret_key,
		)?;
		if integrity_tag != self.integrity_tag {
			return Err(Error::InvalidMasterKeyMask);
		}
		Ok(ExtendedPrivKey {
			network: self.network,
			depth: self.depth,
			parent_fingerprint: self.parent_fingerprint,
			child_number: self.child_number,
			secret_key: SecretKey::from_slice(secp, &unmasked_secret_key)?,
			chain_code: self.chain_code,
		})
	}
}

impl fmt::Debug for MaskedMasterKey {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("MaskedMasterKey")
			.field("network", &self.network)
			.field("depth", &self.depth)
			.field("parent_fingerprint", &self.parent_fingerprint)
			.field("child_number", &self.child_number)
			.field("chain_code", &self.chain_code)
			.field("secret_key", &"<redacted>")
			.field("integrity_tag", &"<redacted>")
			.finish()
	}
}

fn master_key_integrity_tag(
	network: [u8; 4],
	depth: u8,
	parent_fingerprint: Fingerprint,
	child_number: crate::extkey_bip32::ChildNumber,
	chain_code: ChainCode,
	secret_key: &[u8],
) -> Result<[u8; 32], Error> {
	let mut data = Zeroizing::new(Vec::with_capacity(77));
	data.extend_from_slice(&network);
	data.push(depth);
	data.extend_from_slice(&parent_fingerprint[..]);
	data.extend_from_slice(&u32::try_from(child_number)?.to_be_bytes());
	data.extend_from_slice(&chain_code[..]);
	data.extend_from_slice(secret_key);
	let mut integrity_tag = [0u8; 32];
	integrity_tag.copy_from_slice(blake2b(32, &[], &data).as_bytes());
	Ok(integrity_tag)
}

#[derive(Clone, Debug)]
enum MasterKeyState {
	Unmasked(ExtendedPrivKey),
	Masked(MaskedMasterKey),
}

fn xor_secret_key_bytes(
	secret_key: &[u8],
	mask: &SecretKey,
) -> [u8; secp::constants::SECRET_KEY_SIZE] {
	let mut masked_secret_key = [0u8; secp::constants::SECRET_KEY_SIZE];
	for i in 0..secp::constants::SECRET_KEY_SIZE {
		masked_secret_key[i] = secret_key[i] ^ mask.0[i];
	}
	masked_secret_key
}

#[derive(Clone, Debug)]
pub struct ExtKeychain {
	master: MasterKeyState,
	hasher: BIP32MwcHasher,
}

impl ExtKeychain {
	// Note, ExtKeychain master_key marter key is using outside of mwc-node. The mwc-wallet is
	//  using it a lot. That is why we have to expose whole ExtendedPrivKey
	pub fn master_key(&self) -> Result<&ExtendedPrivKey, Error> {
		match &self.master {
			MasterKeyState::Unmasked(master) => Ok(master),
			MasterKeyState::Masked(_) => Err(Error::KeychainMasked),
		}
	}

	pub fn pub_root_key(&self, secp: &Secp256k1) -> Result<ExtendedPubKey, Error> {
		let master = self.master_key()?;
		Ok(ExtendedPubKey::from_private(secp, master, &self.hasher)?)
	}

	pub fn hasher(&self) -> BIP32MwcHasher {
		self.hasher.clone()
	}
}

impl Keychain for ExtKeychain {
	fn from_seed(secp: &Secp256k1, seed: &[u8], is_floo: bool) -> Result<ExtKeychain, Error> {
		let mut h = BIP32MwcHasher::new(is_floo);
		let master = ExtendedPrivKey::new_master(secp, &mut h, seed)?;
		let keychain = ExtKeychain {
			master: MasterKeyState::Unmasked(master),
			hasher: BIP32MwcHasher::new(is_floo),
		};
		Ok(keychain)
	}

	fn from_mnemonic(
		secp: &Secp256k1,
		word_list: &str,
		extension_word: &str,
		is_floo: bool,
	) -> Result<Self, Error> {
		let h = BIP32MwcHasher::new(is_floo);
		let master = ExtendedPrivKey::from_mnemonic(secp, word_list, extension_word, is_floo)?;
		let keychain = ExtKeychain {
			master: MasterKeyState::Unmasked(master),
			hasher: h,
		};
		Ok(keychain)
	}

	fn mask_master_key(&mut self, mask: &SecretKey) -> Result<(), Error> {
		let next_master = match &self.master {
			MasterKeyState::Unmasked(master) => {
				MasterKeyState::Masked(MaskedMasterKey::from_master(master, mask)?)
			}
			MasterKeyState::Masked(master) => {
				MasterKeyState::Unmasked(secp_static::with_none(Error::from, |secp| {
					master.unmask(secp, mask)
				})?)
			}
		};
		self.master = next_master;
		Ok(())
	}

	fn root_key_id() -> Result<Identifier, Error> {
		ExtKeychainPath::new(0, 0, 0, 0, 0)?.to_identifier()
	}

	fn derive_key_id(depth: u8, d1: u32, d2: u32, d3: u32, d4: u32) -> Result<Identifier, Error> {
		ExtKeychainPath::new(depth, d1, d2, d3, d4)?.to_identifier()
	}

	fn public_root_key(&self, secp: &Secp256k1) -> Result<PublicKey, Error> {
		let mut hasher = self.hasher.clone();
		let master = self.master_key()?;
		Ok(ExtendedPubKey::from_private(secp, &master, &mut hasher)?.public_key)
	}

	fn private_root_key(&self) -> Result<SecretKey, Error> {
		Ok(self.master_key()?.secret_key.clone())
	}

	fn derive_key(
		&self,
		secp: &Secp256k1,
		amount: u64,
		id: &Identifier,
		switch: SwitchCommitmentType,
	) -> Result<SecretKey, Error> {
		let mut h = self.hasher.clone();
		let p = id.to_path()?;
		let mut ext_key = self.master_key()?.clone();
		if p.depth as usize > crate::types::MAX_DEPTH_USIZE {
			return Err(Error::InvalidDepth(p.depth));
		}
		for i in 0..p.depth {
			ext_key = ext_key.ckd_priv(secp, &mut h, p.path[i as usize])?;
		}

		match switch {
			SwitchCommitmentType::Regular => Ok(secp.blind_switch(amount, ext_key.secret_key)?),
			SwitchCommitmentType::None => Ok(ext_key.secret_key),
		}
	}

	fn commit(
		&self,
		secp: &Secp256k1,
		amount: u64,
		id: &Identifier,
		switch: SwitchCommitmentType,
	) -> Result<Commitment, Error> {
		let key = self.derive_key(secp, amount, id, switch)?;
		let commit = secp.commit(amount, key)?;
		Ok(commit)
	}

	fn blind_sum(&self, secp: &Secp256k1, blind_sum: &BlindSum) -> Result<BlindingFactor, Error> {
		self.master_key()?;
		let pos_capacity = blind_sum
			.positive_key_ids
			.len()
			.checked_add(blind_sum.positive_blinding_factors.len())
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"ExtKeychain::blind_sum, positive_key_ids_len={} positive_blinding_factors_len={}",
					blind_sum.positive_key_ids.len(),
					blind_sum.positive_blinding_factors.len()
				))
			})?;
		let mut pos_keys = Vec::with_capacity(pos_capacity);
		for key in &blind_sum.positive_key_ids {
			let id = Identifier::from_path(&key.ext_keychain_path)?;
			pos_keys.push(self.derive_key(secp, key.value, &id, key.switch)?);
		}
		for blind in &blind_sum.positive_blinding_factors {
			pos_keys.push(blind.secret_key(secp)?);
		}

		let neg_capacity = blind_sum
			.negative_key_ids
			.len()
			.checked_add(blind_sum.negative_blinding_factors.len())
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"ExtKeychain::blind_sum, negative_key_ids_len={} negative_blinding_factors_len={}",
					blind_sum.negative_key_ids.len(),
					blind_sum.negative_blinding_factors.len()
				))
			})?;
		let mut neg_keys = Vec::with_capacity(neg_capacity);
		for key in &blind_sum.negative_key_ids {
			let id = Identifier::from_path(&key.ext_keychain_path)?;
			neg_keys.push(self.derive_key(secp, key.value, &id, key.switch)?);
		}
		for blind in &blind_sum.negative_blinding_factors {
			neg_keys.push(blind.secret_key(secp)?);
		}

		match secp.blind_sum(pos_keys, neg_keys) {
			Ok(sum) => Ok(BlindingFactor::from_secret_key(sum)),
			Err(secp::Error::ZeroSecretKey) => Ok(BlindingFactor::zero()),
			Err(e) => Err(e.into()),
		}
	}

	fn sign(
		&self,
		secp: &Secp256k1,
		msg: &Message,
		amount: u64,
		id: &Identifier,
		switch: SwitchCommitmentType,
	) -> Result<EcdsaSignature, Error> {
		let skey = self.derive_key(secp, amount, id, switch)?;
		let sig = secp.sign(msg, &skey)?;
		Ok(sig)
	}

	fn sign_with_blinding(
		&self,
		secp: &Secp256k1,
		msg: &Message,
		blinding: &BlindingFactor,
	) -> Result<EcdsaSignature, Error> {
		let skey = &blinding.secret_key(secp)?;
		let sig = secp.sign(msg, &skey)?;
		Ok(sig)
	}
}

#[cfg(test)]
mod test {
	use crate::keychain::ExtKeychain;
	use crate::types::{BlindSum, BlindingFactor, Error, ExtKeychainPath, Keychain};
	use crate::SwitchCommitmentType;
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::secp::key::SecretKey;
	use mwc_crates::secp::{ContextFlag, Message, Secp256k1};

	#[test]
	fn test_key_derivation() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let switch = SwitchCommitmentType::None;

		let path = ExtKeychainPath::new(1, 1, 0, 0, 0).unwrap();
		let key_id = path.to_identifier().unwrap();

		let msg_bytes = [0; 32];
		let msg = Message::from_slice(&msg_bytes[..]).unwrap();

		// now create a zero commitment using the key on the keychain associated with
		// the key_id
		let commit = keychain.commit(&secp, 0, &key_id, switch).unwrap();

		// now check we can use our key to verify a signature from this zero commitment
		let sig = keychain.sign(&secp, &msg, 0, &key_id, switch).unwrap();
		secp.verify_from_commit(&msg, &sig, &commit).unwrap();
	}

	#[test]
	fn masked_keychain_state() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let root_key_id = ExtKeychain::root_key_id().unwrap();
		let root_private = keychain.private_root_key().unwrap();
		let root_public = keychain.public_root_key(&secp).unwrap();
		let root_xpub = keychain.pub_root_key(&secp).unwrap();
		let mask = SecretKey::from_slice(
			&secp,
			&[
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 7,
			],
		)
		.unwrap();
		let wrong_mask = SecretKey::from_slice(
			&secp,
			&[
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 8,
			],
		)
		.unwrap();

		keychain.mask_master_key(&mask).unwrap();

		assert!(matches!(keychain.master_key(), Err(Error::KeychainMasked)));
		assert!(matches!(
			keychain.private_root_key(),
			Err(Error::KeychainMasked)
		));
		assert!(matches!(
			keychain.public_root_key(&secp),
			Err(Error::KeychainMasked)
		));
		assert!(matches!(
			keychain.pub_root_key(&secp),
			Err(Error::KeychainMasked)
		));
		assert!(matches!(
			keychain.derive_key(&secp, 0, &root_key_id, SwitchCommitmentType::None),
			Err(Error::KeychainMasked)
		));
		assert!(matches!(
			keychain.mask_master_key(&wrong_mask),
			Err(Error::InvalidMasterKeyMask)
		));
		assert!(matches!(keychain.master_key(), Err(Error::KeychainMasked)));

		keychain.mask_master_key(&mask).unwrap();

		assert_eq!(keychain.private_root_key().unwrap(), root_private);
		assert_eq!(keychain.public_root_key(&secp).unwrap(), root_public);
		assert_eq!(keychain.pub_root_key(&secp).unwrap(), root_xpub);
	}

	// We plan to "offset" the key used in the kernel commitment
	// so we are going to be doing some key addition/subtraction.
	// This test is mainly to demonstrate that idea that summing commitments
	// and summing the keys used to commit to 0 have the same result.
	#[test]
	fn secret_key_addition() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();

		let skey1 = SecretKey::from_slice(
			&secp,
			&[
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 1,
			],
		)
		.unwrap();

		let skey2 = SecretKey::from_slice(
			&secp,
			&[
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 2,
			],
		)
		.unwrap();

		// adding secret keys 1 and 2 to give secret key 3
		let mut skey3 = skey1.clone();
		skey3.add_assign(&secp, &skey2).unwrap();

		// create commitments for secret keys 1, 2 and 3
		// all committing to the value 0 (which is what we do for tx_kernels)
		let commit_1 = secp.commit(0, skey1.clone()).unwrap();
		let commit_2 = secp.commit(0, skey2.clone()).unwrap();
		let commit_3 = secp.commit(0, skey3.clone()).unwrap();

		// now sum commitments for keys 1 and 2
		let sum = secp.commit_sum(vec![commit_1, commit_2], vec![]).unwrap();

		// confirm the commitment for key 3 matches the sum of the commitments 1 and 2
		assert_eq!(sum, commit_3);

		// now check we can sum keys up using keychain.blind_sum()
		// in the same way (convenience function)
		assert_eq!(
			keychain
				.blind_sum(
					&secp,
					&BlindSum::new()
						.add_blinding_factor(BlindingFactor::from_secret_key(skey1))
						.add_blinding_factor(BlindingFactor::from_secret_key(skey2))
				)
				.unwrap(),
			BlindingFactor::from_secret_key(skey3),
		);
	}

	#[test]
	fn blind_sum_returns_zero_for_zero_result() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let skey = SecretKey::new(&secp, &mut SysRng).unwrap();
		let blind = BlindingFactor::from_secret_key(skey);

		let sum = keychain
			.blind_sum(
				&secp,
				&BlindSum::new()
					.add_blinding_factor(blind.clone())
					.sub_blinding_factor(blind),
			)
			.unwrap();
		assert_eq!(sum, BlindingFactor::zero());
	}

	#[test]
	fn blind_sum_supports_only_positive_values() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let skey1 = SecretKey::new(&secp, &mut SysRng).unwrap();
		let skey2 = SecretKey::new(&secp, &mut SysRng).unwrap();

		let expected = secp
			.blind_sum(vec![skey1.clone(), skey2.clone()], vec![])
			.unwrap();
		let sum = keychain
			.blind_sum(
				&secp,
				&BlindSum::new()
					.add_blinding_factor(BlindingFactor::from_secret_key(skey1))
					.add_blinding_factor(BlindingFactor::from_secret_key(skey2)),
			)
			.unwrap();
		assert_eq!(sum, BlindingFactor::from_secret_key(expected));
	}

	#[test]
	fn blind_sum_supports_only_negative_values() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let skey1 = SecretKey::new(&secp, &mut SysRng).unwrap();
		let skey2 = SecretKey::new(&secp, &mut SysRng).unwrap();

		let expected = secp
			.blind_sum(vec![], vec![skey1.clone(), skey2.clone()])
			.unwrap();
		let sum = keychain
			.blind_sum(
				&secp,
				&BlindSum::new()
					.sub_blinding_factor(BlindingFactor::from_secret_key(skey1))
					.sub_blinding_factor(BlindingFactor::from_secret_key(skey2)),
			)
			.unwrap();
		assert_eq!(sum, BlindingFactor::from_secret_key(expected));
	}
}
