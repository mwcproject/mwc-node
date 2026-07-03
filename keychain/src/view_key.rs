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

use super::extkey_bip32::{
	BIP32Hasher, ChainCode, ChildNumber, Error as BIP32Error, ExtendedPrivKey, ExtendedPubKey,
	Fingerprint,
};
use super::types::{Error, MAX_DEPTH_USIZE};
use crate::SwitchCommitmentType;
use mwc_crates::blake2_rfc::blake2b::blake2b;
use mwc_crates::byteorder::{BigEndian, ByteOrder};
use mwc_crates::digest::Digest;
use mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_crates::secp::pedersen::Commitment;
use mwc_crates::secp::Secp256k1;
use mwc_crates::sha2::Sha256;
use mwc_crates::zeroize::Zeroizing;
use std::convert::TryFrom;
/*const VERSION_FLOO_NS: [u8;4] = [0x03, 0x27, 0x3E, 0x4B];
const VERSION_FLOO: [u8;4]    = [0x03, 0x27, 0x3E, 0x4B];
const VERSION_MAIN_NS: [u8;4] = [0x03, 0x3C, 0x08, 0xDF];
const VERSION_MAIN: [u8;4]    = [0x03, 0x3C, 0x08, 0xDF];*/

/// Key that can be used to scan the chain for owned outputs
/// This is a public key, meaning it cannot be used to spend those outputs
/// Create root view keys with `ViewKey::create`; derive child view keys with
/// `ckd_pub` so the full path is tracked.
#[derive(Clone, PartialEq, Eq)]
pub struct ViewKey {
	/// Whether this view key is meant for floonet or not
	pub is_floo: bool,
	/// How many derivations this key is from the master (which is 0).
	/// Kept private so the tracked path length cannot be desynchronized.
	depth: u8,
	/// Fingerprint of the parent key
	parent_fingerprint: Fingerprint,
	/// Child number of the key used to derive from parent (0 for master)
	pub child_number: ChildNumber,
	/// Full derivation path from the root key to this view key.
	path: [ChildNumber; MAX_DEPTH_USIZE],
	/// Public key
	public_key: PublicKey,
	/// Switch public key, required to view outputs that use switch commitment
	switch_public_key: Option<PublicKey>,
	/// Chain code
	chain_code: ChainCode,
	/// Hash used to generate rewind nonce
	pub rewind_hash: Zeroizing<Vec<u8>>,
}

impl ::std::fmt::Debug for ViewKey {
	fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
		f.debug_struct("ViewKey")
			.field("is_floo", &self.is_floo)
			.field("depth", &self.depth)
			.field("parent_fingerprint", &self.parent_fingerprint)
			.field("child_number", &self.child_number)
			.field("path", &self.path())
			.field("public_key", &self.public_key)
			.field("switch_public_key", &self.switch_public_key)
			.field("chain_code", &self.chain_code)
			.field("rewind_hash", &"<redacted>")
			.finish()
	}
}

impl ViewKey {
	pub fn create<H>(
		secp: &Secp256k1,
		ext_key: &ExtendedPrivKey,
		hasher: &mut H,
		is_floo: bool,
	) -> Result<Self, Error>
	where
		H: BIP32Hasher,
	{
		let ExtendedPubKey {
			network: _,
			depth,
			parent_fingerprint,
			child_number,
			public_key,
			chain_code,
		} = ExtendedPubKey::from_private(secp, ext_key, hasher)?;
		// Extended keys only carry their depth and final child number. Start from
		// root here so child view keys can maintain a complete path via ckd_pub().
		if depth != 0 {
			return Err(Error::InvalidDepth(depth));
		}

		let mut switch_public_key = PublicKey::pub_j_raw();
		// Note, leak key-dependent information through timing or microarchitectural side channels is accepted here
		switch_public_key.mul_assign(secp, &ext_key.secret_key)?;
		let switch_public_key = Some(switch_public_key);

		let rewind_hash = Zeroizing::new(Self::rewind_hash(secp, public_key)?);

		Ok(Self {
			is_floo,
			depth,
			parent_fingerprint,
			child_number,
			path: [ChildNumber::Normal { index: 0 }; MAX_DEPTH_USIZE],
			public_key,
			switch_public_key,
			chain_code,
			rewind_hash,
		})
	}

	pub fn rewind_hash(secp: &Secp256k1, public_root_key: PublicKey) -> Result<Vec<u8>, Error> {
		let ser = public_root_key.serialize_vec(secp, true)?;
		Ok(blake2b(32, &[], &ser[..]).as_bytes().to_vec())
	}

	/// Returns how many derivations this key is from the master key.
	pub fn depth(&self) -> u8 {
		self.depth
	}

	/// Returns the tracked derivation path for this view key.
	pub fn path(&self) -> &[ChildNumber] {
		&self.path[..self.depth as usize]
	}

	fn ckd_pub_tweak<H>(
		&self,
		secp: &Secp256k1,
		hasher: &mut H,
		i: ChildNumber,
	) -> Result<(SecretKey, ChainCode), Error>
	where
		H: BIP32Hasher,
	{
		match i {
			ChildNumber::Hardened { .. } => Err(BIP32Error::CannotDeriveFromHardenedKey.into()),
			ChildNumber::Normal { index: n } => {
				ChildNumber::validate_index_range(n)?;
				hasher.init_sha512(&self.chain_code[..])?;
				hasher.append_sha512(&self.public_key.serialize_vec(secp, true)?[..])?;
				let mut be_n = [0; 4];
				BigEndian::write_u32(&mut be_n, n);
				hasher.append_sha512(&be_n)?;

				let result = hasher.result_sha512()?;

				let secret_key = SecretKey::from_slice(secp, &result[..32])?;
				let chain_code = ChainCode::try_from(&result[32..]).map_err(|e| {
					crate::extkey_bip32::Error::Generic(format!(
						"Unable to build ChainCode from sha512, {}",
						e
					))
				})?;
				Ok((secret_key, chain_code))
			}
		}
	}

	pub fn ckd_pub<H>(
		&self,
		secp: &Secp256k1,
		hasher: &mut H,
		i: ChildNumber,
	) -> Result<Self, Error>
	where
		H: BIP32Hasher,
	{
		let (secret_key, chain_code) = self.ckd_pub_tweak(secp, hasher, i)?;

		let mut public_key = self.public_key;
		public_key.add_exp_assign(secp, &secret_key)?;

		let switch_public_key = match &self.switch_public_key {
			Some(p) => {
				let mut j = PublicKey::pub_j_raw();
				// Note, can leak the chain-code-derived child tweak through timing or microarchitectural
				// side channels, it is accepted
				j.mul_assign(secp, &secret_key)?;
				Some(PublicKey::from_combination(secp, vec![p, &j])?)
			}
			None => None,
		};

		let depth = self
			.depth
			.checked_add(1)
			.ok_or_else(|| Error::InvalidDepth(self.depth))?;
		if usize::from(depth) > MAX_DEPTH_USIZE {
			return Err(Error::InvalidDepth(depth));
		}
		let mut path = self.path;
		path[self.depth as usize] = i;

		Ok(Self {
			is_floo: self.is_floo,
			depth,
			parent_fingerprint: self.fingerprint(secp, hasher)?,
			child_number: i,
			path,
			public_key,
			switch_public_key,
			chain_code,
			rewind_hash: self.rewind_hash.clone(),
		})
	}

	pub fn commit(
		&self,
		secp: &Secp256k1,
		amount: u64,
		switch: SwitchCommitmentType,
	) -> Result<PublicKey, Error> {
		let value_key = secp.commit_value(amount)?.to_pubkey(secp)?;
		let pub_key = PublicKey::from_combination(secp, vec![&self.public_key, &value_key])?;
		match switch {
			SwitchCommitmentType::None => Ok(pub_key),
			SwitchCommitmentType::Regular => {
				let switch_pub = self
					.switch_public_key
					.as_ref()
					.ok_or(Error::SwitchCommitment)?;
				let switch_ser = switch_pub.serialize_vec(secp, true)?;
				let base_commit = Commitment::from_pubkey(secp, &pub_key)?;

				let mut hasher = Sha256::new();
				hasher.update(base_commit.0);
				hasher.update(&switch_ser);
				let blind = SecretKey::from_slice(secp, hasher.finalize().as_slice())?;
				let mut pub_key = pub_key;
				pub_key.add_exp_assign(secp, &blind)?;

				Ok(pub_key)
			}
		}
	}

	fn identifier<H>(&self, secp: &Secp256k1, hasher: &mut H) -> Result<[u8; 20], Error>
	where
		H: BIP32Hasher,
	{
		let sha2_res = hasher.sha_256(&self.public_key.serialize_vec(secp, true)?[..]);
		Ok(hasher.ripemd_160(&sha2_res))
	}

	fn fingerprint<H>(&self, secp: &Secp256k1, hasher: &mut H) -> Result<Fingerprint, Error>
	where
		H: BIP32Hasher,
	{
		Ok(
			Fingerprint::try_from(&self.identifier(secp, hasher)?[0..4]).map_err(|e| {
				crate::extkey_bip32::Error::Generic(format!(
					"Unable to build Fingerprint from identifier, {}",
					e
				))
			})?,
		)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{ExtKeychain, Keychain};
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::secp::ContextFlag;

	#[test]
	fn view_key_debug_redacts_rewind_hash() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let mut hasher = keychain.hasher();
		let view_key =
			ViewKey::create(&secp, keychain.master_key().unwrap(), &mut hasher, false).unwrap();

		let debug = format!("{:?}", view_key);

		assert!(debug.contains("rewind_hash"));
		assert!(debug.contains("<redacted>"));
		assert!(!debug.contains(&format!("{:?}", view_key.rewind_hash.as_slice())));
	}

	#[test]
	fn view_key_regular_commit_matches_keychain_commit() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let mut hasher = keychain.hasher();
		let view_key =
			ViewKey::create(&secp, keychain.master_key().unwrap(), &mut hasher, false).unwrap();
		let amount = 5;
		let id = ExtKeychain::root_key_id().unwrap();
		let keychain_commit = keychain
			.commit(&secp, amount, &id, SwitchCommitmentType::Regular)
			.unwrap()
			.to_pubkey(&secp)
			.unwrap();

		let view_key_commit = view_key
			.commit(&secp, amount, SwitchCommitmentType::Regular)
			.unwrap();

		assert_eq!(view_key_commit, keychain_commit);
	}

	#[test]
	fn view_key_tracks_full_derived_path() {
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

		assert_eq!(
			view_key.path(),
			&[
				ChildNumber::from_normal_idx(10).unwrap(),
				ChildNumber::from_normal_idx(20).unwrap()
			]
		);
	}
}
