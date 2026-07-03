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

// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//! Modified from above to integrate into mwc and allow for different
//! hashing algorithms if desired

use mwc_crates::serde::{self, Deserialize, Serialize};
use std::convert::TryFrom;
use std::default::Default;
use std::fmt;
use std::io::Cursor;
use std::str::FromStr;

use crate::mnemonic;
use mwc_crates::byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use mwc_crates::secp;
use mwc_crates::secp::key::{PublicKey, SecretKey};
use mwc_crates::secp::Secp256k1;

use mwc_crates::digest::Digest;
use mwc_crates::hmac::{digest::KeyInit, Hmac, Mac};
use mwc_crates::ripemd::Ripemd160;
use mwc_crates::sha2::{Sha256, Sha512};
use mwc_crates::zeroize::Zeroizing;
use mwc_util::{
	impl_array_newtype, impl_array_newtype_encodable, impl_array_newtype_show, impl_index_newtype,
	secp_static,
};

use crate::base58;

// Create alias for HMAC-SHA512
type HmacSha512 = Hmac<Sha512>;

/// A chain code
pub struct ChainCode([u8; 32]);
impl_array_newtype!(ChainCode, u8, 32);
impl_array_newtype_encodable!(ChainCode, u8, 32);

/// A fingerprint
pub struct Fingerprint([u8; 4]);
impl_array_newtype!(Fingerprint, u8, 4);
impl_array_newtype_show!(Fingerprint);
impl_array_newtype_encodable!(Fingerprint, u8, 4);

impl ::std::fmt::Debug for ChainCode {
	fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
		write!(f, "ChainCode(******)")
	}
}

impl Default for Fingerprint {
	fn default() -> Fingerprint {
		Fingerprint([0, 0, 0, 0])
	}
}

/// Allow different implementations of hash functions used in BIP32 Derivations
/// Mwc uses blake2 everywhere but the spec calls for SHA512/Ripemd160, so allow
/// this in future and allow us to unit test against published BIP32 test vectors
/// The function names refer to the place of the hash in the reference BIP32 spec,
/// not what the actual implementation is

pub trait BIP32Hasher {
	fn network_priv(&self) -> [u8; 4];
	fn network_pub(&self) -> [u8; 4];
	fn master_seed() -> [u8; 12];
	fn init_sha512(&mut self, seed: &[u8]) -> Result<(), Error>;
	fn append_sha512(&mut self, value: &[u8]) -> Result<(), Error>;
	fn result_sha512(&mut self) -> Result<[u8; 64], Error>;
	fn sha_256(&self, input: &[u8]) -> [u8; 32];
	fn ripemd_160(&self, input: &[u8]) -> [u8; 20];
}

/// Implementation of the above that uses the standard BIP32 Hash algorithms
#[derive(Clone)]
pub struct BIP32MwcHasher {
	is_floo: bool,
	hmac_sha512: Option<Hmac<Sha512>>,
}

impl fmt::Debug for BIP32MwcHasher {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("BIP32MwcHasher")
			.field("is_floo", &self.is_floo)
			// Hash internal is hidden because it might reveal secrets
			.field("hmac_sha512", &self.hmac_sha512.is_some())
			.finish()
	}
}

impl BIP32MwcHasher {
	/// New empty hasher
	pub fn new(is_floo: bool) -> BIP32MwcHasher {
		BIP32MwcHasher {
			is_floo: is_floo,
			hmac_sha512: None,
		}
	}
}

impl BIP32Hasher for BIP32MwcHasher {
	fn network_priv(&self) -> [u8; 4] {
		if self.is_floo {
			[0x03, 0x27, 0x3A, 0x10]
		} else {
			[0x03, 0x3C, 0x04, 0xA4]
		}
	}
	fn network_pub(&self) -> [u8; 4] {
		if self.is_floo {
			[0x03, 0x27, 0x3E, 0x4B]
		} else {
			[0x03, 0x3C, 0x08, 0xDF]
		}
	}
	fn master_seed() -> [u8; 12] {
		b"IamVoldemort".to_owned()
	}
	fn init_sha512(&mut self, seed: &[u8]) -> Result<(), Error> {
		self.hmac_sha512 = Some(
			HmacSha512::new_from_slice(seed)
				.map_err(|e| Error::Generic(format!("Unable init sha512 from seed, {}", e)))?,
		);
		Ok(())
	}
	fn append_sha512(&mut self, value: &[u8]) -> Result<(), Error> {
		let hmac_sha512 = self
			.hmac_sha512
			.as_mut()
			.ok_or_else(|| Error::Generic("sha512 is not initialized".into()))?;
		hmac_sha512.update(value);
		Ok(())
	}
	fn result_sha512(&mut self) -> Result<[u8; 64], Error> {
		let hmac_sha512 = self
			.hmac_sha512
			.take()
			.ok_or_else(|| Error::Generic("sha512 is not initialized".into()))?;
		let mac_output = hmac_sha512.finalize();
		let mut result = [0; 64];
		result.copy_from_slice(mac_output.as_bytes());
		Ok(result)
	}
	fn sha_256(&self, input: &[u8]) -> [u8; 32] {
		let mut sha2_res = [0; 32];
		let mut sha2 = Sha256::new();
		sha2.update(input);
		sha2_res.copy_from_slice(sha2.finalize().as_slice());
		sha2_res
	}
	fn ripemd_160(&self, input: &[u8]) -> [u8; 20] {
		let mut ripemd_res = [0; 20];
		let mut ripemd = Ripemd160::new();
		ripemd.update(input);
		ripemd_res.copy_from_slice(ripemd.finalize().as_slice());
		ripemd_res
	}
}

/// Extended private key
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExtendedPrivKey {
	/// The network this key is to be used on
	pub network: [u8; 4],
	/// How many derivations this key is from the master (which is 0)
	pub depth: u8,
	/// Fingerprint of the parent key (0 for master)
	pub parent_fingerprint: Fingerprint,
	/// Child number of the key used to derive from parent (0 for master)
	pub child_number: ChildNumber,
	/// Secret key
	pub secret_key: SecretKey,
	/// Chain code
	pub chain_code: ChainCode,
}

/// Extended public key
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ExtendedPubKey {
	/// The network this key is to be used on
	pub network: [u8; 4],
	/// How many derivations this key is from the master (which is 0)
	pub depth: u8,
	/// Fingerprint of the parent key
	pub parent_fingerprint: Fingerprint,
	/// Child number of the key used to derive from parent (0 for master)
	pub child_number: ChildNumber,
	/// Public key
	pub public_key: PublicKey,
	/// Chain code
	pub chain_code: ChainCode,
}

const CHILD_NUMBER_LIMIT: u32 = 1u32 << 31;

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ChildNumber {
	/// Non-hardened key
	Normal {
		/// Key index, within [0, 2^31 - 1]
		index: u32,
	},
	/// Hardened key
	Hardened {
		/// Key index, within [0, 2^31 - 1]
		index: u32,
	},
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "serde")]
enum ChildNumberSerde {
	Normal { index: u32 },
	Hardened { index: u32 },
}

impl ChildNumber {
	/// Create a [`Normal`] from an index, panics if the index is not within
	/// [0, 2^31 - 1].
	///
	/// [`Normal`]: #variant.Normal
	pub fn from_normal_idx(index: u32) -> Result<Self, Error> {
		Self::validate_index_range(index)?;
		Ok(ChildNumber::Normal { index: index })
	}

	/// Create a [`Hardened`] from an index, panics if the index is not within
	/// [0, 2^31 - 1].
	///
	/// [`Hardened`]: #variant.Hardened
	pub fn from_hardened_idx(index: u32) -> Result<Self, Error> {
		Self::validate_index_range(index)?;
		Ok(ChildNumber::Hardened { index: index })
	}

	/// Returns `true` if the child number is a [`Normal`] value.
	///
	/// [`Normal`]: #variant.Normal
	pub fn is_normal(self) -> bool {
		!self.is_hardened()
	}

	/// Returns `true` if the child number is a [`Hardened`] value.
	///
	/// [`Hardened`]: #variant.Hardened
	pub fn is_hardened(self) -> bool {
		match self {
			ChildNumber::Hardened { .. } => true,
			ChildNumber::Normal { .. } => false,
		}
	}

	pub(crate) fn validate_index_range(index: u32) -> Result<(), Error> {
		if index >= CHILD_NUMBER_LIMIT {
			Err(Error::ChildNumberOutOfRange)
		} else {
			Ok(())
		}
	}
}

impl Serialize for ChildNumber {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		let value = match *self {
			ChildNumber::Normal { index } => {
				Self::validate_index_range(index).map_err(serde::ser::Error::custom)?;
				ChildNumberSerde::Normal { index }
			}
			ChildNumber::Hardened { index } => {
				Self::validate_index_range(index).map_err(serde::ser::Error::custom)?;
				ChildNumberSerde::Hardened { index }
			}
		};

		value.serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for ChildNumber {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		match ChildNumberSerde::deserialize(deserializer)? {
			ChildNumberSerde::Normal { index } => {
				ChildNumber::from_normal_idx(index).map_err(serde::de::Error::custom)
			}
			ChildNumberSerde::Hardened { index } => {
				ChildNumber::from_hardened_idx(index).map_err(serde::de::Error::custom)
			}
		}
	}
}

impl From<u32> for ChildNumber {
	// Leading 1 bit define the type.
	fn from(number: u32) -> Self {
		if number & (1 << 31) != 0 {
			ChildNumber::Hardened {
				index: number ^ (1 << 31),
			}
		} else {
			ChildNumber::Normal { index: number }
		}
	}
}

impl TryFrom<ChildNumber> for u32 {
	type Error = Error;

	fn try_from(cnum: ChildNumber) -> Result<Self, Error> {
		// Leading 1 bit define the type.
		match cnum {
			ChildNumber::Normal { index } => {
				ChildNumber::validate_index_range(index)?;
				Ok(index)
			}
			ChildNumber::Hardened { index } => {
				ChildNumber::validate_index_range(index)?;
				Ok(index | (1u32 << 31))
			}
		}
	}
}

impl fmt::Display for ChildNumber {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			ChildNumber::Hardened { index } => write!(f, "{}'", index),
			ChildNumber::Normal { index } => write!(f, "{}", index),
		}
	}
}

/// A BIP32 error
#[derive(thiserror::Error, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum Error {
	/// A pk->pk derivation was attempted on a hardened key
	#[error("cannot derive hardened key from public key")]
	CannotDeriveFromHardenedKey,
	/// A secp256k1 error occured
	#[error("secp256k1 error {0}")]
	Ecdsa(secp::Error),
	/// Error creating a master seed --- for application use
	#[error("rng error {0}")]
	RngError(String),
	/// Error converting mnemonic to seed
	#[error("Mnemonic error, {0}")]
	MnemonicError(mnemonic::Error),
	/// Generic internal error
	#[error("{0}")]
	Generic(String),
	/// Data overflow error
	#[error("BIP32 data overflow error, {0}")]
	DataOverflow(String),
	/// Out of range child number value
	#[error("Child number out of range")]
	ChildNumberOutOfRange,
	/// Seed is too short
	#[error("Seed length is out of range: {0}")]
	SeedLengthOutOfRange(usize),
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Ecdsa(e)
	}
}

impl ExtendedPrivKey {
	/// Construct a new master key from a seed value
	pub fn new_master<H>(
		secp: &Secp256k1,
		hasher: &mut H,
		seed: &[u8],
	) -> Result<ExtendedPrivKey, Error>
	where
		H: BIP32Hasher,
	{
		if seed.len() < 16 || seed.len() > 64 {
			return Err(Error::SeedLengthOutOfRange(seed.len()));
		}

		hasher.init_sha512(&H::master_seed())?;
		hasher.append_sha512(seed)?;
		let result = Zeroizing::new(hasher.result_sha512()?);

		Ok(ExtendedPrivKey {
			network: hasher.network_priv(),
			depth: 0,
			parent_fingerprint: Default::default(),
			child_number: ChildNumber::from_normal_idx(0)?,
			secret_key: SecretKey::from_slice(secp, &result[..32]).map_err(Error::Ecdsa)?,
			chain_code: ChainCode::try_from(&result[32..]).map_err(|e| {
				Error::Generic(format!("Unable to build ChainCode from sha512, {}", e))
			})?,
		})
	}

	/// Construct a new master key from a mnemonic and a passphrase
	pub fn from_mnemonic(
		secp: &Secp256k1,
		mnemonic: &str,
		passphrase: &str,
		is_floo: bool,
	) -> Result<ExtendedPrivKey, Error> {
		let seed = mnemonic::to_seed(mnemonic, passphrase).map_err(Error::MnemonicError)?;
		let mut hasher = BIP32MwcHasher::new(is_floo);
		let key = ExtendedPrivKey::new_master(secp, &mut hasher, seed.as_ref())?;
		Ok(key)
	}

	/// Serialize as a Base58Check-encoded extended private key.
	pub fn to_base58(&self) -> Result<String, Error> {
		let child_number = u32::try_from(self.child_number)?;
		let mut ret = [0; 78];
		ret[0..4].copy_from_slice(&self.network[0..4]);
		ret[4] = self.depth;
		ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
		BigEndian::write_u32(&mut ret[9..13], child_number);
		ret[13..45].copy_from_slice(&self.chain_code[..]);
		ret[45] = 0;
		ret[46..78].copy_from_slice(&self.secret_key[..]);
		let res_str = base58::check_encode_slice(&ret[..])
			.map_err(|e| Error::Generic(format!("base58 encoding error, {}", e)))?;
		Ok(res_str)
	}

	/// Attempts to derive an extended private key from a path.
	pub fn derive_priv<H>(
		&self,
		secp: &Secp256k1,
		hasher: &mut H,
		cnums: &[ChildNumber],
	) -> Result<ExtendedPrivKey, Error>
	where
		H: BIP32Hasher,
	{
		let mut sk: ExtendedPrivKey = self.clone();
		for cnum in cnums {
			sk = sk.ckd_priv(secp, hasher, *cnum)?;
		}
		Ok(sk)
	}

	/// Private->Private child key derivation
	pub fn ckd_priv<H>(
		&self,
		secp: &Secp256k1,
		hasher: &mut H,
		i: ChildNumber,
	) -> Result<ExtendedPrivKey, Error>
	where
		H: BIP32Hasher,
	{
		let child_index = u32::try_from(i)?;
		hasher.init_sha512(&self.chain_code[..])?;
		let mut be_n = [0; 4];
		match i {
			ChildNumber::Normal { .. } => {
				// Non-hardened key: compute public data and use that
				hasher.append_sha512(
					&PublicKey::from_secret_key(secp, &self.secret_key)?
						.serialize_vec(secp, true)?[..],
				)?;
			}
			ChildNumber::Hardened { .. } => {
				// Hardened key: use only secret data to prevent public derivation
				hasher.append_sha512(&[0u8])?;
				hasher.append_sha512(&self.secret_key[..])?;
			}
		}
		BigEndian::write_u32(&mut be_n, child_index);

		hasher.append_sha512(&be_n)?;
		let result = Zeroizing::new(hasher.result_sha512()?);
		let mut sk = SecretKey::from_slice(secp, &result[..32]).map_err(Error::Ecdsa)?;
		sk.add_assign(secp, &self.secret_key)
			.map_err(Error::Ecdsa)?;

		let depth = self.depth.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("ExtendedPrivKey::ckd_priv, depth={}", self.depth))
		})?;

		Ok(ExtendedPrivKey {
			network: self.network,
			depth,
			parent_fingerprint: self.fingerprint(secp, hasher)?,
			child_number: i,
			secret_key: sk,
			chain_code: ChainCode::try_from(&result[32..]).map_err(|e| {
				Error::Generic(format!("Unable to build ChainCode from sha512, {}", e))
			})?,
		})
	}

	/// Returns the HASH160 of the chaincode
	pub fn identifier<H>(&self, secp: &Secp256k1, hasher: &mut H) -> Result<[u8; 20], Error>
	where
		H: BIP32Hasher,
	{
		// Compute extended public key
		let pk: ExtendedPubKey = ExtendedPubKey::from_private::<H>(&secp, self, hasher)?;
		// Do SHA256 of just the ECDSA pubkey
		let sha2_res = hasher.sha_256(&pk.public_key.serialize_vec(&secp, true)?[..]);
		// do RIPEMD160
		let res = hasher.ripemd_160(&sha2_res);
		Ok(res)
	}

	/// Returns the first four bytes of the identifier
	pub fn fingerprint<H>(&self, secp: &Secp256k1, hasher: &mut H) -> Result<Fingerprint, Error>
	where
		H: BIP32Hasher,
	{
		Ok(
			Fingerprint::try_from(&self.identifier(secp, hasher)?[0..4]).map_err(|e| {
				Error::Generic(format!(
					"Unable to build Fingerprint from identifier, {}",
					e
				))
			})?,
		)
	}
}

impl ExtendedPubKey {
	/// Derives a public key from a private key
	pub fn from_private<H>(
		secp: &Secp256k1,
		sk: &ExtendedPrivKey,
		hasher: &H,
	) -> Result<ExtendedPubKey, Error>
	where
		H: BIP32Hasher,
	{
		let public_key = PublicKey::from_secret_key(secp, &sk.secret_key)?;

		if sk.network != hasher.network_priv() {
			return Err(Error::Generic(
				"extended private key network does not match hasher".into(),
			));
		}

		Ok(ExtendedPubKey {
			network: hasher.network_pub(),
			depth: sk.depth,
			parent_fingerprint: sk.parent_fingerprint,
			child_number: sk.child_number,
			public_key,
			chain_code: sk.chain_code,
		})
	}

	/// Serialize as a Base58Check-encoded extended public key.
	pub fn to_base58(&self) -> Result<String, Error> {
		let child_number = u32::try_from(self.child_number)?;
		let mut ret = [0; 78];
		ret[0..4].copy_from_slice(&self.network[0..4]);
		ret[4] = self.depth;
		ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
		BigEndian::write_u32(&mut ret[9..13], child_number);
		ret[13..45].copy_from_slice(&self.chain_code[..]);
		let pk = secp_static::with_none(
			|e| Error::Generic(format!("Unable create secp instance, {}", e)),
			|secp| Ok(self.public_key.serialize_vec(secp, true)?),
		)?;
		ret[45..78].copy_from_slice(&pk[..]);
		let res_str = base58::check_encode_slice(&ret[..])
			.map_err(|e| Error::Generic(format!("base58 encoding error, {}", e)))?;
		Ok(res_str)
	}

	/// Attempts to derive an extended public key from a path.
	pub fn derive_pub<H>(
		&self,
		secp: &Secp256k1,
		hasher: &mut H,
		cnums: &[ChildNumber],
	) -> Result<ExtendedPubKey, Error>
	where
		H: BIP32Hasher,
	{
		if self.network != hasher.network_pub() {
			return Err(Error::Generic(
				"Hasher network doesn't match ExtendedPubKey network".into(),
			));
		}

		let mut pk: ExtendedPubKey = *self;
		for cnum in cnums {
			pk = pk.ckd_pub(secp, hasher, *cnum)?
		}
		Ok(pk)
	}

	/// Compute the scalar tweak added to this key to get a child key
	pub fn ckd_pub_tweak<H>(
		&self,
		secp: &Secp256k1,
		hasher: &mut H,
		i: ChildNumber,
	) -> Result<(SecretKey, ChainCode), Error>
	where
		H: BIP32Hasher,
	{
		match i {
			ChildNumber::Hardened { .. } => Err(Error::CannotDeriveFromHardenedKey),
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
					Error::Generic(format!("Unable to build ChainCode from sha512, {}", e))
				})?;
				Ok((secret_key, chain_code))
			}
		}
	}

	/// Public->Public child key derivation
	pub fn ckd_pub<H>(
		&self,
		secp: &Secp256k1,
		hasher: &mut H,
		i: ChildNumber,
	) -> Result<ExtendedPubKey, Error>
	where
		H: BIP32Hasher,
	{
		let (sk, chain_code) = self.ckd_pub_tweak(secp, hasher, i)?;
		let mut pk = self.public_key;
		pk.add_exp_assign(secp, &sk).map_err(Error::Ecdsa)?;

		let depth = self.depth.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("ExtendedPubKey::ckd_pub, depth={}", self.depth))
		})?;

		Ok(ExtendedPubKey {
			network: self.network,
			depth,
			parent_fingerprint: self.fingerprint(secp, hasher)?,
			child_number: i,
			public_key: pk,
			chain_code: chain_code,
		})
	}

	/// Returns the HASH160 of the chaincode
	pub fn identifier<H>(&self, secp: &Secp256k1, hasher: &mut H) -> Result<[u8; 20], Error>
	where
		H: BIP32Hasher,
	{
		// Do SHA256 of just the ECDSA pubkey
		let sha2_res = hasher.sha_256(&self.public_key.serialize_vec(secp, true)?[..]);
		// do RIPEMD160
		Ok(hasher.ripemd_160(&sha2_res))
	}

	/// Returns the first four bytes of the identifier
	pub fn fingerprint<H>(&self, secp: &Secp256k1, hasher: &mut H) -> Result<Fingerprint, Error>
	where
		H: BIP32Hasher,
	{
		Ok(
			Fingerprint::try_from(&self.identifier(secp, hasher)?[0..4]).map_err(|e| {
				Error::Generic(format!(
					"Unable to build Fingerprint from identifier, {}",
					e
				))
			})?,
		)
	}
}

fn validate_master_key_metadata(
	depth: u8,
	parent_fingerprint: &[u8],
	child_number: u32,
) -> Result<(), base58::Error> {
	if depth == 0 && (child_number != 0 || parent_fingerprint.iter().any(|byte| *byte != 0)) {
		return Err(base58::Error::InvalidData(
			"BIP32 master key must have zero parent fingerprint and child number".into(),
		));
	}
	Ok(())
}

impl FromStr for ExtendedPrivKey {
	type Err = base58::Error;

	fn from_str(inp: &str) -> Result<ExtendedPrivKey, base58::Error> {
		if inp.len() > 78 * 2 {
			return Err(base58::Error::InvalidLength(inp.len()));
		}

		let data = base58::from_check(inp)?;

		if data.len() != 78 {
			return Err(base58::Error::InvalidLength(data.len()));
		}

		if data[45] != 0 {
			return Err(base58::Error::InvalidData(
				"ExtendedPrivKey invalid byte 45 value".into(),
			));
		}

		let cn_int: u32 = Cursor::new(&data[9..13])
			.read_u32::<BigEndian>()
			.map_err(|e| base58::Error::Other(format!("u32 read error, {}", e)))?;
		validate_master_key_metadata(data[4], &data[5..9], cn_int)?;
		let child_number: ChildNumber = ChildNumber::from(cn_int);

		let mut network = [0; 4];
		network.copy_from_slice(&data[0..4]);
		if !is_allowed_priv_network(&network) {
			return Err(base58::Error::InvalidVersion(network.to_vec()));
		}

		Ok(ExtendedPrivKey {
			network: network,
			depth: data[4],
			parent_fingerprint: Fingerprint::try_from(&data[5..9]).map_err(|e| {
				base58::Error::Other(format!(
					"Unable to build Fingerprint from identifier, {}",
					e
				))
			})?,
			child_number: child_number,
			chain_code: ChainCode::try_from(&data[13..45]).map_err(|e| {
				base58::Error::Other(format!("Unable to build ChainCode from sha512, {}", e))
			})?,
			secret_key: secp_static::with_none(
				|e| base58::Error::Other(format!("Unable create secp instance, {}", e)),
				|secp| {
					SecretKey::from_slice(secp, &data[46..78]).map_err(|e| {
						base58::Error::Other(format!("Unable to read priv key, {}", e))
					})
				},
			)?,
		})
	}
}

fn is_allowed_priv_network(network: &[u8; 4]) -> bool {
	*network == BIP32MwcHasher::new(false).network_priv()
		|| *network == BIP32MwcHasher::new(true).network_priv()
}

fn is_allowed_pub_network(network: &[u8; 4]) -> bool {
	*network == BIP32MwcHasher::new(false).network_pub()
		|| *network == BIP32MwcHasher::new(true).network_pub()
}

impl FromStr for ExtendedPubKey {
	type Err = base58::Error;

	fn from_str(inp: &str) -> Result<ExtendedPubKey, base58::Error> {
		if inp.len() > 78 * 2 {
			return Err(base58::Error::InvalidLength(inp.len()));
		}

		let data = base58::from_check(inp)?;

		if data.len() != 78 {
			return Err(base58::Error::InvalidLength(data.len()));
		}

		let mut network = [0; 4];
		network.copy_from_slice(&data[0..4]);
		if !is_allowed_pub_network(&network) {
			return Err(base58::Error::InvalidVersion(network.to_vec()));
		}

		let cn_int: u32 = Cursor::new(&data[9..13])
			.read_u32::<BigEndian>()
			.map_err(|e| base58::Error::Other(format!("u32 read error, {}", e)))?;
		validate_master_key_metadata(data[4], &data[5..9], cn_int)?;
		let child_number: ChildNumber = ChildNumber::from(cn_int);

		Ok(ExtendedPubKey {
			network: network,
			depth: data[4],
			parent_fingerprint: Fingerprint::try_from(&data[5..9]).map_err(|e| {
				base58::Error::Other(format!(
					"Unable to build Fingerprint from identifier, {}",
					e
				))
			})?,
			child_number: child_number,
			chain_code: ChainCode::try_from(&data[13..45]).map_err(|e| {
				base58::Error::Other(format!("Unable to build ChainCode from sha512, {}", e))
			})?,
			public_key: secp_static::with_none(
				|e| base58::Error::Other(format!("Unable create secp instance, {}", e)),
				|secp| {
					PublicKey::from_slice(secp, &data[45..78])
						.map_err(|e| base58::Error::Other(format!("Unable to read pub key, {}", e)))
				},
			)?,
		})
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;

	use mwc_crates::secp::Secp256k1;
	use mwc_util::from_hex;

	use super::*;

	fn test_path(
		secp: &Secp256k1,
		seed: &[u8],
		path: &[ChildNumber],
		expected_sk: &str,
		expected_pk: &str,
	) {
		let mut h = BIP32MwcHasher::new(false);
		let mut sk = ExtendedPrivKey::new_master(secp, &mut h, seed).unwrap();
		let mut pk = ExtendedPubKey::from_private::<BIP32MwcHasher>(secp, &sk, &mut h).unwrap();

		// Check derivation convenience method for ExtendedPrivKey
		assert_eq!(
			&sk.derive_priv(secp, &mut h, path)
				.unwrap()
				.to_base58()
				.unwrap()[..],
			expected_sk
		);

		// Check derivation convenience method for ExtendedPubKey, should error
		// appropriately if any ChildNumber is hardened
		if path.iter().any(|cnum| cnum.is_hardened()) {
			assert!(matches!(
				pk.derive_pub(secp, &mut h, path),
				Err(Error::CannotDeriveFromHardenedKey)
			));
		} else {
			assert_eq!(
				&pk.derive_pub(secp, &mut h, path)
					.unwrap()
					.to_base58()
					.unwrap()[..],
				expected_pk
			);
		}

		// Derive keys, checking hardened and non-hardened derivation one-by-one
		for &num in path.iter() {
			sk = sk.ckd_priv(secp, &mut h, num).unwrap();
			match num {
				ChildNumber::Normal { .. } => {
					let pk2 = pk.ckd_pub(secp, &mut h, num).unwrap();
					pk = ExtendedPubKey::from_private::<BIP32MwcHasher>(secp, &sk, &mut h).unwrap();
					assert_eq!(pk, pk2);
				}
				ChildNumber::Hardened { .. } => {
					assert!(matches!(
						pk.ckd_pub(secp, &mut h, num),
						Err(Error::CannotDeriveFromHardenedKey)
					));
					pk = ExtendedPubKey::from_private::<BIP32MwcHasher>(secp, &sk, &mut h).unwrap();
				}
			}
		}

		// Check result against expected base58
		assert_eq!(&sk.to_base58().unwrap()[..], expected_sk);
		assert_eq!(&pk.to_base58().unwrap()[..], expected_pk);
		// Check decoded base58 against result
		let decoded_sk = ExtendedPrivKey::from_str(expected_sk);
		assert_eq!(sk, decoded_sk.unwrap());
		let decoded_pk = ExtendedPubKey::from_str(expected_pk);
		assert_eq!(pk, decoded_pk.unwrap());
	}

	#[test]
	fn mwc_extended_public_key_from_str_rejects_non_public_versions() {
		let secp = Secp256k1::new().unwrap();
		let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
		let mut h = BIP32MwcHasher::new(false);
		let sk = ExtendedPrivKey::new_master(&secp, &mut h, &seed).unwrap();
		let pk = ExtendedPubKey::from_private::<BIP32MwcHasher>(&secp, &sk, &mut h).unwrap();

		let encoded_public = pk.to_base58().unwrap();
		assert_eq!(ExtendedPubKey::from_str(&encoded_public).unwrap(), pk);

		let mut private_version_pk = pk;
		private_version_pk.network = h.network_priv();
		let encoded_private_version = private_version_pk.to_base58().unwrap();
		assert!(matches!(
			ExtendedPubKey::from_str(&encoded_private_version),
			Err(base58::Error::InvalidVersion(_))
		));

		let mut unknown_version_pk = pk;
		unknown_version_pk.network = [0, 1, 2, 3];
		let encoded_unknown_version = unknown_version_pk.to_base58().unwrap();
		assert!(matches!(
			ExtendedPubKey::from_str(&encoded_unknown_version),
			Err(base58::Error::InvalidVersion(_))
		));
	}

	#[test]
	fn extended_key_from_str_rejects_malformed_master_metadata() {
		let secp = Secp256k1::new().unwrap();
		let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
		let mut h = BIP32MwcHasher::new(false);
		let sk = ExtendedPrivKey::new_master(&secp, &mut h, &seed).unwrap();
		let pk = ExtendedPubKey::from_private::<BIP32MwcHasher>(&secp, &sk, &mut h).unwrap();

		let mut sk_with_parent = sk.clone();
		sk_with_parent.depth = 0;
		sk_with_parent.parent_fingerprint = Fingerprint::try_from(&[1, 0, 0, 0][..]).unwrap();
		assert!(matches!(
			ExtendedPrivKey::from_str(&sk_with_parent.to_base58().unwrap()),
			Err(base58::Error::InvalidData(_))
		));

		let mut sk_with_child = sk.clone();
		sk_with_child.depth = 0;
		sk_with_child.child_number = ChildNumber::from_normal_idx(1).unwrap();
		assert!(matches!(
			ExtendedPrivKey::from_str(&sk_with_child.to_base58().unwrap()),
			Err(base58::Error::InvalidData(_))
		));

		let mut pk_with_parent = pk;
		pk_with_parent.depth = 0;
		pk_with_parent.parent_fingerprint = Fingerprint::try_from(&[1, 0, 0, 0][..]).unwrap();
		assert!(matches!(
			ExtendedPubKey::from_str(&pk_with_parent.to_base58().unwrap()),
			Err(base58::Error::InvalidData(_))
		));

		let mut pk_with_child = pk;
		pk_with_child.depth = 0;
		pk_with_child.child_number = ChildNumber::from_normal_idx(1).unwrap();
		assert!(matches!(
			ExtendedPubKey::from_str(&pk_with_child.to_base58().unwrap()),
			Err(base58::Error::InvalidData(_))
		));
	}

	#[test]
	fn test_base58_rejects_invalid_child_number() {
		let secp = Secp256k1::new().unwrap();
		let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
		let mut h = BIP32MwcHasher::new(false);
		let mut sk = ExtendedPrivKey::new_master(&secp, &mut h, &seed).unwrap();
		sk.child_number = ChildNumber::Normal { index: 1 << 31 };
		assert!(matches!(sk.to_base58(), Err(Error::ChildNumberOutOfRange)));

		let mut pk = ExtendedPubKey::from_private::<BIP32MwcHasher>(&secp, &sk, &mut h).unwrap();
		pk.child_number = ChildNumber::Normal { index: 1 << 31 };
		assert!(matches!(pk.to_base58(), Err(Error::ChildNumberOutOfRange)));
	}

	#[test]
	fn test_vector_1() {
		let secp = Secp256k1::new().unwrap();
		let seed = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();

		// m
		test_path(&secp, &seed, &[],
                  "gprv4fhnhBfcc9MdRrRZ2pABw1W1yBgMGvGCnQEXgei2GATSc7TYSgCmswycD87uLXfo6VDtZC1koyk33RfWqtLenu8ugMP7uUvPpK6cDuS5i6N",
                  "gpub9CPpqbhrkX3JKKTLvTpnLRA8YDCHSFT7MhqJyAkKgSFqSbiK552N4SbUPGmyQLTmJRM6iNZMetV5JfjxZNKt3q2xcoidhjSmVRppuL9VNAU");

		// m/0h
		test_path(&secp, &seed, &[ChildNumber::from_hardened_idx(0).unwrap()],
                  "gprv4iTeAn3j5BMS6Uz1dH2iQYaKM5jrYwkE8snDEfnU3kY2qP9sHPSDKiDj5RX7WNoJiYpyniD93sNWEw5oL7TdTXMu7PZ2TpHKc5mH2Wr3oTb",
                  "gpub9F9gKC5yDZ36yx1oWvhJoxERv7FniGw8iBNzXBpmU2LRfsQdunFoWCqbFbXBjQ4bFwUWBHTYgZc6c9Ev2UbfPUBHpACsrz3QCsqAK2UKGCx");

		// m/0h/1
		test_path(&secp, &seed, &[ChildNumber::from_hardened_idx(0).unwrap(), ChildNumber::from_normal_idx(1).unwrap()],
                   "gprv4mHz5FRpNZvEoc3PFvYfF3RmL6EgU5LnQryzAgU9D34TX2U3EWa81JiPM9s3bzjUnyL9SM2pNi6nno7qLtg4znvs9tqFcu75PfbUUymUJVm",
                   "gpub9Hz2DfU4Wwbuh55B9aDFeT5su7kcdQXgzAamTCWSdJrrMWioruPiBoLFXKHeGAjDr3xzPJ1e7oYjZLB2cTXo4WRaUG8V9J8dwa36XKuXYYa");

		// m/0h/1/2h
		test_path(&secp, &seed, &[ChildNumber::from_hardened_idx(0).unwrap(), ChildNumber::from_normal_idx(1).unwrap(), ChildNumber::from_hardened_idx(2).unwrap()],
                  "gprv4mVic6cs2VaeaW37LDoKRi9gu3ch7TQFdhCPj2h2fVTePp4zphELN93ZD6N8MYznKaLn4fH3gamiMJ4iM51YDhVcVGyFovAe6k8erTFZ8FH",
                  "gpub9JBkkWf7AsGKTy4uDsTuq7ooU58dGnbACzoB1YjL5mG3EJKmT63vYdfRPGK4crj6YPJ3ugTn7wSgLShWw3cFn5oPBsBDqvkjBH91SJ1tTu3");

		// m/0h/1/2h/2
		test_path(&secp, &seed, &[ChildNumber::from_hardened_idx(0).unwrap(), ChildNumber::from_normal_idx(1).unwrap(), ChildNumber::from_hardened_idx(2).unwrap(), ChildNumber::from_normal_idx(2).unwrap()],
                  "gprv4p3ezs55MBFgJPd6e7ohzb4AuAc1HiD4Wt2GwNdsZD4EPq5Nv2bBEq4cg4zPJjox4p1HtkKLtXGgiPpzywhSYpxFooJY8K6nSYUT5Qi3xv5",
                  "gpub9Ljh9H7KVYwMBretXmUJPziHUC7wT3Py6Bd4DtgAyUrdEKL9YRQmRKgUrCzsErsZ38u5852Wi4mBk55GwDpa3eLQcpQPiGPeKxAoEfe78P1");

		// m/0h/1/2h/2/1000000000
		test_path(&secp, &seed, &[ChildNumber::from_hardened_idx(0).unwrap(), ChildNumber::from_normal_idx(1).unwrap(), ChildNumber::from_hardened_idx(2).unwrap(), ChildNumber::from_normal_idx(2).unwrap(), ChildNumber::from_normal_idx(1000000000).unwrap()],
                  "gprv4qUYp3r5MAxsUz2msdtrka7dALWMH2kVkb8Byd8PANsFf2bfRBscWQC94tsU3VBDtWrP2cKs5gBydA1rzKA1V3ALSZg5Su5AA1hM35QtQqE",
                  "gpub9NAaxTtKVYeYNT4ZmHZT9ymjjN2HSMwQKtiyG9AgaefeVWrS3ahCgtp1EzMgXDBv9uotiwPZSYyvFuWFfbumvoBcWYHs7yqC6sNwURT76Q6");
	}

	#[test]
	fn test_vector_2() {
		let secp = Secp256k1::new().unwrap();
		let seed = from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();

		// m
		test_path(&secp, &seed, &[],
                  "gprv4fhnhBfcc9MdTFXZmoMqu8SoxEjAFj8aP5GRrBdp4gmiFLxZCgdqMWMLWQxasb8ZeeNYz15E5wru65r8DQN2B5Y5oERRorpsUXqowwadV9W",
                  "gpub9CPpqbhrkX3JLiZMfT2SJY6vXGF6R4KUxNsD8hg7Uxa75qDKq5TRXzyCgYmPfkMQ7jZzqYNoSJhWtZ82KKet5iRMfCnCgsBqwWRCTLAKX2v");

		// m/0
		test_path(&secp, &seed, &[ChildNumber::from_normal_idx(0).unwrap()],
                  "gprv4i6PDr5sHB15nhkFDnH72FCavz5trqcPVqdTQfGa5gReLG6kJoGxDSGjBj3RVAKnF36tPRZKNgD7Ym2MS72E1hfQJ7YNd67adS3Lfvkgc1G",
                  "gpub9EnRNG87RYgkgAn37RwhRerhW1bq2AoJ59EEhBJsVxE3AkMWwC6YPvtbMqZFi7Jdf4Y42YGqdNYcStorzPkBaMtdQXiSmEbiH44nKeGKiLf");

		// m/0/2147483647h
		test_path(&secp, &seed, &[ChildNumber::from_normal_idx(0).unwrap(), ChildNumber::from_hardened_idx(2147483647).unwrap()],
                  "gprv4kY3ejLHg5TEK83nJs4md8LSDeM3Zvm6p3ueCrxhpcZcidvRWBtN6zEDfZTye76ws8GUz6wKrZ7fTKjPFQyKDrXrJmuBdEZpGZXZvRYDwA1",
                  "gpub9HE5o9NXpT8uCb5aCWjN2XzYnfryjFx1PMWRVP11EtN1Z8BC8ahxHUr5qh4WGNXrPt5Tsj11ZqcM2ykpJcWZSap5Mx7VLcH8973v9vKsByR");

		// m/0/2147483647h/1
		test_path(&secp, &seed, &[ChildNumber::from_normal_idx(0).unwrap(), ChildNumber::from_hardened_idx(2147483647).unwrap(), ChildNumber::from_normal_idx(1).unwrap()],
                  "gprv4nyJp12Rehz7DTUTEqGGdxs7UWAn7sARgENZgvYjmtMvhFVrDkr6c5MQZTo7NyRFg6piks5JnwDWY1StQC2tDeYk7u4C97HqQ4Bd4jDH4BT",
                  "gpub9KfLxR4fo5fn6vWF8Uvs3NXE3XgiHCMLFXyLySb3CAAKXjkcr9fgnZyGjccQxmW2DVp5ezcux8rx2XtZyjErwRF2Vm2EKckXMbToYgaKWt1");

		// m/0/2147483647h/1/2147483646h
		test_path(&secp, &seed, &[ChildNumber::from_normal_idx(0).unwrap(), ChildNumber::from_hardened_idx(2147483647).unwrap(), ChildNumber::from_normal_idx(1).unwrap(), ChildNumber::from_hardened_idx(2147483646).unwrap()],
                  "gprv4owvCk6NJQazsR3LG1E7hY8XXSrWghFec39ULDver1SRprSjUbjFL67dcTYpAPkkftyALLag9bhjyM6xZVtb6M2V6MpBW3r94F5JraD1pNo",
                  "gpub9LdxMA8cSnGfkt589eti6wne6UNSr2SZBLkFcjxxGHEpfLhW6zYqWajVncAMrtd5CNgMzFWNwtZyXpWb8SY9H3Hxy5Z7CoHEADXvTd1fdsB");

		// m/0/2147483647h/1/2147483646h/2
		test_path(&secp, &seed, &[ChildNumber::from_normal_idx(0).unwrap(), ChildNumber::from_hardened_idx(2147483647).unwrap(), ChildNumber::from_normal_idx(1).unwrap(), ChildNumber::from_hardened_idx(2147483646).unwrap(), ChildNumber::from_normal_idx(2).unwrap()],
                  "gprv4rRwiH31fpvzpuGVHE485fdkhsr4QZaE63VELoGYdkyCYNdoPHZHQxXEMpE2XKQGFbYykaPNza9WGCLDFyjAxoFeFqJk8YjPbTLQve9V7Vg",
                  "gpub9P7yrh5FpCcfiNJHAsiiV5HsGuMzZtm8fM61dKJr42mbNrta1gNsbT96XwoJEvajF56mTwS3T8n5asUgmMxAo2LhYqjmo2UBVYwCqza3DTD");
	}

	#[test]
	fn test_vector_3() {
		let secp = Secp256k1::new().unwrap();
		let seed = from_hex("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be").unwrap();

		// m
		test_path(&secp, &seed, &[],
                  "gprv4fhnhBfcc9MdSsEqgy9AM1C2pUdNV1PUZF5x3ZW86fFAviHdRt8kvyKAiQ3UFTBXT5RqXK4iq7KY4vmgS2iQK9dU3tFCmLoiuSiJ4CnRRQd",
                  "gpub9CPpqbhrkX3JLLGdacokkQr9PW9JeLaP8YgjL5YRWw3ZmCYQ4GxM7Tw2tXvjSNzNZvFsLm7L87fuzfznGvhpKWhg27iK4YWYVJpfQTvYJXb");

		// m/0h
		test_path(&secp, &seed, &[ChildNumber::from_hardened_idx(0).unwrap()],
                  "gprv4jPnYDwM3SBU39fyi5Hi5GJZJmgPRzTmqYHzBa6r2hk9rVi2KnLBbqedKbRpujzFf8kCinZGzefv4i5CZBTt75Y175CHu8DSQgGqB7Mc7YH",
                  "gpub9G5pgdybBos8vchmbixJUfxfsoCKbKegQqtmU699SyYYgyxnxB9mnLGVVkxACzm78u6xJPNPDHx9GoYCLat5zVZzYenVdcC8ivHVQBo6CYi");
	}
}
