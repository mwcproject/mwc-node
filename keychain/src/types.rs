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

//! Keychain trait and its main supporting types. The Identifier is a
//! semi-opaque structure (just bytes) to track keys within the Keychain.
//! BlindingFactor is a useful wrapper around a private key to help with
//! commitment generation.

use mwc_crates::serde::{self, Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::io::Cursor;

use crate::extkey_bip32::{self, ChildNumber};
use mwc_crates::blake2_rfc::blake2b::blake2b;
use mwc_crates::serde::{de, ser}; //TODO: Convert errors to use ErrorKind

use mwc_crates::secp::constants::SECRET_KEY_SIZE;
use mwc_crates::secp::key::{PublicKey, SecretKey, ZERO_KEY};
use mwc_crates::secp::pedersen::Commitment;
use mwc_crates::secp::{self, EcdsaSignature, Message, Secp256k1};
use mwc_crates::subtle::ConstantTimeEq;
use mwc_crates::zeroize::{Zeroize, Zeroizing};
use mwc_util::{secp_static, ToHex};

use mwc_crates::byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use mwc_crates::rand::rngs::SysRng;

// Size of an identifier in bytes
pub const IDENTIFIER_SIZE: usize = 17;

#[derive(thiserror::Error, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum Error {
	#[error("Keychain secp error, {0}")]
	Secp(String),
	#[error("Keychain derivation key error, {0}")]
	KeyDerivation(#[from] extkey_bip32::Error),
	#[error("Keychain master key is masked")]
	KeychainMasked,
	#[error("Invalid master key mask")]
	InvalidMasterKeyMask,
	#[error("Keychain Transaction error, {0}")]
	Transaction(String),
	#[error("Keychain range proof error, {0}")]
	RangeProof(String),
	#[error("Keychain unknown commitment type")]
	SwitchCommitment,
	#[error("Keychain generic error, {0}")]
	GenericError(String),
	#[error("Keychain data overflow error, {0}")]
	DataOverflow(String),
	#[error("Invalid depth value {0}")]
	InvalidDepth(u8),
	#[error("Invalid length value {0}")]
	InvalidLength(usize),
}

// we have to use e.description  because of the bug at rust-secp256k1-zkp
impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(format!("{}", e))
	}
}

#[derive(Clone, PartialEq, Eq, Ord, Hash, PartialOrd)]
pub struct Identifier([u8; IDENTIFIER_SIZE]);

impl ser::Serialize for Identifier {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: ser::Serializer,
	{
		serializer.serialize_str(&self.to_hex())
	}
}

impl<'de> de::Deserialize<'de> for Identifier {
	fn deserialize<D>(deserializer: D) -> Result<Identifier, D::Error>
	where
		D: de::Deserializer<'de>,
	{
		deserializer.deserialize_str(IdentifierVisitor)
	}
}

struct IdentifierVisitor;

impl<'de> de::Visitor<'de> for IdentifierVisitor {
	type Value = Identifier;

	fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str("an identifier")
	}

	fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
	where
		E: de::Error,
	{
		let identifier = Identifier::from_hex(s)
			.map_err(|e| de::Error::custom(format!("Unable to parse HEX {}, {}", s, e)))?;
		Ok(identifier)
	}
}

impl Identifier {
	pub fn zero() -> Identifier {
		Identifier([0; IDENTIFIER_SIZE])
	}

	pub fn from_path(path: &ExtKeychainPath) -> Result<Identifier, Error> {
		path.to_identifier()
	}

	pub fn to_path(&self) -> Result<ExtKeychainPath, Error> {
		ExtKeychainPath::from_identifier(&self)
	}

	pub fn to_value_path(&self, value: u64) -> Result<ValueExtKeychainPath, Error> {
		// TODO: proper support for different switch commitment schemes
		// For now it is assumed all outputs are using the regular switch commitment scheme
		Ok(ValueExtKeychainPath {
			value,
			ext_keychain_path: self.to_path()?,
			switch: SwitchCommitmentType::Regular,
		})
	}

	/// output the path itself, for insertion into bulletproof
	/// recovery processes can mwcd through possiblities to find the
	/// correct length if required
	pub fn serialize_path(&self) -> [u8; IDENTIFIER_SIZE - 1] {
		let mut retval = [0u8; IDENTIFIER_SIZE - 1];
		retval.copy_from_slice(&self.0[1..IDENTIFIER_SIZE]);
		retval
	}

	/// restore from a serialized path
	pub fn from_serialized_path(len: u8, p: &[u8]) -> Result<Identifier, Error> {
		if p.len() != IDENTIFIER_SIZE - 1 {
			return Err(Error::InvalidLength(p.len()));
		}
		if len > 4 {
			return Err(Error::InvalidDepth(len));
		}

		let mut id = [0; IDENTIFIER_SIZE];
		id[0] = len;
		id[1..IDENTIFIER_SIZE].copy_from_slice(p);
		let ident = Identifier::from_bytes(&id)?;
		let _ = ExtKeychainPath::from_identifier(&ident)?;
		Ok(ident)
	}

	/// Return the parent path
	pub fn parent_path(&self) -> Result<Identifier, Error> {
		let mut p = ExtKeychainPath::from_identifier(&self)?;
		if p.depth > 0 {
			p.path[p.depth as usize - 1] = ChildNumber::from(0);
			p.depth -= 1;
		}
		Identifier::from_path(&p)
	}
	pub fn from_bytes(bytes: &[u8]) -> Result<Identifier, Error> {
		let identifier: [u8; IDENTIFIER_SIZE] = bytes
			.try_into()
			.map_err(|_| Error::InvalidLength(bytes.len()))?;
		Ok(Identifier(identifier))
	}

	pub fn to_bytes(&self) -> [u8; IDENTIFIER_SIZE] {
		self.0
	}

	pub fn from_pubkey(secp: &Secp256k1, pubkey: &PublicKey) -> Result<Identifier, Error> {
		let bytes = pubkey.serialize_vec(secp, true)?;
		let identifier = blake2b(IDENTIFIER_SIZE, &[], &bytes[..]);
		Identifier::from_bytes(&identifier.as_bytes())
	}

	/// Return the identifier of the secret key
	/// which is the blake2b (10 byte) digest of the PublicKey
	/// corresponding to the secret key provided.
	pub fn from_secret_key(secp: &Secp256k1, key: &SecretKey) -> Result<Identifier, Error> {
		let key_id =
			PublicKey::from_secret_key(secp, key).map_err(|e| Error::Secp(format!("{}", e)))?;
		Identifier::from_pubkey(secp, &key_id)
	}

	pub fn from_hex(hex: &str) -> Result<Identifier, Error> {
		let bytes = mwc_util::from_hex(hex)
			.map_err(|e| Error::GenericError(format!("Unable to parse HEX {}, {}", hex, e)))?;
		Identifier::from_bytes(&bytes)
	}

	pub fn to_bip_32_string(&self) -> Result<String, Error> {
		let p = ExtKeychainPath::from_identifier(&self)?;
		let mut retval = String::from("m");
		for i in 0..p.depth {
			retval.push_str(&format!("/{}", p.path[i as usize].to_string()));
		}
		Ok(retval)
	}
}

impl AsRef<[u8]> for Identifier {
	fn as_ref(&self) -> &[u8] {
		&self.0.as_ref()
	}
}

impl ::std::fmt::Debug for Identifier {
	fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
		write!(f, "{}(", stringify!(Identifier))?;
		write!(f, "{}", self.to_hex())?;
		write!(f, ")")
	}
}

impl fmt::Display for Identifier {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.to_hex())
	}
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct BlindingFactor([u8; SECRET_KEY_SIZE]);

impl PartialEq for BlindingFactor {
	fn eq(&self, other: &Self) -> bool {
		self.0.as_ref().ct_eq(other.0.as_ref()).into()
	}
}

impl Eq for BlindingFactor {}

impl Drop for BlindingFactor {
	fn drop(&mut self) {
		self.0.zeroize();
	}
}

// Dummy `Debug` implementation that prevents secret leakage.
impl fmt::Debug for BlindingFactor {
	fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "BlindingFactor(<secret key hidden>)")
	}
}

// Note, BlindingFactor row data access is needed. BlindingFactor is part of the transaction
// that is stored.
impl AsRef<[u8]> for BlindingFactor {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

fn blinding_factor_hex_value(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

fn decode_blinding_factor_hex(hex: &str) -> Result<Zeroizing<[u8; SECRET_KEY_SIZE]>, Error> {
	let hex = hex.trim();
	let hex = hex.strip_prefix("0x").unwrap_or(hex);
	if hex.len() != SECRET_KEY_SIZE * 2 {
		return Err(Error::GenericError(
			"invalid BlindingFactor hex length".into(),
		));
	}

	let hex = hex.as_bytes();
	if !hex
		.iter()
		.all(|byte| blinding_factor_hex_value(*byte).is_some())
	{
		return Err(Error::GenericError("invalid BlindingFactor symbols".into()));
	}

	let mut bytes = Zeroizing::new([0u8; SECRET_KEY_SIZE]);
	for (idx, pair) in hex.chunks_exact(2).enumerate() {
		let high = blinding_factor_hex_value(pair[0])
			.ok_or_else(|| Error::GenericError("invalid BlindingFactor symbols".into()))?;
		let low = blinding_factor_hex_value(pair[1])
			.ok_or_else(|| Error::GenericError("invalid BlindingFactor symbols".into()))?;
		bytes[idx] = (high << 4) | low;
	}
	Ok(bytes)
}

impl BlindingFactor {
	pub fn from_secret_key(skey: SecretKey) -> BlindingFactor {
		BlindingFactor(skey.0)
	}

	pub fn from_slice(data: &[u8]) -> Result<BlindingFactor, Error> {
		if data.len() != SECRET_KEY_SIZE {
			return Err(Error::InvalidLength(data.len()));
		}
		let blind: [u8; SECRET_KEY_SIZE] = data
			.try_into()
			.map_err(|_| Error::InvalidLength(data.len()))?;
		if !bool::from(blind.as_ref().ct_eq(ZERO_KEY.0.as_ref())) {
			secp_static::with_none(Error::from, |secp| Ok(SecretKey::from_slice(secp, &blind)?))?;
		}

		Ok(BlindingFactor(blind))
	}

	pub fn zero() -> BlindingFactor {
		BlindingFactor::from_secret_key(ZERO_KEY)
	}

	pub fn is_zero(&self) -> bool {
		self.0.as_ref().ct_eq(ZERO_KEY.0.as_ref()).into()
	}

	pub fn rand(secp: &Secp256k1) -> Result<BlindingFactor, Error> {
		Ok(BlindingFactor::from_secret_key(SecretKey::new(
			secp,
			&mut SysRng,
		)?))
	}

	pub fn from_hex(hex: &str) -> Result<BlindingFactor, Error> {
		let bytes = decode_blinding_factor_hex(hex)?;
		BlindingFactor::from_slice(bytes.as_ref())
	}

	// Handle "zero" blinding_factor correctly, by returning the "zero" key.
	// We need this for some of the tests.
	pub fn secret_key(&self, secp: &Secp256k1) -> Result<SecretKey, Error> {
		if self.is_zero() {
			Ok(ZERO_KEY)
		} else {
			SecretKey::from_slice(secp, &self.0).map_err(|e| Error::Secp(format!("{}", e)))
		}
	}

	// Convenient (and robust) way to add two blinding_factors together.
	// Handles "zero" blinding_factors correctly.
	pub fn add(&self, other: &BlindingFactor, secp: &Secp256k1) -> Result<BlindingFactor, Error> {
		let mut keys = Vec::with_capacity(2);
		if !self.is_zero() {
			keys.push(self.secret_key(secp)?);
		}
		if !other.is_zero() {
			keys.push(other.secret_key(secp)?);
		}

		if keys.is_empty() {
			Ok(BlindingFactor::zero())
		} else {
			match secp.blind_sum(keys, vec![]) {
				Ok(sum) => Ok(BlindingFactor::from_secret_key(sum)),
				Err(secp::Error::ZeroSecretKey) => Ok(BlindingFactor::zero()),
				Err(e) => Err(e.into()),
			}
		}
	}

	/// Split a blinding_factor (aka secret_key) into a pair of
	/// blinding_factors. We use one of these (k1) to sign the tx_kernel (k1G)
	/// and the other gets aggregated in the block_header as the "offset".
	/// This prevents an actor from being able to sum a set of inputs, outputs
	/// and kernels from a block to identify and reconstruct a particular tx
	/// from a block. You would need both k1, k2 to do this.
	pub fn split(
		&self,
		blind_1: &BlindingFactor,
		secp: &Secp256k1,
	) -> Result<BlindingFactor, Error> {
		// use blind_sum to subtract skey_1 from our key such that skey = skey_1 + skey_2
		let skey = self.secret_key(secp)?;
		let skey_1 = blind_1.secret_key(secp)?;
		let skey_2 = secp.blind_sum(vec![skey], vec![skey_1])?;
		Ok(BlindingFactor::from_secret_key(skey_2))
	}
}

/// Accumulator to compute the sum of blinding factors. Keeps track of each
/// factor as well as the "sign" with which they should be combined.
#[derive(Clone, Debug, PartialEq)]
pub struct BlindSum {
	pub positive_key_ids: Vec<ValueExtKeychainPath>,
	pub negative_key_ids: Vec<ValueExtKeychainPath>,
	// Keep secret bytes behind stable heap allocations; Vec growth then moves
	// only pointers instead of copying BlindingFactor bytes into freed storage.
	pub positive_blinding_factors: Vec<Box<BlindingFactor>>,
	pub negative_blinding_factors: Vec<Box<BlindingFactor>>,
}

impl BlindSum {
	/// Creates a new blinding factor sum.
	pub fn new() -> BlindSum {
		BlindSum {
			positive_key_ids: vec![],
			negative_key_ids: vec![],
			positive_blinding_factors: vec![],
			negative_blinding_factors: vec![],
		}
	}

	pub fn add_key_id(mut self, path: ValueExtKeychainPath) -> BlindSum {
		self.positive_key_ids.push(path);
		self
	}

	pub fn sub_key_id(mut self, path: ValueExtKeychainPath) -> BlindSum {
		self.negative_key_ids.push(path);
		self
	}

	/// Adds the provided key to the sum of blinding factors.
	pub fn add_blinding_factor(mut self, blind: BlindingFactor) -> BlindSum {
		self.positive_blinding_factors.push(Box::new(blind));
		self
	}

	/// Subtracts the provided key to the sum of blinding factors.
	pub fn sub_blinding_factor(mut self, blind: BlindingFactor) -> BlindSum {
		self.negative_blinding_factors.push(Box::new(blind));
		self
	}
}

const MAX_DEPTH: u8 = 4;
pub const MAX_DEPTH_USIZE: usize = 4;

/// Encapsulates a max 4-level deep BIP32 path, which is the most we can
/// currently fit into a rangeproof message. The depth encodes how far the
/// derivation depths go and allows differentiating paths. As m/0, m/0/0
/// or m/0/0/0/0 result in different derivations, a path needs to encode
/// its maximum depth.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(crate = "serde")]
pub struct ExtKeychainPath {
	pub depth: u8,
	pub path: [extkey_bip32::ChildNumber; MAX_DEPTH_USIZE],
}

impl ExtKeychainPath {
	/// Return a new chain path with given derivation and depth
	pub fn new(depth: u8, d0: u32, d1: u32, d2: u32, d3: u32) -> Result<ExtKeychainPath, Error> {
		Self::validate_depth(depth)?;
		let mut path = [
			ChildNumber::from(d0),
			ChildNumber::from(d1),
			ChildNumber::from(d2),
			ChildNumber::from(d3),
		];
		Self::validate_unused_path_components(depth, &mut path)?;
		Ok(ExtKeychainPath { depth: depth, path })
	}

	/// from an Indentifier [manual deserialization]
	pub fn from_identifier(id: &Identifier) -> Result<ExtKeychainPath, Error> {
		let mut rdr = Cursor::new(id.0.to_vec());

		let depth: u8 = rdr.read_u8().map_err(|e| {
			Error::GenericError(format!(
				"ExtKeychainPath::from_identifier invalid data, {}",
				e
			))
		})?;

		Self::validate_depth(depth)?;

		let mut path = [
			ChildNumber::from(rdr.read_u32::<BigEndian>().map_err(|e| {
				Error::GenericError(format!(
					"ExtKeychainPath::from_identifier invalid data, {}",
					e
				))
			})?),
			ChildNumber::from(rdr.read_u32::<BigEndian>().map_err(|e| {
				Error::GenericError(format!(
					"ExtKeychainPath::from_identifier invalid data, {}",
					e
				))
			})?),
			ChildNumber::from(rdr.read_u32::<BigEndian>().map_err(|e| {
				Error::GenericError(format!(
					"ExtKeychainPath::from_identifier invalid data, {}",
					e
				))
			})?),
			ChildNumber::from(rdr.read_u32::<BigEndian>().map_err(|e| {
				Error::GenericError(format!(
					"ExtKeychainPath::from_identifier invalid data, {}",
					e
				))
			})?),
		];
		Self::validate_unused_path_components(depth, &mut path)?;

		Ok(ExtKeychainPath { depth, path })
	}

	/// to an Identifier [manual serialization]
	pub fn to_identifier(&self) -> Result<Identifier, Error> {
		Self::validate_depth(self.depth)?;
		let mut path = self.path;
		Self::validate_unused_path_components(self.depth, &mut path)?;
		let mut wtr = vec![];
		wtr.write_u8(self.depth).map_err(|e| {
			Error::GenericError(format!("ExtKeychainPath::to_identifier write error, {}", e))
		})?;
		wtr.write_u32::<BigEndian>(<u32>::try_from(path[0])?)
			.map_err(|e| {
				Error::GenericError(format!("ExtKeychainPath::to_identifier write error, {}", e))
			})?;
		wtr.write_u32::<BigEndian>(<u32>::try_from(path[1])?)
			.map_err(|e| {
				Error::GenericError(format!("ExtKeychainPath::to_identifier write error, {}", e))
			})?;
		wtr.write_u32::<BigEndian>(<u32>::try_from(path[2])?)
			.map_err(|e| {
				Error::GenericError(format!("ExtKeychainPath::to_identifier write error, {}", e))
			})?;
		wtr.write_u32::<BigEndian>(<u32>::try_from(path[3])?)
			.map_err(|e| {
				Error::GenericError(format!("ExtKeychainPath::to_identifier write error, {}", e))
			})?;
		let mut retval = [0u8; IDENTIFIER_SIZE];
		retval.copy_from_slice(&wtr[0..IDENTIFIER_SIZE]);
		Ok(Identifier(retval))
	}

	/// Last part of the path (for last n_child)
	pub fn last_path_index(&self) -> Result<u32, Error> {
		Self::validate_depth(self.depth)?;
		if self.depth == 0 {
			Ok(0)
		} else {
			// Safe: self.depth was checked above to be non-zero.
			let idx = usize::from(self.depth) - 1;
			Ok(<u32>::try_from(self.path[idx])?)
		}
	}

	pub(crate) fn validate_depth(depth: u8) -> Result<(), Error> {
		if depth > MAX_DEPTH {
			Err(Error::InvalidDepth(depth))
		} else {
			Ok(())
		}
	}

	fn validate_unused_path_components(
		depth: u8,
		path: &[extkey_bip32::ChildNumber; MAX_DEPTH_USIZE],
	) -> Result<(), Error> {
		for component in path.iter().skip(depth as usize) {
			if *component != (ChildNumber::Normal { index: 0 }) {
				return Err(Error::GenericError(
					"Path not zeroized below the depth".into(),
				));
			}
		}
		Ok(())
	}
}

/// Wrapper for amount + switch + path
#[derive(Copy, Clone, PartialEq, Eq, Debug, Deserialize)]
#[serde(crate = "serde")]
pub struct ValueExtKeychainPath {
	pub value: u64,
	pub ext_keychain_path: ExtKeychainPath,
	pub switch: SwitchCommitmentType,
}

pub trait Keychain: Sync + Send + Clone {
	/// Generates a keychain from a raw binary seed (which has already been
	/// decrypted if applicable).
	fn from_seed(secp: &Secp256k1, seed: &[u8], is_floo: bool) -> Result<Self, Error>;

	/// Generates a keychain from a list of space-separated mnemonic words
	fn from_mnemonic(
		secp: &Secp256k1,
		word_list: &str,
		extension_word: &str,
		is_floo: bool,
	) -> Result<Self, Error>;

	/// XOR masks the keychain's master key against another key. Note, resulting key
	/// is not usable until it is recovered with the same mask.
	fn mask_master_key(&mut self, mask: &SecretKey) -> Result<(), Error>;

	/// Root identifier for that keychain
	fn root_key_id() -> Result<Identifier, Error>;

	/// Derives a key id from the depth of the keychain and the values at each
	/// depth level. See `KeychainPath` for more information.
	fn derive_key_id(depth: u8, d1: u32, d2: u32, d3: u32, d4: u32) -> Result<Identifier, Error>;

	/// The public root key
	fn public_root_key(&self, secp: &Secp256k1) -> Result<PublicKey, Error>;

	fn private_root_key(&self) -> Result<SecretKey, Error>;

	fn derive_key(
		&self,
		secp: &Secp256k1,
		amount: u64,
		id: &Identifier,
		switch: SwitchCommitmentType,
	) -> Result<SecretKey, Error>;

	fn commit(
		&self,
		secp: &Secp256k1,
		amount: u64,
		id: &Identifier,
		switch: SwitchCommitmentType,
	) -> Result<Commitment, Error>;

	fn blind_sum(&self, secp: &Secp256k1, blind_sum: &BlindSum) -> Result<BlindingFactor, Error>;

	fn sign(
		&self,
		secp: &Secp256k1,
		msg: &Message,
		amount: u64,
		id: &Identifier,
		switch: SwitchCommitmentType,
	) -> Result<EcdsaSignature, Error>;

	fn sign_with_blinding(
		&self,
		secp: &Secp256k1,
		_: &Message,
		_: &BlindingFactor,
	) -> Result<EcdsaSignature, Error>;
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum SwitchCommitmentType {
	None,
	Regular,
}

impl TryFrom<u8> for SwitchCommitmentType {
	type Error = ();

	fn try_from(value: u8) -> Result<Self, Self::Error> {
		match value {
			0 => Ok(SwitchCommitmentType::None),
			1 => Ok(SwitchCommitmentType::Regular),
			_ => Err(()),
		}
	}
}

impl From<SwitchCommitmentType> for u8 {
	fn from(switch: SwitchCommitmentType) -> Self {
		match switch {
			SwitchCommitmentType::None => 0,
			SwitchCommitmentType::Regular => 1,
		}
	}
}

#[cfg(test)]
mod test {
	use crate::extkey_bip32::ChildNumber;
	use crate::types::{BlindingFactor, Error, ExtKeychainPath, Identifier};
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::secp::constants::SECRET_KEY_SIZE;
	use mwc_crates::secp::key::{SecretKey, ZERO_KEY};
	use mwc_crates::secp::Secp256k1;
	use std::slice::from_raw_parts;

	// This tests cleaning of BlindingFactor (e.g. secret key) on Drop.
	// To make this test fail, just remove `Zeroize` derive from `BlindingFactor` definition.
	#[test]
	fn blinding_factor_clear_on_drop() {
		// Create buffer for blinding factor filled with non-zero bytes.
		let bf_bytes = [0xAA; SECRET_KEY_SIZE];
		let ptr = {
			// Fill blinding factor with some "sensitive" data
			let bf = BlindingFactor::from_slice(&bf_bytes[..]).unwrap();
			bf.0.as_ptr()

			// -- after this line BlindingFactor should be zeroed
		};

		// Unsafely get data from where BlindingFactor was in memory. Should be all zeros.
		let bf_bytes = unsafe { from_raw_parts(ptr, SECRET_KEY_SIZE) };

		// There should be all zeroes.
		let mut all_zeros = true;
		for b in bf_bytes {
			if *b != 0x00 {
				all_zeros = false;
			}
		}

		assert!(all_zeros)
	}

	#[test]
	fn blinding_factor_from_slice_rejects_invalid_nonzero_scalar() {
		assert!(BlindingFactor::from_slice(&[0xff; SECRET_KEY_SIZE]).is_err());
	}

	#[test]
	fn blinding_factor_from_slice_accepts_zero() {
		assert_eq!(
			BlindingFactor::from_slice(&[0; SECRET_KEY_SIZE]).unwrap(),
			BlindingFactor::zero()
		);
	}

	#[test]
	fn blinding_factor_from_hex_accepts_valid_zero_with_prefix() {
		let hex = format!("0x{}", "00".repeat(SECRET_KEY_SIZE));

		assert_eq!(
			BlindingFactor::from_hex(&hex).unwrap(),
			BlindingFactor::zero()
		);
	}

	#[test]
	fn blinding_factor_from_hex_rejects_invalid_input_without_echoing_it() {
		let invalid_hex = format!("{}zz", "aa".repeat(SECRET_KEY_SIZE - 1));

		assert_eq!(
			BlindingFactor::from_hex("0").unwrap_err(),
			Error::GenericError("invalid BlindingFactor hex length".into())
		);
		assert_eq!(
			BlindingFactor::from_hex(&invalid_hex).unwrap_err(),
			Error::GenericError("invalid BlindingFactor symbols".into())
		);
	}

	// split a key, sum the split keys and confirm the sum matches the original key
	#[test]
	fn split_blinding_factor() {
		let secp = Secp256k1::new().unwrap();
		let skey_in = SecretKey::new(&secp, &mut SysRng).unwrap();
		let blind = BlindingFactor::from_secret_key(skey_in.clone());
		let blind_1 = BlindingFactor::rand(&secp).unwrap();
		let blind_2 = blind.split(&blind_1, &secp).unwrap();

		let mut skey_sum = blind_1.secret_key(&secp).unwrap();
		let skey_2 = blind_2.secret_key(&secp).unwrap();
		skey_sum.add_assign(&secp, &skey_2).unwrap();
		assert_eq!(skey_in, skey_sum);
	}

	// Sanity check that we can add the zero key to a secret key and it is still
	// the same key that we started with (k + 0 = k)
	#[test]
	fn zero_key_addition() {
		let secp = Secp256k1::new().unwrap();
		let skey_in = SecretKey::new(&secp, &mut SysRng).unwrap();
		let skey_zero = ZERO_KEY;

		let mut skey_out = skey_in.clone();
		skey_out.add_assign(&secp, &skey_zero).unwrap();

		assert_eq!(skey_in, skey_out);
	}

	#[test]
	fn blinding_factor_add_returns_zero_for_inverse_factors() {
		let secp = Secp256k1::new().unwrap();
		let skey = SecretKey::new(&secp, &mut SysRng).unwrap();
		let inverse = secp.blind_sum(vec![], vec![skey.clone()]).unwrap();

		let sum = BlindingFactor::from_secret_key(skey)
			.add(&BlindingFactor::from_secret_key(inverse), &secp)
			.unwrap();

		assert_eq!(sum, BlindingFactor::zero());
	}

	// Check path identifiers
	#[test]
	fn path_identifier() {
		let path = ExtKeychainPath::new(4, 1, 2, 3, 4).unwrap();
		let id = Identifier::from_path(&path).unwrap();
		let ret_path = id.to_path().unwrap();
		assert_eq!(path, ret_path);

		let path = ExtKeychainPath::new(1, <u32>::max_value(), 0, 0, 0).unwrap();
		let id = Identifier::from_path(&path).unwrap();
		let ret_path = id.to_path().unwrap();
		assert_eq!(path, ret_path);

		let path = ExtKeychainPath::new(3, 0, 0, 10, 0).unwrap();
		let id = Identifier::from_path(&path).unwrap();
		let parent_id = id.parent_path().unwrap();
		let expected_path = ExtKeychainPath::new(2, 0, 0, 0, 0).unwrap();
		let expected_id = Identifier::from_path(&expected_path).unwrap();
		assert_eq!(expected_id, parent_id);
	}

	#[test]
	fn path_identifier_reject_unused_components() {
		let path = ExtKeychainPath {
			depth: 1,
			path: [
				ChildNumber::from(7),
				ChildNumber::from(9),
				ChildNumber::from(11),
				ChildNumber::from(13),
			],
		};
		assert!(Identifier::from_path(&path).is_err());
	}
}
