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

//! Transactions

use crate::core::hash::{DefaultHashable, Hash, Hashed};
use crate::core::{committed, Committed};
use crate::global::get_accept_fee_base;
use crate::libtx::{aggsig, secp_ser};
use crate::ser::{
	self, read_multi, PMMRable, ProtocolVersion, Readable, Reader, Writeable, Writer,
};
use crate::{consensus, global};
use keychain::{self, BlindingFactor};
use mwc_crates::enum_primitive::{
	enum_from_primitive, enum_from_primitive_impl, enum_from_primitive_impl_ty, FromPrimitive,
};
use mwc_crates::secp;
use mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_crates::secp::{constants, Secp256k1, SecretKey};
use mwc_crates::serde::de;
use mwc_crates::serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::Ordering;
use std::cmp::{max, min};
use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::fmt::Display;
use util;
use util::ToHex;

/// Fee fields as in fix-fees RFC: { future_use: 20, fee_shift: 4, fee: 40 }
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FeeFields(u64);

impl DefaultHashable for FeeFields {}

impl Writeable for FeeFields {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if let Err(e) = FeeFields::try_from(self.0) {
			return Err(ser::Error::CorruptedData(format!(
				"Serializing with invalid fee value, {}",
				e
			)));
		}
		writer.write_u64(self.0)
	}
}

impl Readable for FeeFields {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let fee_fields = reader.read_u64()?;
		match FeeFields::try_from(fee_fields) {
			Ok(f) => Ok(f),
			Err(e) => Err(ser::Error::CorruptedData(format!(
				"Deserializing with invalid fee value, {}",
				e
			))),
		}
	}
}

impl Display for FeeFields {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl Serialize for FeeFields {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		validate_fee(self.0)
			.map_err(|e| serde::ser::Error::custom(format!("invalid fee field, {}", e)))?;
		serializer.serialize_u64(self.0)
	}
}

impl<'de> Deserialize<'de> for FeeFields {
	fn deserialize<D>(deserializer: D) -> Result<FeeFields, D::Error>
	where
		D: Deserializer<'de>,
	{
		let value = u64::deserialize(deserializer)?;
		FeeFields::try_from(value)
			.map_err(|e| de::Error::custom(format!("invalid fee field, {}", e)))
	}
}

fn validate_fee(fee: u64) -> Result<(), Error> {
	if fee == 0 {
		Err(Error::InvalidFeeFields(format!("fee is zero")))
	} else if fee > FeeFields::FEE_MASK {
		Err(Error::InvalidFeeFields(format!("fee {} is too high", fee)))
	} else {
		Ok(())
	}
}

/// Conversion from a valid fee to a FeeFields with 0 fee_shift
/// The valid fee range is 1..FEE_MASK
impl TryFrom<u64> for FeeFields {
	type Error = Error;

	fn try_from(fee: u64) -> Result<Self, Self::Error> {
		validate_fee(fee)?;
		Ok(Self(fee))
	}
}

/// Conversion from a 32-bit valid fee to a FeeFields with 0 fee_shift.
impl TryFrom<u32> for FeeFields {
	type Error = Error;

	fn try_from(fee: u32) -> Result<Self, Self::Error> {
		FeeFields::try_from(u64::from(fee))
	}
}

impl From<FeeFields> for u64 {
	fn from(fee_fields: FeeFields) -> Self {
		fee_fields.0 as u64
	}
}

impl FeeFields {
	/// Fees are limited to 40 bits
	const FEE_BITS: u32 = 40;
	/// Used to extract fee field
	const FEE_MASK: u64 = (1u64 << FeeFields::FEE_BITS) - 1;

	/// Create a zero FeeFields with 0 fee and 0 fee_shift
	pub fn zero() -> Self {
		Self(0)
	}

	/// Create a new FeeFields from the provided shift and fee
	/// Checks both are valid (in range)
	pub fn new(fee: u64) -> Result<Self, Error> {
		fee.try_into()
	}

	/// Extract fee field
	pub fn fee(&self) -> u64 {
		self.0 & FeeFields::FEE_MASK
	}
}

fn fee_fields_as_int<S>(fee_fields: &FeeFields, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	validate_fee(fee_fields.0)
		.map_err(|e| serde::ser::Error::custom(format!("Invalid fee {}, {}", fee_fields.0, e)))?;
	serializer.serialize_u64(fee_fields.0)
}

/// Relative height field on NRD kernel variant.
/// u16 representing a height between 1 and MAX (consensus::WEEK_HEIGHT).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NRDRelativeHeight(u16);

impl DefaultHashable for NRDRelativeHeight {}

impl Writeable for NRDRelativeHeight {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		validate_nrd_height(self.0).map_err(|e| {
			ser::Error::CorruptedData(format!(
				"Serializing with invalid NRD relative height, {}",
				e
			))
		})?;
		writer.write_u16(self.0)
	}
}

impl Readable for NRDRelativeHeight {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let x = reader.read_u16()?;
		NRDRelativeHeight::try_from(x).map_err(|e| {
			ser::Error::CorruptedData(format!("Unable to read NRD Relative height, {}", e))
		})
	}
}

impl Serialize for NRDRelativeHeight {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		validate_nrd_height(self.0).map_err(|e| {
			serde::ser::Error::custom(format!("invalid NRD relative height, {}", e))
		})?;
		serializer.serialize_u16(self.0)
	}
}

impl<'de> Deserialize<'de> for NRDRelativeHeight {
	fn deserialize<D>(deserializer: D) -> Result<NRDRelativeHeight, D::Error>
	where
		D: Deserializer<'de>,
	{
		let height = u16::deserialize(deserializer)?;
		NRDRelativeHeight::try_from(height)
			.map_err(|e| de::Error::custom(format!("invalid NRD relative height, {}", e)))
	}
}

fn validate_nrd_height(height: u16) -> Result<(), Error> {
	if height == 0 || height > NRDRelativeHeight::MAX {
		Err(Error::InvalidNRDRelativeHeight)
	} else {
		Ok(())
	}
}

/// Conversion from a u16 to a valid NRDRelativeHeight.
/// Valid height is between 1 and WEEK_HEIGHT inclusive.
impl TryFrom<u16> for NRDRelativeHeight {
	type Error = Error;

	fn try_from(height: u16) -> Result<Self, Self::Error> {
		validate_nrd_height(height)?;
		Ok(Self(height))
	}
}

impl TryFrom<u64> for NRDRelativeHeight {
	type Error = Error;

	fn try_from(height: u64) -> Result<Self, Self::Error> {
		Self::try_from(u16::try_from(height).map_err(|_| Error::InvalidNRDRelativeHeight)?)
	}
}

impl From<NRDRelativeHeight> for u64 {
	fn from(height: NRDRelativeHeight) -> Self {
		height.0 as u64
	}
}

impl NRDRelativeHeight {
	// consensus::WEEK_HEIGHT is a constant that guaranteed to fit u16, so conversion is safe
	const MAX: u16 = consensus::WEEK_HEIGHT as u16;

	/// Create a new NRDRelativeHeight from the provided height.
	/// Checks height is valid (between 1 and WEEK_HEIGHT inclusive).
	pub fn new(height: u64) -> Result<Self, Error> {
		NRDRelativeHeight::try_from(height)
	}
}

/// Various tx kernel variants.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum KernelFeatures {
	/// Plain kernel (the default for Mwc txs).
	Plain {
		/// Plain kernels have fees.
		#[serde(serialize_with = "fee_fields_as_int")]
		fee: FeeFields,
	},
	/// A coinbase kernel.
	Coinbase,
	/// A kernel with an explicit lock height (and fee).
	HeightLocked {
		/// Height locked kernels have fees.
		#[serde(serialize_with = "fee_fields_as_int")]
		fee: FeeFields,
		/// Height locked kernels have lock heights.
		lock_height: u64,
	},
	/// "No Recent Duplicate" (NRD) kernels enforcing relative lock height between instances.
	NoRecentDuplicate {
		/// These have fees.
		#[serde(serialize_with = "fee_fields_as_int")]
		fee: FeeFields,
		/// Relative lock height.
		relative_height: NRDRelativeHeight,
	},
}

impl KernelFeatures {
	const PLAIN_U8: u8 = 0;
	const COINBASE_U8: u8 = 1;
	const HEIGHT_LOCKED_U8: u8 = 2;
	const NO_RECENT_DUPLICATE_U8: u8 = 3;

	/// Underlying (u8) value representing this kernel variant.
	/// This is the first byte when we serialize/deserialize the kernel features.
	pub fn as_u8(&self) -> u8 {
		match self {
			KernelFeatures::Plain { .. } => KernelFeatures::PLAIN_U8,
			KernelFeatures::Coinbase => KernelFeatures::COINBASE_U8,
			KernelFeatures::HeightLocked { .. } => KernelFeatures::HEIGHT_LOCKED_U8,
			KernelFeatures::NoRecentDuplicate { .. } => KernelFeatures::NO_RECENT_DUPLICATE_U8,
		}
	}

	/// Conversion for backward compatibility.
	pub fn as_string(&self) -> String {
		match self {
			KernelFeatures::Plain { .. } => String::from("Plain"),
			KernelFeatures::Coinbase => String::from("Coinbase"),
			KernelFeatures::HeightLocked { .. } => String::from("HeightLocked"),
			KernelFeatures::NoRecentDuplicate { .. } => String::from("NoRecentDuplicate"),
		}
	}

	/// msg = hash(features)                                  for coinbase kernels
	///       hash(features || fee_fields)                    for plain kernels
	///       hash(features || fee_fields || lock_height)     for height locked kernels
	///       hash(features || fee_fields || relative_height) for NRD kernels
	pub fn kernel_sig_msg(&self, context_id: u32) -> Result<secp::Message, Error> {
		let x = self.as_u8();
		let hash = match self {
			KernelFeatures::Plain { fee } => (x, fee).hash(context_id)?,
			KernelFeatures::Coinbase => x.hash(context_id)?,
			KernelFeatures::HeightLocked { fee, lock_height } => {
				(x, fee, lock_height).hash(context_id)?
			}
			KernelFeatures::NoRecentDuplicate {
				fee,
				relative_height,
			} => (x, fee, relative_height).hash(context_id)?,
		};

		let msg = secp::Message::from_slice(&hash.as_bytes())?;
		Ok(msg)
	}

	/// Get paid fee for this kernel
	/// Pessimistic because returned value can be higher then real fee if shift in not 0
	/// For out use case it is ok, there is no transaction priority or whatever
	pub fn get_fee_pessimistic(&self) -> u64 {
		match self {
			KernelFeatures::Plain { fee } => fee.0,
			KernelFeatures::Coinbase => 0,
			KernelFeatures::HeightLocked {
				fee,
				lock_height: _,
			} => fee.0,
			KernelFeatures::NoRecentDuplicate {
				fee,
				relative_height: _,
			} => fee.0,
		}
	}

	/// Write tx kernel features out in v1 protocol format.
	/// Always include the fee_fields and lock_height, writing 0 value if unused.
	fn write_v1<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.as_u8())?;
		match self {
			KernelFeatures::Plain { fee } => {
				fee.write(writer)?;
				// Write "empty" bytes for feature specific data (8 bytes).
				writer.write_empty_bytes(8)?;
			}
			KernelFeatures::Coinbase => {
				// Write "empty" bytes for fee_fields (8 bytes) and feature specific data (8 bytes).
				writer.write_empty_bytes(16)?;
			}
			KernelFeatures::HeightLocked { fee, lock_height } => {
				fee.write(writer)?;
				// 8 bytes of feature specific data containing the lock height as big-endian u64.
				writer.write_u64(*lock_height)?;
			}
			KernelFeatures::NoRecentDuplicate {
				fee,
				relative_height,
			} => {
				fee.write(writer)?;

				// 8 bytes of feature specific data. First 6 bytes are empty.
				// Last 2 bytes contain the relative lock height as big-endian u16.
				// Note: This is effectively the same as big-endian u64.
				// We write "empty" bytes explicitly rather than quietly casting the u16 -> u64.
				writer.write_empty_bytes(6)?;
				relative_height.write(writer)?;
			}
		};
		Ok(())
	}

	/// Write tx kernel features out in v2 protocol format.
	/// These are variable sized based on feature variant.
	/// Only write fee_fields out for feature variants that support it.
	/// Only write lock_height out for feature variants that support it.
	fn write_v2<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.as_u8())?;
		match self {
			KernelFeatures::Plain { fee } => {
				// Fee only, no additional data on plain kernels.
				fee.write(writer)?;
			}
			KernelFeatures::Coinbase => {
				// No additional data.
			}
			KernelFeatures::HeightLocked { fee, lock_height } => {
				fee.write(writer)?;
				// V2 height locked kernels use 8 bytes for the lock height.
				writer.write_u64(*lock_height)?;
			}
			KernelFeatures::NoRecentDuplicate {
				fee,
				relative_height,
			} => {
				fee.write(writer)?;
				// V2 NRD kernels use 2 bytes for the relative lock height.
				relative_height.write(writer)?;
			}
		}
		Ok(())
	}

	// Always read feature byte, 8 bytes for fee_fields and 8 bytes for additional data
	// representing lock height or relative height.
	// Fee and additional data may be unused for some kernel variants but we need
	// to read these bytes and verify they are 0 if unused.
	fn read_v1<R: Reader>(reader: &mut R) -> Result<KernelFeatures, ser::Error> {
		let feature_byte = reader.read_u8()?;
		let features = match feature_byte {
			KernelFeatures::PLAIN_U8 => {
				let fee = FeeFields::read(reader)?;
				// 8 "empty" bytes as additional data is not used.
				reader.read_empty_bytes(8)?;
				KernelFeatures::Plain { fee }
			}
			KernelFeatures::COINBASE_U8 => {
				// 8 "empty" bytes as fee_fields is not used.
				// 8 "empty" bytes as additional data is not used.
				reader.read_empty_bytes(16)?;
				KernelFeatures::Coinbase
			}
			KernelFeatures::HEIGHT_LOCKED_U8 => {
				let fee = FeeFields::read(reader)?;
				// 8 bytes of feature specific data, lock height as big-endian u64.
				let lock_height = reader.read_u64()?;
				KernelFeatures::HeightLocked { fee, lock_height }
			}
			KernelFeatures::NO_RECENT_DUPLICATE_U8 => {
				// NRD kernels are invalid if NRD feature flag is not enabled.
				if !global::is_nrd_enabled(reader.get_context_id()) {
					return Err(ser::Error::CorruptedData("NRD is disabled".to_string()));
				}

				let fee = FeeFields::read(reader)?;

				// 8 bytes of feature specific data.
				// The first 6 bytes must be "empty".
				// The last 2 bytes is the relative height as big-endian u16.
				reader.read_empty_bytes(6)?;
				let relative_height = NRDRelativeHeight::read(reader)?;
				KernelFeatures::NoRecentDuplicate {
					fee,
					relative_height,
				}
			}
			f => {
				return Err(ser::Error::CorruptedData(format!(
					"Unknown kernel feature {}",
					f
				)));
			}
		};
		Ok(features)
	}

	// V2 kernels only expect bytes specific to each variant.
	// Coinbase kernels have no associated fee and we do not serialize a fee for these.
	fn read_v2<R: Reader>(reader: &mut R) -> Result<KernelFeatures, ser::Error> {
		let features = match reader.read_u8()? {
			KernelFeatures::PLAIN_U8 => {
				let fee = FeeFields::read(reader)?;
				KernelFeatures::Plain { fee }
			}
			KernelFeatures::COINBASE_U8 => KernelFeatures::Coinbase,
			KernelFeatures::HEIGHT_LOCKED_U8 => {
				let fee = FeeFields::read(reader)?;
				let lock_height = reader.read_u64()?;
				KernelFeatures::HeightLocked { fee, lock_height }
			}
			KernelFeatures::NO_RECENT_DUPLICATE_U8 => {
				// NRD kernels are invalid if NRD feature flag is not enabled.
				if !global::is_nrd_enabled(reader.get_context_id()) {
					return Err(ser::Error::CorruptedData("NRD is disabled".to_string()));
				}

				let fee = FeeFields::read(reader)?;
				let relative_height = NRDRelativeHeight::read(reader)?;
				KernelFeatures::NoRecentDuplicate {
					fee,
					relative_height,
				}
			}
			f => {
				return Err(ser::Error::CorruptedData(format!(
					"Unknown kernel feature {}",
					f
				)));
			}
		};
		Ok(features)
	}
}

impl Writeable for KernelFeatures {
	/// Protocol version may increment rapidly for other unrelated changes.
	/// So we match on ranges here and not specific version values.
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// Care must be exercised when writing for hashing purposes.
		// All kernels are hashed using original v1 serialization strategy.
		if writer.serialization_mode().is_hash_mode() {
			return self.write_v1(writer);
		}

		match writer.protocol_version().value() {
			0..=1 => self.write_v1(writer),
			2..=ProtocolVersion::MAX => self.write_v2(writer),
		}
	}
}

impl Readable for KernelFeatures {
	fn read<R: Reader>(reader: &mut R) -> Result<KernelFeatures, ser::Error> {
		match reader.protocol_version().value() {
			0..=1 => KernelFeatures::read_v1(reader),
			2..=ProtocolVersion::MAX => KernelFeatures::read_v2(reader),
		}
	}
}

/// Errors thrown by Transaction validation
#[derive(thiserror::Error, Debug)]
pub enum Error {
	/// Underlying Secp256k1 error (signature validation or invalid public key
	/// typically)
	#[error("Secp256k1 error, {0}")]
	Secp(secp::Error),
	/// Underlying keychain related error
	#[error("Keychain error, {0}")]
	Keychain(#[from] keychain::Error),
	/// The sum of output minus input commitments does not
	/// match the sum of kernel commitments
	#[error("Tx Kernel Sum Mismatch")]
	KernelSumMismatch,
	/// Restrict tx total weight.
	#[error("Tx total weight too heavy")]
	TooHeavy,
	/// Error originating from an invalid lock-height
	#[error("Tx Invalid lock height {0}")]
	LockHeight(u64),
	/// Range proof validation error
	#[error("Tx Invalid range proof")]
	RangeProof,
	/// Error originating from an invalid Merkle proof
	#[error("Tx Invalid Merkle Proof")]
	MerkleProof,
	/// Returns if the value hidden within the a RangeProof message isn't
	/// repeated 3 times, indicating it's incorrect
	#[error("Tx Invalid Proof Message")]
	InvalidProofMessage,
	/// Error when verifying kernel sums via committed trait.
	#[error("Tx Verifying kernel sums error, {0}")]
	Committed(#[from] committed::Error),
	/// Validation error relating to cut-through (tx is spending its own
	/// output).
	#[error("Tx cut through error")]
	CutThrough,
	/// Validation error relating to output features.
	/// It is invalid for a transaction to contain a coinbase output, for example.
	#[error("Tx Invalid output feature")]
	InvalidOutputFeatures,
	/// Validation error relating to duplicate output identifiers.
	#[error("Tx Duplicate output")]
	DuplicateOutput,
	/// Validation error relating to duplicate input identifiers.
	#[error("Tx Duplicate input")]
	DuplicateInput,
	/// Validation error relating to duplicate kernel identifiers.
	#[error("Tx Duplicate kernel")]
	DuplicateKernel,
	/// Validation error relating to kernel features.
	/// It is invalid for a transaction to contain a coinbase kernel, for example.
	#[error("Tx Invalid kernel feature")]
	InvalidKernelFeatures,
	/// feeshift is limited to 4 bits and fee must be positive and fit in 40 bits.
	#[error("Invalid Fee Fields, {0}")]
	InvalidFeeFields(String),
	/// NRD kernel relative height is limited to 1 week duration and must be greater than 0.
	#[error("Invalid NRD kernel relative height")]
	InvalidNRDRelativeHeight,
	/// NRD kernels are not valid if disabled locally via "feature flag".
	#[error("NRD kernels are not valid, disabled locally via 'feature flag'")]
	NRDKernelNotEnabled,
	/// Signature verification error.
	#[error("Tx Invalid signature")]
	IncorrectSignature,
	/// Underlying serialization error.
	#[error("Tx Serialization error, {0}")]
	Serialization(#[from] ser::Error),
	/// Underlying IO error.
	#[error("Tx IO error, {0}")]
	IO(#[from] std::io::Error),
	/// Data overflow error.
	#[error("Tx data overflow error, {0}")]
	DataOverflow(String),
	/// Generic error
	#[error("{0}")]
	Generic(String),
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::Secp(e)
	}
}

fn map_duplicate_error(err: ser::Error, duplicate: Error) -> Error {
	match err {
		ser::Error::DuplicateError => duplicate,
		err => err.into(),
	}
}

/// A proof that a transaction sums to zero. Includes both the transaction's
/// Pedersen commitment and the signature, that guarantees that the commitments
/// amount to zero.
/// The signature signs the fee_fields and the lock_height, which are retained for
/// signature validation.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(crate = "serde")]
pub struct TxKernel {
	/// Options for a kernel's structure or use
	pub features: KernelFeatures,
	/// Remainder of the sum of all transaction commitments. If the transaction
	/// is well formed, amounts components should sum to zero and the excess
	/// is hence a valid public key (sum of the commitment public keys).
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub excess: Commitment,
	/// The signature proving the excess is a valid public key, which signs
	/// the transaction fee_fields.
	#[serde(with = "secp_ser::sig_serde")]
	pub excess_sig: secp::AggSigSignature,
}

impl DefaultHashable for TxKernel {}
// Consensus ordering and equality for kernels is by canonical hash, not by
// trait implementations on the type. Use ser::sort_by_hash,
// ser::verify_sorted_and_unique_by_hash, ser::hashes_equal,
// ser::slices_equal_by_hash, or ser::contains_by_hash so hash calculation
// errors are returned to callers instead of being hidden behind infallible
// Ord/PartialEq/Eq/std::hash traits.

impl Writeable for TxKernel {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		self.excess.write(writer)?;
		self.excess_sig.write(writer)?;
		Ok(())
	}
}

impl Readable for TxKernel {
	fn read<R: Reader>(reader: &mut R) -> Result<TxKernel, ser::Error> {
		Ok(TxKernel {
			features: KernelFeatures::read(reader)?,
			excess: Commitment::read(reader)?,
			excess_sig: secp::AggSigSignature::read(reader)?,
		})
	}
}

/// We store kernels in the kernel MMR.
/// Note: These are "variable size" to support different kernel feature variants.
impl PMMRable for TxKernel {
	type E = Self;

	fn as_elmt(&self) -> Result<TxKernel, crate::ser::Error> {
		Ok(self.clone())
	}

	fn elmt_size() -> Option<u16> {
		None
	}
}

impl KernelFeatures {
	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		match self {
			KernelFeatures::Coinbase => true,
			_ => false,
		}
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		match self {
			KernelFeatures::Plain { .. } => true,
			_ => false,
		}
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		match self {
			KernelFeatures::HeightLocked { .. } => true,
			_ => false,
		}
	}

	/// Is this an NRD kernel?
	pub fn is_nrd(&self) -> bool {
		match self {
			KernelFeatures::NoRecentDuplicate { .. } => true,
			_ => false,
		}
	}
}

impl TxKernel {
	/// Estimated data size for TxKernel
	pub const DATA_SIZE: usize =
		(1 + 8 + 8) + constants::PEDERSEN_COMMITMENT_SIZE + constants::COMPACT_SIGNATURE_SIZE;

	/// Is this a coinbase kernel?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain kernel?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}

	/// Is this a height locked kernel?
	pub fn is_height_locked(&self) -> bool {
		self.features.is_height_locked()
	}

	/// Is this an NRD kernel?
	pub fn is_nrd(&self) -> bool {
		self.features.is_nrd()
	}

	/// Return the excess commitment for this tx_kernel.
	pub fn excess(&self) -> Commitment {
		self.excess
	}

	/// The msg signed as part of the tx kernel.
	/// Based on kernel features and associated fields (fee_fields and lock_height).
	pub fn msg_to_sign(&self, context_id: u32) -> Result<secp::Message, Error> {
		let msg = self.features.kernel_sig_msg(context_id)?;
		Ok(msg)
	}

	/// Verify the transaction proof validity. Entails handling the commitment
	/// as a public key and checking the signature verifies with the fee_fields as
	/// message.
	pub fn verify(&self, context_id: u32, secp: &Secp256k1) -> Result<(), Error> {
		let sig = &self.excess_sig;
		// Verify aggsig directly in libsecp
		let pubkey = &self.excess.to_pubkey(&secp)?;
		if !aggsig::verify_single(
			&secp,
			&sig,
			&self.msg_to_sign(context_id)?,
			None,
			pubkey,
			pubkey,
			false,
		)
		.map_err(|e| Error::Generic(format!("aggsig::verify_single error, {}", e)))?
		{
			return Err(Error::IncorrectSignature);
		}
		Ok(())
	}

	/// Batch signature verification.
	pub fn batch_sig_verify(
		context_id: u32,
		tx_kernels: &[TxKernel],
		secp: &Secp256k1,
	) -> Result<(), Error> {
		let len = tx_kernels.len();
		let mut sigs = Vec::with_capacity(len);
		let mut pubkeys = Vec::with_capacity(len);
		let mut msgs = Vec::with_capacity(len);

		for tx_kernel in tx_kernels {
			sigs.push(tx_kernel.excess_sig);
			pubkeys.push(tx_kernel.excess.to_pubkey(&secp)?);
			msgs.push(tx_kernel.msg_to_sign(context_id)?);
		}

		if !aggsig::verify_batch(&secp, &sigs, &msgs, &pubkeys)
			.map_err(|e| Error::Generic(format!("aggsig::verify_batch error, {}", e)))?
		{
			return Err(Error::IncorrectSignature);
		}

		Ok(())
	}

	/// Build an empty tx kernel with zero values.
	pub fn empty() -> Result<TxKernel, Error> {
		TxKernel::with_features(KernelFeatures::Plain {
			fee: FeeFields::zero(),
		})
	}

	/// Build an empty tx kernel with the provided kernel features.
	pub fn with_features(features: KernelFeatures) -> Result<TxKernel, Error> {
		Ok(TxKernel {
			features,
			excess: Commitment::from_vec(vec![0; constants::PEDERSEN_COMMITMENT_SIZE])?,
			excess_sig: secp::AggSigSignature::blank(),
		})
	}
}

/// Enum of possible tx weight verification options -
///
/// * As "transaction" checks tx (as block) weight does not exceed max_block_weight.
/// * As "block" same as above but allow for additional coinbase reward (1 output, 1 kernel).
/// * With "no limit" to skip the weight check.
///
#[derive(Clone, Copy)]
pub enum Weighting {
	/// Tx represents a tx (max block weight, accounting for additional coinbase reward).
	AsTransaction,
	/// Tx representing a tx with artificially limited max_weight.
	/// This is used when selecting mineable txs from the pool.
	AsLimitedTransaction(u64),
	/// Tx represents a block (max block weight).
	AsBlock,
	/// No max weight limit (skip the weight check).
	NoLimit,
}

/// TransactionBody is a common abstraction for transaction and block
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct TransactionBody {
	/// List of inputs spent by the transaction.
	pub inputs: Inputs,
	/// List of outputs the transaction produces.
	pub outputs: Vec<Output>,
	/// List of kernels that make up this transaction (usually a single kernel).
	pub kernels: Vec<TxKernel>,
}

/// Implementation of Writeable for a body, defines how to
/// write the body as binary.
impl Writeable for TransactionBody {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		TransactionBody::verify_transaction_write_weight_for_size(
			writer.get_context_id(),
			self.inputs.len() as u64,
			self.outputs.len() as u64,
			self.kernels.len() as u64,
		)?;

		ser_multiwrite!(
			writer,
			[write_u64, self.inputs.len() as u64],
			[write_u64, self.outputs.len() as u64],
			[write_u64, self.kernels.len() as u64]
		);

		self.inputs.write(writer)?;
		self.outputs.write(writer)?;
		self.kernels.write(writer)?;

		Ok(())
	}
}

/// Implementation of Readable for a body, defines how to read a
/// body from a binary stream.
impl Readable for TransactionBody {
	fn read<R: Reader>(reader: &mut R) -> Result<TransactionBody, ser::Error> {
		let (num_inputs, num_outputs, num_kernels) =
			ser_multiread!(reader, read_u64, read_u64, read_u64);

		// Quick block weight check before proceeding.
		// Note: We use weight_as_block here (inputs have weight).
		TransactionBody::verify_transaction_read_weight_for_size(
			reader.get_context_id(),
			num_inputs,
			num_outputs,
			num_kernels,
		)?;

		// Read protocol version specific inputs.
		let inputs = match reader.protocol_version().value() {
			0..=2 => {
				let inputs: Vec<Input> = read_multi(reader, num_inputs)?;
				Inputs::from(inputs.as_slice())
			}
			3..=ser::ProtocolVersion::MAX => {
				let inputs: Vec<CommitWrapper> = read_multi(reader, num_inputs)?;
				Inputs::from(inputs.as_slice())
			}
		};

		let outputs = read_multi(reader, num_outputs)?;
		let kernels = read_multi(reader, num_kernels)?;

		// Initialize tx body and verify everything is sorted.
		let body = TransactionBody::init(reader.get_context_id(), inputs, &outputs, &kernels, true)
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read transaction, {}", e)))?;

		Ok(body)
	}
}

impl Committed for TransactionBody {
	fn inputs_committed(
		&self,
	) -> Result<committed::CommitmentIterator<'_>, crate::core::committed::Error> {
		let iter: committed::CommitmentIterator<'_> = match &self.inputs {
			Inputs::CommitOnly(inputs) => Box::new(inputs.iter().map(|x| Ok(x.commitment()))),
			Inputs::FeaturesAndCommit(inputs) => {
				Box::new(inputs.iter().map(|x| Ok(x.commitment())))
			}
		};
		Ok(iter)
	}

	fn outputs_committed(
		&self,
	) -> Result<committed::CommitmentIterator<'_>, crate::core::committed::Error> {
		Ok(Box::new(self.outputs().iter().map(|x| Ok(x.commitment()))))
	}

	fn kernels_committed(
		&self,
	) -> Result<committed::CommitmentIterator<'_>, crate::core::committed::Error> {
		Ok(Box::new(self.kernels().iter().map(|x| Ok(x.excess()))))
	}
}

impl Default for TransactionBody {
	fn default() -> TransactionBody {
		TransactionBody::empty()
	}
}

impl TransactionBody {
	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> TransactionBody {
		TransactionBody {
			inputs: Inputs::default(),
			outputs: vec![],
			kernels: vec![],
		}
	}

	/// Sort the inputs|outputs|kernels.
	pub fn sort(&mut self, context_id: u32) -> Result<(), Error> {
		self.inputs.sort_by_hash(context_id)?;
		ser::sort_by_hash_key(context_id, &mut self.outputs, |output| &output.identifier)?;
		ser::sort_by_hash(context_id, &mut self.kernels)?;
		Ok(())
	}

	/// Creates a new transaction body initialized with
	/// the provided inputs, outputs and kernels.
	/// Guarantees inputs, outputs, kernels are sorted lexicographically.
	pub fn init(
		context_id: u32,
		inputs: Inputs,
		outputs: &[Output],
		kernels: &[TxKernel],
		verify_sorted: bool,
	) -> Result<TransactionBody, Error> {
		let mut body = TransactionBody {
			inputs,
			outputs: outputs.to_vec(),
			kernels: kernels.to_vec(),
		};

		if verify_sorted {
			// If we are verifying sort order then verify and
			// return an error if not sorted lexicographically.
			body.verify_sorted(context_id)?;
		} else {
			// If we are not verifying sort order then sort in place and return.
			body.sort(context_id)?;
		}
		Ok(body)
	}

	/// Transaction inputs.
	pub fn inputs(&self) -> Inputs {
		self.inputs.clone()
	}

	/// Transaction outputs.
	pub fn outputs(&self) -> &[Output] {
		&self.outputs
	}

	/// Transaction kernels.
	pub fn kernels(&self) -> &[TxKernel] {
		&self.kernels
	}

	/// Compare two transaction bodies by consensus hash ordering/equality.
	///
	/// Outputs are compared by their output identifiers only. This intentionally
	/// ignores rangeproof bytes because the output commitment is the identity that
	/// matters for this comparison.
	pub fn eq_by_hash(&self, context_id: u32, other: &Self) -> Result<bool, Error> {
		if !self.inputs.eq_by_hash(context_id, &other.inputs)? {
			return Ok(false);
		}
		if !ser::slices_equal_by_hash_key(context_id, &self.outputs, &other.outputs, |output| {
			&output.identifier
		})? {
			return Ok(false);
		}
		Ok(ser::slices_equal_by_hash(
			context_id,
			&self.kernels,
			&other.kernels,
		)?)
	}

	/// Builds a new body with the provided inputs added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(mut self, context_id: u32, input: Input) -> Result<TransactionBody, Error> {
		let inputs = match &mut self.inputs {
			Inputs::CommitOnly(_) => {
				return Err(Error::Generic(
					"cannot add feature-bearing input to commit-only inputs; use with_commit_input to explicitly drop input features".into(),
				));
			}
			Inputs::FeaturesAndCommit(inputs) => inputs,
		};
		ser::sort_by_hash(context_id, inputs)?;
		ser::verify_sorted_and_unique_by_hash(context_id, inputs)
			.map_err(|e| map_duplicate_error(e, Error::DuplicateInput))?;
		let inserted = ser::insert_unique_by_hash(context_id, inputs, input)?;
		if !inserted {
			return Err(Error::DuplicateInput);
		}
		Ok(self)
	}

	/// Builds a new body with the provided commitment-only input added.
	///
	/// This is intentionally lossy when the caller starts from a full `Input`:
	/// `Input::features` is not stored in the `Inputs::CommitOnly` representation.
	/// Use `with_input` on an `Inputs::FeaturesAndCommit` body when feature
	/// metadata must be preserved.
	pub fn with_commit_input(
		mut self,
		context_id: u32,
		commit: Commitment,
	) -> Result<TransactionBody, Error> {
		let inputs = match &mut self.inputs {
			Inputs::CommitOnly(inputs) => inputs,
			Inputs::FeaturesAndCommit(_) => {
				return Err(Error::Generic(
					"cannot add commit-only input to feature-preserving inputs".into(),
				));
			}
		};
		ser::sort_by_hash(context_id, inputs)?;
		ser::verify_sorted_and_unique_by_hash(context_id, inputs)
			.map_err(|e| map_duplicate_error(e, Error::DuplicateInput))?;
		let inserted = ser::insert_unique_by_hash(context_id, inputs, CommitWrapper::from(commit))?;
		if !inserted {
			return Err(Error::DuplicateInput);
		}
		Ok(self)
	}

	/// Fully replace inputs.
	pub fn replace_inputs(
		mut self,
		context_id: u32,
		mut inputs: Inputs,
	) -> Result<TransactionBody, Error> {
		match &mut inputs {
			Inputs::CommitOnly(inputs) => {
				ser::sort_by_hash(context_id, inputs)?;
				ser::verify_sorted_and_unique_by_hash(context_id, inputs)?;
			}
			Inputs::FeaturesAndCommit(inputs) => {
				ser::sort_by_hash(context_id, inputs)?;
				ser::verify_sorted_and_unique_by_hash(context_id, inputs)?;
			}
		}

		self.inputs = inputs;
		Ok(self)
	}

	/// Builds a new TransactionBody with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(
		mut self,
		context_id: u32,
		output: Output,
	) -> Result<TransactionBody, Error> {
		let inserted =
			ser::insert_unique_by_hash_key(context_id, &mut self.outputs, output, |output| {
				&output.identifier
			})?;
		if !inserted {
			return Err(Error::DuplicateOutput);
		}
		Ok(self)
	}

	/// Fully replace outputs.
	pub fn replace_outputs(
		mut self,
		context_id: u32,
		outputs: &[Output],
	) -> Result<TransactionBody, Error> {
		let mut outputs = outputs.to_vec();
		ser::sort_by_hash(context_id, &mut outputs)?;
		ser::verify_sorted_and_unique_by_hash(context_id, &outputs)?;

		self.outputs = outputs;
		Ok(self)
	}

	/// Builds a new TransactionBody with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(
		mut self,
		context_id: u32,
		kernel: TxKernel,
	) -> Result<TransactionBody, Error> {
		let inserted = ser::insert_unique_by_hash(context_id, &mut self.kernels, kernel)?;
		if !inserted {
			return Err(Error::DuplicateKernel);
		}
		Ok(self)
	}

	/// Builds a new TransactionBody replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(mut self, kernel: TxKernel) -> TransactionBody {
		self.kernels.clear();
		self.kernels.push(kernel);
		self
	}

	/// Total fee for a TransactionBody is the sum of fees of all fee carrying kernels.
	pub fn fee(&self) -> Result<u64, Error> {
		self.kernels
			.iter()
			.filter_map(|k| match k.features {
				KernelFeatures::Coinbase => None,
				KernelFeatures::Plain { fee } => Some(fee),
				KernelFeatures::HeightLocked { fee, .. } => Some(fee),
				KernelFeatures::NoRecentDuplicate { fee, .. } => Some(fee),
			})
			.try_fold(0u64, |acc, fee_fields| {
				let fee = fee_fields.fee();
				acc.checked_add(fee).ok_or_else(|| {
					Error::DataOverflow(format!("TransactionBody::fee, acc={} fee={}", acc, fee))
				})
			})
	}

	fn overage(&self) -> Result<i64, Error> {
		let fee = self.fee()?;
		i64::try_from(fee)
			.map_err(|_| Error::DataOverflow(format!("TransactionBody::overage, fee={}", fee)))
	}

	/// Calculate weight of transaction using block weighing
	pub fn weight_size(&self) -> Result<u64, Error> {
		Transaction::weight_for_size(
			self.inputs.len() as u64,
			self.outputs.len() as u64,
			self.kernels.len() as u64,
		)
	}

	/// Lock height of a body is the max lock height of the kernels.
	pub fn lock_height(&self) -> u64 {
		self.kernels
			.iter()
			.filter_map(|x| match x.features {
				KernelFeatures::HeightLocked { lock_height, .. } => Some(lock_height),
				_ => None,
			})
			.max()
			.unwrap_or(0)
	}

	/// Verify the body is not too big in terms of number of inputs|outputs|kernels.
	/// Weight rules vary depending on the "weight type" (block or tx or pool).
	fn verify_weight(&self, context_id: u32, weighting: Weighting) -> Result<(), Error> {
		// A coinbase reward is a single output and a single kernel (for now).
		// We need to account for this when verifying max tx weights.
		let coinbase_weight = consensus::BLOCK_OUTPUT_WEIGHT + consensus::BLOCK_KERNEL_WEIGHT;

		// If "tx" body then remember to reduce the max_block_weight by the weight of a kernel.
		// If "limited tx" then compare against the provided max_weight.
		// If "block" body then verify weight based on full set of inputs|outputs|kernels.
		// If "pool" body then skip weight verification (pool can be larger than single block).
		//
		// Note: Taking a max tx and building a block from it we need to allow room
		// for the additional coinbase reward (1 output + 1 kernel).
		//
		let max_weight = match weighting {
			Weighting::AsTransaction => global::max_tx_weight(context_id),
			Weighting::AsLimitedTransaction(max_weight) => {
				min(global::max_block_weight(context_id), max_weight)
					.saturating_sub(coinbase_weight)
			}
			Weighting::AsBlock => global::max_block_weight(context_id),
			Weighting::NoLimit => {
				// We do not verify "tx as pool" weight so we are done here.
				return Ok(());
			}
		};

		if self.weight_size()? > max_weight {
			return Err(Error::TooHeavy);
		}
		Ok(())
	}

	// It is never valid to have multiple duplicate NRD kernels (by public excess)
	// in the same transaction or block. We check this here.
	// We skip this check if NRD feature is not enabled.
	fn verify_no_nrd_duplicates(&self, context_id: u32) -> Result<(), Error> {
		if !global::is_nrd_enabled(context_id) {
			return Ok(());
		}

		let mut nrd_excess: Vec<Commitment> = self
			.kernels
			.iter()
			.filter(|x| match x.features {
				KernelFeatures::NoRecentDuplicate { .. } => true,
				_ => false,
			})
			.map(|x| x.excess())
			.collect();

		// Sort and dedup and compare length to look for duplicates.
		nrd_excess.sort();
		let original_count = nrd_excess.len();
		nrd_excess.dedup();
		let dedup_count = nrd_excess.len();
		if original_count == dedup_count {
			Ok(())
		} else {
			Err(Error::InvalidNRDRelativeHeight)
		}
	}

	// NRD kernels are not valid in transactions if the global feature flag is disabled.
	fn verify_nrd_enabled(&self, context_id: u32) -> Result<(), Error> {
		if self.kernels.iter().any(|kernel| kernel.is_nrd()) && !global::is_nrd_enabled(context_id)
		{
			return Err(Error::NRDKernelNotEnabled);
		}
		Ok(())
	}

	// Verify that inputs|outputs|kernels are sorted in lexicographical order
	// and that there are no duplicates (they are all unique within this transaction).
	fn verify_sorted(&self, context_id: u32) -> Result<(), Error> {
		self.inputs.verify_sorted_and_unique(context_id)?;
		ser::verify_sorted_and_unique_by_hash_key(context_id, &self.outputs, |output| {
			&output.identifier
		})?;
		ser::verify_sorted_and_unique_by_hash(context_id, &self.kernels)?;
		Ok(())
	}

	// Returns a single sorted vec of all input and output commitments.
	// This gives us a convenient way of verifying cut_through.
	fn inputs_outputs_committed(&self) -> Result<Vec<Commitment>, Error> {
		let inputs = self.inputs_committed()?;
		let outputs = self.outputs_committed()?;
		let mut commits = inputs.chain(outputs).collect::<Result<Vec<_>, _>>()?;
		commits.sort_unstable();
		Ok(commits)
	}

	// Verify that no input is spending an output from the same block.
	// The inputs and outputs are not guaranteed to be sorted consistently once we support "commit only" inputs.
	// We need to allocate as we need to sort the commitments so we keep this very simple and just look
	// for duplicates across all input and output commitments.
	fn verify_cut_through(&self) -> Result<(), Error> {
		let commits = self.inputs_outputs_committed()?;
		for pair in commits.windows(2) {
			if pair[0] == pair[1] {
				return Err(Error::CutThrough);
			}
		}
		Ok(())
	}

	/// Verify we have no invalid outputs or kernels in the transaction
	/// due to invalid features.
	/// Specifically, a transaction cannot contain a coinbase output or a coinbase kernel.
	pub fn verify_features(&self) -> Result<(), Error> {
		self.verify_output_features()?;
		self.verify_kernel_features()?;
		Ok(())
	}

	// Verify we have no outputs tagged as COINBASE.
	fn verify_output_features(&self) -> Result<(), Error> {
		if self.outputs.iter().any(|x| x.is_coinbase()) {
			return Err(Error::InvalidOutputFeatures);
		}
		Ok(())
	}

	// Verify we have no kernels tagged as COINBASE.
	fn verify_kernel_features(&self) -> Result<(), Error> {
		if self.kernels.iter().any(|x| x.is_coinbase()) {
			return Err(Error::InvalidKernelFeatures);
		}
		Ok(())
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification
	/// * kernel signature verification
	pub fn validate_read(&self, context_id: u32, weighting: Weighting) -> Result<(), Error> {
		self.verify_weight(context_id, weighting)?;
		self.verify_no_nrd_duplicates(context_id)?;
		self.verify_sorted(context_id)?;
		self.verify_cut_through()?;
		Ok(())
	}

	/// Validates all relevant parts of a transaction body. Checks the
	/// excess value against the signature as well as range proofs for each
	/// output.
	pub fn validate(
		&self,
		context_id: u32,
		weighting: Weighting,
		secp: &mut Secp256k1,
	) -> Result<(), Error> {
		self.validate_read(context_id, weighting)?;

		// Now batch verify all those unverified rangeproofs
		if !self.outputs.is_empty() {
			let mut commits = vec![];
			let mut proofs = vec![];
			for x in &self.outputs {
				commits.push(x.commitment());
				proofs.push(x.proof);
			}
			Output::batch_verify_proofs(&commits, &proofs, secp)?;
		}

		// Verify the unverified tx kernels.
		TxKernel::batch_sig_verify(context_id, &self.kernels, secp)?;
		Ok(())
	}

	fn verify_count_limit(
		label: &str,
		field: &str,
		count: u64,
		too_large_err: fn(String) -> ser::Error,
	) -> Result<(), ser::Error> {
		if count > ser::READ_VEC_SIZE_LIMIT {
			return Err(too_large_err(format!(
				"{} has too many {}: {}, limit {}",
				label,
				field,
				count,
				ser::READ_VEC_SIZE_LIMIT
			)));
		}
		Ok(())
	}

	fn verify_normalized_weight_for_size(
		context_id: u32,
		label: &str,
		num_inputs: u64,
		num_outputs: u64,
		num_kernels: u64,
		too_large_err: fn(String) -> ser::Error,
	) -> Result<(), ser::Error> {
		let body_weight = Transaction::weight_for_size(num_inputs, num_outputs, num_kernels)
			.map_err(|e| match e {
				Error::DataOverflow(msg) => ser::Error::DataOverflow(msg),
				other => ser::Error::CorruptedData(format!(
					"Failed to calculate {} weight, {}",
					label, other
				)),
			})?;
		let max_weight = global::max_block_weight(context_id);
		if body_weight > max_weight {
			return Err(too_large_err(format!(
				"{} weight {} is too heavy. Limit value {}",
				label, body_weight, max_weight
			)));
		}
		Ok(())
	}

	fn verify_transaction_weight_for_size(
		context_id: u32,
		num_inputs: u64,
		num_outputs: u64,
		num_kernels: u64,
		too_large_err: fn(String) -> ser::Error,
	) -> Result<(), ser::Error> {
		const LABEL: &str = "TransactionBody";
		TransactionBody::verify_count_limit(LABEL, "inputs", num_inputs, too_large_err)?;
		TransactionBody::verify_count_limit(LABEL, "outputs", num_outputs, too_large_err)?;
		TransactionBody::verify_count_limit(LABEL, "kernels", num_kernels, too_large_err)?;
		TransactionBody::verify_normalized_weight_for_size(
			context_id,
			LABEL,
			num_inputs,
			num_outputs,
			num_kernels,
			too_large_err,
		)
	}

	/// Verify transaction vector counts and consensus weight before reading item data.
	pub fn verify_transaction_read_weight_for_size(
		context_id: u32,
		num_inputs: u64,
		num_outputs: u64,
		num_kernels: u64,
	) -> Result<(), ser::Error> {
		TransactionBody::verify_transaction_weight_for_size(
			context_id,
			num_inputs,
			num_outputs,
			num_kernels,
			ser::Error::TooLargeReadErr,
		)
	}

	/// Verify transaction vector counts and consensus weight before writing item data.
	pub fn verify_transaction_write_weight_for_size(
		context_id: u32,
		num_inputs: u64,
		num_outputs: u64,
		num_kernels: u64,
	) -> Result<(), ser::Error> {
		TransactionBody::verify_transaction_weight_for_size(
			context_id,
			num_inputs,
			num_outputs,
			num_kernels,
			ser::Error::TooLargeWriteErr,
		)
	}

	fn verify_compact_block_weight_for_size(
		context_id: u32,
		out_full_len: u64,
		kern_full_len: u64,
		kern_id_len: u64,
		too_large_err: fn(String) -> ser::Error,
	) -> Result<(), ser::Error> {
		const LABEL: &str = "CompactBlockBody";
		TransactionBody::verify_count_limit(LABEL, "full outputs", out_full_len, too_large_err)?;
		TransactionBody::verify_count_limit(LABEL, "full kernels", kern_full_len, too_large_err)?;
		TransactionBody::verify_count_limit(LABEL, "kernel ids", kern_id_len, too_large_err)?;
		let kernel_count = kern_full_len.checked_add(kern_id_len).ok_or_else(|| {
			ser::Error::DataOverflow(format!(
				"CompactBlockBody kernel count overflow, full kernels={} kernel ids={}",
				kern_full_len, kern_id_len
			))
		})?;
		TransactionBody::verify_normalized_weight_for_size(
			context_id,
			LABEL,
			0,
			out_full_len,
			kernel_count,
			too_large_err,
		)
	}

	/// Verify compact block vector counts and consensus weight before reading item data.
	pub fn verify_compact_block_read_weight_for_size(
		context_id: u32,
		out_full_len: u64,
		kern_full_len: u64,
		kern_id_len: u64,
	) -> Result<(), ser::Error> {
		TransactionBody::verify_compact_block_weight_for_size(
			context_id,
			out_full_len,
			kern_full_len,
			kern_id_len,
			ser::Error::TooLargeReadErr,
		)
	}

	/// Verify compact block vector counts and consensus weight before writing item data.
	pub fn verify_compact_block_write_weight_for_size(
		context_id: u32,
		out_full_len: u64,
		kern_full_len: u64,
		kern_id_len: u64,
	) -> Result<(), ser::Error> {
		TransactionBody::verify_compact_block_weight_for_size(
			context_id,
			out_full_len,
			kern_full_len,
			kern_id_len,
			ser::Error::TooLargeWriteErr,
		)
	}
}

/// A transaction
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
pub struct Transaction {
	/// The kernel "offset" k2
	/// excess is k1G after splitting the key k = k1 + k2
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::blind_from_hex"
	)]
	pub offset: BlindingFactor,
	/// The transaction body - inputs/outputs/kernels
	pub body: TransactionBody,
}

impl DefaultHashable for Transaction {}

/// Implementation of Writeable for a fully blinded transaction, defines how to
/// write the transaction as binary.
impl Writeable for Transaction {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.offset.write(writer)?;
		self.body.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction, defines how to read a full
/// transaction from a binary stream.
impl Readable for Transaction {
	fn read<R: Reader>(reader: &mut R) -> Result<Transaction, ser::Error> {
		let offset = BlindingFactor::read(reader)?;
		let body = TransactionBody::read(reader)?;
		let tx = Transaction { offset, body };

		// Now "lightweight" validation of the tx.
		// Treat any validation issues as data corruption.
		// An example of this would be reading a tx
		// that exceeded the allowed number of inputs.
		tx.validate_read(reader.get_context_id())
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read Tx, {}", e)))?;

		Ok(tx)
	}
}

impl Committed for Transaction {
	fn inputs_committed(
		&self,
	) -> Result<committed::CommitmentIterator<'_>, crate::core::committed::Error> {
		self.body.inputs_committed()
	}

	fn outputs_committed(
		&self,
	) -> Result<committed::CommitmentIterator<'_>, crate::core::committed::Error> {
		self.body.outputs_committed()
	}

	fn kernels_committed(
		&self,
	) -> Result<committed::CommitmentIterator<'_>, crate::core::committed::Error> {
		self.body.kernels_committed()
	}
}

impl Default for Transaction {
	fn default() -> Transaction {
		Transaction::empty()
	}
}

impl Transaction {
	/// Creates a new empty transaction (no inputs or outputs, zero fee).
	pub fn empty() -> Transaction {
		Transaction {
			offset: BlindingFactor::zero(),
			body: Default::default(),
		}
	}

	/// Compare two transactions by offset and consensus hash ordering/equality.
	///
	/// This delegates body comparison to `TransactionBody::eq_by_hash`, so output
	/// rangeproof bytes are intentionally ignored.
	pub fn eq_by_hash(&self, context_id: u32, other: &Self) -> Result<bool, Error> {
		Ok(self.offset == other.offset && self.body.eq_by_hash(context_id, &other.body)?)
	}

	/// Creates a new transaction initialized with
	/// the provided inputs, outputs, kernels
	pub fn new(
		context_id: u32,
		inputs: Inputs,
		outputs: &[Output],
		kernels: &[TxKernel],
	) -> Result<Transaction, Error> {
		// Initialize a new tx body and sort everything.
		let body = TransactionBody::init(context_id, inputs, outputs, kernels, false)?;

		Ok(Transaction {
			offset: BlindingFactor::zero(),
			body,
		})
	}

	/// Creates a new transaction using this transaction as a template
	/// and with the specified offset.
	pub fn with_offset(self, offset: BlindingFactor) -> Transaction {
		Transaction { offset, ..self }
	}

	/// Builds a new transaction with the provided inputs added. Existing
	/// inputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_input(self, context_id: u32, input: Input) -> Result<Transaction, Error> {
		Ok(Transaction {
			body: self.body.with_input(context_id, input)?,
			..self
		})
	}

	/// Builds a new transaction with the provided commitment-only input added.
	///
	/// This intentionally stores only the commitment. If converting from a full
	/// `Input`, the caller must explicitly decide that dropping `Input::features`
	/// is acceptable before calling this method.
	pub fn with_commit_input(
		self,
		context_id: u32,
		commit: Commitment,
	) -> Result<Transaction, Error> {
		Ok(Transaction {
			body: self.body.with_commit_input(context_id, commit)?,
			..self
		})
	}

	/// Builds a new transaction with the provided output added. Existing
	/// outputs, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_output(self, context_id: u32, output: Output) -> Result<Transaction, Error> {
		Ok(Transaction {
			body: self.body.with_output(context_id, output)?,
			..self
		})
	}

	/// Builds a new transaction with the provided kernel added. Existing
	/// kernels, if any, are kept intact.
	/// Sort order is maintained.
	pub fn with_kernel(self, context_id: u32, kernel: TxKernel) -> Result<Transaction, Error> {
		Ok(Transaction {
			body: self.body.with_kernel(context_id, kernel)?,
			..self
		})
	}

	/// Builds a new transaction replacing any existing kernels with the provided kernel.
	pub fn replace_kernel(self, kernel: TxKernel) -> Transaction {
		Transaction {
			body: self.body.replace_kernel(kernel),
			..self
		}
	}

	/// Get inputs
	pub fn inputs(&self) -> Inputs {
		self.body.inputs()
	}

	/// Get outputs
	pub fn outputs(&self) -> &[Output] {
		&self.body.outputs()
	}

	/// Get kernels
	pub fn kernels(&self) -> &[TxKernel] {
		&self.body.kernels()
	}

	/// Total fee for a transaction is the sum of fees of all kernels.
	pub fn fee(&self) -> Result<u64, Error> {
		self.body.fee()
	}

	/// Total overage across all kernels.
	pub fn overage(&self) -> Result<i64, Error> {
		self.body.overage()
	}

	/// Lock height of a transaction is the max lock height of the kernels.
	pub fn lock_height(&self) -> u64 {
		self.body.lock_height()
	}

	/// "Lightweight" validation that we can perform quickly during read/deserialization.
	/// Subset of full validation that skips expensive verification steps, specifically -
	/// * rangeproof verification (on the body)
	/// * kernel signature verification (on the body)
	/// * kernel sum verification
	pub fn validate_read(&self, context_id: u32) -> Result<(), Error> {
		self.body
			.validate_read(context_id, Weighting::AsTransaction)?;
		self.body.verify_nrd_enabled(context_id)?;
		self.body.verify_features()?;
		Ok(())
	}

	/// Validates all relevant parts of a fully built transaction. Checks the
	/// excess value against the signature as well as range proofs for each
	/// output.
	pub fn validate(
		&self,
		context_id: u32,
		weighting: Weighting,
		secp: &mut Secp256k1,
	) -> Result<(), Error> {
		self.body.verify_features()?;
		self.body.verify_nrd_enabled(context_id)?;
		self.body.validate(context_id, weighting, secp)?;
		self.verify_kernel_sums(self.overage()?, self.offset.clone(), secp)?;
		Ok(())
	}

	/// Can be used to compare txs by their fee/weight ratio, aka feerate.
	/// Don't use these values for anything else though due to precision multiplier.
	pub fn fee_rate(&self) -> Result<u64, Error> {
		let fee = self.fee()?;
		let weight = self.weight_size()?;
		fee.checked_div(weight).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Transaction::fee_rate, fee={} weight={}",
				fee, weight
			))
		})
	}

	/// Calculate transaction weight
	pub fn weight_size(&self) -> Result<u64, Error> {
		self.body.weight_size()
	}

	/// Transaction minimum acceptable fee
	/// _height is kept for possible fee formula change that will require hardfork
	pub fn accept_fee(&self, context_id: u32) -> Result<u64, Error> {
		// Note, this code is different from grin. Mwc is using the same formula to calculate the transaction/block size and the
		// fees.
		let weight = Transaction::weight_for_fee(
			self.body.inputs.len() as u64,
			self.body.outputs.len() as u64,
			self.body.kernels.len() as u64,
		);
		let fee_base = get_accept_fee_base(context_id);
		weight.checked_mul(fee_base).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Transaction::accept_fee, context_id={} weight={} fee_base={}",
				context_id, weight, fee_base
			))
		})
	}

	/// Calculation transaction base fee, rounded to the higher value
	pub fn get_base_fee(&self) -> Result<u64, Error> {
		let tx_weight = Transaction::weight_for_fee(
			self.body.inputs.len() as u64,
			self.body.outputs.len() as u64,
			self.body.kernels.len() as u64,
		);
		let fee = self.fee()?;
		// (fee + tx_weight - 1) / tx_weight
		let numerator = fee
			.checked_add(tx_weight)
			.and_then(|value| value.checked_sub(1))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Transaction::get_base_fee, fee={} tx_weight={}",
					fee, tx_weight
				))
			})?;
		numerator.checked_div(tx_weight).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Transaction::get_base_fee, numerator={} tx_weight={}",
				numerator, tx_weight
			))
		})
	}

	/// Transaction weight for fee
	/// Consensus related, if transaction fee below expected values, it will be rejected by mining node
	pub fn weight_for_fee(num_inputs: u64, num_outputs: u64, num_kernels: u64) -> u64 {
		// Outputs*4 + kernels*1 - inputs*1
		// Suturated operations are accepted here. If u64 will be full, such transaction fee will be
		// higher than total MWC number in the network.  As a result it will be rejected by a network
		let body_weight = num_outputs
			.saturating_mul(consensus::TXFEE_OUTPUT_WEIGHT as u64)
			.saturating_add(num_kernels.saturating_mul(consensus::TXFEE_KERNEL_WEIGHT as u64))
			.saturating_sub(num_inputs.saturating_mul(consensus::TXFEE_INPUT_WEIGHT as u64));

		max(body_weight, 1)
	}

	/// Caclulate number of inputs to maintain possible minimal fee
	pub fn inputs_for_minimal_fee(num_outputs: u64, num_kernels: u64) -> Result<usize, Error> {
		let body_weight_no_inputs = num_outputs
			.checked_mul(consensus::TXFEE_OUTPUT_WEIGHT)
			.and_then(|outputs_weight| {
				num_kernels
					.checked_mul(consensus::TXFEE_KERNEL_WEIGHT)
					.and_then(|kernels_weight| outputs_weight.checked_add(kernels_weight))
			})
			.and_then(|weight| weight.checked_sub(1))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Transaction::inputs_for_minimal_fee, num_outputs={} num_kernels={}",
					num_outputs, num_kernels
				))
			})?;

		let need_inputs = body_weight_no_inputs
			.checked_add(consensus::TXFEE_INPUT_WEIGHT - 1)
			.and_then(|value| Some(value / consensus::TXFEE_INPUT_WEIGHT))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Transaction::inputs_for_minimal_fee, body_weight_no_inputs={}",
					body_weight_no_inputs
				))
			})?;
		usize::try_from(need_inputs).map_err(|_| {
			Error::DataOverflow(format!(
				"Transaction::inputs_for_minimal_fee, need_inputs={}",
				need_inputs
			))
		})
	}

	/// Calculate number of inputs to made that fee possible
	pub fn inputs_for_fee_points(
		fee_points: u64,
		num_outputs: u64,
		num_kernels: u64,
	) -> Result<usize, Error> {
		if fee_points == 0 {
			return Err(Error::Generic(
				"Transaction::inputs_for_fee_points, fee_points=0".into(),
			));
		}
		let body_weight_no_inputs = num_outputs
			.checked_mul(consensus::TXFEE_OUTPUT_WEIGHT)
			.and_then(|outputs_weight| {
				num_kernels
					.checked_mul(consensus::TXFEE_KERNEL_WEIGHT)
					.and_then(|kernels_weight| outputs_weight.checked_add(kernels_weight))
			})
			.and_then(|weight| Some(weight.saturating_sub(fee_points)))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Transaction::inputs_for_fee_points, fee_points={} num_outputs={} num_kernels={}",
					fee_points, num_outputs, num_kernels
				))
			})?;

		let need_inputs = body_weight_no_inputs
			.checked_add(consensus::TXFEE_INPUT_WEIGHT - 1)
			.and_then(|value| Some(value / consensus::TXFEE_INPUT_WEIGHT))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Transaction::inputs_for_fee_points, body_weight_no_inputs={}",
					body_weight_no_inputs
				))
			})?;
		usize::try_from(need_inputs).map_err(|_| {
			Error::DataOverflow(format!(
				"Transaction::inputs_for_fee_points, need_inputs={}",
				need_inputs
			))
		})
	}

	/// Calculate transaction weight by size, for block weight.
	/// Consensus critical and uses consensus weight values.
	pub fn weight_for_size(
		num_inputs: u64,
		num_outputs: u64,
		num_kernels: u64,
	) -> Result<u64, Error> {
		num_inputs
			.checked_mul(consensus::BLOCK_INPUT_WEIGHT)
			.and_then(|inputs_weight| {
				num_outputs
					.checked_mul(consensus::BLOCK_OUTPUT_WEIGHT)
					.and_then(|outputs_weight| {
						num_kernels
							.checked_mul(consensus::BLOCK_KERNEL_WEIGHT)
							.and_then(|kernels_weight| {
								inputs_weight
									.checked_add(outputs_weight)
									.and_then(|weight| weight.checked_add(kernels_weight))
							})
					})
			})
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"Transaction::weight_for_size, num_inputs={} num_outputs={} num_kernels={}",
					num_inputs, num_outputs, num_kernels,
				))
			})
	}
}

/// Takes a slice of inputs and a slice of outputs and applies "cut-through"
/// eliminating any input/output pairs with input spending output.
/// Returns new slices with cut-through elements removed.
/// Also returns slices of the cut-through elements themselves.
/// Note: Takes slices of hashable values that are AsRef<Commitment> for greater flexibility.
/// So we can cut_through inputs and outputs but we can also cut_through inputs and output identifiers.
/// Or we can get crazy and cut_through inputs with other inputs to identify intersection and difference etc.
///
/// Example:
/// Inputs: [A, B, C]
/// Outputs: [C, D, E]
/// Returns: ([A, B], [D, E], [C], [C]) # element C is cut-through
pub fn cut_through<'a, 'b, T, U>(
	context_id: u32,
	inputs: &'a mut [T],
	outputs: &'b mut [U],
) -> Result<(&'a [T], &'b [U], &'a [T], &'b [U]), Error>
where
	T: AsRef<Commitment> + Hashed,
	U: AsRef<Commitment> + Hashed,
{
	// Sort by commitment for the matching pass.
	inputs.sort_unstable_by_key(|x| *x.as_ref());
	outputs.sort_unstable_by_key(|x| *x.as_ref());

	let mut inputs_idx = 0;
	let mut outputs_idx = 0;
	let mut ncut = 0;
	while inputs_idx < inputs.len() && outputs_idx < outputs.len() {
		match inputs[inputs_idx]
			.as_ref()
			.cmp(outputs[outputs_idx].as_ref())
		{
			// Note, max values of inputs_idx, outputs_idx, ncut are limited by max of inputs.len() and output.len()
			//  That is why increments are safe, no data overflow is possible
			Ordering::Less => {
				inputs.swap(inputs_idx - ncut, inputs_idx);
				inputs_idx += 1;
			}
			Ordering::Greater => {
				outputs.swap(outputs_idx - ncut, outputs_idx);
				outputs_idx += 1;
			}
			Ordering::Equal => {
				inputs_idx += 1;
				outputs_idx += 1;
				ncut += 1;
			}
		}
	}

	// Make sure we move any the remaining inputs into the slice to be returned.
	while inputs_idx < inputs.len() {
		// Safe because inputs_idx - ncut>=0 from above
		inputs.swap(inputs_idx - ncut, inputs_idx);
		// Safe increment because inputs_idx max value is limited by inputs.len()
		inputs_idx += 1;
	}

	// Make sure we move any the remaining outputs into the slice to be returned.
	while outputs_idx < outputs.len() {
		// Safe because outputs_idx - ncut>=0 from above
		outputs.swap(outputs_idx - ncut, outputs_idx);
		// Safe increment because outputs_idx max value is limited by inputs.len()
		outputs_idx += 1;
	}

	// Split inputs and outputs slices into non-cut-through and cut-through slices.
	// Safe because ncut<=min(inputs.len(), outputs.len())
	let (inputs, inputs_cut) = inputs.split_at_mut(inputs.len() - ncut);
	let (outputs, outputs_cut) = outputs.split_at_mut(outputs.len() - ncut);

	// Return slices in consensus hash order, matching the legacy observable
	// ordering while still propagating hash calculation errors.
	ser::sort_slice_by_hash(context_id, inputs)?;
	ser::sort_slice_by_hash(context_id, outputs)?;
	ser::sort_slice_by_hash(context_id, inputs_cut)?;
	ser::sort_slice_by_hash(context_id, outputs_cut)?;

	// Check we have no duplicate inputs after cut-through.
	match ser::verify_sorted_and_unique_by_hash(context_id, inputs) {
		Ok(()) => {}
		Err(ser::Error::DuplicateError) => return Err(Error::CutThrough),
		Err(e) => return Err(e.into()),
	}

	// Check we have no duplicate outputs after cut-through.
	match ser::verify_sorted_and_unique_by_hash(context_id, outputs) {
		Ok(()) => {}
		Err(ser::Error::DuplicateError) => return Err(Error::CutThrough),
		Err(e) => return Err(e.into()),
	}

	Ok((inputs, outputs, inputs_cut, outputs_cut))
}

/// Aggregate a vec of txs into a multi-kernel tx with cut_through.
pub fn aggregate(
	context_id: u32,
	txs: &[Transaction],
	secp: &Secp256k1,
) -> Result<Transaction, Error> {
	// convenience short-circuiting
	if txs.is_empty() {
		return Ok(Transaction::empty());
	} else if txs.len() == 1 {
		return Ok(txs[0].clone());
	}

	let mut n_inputs = 0usize;
	let mut n_outputs = 0usize;
	let mut n_kernels = 0usize;
	for tx in txs {
		n_inputs = n_inputs.checked_add(tx.inputs().len()).ok_or_else(|| {
			Error::DataOverflow(format!(
				"transaction::aggregate, n_inputs={} tx_inputs_len={}",
				n_inputs,
				tx.inputs().len()
			))
		})?;
		n_outputs = n_outputs.checked_add(tx.outputs().len()).ok_or_else(|| {
			Error::DataOverflow(format!(
				"transaction::aggregate, n_outputs={} tx_outputs_len={}",
				n_outputs,
				tx.outputs().len()
			))
		})?;
		n_kernels = n_kernels.checked_add(tx.kernels().len()).ok_or_else(|| {
			Error::DataOverflow(format!(
				"transaction::aggregate, n_kernels={} tx_kernels_len={}",
				n_kernels,
				tx.kernels().len()
			))
		})?;
	}
	let mut inputs: Vec<CommitWrapper> = Vec::with_capacity(n_inputs);
	let mut outputs: Vec<Output> = Vec::with_capacity(n_outputs);
	let mut kernels: Vec<TxKernel> = Vec::with_capacity(n_kernels);

	// we will sum these together at the end to give us the overall offset for the
	// transaction
	let mut kernel_offsets: Vec<BlindingFactor> = Vec::with_capacity(txs.len());
	for tx in txs {
		// we will sum these later to give a single aggregate offset
		kernel_offsets.push(tx.offset.clone());

		let tx_inputs = tx.inputs().into_commit_wrappers(context_id)?;
		inputs.extend_from_slice(&tx_inputs);
		outputs.extend_from_slice(tx.outputs());
		kernels.extend_from_slice(tx.kernels());
	}

	let (inputs, outputs, _, _) = cut_through(context_id, &mut inputs, &mut outputs)?;

	// now sum the kernel_offsets up to give us an aggregate offset for the
	// transaction
	let total_kernel_offset = committed::sum_kernel_offsets(kernel_offsets, vec![], secp)?;

	// build a new aggregate tx from the following -
	//   * cut-through inputs
	//   * cut-through outputs
	//   * full set of tx kernels
	//   * sum of all kernel offsets
	// Note: We sort input/outputs/kernels when building the transaction body internally.
	let tx = Transaction::new(context_id, Inputs::from(inputs), outputs, &kernels)?
		.with_offset(total_kernel_offset);

	Ok(tx)
}

/// Attempt to deaggregate a multi-kernel transaction based on multiple
/// transactions
pub fn deaggregate(
	context_id: u32,
	mk_tx: Transaction,
	txs: &[Transaction],
	secp: &Secp256k1,
) -> Result<Transaction, Error> {
	let mut inputs: Vec<CommitWrapper> = vec![];
	let mut outputs: Vec<Output> = vec![];
	let mut kernels: Vec<TxKernel> = vec![];

	// we will subtract these at the end to give us the overall offset for the
	// transaction
	let mut kernel_offsets = vec![];

	let tx = aggregate(context_id, txs, secp)?;

	let mk_inputs = mk_tx.inputs().into_commit_wrappers(context_id)?;
	let tx_inputs = tx.inputs().into_commit_wrappers(context_id)?;
	for mk_input in mk_inputs {
		if !ser::contains_by_hash(context_id, &tx_inputs, &mk_input)?
			&& !ser::contains_by_hash(context_id, &inputs, &mk_input)?
		{
			inputs.push(mk_input);
		}
	}
	for mk_output in mk_tx.outputs() {
		if !ser::contains_by_hash_key(context_id, tx.outputs(), mk_output, |output| {
			&output.identifier
		})? && !ser::contains_by_hash_key(context_id, &outputs, mk_output, |output| {
			&output.identifier
		})? {
			outputs.push(*mk_output);
		}
	}
	for mk_kernel in mk_tx.kernels() {
		if !ser::contains_by_hash(context_id, tx.kernels(), mk_kernel)?
			&& !ser::contains_by_hash(context_id, &kernels, mk_kernel)?
		{
			kernels.push(*mk_kernel);
		}
	}

	kernel_offsets.push(tx.offset);

	// now compute the total kernel offset
	let total_kernel_offset = {
		let mut positive_key: Vec<SecretKey> = Vec::with_capacity(1);
		if mk_tx.offset != BlindingFactor::zero() {
			positive_key.push(mk_tx.offset.secret_key(secp)?)
		};

		let mut negative_keys: Vec<SecretKey> = Vec::with_capacity(kernel_offsets.len());
		for x in &kernel_offsets {
			if *x != BlindingFactor::zero() {
				negative_keys.push(x.secret_key(&secp)?);
			}
		}

		if positive_key.is_empty() && negative_keys.is_empty() {
			BlindingFactor::zero()
		} else {
			match secp.blind_sum(positive_key, negative_keys) {
				Ok(sum) => BlindingFactor::from_secret_key(sum),
				Err(secp::Error::ZeroSecretKey) => BlindingFactor::zero(),
				Err(e) => return Err(e.into()),
			}
		}
	};

	// Sorting them lexicographically
	ser::sort_by_hash(context_id, &mut inputs)?;
	ser::sort_by_hash_key(context_id, &mut outputs, |output| &output.identifier)?;
	ser::sort_by_hash(context_id, &mut kernels)?;

	// Build a new tx from the above data.
	Ok(Transaction::new(
		context_id,
		Inputs::from(inputs.as_slice()),
		&outputs,
		&kernels,
	)?
	.with_offset(total_kernel_offset))
}

/// A transaction input.
///
/// Primarily a reference to an output being spent by the transaction.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(crate = "serde")]
pub struct Input {
	/// The features of the output being spent.
	/// We will check maturity for coinbase output.
	pub features: OutputFeatures,
	/// The commit referencing the output being spent.
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
}

impl DefaultHashable for Input {}
// Consensus ordering and equality for inputs is by canonical hash, not by trait
// implementations on the type. Use ser::sort_by_hash,
// ser::verify_sorted_and_unique_by_hash, ser::hashes_equal, or
// ser::contains_by_hash so hash calculation errors are returned to callers
// instead of being logged and ignored by Ord/PartialEq/Eq.

impl AsRef<Commitment> for Input {
	fn as_ref(&self) -> &Commitment {
		&self.commit
	}
}

impl From<&OutputIdentifier> for Input {
	fn from(out: &OutputIdentifier) -> Self {
		Input {
			features: out.features,
			commit: out.commit,
		}
	}
}

/// Implementation of Writeable for a transaction Input, defines how to write
/// an Input as binary.
impl Writeable for Input {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		util::secp_static::with_commit(ser::Error::from, |secp| {
			secp.validate_commitment(&self.commit).map_err(|e| {
				ser::Error::CorruptedData(format!("Unable to write Pedersen commitment, {}", e))
			})
		})?;
		self.commit.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Input, defines how to read
/// an Input from a binary stream.
impl Readable for Input {
	fn read<R: Reader>(reader: &mut R) -> Result<Input, ser::Error> {
		let features = OutputFeatures::read(reader)?;
		let commit = Commitment::read(reader)?;
		Ok(Input::new(features, commit))
	}
}

/// The input for a transaction, which spends a pre-existing unspent output.
/// The input commitment is a reproduction of the commitment of the output
/// being spent. Input must also provide the original output features and the
/// hash of the block the output originated from.
impl Input {
	/// Build a new input from the data required to identify and verify an
	/// output being spent.
	pub fn new(features: OutputFeatures, commit: Commitment) -> Input {
		Input { features, commit }
	}

	/// The input commitment which _partially_ identifies the output being
	/// spent. In the presence of a fork we need additional info to uniquely
	/// identify the output. Specifically the block hash (to correctly
	/// calculate lock_height for coinbase outputs).
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Is this a coinbase input?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain input?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}
}

/// We need to wrap commitments so they can be sorted by their consensus hash.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(crate = "serde")]
#[serde(transparent)]
pub struct CommitWrapper {
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	commit: Commitment,
}

impl DefaultHashable for CommitWrapper {}
// Consensus ordering and equality for commit-only inputs is by canonical hash,
// not by trait implementations on the type. Use ser::sort_by_hash,
// ser::verify_sorted_and_unique_by_hash, ser::hashes_equal, or
// ser::contains_by_hash so hash calculation errors are returned to callers
// instead of being logged and ignored by Ord/PartialEq/Eq.

impl From<Commitment> for CommitWrapper {
	fn from(commit: Commitment) -> Self {
		CommitWrapper { commit }
	}
}

impl AsRef<Commitment> for CommitWrapper {
	fn as_ref(&self) -> &Commitment {
		&self.commit
	}
}

impl Readable for CommitWrapper {
	fn read<R: Reader>(reader: &mut R) -> Result<CommitWrapper, ser::Error> {
		let commit = Commitment::read(reader)?;
		Ok(CommitWrapper { commit })
	}
}

impl Writeable for CommitWrapper {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		util::secp_static::with_commit(ser::Error::from, |secp| {
			secp.validate_commitment(&self.commit).map_err(|e| {
				ser::Error::CorruptedData(format!("Unable to write Pedersen commitment, {}", e))
			})
		})?;
		self.commit.write(writer)
	}
}

impl CommitWrapper {
	/// Build a commit-only input wrapper from a full input.
	///
	/// This is intentionally lossy: `Input::features` is consensus-relevant
	/// metadata and is not stored in the commit-only representation. Callers must
	/// make an explicit protocol/compatibility decision before using this.
	pub fn from_input_commitment_only(input: &Input) -> Self {
		CommitWrapper::from(input.commitment())
	}

	/// Wrapped commitment.
	pub fn commitment(&self) -> Commitment {
		self.commit
	}
}
/// Wrapper around a vec of inputs.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "serde")]
#[serde(untagged)]
pub enum Inputs {
	/// Vec of commitments.
	CommitOnly(Vec<CommitWrapper>),
	/// Vec of inputs.
	FeaturesAndCommit(Vec<Input>),
}

impl From<&[Input]> for Inputs {
	fn from(inputs: &[Input]) -> Self {
		Inputs::FeaturesAndCommit(inputs.to_vec())
	}
}

impl From<&[CommitWrapper]> for Inputs {
	fn from(commits: &[CommitWrapper]) -> Self {
		Inputs::CommitOnly(commits.to_vec())
	}
}

/// Used when converting to v2 compatibility.
impl Default for Inputs {
	fn default() -> Self {
		Inputs::CommitOnly(vec![])
	}
}

impl Writeable for Inputs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// Nothing to write so we are done.
		if self.is_empty() {
			return Ok(());
		}

		// If writing for a hash then simply write all our inputs.
		if writer.serialization_mode().is_hash_mode() {
			match self {
				Inputs::CommitOnly(inputs) => inputs.write(writer)?,
				Inputs::FeaturesAndCommit(inputs) => inputs.write(writer)?,
			}
		} else {
			// Otherwise we are writing full data and need to consider our inputs variant and protocol version.
			match self {
				Inputs::CommitOnly(inputs) => match writer.protocol_version().value() {
					0..=2 => {
						return Err(ser::Error::UnsupportedProtocolVersion(format!(
							"get version {}, expecting version >=3",
							writer.protocol_version().value()
						)))
					}
					3..=ProtocolVersion::MAX => inputs.write(writer)?,
				},
				Inputs::FeaturesAndCommit(inputs) => match writer.protocol_version().value() {
					0..=2 => inputs.write(writer)?,
					3..=ProtocolVersion::MAX => {
						let inputs = self.to_commit_wrappers(writer.get_context_id())?;
						inputs.write(writer)?;
					}
				},
			}
		}
		Ok(())
	}
}

impl Inputs {
	/// Compare input collections by consensus hash ordering/equality.
	pub fn eq_by_hash(&self, context_id: u32, other: &Self) -> Result<bool, ser::Error> {
		match (self, other) {
			(Inputs::CommitOnly(lhs), Inputs::CommitOnly(rhs)) => {
				ser::slices_equal_by_hash(context_id, lhs, rhs)
			}
			(Inputs::FeaturesAndCommit(lhs), Inputs::FeaturesAndCommit(rhs)) => {
				ser::slices_equal_by_hash(context_id, lhs, rhs)
			}
			_ => Ok(false),
		}
	}

	/// Build feature-preserving inputs from output identifiers.
	pub fn from_output_identifiers(
		context_id: u32,
		outputs: &[OutputIdentifier],
	) -> Result<Inputs, ser::Error> {
		let mut inputs: Vec<_> = outputs
			.iter()
			.map(|out| Input {
				features: out.features,
				commit: out.commit,
			})
			.collect();
		ser::sort_by_hash(context_id, &mut inputs)?;
		Ok(Inputs::FeaturesAndCommit(inputs))
	}

	/// Convert inputs to commit-only form, preserving consensus hash ordering.
	pub fn into_commit_wrappers(self, context_id: u32) -> Result<Vec<CommitWrapper>, ser::Error> {
		match self {
			Inputs::CommitOnly(inputs) => Ok(inputs),
			Inputs::FeaturesAndCommit(inputs) => {
				let mut commits: Vec<_> = inputs
					.iter()
					.map(CommitWrapper::from_input_commitment_only)
					.collect();
				ser::sort_by_hash(context_id, &mut commits)?;
				Ok(commits)
			}
		}
	}

	/// Convert inputs to commit-only form, preserving consensus hash ordering.
	pub fn to_commit_wrappers(&self, context_id: u32) -> Result<Vec<CommitWrapper>, ser::Error> {
		match self {
			Inputs::CommitOnly(inputs) => Ok(inputs.clone()),
			Inputs::FeaturesAndCommit(inputs) => {
				let mut commits: Vec<_> = inputs
					.iter()
					.map(CommitWrapper::from_input_commitment_only)
					.collect();
				ser::sort_by_hash(context_id, &mut commits)?;
				Ok(commits)
			}
		}
	}

	/// Number of inputs.
	pub fn len(&self) -> usize {
		match self {
			Inputs::CommitOnly(inputs) => inputs.len(),
			Inputs::FeaturesAndCommit(inputs) => inputs.len(),
		}
	}

	/// Empty inputs?
	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// Verify inputs are sorted and unique.
	fn verify_sorted_and_unique(&self, context_id: u32) -> Result<(), ser::Error> {
		match self {
			Inputs::CommitOnly(inputs) => ser::verify_sorted_and_unique_by_hash(context_id, inputs),
			Inputs::FeaturesAndCommit(inputs) => {
				ser::verify_sorted_and_unique_by_hash(context_id, inputs)
			}
		}
	}

	/// Sort the inputs.
	fn sort_by_hash(&mut self, context_id: u32) -> Result<(), ser::Error> {
		match self {
			Inputs::CommitOnly(inputs) => ser::sort_by_hash(context_id, inputs),
			Inputs::FeaturesAndCommit(inputs) => ser::sort_by_hash(context_id, inputs),
		}
	}

	/// For debug purposes only. Do not rely on this for anything.
	pub fn version_str(&self) -> &str {
		match self {
			Inputs::CommitOnly(_) => "v3",
			Inputs::FeaturesAndCommit(_) => "v2",
		}
	}
}

// Enum of various supported kernel "features".
enum_from_primitive! {
	/// Various flavors of tx kernel.
	#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
	#[serde(crate = "serde")]
	#[repr(u8)]
	pub enum OutputFeatures {
		/// Plain output (the default for Mwc txs).
		Plain = 0,
		/// A coinbase output.
		Coinbase = 1,
	}
}

impl Writeable for OutputFeatures {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(*self as u8)?;
		Ok(())
	}
}

impl Readable for OutputFeatures {
	fn read<R: Reader>(reader: &mut R) -> Result<OutputFeatures, ser::Error> {
		let features = OutputFeatures::from_u8(reader.read_u8()?).ok_or(
			ser::Error::CorruptedData("Unable to read output features".to_string()),
		)?;
		Ok(features)
	}
}

/// Output for a transaction, defining the new ownership of coins that are being
/// transferred. The commitment is a blinded value for the output while the
/// range proof guarantees the commitment includes a positive value without
/// overflow and the ownership of the private key.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct Output {
	/// Output identifier (features and commitment).
	#[serde(flatten)]
	pub identifier: OutputIdentifier,
	/// Rangeproof associated with the commitment.
	#[serde(
		serialize_with = "secp_ser::rangeproof_as_hex",
		deserialize_with = "secp_ser::rangeproof_from_hex"
	)]
	pub proof: RangeProof,
}

impl PartialEq for Output {
	// Note, RangeProof are not participate in compare because the transaction unit is commiment,
	// proof is extra that can vary.
	fn eq(&self, other: &Self) -> bool {
		self.identifier.features == other.identifier.features
			&& self.identifier.commit == other.identifier.commit
	}
}

impl Eq for Output {}

impl Hashed for Output {
	fn hash(&self, context_id: u32) -> Result<Hash, std::io::Error> {
		self.identifier.hash(context_id)
	}
}

impl AsRef<Commitment> for Output {
	fn as_ref(&self) -> &Commitment {
		&self.identifier.commit
	}
}

/// Implementation of Writeable for a transaction Output, defines how to write
/// an Output as binary.
impl Writeable for Output {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.identifier.write(writer)?;
		self.proof.write(writer)?;
		Ok(())
	}
}

/// Implementation of Readable for a transaction Output, defines how to read
/// an Output from a binary stream.
impl Readable for Output {
	fn read<R: Reader>(reader: &mut R) -> Result<Output, ser::Error> {
		Ok(Output {
			identifier: OutputIdentifier::read(reader)?,
			proof: RangeProof::read(reader)?,
		})
	}
}

impl OutputFeatures {
	/// Is this a coinbase output?
	pub fn is_coinbase(self) -> bool {
		self == OutputFeatures::Coinbase
	}

	/// Is this a plain output?
	pub fn is_plain(self) -> bool {
		self == OutputFeatures::Plain
	}
}

impl Output {
	/// Create a new output with the provided features, commitment and rangeproof.
	pub fn new(features: OutputFeatures, commit: Commitment, proof: RangeProof) -> Output {
		Output {
			identifier: OutputIdentifier { features, commit },
			proof,
		}
	}

	/// Output identifier.
	pub fn identifier(&self) -> OutputIdentifier {
		self.identifier
	}

	/// Commitment for the output
	pub fn commitment(&self) -> Commitment {
		self.identifier.commitment()
	}

	/// Output features.
	pub fn features(&self) -> OutputFeatures {
		self.identifier.features
	}

	/// Is this a coinbase output?
	pub fn is_coinbase(&self) -> bool {
		self.identifier.is_coinbase()
	}

	/// Is this a plain output?
	pub fn is_plain(&self) -> bool {
		self.identifier.is_plain()
	}

	/// Range proof for the output
	pub fn proof(&self) -> RangeProof {
		self.proof
	}

	/// Get canonical range proof bytes.
	pub fn proof_bytes(&self) -> Result<&[u8], Error> {
		Ok(self.proof.bytes()?)
	}

	/// Validates the range proof using the commitment
	pub fn verify_proof(&self, secp: &mut Secp256k1) -> Result<(), Error> {
		secp.verify_bullet_proof(self.commitment(), self.proof, None)?;
		Ok(())
	}

	/// Batch validates the range proofs using the commitments
	pub fn batch_verify_proofs(
		commits: &[Commitment],
		proofs: &[RangeProof],
		secp: &mut Secp256k1,
	) -> Result<(), Error> {
		secp.verify_bullet_proof_multi(commits.to_vec(), proofs.to_vec(), None)?;
		Ok(())
	}
}

impl AsRef<OutputIdentifier> for Output {
	fn as_ref(&self) -> &OutputIdentifier {
		&self.identifier
	}
}

/// An output_identifier can be build from either an input _or_ an output and
/// contains everything we need to uniquely identify an output being spent.
/// Needed because it is not sufficient to pass a commitment around.
#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(crate = "serde")]
pub struct OutputIdentifier {
	/// Output features (coinbase vs. regular transaction output)
	/// We need to include this when hashing to ensure coinbase maturity can be
	/// enforced.
	pub features: OutputFeatures,
	/// Output commitment
	#[serde(
		serialize_with = "secp_ser::as_hex",
		deserialize_with = "secp_ser::commitment_from_hex"
	)]
	pub commit: Commitment,
}

impl DefaultHashable for OutputIdentifier {}
// Consensus ordering and equality for output identifiers is by canonical hash,
// not by trait implementations on the type. Use ser::sort_by_hash_key,
// ser::verify_sorted_and_unique_by_hash_key, ser::hashes_equal, or
// ser::contains_by_hash_key so hash calculation errors are returned to callers
// instead of being logged and ignored by Ord/PartialEq/Eq.

impl AsRef<Commitment> for OutputIdentifier {
	fn as_ref(&self) -> &Commitment {
		&self.commit
	}
}

impl OutputIdentifier {
	/// Build a new output_identifier.
	pub fn new(features: OutputFeatures, commit: &Commitment) -> OutputIdentifier {
		OutputIdentifier {
			features,
			commit: *commit,
		}
	}

	/// Our commitment.
	pub fn commitment(&self) -> Commitment {
		self.commit
	}

	/// Is this a coinbase output?
	pub fn is_coinbase(&self) -> bool {
		self.features.is_coinbase()
	}

	/// Is this a plain output?
	pub fn is_plain(&self) -> bool {
		self.features.is_plain()
	}

	/// Converts this identifier to a full output, provided a RangeProof
	pub fn into_output(self, proof: RangeProof) -> Output {
		Output {
			identifier: self,
			proof,
		}
	}
}

impl ToHex for OutputIdentifier {
	fn to_hex(&self) -> String {
		// Legacy encoding: the feature prefix is intentionally written as
		// variable-width binary text, followed by the commitment hex. This is not
		// canonical full-byte hex; parsers that consume output identifiers should
		// recognize this form and handle the feature prefix separately.
		format!("{:b}{}", self.features as u8, self.commit.to_hex())
	}
}

impl Writeable for OutputIdentifier {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.features.write(writer)?;
		util::secp_static::with_commit(ser::Error::from, |secp| {
			secp.validate_commitment(&self.commit).map_err(|e| {
				ser::Error::CorruptedData(format!("Unable to write Pedersen commitment, {}", e))
			})
		})?;
		self.commit.write(writer)?;
		Ok(())
	}
}

impl Readable for OutputIdentifier {
	fn read<R: Reader>(reader: &mut R) -> Result<OutputIdentifier, ser::Error> {
		Ok(OutputIdentifier {
			features: OutputFeatures::read(reader)?,
			commit: Commitment::read(reader)?,
		})
	}
}

impl PMMRable for OutputIdentifier {
	type E = Self;

	fn as_elmt(&self) -> Result<OutputIdentifier, crate::ser::Error> {
		Ok(*self)
	}

	fn elmt_size() -> Option<u16> {
		// u16 conversion is safe because it is a constant value, no data truncation  is guaranteed
		Some(1 + secp::constants::PEDERSEN_COMMITMENT_SIZE as u16)
	}
}

impl From<&Input> for OutputIdentifier {
	fn from(input: &Input) -> Self {
		OutputIdentifier {
			features: input.features,
			commit: input.commit,
		}
	}
}

impl AsRef<OutputIdentifier> for OutputIdentifier {
	fn as_ref(&self) -> &OutputIdentifier {
		self
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hash;
	use crate::core::id::{ShortId, ShortIdentifiable};
	use keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::secp::{AggSigSignature, ContextFlag, SecretKey};
	use std::convert::TryInto;

	// For ser/deser signature must be valid. One form floo genesis should work
	fn get_test_valid_signature(secp: &Secp256k1) -> AggSigSignature {
		AggSigSignature::from_raw_data(
			&secp,
			&[
				206, 29, 151, 239, 47, 44, 219, 103, 100, 240, 76, 52, 231, 174, 149, 129, 237,
				164, 234, 60, 232, 149, 90, 94, 161, 93, 131, 148, 120, 81, 161, 155, 170, 177,
				250, 64, 66, 25, 44, 82, 164, 227, 150, 5, 10, 166, 52, 150, 22, 179, 15, 50, 81,
				15, 114, 9, 52, 239, 234, 80, 82, 118, 146, 30,
			],
		)
		.unwrap()
	}

	#[test]
	fn test_plain_kernel_ser_deser() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let commit = keychain
			.commit(&secp, 5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		let sig = get_test_valid_signature(&secp);

		let kernel = TxKernel {
			features: KernelFeatures::Plain {
				fee: 10u32.try_into().unwrap(),
			},
			excess: commit,
			excess_sig: sig.clone(),
		};

		// Test explicit protocol version.
		for version in vec![ProtocolVersion(1), ProtocolVersion(2)] {
			let mut vec = vec![];
			ser::serialize(&mut vec, version, 0, &kernel).expect("serialized failed");
			let kernel2: TxKernel = ser::deserialize_strict(&mut &vec[..], version, 0).unwrap();
			assert_eq!(
				kernel2.features,
				KernelFeatures::Plain {
					fee: 10u32.try_into().unwrap()
				}
			);
			assert_eq!(kernel2.excess, commit);
			assert_eq!(kernel2.excess_sig, sig.clone());
		}

		// Test with "default" protocol version.
		let mut vec = vec![];
		ser::serialize_default(0, &mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(0, &mut &vec[..]).unwrap();
		assert_eq!(
			kernel2.features,
			KernelFeatures::Plain {
				fee: 10u32.try_into().unwrap()
			}
		);
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());
	}

	#[test]
	fn test_height_locked_kernel_ser_deser() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let commit = keychain
			.commit(&secp, 5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		let sig = get_test_valid_signature(&secp);

		// now check a kernel with lock_height serialize/deserialize correctly
		let kernel = TxKernel {
			features: KernelFeatures::HeightLocked {
				fee: 10u32.try_into().unwrap(),
				lock_height: 100,
			},
			excess: commit,
			excess_sig: sig.clone(),
		};

		// Test explicit protocol version.
		for version in vec![ProtocolVersion(1), ProtocolVersion(2)] {
			let mut vec = vec![];
			ser::serialize(&mut vec, version, 0, &kernel).expect("serialized failed");
			let kernel2: TxKernel = ser::deserialize_strict(&mut &vec[..], version, 0).unwrap();
			assert_eq!(kernel.features, kernel2.features);
			assert_eq!(kernel2.excess, commit);
			assert_eq!(kernel2.excess_sig, sig.clone());
		}

		// Test with "default" protocol version.
		let mut vec = vec![];
		ser::serialize_default(0, &mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(0, &mut &vec[..]).unwrap();
		assert_eq!(kernel.features, kernel2.features);
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());
	}

	#[test]
	fn test_nrd_kernel_ser_deser() {
		global::set_local_nrd_enabled(true);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let commit = keychain
			.commit(&secp, 5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		let sig = get_test_valid_signature(&secp);

		// now check an NRD kernel will serialize/deserialize correctly
		let kernel = TxKernel {
			features: KernelFeatures::NoRecentDuplicate {
				fee: 10u32.try_into().unwrap(),
				relative_height: NRDRelativeHeight(100),
			},
			excess: commit,
			excess_sig: sig.clone(),
		};

		// Test explicit protocol version.
		for version in vec![ProtocolVersion(1), ProtocolVersion(2)] {
			let mut vec = vec![];
			ser::serialize(&mut vec, version, 0, &kernel).expect("serialized failed");
			let kernel2: TxKernel = ser::deserialize_strict(&mut &vec[..], version, 0).unwrap();
			assert_eq!(kernel.features, kernel2.features);
			assert_eq!(kernel2.excess, commit);
			assert_eq!(kernel2.excess_sig, sig.clone());
		}

		// Test with "default" protocol version.
		let mut vec = vec![];
		ser::serialize_default(0, &mut vec, &kernel).expect("serialized failed");
		let kernel2: TxKernel = ser::deserialize_default(0, &mut &vec[..]).unwrap();
		assert_eq!(kernel.features, kernel2.features);
		assert_eq!(kernel2.excess, commit);
		assert_eq!(kernel2.excess_sig, sig.clone());
	}

	#[test]
	fn nrd_kernel_verify_sig() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

		let mut kernel = TxKernel::with_features(KernelFeatures::NoRecentDuplicate {
			fee: 10u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight(100),
		})
		.unwrap();

		// Construct the message to be signed.
		let msg = kernel.msg_to_sign(0).unwrap();

		let excess = keychain
			.commit(&secp, 0, &key_id, SwitchCommitmentType::Regular)
			.unwrap();
		let skey = keychain
			.derive_key(&secp, 0, &key_id, SwitchCommitmentType::Regular)
			.unwrap();
		let pubkey = excess.to_pubkey(&secp).unwrap();

		let excess_sig = aggsig::sign_single(&secp, &msg, &skey, None, &pubkey).unwrap();

		kernel.excess = excess;
		kernel.excess_sig = excess_sig;

		// Check the signature verifies.
		assert!(kernel.verify(0, &secp).is_ok());

		// Modify the fee and check signature no longer verifies.
		kernel.features = KernelFeatures::NoRecentDuplicate {
			fee: 9u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight(100),
		};
		assert!(matches!(
			kernel.verify(0, &secp),
			Err(Error::IncorrectSignature)
		));

		// Modify the relative_height and check signature no longer verifies.
		kernel.features = KernelFeatures::NoRecentDuplicate {
			fee: 10u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight(101),
		};
		assert!(matches!(
			kernel.verify(0, &secp),
			Err(Error::IncorrectSignature)
		));

		// Swap the features out for something different and check signature no longer verifies.
		kernel.features = KernelFeatures::Plain {
			fee: 10u32.try_into().unwrap(),
		};
		assert!(matches!(
			kernel.verify(0, &secp),
			Err(Error::IncorrectSignature)
		));

		// Check signature verifies if we use the original features.
		kernel.features = KernelFeatures::NoRecentDuplicate {
			fee: 10u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight(100),
		};
		assert!(kernel.verify(0, &secp).is_ok());
	}

	#[test]
	fn commit_consistency() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[0; 32], false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

		let commit = keychain
			.commit(&secp, 1003, &key_id, SwitchCommitmentType::Regular)
			.unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

		let commit_2 = keychain
			.commit(&secp, 1003, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		assert!(commit == commit_2);
	}

	#[test]
	fn input_short_id() {
		fn assert_short_id_eq(actual: &ShortId, expected: &ShortId) {
			assert_eq!(actual.as_ref(), expected.as_ref());
			assert!(ser::hashes_equal(0, actual, expected).unwrap());
		}

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[0; 32], false).unwrap();
		let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
		let commit = keychain
			.commit(&secp, 5, &key_id, SwitchCommitmentType::Regular)
			.unwrap();

		let input = Input {
			features: OutputFeatures::Plain,
			commit,
		};

		let block_hash =
			Hash::from_hex("3a42e66e46dd7633b57d1f921780a1ac715e6b93c19ee52ab714178eb3a9f673")
				.unwrap();

		let nonce = 0;

		let short_id = input.short_id(0, &block_hash, nonce).unwrap();
		let expected = ShortId::from_hex("c4b05f2ba649").unwrap();
		assert_short_id_eq(&short_id, &expected);

		// now generate the short_id for a *very* similar output (single feature flag
		// different) and check it generates a different short_id
		let input = Input {
			features: OutputFeatures::Coinbase,
			commit,
		};

		let short_id = input.short_id(0, &block_hash, nonce).unwrap();
		let expected = ShortId::from_hex("3f0377c624e9").unwrap();
		assert_short_id_eq(&short_id, &expected);
	}

	#[test]
	fn kernel_features_serialization() -> Result<(), Error> {
		global::set_local_nrd_enabled(false);
		let mut vec = vec![];
		let expected = KernelFeatures::Plain {
			fee: 10u32.try_into().unwrap(),
		};
		ser::serialize_default(0, &mut vec, &expected)?;
		let features: KernelFeatures = ser::deserialize_default(0, &mut &vec[..])?;
		assert_eq!(features, expected);

		let mut vec = vec![];
		let expected = KernelFeatures::Coinbase;
		ser::serialize_default(0, &mut vec, &expected)?;
		let features: KernelFeatures = ser::deserialize_default(0, &mut &vec[..])?;
		assert_eq!(features, expected);

		let mut vec = vec![];
		let expected = KernelFeatures::HeightLocked {
			fee: 10u32.try_into().unwrap(),
			lock_height: 100,
		};
		ser::serialize_default(0, &mut vec, &expected)?;
		let features: KernelFeatures = ser::deserialize_default(0, &mut &vec[..])?;
		assert_eq!(features, expected);

		// NRD kernel support not enabled by default.
		let mut vec = vec![];
		ser::serialize_default(0, &mut vec, &(3u8, 10u64, 100u16)).expect("serialized failed");
		let res: Result<KernelFeatures, _> = ser::deserialize_default(0, &mut &vec[..]);
		assert!(matches!(
			res,
			Err(ser::Error::CorruptedData(ref msg)) if msg == "NRD is disabled"
		));

		// Additional kernel features unsupported.
		let mut vec = vec![];
		ser::serialize_default(0, &mut vec, &(4u8)).expect("serialized failed");
		let res: Result<KernelFeatures, _> = ser::deserialize_default(0, &mut &vec[..]);
		assert!(matches!(
			res,
			Err(ser::Error::CorruptedData(ref msg)) if msg == "Unknown kernel feature 4"
		));

		Ok(())
	}

	#[test]
	fn kernel_features_serialization_nrd_enabled() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(true);

		let mut vec = vec![];
		ser::serialize_default(0, &mut vec, &(3u8, 10u64, 100u16))?;
		let features: KernelFeatures = ser::deserialize_default(0, &mut &vec[..])?;
		assert_eq!(
			features,
			KernelFeatures::NoRecentDuplicate {
				fee: 10u32.try_into().unwrap(),
				relative_height: NRDRelativeHeight(100)
			}
		);

		// NRD with relative height 0 is invalid.
		vec.clear();
		ser::serialize_default(0, &mut vec, &(3u8, 10u64, 0u16))?;
		let res: Result<KernelFeatures, _> = ser::deserialize_default(0, &mut &vec[..]);
		assert!(matches!(
			res,
			Err(ser::Error::CorruptedData(ref msg))
				if msg == "Unable to read NRD Relative height, Invalid NRD kernel relative height"
		));

		// NRD with relative height WEEK_HEIGHT+1 is invalid.
		vec.clear();
		let invalid_height = consensus::WEEK_HEIGHT + 1;
		ser::serialize_default(0, &mut vec, &(3u8, 10u64, invalid_height as u16))?;
		let res: Result<KernelFeatures, _> = ser::deserialize_default(0, &mut &vec[..]);
		assert!(matches!(
			res,
			Err(ser::Error::CorruptedData(ref msg))
				if msg == "Unable to read NRD Relative height, Invalid NRD kernel relative height"
		));

		// Kernel variant 4 (and above) is invalid.
		let mut vec = vec![];
		ser::serialize_default(0, &mut vec, &(4u8))?;
		let res: Result<KernelFeatures, _> = ser::deserialize_default(0, &mut &vec[..]);
		assert!(matches!(
			res,
			Err(ser::Error::CorruptedData(ref msg)) if msg == "Unknown kernel feature 4"
		));

		Ok(())
	}
}
