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

//! Sane serialization & deserialization of cryptographic structs into hex

use keychain::BlindingFactor;
use mwc_crates::secp::constants::MAX_PROOF_SIZE;
use mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_crates::serde::{Deserialize, Deserializer, Serializer};
use util::{from_hex, ToHex};

/// Serializes a secp PublicKey to and from hex
pub mod pubkey_serde {
	use mwc_crates::secp::key::PublicKey;
	use mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use util::{from_hex, secp_static, ToHex};

	///
	pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		use mwc_crates::serde::ser::Error;

		let hex_str = secp_static::with_none(
			|err| Error::custom(format!("Unable create Secp, {}", err)),
			|secp| {
				key.serialize_vec(secp, true).map_err(|err| {
					Error::custom(format!("Public Key serialization error, {}", err))
				})
			},
		)?
		.to_hex();
		serializer.serialize_str(&hex_str)
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
	where
		D: Deserializer<'de>,
	{
		use mwc_crates::serde::de::Error;
		String::deserialize(deserializer)
			.and_then(|string| {
				from_hex(&string).map_err(|err| {
					Error::custom(format!("Unable to decode pub key HEX {}, {}", string, err))
				})
			})
			.and_then(|bytes: Vec<u8>| {
				secp_static::with_none(
					|err| Error::custom(format!("Unable create Secp, {}", err)),
					|secp| {
						PublicKey::from_slice(secp, &bytes).map_err(|err| {
							Error::custom(format!(
								"Unable to build Pub Key from {:?}, {}",
								bytes, err
							))
						})
					},
				)
			})
	}
}

/// Serializes an Option<secp::Signature> to and from hex
pub mod option_sig_serde {
	use mwc_crates::secp;
	use mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use util::{from_hex, secp_static, ToHex};

	///
	pub fn serialize<S>(
		sig: &Option<secp::AggSigSignature>,
		serializer: S,
	) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match sig {
			Some(sig) => {
				let sig_ser = secp_static::with_none(
					|err| {
						mwc_crates::serde::ser::Error::custom(format!(
							"Unable create Secp, {}",
							err
						))
					},
					|secp| {
						sig.serialize_raw(secp).map_err(|err| {
							mwc_crates::serde::ser::Error::custom(format!(
								"Unable serialize signature, {}",
								err
							))
						})
					},
				)?;
				serializer.serialize_str(&(&sig_ser[..]).to_hex())
			}
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<secp::AggSigSignature>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => from_hex(&string)
				.map_err(|err| {
					mwc_crates::serde::de::Error::custom(format!(
						"Fail to parse signature HEX {}, {}",
						string, err
					))
				})
				.and_then(|bytes: Vec<u8>| {
					if bytes.len() != 64 {
						return Err(mwc_crates::serde::de::Error::invalid_length(
							bytes.len(),
							&"64 bytes",
						));
					}
					let mut b = [0u8; 64];
					b.copy_from_slice(&bytes[0..64]);
					secp_static::with_none(
						|err| {
							mwc_crates::serde::de::Error::custom(format!(
								"Unable create Secp, {}",
								err
							))
						},
						|secp| {
							secp::AggSigSignature::from_raw_data(secp, &b)
								.map(Some)
								.map_err(|err| {
									mwc_crates::serde::de::Error::custom(format!(
										"Fail to decode signature, {}",
										err
									))
								})
						},
					)
				}),
			None => Ok(None),
		})
	}
}

/// Serializes an Option<secp::SecretKey> to and from hex
pub mod option_seckey_serde {
	use mwc_crates::secp;
	use mwc_crates::secp::constants::SECRET_KEY_SIZE;
	use mwc_crates::serde::de::Error;
	use mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use mwc_crates::zeroize::Zeroizing;
	use util::{decode_secret_key_hex, secp_static, ToHex, ZeroingString};

	///
	pub fn serialize<S>(
		key: &Option<secp::key::SecretKey>,
		serializer: S,
	) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match key {
			Some(key) => {
				let key_str: Zeroizing<String> = Zeroizing::new(key.0.to_hex());
				serializer.serialize_str(&key_str)
			}
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<secp::key::SecretKey>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => {
				let string = ZeroingString::from(string);
				let bytes =
					decode_secret_key_hex::<SECRET_KEY_SIZE>(&string).map_err(|err| match err {
						util::Error::InvalidLength { actual, .. } => {
							Error::invalid_length(actual, &"32 bytes")
						}
						_ => Error::custom("invalid secret key hex"),
					})?;
				secp_static::with_none(
					|err| Error::custom(format!("Unable create Secp, {}", err)),
					|secp| {
						secp::key::SecretKey::from_slice(secp, bytes.as_ref())
							.map(Some)
							.map_err(|err| Error::custom(format!("Fail to decode key, {}", err)))
					},
				)
			}
			None => Ok(None),
		})
	}
}

/// Serializes a secp::Signature to and from hex
pub mod sig_serde {
	use mwc_crates::secp;
	use mwc_crates::serde::de::Error;
	use mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use util::{from_hex, secp_static, ToHex};

	///
	pub fn serialize<S>(sig: &secp::AggSigSignature, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let sig_ser = secp_static::with_none(
			|err| mwc_crates::serde::ser::Error::custom(format!("Unable create Secp, {}", err)),
			|secp| {
				sig.serialize_raw(secp).map_err(|err| {
					mwc_crates::serde::ser::Error::custom(format!(
						"Unable serialize signature, {}",
						err
					))
				})
			},
		)?;
		serializer.serialize_str(&(&sig_ser[..]).to_hex())
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<secp::AggSigSignature, D::Error>
	where
		D: Deserializer<'de>,
	{
		String::deserialize(deserializer)
			.and_then(|string| {
				from_hex(&string).map_err(|err| {
					Error::custom(format!("Fail to parse signature HEX {}, {}", string, err))
				})
			})
			.and_then(|bytes: Vec<u8>| {
				if bytes.len() != 64 {
					return Err(Error::invalid_length(bytes.len(), &"64 bytes"));
				}
				let mut b = [0u8; 64];
				b.copy_from_slice(&bytes[0..64]);
				secp_static::with_none(
					|err| {
						mwc_crates::serde::de::Error::custom(format!("Unable create Secp, {}", err))
					},
					|secp| {
						secp::AggSigSignature::from_raw_data(secp, &b).map_err(|err| {
							Error::custom(format!("Fail to decode signature, {}", err))
						})
					},
				)
			})
	}
}

/// Serializes an Option<secp::Commitment> to and from hex
pub mod option_commitment_serde {
	use mwc_crates::secp::pedersen::Commitment;
	use mwc_crates::serde::de::Error;
	use mwc_crates::serde::{Deserialize, Deserializer, Serializer};
	use util::{from_hex, secp_static, ToHex};

	///
	pub fn serialize<S>(commit: &Option<Commitment>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match commit {
			Some(c) => serializer.serialize_str(&c.to_hex()),
			None => serializer.serialize_none(),
		}
	}

	///
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Commitment>, D::Error>
	where
		D: Deserializer<'de>,
	{
		Option::<String>::deserialize(deserializer).and_then(|res| match res {
			Some(string) => from_hex(&string)
				.map_err(|err| {
					Error::custom(format!("Fail to parse Commit from HEX {}, {}", string, err))
				})
				.and_then(|bytes: Vec<u8>| {
					let commitment = Commitment::from_vec(bytes)
						.map_err(|e| Error::custom(format!("Invalid Commit {}, {}", string, e)))?;
					secp_static::with_commit(
						|err| Error::custom(format!("Unable create Secp, {}", err)),
						|secp| {
							secp.validate_commitment(&commitment).map_err(|err| {
								Error::custom(format!("Invalid Commit {}, {}", string, err))
							})
						},
					)?;
					Ok(Some(commitment))
				}),
			None => Ok(None),
		})
	}
}
/// Creates a BlindingFactor from a hex string
pub fn blind_from_hex<'de, D>(deserializer: D) -> Result<BlindingFactor, D::Error>
where
	D: Deserializer<'de>,
{
	use mwc_crates::serde::de::Error;
	String::deserialize(deserializer).and_then(|string| {
		BlindingFactor::from_hex(&string)
			.map_err(|err| Error::custom(format!("Fail to parse blinding factor, {}", err)))
	})
}

/// Creates a RangeProof from a hex string
pub fn rangeproof_from_hex<'de, D>(deserializer: D) -> Result<RangeProof, D::Error>
where
	D: Deserializer<'de>,
{
	use mwc_crates::serde::de::{Error, IntoDeserializer};

	let val = String::deserialize(deserializer).and_then(|string| {
		let hex = string.trim();
		let hex = hex.strip_prefix("0x").unwrap_or(hex);
		let max_hex_len = MAX_PROOF_SIZE * 2;
		if hex.len() > max_hex_len {
			return Err(Error::invalid_length(
				hex.len() / 2,
				&"at most MAX_PROOF_SIZE bytes",
			));
		}
		from_hex(hex)
			.map_err(|err| Error::custom(format!("Fail to parse range proof HEX {}, {}", hex, err)))
	})?;
	RangeProof::deserialize(val.into_deserializer())
}

/// Serializes a RangeProof as hex after validating its public length.
pub fn rangeproof_as_hex<S>(proof: &RangeProof, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	use mwc_crates::serde::ser::Error;

	let bytes = proof
		.bytes()
		.map_err(|err| Error::custom(format!("Invalid range proof, {}", err)))?;
	serializer.serialize_str(&bytes.to_hex())
}

/// Creates a Pedersen Commitment from a hex string
pub fn commitment_from_hex<'de, D>(deserializer: D) -> Result<Commitment, D::Error>
where
	D: Deserializer<'de>,
{
	use mwc_crates::serde::de::Error;
	use util::secp_static;

	String::deserialize(deserializer)
		.and_then(|string| {
			from_hex(&string).map_err(|err| {
				Error::custom(format!("Fail to parse commitment HEX {}, {}", string, err))
			})
		})
		.and_then(|bytes: Vec<u8>| {
			let commitment = Commitment::from_vec(bytes.to_vec())
				.map_err(|e| Error::custom(format!("Invalid Commit {:?}, {}", bytes, e)))?;
			secp_static::with_commit(
				|err| Error::custom(format!("Unable create Secp, {}", err)),
				|secp| {
					secp.validate_commitment(&commitment).map_err(|err| {
						Error::custom(format!("Invalid Commit {:?}, {}", bytes, err))
					})
				},
			)?;
			Ok(commitment)
		})
}

/// Seralizes a byte string into hex
pub fn as_hex<T, S>(bytes: T, serializer: S) -> Result<S::Ok, S::Error>
where
	T: AsRef<[u8]>,
	S: Serializer,
{
	serializer.serialize_str(&bytes.to_hex())
}

/// Used to ensure u64s are serialised in json
/// as strings by default, since it can't be guaranteed that consumers
/// will know what to do with u64 literals (e.g. Javascript). However,
/// fields using this tag can be deserialized from literals or strings.
/// From solutions on:
/// https://github.com/serde-rs/json/issues/329
pub mod string_or_u64 {
	use std::fmt;

	use mwc_crates::serde::{de, Deserializer, Serializer};

	/// serialize into a string
	pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
	where
		T: fmt::Display,
		S: Serializer,
	{
		serializer.collect_str(value)
	}

	/// deserialize from either literal or string
	pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct Visitor;
		impl<'a> de::Visitor<'a> for Visitor {
			type Value = u64;
			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				write!(
					formatter,
					"a string containing digits or an int fitting into u64"
				)
			}
			fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
				Ok(v)
			}
			fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				s.parse()
					.map_err(|e| de::Error::custom(format!("Fail to parse u64 {}, {}", s, e)))
			}
		}
		deserializer.deserialize_any(Visitor)
	}
}

/// As above, for Options
pub mod opt_string_or_u64 {
	use std::fmt;

	use mwc_crates::serde::{de, Deserializer, Serializer};

	/// serialize into string or none
	pub fn serialize<T, S>(value: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
	where
		T: fmt::Display,
		S: Serializer,
	{
		match value {
			Some(v) => serializer.collect_str(v),
			None => serializer.serialize_none(),
		}
	}

	/// deser from 'null', literal or string
	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct Visitor;
		impl<'a> de::Visitor<'a> for Visitor {
			type Value = Option<u64>;
			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				write!(
					formatter,
					"null, a string containing digits or an int fitting into u64"
				)
			}
			fn visit_unit<E>(self) -> Result<Self::Value, E> {
				Ok(None)
			}
			fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
				Ok(Some(v))
			}
			fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				let val: u64 = s
					.parse()
					.map_err(|e| de::Error::custom(format!("Fail to parse u64 {}, {}", s, e)))?;
				Ok(Some(val))
			}
		}
		deserializer.deserialize_any(Visitor)
	}
}

// Test serialization methods of components that are being used
#[cfg(test)]
mod test {
	use super::*;
	use crate::libtx::aggsig;
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::rand::TryRng;
	use mwc_crates::secp::key::{PublicKey, SecretKey};
	use mwc_crates::secp::{AggSigSignature, ContextFlag, Message, Secp256k1};
	use mwc_crates::serde::{self, Deserialize, Serialize};
	use mwc_crates::serde_json;

	#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
	#[serde(crate = "serde")]
	struct SerTest {
		#[serde(with = "option_seckey_serde")]
		pub opt_skey: Option<SecretKey>,
		#[serde(with = "pubkey_serde")]
		pub pub_key: PublicKey,
		#[serde(with = "option_sig_serde")]
		pub opt_sig: Option<AggSigSignature>,
		#[serde(with = "option_commitment_serde")]
		pub opt_commit: Option<Commitment>,
		#[serde(with = "sig_serde")]
		pub sig: AggSigSignature,
		#[serde(with = "string_or_u64")]
		pub num: u64,
		#[serde(with = "opt_string_or_u64")]
		pub opt_num: Option<u64>,
	}

	impl SerTest {
		pub fn random() -> SerTest {
			let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			let sk = SecretKey::new(&secp, &mut SysRng).unwrap();
			let mut msg = [0u8; 32];
			SysRng.try_fill_bytes(&mut msg).unwrap();
			let msg = Message::from_slice(&msg).unwrap();
			let pub_key = PublicKey::from_secret_key(&secp, &sk).unwrap();
			let sig = aggsig::sign_single(&secp, &msg, &sk, None, &pub_key).unwrap();
			let commit = secp.commit(30, sk.clone()).unwrap();
			SerTest {
				opt_skey: Some(sk.clone()),
				pub_key,
				opt_sig: Some(sig),
				opt_commit: Some(commit),
				sig: sig,
				num: 30,
				opt_num: Some(33),
			}
		}
	}

	#[test]
	fn ser_secp_primitives() {
		for _ in 0..10 {
			let s = SerTest::random();
			println!("Before Serialization: {:?}", s);
			let serialized = serde_json::to_string_pretty(&s).unwrap();
			println!("JSON: {}", serialized);
			let deserialized: SerTest = serde_json::from_str(&serialized).unwrap();
			println!("After Serialization: {:?}", deserialized);
			println!();
			assert_eq!(s, deserialized);
		}
	}

	#[test]
	fn serializes_aggsig_raw_bytes() {
		let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly).unwrap();
		let s = SerTest::random();
		let sig = sig_serde::serialize(&s.sig, serde_json::value::Serializer).unwrap();
		let expected = util::to_hex(&s.sig.serialize_raw(&secp).unwrap());

		assert_eq!(sig.as_str().unwrap(), expected);
	}

	#[test]
	fn rejects_oversized_rangeproof_hex_before_decode() {
		#[allow(dead_code)]
		#[derive(Deserialize, Debug)]
		#[serde(crate = "serde")]
		struct RangeProofTest {
			#[serde(deserialize_with = "rangeproof_from_hex")]
			pub proof: RangeProof,
		}

		let proof = "00".repeat(MAX_PROOF_SIZE + 1);
		let serialized = format!(r#"{{"proof":"{}"}}"#, proof);

		let err = serde_json::from_str::<RangeProofTest>(&serialized).unwrap_err();
		let err = err.to_string();

		assert!(err.contains("invalid length"));
		assert!(err.contains("at most MAX_PROOF_SIZE bytes"));
	}

	#[test]
	fn rejects_overlong_signature_hex() {
		let s = SerTest::random();
		let serialized = serde_json::to_string(&s).unwrap();
		let sig = sig_serde::serialize(&s.sig, serde_json::value::Serializer).unwrap();
		let sig = sig.as_str().unwrap();
		let overlong_sig = format!("{}00", sig);
		let serialized = serialized.replace(sig, &overlong_sig);

		let res = serde_json::from_str::<SerTest>(&serialized);

		assert!(res.is_err());
	}

	#[test]
	fn rejects_overlong_optional_signature_hex() {
		#[derive(Serialize, Deserialize, Debug)]
		#[serde(crate = "serde")]
		struct OptionSigTest {
			#[serde(with = "option_sig_serde")]
			pub sig: Option<AggSigSignature>,
		}

		let s = SerTest::random();
		let sig = sig_serde::serialize(&s.sig, serde_json::value::Serializer).unwrap();
		let sig = sig.as_str().unwrap();
		let serialized = format!(r#"{{"sig":"{}00"}}"#, sig);

		let res = serde_json::from_str::<OptionSigTest>(&serialized);

		assert!(res.is_err());
	}

	#[test]
	fn rejects_invalid_signature_serialization() {
		let mut s = SerTest::random();
		s.sig = AggSigSignature::blank();

		let res = serde_json::to_string(&s);

		assert!(res.is_err());
	}

	#[test]
	fn rejects_invalid_optional_signature_serialization() {
		#[derive(Serialize, Debug)]
		#[serde(crate = "serde")]
		struct OptionSigTest {
			#[serde(with = "option_sig_serde")]
			pub sig: Option<AggSigSignature>,
		}

		let res = serde_json::to_string(&OptionSigTest {
			sig: Some(AggSigSignature::blank()),
		});

		assert!(res.is_err());
	}

	#[test]
	fn rejects_invalid_optional_commitment_hex() {
		#[derive(Serialize, Deserialize, Debug)]
		#[serde(crate = "serde")]
		struct OptionCommitmentTest {
			#[serde(with = "option_commitment_serde")]
			pub commit: Option<Commitment>,
		}

		let invalid_commit = "00".repeat(33);
		let serialized = format!(r#"{{"commit":"{}"}}"#, invalid_commit);

		let res = serde_json::from_str::<OptionCommitmentTest>(&serialized);

		assert!(res.is_err());
	}

	#[test]
	fn rejects_invalid_commitment_hex() {
		#[derive(Serialize, Deserialize, Debug)]
		#[serde(crate = "serde")]
		struct CommitmentTest {
			#[serde(deserialize_with = "commitment_from_hex")]
			pub commit: Commitment,
		}

		let invalid_commit = "00".repeat(33);
		let serialized = format!(r#"{{"commit":"{}"}}"#, invalid_commit);

		let res = serde_json::from_str::<CommitmentTest>(&serialized);

		assert!(res.is_err());
	}

	#[test]
	fn rejects_overlong_optional_secret_key_hex() {
		#[derive(Serialize, Deserialize, Debug)]
		#[serde(crate = "serde")]
		struct OptionSecretKeyTest {
			#[serde(with = "option_seckey_serde")]
			pub key: Option<SecretKey>,
		}

		let s = SerTest::random();
		let key =
			option_seckey_serde::serialize(&s.opt_skey, serde_json::value::Serializer).unwrap();
		let key = key.as_str().unwrap();
		let serialized = format!(r#"{{"key":"{}00"}}"#, key);

		let res = serde_json::from_str::<OptionSecretKeyTest>(&serialized);

		assert!(res.is_err());
	}

	#[test]
	fn optional_secret_key_parse_error_is_redacted() {
		#[derive(Serialize, Deserialize, Debug)]
		#[serde(crate = "serde")]
		struct OptionSecretKeyTest {
			#[serde(with = "option_seckey_serde")]
			pub key: Option<SecretKey>,
		}

		let secret_like_input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaz";
		let serialized = format!(r#"{{"key":"{}"}}"#, secret_like_input);

		let err = serde_json::from_str::<OptionSecretKeyTest>(&serialized).unwrap_err();
		let err = err.to_string();

		assert!(err.contains("invalid secret key hex"));
		assert!(!err.contains(secret_like_input));
	}
}
