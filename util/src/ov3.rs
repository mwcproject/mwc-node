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

use crate::hex::from_hex;
use crate::ToHex;
use mwc_crates::ed25519_dalek;
use mwc_crates::ed25519_dalek::VerifyingKey;
use mwc_crates::safelog::DispUnredacted;
use mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_crates::tor_hsservice::HsId;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde")]
/// OnionV3 Address Errors
#[derive(thiserror::Error)]
pub enum OnionV3Error {
	/// Error decoding an address from a string
	#[error("Unable to decode Onion address from a string, {0}")]
	AddressDecoding(String),
	/// Error with given private key
	#[error("Invalid private key, {0}")]
	InvalidPrivateKey(String),
	/// Invalid OnionV3Address
	#[error("Invalid onion address, {0}")]
	InvalidOnionV3Address(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
/// Struct to hold an onion V3 address, represented internally as a raw
/// ed25519 public key
pub struct OnionV3Address([u8; 32]);

impl OnionV3Address {
	/// from bytes
	pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, OnionV3Error> {
		match ed25519_dalek::VerifyingKey::from_bytes(&bytes) {
			Ok(pk) => {
				Self::validate_pk(&bytes, &pk)?;
			}
			Err(_) => return Err(OnionV3Error::InvalidOnionV3Address(bytes.to_hex())),
		}
		Ok(OnionV3Address(bytes))
	}

	/// as bytes
	pub fn as_bytes(&self) -> &[u8; 32] {
		&self.0
	}

	/// populate from a private key
	pub fn from_private(key: &[u8; 32]) -> Result<Self, OnionV3Error> {
		let d_skey = ed25519_dalek::SigningKey::from_bytes(key);
		let d_pub_key = d_skey.verifying_key();

		if d_pub_key.is_weak() {
			return Err(OnionV3Error::InvalidOnionV3Address(
				"weak public key".into(),
			));
		}

		Self::validate_pk(d_pub_key.as_bytes(), &d_pub_key)?;

		Ok(OnionV3Address(d_pub_key.to_bytes()))
	}

	/// return dalek public key
	pub fn to_ed25519(&self) -> Result<ed25519_dalek::VerifyingKey, OnionV3Error> {
		let d_skey = match ed25519_dalek::VerifyingKey::from_bytes(&self.0) {
			Ok(k) => k,
			Err(e) => {
				return Err(OnionV3Error::InvalidOnionV3Address(format!(
					"Unable to create dalek public key: {}",
					e
				)));
			}
		};

		Self::validate_pk(d_skey.as_bytes(), &d_skey)?;
		Ok(d_skey)
	}

	/// Return as onion v3 address string
	pub fn to_ov3_str(&self) -> String {
		// Onion address is expected to be valid on constrution. We don't need
		//  extra validation on address to string conversion.
		let hsid = HsId::from(self.0);
		let onion = DispUnredacted(&hsid).to_string();
		onion.strip_suffix(".onion").unwrap_or(&onion).to_string()
	}

	fn validate_pk(bytes: &[u8; 32], pk: &VerifyingKey) -> Result<(), OnionV3Error> {
		if pk.is_weak() {
			return Err(OnionV3Error::InvalidOnionV3Address(
				"weak public key".into(),
			));
		}
		let canonical = pk.to_edwards().compress().to_bytes();
		if canonical != *bytes {
			return Err(OnionV3Error::InvalidOnionV3Address(
				"not canonical PK".into(),
			));
		}
		Ok(())
	}
}

impl fmt::Display for OnionV3Address {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.to_ov3_str())
	}
}

impl Serialize for OnionV3Address {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		self.0.serialize(serializer)
	}
}

impl<'de> Deserialize<'de> for OnionV3Address {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let bytes = <[u8; 32]>::deserialize(deserializer)?;
		OnionV3Address::from_bytes(bytes).map_err(serde::de::Error::custom)
	}
}

impl TryFrom<&str> for OnionV3Address {
	type Error = OnionV3Error;

	fn try_from(input: &str) -> Result<Self, Self::Error> {
		// First attempt to decode a pubkey from hex
		if let Ok(b) = from_hex(input) {
			let addr_bytes: [u8; 32] = b.try_into().map_err(|_| {
				OnionV3Error::AddressDecoding(format!("Public key {} is wrong length", input))
			})?;

			return Ok(OnionV3Address::from_bytes(addr_bytes)?);
		};

		let mut s = input.trim().to_lowercase();

		// Accept URLs too, like your current code did.
		if let Some(rest) = s.strip_prefix("http://") {
			s = rest.to_string();
		} else if let Some(rest) = s.strip_prefix("https://") {
			s = rest.to_string();
		}

		// If a full URL/path was passed, keep only the host part.
		if let Some((host, _)) = s.split_once('/') {
			s = host.to_string();
		}

		// Normalize to the representation HsId::from_str expects: "... .onion"
		let onion_host = if s.ends_with(".onion") {
			s
		} else {
			format!("{}.onion", s)
		};

		// Note, silently accepts malformed non-canonical onion hostnames by reading first 56-character
		// Let's keep it as it is, tor community might do that on purpose to maintain forward compatible addresses.
		let hsid = HsId::from_str(&onion_host).map_err(|e| {
			OnionV3Error::AddressDecoding(format!("Provided onion V3 address is invalid, {}", e))
		})?;

		let key_bytes: [u8; 32] = *hsid.as_ref();

		Ok(OnionV3Address::from_bytes(key_bytes)?)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use std::convert::TryInto;

	#[test]
	fn onion_v3() -> Result<(), OnionV3Error> {
		let onion_address_str = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";
		let onion_address: OnionV3Address = onion_address_str.try_into()?;

		println!("Onion address: {:?}", onion_address);
		let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb";
		let onion_address_2: OnionV3Address = raw_pubkey_str.try_into()?;

		assert_eq!(onion_address, onion_address_2);

		// invalid hex string, should be interpreted as base32 and fail
		let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bx";
		let ret: Result<OnionV3Address, OnionV3Error> = raw_pubkey_str.try_into();
		assert!(ret.is_err());

		// wrong length hex string, should be interpreted as base32 and fail
		let raw_pubkey_str = "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bbff";
		let ret: Result<OnionV3Address, OnionV3Error> = raw_pubkey_str.try_into();
		assert!(ret.is_err());

		// wrong length ov3 string
		let onion_address_str = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyidx";
		let ret: Result<OnionV3Address, OnionV3Error> = onion_address_str.try_into();
		assert!(ret.is_err());

		// not base 32 ov3 string
		let onion_address_str = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyi-";
		let ret: Result<OnionV3Address, OnionV3Error> = onion_address_str.try_into();
		assert!(ret.is_err());

		Ok(())
	}
}
