// Copyright 2020 The Grin Developers
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

//! NIT(Non-Interactive Transaction) Address.
//!
//! Support for Bech32 address format as default.

use bech32::{self, FromBase32, ToBase32};
use failure::Fail;
use std::fmt;
use std::str::FromStr;

use crate::core::hash::Hashed;
use crate::global::ChainTypes;
use util::secp::key::{PublicKey, SecretKey};
use util::secp::{self, Secp256k1};

/// Address error.
#[derive(Fail, Clone, Eq, Debug, PartialEq, Serialize, Deserialize)]
pub enum Error {
	/// HRP(Human Readable Part) error
	#[fail(display = "HRP Error")]
	HRP,
	/// Bech32 encoding error
	#[fail(display = "Bech32: {}", 0)]
	Bech32(String),
	/// Secp Error
	#[fail(display = "Secp error")]
	Secp(secp::Error),
	/// The length must be between 2 and 256 bytes in length.
	#[fail(display = "Invalid Length {}", 0)]
	InvalidLength(usize),
	/// Version must be 0 to 16 inclusive
	#[fail(display = "Invalid Version {}", 0)]
	InvalidVersion(u8),
	/// A v0 address must be with a raw data length of either 33-bytes or 65-bytes.
	#[fail(display = "Invalid V0 Length {}", 0)]
	InvalidV0Length(usize),
	/// Bit conversion error
	#[fail(display = "Bit conversion error {}", 0)]
	BitConversionError(String),
	/// Address type error
	#[fail(display = "Incorrect address type")]
	AddressTypeError,
	/// Incorrect private Key
	#[fail(display = "Incorrect private key")]
	IncorrectKey,
}

impl From<bech32::Error> for Error {
	fn from(inner: bech32::Error) -> Error {
		Error::Bech32(inner.to_string())
	}
}

impl From<secp::Error> for Error {
	fn from(inner: secp::Error) -> Error {
		Error::Secp(inner)
	}
}

/// Inner address data of Bech32Addr
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InnerAddr {
	/// Stealth Address with one single Public Key. Implicitly same key for View and Spend.
	LiteStealthAddr {
		/// The public key
		pubkey: PublicKey,
	},
	/// Stealth Address with Public View Key and Public Spend Key.
	StealthAddr {
		/// The public view key A
		pubkey_view: PublicKey,
		/// The public spend key B
		pubkey_spend: PublicKey,
	},
}

/// Bech32 address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bech32Addr {
	/// The address version
	pub version: bech32::u5,
	/// The inner address data
	pub inner_addr: InnerAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A MWC address
pub struct Address {
	/// The type of the address
	pub bech32_addr: Bech32Addr,
	/// The network on which this address is usable
	pub network: ChainTypes,
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.to_string())
	}
}

impl Default for Address {
	fn default() -> Self {
		Address {
			bech32_addr: Bech32Addr {
				version: bech32::u5::try_from_u8(0).unwrap(),
				inner_addr: InnerAddr::LiteStealthAddr {
					pubkey: PublicKey::new(),
				},
			},
			network: ChainTypes::Mainnet,
		}
	}
}

impl Address {
	/// Create a lite stealth address from one public key.
	pub fn from_one_pubkey(pk: &PublicKey, network: ChainTypes) -> Address {
		Address {
			bech32_addr: Bech32Addr {
				version: bech32::u5::try_from_u8(0).unwrap(),
				inner_addr: InnerAddr::LiteStealthAddr { pubkey: pk.clone() },
			},
			network,
		}
	}

	/// Create a stealth address from one public key.
	pub fn from_pubkey(pk_view: &PublicKey, pk_spend: &PublicKey, network: ChainTypes) -> Address {
		Address {
			bech32_addr: Bech32Addr {
				version: bech32::u5::try_from_u8(0).unwrap(),
				inner_addr: InnerAddr::StealthAddr {
					pubkey_view: pk_view.clone(),
					pubkey_spend: pk_spend.clone(),
				},
			},
			network,
		}
	}

	/// Get the inner public key if it's a LiteStealthAddr.
	pub fn get_inner_pubkey(&self) -> Result<&PublicKey, Error> {
		match self.bech32_addr.inner_addr {
			InnerAddr::LiteStealthAddr { ref pubkey } => Ok(pubkey),
			InnerAddr::StealthAddr { .. } => Err(Error::AddressTypeError),
		}
	}

	/// Get the inner public keys of a stealth address, if it's a StealthAddr.
	pub fn get_inner_pubkeys(&self) -> (&PublicKey, &PublicKey) {
		match self.bech32_addr.inner_addr {
			InnerAddr::LiteStealthAddr { ref pubkey } => (pubkey, pubkey),
			InnerAddr::StealthAddr {
				ref pubkey_view,
				ref pubkey_spend,
			} => (pubkey_view, pubkey_spend),
		}
	}

	/// Get the inner public view key.
	pub fn get_view_pubkey(&self) -> &PublicKey {
		match self.bech32_addr.inner_addr {
			InnerAddr::LiteStealthAddr { ref pubkey } => pubkey,
			InnerAddr::StealthAddr {
				ref pubkey_view,
				pubkey_spend: _,
			} => pubkey_view,
		}
	}

	/// Get the inner public spend key.
	pub fn get_spend_pubkey(&self) -> &PublicKey {
		match self.bech32_addr.inner_addr {
			InnerAddr::LiteStealthAddr { ref pubkey } => pubkey,
			InnerAddr::StealthAddr {
				pubkey_view: _,
				ref pubkey_spend,
			} => pubkey_spend,
		}
	}

	/// Get the Ephemeral key, with the spec of https://eprint.iacr.org/2020/1064.pdf
	/// For Stealth Address (A,B):
	///   `arr/raa = a*R === r*A`.
	///   `A'=Hash(a*R)*G === Hash(r*A)*G`.
	///   `P=A'+B, P'=Hash(A')*G+B`.
	///   `q = Hash(P)`.
	/// where 'a' is the private view key, a*G=A. 'R' is the public nonce, R=r*G.
	///
	/// Calculation Complexity: 3 point-multiply + 2 point-add + 3 hash.
	/// Return the shared ephemeral key `q`, the one-time-public-key `P'`, and `Hash(A')`.
	///
	/// Note: propose to use get_ephemeral_key_for_rx/get_ephemeral_key_for_tx instead of this one.
	pub fn get_ephemeral_key(
		&self,
		secp: &Secp256k1,
		arr_raa: &PublicKey,
	) -> Result<(SecretKey, PublicKey, SecretKey), Error> {
		let bb = self.get_spend_pubkey();

		// Normally the loop here will break at first hash.
		for i in 0..2 {
			// Calculate `A'=Hash(a*R)*G == Hash(r*A)*G`.
			if let Ok(a_apos) = SecretKey::from_slice(
				(
					format!("ecp{}", i).as_bytes().to_vec(),
					arr_raa.serialize_vec(true).as_ref().to_vec(),
				)
					.hash()
					.as_bytes(),
			) {
				let aa_apos = PublicKey::from_secret_key(secp, &a_apos)?;

				// Calculate `q = Hash(A'+B)`.
				if let Ok(q) = SecretKey::from_slice(
					(
						format!("ecp{}", i).as_bytes().to_vec(),
						PublicKey::from_combination(vec![&aa_apos, bb])?
							.serialize_vec(true)
							.as_ref()
							.to_vec(),
					)
						.hash()
						.as_bytes(),
				) {
					// Calculate `P'=Hash(A')*G+B`.
					if let Ok(h) = SecretKey::from_slice(
						(
							format!("ecp{}", i).as_bytes().to_vec(),
							aa_apos.serialize_vec(true).as_ref().to_vec(),
						)
							.hash()
							.as_bytes(),
					) {
						let mut pp_apos = bb.clone();
						pp_apos.add_exp_assign(secp, &h)?;
						return Ok((q, pp_apos, h));
					}
				}
			}
		}
		Err(Error::Secp(secp::Error::InvalidSecretKey))
	}

	/// Get the "view tag" of the Stealth Address on rx side, i.e. the first byte of the shared secret.
	/// It helps to reduce the time to scan the output ownership by at least 65%.
	/// For Stealth Address (A,B):
	///   "view tag" = `Hash(a*R) === Hash(r*A)`.
	/// Calculation Complexity: 1 point-multiply + 1 hash.
	///   comparing the "3 point-multiply + 2 point-add + 3 hash", this is about 1/3 complexity.
	pub fn get_view_tag_for_rx(
		secp: &Secp256k1,
		private_view_key: &SecretKey,
		public_nonce: &PublicKey,
	) -> Result<u8, Error> {
		let mut a_rr = public_nonce.clone();
		a_rr.mul_assign(secp, private_view_key)?;

		for i in 0..2 {
			let h = (
				format!("ecp{}", i).as_bytes().to_vec(),
				a_rr.serialize_vec(true).as_ref().to_vec(),
			)
				.hash();
			if let Ok(_) = SecretKey::from_slice(h.as_bytes()) {
				return Ok(h[0]);
			}
		}
		Err(Error::Secp(secp::Error::InvalidSecretKey))
	}

	/// Get the Ephemeral key on rx side, with the spec of https://eprint.iacr.org/2020/1064.pdf
	/// Return the shared ephemeral key `q` and the one-time-public-key `P'`.
	pub fn get_ephemeral_key_for_rx(
		&self,
		secp: &Secp256k1,
		private_view_key: &SecretKey,
		public_nonce: &PublicKey,
	) -> Result<(SecretKey, PublicKey), Error> {
		// Safety checking whether the private view key match this address.
		let aa = self.get_view_pubkey();
		if PublicKey::from_secret_key(secp, private_view_key)? != *aa {
			return Err(Error::IncorrectKey);
		}

		let mut a_rr = public_nonce.clone();
		a_rr.mul_assign(secp, private_view_key)?;

		self.get_ephemeral_key(secp, &a_rr)
			.and_then(|(q, pp_apos, _a_apos)| Ok((q, pp_apos)))
	}

	/// Get the "view tag" of the Stealth Address on tx side, i.e. the first byte of the shared secret
	/// For Stealth Address (A,B):
	///   "view tag" = `Hash(a*R) === Hash(r*A)`.
	pub fn get_view_tag_for_tx(
		&self,
		secp: &Secp256k1,
		private_nonce: &SecretKey,
	) -> Result<u8, Error> {
		let mut r_aa = self.get_view_pubkey().clone();
		r_aa.mul_assign(secp, private_nonce)?;

		for i in 0..2 {
			let h = (
				format!("ecp{}", i).as_bytes().to_vec(),
				r_aa.serialize_vec(true).as_ref().to_vec(),
			)
				.hash();
			if let Ok(_) = SecretKey::from_slice(h.as_bytes()) {
				return Ok(h[0]);
			}
		}
		Err(Error::Secp(secp::Error::InvalidSecretKey))
	}

	/// Same as above but on sender side.
	pub fn get_ephemeral_key_for_tx(
		&self,
		secp: &Secp256k1,
		private_nonce: &SecretKey,
	) -> Result<(SecretKey, PublicKey), Error> {
		let mut r_aa = self.get_view_pubkey().clone();
		r_aa.mul_assign(secp, private_nonce)?;

		self.get_ephemeral_key(secp, &r_aa)
			.and_then(|(q, pp_apos, _a_apos)| Ok((q, pp_apos)))
	}

	/// Serialize to u8 vector: either 33-bytes or 65-bytes in raw data.
	/// Note: each public key prefix (either 0x02 or 0x03) is serialized as 1 bit and attached as a common suffix byte.
	pub fn to_vec(&self) -> Vec<u8> {
		let mut wtr: Vec<u8> = Vec::with_capacity(65);
		match self.bech32_addr.inner_addr {
			InnerAddr::LiteStealthAddr { pubkey } => {
				let ser_p: Vec<u8> = pubkey.serialize_vec(true).as_ref().to_vec();
				wtr.extend_from_slice(&ser_p[1..]);
				// prefix (0x02 or 0x03) as 1 bit suffix
				wtr.push((ser_p[0] & 1) << 7);
			}
			InnerAddr::StealthAddr {
				pubkey_view: v,
				pubkey_spend: s,
			} => {
				let ser_v: Vec<u8> = v.serialize_vec(true).as_ref().to_vec();
				wtr.extend_from_slice(&ser_v[1..]);
				let ser_s: Vec<u8> = s.serialize_vec(true).as_ref().to_vec();
				wtr.extend_from_slice(&ser_s[1..]);
				// each prefix (0x02 or 0x03) as 1 bit suffix.
				wtr.push(((ser_v[0] & 1) << 7) + ((ser_s[0] & 1) << 6));
			}
		}
		wtr
	}

	/// Get the address string
	pub fn to_string(&self) -> String {
		let mut data: Vec<bech32::u5> = vec![];
		data.push(self.bech32_addr.version);

		// Convert 8-bit data into 5-bit
		let raw = self.to_vec();
		let d5 = match self.bech32_addr.inner_addr {
			// (32 bytes + 1 bit) data + 3 bit padding = 52 d5
			InnerAddr::LiteStealthAddr { .. } => raw.to_base32()[0..52].to_vec(),
			// (32*2 bytes + 2 bits) data + 1 bit padding = 103 d5
			InnerAddr::StealthAddr { .. } => raw.to_base32()[0..103].to_vec(),
		};

		data.extend_from_slice(&d5);
		let hrp = match self.network {
			ChainTypes::Mainnet => "mwc",
			ChainTypes::Floonet => "mwt",
			ChainTypes::UserTesting => "mwu",
			ChainTypes::AutomatedTesting => "mwa",
		};
		bech32::encode(hrp, data).unwrap()
	}
}

impl FromStr for Address {
	type Err = Error;

	fn from_str(s: &str) -> Result<Address, Error> {
		let (hrp, mut payload) = bech32::decode(s)?;
		let network = match hrp.as_str() {
			"mwc" => ChainTypes::Mainnet,
			"mwt" => ChainTypes::Floonet,
			"mwu" => ChainTypes::UserTesting,
			"mwa" => ChainTypes::AutomatedTesting,
			_ => return Err(Error::HRP),
		};

		if payload.is_empty() {
			return Err(Error::InvalidLength(0));
		}

		// Padding before conversion from d5 to u8.
		//   -  52 d5 = 256+4 bits, which need 4bits padding for bytes, i.e. one d5(0) as padding.
		//   - 103 d5 = 512+3 bits, which need 5bits padding for bytes, i.e. one d5(0) as padding.
		payload.push(bech32::u5::try_from_u8(0).unwrap());

		// Get the version and data (converted from 5-bit to 8-bit)
		let (version, mut data): (bech32::u5, Vec<u8>) = {
			let (v, d5) = payload.split_at(1);
			(v[0], FromBase32::from_base32(d5)?)
		};

		// Generic checks.
		if version.to_u8() > 16 {
			return Err(Error::InvalidVersion(version.to_u8()));
		}
		if data.len() < 2 || data.len() > 256 {
			return Err(Error::InvalidLength(data.len()));
		}

		// Specific v0 check.
		if version.to_u8() == 0 && !(data.len() == 33 || data.len() == 65) {
			return Err(Error::InvalidV0Length(data.len()));
		}

		//println!("raw data: {}", util::to_hex(data.clone()));

		match data.len() {
			33 => {
				// public key prefix is either 0x02 or 0x03.
				let prefix = (data[32] >> 7) + 2;
				data.truncate(32);
				data.insert(0, prefix);
				Ok(Address {
					bech32_addr: Bech32Addr {
						version,
						inner_addr: InnerAddr::LiteStealthAddr {
							pubkey: PublicKey::from_slice(&data[0..33])?,
						},
					},
					network,
				})
			}
			65 => {
				let prefix = data[64];
				data.truncate(64);
				data.insert(0, (prefix >> 7) + 2);
				data.insert(33, ((prefix >> 6) & 1) + 2);
				Ok(Address {
					bech32_addr: Bech32Addr {
						version,
						inner_addr: InnerAddr::StealthAddr {
							pubkey_view: PublicKey::from_slice(&data[0..33])?,
							pubkey_spend: PublicKey::from_slice(&data[33..])?,
						},
					},
					network,
				})
			}
			_ => Err(Error::InvalidV0Length(data.len())),
		}
	}
}
