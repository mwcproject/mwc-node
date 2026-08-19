// Copyright 2026 The MWC Developers
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

//! HMAC-SHA512 with zeroizing state, intermediate digest, and output storage.

use crate::extkey_bip32::Error;
use mwc_crates::digest::{
	block_api::{Buffer, UpdateCore, VariableOutputCore},
	Output,
};
use mwc_crates::sha2::block_api::Sha512VarCore;
use mwc_crates::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use std::fmt;

const HMAC_SHA512_BLOCK_SIZE: usize = 128;
const HMAC_SHA512_OUTPUT_SIZE: usize = 64;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// SHA-512 state using the block API so finalization writes directly into
/// caller-owned zeroizing storage instead of creating an ordinary digest output.
#[derive(Clone)]
struct ZeroizingSha512 {
	core: Sha512VarCore,
	buffer: Buffer<Sha512VarCore>,
}

impl ZeroizingSha512 {
	fn new() -> Result<Self, Error> {
		let core = Sha512VarCore::new(HMAC_SHA512_OUTPUT_SIZE)
			.map_err(|_| Error::Generic("Unable to initialize SHA-512 output size".into()))?;
		Ok(Self {
			core,
			buffer: Buffer::<Sha512VarCore>::default(),
		})
	}

	fn update(&mut self, data: &[u8]) {
		let Self { core, buffer } = self;
		buffer.digest_blocks(data, |blocks| core.update_blocks(blocks));
	}

	fn finalize_into(&mut self, output: &mut Zeroizing<[u8; HMAC_SHA512_OUTPUT_SIZE]>) {
		output.zeroize();
		let output: &mut Output<Sha512VarCore> = (&mut **output).into();
		self.core.finalize_variable_core(&mut self.buffer, output);
	}
}

impl ZeroizeOnDrop for ZeroizingSha512 {}

/// Incremental HMAC-SHA512 state whose secret-bearing fields wipe on drop.
#[derive(Clone)]
pub struct ZeroizingHmacSha512 {
	inner: ZeroizingSha512,
	outer: ZeroizingSha512,
}

impl fmt::Debug for ZeroizingHmacSha512 {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("ZeroizingHmacSha512 { ... }")
	}
}

impl ZeroizingHmacSha512 {
	/// Initializes HMAC-SHA512 while keeping normalized key and pad blocks in
	/// zeroizing storage.
	pub fn new(key: &[u8]) -> Result<Self, Error> {
		let mut key_block = Zeroizing::new([0u8; HMAC_SHA512_BLOCK_SIZE]);
		if key.len() > HMAC_SHA512_BLOCK_SIZE {
			let mut key_hash = Zeroizing::new([0u8; HMAC_SHA512_OUTPUT_SIZE]);
			let mut key_hasher = ZeroizingSha512::new()?;
			key_hasher.update(key);
			key_hasher.finalize_into(&mut key_hash);
			key_block[..HMAC_SHA512_OUTPUT_SIZE].copy_from_slice(&key_hash[..]);
		} else {
			key_block[..key.len()].copy_from_slice(key);
		}

		for byte in key_block.iter_mut() {
			*byte ^= IPAD;
		}
		let mut inner = ZeroizingSha512::new()?;
		inner.update(&key_block[..]);

		for byte in key_block.iter_mut() {
			*byte ^= IPAD ^ OPAD;
		}
		let mut outer = ZeroizingSha512::new()?;
		outer.update(&key_block[..]);

		Ok(Self { inner, outer })
	}

	/// Appends message data to the HMAC calculation.
	pub fn update(&mut self, data: &[u8]) {
		self.inner.update(data);
	}

	/// Finalizes the HMAC state in place and writes the tag into zeroizing storage.
	///
	/// This is a terminal operation; the state should be dropped immediately afterward.
	pub fn finalize_into(&mut self, output: &mut Zeroizing<[u8; HMAC_SHA512_OUTPUT_SIZE]>) {
		let mut inner_hash = Zeroizing::new([0u8; HMAC_SHA512_OUTPUT_SIZE]);
		self.inner.finalize_into(&mut inner_hash);
		self.outer.update(&inner_hash[..]);
		self.outer.finalize_into(output);
	}
}

impl ZeroizeOnDrop for ZeroizingHmacSha512 {}

#[cfg(test)]
mod tests {
	use super::{ZeroizingHmacSha512, HMAC_SHA512_OUTPUT_SIZE};
	use mwc_crates::zeroize::Zeroizing;

	fn calculate(key: &[u8], chunks: &[&[u8]]) -> Zeroizing<[u8; HMAC_SHA512_OUTPUT_SIZE]> {
		let mut hmac = ZeroizingHmacSha512::new(key).unwrap();
		for chunk in chunks {
			hmac.update(chunk);
		}
		let mut output = Zeroizing::new([0u8; HMAC_SHA512_OUTPUT_SIZE]);
		hmac.finalize_into(&mut output);
		output
	}

	fn assert_rfc4231(key: &[u8], data: &[u8], expected_hex: &str) {
		let expected = mwc_crates::hex::decode(expected_hex).unwrap();
		let actual = calculate(key, &[data]);
		assert_eq!(&actual[..], expected.as_slice());
	}

	#[test]
	fn matches_rfc4231_sha512_vectors() {
		assert_rfc4231(
			&[0x0b; 20],
			b"Hi There",
			concat!(
				"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde",
				"daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
			),
		);
		assert_rfc4231(
			b"Jefe",
			b"what do ya want for nothing?",
			concat!(
				"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554",
				"9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
			),
		);
		assert_rfc4231(
			&[0xaa; 131],
			b"Test Using Larger Than Block-Size Key - Hash Key First",
			concat!(
				"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352",
				"6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"
			),
		);
	}

	#[test]
	fn incremental_updates_match_single_update() {
		let key = b"BIP32 incremental HMAC key";
		let expected = calculate(key, &[b"address-key derivation"]);
		let actual = calculate(key, &[b"address-", b"key ", b"derivation"]);
		assert_eq!(&actual[..], &expected[..]);
	}
}
