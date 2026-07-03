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

use crate::Error;
use mwc_crates::zeroize::Zeroizing;

/// Encode the provided bytes into a hex string
pub fn to_hex(bytes: &[u8]) -> String {
	const HEX: &[u8; 16] = b"0123456789abcdef";

	let mut s = String::with_capacity(bytes.len() * 2);
	for &b in bytes {
		// Safe: shifting a byte right by four yields a nibble in 0..=15.
		s.push(HEX[usize::from(b >> 4)] as char);
		// Safe: masking a byte with 0x0f yields a nibble in 0..=15.
		s.push(HEX[usize::from(b & 0x0f)] as char);
	}
	s
}

/// Convert to hex
pub trait ToHex {
	/// convert to hex
	fn to_hex(&self) -> String;
}

impl<T: AsRef<[u8]>> ToHex for T {
	fn to_hex(&self) -> String {
		to_hex(self.as_ref())
	}
}

/// Decode a hex string into bytes (non secure version).
pub fn from_hex(hex: &str) -> Result<Vec<u8>, Error> {
	let hex = hex.trim();
	let hex = hex.strip_prefix("0x").unwrap_or(hex);
	if hex.len() % 2 != 0 {
		return Err(Error::Hex(format!("invalid length {} for hex", hex.len())));
	}

	hex.as_bytes()
		.chunks_exact(2)
		.map(|pair| {
			let high = hex_value(pair[0])
				.ok_or_else(|| Error::Hex(format!("invalid symbol {} for hex", pair[0])))?;
			let low = hex_value(pair[1])
				.ok_or_else(|| Error::Hex(format!("invalid symbol {} for hex", pair[1])))?;
			Ok((high << 4) | low)
		})
		.collect()
}

/// Decode fixed-length secret-key hex into zeroizing storage (secure version).
///
/// Unlike `from_hex`, this requires the exact byte length, avoids including
/// input data in errors, and does not allocate a non-zeroizing `Vec`.
pub fn decode_secret_key_hex<const N: usize>(hex: &str) -> Result<Zeroizing<[u8; N]>, Error> {
	let hex = hex.trim();
	let hex = hex.strip_prefix("0x").unwrap_or(hex);
	if hex.len() % 2 != 0 {
		return Err(Error::Hex("invalid secret hex length".to_string()));
	}

	let actual_len = hex.len() / 2;
	if actual_len != N {
		return Err(Error::InvalidLength {
			actual: actual_len,
			expected: N,
		});
	}

	let mut bytes = Zeroizing::new([0u8; N]);
	for (idx, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
		let high =
			hex_value(pair[0]).ok_or_else(|| Error::Hex("invalid secret hex".to_string()))?;
		let low = hex_value(pair[1]).ok_or_else(|| Error::Hex("invalid secret hex".to_string()))?;
		bytes[idx] = (high << 4) | low;
	}
	Ok(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_to_hex() {
		assert_eq!(vec![0, 0, 0, 0].to_hex(), "00000000");
		assert_eq!(vec![10, 11, 12, 13].to_hex(), "0a0b0c0d");
		assert_eq!([0, 0, 0, 255].to_hex(), "000000ff");
	}

	#[test]
	fn test_to_hex_trait() {
		assert_eq!(vec![0, 0, 0, 0].to_hex(), "00000000");
		assert_eq!(vec![10, 11, 12, 13].to_hex(), "0a0b0c0d");
		assert_eq!([0, 0, 0, 255].to_hex(), "000000ff");
	}

	#[test]
	fn test_from_hex() {
		assert_eq!(from_hex("").unwrap(), Vec::<u8>::new());
		assert_eq!(from_hex("00000000").unwrap(), vec![0, 0, 0, 0]);
		assert_eq!(from_hex("0a0b0c0d").unwrap(), vec![10, 11, 12, 13]);
		assert_eq!(from_hex("000000ff").unwrap(), vec![0, 0, 0, 255]);
		assert_eq!(from_hex("0x000000ff").unwrap(), vec![0, 0, 0, 255]);
		assert_eq!(from_hex("0x000000fF").unwrap(), vec![0, 0, 0, 255]);
		assert!(matches!(
			from_hex("0x000000fg"),
			Err(Error::Hex(ref msg)) if msg == "invalid symbol 103 for hex"
		));
		assert!(matches!(
			from_hex("not a hex string"),
			Err(Error::Hex(ref msg)) if msg == "invalid symbol 110 for hex"
		));
		assert!(matches!(
			from_hex("0"),
			Err(Error::Hex(ref msg)) if msg == "invalid length 1 for hex"
		));
	}

	#[test]
	fn test_decode_secret_key_hex() {
		assert_eq!(
			&decode_secret_key_hex::<4>("000000ff").unwrap()[..],
			&[0, 0, 0, 255]
		);
		assert!(matches!(
			decode_secret_key_hex::<4>("000000ff00"),
			Err(Error::InvalidLength {
				actual: 5,
				expected: 4
			})
		));
		assert!(matches!(
			decode_secret_key_hex::<4>("000000f"),
			Err(Error::Hex(ref msg)) if msg == "invalid secret hex length"
		));
		assert!(matches!(
			decode_secret_key_hex::<4>("000000fg"),
			Err(Error::Hex(ref msg)) if msg == "invalid secret hex"
		));
	}
}
