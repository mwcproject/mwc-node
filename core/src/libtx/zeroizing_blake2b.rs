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

use mwc_crates::zeroize::{Zeroize, Zeroizing};
use std::cmp;

const OUTBYTES: usize = 64;
const KEYBYTES: usize = 64;
const BLOCKBYTES: usize = 128;

const IV: [u64; 8] = [
	0x6a09e667f3bcc908,
	0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b,
	0xa54ff53a5f1d36f1,
	0x510e527fade682d1,
	0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b,
	0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
	[11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
	[7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
	[9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
	[2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
	[12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
	[13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
	[6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
	[10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
	[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
	[14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

struct ZeroizingBlake2b {
	h: [u64; 8],
	t: u128,
	buf: [u8; BLOCKBYTES],
	buflen: usize,
	outlen: usize,
}

impl ZeroizingBlake2b {
	fn new(outlen: usize, key_len: usize) -> Self {
		assert!(outlen >= 1 && outlen <= OUTBYTES && key_len <= KEYBYTES);

		let mut h = IV;
		h[0] ^= 0x01010000 ^ ((key_len as u64) << 8) ^ (outlen as u64);

		Self {
			h,
			t: 0,
			buf: [0; BLOCKBYTES],
			buflen: 0,
			outlen,
		}
	}

	fn set_key(&mut self, key: &[u8]) {
		if !key.is_empty() {
			self.buf[..key.len()].copy_from_slice(key);
			self.buflen = BLOCKBYTES;
		}
	}

	fn update(&mut self, mut data: &[u8]) {
		if data.is_empty() {
			return;
		}

		if self.buflen > 0 {
			let fill = BLOCKBYTES - self.buflen;
			if data.len() > fill {
				self.buf[self.buflen..self.buflen + fill].copy_from_slice(&data[..fill]);
				self.buflen = BLOCKBYTES;
				self.increment_counter(BLOCKBYTES);
				compress(&mut self.h, self.t, &self.buf, false);
				self.buf.zeroize();
				self.buflen = 0;
				data = &data[fill..];
			} else {
				self.buf[self.buflen..self.buflen + data.len()].copy_from_slice(data);
				self.buflen += data.len();
				return;
			}
		}

		while data.len() > BLOCKBYTES {
			self.increment_counter(BLOCKBYTES);
			compress(&mut self.h, self.t, &data[..BLOCKBYTES], false);
			data = &data[BLOCKBYTES..];
		}

		self.buf[..data.len()].copy_from_slice(data);
		self.buflen = data.len();
	}

	fn finalize(&mut self) -> Zeroizing<Vec<u8>> {
		self.increment_counter(self.buflen);
		for byte in &mut self.buf[self.buflen..] {
			*byte = 0;
		}
		compress(&mut self.h, self.t, &self.buf, true);

		let mut out = Zeroizing::new(vec![0; self.outlen]);
		let mut offset = 0;
		for word in &self.h {
			let mut bytes = word.to_le_bytes();
			let take = cmp::min(bytes.len(), out.len() - offset);
			out[offset..offset + take].copy_from_slice(&bytes[..take]);
			bytes.zeroize();
			offset += take;
			if offset == out.len() {
				break;
			}
		}

		self.zeroize_state();
		out
	}

	fn increment_counter(&mut self, bytes: usize) {
		self.t = self
			.t
			.checked_add(bytes as u128)
			.expect("hash data length overflow");
	}

	fn zeroize_state(&mut self) {
		self.h.zeroize();
		self.t.zeroize();
		self.buf.zeroize();
		self.buflen.zeroize();
		self.outlen.zeroize();
	}
}

impl Drop for ZeroizingBlake2b {
	fn drop(&mut self) {
		self.zeroize_state();
	}
}

/// Computes BLAKE2b into zeroizing output storage and wipes local hash objects.
pub(super) fn zeroizing_blake2b(outlen: usize, key: &[u8], data: &[u8]) -> Zeroizing<Vec<u8>> {
	let mut state = ZeroizingBlake2b::new(outlen, key.len());
	state.set_key(key);
	state.update(data);
	state.finalize()
}

fn compress(h: &mut [u64; 8], t: u128, block: &[u8], last: bool) {
	debug_assert_eq!(block.len(), BLOCKBYTES);

	let mut m = [0u64; 16];
	for (idx, word) in m.iter_mut().enumerate() {
		let start = idx * 8;
		*word = u64::from_le_bytes([
			block[start],
			block[start + 1],
			block[start + 2],
			block[start + 3],
			block[start + 4],
			block[start + 5],
			block[start + 6],
			block[start + 7],
		]);
	}

	let mut v = [0u64; 16];
	v[..8].copy_from_slice(h);
	v[8..].copy_from_slice(&IV);
	v[12] ^= t as u64;
	v[13] ^= (t >> 64) as u64;
	if last {
		v[14] = !v[14];
	}

	for sigma in &SIGMA {
		round(&mut v, &m, sigma);
	}

	for idx in 0..8 {
		h[idx] ^= v[idx] ^ v[idx + 8];
	}

	m.zeroize();
	v.zeroize();
}

fn round(v: &mut [u64; 16], m: &[u64; 16], sigma: &[usize; 16]) {
	quarter_round(v, m, 0, 4, 8, 12, sigma[0], sigma[1]);
	quarter_round(v, m, 1, 5, 9, 13, sigma[2], sigma[3]);
	quarter_round(v, m, 2, 6, 10, 14, sigma[4], sigma[5]);
	quarter_round(v, m, 3, 7, 11, 15, sigma[6], sigma[7]);
	quarter_round(v, m, 0, 5, 10, 15, sigma[8], sigma[9]);
	quarter_round(v, m, 1, 6, 11, 12, sigma[10], sigma[11]);
	quarter_round(v, m, 2, 7, 8, 13, sigma[12], sigma[13]);
	quarter_round(v, m, 3, 4, 9, 14, sigma[14], sigma[15]);
}

#[inline(always)]
fn quarter_round(
	v: &mut [u64; 16],
	m: &[u64; 16],
	a: usize,
	b: usize,
	c: usize,
	d: usize,
	x: usize,
	y: usize,
) {
	v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[x]);
	v[d] = (v[d] ^ v[a]).rotate_right(32);
	v[c] = v[c].wrapping_add(v[d]);
	v[b] = (v[b] ^ v[c]).rotate_right(24);
	v[a] = v[a].wrapping_add(v[b]).wrapping_add(m[y]);
	v[d] = (v[d] ^ v[a]).rotate_right(16);
	v[c] = v[c].wrapping_add(v[d]);
	v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(test)]
mod tests {
	use super::zeroizing_blake2b;
	use blake2::{
		digest::{FixedOutput, KeyInit, Update, VariableOutput},
		Blake2bMac512, Blake2bVar,
	};
	use mwc_crates::blake2_rfc::blake2b::blake2b;

	#[test]
	fn matches_blake2_rfc() {
		let outlens = [1, 16, 32, 64];
		let key_lens = [0, 1, 16, 33, 64];
		let data_lens = [0, 1, 31, 32, 63, 64, 65, 127, 128, 129, 255, 1024];

		for outlen in outlens {
			for key_len in key_lens {
				for data_len in data_lens {
					let key = seq(key_len);
					let data = seq(data_len);
					let expected = blake2b(outlen, &key, &data);
					let actual = zeroizing_blake2b(outlen, &key, &data);

					assert_eq!(
						actual.as_slice(),
						expected.as_bytes(),
						"outlen={}, key_len={}, data_len={}",
						outlen,
						key_len,
						data_len
					);
				}
			}
		}
	}

	#[test]
	fn matches_rustcrypto_blake2_generated_inputs() {
		let outlens = [1, 16, 32, 64];
		let data_lens = [0, 1, 31, 64, 65, 127, 128, 129, 255, 1024];

		for outlen in outlens {
			for data_len in data_lens {
				let data = seq(data_len);
				let mut expected = vec![0; outlen];
				let mut hasher = Blake2bVar::new(outlen).unwrap();
				hasher.update(&data);
				hasher.finalize_variable(&mut expected).unwrap();

				let actual = zeroizing_blake2b(outlen, &[], &data);
				assert_eq!(
					actual.as_slice(),
					expected.as_slice(),
					"outlen={}, data_len={}",
					outlen,
					data_len
				);
			}
		}

		let key_lens = [1, 16, 64];
		for key_len in key_lens {
			for data_len in data_lens {
				let key = seq(key_len);
				let data = seq(data_len);
				let mut hasher = Blake2bMac512::new_from_slice(&key).unwrap();
				hasher.update(&data);
				let expected = hasher.finalize_fixed();

				let actual = zeroizing_blake2b(64, &key, &data);
				assert_eq!(
					actual.as_slice(),
					&expected[..],
					"key_len={}, data_len={}",
					key_len,
					data_len
				);
			}
		}
	}

	fn seq(len: usize) -> Vec<u8> {
		(0..len)
			.map(|idx| (idx as u8).wrapping_mul(37).wrapping_add(11))
			.collect()
	}
}
