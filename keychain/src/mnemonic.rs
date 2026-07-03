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
//
//! # BIP39 Implementation
//!
//! Implementation of BIP39 Mnemonic code for generating deterministic keys, as defined
//! at https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

use mwc_crates::digest::Digest;
use mwc_crates::hmac::Hmac;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::pbkdf2::pbkdf2;
use mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_crates::sha2::{Sha256, Sha512};
use mwc_crates::zeroize::Zeroizing;
use std::convert::TryFrom;

lazy_static! {
	/// List of bip39 words
	pub static ref WORDS: Vec<String> = include_str!("wordlists/en.txt").split_whitespace().map(|s| s.into()).collect();
}

/// An error that might occur during mnemonic decoding
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum Error {
	/// Invalid word encountered
	#[error("invalid bip39 word")]
	BadWord,
	/// Checksum was not correct (expected, actual)
	#[error("bip39 checksum 0x{0:x} does not match expected 0x{1:x}")]
	BadChecksum(u8, u8),
	/// The number of words/bytes was invalid
	#[error("invalid mnemonic/entropy length {0}")]
	InvalidLength(usize),
	/// Invalid passphase
	#[error("invalid passphrase encoding")]
	IbvalidPassphraseEncoding,
	/// Data overflow error
	#[error("mnemonic data overflow error, {0}")]
	DataOverflow(String),
}

/// Returns the index of a word in the wordlist
pub fn search(word: &str) -> Result<u16, Error> {
	let w = Zeroizing::new(word.to_string());
	match WORDS.binary_search(&w) {
		Ok(index) => u16::try_from(index).map_err(|_| {
			Error::DataOverflow(format!(
				"mnemonic::search, index={} words_len={}",
				index,
				WORDS.len()
			))
		}),
		Err(_) => Err(Error::BadWord),
	}
}

fn mnemonic_words(mnemonic: &str) -> Zeroizing<Vec<String>> {
	Zeroizing::new(mnemonic.split_whitespace().map(|s| s.into()).collect())
}

fn to_entropy_from_words(words: &[String]) -> Result<Zeroizing<Vec<u8>>, Error> {
	let sizes: [usize; 5] = [12, 15, 18, 21, 24];
	if !sizes.contains(&words.len()) {
		return Err(Error::InvalidLength(words.len()));
	}

	// u11 vector of indexes for each word
	let mut indexes: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(words.len()));
	for w in words {
		indexes.push(search(w)?);
	}

	let checksum_bits = words.len() / 3;
	// mask = ((1 << checksum_bits) - 1) as u8;
	let mask = 1u16
		// Safe: accepted BIP39 word counts make checksum_bits 4..=8.
		.checked_shl(checksum_bits as u32)
		.and_then(|value| value.checked_sub(1))
		.and_then(|value| u8::try_from(value).ok())
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"mnemonic::to_entropy_from_words, checksum_bits={}",
				checksum_bits
			))
		})?;
	let last = indexes.pop().ok_or(Error::InvalidLength(0))?;
	// Safe: checksum_bits is at most 8, so truncating to the low byte preserves
	// all checksum bits used by the mask.
	let checksum = (last as u8) & mask;

	// datalen = ((11 * words.len()) - checksum_bits) / 8 - 1;
	let datalen = words
		.len()
		.checked_mul(11)
		.and_then(|value| value.checked_sub(checksum_bits))
		// Safe: divisor is the fixed non-zero number of bits per byte.
		.map(|value| value / 8)
		.and_then(|value| value.checked_sub(1))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"mnemonic::to_entropy_from_words, words_len={} checksum_bits={}",
				words.len(),
				checksum_bits
			))
		})?;
	let mut entropy: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0; datalen]);
	// set the last byte to the data part of the last word
	// Safe: last is an 11-bit word index and shifting by checksum_bits leaves
	// at most 8 data bits.
	entropy.push((last >> checksum_bits) as u8);
	// start setting bits from this index
	let mut loc: usize = 11usize.checked_sub(checksum_bits).ok_or_else(|| {
		Error::DataOverflow(format!(
			"mnemonic::to_entropy_from_words, checksum_bits={}",
			checksum_bits
		))
	})?;

	// cast vector of u11 as u8
	for index in indexes.iter().rev() {
		for i in 0..11 {
			let bit = index & (1 << i) != 0;
			// entropy[datalen - loc / 8] |= (bit as u8) << (loc % 8);
			// loc += 1;
			let entropy_idx = datalen.checked_sub(loc / 8).ok_or_else(|| {
				Error::DataOverflow(format!(
					"mnemonic::to_entropy_from_words, datalen={} loc={}",
					datalen, loc
				))
			})?;
			let byte = entropy
				.get_mut(entropy_idx)
				.ok_or(Error::InvalidLength(entropy_idx))?;
			// Safe: loc % 8 bounds the shift to 0..=7 for a u8 bit.
			*byte |= u8::from(bit) << (loc % 8);
			loc = loc.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!("mnemonic::to_entropy_from_words, loc={}", loc))
			})?;
		}
	}

	let mut hash = Zeroizing::new([0; 32]);
	let mut sha2sum = Sha256::default();
	sha2sum.update(&entropy);
	hash.copy_from_slice(sha2sum.finalize_reset().as_slice());

	// actual = (hash[0] >> (8 - checksum_bits)) & mask;
	let actual_shift = 8usize.checked_sub(checksum_bits).ok_or_else(|| {
		Error::DataOverflow(format!(
			"mnemonic::to_entropy_from_words, checksum_bits={}",
			checksum_bits
		))
	})?;
	let actual = (hash[0] >> actual_shift) & mask;

	if actual != checksum {
		return Err(Error::BadChecksum(checksum, actual));
	}

	Ok(entropy)
}

/// Converts a mnemonic to entropy
pub fn to_entropy(mnemonic: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
	let words = mnemonic_words(mnemonic);
	to_entropy_from_words(&words)
}

/// Converts entropy to a mnemonic
pub fn from_entropy(entropy: &[u8]) -> Result<Zeroizing<String>, Error> {
	let sizes: [usize; 5] = [16, 20, 24, 28, 32];
	let length = entropy.len();
	if !sizes.contains(&length) {
		return Err(Error::InvalidLength(length));
	}

	let checksum_bits = length / 4;
	// mask = ((1 << checksum_bits) - 1) as u8;
	let mask = 1u16
		// Safe: accepted BIP39 entropy lengths make checksum_bits 4..=8.
		.checked_shl(checksum_bits as u32)
		.and_then(|value| value.checked_sub(1))
		.and_then(|value| u8::try_from(value).ok())
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"mnemonic::from_entropy, length={} checksum_bits={}",
				length, checksum_bits
			))
		})?;

	let mut hash = Zeroizing::new([0; 32]);
	let mut sha2sum = Sha256::default();
	sha2sum.update(entropy);
	hash.copy_from_slice(sha2sum.finalize_reset().as_slice());

	//  checksum = (hash[0] >> 8 - checksum_bits) & mask;
	let checksum_shift = 8usize.checked_sub(checksum_bits).ok_or_else(|| {
		Error::DataOverflow(format!(
			"mnemonic::from_entropy, checksum_bits={}",
			checksum_bits
		))
	})?;
	let checksum = (hash[0] >> checksum_shift) & mask;

	// nwords = (length * 8 + checksum_bits) / 11;
	let nwords = length
		.checked_mul(8)
		.and_then(|value| value.checked_add(checksum_bits))
		// Safe: divisor is the fixed non-zero number of bits per BIP39 word.
		.map(|value| value / 11)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"mnemonic::from_entropy, length={} checksum_bits={}",
				length, checksum_bits
			))
		})?;
	let mut indexes: Zeroizing<Vec<u16>> = Zeroizing::new(vec![0; nwords]);
	let mut loc: usize = 0;

	// u8 to u11
	for byte in entropy.iter() {
		for i in (0..8).rev() {
			let bit = byte & (1 << i) != 0;
			// indexes[loc / 11] |= (bit as u16) << (10 - (loc % 11));
			// loc += 1;
			let shift = 10usize.checked_sub(loc % 11).ok_or_else(|| {
				Error::DataOverflow(format!("mnemonic::from_entropy, loc={}", loc))
			})?;
			let word = indexes
				.get_mut(loc / 11)
				.ok_or(Error::InvalidLength(loc / 11))?;
			// Safe: shift is 0..=10 and the source bit is 0 or 1, so the result
			// remains within the 11-bit BIP39 word index range.
			*word |= u16::from(bit) << shift;
			loc = loc.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!("mnemonic::from_entropy, loc={}", loc))
			})?;
		}
	}
	for i in (0..checksum_bits).rev() {
		let bit = checksum & (1 << i) != 0;
		// indexes[loc / 11] |= (bit as u16) << (10 - (loc % 11));
		// loc += 1;
		let shift = 10usize
			.checked_sub(loc % 11)
			.ok_or_else(|| Error::DataOverflow(format!("mnemonic::from_entropy, loc={}", loc)))?;
		let word = indexes
			.get_mut(loc / 11)
			.ok_or(Error::InvalidLength(loc / 11))?;
		// Safe: shift is 0..=10 and the source bit is 0 or 1, so the result
		// remains within the 11-bit BIP39 word index range.
		*word |= u16::from(bit) << shift;
		loc = loc
			.checked_add(1)
			.ok_or_else(|| Error::DataOverflow(format!("mnemonic::from_entropy, loc={}", loc)))?;
	}

	let words: Zeroizing<Vec<String>> = Zeroizing::new(
		indexes
			.iter()
			.map(|x| {
				let idx = usize::from(*x);
				WORDS.get(idx).cloned().ok_or(Error::InvalidLength(idx))
			})
			.collect::<Result<Vec<_>, _>>()?,
	);
	let mnemonic = Zeroizing::new(words.join(" "));
	Ok(mnemonic)
}

/// Converts a nemonic and a passphrase into a seed
/// Note, passphrase is a fixed controlled value
pub fn to_seed(mnemonic: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>, Error> {
	// passphrase is a fixed controlled value. is_ascii guarantee that it will comply with UTF-8 NFKD
	// Unicode passhrase and mnemonics intentionally are not supported by MWC
	if !passphrase.is_ascii() {
		return Err(Error::IbvalidPassphraseEncoding);
	}

	let words = mnemonic_words(mnemonic);
	// make sure the mnemonic is valid and use the same canonical whitespace for PBKDF2
	to_entropy_from_words(&words)?;
	let normalized_mnemonic = Zeroizing::new(words.join(" "));

	let salt = Zeroizing::new(("mnemonic".to_owned() + passphrase).into_bytes());
	let data = normalized_mnemonic.as_bytes();
	let mut seed = Zeroizing::new([0; 64]);

	pbkdf2::<Hmac<Sha512>>(data, &salt[..], 2048, seed.as_mut_slice())
		.map_err(|_| Error::InvalidLength(seed.len()))?;

	Ok(seed)
}

#[cfg(test)]
mod tests {
	use super::{from_entropy, to_entropy, to_seed};
	use mwc_crates::rand::{rng, RngExt};
	use mwc_util::{from_hex, ToHex};

	struct Test<'a> {
		mnemonic: &'a str,
		entropy: &'a str,
		seed: &'a str,
	}

	/// Test vectors from https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#Test_vectors
	fn tests<'a>() -> Vec<Test<'a>> {
		vec![
            Test {
                entropy: "00000000000000000000000000000000",
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                seed: "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            },
            Test {
                entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
                seed: "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
            },
            Test {
                entropy: "80808080808080808080808080808080",
                mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
                seed: "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
            },
            Test {
                entropy: "ffffffffffffffffffffffffffffffff",
                mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
                seed: "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
            },
            Test {
                entropy: "000000000000000000000000000000000000000000000000",
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
                seed: "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
            },
            Test {
                entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
                seed: "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
            },
            Test {
                entropy: "808080808080808080808080808080808080808080808080",
                mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
                seed: "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
            },
            Test {
                entropy: "ffffffffffffffffffffffffffffffffffffffffffffffff",
                mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
                seed: "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
            },
            Test {
                entropy: "0000000000000000000000000000000000000000000000000000000000000000",
                mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
                seed: "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
            },
            Test {
                entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                mnemonic: "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
                seed: "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
            },
            Test {
                entropy: "8080808080808080808080808080808080808080808080808080808080808080",
                mnemonic: "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
                seed: "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
            },
            Test {
                entropy: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                mnemonic: "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
                seed: "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
            },
            Test {
                entropy: "9e885d952ad362caeb4efe34a8e91bd2",
                mnemonic: "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                seed: "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
            },
            Test {
                entropy: "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
                mnemonic: "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
                seed: "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
            },
            Test {
                entropy: "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
                mnemonic: "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
                seed: "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
            },
            Test {
                entropy: "c0ba5a8e914111210f2bd131f3d5e08d",
                mnemonic: "scheme spot photo card baby mountain device kick cradle pact join borrow",
                seed: "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
            },
            Test {
                entropy: "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
                mnemonic: "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
                seed: "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
            },
            Test {
                entropy: "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
                mnemonic: "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
                seed: "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
            },
            Test {
                entropy: "23db8160a31d3e0dca3688ed941adbf3",
                mnemonic: "cat swing flag economy stadium alone churn speed unique patch report train",
                seed: "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
            },
            Test {
                entropy: "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
                mnemonic: "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
                seed: "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
            },
            Test {
                entropy: "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
                mnemonic: "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
                seed: "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
            },
            Test {
                entropy: "f30f8c1da665478f49b001d94c5fc452",
                mnemonic: "vessel ladder alter error federal sibling chat ability sun glass valve picture",
                seed: "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
            },
            Test {
                entropy: "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
                mnemonic: "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
                seed: "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
            },
            Test {
                entropy: "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
                mnemonic: "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
                seed: "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
            }
        ]
	}
	#[test]
	fn test_bip39() {
		let tests = tests();
		for t in tests.iter() {
			assert_eq!(
				(&to_seed(t.mnemonic, "TREZOR").unwrap()[..]).to_hex(),
				t.seed.to_string()
			);
			assert_eq!(
				to_entropy(t.mnemonic).unwrap().to_vec(),
				from_hex(t.entropy).unwrap()
			);
			assert_eq!(
				from_entropy(&from_hex(t.entropy).unwrap())
					.unwrap()
					.to_string(),
				t.mnemonic
			);
		}
	}

	#[test]
	fn test_bip39_whitespace_normalized() {
		let canonical =
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
		let variant =
			"  abandon\tabandon  abandon\nabandon abandon   abandon abandon abandon abandon abandon abandon about  ";

		assert_eq!(
			to_entropy(canonical).unwrap().to_vec(),
			to_entropy(variant).unwrap().to_vec()
		);

		let canonical_seed = to_seed(canonical, "TREZOR").unwrap();
		let variant_seed = to_seed(variant, "TREZOR").unwrap();
		assert_eq!(&canonical_seed[..], &variant_seed[..]);
	}

	#[test]
	fn test_bip39_random() {
		use mwc_crates::rand::prelude::IndexedRandom;
		let sizes: [usize; 5] = [16, 20, 24, 28, 32];

		let mut rng = rng();
		let size = *sizes.choose(&mut rng).unwrap();
		let mut entropy: Vec<u8> = Vec::with_capacity(size);

		for _ in 0..size {
			let val: u8 = rng.random();
			entropy.push(val);
		}

		let from = from_entropy(&entropy).unwrap().to_string();
		assert_eq!(entropy, *to_entropy(&from).unwrap())
	}

	#[test]
	fn test_invalid() {
		// Invalid words
		assert!(to_entropy("this is not a love song this is not a love song").is_err());
		assert!(to_entropy("abandon abandon badword abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_err());
		// Invalid length
		assert!(to_entropy("abandon abandon abandon abandon abandon abandon").is_err());
		assert!(from_entropy(&vec![1, 2, 3, 4, 5]).is_err());
		assert!(from_entropy(&vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).is_err());
		// Invalid checksum
		assert!(to_entropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_err());
		assert!(to_entropy("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo").is_err());
		assert!(to_entropy("scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress abandon").is_err());
	}
}
