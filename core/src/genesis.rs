// Copyright 2018 The Grin Developers
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

//! Definition of the genesis block. Placeholder for now.

// required for genesis replacement
//! #![allow(unused_imports)]

#![cfg_attr(feature = "cargo-clippy", allow(clippy::unreadable_literal))]

use chrono::prelude::{TimeZone, Utc};

use crate::core;
use crate::global;
use crate::pow::{Difficulty, Proof, ProofOfWork};
use crate::util;
use crate::util::secp::constants::SINGLE_BULLET_PROOF_SIZE;
use crate::util::secp::pedersen::{Commitment, RangeProof};
use crate::util::secp::Signature;

use crate::core::hash::Hash;
use crate::keychain::BlindingFactor;

/// Genesis block definition for development networks. The proof of work size
/// is small enough to mine it on the fly, so it does not contain its own
/// proof of work solution. Can also be easily mutated for different tests.
pub fn genesis_dev() -> core::Block {
	core::Block::with_header(core::BlockHeader {
		height: 0,
		// previous: core::hash::Hash([0xff; 32]),
		timestamp: Utc.ymd(1997, 8, 4).and_hms(0, 0, 0),
		pow: ProofOfWork {
			nonce: global::get_genesis_nonce(),
			..Default::default()
		},
		..Default::default()
	})
}

/// Floonet genesis block
pub fn genesis_floo() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(2018, 12, 28).and_hms(20, 48, 4),
		prev_root: Hash::from_hex(
			"00000000000000000017ff4903ef366c8f62e3151ba74e41b8332a126542f538",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"73b5e0a05ea9e1e4e33b8f1c723bc5c10d17f07042c2af7644f4dbb61f4bc556",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"667a3ba22f237a875f67c9933037c8564097fa57a3e75be507916de28fc0da26",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"cfdddfe2d938d0026f8b1304442655bbdddde175ff45ddf44cb03bcb0071a72d",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(5)),
			secondary_scaling: 1856,
			nonce: 23,
			proof: Proof {
				nonces: vec![
					16994232, 22975978, 32664019, 44016212, 50238216, 57272481, 85779161,
					124272202, 125203242, 133907662, 140522149, 145870823, 147481297, 164952795,
					177186722, 183382201, 197418356, 211393794, 239282197, 239323031, 250757611,
					281414565, 305112109, 308151499, 357235186, 374041407, 389924708, 390768911,
					401322239, 401886855, 406986280, 416797005, 418935317, 429007407, 439527429,
					484809502, 486257104, 495589543, 495892390, 525019296, 529899691, 531685572,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		fee: 0,
		lock_height: 0,
		excess: Commitment::from_vec(
			util::from_hex(
				"08df2f1d996cee37715d9ac0a0f3b13aae508d1101945acb8044954aee30960be9".to_string(),
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			25, 176, 52, 246, 172, 1, 12, 220, 247, 111, 73, 101, 13, 16, 157, 130, 110, 196, 123,
			217, 246, 137, 45, 110, 106, 186, 0, 151, 255, 193, 233, 178, 103, 26, 210, 215, 200,
			89, 146, 188, 9, 161, 28, 212, 227, 143, 82, 54, 5, 223, 16, 65, 237, 132, 196, 241,
			39, 76, 133, 45, 252, 131, 88, 0,
		])
		.unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeatures::Coinbase,
		commit: Commitment::from_vec(
			util::from_hex(
				"08c12007af16d1ee55fffe92cef808c77e318dae70c3bc70cb6361f49d517f1b68".to_string(),
			)
			.unwrap(),
		),
		proof: RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				159, 156, 202, 179, 128, 169, 14, 227, 176, 79, 118, 180, 62, 164, 2, 234, 123, 30,
				77, 126, 232, 124, 42, 186, 239, 208, 21, 217, 228, 246, 148, 74, 100, 25, 247,
				251, 82, 100, 37, 16, 146, 122, 164, 5, 2, 165, 212, 192, 221, 167, 199, 8, 231,
				149, 158, 216, 194, 200, 62, 15, 53, 200, 188, 207, 0, 79, 211, 88, 194, 211, 54,
				1, 206, 53, 72, 118, 155, 184, 233, 166, 245, 224, 16, 254, 209, 235, 153, 85, 53,
				145, 33, 186, 218, 118, 144, 35, 189, 241, 63, 229, 52, 237, 231, 39, 176, 202, 93,
				247, 85, 131, 16, 193, 247, 180, 33, 138, 255, 102, 190, 213, 129, 174, 182, 167,
				3, 126, 184, 221, 99, 114, 238, 219, 157, 125, 230, 179, 160, 89, 202, 230, 16, 91,
				199, 57, 158, 225, 142, 125, 12, 211, 164, 78, 9, 4, 155, 106, 157, 41, 233, 188,
				237, 205, 184, 53, 0, 190, 24, 215, 42, 44, 184, 120, 58, 196, 198, 190, 114, 50,
				98, 240, 15, 213, 77, 163, 24, 3, 212, 125, 93, 175, 169, 249, 24, 27, 191, 113,
				89, 59, 169, 40, 87, 250, 144, 159, 118, 171, 232, 92, 217, 5, 179, 152, 249, 247,
				71, 239, 26, 180, 82, 177, 226, 132, 185, 3, 33, 162, 120, 98, 87, 109, 57, 100,
				202, 162, 57, 230, 44, 31, 63, 213, 30, 222, 241, 78, 162, 118, 120, 70, 196, 128,
				72, 223, 110, 5, 17, 151, 97, 214, 43, 57, 157, 1, 59, 87, 96, 17, 159, 174, 144,
				217, 159, 87, 36, 113, 41, 155, 186, 252, 162, 46, 22, 80, 133, 3, 113, 248, 11,
				118, 144, 155, 188, 77, 166, 40, 119, 107, 15, 233, 47, 47, 101, 77, 167, 141, 235,
				148, 34, 218, 164, 168, 71, 20, 239, 71, 24, 12, 109, 146, 232, 243, 65, 31, 72,
				186, 131, 190, 43, 227, 157, 41, 49, 126, 136, 51, 41, 50, 213, 37, 186, 223, 87,
				248, 34, 43, 132, 34, 0, 143, 75, 79, 43, 74, 183, 26, 2, 168, 53, 203, 208, 159,
				69, 107, 124, 33, 68, 113, 206, 127, 216, 158, 15, 52, 206, 1, 101, 109, 199, 13,
				131, 122, 29, 131, 133, 125, 219, 70, 69, 144, 133, 68, 233, 67, 203, 132, 160,
				143, 101, 84, 110, 15, 175, 111, 124, 24, 185, 222, 154, 238, 77, 241, 105, 8, 224,
				230, 43, 178, 49, 95, 137, 33, 227, 118, 207, 239, 56, 21, 51, 220, 22, 48, 162,
				22, 118, 229, 215, 248, 112, 198, 126, 180, 27, 161, 237, 56, 2, 220, 129, 126, 11,
				104, 8, 133, 190, 162, 204, 3, 63, 249, 173, 210, 152, 252, 143, 157, 79, 228, 232,
				230, 72, 164, 131, 183, 151, 230, 219, 186, 21, 34, 154, 219, 215, 231, 179, 47,
				217, 44, 115, 203, 157, 35, 195, 113, 235, 194, 102, 96, 205, 24, 221, 213, 147,
				120, 178, 221, 153, 146, 44, 172, 131, 77, 21, 61, 15, 5, 6, 205, 164, 203, 76,
				228, 29, 126, 136, 88, 230, 210, 62, 164, 103, 125, 55, 231, 129, 89, 61, 222, 50,
				71, 71, 75, 230, 70, 80, 85, 193, 136, 183, 222, 146, 46, 235, 0, 222, 118, 32, 70,
				85, 39, 92, 233, 211, 169, 159, 207, 145, 13, 206, 125, 3, 45, 51, 64, 167, 179,
				133, 83, 57, 190, 51, 239, 211, 74, 116, 75, 71, 248, 249, 184, 13, 31, 129, 107,
				104, 179, 76, 194, 186, 4, 13, 122, 167, 254, 126, 153, 50, 8, 1, 200, 203, 213,
				230, 217, 97, 105, 50, 208, 126, 180, 113, 81, 152, 238, 123, 157, 232, 19, 164,
				159, 164, 89, 75, 33, 70, 140, 204, 158, 236, 10, 226, 102, 14, 88, 134, 82, 131,
				36, 195, 127, 158, 81, 252, 223, 165, 11, 52, 105, 245, 245, 228, 235, 168, 175,
				52, 175, 76, 157, 120, 208, 99, 135, 210, 81, 114, 230, 181,
			],
		},
	};
	gen.with_reward(output, kernel)
}

/// MWC GENESIS - here how genesis block is defined. gen_gen suppose to update the numbers in this file.
/// Mainnet genesis block
pub fn genesis_main() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.ymd(2019, 3, 6).and_hms(18, 58, 38), // REPLACE
		prev_root: Hash::from_hex(
			"00000000000000000002045d9a7a4fb039d468fb751e094efe10e6b0199711ac",
		)
		.unwrap(), // REPLACE
		output_root: Hash::from_hex(
			"4ddd2e2e848d191fab24581420c958426fbc1a5f5c30931c63bdf3f508a42f3b",
		)
		.unwrap(), // REPLACE
		range_proof_root: Hash::from_hex(
			"126de35affdd727d1230103e05dd97ed4a1525ffef31ac0f47f58588002a505a",
		)
		.unwrap(), // REPLACE
		kernel_root: Hash::from_hex(
			"88588ffb085edf3c779dd1326c4f36e3cfd9d2ce5f4753a98c8206a63f875c56",
		)
		.unwrap(), // REPLACE
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(), // REPLACE
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			// MWC - TODO DEBUG  set difficulty to 1 because of testign
			// total_difficulty: Difficulty::from_num(10_u64.pow(5)),
			total_difficulty: Difficulty::min(),
			secondary_scaling: 1856,
			nonce: 72, // REPLACE
			proof: Proof {
				nonces: vec![
					542596, 5343448, 18932353, 27706151, 72715009, 96357555, 109544790, 157351705,
					166540480, 168748197, 168930893, 173897309, 179263885, 190575248, 193025917,
					194781673, 200881755, 210438979, 220806382, 222006787, 225238331, 226217333,
					245428832, 253617060, 258120189, 279272246, 289847363, 301185144, 301830581,
					330487205, 360428031, 378580695, 412728484, 426412724, 461745491, 464019212,
					482207495, 496350313, 499550182, 509365185, 511762027, 529232573,
				], // REPLACE
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		fee: 0,
		lock_height: 0,
		excess: Commitment::from_vec(
			util::from_hex(
				"08896647650f8c80d26a162d5a56b3569a4682adccac36ee535207ce3f7845138f".to_string(),
			)
			.unwrap(),
		), // REPLACE
		excess_sig: Signature::from_raw_data(&[
			243, 9, 174, 143, 108, 199, 220, 224, 112, 128, 199, 150, 163, 35, 13, 154, 145, 119,
			216, 162, 228, 20, 52, 223, 199, 50, 148, 154, 111, 239, 234, 225, 213, 155, 50, 12,
			252, 58, 220, 97, 140, 212, 243, 34, 152, 51, 249, 1, 17, 201, 243, 121, 5, 78, 78, 84,
			69, 143, 236, 161, 171, 229, 46, 235,
		])
		.unwrap(), // REPLACE
	};
	let output = core::Output {
		features: core::OutputFeatures::Coinbase,
		commit: Commitment::from_vec(
			util::from_hex(
				"09c284c119540dc9743358f6460b04082a1c9b7fb69bf9e5848043e16466f2a840".to_string(),
			)
			.unwrap(),
		), // REPLACE
		proof: RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				242, 196, 160, 82, 202, 174, 45, 227, 41, 149, 41, 201, 166, 128, 168, 181, 60,
				190, 121, 182, 239, 166, 237, 196, 78, 206, 90, 196, 93, 180, 237, 22, 153, 166,
				58, 242, 3, 227, 100, 79, 242, 245, 29, 177, 204, 130, 39, 56, 88, 227, 3, 185,
				249, 239, 61, 80, 218, 65, 169, 237, 23, 112, 151, 120, 11, 123, 172, 242, 26, 169,
				222, 32, 33, 54, 173, 88, 4, 54, 188, 2, 129, 191, 19, 147, 120, 56, 24, 121, 42,
				20, 9, 60, 33, 121, 126, 156, 42, 139, 71, 224, 167, 31, 212, 180, 131, 177, 85,
				12, 63, 237, 81, 13, 241, 228, 145, 224, 166, 70, 147, 212, 246, 93, 46, 56, 0,
				252, 54, 160, 136, 183, 125, 129, 126, 223, 50, 138, 40, 81, 104, 54, 111, 154, 94,
				249, 111, 187, 110, 65, 24, 31, 111, 42, 229, 240, 183, 124, 81, 145, 237, 38, 84,
				7, 156, 228, 88, 65, 96, 182, 8, 253, 120, 197, 131, 7, 157, 64, 147, 189, 250,
				204, 142, 41, 89, 9, 33, 202, 66, 74, 165, 160, 111, 92, 112, 31, 27, 23, 177, 11,
				235, 95, 91, 0, 152, 144, 214, 203, 232, 189, 128, 237, 197, 69, 44, 84, 162, 142,
				96, 121, 53, 175, 202, 36, 53, 192, 43, 215, 41, 140, 55, 156, 85, 48, 179, 70, 72,
				60, 85, 23, 246, 42, 191, 94, 26, 110, 5, 173, 38, 29, 224, 153, 182, 2, 217, 0,
				195, 62, 157, 136, 148, 221, 185, 35, 34, 161, 193, 117, 4, 229, 73, 246, 78, 241,
				85, 119, 64, 94, 94, 2, 92, 115, 137, 37, 9, 61, 175, 213, 229, 155, 5, 149, 225,
				22, 116, 8, 229, 207, 185, 112, 93, 194, 58, 26, 77, 104, 79, 34, 9, 126, 117, 110,
				118, 203, 15, 88, 192, 30, 141, 117, 231, 45, 130, 221, 140, 112, 151, 192, 105,
				184, 41, 164, 64, 87, 28, 104, 127, 163, 202, 152, 129, 45, 161, 42, 235, 166, 100,
				172, 5, 99, 233, 105, 103, 56, 228, 243, 0, 188, 82, 158, 155, 105, 35, 215, 239,
				26, 64, 89, 253, 86, 229, 115, 251, 35, 50, 211, 141, 158, 213, 33, 35, 37, 31,
				199, 193, 41, 68, 199, 86, 233, 24, 170, 29, 36, 225, 68, 98, 129, 167, 12, 224,
				185, 26, 37, 87, 235, 3, 20, 53, 165, 149, 135, 99, 177, 236, 112, 208, 65, 131,
				186, 145, 97, 5, 210, 150, 152, 240, 139, 17, 228, 121, 230, 255, 36, 49, 78, 114,
				54, 130, 157, 221, 116, 18, 244, 246, 221, 194, 2, 47, 254, 146, 101, 25, 177, 53,
				119, 31, 215, 37, 229, 118, 173, 13, 31, 207, 190, 62, 70, 128, 69, 113, 221, 71,
				184, 113, 209, 233, 71, 238, 192, 227, 226, 8, 139, 142, 31, 26, 135, 226, 25, 178,
				126, 118, 184, 243, 1, 233, 102, 145, 160, 236, 68, 4, 99, 225, 223, 27, 132, 58,
				39, 124, 154, 215, 77, 233, 145, 6, 189, 35, 162, 129, 197, 198, 93, 239, 165, 45,
				33, 45, 103, 68, 7, 182, 54, 249, 31, 221, 87, 246, 204, 230, 67, 1, 197, 72, 214,
				22, 147, 241, 79, 177, 82, 101, 155, 154, 39, 107, 91, 148, 107, 154, 224, 133,
				108, 25, 135, 249, 59, 95, 111, 237, 20, 54, 19, 73, 214, 84, 191, 254, 192, 133,
				169, 202, 186, 172, 245, 13, 137, 70, 245, 110, 174, 132, 246, 245, 141, 14, 18,
				188, 1, 194, 169, 7, 17, 2, 229, 174, 99, 171, 71, 2, 166, 180, 164, 193, 144, 34,
				210, 129, 74, 127, 37, 11, 202, 134, 186, 203, 217, 44, 219, 172, 0, 181, 12, 41,
				33, 154, 189, 102, 225, 191, 82, 20, 43, 87, 29, 187, 181, 151, 169, 109, 178, 221,
				190, 232, 240, 233, 231, 22, 111, 109, 48, 73, 55, 92, 32, 121, 194, 16, 213, 226,
				147, 19, 54, 234, 14, 36,
			], // REPLACE
		},
	};
	gen.with_reward(output, kernel)
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hashed;
	use crate::ser;

	#[test]
	fn floonet_genesis_hash() {
		let gen_hash = genesis_floo().hash();
		println!("floonet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_floo()).unwrap();
		println!("floonet genesis full hash: {}\n", gen_bin.hash().to_hex());
		assert_eq!(
			gen_hash.to_hex(),
			"edc758c1370d43e1d733f70f58cf187c3be8242830429b1676b89fd91ccf2dab"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"91c638fc019a54e6652bd6bb3d9c5e0c17e889cef34a5c28528e7eb61a884dc4"
		);
	}

	#[test]
	fn mainnet_genesis_hash() {
		let gen_hash = genesis_main().hash();
		println!("mainnet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_main()).unwrap();
		println!("mainnet genesis full hash: {}\n", gen_bin.hash().to_hex());
		assert_eq!(
			gen_hash.to_hex(),
			"f1a30e67578aecd96dcb192ba39794dc193c3f82d8dcbf2efa71743603102e40"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"01a3426d13a68474332c9f66cb065abc4ff8673d883f76ffc19cb1c06f369a98"
		);
	}
}
