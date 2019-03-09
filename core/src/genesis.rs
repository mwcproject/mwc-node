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
		timestamp: Utc.ymd(2019, 4, 3).and_hms(17, 17, 17),
		prev_root: Hash::from_hex(
			"00000000000000000015efd5221becd2eafdf54ae5917cbebfd8bd637fd092cd",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"4ddd2e2e848d191fab24581420c958426fbc1a5f5c30931c63bdf3f508a42f3b",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"126de35affdd727d1230103e05dd97ed4a1525ffef31ac0f47f58588002a505a",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"ec9c78a8a0ec6a3419ac12ff310f571989981249dff37d6f0a02ca018ca1c238",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(1),
			secondary_scaling: 1856,
			nonce: 10021,
			proof: Proof {
				nonces: vec![
					8734864, 13574868, 26540007, 27169350, 33736430, 37924344, 60987328, 63368557,
					79104443, 103322499, 171262139, 180269163, 189551451, 196343856, 199899606,
					230021695, 239792265, 278488832, 283152686, 287630608, 287836978, 323923763,
					333826453, 343449328, 350767271, 352878937, 397098058, 403221015, 405129864,
					411546610, 416497675, 421450490, 447445391, 459359377, 466272947, 482533916,
					482715670, 501771652, 512347234, 525881993, 529416617, 533589542,
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
				"08896647650f8c80d26a162d5a56b3569a4682adccac36ee535207ce3f7845138f".to_string(),
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			223, 213, 230, 51, 53, 234, 24, 47, 190, 50, 229, 181, 23, 42, 126, 199, 185, 210, 227,
			145, 89, 120, 22, 180, 14, 201, 52, 44, 187, 94, 198, 180, 75, 156, 21, 40, 64, 159,
			23, 118, 53, 157, 156, 120, 213, 152, 205, 205, 153, 167, 203, 122, 37, 181, 217, 132,
			46, 95, 118, 18, 119, 96, 155, 60,
		])
		.unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeatures::Coinbase,
		commit: Commitment::from_vec(
			util::from_hex(
				"09c284c119540dc9743358f6460b04082a1c9b7fb69bf9e5848043e16466f2a840".to_string(),
			)
			.unwrap(),
		),
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
		timestamp: Utc.ymd(2019, 3, 7).and_hms(22, 34, 35),
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
			nonce: 10021,
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
			"478a9158db2bb2c2c75a014791f070bbdc897ffc186a929b398f03cdb33978b8"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"1624e6d03e76763065615adedf69041624f07cafc675fff00a9e2b0de58f2e74"
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
