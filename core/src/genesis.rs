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
		timestamp: Utc.ymd(2019, 3, 3).and_hms(16, 30, 1),
		prev_root: Hash::from_hex(
			"00000000000000000015068c9b41537472a73879daad1ee503fc53539e24db4d",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"55c702a0b9d7b514dbf11a2c3ebba1eb516b324dbe4ae7dffa9cc1ccd91a5a32",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"3118350de972ec76372a4da822f8e0b12f29a5c30db93bf847083822bf504246",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"5788adbf89a9668d790f9f168064283b0b457c46b132fcebc1a8ce16234f6182",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10000),
			secondary_scaling: 1856,
			nonce: 25,
			proof: Proof {
				nonces: vec![
					14838406, 15493587, 25882227, 53616276, 69656051, 118247983, 132212005,
					137311630, 138273694, 145819201, 154092703, 166744240, 181460017, 182127358,
					196360419, 215215944, 227038887, 233065794, 246362837, 254877152, 262394328,
					269146177, 281036295, 283346553, 288326868, 292608879, 297639321, 306088943,
					310872575, 353815757, 359328673, 371441535, 398565922, 398771209, 458315865,
					458427441, 485691022, 487492072, 506859758, 519922734, 521219970, 534488083,
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
				"09c94cf2b8dc2e5b35eb6da13787e87c1fa2e64a4da4151ac4b2f1400ce8a3c9de".to_string(),
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			141, 6, 33, 57, 155, 171, 195, 149, 150, 134, 122, 216, 242, 134, 2, 46, 51, 188, 141,
			165, 69, 127, 100, 198, 81, 242, 167, 197, 233, 51, 51, 117, 11, 174, 147, 136, 162,
			188, 33, 120, 93, 40, 24, 185, 116, 24, 189, 241, 3, 240, 84, 143, 151, 225, 186, 202,
			155, 51, 116, 116, 75, 82, 3, 97,
		])
		.unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeatures::Coinbase,
		commit: Commitment::from_vec(
			util::from_hex(
				"09fe7916e33636410f3f80dea48c12e999299300c3a772892071623b9ca67dabc1".to_string(),
			)
			.unwrap(),
		),
		proof: RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				203, 148, 28, 77, 109, 180, 219, 58, 182, 90, 198, 25, 142, 233, 251, 54, 198, 119,
				18, 255, 58, 23, 52, 155, 62, 131, 24, 45, 86, 29, 118, 132, 9, 156, 187, 122, 111,
				224, 131, 113, 109, 93, 4, 32, 143, 1, 252, 73, 16, 233, 67, 80, 236, 6, 147, 104,
				95, 187, 143, 85, 112, 96, 75, 161, 8, 29, 42, 166, 209, 59, 188, 124, 209, 156,
				90, 129, 199, 90, 162, 75, 235, 185, 250, 99, 246, 151, 87, 59, 148, 178, 100, 61,
				8, 199, 99, 139, 25, 40, 43, 77, 126, 122, 84, 186, 99, 244, 29, 158, 96, 2, 73,
				52, 138, 7, 11, 164, 57, 177, 207, 137, 188, 11, 44, 251, 72, 11, 89, 27, 65, 248,
				199, 77, 22, 118, 155, 158, 69, 238, 174, 111, 112, 216, 8, 150, 207, 239, 111,
				176, 161, 139, 146, 68, 135, 181, 171, 106, 47, 31, 183, 122, 243, 89, 190, 192,
				78, 175, 79, 125, 222, 240, 35, 112, 142, 182, 236, 218, 79, 176, 245, 186, 92,
				229, 248, 125, 3, 116, 171, 222, 52, 177, 195, 85, 56, 108, 200, 35, 50, 248, 130,
				226, 7, 218, 102, 197, 4, 188, 54, 64, 42, 103, 46, 56, 137, 128, 125, 36, 190, 24,
				158, 181, 255, 208, 149, 108, 193, 149, 160, 84, 11, 3, 112, 170, 54, 151, 69, 16,
				71, 57, 217, 8, 134, 118, 70, 169, 36, 155, 241, 31, 133, 44, 253, 125, 112, 102,
				35, 118, 77, 188, 148, 90, 231, 18, 123, 156, 127, 2, 94, 199, 0, 4, 155, 9, 6,
				108, 249, 31, 194, 151, 213, 99, 140, 113, 49, 168, 238, 233, 136, 247, 50, 210,
				210, 158, 122, 231, 238, 68, 34, 168, 158, 91, 173, 181, 225, 59, 10, 70, 181, 227,
				90, 93, 15, 76, 186, 121, 212, 185, 37, 1, 165, 154, 21, 59, 197, 140, 78, 129,
				255, 107, 63, 219, 204, 163, 7, 202, 241, 233, 47, 75, 249, 232, 10, 93, 209, 141,
				212, 7, 201, 112, 67, 13, 219, 2, 13, 53, 1, 105, 77, 156, 91, 77, 239, 33, 90, 78,
				204, 73, 199, 8, 208, 193, 196, 210, 142, 54, 117, 143, 180, 228, 98, 61, 104, 52,
				86, 245, 36, 220, 108, 173, 101, 150, 151, 12, 11, 248, 22, 92, 164, 204, 50, 93,
				46, 203, 216, 222, 178, 164, 11, 35, 52, 0, 27, 88, 164, 97, 90, 209, 122, 229,
				105, 58, 179, 109, 159, 140, 30, 186, 244, 253, 44, 117, 205, 164, 49, 6, 161, 108,
				116, 215, 39, 151, 134, 2, 133, 217, 85, 13, 207, 217, 76, 74, 62, 66, 66, 75, 51,
				170, 232, 78, 227, 207, 171, 46, 241, 255, 178, 52, 60, 142, 194, 205, 249, 59, 44,
				178, 243, 6, 159, 164, 101, 11, 148, 42, 166, 107, 169, 92, 164, 144, 253, 19, 5,
				59, 2, 203, 223, 188, 57, 199, 93, 42, 133, 207, 53, 196, 0, 143, 202, 62, 19, 144,
				119, 108, 8, 117, 17, 51, 101, 101, 193, 37, 143, 216, 129, 73, 122, 206, 227, 88,
				146, 50, 40, 0, 230, 128, 209, 199, 174, 43, 249, 20, 81, 208, 0, 222, 166, 124, 5,
				108, 252, 217, 219, 37, 176, 197, 163, 25, 122, 60, 24, 224, 9, 207, 37, 210, 236,
				137, 147, 107, 133, 82, 238, 224, 3, 31, 167, 2, 96, 193, 236, 157, 162, 230, 191,
				50, 131, 36, 83, 212, 210, 137, 10, 50, 221, 39, 73, 222, 95, 142, 30, 18, 131,
				165, 179, 193, 116, 103, 61, 241, 47, 219, 230, 99, 183, 54, 178, 3, 4, 14, 153,
				157, 98, 204, 81, 57, 72, 61, 118, 40, 24, 225, 173, 27, 149, 197, 89, 230, 49,
				223, 197, 32, 57, 147, 119, 130, 125, 127, 61, 243, 16, 248, 135, 14, 87, 208, 47,
				162, 106, 11, 106, 6, 26, 142, 242, 76, 119, 113, 8, 13, 223, 158, 11, 183, 193,
				152, 68,
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
		timestamp: Utc.ymd(2019, 3, 23).and_hms(20, 16, 18),
		prev_root: Hash::from_hex(
			"000000000000000000046f0790420d78821f47d8ba4f3320f06c018471dd75e5",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"fda58fbf64a65e377316c492385118851ef577de3297c2b204af536070f80c91",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"6d4fcb60703dd54ae5b042570b26adaab41608ba41e29f5458140efd19efb4c8",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"edecd2f2162c7a592af606ae734ba2bc7f76a5aee5d8e8f1cafe74c555918a3a",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			// MWC - TODO DEBUG  set difficulty to 1 because of testign
			// total_difficulty: Difficulty::from_num(10_u64.pow(5)),
			total_difficulty: Difficulty::min(),
			secondary_scaling: 1856,
			nonce: 10085,
			proof: Proof {
				nonces: vec![
					31371893, 82590058, 90320793, 102064521, 124771854, 126986448, 128192585,
					128932017, 131895717, 154807524, 159851733, 163547409, 165576756, 199161326,
					204441283, 218872897, 221163011, 222027696, 226010638, 268745036, 270362239,
					275899758, 285667177, 309633413, 309891402, 313217558, 332496283, 339609078,
					366698076, 396692180, 401490064, 410800051, 411208696, 425723601, 431845670,
					434108869, 440403997, 459109823, 476280985, 484820584, 489304888, 493795531,
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
				"091abed0e4a9c1b890d9e59101ac0483e172e3624884bde3c159f3f25224373771".to_string(),
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			178, 157, 199, 236, 194, 58, 177, 5, 90, 226, 185, 7, 50, 197, 59, 79, 41, 176, 64,
			102, 174, 130, 245, 170, 183, 252, 245, 202, 39, 19, 40, 83, 47, 32, 163, 234, 183, 39,
			44, 252, 33, 185, 127, 251, 43, 163, 77, 23, 227, 244, 240, 6, 90, 18, 43, 135, 209,
			131, 139, 235, 176, 163, 100, 197,
		])
		.unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeatures::Coinbase,
		commit: Commitment::from_vec(
			util::from_hex(
				"091e73d194a5a3d93e68c962537389600dc439a065ef14c5c074587ca693063ba5".to_string(),
			)
			.unwrap(),
		),
		proof: RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				90, 18, 59, 154, 82, 206, 161, 99, 153, 121, 24, 145, 24, 173, 210, 155, 235, 244,
				30, 8, 170, 157, 94, 149, 57, 205, 81, 56, 242, 80, 59, 78, 139, 0, 21, 111, 91,
				122, 79, 43, 70, 206, 61, 26, 110, 62, 120, 44, 157, 28, 38, 219, 199, 230, 152,
				254, 234, 29, 196, 246, 60, 67, 234, 235, 10, 206, 67, 194, 218, 111, 161, 161, 75,
				48, 206, 205, 106, 87, 188, 213, 168, 210, 205, 156, 252, 240, 20, 119, 211, 53,
				205, 104, 75, 60, 197, 70, 148, 100, 163, 14, 131, 244, 233, 102, 146, 145, 1, 65,
				191, 16, 86, 64, 26, 204, 21, 109, 194, 181, 175, 61, 113, 167, 72, 215, 232, 23,
				213, 190, 159, 27, 199, 79, 30, 138, 236, 151, 201, 125, 44, 56, 0, 181, 141, 220,
				52, 212, 6, 138, 229, 189, 227, 239, 195, 157, 81, 180, 192, 112, 81, 170, 145, 36,
				86, 123, 15, 249, 214, 147, 111, 225, 218, 87, 95, 118, 193, 87, 100, 181, 185,
				120, 246, 145, 93, 41, 217, 46, 88, 180, 206, 246, 176, 118, 185, 46, 187, 235,
				124, 77, 220, 135, 0, 67, 97, 86, 9, 62, 90, 243, 110, 78, 146, 33, 122, 125, 204,
				186, 51, 106, 90, 1, 144, 252, 139, 109, 224, 148, 98, 230, 219, 116, 170, 135,
				241, 62, 69, 89, 225, 185, 223, 226, 14, 214, 195, 158, 213, 58, 251, 73, 159, 124,
				233, 66, 139, 117, 198, 44, 123, 197, 190, 225, 238, 235, 241, 36, 193, 191, 218,
				3, 252, 103, 52, 122, 87, 71, 34, 105, 199, 237, 188, 176, 16, 56, 49, 14, 158,
				140, 103, 12, 222, 49, 30, 133, 161, 212, 48, 231, 48, 238, 27, 94, 34, 1, 200, 45,
				244, 180, 186, 93, 197, 42, 37, 186, 50, 40, 108, 146, 160, 196, 124, 90, 146, 185,
				212, 101, 67, 209, 18, 64, 213, 204, 101, 175, 23, 148, 27, 53, 169, 82, 52, 79,
				45, 85, 83, 23, 250, 250, 179, 115, 39, 153, 250, 216, 55, 118, 3, 1, 1, 225, 225,
				155, 163, 188, 235, 25, 109, 119, 171, 129, 217, 27, 216, 36, 217, 43, 222, 140,
				111, 120, 104, 13, 89, 17, 176, 245, 126, 239, 240, 109, 33, 193, 62, 13, 147, 35,
				54, 100, 202, 116, 127, 25, 0, 86, 145, 207, 138, 120, 202, 20, 214, 100, 59, 241,
				68, 62, 79, 52, 195, 232, 205, 43, 190, 251, 121, 175, 60, 136, 91, 172, 41, 184,
				84, 42, 175, 185, 184, 198, 89, 42, 116, 48, 83, 173, 252, 22, 141, 114, 16, 252,
				248, 154, 121, 231, 63, 217, 63, 242, 151, 38, 253, 19, 161, 76, 253, 60, 62, 69,
				14, 140, 149, 179, 148, 145, 171, 134, 47, 33, 244, 16, 168, 162, 186, 65, 224,
				135, 39, 18, 177, 38, 90, 10, 135, 137, 132, 100, 238, 127, 9, 239, 26, 100, 108,
				170, 151, 157, 59, 10, 93, 90, 32, 101, 73, 160, 36, 182, 112, 245, 213, 176, 200,
				237, 18, 173, 112, 183, 103, 45, 107, 184, 244, 42, 25, 188, 220, 53, 60, 163, 76,
				242, 199, 71, 6, 0, 183, 229, 206, 207, 183, 144, 119, 228, 110, 16, 219, 70, 84,
				10, 241, 83, 235, 84, 224, 17, 35, 191, 85, 118, 103, 88, 197, 81, 132, 80, 63,
				125, 218, 130, 53, 21, 220, 224, 100, 22, 9, 41, 5, 236, 80, 227, 87, 90, 249, 101,
				221, 36, 211, 219, 230, 69, 149, 27, 147, 203, 51, 94, 104, 106, 211, 216, 86, 55,
				189, 228, 40, 224, 133, 69, 224, 22, 93, 254, 35, 60, 238, 168, 45, 36, 225, 188,
				146, 27, 54, 30, 23, 200, 155, 253, 13, 111, 107, 21, 197, 108, 216, 174, 47, 62,
				218, 134, 14, 201, 96, 238, 60, 195, 51, 60, 2, 78, 159, 202, 120, 101, 18, 26,
				227, 34, 96, 65, 117, 142, 126, 167, 156, 232, 252,
			],
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
			"7f741fabbb640ea6dcb00fcf7d0273922badf5e628a081f7462c0cae770b3b72"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"ac7aa73f0cc6ef69bb0c8f4dad09f9057f8494e402f31cf91b60e9a3fee3f57a"
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
			"a0e4d3bca8724c8f2dc1e8723249c70b5c54b8e2b3ef67f18b25db0aef94cf4e"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"b11ad5ac7dda5d8cf7304d6159f6fa0b2a68269fa4105f1977ba53541eee207b"
		);
	}
}
