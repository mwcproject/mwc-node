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
		timestamp: Utc.ymd(2019, 5, 26).and_hms(16, 30, 1),
		prev_root: Hash::from_hex(
			"000000000000000000257647fb29ce964ddf2b27c639ae60c4c90fafe5c42e53",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"6985966efcd741c9ee42fe1a016476b74ffa1e818dfd4d3b441f8e0f876aa228",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"43c1ac0025e17fb677b332c60e0d8b46ce871df876498c0dd5c95e4294ae8fe5",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"9bd2d376440e2b68ee1b066befed594b0a3d9fb56d20ae043059f5db4d25d6e0",
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
			nonce: 73,
			proof: Proof {
				nonces: vec![
					3192500, 6825707, 24230992, 31245203, 53163694, 90654995, 106472612, 110444199,
					139989294, 156335087, 156355985, 183386417, 189157284, 207907104, 213905482,
					215326841, 220116398, 256066326, 259812081, 260939712, 272131888, 273570144,
					282535412, 304151827, 322481271, 326494676, 355927801, 361940398, 369475836,
					386602103, 399551873, 409685415, 416682585, 419304710, 435496048, 447341740,
					462273908, 468790263, 491944474, 494233402, 511976431, 533915547,
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
				"093d0aeae5f6aab0975096fde31e1a21fa42edfc93db318a1064156ace81f54671".to_string(),
			)
			.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			206, 29, 151, 239, 47, 44, 219, 103, 100, 240, 76, 52, 231, 174, 149, 129, 237, 164,
			234, 60, 232, 149, 90, 94, 161, 93, 131, 148, 120, 81, 161, 155, 170, 177, 250, 64, 66,
			25, 44, 82, 164, 227, 150, 5, 10, 166, 52, 150, 22, 179, 15, 50, 81, 15, 114, 9, 52,
			239, 234, 80, 82, 118, 146, 30,
		])
		.unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeatures::Coinbase,
		commit: Commitment::from_vec(
			util::from_hex(
				"0905a2ebf3913c7d378660a7b60e6bda983be451cb1de8779ad0f51f4d2fb079ea".to_string(),
			)
			.unwrap(),
		),
		proof: RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				207, 70, 243, 199, 101, 231, 4, 202, 173, 57, 169, 221, 164, 31, 29, 146, 28, 166,
				120, 47, 100, 105, 26, 247, 52, 181, 108, 150, 190, 24, 24, 249, 109, 102, 193, 18,
				124, 70, 211, 53, 6, 162, 247, 149, 165, 48, 219, 85, 40, 215, 222, 180, 14, 166,
				132, 139, 80, 135, 117, 103, 67, 227, 81, 86, 12, 198, 70, 55, 156, 172, 68, 136,
				180, 219, 235, 223, 85, 248, 74, 215, 102, 1, 190, 116, 133, 89, 234, 184, 154,
				155, 29, 102, 91, 176, 223, 6, 149, 167, 201, 214, 142, 183, 154, 76, 16, 59, 178,
				57, 82, 145, 215, 49, 184, 176, 150, 58, 103, 215, 61, 243, 14, 2, 187, 10, 157,
				229, 73, 68, 204, 207, 7, 125, 1, 240, 11, 178, 19, 185, 201, 93, 212, 90, 18, 30,
				192, 119, 154, 91, 50, 61, 237, 196, 105, 195, 142, 116, 242, 237, 35, 142, 201,
				60, 24, 161, 224, 12, 234, 91, 4, 52, 241, 69, 88, 118, 239, 144, 100, 227, 56,
				226, 122, 68, 3, 120, 152, 2, 198, 50, 1, 135, 26, 211, 233, 149, 2, 193, 33, 233,
				102, 194, 148, 236, 135, 179, 75, 216, 75, 234, 91, 236, 235, 234, 65, 74, 109,
				138, 26, 116, 204, 35, 229, 208, 31, 133, 11, 130, 8, 210, 202, 20, 179, 243, 80,
				90, 0, 48, 101, 57, 154, 235, 97, 132, 198, 171, 158, 77, 92, 196, 214, 236, 14,
				95, 136, 239, 19, 233, 215, 232, 120, 227, 101, 81, 169, 49, 214, 242, 9, 75, 206,
				243, 97, 193, 37, 37, 120, 226, 112, 105, 58, 93, 240, 198, 112, 85, 223, 71, 88,
				192, 163, 227, 252, 251, 228, 116, 185, 146, 129, 35, 112, 113, 123, 95, 108, 100,
				197, 56, 195, 13, 40, 87, 13, 132, 230, 167, 28, 80, 128, 196, 157, 227, 234, 109,
				189, 201, 32, 161, 209, 40, 62, 64, 72, 10, 45, 170, 191, 192, 225, 32, 105, 103,
				130, 219, 82, 143, 246, 31, 220, 16, 7, 78, 250, 246, 144, 130, 3, 183, 15, 62, 23,
				195, 164, 211, 99, 55, 192, 90, 248, 22, 7, 79, 241, 19, 51, 180, 149, 161, 151,
				146, 91, 163, 91, 141, 1, 79, 170, 168, 114, 73, 11, 188, 40, 99, 117, 77, 6, 164,
				217, 116, 194, 219, 46, 14, 141, 223, 111, 191, 212, 108, 28, 23, 150, 190, 24, 6,
				221, 114, 156, 194, 127, 226, 247, 63, 102, 165, 54, 200, 210, 202, 39, 204, 210,
				140, 240, 121, 148, 131, 199, 241, 96, 141, 110, 76, 123, 210, 187, 245, 113, 198,
				48, 90, 47, 130, 124, 38, 235, 247, 127, 114, 128, 183, 100, 157, 252, 224, 120,
				229, 166, 191, 11, 55, 184, 235, 242, 20, 170, 223, 14, 206, 170, 82, 9, 28, 50,
				167, 49, 81, 26, 212, 85, 222, 86, 86, 0, 20, 190, 248, 164, 215, 23, 146, 158, 56,
				227, 205, 205, 81, 89, 53, 46, 97, 97, 240, 31, 48, 167, 140, 82, 65, 200, 205,
				132, 41, 19, 81, 37, 211, 175, 89, 153, 102, 46, 225, 18, 190, 155, 12, 96, 183,
				237, 218, 146, 166, 96, 14, 222, 22, 148, 255, 137, 118, 145, 10, 231, 27, 209, 35,
				204, 28, 146, 142, 161, 207, 109, 157, 122, 158, 115, 139, 124, 123, 9, 89, 43, 75,
				90, 17, 68, 156, 56, 175, 14, 212, 8, 223, 233, 81, 105, 26, 231, 62, 168, 62, 242,
				160, 150, 188, 14, 40, 107, 7, 2, 229, 238, 118, 196, 239, 47, 56, 26, 149, 22, 0,
				61, 241, 163, 134, 162, 115, 117, 18, 185, 149, 231, 96, 37, 83, 121, 9, 231, 34,
				145, 222, 218, 199, 158, 10, 66, 196, 229, 134, 103, 14, 5, 225, 115, 154, 183, 22,
				28, 128, 28, 20, 74, 248, 20, 17, 184, 13, 150, 114, 46, 61, 253, 143, 184, 111,
				66, 36, 107, 210, 50, 38, 167, 100, 224,
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
			"a10f32177e0b8de4495637c5735577512963cb3dca42ee893fc9c5fade29dfa7"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"1ed0cd8d166353ce22f14a47fd383e78888315b58a670aac95f77a3d49ce973c"
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
