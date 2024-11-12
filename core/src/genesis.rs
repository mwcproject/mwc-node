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

//! Definition of the genesis block. Placeholder for now.

// required for genesis replacement
//! #![allow(unused_imports)]

use crate::core;
use crate::core::hash::Hash;
use crate::pow::{Difficulty, Proof, ProofOfWork};
use chrono::prelude::{TimeZone, Utc};
use keychain::BlindingFactor;
use util::secp::constants::SINGLE_BULLET_PROOF_SIZE;
use util::secp::pedersen::{Commitment, RangeProof};
use util::secp::Signature;

/// Genesis block definition for development networks. The proof of work size
/// is small enough to mine it on the fly, so it does not contain its own
/// proof of work solution. Can also be easily mutated for different tests.
pub fn genesis_dev() -> core::Block {
	core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.with_ymd_and_hms(1997, 8, 4, 0, 0, 0).unwrap(),
		pow: ProofOfWork {
			nonce: 0,
			..Default::default()
		},
		..Default::default()
	})
}

/// Floonet genesis block
pub fn genesis_floo() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.with_ymd_and_hms(2019, 5, 26, 16, 30, 1).unwrap(),
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
		excess: Commitment::from_vec(
			util::from_hex("093d0aeae5f6aab0975096fde31e1a21fa42edfc93db318a1064156ace81f54671")
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
	let output = core::Output::new(
		core::OutputFeatures::Coinbase,
		Commitment::from_vec(
			util::from_hex("0905a2ebf3913c7d378660a7b60e6bda983be451cb1de8779ad0f51f4d2fb079ea")
				.unwrap(),
		),
		RangeProof {
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
	);
	gen.with_reward(output, kernel)
}

/// MWC GENESIS - here how genesis block is defined. gen_gen suppose to update the numbers in this file.
/// Mainnet genesis block
pub fn genesis_main() -> core::Block {
	let gen = core::Block::with_header(core::BlockHeader {
		height: 0,
		timestamp: Utc.with_ymd_and_hms(2019, 11, 11, 9, 0, 0).unwrap(),
		prev_root: Hash::from_hex(
			"00000000000000000004f2fb2ee749923a8131028aeae637070b0b4145617d42",
		)
		.unwrap(),
		output_root: Hash::from_hex(
			"2d672c228f883646d75e73f1b936991fdfb11bb177eca451587f97dea1a4f994",
		)
		.unwrap(),
		range_proof_root: Hash::from_hex(
			"3460123e2e24c9df65cd7a8d0e1384724c23c88c71b0cb32d890854648c7637a",
		)
		.unwrap(),
		kernel_root: Hash::from_hex(
			"cd3e07cff2c0f8e434c30a47d6231270d12d42638c0a7fd2c5c3125d51920d00",
		)
		.unwrap(),
		total_kernel_offset: BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000000",
		)
		.unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			total_difficulty: Difficulty::from_num(10_u64.pow(6)),
			secondary_scaling: 1856,
			nonce: 57,
			proof: Proof {
				nonces: vec![
					7791384, 18725569, 25781440, 34244982, 37735006, 50818018, 71198333, 101194282,
					128077740, 130711994, 140235954, 169405337, 169483469, 205312464, 231543491,
					268105396, 269131498, 289412425, 313057984, 318152989, 347763503, 353494235,
					377703230, 393399875, 409267066, 410265896, 419833577, 424585144, 447415663,
					449338161, 455123370, 474062893, 488026600, 491955742, 492120147, 492287857,
					497798535, 515160542, 520873408, 521363243, 532149389, 533910346,
				],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		excess: Commitment::from_vec(
			util::from_hex("08b659fde3a41284819f45415890330272efef7ef991f833a64b746be802c8fd77")
				.unwrap(),
		),
		excess_sig: Signature::from_raw_data(&[
			189, 52, 60, 137, 172, 160, 134, 69, 17, 47, 82, 86, 169, 136, 4, 240, 104, 188, 8,
			185, 90, 170, 220, 90, 88, 177, 222, 171, 198, 244, 149, 15, 238, 91, 152, 234, 248,
			34, 72, 175, 213, 52, 179, 29, 165, 113, 70, 167, 30, 159, 163, 45, 67, 2, 136, 169,
			248, 200, 90, 86, 70, 192, 73, 37,
		])
		.unwrap(),
	};
	let output = core::Output::new(
		core::OutputFeatures::Coinbase,
		Commitment::from_vec(
			util::from_hex("089dfcac475c94c978861b3dbef1e37b038cc13f9f78de9a4e14f31ed36e7a54c9")
				.unwrap(),
		),
		RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
			proof: [
				39, 189, 154, 255, 86, 63, 70, 66, 231, 125, 153, 190, 221, 206, 198, 108, 50, 76,
				142, 7, 222, 248, 222, 98, 247, 246, 149, 104, 243, 48, 146, 0, 147, 81, 67, 106,
				68, 180, 226, 211, 134, 15, 93, 143, 157, 116, 76, 118, 212, 31, 167, 217, 46, 214,
				56, 80, 103, 7, 43, 214, 73, 180, 151, 218, 6, 69, 81, 3, 19, 203, 210, 32, 78,
				222, 121, 83, 93, 35, 108, 15, 122, 145, 131, 184, 88, 43, 112, 255, 160, 13, 150,
				236, 194, 253, 127, 118, 33, 146, 103, 98, 203, 247, 128, 70, 142, 77, 170, 189,
				161, 57, 186, 190, 33, 37, 15, 245, 112, 135, 85, 144, 109, 237, 188, 255, 99, 70,
				83, 150, 39, 115, 13, 134, 179, 64, 162, 128, 41, 176, 123, 195, 174, 20, 101, 174,
				251, 168, 176, 157, 142, 25, 189, 196, 235, 230, 162, 39, 151, 5, 204, 114, 203,
				170, 214, 205, 106, 96, 250, 44, 238, 39, 44, 141, 117, 102, 205, 61, 181, 105, 54,
				38, 147, 225, 127, 113, 37, 56, 42, 244, 143, 216, 121, 59, 129, 111, 11, 252, 203,
				138, 55, 151, 104, 29, 19, 208, 251, 115, 52, 82, 192, 240, 79, 183, 245, 231, 156,
				209, 118, 13, 75, 29, 185, 149, 186, 168, 180, 204, 14, 59, 185, 129, 60, 62, 198,
				3, 27, 2, 87, 115, 39, 86, 220, 151, 158, 191, 202, 43, 173, 89, 237, 244, 161, 99,
				138, 195, 11, 68, 80, 108, 84, 35, 236, 71, 70, 100, 61, 86, 108, 22, 162, 149,
				167, 5, 210, 136, 11, 165, 58, 52, 48, 216, 228, 97, 246, 100, 24, 68, 61, 164,
				234, 52, 11, 103, 35, 242, 233, 251, 214, 181, 61, 103, 148, 128, 167, 251, 114,
				38, 196, 90, 155, 181, 41, 169, 203, 29, 166, 13, 123, 83, 150, 76, 55, 113, 162,
				166, 147, 14, 80, 75, 13, 109, 178, 226, 6, 3, 126, 86, 114, 86, 39, 151, 65, 24,
				57, 181, 216, 174, 61, 156, 102, 210, 11, 74, 86, 71, 3, 219, 203, 239, 218, 5, 65,
				127, 210, 53, 8, 188, 112, 185, 19, 173, 206, 3, 186, 86, 233, 42, 35, 99, 73, 198,
				154, 41, 236, 242, 14, 115, 28, 100, 182, 45, 58, 128, 70, 212, 100, 157, 238, 65,
				232, 192, 13, 47, 29, 51, 176, 137, 15, 167, 47, 97, 222, 78, 240, 94, 88, 132,
				108, 99, 127, 160, 246, 17, 186, 76, 116, 205, 173, 1, 74, 41, 224, 65, 82, 222,
				247, 148, 74, 82, 169, 5, 6, 41, 169, 204, 52, 82, 204, 153, 99, 161, 195, 32, 159,
				80, 169, 12, 99, 104, 68, 93, 230, 47, 95, 67, 9, 153, 99, 183, 2, 12, 105, 218,
				73, 162, 206, 84, 149, 96, 192, 249, 235, 182, 20, 137, 3, 46, 8, 95, 109, 18, 159,
				154, 114, 9, 7, 192, 180, 236, 122, 80, 82, 142, 145, 226, 247, 209, 170, 132, 142,
				65, 166, 68, 239, 175, 87, 61, 152, 127, 18, 21, 70, 129, 174, 146, 19, 28, 213,
				115, 10, 66, 62, 56, 20, 172, 153, 151, 27, 78, 95, 169, 170, 69, 54, 247, 201,
				179, 234, 157, 168, 222, 193, 210, 50, 91, 79, 242, 96, 69, 163, 60, 246, 183, 90,
				66, 196, 68, 226, 223, 100, 183, 8, 165, 0, 50, 106, 232, 197, 202, 142, 129, 193,
				193, 65, 236, 190, 3, 228, 137, 31, 14, 133, 241, 254, 192, 197, 101, 108, 46, 209,
				168, 59, 9, 160, 171, 3, 8, 212, 66, 123, 218, 6, 231, 232, 215, 207, 62, 53, 130,
				34, 237, 80, 13, 10, 93, 214, 164, 158, 47, 39, 101, 52, 228, 0, 38, 205, 82, 23,
				39, 41, 42, 221, 0, 100, 137, 26, 47, 73, 214, 106, 68, 255, 170, 250, 236, 2, 102,
				132, 89, 141, 42, 34, 2, 29, 187, 5, 189, 153, 17, 234, 32, 144, 149, 211, 164,
				188,
			],
		},
	);
	gen.with_reward(output, kernel)
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::hash::Hashed;
	use crate::global;
	use crate::ser::{self, ProtocolVersion};
	use util::ToHex;

	#[test]
	fn floonet_genesis_hash() {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		let gen_hash = genesis_floo().hash();
		println!("floonet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_floo(), ProtocolVersion(1)).unwrap();
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
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		let gen_hash = genesis_main().hash();
		println!("mainnet genesis hash: {}", gen_hash.to_hex());
		let gen_bin = ser::ser_vec(&genesis_main(), ProtocolVersion(1)).unwrap();
		println!("mainnet genesis full hash: {}\n", gen_bin.hash().to_hex());
		assert_eq!(
			gen_hash.to_hex(),
			"e29e3a72496d85c5ada8186323016f4c7951880f77f3c8867d3b8cd3bf306c3d"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"4fb646ea25485a6dffd3e01e6655e2637d3d7c5758be168f869ac13115d1730e"
		);
	}
}
