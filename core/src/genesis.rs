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
timestamp: Utc.ymd(2019, 3, 10).and_hms(0, 24, 7),  // REPLACE
prev_root: Hash::from_hex("0000000000000000000f20be0a84c423fed310540abad4dead333397ceac9401").unwrap(), // REPLACE
output_root: Hash::from_hex("a414a3392e5cb3a52a63738cbcbe394cb06ace88ea2eab4fc0bca4cab0e16336").unwrap(), // REPLACE
range_proof_root: Hash::from_hex("59bddd635bdb0449a22c1c098a7c9024897302be819bd2d0f0e02fd00ad923cc").unwrap(), // REPLACE
kernel_root: Hash::from_hex("37b14b027aff9427bf4124a5cd4480870f3726bcf0e9212870a4583e26073760").unwrap(), // REPLACE
total_kernel_offset: BlindingFactor::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(), // REPLACE
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			// MWC - TODO DEBUG  set difficulty to 1 because of testign
			// total_difficulty: Difficulty::from_num(10_u64.pow(5)),
			total_difficulty: Difficulty::min(),
			secondary_scaling: 1856,
nonce: 14,// REPLACE
			proof: Proof {
nonces: vec![11790115, 42615812, 56307061, 60805551, 71426241, 89793168, 95451383, 117489796, 118687701, 139293270, 168136396, 182873534, 182915804, 188054210, 208818287, 212148377, 242288959, 263122386, 269134507, 273334796, 303346800, 310399804, 311527637, 342649008, 345057881, 346473601, 348618840, 357687760, 373857353, 376089221, 404938998, 408437747, 409024651, 428100714, 428784762, 429048537, 449589016, 452391249, 463035005, 474386202, 502216970, 507888499],// REPLACE
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		fee: 0,
		lock_height: 0,
excess: Commitment::from_vec(util::from_hex("082295f1d3852b7acdc916159f9a35bf02601c23cacdfbd73ea4c153c43caa4af3".to_string()).unwrap()),// REPLACE
excess_sig: Signature::from_raw_data(&[178, 81, 86, 120, 223, 170, 103, 86, 2, 80, 23, 183, 138, 248, 37, 20, 217, 62, 98, 141, 48, 255, 184, 78, 102, 223, 51, 138, 245, 65, 127, 26, 43, 110, 76, 15, 17, 236, 25, 166, 228, 162, 45, 89, 247, 125, 133, 5, 13, 122, 25, 2, 187, 191, 218, 205, 110, 221, 48, 233, 53, 177, 119, 51]).unwrap(),// REPLACE
	};
	let output = core::Output {
		features: core::OutputFeatures::Coinbase,
commit: Commitment::from_vec(util::from_hex("08c8715caee3a68d0e03d4f89c18929379c344f60fbd176272f80781b88a744f10".to_string()).unwrap()),// REPLACE
		proof: RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
proof: [6, 209, 239, 147, 118, 167, 146, 222, 80, 200, 44, 48, 153, 153, 91, 36, 217, 175, 247, 210, 150, 252, 208, 106, 250, 222, 48, 26, 3, 39, 24, 222, 139, 221, 8, 26, 86, 131, 88, 108, 54, 244, 11, 213, 180, 3, 217, 81, 183, 88, 165, 10, 204, 46, 51, 21, 75, 17, 64, 188, 84, 11, 180, 31, 11, 185, 43, 210, 254, 185, 80, 116, 232, 70, 209, 177, 214, 38, 157, 181, 105, 244, 71, 38, 39, 69, 165, 132, 196, 1, 49, 88, 47, 145, 165, 51, 102, 51, 39, 89, 228, 254, 25, 16, 43, 93, 184, 183, 191, 217, 160, 123, 143, 120, 195, 186, 241, 20, 190, 138, 174, 43, 142, 193, 138, 17, 73, 175, 14, 163, 240, 8, 208, 217, 114, 78, 20, 159, 107, 26, 106, 121, 110, 173, 105, 249, 170, 39, 50, 164, 199, 134, 45, 208, 185, 25, 84, 36, 151, 93, 241, 215, 173, 104, 34, 198, 189, 229, 28, 126, 228, 69, 185, 9, 63, 193, 128, 184, 20, 100, 231, 247, 197, 175, 214, 107, 226, 222, 242, 42, 105, 91, 124, 124, 165, 208, 43, 70, 58, 150, 29, 139, 94, 161, 213, 119, 84, 86, 189, 51, 94, 11, 144, 230, 249, 121, 117, 175, 83, 202, 93, 71, 3, 158, 210, 124, 127, 236, 178, 112, 59, 170, 110, 253, 136, 74, 80, 149, 207, 211, 155, 121, 223, 180, 183, 147, 100, 237, 253, 228, 240, 151, 42, 210, 178, 56, 174, 9, 117, 8, 222, 148, 152, 139, 139, 33, 207, 141, 147, 103, 104, 244, 41, 3, 20, 147, 119, 41, 189, 133, 103, 98, 235, 129, 95, 101, 7, 157, 161, 72, 229, 180, 169, 205, 216, 14, 155, 233, 85, 83, 96, 59, 131, 70, 208, 141, 165, 80, 92, 29, 143, 110, 112, 229, 138, 228, 74, 97, 235, 97, 179, 221, 223, 173, 23, 36, 181, 211, 145, 127, 170, 148, 126, 140, 132, 102, 106, 218, 128, 141, 109, 22, 7, 255, 28, 1, 98, 223, 128, 231, 47, 69, 122, 150, 3, 112, 69, 211, 166, 204, 159, 35, 127, 233, 158, 19, 217, 153, 209, 31, 80, 188, 126, 170, 203, 13, 161, 46, 70, 29, 150, 239, 190, 80, 249, 98, 3, 87, 156, 178, 149, 87, 250, 166, 159, 35, 54, 6, 120, 33, 193, 232, 143, 155, 18, 48, 95, 162, 18, 27, 58, 173, 207, 3, 193, 224, 89, 203, 188, 105, 100, 92, 165, 102, 230, 224, 82, 244, 208, 235, 15, 213, 88, 45, 35, 82, 226, 116, 19, 101, 195, 23, 5, 52, 194, 118, 133, 79, 236, 149, 103, 38, 13, 30, 217, 201, 82, 137, 209, 67, 139, 244, 133, 53, 221, 73, 160, 95, 241, 88, 217, 34, 40, 217, 132, 89, 134, 219, 202, 3, 178, 166, 175, 248, 127, 22, 47, 41, 110, 105, 254, 171, 30, 12, 123, 233, 240, 17, 248, 96, 254, 200, 227, 70, 188, 208, 195, 85, 155, 193, 10, 211, 55, 204, 5, 46, 48, 249, 225, 115, 41, 209, 65, 233, 45, 238, 163, 179, 144, 179, 212, 3, 136, 100, 221, 120, 26, 171, 235, 219, 30, 197, 253, 157, 97, 157, 243, 41, 228, 200, 231, 174, 192, 78, 134, 240, 199, 120, 20, 89, 205, 60, 244, 58, 152, 6, 251, 212, 133, 172, 150, 15, 185, 144, 83, 156, 138, 189, 244, 249, 192, 47, 252, 74, 205, 29, 213, 232, 110, 177, 220, 200, 74, 252, 13, 210, 26, 236, 25, 240, 156, 154, 207, 226, 155, 149, 157, 48, 50, 222, 157, 101, 35, 14, 52, 165, 126, 197, 229, 65, 109, 81, 140, 89, 80, 143, 183, 62, 96, 182, 210, 33, 131, 28, 157, 188, 14, 57, 9, 204, 42, 234, 157, 72, 28, 149, 24, 109, 173, 141, 11, 230, 227, 99, 110, 212, 80, 82, 83, 67, 99, 173, 77, 130, 202, 230, 17, 65, 130, 238, 242, 31, 9, 218, 131],// REPLACE
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
			"041bc4e75886123ec86bb7e56553bfa30e671ce7cfdb1e09164323c8a61d2de4"
		);
		assert_eq!(
			gen_bin.hash().to_hex(),
			"9f39b324457397e407a0c6fc60973b86dc3e4733aed79f2442dfc5dc08765733"
		);
	}
}
