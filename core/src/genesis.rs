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
		timestamp: Utc.ymd(2019, 4, 3).and_hms(16, 30, 1),
		prev_root: Hash::from_hex(
			"00000000000000000000a452f74956d731e32ee32adeb0fa42d9b2d30d4a0ec4",
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
			"2789e7e393a8ed6ec11a40fb0f65f34052444f25959b49fdbe107d3d78145f84",
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
			nonce: 5,
			proof: Proof {
				nonces: vec![
                    10806478, 24469177, 45705076, 48188811, 50975609, 56233788, 57548634, 63642360, 76946544, 100198044, 213420727, 220639895, 249404493, 267132137, 268763916, 300117838, 305796665, 307810803, 309806209, 327282571, 337253995, 349200588, 366303891, 366379837, 368193464, 393265399, 394555181, 407263159, 439697836, 444976858, 454109502, 464582623, 476216138, 483446440, 485005225, 488544815, 492661576, 503848707, 514246675, 521552673, 532743440, 53544157
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
                                             139, 32, 222, 174, 157, 206, 51, 16, 131, 74, 45, 103, 55, 152, 86, 49, 136, 19, 148, 227, 77, 203, 254, 128, 196, 148, 57, 123, 101, 77, 146, 99, 67, 244, 212, 69, 60, 151, 171, 119, 182, 75, 103, 114, 184, 47, 95, 128, 187, 115, 15, 94, 194, 121, 72, 55, 123, 231, 13, 37, 169, 116, 39, 188
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
                90, 18, 59, 154, 82, 206, 161, 99, 153, 121, 24, 145, 24, 173, 210, 155, 235, 244, 30, 8, 170, 157, 94, 149, 57, 205, 81, 56, 242, 80, 59, 78, 139, 0, 21, 111, 91, 122, 79, 43, 70, 206, 61, 26, 110, 62, 120, 44, 157, 28, 38, 219, 199, 230, 152, 254, 234, 29, 196, 246, 60, 67, 234, 235, 10, 206, 67, 194, 218, 111, 161, 161, 75, 48, 206, 205, 106, 87, 188, 213, 168, 210, 205, 156, 252, 240, 20, 119, 211, 53, 205, 104, 75, 60, 197, 70, 148, 100, 163, 14, 131, 244, 233, 102, 146, 145, 1, 65, 191, 16, 86, 64, 26, 204, 21, 109, 194, 181, 175, 61, 113, 167, 72, 215, 232, 23, 213, 190, 159, 27, 199, 79, 30, 138, 236, 151, 201, 125, 44, 56, 0, 181, 141, 220, 52, 212, 6, 138, 229, 189, 227, 239, 195, 157, 81, 180, 192, 112, 81, 170, 145, 36, 86, 123, 15, 249, 214, 147, 111, 225, 218, 87, 95, 118, 193, 87, 100, 181, 185, 120, 246, 145, 93, 41, 217, 46, 88, 180, 206, 246, 176, 118, 185, 46, 187, 235, 124, 77, 220, 135, 0, 67, 97, 86, 9, 62, 90, 243, 110, 78, 146, 33, 122, 125, 204, 186, 51, 106, 90, 1, 144, 252, 139, 109, 224, 148, 98, 230, 219, 116, 170, 135, 241, 62, 69, 89, 225, 185, 223, 226, 14, 214, 195, 158, 213, 58, 251, 73, 159, 124, 233, 66, 139, 117, 198, 44, 123, 197, 190, 225, 238, 235, 241, 36, 193, 191, 218, 3, 252, 103, 52, 122, 87, 71, 34, 105, 199, 237, 188, 176, 16, 56, 49, 14, 158, 140, 103, 12, 222, 49, 30, 133, 161, 212, 48, 231, 48, 238, 27, 94, 34, 1, 200, 45, 244, 180, 186, 93, 197, 42, 37, 186, 50, 40, 108, 146, 160, 196, 124, 90, 146, 185, 212, 101, 67, 209, 18, 64, 213, 204, 101, 175, 23, 148, 27, 53, 169, 82, 52, 79, 45, 85, 83, 23, 250, 250, 179, 115, 39, 153, 250, 216, 55, 118, 3, 1, 1, 225, 225, 155, 163, 188, 235, 25, 109, 119, 171, 129, 217, 27, 216, 36, 217, 43, 222, 140, 111, 120, 104, 13, 89, 17, 176, 245, 126, 239, 240, 109, 33, 193, 62, 13, 147, 35, 54, 100, 202, 116, 127, 25, 0, 86, 145, 207, 138, 120, 202, 20, 214, 100, 59, 241, 68, 62, 79, 52, 195, 232, 205, 43, 190, 251, 121, 175, 60, 136, 91, 172, 41, 184, 84, 42, 175, 185, 184, 198, 89, 42, 116, 48, 83, 173, 252, 22, 141, 114, 16, 252, 248, 154, 121, 231, 63, 217, 63, 242, 151, 38, 253, 19, 161, 76, 253, 60, 62, 69, 14, 140, 149, 179, 148, 145, 171, 134, 47, 33, 244, 16, 168, 162, 186, 65, 224, 135, 39, 18, 177, 38, 90, 10, 135, 137, 132, 100, 238, 127, 9, 239, 26, 100, 108, 170, 151, 157, 59, 10, 93, 90, 32, 101, 73, 160, 36, 182, 112, 245, 213, 176, 200, 237, 18, 173, 112, 183, 103, 45, 107, 184, 244, 42, 25, 188, 220, 53, 60, 163, 76, 242, 199, 71, 6, 0, 183, 229, 206, 207, 183, 144, 119, 228, 110, 16, 219, 70, 84, 10, 241, 83, 235, 84, 224, 17, 35, 191, 85, 118, 103, 88, 197, 81, 132, 80, 63, 125, 218, 130, 53, 21, 220, 224, 100, 22, 9, 41, 5, 236, 80, 227, 87, 90, 249, 101, 221, 36, 211, 219, 230, 69, 149, 27, 147, 203, 51, 94, 104, 106, 211, 216, 86, 55, 189, 228, 40, 224, 133, 69, 224, 22, 93, 254, 35, 60, 238, 168, 45, 36, 225, 188, 146, 27, 54, 30, 23, 200, 155, 253, 13, 111, 107, 21, 197, 108, 216, 174, 47, 62, 218, 134, 14, 201, 96, 238, 60, 195, 51, 60, 2, 78, 159, 202, 120, 101, 18, 26, 227, 34, 96, 65, 117, 142, 126, 167, 156, 232, 252
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
prev_root: Hash::from_hex("000000000000000000046f0790420d78821f47d8ba4f3320f06c018471dd75e5").unwrap(),
output_root: Hash::from_hex("fda58fbf64a65e377316c492385118851ef577de3297c2b204af536070f80c91").unwrap(),
range_proof_root: Hash::from_hex("6d4fcb60703dd54ae5b042570b26adaab41608ba41e29f5458140efd19efb4c8").unwrap(),
kernel_root: Hash::from_hex("edecd2f2162c7a592af606ae734ba2bc7f76a5aee5d8e8f1cafe74c555918a3a").unwrap(),
total_kernel_offset: BlindingFactor::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
		output_mmr_size: 1,
		kernel_mmr_size: 1,
		pow: ProofOfWork {
			// MWC - TODO DEBUG  set difficulty to 1 because of testign
			// total_difficulty: Difficulty::from_num(10_u64.pow(5)),
			total_difficulty: Difficulty::min(),
			secondary_scaling: 1856,
nonce: 10085,
			proof: Proof {
nonces: vec![31371893, 82590058, 90320793, 102064521, 124771854, 126986448, 128192585, 128932017, 131895717, 154807524, 159851733, 163547409, 165576756, 199161326, 204441283, 218872897, 221163011, 222027696, 226010638, 268745036, 270362239, 275899758, 285667177, 309633413, 309891402, 313217558, 332496283, 339609078, 366698076, 396692180, 401490064, 410800051, 411208696, 425723601, 431845670, 434108869, 440403997, 459109823, 476280985, 484820584, 489304888, 493795531],
				edge_bits: 29,
			},
		},
		..Default::default()
	});
	let kernel = core::TxKernel {
		features: core::KernelFeatures::Coinbase,
		fee: 0,
		lock_height: 0,
excess: Commitment::from_vec(util::from_hex("091abed0e4a9c1b890d9e59101ac0483e172e3624884bde3c159f3f25224373771".to_string()).unwrap()),
excess_sig: Signature::from_raw_data(&[178, 157, 199, 236, 194, 58, 177, 5, 90, 226, 185, 7, 50, 197, 59, 79, 41, 176, 64, 102, 174, 130, 245, 170, 183, 252, 245, 202, 39, 19, 40, 83, 47, 32, 163, 234, 183, 39, 44, 252, 33, 185, 127, 251, 43, 163, 77, 23, 227, 244, 240, 6, 90, 18, 43, 135, 209, 131, 139, 235, 176, 163, 100, 197]).unwrap(),
	};
	let output = core::Output {
		features: core::OutputFeatures::Coinbase,
commit: Commitment::from_vec(util::from_hex("091e73d194a5a3d93e68c962537389600dc439a065ef14c5c074587ca693063ba5".to_string()).unwrap()),
		proof: RangeProof {
			plen: SINGLE_BULLET_PROOF_SIZE,
proof: [90, 18, 59, 154, 82, 206, 161, 99, 153, 121, 24, 145, 24, 173, 210, 155, 235, 244, 30, 8, 170, 157, 94, 149, 57, 205, 81, 56, 242, 80, 59, 78, 139, 0, 21, 111, 91, 122, 79, 43, 70, 206, 61, 26, 110, 62, 120, 44, 157, 28, 38, 219, 199, 230, 152, 254, 234, 29, 196, 246, 60, 67, 234, 235, 10, 206, 67, 194, 218, 111, 161, 161, 75, 48, 206, 205, 106, 87, 188, 213, 168, 210, 205, 156, 252, 240, 20, 119, 211, 53, 205, 104, 75, 60, 197, 70, 148, 100, 163, 14, 131, 244, 233, 102, 146, 145, 1, 65, 191, 16, 86, 64, 26, 204, 21, 109, 194, 181, 175, 61, 113, 167, 72, 215, 232, 23, 213, 190, 159, 27, 199, 79, 30, 138, 236, 151, 201, 125, 44, 56, 0, 181, 141, 220, 52, 212, 6, 138, 229, 189, 227, 239, 195, 157, 81, 180, 192, 112, 81, 170, 145, 36, 86, 123, 15, 249, 214, 147, 111, 225, 218, 87, 95, 118, 193, 87, 100, 181, 185, 120, 246, 145, 93, 41, 217, 46, 88, 180, 206, 246, 176, 118, 185, 46, 187, 235, 124, 77, 220, 135, 0, 67, 97, 86, 9, 62, 90, 243, 110, 78, 146, 33, 122, 125, 204, 186, 51, 106, 90, 1, 144, 252, 139, 109, 224, 148, 98, 230, 219, 116, 170, 135, 241, 62, 69, 89, 225, 185, 223, 226, 14, 214, 195, 158, 213, 58, 251, 73, 159, 124, 233, 66, 139, 117, 198, 44, 123, 197, 190, 225, 238, 235, 241, 36, 193, 191, 218, 3, 252, 103, 52, 122, 87, 71, 34, 105, 199, 237, 188, 176, 16, 56, 49, 14, 158, 140, 103, 12, 222, 49, 30, 133, 161, 212, 48, 231, 48, 238, 27, 94, 34, 1, 200, 45, 244, 180, 186, 93, 197, 42, 37, 186, 50, 40, 108, 146, 160, 196, 124, 90, 146, 185, 212, 101, 67, 209, 18, 64, 213, 204, 101, 175, 23, 148, 27, 53, 169, 82, 52, 79, 45, 85, 83, 23, 250, 250, 179, 115, 39, 153, 250, 216, 55, 118, 3, 1, 1, 225, 225, 155, 163, 188, 235, 25, 109, 119, 171, 129, 217, 27, 216, 36, 217, 43, 222, 140, 111, 120, 104, 13, 89, 17, 176, 245, 126, 239, 240, 109, 33, 193, 62, 13, 147, 35, 54, 100, 202, 116, 127, 25, 0, 86, 145, 207, 138, 120, 202, 20, 214, 100, 59, 241, 68, 62, 79, 52, 195, 232, 205, 43, 190, 251, 121, 175, 60, 136, 91, 172, 41, 184, 84, 42, 175, 185, 184, 198, 89, 42, 116, 48, 83, 173, 252, 22, 141, 114, 16, 252, 248, 154, 121, 231, 63, 217, 63, 242, 151, 38, 253, 19, 161, 76, 253, 60, 62, 69, 14, 140, 149, 179, 148, 145, 171, 134, 47, 33, 244, 16, 168, 162, 186, 65, 224, 135, 39, 18, 177, 38, 90, 10, 135, 137, 132, 100, 238, 127, 9, 239, 26, 100, 108, 170, 151, 157, 59, 10, 93, 90, 32, 101, 73, 160, 36, 182, 112, 245, 213, 176, 200, 237, 18, 173, 112, 183, 103, 45, 107, 184, 244, 42, 25, 188, 220, 53, 60, 163, 76, 242, 199, 71, 6, 0, 183, 229, 206, 207, 183, 144, 119, 228, 110, 16, 219, 70, 84, 10, 241, 83, 235, 84, 224, 17, 35, 191, 85, 118, 103, 88, 197, 81, 132, 80, 63, 125, 218, 130, 53, 21, 220, 224, 100, 22, 9, 41, 5, 236, 80, 227, 87, 90, 249, 101, 221, 36, 211, 219, 230, 69, 149, 27, 147, 203, 51, 94, 104, 106, 211, 216, 86, 55, 189, 228, 40, 224, 133, 69, 224, 22, 93, 254, 35, 60, 238, 168, 45, 36, 225, 188, 146, 27, 54, 30, 23, 200, 155, 253, 13, 111, 107, 21, 197, 108, 216, 174, 47, 62, 218, 134, 14, 201, 96, 238, 60, 195, 51, 60, 2, 78, 159, 202, 120, 101, 18, 26, 227, 34, 96, 65, 117, 142, 126, 167, 156, 232, 252],
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
