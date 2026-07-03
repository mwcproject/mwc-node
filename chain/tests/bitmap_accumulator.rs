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

use mwc_chain::txhashset::BitmapAccumulator;
use mwc_core::core::hash::Hash;
use mwc_core::ser::PMMRIndexHashable;
use mwc_crates::bit_vec::BitVec;

fn bitmap_indexes(accumulator: &BitmapAccumulator) -> Vec<u32> {
	accumulator.build_bitmap().unwrap().iter().collect()
}

#[test]
fn test_bitmap_accumulator() {
	mwc_util::init_test_logger().unwrap();

	let mut accumulator = BitmapAccumulator::new(0);
	assert_eq!(accumulator.root().unwrap(), Hash::default());

	// 1000... (rebuild from 0, setting [0] true)
	accumulator.apply(vec![0], vec![Ok(0)], 1).unwrap();
	let expected_hash = {
		let mut bit_vec = BitVec::from_elem(1024, false);
		bit_vec.set(0, true);
		bit_vec.to_bytes().hash_with_index(0, 0).unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// 1100... (rebuild from 0, setting [0, 1] true)
	accumulator.apply(vec![0], vec![Ok(0), Ok(1)], 2).unwrap();
	let expected_hash = {
		let mut bit_vec = BitVec::from_elem(1024, false);
		bit_vec.set(0, true);
		bit_vec.set(1, true);
		bit_vec.to_bytes().hash_with_index(0, 0).unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// 0100... (rebuild from 0, setting [1] true, which will reset [0] false)
	accumulator.apply(vec![0], vec![Ok(1)], 2).unwrap();
	let expected_hash = {
		let mut bit_vec = BitVec::from_elem(1024, false);
		bit_vec.set(1, true);
		let expected_bytes = bit_vec.to_bytes();
		expected_bytes.hash_with_index(0, 0).unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// 0100... (rebuild from 1, setting [1] true)
	accumulator.apply(vec![1], vec![Ok(1)], 2).unwrap();
	let expected_hash = {
		let mut bit_vec = BitVec::from_elem(1024, false);
		bit_vec.set(1, true);
		let expected_bytes = bit_vec.to_bytes();
		expected_bytes.hash_with_index(0, 0).unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// 0100...0001 (rebuild from 0, setting [1, 1023] true)
	accumulator
		.apply(vec![0], vec![Ok(1), Ok(1023)], 1024)
		.unwrap();
	let expected_hash = {
		let mut bit_vec = BitVec::from_elem(1024, false);
		bit_vec.set(1, true);
		bit_vec.set(1023, true);
		let expected_bytes = bit_vec.to_bytes();
		expected_bytes.hash_with_index(0, 0).unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// Now set bits such that we extend the bitmap accumulator across multiple 1024 bit chunks.
	// We need a second bit_vec here to reflect the additional chunk.
	// 0100...0001, 1000...0000 (rebuild from 0, setting [1, 1023, 1024] true)
	accumulator
		.apply(vec![0], vec![Ok(1), Ok(1023), Ok(1024)], 1025)
		.unwrap();
	let expected_hash = {
		let mut bit_vec = BitVec::from_elem(1024, false);
		bit_vec.set(1, true);
		bit_vec.set(1023, true);
		let mut bit_vec2 = BitVec::from_elem(1024, false);
		bit_vec2.set(0, true);
		let expected_bytes_0 = bit_vec.to_bytes();
		let expected_bytes_1 = bit_vec2.to_bytes();
		let expected_hash_0 = expected_bytes_0.hash_with_index(0, 0).unwrap();
		let expected_hash_1 = expected_bytes_1.hash_with_index(0, 1).unwrap();
		(expected_hash_0, expected_hash_1)
			.hash_with_index(0, 2)
			.unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// Just rebuild the second bitmap chunk.
	// 0100...0001, 0100...0000 (rebuild from 1025, setting [1025] true)
	accumulator.apply(vec![1025], vec![Ok(1025)], 1026).unwrap();
	let expected_hash = {
		let mut bit_vec = BitVec::from_elem(1024, false);
		bit_vec.set(1, true);
		bit_vec.set(1023, true);
		let mut bit_vec2 = BitVec::from_elem(1024, false);
		bit_vec2.set(1, true);
		let expected_bytes_0 = bit_vec.to_bytes();
		let expected_bytes_1 = bit_vec2.to_bytes();
		let expected_hash_0 = expected_bytes_0.hash_with_index(0, 0).unwrap();
		let expected_hash_1 = expected_bytes_1.hash_with_index(0, 1).unwrap();
		(expected_hash_0, expected_hash_1)
			.hash_with_index(0, 2)
			.unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// Rebuild the first bitmap chunk and all chunks after it.
	// 0100...0000, 0100...0000 (rebuild from 1, setting [1, 1025] true)
	accumulator
		.apply(vec![1], vec![Ok(1), Ok(1025)], 1026)
		.unwrap();
	let expected_hash = {
		let mut bit_vec = BitVec::from_elem(1024, false);
		bit_vec.set(1, true);
		let mut bit_vec2 = BitVec::from_elem(1024, false);
		bit_vec2.set(1, true);
		let expected_bytes_0 = bit_vec.to_bytes();
		let expected_bytes_1 = bit_vec2.to_bytes();
		let expected_hash_0 = expected_bytes_0.hash_with_index(0, 0).unwrap();
		let expected_hash_1 = expected_bytes_1.hash_with_index(0, 1).unwrap();
		(expected_hash_0, expected_hash_1)
			.hash_with_index(0, 2)
			.unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// Make sure we handle the case where the first chunk is all 0s
	// 0000...0000, 0100...0000 (rebuild from 1, setting [1025] true)
	accumulator.apply(vec![1], vec![Ok(1025)], 1026).unwrap();
	let expected_hash = {
		let bit_vec = BitVec::from_elem(1024, false);
		let mut bit_vec2 = BitVec::from_elem(1024, false);
		bit_vec2.set(1, true);
		let expected_bytes_0 = bit_vec.to_bytes();
		let expected_bytes_1 = bit_vec2.to_bytes();
		let expected_hash_0 = expected_bytes_0.hash_with_index(0, 0).unwrap();
		let expected_hash_1 = expected_bytes_1.hash_with_index(0, 1).unwrap();
		(expected_hash_0, expected_hash_1)
			.hash_with_index(0, 2)
			.unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// Check that removing the last bit in a chunk removes the now empty chunk
	// if it is the rightmost chunk.
	// 0000...0001 (rebuild from 1023, setting [1023] true)
	accumulator.apply(vec![1023], vec![Ok(1023)], 1024).unwrap();
	let expected_hash = {
		let mut bit_vec = BitVec::from_elem(1024, false);
		bit_vec.set(1023, true);
		let expected_bytes = bit_vec.to_bytes();
		expected_bytes.hash_with_index(0, 0).unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);

	// Make sure we pad appropriately with 0s if we set a distant bit to 1.
	// Start with an empty accumulator.
	// 0000...0000, 0000...0000, 0000...0000, 0000...0001 (rebuild from 4095, setting [4095] true)
	let mut accumulator = BitmapAccumulator::new(0);
	accumulator.apply(vec![4095], vec![Ok(4095)], 4096).unwrap();
	let expected_hash = {
		let bit_vec0 = BitVec::from_elem(1024, false);
		let bit_vec1 = BitVec::from_elem(1024, false);
		let bit_vec2 = BitVec::from_elem(1024, false);
		let mut bit_vec3 = BitVec::from_elem(1024, false);
		bit_vec3.set(1023, true);

		let expected_bytes_0 = bit_vec0.to_bytes();
		let expected_bytes_1 = bit_vec1.to_bytes();
		let expected_bytes_2 = bit_vec2.to_bytes();
		let expected_bytes_3 = bit_vec3.to_bytes();

		let expected_hash_0 = expected_bytes_0.hash_with_index(0, 0).unwrap();
		let expected_hash_1 = expected_bytes_1.hash_with_index(0, 1).unwrap();
		let expected_hash_2 = (expected_hash_0, expected_hash_1)
			.hash_with_index(0, 2)
			.unwrap();

		let expected_hash_3 = expected_bytes_2.hash_with_index(0, 3).unwrap();
		let expected_hash_4 = expected_bytes_3.hash_with_index(0, 4).unwrap();
		let expected_hash_5 = (expected_hash_3, expected_hash_4)
			.hash_with_index(0, 5)
			.unwrap();

		(expected_hash_2, expected_hash_5)
			.hash_with_index(0, 6)
			.unwrap()
	};
	assert_eq!(accumulator.root().unwrap(), expected_hash);
}

#[test]
fn bitmap_accumulator_init_rejects_out_of_order_indices() {
	let mut accumulator = BitmapAccumulator::new(0);
	let err = accumulator.init(vec![Ok(1024), Ok(0)], 1025).unwrap_err();

	assert!(err.to_string().contains("expected sorted indices"));
}

#[test]
fn bitmap_accumulator_apply_rejects_invalidated_index_outside_size() {
	let mut accumulator = BitmapAccumulator::new(0);
	let idx = Vec::<Result<u64, mwc_core::core::pmmr::Error>>::new();
	let err = accumulator.apply(vec![1024], idx, 1).unwrap_err();

	assert!(err.to_string().contains("outside bitmap size"));
	assert_eq!(accumulator.root().unwrap(), Hash::default());
}

#[test]
fn bitmap_accumulator_init_commits_empty_bitmap_size() {
	let idx = Vec::<Result<u64, mwc_core::core::pmmr::Error>>::new();
	let mut accumulator = BitmapAccumulator::new(0);
	accumulator.init(idx, 1).unwrap();

	let expected_hash = BitVec::from_elem(1024, false)
		.to_bytes()
		.hash_with_index(0, 0)
		.unwrap();
	assert_eq!(accumulator.root().unwrap(), expected_hash);
	assert_ne!(accumulator.root().unwrap(), Hash::default());

	let idx = Vec::<Result<u64, mwc_core::core::pmmr::Error>>::new();
	let mut larger_accumulator = BitmapAccumulator::new(0);
	larger_accumulator.init(idx, 2048).unwrap();
	assert_ne!(
		accumulator.root().unwrap(),
		larger_accumulator.root().unwrap()
	);
}

#[test]
fn bitmap_accumulator_init_commits_trailing_zero_chunks() {
	let mut short = BitmapAccumulator::new(0);
	short.init(vec![Ok(0)], 1).unwrap();

	let mut long = BitmapAccumulator::new(0);
	long.init(vec![Ok(0)], 2048).unwrap();

	assert_eq!(bitmap_indexes(&short), vec![0]);
	assert_eq!(bitmap_indexes(&long), vec![0]);
	assert_ne!(short.root().unwrap(), long.root().unwrap());
}

#[test]
fn bitmap_accumulator_apply_rolls_back_on_idx_iterator_error() {
	let mut accumulator = BitmapAccumulator::new(0);
	accumulator
		.apply(vec![0], vec![Ok(1), Ok(1024), Ok(2048)], 2049)
		.unwrap();
	let root = accumulator.root().unwrap();
	let bitmap = bitmap_indexes(&accumulator);

	let err = accumulator
		.apply(
			vec![0],
			vec![
				Ok(1),
				Ok(1024),
				Err(mwc_core::core::pmmr::Error::InvalidState("boom".into())),
			],
			2049,
		)
		.unwrap_err();

	assert!(err.to_string().contains("boom"));
	assert_eq!(accumulator.root().unwrap(), root);
	assert_eq!(bitmap_indexes(&accumulator), bitmap);
}

#[test]
fn bitmap_accumulator_apply_with_empty_invalidated_idx_rebuilds_from_start() {
	let mut accumulator = BitmapAccumulator::new(0);
	accumulator.apply(vec![0], vec![Ok(0)], 1).unwrap();

	accumulator
		.apply(Vec::<u64>::new(), vec![Ok(0), Ok(1)], 2)
		.unwrap();

	assert_eq!(bitmap_indexes(&accumulator), vec![0, 1]);
}

#[test]
fn bitmap_accumulator_apply_with_empty_invalidated_idx_rolls_back_on_idx_error() {
	let mut accumulator = BitmapAccumulator::new(0);
	accumulator.apply(vec![0], vec![Ok(0)], 1).unwrap();
	let root = accumulator.root().unwrap();
	let bitmap = bitmap_indexes(&accumulator);

	let err = accumulator
		.apply(
			Vec::<u64>::new(),
			vec![Err(mwc_core::core::pmmr::Error::InvalidState(
				"boom".into(),
			))],
			2,
		)
		.unwrap_err();

	assert!(err.to_string().contains("boom"));
	assert_eq!(accumulator.root().unwrap(), root);
	assert_eq!(bitmap_indexes(&accumulator), bitmap);
}

#[test]
fn bitmap_accumulator_apply_with_empty_invalidated_idx_can_clear_to_zero_size() {
	let mut accumulator = BitmapAccumulator::new(0);
	accumulator.apply(vec![0], vec![Ok(0)], 1).unwrap();

	accumulator
		.apply(
			Vec::<u64>::new(),
			Vec::<Result<u64, mwc_core::core::pmmr::Error>>::new(),
			0,
		)
		.unwrap();

	assert_eq!(accumulator.root().unwrap(), Hash::default());
	assert!(bitmap_indexes(&accumulator).is_empty());
}

#[test]
fn bitmap_accumulator_apply_rolls_back_on_out_of_order_indices() {
	let mut accumulator = BitmapAccumulator::new(0);
	accumulator
		.apply(vec![0], vec![Ok(1), Ok(1024), Ok(2048)], 2049)
		.unwrap();
	let root = accumulator.root().unwrap();
	let bitmap = bitmap_indexes(&accumulator);

	let err = accumulator
		.apply(vec![0], vec![Ok(1024), Ok(1)], 2049)
		.unwrap_err();

	assert!(err.to_string().contains("expected sorted indices"));
	assert_eq!(accumulator.root().unwrap(), root);
	assert_eq!(bitmap_indexes(&accumulator), bitmap);
}

#[test]
fn bitmap_accumulator_apply_rolls_back_padding_on_idx_iterator_error() {
	let mut accumulator = BitmapAccumulator::new(0);
	let idx: Vec<Result<u64, mwc_core::core::pmmr::Error>> = vec![Err(
		mwc_core::core::pmmr::Error::InvalidState("boom".into()),
	)];

	let err = accumulator.apply(vec![4095], idx, 4096).unwrap_err();

	assert!(err.to_string().contains("boom"));
	assert_eq!(accumulator.root().unwrap(), Hash::default());
	assert!(bitmap_indexes(&accumulator).is_empty());
}
