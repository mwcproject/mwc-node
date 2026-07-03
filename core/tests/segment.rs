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

mod common;

use common::TestElem;
use mwc_core::core::hash::Hash;
use mwc_core::core::pmmr;
use mwc_core::core::pmmr::segment::{SegmentError, SegmentProof};
use mwc_core::core::pmmr::ReadablePMMR;
use mwc_core::core::{Segment, SegmentIdentifier};
use mwc_core::ser;
use mwc_crates::croaring::Bitmap;
use std::convert::TryInto;

#[test]
fn segment_identifier_display_handles_invalid_values() {
	let valid = SegmentIdentifier { height: 3, idx: 1 }.to_string();
	assert_eq!(valid, "(h:3, idx:1 offset:8 size:8)");

	let invalid_height = SegmentIdentifier { height: 64, idx: 0 }.to_string();
	assert!(invalid_height.contains("h:64"));
	assert!(invalid_height.contains("idx:0"));
	assert!(invalid_height.contains("Invalid"));

	let invalid_offset = SegmentIdentifier { height: 63, idx: 2 }.to_string();
	assert!(invalid_offset.contains("h:63"));
	assert!(invalid_offset.contains("idx:2"));
	assert!(invalid_offset.contains("Invalid"));
}

#[test]
fn segment_pos_range_rejects_nonexistent_segment() {
	let empty = SegmentIdentifier { height: 0, idx: 0 };
	assert!(matches!(
		empty.segment_pos_range(0),
		Err(SegmentError::NonExistent)
	));

	// A size-8 MMR has five leaves, so the segment starting at leaf offset 8
	// is beyond the end and must not produce an inverted position range.
	let past_end = SegmentIdentifier { height: 2, idx: 2 };
	assert!(matches!(
		past_end.segment_pos_range(8),
		Err(SegmentError::NonExistent)
	));
}

#[test]
fn segment_pos_range_rejects_incomplete_mmr_size() {
	let id = SegmentIdentifier { height: 0, idx: 3 };
	assert!(matches!(
		id.segment_pos_range(5),
		Err(SegmentError::InvalidMMRSize {
			mmr_size: 5,
			next_height: 1
		})
	));
}

#[test]
fn segment_from_parts_rejects_malformed_parallel_vectors() {
	let id = SegmentIdentifier { height: 0, idx: 0 };
	let proof = {
		let mut backend = pmmr::VecBackend::new(0);
		let mut mmr = pmmr::PMMR::new(&mut backend);
		mmr.push(&TestElem([0, 0, 0, 1])).unwrap();
		let segment =
			Segment::<TestElem>::from_pmmr(id, &mmr.readonly_pmmr(), None, 1, usize::MAX).unwrap();
		segment.parts().5
	};

	assert!(matches!(
		Segment::<TestElem>::from_parts(
			id,
			vec![0],
			Vec::new(),
			Vec::new(),
			Vec::new(),
			proof.clone()
		),
		Err(SegmentError::GenericError(msg)) if msg.contains("hash position count")
	));
	assert!(matches!(
		Segment::<TestElem>::from_parts(
			id,
			vec![1, 1],
			vec![Hash::default(), Hash::default()],
			Vec::new(),
			Vec::new(),
			proof.clone()
		),
		Err(SegmentError::GenericError(msg)) if msg.contains("hash positions")
	));
	assert!(matches!(
		Segment::from_parts(
			id,
			Vec::new(),
			Vec::new(),
			vec![0, 1],
			vec![TestElem([0, 0, 0, 1])],
			proof.clone()
		),
		Err(SegmentError::GenericError(msg)) if msg.contains("leaf position count")
	));
	assert!(matches!(
		Segment::from_parts(
			id,
			Vec::new(),
			Vec::new(),
			vec![1, 1],
			vec![TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])],
			proof
		),
		Err(SegmentError::GenericError(msg)) if msg.contains("leaf positions")
	));
}

#[test]
fn segment_validate_rejects_unconsumed_leaves_and_trims_extra_hashes() {
	let id = SegmentIdentifier { height: 1, idx: 0 };
	let mut backend = pmmr::VecBackend::new(0);
	let mut mmr = pmmr::PMMR::new(&mut backend);
	mmr.push(&TestElem([0, 0, 0, 1])).unwrap();
	mmr.push(&TestElem([0, 0, 0, 2])).unwrap();
	let mmr = mmr.readonly_pmmr();
	let mmr_size = mmr.unpruned_size();
	let root = mmr.root().unwrap();

	let valid = Segment::<TestElem>::from_pmmr(id, &mmr, None, 1, usize::MAX).unwrap();
	valid.clone().validate(0, mmr_size, None, &root).unwrap();

	let (id, hash_pos, hashes, mut leaf_pos, mut leaf_data, proof) = valid.clone().parts();
	leaf_pos.push(3);
	leaf_data.push(TestElem([0, 0, 0, 3]));
	let extra_leaf = Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaf_data, proof).unwrap();
	assert!(matches!(
		extra_leaf.validate(0, mmr_size, None, &root),
		Err(SegmentError::GenericError(msg)) if msg.contains("unconsumed leaf position")
	));

	let (id, mut hash_pos, mut hashes, leaf_pos, leaf_data, proof) = valid.parts();
	hash_pos.push(3);
	hashes.push(Hash::default());
	let extra_hash = Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaf_data, proof).unwrap();
	let trimmed = extra_hash.validate(0, mmr_size, None, &root).unwrap();
	let (_, hash_pos, hashes, _, _, _) = trimmed.parts();
	assert!(hash_pos.is_empty());
	assert!(hashes.is_empty());

	let mut bitmap = Bitmap::new();
	bitmap.add_range(0..2);
	let valid = Segment::<TestElem>::from_pmmr(id, &mmr, Some(&bitmap), 1, usize::MAX).unwrap();
	let valid = valid.validate(0, mmr_size, Some(&bitmap), &root).unwrap();
	let (id, mut hash_pos, mut hashes, leaf_pos, leaf_data, proof) = valid.parts();
	hash_pos.push(0);
	hashes.push(Hash::default());
	let extra_hash = Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaf_data, proof).unwrap();
	let trimmed = extra_hash
		.validate(0, mmr_size, Some(&bitmap), &root)
		.unwrap();
	let (_, hash_pos, hashes, _, _, _) = trimmed.parts();
	assert!(hash_pos.is_empty());
	assert!(hashes.is_empty());
}

#[test]
fn segment_from_pmmr_bitmap_requires_kept_leaf_data() {
	let id = SegmentIdentifier { height: 1, idx: 0 };
	let mut backend = pmmr::VecBackend::<TestElem>::new_hash_only(0);
	let mut mmr = pmmr::PMMR::new(&mut backend);
	mmr.push(&TestElem([0, 0, 0, 1])).unwrap();
	mmr.push(&TestElem([0, 0, 0, 2])).unwrap();

	let mut bitmap = Bitmap::new();
	bitmap.add(0);

	assert!(matches!(
		Segment::<TestElem>::from_pmmr(id, &mmr.readonly_pmmr(), Some(&bitmap), 16, usize::MAX),
		Err(SegmentError::MissingLeaf(0))
	));
}

#[test]
fn segment_from_pmmr_keeps_legacy_size_limit_boundary() {
	let leaf_size = 16;
	let id = SegmentIdentifier { height: 0, idx: 0 };
	let mut backend = pmmr::VecBackend::new(0);
	let mut mmr = pmmr::PMMR::new(&mut backend);
	mmr.push(&TestElem([0, 0, 0, 1])).unwrap();
	Segment::<TestElem>::from_pmmr(id, &mmr.readonly_pmmr(), None, leaf_size, 0).unwrap();

	let mut backend = pmmr::VecBackend::new(0);
	let mut mmr = pmmr::PMMR::new(&mut backend);
	mmr.push(&TestElem([0, 0, 0, 1])).unwrap();
	mmr.push(&TestElem([0, 0, 0, 2])).unwrap();

	assert!(matches!(
		Segment::<TestElem>::from_pmmr(
			SegmentIdentifier { height: 1, idx: 0 },
			&mmr.readonly_pmmr(),
			None,
			leaf_size,
			0
		),
		Err(SegmentError::SegmentSizeAboveLimit)
	));
}

#[test]
fn segment_from_pmmr_bitmap_bounds_initial_construction_work() {
	let id = SegmentIdentifier { height: 1, idx: 0 };
	let mut backend = pmmr::VecBackend::new(0);
	let mut mmr = pmmr::PMMR::new(&mut backend);
	mmr.push(&TestElem([0, 0, 0, 1])).unwrap();
	mmr.push(&TestElem([0, 0, 0, 2])).unwrap();

	let bitmap = Bitmap::new();

	assert!(matches!(
		Segment::<TestElem>::from_pmmr(id, &mmr.readonly_pmmr(), Some(&bitmap), 16, 24),
		Err(SegmentError::SegmentSizeAboveLimit)
	));
}

#[test]
fn segment_validate_accepts_large_sparse_bitmap_segment() {
	let id = SegmentIdentifier { height: 12, idx: 0 };
	let mut backend = pmmr::VecBackend::new(0);
	let mut mmr = pmmr::PMMR::new(&mut backend);
	for i in 0..(1 << 12) {
		mmr.push(&TestElem([i / 7, i / 5, i / 3, i])).unwrap();
	}
	let mmr = mmr.readonly_pmmr();
	let mmr_size = mmr.unpruned_size();
	let root = mmr.root().unwrap();

	let mut bitmap = Bitmap::new();
	bitmap.add(2_047);

	let segment = Segment::<TestElem>::from_pmmr(id, &mmr, Some(&bitmap), 16, usize::MAX).unwrap();
	let segment_root = segment.root(0, mmr_size, Some(&bitmap)).unwrap().unwrap();
	let (_first, last) = id.segment_pos_range(mmr_size).unwrap();
	assert_eq!(segment_root, mmr.get_hash(last).unwrap().unwrap());
	segment.validate(0, mmr_size, Some(&bitmap), &root).unwrap();
}

#[test]
fn segment_validate_accepts_sparse_bitmap_final_segment() {
	let id = SegmentIdentifier { height: 6, idx: 1 };
	let mut backend = pmmr::VecBackend::new(0);
	let mut mmr = pmmr::PMMR::new(&mut backend);
	for i in 0..70 {
		mmr.push(&TestElem([i / 7, i / 5, i / 3, i])).unwrap();
	}
	let mmr = mmr.readonly_pmmr();
	let mmr_size = mmr.unpruned_size();
	let root = mmr.root().unwrap();

	let mut bitmap = Bitmap::new();
	bitmap.add(68);

	let segment = Segment::<TestElem>::from_pmmr(id, &mmr, Some(&bitmap), 16, usize::MAX).unwrap();
	segment.validate(0, mmr_size, Some(&bitmap), &root).unwrap();
}

#[test]
fn segment_read_rejects_oversized_counts_before_allocation() {
	let oversized_count = ser::READ_VEC_SIZE_LIMIT + 1;

	let mut bytes = vec![0];
	bytes.extend_from_slice(&0u64.to_be_bytes());
	bytes.extend_from_slice(&oversized_count.to_be_bytes());
	match ser::deserialize_default::<Segment<TestElem>, _>(0, &mut &bytes[..]) {
		Err(ser::Error::TooLargeReadErr(msg)) => {
			assert!(msg.contains("Segment::read n_hashes"), "{}", msg);
		}
		other => panic!("expected oversized n_hashes rejection, got {:?}", other),
	}

	let mut bytes = vec![0];
	bytes.extend_from_slice(&0u64.to_be_bytes());
	bytes.extend_from_slice(&0u64.to_be_bytes());
	bytes.extend_from_slice(&oversized_count.to_be_bytes());
	match ser::deserialize_default::<Segment<TestElem>, _>(0, &mut &bytes[..]) {
		Err(ser::Error::TooLargeReadErr(msg)) => {
			assert!(msg.contains("Segment::read n_leaves"), "{}", msg);
		}
		other => panic!("expected oversized n_leaves rejection, got {:?}", other),
	}
}

#[test]
fn segment_proof_read_rejects_protocol_oversized_hash_count_before_allocation() {
	let protocol_limit = u64::from(u64::BITS) * 2 + 1;
	let mut bytes = Vec::new();
	bytes.extend_from_slice(&(protocol_limit + 1).to_be_bytes());
	match ser::deserialize_default::<SegmentProof, _>(0, &mut &bytes[..]) {
		Err(ser::Error::TooLargeReadErr(msg)) => {
			assert!(msg.contains("SegmentProof::read n_hashes"), "{}", msg);
			assert!(msg.contains("protocol limit"), "{}", msg);
		}
		other => panic!(
			"expected oversized segment proof hash count rejection, got {:?}",
			other
		),
	}
}

#[test]
fn segment_proof_read_allows_protocol_hash_count_limit() {
	let protocol_limit = u64::from(u64::BITS) * 2 + 1;
	let mut bytes = Vec::new();
	bytes.extend_from_slice(&protocol_limit.to_be_bytes());
	for _ in 0..protocol_limit {
		bytes.extend_from_slice(Hash::default().as_ref());
	}

	let proof = ser::deserialize_default::<SegmentProof, _>(0, &mut &bytes[..]).unwrap();

	assert_eq!(proof.size(), protocol_limit as usize);
}

#[test]
fn segment_validate_rejects_trailing_proof_hashes() {
	let id = SegmentIdentifier { height: 0, idx: 0 };
	let mut backend = pmmr::VecBackend::new(0);
	let mut mmr = pmmr::PMMR::new(&mut backend);
	mmr.push(&TestElem([0, 0, 0, 1])).unwrap();
	mmr.push(&TestElem([0, 0, 0, 2])).unwrap();
	let mmr = mmr.readonly_pmmr();
	let mmr_size = mmr.unpruned_size();
	let root = mmr.root().unwrap();

	let valid = Segment::<TestElem>::from_pmmr(id, &mmr, None, 1, usize::MAX).unwrap();
	valid.clone().validate(0, mmr_size, None, &root).unwrap();
	let (id, hash_pos, hashes, leaf_pos, leaf_data, proof) = valid.parts();

	let mut proof_bytes = ser::ser_vec(0, &proof, ser::ProtocolVersion(1)).unwrap();
	let proof_hashes = u64::from_be_bytes(proof_bytes[..8].try_into().unwrap());
	proof_bytes[..8].copy_from_slice(&proof_hashes.checked_add(1).unwrap().to_be_bytes());
	proof_bytes.extend_from_slice(Hash::default().as_ref());
	let proof = ser::deserialize_default::<SegmentProof, _>(0, &mut &proof_bytes[..]).unwrap();
	let segment = Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaf_data, proof).unwrap();

	assert!(matches!(
		segment.validate(0, mmr_size, None, &root),
		Err(SegmentError::GenericError(msg)) if msg.contains("trailing hash")
	));
}

#[test]
fn segment_proof_reconstruct_root_rejects_incomplete_mmr_size() {
	let proof_bytes = 0u64.to_be_bytes();
	let proof = ser::deserialize_default::<SegmentProof, _>(0, &mut &proof_bytes[..]).unwrap();

	assert!(matches!(
		proof.reconstruct_root(0, 5, 3, 3, Hash::default(), 3),
		Err(SegmentError::InvalidMMRSize {
			mmr_size: 5,
			next_height: 1
		})
	));
}

fn test_unprunable_size(height: u8, n_leaves: u32) {
	let size = 1u64 << height;
	let n_segments = (n_leaves as u64 + size - 1) / size;

	// Build an MMR with n_leaves leaves
	let mut ba = pmmr::VecBackend::new(0);
	let mut mmr = pmmr::PMMR::new(&mut ba);
	for i in 0..n_leaves {
		mmr.push(&TestElem([i / 7, i / 5, i / 3, i])).unwrap();
	}
	let mmr = mmr.readonly_pmmr();
	let last_pos = mmr.unpruned_size();
	let root = mmr.root().unwrap();

	for idx in 0..n_segments {
		let id = SegmentIdentifier { height, idx };
		let segment = Segment::<TestElem>::from_pmmr(id, &mmr, None, 1, usize::MAX).unwrap();
		println!(
			"\n\n>>>>>>> N_LEAVES = {}, LAST_POS = {}, SEGMENT = {}:\n{:#?}",
			n_leaves, last_pos, idx, segment
		);
		if idx < n_segments - 1 || (n_leaves as u64) % size == 0 {
			// Check if the reconstructed subtree root matches with the hash stored in the mmr
			let subtree_root = segment.root(0, last_pos, None).unwrap().unwrap();
			let last =
				pmmr::insertion_to_pmmr_index((idx + 1) * size - 1).unwrap() + (height as u64);
			assert_eq!(subtree_root, mmr.get_hash(last).unwrap().unwrap());
			println!(" ROOT OK");
		}
		segment.validate(0, last_pos, None, &root).unwrap();
		println!(" PROOF OK");
	}
}

#[test]
fn unprunable_mmr() {
	for i in 1..=64 {
		test_unprunable_size(3, i);
	}
}

#[test]
fn unprunable_mmr_2618() {
	test_unprunable_size(10, 2618);
}
