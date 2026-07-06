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

use crate::common::TestElem;
use mwc_core::core::hash::Hash;
use mwc_core::core::pmmr::{self, ReadablePMMR, ReadonlyPMMR, RewindablePMMR, VecBackend, PMMR};
use mwc_core::ser::PMMRIndexHashable;
use mwc_crates::croaring::Bitmap;
use std::time::Instant;

#[test]
fn some_peak_map() {
	assert_eq!(pmmr::peak_map_height(0), (0b0, 0));
	assert_eq!(pmmr::peak_map_height(1), (0b1, 0));
	assert_eq!(pmmr::peak_map_height(2), (0b1, 1));
	assert_eq!(pmmr::peak_map_height(3), (0b10, 0));
	assert_eq!(pmmr::peak_map_height(4), (0b11, 0));
	assert_eq!(pmmr::peak_map_height(5), (0b11, 1));
	assert_eq!(pmmr::peak_map_height(6), (0b11, 2));
	assert_eq!(pmmr::peak_map_height(7), (0b100, 0));
	assert_eq!(pmmr::peak_map_height(u64::MAX), ((u64::MAX >> 1) + 1, 0));
	assert_eq!(pmmr::peak_map_height(u64::MAX - 1), (u64::MAX >> 1, 63));
}

#[ignore]
#[test]
fn bench_peak_map() {
	let increments = vec![1_000_000u64, 10_000_000u64, 100_000_000u64];

	for v in increments {
		let start = Instant::now();
		for i in 0..v {
			let _ = pmmr::peak_map_height(i);
		}
		let dur_ms = start.elapsed().as_secs_f64() * 1000.0;
		println!("{:9?} peak_map_height() in {:9.3?}ms", v, dur_ms);
	}
}

#[test]
fn some_peak_size() {
	assert_eq!(pmmr::peak_sizes_height(0), (vec![], 0));
	assert_eq!(pmmr::peak_sizes_height(1), (vec![1], 0));
	assert_eq!(pmmr::peak_sizes_height(2), (vec![1], 1));
	assert_eq!(pmmr::peak_sizes_height(3), (vec![3], 0));
	assert_eq!(pmmr::peak_sizes_height(4), (vec![3, 1], 0));
	assert_eq!(pmmr::peak_sizes_height(5), (vec![3, 1], 1));
	assert_eq!(pmmr::peak_sizes_height(6), (vec![3, 1], 2));
	assert_eq!(pmmr::peak_sizes_height(7), (vec![7], 0));
	assert_eq!(pmmr::peak_sizes_height(u64::MAX), (vec![u64::MAX], 0));

	let size_of_peaks = (1..64).map(|i| u64::MAX >> i).collect::<Vec<u64>>();
	assert_eq!(pmmr::peak_sizes_height(u64::MAX - 1), (size_of_peaks, 63));
}

#[test]
fn rewind_rejects_forward_position_without_resizing() {
	let elem = TestElem([0, 0, 0, 1]);
	let mut backend = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut backend);
	pmmr.push(&elem).unwrap();
	let size = pmmr.unpruned_size();
	let root = pmmr.root().unwrap();

	match pmmr.rewind(3, &Bitmap::new()) {
		Err(pmmr::Error::InvalidState(msg)) => {
			assert!(
				msg.contains("cannot rewind PMMR forward"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected forward rewind rejection, got {:?}", other),
	}

	assert_eq!(pmmr.unpruned_size(), size);
	assert_eq!(pmmr.root().unwrap(), root);
}

#[test]
fn rewindable_pmmr_rejects_forward_rewind() {
	let backend = VecBackend::<TestElem>::new(0);
	let mut pmmr = RewindablePMMR::at(&backend, 4);

	match pmmr.rewind(5) {
		Err(pmmr::Error::InvalidState(msg)) => {
			assert!(
				msg.contains("cannot rewind PMMR forward"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected forward rewind rejection, got {:?}", other),
	}

	assert_eq!(pmmr.as_readonly().unpruned_size(), 4);
	pmmr.rewind(3).unwrap();
	assert_eq!(pmmr.as_readonly().unpruned_size(), 3);
}

#[test]
fn get_hash_rejects_missing_non_compacted_internal_hash() {
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	backend.hashes = vec![Some(Hash::default()), Some(Hash::default()), None];

	let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, 3);
	match pmmr.get_hash(2) {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(msg.contains("Missing non-compacted PMMR hash"));
		}
		other => panic!("expected missing internal hash rejection, got {:?}", other),
	}

	let readonly = pmmr.readonly_pmmr();
	match readonly.get_hash(2) {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(msg.contains("Missing non-compacted PMMR hash"));
		}
		other => panic!(
			"expected readonly missing internal hash rejection, got {:?}",
			other
		),
	}
}

#[test]
fn readonly_get_data_from_file_returns_none_for_internal_node() {
	let elem_1 = TestElem([0, 0, 0, 1]);
	let elem_2 = TestElem([0, 0, 0, 2]);
	let mut backend = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut backend);
	pmmr.push(&elem_1).unwrap();
	pmmr.push(&elem_2).unwrap();

	let readonly = pmmr.readonly_pmmr();
	assert_eq!(readonly.get_data_from_file(2).unwrap(), None);
}

#[test]
#[allow(unused_variables)]
fn first_100_mmr_heights() {
	let first_100_str = "0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 4 \
	                     0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 4 5 \
	                     0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 0 0 1 0 0 1 2 0 0 1 0 0 1 2 3 4 0 0 1 0 0";
	let first_100 = first_100_str.split(' ').map(|n| n.parse::<u64>().unwrap());
	let mut count = 0;
	for n in first_100 {
		assert_eq!(
			n,
			pmmr::bintree_postorder_height(count),
			"expected {}, got {}",
			n,
			pmmr::bintree_postorder_height(count)
		);
		count += 1;
	}
}

#[test]
fn test_bintree_range() {
	assert_eq!(pmmr::bintree_range(0).unwrap(), 0..1);
	assert_eq!(pmmr::bintree_range(1).unwrap(), 1..2);
	assert_eq!(pmmr::bintree_range(2).unwrap(), 0..3);
	assert_eq!(pmmr::bintree_range(3).unwrap(), 3..4);
	assert_eq!(pmmr::bintree_range(4).unwrap(), 4..5);
	assert_eq!(pmmr::bintree_range(5).unwrap(), 3..6);
	assert_eq!(pmmr::bintree_range(6).unwrap(), 0..7);
	assert_eq!(pmmr::bintree_range(u64::MAX - 1).unwrap(), 0..u64::MAX);
}

// The pos of the rightmost leaf for the provided MMR size (last leaf in subtree).
#[test]
fn test_bintree_rightmost() {
	assert_eq!(pmmr::bintree_rightmost(0).unwrap(), 0);
	assert_eq!(pmmr::bintree_rightmost(1).unwrap(), 1);
	assert_eq!(pmmr::bintree_rightmost(2).unwrap(), 1);
	assert_eq!(pmmr::bintree_rightmost(3).unwrap(), 3);
	assert_eq!(pmmr::bintree_rightmost(4).unwrap(), 4);
	assert_eq!(pmmr::bintree_rightmost(5).unwrap(), 4);
	assert_eq!(pmmr::bintree_rightmost(6).unwrap(), 4);
}

// The pos of the leftmost leaf for the provided MMR size (first leaf in subtree).
#[test]
fn test_bintree_leftmost() {
	assert_eq!(pmmr::bintree_leftmost(0).unwrap(), 0);
	assert_eq!(pmmr::bintree_leftmost(1).unwrap(), 1);
	assert_eq!(pmmr::bintree_leftmost(2).unwrap(), 0);
	assert_eq!(pmmr::bintree_leftmost(3).unwrap(), 3);
	assert_eq!(pmmr::bintree_leftmost(4).unwrap(), 4);
	assert_eq!(pmmr::bintree_leftmost(5).unwrap(), 3);
	assert_eq!(pmmr::bintree_leftmost(6).unwrap(), 0);
	assert_eq!(pmmr::bintree_leftmost(u64::MAX - 1).unwrap(), 0);
}

#[test]
fn test_bintree_leaf_pos_iter() {
	assert_eq!(
		pmmr::bintree_leaf_pos_iter(0)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>(),
		[0]
	);
	assert_eq!(
		pmmr::bintree_leaf_pos_iter(1)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>(),
		[1]
	);
	assert_eq!(
		pmmr::bintree_leaf_pos_iter(2)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>(),
		[0, 1]
	);
	assert_eq!(
		pmmr::bintree_leaf_pos_iter(3)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>(),
		[3]
	);
	assert_eq!(
		pmmr::bintree_leaf_pos_iter(4)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>(),
		[4]
	);
	assert_eq!(
		pmmr::bintree_leaf_pos_iter(5)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>(),
		[3, 4]
	);
	assert_eq!(
		pmmr::bintree_leaf_pos_iter(6)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>(),
		[0, 1, 3, 4]
	);
}

#[test]
fn test_bintree_pos_iter() {
	assert_eq!(pmmr::bintree_pos_iter(0).unwrap().collect::<Vec<_>>(), [0]);
	assert_eq!(pmmr::bintree_pos_iter(1).unwrap().collect::<Vec<_>>(), [1]);
	assert_eq!(
		pmmr::bintree_pos_iter(2).unwrap().collect::<Vec<_>>(),
		[0, 1, 2]
	);
	assert_eq!(pmmr::bintree_pos_iter(3).unwrap().collect::<Vec<_>>(), [3]);
	assert_eq!(pmmr::bintree_pos_iter(4).unwrap().collect::<Vec<_>>(), [4]);
	assert_eq!(
		pmmr::bintree_pos_iter(5).unwrap().collect::<Vec<_>>(),
		[3, 4, 5]
	);
	assert_eq!(
		pmmr::bintree_pos_iter(6).unwrap().collect::<Vec<_>>(),
		[0, 1, 2, 3, 4, 5, 6]
	);
}

#[test]
fn test_is_leaf() {
	assert_eq!(pmmr::is_leaf(0), true);
	assert_eq!(pmmr::is_leaf(1), true);
	assert_eq!(pmmr::is_leaf(2), false);
	assert_eq!(pmmr::is_leaf(3), true);
	assert_eq!(pmmr::is_leaf(4), true);
	assert_eq!(pmmr::is_leaf(5), false);
	assert_eq!(pmmr::is_leaf(6), false);
}

#[test]
fn test_pmmr_leaf_to_insertion_index() {
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(0), Some(0));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(1), Some(1));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(3), Some(2));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(4), Some(3));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(7), Some(4));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(8), Some(5));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(10), Some(6));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(11), Some(7));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(15), Some(8));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(16), Some(9));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(18), Some(10));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(19), Some(11));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(22), Some(12));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(23), Some(13));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(25), Some(14));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(26), Some(15));
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(31), Some(16));

	// Not a leaf node
	assert_eq!(pmmr::pmmr_leaf_to_insertion_index(30), None);

	// Sanity check to make sure we don't get an explosion around the u64 max
	// number of leaves
	let n_leaves_max_u64 = pmmr::n_leaves(u64::MAX - 257).unwrap();
	assert_eq!(
		pmmr::pmmr_leaf_to_insertion_index(n_leaves_max_u64),
		Some(4611686018427387884)
	);
}

#[test]
fn test_n_leaves() {
	// make sure we handle an empty MMR correctly
	assert_eq!(pmmr::n_leaves(0).unwrap(), 0);
	// and various sizes on non-empty MMRs
	assert_eq!(pmmr::n_leaves(1).unwrap(), 1);
	assert_eq!(pmmr::n_leaves(2).unwrap(), 2);
	assert_eq!(pmmr::n_leaves(3).unwrap(), 2);
	assert_eq!(pmmr::n_leaves(4).unwrap(), 3);
	assert_eq!(pmmr::n_leaves(5).unwrap(), 4);
	assert_eq!(pmmr::n_leaves(6).unwrap(), 4);
	assert_eq!(pmmr::n_leaves(7).unwrap(), 4);
	assert_eq!(pmmr::n_leaves(8).unwrap(), 5);
	assert_eq!(pmmr::n_leaves(9).unwrap(), 6);
	assert_eq!(pmmr::n_leaves(10).unwrap(), 6);
}

#[test]
fn test_round_up_to_leaf_pos() {
	assert_eq!(pmmr::round_up_to_leaf_pos(0).unwrap(), 0);
	assert_eq!(pmmr::round_up_to_leaf_pos(1).unwrap(), 1);
	assert_eq!(pmmr::round_up_to_leaf_pos(2).unwrap(), 3);
	assert_eq!(pmmr::round_up_to_leaf_pos(3).unwrap(), 3);
	assert_eq!(pmmr::round_up_to_leaf_pos(4).unwrap(), 4);
	assert_eq!(pmmr::round_up_to_leaf_pos(5).unwrap(), 7);
	assert_eq!(pmmr::round_up_to_leaf_pos(6).unwrap(), 7);
	assert_eq!(pmmr::round_up_to_leaf_pos(7).unwrap(), 7);
	assert_eq!(pmmr::round_up_to_leaf_pos(8).unwrap(), 8);
	assert_eq!(pmmr::round_up_to_leaf_pos(9).unwrap(), 10);
	assert_eq!(pmmr::round_up_to_leaf_pos(10).unwrap(), 10);
}

/// Find parent and sibling positions for various node positions.
#[test]
fn various_families() {
	// 0 0 1 0 0 1 2 0 0 1 0 0 1 2 3
	assert_eq!(pmmr::family(0).unwrap(), (2, 1));
	assert_eq!(pmmr::family(1).unwrap(), (2, 0));
	assert_eq!(pmmr::family(2).unwrap(), (6, 5));
	assert_eq!(pmmr::family(3).unwrap(), (5, 4));
	assert_eq!(pmmr::family(4).unwrap(), (5, 3));
	assert_eq!(pmmr::family(5).unwrap(), (6, 2));
	assert_eq!(pmmr::family(6).unwrap(), (14, 13));
	assert_eq!(pmmr::family(999).unwrap(), (1_000, 996));
}

#[test]
fn test_is_left_sibling() {
	assert_eq!(pmmr::is_left_sibling(0).unwrap(), true);
	assert_eq!(pmmr::is_left_sibling(1).unwrap(), false);
	assert_eq!(pmmr::is_left_sibling(2).unwrap(), true);
}

#[test]
fn various_branches() {
	assert!(matches!(
		pmmr::family_branch(0, 0),
		Err(pmmr::Error::InvalidState(_))
	));
	assert!(matches!(
		pmmr::family_branch(4, 4),
		Err(pmmr::Error::InvalidState(_))
	));
	assert!(matches!(
		pmmr::family_branch(5, 4),
		Err(pmmr::Error::InvalidState(_))
	));

	// the two leaf nodes in a 3 node tree (height 1)
	assert_eq!(pmmr::family_branch(0, 3).unwrap(), [(2, 1)]);
	assert_eq!(pmmr::family_branch(1, 3).unwrap(), [(2, 0)]);

	// the root node in a 3 node tree
	assert_eq!(pmmr::family_branch(2, 3).unwrap(), []);

	// leaf node in a larger tree of 7 nodes (height 2)
	assert_eq!(pmmr::family_branch(0, 7).unwrap(), [(2, 1), (6, 5)]);

	// note these only go as far up as the local peak, not necessarily the single
	// root
	assert_eq!(pmmr::family_branch(0, 4).unwrap(), [(2, 1)]);
	// pos 4 in a tree of size 4 is a local peak
	assert_eq!(pmmr::family_branch(3, 4).unwrap(), []);
	// pos 4 in a tree of size 5 is also still a local peak
	assert_eq!(pmmr::family_branch(3, 5).unwrap(), []);
	// pos 4 in a tree of size 6 has a parent and a sibling
	assert_eq!(pmmr::family_branch(3, 6).unwrap(), [(5, 4)]);
	// a tree of size 7 is all under a single root
	assert_eq!(pmmr::family_branch(3, 7).unwrap(), [(5, 4), (6, 2)]);

	// ok now for a more realistic one, a tree with over a million nodes in it
	// find the "family path" back up the tree from a leaf node at 0
	// Note: the first two entries in the branch are consistent with a small 7 node
	// tree Note: each sibling is on the left branch, this is an example of the
	// largest possible list of peaks before we start combining them into larger
	// peaks.
	assert_eq!(
		pmmr::family_branch(0, 1_049_000).unwrap(),
		[
			(2, 1),
			(6, 5),
			(14, 13),
			(30, 29),
			(62, 61),
			(126, 125),
			(254, 253),
			(510, 509),
			(1022, 1021),
			(2046, 2045),
			(4094, 4093),
			(8190, 8189),
			(16382, 16381),
			(32766, 32765),
			(65534, 65533),
			(131070, 131069),
			(262142, 262141),
			(524286, 524285),
			(1048574, 1048573),
		]
	);
}

#[test]
fn some_peaks() {
	// 0 0 1 0 0 1 2 0 0 1 0 0 1 2 3

	let empty: Vec<u64> = vec![];

	// make sure we handle an empty MMR correctly
	assert_eq!(pmmr::peaks(0).unwrap(), empty);

	// and various non-empty MMRs
	assert_eq!(pmmr::peaks(1).unwrap(), [0]);
	assert_eq!(pmmr::peaks(2).unwrap(), empty);
	assert_eq!(pmmr::peaks(3).unwrap(), [2]);
	assert_eq!(pmmr::peaks(4).unwrap(), [2, 3]);
	assert_eq!(pmmr::peaks(5).unwrap(), empty);
	assert_eq!(pmmr::peaks(6).unwrap(), empty);
	assert_eq!(pmmr::peaks(7).unwrap(), [6]);
	assert_eq!(pmmr::peaks(8).unwrap(), [6, 7]);
	assert_eq!(pmmr::peaks(9).unwrap(), empty);
	assert_eq!(pmmr::peaks(10).unwrap(), [6, 9]);
	assert_eq!(pmmr::peaks(11).unwrap(), [6, 9, 10]);
	assert_eq!(pmmr::peaks(22).unwrap(), [14, 21]);
	assert_eq!(pmmr::peaks(32).unwrap(), [30, 31]);
	assert_eq!(pmmr::peaks(35).unwrap(), [30, 33, 34]);
	assert_eq!(pmmr::peaks(42).unwrap(), [30, 37, 40, 41]);

	// large realistic example with almost 1.5 million nodes
	// note the distance between peaks decreases toward the right (trees get
	// smaller)
	assert_eq!(
		pmmr::peaks(1048555).unwrap(),
		[
			524286, 786429, 917500, 983035, 1015802, 1032185, 1040376, 1044471, 1046518, 1047541,
			1048052, 1048307, 1048434, 1048497, 1048528, 1048543, 1048550, 1048553, 1048554,
		],
	);
}

#[test]
fn bag_the_rhs_rejects_missing_rhs_peak() {
	let backend = VecBackend::<TestElem>::new(0);
	let readonly = ReadonlyPMMR::at(&backend, 4);

	match readonly.bag_the_rhs(2) {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(
				msg.contains("Missing RHS PMMR peak hash at position 3"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected missing RHS peak hash rejection, got {:?}", other),
	}
}

#[test]
fn peaks_rejects_missing_peak_hash() {
	let backend = VecBackend::<TestElem>::new(0);
	let readonly = ReadonlyPMMR::at(&backend, 4);

	match readonly.peaks() {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(
				msg.contains("Missing PMMR peak hash at position 2"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected missing peak hash rejection, got {:?}", other),
	}
}

#[test]
fn peak_path_rejects_missing_left_peak() {
	let backend = VecBackend::<TestElem>::new(0);
	let readonly = ReadonlyPMMR::at(&backend, 4);

	match readonly.peak_path(3) {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(
				msg.contains("Missing left PMMR peak hash at position 2"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected missing left peak hash rejection, got {:?}", other),
	}
}

#[test]
fn merkle_proof_rejects_missing_branch_sibling() {
	let elem = TestElem([0, 0, 0, 1]);
	let mut backend = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut backend);
	pmmr.push(&elem).unwrap();
	drop(pmmr);

	let readonly = ReadonlyPMMR::at(&backend, 3);
	match readonly.merkle_proof(0) {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(
				msg.contains("Missing PMMR branch sibling hash at position 1"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected missing branch sibling rejection, got {:?}", other),
	}
}

#[test]
fn get_data_from_file_returns_none_for_internal_node() {
	let elems = [TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])];
	let mut backend = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut backend);
	pmmr.push(&elems[0]).unwrap();
	pmmr.push(&elems[1]).unwrap();

	assert_eq!(pmmr.unpruned_size(), 3);
	assert_eq!(pmmr.get_data_from_file(0).unwrap(), Some(elems[0]));
	assert_eq!(pmmr.get_data_from_file(1).unwrap(), Some(elems[1]));
	assert_eq!(pmmr.get_data_from_file(2).unwrap(), None);
}

#[test]
fn push_pruned_subtree_leaf_advances_size() {
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	let mut pmmr = PMMR::new(&mut backend);

	pmmr.push_pruned_subtree(Hash::from_vec(&[9]), 0).unwrap();

	assert_eq!(pmmr.unpruned_size(), 1);
}

#[test]
fn push_pruned_subtree_combines_with_left_sibling() {
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	let mut pmmr = PMMR::new(&mut backend);
	let left_hash = Hash::from_vec(&[1]);
	let right_hash = Hash::from_vec(&[2]);

	pmmr.push_pruned_subtree(left_hash, 0).unwrap();
	pmmr.push_pruned_subtree(right_hash, 1).unwrap();

	assert_eq!(pmmr.unpruned_size(), 3);
	assert_eq!(
		pmmr.root().unwrap(),
		(left_hash, right_hash).hash_with_index(0, 2).unwrap()
	);
}

#[test]
fn push_pruned_subtree_rejects_gap_without_mutating_backend() {
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		match pmmr.push_pruned_subtree(Hash::from_vec(&[9]), 3) {
			Err(pmmr::Error::InvalidState(msg)) => {
				assert!(msg.contains("not contiguous"), "unexpected error: {}", msg);
			}
			other => panic!("expected non-contiguous subtree rejection, got {:?}", other),
		}
		assert_eq!(pmmr.unpruned_size(), 0);
	}

	assert_eq!(backend.size(), 0);
}

#[test]
fn push_pruned_subtree_does_not_mutate_backend_on_parent_construction_error() {
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	{
		let mut pmmr = PMMR::at(&mut backend, 4);
		match pmmr.push_pruned_subtree(Hash::from_vec(&[9]), 4) {
			Err(pmmr::Error::SerializationError(msg)) => {
				assert!(
					msg.contains("missing left sibling"),
					"unexpected error: {}",
					msg
				);
			}
			other => panic!("expected missing sibling rejection, got {:?}", other),
		}
		assert_eq!(pmmr.unpruned_size(), 4);
	}

	assert_eq!(backend.size(), 0);
}

#[test]
fn validate_rejects_parent_with_one_missing_child() {
	let left = Hash::from_vec(&[1]);
	let right = Hash::from_vec(&[2]);
	let parent = (left, right).hash_with_index(0, 2).unwrap();
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	backend.hashes = vec![Some(left), None, Some(parent)];
	let pmmr = PMMR::at(&mut backend, 3);

	match pmmr.validate() {
		Err(pmmr::Error::DataCorruption(_)) => {}
		other => panic!("expected validation rejection, got {:?}", other),
	}
}

#[test]
fn validate_rejects_incomplete_mmr_size_boundary() {
	for size in [2, 5] {
		let mut backend = VecBackend::<TestElem>::new_hash_only(0);
		backend
			.hashes
			.resize(size as usize, Some(Hash::from_vec(&[1])));
		let pmmr = PMMR::at(&mut backend, size);

		match pmmr.validate() {
			Err(pmmr::Error::DataCorruption(msg)) => {
				assert!(
					msg.contains("incomplete subtree boundary"),
					"unexpected error: {}",
					msg
				);
			}
			other => panic!("expected invalid size boundary rejection, got {:?}", other),
		}
	}
}

#[test]
fn validate_rejects_missing_internal_parent_hash() {
	let left = Hash::from_vec(&[1]);
	let right = Hash::from_vec(&[2]);
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	backend.hashes = vec![Some(left), Some(right), None];
	let pmmr = PMMR::at(&mut backend, 3);

	match pmmr.validate() {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(
				msg.contains("missing parent hash")
					|| msg.contains("Missing non-compacted PMMR hash")
					|| msg.contains("missing peak hash"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected missing parent rejection, got {:?}", other),
	}
}

#[test]
fn validate_rejects_missing_leaf_peak_hash() {
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	backend.hashes = vec![None];
	let pmmr = PMMR::at(&mut backend, 1);

	match pmmr.validate() {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(
				msg.contains("missing peak hash"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected missing leaf peak rejection, got {:?}", other),
	}
}

#[test]
fn validate_rejects_missing_rightmost_leaf_peak_hash() {
	let left = Hash::from_vec(&[1]);
	let right = Hash::from_vec(&[2]);
	let parent = (left, right).hash_with_index(0, 2).unwrap();
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	backend.hashes = vec![Some(left), Some(right), Some(parent), None];
	let pmmr = PMMR::at(&mut backend, 4);

	match pmmr.validate() {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(
				msg.contains("missing peak hash"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!(
			"expected missing rightmost leaf peak rejection, got {:?}",
			other
		),
	}
}

#[test]
fn validate_rejects_parent_with_two_unexpected_missing_children() {
	let left = Hash::from_vec(&[1]);
	let right = Hash::from_vec(&[2]);
	let parent = (left, right).hash_with_index(0, 2).unwrap();
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	backend.hashes = vec![None, None, Some(parent)];
	let pmmr = PMMR::at(&mut backend, 3);

	match pmmr.validate() {
		Err(pmmr::Error::DataCorruption(_)) => {}
		other => panic!("expected validation rejection, got {:?}", other),
	}
}

#[test]
fn validate_rejects_leaf_data_hash_mismatch() {
	let elems = [TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])];
	let mut backend = VecBackend::new(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		pmmr.push(&elems[0]).unwrap();
		pmmr.push(&elems[1]).unwrap();
		pmmr.validate().unwrap();
	}

	backend.data.as_mut().unwrap()[1] = Some(TestElem([9, 9, 9, 9]));
	let pmmr = PMMR::at(&mut backend, 3);

	match pmmr.validate() {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(
				msg.contains("data hash does not match stored hash"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!(
			"expected leaf data hash mismatch rejection, got {:?}",
			other
		),
	}
}

#[test]
fn validate_rejects_missing_non_compacted_leaf_data() {
	let elem = TestElem([0, 0, 0, 1]);
	let mut backend = VecBackend::new(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		pmmr.push(&elem).unwrap();
		pmmr.validate().unwrap();
	}

	backend.data.as_mut().unwrap()[0] = None;
	let pmmr = PMMR::at(&mut backend, 1);

	match pmmr.validate() {
		Err(pmmr::Error::DataCorruption(msg)) => {
			assert!(
				msg.contains("missing leaf data for hash"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected missing leaf data rejection, got {:?}", other),
	}
}

#[test]
fn validate_allows_compacted_leaves() {
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	let mut pmmr = PMMR::new(&mut backend);

	pmmr.push_pruned_subtree(Hash::from_vec(&[1]), 2).unwrap();

	pmmr.validate().unwrap();
}

#[test]
#[allow(unused_variables)]
fn pmmr_push_root() {
	let elems = [
		TestElem([0, 0, 0, 1]),
		TestElem([0, 0, 0, 2]),
		TestElem([0, 0, 0, 3]),
		TestElem([0, 0, 0, 4]),
		TestElem([0, 0, 0, 5]),
		TestElem([0, 0, 0, 6]),
		TestElem([0, 0, 0, 7]),
		TestElem([0, 0, 0, 8]),
		TestElem([1, 0, 0, 0]),
	];

	let mut ba = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut ba);

	// one element
	pmmr.push(&elems[0]).unwrap();
	pmmr.dump(false).unwrap();
	let pos_0 = elems[0].hash_with_index(0, 0).unwrap();
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_0]);
	assert_eq!(pmmr.root().unwrap(), pos_0);
	assert_eq!(pmmr.unpruned_size(), 1);

	// two elements
	pmmr.push(&elems[1]).unwrap();
	pmmr.dump(false).unwrap();
	let pos_1 = elems[1].hash_with_index(0, 1).unwrap();
	let pos_2 = (pos_0, pos_1).hash_with_index(0, 2).unwrap();
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_2]);
	assert_eq!(pmmr.root().unwrap(), pos_2);
	assert_eq!(pmmr.unpruned_size(), 3);

	// three elements
	pmmr.push(&elems[2]).unwrap();
	pmmr.dump(false).unwrap();
	let pos_3 = elems[2].hash_with_index(0, 3).unwrap();
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_2, pos_3]);
	assert_eq!(
		pmmr.root().unwrap(),
		(pos_2, pos_3).hash_with_index(0, 4).unwrap()
	);
	assert_eq!(pmmr.unpruned_size(), 4);

	// four elements
	pmmr.push(&elems[3]).unwrap();
	pmmr.dump(false).unwrap();
	let pos_4 = elems[3].hash_with_index(0, 4).unwrap();
	let pos_5 = (pos_3, pos_4).hash_with_index(0, 5).unwrap();
	let pos_6 = (pos_2, pos_5).hash_with_index(0, 6).unwrap();
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_6]);
	assert_eq!(pmmr.root().unwrap(), pos_6);
	assert_eq!(pmmr.unpruned_size(), 7);

	// five elements
	pmmr.push(&elems[4]).unwrap();
	pmmr.dump(false).unwrap();
	let pos_7 = elems[4].hash_with_index(0, 7).unwrap();
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_6, pos_7]);
	assert_eq!(
		pmmr.root().unwrap(),
		(pos_6, pos_7).hash_with_index(0, 8).unwrap()
	);
	assert_eq!(pmmr.unpruned_size(), 8);

	// six elements
	pmmr.push(&elems[5]).unwrap();
	let pos_8 = elems[5].hash_with_index(0, 8).unwrap();
	let pos_9 = (pos_7, pos_8).hash_with_index(0, 9).unwrap();
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_6, pos_9]);
	assert_eq!(
		pmmr.root().unwrap(),
		(pos_6, pos_9).hash_with_index(0, 10).unwrap()
	);
	assert_eq!(pmmr.unpruned_size(), 10);

	// seven elements
	pmmr.push(&elems[6]).unwrap();
	let pos_10 = elems[6].hash_with_index(0, 10).unwrap();
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_6, pos_9, pos_10]);
	assert_eq!(
		pmmr.root().unwrap(),
		(pos_6, (pos_9, pos_10).hash_with_index(0, 11).unwrap())
			.hash_with_index(0, 11)
			.unwrap()
	);
	assert_eq!(pmmr.unpruned_size(), 11);

	// 001001200100123
	// eight elements
	pmmr.push(&elems[7]).unwrap();
	let pos_11 = elems[7].hash_with_index(0, 11).unwrap();
	let pos_12 = (pos_10, pos_11).hash_with_index(0, 12).unwrap();
	let pos_13 = (pos_9, pos_12).hash_with_index(0, 13).unwrap();
	let pos_14 = (pos_6, pos_13).hash_with_index(0, 14).unwrap();
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_14]);
	assert_eq!(pmmr.root().unwrap(), pos_14);
	assert_eq!(pmmr.unpruned_size(), 15);

	// nine elements
	pmmr.push(&elems[8]).unwrap();
	let pos_15 = elems[8].hash_with_index(0, 15).unwrap();
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_14, pos_15]);
	assert_eq!(
		pmmr.root().unwrap(),
		(pos_14, pos_15).hash_with_index(0, 16).unwrap()
	);
	assert_eq!(pmmr.unpruned_size(), 16);
}

#[test]
fn pmmr_get_last_n_insertions() {
	let elems = [
		TestElem([0, 0, 0, 1]),
		TestElem([0, 0, 0, 2]),
		TestElem([0, 0, 0, 3]),
		TestElem([0, 0, 0, 4]),
		TestElem([0, 0, 0, 5]),
		TestElem([0, 0, 0, 6]),
		TestElem([0, 0, 0, 7]),
		TestElem([0, 0, 0, 8]),
		TestElem([1, 0, 0, 0]),
	];

	let mut ba = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut ba);

	// test when empty
	let res = pmmr.readonly_pmmr().get_last_n_insertions(19).unwrap();
	assert!(res.is_empty());

	pmmr.push(&elems[0]).unwrap();
	let res = pmmr.readonly_pmmr().get_last_n_insertions(19).unwrap();
	assert!(res.len() == 1);

	pmmr.push(&elems[1]).unwrap();

	let res = pmmr.readonly_pmmr().get_last_n_insertions(12).unwrap();
	assert!(res.len() == 2);

	pmmr.push(&elems[2]).unwrap();

	let res = pmmr.readonly_pmmr().get_last_n_insertions(2).unwrap();
	assert!(res.len() == 2);

	pmmr.push(&elems[3]).unwrap();

	let res = pmmr.readonly_pmmr().get_last_n_insertions(19).unwrap();
	assert!(res.len() == 4);

	pmmr.push(&elems[5]).unwrap();
	pmmr.push(&elems[6]).unwrap();
	pmmr.push(&elems[7]).unwrap();
	pmmr.push(&elems[8]).unwrap();

	let res = pmmr.readonly_pmmr().get_last_n_insertions(7).unwrap();
	assert!(res.len() == 7);
}

#[test]
#[allow(unused_variables)]
fn pmmr_prune() {
	let elems = [
		TestElem([0, 0, 0, 1]),
		TestElem([0, 0, 0, 2]),
		TestElem([0, 0, 0, 3]),
		TestElem([0, 0, 0, 4]),
		TestElem([0, 0, 0, 5]),
		TestElem([0, 0, 0, 6]),
		TestElem([0, 0, 0, 7]),
		TestElem([0, 0, 0, 8]),
		TestElem([1, 0, 0, 0]),
	];

	let orig_root: Hash;
	let sz: u64;
	let mut ba = VecBackend::new(0);
	{
		let mut pmmr = PMMR::new(&mut ba);
		for elem in &elems[..] {
			pmmr.push(elem).unwrap();
		}
		orig_root = pmmr.root().unwrap();
		sz = pmmr.unpruned_size();
	}

	// First check the initial numbers of elements.
	assert_eq!(ba.hashes.len(), 16);

	// pruning a leaf with no parent should do nothing
	{
		let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut ba, sz);
		pmmr.prune(15).unwrap();
		assert_eq!(orig_root, pmmr.root().unwrap());
	}
	assert_eq!(ba.hashes.len(), 16);

	// pruning leaves with no shared parent just removes 1 element
	{
		let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut ba, sz);
		pmmr.prune(1).unwrap();
		assert_eq!(orig_root, pmmr.root().unwrap());
	}
	assert_eq!(ba.hashes.len(), 16);

	{
		let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut ba, sz);
		pmmr.prune(3).unwrap();
		assert_eq!(orig_root, pmmr.root().unwrap());
	}
	assert_eq!(ba.hashes.len(), 16);

	// pruning a non-leaf node has no effect
	{
		let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut ba, sz);
		pmmr.prune(2).unwrap_err();
		assert_eq!(orig_root, pmmr.root().unwrap());
	}
	assert_eq!(ba.hashes.len(), 16);

	// TODO - no longer true (leaves only now) - pruning sibling removes subtree
	{
		let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut ba, sz);
		pmmr.prune(4).unwrap();
		assert_eq!(orig_root, pmmr.root().unwrap());
	}
	assert_eq!(ba.hashes.len(), 16);

	// TODO - no longer true (leaves only now) - pruning all leaves under level >1
	// removes all subtree
	{
		let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut ba, sz);
		pmmr.prune(0).unwrap();
		assert_eq!(orig_root, pmmr.root().unwrap());
	}
	assert_eq!(ba.hashes.len(), 16);

	// pruning everything should only leave us with a single peak
	{
		let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut ba, sz);
		for n in 0..15 {
			let _ = pmmr.prune(n);
		}
		assert_eq!(orig_root, pmmr.root().unwrap());
	}
	assert_eq!(ba.hashes.len(), 16);
}

#[test]
fn prune_rejects_out_of_range_leaf_without_mutating_backend() {
	let elem = TestElem([0, 0, 0, 1]);
	let mut backend = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut backend);
	pmmr.push(&elem).unwrap();
	let root = pmmr.root().unwrap();

	match pmmr.prune(1) {
		Err(pmmr::Error::InvalidState(msg)) => {
			assert!(
				msg.contains("outside PMMR size"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected out-of-range prune rejection, got {:?}", other),
	}

	assert_eq!(pmmr.unpruned_size(), 1);
	assert_eq!(pmmr.root().unwrap(), root);
	assert_eq!(pmmr.get_hash(0).unwrap(), Some(root));
}

#[test]
fn check_insertion_to_pmmr_index() {
	assert_eq!(pmmr::insertion_to_pmmr_index(0).unwrap(), 0);
	assert_eq!(pmmr::insertion_to_pmmr_index(1).unwrap(), 1);
	assert_eq!(pmmr::insertion_to_pmmr_index(2).unwrap(), 3);
	assert_eq!(pmmr::insertion_to_pmmr_index(3).unwrap(), 4);
	assert_eq!(pmmr::insertion_to_pmmr_index(4).unwrap(), 7);
	assert_eq!(pmmr::insertion_to_pmmr_index(5).unwrap(), 8);
	assert_eq!(pmmr::insertion_to_pmmr_index(6).unwrap(), 10);
	assert_eq!(pmmr::insertion_to_pmmr_index(7).unwrap(), 11);
}

#[test]
fn check_elements_from_pmmr_index() {
	let mut ba = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut ba);
	// 20 elements should give max index 38
	for x in 1..21 {
		pmmr.push(&TestElem([0, 0, 0, x])).unwrap();
	}

	// Normal case
	let res = pmmr
		.readonly_pmmr()
		.elements_from_pmmr_index(1, 1000, None)
		.unwrap();
	assert_eq!(res.0, 38);
	assert_eq!(res.1.len(), 20);
	assert_eq!(res.1[0].0, pmmr::insertion_to_pmmr_index(1).unwrap());
	assert_eq!((res.1[0].1).0[3], 1);
	assert_eq!(res.1[19].0, 36);
	assert_eq!((res.1[19].1).0[3], 20);

	// Oversized upper bounds are clamped to the PMMR view size.
	let res = pmmr
		.readonly_pmmr()
		.elements_from_pmmr_index(1, 1000, Some(u64::MAX))
		.unwrap();
	assert_eq!(res.0, 38);
	assert_eq!(res.1.len(), 20);

	let res = pmmr
		.readonly_pmmr()
		.elements_from_pmmr_index(1000, 1000, Some(u64::MAX))
		.unwrap();
	assert_eq!(res.0, 999);
	assert!(res.1.is_empty());

	// middle of pack
	let res = pmmr
		.readonly_pmmr()
		.elements_from_pmmr_index(8, 1000, Some(34))
		.unwrap();
	assert_eq!(res.0, 34);
	assert_eq!(res.1.len(), 14);
	assert_eq!((res.1[0].1).0[3], 5);
	assert_eq!((res.1[13].1).0[3], 18);

	// bounded
	let res = pmmr
		.readonly_pmmr()
		.elements_from_pmmr_index(8, 7, Some(34))
		.unwrap();
	assert_eq!(res.0, 19);
	assert_eq!(res.1.len(), 7);
	assert_eq!((res.1[0].1).0[3], 5);
	assert_eq!((res.1[6].1).0[3], 11);

	// pruning a few nodes should get consistent results
	pmmr.prune(pmmr::insertion_to_pmmr_index(4).unwrap())
		.unwrap();
	pmmr.prune(pmmr::insertion_to_pmmr_index(19).unwrap())
		.unwrap();

	let res = pmmr
		.readonly_pmmr()
		.elements_from_pmmr_index(8, 7, Some(34))
		.unwrap();
	assert_eq!(res.0, 20);
	assert_eq!(res.1.len(), 7);
	assert_eq!((res.1[0].1).0[3], 6);
	assert_eq!((res.1[6].1).0[3], 12);
}
