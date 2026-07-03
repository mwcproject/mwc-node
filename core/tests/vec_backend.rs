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
use mwc_core::core::pmmr::{Backend, ReadablePMMR, VecBackend, PMMR};
use mwc_crates::croaring::Bitmap;

#[test]
fn leaf_pos_and_idx_iter_test() {
	let elems = [
		TestElem([0, 0, 0, 1]),
		TestElem([0, 0, 0, 2]),
		TestElem([0, 0, 0, 3]),
		TestElem([0, 0, 0, 4]),
		TestElem([0, 0, 0, 5]),
	];
	let mut backend = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut backend);
	for x in &elems {
		pmmr.push(x).unwrap();
	}
	assert_eq!(
		vec![0, 1, 2, 3, 4],
		pmmr.leaf_idx_iter(0)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
	assert_eq!(
		vec![2, 3, 4],
		pmmr.leaf_idx_iter(2)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
	assert_eq!(
		vec![0, 1, 3, 4, 7],
		pmmr.leaf_pos_iter()
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
}

#[test]
fn leaf_pos_and_idx_iter_hash_only_test() {
	let elems = [
		TestElem([0, 0, 0, 1]),
		TestElem([0, 0, 0, 2]),
		TestElem([0, 0, 0, 3]),
		TestElem([0, 0, 0, 4]),
		TestElem([0, 0, 0, 5]),
	];
	let mut backend = VecBackend::new_hash_only(0);
	let mut pmmr = PMMR::new(&mut backend);
	for x in &elems {
		pmmr.push(x).unwrap();
	}
	assert_eq!(
		vec![0, 1, 2, 3, 4],
		pmmr.leaf_idx_iter(0)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
	assert_eq!(
		vec![2, 3, 4],
		pmmr.leaf_idx_iter(2)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
	assert_eq!(
		vec![0, 1, 3, 4, 7],
		pmmr.leaf_pos_iter()
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
}

#[test]
fn leaf_pos_iter_respects_pmmr_view_size() {
	let elems = [
		TestElem([0, 0, 0, 1]),
		TestElem([0, 0, 0, 2]),
		TestElem([0, 0, 0, 3]),
		TestElem([0, 0, 0, 4]),
		TestElem([0, 0, 0, 5]),
	];
	let mut backend = VecBackend::new(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
	}

	let pmmr = PMMR::at(&mut backend, 4);
	assert_eq!(
		vec![0, 1, 3],
		pmmr.leaf_pos_iter()
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
	assert_eq!(
		vec![0, 1, 2],
		pmmr.leaf_idx_iter(0)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
	assert_eq!(
		vec![0, 1, 3],
		pmmr.readonly_pmmr()
			.leaf_pos_iter()
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
	assert_eq!(
		vec![0, 1, 2],
		pmmr.readonly_pmmr()
			.leaf_idx_iter(0)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
}

#[test]
fn leaf_pos_iter_skips_removed_vec_backend_data() {
	let elems = [
		TestElem([0, 0, 0, 1]),
		TestElem([0, 0, 0, 2]),
		TestElem([0, 0, 0, 3]),
		TestElem([0, 0, 0, 4]),
		TestElem([0, 0, 0, 5]),
	];
	let mut backend = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut backend);
	for x in &elems {
		pmmr.push(x).unwrap();
	}

	pmmr.prune(1).unwrap();

	assert_eq!(
		vec![0, 3, 4, 7],
		pmmr.leaf_pos_iter()
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
}

#[test]
fn get_hash_skips_removed_vec_backend_data() {
	let elems = [TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])];
	let mut backend = VecBackend::new(0);
	let removed_hash;
	{
		let mut pmmr = PMMR::new(&mut backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
		removed_hash = pmmr.get_hash(1).unwrap().unwrap();

		assert!(pmmr.prune(1).unwrap());
		assert_eq!(pmmr.get_hash(1).unwrap(), None);
		assert!(!pmmr.prune(1).unwrap());
	}

	assert_eq!(backend.get_hash(1).unwrap(), None);
	assert_eq!(backend.get_from_file(1).unwrap(), Some(removed_hash));
}

#[test]
fn vec_backend_remove_reports_actual_data_backed_removal() {
	let elems = [TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])];
	let mut backend = VecBackend::new(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
	}

	assert!(Backend::<TestElem>::remove(&mut backend, 1).unwrap());
	assert!(!Backend::<TestElem>::remove(&mut backend, 1).unwrap());
	assert!(!Backend::<TestElem>::remove(&mut backend, 7).unwrap());

	match Backend::<TestElem>::remove(&mut backend, 2) {
		Err(mwc_core::core::pmmr::Error::SerializationError(msg)) => {
			assert!(msg.contains("is not a leaf"), "unexpected error: {}", msg);
		}
		other => panic!("expected non-leaf remove rejection, got {:?}", other),
	}
}

#[test]
fn vec_backend_remove_reports_actual_hash_only_removal() {
	let elems = [TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])];
	let mut backend = VecBackend::new_hash_only(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
	}

	assert!(Backend::<TestElem>::remove(&mut backend, 1).unwrap());
	assert!(!Backend::<TestElem>::remove(&mut backend, 1).unwrap());
	assert!(!Backend::<TestElem>::remove(&mut backend, 7).unwrap());
}

#[test]
fn vec_backend_remove_returns_false_for_missing_leaf_slots() {
	let elems = [TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])];
	let mut data_backend = VecBackend::new(0);
	let mut hash_backend = VecBackend::new_hash_only(0);
	{
		let mut pmmr = PMMR::new(&mut data_backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
	}
	{
		let mut pmmr = PMMR::new(&mut hash_backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
	}

	data_backend.data.as_mut().unwrap()[1] = None;
	hash_backend.hashes[1] = None;

	assert!(!Backend::<TestElem>::remove(&mut data_backend, 1).unwrap());
	assert!(!Backend::<TestElem>::remove(&mut hash_backend, 1).unwrap());
}

#[test]
fn get_data_returns_none_for_internal_nodes() {
	let elems = [TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])];
	let mut backend = VecBackend::new(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
		assert_eq!(pmmr.unpruned_size(), 3);
	}

	assert_eq!(backend.get_data(0).unwrap(), Some(elems[0]));
	assert_eq!(backend.get_data(1).unwrap(), Some(elems[1]));
	assert_eq!(backend.get_data(2).unwrap(), None);
	assert_eq!(backend.get_data_from_file(2).unwrap(), None);
}

#[test]
fn append_pruned_subtree_capacity_error_does_not_mutate() {
	let elems = [
		TestElem([0, 0, 0, 1]),
		TestElem([0, 0, 0, 2]),
		TestElem([0, 0, 0, 3]),
	];
	let mut backend = VecBackend::new(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
		assert_eq!(pmmr.unpruned_size(), 4);
	}

	let hashes = backend.hashes.clone();
	let data = backend.data.clone();
	assert!(!backend.is_compacted(0).unwrap());
	assert!(!backend.is_compacted(1).unwrap());

	match backend.append_pruned_subtree(Hash::from_vec(&[9]), 2) {
		Err(mwc_core::core::pmmr::Error::SerializationError(msg)) => {
			assert!(
				msg.contains("data is out of capacity"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!("expected data capacity rejection, got {:?}", other),
	}

	assert_eq!(backend.hashes, hashes);
	assert_eq!(backend.data, data);
	assert!(!backend.is_compacted(0).unwrap());
	assert!(!backend.is_compacted(1).unwrap());
}

#[test]
fn rewind_restores_removed_vec_backend_leaf() {
	let elems = [TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])];
	let mut backend = VecBackend::new(0);
	let removed_hash;
	{
		let mut pmmr = PMMR::new(&mut backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
		removed_hash = pmmr.get_hash(1).unwrap().unwrap();

		assert!(pmmr.prune(1).unwrap());
		assert_eq!(pmmr.get_hash(1).unwrap(), None);
		assert_eq!(pmmr.get_data(1).unwrap(), None);
	}

	assert_eq!(backend.get_hash(1).unwrap(), None);
	assert_eq!(backend.get_data(1).unwrap(), None);
	assert_eq!(backend.get_data_from_file(1).unwrap(), Some(elems[1]));
	assert_eq!(backend.get_from_file(1).unwrap(), Some(removed_hash));

	backend.rewind(3, &Bitmap::of(&vec![2])).unwrap();

	assert_eq!(backend.get_hash(1).unwrap(), Some(removed_hash));
	assert_eq!(backend.get_data(1).unwrap(), Some(elems[1]));
	assert_eq!(
		vec![0, 1],
		backend
			.leaf_pos_iter()
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
}

#[test]
fn rewind_restores_removed_hash_only_vec_backend_leaf() {
	let elems = [TestElem([0, 0, 0, 1]), TestElem([0, 0, 0, 2])];
	let mut backend = VecBackend::new_hash_only(0);
	let removed_hash;
	{
		let mut pmmr = PMMR::new(&mut backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
		removed_hash = pmmr.get_hash(1).unwrap().unwrap();

		assert!(pmmr.prune(1).unwrap());
		assert_eq!(pmmr.get_hash(1).unwrap(), None);
	}

	assert_eq!(backend.get_hash(1).unwrap(), None);
	assert_eq!(backend.get_from_file(1).unwrap(), Some(removed_hash));

	backend.rewind(3, &Bitmap::of(&vec![2])).unwrap();

	assert_eq!(backend.get_hash(1).unwrap(), Some(removed_hash));
	assert_eq!(
		vec![0, 1],
		backend
			.leaf_pos_iter()
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
}

#[test]
fn rewind_truncates_vec_backend_state() {
	let elems = [
		TestElem([0, 0, 0, 1]),
		TestElem([0, 0, 0, 2]),
		TestElem([0, 0, 0, 3]),
	];
	let mut backend = VecBackend::new(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		for x in &elems {
			pmmr.push(x).unwrap();
		}
		assert_eq!(pmmr.unpruned_size(), 4);
	}

	backend.rewind(3, &Bitmap::new()).unwrap();

	assert_eq!(backend.hashes.len(), 3);
	assert_eq!(backend.data.as_ref().unwrap().len(), 2);
	assert_eq!(
		vec![0, 1],
		backend
			.leaf_pos_iter()
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);
}

#[test]
fn rewind_rejects_forward_positions_without_mutating() {
	let mut backend = VecBackend::new(0);
	{
		let mut pmmr = PMMR::new(&mut backend);
		pmmr.push(&TestElem([0, 0, 0, 1])).unwrap();
	}
	let hashes = backend.hashes.clone();
	let data = backend.data.clone();

	match backend.rewind(2, &Bitmap::new()) {
		Err(mwc_core::core::pmmr::Error::InvalidState(msg)) => {
			assert!(msg.contains("hashes forward"), "unexpected error: {}", msg);
		}
		other => panic!("expected forward hash rewind rejection, got {:?}", other),
	}

	assert_eq!(backend.hashes, hashes);
	assert_eq!(backend.data, data);

	let mut backend = VecBackend::new(0);
	backend.hashes = vec![
		Some(Hash::from_vec(&[1])),
		Some(Hash::from_vec(&[2])),
		Some(Hash::from_vec(&[3])),
	];
	backend.data = Some(vec![Some(TestElem([0, 0, 0, 1]))]);
	let hashes = backend.hashes.clone();
	let data = backend.data.clone();

	match backend.rewind(3, &Bitmap::new()) {
		Err(mwc_core::core::pmmr::Error::InvalidState(msg)) => {
			assert!(msg.contains("data forward"), "unexpected error: {}", msg);
		}
		other => panic!("expected forward data rewind rejection, got {:?}", other),
	}

	assert_eq!(backend.hashes, hashes);
	assert_eq!(backend.data, data);
}

#[test]
fn hash_only_leaf_pos_iter_skips_missing_and_compacted_hashes() {
	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	backend.hashes = vec![
		Some(Hash::from_vec(&[1])),
		None,
		Some(Hash::from_vec(&[2])),
		Some(Hash::from_vec(&[3])),
	];

	assert_eq!(
		vec![0, 3],
		backend
			.leaf_pos_iter()
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>()
	);

	let mut backend = VecBackend::<TestElem>::new_hash_only(0);
	backend
		.append_pruned_subtree(Hash::from_vec(&[9]), 2)
		.unwrap();

	assert!(backend
		.leaf_pos_iter()
		.unwrap()
		.map(|x| x.unwrap())
		.collect::<Vec<_>>()
		.is_empty());
}
