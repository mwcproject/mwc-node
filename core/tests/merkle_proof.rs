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
use mwc_core::core::merkle_proof::MerkleProof;
use mwc_core::core::pmmr::{ReadablePMMR, VecBackend, PMMR};
use mwc_core::ser::{self, PMMRIndexHashable};

#[test]
fn empty_merkle_proof() {
	let proof = MerkleProof::empty();
	assert_eq!(proof.path, vec![]);
	assert_eq!(proof.mmr_size, 0);
}

#[test]
fn merkle_proof_ser_deser() {
	let mut ba = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut ba);
	for x in 0..15 {
		pmmr.push(&TestElem([0, 0, 0, x])).unwrap();
	}
	let proof = pmmr.merkle_proof(8).unwrap();

	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &proof).expect("serialization failed");
	let proof_2: MerkleProof = ser::deserialize_default(0, &mut &vec[..]).unwrap();

	assert_eq!(proof, proof_2);
}

#[test]
fn merkle_proof_from_hex_rejects_trailing_bytes() {
	let proof = MerkleProof::empty();
	let proof_hex = proof.to_hex(0).unwrap();
	assert_eq!(MerkleProof::from_hex(0, &proof_hex).unwrap(), proof);

	let proof_hex_with_trailing_byte = format!("{}00", proof_hex);
	match MerkleProof::from_hex(0, &proof_hex_with_trailing_byte) {
		Err(err) => {
			assert!(
				err.to_string()
					.contains("Trailing bytes after serialized object"),
				"unexpected error: {}",
				err
			);
		}
		other => panic!(
			"expected trailing bytes rejection from MerkleProof::from_hex, got {:?}",
			other
		),
	}
}

#[test]
fn merkle_proof_ser_rejects_implausible_path_len() {
	let proof = MerkleProof {
		mmr_size: 1,
		path: vec![Hash::from_vec(&[1])],
	};
	let mut vec = Vec::new();

	match ser::serialize_default(0, &mut vec, &proof) {
		Err(ser::Error::CorruptedData(msg)) => {
			assert!(msg.contains("MerkleProof path length"), "{}", msg);
		}
		other => panic!("expected invalid path length rejection, got {:?}", other),
	}
}

#[test]
fn merkle_proof_deser_rejects_oversized_path_len() {
	let mut bytes = Vec::new();
	bytes.extend_from_slice(&1u64.to_be_bytes());
	bytes.extend_from_slice(&(ser::READ_VEC_SIZE_LIMIT + 1).to_be_bytes());

	match ser::deserialize_default::<MerkleProof, _>(0, &mut &bytes[..]) {
		Err(ser::Error::TooLargeReadErr(msg)) => {
			assert!(msg.contains("MerkleProof path length"), "{}", msg);
		}
		other => panic!("expected oversized path length rejection, got {:?}", other),
	}
}

#[test]
fn merkle_proof_verify_rejects_invalid_nonzero_mmr_size() {
	let elem = TestElem([0, 0, 0, 1]);
	let root = elem.hash_with_index(0, 0).unwrap();
	let proof = MerkleProof {
		mmr_size: 2,
		path: vec![],
	};

	match proof.verify(0, root, &elem, 0) {
		Err(err) => {
			assert!(
				err.to_string().contains("Invalid MerkleProof mmr_size 2"),
				"unexpected error: {}",
				err
			);
		}
		other => panic!("expected invalid MMR size rejection, got {:?}", other),
	}
}

#[test]
fn merkle_proof_verify_rejects_overlong_path() {
	let elem = TestElem([0, 0, 0, 1]);
	let root = elem.hash_with_index(0, 0).unwrap();
	let proof = MerkleProof {
		mmr_size: 1,
		path: vec![Hash::from_vec(&[1])],
	};

	match proof.verify(0, root, &elem, 0) {
		Err(err) => {
			assert!(
				err.to_string().contains("MerkleProof path length"),
				"unexpected error: {}",
				err
			);
		}
		other => panic!("expected overlong path rejection, got {:?}", other),
	}
}

#[test]
fn merkle_proof_verify_rejects_empty_mmr() {
	let elem = TestElem([0, 0, 0, 1]);
	let root = elem.hash_with_index(0, 0).unwrap();
	let proof = MerkleProof::empty();

	match proof.verify(0, root, &elem, 0) {
		Err(err) => {
			assert!(
				err.to_string().contains("empty MMR"),
				"unexpected error: {}",
				err
			);
		}
		other => panic!("expected empty MMR rejection, got {:?}", other),
	}
}

#[test]
fn merkle_proof_verify_rejects_out_of_range_node_pos() {
	let elem = TestElem([0, 0, 0, 1]);
	let root = elem.hash_with_index(0, 0).unwrap();
	let proof = MerkleProof {
		mmr_size: 1,
		path: vec![],
	};

	match proof.verify(0, root, &elem, 1) {
		Err(err) => {
			assert!(
				err.to_string().contains("outside MMR size"),
				"unexpected error: {}",
				err
			);
		}
		other => panic!(
			"expected out-of-range node position rejection, got {:?}",
			other
		),
	}
}

#[test]
fn merkle_proof_verify_rejects_internal_node_pos() {
	let elem1 = TestElem([0, 0, 0, 1]);
	let elem2 = TestElem([0, 0, 0, 2]);
	let hash1 = elem1.hash_with_index(0, 0).unwrap();
	let hash2 = elem2.hash_with_index(0, 1).unwrap();
	let internal_node = (hash1, hash2);
	let root = internal_node.hash_with_index(0, 2).unwrap();
	let proof = MerkleProof {
		mmr_size: 3,
		path: vec![],
	};

	match proof.verify(0, root, &internal_node, 2) {
		Err(err) => {
			assert!(
				err.to_string().contains("not a PMMR leaf"),
				"unexpected error: {}",
				err
			);
		}
		other => panic!("expected internal node position rejection, got {:?}", other),
	}
}

#[test]
fn pmmr_merkle_proof_prune_and_rewind() {
	let mut ba = VecBackend::new(0);
	let mut pmmr = PMMR::new(&mut ba);
	pmmr.push(&TestElem([0, 0, 0, 1])).unwrap();
	pmmr.push(&TestElem([0, 0, 0, 2])).unwrap();
	let proof = pmmr.merkle_proof(1).unwrap();

	// now prune an element and check we can still generate
	// the correct Merkle proof for the other element (after sibling pruned)
	pmmr.prune(0).unwrap();
	let proof_2 = pmmr.merkle_proof(1).unwrap();
	assert_eq!(proof, proof_2);
}

#[test]
fn pmmr_merkle_proof() {
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

	pmmr.push(&elems[0]).unwrap();
	let pos_0 = elems[0].hash_with_index(0, 0).unwrap();
	assert_eq!(pmmr.get_hash(0).unwrap().unwrap(), pos_0);

	let proof = pmmr.merkle_proof(0).unwrap();
	assert_eq!(proof.path, vec![]);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[0], 0).is_ok());

	pmmr.push(&elems[1]).unwrap();
	let pos_1 = elems[1].hash_with_index(0, 1).unwrap();
	assert_eq!(pmmr.get_hash(1).unwrap().unwrap(), pos_1);
	let pos_2 = (pos_0, pos_1).hash_with_index(0, 2).unwrap();
	assert_eq!(pmmr.get_hash(2).unwrap().unwrap(), pos_2);

	assert_eq!(pmmr.root().unwrap(), pos_2);
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_2]);

	// single peak, path with single sibling
	let proof = pmmr.merkle_proof(0).unwrap();
	assert_eq!(proof.path, vec![pos_1]);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[0], 0).is_ok());

	let proof = pmmr.merkle_proof(1).unwrap();
	assert_eq!(proof.path, vec![pos_0]);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[1], 1).is_ok());

	// three leaves, two peaks (one also the right-most leaf)
	pmmr.push(&elems[2]).unwrap();
	let pos_3 = elems[2].hash_with_index(0, 3).unwrap();
	assert_eq!(pmmr.get_hash(3).unwrap().unwrap(), pos_3);

	assert_eq!(
		pmmr.root().unwrap(),
		(pos_2, pos_3).hash_with_index(0, 4).unwrap()
	);
	assert_eq!(pmmr.peaks().unwrap(), vec![pos_2, pos_3]);

	let proof = pmmr.merkle_proof(0).unwrap();
	assert_eq!(proof.path, vec![pos_1, pos_3]);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[0], 0).is_ok());

	let proof = pmmr.merkle_proof(1).unwrap();
	assert_eq!(proof.path, vec![pos_0, pos_3]);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[1], 1).is_ok());

	let proof = pmmr.merkle_proof(3).unwrap();
	assert_eq!(proof.path, vec![pos_2]);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[2], 3).is_ok());

	// 7 leaves, 3 peaks, 11 pos in total
	pmmr.push(&elems[3]).unwrap();
	let pos_4 = elems[3].hash_with_index(0, 4).unwrap();
	assert_eq!(pmmr.get_hash(4).unwrap().unwrap(), pos_4);
	let pos_5 = (pos_3, pos_4).hash_with_index(0, 5).unwrap();
	assert_eq!(pmmr.get_hash(5).unwrap().unwrap(), pos_5);
	let pos_6 = (pos_2, pos_5).hash_with_index(0, 6).unwrap();
	assert_eq!(pmmr.get_hash(6).unwrap().unwrap(), pos_6);

	pmmr.push(&elems[4]).unwrap();
	let pos_7 = elems[4].hash_with_index(0, 7).unwrap();
	assert_eq!(pmmr.get_hash(7).unwrap().unwrap(), pos_7);

	pmmr.push(&elems[5]).unwrap();
	let pos_8 = elems[5].hash_with_index(0, 8).unwrap();
	assert_eq!(pmmr.get_hash(8).unwrap().unwrap(), pos_8);

	let pos_9 = (pos_7, pos_8).hash_with_index(0, 9).unwrap();
	assert_eq!(pmmr.get_hash(9).unwrap().unwrap(), pos_9);

	pmmr.push(&elems[6]).unwrap();
	let pos_10 = elems[6].hash_with_index(0, 10).unwrap();
	assert_eq!(pmmr.get_hash(10).unwrap().unwrap(), pos_10);

	assert_eq!(pmmr.unpruned_size(), 11);

	let proof = pmmr.merkle_proof(0).unwrap();
	assert_eq!(
		proof.path,
		vec![
			pos_1,
			pos_5,
			(pos_9, pos_10).hash_with_index(0, 11).unwrap()
		]
	);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[0], 0).is_ok());

	let proof = pmmr.merkle_proof(1).unwrap();
	assert_eq!(
		proof.path,
		vec![
			pos_0,
			pos_5,
			(pos_9, pos_10).hash_with_index(0, 11).unwrap()
		]
	);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[1], 1).is_ok());

	let proof = pmmr.merkle_proof(3).unwrap();
	assert_eq!(
		proof.path,
		vec![
			pos_4,
			pos_2,
			(pos_9, pos_10).hash_with_index(0, 11).unwrap()
		]
	);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[2], 3).is_ok());

	let proof = pmmr.merkle_proof(4).unwrap();
	assert_eq!(
		proof.path,
		vec![
			pos_3,
			pos_2,
			(pos_9, pos_10).hash_with_index(0, 11).unwrap()
		]
	);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[3], 4).is_ok());

	let proof = pmmr.merkle_proof(7).unwrap();
	assert_eq!(proof.path, vec![pos_8, pos_10, pos_6]);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[4], 7).is_ok());

	let proof = pmmr.merkle_proof(8).unwrap();
	assert_eq!(proof.path, vec![pos_7, pos_10, pos_6]);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[5], 8).is_ok());

	let proof = pmmr.merkle_proof(10).unwrap();
	assert_eq!(proof.path, vec![pos_9, pos_6]);
	assert!(proof.verify(0, pmmr.root().unwrap(), &elems[6], 10).is_ok());
}
