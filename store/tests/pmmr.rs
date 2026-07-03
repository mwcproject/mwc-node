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

use mwc_crates::chrono::prelude::Utc;
use mwc_crates::croaring::{Bitmap, Portable};
use mwc_crates::env_logger;
use mwc_crates::filetime;

use std::fs;

use mwc_core::core::hash::{DefaultHashable, Hash};
use mwc_core::core::pmmr::{self, Backend, ReadablePMMR, PMMR};
use mwc_core::ser::{
	Error, PMMRIndexHashable, PMMRable, ProtocolVersion, Readable, Reader, Writeable, Writer,
};
use mwc_store::types::{
	AppendOnlyFile, DataFile, SizeEntry, SizeInfo, VariableSizeMetadataValidation,
};

#[test]
fn pmmr_leaf_idx_iter() {
	let (data_dir, elems) = setup("leaf_idx_iter");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		// adding first set of 4 elements and sync
		let mmr_size = load(0, &elems[0..5], &mut backend);
		backend.sync().unwrap();

		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			let leaf_idx = pmmr
				.leaf_idx_iter(0)
				.unwrap()
				.map(|x| x.unwrap())
				.collect::<Vec<_>>();
			let leaf_pos = pmmr
				.leaf_pos_iter()
				.unwrap()
				.map(|x| x.unwrap())
				.collect::<Vec<_>>();

			// The first 5 leaves [0,1,2,3,4] are at pos [1,2,4,5,8] in the MMR.
			assert_eq!(leaf_idx, vec![0, 1, 2, 3, 4]);
			assert_eq!(leaf_pos, vec![0, 1, 3, 4, 7]);
		}
	}
	teardown(data_dir);
}

#[test]
fn pmmr_leaf_pos_iter_from_starts_at_requested_position() {
	let (data_dir, elems) = setup("leaf_pos_iter_from");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let mmr_size = load(0, &elems[0..5], &mut backend);
		backend.sync().unwrap();

		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.prune(3).unwrap();
		}

		let leaf_pos = backend
			.leaf_pos_iter_from(2)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>();
		assert_eq!(leaf_pos, vec![4, 7]);

		let leaf_pos = backend
			.leaf_pos_iter_from(7)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>();
		assert_eq!(leaf_pos, vec![7]);

		let leaf_pos = backend
			.leaf_pos_iter_from(8)
			.unwrap()
			.map(|x| x.unwrap())
			.collect::<Vec<_>>();
		assert!(leaf_pos.is_empty());
	}
	teardown(data_dir);
}

#[test]
fn pmmr_n_unpruned_leaves_respects_view_size() {
	let (data_dir, elems) = setup("n_unpruned_leaves_view_size");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let prefix_size = load(0, &elems[0..4], &mut backend);
		backend.sync().unwrap();
		let full_size = load(prefix_size, &elems[4..9], &mut backend);
		backend.sync().unwrap();

		assert_eq!(backend.n_unpruned_leaves().unwrap(), 9);

		let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, prefix_size);
		assert_eq!(pmmr.unpruned_size(), prefix_size);
		assert_eq!(pmmr.n_unpruned_leaves().unwrap(), 4);
		assert_eq!(pmmr.n_unpruned_leaves_to_index(9).unwrap(), 4);
		assert_eq!(
			pmmr.readonly_pmmr().n_unpruned_leaves_to_index(9).unwrap(),
			4
		);

		let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, full_size);
		assert_eq!(pmmr.n_unpruned_leaves().unwrap(), 9);
		assert_eq!(pmmr.n_unpruned_leaves_to_index(9).unwrap(), 9);
	}
	teardown(data_dir);
}

#[test]
fn pmmr_n_unpruned_leaves_to_index_uses_leaf_index_boundary() {
	let (data_dir, elems) = setup("n_unpruned_leaves_to_index");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let mmr_size = load(0, &elems[0..4], &mut backend);
		backend.sync().unwrap();

		let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
		assert_eq!(pmmr.n_unpruned_leaves_to_index(3).unwrap(), 3);
	}
	teardown(data_dir);
}

#[test]
fn pmmr_backend_open_rejects_non_leaf_leaf_set_entry() {
	let (data_dir, _) = setup("leaf_pos_iter_non_leaf_entry");
	fs::write(
		format!("{}/pmmr_leaf.bin", data_dir),
		Bitmap::of(&[3]).serialize::<Portable>(),
	)
	.unwrap();

	match mwc_store::pmmr::PMMRBackend::<TestElem>::new(
		data_dir.to_string(),
		true,
		ProtocolVersion(1),
		0,
		None,
		VariableSizeMetadataValidation::Full,
	) {
		Err(pmmr::Error::IOErr(io_err)) => {
			assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidData);
		}
		Ok(_) => {
			panic!("expected PMMR backend open non-leaf rejection, got success");
		}
		Err(err) => {
			panic!("expected PMMR backend open non-leaf rejection, got {}", err);
		}
	}

	teardown(data_dir);
}

#[test]
fn pmmr_backend_open_rejects_missing_leaf_set_for_existing_prunable_store() {
	let (data_dir, _) = setup("missing_leaf_set");
	fs::write(format!("{}/pmmr_hash.bin", data_dir), []).unwrap();

	match mwc_store::pmmr::PMMRBackend::<TestElem>::new(
		data_dir.to_string(),
		true,
		ProtocolVersion(1),
		0,
		None,
		VariableSizeMetadataValidation::Full,
	) {
		Err(pmmr::Error::InvalidState(msg)) => {
			assert!(
				msg.contains("Partial PMMR file set"),
				"unexpected error: {}",
				msg
			);
		}
		Ok(_) => panic!("expected missing leaf_set rejection, got success"),
		Err(err) => panic!("expected missing leaf_set rejection, got {}", err),
	}

	teardown(data_dir);
}

#[test]
fn pmmr_backend_new_prunable_creates_metadata_files_before_sync() {
	let (data_dir, _) = setup("new_prunable_creates_metadata_files");
	{
		let _backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		for file_name in [
			"pmmr_hash.bin",
			"pmmr_data.bin",
			"pmmr_leaf.bin",
			"pmmr_prun.bin",
		] {
			assert!(
				std::path::Path::new(&data_dir).join(file_name).exists(),
				"{} should exist after PMMRBackend::new",
				file_name
			);
		}
	}

	mwc_store::pmmr::PMMRBackend::<TestElem>::new(
		data_dir.to_string(),
		true,
		ProtocolVersion(1),
		0,
		None,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();

	teardown(data_dir);
}

#[test]
fn pmmr_backend_open_rejects_leaf_set_without_hash_data_files() {
	let (data_dir, _) = setup("leaf_set_without_hash_data");
	fs::write(
		format!("{}/pmmr_leaf.bin", data_dir),
		Bitmap::of(&[1]).serialize::<Portable>(),
	)
	.unwrap();

	match mwc_store::pmmr::PMMRBackend::<TestElem>::new(
		data_dir.to_string(),
		true,
		ProtocolVersion(1),
		0,
		None,
		VariableSizeMetadataValidation::Full,
	) {
		Err(pmmr::Error::InvalidState(msg)) => {
			assert!(
				msg.contains("metadata files exist without hash/data files"),
				"unexpected error: {}",
				msg
			);
		}
		Ok(_) => panic!("expected partial PMMR file set rejection, got success"),
		Err(err) => panic!("expected partial PMMR file set rejection, got {}", err),
	}

	assert!(!std::path::Path::new(&data_dir)
		.join("pmmr_hash.bin")
		.exists());
	assert!(!std::path::Path::new(&data_dir)
		.join("pmmr_data.bin")
		.exists());
	teardown(data_dir);
}

#[test]
fn pmmr_backend_open_rejects_non_regular_pmmr_file() {
	let (data_dir, _) = setup("non_regular_pmmr_file");
	fs::create_dir(format!("{}/pmmr_hash.bin", data_dir)).unwrap();

	match mwc_store::pmmr::PMMRBackend::<TestElem>::new(
		data_dir.to_string(),
		true,
		ProtocolVersion(1),
		0,
		None,
		VariableSizeMetadataValidation::Full,
	) {
		Err(pmmr::Error::IOErr(io_err)) => {
			assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidInput);
		}
		Ok(_) => panic!("expected non-regular PMMR file rejection, got success"),
		Err(err) => panic!("expected non-regular PMMR file rejection, got {}", err),
	}

	teardown(data_dir);
}

#[cfg(unix)]
#[test]
fn pmmr_backend_open_rejects_symlink_pmmr_file() {
	use std::os::unix::fs::symlink;

	let (data_dir, _) = setup("symlink_pmmr_file");
	fs::write(format!("{}/target_hash.bin", data_dir), []).unwrap();
	symlink(
		format!("{}/target_hash.bin", data_dir),
		format!("{}/pmmr_hash.bin", data_dir),
	)
	.unwrap();

	match mwc_store::pmmr::PMMRBackend::<TestElem>::new(
		data_dir.to_string(),
		true,
		ProtocolVersion(1),
		0,
		None,
		VariableSizeMetadataValidation::Full,
	) {
		Err(pmmr::Error::IOErr(io_err)) => {
			assert_eq!(io_err.kind(), std::io::ErrorKind::InvalidInput);
		}
		Ok(_) => panic!("expected symlink PMMR file rejection, got success"),
		Err(err) => panic!("expected symlink PMMR file rejection, got {}", err),
	}

	teardown(data_dir);
}

#[cfg(unix)]
#[test]
fn data_file_open_rejects_symlink_path() {
	use std::os::unix::fs::symlink;

	let (data_dir, _) = setup("data_file_symlink_path");
	let target_path = format!("{}/target_data.bin", data_dir);
	let data_path = format!("{}/data.bin", data_dir);
	fs::write(&target_path, []).unwrap();
	symlink(&target_path, &data_path).unwrap();

	let err = match DataFile::<TestElem>::open(
		&data_path,
		SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	) {
		Err(err) => err,
		Ok(_) => panic!("expected symlink data file rejection, got success"),
	};

	assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
	assert!(err.to_string().contains("symlink"));
	teardown(data_dir);
}

#[test]
fn pmmr_backend_snapshot_failure_does_not_create_backend_files() {
	mwc_core::global::set_local_chain_type(mwc_core::global::ChainTypes::AutomatedTesting);
	let (data_dir, _) = setup("snapshot_failure_no_backend_files");
	let header = mwc_core::core::BlockHeader::default(0);

	match mwc_store::pmmr::PMMRBackend::<TestElem>::new(
		data_dir.to_string(),
		true,
		ProtocolVersion(1),
		0,
		Some(&header),
		VariableSizeMetadataValidation::Full,
	) {
		Err(pmmr::Error::IOErr(io_err)) => {
			assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
		}
		Ok(_) => panic!("expected snapshot copy failure, got success"),
		Err(err) => panic!("expected snapshot copy failure, got {}", err),
	}

	for file_name in [
		"pmmr_hash.bin",
		"pmmr_data.bin",
		"pmmr_size.bin",
		"pmmr_leaf.bin",
	] {
		assert!(
			!std::path::Path::new(&data_dir).join(file_name).exists(),
			"{} should not have been created",
			file_name
		);
	}
	teardown(data_dir);
}

#[test]
fn pmmr_append() {
	let (data_dir, elems) = setup("append");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		// adding first set of 4 elements and sync
		let mut mmr_size = load(0, &elems[0..4], &mut backend);
		backend.sync().unwrap();

		let pos_0 = elems[0].hash_with_index(0, 0).unwrap();
		let pos_1 = elems[1].hash_with_index(0, 1).unwrap();
		let pos_2 = (pos_0, pos_1).hash_with_index(0, 2).unwrap();

		{
			// Note: 1-indexed PMMR API
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);

			assert_eq!(pmmr.n_unpruned_leaves().unwrap(), 4);
			assert_eq!(pmmr.get_data(0).unwrap(), Some(elems[0]));
			assert_eq!(pmmr.get_data(1).unwrap(), Some(elems[1]));

			assert_eq!(pmmr.get_hash(0).unwrap(), Some(pos_0));
			assert_eq!(pmmr.get_hash(1).unwrap(), Some(pos_1));
			assert_eq!(pmmr.get_hash(2).unwrap(), Some(pos_2));
		}

		// adding the rest and sync again
		mmr_size = load(mmr_size, &elems[4..9], &mut backend);
		backend.sync().unwrap();

		// 0010012001001230

		let pos_3 = elems[2].hash_with_index(0, 3).unwrap();
		let pos_4 = elems[3].hash_with_index(0, 4).unwrap();
		let pos_5 = (pos_3, pos_4).hash_with_index(0, 5).unwrap();
		let pos_6 = (pos_2, pos_5).hash_with_index(0, 6).unwrap();

		let pos_7 = elems[4].hash_with_index(0, 7).unwrap();
		let pos_8 = elems[5].hash_with_index(0, 8).unwrap();
		let pos_9 = (pos_7, pos_8).hash_with_index(0, 9).unwrap();

		let pos_10 = elems[6].hash_with_index(0, 10).unwrap();
		let pos_11 = elems[7].hash_with_index(0, 11).unwrap();
		let pos_12 = (pos_10, pos_11).hash_with_index(0, 12).unwrap();
		let pos_13 = (pos_9, pos_12).hash_with_index(0, 13).unwrap();
		let pos_14 = (pos_6, pos_13).hash_with_index(0, 14).unwrap();

		let pos_15 = elems[8].hash_with_index(0, 15).unwrap();

		{
			// Note: 1-indexed PMMR API
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);

			assert_eq!(pmmr.n_unpruned_leaves().unwrap(), 9);

			// First pair of leaves.
			assert_eq!(pmmr.get_data(0).unwrap(), Some(elems[0]));
			assert_eq!(pmmr.get_data(1).unwrap(), Some(elems[1]));

			// Second pair of leaves.
			assert_eq!(pmmr.get_data(3).unwrap(), Some(elems[2]));
			assert_eq!(pmmr.get_data(4).unwrap(), Some(elems[3]));

			// Third pair of leaves.
			assert_eq!(pmmr.get_data(7).unwrap(), Some(elems[4]));
			assert_eq!(pmmr.get_data(8).unwrap(), Some(elems[5]));
			assert_eq!(pmmr.get_hash(9).unwrap(), Some(pos_9));
		}

		// check the resulting backend store and the computation of the root
		let node_hash = elems[0].hash_with_index(0, 0).unwrap();
		assert_eq!(backend.get_hash(0).unwrap().unwrap(), node_hash);

		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			assert_eq!(
				pmmr.root().unwrap(),
				(pos_14, pos_15).hash_with_index(0, 16).unwrap()
			);
		}
	}

	teardown(data_dir);
}

#[test]
fn non_prunable_read_paths_bypass_u32_prune_metadata() {
	let (data_dir, _) = setup("non_prunable_read_paths_bypass_u32_prune_metadata");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			false,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let high_pos0 = u64::from(u32::MAX);
		let high_leaf_pos0 = pmmr::insertion_to_pmmr_index(u64::from(u32::MAX)).unwrap();
		assert!(high_leaf_pos0 > u64::from(u32::MAX));

		assert!(!backend.is_compacted(high_pos0).unwrap());
		assert_eq!(backend.get_from_file(high_pos0).unwrap(), None);
		assert_eq!(backend.get_peak_from_file(high_pos0).unwrap(), None);
		assert_eq!(backend.get_hash(high_pos0).unwrap(), None);
		match backend.get_data_from_file(high_leaf_pos0) {
			Err(pmmr::Error::DataCorruption(msg)) => {
				assert!(msg.contains("Missing PMMR data"));
			}
			other => panic!("unexpected get_data_from_file result: {:?}", other),
		}
		match backend.get_data(high_leaf_pos0) {
			Err(pmmr::Error::DataCorruption(msg)) => {
				assert!(msg.contains("Missing PMMR data"));
			}
			other => panic!("unexpected get_data result: {:?}", other),
		}
		assert_eq!(backend.unpruned_size().unwrap(), 0);

		match backend
			.rewind(
				high_pos0
					.checked_add(1)
					.expect("test position should not overflow"),
				&Bitmap::new(),
			)
			.unwrap_err()
		{
			pmmr::Error::InvalidState(msg) => {
				assert!(msg.contains("cannot rewind hash file forward"));
			}
			err => panic!("unexpected error: {:?}", err),
		}
	}
	teardown(data_dir);
}

#[test]
fn pmmr_backend_rejects_non_contiguous_pruned_subtree() {
	let (data_dir, _) = setup("non_contiguous_pruned_subtree");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		match backend.append_pruned_subtree(Hash::default(), 5) {
			Err(pmmr::Error::InvalidState(msg)) => {
				assert!(msg.contains("not contiguous"), "unexpected error: {}", msg);
			}
			other => panic!("expected non-contiguous subtree rejection, got {:?}", other),
		}
		assert_eq!(backend.hash_size().unwrap(), 0);
	}
	teardown(data_dir);
}

#[test]
fn pmmr_backend_remove_rejects_missing_leaf() {
	let (data_dir, elems) = setup("remove_missing_leaf");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		load(0, &elems[0..1], &mut backend);

		let res = Backend::<TestElem>::remove(&mut backend, 0).unwrap();
		assert!(res);
		match Backend::<TestElem>::remove(&mut backend, 0) {
			Ok(false) => {}
			other => panic!("expected missing leaf rejection, got {:?}", other),
		}
	}
	teardown(data_dir);
}

#[test]
fn fixed_size_data_file_rejects_partial_trailing_element() {
	let (data_dir, _) = setup("partial_trailing_element");
	let path = format!("{}/partial.bin", data_dir);
	fs::write(&path, [1, 2]).unwrap();

	let err = match mwc_store::types::DataFile::<TestElem>::open(
		&path,
		mwc_store::types::SizeInfo::FixedSize(4),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	) {
		Ok(_) => panic!("expected invalid fixed-size data file"),
		Err(err) => err,
	};
	assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

	teardown(data_dir);
}

#[test]
fn fixed_size_data_file_flush_truncates_prior_partial_append() {
	let (data_dir, elems) = setup("flush_truncates_prior_partial_append");
	let path = format!("{}/data.bin", data_dir);
	let mut data_file = DataFile::<TestElem>::open(
		&path,
		SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	data_file.append(&elems[0]).unwrap();

	// Simulate a previous flush attempt that wrote the buffered bytes but
	// failed before the in-memory buffer was cleared.
	fs::write(
		&path,
		mwc_core::ser::ser_vec(0, &elems[0], ProtocolVersion(1)).unwrap(),
	)
	.unwrap();

	data_file.flush().unwrap();

	assert_eq!(fs::metadata(&path).unwrap().len(), 4);
	assert_eq!(data_file.read(1).unwrap(), Some(elems[0]));
	assert_eq!(data_file.read(2).unwrap(), None);
	teardown(data_dir);
}

#[test]
fn fixed_size_data_file_rejects_wrong_serialized_append_size() {
	let (data_dir, _) = setup("fixed_size_wrong_append_size");
	let short_path = format!("{}/short.bin", data_dir);
	let long_path = format!("{}/long.bin", data_dir);

	let mut short_file = DataFile::<ShortFixedElem>::open(
		&short_path,
		SizeInfo::FixedSize(4),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	let err = short_file.append(&ShortFixedElem).unwrap_err();
	assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
	assert!(err.to_string().contains("serialized 2 bytes"));
	short_file.flush().unwrap();
	assert_eq!(fs::metadata(&short_path).unwrap().len(), 0);

	let mut long_file = DataFile::<LongFixedElem>::open(
		&long_path,
		SizeInfo::FixedSize(4),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	let err = long_file.append(&LongFixedElem).unwrap_err();
	assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
	assert!(err.to_string().contains("serialized 8 bytes"));
	long_file.flush().unwrap();
	assert_eq!(fs::metadata(&long_path).unwrap().len(), 0);

	teardown(data_dir);
}

#[test]
fn fixed_size_append_rejects_unaligned_raw_bytes() {
	let (data_dir, _) = setup("fixed_size_raw_append_unaligned");
	let path = format!("{}/data.bin", data_dir);
	let mut file = AppendOnlyFile::<TestElem>::open(
		&path,
		SizeInfo::FixedSize(4),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	let err = file.append(&mut [1, 2, 3]).unwrap_err();
	assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
	assert!(err.to_string().contains("not aligned"));
	file.flush().unwrap();
	assert_eq!(fs::metadata(&path).unwrap().len(), 0);

	teardown(data_dir);
}

#[test]
fn append_only_file_rejects_tmp_extension_as_persistent_path() {
	let (data_dir, _) = setup("append_only_rejects_tmp_path");
	for ext in ["tmp", "tmP", "tMp", "tMP", "Tmp", "TmP", "TMp", "TMP"] {
		let path = format!("{}/data.{}", data_dir, ext);
		let err = match AppendOnlyFile::<TestElem>::open(
			&path,
			SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		) {
			Ok(_) => panic!("expected .{} append-only path to be rejected", ext),
			Err(err) => err,
		};
		assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("reserved .tmp extension"));
		assert!(!std::path::Path::new(&path).exists());
	}

	teardown(data_dir);
}

#[test]
fn variable_size_append_rejects_empty_raw_bytes() {
	let (data_dir, _) = setup("variable_size_raw_append_empty");
	let data_path = format!("{}/data.bin", data_dir);
	let size_path = format!("{}/data_size.bin", data_dir);
	let size_file = AppendOnlyFile::<SizeEntry>::open(
		&size_path,
		SizeInfo::FixedSize(SizeEntry::LEN),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	let mut file = AppendOnlyFile::<TestElem>::open(
		&data_path,
		SizeInfo::VariableSize(Box::new(size_file)),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	let err = file.append(&mut []).unwrap_err();
	assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
	assert!(err.to_string().contains("cannot be empty"));
	file.flush().unwrap();
	assert_eq!(fs::metadata(&data_path).unwrap().len(), 0);
	assert_eq!(fs::metadata(&size_path).unwrap().len(), 0);

	teardown(data_dir);
}

#[test]
fn variable_size_data_file_rebuilds_size_file_with_bad_offsets() {
	let (data_dir, _) = setup("variable_size_bad_offsets");
	let data_path = format!("{}/data.bin", data_dir);
	let size_path = format!("{}/data_size.bin", data_dir);

	let mut size_bytes = vec![];
	for size_entry in [
		SizeEntry { offset: 4, size: 4 },
		SizeEntry { offset: 0, size: 4 },
	] {
		size_bytes.extend(mwc_core::ser::ser_vec(0, &size_entry, ProtocolVersion(1)).unwrap());
	}
	fs::write(&size_path, size_bytes).unwrap();
	let mut data_bytes = vec![];
	data_bytes.extend(mwc_core::ser::ser_vec(0, &TestElem(1), ProtocolVersion(1)).unwrap());
	data_bytes.extend(mwc_core::ser::ser_vec(0, &TestElem(2), ProtocolVersion(1)).unwrap());
	fs::write(&data_path, data_bytes).unwrap();

	let size_file = AppendOnlyFile::<SizeEntry>::open(
		&size_path,
		SizeInfo::FixedSize(SizeEntry::LEN),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	let data_file = DataFile::<TestElem>::open(
		&data_path,
		SizeInfo::VariableSize(Box::new(size_file)),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();

	assert_eq!(data_file.read(1).unwrap(), Some(TestElem(1)));
	assert_eq!(data_file.read(2).unwrap(), Some(TestElem(2)));

	teardown(data_dir);
}

#[test]
fn variable_size_data_file_rebuilds_size_file_with_bad_boundaries() {
	let (data_dir, _) = setup("variable_size_bad_boundaries");
	let data_path = format!("{}/data.bin", data_dir);
	let size_path = format!("{}/data_size.bin", data_dir);

	let mut size_bytes = vec![];
	for size_entry in [
		SizeEntry { offset: 0, size: 3 },
		SizeEntry { offset: 3, size: 5 },
	] {
		size_bytes.extend(mwc_core::ser::ser_vec(0, &size_entry, ProtocolVersion(1)).unwrap());
	}
	fs::write(&size_path, size_bytes).unwrap();
	let mut data_bytes = vec![];
	data_bytes.extend(mwc_core::ser::ser_vec(0, &TestElem(1), ProtocolVersion(1)).unwrap());
	data_bytes.extend(mwc_core::ser::ser_vec(0, &TestElem(2), ProtocolVersion(1)).unwrap());
	fs::write(&data_path, data_bytes).unwrap();

	let size_file = AppendOnlyFile::<SizeEntry>::open(
		&size_path,
		SizeInfo::FixedSize(SizeEntry::LEN),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	let data_file = DataFile::<TestElem>::open(
		&data_path,
		SizeInfo::VariableSize(Box::new(size_file)),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();

	assert_eq!(data_file.read(1).unwrap(), Some(TestElem(1)));
	assert_eq!(data_file.read(2).unwrap(), Some(TestElem(2)));

	teardown(data_dir);
}

#[test]
fn variable_size_data_file_rebuilds_size_file_with_zero_size_entry() {
	let (data_dir, _) = setup("variable_size_zero_size_entry");
	let data_path = format!("{}/data.bin", data_dir);
	let size_path = format!("{}/data_size.bin", data_dir);

	let mut size_bytes = vec![];
	for size_entry in [
		SizeEntry { offset: 0, size: 4 },
		SizeEntry { offset: 4, size: 0 },
		SizeEntry { offset: 4, size: 4 },
	] {
		size_bytes.extend(mwc_core::ser::ser_vec(0, &size_entry, ProtocolVersion(1)).unwrap());
	}
	fs::write(&size_path, size_bytes).unwrap();
	let mut data_bytes = vec![];
	data_bytes.extend(mwc_core::ser::ser_vec(0, &TestElem(1), ProtocolVersion(1)).unwrap());
	data_bytes.extend(mwc_core::ser::ser_vec(0, &TestElem(2), ProtocolVersion(1)).unwrap());
	fs::write(&data_path, data_bytes).unwrap();

	let size_file = AppendOnlyFile::<SizeEntry>::open(
		&size_path,
		SizeInfo::FixedSize(SizeEntry::LEN),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	let data_file = DataFile::<TestElem>::open(
		&data_path,
		SizeInfo::VariableSize(Box::new(size_file)),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();

	assert_eq!(data_file.read(1).unwrap(), Some(TestElem(1)));
	assert_eq!(data_file.read(2).unwrap(), Some(TestElem(2)));
	assert_eq!(data_file.read(3).unwrap(), None);

	teardown(data_dir);
}

#[test]
fn variable_size_data_file_fast_validation_skips_data_deserialize() {
	let (data_dir, _) = setup("variable_size_fast_validation_skips_read");
	let data_path = format!("{}/data.bin", data_dir);
	let size_path = format!("{}/data_size.bin", data_dir);

	let mut size_bytes = vec![];
	for size_entry in [
		SizeEntry { offset: 0, size: 4 },
		SizeEntry { offset: 4, size: 4 },
	] {
		size_bytes.extend(mwc_core::ser::ser_vec(0, &size_entry, ProtocolVersion(1)).unwrap());
	}
	fs::write(&size_path, size_bytes).unwrap();
	fs::write(&data_path, [1u8, 2, 3, 4, 5, 6, 7, 8]).unwrap();

	let size_file = AppendOnlyFile::<SizeEntry>::open(
		&size_path,
		SizeInfo::FixedSize(SizeEntry::LEN),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	DataFile::<UnreadableElem>::open(
		&data_path,
		SizeInfo::VariableSize(Box::new(size_file)),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Fast,
	)
	.unwrap();

	teardown(data_dir);
}

#[test]
fn variable_size_data_file_fast_validation_rebuilds_bad_offsets() {
	let (data_dir, _) = setup("variable_size_fast_validation_bad_offsets");
	let data_path = format!("{}/data.bin", data_dir);
	let size_path = format!("{}/data_size.bin", data_dir);

	let mut size_bytes = vec![];
	for size_entry in [
		SizeEntry { offset: 4, size: 4 },
		SizeEntry { offset: 0, size: 4 },
	] {
		size_bytes.extend(mwc_core::ser::ser_vec(0, &size_entry, ProtocolVersion(1)).unwrap());
	}
	fs::write(&size_path, size_bytes).unwrap();
	let mut data_bytes = vec![];
	data_bytes.extend(mwc_core::ser::ser_vec(0, &TestElem(1), ProtocolVersion(1)).unwrap());
	data_bytes.extend(mwc_core::ser::ser_vec(0, &TestElem(2), ProtocolVersion(1)).unwrap());
	fs::write(&data_path, data_bytes).unwrap();

	let size_file = AppendOnlyFile::<SizeEntry>::open(
		&size_path,
		SizeInfo::FixedSize(SizeEntry::LEN),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	let data_file = DataFile::<TestElem>::open(
		&data_path,
		SizeInfo::VariableSize(Box::new(size_file)),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Fast,
	)
	.unwrap();

	assert_eq!(data_file.read(1).unwrap(), Some(TestElem(1)));
	assert_eq!(data_file.read(2).unwrap(), Some(TestElem(2)));

	teardown(data_dir);
}

#[test]
fn data_file_replace_with_tmp_rejects_unsynced_state() {
	let (data_dir, elems) = setup("data_file_replace_with_tmp_unsynced_state");
	let data_path = format!("{}/data.bin", data_dir);
	let tmp_path = std::path::Path::new(&data_path).with_extension("tmp");
	{
		let mut data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		data_file.append(&elems[0]).unwrap();
		fs::write(&tmp_path, []).unwrap();

		let err = data_file.replace_with_tmp().unwrap_err();
		assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("unsynced state"));
	}

	teardown(data_dir);
}

#[test]
fn data_file_replace_with_tmp_rejects_persisted_rewind_state() {
	let (data_dir, elems) = setup("data_file_replace_with_tmp_persisted_rewind");
	let data_path = format!("{}/data.bin", data_dir);
	let tmp_path = std::path::Path::new(&data_path).with_extension("tmp");
	{
		let mut data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		data_file.append(&elems[0]).unwrap();
		data_file.append(&elems[1]).unwrap();
		data_file.flush().unwrap();
		data_file.rewind(1).unwrap();
		assert_eq!(data_file.read(1).unwrap(), Some(elems[0]));
		assert_eq!(data_file.read(2).unwrap(), None);
		fs::write(&tmp_path, []).unwrap();

		let err = data_file.replace_with_tmp().unwrap_err();
		assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("unsynced state"));
	}

	teardown(data_dir);
}

#[test]
fn variable_size_data_file_replace_with_tmp_rejects_unsynced_size_state() {
	let (data_dir, elems) = setup("variable_size_replace_with_tmp_unsynced_state");
	let data_path = format!("{}/data.bin", data_dir);
	let size_path = format!("{}/data_size.bin", data_dir);
	let tmp_path = std::path::Path::new(&data_path).with_extension("tmp");
	{
		let size_file = AppendOnlyFile::<SizeEntry>::open(
			&size_path,
			SizeInfo::FixedSize(SizeEntry::LEN),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mut data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::VariableSize(Box::new(size_file)),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		data_file.append(&elems[0]).unwrap();
		let data_len = mwc_core::ser::ser_vec(0, &elems[0], ProtocolVersion(1))
			.unwrap()
			.len() as u64;
		data_file.rewind(0).unwrap();
		data_file.flush().unwrap();
		fs::write(
			&tmp_path,
			mwc_core::ser::ser_vec(0, &elems[1], ProtocolVersion(1)).unwrap(),
		)
		.unwrap();
		data_file.append(&elems[2]).unwrap();

		let err = data_file.replace_with_tmp().unwrap_err();
		assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("unsynced state"));
		assert_eq!(fs::metadata(&data_path).unwrap().len(), 0);
		assert_eq!(data_file.size().unwrap(), 0);
		assert_eq!(data_len, 4);
	}

	teardown(data_dir);
}

#[test]
fn data_file_discard_restores_zero_buffer_start_after_unsynced_rewind() {
	let (data_dir, _) = setup("data_file_discard_zero_buffer_start");
	let data_path = format!("{}/data.bin", data_dir);
	{
		let mut data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		data_file.append(&TestElem(1)).unwrap();
		data_file.rewind(1).unwrap();
		data_file.discard();

		assert_eq!(data_file.size().unwrap(), 0);
		assert_eq!(data_file.read(1).unwrap(), None);
	}

	teardown(data_dir);
}

#[test]
fn data_file_rewind_truncates_inside_unsynced_buffer() {
	let (data_dir, elems) = setup("data_file_rewind_inside_unsynced_buffer");
	let data_path = format!("{}/data.bin", data_dir);
	{
		let mut data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		data_file.append(&elems[0]).unwrap();
		data_file.flush().unwrap();
		data_file.append(&elems[1]).unwrap();
		data_file.append(&elems[2]).unwrap();

		data_file.rewind(2).unwrap();
		assert_eq!(data_file.read(2).unwrap(), Some(elems[1]));
		assert_eq!(data_file.read(3).unwrap(), None);

		data_file.flush().unwrap();
		assert_eq!(data_file.read(2).unwrap(), Some(elems[1]));
		assert_eq!(data_file.read(3).unwrap(), None);
	}

	teardown(data_dir);
}

#[test]
fn variable_size_data_file_rewind_truncates_inside_unsynced_buffer() {
	let (data_dir, elems) = setup("variable_size_data_file_rewind_inside_buffer");
	let data_path = format!("{}/data.bin", data_dir);
	let size_path = format!("{}/data_size.bin", data_dir);
	{
		let size_file = AppendOnlyFile::<SizeEntry>::open(
			&size_path,
			SizeInfo::FixedSize(SizeEntry::LEN),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mut data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::VariableSize(Box::new(size_file)),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		data_file.append(&elems[0]).unwrap();
		data_file.flush().unwrap();
		data_file.append(&elems[1]).unwrap();
		data_file.append(&elems[2]).unwrap();

		data_file.rewind(2).unwrap();
		assert_eq!(data_file.read(2).unwrap(), Some(elems[1]));
		assert_eq!(data_file.read(3).unwrap(), None);

		data_file.flush().unwrap();
	}
	{
		let size_file = AppendOnlyFile::<SizeEntry>::open(
			&size_path,
			SizeInfo::FixedSize(SizeEntry::LEN),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::VariableSize(Box::new(size_file)),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		assert_eq!(data_file.read(1).unwrap(), Some(elems[0]));
		assert_eq!(data_file.read(2).unwrap(), Some(elems[1]));
		assert_eq!(data_file.read(3).unwrap(), None);
	}

	teardown(data_dir);
}

#[test]
fn data_file_rewind_to_buffer_start_discards_unsynced_buffer() {
	let (data_dir, elems) = setup("data_file_rewind_to_buffer_start");
	let data_path = format!("{}/data.bin", data_dir);
	{
		let mut data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		data_file.append(&elems[0]).unwrap();
		data_file.flush().unwrap();
		data_file.append(&elems[1]).unwrap();

		data_file.rewind(1).unwrap();
		assert_eq!(data_file.read(1).unwrap(), Some(elems[0]));
		assert_eq!(data_file.read(2).unwrap(), None);

		data_file.flush().unwrap();
		assert_eq!(data_file.read(1).unwrap(), Some(elems[0]));
		assert_eq!(data_file.read(2).unwrap(), None);
	}

	teardown(data_dir);
}

#[test]
fn data_file_write_tmp_pruned_rejects_unconsumed_prune_pos() {
	let (data_dir, _) = setup("data_file_write_tmp_pruned_out_of_range");
	let data_path = format!("{}/data.bin", data_dir);
	{
		let mut data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		data_file.append(&TestElem(1)).unwrap();
		data_file.flush().unwrap();

		let err = data_file.write_tmp_pruned(&[2]).unwrap_err();
		assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("was not found"));
	}

	teardown(data_dir);
}

#[test]
fn data_file_write_tmp_pruned_rejects_zero_prune_pos() {
	let (data_dir, _) = setup("data_file_write_tmp_pruned_zero_pos");
	let data_path = format!("{}/data.bin", data_dir);
	{
		let data_file = DataFile::<TestElem>::open(
			&data_path,
			SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let err = data_file.write_tmp_pruned(&[0]).unwrap_err();
		assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("1-based and nonzero"));
	}

	teardown(data_dir);
}

#[test]
fn data_file_write_tmp_pruned_rejects_zero_byte_read_progress() {
	let (data_dir, _) = setup("data_file_write_tmp_pruned_zero_progress");
	let data_path = format!("{}/data.bin", data_dir);
	fs::write(&data_path, [1]).unwrap();
	{
		let data_file = DataFile::<ZeroReadElem>::open(
			&data_path,
			SizeInfo::FixedSize(1),
			ProtocolVersion(1),
			0,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let err = data_file.write_tmp_pruned(&[]).unwrap_err();
		assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
		assert!(err.to_string().contains("read made no progress"));
	}

	teardown(data_dir);
}

#[test]
fn append_pruned_subtree_non_contiguous_error_does_not_append_hash() {
	let (data_dir, _) = setup("append_pruned_subtree_non_contiguous_error");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		backend
			.append_pruned_subtree(Hash::from_vec(&[1]), 2)
			.unwrap();
		backend.sync().unwrap();
		let hash_size = backend.hash_size().unwrap();

		match backend.append_pruned_subtree(Hash::from_vec(&[2]), 0) {
			Err(mwc_core::core::pmmr::Error::InvalidState(msg)) => {
				assert!(msg.contains("not contiguous"), "unexpected error: {}", msg);
			}
			other => panic!("expected non-contiguous subtree rejection, got {:?}", other),
		}

		backend.sync().unwrap();
		assert_eq!(backend.hash_size().unwrap(), hash_size);
	}

	teardown(data_dir);
}

#[test]
fn check_compact_rejects_future_cutoff() {
	let (data_dir, elems) = setup("check_compact_future_cutoff");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mmr_size = load(0, &elems[0..2], &mut backend);
		backend.sync().unwrap();

		match backend.check_compact(mmr_size + 1, &Bitmap::new()) {
			Err(mwc_core::core::pmmr::Error::InvalidState(msg)) => {
				assert!(
					msg.contains("beyond current PMMR size"),
					"unexpected error: {}",
					msg
				);
			}
			other => panic!("expected future cutoff rejection, got {:?}", other),
		}
	}

	teardown(data_dir);
}

#[test]
fn unpruned_size_includes_unsynced_pruned_subtree_hashes() {
	let (data_dir, _) = setup("unpruned_size_unsynced_pruned_subtree");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		backend
			.append_pruned_subtree(Hash::from_vec(&[1]), 2)
			.unwrap();

		assert_eq!(backend.hash_size().unwrap(), 0);
		assert_eq!(backend.unpruned_size().unwrap(), 3);

		backend.sync().unwrap();
		assert_eq!(backend.hash_size().unwrap(), 1);
		assert_eq!(backend.unpruned_size().unwrap(), 3);
	}

	teardown(data_dir);
}

#[test]
fn discard_restores_prune_list_state() {
	let (data_dir, _) = setup("discard_restores_prune_list");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		backend
			.append_pruned_subtree(Hash::from_vec(&[1]), 2)
			.unwrap();
		assert!(Backend::<TestElem>::is_compacted(&backend, 0).unwrap());

		backend.discard().unwrap();

		assert!(!Backend::<TestElem>::is_compacted(&backend, 0).unwrap());
	}

	teardown(data_dir);
}

#[test]
fn get_data_rejects_missing_live_leaf_data() {
	let (data_dir, elems) = setup("missing_live_leaf_data");
	let mmr_size;
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		mmr_size = load(0, &elems[..2], &mut backend);
		backend.sync().unwrap();
	}

	let data_path = format!("{}/pmmr_data.bin", data_dir);
	fs::OpenOptions::new()
		.write(true)
		.open(data_path)
		.unwrap()
		.set_len(4)
		.unwrap();

	{
		let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);

		match pmmr.get_data(1) {
			Err(mwc_core::core::pmmr::Error::DataCorruption(msg)) => {
				assert!(
					msg.contains("Missing PMMR data"),
					"unexpected error: {}",
					msg
				);
			}
			other => panic!("expected missing data corruption, got {:?}", other),
		}
	}

	teardown(data_dir);
}

#[test]
fn push_consecutive_pruned_leaf_subtrees_reads_stored_sibling_hash() {
	let (data_dir, _) = setup("consecutive_pruned_leaf_subtrees");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let left = Hash::from_vec(&[1]);
		let right = Hash::from_vec(&[2]);
		let parent = (left, right).hash_with_index(0, 2).unwrap();

		let mut pmmr = PMMR::new(&mut backend);
		pmmr.push_pruned_subtree(left, 0).unwrap();
		pmmr.push_pruned_subtree(right, 1).unwrap();

		assert_eq!(pmmr.unpruned_size(), 3);
		assert_eq!(pmmr.get_hash(2).unwrap(), Some(parent));
	}

	teardown(data_dir);
}

#[test]
fn data_file_rewind_rejects_forward_position() {
	let (data_dir, elems) = setup("data_file_rewind_forward");
	let path = format!("{}/data.bin", data_dir);
	let mut data_file = DataFile::<TestElem>::open(
		&path,
		SizeInfo::FixedSize(TestElem::elmt_size().unwrap()),
		ProtocolVersion(1),
		0,
		VariableSizeMetadataValidation::Full,
	)
	.unwrap();
	data_file.append(&elems[0]).unwrap();

	let err = data_file.rewind(2).unwrap_err();

	assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
	assert_eq!(data_file.read(1).unwrap(), Some(elems[0]));

	teardown(data_dir);
}

#[test]
fn pmmr_compact_leaf_sibling() {
	let (data_dir, elems) = setup("compact_leaf_sibling");

	// setup the mmr store with all elements
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mmr_size = load(0, &elems[..], &mut backend);
		backend.sync().unwrap();

		assert_eq!(backend.n_unpruned_leaves().unwrap(), 19);
		// On far left of the MMR -
		// pos 1 and 2 are leaves (and siblings)
		// the parent is pos 3

		let (pos_0_hash, pos_1_hash, pos_2_hash) = {
			let pmmr = PMMR::at(&mut backend, mmr_size);
			(
				pmmr.get_hash(0).unwrap().unwrap(),
				pmmr.get_hash(1).unwrap().unwrap(),
				pmmr.get_hash(2).unwrap().unwrap(),
			)
		};

		// prune pos 1
		{
			let mut pmmr = PMMR::at(&mut backend, mmr_size);
			pmmr.prune(0).unwrap();

			// prune pos 8 as well to push the remove list past the cutoff
			pmmr.prune(7).unwrap();
		}
		backend.sync().unwrap();

		// // check pos 1, 2, 3 are in the state we expect after pruning
		{
			let pmmr = PMMR::at(&mut backend, mmr_size);

			assert_eq!(pmmr.n_unpruned_leaves().unwrap(), 17);

			// check that pos 0 is "removed"
			assert_eq!(pmmr.get_hash(0).unwrap(), None);

			// check that pos 1 and 2 are unchanged
			assert_eq!(pmmr.get_hash(1).unwrap().unwrap(), pos_1_hash);
			assert_eq!(pmmr.get_hash(2).unwrap().unwrap(), pos_2_hash);
		}

		// check we can still retrieve the "removed" element at pos 0
		// from the backend hash file.
		assert_eq!(backend.get_from_file(0).unwrap().unwrap(), pos_0_hash);

		// aggressively compact the PMMR files
		backend.check_compact(1, &Bitmap::new()).unwrap();

		// check pos 0, 1, 2 are in the state we expect after compacting
		{
			let pmmr = PMMR::at(&mut backend, mmr_size);

			// check that pos 0 is "removed"
			assert_eq!(pmmr.get_hash(0).unwrap(), None);

			// check that pos 1 and 2 are unchanged
			assert_eq!(pmmr.get_hash(1).unwrap().unwrap(), pos_1_hash);
			assert_eq!(pmmr.get_hash(2).unwrap().unwrap(), pos_2_hash);
		}

		// Check we can still retrieve the "removed" hash at pos 1 from the hash file.
		// It should still be available even after pruning and compacting.
		assert_eq!(backend.get_from_file(0).unwrap().unwrap(), pos_0_hash);
	}

	teardown(data_dir);
}

#[test]
fn pmmr_prune_compact() {
	let (data_dir, elems) = setup("prune_compact");

	// setup the mmr store with all elements
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mmr_size = load(0, &elems[..], &mut backend);
		backend.sync().unwrap();

		// save the root
		let root = {
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.root().unwrap()
		};

		// pruning some choice nodes
		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.prune(0).unwrap();
			pmmr.prune(3).unwrap();
			pmmr.prune(4).unwrap();
		}
		backend.sync().unwrap();

		// check the root and stored data
		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			assert_eq!(root, pmmr.root().unwrap());
			// check we can still retrieve same element from leaf index 2
			assert_eq!(pmmr.get_data(1).unwrap().unwrap(), TestElem(2));
			// and the same for leaf index 7
			assert_eq!(pmmr.get_data(10).unwrap().unwrap(), TestElem(7));
		}

		// compact
		backend.check_compact(2, &Bitmap::new()).unwrap();

		// recheck the root and stored data
		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			assert_eq!(root, pmmr.root().unwrap());
			assert_eq!(pmmr.get_data(1).unwrap().unwrap(), TestElem(2));
			assert_eq!(pmmr.get_data(10).unwrap().unwrap(), TestElem(7));
		}
	}

	teardown(data_dir);
}

#[test]
fn pmmr_reload() {
	let (data_dir, elems) = setup("reload");

	// set everything up with an initial backend
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		let mmr_size = load(0, &elems[..], &mut backend);

		// retrieve entries from the hash file for comparison later
		let pos_2_hash = backend.get_hash(2).unwrap().unwrap();
		let pos_3_hash = backend.get_hash(3).unwrap().unwrap();
		let pos_4_hash = backend.get_hash(4).unwrap().unwrap();

		// save the root
		let root = {
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.root().unwrap()
		};

		{
			backend.sync().unwrap();
			assert_eq!(backend.unpruned_size().unwrap(), mmr_size);

			// prune a node so we have prune data
			{
				let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
				pmmr.prune(0).unwrap();
			}
			backend.sync().unwrap();
			assert_eq!(backend.unpruned_size().unwrap(), mmr_size);

			// now check and compact the backend
			backend.check_compact(1, &Bitmap::new()).unwrap();
			assert_eq!(backend.unpruned_size().unwrap(), mmr_size);
			backend.sync().unwrap();
			assert_eq!(backend.unpruned_size().unwrap(), mmr_size);

			// prune another node to force compact to actually do something
			{
				let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
				pmmr.prune(3).unwrap();
				pmmr.prune(1).unwrap();
			}
			backend.sync().unwrap();
			assert_eq!(backend.unpruned_size().unwrap(), mmr_size);

			backend.check_compact(4, &Bitmap::new()).unwrap();

			backend.sync().unwrap();
			assert_eq!(backend.unpruned_size().unwrap(), mmr_size);

			// prune some more to get rm log data
			{
				let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
				pmmr.prune(4).unwrap();
			}
			backend.sync().unwrap();
			assert_eq!(backend.unpruned_size().unwrap(), mmr_size);
		}

		// create a new backend referencing the data files
		// and check everything still works as expected
		{
			let mut backend = mwc_store::pmmr::PMMRBackend::new(
				data_dir.to_string(),
				true,
				ProtocolVersion(1),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			assert_eq!(backend.unpruned_size().unwrap(), mmr_size);
			{
				let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
				assert_eq!(root, pmmr.root().unwrap());
			}

			// pos 0 and pos 1 are both removed (via parent pos 2 in prune list)
			assert_eq!(backend.get_hash(0).unwrap(), None);
			assert_eq!(backend.get_hash(1).unwrap(), None);

			// pos 2 is "removed" but we keep the hash around for root of pruned subtree
			assert_eq!(backend.get_hash(2).unwrap(), Some(pos_2_hash));

			// pos 3 is removed (via prune list)
			assert_eq!(backend.get_hash(3).unwrap(), None);
			// pos 4 is removed (via leaf_set)
			assert_eq!(backend.get_hash(4).unwrap(), None);

			// now check contents of the hash file
			// pos 0 and pos 1 are no longer in the hash file
			assert_eq!(backend.get_from_file(0).unwrap(), None);
			assert_eq!(backend.get_from_file(1).unwrap(), None);

			// pos 2 is still in there
			assert_eq!(backend.get_from_file(2).unwrap(), Some(pos_2_hash));

			// pos 3 and pos 4 are also still in there
			assert_eq!(backend.get_from_file(3).unwrap(), Some(pos_3_hash));
			assert_eq!(backend.get_from_file(4).unwrap(), Some(pos_4_hash));
		}
	}

	teardown(data_dir);
}

#[test]
fn pmmr_rewind() {
	let (data_dir, elems) = setup("rewind");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.clone(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();

		// adding elements and keeping the corresponding root
		let mut mmr_size = load(0, &elems[0..4], &mut backend);
		backend.sync().unwrap();
		let root1 = {
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.root().unwrap()
		};

		mmr_size = load(mmr_size, &elems[4..6], &mut backend);
		backend.sync().unwrap();
		let root2 = {
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			assert_eq!(pmmr.unpruned_size(), 10);
			pmmr.root().unwrap()
		};

		mmr_size = load(mmr_size, &elems[6..9], &mut backend);
		backend.sync().unwrap();
		let root3 = {
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			assert_eq!(pmmr.unpruned_size(), 16);
			pmmr.root().unwrap()
		};

		// prune the first 4 elements (leaves at pos 1, 2, 4, 5)
		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.prune(0).unwrap();
			pmmr.prune(1).unwrap();
			pmmr.prune(3).unwrap();
			pmmr.prune(4).unwrap();
		}
		backend.sync().unwrap();

		// and compact the MMR to remove the pruned elements
		backend.check_compact(6, &Bitmap::new()).unwrap();
		backend.sync().unwrap();

		println!("root1 {:?}, root2 {:?}, root3 {:?}", root1, root2, root3);

		// rewind and check the roots still match
		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.rewind(9, &Bitmap::of(&vec![11, 12, 16])).unwrap();
			assert_eq!(pmmr.unpruned_size(), 10);

			assert_eq!(pmmr.root().unwrap(), root2);
		}

		backend.sync().unwrap();

		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, 10);
			assert_eq!(pmmr.root().unwrap(), root2);
		}

		// Also check the data file looks correct.
		// pos 0, 1, 3, 4 are all leaves but these have been pruned.
		for pos in vec![0, 1, 3, 4] {
			assert_eq!(backend.get_data(pos).unwrap(), None);
		}
		// pos 2, 5, 6 are non-leaves so we have no data for these
		for pos in vec![2, 5, 6] {
			assert_eq!(backend.get_data(pos).unwrap(), None);
		}

		// pos 7 and 8 are both leaves and should be unaffected by prior pruning

		assert_eq!(backend.get_data(7).unwrap(), Some(elems[4]));
		assert_eq!(
			backend.get_hash(7).unwrap(),
			Some(elems[4].hash_with_index(0, 7).unwrap())
		);

		assert_eq!(backend.get_data(8).unwrap(), Some(elems[5]));
		assert_eq!(
			backend.get_hash(8).unwrap(),
			Some(elems[5].hash_with_index(0, 8).unwrap())
		);

		// TODO - Why is this 2 here?
		println!("***** backend size here: {}", backend.data_size().unwrap());
		assert_eq!(backend.data_size().unwrap(), 2);

		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, 10);
			pmmr.rewind(5, &Bitmap::new()).unwrap();
			assert_eq!(pmmr.root().unwrap(), root1);
		}
		backend.sync().unwrap();

		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, 7);
			assert_eq!(pmmr.root().unwrap(), root1);
		}

		// also check the data file looks correct
		// everything up to and including pos 6 should be pruned from the data file
		// but we have rewound to pos 4 so everything after that should be None
		for pos in 0..16 {
			assert_eq!(backend.get_data(pos).unwrap(), None);
		}

		println!(
			"***** backend hash size here: {}",
			backend.hash_size().unwrap()
		);
		println!(
			"***** backend data size here: {}",
			backend.data_size().unwrap()
		);

		// check we have no data in the backend after
		// pruning, compacting and rewinding
		assert_eq!(backend.hash_size().unwrap(), 1);
		assert_eq!(backend.data_size().unwrap(), 0);
	}

	teardown(data_dir);
}

#[test]
fn pmmr_compact_single_leaves() {
	let (data_dir, elems) = setup("compact_single_leaves");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.clone(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mmr_size = load(0, &elems[0..5], &mut backend);
		backend.sync().unwrap();

		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.prune(0).unwrap();
			pmmr.prune(3).unwrap();
		}

		backend.sync().unwrap();

		// compact
		backend.check_compact(2, &Bitmap::new()).unwrap();

		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.prune(1).unwrap();
			pmmr.prune(4).unwrap();
		}

		backend.sync().unwrap();

		// compact
		backend.check_compact(2, &Bitmap::new()).unwrap();
	}

	teardown(data_dir);
}

#[test]
fn pmmr_compact_entire_peak() {
	let (data_dir, elems) = setup("compact_entire_peak");
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.clone(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mmr_size = load(0, &elems[0..5], &mut backend);
		backend.sync().unwrap();

		let pos_6_hash = backend.get_hash(6).unwrap().unwrap();

		let pos_7 = backend.get_data(7).unwrap().unwrap();
		let pos_7_hash = backend.get_hash(7).unwrap().unwrap();

		// prune all leaves under the peak at pos 7
		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.prune(0).unwrap();
			pmmr.prune(1).unwrap();
			pmmr.prune(3).unwrap();
			pmmr.prune(4).unwrap();
		}

		backend.sync().unwrap();

		// compact
		backend.check_compact(2, &Bitmap::new()).unwrap();

		// now check we have pruned up to and including the peak at pos 7
		// hash still available in underlying hash file
		assert_eq!(backend.get_hash(6).unwrap(), Some(pos_6_hash));
		assert_eq!(backend.get_from_file(6).unwrap(), Some(pos_6_hash));

		// now check we still have subsequent hash and data where we expect
		assert_eq!(backend.get_data(7).unwrap(), Some(pos_7));
		assert_eq!(backend.get_hash(7).unwrap(), Some(pos_7_hash));
		assert_eq!(backend.get_from_file(7).unwrap(), Some(pos_7_hash));
	}

	teardown(data_dir);
}

#[test]
fn pmmr_compact_horizon() {
	let (data_dir, elems) = setup("compact_horizon");
	{
		let pos_0_hash;
		let pos_1_hash;
		let pos_2_hash;
		let pos_5_hash;
		let pos_6_hash;

		let pos_7;
		let pos_7_hash;

		let pos_10;
		let pos_10_hash;

		let mmr_size;
		{
			let mut backend = mwc_store::pmmr::PMMRBackend::new(
				data_dir.clone(),
				true,
				ProtocolVersion(1),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();
			mmr_size = load(0, &elems[..], &mut backend);
			backend.sync().unwrap();

			// 0010012001001230
			// 9 leaves
			assert_eq!(backend.data_size().unwrap(), 19);
			assert_eq!(backend.hash_size().unwrap(), 35);

			pos_0_hash = backend.get_hash(0).unwrap().unwrap();
			pos_1_hash = backend.get_hash(1).unwrap().unwrap();
			pos_2_hash = backend.get_hash(2).unwrap().unwrap();
			pos_5_hash = backend.get_hash(5).unwrap().unwrap();
			pos_6_hash = backend.get_hash(6).unwrap().unwrap();

			pos_7 = backend.get_data(7).unwrap().unwrap();
			pos_7_hash = backend.get_hash(7).unwrap().unwrap();

			pos_10 = backend.get_data(10).unwrap().unwrap();
			pos_10_hash = backend.get_hash(10).unwrap().unwrap();

			// pruning some choice nodes
			{
				let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
				pmmr.prune(3).unwrap();
				pmmr.prune(4).unwrap();
				pmmr.prune(0).unwrap();
				pmmr.prune(1).unwrap();
			}
			backend.sync().unwrap();

			// check we can read hashes and data correctly after pruning
			{
				// assert_eq!(backend.get_hash(3).unwrap(), None);
				assert_eq!(backend.get_from_file(2).unwrap(), Some(pos_2_hash));

				// assert_eq!(backend.get_hash(6).unwrap(), None);
				assert_eq!(backend.get_from_file(5).unwrap(), Some(pos_5_hash));

				// assert_eq!(backend.get_hash(7).unwrap(), None);
				assert_eq!(backend.get_from_file(6).unwrap(), Some(pos_6_hash));

				assert_eq!(backend.get_hash(7).unwrap(), Some(pos_7_hash));
				assert_eq!(backend.get_data(7).unwrap(), Some(pos_7));
				assert_eq!(backend.get_from_file(7).unwrap(), Some(pos_7_hash));

				assert_eq!(backend.get_hash(10).unwrap(), Some(pos_10_hash));
				assert_eq!(backend.get_data(10).unwrap(), Some(pos_10));
				assert_eq!(backend.get_from_file(10).unwrap(), Some(pos_10_hash));
			}

			// compact
			backend.check_compact(4, &Bitmap::of(&vec![1, 2])).unwrap();
			backend.sync().unwrap();

			// check we can read a hash by pos correctly after compaction
			{
				assert_eq!(backend.get_hash(0).unwrap(), None);
				assert_eq!(backend.get_from_file(0).unwrap(), Some(pos_0_hash));

				assert_eq!(backend.get_hash(1).unwrap(), None);
				assert_eq!(backend.get_from_file(1).unwrap(), Some(pos_1_hash));

				assert_eq!(backend.get_hash(2).unwrap(), Some(pos_2_hash));

				assert_eq!(backend.get_hash(3).unwrap(), None);
				assert_eq!(backend.get_hash(4).unwrap(), None);
				assert_eq!(backend.get_hash(5).unwrap(), Some(pos_5_hash));

				assert_eq!(backend.get_from_file(6).unwrap(), Some(pos_6_hash));

				assert_eq!(backend.get_hash(7).unwrap(), Some(pos_7_hash));
				assert_eq!(backend.get_from_file(7).unwrap(), Some(pos_7_hash));
			}
		}

		// recheck stored data
		{
			// recreate backend
			let backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
				data_dir.to_string(),
				true,
				ProtocolVersion(1),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			assert_eq!(backend.data_size().unwrap(), 19);
			assert_eq!(backend.hash_size().unwrap(), 35);

			// check we can read a hash by pos correctly from recreated backend
			assert_eq!(backend.get_hash(6).unwrap(), Some(pos_6_hash));
			assert_eq!(backend.get_from_file(6).unwrap(), Some(pos_6_hash));

			assert_eq!(backend.get_hash(7).unwrap(), Some(pos_7_hash));
			assert_eq!(backend.get_from_file(7).unwrap(), Some(pos_7_hash));
		}

		{
			let mut backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
				data_dir.to_string(),
				true,
				ProtocolVersion(1),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			{
				let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);

				pmmr.prune(7).unwrap();
				pmmr.prune(8).unwrap();
			}

			// compact some more
			backend.check_compact(9, &Bitmap::new()).unwrap();
		}

		// recheck stored data
		{
			// recreate backend
			let backend = mwc_store::pmmr::PMMRBackend::<TestElem>::new(
				data_dir.to_string(),
				true,
				ProtocolVersion(1),
				0,
				None,
				VariableSizeMetadataValidation::Full,
			)
			.unwrap();

			// 0010012001001230

			assert_eq!(backend.data_size().unwrap(), 13);
			assert_eq!(backend.hash_size().unwrap(), 27);

			// check we can read a hash by pos correctly from recreated backend
			// get_hash() and get_from_file() should return the same value
			// and we only store leaves in the leaf_set so pos 6 still has a hash in there
			assert_eq!(backend.get_hash(6).unwrap(), Some(pos_6_hash));
			assert_eq!(backend.get_from_file(6).unwrap(), Some(pos_6_hash));

			assert_eq!(backend.get_hash(10).unwrap(), Some(pos_10_hash));
			assert_eq!(backend.get_data(10).unwrap(), Some(pos_10));
			assert_eq!(backend.get_from_file(10).unwrap(), Some(pos_10_hash));
		}
	}

	teardown(data_dir);
}

#[test]
fn compact_twice() {
	let (data_dir, elems) = setup("compact_twice");

	// setup the mmr store with all elements
	// Scoped to allow Windows to teardown
	{
		let mut backend = mwc_store::pmmr::PMMRBackend::new(
			data_dir.to_string(),
			true,
			ProtocolVersion(1),
			0,
			None,
			VariableSizeMetadataValidation::Full,
		)
		.unwrap();
		let mmr_size = load(0, &elems[..], &mut backend);
		backend.sync().unwrap();

		// save the root
		let root = {
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.root().unwrap()
		};

		// pruning some choice nodes
		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.prune(0).unwrap();
			pmmr.prune(1).unwrap();
			pmmr.prune(3).unwrap();
		}
		backend.sync().unwrap();

		// check the root and stored data
		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			assert_eq!(root, pmmr.root().unwrap());
			assert_eq!(pmmr.get_data(4).unwrap().unwrap(), TestElem(4));
			assert_eq!(pmmr.get_data(10).unwrap().unwrap(), TestElem(7));
		}

		// compact
		backend.check_compact(2, &Bitmap::new()).unwrap();

		// recheck the root and stored data
		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			assert_eq!(root, pmmr.root().unwrap());
			assert_eq!(pmmr.get_data(4).unwrap().unwrap(), TestElem(4));
			assert_eq!(pmmr.get_data(10).unwrap().unwrap(), TestElem(7));
		}

		// now prune some more nodes
		{
			let mut pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			pmmr.prune(4).unwrap();
			pmmr.prune(7).unwrap();
			pmmr.prune(8).unwrap();
		}
		backend.sync().unwrap();

		// recheck the root and stored data
		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			assert_eq!(root, pmmr.root().unwrap());
			assert_eq!(pmmr.get_data(10).unwrap().unwrap(), TestElem(7));
		}

		// compact
		backend.check_compact(2, &Bitmap::new()).unwrap();

		// recheck the root and stored data
		{
			let pmmr: PMMR<'_, TestElem, _> = PMMR::at(&mut backend, mmr_size);
			assert_eq!(root, pmmr.root().unwrap());
			assert_eq!(pmmr.get_data(10).unwrap().unwrap(), TestElem(7));
		}
	}

	teardown(data_dir);
}

#[test]
fn cleanup_rewind_files_test() {
	let expected = 10;
	let prefix_to_delete = "foo";
	let prefix_to_save = "bar";
	let seconds_to_delete_after = 100;

	// create the scenario
	let (data_dir, _) = setup("cleanup_rewind_files_test");
	// create some files with the delete prefix that aren't yet old enough to delete
	create_numbered_files(&data_dir, expected, prefix_to_delete, 0, 0);
	// create some files with the delete prefix that are old enough to delete
	create_numbered_files(
		&data_dir,
		expected,
		prefix_to_delete,
		seconds_to_delete_after + 1,
		expected,
	);
	// create some files with the save prefix that are old enough to delete, but will be saved because they don't start
	// with the right prefix
	create_numbered_files(
		&data_dir,
		expected,
		prefix_to_save,
		seconds_to_delete_after,
		0,
	);

	// run the cleaner
	let actual = mwc_store::pmmr::clean_files_by_prefix(
		&data_dir,
		prefix_to_delete,
		seconds_to_delete_after,
	)
	.unwrap();
	assert_eq!(
		actual.deleted, expected,
		"the clean files by prefix function did not report the correct number of files deleted"
	);
	assert_eq!(
		actual.failed, 0,
		"the clean files by prefix function unexpectedly reported cleanup failures"
	);

	// check that the reported number is actually correct, the block is to borrow data_dir for the closure
	{
		// this function simply counts the number of files in the directory based on the prefix
		let count_fn = |prefix| {
			let mut remaining_count = 0;
			for entry in fs::read_dir(&data_dir).unwrap() {
				if entry
					.unwrap()
					.file_name()
					.into_string()
					.unwrap()
					.starts_with(prefix)
				{
					remaining_count += 1;
				}
			}
			remaining_count
		};

		assert_eq!(
			count_fn(prefix_to_delete),
			expected, // we expect this many to be left because they weren't old enough to be deleted yet
			"it should delete all of the files it is supposed to delete"
		);
		assert_eq!(
			count_fn(prefix_to_save),
			expected,
			"it should delete none of the files it is not supposed to"
		);
	}

	teardown(data_dir);
}

#[cfg(unix)]
#[test]
fn cleanup_rewind_files_reports_per_entry_failures() {
	use std::os::unix::fs::PermissionsExt;

	let prefix_to_delete = "foo";
	let seconds_to_delete_after = 100;
	let (data_dir, _) = setup("cleanup_rewind_files_reports_per_entry_failures");
	create_numbered_files(
		&data_dir,
		1,
		prefix_to_delete,
		seconds_to_delete_after + 1,
		0,
	);
	let original_permissions = fs::metadata(&data_dir).unwrap().permissions();
	let mut read_only_permissions = original_permissions.clone();
	read_only_permissions.set_mode(0o500);
	fs::set_permissions(&data_dir, read_only_permissions).unwrap();

	let actual = mwc_store::pmmr::clean_files_by_prefix(
		&data_dir,
		prefix_to_delete,
		seconds_to_delete_after,
	)
	.unwrap();
	fs::set_permissions(&data_dir, original_permissions).unwrap();
	assert_eq!(actual.deleted, 0);
	assert_eq!(actual.failed, 1);

	teardown(data_dir);
}

/// Create some files for testing with, for example
///
/// ```text
/// create_numbered_files(".", 3, "hello.txt.", 100, 2)
/// ```
///
/// will create files
///
/// ```text
/// hello.txt.2
/// hello.txt.3
/// hello.txt.4
/// ```
///
/// in the current working directory that are all 100 seconds old (modified and accessed time)
///
fn create_numbered_files(
	data_dir: &str,
	num_files: u32,
	prefix: &str,
	last_accessed_delay_seconds: u64,
	start_index: u32,
) {
	let now = std::time::SystemTime::now();
	let time_to_set = now - std::time::Duration::from_secs(last_accessed_delay_seconds);
	let time_to_set_ft = filetime::FileTime::from_system_time(time_to_set);

	for rewind_file_num in 0..num_files {
		let path = std::path::Path::new(&data_dir).join(format!(
			"{}.{}",
			prefix,
			start_index + rewind_file_num
		));
		let file = fs::File::create(path.clone()).unwrap();
		let _metadata = file.metadata().unwrap();
		filetime::set_file_times(path, time_to_set_ft, time_to_set_ft).unwrap();
	}
}

fn setup(tag: &str) -> (String, Vec<TestElem>) {
	match env_logger::try_init() {
		Ok(_) => println!("Initializing env logger"),
		Err(e) => println!("env logger already initialized: {:?}", e),
	};
	let t = Utc::now();
	let data_dir = format!(
		"./target/tmp/{}.{}-{}",
		t.timestamp(),
		t.timestamp_subsec_nanos(),
		tag
	);
	fs::create_dir_all(data_dir.clone()).unwrap();

	let mut elems = vec![];
	for x in 1..20 {
		elems.push(TestElem(x));
	}
	(data_dir, elems)
}

/// note that taking ownership of the data_dir is a feature
/// because it will not be able to be used after teardown as intended
fn teardown(data_dir: String) {
	fs::remove_dir_all(data_dir).unwrap();
}

fn load(pos: u64, elems: &[TestElem], backend: &mut mwc_store::pmmr::PMMRBackend<TestElem>) -> u64 {
	let mut pmmr = PMMR::at(backend, pos);
	for elem in elems {
		pmmr.push(elem).unwrap();
	}
	pmmr.unpruned_size()
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct TestElem(u32);

impl DefaultHashable for TestElem {}

impl PMMRable for TestElem {
	type E = Self;

	fn as_elmt(&self) -> Result<TestElem, Error> {
		Ok(self.clone())
	}

	fn elmt_size() -> Option<u16> {
		Some(4)
	}
}

impl Writeable for TestElem {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u32(self.0)
	}
}
impl Readable for TestElem {
	fn read<R: Reader>(reader: &mut R) -> Result<TestElem, Error> {
		Ok(TestElem(reader.read_u32()?))
	}
}

#[derive(Debug)]
struct UnreadableElem;

impl Writeable for UnreadableElem {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u32(0)
	}
}

impl Readable for UnreadableElem {
	fn read<R: Reader>(_reader: &mut R) -> Result<UnreadableElem, Error> {
		Err(Error::CorruptedData(
			"UnreadableElem should not be deserialized".to_string(),
		))
	}
}

#[derive(Copy, Clone, Debug)]
struct ShortFixedElem;

impl Writeable for ShortFixedElem {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u16(1)
	}
}

impl Readable for ShortFixedElem {
	fn read<R: Reader>(reader: &mut R) -> Result<ShortFixedElem, Error> {
		reader.read_u16()?;
		Ok(ShortFixedElem)
	}
}

#[derive(Copy, Clone, Debug)]
struct LongFixedElem;

impl Writeable for LongFixedElem {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u64(1)
	}
}

impl Readable for LongFixedElem {
	fn read<R: Reader>(reader: &mut R) -> Result<LongFixedElem, Error> {
		reader.read_u64()?;
		Ok(LongFixedElem)
	}
}

#[derive(Copy, Clone, Debug)]
struct ZeroReadElem;

impl Writeable for ZeroReadElem {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u8(1)
	}
}

impl Readable for ZeroReadElem {
	fn read<R: Reader>(_reader: &mut R) -> Result<ZeroReadElem, Error> {
		Ok(ZeroReadElem)
	}
}
