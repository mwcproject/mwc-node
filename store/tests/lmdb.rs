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

use mwc_core::global;
use mwc_core::ser::{self, Readable, Reader, Writeable, Writer};
use std::fs;

const WRITE_CHUNK_SIZE: usize = 20;
const TEST_ALLOC_SIZE: usize = mwc_store::lmdb::ALLOC_CHUNK_SIZE_DEFAULT / 8 / WRITE_CHUNK_SIZE;

#[derive(Clone)]
struct PhatChunkStruct {
	phatness: u64,
}

impl PhatChunkStruct {
	/// create
	pub fn new() -> PhatChunkStruct {
		PhatChunkStruct { phatness: 0 }
	}
}

impl Readable for PhatChunkStruct {
	fn read<R: Reader>(reader: &mut R) -> Result<PhatChunkStruct, ser::Error> {
		let mut retval = PhatChunkStruct::new();
		for _ in 0..TEST_ALLOC_SIZE {
			retval.phatness = reader.read_u64()?;
		}
		Ok(retval)
	}
}

impl Writeable for PhatChunkStruct {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		// write many times
		for _ in 0..TEST_ALLOC_SIZE {
			writer.write_u64(self.phatness)?;
		}
		Ok(())
	}
}

fn clean_output_dir(test_dir: &str) {
	let _ = fs::remove_dir_all(test_dir);
}

fn setup(test_dir: &str) {
	global::set_local_chain_type(global::ChainTypes::Mainnet);
	global::set_local_nrd_enabled(false);
	mwc_util::init_test_logger().unwrap();
	clean_output_dir(test_dir);
}

#[cfg(unix)]
#[test]
fn lmdb_creates_owner_only_env_dir() -> Result<(), mwc_store::Error> {
	use std::os::unix::fs::PermissionsExt;

	let test_dir = "target/lmdb_creates_owner_only_env_dir";
	setup(test_dir);

	let store = mwc_store::Store::new(0, test_dir, Some("test1"), None, None)?;
	drop(store);

	let mode = fs::metadata(format!("{}/test1", test_dir))
		.unwrap()
		.permissions()
		.mode()
		& 0o777;
	assert_eq!(mode, 0o700);

	clean_output_dir(test_dir);
	Ok(())
}

#[cfg(unix)]
#[test]
fn lmdb_rejects_group_or_other_writable_env_dir() {
	use std::os::unix::fs::PermissionsExt;

	let test_dir = "target/lmdb_rejects_group_or_other_writable_env_dir";
	setup(test_dir);
	let env_dir = format!("{}/test1", test_dir);
	fs::create_dir_all(&env_dir).unwrap();
	fs::set_permissions(&env_dir, fs::Permissions::from_mode(0o777)).unwrap();

	match mwc_store::Store::new(0, test_dir, Some("test1"), None, None) {
		Err(mwc_store::Error::FileErr(msg)) => {
			assert!(msg.contains("unsafe group/other write permissions"));
		}
		Err(e) => panic!("expected FileErr, got {}", e),
		Ok(_) => panic!("expected unsafe LMDB directory permissions to be rejected"),
	}

	clean_output_dir(test_dir);
}

#[cfg(unix)]
#[test]
fn lmdb_rejects_symlink_env_dir() {
	use std::os::unix::fs::symlink;

	let test_dir = "target/lmdb_rejects_symlink_env_dir";
	setup(test_dir);
	let target_dir = format!("{}/target_dir", test_dir);
	let env_dir = format!("{}/test1", test_dir);
	fs::create_dir_all(&target_dir).unwrap();
	symlink(&target_dir, &env_dir).unwrap();

	match mwc_store::Store::new(0, test_dir, Some("test1"), None, None) {
		Err(mwc_store::Error::FileErr(msg)) => {
			assert!(msg.contains("Unable to secure LMDB directory"));
		}
		Err(e) => panic!("expected FileErr, got {}", e),
		Ok(_) => panic!("expected symlink LMDB directory to be rejected"),
	}

	clean_output_dir(test_dir);
}

#[test]
fn test_exists() -> Result<(), mwc_store::Error> {
	let test_dir = "target/test_exists";
	setup(test_dir);

	let store = mwc_store::Store::new(0, test_dir, Some("test1"), None, None)?;

	let key = [0, 0, 0, 1];
	let value = [1, 1, 1, 1];

	// Start new batch and insert a new key/value entry.
	let batch = store.batch_write()?;
	batch.put(&key, &value)?;

	// Check we can see the new entry in uncommitted batch.
	assert!(batch.exists(&key)?);

	// Check batch iteration uses the batch transaction and can see uncommitted data.
	let mut batch_iter = batch.iter(&[0], |_, v| Ok(v.to_vec()))?;
	assert_eq!(batch_iter.next().transpose()?, Some(value.to_vec()));
	assert_eq!(batch_iter.next().transpose()?, None);
	drop(batch_iter);

	// Check we cannot see the new entry yet outside of the uncommitted batch.
	assert!(!store.exists(&key)?);

	batch.commit()?;

	// Check we can see the new entry after committing the batch.
	assert!(store.exists(&key)?);

	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn store_open_is_idempotent() -> Result<(), mwc_store::Error> {
	let test_dir = "target/store_open_is_idempotent";
	setup(test_dir);

	let store = mwc_store::Store::new(0, test_dir, Some("test1"), None, None)?;
	store.open()?;
	store.open()?;

	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn db_unavailable_is_not_not_found() {
	let err = mwc_store::Error::DbUnavailable("chain db is None".to_string());
	assert!(!err.store_error_is_not_found(), "{:?}", err);
}

#[test]
fn resize_waits_for_active_batch() -> Result<(), mwc_store::Error> {
	use std::sync::mpsc;
	use std::sync::Arc;
	use std::time::Duration;

	let test_dir = "target/resize_waits_for_active_batch";
	setup(test_dir);

	let store = Arc::new(mwc_store::Store::new(
		0,
		test_dir,
		Some("test1"),
		None,
		None,
	)?);
	let store_for_resize = Arc::clone(&store);
	let batch = store.batch_read()?;
	let (done_tx, done_rx) = mpsc::channel();

	let resize_thread = std::thread::spawn(move || {
		let result = store_for_resize.do_resize();
		done_tx.send(()).unwrap();
		result
	});

	assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
	drop(batch);
	done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
	resize_thread.join().unwrap()?;

	drop(store);
	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn test_iter() -> Result<(), mwc_store::Error> {
	let test_dir = "target/test_iter";
	setup(test_dir);

	let store = mwc_store::Store::new(0, test_dir, Some("test1"), None, None)?;

	let key = [0, 0, 0, 1];
	let value = [1, 1, 1, 1];

	// Start new batch and insert a new key/value entry.
	let batch = store.batch_write()?;
	batch.put(&key, &value)?;

	// TODO - This is not currently possible (and we need to be aware of this).
	// Currently our SerIterator is limited to using a ReadTransaction only.
	//
	// Check we can see the new entry via an iterator using the uncommitted batch.
	// let mut iter: SerIterator<Vec<u8>> = batch.iter(&[0])?;
	// assert_eq!(iter.next(), Some((key.to_vec(), value.to_vec())));
	// assert_eq!(iter.next(), None);

	// Check we can not yet see the new entry via an iterator outside the uncommitted batch.
	let mut iter = store.iter(&[0], |_, v| Ok(v.to_vec()))?;
	assert_eq!(iter.next().transpose()?, None);

	batch.commit()?;

	// Check we can see the new entry via an iterator after committing the batch.
	let mut iter = store.iter(&[0], |_, v| Ok(v.to_vec()))?;
	assert_eq!(iter.next().transpose()?, Some(value.to_vec()));
	assert_eq!(iter.next().transpose()?, None);

	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn iter_returns_deserialize_errors() -> Result<(), mwc_store::Error> {
	let test_dir = "target/iter_returns_deserialize_errors";
	setup(test_dir);

	let store = mwc_store::Store::new(0, test_dir, Some("test1"), None, None)?;
	let key = [0, 0, 0, 1];
	let batch = store.batch_write()?;
	batch.put(&key, &[1])?;
	batch.commit()?;

	let mut iter = store.iter(&[0], |_, _| {
		Err::<Vec<u8>, _>(mwc_store::Error::OtherErr("bad record".to_string()))
	})?;
	match iter.next() {
		Some(Err(mwc_store::Error::OtherErr(msg))) => assert_eq!(msg, "bad record"),
		Some(Err(e)) => panic!("expected OtherErr, got {}", e),
		Some(Ok(_)) => panic!("expected iterator error"),
		None => panic!("expected iterator item"),
	}
	assert_eq!(iter.next().transpose()?, None);

	clean_output_dir(test_dir);
	Ok(())
}

#[test]
fn lmdb_allocate() -> Result<(), mwc_store::Error> {
	let test_dir = "target/lmdb_allocate";
	setup(test_dir);
	// Allocate more than the initial chunk, ensuring
	// the DB resizes underneath
	{
		let store = mwc_store::Store::new(0, test_dir, Some("test1"), None, None)?;

		for i in 0..WRITE_CHUNK_SIZE * 2 {
			println!("Allocating chunk: {}", i);
			let chunk = PhatChunkStruct::new();
			let key_val = format!("phat_chunk_set_1_{}", i);
			let batch = store.batch_write()?;
			let key = mwc_store::to_key(b'P', &key_val);
			batch.put_ser(&key, &chunk)?;
			batch.commit()?;
		}
	}
	println!("***********************************");
	println!("***************NEXT*****************");
	println!("***********************************");
	// Open env again and keep adding
	{
		let store = mwc_store::Store::new(0, test_dir, Some("test1"), None, None)?;
		for i in 0..WRITE_CHUNK_SIZE * 2 {
			println!("Allocating chunk: {}", i);
			let chunk = PhatChunkStruct::new();
			let key_val = format!("phat_chunk_set_2_{}", i);
			let batch = store.batch_write()?;
			let key = mwc_store::to_key(b'P', &key_val);
			batch.put_ser(&key, &chunk)?;
			batch.commit()?;
		}
	}

	Ok(())
}
