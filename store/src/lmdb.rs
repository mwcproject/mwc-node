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

//! Storage of core types using LMDB.

use mwc_crates::lmdb_zero;
use mwc_crates::lmdb_zero::traits::CreateCursor;
use mwc_crates::lmdb_zero::LmdbResultExt;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::Error::NotFoundErr;
use mwc_core::global;
use mwc_core::ser::{self, ProtocolVersion};
use mwc_crates::log::{debug, info, trace};
use mwc_crates::parking_lot::{RwLock, RwLockReadGuard};

/// number of bytes to grow the database by when needed
pub const ALLOC_CHUNK_SIZE_DEFAULT: usize = 134_217_728; //128 MB
/// And for test mode, to avoid too much disk allocation on windows
pub const ALLOC_CHUNK_SIZE_DEFAULT_TEST: usize = 1_048_576; //1 MB
const RESIZE_PERCENT_NUMERATOR: usize = 9;
const RESIZE_PERCENT_DENOMINATOR: usize = 10;
/// Want to ensure that each resize gives us at least this %
/// of total space free
const RESIZE_MIN_TARGET_PERCENT_NUMERATOR: usize = 65;
const RESIZE_MIN_TARGET_PERCENT_DENOMINATOR: usize = 100;

/// Main error type for this lmdb
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Couldn't find what we were looking for
	#[error("DB Not Found Error: {0}")]
	NotFoundErr(String),
	/// Database handle is not currently available.
	#[error("Database unavailable: {0}")]
	DbUnavailable(String),
	/// Wraps an error originating from LMDB
	#[error("LMDB error, {0}")]
	LmdbErr(#[from] lmdb_zero::error::Error),
	/// Wraps a serialization error for Writeable or Readable
	#[error("LMDB Serialization Error, {0}")]
	SerErr(#[from] ser::Error),
	/// File handling error
	#[error("File handling Error: {0}")]
	FileErr(String),
	/// Other error
	#[error("Other Error: {0}")]
	OtherErr(String),
	/// Batch type error
	#[error("Incorrect batch type: {0}")]
	BatchTypeError(String),
	/// IO error
	#[error("IO Error: {0}")]
	IOErr(#[from] std::io::Error),
	/// Data overflow occurred.
	#[error("Data overflow error, {0}")]
	DataOverflow(String),
}

impl Error {
	/// Check if error related to DB related not found error
	pub fn store_error_is_not_found(&self) -> bool {
		match &self {
			NotFoundErr(_) => true,
			crate::Error::LmdbErr(mwc_crates::lmdb_zero::error::Error::Code(code)) => {
				*code == mwc_crates::lmdb_zero::error::NOTFOUND
			}
			_ => false,
		}
	}
}

/// unwraps the inner option by converting the none case to a not found error
pub fn option_to_not_found<T, F>(res: Result<Option<T>, Error>, field_name: F) -> Result<T, Error>
where
	F: Fn() -> String,
{
	match res {
		Ok(None) => Err(Error::NotFoundErr(field_name())),
		Ok(Some(o)) => Ok(o),
		Err(e) => Err(e),
	}
}

fn prepare_lmdb_env_dir(full_path: &str) -> Result<(), Error> {
	prepare_lmdb_env_dir_path(Path::new(full_path))
}

#[cfg(not(unix))]
fn prepare_lmdb_env_dir_path(path1: &Path) -> Result<(), Error> {
	// On non-Unix platforms we do not control filesystem permissions here. If
	// an attacker already controls the OS filesystem, there is not much this
	// storage layer can do to enforce LMDB directory isolation.
	fs::create_dir_all(path1).map_err(|e| {
		Error::FileErr(format!(
			"Unable to create LMDB directory '{}': {:?}",
			path1.display(),
			e
		))
	})
}

#[cfg(unix)]
fn prepare_lmdb_env_dir_path(path2: &Path) -> Result<(), Error> {
	use std::io::ErrorKind;
	use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

	let mut existed = path2.try_exists().map_err(|e| {
		Error::FileErr(format!(
			"Unable to inspect LMDB directory '{}': {:?}",
			path2.display(),
			e
		))
	})?;

	if !existed {
		let mut builder = fs::DirBuilder::new();
		builder.recursive(true);
		builder.mode(0o700);
		match builder.create(path2) {
			Ok(()) => {}
			Err(e) if e.kind() == ErrorKind::AlreadyExists => existed = true,
			Err(e) => {
				return Err(Error::FileErr(format!(
					"Unable to create LMDB directory '{}': {:?}",
					path2.display(),
					e
				)))
			}
		}
	}

	let dir = fs::OpenOptions::new()
		.read(true)
		.custom_flags(
			mwc_crates::libc::O_DIRECTORY
				| mwc_crates::libc::O_NOFOLLOW
				| mwc_crates::libc::O_CLOEXEC,
		)
		.open(path2)
		.map_err(|e| {
			Error::FileErr(format!(
				"Unable to open LMDB directory '{}': {:?}",
				path2.display(),
				e
			))
		})?;

	let metadata = dir.metadata().map_err(|e| {
		Error::FileErr(format!(
			"Unable to read LMDB directory metadata '{}': {:?}",
			path2.display(),
			e
		))
	})?;
	if !metadata.is_dir() {
		return Err(Error::FileErr(format!(
			"LMDB path '{}' is not a directory",
			path2.display()
		)));
	}

	// Ownership is intentionally not checked here. We only reject directories
	// that are writable by group/other and then tighten accepted directories to
	// owner-only permissions.
	// O_NOFOLLOW applies to the final path component opened above. LMDB is also
	// opened later by path, so this function does not try to defend against an
	// attacker who can modify ancestor directories, replace intermediate path
	// components, or swap this path after validation. If an attacker controls
	// the filesystem namespace above the database directory, this storage layer
	// cannot reliably preserve the intended directory binding.
	// This check is based on Unix mode bits only. Platform ACLs can grant access
	// independently of those bits, and if an attacker controls filesystem ACL
	// policy there is not much this layer can do to prevent access to the data.
	let mode = metadata.permissions().mode() & 0o777;
	if existed && (mode & 0o022) != 0 {
		return Err(Error::FileErr(format!(
			"LMDB directory '{}' has unsafe group/other write permissions {:o}",
			path2.display(),
			mode
		)));
	}

	dir.set_permissions(fs::Permissions::from_mode(0o700))
		.map_err(|e| {
			Error::FileErr(format!(
				"Unable to set LMDB directory '{}' permissions: {:?}",
				path2.display(),
				e
			))
		})
}

fn lmdb_size_used_bytes(page_size: usize, last_page: usize) -> Result<usize, Error> {
	last_page
		.checked_add(1)
		.and_then(|lp| page_size.checked_mul(lp))
		.ok_or_else(|| {
			Error::OtherErr(format!(
				"LMDB used size overflow, page_size={}, last_page={}",
				page_size, last_page
			))
		})
}

fn resize_threshold_exceeded(
	size_used: usize,
	mapsize: usize,
	numerator: usize,
	denominator: usize,
) -> Result<bool, Error> {
	let lhs = (size_used as u128)
		.checked_mul(denominator as u128)
		.ok_or_else(|| {
			Error::OtherErr(format!(
				"LMDB resize threshold overflow, size_used={}, denominator={}",
				size_used, denominator
			))
		})?;
	let rhs = (mapsize as u128)
		.checked_mul(numerator as u128)
		.ok_or_else(|| {
			Error::OtherErr(format!(
				"LMDB resize threshold overflow, mapsize={}, numerator={}",
				mapsize, numerator
			))
		})?;
	Ok(lhs > rhs)
}

const DEFAULT_DB_VERSION: ProtocolVersion = ProtocolVersion(3);

/// LMDB-backed store facilitating data access and serialization. All writes
/// are done through a Batch abstraction providing atomicity.
pub struct Store {
	env: Arc<lmdb_zero::Environment>,
	db: Arc<RwLock<Option<Arc<lmdb_zero::Database<'static>>>>>,
	resize_lock: Arc<RwLock<()>>,
	name: String,
	version: ProtocolVersion,
	alloc_chunk_size: usize,
	context_id: u32,
}

impl Store {
	/// Create a new LMDB env under the provided directory.
	/// By default creates an environment named "lmdb".
	/// Be aware of transactional semantics in lmdb
	/// (transactions are per environment, not per database).
	pub fn new(
		context_id: u32,
		root_path: &str,
		env_name: Option<&str>,
		db_name: Option<&str>,
		max_readers: Option<u32>,
	) -> Result<Store, Error> {
		let name = match env_name {
			Some(n) => n.to_owned(),
			None => "lmdb".to_owned(),
		};
		let db_name = match db_name {
			Some(n) => n.to_owned(),
			None => "lmdb".to_owned(),
		};
		// env_name is supplied by local, reviewable constants in current callers
		// ("lmdb" or test environment names), not by user input. Keep that
		// invariant rather than accepting path-like values here.
		let full_path = [root_path.to_owned(), name].join("/");
		prepare_lmdb_env_dir(&full_path)?;

		let mut env_builder = lmdb_zero::EnvBuilder::new()?;
		env_builder.set_maxdbs(8)?;

		if let Some(max_readers) = max_readers {
			env_builder.set_maxreaders(max_readers)?;
		}

		let alloc_chunk_size = match global::is_production_mode(context_id) {
			true => ALLOC_CHUNK_SIZE_DEFAULT,
			false => ALLOC_CHUNK_SIZE_DEFAULT_TEST,
		};

		let env = unsafe { env_builder.open(&full_path, lmdb_zero::open::NOTLS, 0o600)? };

		debug!("DB Mapsize for {} is {}", full_path, env.info()?.mapsize);
		let res = Store {
			env: Arc::new(env),
			db: Arc::new(RwLock::new(None)),
			resize_lock: Arc::new(RwLock::new(())),
			name: db_name,
			version: DEFAULT_DB_VERSION,
			alloc_chunk_size,
			context_id,
		};

		{
			let mut w = res.db.write();
			*w = Some(Arc::new(lmdb_zero::Database::open(
				res.env.clone(),
				Some(&res.name),
				&lmdb_zero::DatabaseOptions::new(lmdb_zero::db::CREATE),
			)?));
		}
		Ok(res)
	}

	/// Construct a new store using a specific protocol version.
	/// Permits access to the db with legacy protocol versions for db migrations.
	pub fn with_version(&self, context_id: u32, version: ProtocolVersion) -> Store {
		let alloc_chunk_size = match global::is_production_mode(context_id) {
			true => ALLOC_CHUNK_SIZE_DEFAULT,
			false => ALLOC_CHUNK_SIZE_DEFAULT_TEST,
		};
		Store {
			env: self.env.clone(),
			db: self.db.clone(),
			resize_lock: self.resize_lock.clone(),
			name: self.name.clone(),
			version,
			alloc_chunk_size,
			context_id,
		}
	}

	/// Protocol version for the store.
	pub fn protocol_version(&self) -> ProtocolVersion {
		self.version
	}

	/// Context Id for this store
	pub fn get_context_id(&self) -> u32 {
		self.context_id
	}

	/// Opens the database environment
	pub fn open(&self) -> Result<(), Error> {
		let _resize_guard = self.resize_lock.read_recursive();
		let mut w = self.db.write();
		if w.is_some() {
			return Ok(());
		}
		*w = Some(Arc::new(lmdb_zero::Database::open(
			self.env.clone(),
			Some(&self.name),
			&lmdb_zero::DatabaseOptions::new(lmdb_zero::db::CREATE),
		)?));
		Ok(())
	}

	/// Determines whether the environment needs a resize based on a simple percentage threshold
	pub fn needs_resize(&self) -> Result<bool, Error> {
		let _resize_guard = self.resize_lock.read_recursive();
		let env_info = self.env.info()?;
		let stat = self.env.stat()?;

		let size_used = lmdb_size_used_bytes(stat.psize as usize, env_info.last_pgno)?;
		trace!("DB map size: {}", env_info.mapsize);
		trace!("Space used: {}", size_used);
		if size_used >= env_info.mapsize {
			trace!("Space remaining: 0");
			trace!("Resize threshold met (LMDB reports used size >= map size)");
			return Ok(true);
		}
		trace!("Space remaining: {}", env_info.mapsize - size_used);
		trace!(
			"Percent used: {:.*}  Percent threshold: {}/{}",
			4,
			size_used as f64 / env_info.mapsize as f64,
			RESIZE_PERCENT_NUMERATOR,
			RESIZE_PERCENT_DENOMINATOR
		);

		if resize_threshold_exceeded(
			size_used,
			env_info.mapsize,
			RESIZE_PERCENT_NUMERATOR,
			RESIZE_PERCENT_DENOMINATOR,
		)? || env_info.mapsize < self.alloc_chunk_size
		{
			trace!("Resize threshold met (percent-based)");
			Ok(true)
		} else {
			trace!("Resize threshold not met (percent-based)");
			Ok(false)
		}
	}

	/// Increments the database size by as many ALLOC_CHUNK_SIZES
	/// to give a minimum threshold of free space
	pub fn do_resize(&self) -> Result<(), Error> {
		// Do active waiting for write with try lock, because write() lock will block next read
		// locks that can make a deadlock. Active write lock waiting should be fine
		let _resize_guard = loop {
			match self.resize_lock.try_write() {
				Some(l) => break l,
				None => {
					std::thread::sleep(Duration::from_millis(25));
					continue;
				}
			}
		};
		let env_info = self.env.info()?;
		let stat = self.env.stat()?;
		let size_used = lmdb_size_used_bytes(stat.psize as usize, env_info.last_pgno)?;

		let new_mapsize = if env_info.mapsize < self.alloc_chunk_size {
			self.alloc_chunk_size
		} else {
			let mut tot = env_info.mapsize;
			while resize_threshold_exceeded(
				size_used,
				tot,
				RESIZE_MIN_TARGET_PERCENT_NUMERATOR,
				RESIZE_MIN_TARGET_PERCENT_DENOMINATOR,
			)? {
				tot = tot.checked_add(self.alloc_chunk_size).ok_or_else(|| {
					Error::OtherErr(format!(
						"LMDB resize overflow, current mapsize={}, alloc_chunk_size={}",
						tot, self.alloc_chunk_size
					))
				})?;
			}
			tot
		};

		// Note: Intentionally closing and None DB during resize.
		// If resize failed, none of DB will be opened, so any db access will fails.
		// It is expected behavior, we can't keep using prev instance because it is almost full
		// and performance is degrading. We need to do resize of fail.
		let mut w = self.db.write();
		*w = None;

		unsafe {
			self.env.set_mapsize(new_mapsize)?;
		}

		*w = Some(Arc::new(lmdb_zero::Database::open(
			self.env.clone(),
			Some(&self.name),
			&lmdb_zero::DatabaseOptions::new(lmdb_zero::db::CREATE),
		)?));

		info!(
			"Resized database from {} to {}",
			env_info.mapsize, new_mapsize
		);
		Ok(())
	}

	/// Gets a value from the db, provided its key.
	/// Deserializes the retrieved data using the provided function.
	pub fn get_with<F, T>(
		&self,
		key: &[u8],
		access: &lmdb_zero::ConstAccessor<'_>,
		db: &lmdb_zero::Database<'_>,
		deserialize: F,
	) -> Result<Option<T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		let res: Option<&[u8]> = access.get(db, key).to_opt()?;
		match res {
			None => Ok(None),
			Some(res) => deserialize(key, res).map(Some),
		}
	}

	/// Gets a `Readable` value from the db, provided its key.
	/// Note: Creates a new read transaction so will *not* see any uncommitted data.
	pub fn get_ser<T: ser::Readable>(&self, key: &[u8]) -> Result<Option<T>, Error> {
		let _resize_guard = self.resize_lock.read_recursive();
		let lock = self.db.read_recursive();
		let db = lock
			.as_ref()
			.ok_or_else(|| Error::DbUnavailable("chain db is None".to_string()))?;
		let txn = lmdb_zero::ReadTransaction::new(self.env.clone())?;
		let access = txn.access();
		self.get_with(key, &access, &db, |_, mut data| {
			ser::deserialize_strict(&mut data, self.protocol_version(), self.context_id)
				.map_err(From::from)
		})
	}

	/// Whether the provided key exists
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		let _resize_guard = self.resize_lock.read_recursive();
		let lock = self.db.read_recursive();
		let db = lock
			.as_ref()
			.ok_or_else(|| Error::DbUnavailable("chain db is None".to_string()))?;
		let txn = lmdb_zero::ReadTransaction::new(self.env.clone())?;
		let access = txn.access();

		let res: Option<&lmdb_zero::Ignore> = access.get(db, key).to_opt()?;
		Ok(res.is_some())
	}

	/// Produces an iterator from the provided key prefix.
	pub fn iter<F, T>(
		&self,
		prefix: &[u8],
		deserialize: F,
	) -> Result<PrefixIterator<'_, 'static, F, T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		let resize_guard = self.resize_lock.read_recursive();
		let lock = self.db.read_recursive();
		let db = lock
			.as_ref()
			.ok_or_else(|| Error::DbUnavailable("chain db is None".to_string()))?;
		let tx = Arc::new(lmdb_zero::ReadTransaction::new(self.env.clone())?);
		let cursor = tx.cursor(db.clone())?;
		Ok(PrefixIterator::new_owned_read(
			tx,
			cursor,
			Some(resize_guard),
			prefix,
			deserialize,
		))
	}

	/// Builds a new read only batch to be used with this store.
	pub fn batch_read(&self) -> Result<Batch<'_>, Error> {
		let resize_guard = self.resize_lock.read_recursive();
		let tx = lmdb_zero::ReadTransaction::new(self.env.clone())?;
		Ok(Batch {
			store: self,
			tx_w: None,
			tx_r: Some(tx),
			_resize_guard: Some(resize_guard),
		})
	}

	/// Builds a new batch with write access to be used with this store.
	pub fn batch_write(&self) -> Result<Batch<'_>, Error> {
		// check if the db needs resizing before returning the batch
		if self.needs_resize()? {
			self.do_resize()?;
		}
		let resize_guard = self.resize_lock.read_recursive();
		let tx = lmdb_zero::WriteTransaction::new(self.env.clone())?;
		Ok(Batch {
			store: self,
			tx_w: Some(tx),
			tx_r: None,
			_resize_guard: Some(resize_guard),
		})
	}
}

/// Batch to write multiple Writeables to db in an atomic manner.
pub struct Batch<'a> {
	store: &'a Store,
	tx_w: Option<lmdb_zero::WriteTransaction<'a>>,
	tx_r: Option<lmdb_zero::ReadTransaction<'a>>,
	_resize_guard: Option<RwLockReadGuard<'a, ()>>,
}

impl<'a> Batch<'a> {
	/// Writes a single key/value pair to the db
	pub fn put(&self, key: &[u8], value: &[u8]) -> Result<(), Error> {
		let lock = self.store.db.read_recursive();
		let db = lock
			.as_ref()
			.ok_or_else(|| Error::DbUnavailable("chain db is None".to_string()))?;
		if let Some(tx) = &self.tx_w {
			tx.access()
				.put(db, key, value, lmdb_zero::put::Flags::empty())?;
			Ok(())
		} else {
			return Err(Error::BatchTypeError(
				"expected write batch, got read".to_string(),
			));
		}
	}

	/// Writes a single key and its `Writeable` value to the db.
	/// Encapsulates serialization using the (default) version configured on the store instance.
	pub fn put_ser<W: ser::Writeable>(&self, key: &[u8], value: &W) -> Result<(), Error> {
		self.put_ser_with_version(key, value, self.store.protocol_version())
	}

	/// Protocol version used by this batch.
	pub fn protocol_version(&self) -> ProtocolVersion {
		self.store.protocol_version()
	}

	/// Context id
	pub fn get_context_id(&self) -> u32 {
		self.store.get_context_id()
	}

	/// Writes a single key and its `Writeable` value to the db.
	/// Encapsulates serialization using the specified protocol version.
	pub fn put_ser_with_version<W: ser::Writeable>(
		&self,
		key: &[u8],
		value: &W,
		version: ProtocolVersion,
	) -> Result<(), Error> {
		let ser_value = ser::ser_vec(self.get_context_id(), value, version);
		match ser_value {
			Ok(data) => self.put(key, &data),
			Err(err) => Err(err.into()),
		}
	}

	/// Low-level access for retrieving data by key.
	/// Takes a function for flexible deserialization.
	pub fn get_with<F, T>(&self, key: &[u8], deserialize: F) -> Result<Option<T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		let lock = self.store.db.read_recursive();
		let db = lock
			.as_ref()
			.ok_or_else(|| Error::DbUnavailable("chain db is None".to_string()))?;

		if let Some(tx) = &self.tx_r {
			self.store.get_with(key, &tx.access(), &db, deserialize)
		} else if let Some(tx) = &self.tx_w {
			self.store.get_with(key, &tx.access(), &db, deserialize)
		} else {
			Err(Error::BatchTypeError(
				"No Read/Write transaction is found".to_string(),
			))
		}
	}

	/// Whether the provided key exists.
	/// This is in the context of the current write transaction.
	pub fn exists(&self, key: &[u8]) -> Result<bool, Error> {
		let lock = self.store.db.read_recursive();
		let db = lock
			.as_ref()
			.ok_or_else(|| Error::DbUnavailable("chain db is None".to_string()))?;

		if let Some(tx) = &self.tx_r {
			Ok(tx.access().get::<[u8], [u8]>(db, key).to_opt()?.is_some())
		} else if let Some(tx) = &self.tx_w {
			Ok(tx.access().get::<[u8], [u8]>(db, key).to_opt()?.is_some())
		} else {
			Err(Error::BatchTypeError(
				"No Read/Write transaction is found".to_string(),
			))
		}
	}

	/// Produces an iterator from the provided key prefix.
	pub fn iter<F, T>(
		&self,
		prefix: &[u8],
		deserialize: F,
	) -> Result<PrefixIterator<'_, 'a, F, T>, Error>
	where
		F: Fn(&[u8], &[u8]) -> Result<T, Error>,
	{
		let lock = self.store.db.read_recursive();
		let db = lock
			.as_ref()
			.ok_or_else(|| Error::DbUnavailable("chain db is None".to_string()))?;

		if let Some(tx) = &self.tx_r {
			let cursor = tx.cursor(db.clone())?;
			Ok(PrefixIterator {
				tx: PrefixIteratorTransaction::BorrowedRead(tx),
				cursor,
				seek: false,
				prefix: prefix.to_vec(),
				deserialize,
				_resize_guard: None,
			})
		} else if let Some(tx) = &self.tx_w {
			let cursor = tx.cursor(db.clone())?;
			Ok(PrefixIterator {
				tx: PrefixIteratorTransaction::BorrowedWrite(tx),
				cursor,
				seek: false,
				prefix: prefix.to_vec(),
				deserialize,
				_resize_guard: None,
			})
		} else {
			Err(Error::BatchTypeError(
				"No Read/Write transaction is found".to_string(),
			))
		}
	}

	/// Gets a `Readable` value from the db by provided key and provided deserialization strategy.
	pub fn get_ser<T: ser::Readable>(&self, key: &[u8]) -> Result<Option<T>, Error> {
		self.get_with(key, |_, mut data| {
			match ser::deserialize_strict(
				&mut data,
				self.protocol_version(),
				self.store.get_context_id(),
			) {
				Ok(res) => Ok(res),
				Err(e) => Err(From::from(e)),
			}
		})
	}

	/// Deletes a key/value pair from the db
	pub fn delete(&self, key: &[u8]) -> Result<(), Error> {
		let lock = self.store.db.read_recursive();
		let db = lock
			.as_ref()
			.ok_or_else(|| Error::DbUnavailable("chain db is None".to_string()))?;
		if let Some(tx) = &self.tx_w {
			tx.access().del_key(db, key)?;
			Ok(())
		} else {
			Err(Error::BatchTypeError(
				"expected write batch, got read".to_string(),
			))
		}
	}

	/// Writes the batch to db
	pub fn commit(self) -> Result<(), Error> {
		if let Some(tx) = self.tx_w {
			tx.commit()?;
			Ok(())
		} else {
			Err(Error::BatchTypeError(
				"expected write batch, got read".to_string(),
			))
		}
	}

	/// Creates a child of this batch. It will be merged with its parent on
	/// commit, abandoned otherwise.
	pub fn child(&mut self) -> Result<Batch<'_>, Error> {
		if self.tx_r.is_some() {
			return Err(Error::BatchTypeError(
				"Method 'child' called for read batch".to_string(),
			));
		}

		Ok(Batch {
			store: self.store,
			tx_r: None,
			tx_w: match self.tx_w.as_mut() {
				Some(tx) => Some(tx.child_tx()?),
				None => None,
			},
			_resize_guard: None,
		})
	}
}

/// An iterator based on key prefix.
/// Caller is responsible for deserialization of the data.
pub struct PrefixIterator<'txn, 'env, F, T>
where
	F: Fn(&[u8], &[u8]) -> Result<T, Error>,
{
	tx: PrefixIteratorTransaction<'txn, 'env>,
	cursor: lmdb_zero::Cursor<'txn, 'static>,
	seek: bool,
	prefix: Vec<u8>,
	deserialize: F,
	_resize_guard: Option<RwLockReadGuard<'txn, ()>>,
}

enum PrefixIteratorTransaction<'txn, 'env> {
	OwnedRead(Arc<lmdb_zero::ReadTransaction<'static>>),
	BorrowedRead(&'txn lmdb_zero::ReadTransaction<'env>),
	BorrowedWrite(&'txn lmdb_zero::WriteTransaction<'env>),
}

impl<F, T> Iterator for PrefixIterator<'_, '_, F, T>
where
	F: Fn(&[u8], &[u8]) -> Result<T, Error>,
{
	type Item = Result<T, Error>;

	fn next(&mut self) -> Option<Self::Item> {
		let cursor = &mut self.cursor;
		let seek = &mut self.seek;
		let prefix = &self.prefix;
		let deserialize = &self.deserialize;

		match &self.tx {
			PrefixIteratorTransaction::OwnedRead(tx) => {
				let access = tx.access();
				next_with_access(cursor, seek, prefix, deserialize, &access)
			}
			PrefixIteratorTransaction::BorrowedRead(tx) => {
				let access = tx.access();
				next_with_access(cursor, seek, prefix, deserialize, &access)
			}
			PrefixIteratorTransaction::BorrowedWrite(tx) => {
				let access = tx.access();
				next_with_access(cursor, seek, prefix, deserialize, &access)
			}
		}
	}
}

fn next_with_access<F, T>(
	cursor: &mut lmdb_zero::Cursor<'_, 'static>,
	seek: &mut bool,
	prefix: &[u8],
	deserialize: &F,
	access: &lmdb_zero::ConstAccessor<'_>,
) -> Option<Result<T, Error>>
where
	F: Fn(&[u8], &[u8]) -> Result<T, Error>,
{
	let kv: Result<(&[u8], &[u8]), _> = if *seek {
		cursor.next(access)
	} else {
		*seek = true;
		cursor.seek_range_k(access, prefix)
	};

	match kv.to_opt() {
		Ok(Some((k, v))) => {
			if !k.starts_with(prefix) {
				return None;
			}
			Some((deserialize)(k, v))
		}
		Ok(None) => None,
		Err(e) => Some(Err(e.into())),
	}
}

impl<'txn, 'env, F, T> PrefixIterator<'txn, 'env, F, T>
where
	F: Fn(&[u8], &[u8]) -> Result<T, Error>,
{
	fn new_owned_read(
		tx: Arc<lmdb_zero::ReadTransaction<'static>>,
		cursor: lmdb_zero::Cursor<'txn, 'static>,
		resize_guard: Option<RwLockReadGuard<'txn, ()>>,
		prefix: &[u8],
		deserialize: F,
	) -> PrefixIterator<'txn, 'env, F, T> {
		PrefixIterator {
			tx: PrefixIteratorTransaction::OwnedRead(tx),
			cursor,
			seek: false,
			prefix: prefix.to_vec(),
			deserialize,
			_resize_guard: resize_guard,
		}
	}
}
