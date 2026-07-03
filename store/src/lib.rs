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

//! Storage of core types using RocksDB.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

pub mod leaf_set;
pub mod lmdb;
pub mod pmmr;
pub mod prune_list;
pub mod types;

const SEP: u8 = b':';

use mwc_crates::byteorder::{BigEndian, WriteBytesExt};

pub use crate::lmdb::*;

/// Build a db key from a prefix and a byte vector identifier.
pub fn to_key<K: AsRef<[u8]>>(prefix: u8, k: K) -> Vec<u8> {
	let k = k.as_ref();
	let mut res = Vec::with_capacity(k.len() + 2);
	res.push(prefix);
	res.push(SEP);
	res.extend_from_slice(k);
	res
}

/// Build a db key from a prefix and a byte vector identifier and numeric identifier
pub fn to_key_u64<K: AsRef<[u8]>>(prefix: u8, k: K, val: u64) -> Result<Vec<u8>, Error> {
	let k = k.as_ref();
	let mut res = Vec::with_capacity(k.len() + 10);
	res.push(prefix);
	res.push(SEP);
	res.extend_from_slice(k);
	res.write_u64::<BigEndian>(val)?;
	Ok(res)
}
/// Build a db key from a prefix and a numeric identifier.
pub fn u64_to_key(prefix: u8, val: u64) -> Result<Vec<u8>, Error> {
	let mut res = Vec::with_capacity(10);
	res.push(prefix);
	res.push(SEP);
	res.write_u64::<BigEndian>(val)?;
	Ok(res)
}

use mwc_crates::log::error;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::rand::TryRng;
use std::ffi::OsStr;
use std::fs::{remove_file, rename, File, OpenOptions};
use std::path::{Path, PathBuf};

/// Creates a unique same-directory temporary file using `temp_suffix`.
/// Applies writer function to it and renames temporary file into original specified by `path`.
pub fn save_via_temp_file<F, P, E>(
	path: P,
	temp_suffix: E,
	mut writer: F,
) -> Result<(), std::io::Error>
where
	F: FnMut(&mut File) -> Result<(), std::io::Error>,
	P: AsRef<Path>,
	E: AsRef<OsStr>,
{
	let temp_suffix = temp_suffix.as_ref();
	// All current callers pass a local, reviewable constant suffix (".tmp").
	// Keep it that way rather than accepting user-controlled path fragments here.
	if temp_suffix.is_empty() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidInput,
			"temp suffix must not be empty",
		));
	}

	let original = path.as_ref();
	let (temp_path, mut temp_file) = create_unique_temp_file(original, temp_suffix)?;

	// write the new data to the temp file
	if let Err(e) = writer(&mut temp_file) {
		drop(temp_file);
		remove_temp_file_or_log(&temp_path, "writer error");
		return Err(e);
	}

	// force an fsync on the temp file to ensure bytes are on disk
	if let Err(e) = temp_file.sync_all() {
		drop(temp_file);
		remove_temp_file_or_log(&temp_path, "temp file sync error");
		return Err(e);
	}
	drop(temp_file);

	if let Err(e) = rename(&temp_path, &original) {
		remove_temp_file_or_log(&temp_path, "rename error");
		return Err(e);
	}
	sync_parent_dir(original)?;

	Ok(())
}

fn remove_temp_file_or_log(temp_path: &Path, reason: &str) {
	if let Err(e) = remove_file(temp_path) {
		error!(
			"Failed to remove temporary file {} after {}: {}",
			temp_path.display(),
			reason,
			e
		);
	}
}

fn create_unique_temp_file(
	original: &Path,
	temp_suffix: &OsStr,
) -> Result<(PathBuf, File), std::io::Error> {
	let parent = normalized_parent(original);
	let file_name = original.file_name().ok_or_else(|| {
		std::io::Error::new(
			std::io::ErrorKind::InvalidInput,
			"original path must include a file name",
		)
	})?;
	#[cfg(unix)]
	let file_mode = replacement_file_mode(original)?;

	for _ in 0..128 {
		let mut temp_name = file_name.to_os_string();
		temp_name.push(temp_suffix);
		temp_name.push(".");
		temp_name.push(random_temp_suffix()?.to_string());
		let temp_path = parent.join(temp_name);
		let mut open_options = OpenOptions::new();
		open_options.write(true).create_new(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			open_options.custom_flags(mwc_crates::libc::O_NOFOLLOW);
			open_options.mode(file_mode);
		}

		match open_options.open(&temp_path) {
			Ok(file) => {
				#[cfg(unix)]
				if let Err(e) = set_file_mode(&file, file_mode) {
					drop(file);
					remove_temp_file_or_log(&temp_path, "temp file permission error");
					return Err(e);
				}
				return Ok((temp_path, file));
			}
			Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
			Err(e) => return Err(e),
		}
	}

	Err(std::io::Error::new(
		std::io::ErrorKind::AlreadyExists,
		"unable to create unique temporary file",
	))
}

fn random_temp_suffix() -> Result<u32, std::io::Error> {
	SysRng.try_next_u32().map_err(|e| {
		std::io::Error::new(
			std::io::ErrorKind::Other,
			format!("failed to generate temporary file suffix: {}", e),
		)
	})
}

#[cfg(unix)]
fn replacement_file_mode(original: &Path) -> Result<u32, std::io::Error> {
	use std::os::unix::fs::PermissionsExt;

	match original.symlink_metadata() {
		Ok(metadata) if metadata.file_type().is_symlink() => Err(std::io::Error::new(
			std::io::ErrorKind::InvalidInput,
			format!(
				"refusing to replace symlink path {} via temporary file",
				original.display()
			),
		)),
		Ok(metadata) => Ok(metadata.permissions().mode() & 0o777),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0o600),
		Err(e) => Err(e),
	}
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> Result<(), std::io::Error> {
	use std::os::unix::fs::PermissionsExt;

	file.set_permissions(std::fs::Permissions::from_mode(mode))
}

pub(crate) fn sync_parent_dir(path: &Path) -> Result<(), std::io::Error> {
	File::open(normalized_parent(path))?.sync_all()
}

fn normalized_parent(path: &Path) -> &Path {
	let parent = path.parent().unwrap_or_else(|| Path::new("."));
	if parent.as_os_str().is_empty() {
		Path::new(".")
	} else {
		parent
	}
}

pub(crate) fn open_existing_regular_file(path: &Path) -> Result<File, std::io::Error> {
	let mut options = OpenOptions::new();
	options.read(true);
	open_regular_file(path, &mut options)
}

pub(crate) fn open_regular_file(
	path: &Path,
	options: &mut OpenOptions,
) -> Result<File, std::io::Error> {
	match path.symlink_metadata() {
		Ok(metadata) => {
			let file_type = metadata.file_type();
			if file_type.is_symlink() {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidInput,
					format!("{} must not be a symlink", path.display()),
				));
			}
			if !file_type.is_file() {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidInput,
					format!("{} must be a regular file", path.display()),
				));
			}
		}
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
		Err(e) => return Err(e),
	}

	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(mwc_crates::libc::O_NOFOLLOW);
	}
	#[cfg(not(unix))]
	{
		// Rust std does not provide a portable no-follow open flag. The checks
		// around this open reject symlinks and non-regular files on normal
		// paths, but they cannot fully defend against a race if an attacker can
		// modify the storage directory or otherwise control the filesystem.
	}

	let file = options.open(path)?;
	if !file.metadata()?.file_type().is_file() {
		return Err(std::io::Error::new(
			std::io::ErrorKind::InvalidInput,
			format!("{} must be a regular file", path.display()),
		));
	}
	Ok(file)
}

use mwc_crates::croaring::{self, Bitmap};
use std::io::{self, Read};
/// Read Bitmap from a file
pub fn read_bitmap<P: AsRef<Path>>(file_path: P) -> io::Result<Bitmap> {
	let mut bitmap_file = open_existing_regular_file(file_path.as_ref())?;
	let f_md = bitmap_file.metadata()?;
	let mut buffer = Vec::with_capacity(f_md.len() as usize);
	bitmap_file.read_to_end(&mut buffer)?;
	let bitmap = Bitmap::try_deserialize::<croaring::Portable>(&buffer).ok_or_else(|| {
		io::Error::new(
			io::ErrorKind::InvalidData,
			"invalid serialized roaring bitmap",
		)
	})?;
	if bitmap.get_serialized_size_in_bytes::<croaring::Portable>() != buffer.len() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"serialized roaring bitmap contains trailing data",
		));
	}
	Ok(bitmap)
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::croaring::Portable;
	use std::fs::{create_dir_all, write};
	use std::io::Write;
	use std::time::{SystemTime, UNIX_EPOCH};

	fn test_path(name: &str) -> std::path::PathBuf {
		let nonce = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		Path::new("target").join(format!("{}_{}.bin", name, nonce))
	}

	#[test]
	fn read_bitmap_rejects_invalid_data() {
		create_dir_all("target").unwrap();
		let path = test_path("invalid_bitmap");
		write(&path, [0xff, 0x00, 0x01]).unwrap();

		let err = read_bitmap(&path).unwrap_err();

		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}

	#[test]
	fn save_via_temp_file_replaces_file() {
		create_dir_all("target").unwrap();
		let path = test_path("replace");
		write(&path, b"old").unwrap();

		save_via_temp_file(&path, ".tmp", |file| file.write_all(b"new")).unwrap();

		assert_eq!(std::fs::read(&path).unwrap(), b"new");
		assert!(!path
			.with_file_name(format!(
				"{}{}",
				path.file_name().unwrap().to_string_lossy(),
				".tmp"
			))
			.exists());
	}

	#[test]
	fn save_via_temp_file_preserves_existing_deterministic_temp_path() {
		create_dir_all("target").unwrap();
		let path = test_path("replace_existing_tmp");
		let temp_path = path.with_file_name(format!(
			"{}{}",
			path.file_name().unwrap().to_string_lossy(),
			".tmp"
		));
		write(&path, b"old").unwrap();
		write(&temp_path, b"preexisting").unwrap();

		save_via_temp_file(&path, ".tmp", |file| file.write_all(b"new")).unwrap();

		assert_eq!(std::fs::read(&path).unwrap(), b"new");
		assert_eq!(std::fs::read(&temp_path).unwrap(), b"preexisting");
	}

	#[cfg(unix)]
	#[test]
	fn save_via_temp_file_preserves_existing_permissions() {
		use std::os::unix::fs::PermissionsExt;

		create_dir_all("target").unwrap();
		let path = test_path("replace_mode");
		write(&path, b"old").unwrap();
		std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

		save_via_temp_file(&path, ".tmp", |file| file.write_all(b"new")).unwrap();

		assert_eq!(std::fs::read(&path).unwrap(), b"new");
		assert_eq!(
			std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
			0o600
		);
	}

	#[cfg(unix)]
	#[test]
	fn save_via_temp_file_rejects_symlink_replacement_path() {
		use std::os::unix::fs::symlink;

		create_dir_all("target").unwrap();
		let target = test_path("replace_symlink_target");
		let path = test_path("replace_symlink");
		write(&target, b"target").unwrap();
		symlink(&target, &path).unwrap();

		let err = save_via_temp_file(&path, ".tmp", |file| file.write_all(b"new")).unwrap_err();

		assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("symlink"));
		assert_eq!(std::fs::read(&target).unwrap(), b"target");
	}

	#[cfg(unix)]
	#[test]
	fn read_bitmap_rejects_symlink_path() {
		use std::os::unix::fs::symlink;

		create_dir_all("target").unwrap();
		let target = test_path("bitmap_symlink_target");
		let path = test_path("bitmap_symlink");
		let mut bitmap = Bitmap::new();
		bitmap.add(42);
		write(&target, bitmap.serialize::<Portable>()).unwrap();
		symlink(&target, &path).unwrap();

		let err = read_bitmap(&path).unwrap_err();

		assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
		assert!(err.to_string().contains("symlink"));
	}

	#[test]
	fn read_bitmap_accepts_valid_serialized_bitmap() {
		create_dir_all("target").unwrap();
		let path = test_path("valid_bitmap");
		let mut bitmap = Bitmap::new();
		bitmap.add(42);
		bitmap.add(1_000);
		write(&path, bitmap.serialize::<Portable>()).unwrap();

		let read = read_bitmap(&path).unwrap();

		assert_eq!(read, bitmap);
	}

	#[test]
	fn read_bitmap_rejects_trailing_data() {
		create_dir_all("target").unwrap();
		let path = test_path("trailing_bitmap");
		let mut bitmap = Bitmap::new();
		bitmap.add(42);
		let mut serialized = bitmap.serialize::<Portable>();
		serialized.push(0xff);
		write(&path, serialized).unwrap();

		let err = read_bitmap(&path).unwrap_err();

		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}
}
