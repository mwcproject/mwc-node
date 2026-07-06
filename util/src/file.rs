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
use mwc_crates::walkdir::WalkDir;
use mwc_crates::zeroize::Zeroizing;
use std::convert::TryFrom;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

/// Result of opening an owner-only file with exposure detection.
pub enum OwnerOnlyFile {
	/// The file is owner-only and safe to read.
	File(fs::File),
	/// The file was readable by group or others, so callers should not trust its contents.
	Exposed,
}

/// Ensure a directory exists and is writable only by the current owner.
pub fn ensure_owner_only_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {
	ensure_owner_only_dir_impl(path.as_ref(), false, true)
}

/// Ensure a directory and any missing parents exist, with the final directory owner-only.
pub fn ensure_owner_only_dir_all<P: AsRef<Path>>(path: P) -> io::Result<()> {
	ensure_owner_only_dir_impl(path.as_ref(), true, true)
}

/// Ensure a directory and any missing parents exist without checking directory ownership.
pub fn ensure_owner_only_dir_all_no_owner_check<P: AsRef<Path>>(path: P) -> io::Result<()> {
	ensure_owner_only_dir_impl(path.as_ref(), true, false)
}

/// Delete a directory or file
pub fn delete(path_buf: PathBuf) -> io::Result<()> {
	let metadata = match fs::symlink_metadata(&path_buf) {
		Ok(metadata) => metadata,
		Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
		Err(err) => return Err(err),
	};

	if metadata.is_dir() {
		fs::remove_dir_all(path_buf)
	} else {
		fs::remove_file(path_buf)
	}
}

/// Copy directory, create destination if needed
/// Note, returned number of copy bytes will be capped by u64::MAX value.
/// Note, this helper intentionally persists a plaintext copy of all copied source entries at
/// the destination path. Callers must only use it for data that is safe to duplicate on disk, or
/// for destinations that are trusted and protected by the caller. It does not classify, redact,
/// or encrypt wallet, key, seed, or other sensitive crypto application data.
/// Note, symlinks intentionally are not rejected, even that can lead to recursion.
/// Note, default system security settings will be used for destination files and directories.
///   If attacker want to mess with file system, we are not able to handle that properly.
pub fn copy_dir_to(src: &Path, dst: &Path) -> io::Result<u64> {
	let src_root = fs::canonicalize(src)?;
	let dst_root = resolved_destination_path(dst)?;
	if src_root.starts_with(&dst_root) || dst_root.starts_with(&src_root) {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!(
				"Refusing to copy overlapping directory trees: {} -> {}",
				src.display(),
				dst.display()
			),
		));
	}

	let mut counter = 0u64;
	match fs::metadata(dst) {
		Ok(metadata) if metadata.is_dir() => {}
		Ok(_) => {
			return Err(io::Error::new(
				io::ErrorKind::AlreadyExists,
				format!("Destination is not a directory: {}", dst.display()),
			));
		}
		Err(err) if err.kind() == io::ErrorKind::NotFound => fs::create_dir(dst)?,
		Err(err) => return Err(err),
	}

	for entry_result in src.read_dir()? {
		let entry = entry_result?;
		let file_type = entry.file_type()?;
		// Copy without without rejecting an existing destination file. It is expected.
		let count = copy_to(&entry.path(), file_type, &dst.join(entry.file_name()))?;
		// Overflow is acceptable sinse it is a total numbver of copied byted and used for monitoring only.
		counter = u64::saturating_add(counter, count);
	}
	Ok(counter)
}

fn resolved_destination_path(dst: &Path) -> io::Result<PathBuf> {
	match fs::canonicalize(dst) {
		Ok(path) => Ok(path),
		Err(err) if err.kind() == io::ErrorKind::NotFound => {
			let parent = dst
				.parent()
				.filter(|path| !path.as_os_str().is_empty())
				.unwrap_or_else(|| Path::new("."));
			let file_name = dst.file_name().ok_or_else(|| {
				io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("Invalid destination path: {}", dst.display()),
				)
			})?;

			Ok(fs::canonicalize(parent)?.join(file_name))
		}
		Err(err) => Err(err),
	}
}

/// List directory
pub fn list_files(path: &Path) -> io::Result<Vec<PathBuf>> {
	let mut files = Vec::new();
	for entry_result in WalkDir::new(path)
		.sort_by(|a, b| a.path().cmp(b.path()))
		.min_depth(1)
	{
		let entry = entry_result.map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
		if entry.file_type().is_file() {
			let relative_path = entry.path().strip_prefix(path).map_err(|err| {
				io::Error::new(
					io::ErrorKind::Other,
					format!(
						"failed to strip prefix {} from {}: {}",
						path.display(),
						entry.path().display(),
						err
					),
				)
			})?;
			files.push(relative_path.to_path_buf());
		}
	}
	Ok(files)
}

// Copy without without rejecting an existing destination file. It is expected.
// Note, it is expected that there are no concurrent access to the same files
// Note, symlinks intentionally are not rejected, even that can lead to recursion.
// Note, default system security settings will be used for destination files and directories.
//   If attacker want to mess with file system, we are not able to handle that properly.
fn copy_to(src: &Path, src_type: fs::FileType, dst: &Path) -> io::Result<u64> {
	if src_type.is_file() {
		fs::copy(src, dst)
	} else if src_type.is_dir() {
		copy_dir_to(src, dst)
	} else {
		Err(io::Error::new(
			io::ErrorKind::Other,
			format!("Could not copy: {}", src.display()),
		))
	}
}

/// Retrieve first line from file
pub fn get_first_line(file_path: Option<String>) -> io::Result<Option<String>> {
	let path = match file_path {
		Some(path) => path,
		None => return Ok(None),
	};

	let file = fs::File::open(&path)?;
	let mut lines_iter = io::BufReader::new(file).lines();
	match lines_iter.next() {
		Some(line) => line.map(Some),
		None => Err(io::Error::new(
			io::ErrorKind::UnexpectedEof,
			format!("File is empty: {}", path),
		)),
	}
}

/// Retrieve the first line from an existing owner-only regular file.
pub fn get_owner_only_first_line(file_path: Option<String>) -> io::Result<Option<String>> {
	let path = match file_path {
		Some(path) => path,
		None => return Ok(None),
	};

	let file = open_owner_only_file(&path)?;
	let mut lines_iter = io::BufReader::new(file).lines();
	match lines_iter.next() {
		Some(line) => line.map(Some),
		None => Err(io::Error::new(
			io::ErrorKind::UnexpectedEof,
			format!("File is empty: {}", path),
		)),
	}
}

/// Retrieve the first line from an existing owner-only regular file into zeroizing memory.
pub fn get_owner_only_first_line_zeroizing(
	file_path: Option<String>,
) -> io::Result<Option<Zeroizing<String>>> {
	let path = match file_path {
		Some(path) => path,
		None => return Ok(None),
	};

	let bytes = read_owner_only_file(&path)?;
	let contents = std::str::from_utf8(bytes.as_slice()).map_err(|e| {
		io::Error::new(
			io::ErrorKind::InvalidData,
			format!("File is not valid UTF-8: {}", e),
		)
	})?;

	match contents.lines().next() {
		Some(line) => {
			let mut first_line = Zeroizing::new(String::with_capacity(line.len()));
			first_line.push_str(line);
			Ok(Some(first_line))
		}
		None => Err(io::Error::new(
			io::ErrorKind::UnexpectedEof,
			format!("File is empty: {}", path),
		)),
	}
}

/// Open an existing regular file that must be readable and writable only by the owner.
pub fn open_owner_only_file<P: AsRef<Path>>(path: P) -> io::Result<fs::File> {
	match open_owner_only_file_or_exposed(path)? {
		OwnerOnlyFile::File(file) => Ok(file),
		OwnerOnlyFile::Exposed => Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			"owner-only file has unsafe group/other permissions",
		)),
	}
}

/// Open an owner-only regular file, returning `Exposed` for group/other-readable files.
///
/// Group/other-writable files are always rejected because another local user may have tampered
/// with their contents. Group/other-readable files are reported as exposed so callers can rotate
/// secrets without trusting the old value.
pub fn open_owner_only_file_or_exposed<P: AsRef<Path>>(path: P) -> io::Result<OwnerOnlyFile> {
	open_owner_only_file_or_exposed_impl(path.as_ref())
}

/// Read an existing owner-only regular file into zeroizing memory.
pub fn read_owner_only_file<P: AsRef<Path>>(path: P) -> io::Result<Zeroizing<Vec<u8>>> {
	let mut file = open_owner_only_file(path)?;
	let len = usize::try_from(file.metadata()?.len()).map_err(|_| {
		io::Error::new(
			io::ErrorKind::InvalidData,
			"owner-only file is too large to read into memory",
		)
	})?;

	// Read into the final zeroizing allocation sized from metadata. Growing a
	// Vec with read_to_end can leave stale secret copies in old heap allocations.
	let mut bytes = Zeroizing::new(vec![0; len]);
	file.read_exact(&mut bytes[..])?;

	let mut extra = Zeroizing::new([0u8; 1]);
	if file.read(&mut extra[..])? != 0 {
		return Err(io::Error::new(
			io::ErrorKind::InvalidData,
			"owner-only file changed size while reading",
		));
	}

	Ok(bytes)
}

/// Create or truncate a regular file as owner-only and write all bytes to it.
pub fn write_owner_only_file<P, B>(path: P, bytes: B) -> io::Result<()>
where
	P: AsRef<Path>,
	B: AsRef<[u8]>,
{
	let mut file = create_owner_only_file(path)?;
	write_all_and_sync(&mut file, bytes.as_ref())
}

/// Create a new owner-only regular file and write all bytes to it.
///
/// The file must not already exist. On Unix this uses `O_NOFOLLOW` and `0600` permissions.
pub fn write_new_owner_only_file<P, B>(path: P, bytes: B) -> io::Result<()>
where
	P: AsRef<Path>,
	B: AsRef<[u8]>,
{
	let path = path.as_ref();
	let mut file = match create_new_owner_only_file(path) {
		Ok(file) => file,
		Err(e) => return Err(e),
	};
	if let Err(e) = write_all_and_sync(&mut file, bytes.as_ref()) {
		drop(file);
		// Accepted risk: cleanup is best-effort after a write or sync failure.
		// Preserve the original I/O error even if removing the newly-created
		// file also fails, which may leave a partial owner-only file on disk.
		let _ = fs::remove_file(path);
		return Err(e);
	}
	// A new file is not crash-durable until both the file and the containing
	// directory entry have been synced. The file sync above persists the bytes;
	// this sync persists the name-to-file link before reporting success.
	sync_parent_dir(path)
}

/// Create or truncate an owner-only regular file.
pub fn create_owner_only_file<P: AsRef<Path>>(path: P) -> io::Result<fs::File> {
	create_owner_only_file_impl(path.as_ref(), false)
}

/// Create a new owner-only regular file that must not already exist.
pub fn create_new_owner_only_file<P: AsRef<Path>>(path: P) -> io::Result<fs::File> {
	create_owner_only_file_impl(path.as_ref(), true)
}

fn write_all_and_sync(file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
	file.write_all(bytes)?;
	file.sync_all()
}

#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> io::Result<()> {
	fs::File::open(normalized_parent(path))?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> io::Result<()> {
	Ok(())
}

#[cfg(unix)]
fn normalized_parent(path: &Path) -> &Path {
	let parent = path.parent().unwrap_or_else(|| Path::new("."));
	if parent.as_os_str().is_empty() {
		Path::new(".")
	} else {
		parent
	}
}

#[cfg(unix)]
fn ensure_owner_only_dir_impl(path: &Path, recursive: bool, check_owner: bool) -> io::Result<()> {
	use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

	let mut existed = path.try_exists()?;
	if !existed {
		let mut builder = fs::DirBuilder::new();
		builder.mode(0o700);
		if recursive {
			builder.recursive(true);
		}
		match builder.create(path) {
			Ok(()) => {}
			Err(err) if err.kind() == io::ErrorKind::AlreadyExists => existed = true,
			Err(err) => return Err(err),
		}
	}

	let dir = fs::OpenOptions::new()
		.read(true)
		.custom_flags(
			mwc_crates::libc::O_DIRECTORY
				| mwc_crates::libc::O_NOFOLLOW
				| mwc_crates::libc::O_CLOEXEC,
		)
		.open(path)?;
	let metadata = dir.metadata()?;
	if !metadata.is_dir() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("owner-only path '{}' is not a directory", path.display()),
		));
	}

	if check_owner {
		// SAFETY: geteuid has no arguments and only reads the process effective UID.
		let effective_uid = unsafe { mwc_crates::libc::geteuid() };
		if metadata.uid() != effective_uid {
			return Err(io::Error::new(
				io::ErrorKind::PermissionDenied,
				format!(
					"owner-only directory '{}' is owned by uid {}, expected effective uid {}",
					path.display(),
					metadata.uid(),
					effective_uid
				),
			));
		}
	}

	let mode = metadata.permissions().mode() & 0o777;
	if existed && (mode & 0o022) != 0 {
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			format!(
				"owner-only directory '{}' has unsafe group/other write permissions {:o}",
				path.display(),
				mode
			),
		));
	}

	dir.set_permissions(fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn ensure_owner_only_dir_impl(path: &Path, recursive: bool, _check_owner: bool) -> io::Result<()> {
	if !path.try_exists()? {
		if recursive {
			fs::create_dir_all(path)?;
		} else {
			fs::create_dir(path)?;
		}
	}
	if !path.metadata()?.is_dir() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("owner-only path '{}' is not a directory", path.display()),
		));
	}
	Ok(())
}

#[cfg(unix)]
fn create_owner_only_file_impl(path: &Path, create_new: bool) -> io::Result<fs::File> {
	use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

	if !create_new {
		match fs::symlink_metadata(path) {
			Ok(metadata) if !metadata.file_type().is_file() => {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					format!("{} must be a regular file", path.display()),
				));
			}
			Ok(metadata) => {
				let mode = metadata.permissions().mode() & 0o777;
				if (mode & 0o022) != 0 {
					return Err(io::Error::new(
						io::ErrorKind::PermissionDenied,
						format!(
							"owner-only file '{}' has unsafe group/other write permissions {:o}",
							path.display(),
							mode
						),
					));
				}
				if mode != 0o600 {
					fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
				}
			}
			Err(err) if err.kind() == io::ErrorKind::NotFound => {}
			Err(err) => return Err(err),
		}
	}

	let mut options = fs::OpenOptions::new();
	options.write(true).mode(0o600).custom_flags(
		mwc_crates::libc::O_NOFOLLOW | mwc_crates::libc::O_CLOEXEC | mwc_crates::libc::O_NONBLOCK,
	);
	if create_new {
		options.create_new(true);
	} else {
		// Existing files with only read exposure are tightened before reuse, but
		// group/other-writable files are rejected before we reuse their inode.
		// Accepted risk: chmod(0600) does not revoke read descriptors that
		// another local user may already have opened while the file was
		// group/other-readable. We accept that exposure for this reuse path.
		// Accepted risk: we verify the file is a regular file with mode 0600,
		// but we do not verify that its owner UID matches the process effective
		// UID. An elevated process could therefore truncate and write secrets
		// into another local user's 0600 file, leaving that user able to read
		// the new contents because chmod(0600) preserves ownership.
		// Accepted risk: this validates the path before opening it, so callers
		// must use trusted directories if namespace replacement races are in scope.
		options.create(true).truncate(true);
	}
	let file = options.open(path)?;
	if !file.metadata()?.is_file() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("{} must be a regular file", path.display()),
		));
	}
	// Accepted risk: this enforces only classic Unix mode bits. It does not
	// inspect or clear platform-specific ACLs or inherited ACLs, so a file with
	// mode 0600 can still grant access to another local principal through ACL
	// rules that are not represented in st_mode.
	file.set_permissions(fs::Permissions::from_mode(0o600))?;
	Ok(file)
}

#[cfg(not(unix))]
fn create_owner_only_file_impl(path: &Path, create_new2: bool) -> io::Result<fs::File> {
	let mut options = fs::OpenOptions::new();
	options.write(true);
	if create_new2 {
		options.create_new(true);
	} else {
		options.create(true).truncate(true);
	}
	let file = options.open(path)?;
	if !file.metadata()?.is_file() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("{} must be a regular file", path.display()),
		));
	}
	Ok(file)
}

fn owner_only_regular_file_metadata(path: &Path) -> io::Result<fs::Metadata> {
	let metadata = fs::symlink_metadata(path)?;
	let file_type = metadata.file_type();
	if file_type.is_symlink() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("{} must not be a symlink", path.display()),
		));
	}
	if !file_type.is_file() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("{} must be a regular file", path.display()),
		));
	}
	Ok(metadata)
}

#[cfg(unix)]
fn open_owner_only_file_or_exposed_impl(path: &Path) -> io::Result<OwnerOnlyFile> {
	use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

	let metadata = owner_only_regular_file_metadata(path)?;
	let mode = metadata.permissions().mode() & 0o777;
	if let Some(owner_file) = classify_owner_only_file_mode(path, mode)? {
		return Ok(owner_file);
	}

	let file = fs::OpenOptions::new()
		.read(true)
		.custom_flags(mwc_crates::libc::O_NOFOLLOW | mwc_crates::libc::O_CLOEXEC)
		.open(path)?;
	let metadata = file.metadata()?;
	if !metadata.is_file() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("{} must be a regular file", path.display()),
		));
	}

	// Accepted risk: this validates only classic Unix mode bits. It does not
	// verify that the file owner matches the process effective UID, so an
	// elevated process can accept a 0600 file owned by another local user, who
	// may still control the trusted contents. It also does not inspect
	// platform-specific ACLs, so a file with mode 0600 can still be exposed to
	// another local principal through ACL rules that are not represented here.
	let mode = metadata.permissions().mode() & 0o777;
	if let Some(owner_file) = classify_owner_only_file_mode(path, mode)? {
		return Ok(owner_file);
	}
	if mode != 0o600 {
		file.set_permissions(fs::Permissions::from_mode(0o600))?;
	}

	Ok(OwnerOnlyFile::File(file))
}

#[cfg(unix)]
fn classify_owner_only_file_mode(path: &Path, mode: u32) -> io::Result<Option<OwnerOnlyFile>> {
	if (mode & 0o022) != 0 {
		return Err(io::Error::new(
			io::ErrorKind::PermissionDenied,
			format!(
				"owner-only file '{}' has unsafe group/other write permissions {:o}",
				path.display(),
				mode
			),
		));
	}
	if (mode & 0o077) != 0 {
		return Ok(Some(OwnerOnlyFile::Exposed));
	}
	Ok(None)
}

#[cfg(not(unix))]
fn open_owner_only_file_or_exposed_impl(path2: &Path) -> io::Result<OwnerOnlyFile> {
	owner_only_regular_file_metadata(path2)?;

	let file = fs::File::open(path2)?;
	let metadata = file.metadata()?;
	if !metadata.is_file() {
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			format!("{} must be a regular file", path2.display()),
		));
	}

	// Accepted risk: non-Unix builds use only Rust's portable filesystem API.
	// std::fs can reject symlink paths before open and validate that the opened
	// target is a regular file, but cannot make the path check and open atomic.
	// It also does not expose platform ACLs or owner-only permission checks. We
	// therefore accept that this branch cannot distinguish owner-private files
	// from files exposed to other local users without adding platform-specific
	// filesystem support.
	Ok(OwnerOnlyFile::File(file))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(unix)]
	#[test]
	fn ensure_owner_only_dir_all_creates_owner_only_directory() {
		use std::os::unix::fs::PermissionsExt;

		let temp_dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let path = temp_dir.path().join("parent").join("child");

		ensure_owner_only_dir_all(&path).unwrap();

		let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o700);
	}

	#[cfg(unix)]
	#[test]
	fn ensure_owner_only_dir_tightens_existing_non_writable_directory() {
		use std::os::unix::fs::PermissionsExt;

		let temp_dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let path = temp_dir.path().join("child");
		fs::create_dir(&path).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

		ensure_owner_only_dir(&path).unwrap();

		let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
		assert_eq!(mode, 0o700);
	}

	#[cfg(unix)]
	#[test]
	fn ensure_owner_only_dir_rejects_group_or_world_writable_directory() {
		use std::os::unix::fs::PermissionsExt;

		let temp_dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let path = temp_dir.path().join("child");
		fs::create_dir(&path).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();

		let err = ensure_owner_only_dir(&path).unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
		assert!(err
			.to_string()
			.contains("unsafe group/other write permissions"));
	}

	#[cfg(unix)]
	#[test]
	fn ensure_owner_only_dir_rejects_symlinked_directory() {
		use std::os::unix::fs::symlink;

		let temp_dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let target = temp_dir.path().join("target");
		let link = temp_dir.path().join("link");
		fs::create_dir(&target).unwrap();
		symlink(&target, &link).unwrap();

		assert!(ensure_owner_only_dir(&link).is_err());
	}
}
