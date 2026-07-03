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

use mwc_util::file;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

#[test]
fn copy_dir() {
	let root = Path::new("./target/tmp2");
	fs::create_dir_all(root.join("./original/sub")).unwrap();
	fs::create_dir_all(root.join("./original/sub2")).unwrap();
	write_files("original".to_string(), &root).unwrap();
	let original_path = Path::new("./target/tmp2/original");
	let copy_path = Path::new("./target/tmp2/copy");
	file::copy_dir_to(original_path, copy_path).unwrap();
	let original_files = file::list_files(&Path::new("./target/tmp2/original")).unwrap();
	let copied_files = file::list_files(&Path::new("./target/tmp2/copy")).unwrap();
	assert_eq!(original_files, copied_files);
	fs::remove_dir_all(root).unwrap();
}

fn write_files(dir_name: String, root: &Path) -> io::Result<()> {
	let mut file = File::create(root.join(dir_name.clone() + "/foo.txt"))?;
	file.write_all(b"Hello, world!")?;
	let mut file = File::create(root.join(dir_name.clone() + "/bar.txt"))?;
	file.write_all(b"Goodbye, world!")?;
	let mut file = File::create(root.join(dir_name + "/sub/lorem"))?;
	file.write_all(b"Lorem ipsum dolor sit amet, consectetur adipiscing elit")?;
	Ok(())
}

#[cfg(any(unix, windows))]
fn owner_file_test_path(name: &str) -> std::path::PathBuf {
	let dir = std::env::temp_dir().join(format!(
		"mwc_util_owner_file_{}_{}",
		name,
		std::process::id()
	));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir.join("secret")
}

#[cfg(unix)]
fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
	std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
	std::os::windows::fs::symlink_file(target, link)
}

#[cfg(unix)]
#[test]
fn write_owner_only_file_sets_owner_only_permissions() {
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("write");

	file::write_owner_only_file(&path, b"secret").unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	assert_eq!(fs::read(&path).unwrap(), b"secret");
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn write_owner_only_file_rejects_existing_exposed_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("write_exposed");
	fs::write(&path, b"old").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
	let _old_writer = fs::OpenOptions::new().write(true).open(&path).unwrap();

	let err = file::write_owner_only_file(&path, b"secret").unwrap_err();

	assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
	assert_eq!(fs::read(&path).unwrap(), b"old");
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn write_owner_only_file_rejects_fifo() {
	use std::os::unix::fs::OpenOptionsExt;

	let path = owner_file_test_path("fifo");
	let status = std::process::Command::new("mkfifo")
		.arg(&path)
		.status()
		.unwrap();
	assert!(status.success());

	let mut reader = fs::OpenOptions::new()
		.read(true)
		.custom_flags(mwc_crates::libc::O_NONBLOCK)
		.open(&path)
		.unwrap();

	let err = file::write_owner_only_file(&path, b"secret").unwrap_err();
	assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

	let mut bytes = [0u8; 16];
	match reader.read(&mut bytes) {
		Ok(0) => {}
		Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
		other => panic!("expected no FIFO bytes, got {:?}", other),
	}

	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn open_owner_only_file_rejects_exposed_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("strict_exposed");
	fs::write(&path, b"secret").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

	assert!(file::open_owner_only_file(&path).is_err());
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn open_owner_only_file_or_exposed_flags_readable_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("flag_exposed");
	fs::write(&path, b"secret").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

	match file::open_owner_only_file_or_exposed(&path).unwrap() {
		file::OwnerOnlyFile::Exposed => {}
		file::OwnerOnlyFile::File(_) => panic!("expected exposed owner-only file result"),
	}
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn open_owner_only_file_or_exposed_flags_owner_unreadable_exposed_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("owner_unreadable_exposed");
	fs::write(&path, b"secret").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o004)).unwrap();

	match file::open_owner_only_file_or_exposed(&path).unwrap() {
		file::OwnerOnlyFile::Exposed => {}
		file::OwnerOnlyFile::File(_) => panic!("expected exposed owner-only file result"),
	}
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(any(unix, windows))]
#[test]
fn open_owner_only_file_or_exposed_rejects_symlink_path() {
	#[cfg(unix)]
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("symlink_path");
	let link = path.with_file_name("secret_link");
	fs::write(&path, b"secret").unwrap();
	#[cfg(unix)]
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	match create_file_symlink(&path, &link) {
		Ok(()) => {}
		Err(err) if cfg!(windows) && err.kind() == io::ErrorKind::PermissionDenied => {
			fs::remove_dir_all(path.parent().unwrap()).unwrap();
			return;
		}
		Err(err) => panic!("failed to create symlink: {}", err),
	}

	let err = match file::open_owner_only_file_or_exposed(&link) {
		Ok(_) => panic!("expected symlink path to be rejected"),
		Err(err) => err,
	};
	assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
	assert!(err.to_string().contains("must not be a symlink"));
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn get_owner_only_first_line_reads_owner_only_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("first_line");
	fs::write(&path, b"secret\nsecond").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	assert_eq!(
		file::get_owner_only_first_line(Some(path.to_string_lossy().into_owned())).unwrap(),
		Some("secret".to_string())
	);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn get_owner_only_first_line_zeroizing_returns_none_without_path() {
	assert!(file::get_owner_only_first_line_zeroizing(None)
		.unwrap()
		.is_none());
}

#[cfg(unix)]
#[test]
fn get_owner_only_first_line_zeroizing_reads_owner_only_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("first_line_zeroizing");
	fs::write(&path, b"secret\nsecond").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	let secret =
		file::get_owner_only_first_line_zeroizing(Some(path.to_string_lossy().into_owned()))
			.unwrap()
			.unwrap();

	assert_eq!(&*secret, "secret");
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn get_owner_only_first_line_zeroizing_rejects_empty_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("first_line_zeroizing_empty");
	fs::write(&path, b"").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	let err = file::get_owner_only_first_line_zeroizing(Some(path.to_string_lossy().into_owned()))
		.unwrap_err();

	assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn get_owner_only_first_line_zeroizing_rejects_invalid_utf8() {
	use std::os::unix::fs::PermissionsExt;

	let path = owner_file_test_path("first_line_zeroizing_invalid_utf8");
	fs::write(&path, [0xff]).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

	let err = file::get_owner_only_first_line_zeroizing(Some(path.to_string_lossy().into_owned()))
		.unwrap_err();

	assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn write_new_owner_only_file_rejects_existing_file() {
	let path = owner_file_test_path("create_new");
	file::write_new_owner_only_file(&path, b"secret").unwrap();

	assert!(file::write_new_owner_only_file(&path, b"replacement").is_err());
	assert_eq!(fs::read(&path).unwrap(), b"secret");
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
