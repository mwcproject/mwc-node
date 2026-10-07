// Copyright 2026 The MWC Developers
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

use mwc_crates::fs2::FileExt;
use mwc_crates::tempfile::TempDir;
use mwc_util::file::write_owner_only_file;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::process::{Command, Output};

const SECRET_FILES: [&str; 2] = [".api_secret", ".foreign_api_secret"];

fn run_mwc(dir: &Path, args: &[&str]) -> Output {
	Command::new(env!("CARGO_BIN_EXE_mwc"))
		.current_dir(dir)
		.args(args)
		.output()
		.unwrap()
}

fn output_text(output: &Output) -> String {
	format!(
		"{}\n{}",
		String::from_utf8_lossy(&output.stdout),
		String::from_utf8_lossy(&output.stderr)
	)
}

fn config_dir() -> TempDir {
	let dir = TempDir::new().unwrap();
	let output = run_mwc(dir.path(), &["server", "config"]);
	assert!(output.status.success(), "{}", output_text(&output));
	dir
}

fn load_explicit_config(dir: &Path) -> Output {
	let config_path = dir.join("mwc-server.toml");
	// Omitting the server subcommand exercises startup configuration without
	// starting a node or connecting to the network.
	run_mwc(
		dir,
		&["server", "--config_file", config_path.to_str().unwrap()],
	)
}

fn assert_config_loaded(output: &Output) {
	assert!(!output.status.success());
	assert!(
		output_text(output).contains("Subcommand required"),
		"{}",
		output_text(output)
	);
}

#[test]
fn explicit_config_provisions_missing_and_rotates_blank_api_secrets() {
	for blank_files in [false, true] {
		let dir = config_dir();
		if blank_files {
			for name in SECRET_FILES {
				write_owner_only_file(dir.path().join(name), b"\n").unwrap();
			}
		}

		assert_config_loaded(&load_explicit_config(dir.path()));

		for name in SECRET_FILES {
			let secret = fs::read(dir.path().join(name)).unwrap();
			assert_eq!(secret.len(), 20);
			assert!(secret.iter().all(u8::is_ascii_alphanumeric));
		}
	}
}

#[test]
fn explicit_config_preserves_valid_api_secrets() {
	let dir = config_dir();
	let secrets = [
		b"owner-secret-for-test".as_slice(),
		b"foreign-secret-for-test",
	];
	for (name, secret) in SECRET_FILES.iter().zip(secrets) {
		write_owner_only_file(dir.path().join(name), secret).unwrap();
	}

	assert_config_loaded(&load_explicit_config(dir.path()));

	let config_name = "mwc-конфигурация.toml";
	fs::rename(
		dir.path().join("mwc-server.toml"),
		dir.path().join(config_name),
	)
	.unwrap();
	assert_config_loaded(&run_mwc(
		dir.path(),
		&["server", "--config_file", config_name],
	));

	for (name, secret) in SECRET_FILES.iter().zip(secrets) {
		assert_eq!(fs::read(dir.path().join(name)).unwrap(), secret);
	}
}

#[test]
fn explicit_config_reports_invalid_utf8() {
	for invalid_name in SECRET_FILES {
		let dir = config_dir();
		for name in SECRET_FILES {
			write_owner_only_file(dir.path().join(name), b"valid-secret-for-test").unwrap();
		}
		let invalid_path = dir.path().join(invalid_name);
		write_owner_only_file(&invalid_path, [0xff]).unwrap();

		let output = load_explicit_config(dir.path());
		assert!(!output.status.success());
		assert!(
			output_text(&output).contains("not valid UTF-8"),
			"{}",
			output_text(&output)
		);
		assert_eq!(fs::read(invalid_path).unwrap(), [0xff]);
	}

	#[cfg(unix)]
	{
		use std::ffi::OsString;
		use std::os::unix::ffi::OsStringExt;

		let dir = TempDir::new().unwrap();
		let output = Command::new(env!("CARGO_BIN_EXE_mwc"))
			.current_dir(dir.path())
			.args(["server", "--config_file"])
			.arg(OsString::from_vec(b"mwc-\xff.toml".to_vec()))
			.output()
			.unwrap();

		assert_eq!(output.status.code(), Some(1), "{}", output_text(&output));
		assert!(
			output_text(&output)
				.contains("Invalid value for --config_file: value must be valid UTF-8"),
			"{}",
			output_text(&output)
		);
	}
}

#[test]
fn clean_refuses_a_locked_database_without_deleting_data() {
	let dir = config_dir();
	let db = dir.path().join("chain_data");
	fs::create_dir(&db).unwrap();
	let lock = OpenOptions::new()
		.read(true)
		.write(true)
		.create_new(true)
		.open(db.join("mwc.lock"))
		.unwrap();
	FileExt::try_lock_exclusive(&lock).unwrap();
	let data = db.join("chain-data");
	fs::write(&data, b"database must survive").unwrap();

	let output = run_mwc(dir.path(), &["clean"]);

	assert!(!output.status.success());
	assert!(
		output_text(&output).contains("Unable to get exclusive lock"),
		"{}",
		output_text(&output)
	);
	assert_eq!(fs::read(data).unwrap(), b"database must survive");
	assert!(db.join("mwc.lock").is_file());
}

#[test]
fn clean_removes_data_and_preserves_the_existing_lock_file() {
	let dir = config_dir();
	let db = dir.path().join("chain_data");
	fs::create_dir(&db).unwrap();
	let lock_path = db.join("mwc.lock");
	// Model a server that opened the lock file before cleanup, but has not yet
	// acquired its lock. Its handle must remain valid for future exclusion.
	let existing_lock = OpenOptions::new()
		.read(true)
		.write(true)
		.create_new(true)
		.open(&lock_path)
		.unwrap();
	fs::create_dir(db.join("nested")).unwrap();
	fs::write(db.join("nested").join("data"), b"nested data").unwrap();
	fs::write(db.join("data"), b"data").unwrap();

	let output = run_mwc(dir.path(), &["clean"]);

	assert!(output.status.success(), "{}", output_text(&output));
	let entries: Vec<_> = fs::read_dir(&db)
		.unwrap()
		.map(|entry| entry.unwrap().file_name())
		.collect();
	assert_eq!(entries, [std::ffi::OsString::from("mwc.lock")]);

	FileExt::try_lock_exclusive(&existing_lock).unwrap();
	let new_lock = OpenOptions::new()
		.read(true)
		.write(true)
		.open(&lock_path)
		.unwrap();
	assert!(FileExt::try_lock_exclusive(&new_lock).is_err());
}
