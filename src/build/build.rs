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

//! Build hooks to spit out version+build time info

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

// Note: build scripts run at build time, so panicking on setup/generation failures
// is acceptable and gives Cargo a clear failure reason.
fn main() {
	// Setting up git hooks in the project: rustfmt and so on.
	let git_hooks = format!(
		"git config core.hooksPath {}",
		PathBuf::from("./.hooks").to_str().unwrap()
	);

	let output = if cfg!(target_os = "windows") {
		Command::new("cmd")
			.args(&["/C", &git_hooks])
			.output()
			.expect("failed to execute git config for hooks")
	} else {
		Command::new("sh")
			.args(&["-c", &git_hooks])
			.output()
			.expect("failed to execute git config for hooks")
	};

	if !output.status.success() {
		let stderr = String::from_utf8_lossy(&output.stderr);
		if stderr.trim().is_empty() {
			panic!("failed to configure git hooks: {}", output.status);
		}
		panic!(
			"failed to configure git hooks: {}: {}",
			output.status,
			stderr.trim()
		);
	}

	// build and versioning information
	let out_dir_path = format!("{}{}", env::var("OUT_DIR").unwrap(), "/built.rs");
	built::write_built_file_with_opts(
		Some(Path::new(env!("CARGO_MANIFEST_DIR"))),
		Path::new(&out_dir_path),
	)
	.expect("failed to generate built.rs build metadata");
}
