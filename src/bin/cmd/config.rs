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

/// Mwc configuration file output command
use mwc_config::GlobalConfig;
use mwc_core::global;
use std::{
	env,
	path::{Component, Path},
};

use super::Error;

/// Create a config file in the current directory.
pub fn config_command_server(
	chain_type: &global::ChainTypes,
	file_name: &str,
) -> Result<(), Error> {
	if !is_single_normal_filename(file_name) {
		return Err(Error::ArgumentError(
			"Error creating config file: invalid filename".into(),
		));
	}

	let mut default_config = GlobalConfig::for_chain(chain_type)
		.map_err(|e| Error::ArgumentError(format!("Unable to generate config: {}", e)))?;

	let current_dir = env::current_dir()
		.map_err(|e| Error::ArgumentError(format!("Error creating config file: {}", e)))?;
	let mut config_file_name = current_dir.clone();
	config_file_name.push(file_name);
	match config_file_name.try_exists() {
		Ok(true) => {
			return Err(Error::ArgumentError(format!(
				"{} already exists in the current directory. Please remove it first",
				file_name
			)));
		}
		Ok(false) => {}
		Err(e) => {
			return Err(Error::ArgumentError(format!(
				"Error checking config file: {}",
				e
			)));
		}
	}
	default_config
		.update_paths(&current_dir)
		.map_err(|e| Error::ArgumentError(format!("Unable to provision paths: {}", e)))?;
	let Some(config_file_name) = config_file_name.to_str() else {
		return Err(Error::ArgumentError(
			"Error creating config file: invalid path".into(),
		));
	};
	default_config
		.write_to_file(config_file_name)
		.map_err(|e| Error::ArgumentError(format!("Error creating config file: {}", e)))?;

	println!(
		"{} file configured and created in current directory",
		file_name
	);
	Ok(())
}

fn is_single_normal_filename(file_name: &str) -> bool {
	let mut components = Path::new(file_name).components();
	matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

#[cfg(test)]
mod tests {
	use super::{config_command_server, is_single_normal_filename};
	use mwc_core::global;

	#[test]
	fn accepts_single_normal_filename() {
		assert!(is_single_normal_filename("mwc-server.toml"));
	}

	#[test]
	fn rejects_path_components() {
		assert!(!is_single_normal_filename(""));
		assert!(!is_single_normal_filename("."));
		assert!(!is_single_normal_filename(".."));
		assert!(!is_single_normal_filename("../mwc-server.toml"));
		assert!(!is_single_normal_filename("config/mwc-server.toml"));
		assert!(!is_single_normal_filename("/tmp/mwc-server.toml"));
	}

	#[test]
	fn returns_error_for_invalid_filename() {
		let err = config_command_server(&global::ChainTypes::Mainnet, "../mwc-server.toml")
			.expect_err("invalid filename should fail");

		assert_eq!(
			err.to_string(),
			"Error creating config file: invalid filename"
		);
	}
}
