// Copyright 2021 The Grin Developers
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

//! Public types for config modules

use std::io;
use std::path::PathBuf;

use crate::servers::ServerConfig;
use crate::util::logger::LoggingConfig;

/// Error type wrapping config errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
	/// Error with parsing of config file
	#[error("Error parsing configuration file {0}, {1}")]
	ParseError(String, String),

	/// Error with fileIO while reading config file
	#[error("Node Config file {0} IO error, {1}")]
	FileIOError(String, String),

	/// No file found
	#[error("Node Configuration file not found: {0}")]
	FileNotFoundError(String),

	/// Error serializing config values
	#[error("Error serializing node configuration: {0}")]
	SerializationError(String),
}

impl From<io::Error> for ConfigError {
	fn from(error: io::Error) -> ConfigError {
		ConfigError::FileIOError(
			String::from(""),
			format!("Error loading config file: {}", error),
		)
	}
}

/// Going to hold all of the various configuration types
/// separately for now, then put them together as a single
/// ServerConfig object afterwards. This is to flatten
/// out the configuration file into logical sections,
/// as they tend to be quite nested in the code
/// Most structs optional, as they may or may not
/// be needed depending on what's being run
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GlobalConfig {
	/// Keep track of the file we've read
	pub config_file_path: Option<PathBuf>,
	/// Global member config
	pub members: Option<ConfigMembers>,
}

/// Keeping an 'inner' structure here, as the top
/// level GlobalConfigContainer options might want to keep
/// internal state that we don't necessarily
/// want serialised or deserialised
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConfigMembers {
	/// Config file version (None == version 1)
	pub config_file_version: Option<u32>,
	/// Server config
	#[serde(default)]
	pub server: ServerConfig,
	/// Logging config
	pub logging: Option<LoggingConfig>,
}
