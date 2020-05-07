// Copyright 2020 The Grin Developers
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

use failure::Fail;
use std::io;
use std::path::PathBuf;

use crate::servers::ServerConfig;
use crate::util::logger::LoggingConfig;

/// Error type wrapping config errors.
#[derive(Debug, Fail)]
pub enum ConfigError {
	/// Error with parsing of config file
	#[fail(display = "Error parsing configuration file {}, {}", _0, _1)]
	ParseError(String, String),

	/// Error with fileIO while reading config file
	#[fail(display = "Node Config file {} IO error, {}", _0, _1)]
	FileIOError(String, String),

	/// No file found
	#[fail(display = "Node Configuration file not found: {}", _0)]
	FileNotFoundError(String),

	/// Error serializing config values
	#[fail(display = "Error serializing node configuration: {}", _0)]
	SerializationError(String),
}

impl From<io::Error> for ConfigError {
	fn from(error: io::Error) -> ConfigError {
		ConfigError::FileIOError(
			String::from(""),
			String::from(format!("Error loading config file: {}", error)),
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
	/// Server config
	#[serde(default)]
	pub server: ServerConfig,
	/// Logging config
	pub logging: Option<LoggingConfig>,
}
