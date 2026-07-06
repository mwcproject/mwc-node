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

//! Public types for config modules

use mwc_crates::serde::{self, Deserialize, Serialize};
use std::io;
use std::path::PathBuf;

use mwc_servers::ServerConfig;
use mwc_util::logger::LoggingConfig;

pub(crate) const CONFIG_FILE_VERSION: u32 = 3;

/// Error type wrapping config errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
	/// Error with parsing of config file
	#[error("Error parsing configuration file {0}, {1}")]
	ParseError(String, String),

	/// Error with fileIO while reading config file
	#[error("Node Config file {0} IO error, {1}")]
	FileIOError(String, String),
	/// Underlying IO error.
	#[error("Node Config IO error, {0}")]
	IO(#[from] io::Error),

	/// No file found
	#[error("Node Configuration file not found: {0}")]
	FileNotFoundError(String),

	/// Error serializing config values
	#[error("Error serializing node configuration: {0}")]
	SerializationError(String),

	/// Config error
	#[error("Configuraiton error, {0}")]
	ConfigError(String),
}

/// Going to hold all of the various configuration types
/// separately for now, then put them together as a single
/// ServerConfig object afterwards. This is to flatten
/// out the configuration file into logical sections,
/// as they tend to be quite nested in the code
/// Most structs optional, as they may or may not
/// be needed depending on what's being run
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(crate = "serde")]
pub struct GlobalConfig {
	/// Keep track of the file we've read
	pub config_file_path: Option<PathBuf>,
	/// Global member config
	pub members: ConfigMembers,
}

/// Keeping an 'inner' structure here, as the top
/// level GlobalConfigContainer options might want to keep
/// internal state that we don't necessarily
/// want serialised or deserialised
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(crate = "serde")]
pub struct ConfigMembers {
	/// Config file version (None == version 1)
	pub config_file_version: Option<u32>,
	/// Server config
	#[serde(default)]
	pub server: ServerConfig,
	/// Logging config
	pub logging: LoggingConfig,
}
