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

//! Configuration file management

use mwc_crates::dirs;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::rand::TryRng;
use mwc_crates::toml;
use mwc_crates::zeroize::Zeroizing;
use std::convert::TryFrom;
use std::env;
use std::fs;
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use crate::comments::insert_comments;
use crate::types::{ConfigError, ConfigMembers, GlobalConfig};
use mwc_core::global;
use mwc_crates::log::{error, info};
use mwc_p2p::Seeding;
use mwc_servers::ServerConfig;
use mwc_util::file::{self, OwnerOnlyFile};
use mwc_util::logger::LoggingConfig;

/// The default file name to use when trying to derive
/// the node config file location
pub const SERVER_CONFIG_FILE_NAME: &str = "mwc-server.toml";
const SERVER_LOG_FILE_NAME: &str = "mwc-server.log";
const MWC_HOME: &str = ".mwc";
const MWC_CHAIN_DIR: &str = "chain_data";
/// Node Rest API and V2 Owner API secret
pub const API_SECRET_FILE_NAME: &str = ".api_secret";
/// Foreign API secret
pub const FOREIGN_API_SECRET_FILE_NAME: &str = ".foreign_api_secret";
const API_SECRET_LEN: usize = 20;
const API_SECRET_MAX_FILE_SIZE: u64 = 4096;
const API_SECRET_ALPHABET: &[u8] =
	b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn get_mwc_path(chain_type: &global::ChainTypes) -> Result<PathBuf, ConfigError> {
	let mut mwc_path = dirs::home_dir()
		.ok_or_else(|| ConfigError::ConfigError("Unable to determine home directory".into()))?;
	if !mwc_path.is_absolute() {
		return Err(ConfigError::ConfigError(format!(
			"Home directory path is not absolute: {}",
			mwc_path.display()
		)));
	}
	mwc_path.push(MWC_HOME);
	ensure_secure_mwc_dir(&mwc_path)?;
	mwc_path.push(chain_type.shortname());
	ensure_secure_mwc_dir(&mwc_path)?;
	Ok(mwc_path)
}

fn ensure_secure_mwc_dir(path: &Path) -> Result<(), ConfigError> {
	match file::ensure_owner_only_dir(path) {
		Ok(()) => Ok(()),
		Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
			Err(ConfigError::ConfigError(e.to_string()))
		}
		Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
			Err(ConfigError::ConfigError(e.to_string()))
		}
		Err(e) => Err(ConfigError::FileIOError(
			path.display().to_string(),
			format!("Unable to secure MWC directory: {}", e),
		)),
	}
}

fn check_config_current_dir(path: &str) -> Result<Option<PathBuf>, ConfigError> {
	let mut c = env::current_dir()?;
	c.push(path);
	if c.try_exists()? {
		return Ok(Some(c));
	}
	Ok(None)
}

fn generate_api_secret() -> Result<Zeroizing<String>, ConfigError> {
	let mut api_secret = String::with_capacity(API_SECRET_LEN);
	while api_secret.len() < API_SECRET_LEN {
		let idx = SysRng
			.try_next_u32()
			.map_err(|e| ConfigError::ConfigError(format!("SysRng error: {}", e)))?
			>> (32 - 6);
		if idx < API_SECRET_ALPHABET.len() as u32 {
			api_secret.push(API_SECRET_ALPHABET[idx as usize] as char);
		}
	}
	Ok(Zeroizing::new(api_secret))
}

/// Create file with api secret
pub fn init_api_secret(api_secret_path: &PathBuf) -> Result<(), ConfigError> {
	let api_secret = generate_api_secret()?;
	file::write_owner_only_file(api_secret_path, api_secret.as_bytes())?;
	Ok(())
}

/// Check if file contains a secret and nothing else. Note, we are not checking the entripy
/// of the secret. If user choose to use it's own secret, it user's responsibility to make secret strong
pub fn check_api_secret(api_secret_path: &PathBuf) -> Result<(), ConfigError> {
	let mut api_secret_file = match file::open_owner_only_file_or_exposed(api_secret_path)? {
		OwnerOnlyFile::File(file) => file,
		OwnerOnlyFile::Exposed => {
			error!(
				"api secret {} had unsafe read permissions. We will rotate the secret.",
				api_secret_path.display()
			);
			fs::remove_file(api_secret_path)?;
			init_api_secret(api_secret_path)?;
			return Ok(());
		}
	};
	let file_len = api_secret_file.metadata()?.len();
	if file_len > API_SECRET_MAX_FILE_SIZE {
		error!(
			"api secret {} is too large. We will reset the secret.",
			api_secret_path.display()
		);
		drop(api_secret_file);
		fs::remove_file(api_secret_path)?;
		init_api_secret(api_secret_path)?;
		return Ok(());
	}

	let mut secret_bytes = Zeroizing::new(Vec::with_capacity(file_len as usize));
	api_secret_file.read_to_end(&mut *secret_bytes)?;
	let secret_contents = std::str::from_utf8(secret_bytes.as_slice()).map_err(|e| {
		ConfigError::ConfigError(format!(
			"api secret {} is not valid UTF-8: {}",
			api_secret_path.display(),
			e
		))
	})?;
	let mut lines_iter = secret_contents.lines();

	let first_line = match lines_iter.next() {
		Some(line) => line,
		None => {
			drop(api_secret_file);
			fs::remove_file(api_secret_path)?;
			init_api_secret(api_secret_path)?;
			return Ok(());
		}
	};

	// secret is expected in the forst line. Other lines, if they exist, must be empty
	let mut valid_secret_file = !first_line.is_empty();
	for line in lines_iter {
		if !line.is_empty() {
			error!(
				"api secret {} is invalid because there is some noise is found. We will reset the secret.",
				api_secret_path.display()
			);
			valid_secret_file = false;
		}
	}
	// API secret can be weaker then default len. It is still long enough
	if first_line.len() < API_SECRET_LEN - 5 {
		error!(
			"api secret {} is too weak. We will reset the secret.",
			api_secret_path.display()
		);
		valid_secret_file = false;
	}

	if !valid_secret_file {
		info!("api secret {} was reset.", api_secret_path.display());
		drop(api_secret_file);
		fs::remove_file(api_secret_path)?;
		init_api_secret(api_secret_path)?;
	}

	Ok(())
}

fn check_api_secret_file(api_secret_path: &Path) -> Result<(), ConfigError> {
	if !api_secret_path.try_exists()? {
		init_api_secret(&api_secret_path.to_path_buf())
	} else {
		check_api_secret(&api_secret_path.to_path_buf())
	}
}

fn check_configured_api_secret_file(api_secret_path: &Option<String>) -> Result<(), ConfigError> {
	if let Some(api_secret_path) = api_secret_path {
		check_api_secret_file(Path::new(api_secret_path))?;
	}
	Ok(())
}

/// Check that the configured api secret files exist and are valid
fn check_configured_api_secret_files(config: &GlobalConfig) -> Result<(), ConfigError> {
	check_configured_api_secret_file(&config.members.server.api_secret_path)?;
	check_configured_api_secret_file(&config.members.server.foreign_api_secret_path)?;
	Ok(())
}

/// Handles setup and detection of paths for node
pub fn initial_setup_server(chain_type: &global::ChainTypes) -> Result<GlobalConfig, ConfigError> {
	// Use config file if current directory if it exists, .mwc home otherwise
	let config = if let Some(p) = check_config_current_dir(SERVER_CONFIG_FILE_NAME)? {
		GlobalConfig::new(p.to_str().ok_or(ConfigError::ConfigError(
			"Internal error at server config file init".into(),
		))?)
	} else {
		// Check if mwc dir exists
		let mwc_path = get_mwc_path(chain_type)?;

		// Get path to default config file
		let mut config_path = mwc_path.clone();
		config_path.push(SERVER_CONFIG_FILE_NAME);

		// Spit it out if it doesn't exist
		if !config_path.try_exists()? {
			let mut default_config = GlobalConfig::for_chain(chain_type)?;
			// update paths relative to current dir
			default_config.update_paths(&mwc_path)?;
			default_config.write_to_file(config_path.to_str().ok_or(
				ConfigError::ConfigError("Internal error at server config file init".into()),
			)?)?;
		}

		GlobalConfig::new(config_path.to_str().ok_or(ConfigError::ConfigError(
			"Internal error at server config file init".into(),
		))?)
	}?;
	check_configured_api_secret_files(&config)?;
	Ok(config)
}

/// Returns the defaults, as strewn throughout the code
impl Default for ConfigMembers {
	fn default() -> ConfigMembers {
		ConfigMembers {
			config_file_version: Some(crate::types::CONFIG_FILE_VERSION),
			server: ServerConfig::default(),
			logging: LoggingConfig::default(),
		}
	}
}

impl Default for GlobalConfig {
	fn default() -> GlobalConfig {
		GlobalConfig {
			config_file_path: None,
			members: ConfigMembers::default(),
		}
	}
}

impl GlobalConfig {
	/// Same as GlobalConfig::default() but further tweaks parameters to
	/// apply defaults for each chain type
	pub fn for_chain(chain_type: &global::ChainTypes) -> Result<GlobalConfig, ConfigError> {
		let mut defaults_conf = GlobalConfig::default();
		let defaults = &mut defaults_conf.members.server;
		defaults.chain_type = chain_type.clone();

		match *chain_type {
			global::ChainTypes::Mainnet => {}
			global::ChainTypes::Floonet => {
				defaults.api_http_addr = "127.0.0.1:13413".to_owned();
				defaults.p2p_config.port = 13414;
				defaults.stratum_mining_config.stratum_server_addr =
					Some("127.0.0.1:13416".to_owned());
				defaults.stratum_mining_config.wallet_listener_url =
					"http://127.0.0.1:13415".to_owned();
			}
			global::ChainTypes::UserTesting => {
				defaults.api_http_addr = "127.0.0.1:23413".to_owned();
				defaults.p2p_config.port = 23414;
				defaults.p2p_config.seeding_type = Seeding::None;
				defaults.stratum_mining_config.stratum_server_addr =
					Some("127.0.0.1:23416".to_owned());
				defaults.stratum_mining_config.wallet_listener_url =
					"http://127.0.0.1:23415".to_owned();
			}
			global::ChainTypes::AutomatedTesting => {
				return Err(ConfigError::ConfigError(format!(
					"Invalid chain type: {:?}",
					chain_type
				)));
			}
		}
		Ok(defaults_conf)
	}

	/// Requires the path to a config file
	pub fn new(file_path: &str) -> Result<GlobalConfig, ConfigError> {
		let config_file = PathBuf::from(&file_path);

		// Config file path is given but not valid
		if !config_file.try_exists()? {
			return Err(ConfigError::FileNotFoundError(file_path.into()));
		}

		let mut return_value = GlobalConfig::default();
		return_value.config_file_path = Some(config_file);

		// Try to parse the config file if it exists, explode if it does exist but
		// something's wrong with it
		return_value.read_config()
	}

	/// Read config
	fn read_config(mut self) -> Result<GlobalConfig, ConfigError> {
		let config_file_path =
			self.config_file_path
				.as_ref()
				.ok_or(crate::types::ConfigError::ConfigError(
					"config_file_path is not defined".into(),
				))?;
		let mut config_file = file::open_owner_only_file(config_file_path)?;
		let file_len = usize::try_from(config_file.metadata()?.len()).map_err(|_| {
			ConfigError::ConfigError(format!(
				"config file {} is too large to read",
				config_file_path.display()
			))
		})?;
		let mut config_bytes = Zeroizing::new(vec![0; file_len]);
		config_file.read_exact(&mut config_bytes[..])?;
		let mut extra = Zeroizing::new([0u8; 1]);
		if config_file.read(&mut extra[..])? != 0 {
			return Err(ConfigError::ConfigError(format!(
				"config file {} changed size while reading",
				config_file_path.display()
			)));
		}
		let config_text = std::str::from_utf8(config_bytes.as_slice()).map_err(|e| {
			ConfigError::ConfigError(format!(
				"config file {} is not valid UTF-8: {}",
				config_file_path.display(),
				e
			))
		})?;
		let contents = Zeroizing::new(config_text.to_owned());
		drop(config_bytes);
		let (migrated, migrated_changed) =
			GlobalConfig::migrate_config_file_version_to_2(contents)?;
		if migrated_changed {
			// We understand that file might be partial in case of failure.
			// It is acceptable because such config will not be robust, so user will need to do a
			// clean up in.
			file::write_owner_only_file(config_file_path, migrated.as_bytes())?;
		}

		let decoded: Result<ConfigMembers, toml::de::Error> = {
			let fixed = GlobalConfig::fix_warning_level(migrated.as_str());
			toml::from_str(fixed.as_str())
		};
		match decoded {
			Ok(gc) => {
				self.members = gc;
				self.validate()?;
				return Ok(self);
			}
			Err(e) => {
				return Err(ConfigError::ParseError(
					// Even there is a chance that parse error might contain some sensitive config,
					//  we still want to print the error because it gives more benefets that risks.
					config_file_path.to_string_lossy().into_owned(),
					format!("{}", e),
				));
			}
		}
	}

	/// Update paths
	pub fn update_paths(&mut self, mwc_home: &PathBuf) -> Result<(), ConfigError> {
		// need to update server chain path
		let mut chain_path = mwc_home.clone();
		chain_path.push(MWC_CHAIN_DIR);
		self.members.server.db_root = chain_path
			.to_str()
			.ok_or(ConfigError::ConfigError(
				"Internal error, chain_path is invalid".into(),
			))?
			.to_owned();
		let mut api_secret_path = mwc_home.clone();
		api_secret_path.push(API_SECRET_FILE_NAME);
		self.members.server.api_secret_path = Some(
			api_secret_path
				.to_str()
				.ok_or(ConfigError::ConfigError(
					"Internal error, api_secret_path is invalid".into(),
				))?
				.to_owned(),
		);
		let mut foreign_api_secret_path = mwc_home.clone();
		foreign_api_secret_path.push(FOREIGN_API_SECRET_FILE_NAME);
		self.members.server.foreign_api_secret_path = Some(
			foreign_api_secret_path
				.to_str()
				.ok_or(ConfigError::ConfigError(
					"Internal error, foreign_api_secret_path is invalid".into(),
				))?
				.to_owned(),
		);
		let mut log_path = mwc_home.clone();
		log_path.push(SERVER_LOG_FILE_NAME);
		self.members.logging.log_file_path = log_path
			.to_str()
			.ok_or(ConfigError::ConfigError(
				"Internal error, log_path is invalid".into(),
			))?
			.to_owned();
		Ok(())
	}

	/// Enable mining
	pub fn stratum_enabled(&mut self) -> bool {
		return self
			.members
			.server
			.stratum_mining_config
			.enable_stratum_server
			.unwrap_or(false);
	}

	fn validate(&self) -> Result<(), ConfigError> {
		self.members
			.server
			.dandelion_config
			.validate()
			.map_err(ConfigError::ConfigError)
	}

	/// Serialize config
	pub fn ser_config(&mut self) -> Result<Zeroizing<String>, ConfigError> {
		self.validate()?;
		let encoded: Result<String, toml::ser::Error> = toml::to_string(&self.members);
		match encoded {
			Ok(enc) => return Ok(Zeroizing::new(enc)),
			Err(e) => {
				return Err(ConfigError::SerializationError(format!("{}", e)));
			}
		}
	}

	/// Write configuration to a file
	pub fn write_to_file(&mut self, name: &str) -> Result<(), ConfigError> {
		// Current call sites generate config templates, where onion_expanded_key is None.
		// Operators that need a stable Tor address set that key manually in the owner-only config.
		let conf_out = self.ser_config()?;
		let fixed_config = GlobalConfig::fix_log_level(conf_out.as_str());
		let commented_config = insert_comments(fixed_config.as_str());
		file::write_owner_only_file(name, commented_config.as_bytes())?;
		Ok(())
	}

	/// It is placeholder for the future migration.
	/// MWC doesn't have anything to migrate yet
	fn migrate_config_file_version_to_2(
		mut config_str: Zeroizing<String>,
	) -> Result<(Zeroizing<String>, bool), ConfigError> {
		// Parse existing config and return unchanged if not eligible for migration

		// Nothing to migrate in MWC. Keeping commented code as example
		let mut config: ConfigMembers = {
			let fixed = GlobalConfig::fix_warning_level(config_str.as_str());
			toml::from_str(fixed.as_str()).map_err(|e| {
				error!("Unable to parse configuration, {}", e);
				ConfigError::ParseError(
					"config migration".into(),
					format!("Unable to parse configuration, {}", e),
				)
			})?
		};
		if config.config_file_version == Some(crate::types::CONFIG_FILE_VERSION) {
			return Ok((config_str, false));
		}
		let cur_config_ver = config.config_file_version.unwrap_or(1);
		if cur_config_ver > crate::types::CONFIG_FILE_VERSION {
			return Err(ConfigError::ConfigError(format!(
				"Config version is too high: {}. We can't process future config versions",
				cur_config_ver
			)));
		}

		// Apply changes both textually and structurally
		match config.config_file_version {
			Some(config_file_version) => {
				config_str = Zeroizing::new(
					config_str.replace(
						format!("\nconfig_file_version = {}\n", config_file_version).as_str(),
						format!(
							"\nconfig_file_version = {}\n",
							crate::types::CONFIG_FILE_VERSION
						)
						.as_str(),
					),
				);
			}
			None => {
				// Note, this is a legacy config upgrade code, it works for along time and we don't want to change it
				let server_config_header = "\n#########################################\n### SERVER CONFIGURATION              ###";
				let versioned_server_config_header = format!(
					"\nconfig_file_version = {}\n\n#########################################\n### SERVER CONFIGURATION              ###",
					crate::types::CONFIG_FILE_VERSION
				);
				config_str = Zeroizing::new(config_str.replace(
					server_config_header,
					versioned_server_config_header.as_str(),
				));
			}
		}
		config.config_file_version = Some(crate::types::CONFIG_FILE_VERSION);

		// Note, migration with replace works as intended. We want to keep the original toml as it is
		// with all comments and custom configs.
		// We don't want to keep old accept_fee_base, tx_fee_base value should be reset.
		// Config params are well known, no collisions can happens
		config_str = Zeroizing::new(config_str.replace(
			"\naccept_fee_base",
			"\n# 'accept_fee_base' is renamed to 'tx_fee_base'. Normally you are not expected to set it, use default value.\n#accept_fee_base",
		));

		// Note, migration with replace works as intended. We want to keep the original toml as it is
		// with all comments and custom configs.
		// Config params are well known, no collisions can happens
		config_str = Zeroizing::new(config_str.replace(
			"\nhost",
			"\n# 'host' is obsolete now because it value defined by tor usage.\n#host",
		));

		// Verify equivalence

		let restored_conf = {
			let fixed = GlobalConfig::fix_warning_level(config_str.as_str());
			toml::from_str(fixed.as_str()).map_err(|e| {
				ConfigError::ConfigError(format!(
					"Internal error, unable to restore config from string, {}",
					e
				))
			})?
		};

		if config != restored_conf {
			return Err(ConfigError::ConfigError(
				"Internal error, failed to migrate config".into(),
			));
		}

		Ok((config_str, true))
	}

	// For forwards compatibility old config needs `Warning` log level changed to standard log::Level `WARN`
	fn fix_warning_level(conf: &str) -> Zeroizing<String> {
		let mut fixed = Zeroizing::new(String::with_capacity(conf.len()));
		GlobalConfig::push_fixed_logging_level_fields(&mut *fixed, conf, &[("Warning", "WARN")]);
		fixed
	}

	// For backwards compatibility only first letter of log level should be capitalised.
	fn fix_log_level(conf: &str) -> Zeroizing<String> {
		// Allocate enough headroom so growing replacements such as WARN -> Warning do not
		// reallocate after sensitive config values have already been copied.
		let mut fixed = Zeroizing::new(String::with_capacity(conf.len().saturating_mul(2)));
		GlobalConfig::push_fixed_logging_level_fields(
			&mut *fixed,
			conf,
			&[
				("TRACE", "Trace"),
				("DEBUG", "Debug"),
				("INFO", "Info"),
				("WARN", "Warning"),
				("ERROR", "Error"),
			],
		);
		fixed
	}

	fn push_fixed_logging_level_fields(
		fixed: &mut String,
		conf: &str,
		replacements: &[(&str, &str)],
	) {
		for line in conf.split_inclusive('\n') {
			GlobalConfig::push_fixed_logging_level_line(fixed, line, replacements);
		}
	}

	fn push_fixed_logging_level_line(
		fixed: &mut String,
		line: &str,
		replacements: &[(&str, &str)],
	) {
		let trimmed = line.trim_start();
		if trimmed.starts_with('#') {
			fixed.push_str(line);
			return;
		}

		let Some(eq_pos) = line.find('=') else {
			fixed.push_str(line);
			return;
		};
		let key = line[..eq_pos].trim();
		if key != "stdout_log_level" && key != "file_log_level" {
			fixed.push_str(line);
			return;
		}

		let value_prefix = &line[eq_pos + 1..];
		let Some(value_offset) = value_prefix.find(|c: char| !c.is_whitespace()) else {
			fixed.push_str(line);
			return;
		};
		let value_pos = eq_pos + 1 + value_offset;
		for (from, to) in replacements {
			for quote in ['"', '\''] {
				let old_value = format!("{}{}{}", quote, from, quote);
				if let Some(rest) = line[value_pos..].strip_prefix(&old_value) {
					if rest
						.chars()
						.next()
						.map(|c| c.is_whitespace() || c == '#')
						.unwrap_or(true)
					{
						fixed.push_str(&line[..value_pos]);
						fixed.push(quote);
						fixed.push_str(to);
						fixed.push(quote);
						fixed.push_str(rest);
						return;
					}
				}
			}
		}

		fixed.push_str(line);
	}
}

#[test]
fn test_fix_log_level() {
	let config = r#"
[logging]
stdout_log_level = "WARN" # keep this comment
file_log_level='ERROR'
log_file_path = "WARN/mwc.log"

[server]
api_secret_path = "WARN-secret"
#stdout_log_level = "WARN"
"#
	.to_string();
	let fixed_config = GlobalConfig::fix_log_level(&config);
	assert!(fixed_config.contains("stdout_log_level = \"Warning\" # keep this comment"));
	assert!(fixed_config.contains("file_log_level='Error'"));
	assert!(fixed_config.contains("log_file_path = \"WARN/mwc.log\""));
	assert!(fixed_config.contains("api_secret_path = \"WARN-secret\""));
	assert!(fixed_config.contains("#stdout_log_level = \"WARN\""));
}

#[test]
fn test_fix_warning_level() {
	let config = r#"
[logging]
stdout_log_level = "Warning" # keep this comment
file_log_level = "Info"
log_file_path = "Warning/mwc.log"

[server]
api_secret_path = "Warning-secret"
#stdout_log_level = "Warning"
"#
	.to_string();
	let fixed_config = GlobalConfig::fix_warning_level(&config);
	assert!(fixed_config.contains("stdout_log_level = \"WARN\" # keep this comment"));
	assert!(fixed_config.contains("file_log_level = \"Info\""));
	assert!(fixed_config.contains("log_file_path = \"Warning/mwc.log\""));
	assert!(fixed_config.contains("api_secret_path = \"Warning-secret\""));
	assert!(fixed_config.contains("#stdout_log_level = \"Warning\""));
}

#[cfg(test)]
fn config_test_dir_path(name: &str) -> PathBuf {
	let mut dir = env::temp_dir();
	let nonce = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_nanos();
	dir.push(format!(
		"mwc_config_dir_{}_{}_{}",
		name,
		std::process::id(),
		nonce
	));
	dir
}

#[cfg(test)]
fn api_secret_test_path(name: &str) -> PathBuf {
	let mut dir = env::temp_dir();
	let nonce = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_nanos();
	dir.push(format!(
		"mwc_config_api_secret_{}_{}_{}",
		name,
		std::process::id(),
		nonce
	));
	fs::create_dir_all(&dir).unwrap();
	dir.push(".api_secret");
	dir
}

#[cfg(test)]
fn set_api_secret_owner_only(path: &Path) {
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
	}
}

#[test]
fn check_api_secret_allows_empty_trailing_lines() {
	let path = api_secret_test_path("empty_trailing_lines");
	fs::write(&path, "super_secret_double\n\n").unwrap();
	set_api_secret_owner_only(&path);

	check_api_secret(&path).unwrap();

	assert_eq!(
		fs::read_to_string(&path).unwrap(),
		"super_secret_double\n\n"
	);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn check_api_secret_short() {
	let path = api_secret_test_path("short_secret");
	fs::write(&path, "secret\n\n").unwrap();
	set_api_secret_owner_only(&path);

	check_api_secret(&path).unwrap();

	let new_str = fs::read_to_string(&path).unwrap();
	assert!(new_str.len() == API_SECRET_LEN);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn check_api_secret_regenerates_extra_non_empty_lines() {
	let path = api_secret_test_path("extra_non_empty_lines");
	fs::write(&path, "secret\nextra\n").unwrap();
	set_api_secret_owner_only(&path);

	check_api_secret(&path).unwrap();

	let contents = fs::read_to_string(&path).unwrap();
	assert_ne!(contents, "secret\nextra\n");
	assert_eq!(contents.len(), 20);
	assert_eq!(contents.lines().count(), 1);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_rotates_group_or_world_readable_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("readable_permissions");
	let old_secret = "super_secret_double\n";
	fs::write(&path, old_secret).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

	check_api_secret(&path).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	let contents = fs::read_to_string(&path).unwrap();
	assert_eq!(contents.len(), API_SECRET_LEN);
	assert_ne!(contents, old_secret);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_repairs_owner_only_file_permissions() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("repair_permissions");
	fs::write(&path, "super_secret_double\n").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

	check_api_secret(&path).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	assert_eq!(fs::read_to_string(&path).unwrap(), "super_secret_double\n");
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn check_api_secret_rejects_group_or_world_writable_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("unsafe_writable");
	fs::write(&path, "super_secret_double\n").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

	assert!(check_api_secret(&path).is_err());
	assert_eq!(fs::read_to_string(&path).unwrap(), "super_secret_double\n");
	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o666);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn check_configured_api_secret_files_uses_configured_paths() {
	let api_path = api_secret_test_path("configured_api");
	let foreign_path = api_secret_test_path("configured_foreign");
	let mut config = GlobalConfig::default();
	config.members.server.api_secret_path = Some(api_path.to_string_lossy().into_owned());
	config.members.server.foreign_api_secret_path =
		Some(foreign_path.to_string_lossy().into_owned());

	check_configured_api_secret_files(&config).unwrap();

	assert_eq!(fs::read_to_string(&api_path).unwrap().len(), API_SECRET_LEN);
	assert_eq!(
		fs::read_to_string(&foreign_path).unwrap().len(),
		API_SECRET_LEN
	);
	fs::remove_dir_all(api_path.parent().unwrap()).unwrap();
	fs::remove_dir_all(foreign_path.parent().unwrap()).unwrap();
}

#[test]
fn check_api_secret_propagates_read_errors_without_regenerating() {
	let path = api_secret_test_path("read_error");
	fs::write(&path, [0xff]).unwrap();
	set_api_secret_owner_only(&path);

	assert!(check_api_secret(&path).is_err());
	assert_eq!(fs::read(&path).unwrap(), vec![0xff]);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn ensure_secure_mwc_dir_creates_owner_only_directory() {
	use std::os::unix::fs::PermissionsExt;

	let path = config_test_dir_path("owner_only");

	ensure_secure_mwc_dir(&path).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o700);
	fs::remove_dir_all(&path).unwrap();
}

#[cfg(unix)]
#[test]
fn ensure_secure_mwc_dir_tightens_existing_non_writable_directory() {
	use std::os::unix::fs::PermissionsExt;

	let path = config_test_dir_path("tighten");
	fs::create_dir(&path).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();

	ensure_secure_mwc_dir(&path).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o700);
	fs::remove_dir_all(&path).unwrap();
}

#[cfg(unix)]
#[test]
fn ensure_secure_mwc_dir_rejects_group_or_world_writable_directory() {
	use std::os::unix::fs::PermissionsExt;

	let path = config_test_dir_path("unsafe_writable");
	fs::create_dir(&path).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();

	assert!(ensure_secure_mwc_dir(&path).is_err());
	fs::remove_dir_all(&path).unwrap();
}

#[cfg(unix)]
#[test]
fn ensure_secure_mwc_dir_rejects_symlinked_directory() {
	use std::os::unix::fs::symlink;

	let target = config_test_dir_path("symlink_target");
	let path = config_test_dir_path("symlink");
	fs::create_dir(&target).unwrap();
	symlink(&target, &path).unwrap();

	assert!(ensure_secure_mwc_dir(&path).is_err());
	fs::remove_file(&path).unwrap();
	fs::remove_dir_all(&target).unwrap();
}

#[cfg(unix)]
#[test]
fn init_api_secret_creates_owner_only_file() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("owner_only");

	init_api_secret(&path).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn write_to_file_creates_owner_only_config_file() {
	use std::os::unix::fs::PermissionsExt;

	let dir = config_test_dir_path("config_owner_only");
	fs::create_dir(&dir).unwrap();
	let path = dir.join(SERVER_CONFIG_FILE_NAME);
	let mut config = GlobalConfig::default();

	config.write_to_file(path.to_str().unwrap()).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn write_to_file_tightens_existing_config_file_permissions() {
	use std::os::unix::fs::PermissionsExt;

	let dir = config_test_dir_path("config_fix_permissions");
	fs::create_dir(&dir).unwrap();
	let path = dir.join(SERVER_CONFIG_FILE_NAME);
	fs::write(&path, "old-config").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
	let mut config = GlobalConfig::default();

	config.write_to_file(path.to_str().unwrap()).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	assert_ne!(fs::read_to_string(&path).unwrap(), "old-config");
	fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn new_tightens_existing_config_file_permissions_before_read() {
	use std::os::unix::fs::PermissionsExt;

	let dir = config_test_dir_path("config_read_fix_permissions");
	fs::create_dir(&dir).unwrap();
	let path = dir.join(SERVER_CONFIG_FILE_NAME);
	let mut config = GlobalConfig::default();
	config.write_to_file(path.to_str().unwrap()).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

	GlobalConfig::new(path.to_str().unwrap()).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn new_rejects_dandelion_stem_probability_above_100() {
	let dir = config_test_dir_path("config_invalid_stem_probability");
	fs::create_dir(&dir).unwrap();
	let path = dir.join(SERVER_CONFIG_FILE_NAME);
	let mut config = GlobalConfig::default();
	config.write_to_file(path.to_str().unwrap()).unwrap();

	let config_text = fs::read_to_string(&path).unwrap();
	assert!(config_text.contains("stem_probability = 90"));
	fs::write(
		&path,
		config_text.replace("stem_probability = 90", "stem_probability = 101"),
	)
	.unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
	}

	let err = GlobalConfig::new(path.to_str().unwrap()).unwrap_err();

	assert!(matches!(
		err,
		ConfigError::ConfigError(message)
			if message.contains("stem_probability") && message.contains("0..=100")
	));
	fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn new_rejects_group_or_world_readable_config_file() {
	use std::os::unix::fs::PermissionsExt;

	let dir = config_test_dir_path("config_read_unsafe_readable");
	fs::create_dir(&dir).unwrap();
	let path = dir.join(SERVER_CONFIG_FILE_NAME);
	let mut config = GlobalConfig::default();
	config.write_to_file(path.to_str().unwrap()).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

	assert!(GlobalConfig::new(path.to_str().unwrap()).is_err());

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o644);
	fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn new_rejects_group_or_world_writable_config_file() {
	use std::os::unix::fs::PermissionsExt;

	let dir = config_test_dir_path("config_read_unsafe_writable");
	fs::create_dir(&dir).unwrap();
	let path = dir.join(SERVER_CONFIG_FILE_NAME);
	let mut config = GlobalConfig::default();
	config.write_to_file(path.to_str().unwrap()).unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

	assert!(GlobalConfig::new(path.to_str().unwrap()).is_err());

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o666);
	fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn new_rejects_config_file_with_invalid_utf8() {
	let dir = config_test_dir_path("config_invalid_utf8");
	fs::create_dir(&dir).unwrap();
	let path = dir.join(SERVER_CONFIG_FILE_NAME);
	fs::write(&path, [b'[', 0xff]).unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
	}

	let err = GlobalConfig::new(path.to_str().unwrap()).unwrap_err();

	assert!(matches!(
		err,
		ConfigError::ConfigError(message) if message.contains("not valid UTF-8")
	));
	fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn init_api_secret_fixes_existing_file_permissions_before_write() {
	use std::os::unix::fs::PermissionsExt;

	let path = api_secret_test_path("fix_permissions");
	fs::write(&path, "old-secret").unwrap();
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

	init_api_secret(&path).unwrap();

	let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o600);
	assert_ne!(fs::read_to_string(&path).unwrap(), "old-secret");
	fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
