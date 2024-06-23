// Copyright 2019 The Grin Developers
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

//! Tor Configuration + Onion (Hidden) Service operations
use crate::util::secp::key::SecretKey;
use crate::Error;
use grin_util::OnionV3Address;

use ed25519_dalek::PublicKey as DalekPublicKey;
use ed25519_dalek::SecretKey as DalekSecretKey;
use ed25519_dalek::{ExpandedSecretKey, SECRET_KEY_LENGTH};

use std::convert::TryFrom;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, MAIN_SEPARATOR};

use grin_core::global;
use grin_util::secp::Secp256k1;

pub const SEC_KEY_FILE_COPY: &str = "secret_key";
const SEC_KEY_FILE: &str = "hs_ed25519_secret_key";
const PUB_KEY_FILE: &str = "hs_ed25519_public_key";
const HOSTNAME_FILE: &str = "hostname";
const TORRC_FILE: &str = "torrc";
const TOR_DATA_DIR: &str = "data";
const AUTH_CLIENTS_DIR: &str = "authorized_clients";
const HIDDEN_SERVICES_DIR: &str = "onion_service_addresses";

#[cfg(unix)]
fn set_permissions(file_path: &str) -> Result<(), Error> {
	use std::os::unix::prelude::*;
	fs::set_permissions(file_path, fs::Permissions::from_mode(0o700)).map_err(|e| {
		Error::IO(format!(
			"Unable to update permissions for {}, {}",
			file_path, e
		))
	})?;
	Ok(())
}

#[cfg(windows)]
fn set_permissions(_file_path: &str) -> Result<(), Error> {
	Ok(())
}

struct TorRcConfigItem {
	pub name: String,
	pub value: String,
}

impl TorRcConfigItem {
	/// Create new
	pub fn new(name: &str, value: &str) -> Self {
		Self {
			name: name.into(),
			value: value.into(),
		}
	}
}

struct TorRcConfig {
	pub items: Vec<TorRcConfigItem>,
}

impl TorRcConfig {
	/// Create new
	pub fn new() -> Self {
		Self { items: vec![] }
	}

	/// add item
	pub fn add_item(&mut self, name: &str, value: &str) {
		self.items.push(TorRcConfigItem::new(name, value));
	}

	/// write to file
	pub fn write_to_file(&self, file_path: &str) -> Result<(), Error> {
		let mut file = File::create(file_path)
			.map_err(|e| Error::IO(format!("Unable to create file {}, {}", file_path, e)))?;
		for item in &self.items {
			file.write_all(item.name.as_bytes()).map_err(|e| {
				Error::IO(format!("Unable to write into file {}, {}", file_path, e))
			})?;
			file.write_all(b" ").map_err(|e| {
				Error::IO(format!("Unable to write into file {}, {}", file_path, e))
			})?;
			file.write_all(item.value.as_bytes()).map_err(|e| {
				Error::IO(format!("Unable to write into file {}, {}", file_path, e))
			})?;
			file.write_all(b"\n").map_err(|e| {
				Error::IO(format!("Unable to write into file {}, {}", file_path, e))
			})?;
		}
		Ok(())
	}
}

pub fn create_onion_service_sec_key_file(
	os_directory: &str,
	sec_key: &DalekSecretKey,
) -> Result<(), Error> {
	let key_file_path = &format!("{}{}{}", os_directory, MAIN_SEPARATOR, SEC_KEY_FILE);
	let mut file = File::create(key_file_path)
		.map_err(|e| Error::IO(format!("Unable to create file {}, {}", key_file_path, e)))?;
	// Tag is always 32 bytes, so pad with null zeroes
	file.write(b"== ed25519v1-secret: type0 ==\0\0\0")
		.map_err(|e| {
			Error::IO(format!(
				"Unable to write into file {}, {}",
				key_file_path, e
			))
		})?;
	let expanded_skey: ExpandedSecretKey = ExpandedSecretKey::from(sec_key);
	file.write_all(&expanded_skey.to_bytes()).map_err(|e| {
		Error::IO(format!(
			"Unable to write into file {}, {}",
			key_file_path, e
		))
	})?;
	Ok(())
}

pub fn create_sec_key_file(os_directory: &str, sec_key: &DalekSecretKey) -> Result<(), Error> {
	let key_file_path = &format!("{}{}{}", os_directory, MAIN_SEPARATOR, SEC_KEY_FILE_COPY);
	let mut file = File::create(key_file_path)
		.map_err(|e| Error::IO(format!("Unable to create file {}, {}", key_file_path, e)))?;
	file.write(&sec_key.to_bytes()).map_err(|e| {
		Error::IO(format!(
			"Unable to write into file {}, {}",
			key_file_path, e
		))
	})?;
	Ok(())
}

pub fn read_sec_key_file(os_directory: &str, secp: &Secp256k1) -> Result<SecretKey, Error> {
	let key_file_path = &format!("{}{}{}", os_directory, MAIN_SEPARATOR, SEC_KEY_FILE_COPY);
	let mut file = File::open(key_file_path)
		.map_err(|e| Error::IO(format!("Unable to create file {}, {}", key_file_path, e)))?;

	let mut buf: [u8; SECRET_KEY_LENGTH] = [0; SECRET_KEY_LENGTH];

	let sz = file
		.read(&mut buf)
		.map_err(|e| Error::IO(format!("Unable to read from file {}, {}", key_file_path, e)))?;
	if sz != buf.len() {
		return Err(Error::IO(format!("Not found expected data at file {}", key_file_path)).into());
	}

	let sk = SecretKey::from_slice(secp, &buf)?;
	Ok(sk)
}

pub fn create_onion_service_pub_key_file(
	os_directory: &str,
	pub_key: &DalekPublicKey,
) -> Result<(), Error> {
	let key_file_path = &format!("{}{}{}", os_directory, MAIN_SEPARATOR, PUB_KEY_FILE);
	let mut file = File::create(key_file_path)
		.map_err(|e| Error::IO(format!("Unable to create file {}, {}", key_file_path, e)))?;
	// Tag is always 32 bytes, so pad with null zeroes
	file.write(b"== ed25519v1-public: type0 ==\0\0\0")
		.map_err(|e| {
			Error::IO(format!(
				"Unable to write into file {}, {}",
				key_file_path, e
			))
		})?;
	file.write_all(pub_key.as_bytes()).map_err(|e| {
		Error::IO(format!(
			"Fail to write data to file {}, {}",
			key_file_path, e
		))
	})?;
	Ok(())
}

pub fn create_onion_service_hostname_file(os_directory: &str, hostname: &str) -> Result<(), Error> {
	let file_path = &format!("{}{}{}", os_directory, MAIN_SEPARATOR, HOSTNAME_FILE);
	let mut file = File::create(file_path)
		.map_err(|e| Error::IO(format!("Unable to create file {}, {}", file_path, e)))?;
	file.write_all(&format!("{}.onion\n", hostname).as_bytes())
		.map_err(|e| Error::IO(format!("Fail to store data to file {}, {}", file_path, e)))?;
	Ok(())
}

pub fn create_onion_auth_clients_dir(os_directory: &str) -> Result<(), Error> {
	let auth_dir_path = &format!("{}{}{}", os_directory, MAIN_SEPARATOR, AUTH_CLIENTS_DIR);
	fs::create_dir_all(auth_dir_path)
		.map_err(|e| Error::IO(format!("Unable to create dir {}, {}", auth_dir_path, e)))?;
	Ok(())
}
/// output an onion service config for the secret key, and return the address
pub fn output_onion_service_config(
	tor_config_directory: &str,
	sec_key: &SecretKey,
) -> Result<OnionV3Address, Error> {
	let d_sec_key = DalekSecretKey::from_bytes(&sec_key.0)
		.map_err(|e| Error::ED25519Key(format!("Unable to parse private key, {}", e)))?;
	let address = OnionV3Address::from_private(&sec_key.0)?;
	let hs_dir_file_path = format!(
		"{}{}{}{}{}",
		tor_config_directory, MAIN_SEPARATOR, HIDDEN_SERVICES_DIR, MAIN_SEPARATOR, address
	);

	// If file already exists, don't overwrite it, just return address
	if Path::new(&hs_dir_file_path).exists() {
		return Ok(address);
	}

	// create directory if it doesn't exist
	fs::create_dir_all(&hs_dir_file_path)
		.map_err(|e| Error::IO(format!("Unable to create dir {}, {}", hs_dir_file_path, e)))?;

	create_sec_key_file(&hs_dir_file_path, &d_sec_key)?;
	create_onion_service_sec_key_file(&hs_dir_file_path, &d_sec_key)?;
	create_onion_service_pub_key_file(&hs_dir_file_path, &address.to_ed25519()?)?;
	create_onion_service_hostname_file(&hs_dir_file_path, &address.to_string())?;
	create_onion_auth_clients_dir(&hs_dir_file_path)?;

	set_permissions(&hs_dir_file_path)?;

	Ok(address)
}

/// output torrc file given a list of hidden service directories
pub fn output_torrc(
	tor_config_directory: &str,
	server_p2p_listener_addr: &str,
	api_listener_addr: &str,
	libp2p_port: u16,
	socks_port: &str,
	service_dirs: &[String],
) -> Result<(), Error> {
	let torrc_file_path = format!("{}{}{}", tor_config_directory, MAIN_SEPARATOR, TORRC_FILE);

	let tor_data_dir = format!("./{}", TOR_DATA_DIR);

	let mut props = TorRcConfig::new();
	props.add_item("SocksPort", &format!("127.0.0.1:{}", socks_port));
	props.add_item("DataDirectory", &tor_data_dir);

	for dir in service_dirs {
		let service_file_name = format!("./{}{}{}", HIDDEN_SERVICES_DIR, MAIN_SEPARATOR, dir);
		props.add_item("HiddenServiceDir", &service_file_name);
		props.add_item("HiddenServiceVersion", &format!("3"));
		props.add_item(
			"HiddenServicePort",
			&format!("80 {}", server_p2p_listener_addr),
		);
		props.add_item("HiddenServicePort", &format!("8080 {}", api_listener_addr));
		props.add_item(
			"HiddenServicePort",
			&format!(
				"{} 127.0.0.1:{}",
				global::get_tor_libp2p_port(),
				libp2p_port
			),
		);
	}

	props.write_to_file(&torrc_file_path)?;

	Ok(())
}

/// output entire tor config for a list of secret keys
pub fn output_tor_listener_config(
	tor_config_directory: &str,
	server_p2p_listener_addr: &str,
	api_listener_addr: &str,
	libp2p_port: u16,
	listener_keys: Option<&[SecretKey]>,
	onion_address: Option<String>,
	socks_port: u16,
) -> Result<(), Error> {
	let tor_data_dir = format!("{}{}{}", tor_config_directory, MAIN_SEPARATOR, TOR_DATA_DIR);

	// create data directory if it doesn't exist
	fs::create_dir_all(&tor_data_dir)
		.map_err(|e| Error::IO(format!("Unable to create dir {}, {}", tor_data_dir, e)))?;

	let mut service_dirs = vec![];

	if listener_keys.is_some() {
		let listener_keys = listener_keys.unwrap();
		for k in listener_keys {
			let service_dir = output_onion_service_config(tor_config_directory, &k)?;
			service_dirs.push(service_dir.to_string());
		}
	} else if onion_address.is_some() {
		service_dirs.push(onion_address.unwrap());
	}

	// hidden service listener doesn't need a socks port
	output_torrc(
		tor_config_directory,
		server_p2p_listener_addr,
		api_listener_addr,
		libp2p_port,
		&format!("{}", socks_port),
		&service_dirs,
	)?;

	Ok(())
}

pub fn _is_tor_address(input: &str) -> Result<(), Error> {
	match OnionV3Address::try_from(input) {
		Ok(_) => Ok(()),
		Err(e) => Err(Error::NotOnion(format!("{}, {}", input, e)))?,
	}
}

pub fn _complete_tor_address(input: &str) -> Result<String, Error> {
	let input = if input.ends_with("/") {
		&input[..input.len() - 1]
	} else {
		input
	};
	_is_tor_address(input)?;
	let mut input = input.to_uppercase();
	if !input.starts_with("HTTP://") && !input.starts_with("HTTPS://") {
		input = format!("HTTP://{}", input);
	}
	if !input.ends_with(".ONION") {
		input = format!("{}.ONION", input);
	}
	Ok(input.to_lowercase())
}

#[cfg(test)]
mod tests {
	use super::*;

	use grin_util::secp::ContextFlag;
	use rand::rngs::mock::StepRng;

	use crate::util::{self, secp};

	pub fn clean_output_dir(test_dir: &str) {
		let _ = fs::remove_dir_all(test_dir);
	}

	pub fn setup(test_dir: &str) {
		util::init_test_logger();
		clean_output_dir(test_dir);
	}

	#[test]
	fn test_service_config() -> Result<(), Error> {
		let test_dir = "target/test_output/onion_service";
		setup(test_dir);
		let secp = Secp256k1::with_caps(ContextFlag::None);
		let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
		let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);
		output_onion_service_config(test_dir, &sec_key)?;
		clean_output_dir(test_dir);
		Ok(())
	}

	#[test]
	fn test_output_tor_config() -> Result<(), Error> {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let test_dir = "./target/test_output/tor";
		setup(test_dir);
		let secp = Secp256k1::with_caps(ContextFlag::None);
		let mut test_rng = StepRng::new(1_234_567_890_u64, 1);
		let sec_key = secp::key::SecretKey::new(&secp, &mut test_rng);
		output_tor_listener_config(
			test_dir,
			"127.0.0.1:3415",
			"127.0.0.1:3416",
			1234,
			Some(&[sec_key]),
			None,
			0,
		)?;
		clean_output_dir(test_dir);
		Ok(())
	}

	#[test]
	fn test_is_tor_address() -> Result<(), Error> {
		assert!(
			_is_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid").is_ok()
		);
		assert!(
			_is_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid").is_ok()
		);
		assert!(
			_is_tor_address("kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid").is_ok()
		);
		assert!(_is_tor_address(
			"http://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
		)
		.is_ok());
		assert!(_is_tor_address(
			"https://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
		)
		.is_ok());
		assert!(
			_is_tor_address("http://kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid")
				.is_ok()
		);
		assert!(
			_is_tor_address("kcgiy5g6m76nzlzz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion")
				.is_ok()
		);
		// address too short
		assert!(_is_tor_address(
			"http://kcgiy5g6m76nzlz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid.onion"
		)
		.is_err());
		assert!(
			_is_tor_address("kcgiy5g6m76nzlz4vyqmgdv34f6yokdqwfhdhaafanpo5p4fceibyid").is_err()
		);
		Ok(())
	}

	#[test]
	fn test_complete_tor_address() -> Result<(), Error> {
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			_complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid")
				.unwrap()
		);
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			_complete_tor_address(
				"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid"
			)
			.unwrap()
		);
		assert_eq!(
			"http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion",
			_complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion")
				.unwrap()
		);
		assert!(
			_complete_tor_address("2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyi")
				.is_err()
		);
		Ok(())
	}
}
