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

//! Implementation specific error types
use mwc_crates::secp;
use mwc_util::OnionV3Error;

/// Error definition
/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Configuration Error
	#[error("Config Error: {0}")]
	Config(String),

	/// Tor Configuration Error
	#[error("Tor Config Error: {0}")]
	TorConfig(String),

	/// Tor Process error
	#[error("Tor Process Error: {0}")]
	TorProcess(String),

	/// Tor Process error
	#[error("Onion Service Error: {0}")]
	TorOnionService(String),

	/// Onion V3 Address Error
	#[error("Onion V3 Address Error")]
	OnionV3Address(#[from] OnionV3Error),

	/// Error when formatting json
	#[error("IO error, {0}")]
	IO(#[from] std::io::Error),

	/// Secp Error
	#[error("Secp error, {0}")]
	Secp(secp::Error),

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {0}")]
	ED25519Key(String),

	/// Checking for onion address
	#[error("Address is not an Onion v3 Address: {0}")]
	NotOnion(String),

	/// Data overflow error
	#[error("Server data overflow error, {0}")]
	DataOverflow(String),

	/// Generic Error
	#[error("Node server error, {0}")]
	ServerError(String),

	/// Hooks Error
	#[error("Hooks error, {0}")]
	HooksError(String),
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error::Secp(error)
	}
}
