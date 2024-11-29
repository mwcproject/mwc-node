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
use crate::util::secp;
use crate::util::OnionV3AddressError;

/// Error definition
/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum Error {
	/// Tor Configuration Error
	#[error("Tor Config Error: {0}")]
	TorConfig(String),

	/// Tor Process error
	#[error("Tor Process Error: {0}")]
	TorProcess(String),

	/// Onion V3 Address Error
	#[error("Onion V3 Address Error")]
	OnionV3Address(OnionV3AddressError),

	/// Error when formatting json
	#[error("IO error, {0}")]
	IO(String),

	/// Secp Error
	#[error("Secp error, {0}")]
	Secp(secp::Error),

	/// Generating ED25519 Public Key
	#[error("Error generating ed25519 secret key: {0}")]
	ED25519Key(String),

	/// Checking for onion address
	#[error("Address is not an Onion v3 Address: {0}")]
	NotOnion(String),

	/// Generic Error
	#[error("libp2p Error, {0}")]
	LibP2P(String),
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error::Secp(error)
	}
}

impl From<OnionV3AddressError> for Error {
	fn from(error: OnionV3AddressError) -> Error {
		Error::OnionV3Address(error)
	}
}
