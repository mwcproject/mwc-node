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

//! libtx specific errors
use crate::core::transaction;
use util::secp;

/// Lib tx error definition
#[derive(Clone, Debug, Eq, thiserror::Error, PartialEq, Serialize, Deserialize)]
/// Libwallet error types
pub enum Error {
	/// SECP error
	#[error("LibTx Secp Error, {0}")]
	Secp(secp::Error),
	/// Keychain error
	#[error("LibTx Keychain Error, {0}")]
	Keychain(keychain::Error),
	/// Transaction error
	#[error("LibTx Transaction Error, {0}")]
	Transaction(transaction::Error),
	/// Signature error
	#[error("LibTx Signature Error, {0}")]
	Signature(String),
	/// Rangeproof error
	#[error("LibTx Rangeproof Error, {0}")]
	RangeProof(String),
	/// Other error
	#[error("LibTx Other Error, {0}")]
	Other(String),
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error::Secp(error)
	}
}

impl From<keychain::Error> for Error {
	fn from(error: keychain::Error) -> Error {
		Error::Keychain(error)
	}
}

impl From<transaction::Error> for Error {
	fn from(error: transaction::Error) -> Error {
		Error::Transaction(error)
	}
}
