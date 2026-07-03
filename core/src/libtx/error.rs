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

//! libtx specific errors
use crate::consensus;
use crate::core::transaction;
use mwc_crates::secp;

/// Lib tx error definition
#[derive(Debug, thiserror::Error)]
/// Libwallet error types
pub enum Error {
	/// SECP error
	#[error("LibTx Secp Error, {0}")]
	Secp(secp::Error),
	/// Keychain error
	#[error("LibTx Keychain Error, {source:?}")]
	Keychain {
		/// Keychain error
		#[from]
		source: keychain::Error,
	},
	/// Transaction error
	#[error("LibTx Transaction Error, {source:?}")]
	Transaction {
		/// Transaction error
		#[from]
		source: transaction::Error,
	},
	/// Zero blinding sum
	#[error("Zero blinding sum")]
	ZeroBlindingSum,
	/// Signature error
	#[error("LibTx Signature Error, {0}")]
	Signature(String),
	/// Rangeproof error
	#[error("LibTx Rangeproof Error, {0}")]
	RangeProof(String),
	/// Data overflow error
	#[error("LibTx data overflow error, {0}")]
	DataOverflow(String),
	/// Other error
	#[error("LibTx Other Error, {0}")]
	Other(String),
	/// Consensus error
	#[error("Consensus error {0}")]
	ConsensusError(#[from] consensus::Error),
}

impl From<secp::Error> for Error {
	fn from(err: secp::Error) -> Self {
		Error::Secp(err)
	}
}
