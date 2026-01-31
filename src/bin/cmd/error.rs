// Copyright 2026 The MWC Developers
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

/// Error type wrapping underlying module errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// RPC Error
	#[error("RPC error: {0}")]
	RPCError(String),
	/// Internal error
	#[error("Internal error: {0}")]
	Internal(String),
	/// Terminal IO error
	#[error("Terminal IO error: {0}")]
	TerminalIO(#[from] term::Error),
	/// Write IO error
	#[error("Write IO error: {0}")]
	WriteIO(#[from] std::io::Error),
	/// Argumnet error
	#[error("{0}")]
	ArgumentError(String),
}
