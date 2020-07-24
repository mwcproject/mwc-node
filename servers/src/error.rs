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

//! Implementation specific error types
use crate::util::secp;
use crate::util::OnionV3AddressError;
use failure::{Backtrace, Context, Fail};
use std::env;
use std::fmt::{self, Display};

/// Error definition
#[derive(Debug)]
pub struct Error {
	/// Inner Error
	pub inner: Context<ErrorKind>,
}

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	/// Tor Configuration Error
	#[fail(display = "Tor Config Error: {}", _0)]
	TorConfig(String),

	/// Tor Process error
	#[fail(display = "Tor Process Error: {}", _0)]
	TorProcess(String),

	/// Onion V3 Address Error
	#[fail(display = "Onion V3 Address Error")]
	OnionV3Address(OnionV3AddressError),

	/// Error when formatting json
	#[fail(display = "IO error, {}", _0)]
	IO(String),

	/// Secp Error
	#[fail(display = "Secp error, {}", _0)]
	Secp(secp::Error),

	/// Generating ED25519 Public Key
	#[fail(display = "Error generating ed25519 secret key: {}", _0)]
	ED25519Key(String),

	/// Checking for onion address
	#[fail(display = "Address is not an Onion v3 Address: {}", _0)]
	NotOnion(String),
}

impl Fail for Error {
	fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}

	fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let show_bt = match env::var("RUST_BACKTRACE") {
			Ok(r) => r == "1",
			Err(_) => false,
		};
		let backtrace = match self.backtrace() {
			Some(b) => format!("{}", b),
			None => String::from("Unknown"),
		};
		let inner_output = format!("{}", self.inner,);
		let backtrace_output = format!("\nBacktrace: {}", backtrace);
		let mut output = inner_output;
		if show_bt {
			output.push_str(&backtrace_output);
		}
		Display::fmt(&output, f)
	}
}

impl Error {
	/// get kind
	pub fn kind(&self) -> ErrorKind {
		self.inner.get_context().clone()
	}
	/// get cause
	pub fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}
	/// get backtrace
	pub fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<Context<ErrorKind>> for Error {
	fn from(inner: Context<ErrorKind>) -> Error {
		Error { inner: inner }
	}
}

impl From<secp::Error> for Error {
	fn from(error: secp::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Secp(error)),
		}
	}
}

impl From<OnionV3AddressError> for Error {
	fn from(error: OnionV3AddressError) -> Error {
		Error::from(ErrorKind::OnionV3Address(error))
	}
}
