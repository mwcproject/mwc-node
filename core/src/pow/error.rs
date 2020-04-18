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

//! Cuckatoo specific errors
use failure::{Backtrace, Context, Fail};
use std::fmt::{self, Display};
use std::io;

/// Cuckatoo solver or validation error
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

#[derive(Clone, Debug, Eq, Fail, PartialEq)]
/// Libwallet error types
pub enum ErrorKind {
	/// Pre POW error
	#[fail(display = "POW prepare error: {}", _0)]
	PrePowError(String),
	/// Verification error
	#[fail(display = "POW Verification Error: {}", _0)]
	Verification(String),
	/// Failure to cast from/to generic integer type
	#[fail(display = "POW IntegerCast")]
	IntegerCast,
	/// IO Error
	#[fail(display = "POW IO Error")]
	IOError,
	/// Unexpected Edge Error
	#[fail(display = "POW Edge Addition Error")]
	EdgeAddition,
	/// Path Error
	#[fail(display = "POW Path Error")]
	Path,
	/// Invalid cycle
	#[fail(display = "POW Invalid Cycle length: {}", _0)]
	InvalidCycle(usize),
	/// No Cycle
	#[fail(display = "POW No Cycle")]
	NoCycle,
	/// No Solution
	#[fail(display = "POW No Solution")]
	NoSolution,
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
		Display::fmt(&self.inner, f)
	}
}

impl Error {
	/// Return errorkind
	pub fn kind(&self) -> ErrorKind {
		self.inner.get_context().clone()
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
		Error { inner }
	}
}

impl From<fmt::Error> for Error {
	fn from(_error: fmt::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IntegerCast),
		}
	}
}

impl From<io::Error> for Error {
	fn from(_error: io::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::IOError),
		}
	}
}
