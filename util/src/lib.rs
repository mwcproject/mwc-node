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

//! Logging, as well as various low-level utilities that factor Rust
//! patterns that are frequent within the mwc codebase.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

mod ov3;
use mwc_crates::base64;
use mwc_crates::base64::Engine;
pub use ov3::OnionV3Address;
pub use ov3::OnionV3Error;

/// Utility error type.
#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum Error {
	/// A one-time value was initialized more than once.
	#[error("OneTime::set, value is already initialized")]
	OneTimeAlreadyInitialized,
	/// A one-time value was borrowed before initialization.
	#[error("OneTime::borrow, value is not initialized")]
	OneTimeNotInitialized,
	/// Async runtime setup or execution failed.
	#[error("Async runtime error, {0}")]
	AsyncRuntime(String),
	/// Logging setup or access failed.
	#[error("Logging error, {0}")]
	Logging(String),
	/// Hex decoding failed.
	#[error("Hex error, {0}")]
	Hex(String),
	/// Data overflow occurred.
	#[error("Data overflow error, {0}")]
	DataOverflow(String),
	/// Invalid fixed-length input.
	#[error("Invalid length, actual={actual} expected={expected}")]
	InvalidLength {
		/// Actual input length.
		actual: usize,
		/// Expected input length.
		expected: usize,
	},
}

// Re-export so only has to be included once
// Logging related
pub mod logger;
pub use crate::logger::{init_logger, init_test_logger};

// Static secp instance
pub mod secp_static;

pub mod types;
pub use crate::types::ZeroingString;

pub mod macros;

// other utils
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
mod hex;
pub use crate::hex::*;

/// File util
pub mod file;

mod async_runtime;
mod rate_counter;

pub use crate::rate_counter::RateCounter;

pub use crate::async_runtime::global_runtime;
pub use crate::async_runtime::init_global_runtime;
pub use crate::async_runtime::run_global_async_block;

pub use crate::logger::is_console_output_enabled;

pub use mwc_crates::parking_lot::{Mutex, RwLock};

/// Encapsulation of a RwLock<Option<T>> for one-time initialization.
/// Misuse is reported as an error if borrowed before initialization or
/// initialized more than once without override.
#[derive(Clone)]
pub struct OneTime<T> {
	/// The inner value.
	inner: Arc<RwLock<Option<T>>>,
}

impl<T> OneTime<T>
where
	T: Clone,
{
	/// Builds a new uninitialized OneTime.
	pub fn new() -> OneTime<T> {
		OneTime {
			inner: Arc::new(RwLock::new(None)),
		}
	}

	/// Initializes the OneTime, should only be called once after construction.
	pub fn init(&self, value: T) -> Result<(), Error> {
		self.set(value, false)
	}

	/// Allows the one time to be set again with an override.
	pub fn set(&self, value: T, is_override: bool) -> Result<(), Error> {
		let mut inner = self.inner.write();
		if !is_override && inner.is_some() {
			return Err(Error::OneTimeAlreadyInitialized);
		}
		*inner = Some(value);
		Ok(())
	}

	/// Borrows the OneTime, returning an error if it has not been initialized.
	pub fn borrow(&self) -> Result<T, Error> {
		let inner = self.inner.read_recursive();
		inner.clone().ok_or(Error::OneTimeNotInitialized)
	}

	/// Has this OneTime been initialized?
	pub fn is_init(&self) -> bool {
		self.inner.read_recursive().is_some()
	}
}

/// Encode an utf8 string to a base64 string
pub fn to_base64(s: &str) -> String {
	base64::engine::general_purpose::STANDARD.encode(s)
}

/// Escape a UTF-8 string to printable ASCII, except for newlines and QR code blocks.
pub fn escape_to_printable_ascii(input: &str) -> String {
	let mut escaped = String::with_capacity(input.len());
	for c in input.chars() {
		match c {
			// Slatepack QR codes need these blocks and line breaks to stay scannable.
			// Escaping them would print literal escape sequences instead of the QR code.
			'\n' | '█' | '▀' | '▄' => escaped.push(c),
			_ => escaped.extend(c.escape_default()),
		}
	}
	escaped
}

/// Global stopped/paused state shared across various subcomponents of Mwc.
///
/// "Stopped" allows a clean shutdown of the Mwc server.
/// "Paused" is used in some tests to allow nodes to reach steady state etc.
///
pub struct StopState {
	stopped: AtomicBool,
	paused: AtomicBool,
}

impl StopState {
	/// Create a new stop_state in default "running" state.
	pub fn new() -> StopState {
		StopState {
			stopped: AtomicBool::new(false),
			paused: AtomicBool::new(false),
		}
	}

	/// Check if we are stopped.
	pub fn is_stopped(&self) -> bool {
		self.stopped.load(Ordering::Relaxed)
	}

	/// Check if we are paused.
	pub fn is_paused(&self) -> bool {
		self.paused.load(Ordering::Relaxed)
	}

	/// Stop the server.
	pub fn stop(&self) {
		self.stopped.store(true, Ordering::Relaxed)
	}

	/// Pause the server (only used in tests).
	pub fn pause(&self) {
		self.paused.store(true, Ordering::Relaxed)
	}

	/// Resume a paused server (only used in tests).
	pub fn resume(&self) {
		self.paused.store(false, Ordering::Relaxed)
	}
}

#[cfg(test)]
mod tests {
	use super::escape_to_printable_ascii;
	use mwc_crates::qr_code::QrCode;

	#[test]
	fn escape_to_printable_ascii_escapes_other_controls_and_unicode() {
		let escaped = escape_to_printable_ascii("ok\nbad\0\t\r\u{1b}[2J\u{7f}\u{85}\u{e9}\u{202e}");

		assert_eq!(
			escaped,
			"ok\nbad\\u{0}\\t\\r\\u{1b}[2J\\u{7f}\\u{85}\\u{e9}\\u{202e}"
		);
		assert!(escaped
			.bytes()
			.all(|b| b == b'\n' || (0x20..=0x7e).contains(&b)));
	}

	#[test]
	fn escape_to_printable_ascii_preserves_slatepack_qr_code() {
		let address = "25hmwrbw77nwfw7nvjg2l577wondhh6fyyuhxvivldi5y2dpxrhwyrid";
		let qr = QrCode::new(address).unwrap().to_string(false, 3);
		let message = format!("Slatepack Address is: {}\n{}", address, qr);

		assert_eq!(escape_to_printable_ascii(&message), message);
		assert_eq!(
			escape_to_printable_ascii(&format!("{}\u{1b}[2J\r", message)),
			format!("{}\\u{{1b}}[2J\\r", message)
		);
	}
}
