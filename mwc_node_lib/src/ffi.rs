// Copyright 2025 The MWC Developers
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

use crate::mwc_node_calls::call_mwc_node_request;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::libc;
use mwc_crates::log::{error, info};
use mwc_crates::parking_lot::RwLock;
use safer_ffi::prelude::*;
use std::collections::HashMap;

/// Callback receives a temporary message pointer.
///
/// Notification callbacks may return null. Response-style callbacks, such as
/// wallet node-client callbacks, return a pointer to a valid C string that
/// remains valid until Rust copies it after the callback returns.
pub type CallbackFn =
	extern "C" fn(ctx: *mut std::ffi::c_void, message: *const libc::c_char) -> *const libc::c_char;

lazy_static! {
	// FFI safety note:
	// The caller-owned context pointer is stored as usize, then cast back to
	// *mut c_void during callback dispatch. This intentionally treats the value
	// as an opaque address, but it also strips pointer typing/provenance and
	// bypasses Rust's raw-pointer Send/Sync checks for this global registry.
	// Integration callers must account for that boundary: the context must stay
	// valid until unregister returns and must be safe to use from any logging or
	// webhook thread that can invoke the registered callback.
	pub static ref LIB_CALLBACKS: RwLock<HashMap<String, (CallbackFn, usize)>> =
		RwLock::new(HashMap::new());
}

/// Register a callback and context pointer from C.
///
/// The context pointer is owned by the caller. Rust stores it only as an opaque
/// pointer and never owns, frees, or otherwise manages the pointed-to data. The
/// caller must keep it valid until `unregister_lib_callback` returns after being
/// called with the exact registered callback name.
///
/// Callback implementations must not synchronously call `register_lib_callback`
/// or `unregister_lib_callback`; dispatch holds the callback registry read lock
/// until the callback returns so unregister can wait for in-flight users of
/// `ctx`.
///
/// Note, Callback will get temporary string pointer, C code cannot store it.
/// Notification callbacks may return null. Wallet node-client callbacks must
/// synchronously return a valid JSON response C string; Rust copies it before
/// the callback frame is released.
#[ffi_export]
pub fn register_lib_callback(
	callback_name: char_p::Ref<'static>,
	cb: Option<CallbackFn>,
	ctx: *mut std::ffi::c_void,
) {
	let Some(cb) = cb else {
		return;
	};

	// Keep the registration API void-compatible: callers cannot receive invalid-name
	// or duplicate-name errors without a signature change. Logging is not reliable
	// at this stage either, since this registration may be setting up the
	// logging callback.
	let Some(callback_name) = std::str::from_utf8(callback_name.to_bytes()).ok() else {
		return;
	};

	{
		let mut callbacks = LIB_CALLBACKS.write();
		if callbacks.contains_key(callback_name) {
			return;
		}
		callbacks.insert(callback_name.to_string(), (cb, ctx as usize));
	}
	info!("Register callback {}", callback_name);
}

/// Unregister the callback.
///
/// After this returns for a registered callback name, no future callback
/// dispatch by this name will use the registered function/context pair. If a
/// dispatch is already in progress, this call waits for it to finish before
/// returning. The caller may free or reuse the caller-owned context only after
/// calling this function with the exact registered callback name and waiting for
/// it to return. Invalid UTF-8 or unregistered callback names remove nothing and
/// are logged as errors.
#[ffi_export]
pub fn unregister_lib_callback(callback_name: char_p::Ref<'static>) {
	let callback_name = match std::str::from_utf8(callback_name.to_bytes()) {
		Ok(callback_name) => callback_name,
		Err(e) => {
			error!(
				"Unable to unregister callback: callback name is not valid UTF-8: {}",
				e
			);
			return;
		}
	};

	let removed = {
		let mut callbacks = LIB_CALLBACKS.write();
		callbacks.remove(callback_name)
	};
	if removed.is_some() {
		info!("Removed the callback {}", callback_name);
	} else {
		error!(
			"Unable to unregister callback {}: callback is not registered",
			callback_name
		);
	}
}

/// Process mwc-node related call.
/// Input: json stirng param
/// return: json string as a result. Call process_mwc_node_request to release the memory
#[ffi_export]
fn process_mwc_node_request(input: char_p::Ref<'_>) -> char_p::Box {
	let resposne = match std::str::from_utf8(input.to_bytes()) {
		Ok(input) => call_mwc_node_request(input.to_string()),
		Err(e) => mwc_crates::serde_json::json!({
			"success": false,
			"error": format!("Invalid UTF-8 input: {}", e),
		})
		.to_string(),
	};
	// ffi failure must be fatal, somrthing really wrong, crash is the only option
	resposne.try_into().expect("Safer FFI failure")
}

/// Free process_mwc_node_request response string
#[ffi_export]
fn free_lib_string(s: char_p::Box) {
	drop(s)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::ffi::CStr;
	use std::ptr::NonNull;

	extern "C" fn test_callback(
		_ctx: *mut std::ffi::c_void,
		_message: *const libc::c_char,
	) -> *const libc::c_char {
		std::ptr::null()
	}

	fn callback_name(name: &'static [u8]) -> char_p::Ref<'static> {
		char_p::Ref::from(CStr::from_bytes_with_nul(name).unwrap())
	}

	#[test]
	fn unregister_removes_registered_callback() {
		let callback_name = callback_name(b"ffi_unregister_remove_test\0");
		LIB_CALLBACKS.write().remove("ffi_unregister_remove_test");

		register_lib_callback(callback_name, Some(test_callback), std::ptr::null_mut());
		assert!(LIB_CALLBACKS
			.read()
			.contains_key("ffi_unregister_remove_test"));

		unregister_lib_callback(callback_name);
		assert!(!LIB_CALLBACKS
			.read()
			.contains_key("ffi_unregister_remove_test"));
	}

	#[test]
	fn unregister_missing_name_does_not_remove_other_callback() {
		let registered_name = callback_name(b"ffi_unregister_registered_test\0");
		let missing_name = callback_name(b"ffi_unregister_missing_test\0");
		{
			let mut callbacks = LIB_CALLBACKS.write();
			callbacks.remove("ffi_unregister_registered_test");
			callbacks.remove("ffi_unregister_missing_test");
		}

		register_lib_callback(registered_name, Some(test_callback), std::ptr::null_mut());

		unregister_lib_callback(missing_name);
		assert!(LIB_CALLBACKS
			.read()
			.contains_key("ffi_unregister_registered_test"));

		unregister_lib_callback(registered_name);
	}

	#[test]
	fn unregister_invalid_utf8_name_does_not_remove_other_callback() {
		let registered_name = callback_name(b"ffi_unregister_invalid_utf8_survivor\0");
		LIB_CALLBACKS
			.write()
			.remove("ffi_unregister_invalid_utf8_survivor");
		register_lib_callback(registered_name, Some(test_callback), std::ptr::null_mut());

		let invalid_name = Box::leak(Box::new([0xff_u8, 0]));
		let invalid_name = unsafe {
			char_p::Ref::from_ptr_unchecked(NonNull::new(invalid_name.as_mut_ptr()).unwrap())
		};

		unregister_lib_callback(invalid_name);
		assert!(LIB_CALLBACKS
			.read()
			.contains_key("ffi_unregister_invalid_utf8_survivor"));

		unregister_lib_callback(registered_name);
	}
}
