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
use lazy_static::lazy_static;
use safer_ffi::prelude::*;
use std::collections::HashMap;
use std::sync::RwLock;

pub type CallbackFn = extern "C" fn(ctx: *mut std::ffi::c_void, message: *const libc::c_char);

lazy_static! {
	pub(crate) static ref NODE_LIB_CALLBACKS: RwLock<HashMap<String, (CallbackFn, usize)>> =
		RwLock::new(HashMap::new());
}

/// Register a callback and context pointer from C
/// Note, Callback will get temprary string pointer, C code can't store it.
#[ffi_export]
pub fn register_callback(
	callback_name: char_p::Ref<'static>,
	cb: CallbackFn,
	ctx: *mut std::ffi::c_void,
) {
	let mut callbacks = NODE_LIB_CALLBACKS.write().expect("RwLock failure");
	let callback_name = callback_name.to_str();
	callbacks.insert(callback_name.to_string(), (cb, ctx as usize));
}

/// Unregister the callback
#[ffi_export]
pub fn unregister_callback(callback_name: char_p::Ref<'static>) {
	let mut callbacks = NODE_LIB_CALLBACKS.write().expect("RwLock failure");
	let callback_name = callback_name.to_str();
	callbacks.remove(&callback_name.to_string());
}

/// Process mwc-node related call.
/// Input: json stirng param
/// return: json string as a result
#[ffi_export]
fn process_mwc_node_request(input: char_p::Ref<'_>) -> char_p::Box {
	let input = input.to_str();

	let resposne: String = call_mwc_node_request(input.to_string());
	resposne.try_into().expect("Safer FFI failure")
}

/// Free process_mwc_node_request response string
#[ffi_export]
fn free_node_lib_string(s: char_p::Box) {
	drop(s)
}
