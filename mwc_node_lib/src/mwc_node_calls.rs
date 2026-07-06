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

use crate::ffi::LIB_CALLBACKS;
use mwc_crates::bytes::Bytes;
use mwc_crates::futures;
use mwc_crates::http::Response;
use mwc_crates::http_body_util::{BodyExt, Full};
use mwc_crates::libc;
use mwc_crates::log::Level;
use mwc_crates::serde::de::DeserializeOwned;
use mwc_crates::serde_json;
use mwc_crates::serde_json::{json, Value};
use mwc_crates::zeroize::Zeroizing;
use mwc_servers::{ServerConfig, ServerStats};
use mwc_util::logger::CallbackLoggingConfig;
use safer_ffi::prelude::*;
use std::ffi::CString;
use std::sync::Arc;

fn ensure_lib_callback_registered(callback_name: &str) -> Result<(), String> {
	if LIB_CALLBACKS.read_recursive().contains_key(callback_name) {
		Ok(())
	} else {
		Err(format!(
			"Callback function {} is not registered",
			callback_name
		))
	}
}

fn call_lib_callback(callback_name: &str, message: *const libc::c_char) {
	let callbacks = LIB_CALLBACKS.read_recursive();
	if let Some((cb, ctx)) = callbacks.get(callback_name) {
		// Keep the registry read lock until the C callback returns. This makes
		// unregister_lib_callback wait before the caller-owned context can be
		// freed or reused by the host application.
		cb(*ctx as *mut std::ffi::c_void, message);
	}
}

fn process_request(input: String) -> Result<Value, String> {
	let input = Zeroizing::new(input);
	let mut input_json: Value = serde_json::from_str(input.as_str())
		.map_err(|e| format!("Unable to parse input as a json, {}", e))?;

	let method = match input_json.get("method") {
		Some(method) => method
			.as_str()
			.ok_or("Invalid 'method' value ")?
			.to_string(),
		None => return Err("Not found input 'method' attribute".into()),
	};

	if method == "create_server" {
		let params = input_json
			.get_mut("params")
			.ok_or_else(|| "Not found input 'params' attribute".to_string())?;
		return process_create_server_request(params);
	}

	let params = match input_json.get("params") {
		Some(params) => params,
		None => return Err("Not found input 'params' attribute".into()),
	};

	let response = match method.as_str() {
		"create_context" => {
			let context_id = mwc_node_workflow::context::allocate_new_context(
				get_param(&params, "chain_type")?,
				get_option_param(&params, "accept_fee_base")?,
				get_option_param(&params, "nrd_feature_enabled")?,
			)
			.map_err(|e| format!("New context allocation error, {}", e))?;
			json!({
				"context_id": context_id,
			})
		}
		"release_context" => {
			mwc_node_workflow::context::release_context(get_param(&params, "context_id")?)
				.map_err(|e| format!("Release context error, {}", e))?;
			json!({})
		}
		"init_file_logs" => {
			let _ = mwc_node_workflow::logging::init_bin_logs(&get_param(&params, "config")?)
				.map_err(|e| e.to_string())?;
			json!({})
		}
		"init_callback_logs" => {
			let log_callback_name: String = get_param(&params, "log_callback_name")?;

			ensure_lib_callback_registered(&log_callback_name)?;

			let callback = move |le: mwc_util::logger::LogEntry| {
				let log_line = format!("{} {}", le.level, le.log).replace('\0', "\\0");
				let Ok(c_log_line) = CString::new(log_line) else {
					return;
				};
				let c_compatible_ref: *const libc::c_char = c_log_line.as_c_str().as_ptr();
				// Note, c_compatible_ref can't be stored at C code
				call_lib_callback(&log_callback_name, c_compatible_ref);
			};

			let config = CallbackLoggingConfig {
				log_level: get_param(&params, "log_level")?,
				log_buffer_size: get_option_param(&params, "log_buffer_size")?.unwrap_or(1000),
				callback: Arc::new(Some(Box::new(callback))),
			};
			mwc_node_workflow::logging::init_buffered_logs(config).map_err(|e| e.to_string())?;
			json!({})
		}
		"release_callback_logs" => {
			let config = CallbackLoggingConfig {
				log_level: Level::Error,
				log_buffer_size: 1,
				callback: Arc::new(None),
			};
			mwc_node_workflow::logging::init_buffered_logs(config).map_err(|e| e.to_string())?;
			json!({})
		}
		"get_buffered_logs" => {
			let result = mwc_node_workflow::logging::get_buffered_logs(
				get_option_param(&params, "last_known_id")?,
				get_param(&params, "result_size_limit")?,
			)
			.map_err(|e| e.to_string())?;
			json!({
				"log_entries": serde_json::to_value(&result).
					map_err(|e| format!("Json error: {}", e))?
			})
		}
		"start_tor" => {
			let base_dir: String = get_param(&params, "base_dir")?;
			mwc_node_workflow::server::start_tor(&get_param(&params, "config")?, &base_dir)
				.map_err(|e| format!("Unable connect to Tor, {}", e))?;
			json!({})
		}
		"shutdown_tor" => {
			mwc_p2p::tor::arti::shutdown_arti();
			json!({})
		}
		"tor_status" => {
			let (started, healthy) = mwc_node_workflow::server::tor_status();
			json!({
				"started": started,
				"healthy": healthy,
			})
		}
		"release_server" => {
			mwc_node_workflow::server::release_server(get_param(&params, "context_id")?);
			json!({})
		}
		"init_call_api" => {
			mwc_node_workflow::server::init_call_api(get_param(&params, "context_id")?)
				.map_err(|e| format!("init_call_api is failed, {}", e))?;
			json!({})
		}
		"process_api_call" => {
			match mwc_node_workflow::server::process_call(
				get_param(&params, "context_id")?,
				get_param(&params, "method")?,
				get_param(&params, "uri")?,
				get_param(&params, "body")?,
			) {
				Ok(response) => process_api_response(response)?,
				Err(e) => return Err(format!("process_call error: {}", e)),
			}
		}
		"start_stratum" => {
			mwc_node_workflow::server::start_stratum(get_param(&params, "context_id")?)
				.map_err(|e| format!("Unable to start the stratum server, {}", e))?;
			json!({})
		}
		"start_discover_peers" => {
			mwc_node_workflow::server::start_discover_peers(get_param(&params, "context_id")?)
				.map_err(|e| format!("Unable to start the peers discovery, {}", e))?;
			json!({})
		}
		"start_sync_monitoring" => {
			mwc_node_workflow::server::start_sync_monitoring(get_param(&params, "context_id")?)
				.map_err(|e| format!("Unable to start the sync monitoring, {}", e))?;
			json!({})
		}
		"start_listen_peers" => {
			// Listener startup is confirmed before returning so bind/Tor
			// startup failures are reported to the caller.
			mwc_node_workflow::server::start_listen_peers(get_param(&params, "context_id")?)
				.map_err(|e| format!("Unable to start the peers listening, {}", e))?;
			json!({})
		}
		"start_dandelion" => {
			mwc_node_workflow::server::start_dandelion(get_param(&params, "context_id")?)
				.map_err(|e| format!("Unable to start the dandelion service, {}", e))?;
			json!({})
		}
		"get_server_stats" => {
			let stats: ServerStats =
				mwc_node_workflow::server::get_server_stats(get_param(&params, "context_id")?)
					.map_err(|e| format!("Unable to get mwc node stats data, {}", e))?;
			serde_json::to_value(&stats).map_err(|e| format!("Json error: {}", e))?
		}
		_ => return Err(format!("Unknown method: {}", method)),
	};

	Ok(response)
}

fn process_api_response(response: Response<Full<Bytes>>) -> Result<Value, String> {
	let status = response.status();
	let body = response.into_body();
	let body = futures::executor::block_on(async { body.collect().await })
		.map(|b| b.to_bytes())
		.map_err(|e| format!("Broken body data, {}", e))?;
	let body = String::from_utf8(body.to_vec()).map_err(|e| format!("Broken body data, {}", e))?;

	if !status.is_success() {
		return Err(format!(
			"process_call returned HTTP status {}: {}",
			status, body
		));
	}

	Ok(json!({
		"response" : body,
	}))
}

fn process_create_server_request(params: &mut Value) -> Result<Value, String> {
	let params = params
		.as_object_mut()
		.ok_or_else(|| "Invalid 'params' value ".to_string())?;
	let onion_expanded_key = take_onion_expanded_key(params)?;

	// For this case we have to build the config by ourselves
	let context_id: u32 = get_object_param(params, "context_id")?;
	let db_root: String = get_object_param(params, "db_root")?;

	let mut config = ServerConfig::default();
	config.db_root = db_root;
	config.chain_type =
		mwc_node_workflow::context::get_chain_type(context_id).map_err(|e| e.to_string())?;

	let hook_callback_name: Option<String> = get_option_object_param(params, "hook_callback_name")?;
	if let Some(hook_callback_name) = hook_callback_name {
		// Adding the callback
		ensure_lib_callback_registered(&hook_callback_name)?;

		// events: header_received, block_received, transaction_received, block_accepted
		let callback = move |event: &str, value: &Value| {
			let payload = json!({
				"context_id": context_id,
				"event": event,
				"data": value,
			});

			// Payload to String is fatal error. Normally payload is well defined, it should never happen
			let payload = serde_json::to_string(&payload).expect("Json encoding failure");
			// Converting to C String failure is fatal. It is breaking contract between this library and parent app.
			let c_payload = CString::new(payload).expect("Unable convert string into C format");
			let c_compatible_ref: *const libc::c_char = c_payload.as_c_str().as_ptr();
			// Note, c_compatible_ref can't be stored at C code
			call_lib_callback(&hook_callback_name, c_compatible_ref);
		};
		config.webhook_config.callback = Arc::new(Some(Box::new(callback)));
	}

	if let Some(mut onion_expanded_key) = onion_expanded_key {
		// Move into P2PConfig only at the final boundary; P2PConfig zeroizes
		// the retained field on drop.
		config.p2p_config.onion_expanded_key = Some(std::mem::take(&mut *onion_expanded_key));
	}

	mwc_node_workflow::server::create_server(context_id, config)
		.map_err(|e| format!("Unable to start the node server, {}", e))?;
	Ok(json!({}))
}

fn take_onion_expanded_key(
	params: &mut serde_json::Map<String, Value>,
) -> Result<Option<Zeroizing<String>>, String> {
	match params.remove("onion_expanded_key") {
		Some(Value::String(onion_expanded_key)) => Ok(Some(Zeroizing::new(onion_expanded_key))),
		Some(_) => Err("Unable to parse parameter onion_expanded_key".into()),
		None => Ok(None),
	}
}

fn get_param<T: DeserializeOwned>(params: &serde_json::Value, key: &str) -> Result<T, String> {
	let value = params
		.get(key)
		.ok_or_else(|| format!("Not found expected parameter {}", key))?;

	T::deserialize(value).map_err(|e| format!("Unable to parse expected parameter {}, {}", key, e))
}

fn get_option_param<T: DeserializeOwned>(
	params: &serde_json::Value,
	key: &str,
) -> Result<Option<T>, String> {
	match params.get(key) {
		Some(value) => {
			let res = T::deserialize(value)
				.map_err(|e| format!("Unable to parse parameter {}, {}", key, e))?;
			Ok(Some(res))
		}
		None => Ok(None),
	}
}

fn get_object_param<T: DeserializeOwned>(
	params: &serde_json::Map<String, Value>,
	key: &str,
) -> Result<T, String> {
	let value = params
		.get(key)
		.ok_or_else(|| format!("Not found expected parameter {}", key))?;

	T::deserialize(value).map_err(|e| format!("Unable to parse expected parameter {}, {}", key, e))
}

fn get_option_object_param<T: DeserializeOwned>(
	params: &serde_json::Map<String, Value>,
	key: &str,
) -> Result<Option<T>, String> {
	match params.get(key) {
		Some(value) => {
			let res = T::deserialize(value)
				.map_err(|e| format!("Unable to parse parameter {}, {}", key, e))?;
			Ok(Some(res))
		}
		None => Ok(None),
	}
}

pub(crate) fn call_mwc_node_request(input: String) -> String {
	let json_res = match process_request(input) {
		Ok(res) => {
			json!({
				"success": true,
				"result": res,
			})
		}
		Err(err) => {
			json!({
				"success": false,
				"error": err,
			})
		}
	};

	serde_json::to_string(&json_res).expect("Json internal failure")
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::http::StatusCode;

	fn api_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
		Response::builder()
			.status(status)
			.body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
			.expect("test response should build")
	}

	#[test]
	fn process_api_response_keeps_success_body_shape() {
		let response = process_api_response(api_response(StatusCode::OK, "{\"ok\":true}"))
			.expect("HTTP success should remain successful");

		assert_eq!(response, json!({ "response": "{\"ok\":true}" }));
	}

	#[test]
	fn process_api_response_rejects_non_success_status() {
		let err = process_api_response(api_response(StatusCode::NOT_FOUND, "missing"))
			.expect_err("HTTP errors must not be reported as success");

		assert!(err.contains("HTTP status 404 Not Found"));
		assert!(err.contains("missing"));
	}
}
