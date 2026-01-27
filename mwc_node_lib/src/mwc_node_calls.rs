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
use hyper::body::to_bytes;
use mwc_core::global;
use mwc_servers::{ServerConfig, ServerStats};
use mwc_util::logger::CallbackLoggingConfig;
use safer_ffi::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::ffi::CString;
use std::sync::Arc;

fn process_request(input: String) -> Result<Value, String> {
	let input_json: Value = serde_json::from_str(&input)
		.map_err(|e| format!("Unable to parse input as a json, {}", e))?;

	let method = match input_json.get("method") {
		Some(method) => method
			.as_str()
			.ok_or("Invalid 'method' value ")?
			.to_string(),
		None => return Err("Not found input 'method' attribute".into()),
	};

	let params = match input_json.get("params") {
		Some(params) => params.clone(),
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
			let _ = mwc_node_workflow::logging::init_bin_logs(&get_param(&params, "config")?)?;
			json!({})
		}
		"init_callback_logs" => {
			let log_callback_name: String = get_param(&params, "log_callback_name")?;

			let (cb, ctx) = LIB_CALLBACKS
				.read()
				.unwrap_or_else(|e| e.into_inner())
				.get(&log_callback_name)
				.cloned()
				.ok_or(format!(
					"Callback function {} is not registered",
					log_callback_name
				))?;

			let callback = move |le: mwc_util::logger::LogEntry| {
				let log_line = format!("{} {}", le.level, le.log);
				let c_log_line =
					CString::new(log_line).expect("Unable convert string into C format");
				let c_compatible_ref: *const libc::c_char = c_log_line.as_c_str().as_ptr();
				// Note, c_compatible_ref can't be stored at C code
				cb(ctx as *mut std::ffi::c_void, c_compatible_ref);
			};

			let config = CallbackLoggingConfig {
				log_level: get_param(&params, "log_level")?,
				log_buffer_size: get_option_param(&params, "log_buffer_size")?.unwrap_or(1000),
				callback: Arc::new(Some(Box::new(callback))),
			};
			mwc_node_workflow::logging::init_buffered_logs(config)?;
			json!({})
		}
		"release_callback_logs" => {
			let config = CallbackLoggingConfig {
				log_level: log::Level::Error,
				log_buffer_size: 1,
				callback: Arc::new(None),
			};
			mwc_node_workflow::logging::init_buffered_logs(config)?;
			json!({})
		}
		"get_buffered_logs" => {
			let result = mwc_node_workflow::logging::get_buffered_logs(
				get_option_param(&params, "last_known_id")?,
				get_param(&params, "result_size_limit")?,
			)?;
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
		"shoutdown_tor" => {
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
		"create_server" => {
			// For this case we have to build the config by ourselves
			let context_id: u32 = get_param(&params, "context_id")?;
			let db_root: String = get_param(&params, "db_root")?;
			let onion_expanded_key: Option<String> =
				get_option_param(&params, "onion_expanded_key")?;

			let mut config = ServerConfig::default();
			config.db_root = db_root;
			config.chain_type = global::get_chain_type(context_id);
			config.p2p_config.onion_expanded_key = onion_expanded_key;

			let hook_callback_name: Option<String> =
				get_option_param(&params, "hook_callback_name")?;
			if let Some(hook_callback_name) = hook_callback_name {
				// Adding the callback
				let (cb, ctx) = LIB_CALLBACKS
					.read()
					.unwrap_or_else(|e| e.into_inner())
					.get(&hook_callback_name)
					.cloned()
					.ok_or(format!(
						"Callback function {} is not registered",
						hook_callback_name
					))?;

				// events: header_received, block_received, transaction_received, block_accepted
				let callback = move |event: &str, value: &Value| {
					let payload = json!({
						"context_id": context_id,
						"event": event,
						"data": value,
					});

					let payload = serde_json::to_string(&payload).expect("Json encoding failure");

					let c_payload =
						CString::new(payload).expect("Unable convert string into C format");
					let c_compatible_ref: *const libc::c_char = c_payload.as_c_str().as_ptr();
					// Note, c_compatible_ref can't be stored at C code
					cb(ctx as *mut std::ffi::c_void, c_compatible_ref);
				};
				config.webhook_config.callback = Arc::new(Some(Box::new(callback)));
			}

			mwc_node_workflow::server::create_server(context_id, config)
				.map_err(|e| format!("Unable to start the node server, {}", e))?;
			json!({})
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
				Ok(response) => {
					let body = response.into_body();
					let body = futures::executor::block_on(to_bytes(body))
						.map(|b| b.to_vec())
						.map_err(|e| format!("Broken body data, {}", e))?;
					let body =
						String::from_utf8(body).map_err(|e| format!("Broken body data, {}", e))?;

					json!({
						"response" : body,
					})
				}
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
			// No waiting, it is Lib call, we want it start in the background.
			// With waiting 'true' be aware that listen will wait for Tor to start first, so tor can't be shut down.
			mwc_node_workflow::server::start_listen_peers(get_param(&params, "context_id")?, false)
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

fn get_param<T: DeserializeOwned>(params: &serde_json::Value, key: &str) -> Result<T, String> {
	let value = params
		.get(key)
		.cloned()
		.ok_or_else(|| format!("Not found expected parameter {}", key))?;

	serde_json::from_value::<T>(value)
		.map_err(|e| format!("Unable to parse expected parameter {}, {}", key, e))
}

fn get_option_param<T: DeserializeOwned>(
	params: &serde_json::Value,
	key: &str,
) -> Result<Option<T>, String> {
	match params.get(key) {
		Some(value) => {
			let res = serde_json::from_value::<T>(value.clone())
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
