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

// Server management routine

use crate::Error;
use mwc_api::Router;
use mwc_crates::bytes::Bytes;
use mwc_crates::futures;
use mwc_crates::http;
use mwc_crates::http_body_util::Full;
use mwc_crates::hyper::service::Service;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::log::error;
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_p2p::tor::arti;
use mwc_p2p::TorConfig;
use mwc_servers::{Server, ServerConfig, ServerStats};
use mwc_util::StopState;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

lazy_static! {
		/// Global chain status flags. It is expected that init call will set them first for every needed context
		/// Note, both node and wallet will need to set it up. Any param can be set once
	static ref SERVER_CONTEXT: RwLock< HashMap<u32, mwc_servers::Server>> = RwLock::new(HashMap::new());

	static ref SERVER_STARTUP_STOP_STATE: RwLock<HashMap<u32, Arc<StopState>>> =
		RwLock::new(HashMap::new());

	static ref CALL_ROUTER_CONTEXT: RwLock< HashMap<u32, Arc<Router>>> = RwLock::new(HashMap::new());
}

/// Stop the server jobs and release the server.
///
/// This is a best-effort, idempotent cleanup operation. If the server for this
/// context was already released or was never created, the call still succeeds
/// after clearing any remaining per-context router/chain data.
pub fn release_server(context_id: u32) {
	let startup_stop_state = SERVER_STARTUP_STOP_STATE
		.read_recursive()
		.get(&context_id)
		.cloned();
	if let Some(stop_state) = &startup_stop_state {
		stop_state.stop();
	}

	let server = {
		let mut servers = SERVER_CONTEXT.write();
		servers.remove(&context_id)
	};
	CALL_ROUTER_CONTEXT.write().remove(&context_id);
	if let Some(server) = server {
		server.stop();
		mwc_chain::pipe::release_context_data(context_id);
	} else if startup_stop_state.is_none() {
		mwc_chain::pipe::release_context_data(context_id);
	}
}

/// Tor client needs to be started once, no context_id is requred
pub fn start_tor(config: &TorConfig, base_dir: &str) -> Result<(), Error> {
	arti::start_arti(
		config,
		PathBuf::from(base_dir).as_path(),
		mwc_util::is_console_output_enabled(),
		false,
	)
	.map_err(|e| Error::TorError(format!("Arti start error, {}", e)))?;
	Ok(())
}

/// Get ro status: <started, healthy>
pub fn tor_status() -> (bool, bool) {
	(arti::is_arti_started(), arti::is_arti_healthy())
}

/// Create a new server instance. No jobs will be started.
///
/// The provided stop state is registered before chain initialization begins,
/// allowing callers to cancel txhashset startup indexing before the server is
/// fully constructed.
pub fn create_server(
	context_id: u32,
	config: ServerConfig,
	stop_state: Arc<StopState>,
) -> Result<(), Error> {
	{
		let mut startup_states = SERVER_STARTUP_STOP_STATE.write();
		if startup_states.contains_key(&context_id) {
			return Err(Error::ContextError(
				"Node server is already starting for this context".into(),
			));
		}
		startup_states.insert(context_id, stop_state.clone());
	}

	if SERVER_CONTEXT.read_recursive().contains_key(&context_id) {
		SERVER_STARTUP_STOP_STATE.write().remove(&context_id);
		return Err(Error::ContextError(
			"Node server already created for this context".into(),
		));
	}

	let secp = match Secp256k1::with_caps(ContextFlag::Commit) {
		Ok(secp) => secp,
		Err(e) => {
			SERVER_STARTUP_STOP_STATE.write().remove(&context_id);
			return Err(Error::ServerError(format!(
				"Secp instance creation error, {}",
				e
			)));
		}
	};

	let serv = match Server::create_server(&secp, context_id, config, stop_state.clone()) {
		Ok(serv) => serv,
		Err(e) => {
			SERVER_STARTUP_STOP_STATE.write().remove(&context_id);
			mwc_chain::pipe::release_context_data(context_id);
			return Err(Error::ServerError(format!(
				"Unable to create server, {}",
				e
			)));
		}
	};

	if stop_state.is_stopped() {
		SERVER_STARTUP_STOP_STATE.write().remove(&context_id);
		serv.stop();
		mwc_chain::pipe::release_context_data(context_id);
		return Err(Error::ServerError(
			"Server start was cancelled during blockchain indexing".into(),
		));
	}

	let mut serv = Some(serv);
	let inserted = {
		let mut servers = SERVER_CONTEXT.write();
		if servers.contains_key(&context_id) {
			false
		} else {
			servers.insert(context_id, serv.take().expect("server is present"));
			true
		}
	};

	if !inserted {
		SERVER_STARTUP_STOP_STATE.write().remove(&context_id);
		if let Some(serv) = serv {
			serv.stop();
		}
		return Err(Error::ContextError(
			"Node server already created for this context".into(),
		));
	}

	SERVER_STARTUP_STOP_STATE.write().remove(&context_id);
	if stop_state.is_stopped() {
		release_server(context_id);
		return Err(Error::ServerError(
			"Server start was cancelled during blockchain indexing".into(),
		));
	}

	Ok(())
}

/// Start Stratum protocol, needed for the mining
pub fn start_stratum(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_stratum()
			.map_err(|e| Error::ServerError(format!("Unable to start stratum, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}

	Ok(())
}

/// Start pees discovery p2p peers job
pub fn start_discover_peers(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_discover_peers()
			.map_err(|e| Error::ServerError(format!("Unable to start discover peers, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Start node syncing job
pub fn start_sync_monitoring(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_sync_monitoring()
			.map_err(|e| Error::ServerError(format!("Unable to start sync thread, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Start p2p listening job. Needed for inbound peers connection
pub fn start_listen_peers(context_id: u32) -> Result<(), Error> {
	let pending_listener = {
		let mut servers = SERVER_CONTEXT.write();
		match servers.get_mut(&context_id) {
			Some(serv) => serv.begin_start_listen_peers().map_err(|e| {
				Error::ServerError(format!("Unable to start listening for peers, {}", e))
			})?,
			None => {
				return Err(Error::ServerError(format!(
					"Server not exist for context {}",
					context_id
				)));
			}
		}
	};

	let startup_result = pending_listener.wait_for_startup();

	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => match startup_result {
			Ok(started_listener) => {
				serv.finish_start_listen_peers(started_listener)
					.map_err(|e| {
						Error::ServerError(format!("Unable to start listening for peers, {}", e))
					})?
			}
			Err(e) => {
				serv.finish_failed_listen_peers_startup();
				return Err(Error::ServerError(format!(
					"Unable to start listening for peers, {}",
					e
				)));
			}
		},
		None => {
			drop(servers);
			if let Ok(started_listener) = startup_result {
				started_listener.wait_for_shutdown();
			}
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Starting node rest API, needed for communication with mwc-wallet
pub fn start_rest_api(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_rest_api()
			.map_err(|e| Error::ServerError(format!("Unable to start node rest api, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Init router for lib based API
pub fn init_call_api(context_id: u32) -> Result<(), Error> {
	let servers = SERVER_CONTEXT.read_recursive();
	let router = match servers.get(&context_id) {
		Some(serv) => serv
			.build_api_router_no_secrets()
			.map_err(|e| Error::ServerError(format!("Unable to build node call api, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	};
	CALL_ROUTER_CONTEXT
		.write()
		.insert(context_id, Arc::new(router));
	Ok(())
}

/// Process rest API related call
pub fn process_call(
	context_id: u32,
	method: String,
	uri: String,
	body: String,
) -> Result<http::Response<Full<Bytes>>, Error> {
	let router = {
		let routers = CALL_ROUTER_CONTEXT.read_recursive();
		routers.get(&context_id).cloned()
	};

	match router {
		Some(router) => {
			let method = http::Method::from_bytes(method.as_bytes()).map_err(|e| {
				Error::ServerError(format!("HTTP request get invalid method {}, {}", method, e))
			})?;
			let uri = uri.parse::<http::Uri>().map_err(|e| {
				Error::ServerError(format!("HTTP request get invalid Uri {}, {}", uri, e))
			})?;

			let request = http::Request::builder()
				.method(method)
				.uri(uri)
				.version(http::Version::HTTP_10)
				.body(Bytes::from(body))
				.map_err(|e| Error::ServerError(format!("Unable to build a request, {}", e)))?;

			let res = router.call(request);
			let response = futures::executor::block_on(res);
			let response = match response {
				Ok(response) => response,
				Err(e) => {
					error!("Unable to process API request, {}", e);
					return Err(Error::ServerError(format!(
						"Unable to process API request, {}",
						e
					)));
				}
			};
			Ok(response)
		}
		None => Err(Error::ServerError(format!(
			"Call API not exist for context {}",
			context_id
		))),
	}
}

/// Start dandelion protocol. Needed for publishing transactions
pub fn start_dandelion(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_dandelion()
			.map_err(|e| Error::ServerError(format!("Unable to start dandelion, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Get server stats data, used by node UI.
pub fn get_server_stats(context_id: u32) -> Result<ServerStats, Error> {
	match SERVER_CONTEXT.try_read_recursive() {
		Some(servers) => match servers.get(&context_id) {
			Some(serv) => Ok(serv.get_server_stats().map_err(|e| {
				Error::ServerError(format!("Unable to get server stat data, {}", e))
			})?),
			None => Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			))),
		},
		None => Err(Error::ServerError("Server is busy".into())),
	}
}
