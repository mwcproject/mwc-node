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
use hyper::http;
use hyper::service::Service;
use lazy_static::lazy_static;
use mwc_api::Router;
use mwc_p2p::tor::arti;
use mwc_p2p::TorConfig;
use mwc_servers::{Server, ServerConfig, ServerStats};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

lazy_static! {
		/// Global chain status flags. It is expected that init call will set them first for every needed context
		/// Note, both node and wallet will need to set it up. Any param can be set once
	static ref SERVER_CONTEXT: RwLock< HashMap<u32, mwc_servers::Server>> = RwLock::new(HashMap::new());

	static ref CALL_ROUTER_CONTEXT: RwLock< HashMap<u32, Router>> = RwLock::new(HashMap::new());
}

/// Stot the server jobs and release the server
pub fn release_server(context_id: u32) {
	if let Some(server) = SERVER_CONTEXT
		.write()
		.unwrap_or_else(|e| e.into_inner())
		.remove(&context_id)
	{
		server.stop();
	}

	CALL_ROUTER_CONTEXT
		.write()
		.unwrap_or_else(|e| e.into_inner())
		.remove(&context_id);
}

/// Tor client needs to be started once, no context_id is requred
pub fn start_tor(config: &TorConfig, base_dir: &str) -> Result<(), Error> {
	arti::start_arti(
		config,
		PathBuf::from(base_dir).as_path(),
		mwc_util::is_console_output_enabled(),
	)
	.map_err(|e| Error::TorError(format!("Arti start error, {}", e)))?;
	Ok(())
}

/// Get ro status: <started, healthy>
pub fn tor_status() -> (bool, bool) {
	(arti::is_arti_started(), arti::is_arti_healthy())
}

/// Create a new server instance. No jobs will be started
pub fn create_server(context_id: u32, config: ServerConfig) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().unwrap_or_else(|e| e.into_inner());
	if servers.contains_key(&context_id) {
		return Err(Error::ContextError(
			"Node server already created for this context".into(),
		));
	}

	let serv = Server::create_server(context_id, config)
		.map_err(|e| Error::ServerError(format!("Unable to create server, {}", e)))?;

	servers.insert(context_id, serv);
	Ok(())
}

/// Start Stratum protocol, needed for the mining
pub fn start_stratum(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().unwrap_or_else(|e| e.into_inner());
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_stratum()
			.map_err(|e| Error::ServerError(format!("Unable to start stratum, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)))
		}
	}

	Ok(())
}

/// Start pees discovery p2p peers job
pub fn start_discover_peers(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().unwrap_or_else(|e| e.into_inner());
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_discover_peers()
			.map_err(|e| Error::ServerError(format!("Unable to start discover peers, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)))
		}
	}
	Ok(())
}

/// Start node syncing job
pub fn start_sync_monitoring(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().unwrap_or_else(|e| e.into_inner());
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_sync_monitoring()
			.map_err(|e| Error::ServerError(format!("Unable to start sync thread, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)))
		}
	}
	Ok(())
}

/// Start p2p listening job. Needed for inbound peers connection
pub fn start_listen_peers(context_id: u32, wait_for_starting: bool) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().unwrap_or_else(|e| e.into_inner());
	match servers.get_mut(&context_id) {
		Some(serv) => serv.start_listen_peers(wait_for_starting).map_err(|e| {
			Error::ServerError(format!("Unable to start listening for peers, {}", e))
		})?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)))
		}
	}
	Ok(())
}

/// Starting node rest API, needed for communication with mwc-wallet
pub fn start_rest_api(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().unwrap_or_else(|e| e.into_inner());
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_rest_api()
			.map_err(|e| Error::ServerError(format!("Unable to start node rest api, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)))
		}
	}
	Ok(())
}

/// Init router for lib based API
pub fn init_call_api(context_id: u32) -> Result<(), Error> {
	let router = {
		let servers = SERVER_CONTEXT.read().unwrap_or_else(|e| e.into_inner());
		match servers.get(&context_id) {
			Some(serv) => {
				let router = serv.build_api_router_no_secrets().map_err(|e| {
					Error::ServerError(format!("Unable to build node call api, {}", e))
				})?;
				router
			}
			None => {
				return Err(Error::ServerError(format!(
					"Server not exist for context {}",
					context_id
				)))
			}
		}
	};
	CALL_ROUTER_CONTEXT
		.write()
		.unwrap_or_else(|e| e.into_inner())
		.insert(context_id, router);
	Ok(())
}

/// Process rest API related call
pub fn process_call(
	context_id: u32,
	method: String,
	uri: String,
	body: String,
) -> Result<http::Response<hyper::Body>, Error> {
	match CALL_ROUTER_CONTEXT
		.write()
		.unwrap_or_else(|e| e.into_inner())
		.get_mut(&context_id)
	{
		Some(router) => {
			let method = http::Method::from_bytes(method.as_bytes()).map_err(|e| {
				Error::ServerError(format!("HTTP request get invalid method {}, {}", method, e))
			})?;
			let uri = uri.parse::<http::Uri>().map_err(|e| {
				Error::ServerError(format!("HTTP request get invalid Uri {}, {}", uri, e))
			})?;

			let builder = http::Request::builder()
				.method(method)
				.uri(uri)
				.version(http::Version::HTTP_10);

			// All headers are skipped, router should handle that
			let body = hyper::Body::from(body);

			let request = builder
				.body(body)
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
	let mut servers = SERVER_CONTEXT.write().unwrap_or_else(|e| e.into_inner());
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_dandelion()
			.map_err(|e| Error::ServerError(format!("Unable to start dandelion, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)))
		}
	}
	Ok(())
}

/// Get server stats data, used by node UI.
pub fn get_server_stats(context_id: u32) -> Result<ServerStats, Error> {
	let servers = SERVER_CONTEXT.read().unwrap_or_else(|e| e.into_inner());
	match servers.get(&context_id) {
		Some(serv) => Ok(serv
			.get_server_stats()
			.map_err(|e| Error::ServerError(format!("Unable to get server stat data, {}", e)))?),
		None => Err(Error::ServerError(format!(
			"Server not exist for context {}",
			context_id
		))),
	}
}
