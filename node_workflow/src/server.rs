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
use futures::channel::oneshot;
use lazy_static::lazy_static;
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
}

/// Stot the server jobs and release the server
pub fn release_server(context_id: u32) {
	if let Some(server) = SERVER_CONTEXT
		.write()
		.expect("RwLock failure")
		.remove(&context_id)
	{
		server.stop();
	}
}

/// Tor client needs to be started once, no context_id is requred
pub fn start_tor(config: &TorConfig, base_dir: &str) -> Result<(), Error> {
	println!("Starting Arti client, please wait...");
	arti::start_arti(config, PathBuf::from(base_dir).as_path())
		.map_err(|e| Error::TorError(format!("Arti start error, {}", e)))?;
	Ok(())
}

/// Create a new server instance. No jobs will be started
pub fn create_server(context_id: u32, config: ServerConfig) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().expect("RwLock failure");
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
	let mut servers = SERVER_CONTEXT.write().expect("RwLock failure");
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
	let mut servers = SERVER_CONTEXT.write().expect("RwLock failure");
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
	let mut servers = SERVER_CONTEXT.write().expect("RwLock failure");
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
pub fn start_listen_peers(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().expect("RwLock failure");
	match servers.get_mut(&context_id) {
		Some(serv) => serv.start_listen_peers().map_err(|e| {
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
pub fn start_rest_api(
	context_id: u32,
	api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>),
) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().expect("RwLock failure");
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.start_rest_api(api_chan)
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

/// Start dandelion protocol. Needed for publishing transactions
pub fn start_dandelion(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write().expect("RwLock failure");
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
	let servers = SERVER_CONTEXT.read().expect("RwLock failure");
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
