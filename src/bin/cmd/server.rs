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

/// Mwc server commands processing
use mwc_crates::ctrlc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use mwc_crates::clap::ArgMatches;

use crate::cmd::error::Error;
use crate::tui::ui;
use mwc_config::GlobalConfig;
use mwc_crates::log::{error, info, warn};
use mwc_p2p::msg::PeerAddrs;
use mwc_p2p::PeerAddr;
use mwc_p2p::Seeding;
use mwc_util::logger::LogEntry;
use std::net::{IpAddr, SocketAddr};
use std::sync::{mpsc, Arc};

/// wrap below to allow UI to clean up on stop
pub fn start_server(
	context_id: u32,
	config: mwc_servers::ServerConfig,
	logs_rx: Option<mpsc::Receiver<LogEntry>>,
	offline: bool,
) -> Result<(), Error> {
	start_server_tui(context_id, config, logs_rx, offline)
		.map_err(|e| Error::ServerStart(e.to_string()))
}

fn start_server_tui(
	context_id: u32,
	config: mwc_servers::ServerConfig,
	logs_rx: Option<mpsc::Receiver<LogEntry>>,
	offline: bool,
) -> Result<(), mwc_node_workflow::Error> {
	info!("Creating MWC node server...");
	mwc_node_workflow::server::create_server(context_id, config.clone())?;

	let res = (|| {
		if !offline && config.tor_config.need_start_arti() {
			info!("Bootstrapping tor rich client Arti...");
			mwc_node_workflow::server::start_tor(&config.tor_config, &config.db_root)?;
		}

		if !offline {
			info!("Starting listening peers...");
			mwc_node_workflow::server::start_listen_peers(context_id)?;
			info!("Starting discovery peers...");
			mwc_node_workflow::server::start_discover_peers(context_id)?;
			info!("Starting syncyng...");
			mwc_node_workflow::server::start_sync_monitoring(context_id)?;

			info!("Starting node API...");
			mwc_node_workflow::server::start_rest_api(context_id)?;

			info!("Starting dandellion...");
			mwc_node_workflow::server::start_dandelion(context_id)?;

			if config
				.stratum_mining_config
				.enable_stratum_server
				.unwrap_or(false)
			{
				info!("Starting stratum server...");
				mwc_node_workflow::server::start_stratum(context_id)?;
			}
		}
		info!("MC node is started and running");

		// Run the UI controller.. here for now for simplicity to access
		// everything it might need
		if config.run_tui.unwrap_or(false) {
			warn!("Starting MWC UI...");

			match logs_rx {
				Some(logs_rx) => {
					let mut controller = ui::Controller::new(context_id, logs_rx).map_err(|e| {
						error!("{}", e);
						mwc_node_workflow::Error::UIError(e)
					})?;
					controller.run(context_id);
					Ok(())
				}
				None => {
					let msg = "Internal error, logs_rx is not set properly";
					error!("{}", msg);
					Err(mwc_node_workflow::Error::UIError(msg.to_string()))
				}
			}
		} else {
			warn!("Running MWC w/o UI...");

			let running = Arc::new(AtomicBool::new(true));
			let r = running.clone();
			if let Err(e) = ctrlc::set_handler(move || {
				r.store(false, Ordering::SeqCst);
			}) {
				return Err(mwc_node_workflow::Error::ServerError(format!(
					"Error setting handler for both SIGINT (Ctrl+C) and SIGTERM (kill): {}",
					e
				)));
			}

			while running.load(Ordering::SeqCst) {
				thread::sleep(Duration::from_millis(300));
			}
			warn!("Received SIGINT (Ctrl+C) or SIGTERM (kill).");
			mwc_node_workflow::server::release_server(context_id);
			Ok(())
		}
	})();

	if res.is_err() {
		mwc_node_workflow::server::release_server(context_id);
	}
	res
}

/// Handles the server part of the command line, mostly running, starting and
/// stopping the Mwc blockchain server. Processes all the command line
/// arguments to build a proper configuration and runs Mwc with that
/// configuration.
pub fn server_command(
	context_id: u32,
	server_args: Option<&ArgMatches<'_>>,
	global_config: GlobalConfig,
	logs_rx: Option<mpsc::Receiver<LogEntry>>,
) -> Result<(), Error> {
	// just get defaults from the global config
	let mut server_config = global_config.members.server.clone();
	let mut offline = false;

	if let Some(a) = server_args {
		if let Some(port) = a.value_of("port") {
			server_config.p2p_config.port = port.parse().map_err(|e| {
				Error::ArgumentError(format!("Invalid value at 'port' value {}, {}", port, e))
			})?;
		}

		match (a.value_of("api_host"), a.value_of("api_port")) {
			(Some(host), Some(port)) => {
				server_config.api_http_addr = api_http_addr_from_host_port(host, port)?;
			}
			(None, Some(_)) => {
				return Err(Error::ArgumentError(
					"--api_port requires --api_host so API binding is explicit".into(),
				));
			}
			(Some(_), None) => {
				return Err(Error::ArgumentError(
					"--api_host requires --api_port so API binding is explicit".into(),
				));
			}
			(None, None) => {}
		}

		if let Some(wallet_url) = a.value_of("wallet_url") {
			server_config.stratum_mining_config.wallet_listener_url = wallet_url.to_string();
		}

		if let Some(seeds) = a.values_of("seed") {
			let peers = seeds
				.map(|s| {
					s.parse().map(PeerAddr::Ip).map_err(|e| {
						Error::ArgumentError(format!("Invalid value at 'seed' value {}, {}", s, e))
					})
				})
				.collect::<Result<Vec<_>, _>>()?;
			server_config.p2p_config.seeding_type = Seeding::List;
			server_config.p2p_config.seeds = Some(PeerAddrs { peers });
		}

		offline = a.is_present("offline");
	}

	if offline {
		warn!("Running in offline mode! Not connecting to any peers.");
	}

	if let Some(a) = server_args {
		match a.subcommand() {
			("run", _) => {
				start_server(context_id, server_config, logs_rx, offline)?;
			}
			("", _) => {
				return Err(Error::ArgumentError(
					"Subcommand required, use 'mwc help server' for details".into(),
				));
			}
			(cmd, _) => {
				return Err(Error::ArgumentError(format!(
					"Unknown server command '{}', use 'mwc help server' for details",
					cmd
				)));
			}
		}
	} else {
		start_server(context_id, server_config, logs_rx, offline)?;
	}
	Ok(())
}

fn api_http_addr_from_host_port(api_host: &str, api_port: &str) -> Result<String, Error> {
	let host = api_host.trim();
	let host = host
		.strip_prefix('[')
		.and_then(|host| host.strip_suffix(']'))
		.unwrap_or(host);
	if host.is_empty() {
		return Err(Error::ArgumentError(
			"Invalid value for --api_host: host must not be empty".into(),
		));
	}

	let ip = host.parse::<IpAddr>().map_err(|e| {
		Error::ArgumentError(format!(
			"Invalid value for --api_host '{}': {}",
			api_host, e
		))
	})?;
	let port = api_port.parse::<u16>().map_err(|e| {
		Error::ArgumentError(format!(
			"Invalid value for --api_port '{}': {}",
			api_port, e
		))
	})?;

	Ok(SocketAddr::new(ip, port).to_string())
}
