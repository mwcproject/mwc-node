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

//! Main for building the binary of a Mwc peer-to-peer node.

#[macro_use]
extern crate clap;

#[macro_use]
extern crate log;
use crate::config::config::SERVER_CONFIG_FILE_NAME;
use crate::core::global;

use mwc_api as api;
use mwc_chain as chain;
use mwc_config as config;
use mwc_core as core;
use mwc_p2p as p2p;
use mwc_servers as servers;
use mwc_util as util;

use clap::App;

mod cmd;
pub mod tui;

// include build information
pub mod built_info {
	include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

pub fn info_strings() -> (String, String) {
	(
		format!(
			"This is MWC version {}{}, built for {} by {}.",
			built_info::PKG_VERSION,
			built_info::GIT_VERSION.map_or_else(|| "".to_owned(), |v| format!(" (git {})", v)),
			built_info::TARGET,
			built_info::RUSTC_VERSION,
		),
		format!(
			"Built with profile \"{}\", features \"{}\".",
			built_info::PROFILE,
			built_info::FEATURES_STR,
		),
	)
}

fn log_build_info() {
	let (basic_info, detailed_info) = info_strings();
	info!("{}", basic_info);
	debug!("{}", detailed_info);
}

fn main() {
	let exit_code = real_main();
	std::process::exit(exit_code);
}

fn real_main() -> i32 {
	let yml = load_yaml!("mwc.yml");
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();
	let node_config;

	let chain_type = if args.is_present("floonet") {
		global::ChainTypes::Floonet
	} else if args.is_present("usernet") {
		global::ChainTypes::UserTesting
	} else {
		global::ChainTypes::Mainnet
	};

	// Deal with configuration file creation
	if let ("server", Some(server_args)) = args.subcommand() {
		// If it's just a server config command, do it and exit
		if let ("config", Some(_)) = server_args.subcommand() {
			cmd::config_command_server(&chain_type, SERVER_CONFIG_FILE_NAME);
			return 0;
		}
	}

	// Load relevant config
	match args.subcommand() {
		// When the subscommand is 'server' take into account the 'config_file' flag
		("server", Some(server_args)) => {
			if let Some(_path) = server_args.value_of("config_file") {
				node_config = Some(config::GlobalConfig::new(_path).unwrap_or_else(|e| {
					panic!("Error loading server configuration: {}", e);
				}));
			} else {
				node_config = Some(
					config::initial_setup_server(&chain_type).unwrap_or_else(|e| {
						panic!("Error loading server configuration: {}", e);
					}),
				);
			}
		}
		// Otherwise load up the node config as usual
		_ => {
			node_config = Some(
				config::initial_setup_server(&chain_type).unwrap_or_else(|e| {
					panic!("Error loading server configuration: {}", e);
				}),
			);
		}
	}

	let config = node_config.clone().unwrap();
	let mut logging_config = config.members.as_ref().unwrap().logging.clone().unwrap();
	logging_config.tui_running = config.members.as_ref().unwrap().server.run_tui;

	let logs_rx = mwc_node_workflow::logging::init_bin_logs(&logging_config);

	let server_config = config.members.as_ref().unwrap().server.clone();

	let accept_fee_base = config
		.members
		.as_ref()
		.unwrap()
		.server
		.pool_config
		.tx_fee_base
		.clone();

	let context_id = match mwc_node_workflow::context::allocate_new_context(
		server_config.chain_type,
		accept_fee_base,
		None,
		&server_config.invalid_block_hashes,
	) {
		Ok(c_id) => c_id,
		Err(e) => {
			println!("Unable to allocate the context. {}", e);
			error!("Unable to allocate the context. {}", e);
			return -1;
		}
	};

	if let Some(file_path) = &config.config_file_path {
		info!(
			"Using configuration file at {}",
			file_path.to_str().unwrap()
		);
	} else {
		info!("Node configuration file not found, using default");
	};

	log_build_info();

	info!("Network: {:?}", global::get_chain_type(context_id));
	info!(
		"Accept Fee Base: {:?}",
		global::get_accept_fee_base(context_id)
	);
	info!(
		"Feature: NRD kernel enabled: {}",
		global::is_nrd_enabled(context_id)
	);

	// Execute subcommand
	let res = match args.subcommand() {
		// server commands and options
		("server", Some(server_args)) => {
			cmd::server_command(context_id, Some(server_args), node_config.unwrap(), logs_rx)
		}

		// client commands and options
		("client", Some(client_args)) => {
			cmd::client_command(context_id, client_args, node_config.unwrap())
		}

		// clean command
		("clean", _) => {
			let db_root_path = node_config.unwrap().members.unwrap().server.db_root;
			warn!("Cleaning chain data directory: {}", db_root_path);
			match std::fs::remove_dir_all(db_root_path) {
				Ok(_) => 0,
				Err(_) => 1,
			}
		}

		// If nothing is specified, try to just use the config file instead
		// this could possibly become the way to configure most things
		// with most command line options being phased out
		_ => cmd::server_command(context_id, None, node_config.unwrap(), logs_rx),
	};

	let _ = mwc_node_workflow::context::release_context(context_id);

	res
}
