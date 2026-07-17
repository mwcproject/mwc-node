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

use mwc_config::config::SERVER_CONFIG_FILE_NAME;
use mwc_core::global;

use mwc_crates::clap::{App, YamlLoader};
use mwc_crates::log::{debug, error, info, warn};
use mwc_util::escape_to_printable_ascii;

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
	let yml = match YamlLoader::load_from_str(include_str!("mwc.yml")) {
		Ok(yml) => yml,
		Err(e) => {
			println!("Error loading command line configuration: {}", e);
			return -1;
		}
	};
	let Some(yml) = yml.first() else {
		println!("Error loading command line configuration: empty YAML");
		return -1;
	};
	let args = App::from_yaml(yml)
		.version(built_info::PKG_VERSION)
		.get_matches();

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
			return res_to_ret_val(cmd::config_command_server(
				&chain_type,
				SERVER_CONFIG_FILE_NAME,
			));
		}
	}

	// Load relevant config
	let config = match args.subcommand() {
		// When the subscommand is 'server' take into account the 'config_file' flag
		("server", Some(server_args)) => {
			if let Some(_path) = server_args.value_of("config_file") {
				match mwc_config::GlobalConfig::new(_path) {
					Ok(config) => config,
					Err(e) => {
						println!("Error loading server configuration: {}", e);
						return -1;
					}
				}
			} else {
				match mwc_config::initial_setup_server(&chain_type) {
					Ok(config) => config,
					Err(e) => {
						println!("Error loading server configuration: {}", e);
						return -1;
					}
				}
			}
		}
		// Otherwise load up the node config as usual
		_ => match mwc_config::initial_setup_server(&chain_type) {
			Ok(config) => config,
			Err(e) => {
				println!("Error loading server configuration: {}", e);
				return -1;
			}
		},
	};

	let mut logging_config = config.members.logging.clone();
	logging_config.tui_running = config.members.server.run_tui;

	let tui_logs = match mwc_node_workflow::logging::init_bin_logs(&logging_config) {
		Ok(logs) => logs,
		Err(e) => {
			println!("Unable to initilize the logs. {}", e);
			return -1;
		}
	};

	let server_config = config.members.server.clone();

	let accept_fee_base = config.members.server.pool_config.tx_fee_base.clone();

	let context_id = match mwc_node_workflow::context::allocate_new_context(
		server_config.chain_type,
		accept_fee_base,
		None,
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
			file_path.to_string_lossy()
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
	let mut res = match args.subcommand() {
		// server commands and options
		("server", Some(server_args)) => res_to_ret_val(cmd::server_command(
			context_id,
			Some(server_args),
			config,
			tui_logs,
		)),
		// client commands and options
		("client", Some(client_args)) => {
			res_to_ret_val(cmd::client_command(context_id, client_args, config))
		}
		// clean command
		("clean", _) => {
			let db_root_path = config.members.server.db_root;
			warn!("Cleaning chain data directory: {}", db_root_path);
			match std::fs::remove_dir_all(db_root_path) {
				Ok(_) => 0,
				Err(e) => {
					println!("{}", e);
					1
				}
			}
		}

		// If nothing is specified, try to just use the config file instead
		// this could possibly become the way to configure most things
		// with most command line options being phased out
		_ => res_to_ret_val(cmd::server_command(context_id, None, config, tui_logs)),
	};

	if let Err(e) = mwc_node_workflow::context::release_context(context_id) {
		let msg = format!("Unable to release the context. {}", e);
		println!("{}", escape_to_printable_ascii(&msg));
		error!("{}", msg);
		if res == 0 {
			res = 1;
		}
	}

	res
}

fn res_to_ret_val(res: Result<(), crate::cmd::Error>) -> i32 {
	match res {
		Ok(_) => 0,
		Err(e) => {
			println!("{}", escape_to_printable_ascii(&e.to_string()));
			1
		}
	}
}
