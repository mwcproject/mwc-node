// Copyright 2023 The MWC Developers
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

use clap::ArgMatches;
/// Mwc client commands processing
use std::net::SocketAddr;
use std::time::Duration;

use crate::api::types::Status;
use crate::cmd::error::Error;
use crate::config::GlobalConfig;
use crate::p2p::types::PeerInfoDisplay;
use crate::util::file::get_first_line;
use mwc_api::client::HttpClient;
use serde_json::json;

const ENDPOINT: &str = "/v2/owner";

#[derive(Clone)]
pub struct HTTPNodeClient {
	node_url: String,
	client_validation: HttpClient,
	client_normal: HttpClient,
}

impl HTTPNodeClient {
	/// Create a new client that will communicate with the given mwc node
	pub fn new(context_id: u32, node_url: &str, node_api_secret: Option<String>) -> HTTPNodeClient {
		HTTPNodeClient {
			node_url: node_url.to_owned(),
			client_validation: HttpClient::new(
				context_id,
				Duration::from_secs(21600),
				node_api_secret.clone(),
			),
			client_normal: HttpClient::new(
				context_id,
				Duration::from_secs(20),
				node_api_secret.clone(),
			),
		}
	}

	fn send_json_request<D: serde::de::DeserializeOwned>(
		&self,
		method: &str,
		params: &serde_json::Value,
	) -> Result<D, Error> {
		let client = match method {
			// 6 hours read timeout
			"validate_chain" => &self.client_validation,
			_ => &self.client_normal,
		};
		let url = format!("http://{}{}", self.node_url, ENDPOINT);
		let res = client.post_request(&url, params);

		match res {
			Err(e) => {
				let report = format!("Error calling {}: {}", method, e);
				error!("{}", report);
				Err(Error::RPCError(report))
			}
			Ok(inner) => match serde_json::from_value(inner) {
				Ok(r) => Ok(r),
				Err(e) => {
					let report = format!("Unable to parse response for {}: {}", method, e);
					error!("{}", report);
					Err(Error::RPCError(report))
				}
			},
		}
	}

	pub fn show_status(&self) -> Result<(), Error> {
		let mut t = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		println!();
		let title = "Mwc Server Status".to_string();
		t.fg(term::color::MAGENTA)?;
		writeln!(t, "{}", title)?;
		writeln!(t, "--------------------------")?;
		t.reset()?;
		match self.send_json_request::<Status>("get_status", &serde_json::Value::Null) {
			Ok(status) => {
				writeln!(e, "Protocol version: {:?}", status.protocol_version)?;
				writeln!(e, "User agent: {}", status.user_agent)?;
				writeln!(e, "Connections: {}", status.connections)?;
				writeln!(e, "Chain height: {}", status.tip.height)?;
				writeln!(e, "Last block hash: {}", status.tip.last_block_pushed)?;
				writeln!(e, "Previous block hash: {}", status.tip.prev_block_to_last)?;
				writeln!(e, "Total difficulty: {}", status.tip.total_difficulty)?;
				writeln!(e, "Sync status: {}", status.sync_status)?;
				if let Some(sync_info) = status.sync_info {
					writeln!(e, "Sync info: {}", sync_info)?;
				}
			}
			Err(_) => writeln!(
				e,
				"WARNING: Client failed to get data. Is your `mwc server` offline or broken?"
			)?,
		};
		e.reset()?;
		println!();
		Ok(())
	}

	pub fn list_connected_peers(&self) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		match self.send_json_request::<Vec<PeerInfoDisplay>>(
			"get_connected_peers",
			&serde_json::Value::Null,
		) {
			Ok(connected_peers) => {
				for (index, connected_peer) in connected_peers.into_iter().enumerate() {
					writeln!(e, "Peer {}:", index)?;
					writeln!(e, "Capabilities: {:?}", connected_peer.capabilities)?;
					writeln!(e, "User agent: {}", connected_peer.user_agent)?;
					writeln!(e, "Version: {:?}", connected_peer.version)?;
					writeln!(e, "Peer address: {}", connected_peer.addr)?;
					writeln!(e, "Height: {}", connected_peer.height)?;
					writeln!(e, "Total difficulty: {}", connected_peer.total_difficulty)?;
					writeln!(e, "Direction: {:?}", connected_peer.direction)?;
					println!();
				}
			}
			Err(_) => writeln!(e, "Failed to get connected peers")?,
		};
		e.reset()?;
		Ok(())
	}

	pub fn reset_chain_head(&self, hash: String) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([hash]);
		match self.send_json_request::<()>("reset_chain_head", &params) {
			Ok(_) => writeln!(e, "Successfully reset chain head {}", hash)?,
			Err(_) => writeln!(e, "Failed to reset chain head {}", hash)?,
		}
		e.reset()?;
		Ok(())
	}

	pub fn invalidate_header(&self, hash: String) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([hash]);
		match self.send_json_request::<()>("invalidate_header", &params) {
			Ok(_) => writeln!(e, "Successfully invalidated header: {}", hash)?,
			Err(_) => writeln!(e, "Failed to invalidate header: {}", hash)?,
		}
		e.reset()?;
		Ok(())
	}

	pub fn verify_chain(&self, assume_valid_rangeproofs_kernels: bool) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([assume_valid_rangeproofs_kernels]);
		writeln!(
			e,
			"Checking the state of the chain. This might take time..."
		)?;
		match self.send_json_request::<()>("validate_chain", &params) {
			Ok(_) => {
				if assume_valid_rangeproofs_kernels {
					writeln!(e, "Successfully validated the sum of kernel excesses! [fast_verification enabled]")?
				} else {
					writeln!(e, "Successfully validated the sum of kernel excesses, kernel signature and rangeproofs!")?
				}
			}
			Err(err) => writeln!(e, "Failed to validate chain: {:?}", err)?,
		}
		e.reset()?;
		Ok(())
	}

	pub fn ban_peer(&self, peer_addr: &SocketAddr) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([peer_addr]);
		match self.send_json_request::<()>("ban_peer", &params) {
			Ok(_) => writeln!(e, "Successfully banned peer {}", peer_addr)?,
			Err(_) => writeln!(e, "Failed to ban peer {}", peer_addr)?,
		};
		e.reset()?;
		Ok(())
	}

	pub fn unban_peer(&self, peer_addr: &SocketAddr) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([peer_addr]);
		match self.send_json_request::<()>("unban_peer", &params) {
			Ok(_) => writeln!(e, "Successfully unbanned peer {}", peer_addr)?,
			Err(_) => writeln!(e, "Failed to unban peer {}", peer_addr)?,
		};
		e.reset()?;
		Ok(())
	}
}

pub fn client_command(
	context_id: u32,
	client_args: &ArgMatches<'_>,
	global_config: GlobalConfig,
) -> Result<(), Error> {
	// just get defaults from the global config
	let server_config = global_config.members.server;
	let api_secret = get_first_line(server_config.api_secret_path.clone());
	let node_client = HTTPNodeClient::new(context_id, &server_config.api_http_addr, api_secret);

	match client_args.subcommand() {
		("status", Some(_)) => {
			node_client.show_status()?;
		}
		("listconnectedpeers", Some(_)) => {
			node_client.list_connected_peers()?;
		}
		("resetchainhead", Some(args)) => {
			let hash = args.value_of("hash").ok_or(Error::ArgumentError(
				"Not found expected argument 'hash'".into(),
			))?;
			node_client.reset_chain_head(hash.to_string())?;
		}
		("invalidateheader", Some(args)) => {
			let hash = args.value_of("hash").ok_or(Error::ArgumentError(
				"Not found expected argument 'hash'".into(),
			))?;
			node_client.invalidate_header(hash.to_string())?;
		}
		("verify-chain", Some(args)) => {
			let assume_valid_rangeproofs_kernels = args.is_present("fast");
			node_client.verify_chain(assume_valid_rangeproofs_kernels)?;
		}
		("ban", Some(peer_args)) => {
			let peer = peer_args.value_of("peer").ok_or(Error::ArgumentError(
				"Not found expected argument 'peer'".into(),
			))?;

			if let Ok(addr) = peer.parse() {
				node_client.ban_peer(&addr)?;
			} else {
				return Err(Error::ArgumentError("Invalid peer address format".into()));
			}
		}
		("unban", Some(peer_args)) => {
			let peer = peer_args.value_of("peer").ok_or(Error::ArgumentError(
				"Not found expected argument 'peer'".into(),
			))?;

			if let Ok(addr) = peer.parse() {
				node_client.unban_peer(&addr)?;
			} else {
				return Err(Error::ArgumentError("Invalid peer address format".into()));
			}
		}
		_ => {
			return Err(Error::ArgumentError(
				"Unknown client command, use 'mwc help client' for details".into(),
			))
		}
	}
	Ok(())
}
