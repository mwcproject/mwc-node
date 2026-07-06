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

use mwc_crates::clap::ArgMatches;
use mwc_crates::serde;
use mwc_crates::serde_json;
use mwc_crates::term;
use mwc_crates::url::{Host, Url};
/// Mwc client commands processing
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::cmd::error::Error;
use mwc_api::client::HttpClient;
use mwc_api::json_rpc;
use mwc_api::types::Status;
use mwc_config::GlobalConfig;
use mwc_crates::log::error;
use mwc_crates::serde_json::json;
use mwc_crates::zeroize::Zeroizing;
use mwc_p2p::types::PeerInfoDisplayLegacy;
use mwc_util::escape_to_printable_ascii;
use mwc_util::file::get_owner_only_first_line_zeroizing;

const ENDPOINT: &str = "/v2/owner";

#[derive(Clone)]
pub struct HTTPNodeClient {
	node_url: String,
	client_validation: HttpClient,
	client_normal: HttpClient,
}

impl HTTPNodeClient {
	/// Create a new client that will communicate with the given mwc node
	pub fn new(
		context_id: u32,
		node_url: &str,
		node_api_secret: Option<Zeroizing<String>>,
	) -> Result<HTTPNodeClient, Error> {
		let has_api_secret = node_api_secret.is_some();
		let node_url = normalize_node_url(node_url, has_api_secret)?;

		Ok(HTTPNodeClient {
			node_url,
			client_validation: HttpClient::new(
				context_id,
				Duration::from_secs(21600),
				node_api_secret.clone(),
			),
			client_normal: HttpClient::new(context_id, Duration::from_secs(20), node_api_secret),
		})
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
		let url = format!("{}{}", self.node_url, ENDPOINT);
		let rpc_params = if params.is_null() {
			json!([])
		} else {
			params.clone()
		};
		let rpc_request = json_rpc::build_request(1, method, &rpc_params);
		let request_id = rpc_request.id.clone();
		let request_body = serde_json::to_value(rpc_request).map_err(|e| {
			let report = format!("Unable to build JSON-RPC request for {}: {}", method, e);
			error!("{}", report);
			Error::RPCError(report)
		})?;
		let res = client.post_request(&url, &request_body);

		match res {
			Err(e) => {
				let report = format!("Error calling {}: {}", method, e);
				error!("{}", report);
				Err(Error::RPCError(report))
			}
			Ok(inner) => {
				let response: json_rpc::Response = serde_json::from_value(inner).map_err(|e| {
					let report = format!("Unable to parse JSON-RPC response for {}: {}", method, e);
					error!("{}", report);
					Error::RPCError(report)
				})?;

				if let Some(ref rpc_error) = response.error {
					let report = format!("JSON-RPC call {} failed: {}", method, rpc_error);
					error!("{}", report);
					return Err(Error::RPCError(report));
				}

				if response.id != request_id {
					let report = format!("JSON-RPC response id mismatch for {}", method);
					error!("{}", report);
					return Err(Error::RPCError(report));
				}

				response.result::<D>().map_err(|e| {
					let report = format!("JSON-RPC call {} failed: {}", method, e);
					error!("{}", report);
					Error::RPCError(report)
				})
			}
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
		let result = match self.send_json_request::<Status>("get_status", &serde_json::Value::Null)
		{
			Ok(status) => {
				writeln!(e, "Protocol version: {:?}", status.protocol_version)?;
				writeln!(
					e,
					"User agent: {}",
					escape_to_printable_ascii(&status.user_agent)
				)?;
				writeln!(e, "Connections: {}", status.connections)?;
				writeln!(e, "Chain height: {}", status.tip.height)?;
				writeln!(
					e,
					"Last block hash: {}",
					escape_to_printable_ascii(&status.tip.last_block_pushed)
				)?;
				writeln!(
					e,
					"Previous block hash: {}",
					escape_to_printable_ascii(&status.tip.prev_block_to_last)
				)?;
				writeln!(e, "Total difficulty: {}", status.tip.total_difficulty)?;
				writeln!(
					e,
					"Sync status: {}",
					escape_to_printable_ascii(&status.sync_status)
				)?;
				if let Some(sync_info) = status.sync_info {
					writeln!(
						e,
						"Sync info: {}",
						escape_to_printable_ascii(&sync_info.to_string())
					)?;
				}
				Ok(())
			}
			Err(err) => {
				writeln!(
					e,
					"WARNING: Client failed to get data. Is your `mwc server` offline or broken? {}",
					escape_to_printable_ascii(&err.to_string())
				)?;
				Err(err)
			}
		};
		e.reset()?;
		println!();
		result
	}

	pub fn list_connected_peers(&self) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let result = match self.send_json_request::<Vec<PeerInfoDisplayLegacy>>(
			"get_connected_peers",
			&serde_json::Value::Null,
		) {
			Ok(connected_peers) => {
				for (index, connected_peer) in connected_peers.into_iter().enumerate() {
					writeln!(e, "Peer {}:", index)?;
					writeln!(e, "Capabilities: {:?}", connected_peer.capabilities)?;
					writeln!(
						e,
						"User agent: {}",
						escape_to_printable_ascii(&connected_peer.user_agent)
					)?;
					writeln!(e, "Version: {:?}", connected_peer.version)?;
					writeln!(
						e,
						"Peer address: {}",
						escape_to_printable_ascii(&connected_peer.addr)
					)?;
					writeln!(e, "Height: {}", connected_peer.height)?;
					writeln!(e, "Total difficulty: {}", connected_peer.total_difficulty)?;
					writeln!(e, "Direction: {:?}", connected_peer.direction)?;
					println!();
				}
				Ok(())
			}
			Err(err) => {
				writeln!(
					e,
					"Failed to get connected peers: {}",
					escape_to_printable_ascii(&err.to_string())
				)?;
				Err(err)
			}
		};
		e.reset()?;
		result
	}

	pub fn reset_chain_head(&self, hash: String) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([hash]);
		let hash_display = escape_to_printable_ascii(&hash);
		let result = match self.send_json_request::<()>("reset_chain_head", &params) {
			Ok(_) => {
				writeln!(e, "Successfully reset chain head {}", hash_display)?;
				Ok(())
			}
			Err(err) => {
				writeln!(
					e,
					"Failed to reset chain head {}: {}",
					hash_display,
					escape_to_printable_ascii(&err.to_string())
				)?;
				Err(err)
			}
		};
		e.reset()?;
		result
	}

	pub fn invalidate_header(&self, hash: String) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([[hash]]);
		let hash_display = escape_to_printable_ascii(&hash);
		match self.send_json_request::<()>("invalidate_header", &params) {
			Ok(_) => {
				writeln!(e, "Successfully invalidated header: {}", hash_display)?;
				e.reset()?;
				Ok(())
			}
			Err(err) => {
				let _ = writeln!(
					e,
					"Failed to invalidate header {}: {}",
					hash_display,
					escape_to_printable_ascii(&err.to_string())
				);
				let _ = e.reset();
				Err(err)
			}
		}
	}

	pub fn verify_chain(&self, assume_valid_rangeproofs_kernels: bool) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([assume_valid_rangeproofs_kernels]);
		writeln!(
			e,
			"Checking the state of the chain. This might take time..."
		)?;
		let result = match self.send_json_request::<()>("validate_chain", &params) {
			Ok(_) => {
				if assume_valid_rangeproofs_kernels {
					writeln!(
						e,
						"Successfully validated the sum of kernel excesses! [fast_verification enabled]"
					)?;
				} else {
					writeln!(
						e,
						"Successfully validated the sum of kernel excesses, kernel signature and rangeproofs!"
					)?;
				}
				Ok(())
			}
			Err(err) => {
				let _ = writeln!(
					e,
					"Failed to validate chain: {}",
					escape_to_printable_ascii(&err.to_string())
				);
				Err(err)
			}
		};
		if result.is_err() {
			let _ = e.reset();
			return result;
		}
		e.reset()?;
		result
	}

	pub fn ban_peer(&self, peer_addr: &SocketAddr) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([peer_addr]);
		let result = match self.send_json_request::<()>("ban_peer", &params) {
			Ok(_) => {
				writeln!(e, "Successfully banned peer {}", peer_addr)?;
				Ok(())
			}
			Err(err) => {
				writeln!(
					e,
					"Failed to ban peer {}: {}",
					peer_addr,
					escape_to_printable_ascii(&err.to_string())
				)?;
				Err(err)
			}
		};
		e.reset()?;
		result
	}

	pub fn unban_peer(&self, peer_addr: &SocketAddr) -> Result<(), Error> {
		let mut e = term::stdout().ok_or(Error::Internal("Unable open terminal".into()))?;
		let params = json!([peer_addr]);
		let result = match self.send_json_request::<()>("unban_peer", &params) {
			Ok(_) => {
				writeln!(e, "Successfully unbanned peer {}", peer_addr)?;
				Ok(())
			}
			Err(err) => {
				writeln!(
					e,
					"Failed to unban peer {}: {}",
					peer_addr,
					escape_to_printable_ascii(&err.to_string())
				)?;
				Err(err)
			}
		};
		e.reset()?;
		result
	}
}

fn node_url_from_server_config(server_config: &mwc_servers::ServerConfig) -> Result<String, Error> {
	let api_http_addr = server_config.api_http_addr.trim();
	if api_http_addr.is_empty() {
		return Err(Error::ArgumentError(
			"Node API address must not be empty".into(),
		));
	}

	if let Some(scheme) = api_http_addr.split_once("://").map(|(scheme, _)| scheme) {
		if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
			return Ok(api_http_addr.to_owned());
		}

		return Err(Error::ArgumentError(format!(
			"Unsupported node API URL scheme '{}'; expected http or https",
			scheme
		)));
	}

	let scheme = match (
		&server_config.tls_certificate_file,
		&server_config.tls_certificate_key,
	) {
		(Some(_), Some(_)) => "https",
		(None, None) => "http",
		_ => {
			return Err(Error::ArgumentError(
				"TLS certificate and private key must both be configured to use HTTPS".into(),
			));
		}
	};

	Ok(format!("{}://{}", scheme, api_http_addr))
}

fn normalize_node_url(node_url: &str, has_api_secret: bool) -> Result<String, Error> {
	let trimmed = node_url.trim().trim_end_matches('/');
	if trimmed.is_empty() {
		return Err(Error::ArgumentError(
			"Node API URL must not be empty".into(),
		));
	}

	let node_url = if trimmed.split_once("://").is_some() {
		trimmed.to_owned()
	} else {
		format!("http://{}", trimmed)
	};

	let mut url = Url::parse(&node_url)
		.map_err(|e| Error::ArgumentError(format!("Invalid node API URL '{}': {}", node_url, e)))?;

	match url.scheme() {
		"http" | "https" => {}
		scheme => {
			return Err(Error::ArgumentError(format!(
				"Unsupported node API URL scheme '{}'; expected http or https",
				scheme
			)));
		}
	}

	if url.host().is_none() {
		return Err(Error::ArgumentError(format!(
			"Node API URL '{}' must include a host",
			node_url
		)));
	}

	if !url.username().is_empty() || url.password().is_some() {
		return Err(Error::ArgumentError(
			"Node API URL must not include embedded credentials".into(),
		));
	}

	if url.query().is_some() || url.fragment().is_some() {
		return Err(Error::ArgumentError(format!(
			"Node API URL '{}' must not include a query string or fragment",
			node_url
		)));
	}

	rewrite_unspecified_host_to_loopback(&mut url)?;

	if url.scheme() == "http" && has_api_secret && !is_trusted_plaintext_host(&url) {
		return Err(Error::ArgumentError(format!(
			"Plaintext node API URL '{}' is not allowed with an API secret unless it targets a literal loopback address; use https:// for remote node APIs",
			url
		)));
	}

	Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn rewrite_unspecified_host_to_loopback(url: &mut Url) -> Result<(), Error> {
	let loopback = match url.host() {
		Some(Host::Ipv4(addr)) if addr.is_unspecified() => {
			Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
		}
		Some(Host::Ipv6(addr)) if addr.is_unspecified() => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
		_ => None,
	};

	if let Some(loopback) = loopback {
		url.set_ip_host(loopback).map_err(|_| {
			Error::ArgumentError("Unable to rewrite wildcard node API address".into())
		})?;
	}

	Ok(())
}

fn is_trusted_plaintext_host(url: &Url) -> bool {
	match url.host() {
		Some(Host::Ipv4(addr)) => addr.is_loopback(),
		Some(Host::Ipv6(addr)) => addr.is_loopback(),
		Some(Host::Domain(_)) | None => false,
	}
}

pub fn client_command(
	context_id: u32,
	client_args: &ArgMatches<'_>,
	global_config: GlobalConfig,
) -> Result<(), Error> {
	// just get defaults from the global config
	let server_config = global_config.members.server;
	let api_secret = get_owner_only_first_line_zeroizing(server_config.api_secret_path.clone())?;
	let node_url = node_url_from_server_config(&server_config)?;
	let node_client = HTTPNodeClient::new(context_id, &node_url, api_secret)?;

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
			));
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn api_secret() -> Zeroizing<String> {
		Zeroizing::new("secret".to_owned())
	}

	#[test]
	fn normalizes_bare_loopback_node_url_to_http() {
		let client = HTTPNodeClient::new(0, "127.0.0.1:3413", Some(api_secret())).unwrap();

		assert_eq!(client.node_url, "http://127.0.0.1:3413");
	}

	#[test]
	fn preserves_explicit_https_node_url_with_api_secret() {
		let client =
			HTTPNodeClient::new(0, "https://node.example.com:3413", Some(api_secret())).unwrap();

		assert_eq!(client.node_url, "https://node.example.com:3413");
	}

	#[test]
	fn rejects_plaintext_remote_node_url_with_api_secret() {
		let err = match HTTPNodeClient::new(0, "http://node.example.com:3413", Some(api_secret())) {
			Ok(_) => panic!("remote HTTP node URL with an API secret must be rejected"),
			Err(err) => err,
		};

		assert!(err.to_string().contains("Plaintext node API URL"));
	}

	#[test]
	fn rejects_plaintext_localhost_node_url_with_api_secret() {
		let err = match HTTPNodeClient::new(0, "http://localhost:3413", Some(api_secret())) {
			Ok(_) => panic!("localhost HTTP node URL with an API secret must be rejected"),
			Err(err) => err,
		};

		assert!(err.to_string().contains("literal loopback address"));
	}

	#[test]
	fn allows_plaintext_remote_node_url_without_api_secret() {
		let client = HTTPNodeClient::new(0, "node.example.com:3413", None).unwrap();

		assert_eq!(client.node_url, "http://node.example.com:3413");
	}

	#[test]
	fn rejects_node_url_with_embedded_credentials() {
		for node_url in [
			"https://trusted.example@attacker.example:3413",
			"https://user:pass@node.example.com:3413",
		] {
			let err = match HTTPNodeClient::new(0, node_url, Some(api_secret())) {
				Ok(_) => panic!("node URL with embedded credentials must be rejected"),
				Err(err) => err,
			};

			assert!(err.to_string().contains("embedded credentials"));
		}
	}

	#[test]
	fn rewrites_wildcard_bind_address_to_loopback_client_url() {
		let client = HTTPNodeClient::new(0, "0.0.0.0:3413", Some(api_secret())).unwrap();

		assert_eq!(client.node_url, "http://127.0.0.1:3413");
	}

	#[test]
	fn server_config_uses_https_when_tls_is_configured() {
		let config = mwc_servers::ServerConfig {
			api_http_addr: "127.0.0.1:3413".to_owned(),
			tls_certificate_file: Some("cert.pem".to_owned()),
			tls_certificate_key: Some("key.pem".to_owned()),
			..mwc_servers::ServerConfig::default()
		};

		assert_eq!(
			node_url_from_server_config(&config).unwrap(),
			"https://127.0.0.1:3413"
		);
	}

	#[test]
	fn server_config_rejects_incomplete_tls_config() {
		let config = mwc_servers::ServerConfig {
			api_http_addr: "127.0.0.1:3413".to_owned(),
			tls_certificate_file: Some("cert.pem".to_owned()),
			tls_certificate_key: None,
			..mwc_servers::ServerConfig::default()
		};

		let err = node_url_from_server_config(&config).unwrap_err();

		assert!(err.to_string().contains("TLS certificate and private key"));
	}
}
