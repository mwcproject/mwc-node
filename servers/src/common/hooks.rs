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

//! This module allows to register callbacks on certain events. To add a custom
//! callback simply implement the coresponding trait and add it to the init function

use crate::chain::BlockStatus;
use crate::common::types::{ServerConfig, WebHooksConfig};
use crate::core::core;
use crate::core::core::hash::Hashed;
use crate::p2p::types::PeerAddr;
use futures::TryFutureExt;
use hyper::client::HttpConnector;
use hyper::header::HeaderValue;
use hyper::Client;
use hyper::{Body, Method, Request};
use hyper_rustls::HttpsConnector;
use mwc_core::core::hash::Hash;
use mwc_util::{global_runtime, ToHex};
use serde::Serialize;
use serde_json::{json, to_string};
use std::sync::Arc;
use std::time::Duration;

/// Returns the list of event hooks that will be initialized for network events
pub fn init_net_hooks(config: &ServerConfig) -> Vec<Box<dyn NetEvents + Send + Sync>> {
	let mut list: Vec<Box<dyn NetEvents + Send + Sync>> = Vec::new();
	list.push(Box::new(EventLogger));
	if config.webhook_config.block_received_url.is_some()
		|| config.webhook_config.tx_received_url.is_some()
		|| config.webhook_config.header_received_url.is_some()
		|| config.webhook_config.callback.is_some()
	{
		list.push(Box::new(WebHook::from_config(&config.webhook_config)));
	}
	list
}

/// Returns the list of event hooks that will be initialized for chain events
pub fn init_chain_hooks(config: &ServerConfig) -> Vec<Box<dyn ChainEvents + Send + Sync>> {
	let mut list: Vec<Box<dyn ChainEvents + Send + Sync>> = Vec::new();
	list.push(Box::new(EventLogger));
	if config.webhook_config.block_accepted_url.is_some() {
		list.push(Box::new(WebHook::from_config(&config.webhook_config)));
	}
	list
}

#[allow(unused_variables)]
/// Trait to be implemented by Network Event Hooks
pub trait NetEvents {
	/// Triggers when a new transaction arrives
	fn on_transaction_received(&self, tx: &core::Transaction) {}

	/// Triggers when a new block arrives
	fn on_block_received(&self, block: &core::Block, addr: &PeerAddr) {}

	/// Triggers when a new block header arrives
	fn on_header_received(&self, header: &core::BlockHeader, addr: &PeerAddr) {}
}

#[allow(unused_variables)]
/// Trait to be implemented by Chain Event Hooks
pub trait ChainEvents {
	/// Triggers when a new block is accepted by the chain (might be a Reorg or a Fork)
	fn on_block_accepted(&self, block: &core::Block, status: BlockStatus) {}
}

/// Basic Logger
struct EventLogger;

impl NetEvents for EventLogger {
	fn on_transaction_received(&self, tx: &core::Transaction) {
		info!(
			"Received tx {}, [in/out/kern: {}/{}/{}] going to process.",
			tx.hash().unwrap_or(Hash::default()),
			tx.inputs().len(),
			tx.outputs().len(),
			tx.kernels().len(),
		);
	}

	fn on_block_received(&self, block: &core::Block, addr: &PeerAddr) {
		info!(
			"Received block {} at {} from {} [in/out/kern: {}/{}/{}] going to process.",
			block.hash().unwrap_or(Hash::default()),
			block.header.height,
			addr,
			block.inputs().len(),
			block.outputs().len(),
			block.kernels().len(),
		);
	}

	fn on_header_received(&self, header: &core::BlockHeader, addr: &PeerAddr) {
		info!(
			"Received block header {} at {} from {}, going to process.",
			header.hash().unwrap_or(Hash::default()),
			header.height,
			addr
		);
	}
}

impl ChainEvents for EventLogger {
	fn on_block_accepted(&self, block: &core::Block, status: BlockStatus) {
		match status {
			BlockStatus::Reorg {
				prev,
				prev_head,
				fork_point,
			} => {
				warn!(
					"block_accepted (REORG!): {} at {}, (prev: {} at {}, prev_head: {} at {}, fork_point: {} at {}, depth: {})",
					block.hash().unwrap_or(Hash::default()),
					block.header.height,
					prev.hash().unwrap_or(Hash::default()),
					prev.height,
					prev_head.hash().unwrap_or(Hash::default()),
					prev_head.height,
					fork_point.hash().unwrap_or(Hash::default()),
					fork_point.height,
					prev_head.height.saturating_sub(fork_point.height),
				);
			}
			BlockStatus::Fork {
				prev,
				head,
				fork_point,
			} => {
				debug!(
					"block_accepted (fork?): {} at {}, (prev: {} at {}, head: {} at {}, fork_point: {} at {}, depth: {})",
					block.hash().unwrap_or(Hash::default()),
					block.header.height,
					prev.hash().unwrap_or(Hash::default()),
					prev.height,
					head.hash().unwrap_or(Hash::default()),
					head.height,
					fork_point.hash().unwrap_or(Hash::default()),
					fork_point.height,
					head.height.saturating_sub(fork_point.height),
				);
			}
			BlockStatus::Next { prev } => {
				debug!(
					"block_accepted (head+): {} at {} (prev: {} at {})",
					block.hash().unwrap_or(Hash::default()),
					block.header.height,
					prev.hash().unwrap_or(Hash::default()),
					prev.height,
				);
			}
		}
	}
}

fn parse_url(value: &Option<String>) -> Option<hyper::Uri> {
	match value {
		Some(url) => {
			let uri: hyper::Uri = match url.parse() {
				Ok(value) => value,
				Err(_) => panic!("Invalid url : {}", url),
			};
			let scheme = uri.scheme().map(|s| s.as_str());
			if (scheme != Some("http")) && (scheme != Some("https")) {
				panic!(
					"Invalid url scheme {}, expected one of ['http', https']",
					url
				)
			};
			Some(uri)
		}
		None => None,
	}
}

/// A struct that holds the hyper/tokio runtime.
struct WebHook {
	/// url to POST transaction data when a new transaction arrives from a peer
	tx_received_url: Option<hyper::Uri>,
	/// url to POST header data when a new header arrives from a peer
	header_received_url: Option<hyper::Uri>,
	/// url to POST block data when a new block arrives from a peer
	block_received_url: Option<hyper::Uri>,
	/// url to POST block data when a new block is accepted by our node (might be a reorg or a fork)
	block_accepted_url: Option<hyper::Uri>,
	/// The hyper client to be used for all requests
	client: Client<HttpsConnector<HttpConnector>>,
	/// Callback for lib usage
	callback: Arc<Option<Box<dyn Fn(&str, &serde_json::Value) + Send + Sync>>>,
}

impl WebHook {
	/// Instantiates a Webhook struct
	fn new(
		tx_received_url: Option<hyper::Uri>,
		header_received_url: Option<hyper::Uri>,
		block_received_url: Option<hyper::Uri>,
		block_accepted_url: Option<hyper::Uri>,
		nthreads: u16,
		timeout: u16,
		callback: Arc<Option<Box<dyn Fn(&str, &serde_json::Value) + Send + Sync>>>,
	) -> WebHook {
		let keep_alive = Duration::from_secs(timeout as u64);

		info!(
			"Spawning {} threads for webhooks (timeout set to {} secs)",
			nthreads, timeout
		);

		let https = hyper_rustls::HttpsConnectorBuilder::new()
			.with_native_roots()
			.https_only()
			.enable_http1()
			.build();

		let client = Client::builder()
			.pool_idle_timeout(keep_alive)
			.build::<_, hyper::Body>(https);

		WebHook {
			tx_received_url,
			block_received_url,
			header_received_url,
			block_accepted_url,
			client,
			callback,
		}
	}

	/// Instantiates a Webhook struct from a configuration file
	fn from_config(config: &WebHooksConfig) -> WebHook {
		WebHook::new(
			parse_url(&config.tx_received_url),
			parse_url(&config.header_received_url),
			parse_url(&config.block_received_url),
			parse_url(&config.block_accepted_url),
			config.nthreads,
			config.timeout,
			config.callback.clone(),
		)
	}

	fn post(&self, url: hyper::Uri, data: String) {
		let mut req = Request::new(Body::from(data));
		*req.method_mut() = Method::POST;
		*req.uri_mut() = url.clone();
		req.headers_mut().insert(
			hyper::header::CONTENT_TYPE,
			HeaderValue::from_static("application/json"),
		);

		let future = self.client.request(req).map_err(move |e| {
			warn!("Error sending POST request to {}, error: {}", url, e);
		});

		global_runtime().spawn(future);
	}
	fn make_request<T: Serialize>(&self, payload: &T, uri: &Option<hyper::Uri>) -> bool {
		if let Some(url) = uri {
			let payload = match to_string(payload) {
				Ok(serialized) => serialized,
				Err(_) => {
					return false; // print error message
				}
			};
			self.post(url.clone(), payload);
		}
		true
	}
}

impl ChainEvents for WebHook {
	fn on_block_accepted(&self, block: &core::Block, status: BlockStatus) {
		let status_str = match status {
			BlockStatus::Reorg { .. } => "reorg",
			BlockStatus::Fork { .. } => "fork",
			BlockStatus::Next { .. } => "head",
		};

		// Add additional `depth` field to the JSON in case of reorg
		let payload = if let BlockStatus::Reorg {
			fork_point,
			prev_head,
			..
		} = status
		{
			let depth = prev_head.height.saturating_sub(fork_point.height);
			json!({
				"hash": block.header.hash().unwrap_or(Hash::default()).to_hex(),
				"status": status_str,
				"data": block,
				"depth": depth
			})
		} else {
			json!({
				"hash": block.header.hash().unwrap_or(Hash::default()).to_hex(),
				"status": status_str,
				"data": block
			})
		};

		self.callback
			.as_ref()
			.as_ref()
			.map(|f| f("block_accepted", &payload));

		if !self.make_request(&payload, &self.block_accepted_url) {
			error!(
				"Failed to serialize block {} at height {}",
				block.hash().unwrap_or(Hash::default()),
				block.header.height
			);
		}
	}
}

impl NetEvents for WebHook {
	/// Triggers when a new transaction arrives
	fn on_transaction_received(&self, tx: &core::Transaction) {
		let payload = json!({
			"hash": tx.hash().unwrap_or(Hash::default()).to_hex(),
			"data": tx
		});

		self.callback
			.as_ref()
			.as_ref()
			.map(|f| f("transaction_received", &payload));
		if !self.make_request(&payload, &self.tx_received_url) {
			error!(
				"Failed to serialize transaction {}",
				tx.hash().unwrap_or(Hash::default())
			);
		}
	}

	/// Triggers when a new block arrives
	fn on_block_received(&self, block: &core::Block, addr: &PeerAddr) {
		let payload = json!({
			"hash": block.header.hash().unwrap_or(Hash::default()).to_hex(),
			"peer": addr,
			"data": block
		});

		self.callback
			.as_ref()
			.as_ref()
			.map(|f| f("block_received", &payload));

		if !self.make_request(&payload, &self.block_received_url) {
			error!(
				"Failed to serialize block {} at height {}",
				block.hash().unwrap_or(Hash::default()).to_hex(),
				block.header.height
			);
		}
	}

	/// Triggers when a new block header arrives
	fn on_header_received(&self, header: &core::BlockHeader, addr: &PeerAddr) {
		let payload = json!({
			"hash": header.hash().unwrap_or(Hash::default()).to_hex(),
			"peer": addr,
			"data": header
		});

		self.callback
			.as_ref()
			.as_ref()
			.map(|f| f("header_received", &payload));

		if !self.make_request(&payload, &self.header_received_url) {
			error!(
				"Failed to serialize header {} at height {}",
				header.hash().unwrap_or(Hash::default()),
				header.height
			);
		}
	}
}
