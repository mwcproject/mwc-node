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

use crate::common::types::{ServerConfig, WebHooksConfig};
use crate::Error;
use mwc_chain::BlockStatus;
use mwc_core::core;
use mwc_core::core::hash::Hashed;
use mwc_crates::log::{debug, error, info, warn};
use mwc_crates::reqwest;
use mwc_crates::serde::Serialize;
use mwc_crates::serde_json;
use mwc_crates::serde_json::{to_string, Value};
use mwc_crates::tokio::sync::{OwnedSemaphorePermit, Semaphore};
use mwc_p2p::types::PeerAddr;
use mwc_util::{global_runtime, ToHex};
use std::sync::Arc;
use std::time::Duration;

/// Chain and network event hooks initialized for a server instance.
pub struct ServerHooks {
	/// Hooks invoked by chain events.
	pub chain_hooks: Vec<Box<dyn ChainEvents + Send + Sync>>,
	/// Hooks invoked by network events.
	pub net_hooks: Vec<Box<dyn NetEvents + Send + Sync>>,
}

/// Returns the event hooks initialized for this server instance.
pub fn init_hooks(config: &ServerConfig) -> Result<ServerHooks, Error> {
	let limiter = WebHookLimiter::from_config(&config.webhook_config);
	Ok(ServerHooks {
		chain_hooks: init_chain_hooks_with_limiter(config, limiter.clone())?,
		net_hooks: init_net_hooks_with_limiter(config, limiter)?,
	})
}

fn init_net_hooks_with_limiter(
	config: &ServerConfig,
	limiter: WebHookLimiter,
) -> Result<Vec<Box<dyn NetEvents + Send + Sync>>, Error> {
	let mut list: Vec<Box<dyn NetEvents + Send + Sync>> = Vec::new();
	list.push(Box::new(EventLogger));
	if config.webhook_config.block_received_url.is_some()
		|| config.webhook_config.tx_received_url.is_some()
		|| config.webhook_config.header_received_url.is_some()
		|| config.webhook_config.callback.is_some()
	{
		list.push(Box::new(WebHook::from_config(
			&config.webhook_config,
			limiter,
		)?));
	}
	Ok(list)
}

fn init_chain_hooks_with_limiter(
	config: &ServerConfig,
	limiter: WebHookLimiter,
) -> Result<Vec<Box<dyn ChainEvents + Send + Sync>>, Error> {
	let mut list: Vec<Box<dyn ChainEvents + Send + Sync>> = Vec::new();
	list.push(Box::new(EventLogger));
	if config.webhook_config.block_accepted_url.is_some()
		|| config.webhook_config.callback.is_some()
	{
		list.push(Box::new(WebHook::from_config(
			&config.webhook_config,
			limiter,
		)?));
	}
	Ok(list)
}

#[allow(unused_variables)]
/// Trait to be implemented by Network Event Hooks
pub trait NetEvents {
	/// Triggers when a new transaction arrives
	fn on_transaction_received(&self, context_id: u32, tx: &core::Transaction) {}

	/// Triggers when a new block arrives
	fn on_block_received(&self, context_id: u32, block: &core::Block, addr: &PeerAddr) {}

	/// Triggers when a new block header arrives
	fn on_header_received(&self, context_id: u32, header: &core::BlockHeader, addr: &PeerAddr) {}
}

#[allow(unused_variables)]
/// Trait to be implemented by Chain Event Hooks
pub trait ChainEvents {
	/// Triggers when a new block is accepted by the chain (might be a Reorg or a Fork)
	fn on_block_accepted(&self, context_id: u32, block: &core::Block, status: BlockStatus) {}
}

/// Basic Logger
struct EventLogger;

fn format_event_hash<T: Hashed>(context_id: u32, value: &T) -> String {
	match value.hash(context_id) {
		Ok(hash) => hash.to_string(),
		Err(e) => format!("<hash error: {}>", e),
	}
}

impl NetEvents for EventLogger {
	fn on_transaction_received(&self, context_id: u32, tx: &core::Transaction) {
		info!(
			"Received tx {}, [in/out/kern: {}/{}/{}] going to process.",
			format_event_hash(context_id, tx),
			tx.inputs().len(),
			tx.outputs().len(),
			tx.kernels().len(),
		);
	}

	fn on_block_received(&self, context_id: u32, block: &core::Block, addr: &PeerAddr) {
		info!(
			"Received block {} at {} from {} [in/out/kern: {}/{}/{}] going to process.",
			format_event_hash(context_id, block),
			block.header.height,
			addr,
			block.inputs().len(),
			block.outputs().len(),
			block.kernels().len(),
		);
	}

	fn on_header_received(&self, context_id: u32, header: &core::BlockHeader, addr: &PeerAddr) {
		info!(
			"Received block header {} at {} from {}, going to process.",
			format_event_hash(context_id, header),
			header.height,
			addr
		);
	}
}

impl ChainEvents for EventLogger {
	fn on_block_accepted(&self, context_id: u32, block: &core::Block, status: BlockStatus) {
		match status {
			BlockStatus::Reorg {
				prev,
				prev_head,
				fork_point,
			} => {
				warn!(
					"block_accepted (REORG!): {} at {}, (prev: {} at {}, prev_head: {} at {}, fork_point: {} at {}, depth: {})",
					format_event_hash(context_id, block),
					block.header.height,
					format_event_hash(context_id, &prev),
					prev.height,
					format_event_hash(context_id, &prev_head),
					prev_head.height,
					format_event_hash(context_id, &fork_point),
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
					format_event_hash(context_id, block),
					block.header.height,
					format_event_hash(context_id, &prev),
					prev.height,
					format_event_hash(context_id, &head),
					head.height,
					format_event_hash(context_id, &fork_point),
					fork_point.height,
					head.height.saturating_sub(fork_point.height),
				);
			}
			BlockStatus::Next { prev } => {
				debug!(
					"block_accepted (head+): {} at {} (prev: {} at {})",
					format_event_hash(context_id, block),
					block.header.height,
					format_event_hash(context_id, &prev),
					prev.height,
				);
			}
		}
	}
}

// Webhook URLs can contain deployment-specific tokens or credentials. Keep
// configured endpoint strings out of errors and logs.
fn parse_url(value: &Option<String>) -> Result<Option<reqwest::Url>, Error> {
	match value {
		Some(url) => {
			let uri: reqwest::Url = match url.parse() {
				Ok(value) => value,
				Err(e) => return Err(Error::Config(format!("Invalid webhook URL: {}", e))),
			};
			let scheme = uri.scheme();
			// HTTP webhooks are intentionally supported for local and
			// operator-managed deployments. HTTP does not provide transport
			// confidentiality or integrity, so operators must understand the
			// risk before using it on untrusted networks. MWC node webhook
			// payloads contain event data, not node credentials or secrets.
			if (scheme != "http") && (scheme != "https") {
				return Err(Error::Config(format!(
					"Invalid webhook URL scheme: {}",
					scheme
				)));
			}
			Ok(Some(uri))
		}
		None => Ok(None),
	}
}

#[derive(Clone)]
struct WebHookLimiter {
	request_slots: Arc<Semaphore>,
	max_concurrent_requests: usize,
}

type PendingWebHookRequest = (reqwest::Url, OwnedSemaphorePermit);

impl WebHookLimiter {
	fn from_config(config: &WebHooksConfig) -> WebHookLimiter {
		let max_concurrent_requests = usize::from(config.nthreads.max(1));
		WebHookLimiter {
			request_slots: Arc::new(Semaphore::new(max_concurrent_requests)),
			max_concurrent_requests,
		}
	}
}

/// A struct that holds the async webhook client.
struct WebHook {
	/// url to POST transaction data when a new transaction arrives from a peer
	tx_received_url: Option<reqwest::Url>,
	/// url to POST header data when a new header arrives from a peer
	header_received_url: Option<reqwest::Url>,
	/// url to POST block data when a new block arrives from a peer
	block_received_url: Option<reqwest::Url>,
	/// url to POST block data when a new block is accepted by our node (might be a reorg or a fork)
	block_accepted_url: Option<reqwest::Url>,
	/// The reqwest client to be used for all requests
	client: reqwest::Client,
	/// Shared limit for all outstanding webhook POST requests.
	limiter: WebHookLimiter,
	/// Callback for lib usage
	callback: Arc<Option<Box<dyn Fn(&str, &serde_json::Value) + Send + Sync>>>,
}

impl WebHook {
	/// Instantiates a Webhook struct
	fn new(
		tx_received_url: Option<reqwest::Url>,
		header_received_url: Option<reqwest::Url>,
		block_received_url: Option<reqwest::Url>,
		block_accepted_url: Option<reqwest::Url>,
		timeout: u16,
		callback: Arc<Option<Box<dyn Fn(&str, &serde_json::Value) + Send + Sync>>>,
		limiter: WebHookLimiter,
	) -> Result<WebHook, Error> {
		let request_timeout = Duration::from_secs(timeout as u64);

		info!(
			concat!(
				"Configuring webhook client with shared max {} concurrent requests ",
				"(request timeout set to {} secs)"
			),
			limiter.max_concurrent_requests, timeout
		);

		let client = match reqwest::Client::builder()
			.timeout(request_timeout)
			.redirect(reqwest::redirect::Policy::none())
			.build()
		{
			Ok(client) => client,
			Err(e) => {
				return Err(Error::HooksError(format!(
					"failed to build webhook reqwest client: {}",
					e
				)));
			}
		};

		Ok(WebHook {
			tx_received_url,
			block_received_url,
			header_received_url,
			block_accepted_url,
			client,
			limiter,
			callback,
		})
	}

	/// Instantiates a Webhook struct from a configuration file
	fn from_config(config: &WebHooksConfig, limiter: WebHookLimiter) -> Result<WebHook, Error> {
		Ok(WebHook::new(
			parse_url(&config.tx_received_url)?,
			parse_url(&config.header_received_url)?,
			parse_url(&config.block_received_url)?,
			parse_url(&config.block_accepted_url)?,
			config.timeout,
			config.callback.clone(),
			limiter,
		)?)
	}

	// Note, post request is async. Delivery is not guarantee. In case of failure
	// 	no response will be provided to the caller.
	fn schedule_post(
		&self,
		url: reqwest::Url,
		data: String,
		request_permit: OwnedSemaphorePermit,
	) -> Result<(), Error> {
		let client = self.client.clone();
		let runtime = match global_runtime() {
			Ok(runtime) => runtime,
			Err(e) => {
				return Err(Error::HooksError(format!(
					"Unable to get a runtime for webhook POST request, error: {}",
					e
				)));
			}
		};
		runtime.spawn(async move {
			let _request_permit = request_permit;
			match client
				.post(url.clone())
				.header(reqwest::header::CONTENT_TYPE, "application/json")
				.body(data)
				.send()
				.await
			{
				Ok(response) if !response.status().is_success() => {
					warn!(
						"Webhook POST request returned HTTP status {}",
						response.status()
					);
				}
				Ok(_) => {}
				Err(e) => {
					warn!(
						"Error sending webhook POST request, error: {}",
						e.without_url()
					);
				}
			}
		});
		Ok(())
	}

	fn callback_configured(&self) -> bool {
		self.callback.as_ref().is_some()
	}

	fn call_callback(&self, event_name: &str, payload: &serde_json::Value) {
		if let Some(callback) = self.callback.as_ref().as_ref() {
			callback(event_name, payload);
		}
	}

	fn prepare_request(&self, uri: &Option<reqwest::Url>) -> Option<PendingWebHookRequest> {
		let url = uri.as_ref()?;
		let request_permit = match self.limiter.request_slots.clone().try_acquire_owned() {
			Ok(permit) => permit,
			Err(_) => {
				warn!(
					"Webhook request limit reached ({}), dropping POST request",
					self.limiter.max_concurrent_requests
				);
				return None;
			}
		};
		Some((url.clone(), request_permit))
	}

	fn make_request<T: Serialize>(
		&self,
		payload: &T,
		request: Option<PendingWebHookRequest>,
	) -> Result<(), Error> {
		if let Some((url, request_permit)) = request {
			let payload = match to_string(payload) {
				Ok(serialized) => serialized,
				Err(e) => {
					return Err(Error::HooksError(format!(
						"Unable to serialize a payload, {}",
						e
					)))
				}
			};
			self.schedule_post(url, payload, request_permit)?;
		}
		Ok(())
	}
}

#[derive(Serialize)]
#[serde(crate = "mwc_crates::serde")]
struct DataPayload<'a, T: Serialize> {
	hash: String,
	data: &'a T,
}

#[derive(Serialize)]
#[serde(crate = "mwc_crates::serde")]
struct PeerPayload<'a, T: Serialize> {
	hash: String,
	peer: &'a PeerAddr,
	data: &'a T,
}

#[derive(Serialize)]
#[serde(crate = "mwc_crates::serde")]
struct BlockAcceptedPayload<'a> {
	hash: String,
	status: &'static str,
	data: &'a core::Block,
}

#[derive(Serialize)]
#[serde(crate = "mwc_crates::serde")]
struct BlockAcceptedReorgPayload<'a> {
	hash: String,
	status: &'static str,
	data: &'a core::Block,
	depth: u64,
}

fn serialize_hook_payload<T: Serialize>(event_name: &str, payload: T) -> Result<Value, Error> {
	serde_json::to_value(payload).map_err(|e| {
		Error::HooksError(format!(
			"Unable to serialize {} hook payload, {}",
			event_name, e
		))
	})
}

impl ChainEvents for WebHook {
	fn on_block_accepted(&self, context_id: u32, block: &core::Block, status: BlockStatus) {
		let request = self.prepare_request(&self.block_accepted_url);
		if !self.callback_configured() && request.is_none() {
			return;
		}

		let status_str = match status {
			BlockStatus::Reorg { .. } => "reorg",
			BlockStatus::Fork { .. } => "fork",
			BlockStatus::Next { .. } => "head",
		};
		let block_hash = match block.hash(context_id) {
			Ok(hash) => hash,
			Err(e) => {
				error!(
					"Unable to build hash for block_accepted hook at height {}, {}",
					block.header.height, e
				);
				return;
			}
		};

		// Add additional `depth` field to the JSON in case of reorg
		let payload = if let BlockStatus::Reorg {
			fork_point,
			prev_head,
			..
		} = status
		{
			let depth = prev_head.height.saturating_sub(fork_point.height);
			serialize_hook_payload(
				"block_accepted",
				BlockAcceptedReorgPayload {
					hash: block_hash.to_hex(),
					status: status_str,
					data: block,
					depth,
				},
			)
		} else {
			serialize_hook_payload(
				"block_accepted",
				BlockAcceptedPayload {
					hash: block_hash.to_hex(),
					status: status_str,
					data: block,
				},
			)
		};
		let payload = match payload {
			Ok(payload) => payload,
			Err(e) => {
				error!(
					"Unable to build payload for block_accepted hook at height {}, {}",
					block.header.height, e
				);
				return;
			}
		};

		self.call_callback("block_accepted", &payload);

		if let Err(e) = self.make_request(&payload, request) {
			error!(
				"Hook failed for event, block {} at height {}, {}",
				block_hash, block.header.height, e
			);
		}
	}
}

impl NetEvents for WebHook {
	/// Triggers when a new transaction arrives
	fn on_transaction_received(&self, context_id: u32, tx: &core::Transaction) {
		let request = self.prepare_request(&self.tx_received_url);
		if !self.callback_configured() && request.is_none() {
			return;
		}

		let tx_hash = match tx.hash(context_id) {
			Ok(hash) => hash,
			Err(e) => {
				error!("Unable to build hash for transaction_received hook, {}", e);
				return;
			}
		};
		let payload = match serialize_hook_payload(
			"transaction_received",
			DataPayload {
				hash: tx_hash.to_hex(),
				data: tx,
			},
		) {
			Ok(payload) => payload,
			Err(e) => {
				error!(
					"Unable to build payload for transaction_received hook, {}",
					e
				);
				return;
			}
		};

		self.call_callback("transaction_received", &payload);
		if let Err(e) = self.make_request(&payload, request) {
			error!("Hook failed for transaction {}, {}", tx_hash, e);
		}
	}

	/// Triggers when a new block arrives
	fn on_block_received(&self, context_id: u32, block: &core::Block, addr: &PeerAddr) {
		let request = self.prepare_request(&self.block_received_url);
		if !self.callback_configured() && request.is_none() {
			return;
		}

		let block_hash = match block.hash(context_id) {
			Ok(hash) => hash,
			Err(e) => {
				error!(
					"Unable to build hash for block_received hook at height {}, {}",
					block.header.height, e
				);
				return;
			}
		};
		let payload = match serialize_hook_payload(
			"block_received",
			PeerPayload {
				hash: block_hash.to_hex(),
				peer: addr,
				data: block,
			},
		) {
			Ok(payload) => payload,
			Err(e) => {
				error!(
					"Unable to build payload for block_received hook at height {}, {}",
					block.header.height, e
				);
				return;
			}
		};

		self.call_callback("block_received", &payload);

		if let Err(e) = self.make_request(&payload, request) {
			error!(
				"Hook failed for block {} at height {}, {}",
				block_hash.to_hex(),
				block.header.height,
				e
			);
		}
	}

	/// Triggers when a new block header arrives
	fn on_header_received(&self, context_id: u32, header: &core::BlockHeader, addr: &PeerAddr) {
		let request = self.prepare_request(&self.header_received_url);
		if !self.callback_configured() && request.is_none() {
			return;
		}

		let header_hash = match header.hash(context_id) {
			Ok(hash) => hash,
			Err(e) => {
				error!(
					"Unable to build hash for header_received hook at height {}, {}",
					header.height, e
				);
				return;
			}
		};
		let payload = match serialize_hook_payload(
			"header_received",
			PeerPayload {
				hash: header_hash.to_hex(),
				peer: addr,
				data: header,
			},
		) {
			Ok(payload) => payload,
			Err(e) => {
				error!(
					"Unable to build payload for header_received hook at height {}, {}",
					header.height, e
				);
				return;
			}
		};

		self.call_callback("header_received", &payload);

		if let Err(e) = self.make_request(&payload, request) {
			error!(
				"Hook failed for header {} at height {}, {}",
				header_hash, header.height, e
			);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	struct PanicOnSerialize;

	impl mwc_crates::serde::Serialize for PanicOnSerialize {
		fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
		where
			S: mwc_crates::serde::Serializer,
		{
			panic!("payload should not be serialized when webhook request is dropped");
		}
	}

	struct ErrorOnSerialize;

	impl mwc_crates::serde::Serialize for ErrorOnSerialize {
		fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
		where
			S: mwc_crates::serde::Serializer,
		{
			Err(mwc_crates::serde::ser::Error::custom(
				"test serialization failure",
			))
		}
	}

	struct HashFails;

	impl Hashed for HashFails {
		fn hash(&self, _context_id: u32) -> Result<mwc_core::core::hash::Hash, std::io::Error> {
			Err(std::io::Error::new(
				std::io::ErrorKind::InvalidData,
				"test hash failure",
			))
		}
	}

	#[test]
	fn event_hash_formatter_reports_hash_errors() {
		assert_eq!(
			format_event_hash(0, &HashFails),
			"<hash error: test hash failure>"
		);
	}

	#[test]
	fn webhook_payload_builder_reports_data_serialization_errors() {
		let err = serialize_hook_payload(
			"block_received",
			DataPayload {
				hash: "test_hash".to_string(),
				data: &ErrorOnSerialize,
			},
		)
		.unwrap_err();

		match err {
			Error::HooksError(msg) => {
				assert!(msg.contains("block_received"));
				assert!(msg.contains("test serialization failure"));
			}
			other => panic!("unexpected error: {:?}", other),
		}
	}

	#[test]
	fn webhook_instances_share_request_limiter() {
		let mut config = WebHooksConfig::default();
		config.nthreads = 1;
		config.tx_received_url = Some("http://127.0.0.1/tx".to_string());
		config.block_accepted_url = Some("http://127.0.0.1/block".to_string());
		let limiter = WebHookLimiter::from_config(&config);

		let net_hook = WebHook::from_config(&config, limiter.clone()).unwrap();
		let chain_hook = WebHook::from_config(&config, limiter).unwrap();

		assert!(Arc::ptr_eq(
			&net_hook.limiter.request_slots,
			&chain_hook.limiter.request_slots
		));
		let permit = net_hook
			.limiter
			.request_slots
			.clone()
			.try_acquire_owned()
			.unwrap();
		assert!(chain_hook
			.limiter
			.request_slots
			.clone()
			.try_acquire_owned()
			.is_err());
		drop(permit);
		assert!(chain_hook
			.limiter
			.request_slots
			.clone()
			.try_acquire_owned()
			.is_ok());
	}

	#[test]
	fn full_limiter_skips_http_payload_serialization() {
		let mut config = WebHooksConfig::default();
		config.nthreads = 1;
		config.tx_received_url = Some("http://127.0.0.1/tx".to_string());
		let hook = WebHook::from_config(&config, WebHookLimiter::from_config(&config)).unwrap();

		let _permit = hook
			.limiter
			.request_slots
			.clone()
			.try_acquire_owned()
			.unwrap();

		let request = hook.prepare_request(&hook.tx_received_url);
		assert!(request.is_none());
		hook.make_request(&PanicOnSerialize, request).unwrap();
	}

	#[test]
	fn webhook_config_url_errors_do_not_echo_configured_url() {
		let invalid_url =
			Some("http://user:password@exa mple.com/secret_path?token=query_secret".to_string());
		let err = parse_url(&invalid_url).unwrap_err();
		match err {
			Error::Config(msg) => {
				assert!(msg.contains("Invalid webhook URL"));
				assert!(!msg.contains("password"));
				assert!(!msg.contains("secret_path"));
				assert!(!msg.contains("query_secret"));
			}
			other => panic!("unexpected error: {:?}", other),
		}

		let invalid_scheme =
			Some("ftp://user:password@example.com/secret_path?token=query_secret".to_string());
		let err = parse_url(&invalid_scheme).unwrap_err();
		match err {
			Error::Config(msg) => {
				assert_eq!(msg, "Invalid webhook URL scheme: ftp");
				assert!(!msg.contains("password"));
				assert!(!msg.contains("secret_path"));
				assert!(!msg.contains("query_secret"));
			}
			other => panic!("unexpected error: {:?}", other),
		}
	}

	#[test]
	fn webhook_config_debug_masks_configured_urls() {
		let mut config = WebHooksConfig::default();
		config.tx_received_url =
			Some("https://user:password@example.com/secret_path?token=query_secret".to_string());

		let debug = format!("{:?}", config);
		assert!(debug.contains("tx_received_url: Some(\"<configured>\")"));
		assert!(!debug.contains("password"));
		assert!(!debug.contains("secret_path"));
		assert!(!debug.contains("query_secret"));
	}
}
