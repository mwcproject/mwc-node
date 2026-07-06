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

pub mod blocks_api;
pub mod chain_api;
pub mod peers_api;
pub mod pool_api;
pub mod server_api;
pub mod transactions_api;
pub mod utils;
pub mod version_api;

use self::blocks_api::BlockHandler;
use self::blocks_api::HeaderHandler;
use self::chain_api::ChainCompactHandler;
use self::chain_api::ChainHandler;
use self::chain_api::ChainValidationHandler;
use self::chain_api::KernelHandler;
use self::chain_api::OutputHandler;
use self::peers_api::PeerHandler;
use self::peers_api::PeersAllHandler;
use self::peers_api::PeersConnectedHandler;
use self::pool_api::PoolInfoHandler;
use self::pool_api::PoolPushHandler;
use self::server_api::IndexHandler;
use self::server_api::StatusHandler;
use self::transactions_api::TxHashSetHandler;
use self::version_api::VersionHandler;
use crate::auth::{
	BasicAuthMiddleware, BasicAuthURIMiddleware, MWC_BASIC_REALM, MWC_FOREIGN_BASIC_REALM,
};
use crate::foreign::{Foreign, ProcessStatusCache};
use crate::foreign_rpc::ForeignRpcCompat;
use crate::owner::Owner;
use crate::owner_rpc::OwnerRpc;
use crate::rest::{ApiServer, Error, TLSConfig};
use crate::router::ResponseFuture;
use crate::router::{Router, RouterError};
use crate::stratum::Stratum;
use crate::stratum_rpc::StratumRpc;
use crate::web::*;
use mwc_chain::{Chain, SyncState};
use mwc_core::global;
use mwc_core::stratum;
use mwc_crates::bytes::Bytes;
use mwc_crates::easy_jsonrpc_mwc::{Handler, MaybeReply};
use mwc_crates::http_body_util::Full;
use mwc_crates::hyper;
use mwc_crates::hyper::{Request, Response, StatusCode};
use mwc_crates::log::{error, warn};
use mwc_crates::parking_lot::{Mutex, RwLock};
use mwc_crates::serde::Serialize;
use mwc_crates::serde_json;
use mwc_crates::zeroize::Zeroizing;
use mwc_pool::{BlockChain, PoolAdapter};
use mwc_util::StopState;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use std::thread;
use std::thread::JoinHandle;
use std::time::Instant;

/// Threads started for the node HTTP APIs.
pub struct NodeApiThreads {
	pub api_thread: JoinHandle<()>,
	pub api_monitor_thread: JoinHandle<Result<(), String>>,
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
pub fn build_node_router<B, P>(
	chain: Arc<Chain>,
	tx_pool: Arc<RwLock<mwc_pool::TransactionPool<B, P>>>,
	peers: Arc<mwc_p2p::Peers>,
	sync_state: Arc<SyncState>,
	api_secret: Option<Zeroizing<String>>,
	foreign_api_secret: Option<Zeroizing<String>>,
	stratum_ip_pool: Arc<stratum::connections::StratumIpPool>,
	stop_state: Arc<StopState>,
) -> Result<Router, Error>
where
	B: BlockChain + 'static,
	P: PoolAdapter + 'static,
{
	// Adding legacy owner v1 API
	let mut router = build_router(
		chain.clone(),
		tx_pool.clone(),
		peers.clone(),
		sync_state.clone(),
		stop_state.clone(),
	)
	.map_err(|e| Error::Internal(format!("unable to build API router, {}", e)))?;

	let context_id = chain.get_context_id();
	let basic_auth_key = if global::is_mainnet(context_id) {
		"mwcmain"
	} else if global::is_floonet(context_id) {
		"mwcfloo"
	} else {
		"mwc"
	};

	// Add basic auth to v1 API and owner v2 API
	if let Some(api_secret) = api_secret {
		let basic_auth_middleware = Arc::new(BasicAuthMiddleware::from_api_secret(
			basic_auth_key,
			&api_secret,
			&MWC_BASIC_REALM,
			Some("/v2/foreign".into()),
		));
		router.add_middleware(basic_auth_middleware);
	}

	let api_handler = OwnerAPIHandlerV2::new(
		Arc::downgrade(&chain),
		Arc::downgrade(&peers),
		Arc::downgrade(&sync_state),
		Arc::downgrade(&stop_state),
	);
	router.add_route("/v2/owner", Arc::new(api_handler))?;

	let stratum_handler_v2 = StratumAPIHandlerV2::new(stratum_ip_pool);
	router.add_route("/v2/stratum", Arc::new(stratum_handler_v2))?;

	// Add basic auth to v2 foreign API only
	if let Some(api_secret) = foreign_api_secret {
		let basic_auth_middleware = Arc::new(BasicAuthURIMiddleware::from_api_secret(
			basic_auth_key,
			&api_secret,
			&MWC_FOREIGN_BASIC_REALM,
			"/v2/foreign".into(),
		));
		router.add_middleware(basic_auth_middleware);
	}

	let api_handler = ForeignAPIHandlerV2::new(
		Arc::downgrade(&peers),
		Arc::downgrade(&chain),
		Arc::downgrade(&tx_pool),
		Arc::downgrade(&sync_state),
	);
	router.add_route("/v2/foreign", Arc::new(api_handler))?;

	Ok(router)
}

/// Listener version, providing same API but listening for requests on a
/// port and wrapping the calls
pub fn node_apis<B, P>(
	addr: &str,
	chain: Arc<Chain>,
	tx_pool: Arc<RwLock<mwc_pool::TransactionPool<B, P>>>,
	peers: Arc<mwc_p2p::Peers>,
	sync_state: Arc<SyncState>,
	api_secret: Option<Zeroizing<String>>,
	foreign_api_secret: Option<Zeroizing<String>>,
	tls_config: Option<TLSConfig>,
	stratum_ip_pool: Arc<stratum::connections::StratumIpPool>,
	stop_state: Arc<StopState>,
) -> Result<NodeApiThreads, Error>
where
	B: BlockChain + 'static,
	P: PoolAdapter + 'static,
{
	let router = build_node_router(
		chain,
		tx_pool,
		peers,
		sync_state,
		api_secret,
		foreign_api_secret,
		stratum_ip_pool,
		stop_state.clone(),
	)?;

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Node APIs server at {}.", addr);
	let socket_addr: SocketAddr = addr
		.parse()
		.map_err(|e| Error::Argument(format!("unable to parse socket address {}, {}", addr, e)))?;
	let api_thread = apis.start(socket_addr, router, tls_config).map_err(|e| {
		error!("HTTP API server failed to start. Err: {}", e);
		Error::Internal(format!("HTTP API server failed to start, {}", e))
	})?;

	let api_monitor_thread = thread::Builder::new()
		.name("api_monitor".to_string())
		.spawn(move || -> Result<(), String> {
			// monitor for stop state is_stopped
			loop {
				std::thread::sleep(std::time::Duration::from_millis(100));
				if stop_state.is_stopped() {
					if apis.stop() {
						return Ok(());
					}

					return Err("HTTP API server shutdown failed".to_string());
				}
			}
		})
		.map_err(|e| Error::Internal(format!("Unable to start the api_monitor thread, {}", e)))?;

	warn!("HTTP Node listener started.");

	Ok(NodeApiThreads {
		api_thread,
		api_monitor_thread,
	})
}

/// V2 API Handler/Wrapper for owner functions
pub struct OwnerAPIHandlerV2 {
	pub chain: Weak<Chain>,
	pub peers: Weak<mwc_p2p::Peers>,
	pub sync_state: Weak<SyncState>,
	pub stop_state: Weak<StopState>,
}

impl OwnerAPIHandlerV2 {
	/// Create a new owner API handler for GET methods
	pub fn new(
		chain: Weak<Chain>,
		peers: Weak<mwc_p2p::Peers>,
		sync_state: Weak<SyncState>,
		stop_state: Weak<StopState>,
	) -> Self {
		OwnerAPIHandlerV2 {
			chain,
			peers,
			sync_state,
			stop_state,
		}
	}
}

impl crate::router::Handler for OwnerAPIHandlerV2 {
	fn post(&self, req: Request<Bytes>) -> ResponseFuture {
		let api = Owner::new(
			self.chain.clone(),
			self.peers.clone(),
			self.sync_state.clone(),
			self.stop_state.clone(),
		);

		Box::pin(async move {
			match parse_body(req).await {
				Ok(val) => {
					let owner_api = &api as &dyn OwnerRpc;
					let res = match owner_api.handle_request(val) {
						MaybeReply::Reply(r) => r,
						MaybeReply::DontReply => {
							// Since it's http, we need to return something. We return [] because jsonrpc
							// clients will parse it as an empty batch response.
							serde_json::json!([])
						}
					};
					Ok(json_response_pretty(&res))
				}
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Bytes>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
	}
}

/// V2 API Handler/Wrapper for foreign functions
pub struct ForeignAPIHandlerV2<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	pub peers: Weak<mwc_p2p::Peers>,
	pub chain: Weak<Chain>,
	pub tx_pool: Weak<RwLock<mwc_pool::TransactionPool<B, P>>>,
	pub sync_state: Weak<SyncState>,
	start_time: Instant,
	process_status_cache: Arc<Mutex<ProcessStatusCache>>,
}

impl<B, P> ForeignAPIHandlerV2<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	/// Create a new foreign API handler for GET methods
	pub fn new(
		peers: Weak<mwc_p2p::Peers>,
		chain: Weak<Chain>,
		tx_pool: Weak<RwLock<mwc_pool::TransactionPool<B, P>>>,
		sync_state: Weak<SyncState>,
	) -> Self {
		ForeignAPIHandlerV2 {
			peers,
			chain,
			tx_pool,
			sync_state,
			start_time: Instant::now(),
			process_status_cache: Arc::new(Mutex::new(ProcessStatusCache::new())),
		}
	}
}

impl<B, P> crate::router::Handler for ForeignAPIHandlerV2<B, P>
where
	B: BlockChain + 'static,
	P: PoolAdapter + 'static,
{
	fn post(&self, req: Request<Bytes>) -> ResponseFuture {
		let api = Foreign::new(
			self.peers.clone(),
			self.chain.clone(),
			self.tx_pool.clone(),
			self.sync_state.clone(),
			self.start_time.clone(),
			self.process_status_cache.clone(),
		);

		Box::pin(async move {
			match parse_body(req).await {
				Ok(val) => {
					let foreign_api = ForeignRpcCompat::new(&api);
					let res = match foreign_api.handle_request(val) {
						MaybeReply::Reply(r) => r,
						MaybeReply::DontReply => {
							// Since it's http, we need to return something. We return [] because jsonrpc
							// clients will parse it as an empty batch response.
							serde_json::json!([])
						}
					};
					Ok(json_response_pretty(&res))
				}
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Bytes>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
	}
}

/// V2 API Handler/Wrapper for stratum
pub struct StratumAPIHandlerV2 {
	stratum_ip_pool: Arc<stratum::connections::StratumIpPool>,
}

impl StratumAPIHandlerV2 {
	/// Create a new owner API handler for GET methods
	pub fn new(stratum_ip_pool: Arc<stratum::connections::StratumIpPool>) -> Self {
		StratumAPIHandlerV2 { stratum_ip_pool }
	}
}

impl crate::router::Handler for StratumAPIHandlerV2 {
	fn post(&self, req: Request<Bytes>) -> ResponseFuture {
		let api = Stratum::new(self.stratum_ip_pool.clone());

		Box::pin(async move {
			match parse_body(req).await {
				Ok(val) => {
					let stratum_api = &api as &dyn StratumRpc;
					let res = match stratum_api.handle_request(val) {
						MaybeReply::Reply(r) => r,
						MaybeReply::DontReply => {
							// Since it's http, we need to return something. We return [] because jsonrpc
							// clients will parse it as an empty batch response.
							serde_json::json!([])
						}
					};
					Ok(json_response_pretty(&res))
				}
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Bytes>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
	}
}

// pretty-printed version of above
fn json_response_pretty<T>(s: &T) -> Response<Full<Bytes>>
where
	T: Serialize,
{
	match serde_json::to_string_pretty(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(e) => response(
			StatusCode::INTERNAL_SERVER_ERROR,
			serde_json::json!({ "error": e.to_string() }).to_string(),
		),
	}
}

fn create_error_response(e: Error) -> Response<Full<Bytes>> {
	match Response::builder()
		// Keep this JSON-RPC wrapper simple: any error on this path is reported
		// as HTTP 500 instead of classifying Error variants into HTTP statuses.
		.status(StatusCode::INTERNAL_SERVER_ERROR)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.body(Full::new(Bytes::from(format!("{}", e))))
	{
		Ok(r) => r,
		Err(e) => response_build_error(e),
	}
}

fn create_ok_response(json: &str) -> Response<Full<Bytes>> {
	match Response::builder()
		.status(StatusCode::OK)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.header(hyper::header::CONTENT_TYPE, "application/json")
		.body(Full::new(Bytes::from(json.to_string())))
	{
		Ok(r) => r,
		Err(e) => response_build_error(e),
	}
}

fn response_build_error(e: hyper::http::Error) -> Response<Full<Bytes>> {
	let mut response = Response::new(Full::new(Bytes::from(format!(
		"response construction failed: {}",
		e
	))));
	*response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
	response
}

/// Build a new hyper Response with the status code and body provided.
///
/// Whenever the status code is `StatusCode::OK` the text parameter should be
/// valid JSON as the content type header will be set to `application/json'
fn response<T: Into<Bytes>>(status: StatusCode, text: T) -> Response<Full<Bytes>> {
	let mut builder = Response::builder();

	builder = builder
		.status(status)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		);

	if status == StatusCode::OK {
		builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
	}

	match builder.body(Full::new(text.into())) {
		Ok(r) => r,
		Err(e) => response_build_error(e),
	}
}

// Legacy V1 router
/*#[deprecated(
	since = "4.0.0",
	note = "The V1 Node API will be removed in mwc 5.0.0. Please migrate to the V2 API as soon as possible."
)]*/
pub fn build_router<B, P>(
	chain: Arc<Chain>,
	tx_pool: Arc<RwLock<mwc_pool::TransactionPool<B, P>>>,
	peers: Arc<mwc_p2p::Peers>,
	sync_state: Arc<SyncState>,
	stop_state: Arc<StopState>,
) -> Result<Router, RouterError>
where
	B: BlockChain + 'static,
	P: PoolAdapter + 'static,
{
	let route_list = vec![
		"get blocks".to_string(),
		"get headers".to_string(),
		"get chain".to_string(),
		"post chain/compact".to_string(),
		"get chain/validate?fast=true".to_string(),
		"get chain/kernels/xxx?min_height=yyy&max_height=zzz".to_string(),
		"get chain/outputs/byids?id=xxx,yyy,zzz".to_string(),
		"get chain/outputs/byheight?start_height=101&end_height=200".to_string(),
		"get status".to_string(),
		"get txhashset/roots".to_string(),
		"get txhashset/lastoutputs?n=10".to_string(),
		"get txhashset/lastrangeproofs".to_string(),
		"get txhashset/lastkernels".to_string(),
		"get txhashset/outputs?start_index=1&max=100".to_string(),
		"get txhashset/merkleproof?n=1".to_string(),
		"get pool".to_string(),
		"post pool/push_tx".to_string(),
		"post peers/a.b.c.d:p/ban".to_string(),
		"post peers/a.b.c.d:p/unban".to_string(),
		"get peers/all".to_string(),
		"get peers/connected".to_string(),
		"get peers/a.b.c.d".to_string(),
		"get version".to_string(),
	];
	let index_handler = IndexHandler { list: route_list };

	let output_handler = OutputHandler {
		chain: Arc::downgrade(&chain),
	};
	let kernel_handler = KernelHandler {
		chain: Arc::downgrade(&chain),
	};
	let block_handler = BlockHandler {
		chain: Arc::downgrade(&chain),
	};
	let header_handler = HeaderHandler {
		chain: Arc::downgrade(&chain),
	};
	let chain_tip_handler = ChainHandler {
		chain: Arc::downgrade(&chain),
	};
	let chain_compact_handler = ChainCompactHandler {
		chain: Arc::downgrade(&chain),
		stop_state,
	};
	let chain_validation_handler = ChainValidationHandler {
		chain: Arc::downgrade(&chain),
	};
	let status_handler = StatusHandler {
		chain: Arc::downgrade(&chain),
		peers: Arc::downgrade(&peers),
		sync_state: Arc::downgrade(&sync_state),
	};
	let txhashset_handler = TxHashSetHandler {
		chain: Arc::downgrade(&chain),
	};
	let pool_info_handler = PoolInfoHandler {
		tx_pool: Arc::downgrade(&tx_pool),
	};
	let pool_push_handler = PoolPushHandler {
		tx_pool: Arc::downgrade(&tx_pool),
	};
	let peers_all_handler = PeersAllHandler {
		peers: Arc::downgrade(&peers),
	};
	let peers_connected_handler = PeersConnectedHandler {
		peers: Arc::downgrade(&peers),
	};
	let peer_handler = PeerHandler {
		peers: Arc::downgrade(&peers),
	};
	let version_handler = VersionHandler {
		chain: Arc::downgrade(&chain),
	};

	let mut router = Router::new();

	router.add_route("/v1/", Arc::new(index_handler))?;
	router.add_route("/v1/blocks/*", Arc::new(block_handler))?;
	router.add_route("/v1/headers/*", Arc::new(header_handler))?;
	router.add_route("/v1/chain", Arc::new(chain_tip_handler))?;
	router.add_route("/v1/chain/outputs/*", Arc::new(output_handler))?;
	router.add_route("/v1/chain/kernels/*", Arc::new(kernel_handler))?;
	router.add_route("/v1/chain/compact", Arc::new(chain_compact_handler))?;
	router.add_route("/v1/chain/validate", Arc::new(chain_validation_handler))?;
	router.add_route("/v1/txhashset/*", Arc::new(txhashset_handler))?;
	router.add_route("/v1/status", Arc::new(status_handler))?;
	router.add_route("/v1/pool", Arc::new(pool_info_handler))?;
	router.add_route("/v1/pool/push_tx", Arc::new(pool_push_handler))?;
	router.add_route("/v1/peers/all", Arc::new(peers_all_handler))?;
	router.add_route("/v1/peers/connected", Arc::new(peers_connected_handler))?;
	router.add_route("/v1/peers/**", Arc::new(peer_handler))?;
	router.add_route("/v1/version", Arc::new(version_handler))?;
	Ok(router)
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::http_body_util::BodyExt;
	use mwc_crates::serde::ser::Serializer;

	struct BrokenSerialize;

	impl Serialize for BrokenSerialize {
		fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			Err(<S::Error as mwc_crates::serde::ser::Error>::custom(
				"bad \"field\"\n\\trail",
			))
		}
	}

	#[test]
	fn json_response_pretty_escapes_serialization_errors() {
		let response = json_response_pretty(&BrokenSerialize);

		assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
		let body = mwc_crates::futures::executor::block_on(response.into_body().collect())
			.unwrap()
			.to_bytes();
		let value: serde_json::Value = serde_json::from_slice(&body).unwrap();

		assert_eq!(value["error"], "bad \"field\"\n\\trail");
	}
}
