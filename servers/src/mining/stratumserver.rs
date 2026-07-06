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

//! Mining Stratum Server

use mwc_crates::async_stream;
use mwc_crates::futures;
use mwc_crates::futures::channel::oneshot;
use mwc_crates::futures::pin_mut;
use mwc_crates::futures::{SinkExt, StreamExt, TryStreamExt};
use mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_crates::serde_json;
use mwc_crates::tokio;
use mwc_crates::tokio::io::AsyncWriteExt;
use mwc_crates::tokio::net::TcpListener;
use mwc_crates::tokio_util::codec::{Framed, LinesCodec};

use mwc_crates::parking_lot::RwLock;
use mwc_crates::serde_json::Value;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{mpsc as std_mpsc, Arc};
use std::time::{Duration, Instant};
use std::{cmp, thread};

use super::stratum_data::{WorkerRef, WorkersList, WORKER_RESPONSE_QUEUE_CAPACITY};
use crate::common::stats::{StratumStats, WorkerStats};
use crate::common::types::StratumServerConfig;
use crate::mining::mine_block;
use crate::Error;
use crate::ServerTxPool;
use mwc_api::client::HttpClient;
use mwc_chain::{self, SyncState};
use mwc_core::core::hash::Hashed;
use mwc_core::core::Block;
use mwc_core::global;
use mwc_core::stratum::connections;
use mwc_core::{pow, ser};
use mwc_crates::log::{debug, error, info, warn};
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_crates::tokio::sync::{mpsc, Mutex};
use mwc_keychain;
use mwc_util;
use mwc_util::ToHex;
use mwc_util::{global_runtime, run_global_async_block, secp_static, StopState};
use std::cmp::min;
// ----------------------------------------
// http://www.jsonrpc.org/specification
// RPC Methods

const MIN_IP_POOL_BAN_HISTORY_S: u64 = 10;
const IP_POOL_BAN_HISTORY_MS_FACTOR: u64 = 1000;
const MAX_STRATUM_LINE_LENGTH: usize = 64 * 1024;
const MAX_CURRENT_BLOCK_VERSIONS: usize = 100;
const STRATUM_ACCEPT_ERROR_INITIAL_BACKOFF_MS: u64 = 100;
const STRATUM_ACCEPT_ERROR_MAX_BACKOFF_MS: u64 = 1_000;

pub(crate) type StratumStartupStatusTx = std_mpsc::Sender<Result<(), String>>;

fn report_startup_status(
	startup_status_tx: &mut Option<StratumStartupStatusTx>,
	status: Result<(), String>,
) {
	if let Some(tx) = startup_status_tx.take() {
		if let Err(std_mpsc::SendError(status)) = tx.send(status) {
			warn!(
				"Failed to report stratum startup status; receiver disconnected: {:?}",
				status
			);
		}
	}
}

fn validate_ip_pool_ban_history_s(ip_pool_ban_history_s: u64) -> Result<(), Error> {
	if ip_pool_ban_history_s <= MIN_IP_POOL_BAN_HISTORY_S {
		return Err(Error::Config(format!(
			"Stratum ip_pool_ban_history_s must be greater than {} seconds, got {}",
			MIN_IP_POOL_BAN_HISTORY_S, ip_pool_ban_history_s
		)));
	}

	let ip_pool_history_ms = ip_pool_ban_history_ms(ip_pool_ban_history_s)?;
	let ip_pool_checking_period = Duration::from_millis(ip_pool_history_ms / 10);
	checked_instant_add(
		Instant::now(),
		ip_pool_checking_period,
		"ip_pool_ban_history_s checking period",
	)?;

	Ok(())
}

fn checked_instant_add(base: Instant, duration: Duration, context: &str) -> Result<Instant, Error> {
	base.checked_add(duration).ok_or_else(|| {
		Error::DataOverflow(format!(
			"Stratum {} duration {:?} is too large for Instant deadline",
			context, duration
		))
	})
}

fn ip_pool_ban_history_ms(ip_pool_ban_history_s: u64) -> Result<u64, Error> {
	ip_pool_ban_history_s
		.checked_mul(IP_POOL_BAN_HISTORY_MS_FACTOR)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"Stratum ip_pool_ban_history_s {} seconds is too large to convert to milliseconds",
				ip_pool_ban_history_s
			))
		})
}

fn warn_ip_pool_accounting(
	action: &str,
	worker_id: usize,
	ip: &str,
	err: connections::StratumIpPoolError,
) {
	warn!(
		"Stratum {} accounting failed for worker {}, ip {}: {}",
		action, worker_id, ip, err
	);
}

fn cleanup_worker_registration(
	handler: &Handler,
	ip_pool: &connections::StratumIpPool,
	worker_id: usize,
	ip: &String,
	action: &str,
) {
	handler.workers.remove_worker(worker_id);
	let report = ip_pool.delete_worker(ip);
	if let Err(e) = report {
		warn_ip_pool_accounting(action, worker_id, ip, e);
	}
	release_worker_connection(handler);
}

fn reserve_worker_connection(handler: &Handler) -> bool {
	handler
		.worker_connections
		.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
			if count >= handler.config.workers_connection_limit {
				None
			} else {
				Some(count.saturating_add(1))
			}
		})
		.is_ok()
}

fn release_worker_connection(handler: &Handler) {
	let _ =
		handler
			.worker_connections
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
				Some(count.saturating_sub(1))
			});
}

fn trigger_worker_shutdown(workers: &WorkersList) {
	for worker in workers.get_workers_list() {
		if let Err(e) = worker.trigger_kill_switch() {
			debug!(
				"Stratum worker {} already stopped during server shutdown: {}",
				worker.id, e
			);
		}
	}
}

/// Represents a compliant JSON RPC 2.0 id.
/// Valid id: Integer, String.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(crate = "serde")]
#[serde(untagged)]
enum JsonId {
	IntId(u32),
	StrId(String),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(crate = "serde")]
struct RpcRequest {
	id: JsonId,
	jsonrpc: String,
	method: String,
	params: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(crate = "serde")]
struct RpcResponse {
	id: JsonId,
	jsonrpc: String,
	method: String,
	result: Option<Value>,
	error: Option<Value>,
}

fn rpc_request_log_metadata(request: &RpcRequest, worker_id: usize) -> String {
	format!(
		"get request: worker_id={}, method={:?}, id={:?}",
		worker_id, request.method, request.id
	)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
struct RpcError {
	code: i32,
	message: String,
}

impl RpcError {
	pub fn internal_error(err: &str) -> Self {
		error!("Stratum internal RPC error: {}", err);
		RpcError {
			code: -32603,
			message: "Internal error".to_owned(),
		}
	}
	pub fn node_is_syncing() -> Self {
		RpcError {
			code: -32000,
			message: "Node is syncing - Please wait".to_owned(),
		}
	}
	pub fn method_not_found() -> Self {
		RpcError {
			code: -32601,
			message: "Method not found".to_owned(),
		}
	}
	pub fn too_late() -> Self {
		RpcError {
			code: -32503,
			message: "Solution submitted too late".to_string(),
		}
	}
	pub fn cannot_validate() -> Self {
		RpcError {
			code: -32502,
			message: "Failed to validate solution".to_string(),
		}
	}
	pub fn too_low_difficulty() -> Self {
		RpcError {
			code: -32501,
			message: "Share rejected due to low difficulty".to_string(),
		}
	}
	pub fn invalid_request() -> Self {
		RpcError {
			code: -32600,
			message: "Invalid Request".to_string(),
		}
	}
	pub fn worker_not_logged_in() -> Self {
		RpcError {
			code: -32504,
			message: "Worker not logged in".to_string(),
		}
	}
}

impl From<RpcError> for Value {
	fn from(e: RpcError) -> Self {
		let mut error = serde_json::Map::new();
		error.insert("code".to_string(), Value::from(e.code));
		error.insert("message".to_string(), Value::from(e.message));

		Value::Object(error)
	}
}

#[derive(Debug)]
enum BroadcastJobError {
	Rpc(RpcError),
	Workers(Vec<WorkerRef>),
}

impl From<RpcError> for BroadcastJobError {
	fn from(e: RpcError) -> Self {
		BroadcastJobError::Rpc(e)
	}
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
struct LoginParams {
	login: String,
	#[allow(dead_code)]
	// Password auth is not used by the default Stratum server. We intentionally
	// do not zeroize this field here because the raw JSON request and serde
	// intermediates can also contain password copies; deployments that customize
	// miner password auth must address zeroization end-to-end.
	pass: String,
	agent: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
struct SubmitParams {
	height: u64,
	job_id: u64,
	nonce: u64,
	edge_bits: u32,
	pow: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
pub struct JobTemplate {
	height: u64,
	job_id: u64,
	difficulty: u64,
	pre_pow: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "serde")]
pub struct WorkerStatus {
	id: String,
	height: u64,
	difficulty: u64,
	accepted: u64,
	rejected: u64,
	stale: u64,
}

struct State {
	current_block_versions: Vec<Block>,
	current_block_versions_first_job_id: u64,
	next_job_id: u64,
	// to prevent the wallet from generating a new HD key derivation for each
	// iteration, we keep the returned derivation to provide it back when
	// nothing has changed. We only want to create a key_id for each new block,
	// and reuse it when we rebuild the current block to add new tx.
	current_key_id: Option<mwc_keychain::Identifier>,
	current_difficulty: u64,       // scaled
	minimum_share_difficulty: u64, // unscaled
}

impl State {
	pub fn new(minimum_share_difficulty: u64) -> Self {
		State {
			current_block_versions: Vec::new(),
			current_block_versions_first_job_id: 0,
			next_job_id: 0,
			current_key_id: None,
			current_difficulty: 0,
			minimum_share_difficulty,
		}
	}

	fn latest_job_id(&self) -> Option<u64> {
		if self.current_block_versions.is_empty() {
			None
		} else {
			self.current_block_versions_first_job_id
				.checked_add((self.current_block_versions.len() - 1) as u64)
		}
	}

	fn get_block_version(&self, job_id: u64) -> Option<Block> {
		let offset = job_id.checked_sub(self.current_block_versions_first_job_id)?;
		let offset = usize::try_from(offset).ok()?;
		self.current_block_versions.get(offset).cloned()
	}

	fn clear_block_versions(&mut self) {
		self.current_block_versions.clear();
		self.current_block_versions_first_job_id = self.next_job_id;
	}

	fn push_block_version(&mut self, block: Block) -> Result<(), Error> {
		let job_id = self.next_job_id;
		self.next_job_id = self.next_job_id.checked_add(1).ok_or_else(|| {
			Error::DataOverflow("State::push_block_version, next_job_id overflow".into())
		})?;

		if self.current_block_versions.is_empty() {
			self.current_block_versions_first_job_id = job_id;
		}
		self.current_block_versions.push(block);

		let excess = self
			.current_block_versions
			.len()
			.saturating_sub(MAX_CURRENT_BLOCK_VERSIONS);
		if excess > 0 {
			self.current_block_versions.drain(0..excess);
			self.current_block_versions_first_job_id = self
				.current_block_versions_first_job_id
				.checked_add(excess as u64)
				.ok_or_else(|| {
					Error::DataOverflow("State::push_block_version, first job id overflow".into())
				})?;
		}

		Ok(())
	}
}

fn login_worker(
	workers: &WorkersList,
	worker_id: &usize,
	params: LoginParams,
) -> Result<bool, RpcError> {
	let count_ok_login = workers
		.get_worker(worker_id)
		.map(|worker| worker.login.is_none())
		.unwrap_or(false);
	if !workers.login(worker_id, params.login, params.agent) {
		return Err(RpcError::internal_error(&format!(
			"Unable to login worker {}",
			worker_id
		)));
	}
	Ok(count_ok_login)
}

fn rpc_method_requires_login(method: &str) -> bool {
	matches!(method, "submit" | "keepalive" | "getjobtemplate" | "status")
}

fn ensure_rpc_method_authorized(
	workers: &WorkersList,
	config: &StratumServerConfig,
	method: &str,
	worker_id: usize,
	ip: &str,
) -> Result<(), RpcError> {
	if config.worker_login_timeout_ms <= 0
		|| config.ip_white_list.contains(ip)
		|| !rpc_method_requires_login(method)
	{
		return Ok(());
	}

	match workers.get_worker(&worker_id) {
		Some(worker) if worker.login.is_some() => Ok(()),
		Some(_) => Err(RpcError::worker_not_logged_in()),
		None => Err(RpcError::internal_error(&format!(
			"Unknown worker with id {}",
			worker_id
		))),
	}
}

struct Handler {
	id: String,
	workers: Arc<WorkersList>,
	sync_state: Arc<SyncState>,
	stop_state: Arc<StopState>,
	chain: Arc<mwc_chain::Chain>,
	current_state: Arc<RwLock<State>>,
	ip_pool: Arc<connections::StratumIpPool>,
	worker_connections: Arc<AtomicU32>,
	config: StratumServerConfig,
}

impl Handler {
	pub fn from_stratum(stratum: &StratumServer) -> Result<Self, Error> {
		validate_ip_pool_ban_history_s(stratum.config.ip_pool_ban_history_s)?;

		Ok(Handler {
			id: stratum.id.clone(),
			workers: Arc::new(WorkersList::new(stratum.stratum_stats.clone())),
			sync_state: stratum.sync_state.clone(),
			stop_state: stratum.stop_state.clone(),
			chain: stratum.chain.clone(),
			current_state: Arc::new(RwLock::new(State::new(
				stratum.config.minimum_share_difficulty,
			))),
			ip_pool: stratum.ip_pool.clone(),
			worker_connections: stratum.worker_connections.clone(),
			config: stratum.config.clone(),
		})
	}

	fn handle_rpc_requests(&self, request: RpcRequest, worker_id: usize, ip: &String) -> String {
		let RpcRequest {
			id,
			jsonrpc: _,
			method,
			params,
		} = request;
		if !self.workers.last_seen(worker_id) {
			let resp = RpcResponse {
				id,
				jsonrpc: String::from("2.0"),
				method,
				result: None,
				error: Some(
					RpcError::internal_error(&format!("Unknown worker with id {}", worker_id))
						.into(),
				),
			};
			return serde_json::to_string(&resp).unwrap_or("{}".to_string());
		}

		if let Err(rpc_error) =
			ensure_rpc_method_authorized(&self.workers, &self.config, &method, worker_id, ip)
		{
			let resp = RpcResponse {
				id,
				jsonrpc: String::from("2.0"),
				method,
				result: None,
				error: Some(rpc_error.into()),
			};
			return serde_json::to_string(&resp).unwrap_or("{}".to_string());
		}

		// Call the handler function for requested method
		let response = match method.as_str() {
			"login" => match self.handle_login(params, &worker_id) {
				Ok((r, count_ok_login)) => {
					if count_ok_login {
						if let Err(e) = self.ip_pool.report_ok_login(ip) {
							warn_ip_pool_accounting("ok-login", worker_id, ip, e);
						}
					}
					Ok(r)
				}
				Err(e) => {
					if let Err(accounting_err) = self.ip_pool.report_fail_login(ip) {
						warn_ip_pool_accounting("failed-login", worker_id, ip, accounting_err);
					}
					Err(e)
				}
			},
			"submit" => {
				secp_static::with_commit_mut(
					|_| RpcError::internal_error("unable create secp context"),
					|secp| {
						let res = self.handle_submit(secp, params, worker_id);
						// this key_id has been used now, reset
						let res = match res {
							Ok(ok) => {
								if let Err(accounting_err) = self.ip_pool.report_ok_shares(ip) {
									warn_ip_pool_accounting(
										"ok-share",
										worker_id,
										ip,
										accounting_err,
									);
								}
								Ok(ok)
							}
							Err(rpc_err) => {
								if rpc_err.code != RpcError::too_late().code {
									let report = self.ip_pool.report_fail_noise(ip);
									if let Err(accounting_err) = report {
										warn_ip_pool_accounting(
											"bad-traffic",
											worker_id,
											ip,
											accounting_err,
										);
									}
								};
								Err(rpc_err)
							}
						};
						if let Ok((_, true)) = res {
							self.current_state.write().current_key_id = None;
						}
						res.map(|(v, _)| v)
					},
				)
			}
			"keepalive" => self.handle_keepalive(),
			"getjobtemplate" => {
				if self.sync_state.is_syncing() {
					Err(RpcError::node_is_syncing())
				} else {
					self.handle_getjobtemplate()
				}
			}
			"status" => self.handle_status(worker_id),
			_ => {
				if let Err(accounting_err) = self.ip_pool.report_fail_noise(ip) {
					warn_ip_pool_accounting("bad-traffic", worker_id, ip, accounting_err);
				}
				// Called undefined method
				Err(RpcError::method_not_found())
			}
		};

		// Package the reply as RpcResponse json
		let resp = match response {
			Err(rpc_error) => RpcResponse {
				id,
				jsonrpc: String::from("2.0"),
				method,
				result: None,
				error: Some(rpc_error.into()),
			},
			Ok(response) => RpcResponse {
				id,
				jsonrpc: String::from("2.0"),
				method,
				result: Some(response),
				error: None,
			},
		};
		serde_json::to_string(&resp).unwrap_or("{}".to_string())
	}

	fn handle_login(
		&self,
		params: Option<Value>,
		worker_id: &usize,
	) -> Result<(Value, bool), RpcError> {
		// Note !!!! self.workers.login HAS to be there.
		let params: LoginParams = parse_params(params)?;
		let count_ok_login = login_worker(&self.workers, worker_id, params)?;
		return Ok(("ok".into(), count_ok_login));
	}

	// Handle KEEPALIVE message
	fn handle_keepalive(&self) -> Result<Value, RpcError> {
		return Ok("ok".into());
	}

	fn handle_status(&self, worker_id: usize) -> Result<Value, RpcError> {
		// Return worker status in json for use by a dashboard or healthcheck.
		let stats = self
			.workers
			.get_stats(worker_id)
			.ok_or_else(|| RpcError::internal_error("Unknown worker"))?;

		let height = self
			.current_state
			.read_recursive()
			.current_block_versions
			.last()
			.ok_or_else(|| RpcError::internal_error("No blocks in task buffer"))?
			.header
			.height;

		let status = WorkerStatus {
			id: stats.id.clone(),
			height,
			difficulty: stats.pow_difficulty,
			accepted: stats.num_accepted,
			rejected: stats.num_rejected,
			stale: stats.num_stale,
		};
		let response = serde_json::to_value(&status).map_err(|e| {
			RpcError::internal_error(&format!("Unable to serialize worker status: {}", e))
		})?;
		Ok(response)
	}

	fn update_worker_stats(
		&self,
		worker_id: usize,
		f: impl FnOnce(&mut WorkerStats),
	) -> Result<(), RpcError> {
		if self.workers.update_stats(worker_id, f) {
			Ok(())
		} else {
			Err(RpcError::internal_error(&format!(
				"Unknown worker with id {}",
				worker_id
			)))
		}
	}

	// Handle GETJOBTEMPLATE message
	fn handle_getjobtemplate(&self) -> Result<Value, RpcError> {
		// Build a JobTemplate from a BlockHeader and return JSON
		let job_template = self.build_block_template()?;
		let response = serde_json::to_value(&job_template).map_err(|e| {
			RpcError::internal_error(&format!("Unable to serialize job template, {}", e))
		})?;
		debug!(
			"(Server ID: {}) sending block {} with id {} to single worker",
			self.id, job_template.height, job_template.job_id,
		);
		return Ok(response);
	}

	// Build and return a JobTemplate for mining the current block
	fn build_block_template(&self) -> Result<JobTemplate, RpcError> {
		let (bh, job_id, difficulty) = {
			let state = self.current_state.read_recursive();

			(
				state
					.current_block_versions
					.last()
					.ok_or_else(|| RpcError::internal_error("Empty block task buffer"))?
					.header
					.clone(),
				state
					.latest_job_id()
					.ok_or_else(|| RpcError::internal_error("Empty block task buffer"))?,
				state.minimum_share_difficulty,
			)
		};

		// Serialize the block header into pre and post nonce strings
		let mut header_buf = vec![];
		{
			let mut writer = ser::BinWriter::default(self.chain.get_context_id(), &mut header_buf);
			bh.write_pre_pow(&mut writer).map_err(|e| {
				RpcError::internal_error(&format!("Unable write into buffer, {}", e))
			})?;
			bh.pow.write_pre_pow(&mut writer).map_err(|e| {
				RpcError::internal_error(&format!("Unable write into buffer, {}", e))
			})?;
		}
		let pre_pow = mwc_util::to_hex(&header_buf);
		let job_template = JobTemplate {
			height: bh.height,
			job_id,
			difficulty,
			pre_pow,
		};
		return Ok(job_template);
	}
	// Handle SUBMIT message
	// params contains a solved block header
	// We accept and log valid shares of all difficulty above configured minimum
	// Accepted shares that are full solutions will also be submitted to the
	// network
	fn handle_submit(
		&self,
		secp: &mut Secp256k1,
		params: Option<Value>,
		worker_id: usize,
	) -> Result<(Value, bool), RpcError> {
		// Validate parameters
		let params: SubmitParams = parse_params(params)?;

		let (b, header_height, minimum_share_difficulty, current_difficulty) = {
			let state = self.current_state.read_recursive();

			(
				state.get_block_version(params.job_id),
				state
					.current_block_versions
					.last()
					.ok_or_else(|| RpcError::internal_error("Empty block task buffer"))?
					.header
					.height,
				state.minimum_share_difficulty,
				state.current_difficulty,
			)
		};

		// Find the correct version of the block to match this header
		if params.height != header_height || b.is_none() {
			// Return error status
			error!(
				"(Server ID: {}) Share at height {}, edge_bits {}, nonce {}, job_id {} submitted too late",
				self.id, params.height, params.edge_bits, params.nonce, params.job_id,
			);
			self.update_worker_stats(worker_id, |ws| {
				ws.num_stale = ws.num_stale.saturating_add(1)
			})?;
			return Err(RpcError::too_late());
		}

		let scaled_share_difficulty: u64;
		let unscaled_share_difficulty: u64;
		let mut share_is_block = false;

		let mut b: Block = b
			.ok_or_else(|| RpcError::internal_error("Unable to build a block"))?
			.clone();
		let context_id = self.chain.get_context_id();
		// Reconstruct the blocks header with this nonce and pow added
		let edge_bits_u8 = u8::try_from(params.edge_bits).map_err(|_| {
			error!(
				"(Server ID: {}) Invalid submit edge_bits {} from worker {}",
				self.id, params.edge_bits, worker_id,
			);
			RpcError::invalid_request()
		})?;
		b.header.pow.proof.edge_bits = edge_bits_u8;
		b.header.pow.nonce = params.nonce;
		b.header.pow.proof.nonces = params.pow;
		let block_hash = match b.hash(context_id) {
			Ok(hash) => hash,
			Err(e) => {
				error!(
					"(Server ID: {}) Failed to hash submitted share at height {}, edge_bits {}, nonce {}, job_id {}: {}",
					self.id, params.height, params.edge_bits, params.nonce, params.job_id, e,
				);
				self.update_worker_stats(worker_id, |worker_stats| {
					worker_stats.num_rejected = worker_stats.num_rejected.saturating_add(1)
				})?;
				return Err(RpcError::cannot_validate());
			}
		};

		if !b.header.pow.is_primary(context_id) && !b.header.pow.is_secondary() {
			// Return error status
			error!(
				"(Server ID: {}) Failed to validate solution at height {}, hash {}, edge_bits {}, nonce {}, job_id {}: cuckoo size too small",
				self.id, params.height, block_hash, params.edge_bits, params.nonce, params.job_id,
			);
			self.update_worker_stats(worker_id, |worker_stats| {
				worker_stats.num_rejected = worker_stats.num_rejected.saturating_add(1)
			})?;
			return Err(RpcError::cannot_validate());
		}

		// Get share difficulty values
		scaled_share_difficulty = match b.header.pow.to_difficulty(context_id, b.header.height) {
			Ok(difficulty) => difficulty.to_num(),
			Err(e) => {
				error!(
					"(Server ID: {}) Failed to calculate share difficulty at height {}, hash {}, edge_bits {}, nonce {}, job_id {}: {}",
					self.id,
					params.height,
					block_hash,
					params.edge_bits,
					params.nonce,
					params.job_id,
					e,
				);
				self.update_worker_stats(worker_id, |worker_stats| {
					worker_stats.num_rejected = worker_stats.num_rejected.saturating_add(1)
				})?;
				return Err(RpcError::cannot_validate());
			}
		};
		unscaled_share_difficulty = match b.header.pow.to_unscaled_difficulty() {
			Ok(difficulty) => difficulty.to_num(),
			Err(e) => {
				error!(
					"(Server ID: {}) Failed to calculate unscaled share difficulty at height {}, hash {}, edge_bits {}, nonce {}, job_id {}: {}",
					self.id,
					params.height,
					block_hash,
					params.edge_bits,
					params.nonce,
					params.job_id,
					e,
				);
				self.update_worker_stats(worker_id, |worker_stats| {
					worker_stats.num_rejected = worker_stats.num_rejected.saturating_add(1)
				})?;
				return Err(RpcError::cannot_validate());
			}
		};
		// If the difficulty is high enough, submit it (which also validates it)
		if scaled_share_difficulty >= current_difficulty {
			// This is a full solution, submit it to the network
			let res = self.chain.process_block(
				secp,
				b.clone(),
				mwc_chain::Options::MINE,
				std::collections::HashSet::new(),
			);
			if let Err(e) = res {
				// Return error status
				error!(
					"(Server ID: {}) Failed to validate solution at height {}, hash {}, edge_bits {}, nonce {}, job_id {}, {}",
					self.id,
					params.height,
					block_hash,
					params.edge_bits,
					params.nonce,
					params.job_id,
					e,
				);
				self.update_worker_stats(worker_id, |worker_stats| {
					worker_stats.num_rejected = worker_stats.num_rejected.saturating_add(1)
				})?;
				return Err(RpcError::cannot_validate());
			}
			share_is_block = true;
			self.update_worker_stats(worker_id, |worker_stats| {
				worker_stats.num_blocks_found = worker_stats.num_blocks_found.saturating_add(1)
			})?;
			self.workers.increment_block_found();
			// Log message to make it obvious we found a block
			let stats = self.workers.get_stats(worker_id).ok_or_else(|| {
				RpcError::internal_error(&format!("Unknown worker with id {}", worker_id))
			})?;
			warn!(
				"(Server ID: {}) Solution Found for block {}, hash {} - Yay!!! Worker ID: {}, blocks found: {}, shares: {}",
				self.id, params.height,
				block_hash,
				stats.id,
				stats.num_blocks_found,
				stats.num_accepted,
			);
		} else {
			// Note:  state.minimum_share_difficulty is unscaled
			//        state.current_difficulty is scaled
			// The minimum share difficulty only filters non-block shares.
			if unscaled_share_difficulty < minimum_share_difficulty {
				// Return error status
				error!(
					"(Server ID: {}) Share at height {}, hash {}, edge_bits {}, nonce {}, job_id {} rejected due to low difficulty: {}/{}",
					self.id, params.height, block_hash, params.edge_bits, params.nonce, params.job_id, unscaled_share_difficulty, minimum_share_difficulty,
				);
				self.update_worker_stats(worker_id, |worker_stats| {
					worker_stats.num_rejected = worker_stats.num_rejected.saturating_add(1)
				})?;
				return Err(RpcError::too_low_difficulty());
			}

			// Do some validation but dont submit
			let res = pow::verify_size(context_id, &b.header);
			if res.is_err() {
				// Return error status
				error!(
					"(Server ID: {}) Failed to validate share at height {}, hash {}, edge_bits {}, nonce {}, job_id {}. {:?}",
					self.id,
					params.height,
					block_hash,
					params.edge_bits,
					b.header.pow.nonce,
					params.job_id,
					res,
				);
				self.update_worker_stats(worker_id, |worker_stats| {
					worker_stats.num_rejected = worker_stats.num_rejected.saturating_add(1)
				})?;
				return Err(RpcError::cannot_validate());
			}
		}
		// Log this as a valid share
		self.workers.update_edge_bits(edge_bits_u8 as u16);
		if let Some(worker) = self.workers.get_worker(&worker_id) {
			let submitted_by = match worker.login {
				None => worker.id.to_string(),
				Some(login) => login.clone(),
			};

			info!(
				"(Server ID: {}) Got share at height {}, hash {}, edge_bits {}, nonce {}, job_id {}, difficulty {}/{}, submitted by {}",
				self.id,
				b.header.height,
				block_hash,
				b.header.pow.proof.edge_bits,
				b.header.pow.nonce,
				params.job_id,
				scaled_share_difficulty,
				current_difficulty,
				submitted_by,
			);
		}

		self.update_worker_stats(worker_id, |worker_stats| {
			worker_stats.num_accepted = worker_stats.num_accepted.saturating_add(1)
		})?;
		let submit_response = if share_is_block {
			format!("blockfound - {}", block_hash.to_hex())
		} else {
			"ok".to_string()
		};
		return Ok((
			serde_json::to_value(submit_response).unwrap_or(Value::Null),
			share_is_block,
		));
	} // handle submit a solution

	fn broadcast_job(&self) -> Result<(), BroadcastJobError> {
		debug!("broadcast job");
		// Package new block into RpcRequest
		let job_template = self.build_block_template()?;
		let job_template_value = serde_json::to_value(&job_template).map_err(|e| {
			RpcError::internal_error(&format!("Unable to serialize job template, {}", e))
		})?;
		let job_request = RpcRequest {
			id: JsonId::StrId(String::from("Stratum")),
			jsonrpc: String::from("2.0"),
			method: String::from("job"),
			params: Some(job_template_value),
		};
		let job_request_json = serde_json::to_string(&job_request).map_err(|e| {
			RpcError::internal_error(&format!("Unable to serialize job request, {}", e))
		})?;
		debug!(
			"(Server ID: {}) sending block {} with id {} to stratum clients",
			self.id, job_template.height, job_template.job_id,
		);
		self.workers
			.broadcast(job_request_json)
			.map_err(BroadcastJobError::Workers)
	}

	fn disconnect_workers(&self, worker_refs: Vec<WorkerRef>, reason: &str) {
		for worker_ref in worker_refs {
			match self.workers.get_worker(&worker_ref.id) {
				Some(worker) if worker.connection_id == worker_ref.connection_id => {
					warn!(
						"(Server ID: {}) Disconnecting worker {} connection {}: {}",
						self.id, worker_ref.id, worker_ref.connection_id, reason
					);
					if let Err(e) = worker.trigger_kill_switch() {
						error!(
							"(Server ID: {}) Failed to disconnect worker {} connection {}: {}",
							self.id, worker_ref.id, worker_ref.connection_id, e
						);
					}
				}
				Some(worker) => {
					debug!(
						"(Server ID: {}) Worker {} connection {} was replaced by connection {}; skipping disconnect: {}",
						self.id, worker_ref.id, worker_ref.connection_id, worker.connection_id, reason
					);
				}
				None => {
					debug!(
						"(Server ID: {}) Worker {} connection {} already disconnected: {}",
						self.id, worker_ref.id, worker_ref.connection_id, reason
					);
				}
			}
		}
	}

	pub fn run(&self, config: &StratumServerConfig, tx_pool: &ServerTxPool) -> Result<(), Error> {
		debug!("Run main loop");
		let mut block_rebuild_deadline = Instant::now();
		let head = self.chain.head().map_err(|e| {
			Error::ServerError(format!("StratumServer::run, unable to get head, {}", e))
		})?;
		let mut current_hash = head.prev_block_h;

		let worker_checking_period_ms = if self.config.worker_login_timeout_ms <= 0 {
			1000
		} else {
			min(1000, self.config.worker_login_timeout_ms as u64)
		};
		let worker_checking_period = Duration::from_millis(worker_checking_period_ms);
		let ip_pool_history_ms = ip_pool_ban_history_ms(self.config.ip_pool_ban_history_s)?;
		let ip_pool_history = Duration::from_millis(ip_pool_history_ms);
		let ip_pool_checking_period = Duration::from_millis(ip_pool_history_ms / 10);

		let mut next_worker_checking = checked_instant_add(
			Instant::now(),
			worker_checking_period,
			"worker checking period",
		)?;
		let mut next_ip_pool_checking = checked_instant_add(
			Instant::now(),
			ip_pool_checking_period,
			"ip pool checking period",
		)?;
		let mining_wallet_client =
			HttpClient::new(self.chain.get_context_id(), Duration::from_secs(5), None);

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).map_err(|e| {
			Error::ServerError(format!(
				"StratumServer::run, unable create secp instance, {}",
				e
			))
		})?;

		loop {
			if self.stop_state.is_stopped() {
				break;
			}

			// get the latest chain state
			let head = self.chain.head().map_err(|e| {
				Error::ServerError(format!("StratumServer::run, unable to get head, {}", e))
			})?;
			let latest_hash = head.last_block_h;

			// Build a new block if there is at least one worker and
			// There is a new block on the chain or its time to rebuild
			// the current one to include new transactions
			if current_hash != latest_hash || Instant::now() >= block_rebuild_deadline {
				{
					debug!("resend updated block");
					let wallet_listener_url = if !config.burn_reward {
						Some(config.wallet_listener_url.clone())
					} else {
						None
					};
					let current_key_id = {
						let state = self.current_state.read_recursive();
						state.current_key_id.clone()
					};
					// Build the new block (version)
					let built_block = match mine_block::get_block(
						&mut secp,
						&self.chain,
						tx_pool,
						current_key_id,
						wallet_listener_url,
						&mining_wallet_client,
						&self.stop_state,
					) {
						Ok(built_block) => built_block,
						Err(e) => {
							error!("Build block error {}", e);
							continue;
						}
					};
					let new_parent_hash = built_block.parent_hash;
					let clear_blocks = current_hash != new_parent_hash;

					let current_difficulty = {
						let mut state = self.current_state.write();

						// scaled difficulty
						state.current_difficulty = (built_block.block.header.total_difficulty()
							- built_block.parent_header.total_difficulty())
						.map_err(|e| {
							Error::DataOverflow(format!(
								"StratumServer::run, unable to find current_difficulty, {}",
								e
							))
						})?
						.to_num();

						state.current_key_id = built_block.fees.key_id();

						current_hash = new_parent_hash;
						// set the minimum acceptable share unscaled difficulty for this block
						state.minimum_share_difficulty =
							cmp::min(config.minimum_share_difficulty, state.current_difficulty);

						state.current_difficulty
					};

					// set a new deadline for rebuilding with fresh transactions
					block_rebuild_deadline = checked_instant_add(
						Instant::now(),
						Duration::from_secs(u64::from(config.attempt_time_per_block)),
						"block rebuild deadline",
					)?;

					// Update the mining stats
					self.workers
						.update_block_height(built_block.block.header.height);
					self.workers.update_network_difficulty(current_difficulty);
					self.workers
						.update_network_hashrate(self.chain.get_context_id())
						.map_err(|e| {
							Error::ServerError(format!(
								"StratumServer::run, unable to update network hashrate, {}",
								e
							))
						})?;

					{
						let mut state = self.current_state.write();

						// If this is a new block we will clear the current_block version history
						if clear_blocks {
							state.clear_block_versions();
						}
						// Add this new block candidate onto our list of block versions for this height
						state.push_block_version(built_block.block)?;
					}
				}
				// Send this job to all connected workers
				match self.broadcast_job() {
					Ok(()) => {}
					Err(BroadcastJobError::Workers(worker_ids)) => {
						error!(
							"Stratum failed to broadcast job to workers {:?}; disconnecting",
							worker_ids
						);
						self.disconnect_workers(worker_ids, "job broadcast queue is unavailable");
					}
					Err(BroadcastJobError::Rpc(e)) => {
						// The caller has no useful recovery path for job build/serialization
						// failures here, so logging the error is sufficient.
						error!("Stratum failed to broadcast job, {:?}", e);
					}
				}
			}

			// Check workers login statuses and do IP pool maintaince
			let cur_time = Instant::now();

			if cur_time > next_worker_checking {
				next_worker_checking = checked_instant_add(
					cur_time,
					worker_checking_period,
					"worker checking period",
				)?;

				let enforce_login_timeout = self.config.worker_login_timeout_ms > 0;
				if config.ip_tracking || enforce_login_timeout {
					let mut banned_ips = if config.ip_tracking {
						self.ip_pool.get_banned_ips()
					} else {
						Default::default()
					};

					if config.ip_tracking {
						let mut extra_con = self
							.worker_connections
							.load(Ordering::Relaxed)
							.saturating_sub(self.config.workers_connection_limit);

						if extra_con > 0 {
							// we need to limit slash some connections.
							// Let's do that with least profitable IP adresses
							let mut ip_prof = self.ip_pool.get_ip_profitability();
							// Last to del first
							ip_prof.sort_by(|a, b| b.1.cmp(&a.1));

							while extra_con > 0 && !ip_prof.is_empty() {
								let prof = ip_prof.pop().ok_or_else(|| {
									Error::ServerError(
										"StratumServer::run, IP pool is empty".into(),
									)
								})?;
								warn!("Stratum need to clean {} connections. Will retire {} workers from IP {}", extra_con, prof.2, prof.0);
								extra_con = extra_con.saturating_sub(prof.2);
								banned_ips.insert(prof.0);
							}
						}
					}

					let login_timeout = if enforce_login_timeout {
						Duration::from_millis(self.config.worker_login_timeout_ms as u64)
					} else {
						Duration::ZERO
					};

					// we are working with a snapshot. Worker can be changed during the workflow.
					for mut w in self.workers.get_workers_list() {
						if self.config.ip_white_list.contains(&w.ip) {
							continue; // skipping all while listed workers. They can do whatever that want.
						}

						if enforce_login_timeout
							&& w.login.is_none() && !w.authenticated
							&& w.create_time.elapsed() > login_timeout
						{
							let Some(w) = self
								.workers
								.mark_login_timeout_accounted(w.id, w.connection_id)
							else {
								continue;
							};
							// Mark the login timeout once before disconnect; cleanup only
							// removes active worker accounting.
							if config.ip_tracking {
								if let Err(e) = self.ip_pool.report_fail_login(&w.ip) {
									warn_ip_pool_accounting("login-timeout", w.id, &w.ip, e);
								}
							}
							warn!(
								"Worker id:{} ip:{} disconnected because of login timeout",
								w.id, w.ip
							);
							if let Err(e) = w.trigger_kill_switch() {
								error!(
									"Failed to disconnect worker {} after login timeout: {}",
									w.id, e
								);
							}
						} else if config.ip_tracking && banned_ips.contains(&w.ip) {
							// Cleaning all workers from the ban
							warn!(
								"Worker id:{} ip:{} banned because IP is in the kick out list",
								w.id, w.ip
							);

							// We don't want double ban just connected workers. Assume they are authenticated
							w.authenticated = true;
							if !self.workers.update_worker(&w) {
								error!("Stratum: failed to update worker {}", w.id);
							}

							if let Err(e) = w.trigger_kill_switch() {
								error!("Failed to disconnect worker {} after IP ban: {}", w.id, e);
							}
						}
					}
				}
			} else if cur_time > next_ip_pool_checking {
				next_ip_pool_checking = checked_instant_add(
					cur_time,
					ip_pool_checking_period,
					"ip pool checking period",
				)?;
				self.ip_pool.retire_old_events(ip_pool_history);
			}

			// sleep before restarting loop
			thread::sleep(Duration::from_millis(5));
		} // Main Loop
		info!("Stratum server exited");
		Ok(())
	}
}

// ----------------------------------------
// Worker Factory Thread Function
// Returned runtime must be kept for a server lifetime
fn accept_connections(
	stop_state: Arc<StopState>,
	listen_addr: SocketAddr,
	handler: Arc<Handler>,
	startup_tx: std_mpsc::Sender<Result<(), String>>,
) {
	info!("Start tokio stratum server");

	if !handler.config.ip_white_list.is_empty() {
		warn!(
			"Stratum miners IP white list: {:?}",
			handler.config.ip_white_list
		);
	}
	if !handler.config.ip_black_list.is_empty() {
		warn!(
			"Stratum miners IP black list: {:?}",
			handler.config.ip_black_list
		);
	}

	if handler.config.ip_tracking {
		warn!("Stratum miners IP tracking is ACTIVE. Parameters - connection_limit:{} connection_pace(ms):{} ban_action_limit:{} shares_weight:{} login_timeout(ms):{} ban_history(ms):{}",
			  handler.config.workers_connection_limit,
			  handler.config.connection_pace_ms,
			  handler.config.ban_action_limit,
			  handler.config.shares_weight,
			  handler.config.worker_login_timeout_ms,
			  handler.config.ip_pool_ban_history_s,
		);
	} else {
		warn!("Stratum miners IP tracking is disabled. You might enable it if you are running public mining pool and expecting any attacks.");
	}

	let runtime_startup_tx = startup_tx.clone();
	let task = async move {
		let listener = match TcpListener::bind(&listen_addr).await {
			Ok(listener) => {
				let _ = startup_tx.send(Ok(()));
				listener
			}
			Err(e) => {
				let msg = format!("Failed to bind to listen address {}, {}", listen_addr, e);
				error!("Stratum: {}", msg);
				let _ = startup_tx.send(Err(msg));
				return;
			}
		};

		let mut accept_error_backoff_ms = STRATUM_ACCEPT_ERROR_INITIAL_BACKOFF_MS;
		let workers_for_shutdown = handler.workers.clone();
		let server = async_stream::stream! {
			loop {
				if stop_state.is_stopped() {
					trigger_worker_shutdown(&workers_for_shutdown);
					break;
				}

				match tokio::time::timeout(Duration::from_secs(1), listener.accept()).await {
					Ok(Ok((socket, peer_addr))) => {
						if stop_state.is_stopped() {
							drop(socket);
							trigger_worker_shutdown(&workers_for_shutdown);
							break;
						}
						accept_error_backoff_ms = STRATUM_ACCEPT_ERROR_INITIAL_BACKOFF_MS;
						yield (socket, peer_addr);
					}
					Ok(Err(e)) => {
						let backoff = Duration::from_millis(accept_error_backoff_ms);
						error!("accept error = {:?}; backing off for {:?}", e, backoff);
						tokio::time::sleep(backoff).await;
						accept_error_backoff_ms = accept_error_backoff_ms
							.saturating_mul(2)
							.min(STRATUM_ACCEPT_ERROR_MAX_BACKOFF_MS);
						continue;
					}
					Err(_) => {
						// timeout
						accept_error_backoff_ms = STRATUM_ACCEPT_ERROR_INITIAL_BACKOFF_MS;
						continue;
					}
				}
			}
		}
		.for_each(move |(socket, peer_addr)| {
			let ip = peer_addr.ip().to_string();

			let handler = handler.clone();

				async move {
					let config = &handler.config;

					let ip_is_white_listed = config.ip_white_list.contains(&ip);
					let accepting_connection = if ip_is_white_listed {
						true
					} else if config.ip_black_list.contains(&ip) {
						warn!(
							"Stratum rejecting new connection for {}, it is in black list",
							ip
						);
						false
					} else if config.ip_tracking && handler.ip_pool.is_banned(&ip, true) {
						warn!("Rejecting connection from ip {} because ip_tracking is active and that ip is banned.", ip);
						false
					} else {
						true
					};

					if !accepting_connection {
						let mut socket = socket;
						let _ = socket.shutdown().await;
						return;
					}

					if !reserve_worker_connection(&handler) {
						warn!(
							"Stratum rejecting new connection from {} because workers_connection_limit {} is reached",
							ip, config.workers_connection_limit
						);
						let mut socket = socket;
						let _ = socket.shutdown().await;
						return;
					}

					if ip_is_white_listed {
						info!(
							"Stratum accepting new connection for {}, it is in white list",
							ip
						);
					} else {
						info!("Stratum accepting new connection for {}", ip);
					}

					let ip_pool = handler.ip_pool.clone();

					// Worker IO channels
					let (tx, mut rx) = mpsc::channel(WORKER_RESPONSE_QUEUE_CAPACITY);

					// Worker killer switch
					let (kill_switch, kill_switch_receiver) = oneshot::channel::<()>();

					let worker_id = match handler.workers.add_worker(ip.clone(), tx, kill_switch) {
						Ok(worker_id) => worker_id,
						Err(e) => {
							error!("Unable to register stratum worker for ip {}: {}", ip, e);
							release_worker_connection(&handler);
							let mut socket = socket;
							let _ = socket.shutdown().await;
							return;
						}
					};
					info!("Worker {} connected", worker_id);
					ip_pool.add_worker(&ip);

					let framed = Framed::new(
						socket,
						LinesCodec::new_with_max_length(MAX_STRATUM_LINE_LENGTH),
					);
                    let (writer, mut reader) = framed.split();
					let writer = Arc::new(Mutex::new(writer));

                    let h = handler.clone();
                    let workers = h.workers.clone();
                    let ip_clone = ip.clone();
                    let ip_clone2 = ip.clone();
                    let ip_pool_clone2 = ip_pool.clone();
                    let ip_pool_clone3 = ip_pool.clone();
                    let ip_disconnect = ip.clone();
                    let ip_pool_disconnect = ip_pool.clone();

					let read = async move {
						loop {
							let next = tokio::time::timeout(
								Duration::from_secs(300), // waiting any response from worker for 5 minutes. Should be enough
								reader.try_next(),
							)
							.await;

							match next {
								Ok(Ok(Some(line))) => {
									if !line.is_empty() {
										let request = serde_json::from_str(&line).map_err(|e| {
											let report = ip_pool_clone3.report_fail_noise(&ip_clone2);
											if let Err(accounting_err) = report {
												warn_ip_pool_accounting(
													"bad-traffic",
													worker_id,
													&ip_clone2,
													accounting_err,
												);
											}
											error!("error serializing line: {}", e)
										})?;
										debug!("{}", rpc_request_log_metadata(&request, worker_id));
										let resp = h.handle_rpc_requests(request, worker_id, &ip_clone);
										if !workers.send_to(&worker_id, resp) {
											warn!(
												"Unable to send response to worker {}; disconnecting",
												worker_id
											);
											break;
										}
									}
								}
								Ok(Ok(None)) => {
									// Peer closed
									break;
								}
								Ok(Err(e)) => {
									let report = ip_pool_clone2.report_fail_noise(&ip_clone2);
									if let Err(accounting_err) = report {
										warn_ip_pool_accounting(
											"bad-traffic",
											worker_id,
											&ip_clone2,
											accounting_err,
										);
									}
									error!("error processing request to stratum, {}", e);
									break;
								}
								Err(_) => {
									// Idle timeout, drop connection to avoid CLOSE_WAIT leaks
									warn!(
										"Stratum read idle timeout for worker {}, ip {}",
										worker_id, ip_clone2
									);
									break;
								}
							}
						}

						Result::<_, ()>::Ok(())
					};

					let writer2 = writer.clone();
					let write = async move {
						while let Some(line) = rx.recv().await {
							// No need to add line separator for the client, because
							// Frames with LinesCodec does that.
							tokio::time::timeout(
								Duration::from_secs(10),
								writer2.lock().await.send(line),
							)
								.await
								.map_err(|_| {
									error!(
										"stratum cannot send data to worker, send timed out"
									)
								})?
								.map_err(|e| {
									error!("stratum cannot send data to worker, {}", e)
								})?;
						}
						Result::<_, ()>::Ok(())
					};

					let task_handler = handler.clone();
					let task_ip_pool_disconnect = ip_pool_disconnect.clone();
					let task_ip_disconnect = ip_disconnect.clone();
					let task_writer = writer.clone();
					let task = async move {
						pin_mut!(read, write);
						let rw = futures::future::select(read, write);
						futures::future::select(rw, kill_switch_receiver).await;
						let _ = task_writer.lock().await.close().await;
						cleanup_worker_registration(
							&task_handler,
							&task_ip_pool_disconnect,
							worker_id,
							&task_ip_disconnect,
							"worker disconnect",
						);
						info!("Worker {} disconnected", worker_id);
					};
					match global_runtime() {
						Ok(runtime) => {
							runtime.spawn(task);
						}
						Err(e) => {
							error!("Unable to spawn stratum worker task: {}", e);
							drop(task);
							let _ = writer.lock().await.close().await;
							cleanup_worker_registration(
								&handler,
								&ip_pool,
								worker_id,
								&ip,
								"worker spawn failure",
							);
						}
					}
                }
            });
		server.await
	};

	if let Err(e) = run_global_async_block(task) {
		let msg = format!("Unable to accept stratum connection, {}", e);
		error!("{}", msg);
		let _ = runtime_startup_tx.send(Err(msg));
	}
}

// ----------------------------------------
// Mwc Stratum Server

pub struct StratumServer {
	id: String,
	config: StratumServerConfig,
	chain: Arc<mwc_chain::Chain>,
	pub tx_pool: ServerTxPool,
	sync_state: Arc<SyncState>,
	stop_state: Arc<StopState>,
	stratum_stats: Arc<StratumStats>,
	ip_pool: Arc<connections::StratumIpPool>,
	worker_connections: Arc<AtomicU32>,
	startup_status_tx: Option<StratumStartupStatusTx>,
}

impl StratumServer {
	/// Creates a new Stratum Server.
	pub fn new(
		config: StratumServerConfig,
		chain: Arc<mwc_chain::Chain>,
		tx_pool: ServerTxPool,
		stratum_stats: Arc<StratumStats>,
		ip_pool: Arc<connections::StratumIpPool>,
		sync_state: Arc<SyncState>,
		stop_state: Arc<StopState>,
	) -> StratumServer {
		StratumServer {
			id: String::from("0"),
			config,
			chain,
			tx_pool,
			sync_state: sync_state,
			stratum_stats: stratum_stats,
			ip_pool,
			worker_connections: Arc::new(AtomicU32::new(0)),
			stop_state,
			startup_status_tx: None,
		}
	}

	fn join_listener_thread(&self, listener_th: thread::JoinHandle<()>) -> Result<(), Error> {
		let result = if let Err(panic) = listener_th.join() {
			let panic_msg = panic
				.downcast_ref::<&str>()
				.map(|msg| (*msg).to_string())
				.or_else(|| panic.downcast_ref::<String>().cloned())
				.unwrap_or_else(|| "unknown panic payload".to_string());
			error!("Stratum listener thread panicked: {}", panic_msg);
			self.stop_state.stop();
			Err(Error::ServerError(format!(
				"Stratum listener thread panicked: {}",
				panic_msg
			)))
		} else {
			Ok(())
		};

		self.stratum_stats
			.is_running
			.store(false, Ordering::Relaxed);
		result
	}

	pub(crate) fn set_startup_status_tx(&mut self, startup_status_tx: StratumStartupStatusTx) {
		self.startup_status_tx = Some(startup_status_tx);
	}

	/// "main()" - Starts the stratum-server. Creates a thread to listen for
	/// connections, then enters a loop, building a new block on top of the
	/// existing chain anytime required and sending that to the connected
	/// stratum miner, proxy, or pool, and accepts full solutions to be
	/// submitted.
	pub fn run_loop(&mut self, proof_size: usize) -> Result<(), Error> {
		let startup_status_tx = self.startup_status_tx.take();
		self.run_loop_impl(proof_size, startup_status_tx)
	}

	fn run_loop_impl(
		&mut self,
		proof_size: usize,
		mut startup_status_tx: Option<StratumStartupStatusTx>,
	) -> Result<(), Error> {
		info!(
			"(Server ID: {}) Starting stratum server with proof_size = {}",
			self.id, proof_size
		);

		let stratum_server_addr = match &self.config.stratum_server_addr {
			Some(adr) => adr.clone(),
			None => {
				let err =
					Error::Config("Invalid config. 'stratum_server_addr' is not defined.".into());
				error!("{}", err);
				report_startup_status(&mut startup_status_tx, Err(err.to_string()));
				return Err(err);
			}
		};

		let listen_addr = match stratum_server_addr.parse() {
			Ok(addr) => addr,
			Err(e) => {
				let err = Error::Config(format!(
					"Stratum: Incorrect address {}, exiting...  Error: {}",
					stratum_server_addr, e
				));
				error!("{}", err);
				report_startup_status(&mut startup_status_tx, Err(err.to_string()));
				return Err(err);
			}
		};

		let handler = match Handler::from_stratum(&self) {
			Ok(handler) => Arc::new(handler),
			Err(e) => {
				error!("Invalid stratum config, exiting... {}", e);
				report_startup_status(&mut startup_status_tx, Err(e.to_string()));
				return Err(e);
			}
		};
		let h = handler.clone();

		let stop_state = self.stop_state.clone();
		let (startup_tx, startup_rx) = std_mpsc::channel();
		let listener_th = thread::Builder::new()
			.name("stratum_listener".to_string())
			.spawn(move || {
				accept_connections(stop_state, listen_addr, h, startup_tx);
			});

		let listener_th = match listener_th {
			Ok(thr) => thr,
			Err(e) => {
				let err =
					Error::ServerError(format!("Failed to start stratum listener thread, {}", e));
				error!("{}", err);
				report_startup_status(&mut startup_status_tx, Err(err.to_string()));
				return Err(err);
			}
		};

		match startup_rx.recv_timeout(Duration::from_secs(10)) {
			Ok(Ok(())) => {}
			Ok(Err(e)) => {
				let err = Error::ServerError(format!("Failed to start stratum listener, {}", e));
				error!("{}", err);
				report_startup_status(&mut startup_status_tx, Err(err.to_string()));
				self.stop_state.stop();
				self.join_listener_thread(listener_th)?;
				return Err(err);
			}
			Err(std_mpsc::RecvTimeoutError::Timeout) => {
				let err =
					Error::ServerError("Timed out waiting for stratum listener startup".into());
				error!("{}", err);
				report_startup_status(&mut startup_status_tx, Err(err.to_string()));
				self.stop_state.stop();
				self.join_listener_thread(listener_th)?;
				return Err(err);
			}
			Err(std_mpsc::RecvTimeoutError::Disconnected) => {
				let err = Error::ServerError(
					"Stratum listener exited before reporting startup status".into(),
				);
				error!("{}", err);
				report_startup_status(&mut startup_status_tx, Err(err.to_string()));
				self.stop_state.stop();
				self.join_listener_thread(listener_th)?;
				return Err(err);
			}
		}

		// We have started
		self.stratum_stats.is_running.store(true, Ordering::Relaxed);
		// Safe: min_edge_bits is a u8 consensus edge size; widening to u16 and
		// adding one stays far below u16::MAX.
		let edge_bits = u16::from(global::min_edge_bits(self.chain.get_context_id())) + 1;
		self.stratum_stats
			.edge_bits
			.store(edge_bits, Ordering::Relaxed);
		self.stratum_stats
			.minimum_share_difficulty
			.store(self.config.minimum_share_difficulty, Ordering::Relaxed);

		warn!("Stratum server started on {}", stratum_server_addr);
		report_startup_status(&mut startup_status_tx, Ok(()));

		// Initial Loop. Waiting node complete syncing
		while self.sync_state.is_syncing() && !self.stop_state.is_stopped() {
			thread::sleep(Duration::from_millis(50));
		}

		if let Err(e) = handler.run(&self.config, &self.tx_pool) {
			error!("Stratum exiting because of handler run error, {}", e);
			self.stop_state.stop();
			self.join_listener_thread(listener_th)?;
			return Err(e);
		}

		self.join_listener_thread(listener_th)
	} // fn run_loop()
} // StratumServer

// Utility function to parse a JSON RPC parameter object, returning a proper
// error if things go wrong.
fn parse_params<T>(params: Option<Value>) -> Result<T, RpcError>
where
	for<'de> T: serde::Deserialize<'de>,
{
	params
		.and_then(|v| serde_json::from_value(v).ok())
		.ok_or_else(RpcError::invalid_request)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn internal_error_hides_diagnostic() {
		let rpc_error = RpcError::internal_error("Unknown worker with id 42");

		assert_eq!(-32603, rpc_error.code);
		assert_eq!("Internal error", rpc_error.message);
	}

	#[test]
	fn login_worker_returns_error_when_worker_update_fails() {
		let workers = WorkersList::new(Arc::new(StratumStats::default()));
		let params = LoginParams {
			login: "miner".to_string(),
			pass: "x".to_string(),
			agent: "test-agent".to_string(),
		};

		let rpc_error = login_worker(&workers, &0, params).unwrap_err();

		assert_eq!(-32603, rpc_error.code);
		assert_eq!("Internal error", rpc_error.message);
	}

	fn add_test_worker(workers: &WorkersList, ip: &str) -> usize {
		let (tx, _rx) = mpsc::channel(WORKER_RESPONSE_QUEUE_CAPACITY);
		let (kill_switch, _kill_rx) = oneshot::channel();
		workers.add_worker(ip.to_string(), tx, kill_switch).unwrap()
	}

	fn assert_worker_not_logged_in(err: RpcError) {
		assert_eq!(-32504, err.code);
		assert_eq!("Worker not logged in", err.message);
	}

	#[test]
	fn rpc_methods_require_login_when_login_timeout_enabled() {
		let workers = WorkersList::new(Arc::new(StratumStats::default()));
		let worker_id = add_test_worker(&workers, "192.0.2.1");
		let mut config = StratumServerConfig::default();
		config.worker_login_timeout_ms = 1000;

		for method in ["submit", "keepalive", "getjobtemplate", "status"] {
			let err =
				ensure_rpc_method_authorized(&workers, &config, method, worker_id, "192.0.2.1")
					.unwrap_err();
			assert_worker_not_logged_in(err);
		}
	}

	#[test]
	fn rpc_login_gate_uses_login_not_authenticated_marker() {
		let workers = WorkersList::new(Arc::new(StratumStats::default()));
		let worker_id = add_test_worker(&workers, "192.0.2.1");
		let connection_id = workers.get_worker(&worker_id).unwrap().connection_id;
		let marked_worker = workers
			.mark_login_timeout_accounted(worker_id, connection_id)
			.unwrap();
		let mut config = StratumServerConfig::default();
		config.worker_login_timeout_ms = 1000;

		assert!(marked_worker.authenticated);
		assert!(marked_worker.login.is_none());
		let err = ensure_rpc_method_authorized(&workers, &config, "submit", worker_id, "192.0.2.1")
			.unwrap_err();

		assert_worker_not_logged_in(err);
	}

	#[test]
	fn rpc_methods_allow_logged_in_workers_when_login_timeout_enabled() {
		let workers = WorkersList::new(Arc::new(StratumStats::default()));
		let worker_id = add_test_worker(&workers, "192.0.2.1");
		let mut config = StratumServerConfig::default();
		config.worker_login_timeout_ms = 1000;

		assert!(workers.login(&worker_id, "miner".to_string(), "agent".to_string()));

		for method in ["submit", "keepalive", "getjobtemplate", "status"] {
			ensure_rpc_method_authorized(&workers, &config, method, worker_id, "192.0.2.1")
				.unwrap();
		}
	}

	#[test]
	fn rpc_methods_allow_without_login_when_login_timeout_disabled() {
		let workers = WorkersList::new(Arc::new(StratumStats::default()));
		let worker_id = add_test_worker(&workers, "192.0.2.1");
		let config = StratumServerConfig::default();

		for method in ["submit", "keepalive", "getjobtemplate", "status"] {
			ensure_rpc_method_authorized(&workers, &config, method, worker_id, "192.0.2.1")
				.unwrap();
		}
	}

	#[test]
	fn rpc_methods_allow_whitelisted_ip_without_login() {
		let workers = WorkersList::new(Arc::new(StratumStats::default()));
		let worker_id = add_test_worker(&workers, "192.0.2.1");
		let mut config = StratumServerConfig::default();
		config.worker_login_timeout_ms = 1000;
		config.ip_white_list.insert("192.0.2.1".to_string());

		for method in ["submit", "keepalive", "getjobtemplate", "status"] {
			ensure_rpc_method_authorized(&workers, &config, method, worker_id, "192.0.2.1")
				.unwrap();
		}
	}

	#[test]
	fn rpc_login_gate_does_not_intercept_login_or_unknown_methods() {
		let workers = WorkersList::new(Arc::new(StratumStats::default()));
		let worker_id = add_test_worker(&workers, "192.0.2.1");
		let mut config = StratumServerConfig::default();
		config.worker_login_timeout_ms = 1000;

		ensure_rpc_method_authorized(&workers, &config, "login", worker_id, "192.0.2.1").unwrap();
		ensure_rpc_method_authorized(&workers, &config, "unknown", worker_id, "192.0.2.1").unwrap();
	}

	#[test]
	fn state_retains_only_latest_block_versions_with_stable_job_ids() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let mut state = State::new(1);

		for nonce in 0..(MAX_CURRENT_BLOCK_VERSIONS + 5) {
			let mut block = Block::default(0);
			block.header.pow.nonce = nonce as u64;
			state.push_block_version(block).unwrap();
		}

		assert_eq!(
			MAX_CURRENT_BLOCK_VERSIONS,
			state.current_block_versions.len()
		);
		assert_eq!(Some(104), state.latest_job_id());
		assert!(state.get_block_version(4).is_none());
		assert_eq!(5, state.get_block_version(5).unwrap().header.pow.nonce);
		assert_eq!(104, state.get_block_version(104).unwrap().header.pow.nonce);
		assert!(state.get_block_version(105).is_none());

		state.clear_block_versions();
		assert_eq!(None, state.latest_job_id());

		let mut block = Block::default(0);
		block.header.pow.nonce = 999;
		state.push_block_version(block).unwrap();

		assert_eq!(Some(105), state.latest_job_id());
		assert!(state.get_block_version(104).is_none());
		assert_eq!(999, state.get_block_version(105).unwrap().header.pow.nonce);
	}

	#[test]
	fn ip_pool_ban_history_rejects_invalid_window() {
		assert!(validate_ip_pool_ban_history_s(10).is_err());
		assert!(validate_ip_pool_ban_history_s(0).is_err());
		assert!(validate_ip_pool_ban_history_s(MIN_IP_POOL_BAN_HISTORY_S + 1).is_ok());
	}

	#[test]
	fn ip_pool_ban_history_rejects_millisecond_overflow() {
		assert!(ip_pool_ban_history_ms(u64::MAX / IP_POOL_BAN_HISTORY_MS_FACTOR).is_ok());
		assert!(ip_pool_ban_history_ms(u64::MAX / IP_POOL_BAN_HISTORY_MS_FACTOR + 1).is_err());
	}

	#[test]
	fn checked_instant_add_rejects_unrepresentable_deadline() {
		assert!(matches!(
			checked_instant_add(Instant::now(), Duration::MAX, "test"),
			Err(Error::DataOverflow(_))
		));
	}

	#[test]
	fn rpc_request_log_metadata_omits_login_params() {
		let json = r#"{"id":"1","method":"login","jsonrpc":"2.0","params":{"login":"miner-user","pass":"secret-password","agent":"test-agent"}}"#;
		let request: RpcRequest = serde_json::from_str(json).unwrap();

		let metadata = rpc_request_log_metadata(&request, 42);

		assert!(metadata.contains("worker_id=42"));
		assert!(metadata.contains("method=\"login\""));
		assert!(metadata.contains("id=StrId(\"1\")"));
		assert!(!metadata.contains("params"));
		assert!(!metadata.contains("pass"));
		assert!(!metadata.contains("secret-password"));
		assert!(!metadata.contains("miner-user"));
		assert!(!metadata.contains("test-agent"));
	}

	/// Tests deserializing an `RpcRequest` given a String as the id.
	#[test]
	fn test_request_deserialize_str() {
		let expected = RpcRequest {
			id: JsonId::StrId(String::from("1")),
			method: String::from("login"),
			jsonrpc: String::from("2.0"),
			params: None,
		};
		let json = r#"{"id":"1","method":"login","jsonrpc":"2.0","params":null}"#;
		let serialized: RpcRequest = serde_json::from_str(json).unwrap();

		assert_eq!(expected, serialized);
	}

	/// Tests serializing an `RpcRequest` given a String as the id.
	/// The extra step of deserializing again is due to associative structures not maintaining order.
	#[test]
	fn test_request_serialize_str() {
		let expected = r#"{"id":"1","method":"login","jsonrpc":"2.0","params":null}"#;
		let rpc = RpcRequest {
			id: JsonId::StrId(String::from("1")),
			method: String::from("login"),
			jsonrpc: String::from("2.0"),
			params: None,
		};
		let json_actual = serde_json::to_string(&rpc).unwrap();

		let expected_deserialized: RpcRequest = serde_json::from_str(expected).unwrap();
		let actual_deserialized: RpcRequest = serde_json::from_str(&json_actual).unwrap();

		assert_eq!(expected_deserialized, actual_deserialized);
	}

	/// Tests deserializing an `RpcResponse` given a String as the id.
	#[test]
	fn test_response_deserialize_str() {
		let expected = RpcResponse {
			id: JsonId::StrId(String::from("1")),
			method: String::from("login"),
			jsonrpc: String::from("2.0"),
			result: None,
			error: None,
		};
		let json = r#"{"id":"1","method":"login","jsonrpc":"2.0","params":null}"#;
		let serialized: RpcResponse = serde_json::from_str(json).unwrap();

		assert_eq!(expected, serialized);
	}

	/// Tests serializing an `RpcResponse` given a String as the id.
	/// The extra step of deserializing again is due to associative structures not maintaining order.
	#[test]
	fn test_response_serialize_str() {
		let expected = r#"{"id":"1","method":"login","jsonrpc":"2.0","params":null}"#;
		let rpc = RpcResponse {
			id: JsonId::StrId(String::from("1")),
			method: String::from("login"),
			jsonrpc: String::from("2.0"),
			result: None,
			error: None,
		};
		let json_actual = serde_json::to_string(&rpc).unwrap();

		let expected_deserialized: RpcResponse = serde_json::from_str(expected).unwrap();
		let actual_deserialized: RpcResponse = serde_json::from_str(&json_actual).unwrap();

		assert_eq!(expected_deserialized, actual_deserialized);
	}

	/// Tests deserializing an `RpcRequest` given an integer as the id.
	#[test]
	fn test_request_deserialize_int() {
		let expected = RpcRequest {
			id: JsonId::IntId(1),
			method: String::from("login"),
			jsonrpc: String::from("2.0"),
			params: None,
		};
		let json = r#"{"id":1,"method":"login","jsonrpc":"2.0","params":null}"#;
		let serialized: RpcRequest = serde_json::from_str(json).unwrap();

		assert_eq!(expected, serialized);
	}

	/// Tests serializing an `RpcRequest` given an integer as the id.
	/// The extra step of deserializing again is due to associative structures not maintaining order.
	#[test]
	fn test_request_serialize_int() {
		let expected = r#"{"id":1,"method":"login","jsonrpc":"2.0","params":null}"#;
		let rpc = RpcRequest {
			id: JsonId::IntId(1),
			method: String::from("login"),
			jsonrpc: String::from("2.0"),
			params: None,
		};
		let json_actual = serde_json::to_string(&rpc).unwrap();

		let expected_deserialized: RpcRequest = serde_json::from_str(expected).unwrap();
		let actual_deserialized: RpcRequest = serde_json::from_str(&json_actual).unwrap();

		assert_eq!(expected_deserialized, actual_deserialized);
	}

	/// Tests deserializing an `RpcResponse` given an integer as the id.
	#[test]
	fn test_response_deserialize_int() {
		let expected = RpcResponse {
			id: JsonId::IntId(1),
			method: String::from("login"),
			jsonrpc: String::from("2.0"),
			result: None,
			error: None,
		};
		let json = r#"{"id":1,"method":"login","jsonrpc":"2.0","params":null}"#;
		let serialized: RpcResponse = serde_json::from_str(json).unwrap();

		assert_eq!(expected, serialized);
	}

	/// Tests serializing an `RpcResponse` given an integer as the id.
	/// The extra step of deserializing again is due to associative structures not maintaining order.
	#[test]
	fn test_response_serialize_int() {
		let expected = r#"{"id":1,"method":"login","jsonrpc":"2.0","params":null}"#;
		let rpc = RpcResponse {
			id: JsonId::IntId(1),
			method: String::from("login"),
			jsonrpc: String::from("2.0"),
			result: None,
			error: None,
		};
		let json_actual = serde_json::to_string(&rpc).unwrap();

		let expected_deserialized: RpcResponse = serde_json::from_str(expected).unwrap();
		let actual_deserialized: RpcResponse = serde_json::from_str(&json_actual).unwrap();

		assert_eq!(expected_deserialized, actual_deserialized);
	}
}
