// Copyright 2021 The Grin Developers
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

use futures::channel::{mpsc, oneshot};
use futures::pin_mut;
use futures::{SinkExt, StreamExt, TryStreamExt};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_util::codec::{Framed, LinesCodec};

use crate::util::RwLock;
use chrono::prelude::Utc;
use serde_json::Value;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, thread};

use super::stratum_data::WorkersList;
use crate::chain::{self, SyncState};
use crate::common::stats::StratumStats;
use crate::common::types::StratumServerConfig;
use crate::core::core::hash::Hashed;
use crate::core::core::Block;
use crate::core::global;
use crate::core::stratum::connections;
use crate::core::{pow, ser};
use crate::keychain;
use crate::mining::mine_block;
use crate::util;
use crate::util::ToHex;
use crate::ServerTxPool;
use std::cmp::min;

// ----------------------------------------
// http://www.jsonrpc.org/specification
// RPC Methods

/// Represents a compliant JSON RPC 2.0 id.
/// Valid id: Integer, String.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(untagged)]
enum JsonId {
	IntId(u32),
	StrId(String),
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct RpcRequest {
	id: JsonId,
	jsonrpc: String,
	method: String,
	params: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct RpcResponse {
	id: JsonId,
	jsonrpc: String,
	method: String,
	result: Option<Value>,
	error: Option<Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct RpcError {
	code: i32,
	message: String,
}

impl RpcError {
	pub fn internal_error() -> Self {
		RpcError {
			code: 32603,
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
}

impl From<RpcError> for Value {
	fn from(e: RpcError) -> Self {
		serde_json::to_value(e).unwrap_or(Value::Null)
	}
}

impl<T> From<T> for RpcError
where
	T: std::error::Error,
{
	fn from(e: T) -> Self {
		error!("Received unhandled error: {}", e);
		RpcError::internal_error()
	}
}

#[derive(Serialize, Deserialize, Debug)]
struct LoginParams {
	login: String,
	pass: String,
	agent: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct SubmitParams {
	height: u64,
	job_id: u64,
	nonce: u64,
	edge_bits: u32,
	pow: Vec<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JobTemplate {
	height: u64,
	job_id: u64,
	difficulty: u64,
	pre_pow: String,
}

#[derive(Serialize, Deserialize, Debug)]
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
	// to prevent the wallet from generating a new HD key derivation for each
	// iteration, we keep the returned derivation to provide it back when
	// nothing has changed. We only want to create a key_id for each new block,
	// and reuse it when we rebuild the current block to add new tx.
	current_key_id: Option<keychain::Identifier>,
	current_difficulty: u64,       // scaled
	minimum_share_difficulty: u64, // unscaled
}

impl State {
	pub fn new(minimum_share_difficulty: u64) -> Self {
		let blocks = vec![Block::default()];
		State {
			current_block_versions: blocks,
			current_key_id: None,
			current_difficulty: <u64>::max_value(),
			minimum_share_difficulty: minimum_share_difficulty,
		}
	}
}

struct Handler {
	id: String,
	workers: Arc<WorkersList>,
	sync_state: Arc<SyncState>,
	chain: Arc<chain::Chain>,
	current_state: Arc<RwLock<State>>,
	ip_pool: Arc<connections::StratumIpPool>,
	worker_connections: Arc<AtomicI32>,
	config: StratumServerConfig,
}

impl Handler {
	pub fn from_stratum(stratum: &StratumServer) -> Self {
		assert!(
			stratum.config.ip_pool_ban_history_s > 10,
			"Stratum ip_pool_ban_history_s value must has reasonable value"
		);

		Handler {
			id: stratum.id.clone(),
			workers: Arc::new(WorkersList::new(stratum.stratum_stats.clone())),
			sync_state: stratum.sync_state.clone(),
			chain: stratum.chain.clone(),
			current_state: Arc::new(RwLock::new(State::new(
				stratum.config.minimum_share_difficulty,
			))),
			ip_pool: stratum.ip_pool.clone(),
			worker_connections: stratum.worker_connections.clone(),
			config: stratum.config.clone(),
		}
	}

	fn handle_rpc_requests(&self, request: RpcRequest, worker_id: usize, ip: &String) -> String {
		self.workers.last_seen(worker_id);

		// Call the handler function for requested method
		let response = match request.method.as_str() {
			"login" => match self.handle_login(request.params, &worker_id) {
				Ok(r) => {
					self.ip_pool.report_ok_login(ip);
					Ok(r)
				}
				Err(e) => {
					self.ip_pool.report_fail_login(ip);
					Err(e)
				}
			},
			"submit" => {
				let res = self.handle_submit(request.params, worker_id);
				// this key_id has been used now, reset
				let res = match res {
					Ok(ok) => {
						self.ip_pool.report_ok_shares(ip);
						Ok(ok)
					}
					Err(rpc_err) => {
						if rpc_err.code != RpcError::too_late().code {
							self.ip_pool.report_fail_noise(ip);
						};
						Err(rpc_err)
					}
				};
				if let Ok((_, true)) = res {
					self.current_state.write().current_key_id = None;
				}
				res.map(|(v, _)| v)
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
				self.ip_pool.report_fail_noise(ip);
				// Called undefined method
				Err(RpcError::method_not_found())
			}
		};

		// Package the reply as RpcResponse json
		let resp = match response {
			Err(rpc_error) => RpcResponse {
				id: request.id,
				jsonrpc: String::from("2.0"),
				method: request.method,
				result: None,
				error: Some(rpc_error.into()),
			},
			Ok(response) => RpcResponse {
				id: request.id,
				jsonrpc: String::from("2.0"),
				method: request.method,
				result: Some(response),
				error: None,
			},
		};
		serde_json::to_string(&resp).unwrap_or("{}".to_string())
	}

	fn handle_login(&self, params: Option<Value>, worker_id: &usize) -> Result<Value, RpcError> {
		// Note !!!! self.workers.login HAS to be there.
		let params: LoginParams = parse_params(params)?;
		if !self.workers.login(worker_id, params.login, params.agent) {
			return Ok("false".into()); // you migth change that response, Possible solution Error 'Unauthorized worker'
		}
		return Ok("ok".into());
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
			.ok_or(RpcError::internal_error())?;
		let status = WorkerStatus {
			id: stats.id.clone(),
			height: self
				.current_state
				.read()
				.current_block_versions
				.last()
				.unwrap()
				.header
				.height,
			difficulty: stats.pow_difficulty,
			accepted: stats.num_accepted,
			rejected: stats.num_rejected,
			stale: stats.num_stale,
		};
		let response = serde_json::to_value(&status).unwrap_or(Value::Null);
		return Ok(response);
	}
	// Handle GETJOBTEMPLATE message
	fn handle_getjobtemplate(&self) -> Result<Value, RpcError> {
		// Build a JobTemplate from a BlockHeader and return JSON
		let job_template = self.build_block_template();
		let response = serde_json::to_value(&job_template).unwrap_or(Value::Null);
		debug!(
			"(Server ID: {}) sending block {} with id {} to single worker",
			self.id, job_template.height, job_template.job_id,
		);
		return Ok(response);
	}

	// Build and return a JobTemplate for mining the current block
	fn build_block_template(&self) -> JobTemplate {
		let (bh, job_id, difficulty) = {
			let state = self.current_state.read();

			(
				state.current_block_versions.last().unwrap().header.clone(),
				state.current_block_versions.len() - 1,
				state.minimum_share_difficulty,
			)
		};

		// Serialize the block header into pre and post nonce strings
		let mut header_buf = vec![];
		{
			let mut writer = ser::BinWriter::default(&mut header_buf);
			bh.write_pre_pow(&mut writer).unwrap();
			bh.pow.write_pre_pow(&mut writer).unwrap();
		}
		let pre_pow = util::to_hex(&header_buf);
		let job_template = JobTemplate {
			height: bh.height,
			job_id: job_id as u64,
			difficulty,
			pre_pow,
		};
		return job_template;
	}
	// Handle SUBMIT message
	// params contains a solved block header
	// We accept and log valid shares of all difficulty above configured minimum
	// Accepted shares that are full solutions will also be submitted to the
	// network
	fn handle_submit(
		&self,
		params: Option<Value>,
		worker_id: usize,
	) -> Result<(Value, bool), RpcError> {
		// Validate parameters
		let params: SubmitParams = parse_params(params)?;

		let (b, header_height, minimum_share_difficulty, current_difficulty) = {
			let state = self.current_state.read();

			(
				state
					.current_block_versions
					.get(params.job_id as usize)
					.map(|b| b.clone()),
				state.current_block_versions.last().unwrap().header.height,
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
			self.workers.update_stats(worker_id, |ws| ws.num_stale += 1);
			return Err(RpcError::too_late());
		}

		let scaled_share_difficulty: u64;
		let unscaled_share_difficulty: u64;
		let mut share_is_block = false;

		let mut b: Block = b.unwrap().clone();
		// Reconstruct the blocks header with this nonce and pow added
		b.header.pow.proof.edge_bits = params.edge_bits as u8;
		b.header.pow.nonce = params.nonce;
		b.header.pow.proof.nonces = params.pow;

		if !b.header.pow.is_primary() && !b.header.pow.is_secondary() {
			// Return error status
			error!(
				"(Server ID: {}) Failed to validate solution at height {}, hash {}, edge_bits {}, nonce {}, job_id {}: cuckoo size too small",
				self.id, params.height, b.hash(), params.edge_bits, params.nonce, params.job_id,
			);
			self.workers
				.update_stats(worker_id, |worker_stats| worker_stats.num_rejected += 1);
			return Err(RpcError::cannot_validate());
		}

		// Get share difficulty values
		scaled_share_difficulty = b.header.pow.to_difficulty(b.header.height).to_num();
		unscaled_share_difficulty = b.header.pow.to_unscaled_difficulty().to_num();
		// Note:  state.minimum_share_difficulty is unscaled
		//        state.current_difficulty is scaled
		// If the difficulty is too low its an error
		if unscaled_share_difficulty < minimum_share_difficulty {
			// Return error status
			error!(
				"(Server ID: {}) Share at height {}, hash {}, edge_bits {}, nonce {}, job_id {} rejected due to low difficulty: {}/{}",
				self.id, params.height, b.hash(), params.edge_bits, params.nonce, params.job_id, unscaled_share_difficulty, minimum_share_difficulty,
			);
			self.workers
				.update_stats(worker_id, |worker_stats| worker_stats.num_rejected += 1);
			return Err(RpcError::too_low_difficulty());
		}

		// If the difficulty is high enough, submit it (which also validates it)
		if scaled_share_difficulty >= current_difficulty {
			// This is a full solution, submit it to the network
			let res = self.chain.process_block(b.clone(), chain::Options::MINE);
			if let Err(e) = res {
				// Return error status
				error!(
					"(Server ID: {}) Failed to validate solution at height {}, hash {}, edge_bits {}, nonce {}, job_id {}, {}",
					self.id,
					params.height,
					b.hash(),
					params.edge_bits,
					params.nonce,
					params.job_id,
					e,
				);
				self.workers
					.update_stats(worker_id, |worker_stats| worker_stats.num_rejected += 1);
				return Err(RpcError::cannot_validate());
			}
			share_is_block = true;
			self.workers
				.update_stats(worker_id, |worker_stats| worker_stats.num_blocks_found += 1);
			self.workers.increment_block_found();
			// Log message to make it obvious we found a block
			let stats = self
				.workers
				.get_stats(worker_id)
				.ok_or(RpcError::internal_error())?;
			warn!(
				"(Server ID: {}) Solution Found for block {}, hash {} - Yay!!! Worker ID: {}, blocks found: {}, shares: {}",
				self.id, params.height,
				b.hash(),
				stats.id,
				stats.num_blocks_found,
				stats.num_accepted,
			);
		} else {
			// Do some validation but dont submit
			let res = pow::verify_size(&b.header);
			if res.is_err() {
				// Return error status
				error!(
					"(Server ID: {}) Failed to validate share at height {}, hash {}, edge_bits {}, nonce {}, job_id {}. {:?}",
					self.id,
					params.height,
					b.hash(),
					params.edge_bits,
					b.header.pow.nonce,
					params.job_id,
					res,
				);
				self.workers
					.update_stats(worker_id, |worker_stats| worker_stats.num_rejected += 1);
				return Err(RpcError::cannot_validate());
			}
		}
		// Log this as a valid share
		self.workers.update_edge_bits(params.edge_bits as u16);
		if let Some(worker) = self.workers.get_worker(&worker_id) {
			let submitted_by = match worker.login {
				None => worker.id.to_string(),
				Some(login) => login.clone(),
			};

			info!(
				"(Server ID: {}) Got share at height {}, hash {}, edge_bits {}, nonce {}, job_id {}, difficulty {}/{}, submitted by {}",
				self.id,
				b.header.height,
				b.hash(),
				b.header.pow.proof.edge_bits,
				b.header.pow.nonce,
				params.job_id,
				scaled_share_difficulty,
				current_difficulty,
				submitted_by,
			);
		}

		self.workers
			.update_stats(worker_id, |worker_stats| worker_stats.num_accepted += 1);
		let submit_response = if share_is_block {
			format!("blockfound - {}", b.hash().to_hex())
		} else {
			"ok".to_string()
		};
		return Ok((
			serde_json::to_value(submit_response).unwrap_or(Value::Null),
			share_is_block,
		));
	} // handle submit a solution

	fn broadcast_job(&self) {
		debug!("broadcast job");
		// Package new block into RpcRequest
		let job_template = self.build_block_template();
		let job_template_json = serde_json::to_string(&job_template).unwrap_or("{}".to_string());
		// Issue #1159 - use a serde_json Value type to avoid extra quoting
		let job_template_value: Value =
			serde_json::from_str(&job_template_json).unwrap_or(Value::Null);
		let job_request = RpcRequest {
			id: JsonId::StrId(String::from("Stratum")),
			jsonrpc: String::from("2.0"),
			method: String::from("job"),
			params: Some(job_template_value),
		};
		let job_request_json = serde_json::to_string(&job_request).unwrap_or("{}".to_string());
		debug!(
			"(Server ID: {}) sending block {} with id {} to stratum clients",
			self.id, job_template.height, job_template.job_id,
		);
		self.workers.broadcast(job_request_json);
	}

	pub fn run(&self, config: &StratumServerConfig, tx_pool: &ServerTxPool) {
		debug!("Run main loop");
		let mut deadline: i64 = 0;
		let mut head = self.chain.head().unwrap();
		let mut current_hash = head.prev_block_h;

		let worker_checking_period = if self.config.worker_login_timeout_ms <= 0 {
			1000
		} else {
			min(1000, self.config.worker_login_timeout_ms)
		};

		let mut next_worker_checking = Utc::now().timestamp_millis() + worker_checking_period;
		let mut next_ip_pool_checking =
			Utc::now().timestamp_millis() + self.config.ip_pool_ban_history_s * 1000 / 10;

		loop {
			// get the latest chain state
			head = self.chain.head().unwrap();
			let latest_hash = head.last_block_h;

			// Build a new block if there is at least one worker and
			// There is a new block on the chain or its time to rebuild
			// the current one to include new transactions
			if (current_hash != latest_hash || Utc::now().timestamp() >= deadline)
				&& self.workers.count() > 0
			{
				{
					debug!("resend updated block");
					let wallet_listener_url = if !config.burn_reward {
						Some(config.wallet_listener_url.clone())
					} else {
						None
					};
					// If this is a new block we will clear the current_block version history
					let clear_blocks = current_hash != latest_hash;

					// Build the new block (version)
					let (new_block, block_fees) = mine_block::get_block(
						&self.chain,
						tx_pool,
						self.current_state.read().current_key_id.clone(),
						wallet_listener_url,
					);

					{
						let mut state = self.current_state.write();

						// scaled difficulty
						state.current_difficulty =
							(new_block.header.total_difficulty() - head.total_difficulty).to_num();

						state.current_key_id = block_fees.key_id();

						current_hash = latest_hash;
						// set the minimum acceptable share unscaled difficulty for this block
						state.minimum_share_difficulty =
							cmp::min(config.minimum_share_difficulty, state.current_difficulty);
					}

					// set a new deadline for rebuilding with fresh transactions
					deadline = Utc::now().timestamp() + config.attempt_time_per_block as i64;

					// Update the mining stats
					self.workers.update_block_height(new_block.header.height);
					let difficulty = new_block.header.total_difficulty() - head.total_difficulty;
					self.workers.update_network_difficulty(difficulty.to_num());
					self.workers.update_network_hashrate();

					{
						let mut state = self.current_state.write();

						// If this is a new block we will clear the current_block version history
						if clear_blocks {
							state.current_block_versions.clear();
						}
						// Add this new block candidate onto our list of block versions for this height
						state.current_block_versions.push(new_block);
					}
				}
				// Send this job to all connected workers
				self.broadcast_job();
			}

			// Check workers login statuses and do IP pool maintaince
			let cur_time = Utc::now().timestamp_millis();

			if cur_time > next_worker_checking {
				next_worker_checking = cur_time + worker_checking_period;

				if config.ip_tracking {
					let mut banned_ips = self.ip_pool.get_banned_ips();

					let mut extra_con = self.worker_connections.load(Ordering::Relaxed)
						- self.config.workers_connection_limit;

					if extra_con > 0 {
						// we need to limit slash some connections.
						// Let's do that with least profitable IP adresses
						let mut ip_prof = self.ip_pool.get_ip_profitability();
						// Last to del first
						ip_prof.sort_by(|a, b| b.1.cmp(&a.1));

						while extra_con > 0 && !ip_prof.is_empty() {
							let prof = ip_prof.pop().unwrap();
							warn!("Stratum need to clean {} connections. Will retire {} workers from IP {}", extra_con, prof.2, prof.0);
							extra_con -= prof.2;
							banned_ips.insert(prof.0);
						}
					}

					let login_deadline = if self.config.worker_login_timeout_ms <= 0 {
						0
					} else {
						cur_time - self.config.worker_login_timeout_ms
					};

					// we are working with a snapshot. Worker can be changed during the workflow.
					for mut w in self.workers.get_workers_list() {
						if self.config.ip_white_list.contains(&w.ip) {
							continue; // skipping all while listed workers. They can do whatever that want.
						}

						if w.login.is_none() && w.create_time < login_deadline {
							// Don't need to report login issue, will be processed at exit
							warn!(
								"Worker id:{} ip:{} banned because of login timeout",
								w.id, w.ip
							);
							w.trigger_kill_switch();
						} else if banned_ips.contains(&w.ip) {
							// Cleaning all workers from the ban
							warn!(
								"Worker id:{} ip:{} banned because IP is in the kick out list",
								w.id, w.ip
							);

							// We don't want double ban just connected workers. Assume they are authenticated
							w.authenticated = true;
							self.workers.update_worker(&w);

							w.trigger_kill_switch();
						}
					}
				}
			} else if cur_time > next_ip_pool_checking {
				next_ip_pool_checking = cur_time + self.config.ip_pool_ban_history_s * 1000 / 10;

				self.ip_pool
					.retire_old_events(cur_time - self.config.ip_pool_ban_history_s * 1000);
			}

			// sleep before restarting loop
			thread::sleep(Duration::from_millis(5));
		} // Main Loop
	}
}

// ----------------------------------------
// Worker Factory Thread Function
// Returned runtime must be kept for a server lifetime
fn accept_connections(listen_addr: SocketAddr, handler: Arc<Handler>) {
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

	let task = async move {
		let mut listener = match TcpListener::bind(&listen_addr).await {
			Ok(listener) => listener,
			Err(e) => {
				error!(
					"Stratum: Failed to bind to listen address {}, {}",
					listen_addr, e
				);
				return;
			}
		};

		let server = listener
			.incoming()
			.filter_map(|s| async { s.map_err(|e| error!("accept error = {:?}", e)).ok() })
			.for_each(move |socket| {
				let peer_addr = socket
					.peer_addr()
					.unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1234));
				let ip = peer_addr.ip().to_string();

				let handler = handler.clone();

				async move {
					let config = &handler.config;

					let accepting_connection = if config.ip_white_list.contains(&ip) {
						info!(
							"Stratum accepting new connection for {}, it is in white list",
							ip
						);
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
						info!("Stratum accepting new connection for {}", ip);
						true
					};

					handler.worker_connections.fetch_add(1, Ordering::Relaxed);
					let ip_pool = handler.ip_pool.clone();

					// Worker IO channels
					let (tx, mut rx) = mpsc::unbounded();

					// Worker killer switch
					let (kill_switch, kill_switch_receiver) = oneshot::channel::<()>();

					let worker_id = handler.workers.add_worker(ip.clone(), tx, kill_switch);
					info!("Worker {} connected", worker_id);
					ip_pool.add_worker(&ip);

					let framed = Framed::new(socket, LinesCodec::new());
					let (mut writer, mut reader) = framed.split();

					let h = handler.clone();
					let workers = h.workers.clone();
					let ip_clone = ip.clone();
					let ip_clone2 = ip.clone();
					let ip_pool_clone2 = ip_pool.clone();
					let ip_pool_clone3 = ip_pool.clone();

					let read = async move {
						if accepting_connection {
							while let Some(line) = reader.try_next().await.map_err(|e| {
								ip_pool_clone2.report_fail_noise(&ip_clone2);
								error!("error processing request to stratum, {}", e)
							})? {
								if !line.is_empty() {
									debug!("get request: {}", line);
									let request = serde_json::from_str(&line).map_err(|e| {
										ip_pool_clone3.report_fail_noise(&ip_clone2);
										error!("error serializing line: {}", e)
									})?;
									let resp = h.handle_rpc_requests(request, worker_id, &ip_clone);
									workers.send_to(&worker_id, resp);
								}
							}
						}

						Result::<_, ()>::Ok(())
					};

					let write = async move {
						if accepting_connection {
							while let Some(line) = rx.next().await {
								// No need to add line separator for the client, because
								// Frames with LinesCodec does that.
								writer.send(line).await.map_err(|e| {
									error!("stratum cannot send data to worker, {}", e)
								})?;
							}
						}
						Result::<_, ()>::Ok(())
					};

					let task = async move {
						pin_mut!(read, write);
						let rw = futures::future::select(read, write);
						futures::future::select(rw, kill_switch_receiver).await;
						handler.workers.remove_worker(worker_id);
						info!("Worker {} disconnected", worker_id);
					};
					tokio::spawn(task);
				}
			});
		server.await
	};

	let mut rt = Runtime::new().unwrap();
	rt.block_on(task);
}

// ----------------------------------------
// Grin Stratum Server

pub struct StratumServer {
	id: String,
	config: StratumServerConfig,
	chain: Arc<chain::Chain>,
	pub tx_pool: ServerTxPool,
	sync_state: Arc<SyncState>,
	stratum_stats: Arc<StratumStats>,
	ip_pool: Arc<connections::StratumIpPool>,
	worker_connections: Arc<AtomicI32>,
}

impl StratumServer {
	/// Creates a new Stratum Server.
	pub fn new(
		config: StratumServerConfig,
		chain: Arc<chain::Chain>,
		tx_pool: ServerTxPool,
		stratum_stats: Arc<StratumStats>,
		ip_pool: Arc<connections::StratumIpPool>,
	) -> StratumServer {
		StratumServer {
			id: String::from("0"),
			config,
			chain,
			tx_pool,
			sync_state: Arc::new(SyncState::new()),
			stratum_stats: stratum_stats,
			ip_pool,
			worker_connections: Arc::new(AtomicI32::new(0)),
		}
	}

	/// "main()" - Starts the stratum-server.  Creates a thread to Listens for
	/// a connection, then enters a loop, building a new block on top of the
	/// existing chain anytime required and sending that to the connected
	/// stratum miner, proxy, or pool, and accepts full solutions to
	/// be submitted.
	pub fn run_loop(&mut self, proof_size: usize, sync_state: Arc<SyncState>) {
		info!(
			"(Server ID: {}) Starting stratum server with proof_size = {}",
			self.id, proof_size
		);

		self.sync_state = sync_state;

		let listen_addr = self
			.config
			.stratum_server_addr
			.clone()
			.unwrap()
			.parse()
			.expect("Stratum: Incorrect address ");

		let handler = Arc::new(Handler::from_stratum(&self));
		let h = handler.clone();

		let _listener_th = thread::spawn(move || {
			accept_connections(listen_addr, h);
		});

		// We have started
		self.stratum_stats.is_running.store(true, Ordering::Relaxed);
		self.stratum_stats
			.edge_bits
			.store(global::min_edge_bits() as u16 + 1, Ordering::Relaxed);
		self.stratum_stats
			.minimum_share_difficulty
			.store(self.config.minimum_share_difficulty, Ordering::Relaxed);

		warn!(
			"Stratum server started on {}",
			self.config.stratum_server_addr.clone().unwrap()
		);

		// Initial Loop. Waiting node complete syncing
		while self.sync_state.is_syncing() {
			thread::sleep(Duration::from_millis(50));
		}

		handler.run(&self.config, &self.tx_pool);
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
