// Copyright 2020 The MWC Developers
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

// ----------------------------------------
// Worker Object - a connected stratum client - a miner, pool, proxy, etc...

use crate::common::stats::{StratumStats, WorkerStats};
use crate::core::consensus::graph_weight;
use crate::util::RwLock;
use chrono::prelude::Utc;
use futures::channel::mpsc;
use futures::channel::oneshot;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::SystemTime;

type Tx = mpsc::UnboundedSender<String>;

/// Worker miner
#[derive(Clone)]
pub struct Worker {
	pub id: usize,
	pub ip: String,
	pub create_time: i64,
	pub agent: String,
	pub login: Option<String>,
	pub authenticated: bool,
	tx: Arc<Tx>, // private, please use send_to method
	kill_switch: Arc<RwLock<Option<oneshot::Sender<()>>>>,
}

impl Worker {
	/// Creates a new Stratum Worker.
	pub fn new(id: usize, ip: String, tx: Tx, kill_switch: oneshot::Sender<()>) -> Worker {
		Worker {
			id: id,
			ip,
			create_time: Utc::now().timestamp_millis(),
			agent: String::from(""),
			login: None,
			authenticated: false,
			tx: Arc::new(tx),
			kill_switch: Arc::new(RwLock::new(Some(kill_switch))),
		}
	}

	pub fn update(&mut self, worker: &Worker) {
		debug_assert!(self.id == worker.id);

		// updating only 'data' releated data
		self.agent = worker.agent.clone();
		self.login = worker.login.clone();
		self.authenticated = worker.authenticated;
	}

	// triggering will kick out worker from the stratum server.
	pub fn trigger_kill_switch(&self) {
		if let Some(s) = self.kill_switch.write().take() {
			let _ = s.send(());
		}
	}
} // impl Worker

/// Collection of the active workers
struct WorkersMap {
	workers: RwLock<HashMap<usize, Worker>>,
}

impl WorkersMap {
	pub fn new() -> Self {
		WorkersMap {
			workers: RwLock::new(HashMap::new()),
		}
	}

	fn size(&self) -> usize {
		self.workers.read().len()
	}

	/// Add a new worker, return total number of registered workers
	/// Return : number of registered workers
	fn add(&self, worker_id: &usize, worker: Worker) -> usize {
		let mut workers = self.workers.write();
		workers.insert(worker_id.clone(), worker);
		workers.len()
	}

	/// Get worker data
	fn get(&self, worker_id: &usize) -> Option<Worker> {
		match self.workers.read().get(worker_id) {
			Some(worker) => Some(worker.clone()),
			_ => None,
		}
	}

	/// Get worker tx channel, for message sending
	fn get_tx(&self, worker_id: &usize) -> Option<Arc<Tx>> {
		match self.workers.read().get(worker_id) {
			Some(worker) => Some(worker.tx.clone()),
			_ => None,
		}
	}

	/// Update worker data
	fn update(&self, worker: &Worker) {
		if let Some(w) = self.workers.write().get_mut(&worker.id) {
			w.update(worker);
		}
	}

	/// Add a new worker, return total number of registered workers
	/// Return : number of registered workers
	fn remove(&self, worker_id: &usize) -> usize {
		let mut workers = self.workers.write();
		if workers.remove(&worker_id).is_none() {
			error!("Stratum: no such addr in map for worker {}", worker_id);
		}
		workers.len()
	}

	fn get_workers_list(&self) -> Vec<Worker> {
		self.workers.read().values().map(|w| w.clone()).collect()
	}

	fn get_woker_id_list(&self) -> Vec<usize> {
		self.workers.read().keys().map(|k| k.clone()).collect()
	}
}

pub struct WorkersList {
	// Please never use workers_list directly, allways use getter/setter for that
	workers_map: Arc<WorkersMap>,
	stratum_stats: Arc<StratumStats>,
}

impl WorkersList {
	pub fn new(stratum_stats: Arc<StratumStats>) -> Self {
		WorkersList {
			workers_map: Arc::new(WorkersMap::new()),
			stratum_stats: stratum_stats,
		}
	}

	pub fn add_worker(&self, ip: String, tx: Tx, kill_switch: oneshot::Sender<()>) -> usize {
		// Original mwc code allways add a new item into the records. It is not good if we have unstable worker.
		// Or just somebody want to attack the mining pool.
		// let worker_id = stratum_stats.worker_stats.len();

		let worker_id = self.stratum_stats.allocate_new_worker(
			self.stratum_stats
				.minimum_share_difficulty
				.load(Ordering::Relaxed),
		);
		let worker = Worker::new(worker_id, ip, tx, kill_switch);

		let num_workers = self.workers_map.add(&worker_id, worker);
		self.stratum_stats
			.num_workers
			.store(num_workers, Ordering::Relaxed);

		worker_id
	}

	pub fn get_worker(&self, worker_id: &usize) -> Option<Worker> {
		self.workers_map.get(worker_id)
	}

	pub fn get_workers_list(&self) -> Vec<Worker> {
		self.workers_map.get_workers_list()
	}

	pub fn update_worker(&self, worker: &Worker) {
		self.workers_map.update(worker);
	}

	pub fn remove_worker(&self, worker_id: usize) {
		let num_workers = self.workers_map.remove(&worker_id);
		self.stratum_stats
			.num_workers
			.store(num_workers, Ordering::Relaxed);
		self.update_stats(worker_id, |ws| ws.is_connected = false);
	}

	pub fn login(&self, worker_id: &usize, login: String, agent: String) -> bool {
		if let Some(mut worker) = self.get_worker(worker_id) {
			worker.login = Some(login);

			// XXX TODO Future - Validate password?
			// Here you can add you code and work with worker as long as you need. Here nothing is blocked

			worker.agent = agent;
			worker.authenticated = true;

			// Apply what you changed to the workrer
			self.update_worker(&worker);
			return true;
		}

		false
	}

	pub fn get_stats(&self, worker_id: usize) -> Option<WorkerStats> {
		self.stratum_stats.get_stats(worker_id)
	}

	pub fn last_seen(&self, worker_id: usize) {
		//self.stratum_stats.write().worker_stats[worker_id].last_seen = SystemTime::now();
		self.update_stats(worker_id, |ws| ws.last_seen = SystemTime::now());
	}

	// f - must be very functional, no blocking allowed
	pub fn update_stats(&self, worker_id: usize, f: impl FnOnce(&mut WorkerStats) -> ()) {
		self.stratum_stats.update_stats(worker_id, f);
	}

	pub fn send_to(&self, worker_id: &usize, msg: String) {
		if let Some(tx) = self.workers_map.get_tx(worker_id) {
			if tx.unbounded_send(msg).is_err() {
				error!("Unable to send message to worker {}", worker_id)
			}
		}
	}

	pub fn broadcast(&self, msg: String) {
		let keys: Vec<usize> = self.workers_map.get_woker_id_list();

		for worker_id in keys {
			self.send_to(&worker_id, msg.clone());
		}
	}

	pub fn count(&self) -> usize {
		self.workers_map.size()
	}

	pub fn update_block_height(&self, height: u64) {
		self.stratum_stats
			.block_height
			.store(height, Ordering::Relaxed);
	}

	pub fn update_network_difficulty(&self, difficulty: u64) {
		self.stratum_stats
			.network_difficulty
			.store(difficulty, Ordering::Relaxed);
	}

	pub fn update_network_hashrate(&self) {
		let network_hashrate =
			42.0 * (self
				.stratum_stats
				.network_difficulty
				.load(Ordering::Relaxed) as f64
				/ graph_weight(
					self.stratum_stats.block_height.load(Ordering::Relaxed),
					self.stratum_stats.edge_bits.load(Ordering::Relaxed) as u8,
				) as f64) / 60.0;

		self.stratum_stats
			.network_hashrate
			.store(network_hashrate, Ordering::Relaxed);
	}

	pub fn update_edge_bits(&self, edge_bits: u16) {
		self.stratum_stats
			.edge_bits
			.store(edge_bits, Ordering::Relaxed);
	}

	pub fn increment_block_found(&self) {
		self.stratum_stats
			.blocks_found
			.fetch_add(1, Ordering::Relaxed);
	}
}
