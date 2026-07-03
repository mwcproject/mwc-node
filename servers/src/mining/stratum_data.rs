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
use mwc_core::consensus::graph_weight;
use mwc_crates::futures::channel::oneshot;
use mwc_crates::log::error;
use mwc_crates::parking_lot::RwLock;
use mwc_crates::tokio::sync::mpsc;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

pub const WORKER_RESPONSE_QUEUE_CAPACITY: usize = 3;

type Tx = mpsc::Sender<String>;

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
	while b != 0 {
		let r = a % b;
		a = b;
		b = r;
	}
	a
}

/// Worker miner
#[derive(Clone)]
pub struct Worker {
	pub id: usize,
	pub connection_id: u64,
	pub ip: String,
	pub create_time: Instant,
	pub agent: String,
	pub login: Option<String>,
	pub authenticated: bool,
	tx: Arc<Tx>, // private, please use send_to method
	kill_switch: Arc<RwLock<Option<oneshot::Sender<()>>>>,
}

impl Worker {
	/// Creates a new Stratum Worker.
	pub fn new(
		id: usize,
		connection_id: u64,
		ip: String,
		tx: Tx,
		kill_switch: oneshot::Sender<()>,
	) -> Worker {
		Worker {
			id: id,
			connection_id,
			ip,
			create_time: Instant::now(),
			agent: String::from(""),
			login: None,
			authenticated: false,
			tx: Arc::new(tx),
			kill_switch: Arc::new(RwLock::new(Some(kill_switch))),
		}
	}

	#[must_use]
	pub fn update(&mut self, worker: &Worker) -> bool {
		if self.id != worker.id {
			error!(
				"Stratum: refusing worker update for mismatched ids: target={}, source={}",
				self.id, worker.id
			);
			return false;
		}
		if self.connection_id != worker.connection_id {
			error!(
				"Stratum: refusing worker update for mismatched connection ids: target={} source={}",
				self.connection_id, worker.connection_id
			);
			return false;
		}

		// updating only 'data' related data
		self.agent = worker.agent.clone();
		self.login = worker.login.clone();
		self.authenticated = worker.authenticated;
		true
	}

	// triggering will kick out worker from the stratum server.
	pub fn trigger_kill_switch(&self) -> Result<(), &'static str> {
		let Some(sender) = self.kill_switch.write().take() else {
			return Err("kill switch already triggered");
		};

		sender.send(()).map_err(|_| "kill switch receiver dropped")
	}

	fn worker_ref(&self) -> WorkerRef {
		WorkerRef {
			id: self.id,
			connection_id: self.connection_id,
		}
	}

	fn try_send(&self, msg: String) -> bool {
		match self.tx.try_send(msg) {
			Ok(()) => true,
			Err(e) => {
				error!("Unable to send message to worker {}: {}", self.id, e);
				false
			}
		}
	}
} // impl Worker

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkerRef {
	pub id: usize,
	pub connection_id: u64,
}

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

	#[allow(dead_code)]
	fn size(&self) -> usize {
		self.workers.read_recursive().len()
	}

	/// Add a new worker, return total number of registered workers
	/// Return : number of registered workers
	fn add(&self, worker_id: usize, worker: Worker) -> Result<usize, Worker> {
		let mut workers = self.workers.write();
		let new_len = workers.len() + 1;
		match workers.entry(worker_id) {
			Entry::Vacant(entry) => {
				entry.insert(worker);
				Ok(new_len)
			}
			Entry::Occupied(_) => Err(worker),
		}
	}

	/// Get worker data
	fn get(&self, worker_id: &usize) -> Option<Worker> {
		match self.workers.read_recursive().get(worker_id) {
			Some(worker) => Some(worker.clone()),
			_ => None,
		}
	}

	/// Update worker data
	#[must_use]
	fn update(&self, worker: &Worker) -> bool {
		if let Some(w) = self.workers.write().get_mut(&worker.id) {
			return w.update(worker);
		}
		false
	}

	fn mark_login_timeout_accounted(&self, worker_id: usize, connection_id: u64) -> Option<Worker> {
		let mut workers = self.workers.write();
		let worker = workers.get_mut(&worker_id)?;
		if worker.connection_id != connection_id || worker.login.is_some() || worker.authenticated {
			return None;
		}

		worker.authenticated = true;
		Some(worker.clone())
	}

	/// Remove a worker if present and return the current number of registered workers.
	///
	/// This is idempotent for the active worker map: removing an already absent
	/// worker leaves the map unchanged, logs the lifecycle mismatch, and returns
	/// the current worker count.
	fn remove(&self, worker_id: &usize) -> usize {
		let mut workers = self.workers.write();
		if workers.remove(&worker_id).is_none() {
			// The worker is already absent from the active map. At disconnect time
			// there is no worker left to remove or recover, so logging the lifecycle
			// mismatch is the only meaningful handling before returning the current
			// worker count for stats accounting.
			error!("Stratum: no such addr in map for worker {}", worker_id);
		}
		workers.len()
	}

	fn get_workers_list(&self) -> Vec<Worker> {
		self.workers
			.read_recursive()
			.values()
			.map(|w| w.clone())
			.collect()
	}
}

pub struct WorkersList {
	// Please never use workers_list directly, allways use getter/setter for that
	workers_map: Arc<WorkersMap>,
	stratum_stats: Arc<StratumStats>,
	next_connection_id: AtomicU64,
}

impl WorkersList {
	pub fn new(stratum_stats: Arc<StratumStats>) -> Self {
		WorkersList {
			workers_map: Arc::new(WorkersMap::new()),
			stratum_stats: stratum_stats,
			next_connection_id: AtomicU64::new(0),
		}
	}

	fn next_connection_id(&self) -> Result<u64, &'static str> {
		self.next_connection_id
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next_id| {
				next_id.checked_add(1)
			})
			.map_err(|_| "connection id space exhausted")
	}

	pub fn add_worker(
		&self,
		ip: String,
		tx: Tx,
		kill_switch: oneshot::Sender<()>,
	) -> Result<usize, &'static str> {
		// Original mwc code allways add a new item into the records. It is not good if we have unstable worker.
		// Or just somebody want to attack the mining pool.
		// let worker_id = stratum_stats.worker_stats.len();

		let connection_id = self.next_connection_id()?;
		let pow_difficulty = self
			.stratum_stats
			.minimum_share_difficulty
			.load(Ordering::Relaxed);
		let mut worker_id = self.stratum_stats.allocate_new_worker(pow_difficulty);
		let mut worker = Worker::new(worker_id, connection_id, ip, tx, kill_switch);

		loop {
			match self.workers_map.add(worker_id, worker) {
				Ok(num_workers) => {
					self.stratum_stats
						.num_workers
						.store(num_workers, Ordering::Relaxed);
					return Ok(worker_id);
				}
				Err(rejected_worker) => {
					error!(
						"Stratum: duplicate worker id {} allocated, retrying with a fresh id",
						worker_id
					);
					worker_id = self.stratum_stats.allocate_new_worker(pow_difficulty);
					worker = rejected_worker;
					worker.id = worker_id;
				}
			}
		}
	}

	pub fn get_worker(&self, worker_id: &usize) -> Option<Worker> {
		self.workers_map.get(worker_id)
	}

	pub fn get_workers_list(&self) -> Vec<Worker> {
		self.workers_map.get_workers_list()
	}

	#[must_use]
	pub fn update_worker(&self, worker: &Worker) -> bool {
		self.workers_map.update(worker)
	}

	pub fn mark_login_timeout_accounted(
		&self,
		worker_id: usize,
		connection_id: u64,
	) -> Option<Worker> {
		self.workers_map
			.mark_login_timeout_accounted(worker_id, connection_id)
	}

	pub fn remove_worker(&self, worker_id: usize) {
		let num_workers = self.workers_map.remove(&worker_id);
		self.stratum_stats
			.num_workers
			.store(num_workers, Ordering::Relaxed);
		if !self.update_stats(worker_id, |ws| ws.is_connected = false) {
			error!("Stratum: no stats record for worker {}", worker_id);
		}
	}

	pub fn login(&self, worker_id: &usize, login: String, agent: String) -> bool {
		if let Some(mut worker) = self.get_worker(worker_id) {
			worker.login = Some(login);

			// XXX TODO Future - Validate password?
			// Here you can add you code and work with worker as long as you need. Here nothing is blocked

			worker.agent = agent;
			worker.authenticated = true;

			// Apply what you changed to the worker
			return self.update_worker(&worker);
		}

		false
	}

	pub fn get_stats(&self, worker_id: usize) -> Option<WorkerStats> {
		self.stratum_stats.get_stats(worker_id)
	}

	pub fn last_seen(&self, worker_id: usize) -> bool {
		//self.stratum_stats.write().worker_stats[worker_id].last_seen = SystemTime::now();
		self.update_stats(worker_id, |ws| ws.last_seen = SystemTime::now())
	}

	// f - must be very functional, no blocking allowed
	pub fn update_stats(&self, worker_id: usize, f: impl FnOnce(&mut WorkerStats)) -> bool {
		self.stratum_stats.update_stats(worker_id, f)
	}

	#[must_use]
	pub fn send_to(&self, worker_id: &usize, msg: String) -> bool {
		if let Some(worker) = self.workers_map.get(worker_id) {
			return worker.try_send(msg);
		}
		error!("Unable to send message to missing worker {}", worker_id);
		false
	}

	pub fn broadcast(&self, msg: String) -> Result<(), Vec<WorkerRef>> {
		let workers = self.workers_map.get_workers_list();
		let mut failed_workers = Vec::new();

		for worker in workers {
			if !worker.try_send(msg.clone()) {
				failed_workers.push(worker.worker_ref());
			}
		}

		if failed_workers.is_empty() {
			Ok(())
		} else {
			Err(failed_workers)
		}
	}

	#[allow(dead_code)]
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

	pub fn update_network_hashrate(
		&self,
		context_id: u32,
	) -> Result<(), mwc_core::consensus::Error> {
		let edge_bits = self.stratum_stats.edge_bits.load(Ordering::Relaxed);
		let edge_bits = u8::try_from(edge_bits).map_err(|_| {
			mwc_core::consensus::Error::DataOverflow(format!(
				"WorkersList::update_network_hashrate, edge_bits={}",
				edge_bits
			))
		})?;
		let graph_weight = graph_weight(
			context_id,
			self.stratum_stats.block_height.load(Ordering::Relaxed),
			edge_bits,
		)?;
		// Original formula: 42.0 * (network_difficulty / graph_weight) / 60
		let network_difficulty = self
			.stratum_stats
			.network_difficulty
			.load(Ordering::Relaxed);
		let mut numerator = u128::from(network_difficulty) * 7;
		let mut denominator = u128::from(graph_weight) * 10;
		let divisor = gcd_u128(numerator, denominator);
		numerator /= divisor;
		denominator /= divisor;
		// Keep the hashrate ratio in integer form until the final AtomicF64
		// publication. Casting u64 inputs above 2^53 directly to f64 can round
		// them before the division; reducing first minimizes that precision loss.
		let network_hashrate = numerator as f64 / denominator as f64;

		self.stratum_stats
			.network_hashrate
			.store(network_hashrate, Ordering::Relaxed);
		Ok(())
	}

	pub fn update_edge_bits(&self, edge_bits: u16) {
		self.stratum_stats
			.edge_bits
			.store(edge_bits, Ordering::Relaxed);
	}

	pub fn increment_block_found(&self) {
		let _ = self.stratum_stats.blocks_found.fetch_update(
			Ordering::Relaxed,
			Ordering::Relaxed,
			|blocks_found| Some(blocks_found.saturating_add(1)),
		);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_worker_with_connection(id: usize, connection_id: u64, ip: &str) -> Worker {
		let (tx, _) = mpsc::channel(WORKER_RESPONSE_QUEUE_CAPACITY);
		let (kill_switch, _) = oneshot::channel();
		Worker::new(id, connection_id, ip.to_string(), tx, kill_switch)
	}

	fn test_worker(id: usize, ip: &str) -> Worker {
		test_worker_with_connection(id, id as u64, ip)
	}

	#[test]
	fn workers_map_add_rejects_duplicate_id_without_replacement() {
		let workers = WorkersMap::new();

		assert!(matches!(workers.add(7, test_worker(7, "one")), Ok(1)));

		let rejected = match workers.add(7, test_worker(7, "two")) {
			Ok(_) => panic!("duplicate worker id was accepted"),
			Err(worker) => worker,
		};

		assert_eq!(rejected.ip, "two");
		assert_eq!(workers.size(), 1);
		assert_eq!(workers.get(&7).unwrap().ip, "one");
	}

	#[test]
	fn worker_update_rejects_mismatched_id() {
		let mut target = test_worker(1, "target");
		let mut source = test_worker(2, "source");
		source.agent = "agent".to_string();
		source.login = Some("login".to_string());
		source.authenticated = true;

		assert!(!target.update(&source));
		assert_eq!(target.agent, "");
		assert_eq!(target.login, None);
		assert!(!target.authenticated);
	}

	#[test]
	fn worker_update_rejects_mismatched_connection_id() {
		let mut target = test_worker_with_connection(1, 10, "target");
		let mut source = test_worker_with_connection(1, 11, "source");
		source.agent = "agent".to_string();
		source.login = Some("login".to_string());
		source.authenticated = true;

		assert!(!target.update(&source));
		assert_eq!(target.agent, "");
		assert_eq!(target.login, None);
		assert!(!target.authenticated);
	}

	#[test]
	fn mark_login_timeout_accounted_marks_only_current_unauthenticated_worker() {
		let workers = WorkersMap::new();
		assert!(matches!(
			workers.add(1, test_worker_with_connection(1, 10, "127.0.0.1")),
			Ok(1)
		));

		let accounted = workers.mark_login_timeout_accounted(1, 10).unwrap();
		assert!(accounted.authenticated);
		assert!(workers.get(&1).unwrap().authenticated);
		assert!(workers.mark_login_timeout_accounted(1, 10).is_none());
	}

	#[test]
	fn mark_login_timeout_accounted_rejects_stale_or_logged_in_worker() {
		let workers = WorkersMap::new();
		assert!(matches!(
			workers.add(1, test_worker_with_connection(1, 10, "127.0.0.1")),
			Ok(1)
		));

		assert!(workers.mark_login_timeout_accounted(1, 11).is_none());
		assert!(!workers.get(&1).unwrap().authenticated);

		let mut logged_in = workers.get(&1).unwrap();
		logged_in.login = Some("miner".to_string());
		logged_in.authenticated = true;
		assert!(workers.update(&logged_in));

		assert!(workers.mark_login_timeout_accounted(1, 10).is_none());
		assert_eq!(workers.get(&1).unwrap().login, Some("miner".to_string()));
	}

	#[test]
	fn broadcast_failure_reports_stable_connection_ref() {
		let stats = Arc::new(StratumStats::default());
		let workers = WorkersList::new(stats);
		let (tx, _rx) = mpsc::channel(1);
		let (kill_switch, _) = oneshot::channel();
		let worker_id = workers
			.add_worker("127.0.0.1".to_string(), tx, kill_switch)
			.unwrap();
		let connection_id = workers.get_worker(&worker_id).unwrap().connection_id;

		assert!(workers.broadcast("first".to_string()).is_ok());
		assert_eq!(
			workers.broadcast("second".to_string()).unwrap_err(),
			vec![WorkerRef {
				id: worker_id,
				connection_id
			}]
		);

		workers.remove_worker(worker_id);
		let (tx, _rx2) = mpsc::channel(1);
		let (kill_switch, _) = oneshot::channel();
		let reused_worker_id = workers
			.add_worker("127.0.0.2".to_string(), tx, kill_switch)
			.unwrap();
		let reused_connection_id = workers.get_worker(&reused_worker_id).unwrap().connection_id;

		assert_eq!(reused_worker_id, worker_id);
		assert_ne!(reused_connection_id, connection_id);
	}

	#[test]
	fn add_worker_rejects_exhausted_connection_ids() {
		let stats = Arc::new(StratumStats::default());
		let workers = WorkersList::new(stats);
		workers
			.next_connection_id
			.store(u64::MAX, Ordering::Relaxed);
		let (tx, _) = mpsc::channel(WORKER_RESPONSE_QUEUE_CAPACITY);
		let (kill_switch, _) = oneshot::channel();

		assert_eq!(
			workers.add_worker("127.0.0.1".to_string(), tx, kill_switch),
			Err("connection id space exhausted")
		);
		assert_eq!(workers.count(), 0);
	}
}
