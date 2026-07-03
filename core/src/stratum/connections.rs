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

//! Some tools to easy stratum server attacks

use mwc_crates::log::debug;
use mwc_crates::parking_lot::RwLock;
use mwc_crates::serde::{self, Deserialize, Serialize};
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const CONNECT_HISTORY_LIMIT: usize = 10; // History length that we are keeping
const CONNECT_HISTORY_MIN: usize = 3; // History length to start check for connections

/// Error returned when stratum IP pool accounting cannot apply an event.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StratumIpPoolError {
	/// The requested IP entry is not present in the pool.
	#[error("untracked ip {0} in stratum IP pool")]
	UnknownIp(String),
	/// A worker delete was requested for an IP with no active workers.
	#[error("zero workers for ip {0} in stratum IP pool")]
	NoWorkers(String),
	/// Cleanup was requested for an IP that still has active workers.
	#[error("active workers for ip {0} in stratum IP pool")]
	ActiveWorkers(String),
}

#[derive(Debug)]
struct StratumConnections {
	/// IP address, used for connection
	ip: String,

	/// Last time when connection was accepted
	last_connect_time: VecDeque<Instant>,

	/// Total number of connected workers
	workers: u32,
	///  Time when shares was submitted
	ok_shares: VecDeque<Instant>,
	/// Time when successful login was made
	ok_logins: VecDeque<Instant>,

	/// Was banned due non logging in
	ban_login: VecDeque<Instant>,
	/// bad traffic
	ban_noise: VecDeque<Instant>,
	/// Maximum number of scored events retained per queue.
	events_limit: usize,
}

impl StratumConnections {
	pub fn new(ip: String, events_limit: usize) -> StratumConnections {
		StratumConnections {
			ip,
			last_connect_time: VecDeque::new(),
			workers: 0,
			ok_shares: VecDeque::new(),
			ok_logins: VecDeque::new(),
			ban_login: VecDeque::new(),
			ban_noise: VecDeque::new(),
			events_limit: std::cmp::max(events_limit, 30),
		}
	}

	// connection_pace - how many connection per second is acceptable...
	pub fn is_banned(
		&self,
		ban_action_limit: usize,
		shares_weight: usize,
		connection_pace_ms: i64,
		new_worker: bool,
	) -> bool {
		if connection_pace_ms >= 0
			&& new_worker
			&& self.last_connect_time.len() >= CONNECT_HISTORY_MIN
		{
			if let Some(last_connect_time) = self.last_connect_time.front() {
				let elapsed_ms = last_connect_time
					.elapsed()
					.as_millis()
					.min(i64::MAX as u128) as i64;
				let current_pace_ms = elapsed_ms / self.last_connect_time.len() as i64;
				if connection_pace_ms > current_pace_ms {
					return true;
				}
			}
		}

		let ok_score = self
			.ok_shares
			.len()
			.saturating_mul(shares_weight)
			.saturating_add(self.ok_logins.len());
		let ban_score = self.ban_login.len().saturating_add(self.ban_noise.len());
		ban_score.saturating_sub(ok_score) > ban_action_limit
	}

	pub fn is_empty(&self) -> bool {
		self.workers == 0
			&& self.last_connect_time.is_empty()
			&& self.ok_shares.is_empty()
			&& self.ok_logins.is_empty()
			&& self.ban_login.is_empty()
			&& self.ban_noise.is_empty()
	}

	pub fn retire_old_events(&mut self, max_age: Duration) {
		Self::retire_events(&mut self.last_connect_time, max_age);
		Self::retire_events(&mut self.ok_shares, max_age);
		Self::retire_events(&mut self.ok_logins, max_age);
		Self::retire_events(&mut self.ban_login, max_age);
		Self::retire_events(&mut self.ban_noise, max_age);
		debug!(
			"StratumConnections retire_old_events for max age {:?}. {:?}",
			max_age, self
		);
	}

	pub fn add_worker(&mut self) {
		self.workers = self.workers.saturating_add(1);
		self.last_connect_time.push_back(Instant::now());
		while self.last_connect_time.len() > CONNECT_HISTORY_LIMIT {
			self.last_connect_time.pop_front();
		}
		debug!("StratumConnections add_worker. {:?}", self);
	}

	pub fn delete_worker(&mut self) -> Result<(), StratumIpPoolError> {
		if self.workers == 0 {
			return Err(StratumIpPoolError::NoWorkers(self.ip.clone()));
		}

		self.workers -= 1;
		debug!("StratumConnections delete_worker. {:?}", self);
		Ok(())
	}

	pub fn report_ok_shares(&mut self) {
		Self::push_limited_event(&mut self.ok_shares, self.events_limit);
		debug!("StratumConnections report_ok_shares. {:?}", self);
	}

	pub fn report_ok_login(&mut self) {
		Self::push_limited_event(&mut self.ok_logins, self.events_limit);
		debug!("StratumConnections report_ok_login. {:?}", self);
	}

	pub fn report_fail_login(&mut self) {
		Self::push_limited_event(&mut self.ban_login, self.events_limit);
		debug!("StratumConnections report_fail_login. {:?}", self);
	}

	pub fn report_fail_noise(&mut self) {
		Self::push_limited_event(&mut self.ban_noise, self.events_limit);
		debug!("StratumConnections report_fail_noise. {:?}", self);
	}

	fn push_limited_event(events: &mut VecDeque<Instant>, events_limit: usize) {
		events.push_back(Instant::now());
		while events.len() > events_limit {
			let _ = events.pop_front();
		}
	}

	fn retire_events(events: &mut VecDeque<Instant>, max_age: Duration) {
		// Event times are appended from a monotonic clock, so the hot path treats
		// this deque as time-ordered and retires only the old front entries. We do
		// not need a full cleanup pass here; the goal is to keep scoring buffers
		// manageable, and avoiding an O(n) scan matters for stratum traffic.
		while events
			.front()
			.map_or(false, |event| event.elapsed() > max_age)
		{
			let _ = events.pop_front();
		}
	}
}

/// Stratum IP pool. Used for tracking miner worker activity and detect attacks
#[derive(Debug)]
pub struct StratumIpPool {
	// setting for the ban:
	// number of point to ban IP
	ban_action_limit: usize,
	// If shared was mined, what is the weight.
	shares_weight: usize,

	// Acceptable connection pace. It is average pace for last 3-10 connections.  -1 - disabled
	connection_pace_ms: i64,

	connection_info: RwLock<HashMap<String, StratumConnections>>,
}

impl StratumIpPool {
	/// Creating new Stratum IP pool object.
	pub fn new(
		ban_action_limit: usize,
		shares_weight: usize,
		connection_pace_ms: i64,
	) -> StratumIpPool {
		StratumIpPool {
			connection_info: RwLock::new(HashMap::new()),
			ban_action_limit,
			shares_weight,
			connection_pace_ms,
		}
	}

	/// Get a set of banned IPs
	pub fn get_banned_ips(&self) -> HashSet<String> {
		self.connection_info
			.read_recursive()
			.values()
			.filter(|conn| {
				conn.is_banned(
					self.ban_action_limit,
					self.shares_weight,
					self.connection_pace_ms,
					false,
				)
			})
			.map(|con| con.ip.clone())
			.collect()
	}

	// Note: rust doesn't like floats. That is why we go with i64 for profitability
	/// Get 'profitability' params for IP addresses
	/// return: (ip, profitability(0-1_000_000), number_of_workers)
	pub fn get_ip_profitability(&self) -> Vec<(String, i64, u32)> {
		self.connection_info
			.read_recursive()
			.values()
			.filter(|conn| {
				!conn.is_banned(
					self.ban_action_limit,
					self.shares_weight,
					self.connection_pace_ms,
					false,
				) && conn.workers > 0
			})
			.map(|con| {
				(
					con.ip.clone(),
					con.ok_shares.len() as i64 * 1_000_000 / con.workers as i64,
					con.workers,
				)
			})
			.collect()
	}

	/// Does events rotations and retire expired events
	pub fn retire_old_events(&self, max_age: Duration) {
		let mut con_info = self.connection_info.write();

		// First Update events
		con_info
			.values_mut()
			.for_each(|con| con.retire_old_events(max_age));
		con_info.retain(|_ip, con| !con.is_empty());
	}

	/// Check if this IP is banned
	pub fn is_banned(&self, ip: &String, new_worker: bool) -> bool {
		self.connection_info
			.read_recursive()
			.get(ip)
			.map(|con| {
				con.is_banned(
					self.ban_action_limit,
					self.shares_weight,
					self.connection_pace_ms,
					new_worker,
				)
			})
			.unwrap_or(false)
	}

	/// Register new worker for this IP
	pub fn add_worker(&self, ip: &String) {
		let mut con_info = self.connection_info.write();
		match con_info.get_mut(ip) {
			Some(conn) => conn.add_worker(),
			None => {
				let events_limit = self.ban_action_limit.saturating_mul(10);
				let mut c = StratumConnections::new(ip.clone(), events_limit);
				c.add_worker();
				con_info.insert(ip.clone(), c);
			}
		}
	}

	/// Delete worker from this IP
	pub fn delete_worker(&self, ip: &String) -> Result<(), StratumIpPoolError> {
		let mut con_info = self.connection_info.write();
		con_info
			.get_mut(ip)
			.ok_or_else(|| StratumIpPoolError::UnknownIp(ip.clone()))?
			.delete_worker()
	}

	/// Report workers good shares
	pub fn report_ok_shares(&self, ip: &String) -> Result<(), StratumIpPoolError> {
		self.connection_info
			.write()
			.get_mut(ip)
			.ok_or_else(|| StratumIpPoolError::UnknownIp(ip.clone()))?
			.report_ok_shares();
		Ok(())
	}

	/// Report worker good login
	pub fn report_ok_login(&self, ip: &String) -> Result<(), StratumIpPoolError> {
		self.connection_info
			.write()
			.get_mut(ip)
			.ok_or_else(|| StratumIpPoolError::UnknownIp(ip.clone()))?
			.report_ok_login();
		Ok(())
	}

	/// Report worker bad login
	pub fn report_fail_login(&self, ip: &String) -> Result<(), StratumIpPoolError> {
		self.connection_info
			.write()
			.get_mut(ip)
			.ok_or_else(|| StratumIpPoolError::UnknownIp(ip.clone()))?
			.report_fail_login();
		Ok(())
	}

	/// Report worker bad data
	pub fn report_fail_noise(&self, ip: &String) -> Result<(), StratumIpPoolError> {
		self.connection_info
			.write()
			.get_mut(ip)
			.ok_or_else(|| StratumIpPoolError::UnknownIp(ip.clone()))?
			.report_fail_noise();
		Ok(())
	}

	/// Get IP list info for API
	pub fn get_ip_list(&self, get_banned: bool, get_active: bool) -> Vec<StratumIpPrintable> {
		let mut res: Vec<StratumIpPrintable> = Vec::new();

		for ip_info in self.connection_info.read_recursive().values() {
			let banned = ip_info.is_banned(
				self.ban_action_limit,
				self.shares_weight,
				self.connection_pace_ms,
				false,
			);

			if banned {
				if get_banned {
					res.push(StratumIpPrintable::from_stratum_connection(ip_info, banned));
				}
			} else {
				if get_active {
					res.push(StratumIpPrintable::from_stratum_connection(ip_info, banned));
				}
			}
		}
		res
	}

	/// Get IP info info for API
	pub fn get_ip_info(&self, ip: &String) -> StratumIpPrintable {
		match self.connection_info.read_recursive().get(ip) {
			Some(con) => StratumIpPrintable::from_stratum_connection(
				con,
				con.is_banned(
					self.ban_action_limit,
					self.shares_weight,
					self.connection_pace_ms,
					false,
				),
			),
			None => StratumIpPrintable::from_ip(ip),
		}
	}

	/// Clean IP from the pool.
	pub fn clean_ip(&self, ip: &String) -> Result<(), StratumIpPoolError> {
		let mut con_info = self.connection_info.write();
		match con_info.get(ip) {
			Some(conn) if conn.workers > 0 => Err(StratumIpPoolError::ActiveWorkers(ip.clone())),
			Some(_) => {
				con_info.remove(ip);
				Ok(())
			}
			None => Err(StratumIpPoolError::UnknownIp(ip.clone())),
		}
	}
}

/// Printable representation of stratum IP address
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(crate = "serde")]
pub struct StratumIpPrintable {
	/// ip address
	pub ip: String,
	/// flag if this IP currently under the ban
	pub ban: bool,
	/// Age of the last accepted connection in milliseconds.
	pub last_connect_time_ms: Option<u64>,
	/// Total number of connected workers
	pub workers: u32,
	/// Number of requests with shares
	pub ok_shares: usize,
	/// Number of successed login
	pub ok_logins: usize,
	/// Number of failed logins
	pub failed_login: usize,
	/// Number of bad traffic
	pub failed_requests: usize,
}

impl StratumIpPrintable {
	/// Convert Stratum IP into this printable
	fn from_stratum_connection(stratum_connection: &StratumConnections, banned: bool) -> Self {
		StratumIpPrintable {
			ip: stratum_connection.ip.clone(),
			ban: banned,
			last_connect_time_ms: stratum_connection
				.last_connect_time
				.back()
				.map(|event| event.elapsed().as_millis().min(u64::MAX as u128) as u64),
			workers: stratum_connection.workers,
			ok_shares: stratum_connection.ok_shares.len(),
			ok_logins: stratum_connection.ok_logins.len(),
			failed_login: stratum_connection.ban_login.len(),
			failed_requests: stratum_connection.ban_noise.len(),
		}
	}

	// Empty for IP
	fn from_ip(ip: &String) -> Self {
		StratumIpPrintable {
			ip: ip.clone(),
			ban: false,
			last_connect_time_ms: None,
			workers: 0,
			ok_shares: 0,
			ok_logins: 0,
			failed_login: 0,
			failed_requests: 0,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn empty_connection_retains_recent_connect_history() {
		let mut conn = StratumConnections::new("127.0.0.1".into(), 10);
		conn.last_connect_time
			.push_back(Instant::now() - Duration::from_millis(100));

		conn.retire_old_events(Duration::from_millis(150));
		assert!(!conn.is_empty());

		conn.retire_old_events(Duration::from_millis(50));
		assert!(conn.is_empty());
	}

	#[test]
	fn delete_worker_allows_ip_pool_cleanup_after_connection_history_expires() {
		let pool = StratumIpPool::new(100, 1, -1);
		let ip = "127.0.0.1".to_string();

		pool.add_worker(&ip);
		pool.delete_worker(&ip).unwrap();
		pool.retire_old_events(Duration::from_secs(1));

		let info = pool.get_ip_info(&ip);
		assert_eq!(info.workers, 0);
		assert!(info.last_connect_time_ms.is_some());

		pool.connection_info
			.write()
			.get_mut(&ip)
			.unwrap()
			.last_connect_time
			.front_mut()
			.unwrap()
			.clone_from(&(Instant::now() - Duration::from_secs(2)));
		pool.retire_old_events(Duration::from_secs(1));

		let info = pool.get_ip_info(&ip);
		assert_eq!(info.workers, 0);
		assert!(info.last_connect_time_ms.is_none());
	}

	#[test]
	fn delete_worker_reports_missing_or_empty_accounting() {
		let pool = StratumIpPool::new(100, 1, -1);
		let ip = "127.0.0.1".to_string();

		assert_eq!(
			pool.delete_worker(&ip),
			Err(StratumIpPoolError::UnknownIp(ip.clone()))
		);

		pool.add_worker(&ip);
		pool.delete_worker(&ip).unwrap();
		assert_eq!(
			pool.delete_worker(&ip),
			Err(StratumIpPoolError::NoWorkers(ip))
		);
	}

	#[test]
	fn login_reports_missing_ip_accounting() {
		let pool = StratumIpPool::new(100, 1, -1);
		let ip = "127.0.0.1".to_string();

		assert_eq!(
			pool.report_ok_shares(&ip),
			Err(StratumIpPoolError::UnknownIp(ip.clone()))
		);
		assert_eq!(
			pool.report_ok_login(&ip),
			Err(StratumIpPoolError::UnknownIp(ip.clone()))
		);
		assert_eq!(
			pool.report_fail_login(&ip),
			Err(StratumIpPoolError::UnknownIp(ip))
		);
	}

	#[test]
	fn fail_noise_reports_missing_ip_accounting() {
		let pool = StratumIpPool::new(100, 1, -1);
		let ip = "127.0.0.1".to_string();

		assert_eq!(
			pool.report_fail_noise(&ip),
			Err(StratumIpPoolError::UnknownIp(ip))
		);
	}

	#[test]
	fn clean_ip_preserves_active_worker_accounting() {
		let pool = StratumIpPool::new(100, 1, -1);
		let ip = "127.0.0.1".to_string();

		assert_eq!(
			pool.clean_ip(&ip),
			Err(StratumIpPoolError::UnknownIp(ip.clone()))
		);

		pool.add_worker(&ip);
		assert_eq!(
			pool.clean_ip(&ip),
			Err(StratumIpPoolError::ActiveWorkers(ip.clone()))
		);
		pool.report_ok_shares(&ip).unwrap();

		let info = pool.get_ip_info(&ip);
		assert_eq!(info.workers, 1);
		assert_eq!(info.ok_shares, 1);

		pool.delete_worker(&ip).unwrap();
		assert_eq!(pool.clean_ip(&ip), Ok(()));
		assert_eq!(pool.clean_ip(&ip), Err(StratumIpPoolError::UnknownIp(ip)));
	}

	#[test]
	fn score_event_queues_are_limited_by_ban_action_limit() {
		let pool = StratumIpPool::new(2, 1, -1);
		let ip = "127.0.0.1".to_string();

		pool.add_worker(&ip);
		for _ in 0..20 {
			pool.report_ok_shares(&ip).unwrap();
			pool.report_ok_login(&ip).unwrap();
			pool.report_fail_login(&ip).unwrap();
			pool.report_fail_noise(&ip).unwrap();
		}

		let info = pool.get_ip_info(&ip);
		assert_eq!(info.ok_shares, 20);
		assert_eq!(info.ok_logins, 20);
		assert_eq!(info.failed_login, 20);
		assert_eq!(info.failed_requests, 20);
	}
}
