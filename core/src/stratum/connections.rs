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

use chrono::Utc;
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use util::RwLock;

const CONNECT_HISTORY_LIMIT: usize = 10; // History length that we are keeping
const CONNECT_HISTORY_MIN: usize = 3; // History length to start check for connections

#[derive(Debug)]
struct StratumConnections {
	/// IP address, used for connection
	ip: String,

	/// Last time when connection was accepted
	last_connect_time_ms: VecDeque<i64>,

	/// Total number of connected workers
	workers: i32,
	///  Time when shares was submitted
	ok_shares: VecDeque<i64>,
	/// Time when successful login was made
	ok_logins: VecDeque<i64>,

	/// Was banned due non logging in
	ban_login: VecDeque<i64>,
	/// bad traffic
	ban_noise: VecDeque<i64>,
}

impl StratumConnections {
	pub fn new(ip: String) -> StratumConnections {
		StratumConnections {
			ip,
			last_connect_time_ms: VecDeque::new(),
			workers: 0,
			ok_shares: VecDeque::new(),
			ok_logins: VecDeque::new(),
			ban_login: VecDeque::new(),
			ban_noise: VecDeque::new(),
		}
	}

	// connection_pace - how many connection per second is acceptable...
	pub fn is_banned(
		&self,
		ban_action_limit: i32,
		shares_weight: i32,
		connection_pace_ms: i64,
		new_worker: bool,
	) -> bool {
		if connection_pace_ms >= 0
			&& new_worker
			&& self.last_connect_time_ms.len() >= CONNECT_HISTORY_MIN
		{
			let current_pace_ms = (Utc::now().timestamp_millis()
				- self.last_connect_time_ms.front().unwrap())
				/ self.last_connect_time_ms.len() as i64;
			if connection_pace_ms > current_pace_ms {
				return true;
			}
		}

		let ok_score: i32 =
			self.ok_shares.len() as i32 * shares_weight + self.ok_logins.len() as i32;
		let ban_score: i32 = self.ban_login.len() as i32 + self.ban_noise.len() as i32;
		ban_score - ok_score > ban_action_limit
	}

	pub fn is_empty(&self) -> bool {
		self.workers == 0
			&& self.ok_shares.is_empty()
			&& self.ok_logins.is_empty()
			&& self.ban_login.is_empty()
			&& self.ban_noise.is_empty()
	}

	pub fn retire_old_events(&mut self, event_time_low_limit: i64) {
		Self::retire_events(&mut self.ok_shares, event_time_low_limit);
		Self::retire_events(&mut self.ok_logins, event_time_low_limit);
		Self::retire_events(&mut self.ban_login, event_time_low_limit);
		Self::retire_events(&mut self.ban_noise, event_time_low_limit);
		debug!(
			"StratumConnections retire_old_events for time limit {}. {:?}",
			event_time_low_limit, self
		);
	}

	pub fn add_worker(&mut self) {
		self.workers += 1;
		self.last_connect_time_ms
			.push_back(Utc::now().timestamp_millis());
		while self.last_connect_time_ms.len() > CONNECT_HISTORY_LIMIT {
			self.last_connect_time_ms.pop_front();
		}
		debug!("StratumConnections add_worker. {:?}", self);
	}

	pub fn delete_worker(&mut self) {
		self.workers -= 1;
		debug!("StratumConnections delete_worker. {:?}", self);
		debug_assert!(self.workers >= 0);
	}

	pub fn report_ok_shares(&mut self) {
		self.ok_shares.push_back(Utc::now().timestamp_millis());
		debug!("StratumConnections report_ok_shares. {:?}", self);
	}

	pub fn report_ok_login(&mut self) {
		self.ok_logins.push_back(Utc::now().timestamp_millis());
		debug!("StratumConnections report_ok_login. {:?}", self);
	}

	pub fn report_fail_login(&mut self) {
		self.ban_login.push_back(Utc::now().timestamp_millis());
		debug!("StratumConnections report_fail_login. {:?}", self);
	}

	pub fn report_fail_noise(&mut self) {
		self.ban_noise.push_back(Utc::now().timestamp_millis());
		debug!("StratumConnections report_fail_noise. {:?}", self);
	}

	fn retire_events(events: &mut VecDeque<i64>, event_time_low_limit: i64) {
		while *events.get(0).unwrap_or(&event_time_low_limit) < event_time_low_limit {
			let _ = events.pop_front();
		}
	}
}

/// Stratum IP pool. Used for tracking miner worker activity and detect attacks
#[derive(Debug)]
pub struct StratumIpPool {
	// setting for the ban:
	// number of point to ban IP
	ban_action_limit: i32,
	// If shared was mined, what is the weight.
	shares_weight: i32,

	// Acceptable connection pace. It is average pace for last 3-10 connections.  -1 - disabled
	connection_pace_ms: i64,

	connection_info: RwLock<HashMap<String, StratumConnections>>,
}

impl StratumIpPool {
	/// Creating new Stratum IP pool object.
	pub fn new(
		ban_action_limit: i32,
		shares_weight: i32,
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
			.read()
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
	pub fn get_ip_profitability(&self) -> Vec<(String, i64, i32)> {
		self.connection_info
			.read()
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
	pub fn retire_old_events(&self, event_time_low_limit: i64) {
		let mut con_info = self.connection_info.write();

		// First Update events
		con_info
			.values_mut()
			.for_each(|con| con.retire_old_events(event_time_low_limit));
		con_info.retain(|_ip, con| !con.is_empty());
	}

	/// Check if this IP is banned
	pub fn is_banned(&self, ip: &String, new_worker: bool) -> bool {
		self.connection_info
			.read()
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
				let mut c = StratumConnections::new(ip.clone());
				c.add_worker();
				con_info.insert(ip.clone(), c);
			}
		}
	}

	/// Delete worker from this IP
	pub fn delete_worker(&self, ip: &String) {
		if let Some(c) = self.connection_info.write().get_mut(ip) {
			c.delete_worker();
		}
	}

	/// Report workers good shares
	pub fn report_ok_shares(&self, ip: &String) {
		if let Some(c) = self.connection_info.write().get_mut(ip) {
			c.report_ok_shares();
		}
	}

	/// Report worker good login
	pub fn report_ok_login(&self, ip: &String) {
		if let Some(c) = self.connection_info.write().get_mut(ip) {
			c.report_ok_login();
		}
	}

	/// Report worker bad login
	pub fn report_fail_login(&self, ip: &String) {
		if let Some(c) = self.connection_info.write().get_mut(ip) {
			c.report_fail_login();
		}
	}

	/// Report worker bad data
	pub fn report_fail_noise(&self, ip: &String) {
		if let Some(c) = self.connection_info.write().get_mut(ip) {
			c.report_fail_noise();
		}
	}

	/// Get IP list info for API
	pub fn get_ip_list(&self, get_banned: bool, get_active: bool) -> Vec<StratumIpPrintable> {
		let mut res: Vec<StratumIpPrintable> = Vec::new();

		for ip_info in self.connection_info.read().values() {
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
		match self.connection_info.read().get(ip) {
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
	pub fn clean_ip(&self, ip: &String) {
		self.connection_info.write().remove(ip);
	}
}

/// Printable representation of stratum IP address
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StratumIpPrintable {
	/// ip address
	pub ip: String,
	/// flag if this IP currently under the ban
	pub ban: bool,
	/// Last time when connection was accepted, timestamp in ms
	pub last_connect_time_ms: Option<i64>,
	/// Total number of connected workers
	pub workers: i32,
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
				.last_connect_time_ms
				.back()
				.map(|t| t.clone()),
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
