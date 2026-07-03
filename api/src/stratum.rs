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

use crate::rest::Error;
use mwc_core::stratum::{self, connections::StratumIpPoolError};
use std::net::IpAddr;
use std::sync::Arc;

pub struct Stratum {
	stratum_ip_pool: Arc<stratum::connections::StratumIpPool>,
}

impl Stratum {
	/// Create a new API instance with the stratum IP pool
	///
	/// # Arguments
	/// * `stratum_ip_pool` - shared with stratum instance of IP pool
	///
	pub fn new(stratum_ip_pool: Arc<stratum::connections::StratumIpPool>) -> Self {
		Stratum { stratum_ip_pool }
	}

	/// Get Stratum IP list
	pub fn get_ip_list(
		&self,
		banned: Option<bool>,
	) -> Result<Vec<stratum::connections::StratumIpPrintable>, Error> {
		let mut get_banned = true;
		let mut get_active = true;

		if let Some(banned) = banned {
			get_banned = banned;
			get_active = !get_banned;
		}

		Ok(self.stratum_ip_pool.get_ip_list(get_banned, get_active))
	}

	pub fn clean_ip(&self, ip: &String) -> Result<(), Error> {
		let canonical_ip = ip
			.parse::<IpAddr>()
			.map_err(|e| Error::Argument(format!("invalid IP address {}: {}", ip, e)))?
			.to_string();

		self.stratum_ip_pool
			.clean_ip(&canonical_ip)
			.map_err(|err| match err {
				StratumIpPoolError::UnknownIp(_) => {
					Error::NotFound(format!("IP {} not found", canonical_ip))
				}
				StratumIpPoolError::ActiveWorkers(_) => Error::Argument(format!(
					"IP {} has active workers and cannot be cleaned",
					canonical_ip
				)),
				StratumIpPoolError::NoWorkers(ip) => Error::Internal(format!(
					"unexpected zero-worker cleanup error for IP {}",
					ip
				)),
			})
	}

	pub fn get_ip_info(
		&self,
		ip: &String,
	) -> Result<stratum::connections::StratumIpPrintable, Error> {
		Ok(self.stratum_ip_pool.get_ip_info(ip))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn new_stratum() -> Stratum {
		Stratum::new(Arc::new(stratum::connections::StratumIpPool::new(
			100, 1, -1,
		)))
	}

	#[test]
	fn clean_ip_rejects_invalid_ip() {
		let api = new_stratum();
		let ip = "not-an-ip".to_string();

		match api.clean_ip(&ip) {
			Err(Error::Argument(msg)) => assert!(msg.contains("invalid IP address")),
			other => panic!("expected invalid IP argument error, got {:?}", other),
		}
	}

	#[test]
	fn clean_ip_reports_untracked_ip() {
		let api = new_stratum();
		let ip = "127.0.0.1".to_string();

		match api.clean_ip(&ip) {
			Err(Error::NotFound(msg)) => assert!(msg.contains("127.0.0.1")),
			other => panic!("expected not found error, got {:?}", other),
		}
	}

	#[test]
	fn clean_ip_rejects_active_ip() {
		let api = new_stratum();
		let ip = "127.0.0.1".to_string();

		api.stratum_ip_pool.add_worker(&ip);

		match api.clean_ip(&ip) {
			Err(Error::Argument(msg)) => assert!(msg.contains("active workers")),
			other => panic!("expected active worker argument error, got {:?}", other),
		}

		api.stratum_ip_pool.report_ok_shares(&ip).unwrap();
		let info = api.stratum_ip_pool.get_ip_info(&ip);
		assert_eq!(info.workers, 1);
		assert_eq!(info.ok_shares, 1);
	}

	#[test]
	fn clean_ip_removes_inactive_tracked_ip() {
		let api = new_stratum();
		let ip = "127.0.0.1".to_string();

		api.stratum_ip_pool.add_worker(&ip);
		api.stratum_ip_pool.delete_worker(&ip).unwrap();
		api.clean_ip(&ip).unwrap();

		match api.clean_ip(&ip) {
			Err(Error::NotFound(msg)) => assert!(msg.contains("127.0.0.1")),
			other => panic!("expected not found error after cleanup, got {:?}", other),
		}
	}
}
