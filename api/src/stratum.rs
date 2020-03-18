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

use crate::core::stratum;
use crate::rest::Error;
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

		if banned.is_some() {
			get_banned = banned.unwrap();
			get_active = !get_banned;
		}

		Ok(self.stratum_ip_pool.get_ip_list(get_banned, get_active))
	}

	pub fn clean_ip(&self, ip: &String) -> Result<(), Error> {
		self.stratum_ip_pool.clean_ip(ip);
		Ok(())
	}

	pub fn get_ip_info(
		&self,
		ip: &String,
	) -> Result<stratum::connections::StratumIpPrintable, Error> {
		Ok(self.stratum_ip_pool.get_ip_info(ip))
	}
}
