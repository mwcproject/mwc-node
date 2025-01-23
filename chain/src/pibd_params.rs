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

//! Set of static definitions for all parameters related to PIBD and Desegmentation
//! Note these are for experimentation via compilation, not meant to be exposed as
//! configuration parameters anywhere

use chrono::{DateTime, Utc};
use mwc_util::RwLock;
use std::cmp;
use std::sync::Arc;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};

/// Segment heights for Header Hashes. Note, this number is needs to be the same for all network
pub const PIBD_MESSAGE_SIZE_LIMIT: usize = 256 * 1034; // Let's use 256k messages max. I think we should be good to handle that

// Here are series for different available resources. Mem and CPU thresholds are allways the same.
const HEADERS_HASH_BUFFER_LEN: [usize; 4] = [10, 20, 30, 60];

const HEADERS_BUFFER_LEN: [usize; 4] = [50, 100, 250, 400];
const BITMAPS_BUFFER_LEN: [usize; 4] = [10, 20, 30, 40];

// segment size are from around 30-40 kB. Then double for every level
const SEGMENTS_BUFFER_LEN: [usize; 4] = [30, 40, 50, 60];

// One block can be up to 1.5Mb in size. We still need some to run the node
const ORPHANS_BUFFER_LEN: [usize; 4] = [20, 100, 250, 500];

const SEGMENTS_REQUEST_LIMIT: [usize; 4] = [20, 30, 40, 40];

/// How long the state sync should wait after requesting a segment from a peer before
/// deciding the segment isn't going to arrive. The syncer will then re-request the segment
pub const PIBD_REQUESTS_TIMEOUT_SECS: i64 = 30;

struct SysMemoryInfo {
	available_memory_mb: u64,
	update_time: DateTime<Utc>,
}

impl SysMemoryInfo {
	fn update() -> Self {
		let sys = System::new_with_specifics(
			RefreshKind::new().with_memory(MemoryRefreshKind::new().with_ram()),
		);
		let available_memory_mb = sys.available_memory() / 1024 / 1024;
		debug!("System Available Memory: {} mb", available_memory_mb);
		SysMemoryInfo {
			available_memory_mb,
			update_time: Utc::now(),
		}
	}
}

struct NetworkSpeed {
	last_network_speed_update: DateTime<Utc>,
	network_speed_multiplier: f64,
}

/// Pibd Sync related params. Note, most of settings are dynamic calculated to match available resources.
pub struct PibdParams {
	cpu_num: usize,
	sys_memory_info: Arc<RwLock<SysMemoryInfo>>,
	network_speed: RwLock<NetworkSpeed>,
}

impl PibdParams {
	/// Create new PibdParams instance. Expected one instance for at least whole sync session.
	pub fn new() -> Self {
		let num_cores = num_cpus::get();
		let mem_info = SysMemoryInfo::update();
		let res = PibdParams {
			cpu_num: num_cores,
			sys_memory_info: Arc::new(RwLock::new(mem_info)),
			network_speed: RwLock::new(NetworkSpeed {
				last_network_speed_update: Utc::now(),
				network_speed_multiplier: 1.0,
			}),
		};
		debug!(
			"PibdParams config: cpu_num={}, available_memory_mb={}",
			res.cpu_num,
			res.sys_memory_info.read().available_memory_mb
		);
		res
	}

	/// Buffer size for header hashes
	pub fn get_headers_hash_buffer_len(&self) -> usize {
		Self::calc_mem_adequate_val2(
			&HEADERS_HASH_BUFFER_LEN,
			self.get_available_memory_mb(),
			self.cpu_num,
		)
	}

	/// Buffer size for headers
	pub fn get_headers_buffer_len(&self) -> usize {
		Self::calc_mem_adequate_val2(
			&HEADERS_BUFFER_LEN,
			self.get_available_memory_mb(),
			self.cpu_num,
		)
	}

	/// Buffer size for output bitmaps
	pub fn get_bitmaps_buffer_len(&self) -> usize {
		Self::calc_mem_adequate_val2(
			&BITMAPS_BUFFER_LEN,
			self.get_available_memory_mb(),
			self.cpu_num,
		)
	}

	/// Buffer size for outputs
	pub fn get_segments_buffer_len(&self) -> usize {
		Self::calc_mem_adequate_val2(
			&SEGMENTS_BUFFER_LEN,
			self.get_available_memory_mb(),
			self.cpu_num,
		)
	}

	/// Man number of orphans to keep
	pub fn get_orphans_num_limit(&self) -> usize {
		Self::calc_mem_adequate_val2(
			&ORPHANS_BUFFER_LEN,
			self.get_available_memory_mb(),
			self.cpu_num,
		)
	}

	/// Number of simultaneous requests for blocks we should make per available peer.
	pub fn get_blocks_request_per_peer(&self) -> usize {
		cmp::min(8, self.cpu_num * 2)
	}

	/// Maxumum number of blocks that can await into the DB as orphans
	pub fn get_blocks_request_limit(&self, average_latency_ms: u32) -> usize {
		let req_limit = self.get_orphans_num_limit() / 2;
		cmp::max(
			1,
			(req_limit as f64 * self.get_network_speed_multiplier(average_latency_ms)).round()
				as usize,
		)
	}

	/// Number of simultaneous requests for segments we should make per available peer. Note this is currently
	/// divisible by 3 to try and evenly spread requests amount the 3 main MMRs (Bitmap segments
	/// will always be requested first)
	pub fn get_segments_request_per_peer(&self) -> usize {
		cmp::min(8, self.cpu_num * 2)
	}

	/// Maximum number of simultaneous requests. Please note, the data will be processed in a single thread, so
	/// don't overload much
	pub fn get_segments_requests_limit(&self, average_latency_ms: u32) -> usize {
		let req_limit = Self::calc_mem_adequate_val2(
			&SEGMENTS_REQUEST_LIMIT,
			self.get_available_memory_mb(),
			self.cpu_num,
		);
		cmp::max(
			1,
			(req_limit as f64 * self.get_network_speed_multiplier(average_latency_ms)).round()
				as usize,
		)
	}

	fn get_network_speed_multiplier(&self, average_latency_ms: u32) -> f64 {
		if average_latency_ms == 0 || average_latency_ms == 30000 {
			return 1.0;
		}
		if (Utc::now() - self.network_speed.read().last_network_speed_update).num_seconds() > 5 {
			let mut network_speed = self.network_speed.write();
			network_speed.last_network_speed_update = Utc::now();
			let expected_latency_ms = PIBD_REQUESTS_TIMEOUT_SECS as u32 / 2 * 1000;
			if average_latency_ms < expected_latency_ms {
				let update_mul =
					(expected_latency_ms - average_latency_ms) as f64 / expected_latency_ms as f64;
				debug_assert!(update_mul >= 0.0 && update_mul <= 1.0);
				network_speed.network_speed_multiplier =
					1.0f64.min((network_speed.network_speed_multiplier) * (1.0 + 0.1 * update_mul));
			} else {
				let update_mul =
					(average_latency_ms - expected_latency_ms) as f64 / expected_latency_ms as f64;
				let update_mul = 1.0f64.min(update_mul);
				debug_assert!(update_mul >= 0.0 && update_mul <= 1.0);
				network_speed.network_speed_multiplier = 0.05f64
					.max((network_speed.network_speed_multiplier) / (1.0 + 0.15 * update_mul));
			}
			debug!(
				"for current latency {} ms the new network speed multiplier is {}",
				average_latency_ms, network_speed.network_speed_multiplier
			);
			network_speed.network_speed_multiplier
		} else {
			self.network_speed.read().network_speed_multiplier
		}
	}

	fn get_available_memory_mb(&self) -> u64 {
		let mut sys_memory_info = self.sys_memory_info.write();
		if (Utc::now() - sys_memory_info.update_time).num_seconds() > 2 {
			*sys_memory_info = SysMemoryInfo::update();
		}
		sys_memory_info.available_memory_mb
	}

	fn calc_mem_adequate_val2<T: Clone>(
		vals: &[T],
		available_memory_mb: u64,
		num_cores: usize,
	) -> T {
		debug_assert!(vals.len() > 0);

		if available_memory_mb < 500 || num_cores <= 1 {
			vals[0].clone()
		} else if available_memory_mb < 1000 || num_cores <= 2 {
			vals[cmp::min(1, vals.len() - 1)].clone()
		} else if available_memory_mb < 2000 {
			vals[cmp::min(2, vals.len() - 1)].clone()
		} else {
			debug_assert!(vals.len() <= 4); // it is not true, add more ifs for memory checking
			vals[cmp::min(3, vals.len() - 1)].clone()
		}
	}
}

#[cfg(test)]
mod tests {
	use sysinfo::{MemoryRefreshKind, RefreshKind, System};

	#[test]
	fn check_sys_info() {
		// Please note that we use "new_all" to ensure that all lists of
		// CPUs and processes are filled!
		let mut sys = System::new_with_specifics(
			RefreshKind::new().with_memory(MemoryRefreshKind::new().with_ram()),
		);

		sys.refresh_memory_specifics(MemoryRefreshKind::new().with_ram());

		println!("=> system:");
		// RAM and swap information:
		println!("total memory: {} mb", sys.total_memory() / 1024 / 1024);
		println!("used memory : {} mb", sys.used_memory() / 1024 / 1024);
		println!("free memory : {} mb", sys.free_memory() / 1024 / 1024);
		println!(
			"available memory : {} mb",
			sys.available_memory() / 1024 / 1024
		);
		//println!("total swap  : {} bytes", sys.total_swap());
		//println!("used swap   : {} bytes", sys.used_swap());
		//println!("free swap   : {} bytes", sys.free_swap());

		let num_cores = num_cpus::get();
		println!("CPU Cores   : {} cores", num_cores);
	}
}
