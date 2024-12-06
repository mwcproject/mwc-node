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
use std::ops::Range;
use std::sync::Arc;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};

/// Segment heights for Header Hashes
pub const HEADERS_HASHES_SEGMENT_HEIGHT_RANGE: Range<u8> = 10..13; // ~32b
/// Segment heights for kernels
pub const KERNEL_SEGMENT_HEIGHT_RANGE: Range<u8> = 8..11; // ~ 100 b
/// Segment heights for output bitmaps
pub const BITMAP_SEGMENT_HEIGHT_RANGE: Range<u8> = 8..11; // ~ 128 b
/// Segment heights for outputs
pub const OUTPUT_SEGMENT_HEIGHT_RANGE: Range<u8> = 10..13; // ~ 33 b
/// Segment heights for rangeproofs
pub const RANGEPROOF_SEGMENT_HEIGHT_RANGE: Range<u8> = 6..9; // ~ 675 b

// Here are series for different available resources. Mem and CPU thresholds are allways the same.
const HEADERS_HASH_BUFFER_LEN: [usize; 4] = [10, 20, 30, 60];
const BITMAPS_BUFFER_LEN: [usize; 4] = [10, 20, 30, 40];

const OUTPUTS_BUFFER_LEN: [usize; 4] = [7, 15, 30, 40];
const KERNELS_BUFFER_LEN: [usize; 4] = [7, 15, 30, 40];
const RANGEPROOFS_BUFFER_LEN: [usize; 4] = [7, 15, 30, 40];

// One block can be up to 1.5Mb in size. We still need some to run the node
const ORPHANS_BUFFER_LEN: [usize; 4] = [20, 100, 250, 500];

const SEGMENTS_REQUEST_LIMIT: [usize; 4] = [20, 40, 80, 120];

/// How long the state sync should wait after requesting a segment from a peer before
/// deciding the segment isn't going to arrive. The syncer will then re-request the segment
pub const SEGMENT_REQUEST_TIMEOUT_SECS: i64 = 60;

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

/// Pibd Sync related params. Note, most of settings are dynamic calculated to match available resources.
pub struct PibdParams {
	cpu_num: usize,
	sys_memory_info: Arc<RwLock<SysMemoryInfo>>,

	bitmap_segment_height: u8,
	headers_segment_height: u8,
	output_segment_height: u8,
	rangeproof_segment_height: u8,
	kernel_segment_height: u8,
}

impl PibdParams {
	/// Create new PibdParams instance. Expected one instance for at least whole sync session.
	pub fn new() -> Self {
		let num_cores = num_cpus::get();
		let mem_info = SysMemoryInfo::update();
		let res = PibdParams {
			cpu_num: num_cores,
			bitmap_segment_height: Self::calc_mem_adequate_val(
				&BITMAP_SEGMENT_HEIGHT_RANGE,
				mem_info.available_memory_mb,
				num_cores,
			),
			headers_segment_height: Self::calc_mem_adequate_val(
				&HEADERS_HASHES_SEGMENT_HEIGHT_RANGE,
				mem_info.available_memory_mb,
				num_cores,
			),
			output_segment_height: Self::calc_mem_adequate_val(
				&OUTPUT_SEGMENT_HEIGHT_RANGE,
				mem_info.available_memory_mb,
				num_cores,
			),
			rangeproof_segment_height: Self::calc_mem_adequate_val(
				&RANGEPROOF_SEGMENT_HEIGHT_RANGE,
				mem_info.available_memory_mb,
				num_cores,
			),
			kernel_segment_height: Self::calc_mem_adequate_val(
				&KERNEL_SEGMENT_HEIGHT_RANGE,
				mem_info.available_memory_mb,
				num_cores,
			),
			sys_memory_info: Arc::new(RwLock::new(mem_info)),
		};
		debug!("PibdParams config: cpu_num={}, bitmap_segment_height={}, headers_segment_height={}, output_segment_height={}, rangeproof_segment_height={}, kernel_segment_height={}, available_memory_mb={}",
			res.cpu_num, res.bitmap_segment_height, res.headers_segment_height, res.output_segment_height, res.rangeproof_segment_height, res.kernel_segment_height, res.sys_memory_info.read().available_memory_mb );
		res
	}

	/// Get segment height for output bitmaps
	pub fn get_bitmap_segment_height(&self) -> u8 {
		self.bitmap_segment_height
	}
	/// Get segment height for header hashes
	pub fn get_headers_segment_height(&self) -> u8 {
		self.headers_segment_height
	}
	/// Get segment height for outputs
	pub fn get_output_segment_height(&self) -> u8 {
		self.output_segment_height
	}
	/// Get segment height for rangeproofs
	pub fn get_rangeproof_segment_height(&self) -> u8 {
		self.rangeproof_segment_height
	}
	/// Get segment height for kernels
	pub fn get_kernel_segment_height(&self) -> u8 {
		self.kernel_segment_height
	}

	/// Buffer size for header hashes
	pub fn get_headers_hash_buffer_len(&self) -> usize {
		Self::calc_mem_adequate_val2(
			&HEADERS_HASH_BUFFER_LEN,
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
	pub fn get_outputs_buffer_len(&self, non_complete_num: usize) -> usize {
		let k = if non_complete_num <= 1 { 2 } else { 1 };
		Self::calc_mem_adequate_val2(
			&OUTPUTS_BUFFER_LEN,
			self.get_available_memory_mb(),
			self.cpu_num,
		) * k
	}

	/// Buffer size for kernels
	pub fn get_kernels_buffer_len(&self, non_complete_num: usize) -> usize {
		let k = if non_complete_num <= 1 { 2 } else { 1 };
		Self::calc_mem_adequate_val2(
			&KERNELS_BUFFER_LEN,
			self.get_available_memory_mb(),
			self.cpu_num,
		) * k
	}

	/// Buffer size for rangeproofs
	pub fn get_rangeproofs_buffer_len(&self, non_complete_num: usize) -> usize {
		let k = if non_complete_num <= 1 { 2 } else { 1 };
		Self::calc_mem_adequate_val2(
			&RANGEPROOFS_BUFFER_LEN,
			self.get_available_memory_mb(),
			self.cpu_num,
		) * k
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
		match self.cpu_num {
			1 => 3,
			2 => 6,
			_ => 15,
		}
	}

	/// Maxumum number of blocks that can await into the DB as orphans
	pub fn get_blocks_request_limit(&self) -> usize {
		self.get_orphans_num_limit() / 2
	}

	/// Number of simultaneous requests for segments we should make per available peer. Note this is currently
	/// divisible by 3 to try and evenly spread requests amount the 3 main MMRs (Bitmap segments
	/// will always be requested first)
	pub fn get_segments_request_per_peer(&self) -> usize {
		match self.cpu_num {
			1 => 2,
			2 => 4,
			_ => 6,
		}
	}

	/// Maximum number of simultaneous requests. Please note, the data will be processed in a single thread, so
	/// don't overload much
	pub fn get_segments_requests_limit(&self) -> usize {
		Self::calc_mem_adequate_val2(
			&SEGMENTS_REQUEST_LIMIT,
			self.get_available_memory_mb(),
			self.cpu_num,
		)
	}

	fn get_available_memory_mb(&self) -> u64 {
		let mut sys_memory_info = self.sys_memory_info.write();
		if (Utc::now() - sys_memory_info.update_time).num_seconds() > 2 {
			*sys_memory_info = SysMemoryInfo::update();
		}
		sys_memory_info.available_memory_mb
	}

	fn calc_mem_adequate_val(range: &Range<u8>, available_memory_mb: u64, num_cores: usize) -> u8 {
		if available_memory_mb < 500 || num_cores <= 1 {
			range.start
		} else if available_memory_mb < 1000 || num_cores <= 2 {
			cmp::min(range.start.saturating_add(1), range.end.saturating_sub(1))
		} else {
			debug_assert!(range.end - range.start <= 3); // it is not true, add more ifs for memory checking
			cmp::min(range.start.saturating_add(2), range.end.saturating_sub(1))
		}
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
