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

/// Bitmap segment height assumed for requests and segment calculation
pub const BITMAP_SEGMENT_HEIGHT: u8 = 9;

/// Headers Hash height assumed for requests and segment calculation
pub const HEADERS_SEGMENT_HEIGHT: u8 = 10;

/// Output segment height assumed for requests and segment calculation
pub const OUTPUT_SEGMENT_HEIGHT: u8 = 11;

/// Rangeproof segment height assumed for requests and segment calculation
pub const RANGEPROOF_SEGMENT_HEIGHT: u8 = 11;

/// Kernel segment height assumed for requests and segment calculation
pub const KERNEL_SEGMENT_HEIGHT: u8 = 11;

/// How long the state sync should wait after requesting a segment from a peer before
/// deciding the segment isn't going to arrive. The syncer will then re-request the segment
pub const SEGMENT_REQUEST_TIMEOUT_SECS: i64 = 60;

/// Number of simultaneous requests for segments we should make per available peer. Note this is currently
/// divisible by 3 to try and evenly spread requests amount the 3 main MMRs (Bitmap segments
/// will always be requested first)
pub const SEGMENT_REQUEST_PER_PEER: usize = 6;
/// Maximum number of simultaneous requests. Please note, the data will be processed in a single thread, so
/// don't overload much
pub const SEGMENT_REQUEST_LIMIT: usize = 120;

/// Number of simultaneous requests for blocks we should make per available peer.
pub const BLOCKS_REQUEST_PER_PEER: usize = 30;

/// Maxumum number of blocks that can await into the DB as orphans
pub const BLOCKS_REQUEST_LIMIT: usize = 500;

#[cfg(test)]
mod tests {
	use sysinfo::{
		Components, CpuRefreshKind, Disks, MemoryRefreshKind, Networks, RefreshKind, System,
	};

	#[test]
	fn check_sys_info() {
		// Please note that we use "new_all" to ensure that all lists of
		// CPUs and processes are filled!
		let sys = System::new_with_specifics(
			RefreshKind::new().with_memory(MemoryRefreshKind::everything()),
		);

		println!("=> system:");
		// RAM and swap information:
		println!("total memory: {} bytes", sys.total_memory());
		println!("used memory : {} bytes", sys.used_memory());
		println!("free memory : {} bytes", sys.free_memory());
		println!("available memory : {} bytes", sys.available_memory());
		println!("total swap  : {} bytes", sys.total_swap());
		println!("used swap   : {} bytes", sys.used_swap());
		println!("free swap   : {} bytes", sys.free_swap());

		let num_cores = num_cpus::get();
		println!("CPU Cores   : {} cores", num_cores);
	}
}
