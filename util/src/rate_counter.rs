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

use std::collections::VecDeque;
/// Utility to track the rate of data transfers
use std::time::{Duration, Instant};

struct Entry {
	bytes: u64,
	timestamp: Instant,
}

impl Entry {
	fn new(bytes: u64) -> Entry {
		Entry {
			bytes,
			timestamp: Instant::now(),
		}
	}
}

/// A rate counter tracks the number of transfers, the amount of data
/// exchanged and the rate of transfer (via a few timers) over the last
/// minute. The counter does not try to be accurate and update times
/// proactively, instead it only does so lazily. As a result, produced
/// rates are worst-case estimates.
pub struct RateCounter {
	last_min_entries: VecDeque<Entry>,
}

const RATE_ENTRIES_LIMIT: usize = 10000;

impl RateCounter {
	/// Instantiate a new rate counter
	pub fn new() -> RateCounter {
		RateCounter {
			last_min_entries: VecDeque::new(),
		}
	}

	/// Increments number of bytes transferred, updating counts and rates.
	pub fn inc(&mut self, bytes: u64) {
		self.truncate();
		self.last_min_entries.push_back(Entry::new(bytes));
	}

	fn truncate(&mut self) {
		while self.last_min_entries.len() > RATE_ENTRIES_LIMIT
			|| self
				.last_min_entries
				.front()
				.map(|entry| entry.timestamp.elapsed() > Duration::from_secs(60))
				.unwrap_or(false)
		{
			self.last_min_entries.pop_front();
		}
	}

	/// Number of bytes counted in the last minute.
	/// Includes "quiet" byte increments.
	pub fn bytes_per_min(&self) -> u64 {
		let mut sum: u64 = 0;
		for x in &self.last_min_entries {
			sum = sum.saturating_add(x.bytes);
		}
		sum
	}

	/// Count of increases in the last minute.
	pub fn count_per_min(&mut self) -> u64 {
		self.truncate();
		self.last_min_entries.len() as u64
	}
}
