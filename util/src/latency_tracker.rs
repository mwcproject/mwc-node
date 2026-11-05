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
use std::time::Duration;

/// Rolling latency history for the last seven response or timeout samples.
pub struct LatencyTracker {
	latency_history: VecDeque<i64>,
	latency_sum: i64,
}

impl LatencyTracker {
	/// Start without any latency samples.
	pub fn new() -> Self {
		LatencyTracker {
			latency_history: VecDeque::new(),
			latency_sum: 0,
		}
	}

	/// Add a response latency in milliseconds, ignoring nonpositive samples.
	pub fn add_latency(&mut self, latency_ms: i64) {
		if latency_ms <= 0 {
			return;
		}
		self.latency_history.push_back(latency_ms);
		// Safe: request latency is measured from an in-process timestamp and the
		// history is capped at 7 entries, so the accumulated milliseconds stay
		// far below i64::MAX.
		self.latency_sum += latency_ms;
		while self.latency_history.len() > 7 {
			let Some(lt) = self.latency_history.pop_front() else {
				break;
			};
			// Safe: lt was previously included in latency_sum.
			self.latency_sum -= lt;
		}
	}

	/// Average the retained response durations, if any.
	pub fn get_average_latency(&self) -> Option<Duration> {
		if self.latency_history.is_empty() {
			None
		} else {
			let latency_ms = self.latency_sum / self.latency_history.len() as i64;
			if latency_ms <= 0 {
				Some(Duration::ZERO)
			} else {
				Some(Duration::from_millis(latency_ms as u64))
			}
		}
	}

	/// Allow twice the average latency plus eight seconds, capped by the caller.
	/// Without samples, use the caller's maximum.
	pub fn get_time_out(&self, max_timeout: Duration) -> Duration {
		self.get_average_latency().map_or(max_timeout, |latency| {
			latency
				.saturating_mul(2)
				.saturating_add(Duration::from_secs(8))
				.min(max_timeout)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn timeout_uses_average_plus_eight_seconds_and_the_supplied_cap() {
		let mut tracker = LatencyTracker::new();
		let maximum = Duration::from_secs(30);
		assert_eq!(tracker.get_time_out(maximum), maximum);
		tracker.add_latency(200);
		assert_eq!(tracker.get_time_out(maximum), Duration::from_millis(8400));
		tracker.add_latency(3800);
		assert_eq!(tracker.get_time_out(maximum), Duration::from_secs(12));
		assert_eq!(
			tracker.get_time_out(Duration::from_secs(3)),
			Duration::from_secs(3)
		);
	}

	#[test]
	fn rolling_history_is_bounded_and_zero_samples_are_ignored() {
		let mut tracker = LatencyTracker::new();
		tracker.add_latency(0);
		assert_eq!(tracker.get_average_latency(), None);
		tracker.add_latency(60_000);
		for _ in 0..7 {
			tracker.add_latency(4_000);
		}
		assert_eq!(tracker.latency_history.len(), 7);
		assert_eq!(tracker.get_average_latency(), Some(Duration::from_secs(4)));
		assert_eq!(
			tracker.get_time_out(Duration::from_secs(30)),
			Duration::from_secs(16)
		);
	}

	#[test]
	fn oversized_latency_saturates_at_the_timeout_cap() {
		let mut tracker = LatencyTracker::new();
		tracker.add_latency(i64::MAX);
		assert_eq!(
			tracker.get_time_out(Duration::from_secs(30)),
			Duration::from_secs(30)
		);
	}
}
