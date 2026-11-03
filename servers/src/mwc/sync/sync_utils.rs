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

// sync_utils contain banch of shared between mutiple sync modules routines
// Normally we would put that into the base class, but rust doesn't support that.

use mwc_chain::{Chain, Error};
use mwc_p2p::{Capabilities, Peer, Peers};
use std::cmp;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// current height back to 0 decreasing in powers of 2
pub fn get_locator_heights(height: u64) -> Vec<u64> {
	let mut current = height;
	let mut heights = vec![];
	while current > 0 {
		heights.push(current);
		if heights.len() >= (mwc_p2p::MAX_LOCATORS as usize) - 1 {
			break;
		}
		let next = 2u64.pow(heights.len() as u32);
		current = if current > next { current - next } else { 0 }
	}
	heights.push(0);
	heights
}

#[derive(Clone, Debug, PartialEq)]
pub enum SyncRequestResponses {
	Syncing,
	WaitingForPeers,
	HeadersHashReady,
	WaitingForHeadersHash,
	HeadersPibdReady,
	HeadersReady,
	HasMoreHeadersToApply,
	WaitingForHeaders,
	StatePibdReady,
	BodyReady,
	SyncDone,
}

#[derive(Clone, Debug)]
pub struct SyncResponse {
	pub response: SyncRequestResponses,
	pub peers_capabilities: Capabilities,
	pub message: String,
}

impl SyncResponse {
	pub fn new(
		response: SyncRequestResponses,
		peers_capabilities: Capabilities,
		message: String,
	) -> Self {
		SyncResponse {
			response,
			peers_capabilities,
			message,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuorumSelection<V, I> {
	Selected { value: V, items: Vec<I> },
	NeedMoreResponses { responses: usize },
	NoQuorum { responses: usize, best_count: usize },
}

pub fn select_quorum<I, V>(
	items: impl Iterator<Item = I>,
	required_responses: usize,
	min_responses: usize,
	value_fn: impl Fn(&I) -> V,
) -> QuorumSelection<V, I>
where
	V: Copy + Eq + std::hash::Hash,
{
	let required_responses = cmp::max(required_responses, min_responses);
	let mut items_by_value: HashMap<V, Vec<I>> = HashMap::new();
	let mut responses = 0;
	for item in items {
		responses += 1;
		items_by_value
			.entry(value_fn(&item))
			.or_default()
			.push(item);
	}

	if responses < required_responses {
		return QuorumSelection::NeedMoreResponses { responses };
	}

	let (best_value, best_items) = match items_by_value
		.into_iter()
		.max_by_key(|(_, items)| items.len())
	{
		Some(best) => best,
		None => {
			return QuorumSelection::NeedMoreResponses { responses };
		}
	};
	let best_count = best_items.len();
	if best_count >= required_responses {
		QuorumSelection::Selected {
			value: best_value,
			items: best_items,
		}
	} else {
		QuorumSelection::NoQuorum {
			responses,
			best_count,
		}
	}
}

#[derive(Clone)]
pub struct CachedResponse<T> {
	time: Instant,
	response: T,
}

impl<T> CachedResponse<T> {
	pub fn new(response: T, timeout: Duration) -> Result<Self, Error> {
		let now = Instant::now();
		let time = now.checked_add(timeout).ok_or_else(|| {
			Error::DataOverflow(format!(
				"CachedResponse timeout exceeds representable Instant range: {:?}",
				timeout
			))
		})?;
		Ok(CachedResponse { time, response })
	}

	pub fn is_expired(&self) -> bool {
		Instant::now() > self.time
	}

	pub fn to_response(self) -> T {
		self.response
	}
}

/// Get a list of qualify peers. Peers that has needed height and capability
pub fn get_qualify_peers(
	peers: &Arc<Peers>,
	archive_height: u64,
	capability: Capabilities,
) -> Vec<Arc<Peer>> {
	// First, get max difficulty or greater peers
	peers
		.iter()
		.outbound()
		.connected()
		.into_iter()
		.filter(|peer| {
			let (height, _) = peer.info.get_height_and_difficulty();
			Chain::height_2_archive_height(peers.get_context_id(), height) == archive_height
				&& peer.info.capabilities.contains(capability)
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::{CachedResponse, QuorumSelection};
	use mwc_chain::pibd_params;
	use mwc_util::LatencyTracker;
	use std::time::Duration;

	#[test]
	fn empty_latency_history_has_no_average() {
		let tracker = LatencyTracker::new();

		assert_eq!(tracker.get_average_latency(), None);
	}

	#[test]
	fn cached_response_returns_error_for_oversized_timeout() {
		let response = CachedResponse::new(42, Duration::new(u64::MAX, 999_999_999));

		assert!(matches!(response, Err(mwc_chain::Error::DataOverflow(_))));
	}

	#[test]
	fn quorum_selection_returns_selected_value_and_items() {
		let selection = super::select_quorum(
			vec![("a", 1), ("b", 2), ("c", 1)].into_iter(),
			2,
			2,
			|(_, value)| *value,
		);

		assert_eq!(
			selection,
			super::QuorumSelection::Selected {
				value: 1,
				items: vec![("a", 1), ("c", 1)]
			}
		);
	}

	#[test]
	fn sync_height_selection_ignores_single_archive_height_outlier() {
		let votes = vec![(300, 350), (100, 150), (100, 160), (100, 170)];
		let selection = super::select_quorum(votes.into_iter(), 3, 2, |(archive_height, _)| {
			*archive_height
		});

		match selection {
			QuorumSelection::Selected {
				value: archive_height,
				items,
			} => {
				let best_height = items.iter().map(|(_, height)| *height).max();
				assert_eq!(archive_height, 100);
				assert_eq!(best_height, Some(170));
				assert_eq!(items, vec![(100, 150), (100, 160), (100, 170)]);
			}
			_ => panic!("expected selected archive height"),
		}
	}

	#[test]
	fn sync_height_selection_rejects_split_without_strict_majority() {
		let selection = super::select_quorum(
			vec![(200, 250), (200, 251), (100, 150), (100, 151)].into_iter(),
			3,
			2,
			|(archive_height, _)| *archive_height,
		);

		assert_eq!(
			selection,
			QuorumSelection::NoQuorum {
				responses: 4,
				best_count: 2
			}
		);
	}

	#[test]
	fn sync_height_selection_requires_at_least_two_peers() {
		let selection =
			super::select_quorum(vec![(100, 150)].into_iter(), 1, 2, |(archive_height, _)| {
				*archive_height
			});

		assert_eq!(
			selection,
			QuorumSelection::NeedMoreResponses { responses: 1 }
		);
	}

	#[test]
	fn timeout_latency_sample_is_measured_latency() {
		let mut tracker = LatencyTracker::new();
		let timeout_ms = pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as i64 * 1000;

		tracker.add_latency(timeout_ms);

		assert_eq!(
			tracker.get_average_latency(),
			Some(Duration::from_millis(timeout_ms as u64))
		);
	}
}

#[cfg(test)]
mod locator_tests {
	use super::get_locator_heights;

	#[test]
	fn test_get_locator_heights() {
		assert_eq!(get_locator_heights(0), vec![0]);
		assert_eq!(get_locator_heights(1), vec![1, 0]);
		assert_eq!(get_locator_heights(2), vec![2, 0]);
		assert_eq!(get_locator_heights(3), vec![3, 1, 0]);
		assert_eq!(get_locator_heights(10), vec![10, 8, 4, 0]);
		assert_eq!(get_locator_heights(100), vec![100, 98, 94, 86, 70, 38, 0]);
		assert_eq!(
			get_locator_heights(1000),
			vec![1000, 998, 994, 986, 970, 938, 874, 746, 490, 0]
		);
		// check the locator is still a manageable length, even for large numbers of
		// headers
		assert_eq!(
			get_locator_heights(10000),
			vec![10000, 9998, 9994, 9986, 9970, 9938, 9874, 9746, 9490, 8978, 7954, 5906, 1810, 0,]
		);
	}
}
