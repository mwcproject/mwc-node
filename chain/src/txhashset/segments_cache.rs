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

//! Manages the segments caching

use crate::error::Error;
use crate::pibd_params;
use crate::txhashset::request_lookup::RequestLookup;
use mwc_core::core::{Segment, SegmentIdentifier, SegmentType};
use std::cmp;
use std::collections::HashMap;

/// Cahing for some type of segments. Segments are coming out of order, and we need to handle that.
//#[derive(Clone)]
pub struct SegmentsCache<T> {
	// Cached segments, waiting to apply
	seg_type: SegmentType,
	segment_cache: HashMap<u64, Segment<T>>,

	// Height to track progress.
	required_segments: u64,
	received_segments: u64,
}

impl<T> SegmentsCache<T> {
	/// Create a new instance
	pub fn new(seg_type: SegmentType, required_segments: u64) -> Self {
		SegmentsCache {
			seg_type,
			segment_cache: HashMap::new(),
			required_segments,
			received_segments: 0,
		}
	}

	/// Clear the data
	pub fn reset(&mut self) {
		self.segment_cache.clear();
		self.received_segments = 0;
	}

	/// Check if the requests are completed
	pub fn is_complete(&self) -> bool {
		self.received_segments == self.required_segments
	}

	/// Requered segments
	pub fn get_required_segments(&self) -> u64 {
		self.required_segments
	}

	/// Recieved segments (without cached)
	pub fn get_received_segments(&self) -> u64 {
		self.received_segments
	}

	/// Return list of the next preferred segments the desegmenter needs based on
	/// the current real state of the underlying elements, retry requests, all waiting requests
	pub fn next_desired_segments(
		&self,
		height: u8,
		max_elements: usize,
		requested: &dyn RequestLookup<(SegmentType, u64)>,
		cache_size_limit: usize,
	) -> (
		Vec<SegmentIdentifier>,
		Vec<SegmentIdentifier>,
		Vec<SegmentIdentifier>,
	) {
		let mut result = vec![];
		debug_assert!(max_elements > 0);
		debug_assert!(cache_size_limit > 0);
		// We don't want keep too many segments into the cache. 100 seems like a very reasonable number. Segments are relatevly large.
		let max_segm_idx = cmp::min(
			self.received_segments + cache_size_limit as u64,
			self.required_segments,
		);

		let mut waiting_indexes: Vec<(u64, SegmentIdentifier)> = Vec::new();
		let mut first_in_cache = 0;
		let mut last_in_cache = 0;
		let mut has_5_idx = 0;

		for idx in self.received_segments..max_segm_idx {
			if self.segment_cache.contains_key(&idx) {
				if idx == last_in_cache + 1 {
					last_in_cache = idx;
				} else {
					first_in_cache = idx;
					last_in_cache = idx;
				}
				continue;
			}

			if last_in_cache > 0 {
				if last_in_cache - first_in_cache > pibd_params::SEGMENTS_RETRY_DELTA {
					has_5_idx = first_in_cache;
				}
				first_in_cache = 0;
				last_in_cache = 0;
			}

			let request = SegmentIdentifier {
				height: height,
				idx: idx,
			};

			if !requested.contains_request(&(self.seg_type.clone(), idx)) {
				result.push(request);
				if result.len() >= max_elements {
					break;
				}
			} else {
				waiting_indexes.push((idx, request));
			}
		}

		// Let's check if we want to retry something...
		let mut retry_vec = vec![];
		if has_5_idx > 0 {
			for (idx, req) in &waiting_indexes {
				if *idx >= has_5_idx {
					break;
				}
				retry_vec.push(req.clone());
			}
		}

		(
			result,
			retry_vec,
			waiting_indexes.into_iter().map(|w| w.1).collect(),
		)
	}

	pub fn is_duplicate_segment(&self, segment_idx: u64) -> bool {
		segment_idx < self.received_segments || self.segment_cache.contains_key(&segment_idx)
	}

	pub fn apply_new_segment<F>(
		&mut self,
		segment: Segment<T>,
		mut callback: F,
	) -> Result<(), Error>
	where
		F: FnMut(Vec<Segment<T>>) -> Result<(), Error>,
	{
		if segment.id().idx < self.received_segments {
			return Ok(());
		}

		self.segment_cache.insert(segment.id().idx, segment);

		// apply found data from the cache
		let mut segments: Vec<Segment<T>> = Vec::new();
		let mut received_segments = 0;
		while self.received_segments + received_segments < self.required_segments {
			match self
				.segment_cache
				.remove(&(self.received_segments + received_segments))
			{
				Some(v) => {
					segments.push(v);
					received_segments += 1;
				}
				None => break,
			}
		}

		if !segments.is_empty() {
			callback(segments)?;
			self.received_segments += received_segments;
			let received_segments = self.received_segments;
			self.segment_cache.retain(|idx, _| *idx > received_segments);
		}

		Ok(())
	}
}
