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
use grin_core::core::{Segment, SegmentIdentifier};
use std::cmp;
use std::collections::HashMap;

/// Cahing for some type of segments. Segments are coming out of order, and we need to handle that.
//#[derive(Clone)]
pub struct SegmentsCache<T> {
	// Cached segments, waiting to apply
	segment_cache: HashMap<i32, Segment<T>>,

	// Height to track progress.
	required_segments: i32,
	received_segments: i32,
}

impl<T> SegmentsCache<T> {
	/// Create a new instance
	pub fn new(required_segments: i32) -> Self {
		SegmentsCache {
			segment_cache: HashMap::new(),
			required_segments,
			received_segments: 0,
		}
	}

	/*    pub fn open(required_segments : i32) -> Self {
		SegmentsCache {
			segment_cache: HashMap::new(),
			required_segments,
			received_segments: required_segments
		}
	}*/

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
	pub fn get_required_segments(&self) -> i32 {
		self.required_segments
	}

	/// Recieved segments (without cached)
	pub fn get_received_segments(&self) -> i32 {
		self.received_segments
	}

	/// Return list of the next preferred segments the desegmenter needs based on
	/// the current real state of the underlying elements
	pub fn next_desired_segments(
		&self,
		height: u8,
		max_elements: i32,
	) -> Result<Vec<SegmentIdentifier>, Error> {
		let mut return_vec = vec![];

		let segm_lim = cmp::min(
			self.received_segments + max_elements,
			self.required_segments,
		);
		for idx in self.received_segments..segm_lim {
			if !self.segment_cache.contains_key(&idx) {
				return_vec.push(SegmentIdentifier {
					height: height,
					idx: idx as u64,
				});
			}
		}
		Ok(return_vec)
	}

	pub fn is_duplicate_segment(&self, segment_idx: i32) -> bool {
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
		self.segment_cache.insert(segment.id().idx as i32, segment);

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
		}

		Ok(())
	}
}
