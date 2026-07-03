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
	required_segments: Vec<SegmentIdentifier>,
	received_segments: usize,
}

impl<T> SegmentsCache<T> {
	/// Create a new instance
	pub fn new(seg_type: SegmentType, required_segments: Vec<SegmentIdentifier>) -> Self {
		SegmentsCache {
			seg_type,
			segment_cache: HashMap::new(),
			required_segments,
			received_segments: 0,
		}
	}

	/// This cache Segment type
	pub fn get_segment_type(&self) -> &SegmentType {
		&self.seg_type
	}

	fn required_segment_idx(&self, seg_id: &SegmentIdentifier) -> Result<Option<usize>, Error> {
		let leaf_offset = seg_id.leaf_offset()?;

		let mut left = 0;
		let mut right = self.required_segments.len();
		while left < right {
			let mid = left + (right - left) / 2;
			match self.required_segments[mid].leaf_offset()?.cmp(&leaf_offset) {
				cmp::Ordering::Less => left = mid + 1,
				cmp::Ordering::Greater => right = mid,
				cmp::Ordering::Equal => {
					if self.required_segments[mid] == *seg_id {
						return Ok(Some(mid));
					} else {
						return Ok(None);
					}
				}
			}
		}

		Ok(None)
	}

	pub fn has_segment(&self, seg_id: &SegmentIdentifier) -> Result<bool, Error> {
		Ok(self.required_segment_idx(seg_id)?.is_some())
	}

	/// Check whether this segment is in the active receive/cache window.
	pub fn is_segment_in_receive_window(
		&self,
		seg_id: &SegmentIdentifier,
		cache_size_limit: usize,
	) -> Result<bool, Error> {
		let Some(seg_idx) = self.required_segment_idx(seg_id)? else {
			return Ok(false);
		};
		let max_segm_idx = cmp::min(
			self.received_segments.saturating_add(cache_size_limit),
			self.required_segments.len(),
		);

		Ok(seg_idx >= self.received_segments && seg_idx < max_segm_idx)
	}

	/// Clear the data
	pub fn reset(&mut self) {
		self.segment_cache.clear();
		self.received_segments = 0;
	}

	/// Check if the requests are completed
	pub fn is_complete(&self) -> bool {
		self.received_segments >= self.required_segments.len()
	}

	/// Requered segments
	pub fn get_required_segments_num(&self) -> usize {
		self.required_segments.len()
	}

	/// Recieved segments (without cached)
	#[cfg(test)]
	pub fn get_received_segments(&self) -> usize {
		self.received_segments
	}

	/// Received segments including validated segments cached behind a gap.
	pub fn get_accepted_segments(&self) -> usize {
		self.received_segments
			.saturating_add(self.segment_cache.len())
			.min(self.required_segments.len())
	}

	/// Return list of the next preferred segments the desegmenter needs based on
	/// the current real state of the underlying elements, retry requests, all waiting requests
	pub fn next_desired_segments(
		&self,
		max_elements: usize,
		requested: &dyn RequestLookup<(SegmentType, u64)>,
		cache_size_limit: usize,
	) -> Result<
		(
			Vec<SegmentIdentifier>,
			Vec<SegmentIdentifier>,
			Vec<SegmentIdentifier>,
		),
		Error,
	> {
		if max_elements == 0 {
			return Ok((Vec::new(), Vec::new(), Vec::new()));
		}
		if cache_size_limit == 0 {
			return Err(Error::InvalidSegment(
				"cache_size_limit must be greater than zero".to_string(),
			));
		}

		let mut result = vec![];
		// We don't want keep too many segments into the cache. 100 seems like a very reasonable number. Segments are relatively large.
		let max_segm_idx = cmp::min(
			self.received_segments.saturating_add(cache_size_limit),
			self.required_segments.len(),
		);

		let mut waiting_indexes: Vec<(usize, SegmentIdentifier)> = Vec::new();
		let mut cached_run: Option<(usize, usize)> = None;
		let mut retry_before_idx: Option<usize> = None;
		let retry_delta = cache_size_limit / 5;
		let evaluate_cached_run = |cached_run: Option<(usize, usize)>| -> Option<usize> {
			let (first_in_cache, last_in_cache) = cached_run?;
			if last_in_cache - first_in_cache > retry_delta {
				Some(first_in_cache)
			} else {
				None
			}
		};

		for idx in self.received_segments..max_segm_idx {
			let segm = &self.required_segments[idx];
			let leaf_offset = segm.leaf_offset()?;
			if self.segment_cache.contains_key(&leaf_offset) {
				cached_run = Some(match cached_run {
					Some((first_in_cache, _)) => (first_in_cache, idx),
					None => (idx, idx),
				});
				continue;
			}

			if let Some(idx) = evaluate_cached_run(cached_run.take()) {
				retry_before_idx = Some(idx);
			}

			if !requested.contains_request(&(self.seg_type.clone(), leaf_offset)) {
				result.push(segm.clone());
				if result.len() >= max_elements {
					break;
				}
			} else {
				waiting_indexes.push((idx, segm.clone()));
			}
		}

		if let Some(idx) = evaluate_cached_run(cached_run) {
			retry_before_idx = Some(idx);
		}

		// Let's check if we want to retry something...
		let mut retry_vec = vec![];
		if let Some(retry_before_idx) = retry_before_idx {
			for (idx, req) in &waiting_indexes {
				if *idx >= retry_before_idx {
					break;
				}
				retry_vec.push(req.clone());
			}
		}

		Ok((
			result,
			retry_vec,
			waiting_indexes.into_iter().map(|w| w.1).collect(),
		))
	}

	pub fn is_duplicate_segment(&self, seg_id: &SegmentIdentifier) -> Result<bool, Error> {
		let leaf_offset = seg_id.leaf_offset()?;
		if self.received_segments >= self.required_segments.len()
			|| leaf_offset < self.required_segments[self.received_segments].leaf_offset()?
		{
			return Ok(true);
		}
		Ok(self.segment_cache.contains_key(&leaf_offset))
	}

	pub fn apply_new_segment<F>(
		&mut self,
		segment: Segment<T>,
		pruned: bool,
		cache_size_limit: usize,
		mut callback: F,
	) -> Result<(), Error>
	where
		T: Clone,
		F: FnMut(Vec<Segment<T>>) -> Result<(), Error>,
	{
		let segment_leaf_offset = segment.id().leaf_offset()?;
		if self.received_segments >= self.required_segments.len()
			|| segment_leaf_offset < self.required_segments[self.received_segments].leaf_offset()?
		{
			return Ok(());
		}

		if !self.is_segment_in_receive_window(segment.id(), cache_size_limit)? {
			return Err(Error::InvalidSegmentId);
		}

		if !pruned {
			if !segment.is_no_prune() {
				return Err(Error::InvalidPruneState);
			}
		}

		// Stage the contiguous run without removing cached entries. The callback
		// can fail after partially applying data, so the cache cursor and cached
		// originals must remain unchanged until the callback succeeds.
		let mut offsets: Vec<u64> = Vec::new();
		while self.received_segments + offsets.len() < self.required_segments.len() {
			let leaf_offset =
				self.required_segments[self.received_segments + offsets.len()].leaf_offset()?;
			if leaf_offset == segment_leaf_offset || self.segment_cache.contains_key(&leaf_offset) {
				offsets.push(leaf_offset);
			} else {
				break;
			}
		}
		let next_leaf_offset = self
			.required_segments
			.get(self.received_segments + offsets.len())
			.map(|i| i.leaf_offset())
			.transpose()?;
		let segments: Vec<Segment<T>> = offsets
			.iter()
			.map(|idx| {
				if *idx == segment_leaf_offset {
					Ok(segment.clone())
				} else {
					self.segment_cache.get(idx).cloned().ok_or_else(|| {
						Error::Other(format!(
							"SegmentsCache::apply_new_segment, missing cached segment {}",
							idx
						))
					})
				}
			})
			.collect::<Result<Vec<_>, Error>>()?;

		self.segment_cache.insert(segment_leaf_offset, segment);

		// apply found data from the cache
		if !offsets.is_empty() {
			callback(segments)?;

			for idx in &offsets {
				self.segment_cache.remove(idx);
			}
			self.received_segments += offsets.len();
			match next_leaf_offset {
				Some(leaf_offset) => {
					self.segment_cache.retain(|idx, _| *idx > leaf_offset);
				}
				None => {
					self.segment_cache.clear();
				}
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::core::SegmentProof;
	use mwc_core::ser;

	struct EmptyRequests;

	impl RequestLookup<(SegmentType, u64)> for EmptyRequests {
		fn contains_request(&self, _key: &(SegmentType, u64)) -> bool {
			false
		}
	}

	struct Requests(Vec<(SegmentType, u64)>);

	impl RequestLookup<(SegmentType, u64)> for Requests {
		fn contains_request(&self, key: &(SegmentType, u64)) -> bool {
			self.0.iter().any(|request| request == key)
		}
	}

	fn empty_segment(identifier: SegmentIdentifier) -> Segment<()> {
		let mut proof_bytes = [0u8; 8].as_ref();
		let proof: SegmentProof = ser::deserialize_default(0, &mut proof_bytes).unwrap();
		Segment::from_parts(
			identifier,
			Vec::new(),
			Vec::new(),
			Vec::new(),
			Vec::new(),
			proof,
		)
		.unwrap()
	}

	fn cache_segment(cache: &mut SegmentsCache<()>, idx: u64) {
		let segment = empty_segment(SegmentIdentifier::new(0, idx));
		let leaf_offset = segment.id().leaf_offset().unwrap();
		cache.segment_cache.insert(leaf_offset, segment);
	}

	fn request_for(idx: u64) -> (SegmentType, u64) {
		(
			SegmentType::Output,
			SegmentIdentifier::new(0, idx).leaf_offset().unwrap(),
		)
	}

	#[test]
	fn next_desired_segments_respects_zero_max_elements() {
		let cache = SegmentsCache::<()>::new(
			SegmentType::Output,
			vec![SegmentIdentifier::new(0, 0), SegmentIdentifier::new(0, 1)],
		);

		let (new_requests, retry_requests, waiting_requests) =
			cache.next_desired_segments(0, &EmptyRequests, 10).unwrap();

		assert!(new_requests.is_empty());
		assert!(retry_requests.is_empty());
		assert!(waiting_requests.is_empty());
	}

	#[test]
	fn next_desired_segments_rejects_zero_cache_size_limit() {
		let cache = SegmentsCache::<()>::new(
			SegmentType::Output,
			vec![SegmentIdentifier::new(0, 0), SegmentIdentifier::new(0, 1)],
		);

		let err = cache
			.next_desired_segments(1, &EmptyRequests, 0)
			.unwrap_err();

		assert!(matches!(err, Error::InvalidSegment(_)));
	}

	#[test]
	fn next_desired_segments_retries_before_cached_run_starting_at_one() {
		let mut cache = SegmentsCache::<()>::new(
			SegmentType::Output,
			(0..5).map(|idx| SegmentIdentifier::new(0, idx)).collect(),
		);
		let requested = Requests(vec![request_for(0)]);

		for idx in 1..4 {
			cache_segment(&mut cache, idx);
		}

		let (new_requests, retry_requests, waiting_requests) =
			cache.next_desired_segments(10, &requested, 5).unwrap();

		assert_eq!(new_requests, vec![SegmentIdentifier::new(0, 4)]);
		assert_eq!(retry_requests, vec![SegmentIdentifier::new(0, 0)]);
		assert_eq!(waiting_requests, vec![SegmentIdentifier::new(0, 0)]);
	}

	#[test]
	fn next_desired_segments_retries_before_cached_run_at_receive_window_end() {
		let mut cache = SegmentsCache::<()>::new(
			SegmentType::Output,
			(0..5).map(|idx| SegmentIdentifier::new(0, idx)).collect(),
		);
		let requested = Requests(vec![request_for(0), request_for(1)]);

		for idx in 2..5 {
			cache_segment(&mut cache, idx);
		}

		let (new_requests, retry_requests, waiting_requests) =
			cache.next_desired_segments(10, &requested, 5).unwrap();

		assert!(new_requests.is_empty());
		assert_eq!(
			retry_requests,
			vec![SegmentIdentifier::new(0, 0), SegmentIdentifier::new(0, 1)]
		);
		assert_eq!(
			waiting_requests,
			vec![SegmentIdentifier::new(0, 0), SegmentIdentifier::new(0, 1)]
		);
	}

	#[test]
	fn has_segment_propagates_required_segment_leaf_offset_errors() {
		let cache =
			SegmentsCache::<()>::new(SegmentType::Output, vec![SegmentIdentifier::new(64, 0)]);

		assert!(matches!(
			cache.has_segment(&SegmentIdentifier::new(0, 0)),
			Err(Error::SegmentError(_))
		));
	}

	#[test]
	fn receive_window_rejects_required_segments_outside_cache_limit() {
		let cache = SegmentsCache::<()>::new(
			SegmentType::Output,
			(0..5).map(|idx| SegmentIdentifier::new(0, idx)).collect(),
		);

		assert!(cache
			.is_segment_in_receive_window(&SegmentIdentifier::new(0, 0), 2)
			.unwrap());
		assert!(cache
			.is_segment_in_receive_window(&SegmentIdentifier::new(0, 1), 2)
			.unwrap());
		assert!(!cache
			.is_segment_in_receive_window(&SegmentIdentifier::new(0, 2), 2)
			.unwrap());
	}

	#[test]
	fn apply_new_segment_rejects_future_segment_outside_receive_window() {
		let mut cache = SegmentsCache::<()>::new(
			SegmentType::Output,
			(0..5).map(|idx| SegmentIdentifier::new(0, idx)).collect(),
		);
		let mut applied = false;

		let res = cache.apply_new_segment(
			empty_segment(SegmentIdentifier::new(0, 2)),
			false,
			2,
			|_| {
				applied = true;
				Ok(())
			},
		);

		assert!(matches!(res, Err(Error::InvalidSegmentId)));
		assert!(!applied);
		assert_eq!(cache.get_received_segments(), 0);
	}

	#[test]
	fn apply_new_segment_accepts_segment_inside_receive_window() {
		let mut cache = SegmentsCache::<()>::new(
			SegmentType::Output,
			(0..5).map(|idx| SegmentIdentifier::new(0, idx)).collect(),
		);
		let mut applied = false;

		cache
			.apply_new_segment(
				empty_segment(SegmentIdentifier::new(0, 0)),
				false,
				2,
				|segments| {
					assert_eq!(segments.len(), 1);
					assert_eq!(*segments[0].id(), SegmentIdentifier::new(0, 0));
					applied = true;
					Ok(())
				},
			)
			.unwrap();

		assert!(applied);
		assert_eq!(cache.get_received_segments(), 1);
	}

	#[test]
	fn accepted_segments_include_cached_entries() {
		let mut cache = SegmentsCache::<()>::new(
			SegmentType::Output,
			(0..5).map(|idx| SegmentIdentifier::new(0, idx)).collect(),
		);

		cache
			.apply_new_segment(
				empty_segment(SegmentIdentifier::new(0, 1)),
				false,
				3,
				|_| panic!("future segment should stay cached"),
			)
			.unwrap();

		assert_eq!(cache.get_received_segments(), 0);
		assert_eq!(cache.get_accepted_segments(), 1);
	}

	#[test]
	fn apply_new_segment_keeps_staged_segments_when_callback_fails() {
		let mut cache = SegmentsCache::<()>::new(
			SegmentType::Output,
			(0..2).map(|idx| SegmentIdentifier::new(0, idx)).collect(),
		);

		cache
			.apply_new_segment(
				empty_segment(SegmentIdentifier::new(0, 1)),
				false,
				2,
				|_| panic!("future segment should not be applied before segment 0"),
			)
			.unwrap();
		assert_eq!(cache.get_received_segments(), 0);
		assert!(cache.segment_cache.contains_key(&1));

		let res = cache.apply_new_segment(
			empty_segment(SegmentIdentifier::new(0, 0)),
			false,
			2,
			|segments| {
				assert_eq!(
					segments
						.iter()
						.map(|segment| *segment.id())
						.collect::<Vec<_>>(),
					vec![SegmentIdentifier::new(0, 0), SegmentIdentifier::new(0, 1)]
				);
				Err(Error::Other("callback failed".into()))
			},
		);

		assert!(matches!(res, Err(Error::Other(_))));
		assert_eq!(cache.get_received_segments(), 0);
		assert!(cache.segment_cache.contains_key(&0));
		assert!(cache.segment_cache.contains_key(&1));

		let mut applied_segments = Vec::new();
		cache
			.apply_new_segment(
				empty_segment(SegmentIdentifier::new(0, 0)),
				false,
				2,
				|segments| {
					applied_segments = segments
						.iter()
						.map(|segment| *segment.id())
						.collect::<Vec<_>>();
					Ok(())
				},
			)
			.unwrap();

		assert_eq!(
			applied_segments,
			vec![SegmentIdentifier::new(0, 0), SegmentIdentifier::new(0, 1)]
		);
		assert_eq!(cache.get_received_segments(), 2);
		assert!(cache.segment_cache.is_empty());
	}
}
