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

//! Private difficulty-window cache used by consensus difficulty calculation.

use crate::consensus;
use crate::consensus::{
	HeaderDifficultyInfo, IntoHeaderDifficultyInfo, BLOCK_TIME_SEC, DIFFICULTY_ADJUST_WINDOW,
};
use std::collections::VecDeque;
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicU64, Ordering};

/// Opaque cache for recent difficulty data.
///
/// The entries are intentionally private. Consensus validation may use cached
/// data only when it was populated by this module from a difficulty iterator or
/// extended from difficulty iterator data in the same calculation path.
#[derive(Debug, Default)]
pub struct DifficultyCache {
	entries: VecDeque<HeaderDifficultyInfo>,
}

impl DifficultyCache {
	/// Create an empty difficulty cache.
	pub fn new() -> DifficultyCache {
		DifficultyCache::default()
	}

	/// Number of cached entries.
	pub fn len(&self) -> usize {
		self.entries.len()
	}

	/// Whether this cache has no entries.
	pub fn is_empty(&self) -> bool {
		self.entries.is_empty()
	}

	/// Read-only access to cached entries, primarily for diagnostics and tests.
	pub fn iter(&self) -> std::collections::vec_deque::Iter<'_, HeaderDifficultyInfo> {
		self.entries.iter()
	}

	/// Initialize this cache as a rolling difficulty window from newest-to-oldest
	/// difficulty iterator data.
	pub fn reset_rolling<T>(&mut self, cursor: T) -> Result<(), consensus::Error>
	where
		T: IntoIterator,
		T::Item: IntoHeaderDifficultyInfo,
	{
		let needed_block_count = DIFFICULTY_ADJUST_WINDOW as usize + 1;
		let last_n: Vec<HeaderDifficultyInfo> = cursor
			.into_iter()
			.take(needed_block_count)
			.map(|item| item.into_header_difficulty_info())
			.collect::<Result<_, _>>()?;

		if last_n.is_empty() {
			return Err(consensus::Error::HistoryTooShort);
		}

		// Cache entries are kept oldest-to-newest. DifficultyIter provides data
		// newest-to-oldest, so reverse when initializing the rolling window.
		self.entries.clear();
		self.entries.extend(last_n.into_iter().rev());
		Ok(())
	}

	/// Calculate the next difficulty from the current rolling window.
	pub fn next_rolling_difficulty(
		&self,
		context_id: u32,
		height: u64,
	) -> Result<HeaderDifficultyInfo, consensus::Error> {
		let last_n = self.entries.iter().rev().cloned().collect::<Vec<_>>();
		let diff_data = difficulty_data_from_last_n(context_id, last_n)?;
		consensus::next_difficulty_from_diff_data(height, &diff_data)
	}

	/// Add a just-validated header difficulty entry to the rolling window.
	pub fn push_rolling_header(
		&mut self,
		header_info: HeaderDifficultyInfo,
	) -> Result<(), consensus::Error> {
		if self.entries.is_empty() {
			return Err(consensus::Error::HistoryTooShort);
		}

		if let Some(head) = self.entries.back() {
			let expected_height = head.height.checked_add(1).ok_or_else(|| {
				consensus::Error::DataOverflow(format!(
					"DifficultyCache::push_rolling_header, head.height={}",
					head.height
				))
			})?;
			if header_info.height != expected_height {
				return Err(consensus::Error::InvalidParameter(format!(
					"rolling difficulty header height {} does not follow cache head {}",
					header_info.height, head.height
				)));
			}
		}

		let needed_block_count = DIFFICULTY_ADJUST_WINDOW as usize + 1;
		self.entries.push_back(header_info);
		while self.entries.len() > needed_block_count {
			self.entries.pop_front();
		}
		Ok(())
	}

	fn span(&self) -> Option<(u64, u64)> {
		let cache_tail_height = self.entries.front()?.height;
		let cache_head_height = self.entries.back()?.height;
		if cache_head_height < cache_tail_height {
			return None;
		}

		// Safe: callers cap entries to a small multiple of the difficulty
		// window before calling this helper, and front()/back() imply len() >= 1.
		let cache_span = cache_head_height - cache_tail_height;
		let expected_span = (self.entries.len() - 1) as u64;

		if cache_span == expected_span {
			Some((cache_tail_height, cache_head_height))
		} else {
			None
		}
	}
}

#[cfg(debug_assertions)]
static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Converts an iterator of block difficulty data to a more manageable vector
/// and pads if needed, which is only needed for the first few blocks after
/// genesis.
///
/// The cache is used because this step is hot during header sync. The cache is
/// opaque so consensus callers cannot provide arbitrary entries directly.
pub fn difficulty_data_to_vector<T>(
	context_id: u32,
	cursor: T,
	cache_values: &mut DifficultyCache,
) -> Result<Vec<HeaderDifficultyInfo>, consensus::Error>
where
	T: IntoIterator,
	T::Item: IntoHeaderDifficultyInfo,
{
	// Convert iterator to vector, so we can append to it if necessary.
	let needed_block_count = DIFFICULTY_ADJUST_WINDOW as usize + 1;
	// Safe: DIFFICULTY_ADJUST_WINDOW is HOUR_HEIGHT (60 blocks), so these
	// cache limits are tiny and cannot overflow usize.
	let max_cache_len = needed_block_count * 10;
	let keep_cache_len = needed_block_count * 7;

	// In debug mode we want to validate the cache. It is expected that last_n
	// are exactly the same with and without a cache.
	#[cfg(debug_assertions)]
	let perform_debug_test = CALL_COUNTER.fetch_add(1, Ordering::Relaxed) % 500 == 0;
	#[cfg(debug_assertions)]
	let (test_last_n, mut iter): (
		Option<Vec<HeaderDifficultyInfo>>,
		Box<dyn Iterator<Item = Result<HeaderDifficultyInfo, consensus::Error>> + '_>,
	) = if perform_debug_test {
		let test_last_n: Vec<HeaderDifficultyInfo> = cursor
			.into_iter()
			.take(needed_block_count)
			.map(|item| item.into_header_difficulty_info())
			.collect::<Result<_, _>>()?;
		let iter = Box::new(test_last_n.clone().into_iter().map(Ok));
		(Some(test_last_n), iter)
	} else {
		let iter = Box::new(
			cursor
				.into_iter()
				.map(|item| item.into_header_difficulty_info()),
		);
		(None, iter)
	};
	#[cfg(not(debug_assertions))]
	let mut iter = cursor
		.into_iter()
		.map(|item| item.into_header_difficulty_info());

	let mut last_n: Vec<HeaderDifficultyInfo> = Vec::with_capacity(needed_block_count);

	while let Some(item) = iter.next() {
		let item = item?;
		if cache_values.entries.len() > max_cache_len {
			cache_values.entries.clear();
		}

		if !cache_values.entries.is_empty() {
			let cache_span = cache_values.span();

			if let Some((cache_tail_height, cache_head_height)) = cache_span {
				if item.height >= cache_tail_height && item.height <= cache_head_height {
					// Safe: span proves the height span maps to entries.len(), and
					// entries is capped above.
					let item_idx = (item.height - cache_tail_height) as usize;
					let base_idx = item_idx + last_n.len();

					if base_idx + 1 >= needed_block_count {
						match cache_values.entries.get(item_idx) {
							Some(cached_item)
								if cached_item.height == item.height
									&& cached_item.hash.is_some()
									&& cached_item.hash == item.hash =>
							{
								// Safe: the check above guarantees this subtraction cannot
								// underflow. base_idx is bounded by max_cache_len + window.
								let start_idx = base_idx + 1 - needed_block_count;

								let cache_len = cache_values.entries.len();
								let mut cached_last_n = Vec::with_capacity(needed_block_count);
								let mut cache_hit_valid = true;

								for idx in (start_idx..=base_idx).rev() {
									let (cached_header, expected_height) = if idx < cache_len {
										// Safe: idx is inside the capped, contiguous cache span,
										// so cache_tail_height + idx cannot exceed cache_head_height.
										(
											cache_values.entries.get(idx),
											cache_tail_height + idx as u64,
										)
									} else {
										let appended_idx = idx - cache_len;
										// Safe: idx <= base_idx = item_idx + last_n.len(),
										// and item_idx < cache_len, so appended_idx < last_n.len().
										let last_n_idx = last_n.len() - 1 - appended_idx;
										let expected_height = cache_head_height
											.checked_add((appended_idx + 1) as u64)
											.ok_or_else(|| {
												consensus::Error::DataOverflow(format!(
													"difficulty_cache::difficulty_data_to_vector, cache_head_height={} appended_idx={}",
													cache_head_height, appended_idx
												))
											})?;
										(Some(&last_n[last_n_idx]), expected_height)
									};

									match cached_header {
										Some(header)
											if header.height == expected_height
												&& header.hash.is_some() =>
										{
											cached_last_n.push(header.clone());
										}
										_ => {
											cache_hit_valid = false;
											break;
										}
									}
								}

								if cache_hit_valid
									&& last_n.iter().all(|header| header.hash.is_some())
								{
									// Cache hit, can finish the query.
									while let Some(h) = last_n.pop() {
										cache_values.entries.push_back(h);
									}
									last_n = cached_last_n;
									// Done with cursor, last_n is full.
									break;
								}

								cache_values.entries.clear();
							}
							Some(cached_item) if cached_item.height == item.height => {
								// Cache is invalid, probably there are branches.
								cache_values.entries.clear();
							}
							_ => {
								// The cache shape looked plausible from the endpoints, but an
								// indexed entry did not match its derived height.
								cache_values.entries.clear();
							}
						}
					}
				}
			} else {
				cache_values.entries.clear();
			}
		}
		last_n.push(item);
		if last_n.len() == needed_block_count && needed_block_count > 2 {
			// The cache is obsolete; initialize it from the iterator data after
			// validating the shape. Test cases include histories that cannot be
			// cached well.
			let mut last_n_valid = true;

			for i in 1..last_n.len() {
				let h1 = &last_n[i - 1];
				let h2 = &last_n[i];
				if h1.height <= h2.height
					|| h1.hash.is_none()
					|| h2.hash.is_none()
					|| h1.difficulty <= h2.difficulty
					|| h1.timestamp <= h2.timestamp
				{
					last_n_valid = false;
					break;
				}
			}

			cache_values.entries.clear();
			if last_n_valid {
				cache_values.entries.extend(last_n.iter().rev().cloned());
			}
			break;
		}
	}

	if cache_values.entries.len() > max_cache_len {
		let drain_len = cache_values.entries.len() - keep_cache_len;
		cache_values.entries.drain(0..drain_len);
	}

	#[cfg(debug_assertions)]
	if let Some(test_last_n) = test_last_n {
		debug_assert!(test_last_n == last_n);
	}

	difficulty_data_from_last_n(context_id, last_n)
}

fn difficulty_data_from_last_n(
	context_id: u32,
	mut last_n: Vec<HeaderDifficultyInfo>,
) -> Result<Vec<HeaderDifficultyInfo>, consensus::Error> {
	let n = last_n.len();
	let needed_block_count = DIFFICULTY_ADJUST_WINDOW as usize + 1;

	// Only needed just after blockchain launch. This ensures there is always
	// enough data by simulating perfectly timed pre-genesis blocks at genesis
	// difficulty as needed.
	if needed_block_count > n {
		if n == 0 {
			return Err(consensus::Error::HistoryTooShort);
		}

		let last_ts_delta = if n > 1 {
			last_n[0]
				.timestamp
				.checked_sub(last_n[1].timestamp)
				.ok_or_else(|| {
					consensus::Error::DataOverflow(format!(
						"difficulty_cache::difficulty_data_to_vector, timestamp0={} timestamp1={}",
						last_n[0].timestamp, last_n[1].timestamp
					))
				})?
		} else {
			BLOCK_TIME_SEC
		};
		let missing_block_count = needed_block_count - n;
		let max_synthetic_ts_delta = last_n
			.last()
			.map(|last| last.timestamp / missing_block_count as u64)
			.ok_or_else(|| consensus::Error::HistoryTooShort)?;
		if max_synthetic_ts_delta == 0 {
			return Err(consensus::Error::InvalidParameter(format!(
				"difficulty_cache::difficulty_data_to_vector, not enough timestamp space for synthetic padding: oldest_timestamp={} missing_blocks={}",
				last_n.last().map(|last| last.timestamp).unwrap_or(0),
				missing_block_count
			)));
		}
		let synthetic_ts_delta = last_ts_delta.min(max_synthetic_ts_delta);
		if synthetic_ts_delta == 0 {
			return Err(consensus::Error::InvalidParameter(
				"difficulty_cache::difficulty_data_to_vector, zero synthetic timestamp delta"
					.to_string(),
			));
		}
		let last_diff = last_n[0].difficulty;
		let secondary_scaling = crate::global::initial_graph_weight(context_id);

		// Fill in simulated blocks with values from the previous real block.
		let mut last_ts = match last_n.last() {
			Some(last) => last.timestamp,
			None => return Err(consensus::Error::HistoryTooShort),
		};
		for idx in 0..missing_block_count {
			last_ts = last_ts.checked_sub(synthetic_ts_delta).ok_or_else(|| {
				consensus::Error::DataOverflow(format!(
					"difficulty_cache::difficulty_data_to_vector, last_ts={} synthetic_ts_delta={}",
					last_ts, synthetic_ts_delta
				))
			})?;
			last_n.push(HeaderDifficultyInfo::new(
				(missing_block_count - idx - 1) as u64,
				None,
				last_ts,
				last_diff,
				secondary_scaling,
				true,
			));
		}
	}
	last_n.reverse();
	Ok(last_n)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::core::hash::Hash;
	use crate::pow::Difficulty;

	fn header_with_hash(height: u64) -> HeaderDifficultyInfo {
		header(
			height,
			Some(Hash::from_vec(&height.to_le_bytes())),
			1_000_000,
			1,
		)
	}

	fn header_without_hash(
		height: u64,
		timestamp_base: u64,
		difficulty_base: u64,
	) -> HeaderDifficultyInfo {
		header(height, None, timestamp_base, difficulty_base)
	}

	fn header(
		height: u64,
		hash: Option<Hash>,
		timestamp_base: u64,
		difficulty_base: u64,
	) -> HeaderDifficultyInfo {
		HeaderDifficultyInfo::new(
			height,
			hash,
			timestamp_base + height,
			Difficulty::from_num(difficulty_base + height),
			1,
			false,
		)
	}

	#[test]
	fn cache_hit_requires_block_hash() {
		let needed_block_count = DIFFICULTY_ADJUST_WINDOW as usize + 1;
		let mut cache_values = DifficultyCache::new();
		cache_values.entries.extend(
			(0..needed_block_count as u64).map(|height| header_without_hash(height, 1_000_000, 1)),
		);

		let cursor = (0..needed_block_count as u64)
			.rev()
			.map(|height| header_without_hash(height, 2_000_000, 10_000))
			.collect::<Vec<_>>();
		let mut expected = cursor.clone();
		expected.reverse();

		let result = difficulty_data_to_vector(0, cursor, &mut cache_values).unwrap();

		assert_eq!(result, expected);
		assert!(cache_values.is_empty());
	}

	#[test]
	fn cache_hit_does_not_append_headers_without_hashes() {
		let needed_block_count = DIFFICULTY_ADJUST_WINDOW as usize + 1;
		let mut cache_values = DifficultyCache::new();
		cache_values
			.entries
			.extend((0..needed_block_count as u64).map(header_with_hash));

		let next_height = needed_block_count as u64;
		let cursor = (1..=next_height)
			.rev()
			.map(|height| {
				if height == next_height {
					header_without_hash(height, 1_000_000, 1)
				} else {
					header_with_hash(height)
				}
			})
			.collect::<Vec<_>>();
		let mut expected = cursor.clone();
		expected.reverse();

		let result = difficulty_data_to_vector(0, cursor, &mut cache_values).unwrap();

		assert_eq!(result, expected);
		assert!(cache_values.is_empty());
	}

	#[test]
	fn rolling_cache_matches_cursor_calculation_after_push() {
		let needed_block_count = DIFFICULTY_ADJUST_WINDOW as usize + 1;
		let initial_cursor = (0..needed_block_count as u64)
			.rev()
			.map(header_with_hash)
			.collect::<Vec<_>>();
		let mut rolling_cache = DifficultyCache::new();
		rolling_cache.reset_rolling(initial_cursor.clone()).unwrap();

		let next_height = needed_block_count as u64;
		let mut cursor_cache = DifficultyCache::new();
		let expected =
			consensus::next_difficulty(0, next_height, initial_cursor, &mut cursor_cache).unwrap();
		assert_eq!(
			rolling_cache
				.next_rolling_difficulty(0, next_height)
				.unwrap(),
			expected
		);

		rolling_cache
			.push_rolling_header(header_with_hash(next_height))
			.unwrap();
		let cursor_after_push = (1..=next_height)
			.rev()
			.map(header_with_hash)
			.collect::<Vec<_>>();
		let mut cursor_cache = DifficultyCache::new();
		let expected =
			consensus::next_difficulty(0, next_height + 1, cursor_after_push, &mut cursor_cache)
				.unwrap();
		assert_eq!(
			rolling_cache
				.next_rolling_difficulty(0, next_height + 1)
				.unwrap(),
			expected
		);
	}

	#[test]
	fn rolling_cache_rejects_non_contiguous_push() {
		let needed_block_count = DIFFICULTY_ADJUST_WINDOW as usize + 1;
		let mut rolling_cache = DifficultyCache::new();
		rolling_cache
			.reset_rolling((0..needed_block_count as u64).rev().map(header_with_hash))
			.unwrap();

		let err = rolling_cache
			.push_rolling_header(header_with_hash(needed_block_count as u64 + 1))
			.unwrap_err();
		assert!(matches!(err, consensus::Error::InvalidParameter(_)));
	}
}
