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

//! Authenticates and assembles the checkpoint hashes used by PIBD header sync.

use crate::error::Error;
use crate::pibd_params;
use crate::txhashset::Desegmenter;
use crate::types::HEADERS_PER_BATCH;
use mwc_core::core::hash::Hash;
use mwc_core::core::pmmr;
use mwc_core::core::pmmr::{Backend, VecBackend, PMMR};
use mwc_core::core::Segment;
use mwc_core::core::SegmentIdentifier;

/// Maximum number of header-hash segments to allocate for a PIBD headers sync.
pub const MAX_HEADER_HASH_SEGMENTS: u64 = 65_536;

/// Desegmenter for rebuilding a header_pmmr from PIBD segments
pub struct HeaderHashesDesegmenter {
	genesis_hash: Hash,
	header_pmmr: VecBackend<Hash>,
	target_height: u64,
	headers_root_hash: Hash, // target height and headers_root_hash must be get as a result of handshake process.
	header_pmmr_size: u64,

	required_segments: Vec<SegmentIdentifier>,
	applied_segments: usize,
}

/// Authenticated checkpoint hashes, bound to the root and target used to validate them.
/// Private fields ensure application can only use the sanitized validation result.
pub struct ValidatedHeaderHashesSegment {
	segment: Segment<Hash>,
	root: Hash,
	target_height: u64,
}

/// This formula must be the same for segmenter and desegmenter
/// Both party needs to be onthe same page regarding the size of the data
pub fn calc_header_hashes_from_target_height(target_height: u64) -> u64 {
	// Safe: HEADERS_PER_BATCH is a non-zero u32 constant, and conversion to u64 is lossless.
	target_height / u64::from(HEADERS_PER_BATCH) + 1
}

impl HeaderHashesDesegmenter {
	/// Create a new segmenter based on the provided txhashset and the specified block header
	pub fn new(
		context_id: u32,
		genesis_hash: Hash,
		target_height: u64,
		headers_root_hash: Hash, // target height and headers_root_hash must be get as a result of handshake process.
	) -> Result<Self, Error> {
		let n_leaves = calc_header_hashes_from_target_height(target_height);
		let header_pmmr_size = pmmr::insertion_to_pmmr_index(n_leaves)?;
		let header_segments_num = Desegmenter::count_non_prunable_segments(
			Hash::LEN,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			header_pmmr_size,
		)?;
		if header_segments_num > MAX_HEADER_HASH_SEGMENTS {
			return Err(Error::InvalidHeaderHeight(target_height));
		}
		let header_segments = Desegmenter::generate_segments(
			Hash::LEN,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
			header_pmmr_size,
			None,
		)?;

		Ok(HeaderHashesDesegmenter {
			genesis_hash,
			header_pmmr: VecBackend::new(context_id),
			target_height,
			headers_root_hash,
			header_pmmr_size,
			required_segments: header_segments,
			applied_segments: 0,
		})
	}

	/// Number of segments successfully applied to the checkpoint PMMR.
	pub fn get_segments_applied(&self) -> usize {
		self.applied_segments
	}

	/// Get number of total segments
	pub fn get_segments_total(&self) -> usize {
		self.required_segments.len()
	}

	/// Whether we have all the segments we need
	pub fn is_complete(&self) -> bool {
		self.applied_segments == self.required_segments.len()
	}

	/// get Root hash for all headers
	pub fn get_headers_root_hash(&self) -> &Hash {
		return &self.headers_root_hash;
	}

	/// Get PIBD height to retrieve data for. Normally it is archive header height.
	pub fn get_target_height(&self) -> u64 {
		self.target_height
	}

	/// Authenticated checkpoint hashes, in height order, after all segments are applied.
	pub fn get_header_hashes(&self) -> Result<Vec<Hash>, Error> {
		if !self.is_complete() {
			return Err(Error::Other("Header hashes are not complete".into()));
		}
		let data = self
			.header_pmmr
			.data
			.as_ref()
			.ok_or_else(|| Error::Other("Missing checkpoint hash data".into()))?;
		if data.len() as u64 != calc_header_hashes_from_target_height(self.target_height) {
			return Err(Error::Other("Incomplete checkpoint hash list".into()));
		}
		data.iter()
			.map(|hash| hash.ok_or_else(|| Error::Other("Missing checkpoint hash".into())))
			.collect()
	}

	/// Next layout entries after the applied prefix and tasks already owned by the caller.
	pub fn next_segments(
		&self,
		queued: usize,
		limit: usize,
	) -> Result<Vec<SegmentIdentifier>, Error> {
		let start = self
			.applied_segments
			.checked_add(queued)
			.filter(|start| *start <= self.required_segments.len())
			.ok_or_else(|| Error::Other("Header hash tasks exceed segment layout".into()))?;
		Ok(self.required_segments[start..]
			.iter()
			.take(limit)
			.copied()
			.collect())
	}

	/// Authenticate a response without changing the PMMR. The caller may buffer it
	/// until earlier segments are ready to apply.
	pub fn validate_segment(
		&self,
		segment: Segment<Hash>,
	) -> Result<ValidatedHeaderHashesSegment, Error> {
		let segment = segment.validate(
			self.header_pmmr.get_context_id(),
			self.header_pmmr_size,
			None,
			&self.headers_root_hash,
		)?;
		if !segment.is_no_prune() {
			return Err(Error::InvalidPruneState);
		}
		if segment.id().leaf_offset()? == 0
			&& segment.leaf_iter().next().map(|(_, hash)| *hash) != Some(self.genesis_hash)
		{
			return Err(Error::InvalidGenesisHash);
		}
		Ok(ValidatedHeaderHashesSegment {
			segment,
			root: self.headers_root_hash,
			target_height: self.target_height,
		})
	}

	/// Append the next authenticated segment. Failed application leaves both the
	/// PMMR and applied cursor unchanged so its task can retain the response.
	pub fn apply_segment(&mut self, validated: &ValidatedHeaderHashesSegment) -> Result<(), Error> {
		if validated.root != self.headers_root_hash || validated.target_height != self.target_height
		{
			return Err(Error::InvalidHeadersRoot);
		}
		if self.required_segments.get(self.applied_segments) != Some(validated.segment.id()) {
			return Err(Error::InvalidSegmentId);
		}
		let size = self.header_pmmr.size();
		let result = (|| {
			let mut mmr = PMMR::at(&mut self.header_pmmr, size);
			for (position, hash) in validated.segment.leaf_iter() {
				if position != mmr.size() {
					return Err(Error::InvalidSegment(
						"Noncontiguous checkpoint hashes".into(),
					));
				}
				mmr.push(hash)?;
			}
			Ok(())
		})();
		if let Err(error) = result {
			// This is an append-only in-memory PMMR; remove any partial suffix.
			self.header_pmmr.detach_tail(size)?;
			return Err(error);
		}
		self.applied_segments += 1;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::core::pmmr::ReadablePMMR;

	fn checkpoint_segments() -> (HeaderHashesDesegmenter, Vec<Segment<Hash>>, Vec<Hash>) {
		// Build a real checkpoint PMMR spanning multiple segments, without mining blocks.
		let hashes: Vec<_> = (1u64..=8193)
			.map(|index| {
				let mut bytes = [0; Hash::LEN];
				bytes[..8].copy_from_slice(&index.to_le_bytes());
				Hash::from_vec(&bytes)
			})
			.collect();
		let mut backend = VecBackend::new(0);
		let mut mmr = PMMR::new(&mut backend);
		for hash in &hashes {
			mmr.push(hash).unwrap();
		}
		let target = (hashes.len() as u64 - 1) * u64::from(HEADERS_PER_BATCH);
		let desegmenter =
			HeaderHashesDesegmenter::new(0, hashes[0], target, mmr.root().unwrap()).unwrap();
		let segments = desegmenter
			.next_segments(0, usize::MAX)
			.unwrap()
			.into_iter()
			.map(|id| {
				Segment::from_pmmr(
					id,
					&mmr.readonly_pmmr(),
					None,
					Hash::LEN,
					pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
				)
				.unwrap()
			})
			.collect();
		(desegmenter, segments, hashes)
	}

	#[test]
	fn validated_responses_apply_only_in_checkpoint_order() {
		let (mut desegmenter, segments, hashes) = checkpoint_segments();
		assert!(segments.len() > 1);
		assert_eq!(
			desegmenter.next_segments(1, 1).unwrap(),
			vec![*segments[1].id()]
		);
		assert!(desegmenter.next_segments(0, 0).unwrap().is_empty());
		assert!(desegmenter.next_segments(segments.len() + 1, 1).is_err());

		// Replies may arrive in reverse order. Validation leaves the PMMR untouched,
		// and even authenticated later data cannot skip the first checkpoint segment.
		let mut validated: Vec<_> = segments
			.into_iter()
			.rev()
			.map(|segment| desegmenter.validate_segment(segment).unwrap())
			.collect();
		assert_eq!(desegmenter.get_segments_applied(), 0);
		assert_eq!(desegmenter.header_pmmr.size(), 0);
		assert!(desegmenter.get_header_hashes().is_err());
		assert!(matches!(
			desegmenter.apply_segment(&validated[0]),
			Err(Error::InvalidSegmentId)
		));
		assert_eq!(desegmenter.header_pmmr.size(), 0);

		// Applying the buffered prefix in order produces the exact original list.
		// Reapplying any segment is rejected without advancing the cursor twice.
		while let Some(segment) = validated.pop() {
			desegmenter.apply_segment(&segment).unwrap();
			assert!(matches!(
				desegmenter.apply_segment(&segment),
				Err(Error::InvalidSegmentId)
			));
		}
		assert!(desegmenter.is_complete());
		assert!(desegmenter.next_segments(0, 1).unwrap().is_empty());
		assert!(desegmenter.next_segments(usize::MAX, 1).is_err());
		assert_eq!(desegmenter.get_header_hashes().unwrap(), hashes);
	}

	#[test]
	fn rejects_corrupt_data_and_responses_for_another_commitment() {
		let (desegmenter, segments, hashes) = checkpoint_segments();
		let (id, positions, nodes, leaves, mut data, proof) = segments[0].clone().parts();
		data[0] = Hash::default();
		let corrupt = Segment::from_parts(id, positions, nodes, leaves, data, proof).unwrap();
		// Modifying a checkpoint invalidates its proof and cannot advance progress.
		assert!(desegmenter.validate_segment(corrupt).is_err());
		assert_eq!(desegmenter.get_segments_applied(), 0);
		assert_eq!(desegmenter.header_pmmr.size(), 0);

		let root = *desegmenter.get_headers_root_hash();
		let target = desegmenter.get_target_height();
		let wrong_genesis = HeaderHashesDesegmenter::new(0, Hash::default(), target, root).unwrap();
		assert!(matches!(
			wrong_genesis.validate_segment(segments[0].clone()),
			Err(Error::InvalidGenesisHash)
		));

		// Already-authenticated data remains tied to its original root and archive
		// target, so resetting a download cannot reuse another session's response.
		let validated = desegmenter.validate_segment(segments[0].clone()).unwrap();
		for (target, root) in [
			(target + u64::from(HEADERS_PER_BATCH), root),
			(target, Hash::default()),
		] {
			let mut other = HeaderHashesDesegmenter::new(0, hashes[0], target, root).unwrap();
			assert!(matches!(
				other.apply_segment(&validated),
				Err(Error::InvalidHeadersRoot)
			));
			assert_eq!(other.header_pmmr.size(), 0);
			assert_eq!(other.get_segments_applied(), 0);
		}
	}

	#[test]
	fn rejects_target_height_requiring_too_many_header_hash_segments() {
		let res = HeaderHashesDesegmenter::new(0, Hash::default(), u64::MAX, Hash::default());

		match res {
			Err(Error::InvalidHeaderHeight(height)) => assert_eq!(height, u64::MAX),
			Err(e) => panic!("unexpected error: {}", e),
			Ok(_) => panic!("huge target height should be rejected"),
		}
	}
}
