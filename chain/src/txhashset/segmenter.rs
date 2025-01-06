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

//! Generation of the various necessary segments requested during PIBD.

use crate::core::core::hash::Hash;
use crate::core::core::pmmr::ReadablePMMR;
use crate::core::core::{BlockHeader, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use crate::error::Error;
use crate::pibd_params;
use crate::txhashset::{BitmapAccumulator, BitmapChunk, TxHashSet};
use crate::util::secp::pedersen::RangeProof;
use crate::util::RwLock;
use croaring::Bitmap;
use mwc_core::core::pmmr::{ReadonlyPMMR, VecBackend};
use mwc_util::secp::constants;
use std::{sync::Arc, time::Instant};

/// Segmenter for generating PIBD segments.
/// Note!!! header_pmmr, txhashset & store are from the Chain. Same locking rules are applicable
#[derive(Clone)]
pub struct Segmenter {
	// every 512th header (HEADERS_PER_BATCH) must be here, we don't need all header hashes
	header_pmmr: Arc<RwLock<VecBackend<Hash>>>,
	txhashset: Arc<RwLock<TxHashSet>>,
	bitmap_snapshot: Arc<BitmapAccumulator>,
	bitmap: Bitmap,
	header: BlockHeader,
}

impl Segmenter {
	/// Create a new segmenter based on the provided txhashset.
	pub fn new(
		header_pmmr: Arc<RwLock<VecBackend<Hash>>>,
		txhashset: Arc<RwLock<TxHashSet>>,
		bitmap_snapshot: BitmapAccumulator,
		header: BlockHeader,
	) -> Segmenter {
		Segmenter {
			header_pmmr,
			txhashset,
			bitmap: bitmap_snapshot.build_bitmap(),
			bitmap_snapshot: Arc::new(bitmap_snapshot),
			header,
		}
	}

	/// Header associated with this segmenter instance.
	/// The bitmap "snapshot" corresponds to rewound state at this header.
	pub fn header(&self) -> &BlockHeader {
		&self.header
	}

	/// Root hash for headers Hashes MMR
	pub fn headers_root(&self) -> Result<Hash, Error> {
		let header_pmmr = self.header_pmmr.read();
		let pmmr = ReadonlyPMMR::at(&*header_pmmr, header_pmmr.size());
		let root = pmmr.root().map_err(&Error::TxHashSetErr)?;
		Ok(root)
	}

	/// The root of the bitmap snapshot PMMR.
	pub fn bitmap_root(&self) -> Result<Hash, Error> {
		let pmmr = self.bitmap_snapshot.readonly_pmmr();
		let root = pmmr.root().map_err(&Error::TxHashSetErr)?;
		Ok(root)
	}

	/// Create a utxo bitmap segment based on our bitmap "snapshot" and return it with
	/// the corresponding output root.
	pub fn bitmap_segment(&self, id: SegmentIdentifier) -> Result<Segment<BitmapChunk>, Error> {
		let now = Instant::now();
		let bitmap_pmmr = self.bitmap_snapshot.readonly_pmmr();
		let segment = Segment::from_pmmr(
			id,
			&bitmap_pmmr,
			None,
			BitmapChunk::LEN_BYTES,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
		)?;
		debug!(
			"bitmap_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}

	/// Create headers segment.
	pub fn headers_segment(&self, id: SegmentIdentifier) -> Result<Segment<Hash>, Error> {
		let now = Instant::now();
		let header_pmmr = self.header_pmmr.read();
		let header_pmmr = ReadonlyPMMR::at(&*header_pmmr, header_pmmr.size());
		let segment = Segment::from_pmmr(
			id,
			&header_pmmr,
			None,
			Hash::LEN,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
		)?;
		debug!(
			"headers_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}

	/// Create an output segment and return it with the corresponding bitmap root.
	pub fn output_segment(
		&self,
		id: SegmentIdentifier,
	) -> Result<Segment<OutputIdentifier>, Error> {
		let now = Instant::now();
		let txhashset = self.txhashset.read();
		let output_pmmr = txhashset.output_pmmr_at(&self.header);
		let segment = Segment::from_pmmr(
			id,
			&output_pmmr,
			Some(&self.bitmap),
			constants::PEDERSEN_COMMITMENT_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT * 2, // In reality 1x should be enough, using 2x to cover some edge cases
		)?;
		debug!(
			"output_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}

	/// Create a kernel segment.
	pub fn kernel_segment(&self, id: SegmentIdentifier) -> Result<Segment<TxKernel>, Error> {
		let now = Instant::now();
		let txhashset = self.txhashset.read();
		let kernel_pmmr = txhashset.kernel_pmmr_at(&self.header);
		let segment = Segment::from_pmmr(
			id,
			&kernel_pmmr,
			None,
			TxKernel::DATA_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
		)?;
		debug!(
			"kernel_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}

	/// Create a rangeproof segment.
	pub fn rangeproof_segment(&self, id: SegmentIdentifier) -> Result<Segment<RangeProof>, Error> {
		let now = Instant::now();
		let txhashset = self.txhashset.read();
		let pmmr = txhashset.rangeproof_pmmr_at(&self.header);
		// Some overhead is fine, there are chances that we can't make optimal segments
		let segment = Segment::from_pmmr(
			id,
			&pmmr,
			Some(&self.bitmap),
			constants::SINGLE_BULLET_PROOF_SIZE,
			pibd_params::PIBD_MESSAGE_SIZE_LIMIT * 2, // In reality 1x should be enough, using 2x to cover some edge cases
		)?;
		debug!(
			"rangeproof_segment: id: {}, leaves: {}, hashes: {}, proof hashes: {}, took {}ms",
			segment.id(),
			segment.leaf_iter().count(),
			segment.hash_iter().count(),
			segment.proof().size(),
			now.elapsed().as_millis()
		);
		Ok(segment)
	}
}
