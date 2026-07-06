// Copyright 2026 The MWC Developers
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

use mwc_chain::pibd_params;
use mwc_chain::txhashset::{BitmapAccumulator, BitmapChunk, BitmapSegment};
use mwc_core::core::pmmr::segment::{Segment, SegmentIdentifier};
use mwc_core::ser::{BinReader, BinWriter, ProtocolVersion, Readable, Writeable};
use mwc_crates::croaring::Bitmap;
use mwc_crates::rand::rng;
use mwc_crates::rand::RngExt;
use std::convert::TryFrom;
use std::io::Cursor;

fn test_roundtrip(entries: usize) {
	let mut rng = rng();

	let identifier = SegmentIdentifier {
		height: 10,
		idx: rng.random_range(8..16),
	};
	let block = rng.random_range(2..16);

	let mut bitmap = Bitmap::new();
	let block_size = 1 << 16;
	let offset = (1 << identifier.height) * 1024 * identifier.idx + block_size * block;
	let mut count = 0;
	while count < entries {
		let idx = (offset + rng.random_range(0..block_size)) as u32;
		if !bitmap.contains(idx) {
			count += 1;
			bitmap.add(idx);
		}
	}

	// Add a bunch of segments after the one we are interested in
	let size = bitmap.maximum().unwrap() as u64
		+ (1 << identifier.height) * 1024 * rng.random_range(0..64);

	// Construct the accumulator
	let mut accumulator = BitmapAccumulator::new(0);
	accumulator
		.init(bitmap.iter().map(|v| Ok(v as u64)), size)
		.unwrap();

	let mmr = accumulator.readonly_pmmr();
	let segment = Segment::<BitmapChunk>::from_pmmr(
		identifier,
		&mmr,
		None,
		BitmapChunk::LEN_BYTES,
		pibd_params::PIBD_MESSAGE_SIZE_LIMIT,
	)
	.unwrap();

	// Convert to `BitmapSegment`
	let bms = BitmapSegment::try_from(segment.clone()).unwrap();

	// Serialize `BitmapSegment`
	let mut cursor = Cursor::new(Vec::<u8>::new());
	let mut writer = BinWriter::new(&mut cursor, ProtocolVersion(1), 0);
	Writeable::write(&bms, &mut writer).unwrap();

	// Read `BitmapSegment`
	cursor.set_position(0);
	let mut reader = BinReader::new(&mut cursor, ProtocolVersion(1), 0);
	let bms2: BitmapSegment = Readable::read(&mut reader).unwrap();
	assert_eq!(bms, bms2);

	// Convert back to `Segment`
	let segment2 = Segment::try_from(bms2).unwrap();
	assert_eq!(segment, segment2);
}

#[test]
fn segment_ser_roundtrip() {
	let threshold = 4096;
	test_roundtrip(rng().random_range(threshold..4 * threshold));
}

#[test]
fn sparse_segment_ser_roundtrip() {
	test_roundtrip(rng().random_range(1024..4096));
}

#[test]
fn abundant_segment_ser_roundtrip() {
	let max = 1 << 16;
	test_roundtrip(rng().random_range(max - 4096..max - 1024));
}
