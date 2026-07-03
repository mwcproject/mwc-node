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

use mwc_core::core::pmmr;
use mwc_crates::chrono::prelude::Utc;
use mwc_crates::croaring::Bitmap;
use mwc_crates::env_logger;
use mwc_store::leaf_set::LeafSet;

use std::fs;
use std::time::{Duration, Instant};

pub fn as_millis(d: Duration) -> u128 {
	d.as_secs() as u128 * 1_000 as u128 + (d.subsec_nanos() / (1_000 * 1_000)) as u128
}

#[test]
fn test_leaf_set_performance() {
	let (mut leaf_set, data_dir) = setup("leaf_set_perf");

	println!("Timing some common operations:");

	let positions = (0..1_000_000)
		.map(|idx| pmmr::insertion_to_pmmr_index(idx).unwrap())
		.collect::<Vec<_>>();
	let cutoff_pos = pmmr::insertion_to_pmmr_index(1_000_000).unwrap();

	// Add a million pos to the  set, syncing data to disk in 1,000 pos chunks
	// Simulating 1,000 blocks with 1,000 outputs each.
	let now = Instant::now();
	for x in 0usize..1_000 {
		for y in 0usize..1_000 {
			let idx = (x * 1_000) + y;
			leaf_set.add(positions[idx]).unwrap();
		}
		leaf_set.flush().unwrap();
	}
	assert_eq!(leaf_set.len(), 1_000_000);
	println!(
		"Adding 1,000 chunks of 1,000 pos to leaf_set took {}ms",
		as_millis(now.elapsed())
	);

	// Simulate looking up existence of a large number of pos in the leaf_set.
	let now = Instant::now();
	for pos in positions.iter() {
		assert!(leaf_set.includes(*pos).unwrap());
	}
	println!(
		"Checking 1,000,000 inclusions in leaf_set took {}ms",
		as_millis(now.elapsed())
	);

	// Remove a large number of pos in chunks to simulate blocks containing tx
	// spending outputs. Simulate 1,000 blocks each spending 1,000 outputs.
	let now = Instant::now();
	for x in 0usize..1_000 {
		for y in 0usize..1_000 {
			let idx = (x * 1_000) + y;
			leaf_set.remove(positions[idx]).unwrap();
		}
		leaf_set.flush().unwrap();
	}
	assert_eq!(leaf_set.len(), 0);
	println!(
		"Removing 1,000 chunks of 1,000 pos from leaf_set took {}ms",
		as_millis(now.elapsed())
	);

	// Rewind pos in chunks of 1,000 to simulate rewinding over the same blocks.
	let now = Instant::now();
	for x in 0usize..1_000 {
		let from_idx = x * 1_000;
		let to_idx = from_idx + 1_000;
		let bitmap: Bitmap = positions[from_idx..to_idx]
			.iter()
			.map(|pos| (*pos + 1) as u32)
			.collect();
		leaf_set.rewind(cutoff_pos, &bitmap).unwrap();
	}
	assert_eq!(leaf_set.len(), 1_000_000);
	println!(
		"Rewinding 1,000 chunks of 1,000 pos from leaf_set took {}ms",
		as_millis(now.elapsed())
	);

	// panic!("stop here to display results");

	teardown(data_dir);
}

fn setup(test_name: &str) -> (LeafSet, String) {
	let _ = env_logger::init();
	let data_dir = format!("./target/{}-{}", test_name, Utc::now().timestamp());
	fs::create_dir_all(data_dir.clone()).unwrap();
	let leaf_set = LeafSet::open_or_create(&format!("{}/{}", data_dir, "utxo.bin")).unwrap();
	(leaf_set, data_dir)
}

fn teardown(data_dir: String) {
	fs::remove_dir_all(data_dir).unwrap();
}
