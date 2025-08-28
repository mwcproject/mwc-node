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

use mwc_chain as chain;
use mwc_core as core;
use mwc_util as util;

#[macro_use]
extern crate log;

use crate::chain::types::NoopAdapter;
use crate::core::core::hash::Hashed;
use crate::core::{genesis, global, pow};
use mwc_core::consensus::MWC_BASE;
use mwc_core::core::KernelFeatures;
use std::sync::Arc;

mod chain_test_helper;

#[test]
#[ignore]
// Manual checking test, one time test
fn test_chain_validation() {
	util::init_test_logger();

	let src_root_dir = format!("/Users/mw/main_archive_aug27/chain_data");
	info!("Read data from {}", src_root_dir);

	global::set_global_chain_type(global::ChainTypes::Mainnet);
	let genesis = genesis::genesis_main();

	let dummy_adapter = Arc::new(NoopAdapter {});

	// The original chain we're reading from
	let src_chain = chain::Chain::init(
		src_root_dir.into(),
		dummy_adapter.clone(),
		genesis.clone(),
		pow::verify_size,
		false,
	)
	.unwrap();

	let src_head = src_chain.head().unwrap();
	info!("The head tip: {}", src_head.height);

	for height in 0..src_head.height {
		if height % 1000 == 0 {
			info!("Processing block {}", height);
		}
		let hdr = src_chain.get_header_by_height(height).unwrap();
		let block = src_chain.get_block(&hdr.hash()).unwrap();
		for kernel in &block.body.kernels {
			let fee = match kernel.features {
				KernelFeatures::Plain { fee } => fee.fee(),
				KernelFeatures::Coinbase => 0,
				KernelFeatures::HeightLocked { fee, .. } => fee.fee(),
				KernelFeatures::NoRecentDuplicate { fee, .. } => fee.fee(),
			};
			if fee > MWC_BASE * 10 {
				panic!("We got large fee {} at {}", fee, height);
			}
			if fee > ((1 as u64) << 40) - 1 {
				panic!("Fee {} at {} doesn't fit the mask", fee, height);
			}
		}
	}
}
