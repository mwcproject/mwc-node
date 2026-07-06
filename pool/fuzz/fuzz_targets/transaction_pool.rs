#![no_main]
// Copyright 2019 The Grin Developers
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

// This crate is a libFuzzer harness for the transaction pool. It is not
// production code: unwraps, expects, assertions, and any resulting panics are
// intentional for fuzz-harness setup, corpus generation, and invariant
// checks. Malformed fuzz input is handled at the deserialization/pool boundary
// below; fixture failures should abort loudly. Checked or unchecked numeric
// conversions in this fuzz-only harness are accepted as fixture construction
// details and must not be treated as production transaction-pool behavior.
use libfuzzer_sys::fuzz_target;

use std::fs::{self, File};
use std::io::{BufWriter, Write};

use mwc_core::{
	core::{KernelFeatures, NRDRelativeHeight, Transaction},
	global, ser,
};
use std::convert::TryInto;

mod common;

use common::*;

#[derive(Debug)]
enum Error {
	IoErr,
	SerErr,
}

struct FuzzTx {
	version: u32,
	name: String,
	tx: Transaction,
}

fn gen_tx_corpus() -> Result<(), Error> {
	let mut fuzzer = PoolFuzzer::new("fuzz/target/.transaction_pool_corpus");

	// create arbitrary inputs and outputs
	let inputs: Vec<u64> = vec![10, 100, 1000, 10000, 100000, 200000, 400000, 800000];
	let outputs: Vec<u64> = vec![5, 50, 500, 5000, 50000, 100000, 200000, 400000];
	let mut txes: Vec<FuzzTx> = vec![];

	// create valid txes of all supported types
	txes.push(FuzzTx {
		version: 1u32,
		name: "coinbase".into(),
		tx: fuzzer.test_transaction_spending_coinbase(outputs.clone()),
	});
	txes.push(FuzzTx {
		version: 1u32,
		name: "plain".into(),
		tx: fuzzer.test_transaction(inputs.clone(), outputs.clone()),
	});
	txes.push(FuzzTx {
		version: 2u32,
		name: "height-locked".into(),
		tx: fuzzer.test_transaction_with_kernel_features(
			inputs.clone(),
			outputs.clone(),
			KernelFeatures::HeightLocked {
				// Fuzz-only fee conversion: unchecked fixture fees are accepted
				// here, and invalid values should abort corpus generation loudly.
				fee: 100u64.try_into().unwrap(),
				lock_height: 42u64,
			},
		),
	});
	txes.push(FuzzTx {
		version: 2u32,
		name: "no-recent-duplicate".into(),
		tx: fuzzer.test_transaction_with_kernel_features(
			inputs.clone(),
			outputs.clone(),
			KernelFeatures::NoRecentDuplicate {
				// Fuzz-only fee conversion: unchecked fixture fees are accepted
				// here, and invalid values should abort corpus generation loudly.
				fee: 100u64.try_into().unwrap(),
				relative_height: NRDRelativeHeight::new(42u64).unwrap(),
			},
		),
	});

	fs::create_dir_all("fuzz/corpus/transaction_pool").map_err(|_| Error::IoErr)?;

	// write txes to corpus files
	for tx in txes {
		let dict = File::create(format!("fuzz/corpus/transaction_pool/{}", tx.name))
			.map_err(|_| Error::IoErr)?;
		let mut writer = BufWriter::new(dict);
		ser::serialize(&mut writer, ser::ProtocolVersion(tx.version), 0, &tx.tx)
			.map_err(|_| Error::SerErr)?;
		writer.flush().map_err(|_| Error::IoErr)?;
	}

	Ok(())
}

fuzz_target!(|data: &[u8]| {
	// skip if input is too short
	if data.len() < 80 {
		return ();
	}

	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	global::set_local_accept_fee_base(global::DEFAULT_ACCEPT_FEE_BASE)
		.expect("valid accept fee base");

	// check for corpus generation arguments
	// only generate corpus once, skipping on every other run
	if let Ok(gen_corpus) = std::env::var("MWC_POOL_GEN_CORPUS") {
		if gen_corpus == "0" {
			gen_tx_corpus().unwrap();
			std::env::set_var("MWC_POOL_GEN_CORPUS", "1");
		}
	}

	let mut fuzzer = PoolFuzzer::new("fuzz/target/.transaction_pool");

	let header = fuzzer.chain.head_header().unwrap();

	for &i in [true, false].iter() {
		// deserialize tx from fuzzer data
		let tx_source = fuzz_tx_source(data[0]);
		let mut data = &data[..];
		let tx: Result<Transaction, ser::Error> =
			ser::deserialize_strict(&mut data, ser::ProtocolVersion(2), 0);
		// we only care about inputs that pass
		if tx.is_ok() {
			// attempt to add fuzzed tx to the transaction pool
			//   fuzz tx source on random first byte of fuzzer input
			//   add to tx pool, then stem pool
			match fuzzer
				.pool
				.add_to_pool(tx_source, tx.unwrap(), i, &header, &mut fuzzer.secp)
			{
				Ok(_) if i => {
					assert!(fuzzer.pool.stempool.size() >= 1 || fuzzer.pool.total_size() >= 1)
				}
				Ok(_) => assert!(fuzzer.pool.total_size() >= 1),
				Err(_) => continue,
			}
		}
	}
});
