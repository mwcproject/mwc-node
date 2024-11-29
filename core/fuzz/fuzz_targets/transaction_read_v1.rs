#![no_main]
use libfuzzer_sys::fuzz_target;

extern crate mwc_core;

use mwc_core::core::Transaction;
use mwc_core::ser::{self, DeserializationMode};

fuzz_target!(|data: &[u8]| {
	let mut d = data.clone();
	let _t: Result<Transaction, ser::Error> =
		ser::deserialize(&mut d, ser::ProtocolVersion(1), DeserializationMode::Full);
});
