#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

extern crate mwc_core;

use mwc_core::core::UntrustedCompactBlock;
use mwc_core::global::{set_local_chain_type, set_local_nrd_enabled, ChainTypes};
use mwc_core::ser;

fuzz_target!(|data: &[u8]| {
	set_local_chain_type(ChainTypes::Mainnet);
	set_local_nrd_enabled(true);
	let mut reader = Cursor::new(data);
	// Note, result is intentionally ignored. It is a fuzz test, deserialize is expected to fail
	let _t: Result<UntrustedCompactBlock, ser::Error> =
		ser::deserialize_strict(&mut reader, ser::ProtocolVersion(1), 0);
});
