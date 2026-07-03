#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate mwc_core;
extern crate mwc_p2p;

mod fuzz_global;

use mwc_core::ser;
use mwc_core::ser::ProtocolVersion;
use mwc_p2p::msg::MsgHeaderWrapper;

fuzz_target!(|data: &[u8]| {
	fuzz_global::init();
	let mut d = data;
	// it is fuzz test, no error handling expected
	let _t: Result<MsgHeaderWrapper, ser::Error> =
		ser::deserialize_strict(&mut d, ProtocolVersion::local_db(), 0);
});
