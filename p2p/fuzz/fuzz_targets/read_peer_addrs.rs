#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate mwc_core;
extern crate mwc_p2p;

use mwc_core::ser;
use mwc_p2p::msg::PeerAddrs;

fuzz_target!(|data: &[u8]| {
	let mut d = data.clone();
	let _t: Result<PeerAddrs, ser::Error> = ser::deserialize(&mut d);
});
