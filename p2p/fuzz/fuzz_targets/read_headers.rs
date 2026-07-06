#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate mwc_core;
extern crate mwc_p2p;

mod fuzz_global;

use mwc_core::core::block::{BlockHeader, UntrustedBlockHeader};
use mwc_core::ser;
use mwc_core::ser::{ProtocolVersion, Readable, Reader};
use mwc_p2p::MAX_BLOCK_HEADERS;

struct FuzzHeaders {
	_headers: Vec<BlockHeader>,
}

impl Readable for FuzzHeaders {
	fn read<R: Reader>(reader: &mut R) -> Result<FuzzHeaders, ser::Error> {
		let len = reader.read_u16()?;
		if (len as u32) > MAX_BLOCK_HEADERS {
			return Err(ser::Error::TooLargeReadErr(format!(
				"too many headers: {}",
				len
			)));
		}

		let mut headers = Vec::with_capacity(len as usize);
		for _ in 0..len {
			let header = UntrustedBlockHeader::read(reader)?;
			headers.push(header.into());
		}

		Ok(FuzzHeaders { _headers: headers })
	}
}

fuzz_target!(|data: &[u8]| {
	fuzz_global::init();
	let mut d = data;
	// it is fuzz test, no error handling expected
	let _t: Result<FuzzHeaders, ser::Error> =
		ser::deserialize_strict(&mut d, ProtocolVersion::local_db(), 0);
});
