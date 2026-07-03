extern crate mwc_core;
extern crate mwc_keychain;

use mwc_core::core::{Block, CompactBlock, Transaction};
use mwc_core::global::{set_local_chain_type, ChainTypes};
use mwc_core::ser;
use mwc_crates::log::error;
use std::fs::{self, File};
use std::path::Path;

// Note, the Fuzz test doesn't need to meet production standards.
// It is acceptable to handle errors with 'unwrap/
fn main() {
	set_local_chain_type(ChainTypes::Mainnet);
	generate(
		"transaction_read_v1",
		ser::ProtocolVersion(1),
		Transaction::default(),
	)
	.unwrap();
	generate("block_read_v1", ser::ProtocolVersion(1), Block::default(0)).unwrap();
	generate(
		"compact_block_read_v1",
		ser::ProtocolVersion(1),
		CompactBlock::from(Block::default(0)).unwrap(),
	)
	.unwrap();
	generate(
		"transaction_read_v2",
		ser::ProtocolVersion(2),
		Transaction::default(),
	)
	.unwrap();
	generate("block_read_v2", ser::ProtocolVersion(2), Block::default(0)).unwrap();
	generate(
		"compact_block_read_v2",
		ser::ProtocolVersion(2),
		CompactBlock::from(Block::default(0)).unwrap(),
	)
	.unwrap();
}

fn generate<W: ser::Writeable>(
	target: &str,
	version: ser::ProtocolVersion,
	obj: W,
) -> Result<(), ser::Error> {
	// Note, the Fuzz test doesn't need to meet production standards.
	// Corpus data is trusted, it treats any existing pattern file as valid cached data.
	// It doesn't handle any data corruption
	let dir_path = Path::new("corpus").join(target);
	if !dir_path.is_dir() {
		fs::create_dir_all(&dir_path).map_err(|e| {
			error!("fail: {}", e);
			ser::Error::IOErr("can't create corpus directory".to_owned(), e.kind())
		})?;
	}

	let pattern_path = dir_path.join("pattern");
	if !pattern_path.exists() {
		let mut file = File::create(&pattern_path)
			.map_err(|e| ser::Error::IOErr("can't create a pattern file".to_owned(), e.kind()))?;
		ser::serialize(&mut file, version, 0, &obj)
	} else {
		Ok(())
	}
}
