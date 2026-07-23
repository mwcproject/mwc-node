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

mod common;
use crate::common::build::{self, input, output};
use crate::common::{new_block, tx1i2o, tx2i1o, txspend1i1o};
use keychain::{BlindingFactor, ExtKeychain, Keychain};
use mwc_core::consensus::{self, BLOCK_OUTPUT_WEIGHT};
use mwc_core::core::block::{Block, BlockHeader, Error, HeaderVersion, UntrustedBlockHeader};
use mwc_core::core::hash::Hashed;
use mwc_core::core::id::ShortIdentifiable;
use mwc_core::core::transaction::{
	self, FeeFields, KernelFeatures, NRDRelativeHeight, Output, OutputFeatures, OutputIdentifier,
	Transaction,
};
use mwc_core::core::{Committed, CompactBlock, CompactBlockBody, Inputs, UntrustedCompactBlock};
use mwc_core::libtx::{reward, ProofBuilder};
use mwc_core::ser::{Writeable, Writer};
use mwc_core::{global, pow, ser};
use mwc_crates::chrono::Duration;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Error as SecpError, Secp256k1, SecretKey};
use std::convert::TryInto;
use util::ToHex;

// Setup test with AutomatedTesting chain_type;
fn test_setup() {
	util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
}

#[test]
fn too_large_block() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let max_out = global::max_block_weight(0) / BLOCK_OUTPUT_WEIGHT;

	let mut pks = vec![];
	for n in 0..(max_out + 1) {
		pks.push(ExtKeychain::derive_key_id(1, n as u32, 0, 0, 0).unwrap());
	}

	let mut parts = vec![];
	for _ in 0..max_out {
		parts.push(output(5, pks.pop().unwrap()));
	}

	parts.append(&mut vec![input(500000, pks.pop().unwrap())]);
	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap(),
		},
		&parts,
		&keychain,
		&builder,
	)
	.unwrap();

	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[tx], &keychain, &builder, &prev, &key_id);
	assert!(b.validate(0, &BlindingFactor::zero(), &mut secp).is_err());
}

#[test]
// block with no inputs/outputs/kernels
// no fees, no reward, no coinbase
fn very_empty_block() {
	test_setup();
	let b = Block::with_header(0, BlockHeader::default(0));
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	assert!(matches!(
		b.verify_coinbase(0, &secp),
		Err(Error::Secp(SecpError::IncorrectCommitSum))
	));
}

#[test]
fn with_reward_rejects_non_empty_block() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let block = new_block(&[tx1i2o()], &keychain, &builder, &prev, &key_id);
	let reward = reward::output(0, &keychain, &builder, &key_id, 0, false, 0, &mut secp).unwrap();

	assert!(matches!(
		block.with_reward(reward.0, reward.1),
		Err(Error::Other(_))
	));
}

#[test]
fn block_with_nrd_kernel_pre_post_hf3() {
	// automated testing - HF{1|2|3} at block heights {3, 6, 9}
	// Enable the global NRD feature flag. NRD kernels valid at HF3 at height 9.
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(true);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::NoRecentDuplicate {
			fee: 2u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(1440).unwrap(),
		},
		&[input(7, key_id1), output(5, key_id2)],
		&keychain,
		&builder,
	)
	.unwrap();
	let txs = &[tx];

	let prev_height = consensus::TESTING_THIRD_HARD_FORK - 2;
	let prev = BlockHeader {
		height: prev_height,
		version: consensus::header_version(0, prev_height),
		..BlockHeader::default(0)
	};
	let b = new_block(
		txs,
		&keychain,
		&builder,
		&prev,
		&ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap(),
	);

	// Block is invalid at header version 3 if it contains an NRD kernel.
	assert_eq!(b.header.version, HeaderVersion(3));
	assert!(matches!(
		b.validate(0, &BlindingFactor::zero(), &mut secp),
		Err(Error::NRDKernelPreHF3)
	));

	let prev_height = consensus::TESTING_THIRD_HARD_FORK - 1;
	let prev = BlockHeader {
		height: prev_height,
		version: consensus::header_version(0, prev_height),
		..BlockHeader::default(0)
	};
	let b = new_block(
		txs,
		&keychain,
		&builder,
		&prev,
		&ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap(),
	);

	// Block is valid at header version 4 (at HF height) if it contains an NRD kernel.
	assert_eq!(b.header.height, consensus::TESTING_THIRD_HARD_FORK);
	assert_eq!(b.header.version, HeaderVersion(4));
	assert!(b.validate(0, &BlindingFactor::zero(), &mut secp).is_ok());

	let prev_height = consensus::TESTING_THIRD_HARD_FORK;
	let prev = BlockHeader {
		height: prev_height,
		version: consensus::header_version(0, prev_height),
		..BlockHeader::default(0)
	};
	let b = new_block(
		txs,
		&keychain,
		&builder,
		&prev,
		&ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap(),
	);

	// Block is valid at header version 4 if it contains an NRD kernel.
	assert_eq!(b.header.version, HeaderVersion(4));
	assert!(b.validate(0, &BlindingFactor::zero(), &mut secp).is_ok());
}

#[test]
fn block_with_nrd_kernel_nrd_not_enabled() {
	global::set_local_nrd_enabled(false);
	// automated testing - HF{1|2|3} at block heights {3, 6, 9}
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::NoRecentDuplicate {
			fee: 2u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(1440).unwrap(),
		},
		&[input(7, key_id1), output(5, key_id2)],
		&keychain,
		&builder,
	)
	.unwrap();

	let txs = &[tx];

	let prev_height = consensus::TESTING_THIRD_HARD_FORK - 2;
	let prev = BlockHeader {
		height: prev_height,
		version: consensus::header_version(0, prev_height),
		..BlockHeader::default(0)
	};
	let b = new_block(
		txs,
		&keychain,
		&builder,
		&prev,
		&ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap(),
	);

	// Block is invalid as NRD not enabled.
	assert_eq!(b.header.version, HeaderVersion(3));
	assert!(matches!(
		b.validate(0, &BlindingFactor::zero(), &mut secp),
		Err(Error::NRDKernelNotEnabled)
	));

	let prev_height = consensus::TESTING_THIRD_HARD_FORK - 1;
	let prev = BlockHeader {
		height: prev_height,
		version: consensus::header_version(0, prev_height),
		..BlockHeader::default(0)
	};
	let b = new_block(
		txs,
		&keychain,
		&builder,
		&prev,
		&ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap(),
	);

	// Block is invalid as NRD not enabled.
	assert_eq!(b.header.height, consensus::TESTING_THIRD_HARD_FORK);
	assert_eq!(b.header.version, HeaderVersion(4));
	assert!(matches!(
		b.validate(0, &BlindingFactor::zero(), &mut secp),
		Err(Error::NRDKernelNotEnabled)
	));

	let prev_height = consensus::TESTING_THIRD_HARD_FORK;
	let prev = BlockHeader {
		height: prev_height,
		version: consensus::header_version(0, prev_height),
		..BlockHeader::default(0)
	};
	let b = new_block(
		txs,
		&keychain,
		&builder,
		&prev,
		&ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap(),
	);

	// Block is invalid as NRD not enabled.
	assert_eq!(b.header.version, HeaderVersion(4));
	assert!(matches!(
		b.validate(0, &BlindingFactor::zero(), &mut secp),
		Err(Error::NRDKernelNotEnabled)
	));
}

#[test]
// builds a block with a tx spending another and check that cut_through occurred
fn block_with_cut_through() {
	global::set_local_nrd_enabled(false);
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	let btx1 = tx2i1o();
	let btx2 = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap(),
		},
		&[input(7, key_id1), output(5, key_id2.clone())],
		&keychain,
		&builder,
	)
	.unwrap();

	// spending tx2 - reuse key_id2

	let btx3 = txspend1i1o(5, &keychain, &builder, key_id2, key_id3);
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[btx1, btx2, btx3], &keychain, &builder, &prev, &key_id);

	// block should have been automatically compacted (including reward
	// output) and should still be valid
	b.validate(0, &BlindingFactor::zero(), &mut secp).unwrap();
	assert_eq!(b.inputs().len(), 3);
	assert_eq!(b.outputs().len(), 3);
}

#[test]
fn empty_block_with_coinbase_is_valid() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);

	assert_eq!(b.inputs().len(), 0);
	assert_eq!(b.outputs().len(), 1);
	assert_eq!(b.kernels().len(), 1);

	let coinbase_outputs = b
		.outputs()
		.iter()
		.filter(|out| out.is_coinbase())
		.cloned()
		.collect::<Vec<_>>();
	assert_eq!(coinbase_outputs.len(), 1);

	let coinbase_kernels = b
		.kernels()
		.iter()
		.filter(|out| out.is_coinbase())
		.cloned()
		.collect::<Vec<_>>();
	assert_eq!(coinbase_kernels.len(), 1);

	// the block should be valid here (single coinbase output with corresponding
	// txn kernel)
	assert!(b.validate(0, &BlindingFactor::zero(), &mut secp).is_ok());
}

#[test]
// test that flipping the COINBASE flag on the output features
// invalidates the block and specifically it causes verify_coinbase to fail
// additionally verifying the merkle_inputs_outputs also fails
fn remove_coinbase_output_flag() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let output = b.outputs()[0];
	let output = Output::new(OutputFeatures::Plain, output.commitment(), output.proof());
	let b = Block {
		body: b.body.replace_outputs(0, &[output]).unwrap(),
		..b
	};

	assert!(matches!(
		b.verify_coinbase(0, &mut secp),
		Err(Error::CoinbaseSumMismatch)
	));
	assert!(b
		.verify_kernel_sums(
			b.header.overage(0).unwrap(),
			b.header.total_kernel_offset(),
			&mut secp
		)
		.is_ok());
	assert!(matches!(
		b.validate(0, &BlindingFactor::zero(), &mut secp),
		Err(Error::CoinbaseSumMismatch)
	));
}

#[test]
// test that flipping the COINBASE flag on the kernel features
// invalidates the block and specifically it causes verify_coinbase to fail
fn remove_coinbase_kernel_flag() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let mut b = new_block(&[], &keychain, &builder, &prev, &key_id);

	let mut kernel = b.kernels()[0].clone();
	kernel.features = KernelFeatures::Plain {
		fee: FeeFields::new(10).unwrap(),
	};
	b.body = b.body.replace_kernel(kernel);

	// Flipping the coinbase flag results in kernels not summing correctly.
	assert!(matches!(
		b.verify_coinbase(0, &mut secp),
		Err(Error::Secp(SecpError::IncorrectCommitSum))
	));

	// Also results in the block no longer validating correctly
	// because the message being signed on each tx kernel includes the kernel features.
	assert!(matches!(
		b.validate(0, &BlindingFactor::zero(), &mut secp),
		Err(Error::Transaction(transaction::Error::IncorrectSignature))
	));
}

#[test]
fn serialize_deserialize_header_version() {
	let mut vec1 = Vec::new();
	ser::serialize_default(0, &mut vec1, &1_u16).expect("serialization failed");

	let mut vec2 = Vec::new();
	ser::serialize_default(0, &mut vec2, &HeaderVersion(1)).expect("serialization failed");

	// Check that a header_version serializes to a
	// single u16 value with no extraneous bytes wrapping it.
	assert_eq!(vec1, vec2);

	// Check we can successfully deserialize a header_version.
	let version: HeaderVersion = ser::deserialize_default(0, &mut &vec2[..]).unwrap();
	assert_eq!(version.0, 1)
}

#[test]
fn serialize_deserialize_block_header() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let header1 = b.header;

	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &header1).expect("serialization failed");
	let header2: BlockHeader = ser::deserialize_default(0, &mut &vec[..]).unwrap();

	assert_eq!(header1.hash(0).unwrap(), header2.hash(0).unwrap());
	assert_eq!(header1, header2);
}

#[test]
fn block_header_rejects_subsecond_timestamp_precision() {
	test_setup();
	let mut header = BlockHeader::default(0);
	header.timestamp = header.timestamp + Duration::nanoseconds(1);

	let precision_err = header.validate_timestamp_precision().unwrap_err();
	assert!(matches!(precision_err, ser::Error::CorruptedData(_)));

	let mut header_buf = vec![];
	let mut writer = ser::BinWriter::default(0, &mut header_buf);
	let pre_pow_err = header.write_pre_pow(&mut writer).unwrap_err();
	assert!(matches!(pre_pow_err, ser::Error::CorruptedData(_)));

	let pmmr_err = ser::PMMRable::as_elmt(&header).unwrap_err();
	assert!(matches!(pmmr_err, ser::Error::CorruptedData(_)));
}

fn set_pow(header: &mut BlockHeader) {
	// Set valid pow on the block as we will test deserialization of this "untrusted" from the network.
	let edge_bits = global::min_edge_bits(0);
	header.pow.proof.edge_bits = edge_bits;
	pow::pow_size(
		0,
		header,
		pow::Difficulty::min(),
		global::proofsize(0),
		edge_bits,
	)
	.unwrap();
}

#[test]
fn deserialize_untrusted_header_weight() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let mut b = new_block(&[], &keychain, &builder, &prev, &key_id);

	// Set excessively large output mmr size on the header.
	b.header.output_mmr_size = 10_000;
	b.header.kernel_mmr_size = 0;
	set_pow(&mut b.header);

	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &b.header).expect("serialization failed");
	let res: Result<UntrustedBlockHeader, _> = ser::deserialize_default(0, &mut &vec[..]);
	assert!(matches!(
		res,
		Err(ser::Error::CorruptedData(ref msg)) if msg == "Tx global weight is exceed the limit"
	));

	// Set excessively large kernel mmr size on the header.
	b.header.output_mmr_size = 0;
	b.header.kernel_mmr_size = 10_000;
	set_pow(&mut b.header);

	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &b.header).expect("serialization failed");
	let res: Result<UntrustedBlockHeader, _> = ser::deserialize_default(0, &mut &vec[..]);
	assert!(matches!(
		res,
		Err(ser::Error::CorruptedData(ref msg)) if msg == "Tx global weight is exceed the limit"
	));

	// Set reasonable mmr sizes on the header to confirm the header can now be read "untrusted".
	b.header.output_mmr_size = 1;
	b.header.kernel_mmr_size = 1;
	set_pow(&mut b.header);

	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &b.header).expect("serialization failed");
	let res: Result<UntrustedBlockHeader, _> = ser::deserialize_default(0, &mut &vec[..]);
	assert!(res.is_ok());
}

#[test]
fn serialize_deserialize_block() {
	test_setup();
	let tx1 = tx1i2o();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);

	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &b).expect("serialization failed");
	let b2: Block = ser::deserialize_default(0, &mut &vec[..]).unwrap();

	assert_eq!(b.hash(0).unwrap(), b2.hash(0).unwrap());
	assert_eq!(b.header, b2.header);
	assert!(b.inputs().eq_by_hash(0, &b2.inputs()).unwrap());
	assert_eq!(b.outputs(), b2.outputs());
	assert!(ser::slices_equal_by_hash(0, b.kernels(), b2.kernels()).unwrap());
}

#[test]
fn empty_block_serialized_size() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &b).expect("serialization failed");
	assert_eq!(vec.len(), 1_096);
}

#[test]
fn block_single_tx_serialized_size() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let tx1 = tx1i2o();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);

	// Default protocol version (3)
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &b).expect("serialization failed");
	assert_eq!(vec.len(), 2_669);

	// Protocol version 3
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(3), 0, &b).expect("serialization failed");
	assert_eq!(vec.len(), 2_669);

	// Protocol version 2.
	// Note: block must be in "v2" compatibility with "features and commit" inputs for this.
	// Normally we would convert the block by looking inputs up in utxo but we fake it here for testing.
	let inputs = b
		.inputs()
		.into_commit_wrappers(0)
		.expect("convert inputs to commit-only form");
	let inputs: Vec<_> = inputs
		.iter()
		.map(|input| OutputIdentifier {
			features: OutputFeatures::Plain,
			commit: input.commitment(),
		})
		.collect();
	let b = Block {
		header: b.header,
		body: b
			.body
			.replace_inputs(
				0,
				Inputs::from_output_identifiers(0, inputs.as_slice()).unwrap(),
			)
			.unwrap(),
	};

	// Protocol version 2
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(2), 0, &b).expect("serialization failed");
	assert_eq!(vec.len(), 2_670);

	// Protocol version 1 (fixed size kernels)
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(1), 0, &b).expect("serialization failed");
	assert_eq!(vec.len(), 2_694);

	// Check we can also serialize a v2 compatibility block in v3 protocol version
	// without needing to explicitly convert the block.
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(3), 0, &b).expect("serialization failed");
	assert_eq!(vec.len(), 2_669);

	// Default protocol version (3) for completeness
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &b).expect("serialization failed");
	assert_eq!(vec.len(), 2_669);
}

#[test]
fn empty_compact_block_serialized_size() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = CompactBlock::from(b).unwrap();
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &cb).expect("serialization failed");
	assert_eq!(vec.len(), 1_104);
}

#[test]
fn compact_block_single_tx_serialized_size() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let tx1 = tx1i2o();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = CompactBlock::from(b).unwrap();
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &cb).expect("serialization failed");
	assert_eq!(vec.len(), 1_110);
}

#[test]
fn block_4_tx_serialized_size() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();

	let mut txs = vec![];
	for _ in 0..4 {
		let tx = tx1i2o();
		txs.push(tx);
	}
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&txs, &keychain, &builder, &prev, &key_id);

	{
		let mut vec = Vec::new();
		ser::serialize_default(0, &mut vec, &b).expect("serialization failed");
		assert_eq!(vec.len(), 7_388);
	}
}

#[test]
fn compact_block_10_tx_serialized_size() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();

	let mut txs = vec![];
	for _ in 0..10 {
		let tx = tx1i2o();
		txs.push(tx);
	}
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&txs, &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = CompactBlock::from(b).unwrap();
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &cb).expect("serialization failed");
	assert_eq!(vec.len(), 1_164);
}

#[test]
fn compact_block_hash_with_nonce() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let tx = tx1i2o();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[tx.clone()], &keychain, &builder, &prev, &key_id);
	let cb1: CompactBlock = CompactBlock::from(b.clone()).unwrap();
	let cb2: CompactBlock = CompactBlock::from(b.clone()).unwrap();

	// random nonce will not affect the hash of the compact block itself
	// hash is based on header POW only
	assert!(cb1.nonce != cb2.nonce);
	assert_eq!(b.hash(0).unwrap(), cb1.hash(0).unwrap());
	assert_eq!(cb1.hash(0).unwrap(), cb2.hash(0).unwrap());

	assert!(!ser::hashes_equal(0, &cb1.kern_ids()[0], &cb2.kern_ids()[0]).unwrap());

	// check we can identify the specified kernel from the short_id
	// correctly in both of the compact_blocks
	let expected = tx.kernels()[0]
		.short_id(0, &cb1.hash(0).unwrap(), cb1.nonce)
		.unwrap();
	assert!(ser::hashes_equal(0, &cb1.kern_ids()[0], &expected).unwrap());
	let expected = tx.kernels()[0]
		.short_id(0, &cb2.hash(0).unwrap(), cb2.nonce)
		.unwrap();
	assert!(ser::hashes_equal(0, &cb2.kern_ids()[0], &expected).unwrap());
}

#[test]
fn convert_block_to_compact_block() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let tx1 = tx1i2o();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = CompactBlock::from(b.clone()).unwrap();

	assert_eq!(cb.out_full().len(), 1);
	assert_eq!(cb.kern_full().len(), 1);
	assert_eq!(cb.kern_ids().len(), 1);

	let expected = b
		.kernels()
		.iter()
		.find(|x| !x.is_coinbase())
		.unwrap()
		.short_id(0, &cb.hash(0).unwrap(), cb.nonce)
		.unwrap();
	assert!(ser::hashes_equal(0, &cb.kern_ids()[0], &expected).unwrap());
}

#[test]
fn hydrate_empty_compact_block() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);
	let cb: CompactBlock = CompactBlock::from(b.clone()).unwrap();
	let hb = Block::hydrate_from(cb, &[]).unwrap();
	assert_eq!(hb.header, b.header);
	assert_eq!(hb.outputs(), b.outputs());
	assert!(ser::slices_equal_by_hash(0, hb.kernels(), b.kernels()).unwrap());
}

#[test]
fn serialize_deserialize_compact_block() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let tx1 = tx1i2o();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[tx1], &keychain, &builder, &prev, &key_id);

	let mut cb1: CompactBlock = CompactBlock::from(b.into()).unwrap();

	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &cb1).expect("serialization failed");

	// After header serialization, timestamp will lose 'nanos' info, that's the designed behavior.
	// To suppress 'nanos' difference caused assertion fail, we force b.header also lose 'nanos'.
	let origin_ts = cb1.header.timestamp;
	cb1.header.timestamp =
		origin_ts - Duration::nanoseconds(origin_ts.timestamp_subsec_nanos() as i64);

	let cb2: CompactBlock = ser::deserialize_default(0, &mut &vec[..]).unwrap();

	assert_eq!(cb1.header, cb2.header);
	assert!(ser::slices_equal_by_hash(0, cb1.kern_ids(), cb2.kern_ids()).unwrap());
}

fn serialize_compact_block_with_body(cb: &CompactBlock, body: &CompactBlockBody) -> Vec<u8> {
	let mut vec = Vec::new();
	{
		let mut writer = ser::BinWriter::default(0, &mut vec);
		cb.header.write(&mut writer).unwrap();
		writer.write_u64(cb.nonce).unwrap();
		body.write(&mut writer).unwrap();
	}
	vec
}

fn serialize_compact_block_body(body: &CompactBlockBody) -> Vec<u8> {
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, body).expect("serialization failed");
	vec
}

fn serialize_compact_block_with_body_counts(
	cb: &CompactBlock,
	out_full_len: u64,
	kern_full_len: u64,
	kern_id_len: u64,
) -> Vec<u8> {
	let mut vec = Vec::new();
	{
		let mut writer = ser::BinWriter::default(0, &mut vec);
		cb.header.write(&mut writer).unwrap();
		writer.write_u64(cb.nonce).unwrap();
		writer.write_u64(out_full_len).unwrap();
		writer.write_u64(kern_full_len).unwrap();
		writer.write_u64(kern_id_len).unwrap();
	}
	vec
}

#[test]
fn compact_block_body_read_rejects_non_coinbase_full_output() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let mut b = new_block(&[], &keychain, &builder, &prev, &key_id);
	set_pow(&mut b.header);
	let cb = CompactBlock::from(b).unwrap();

	let output = cb.out_full()[0];
	let output = Output::new(OutputFeatures::Plain, output.commitment(), output.proof());
	let body = CompactBlockBody {
		out_full: vec![output],
		kern_full: cb.kern_full().to_vec(),
		kern_ids: cb.kern_ids().to_vec(),
	};
	let vec = serialize_compact_block_body(&body);

	match ser::deserialize_default::<CompactBlockBody, _>(0, &mut &vec[..]) {
		Err(ser::Error::CorruptedData(msg)) => {
			assert!(
				msg.contains("non-coinbase full output"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!(
			"expected non-coinbase full output rejection, got {:?}",
			other
		),
	}
}

#[test]
fn compact_block_body_read_rejects_non_coinbase_full_kernel() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let mut b = new_block(&[], &keychain, &builder, &prev, &key_id);
	set_pow(&mut b.header);
	let cb = CompactBlock::from(b).unwrap();

	let mut kernel = cb.kern_full()[0].clone();
	kernel.features = KernelFeatures::Plain {
		fee: FeeFields::new(1).unwrap(),
	};
	let body = CompactBlockBody {
		out_full: cb.out_full().to_vec(),
		kern_full: vec![kernel],
		kern_ids: cb.kern_ids().to_vec(),
	};
	let vec = serialize_compact_block_body(&body);

	match ser::deserialize_default::<CompactBlockBody, _>(0, &mut &vec[..]) {
		Err(ser::Error::CorruptedData(msg)) => {
			assert!(
				msg.contains("non-coinbase full kernel"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!(
			"expected non-coinbase full kernel rejection, got {:?}",
			other
		),
	}
}

#[test]
fn untrusted_compact_block_rejects_overweight_body_before_payload() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let mut b = new_block(&[], &keychain, &builder, &prev, &key_id);
	set_pow(&mut b.header);
	let cb = CompactBlock::from(b).unwrap();

	let overweight_kernel_ids = global::max_block_weight(0) / consensus::BLOCK_KERNEL_WEIGHT + 1;
	assert!(overweight_kernel_ids <= ser::READ_VEC_SIZE_LIMIT);
	let vec = serialize_compact_block_with_body_counts(&cb, 0, 0, overweight_kernel_ids);

	match ser::deserialize_default::<UntrustedCompactBlock, _>(0, &mut &vec[..]) {
		Err(ser::Error::TooLargeReadErr(msg)) => {
			assert!(
				msg.contains("CompactBlockBody weight"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!(
			"expected overweight compact block rejection, got {:?}",
			other
		),
	}
}

#[test]
fn untrusted_compact_block_rejects_non_coinbase_full_output() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let mut b = new_block(&[], &keychain, &builder, &prev, &key_id);
	set_pow(&mut b.header);
	let cb = CompactBlock::from(b).unwrap();

	let output = cb.out_full()[0];
	let output = Output::new(OutputFeatures::Plain, output.commitment(), output.proof());
	let body = CompactBlockBody {
		out_full: vec![output],
		kern_full: cb.kern_full().to_vec(),
		kern_ids: cb.kern_ids().to_vec(),
	};
	let vec = serialize_compact_block_with_body(&cb, &body);

	match ser::deserialize_default::<UntrustedCompactBlock, _>(0, &mut &vec[..]) {
		Err(ser::Error::CorruptedData(msg)) => {
			assert!(
				msg.contains("non-coinbase full output"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!(
			"expected non-coinbase full output rejection, got {:?}",
			other
		),
	}
}

#[test]
fn untrusted_compact_block_rejects_non_coinbase_full_kernel() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let mut b = new_block(&[], &keychain, &builder, &prev, &key_id);
	set_pow(&mut b.header);
	let cb = CompactBlock::from(b).unwrap();

	let mut kernel = cb.kern_full()[0].clone();
	kernel.features = KernelFeatures::Plain {
		fee: FeeFields::new(1).unwrap(),
	};
	let body = CompactBlockBody {
		out_full: cb.out_full().to_vec(),
		kern_full: vec![kernel],
		kern_ids: cb.kern_ids().to_vec(),
	};
	let vec = serialize_compact_block_with_body(&cb, &body);

	match ser::deserialize_default::<UntrustedCompactBlock, _>(0, &mut &vec[..]) {
		Err(ser::Error::CorruptedData(msg)) => {
			assert!(
				msg.contains("non-coinbase full kernel"),
				"unexpected error: {}",
				msg
			);
		}
		other => panic!(
			"expected non-coinbase full kernel rejection, got {:?}",
			other
		),
	}
}

// Duplicate a range proof from a valid output into another of the same amount
#[test]
fn same_amount_outputs_copy_range_proof() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = keychain::ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = keychain::ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = keychain::ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 1u32.try_into().unwrap(),
		},
		&[input(7, key_id1), output(3, key_id2), output(3, key_id3)],
		&keychain,
		&builder,
	)
	.unwrap();

	// now we reconstruct the transaction, swapping the rangeproofs so they
	// have the wrong privkey
	let mut outs = tx.outputs().to_vec();
	outs[0].proof = outs[1].proof;

	let key_id = keychain::ExtKeychain::derive_key_id(1, 4, 0, 0, 0).unwrap();
	let prev = BlockHeader::default(0);
	let b = new_block(
		&[Transaction::new(0, tx.inputs(), &outs, tx.kernels()).unwrap()],
		&keychain,
		&builder,
		&prev,
		&key_id,
	);

	// block should have been automatically compacted (including reward
	// output) and should still be valid
	match b.validate(0, &BlindingFactor::zero(), &mut secp) {
		Err(Error::Transaction(transaction::Error::Secp(SecpError::InvalidRangeProof))) => {}
		_ => panic!("Bad range proof should be invalid"),
	}
}

// Swap a range proof with the right private key but wrong amount
#[test]
fn wrong_amount_range_proof() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = keychain::ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = keychain::ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = keychain::ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	let tx1 = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 1u32.try_into().unwrap(),
		},
		&[
			input(7, key_id1.clone()),
			output(3, key_id2.clone()),
			output(3, key_id3.clone()),
		],
		&keychain,
		&builder,
	)
	.unwrap();
	let tx2 = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 1u32.try_into().unwrap(),
		},
		&[input(7, key_id1), output(2, key_id2), output(4, key_id3)],
		&keychain,
		&builder,
	)
	.unwrap();

	// we take the range proofs from tx2 into tx1 and rebuild the transaction
	let mut outs = tx1.outputs().to_vec();
	outs[0].proof = tx2.outputs()[0].proof;
	outs[1].proof = tx2.outputs()[1].proof;

	let key_id = keychain::ExtKeychain::derive_key_id(1, 4, 0, 0, 0).unwrap();
	let prev = BlockHeader::default(0);
	let b = new_block(
		&[Transaction::new(0, tx1.inputs(), &outs, tx1.kernels()).unwrap()],
		&keychain,
		&builder,
		&prev,
		&key_id,
	);

	// block should have been automatically compacted (including reward
	// output) and should still be valid
	match b.validate(0, &BlindingFactor::zero(), &mut secp) {
		Err(Error::Transaction(transaction::Error::Secp(SecpError::InvalidRangeProof))) => {}
		_ => panic!("Bad range proof should be invalid"),
	}
}

#[test]
fn validate_header_proof() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let b = new_block(&[], &keychain, &builder, &prev, &key_id);

	let mut header_buf = vec![];
	{
		let mut writer = ser::BinWriter::default(0, &mut header_buf);
		b.header.write_pre_pow(&mut writer).unwrap();
		b.header.pow.write_pre_pow(&mut writer).unwrap();
	}
	let pre_pow = header_buf.to_hex();

	let reconstructed = BlockHeader::from_pre_pow_and_proof(
		0,
		pre_pow.clone(),
		b.header.pow.nonce,
		b.header.pow.proof.clone(),
	)
	.unwrap();
	assert_eq!(reconstructed, b.header);

	// Extra bytes in the pre-PoW prefix are non-canonical and must be rejected.
	let mut extra_pre_pow = header_buf.clone();
	extra_pre_pow.push(0);
	assert!(BlockHeader::from_pre_pow_and_proof(
		0,
		extra_pre_pow.to_hex(),
		b.header.pow.nonce,
		b.header.pow.proof.clone(),
	)
	.is_err());

	// The pre-PoW prefix must not already contain nonce/proof data.
	let mut full_header = vec![];
	ser::serialize_default(0, &mut full_header, &b.header).unwrap();
	assert!(BlockHeader::from_pre_pow_and_proof(
		0,
		full_header.to_hex(),
		b.header.pow.nonce,
		b.header.pow.proof.clone(),
	)
	.is_err());

	// The supplied proof must be encoded for the same context that will read it.
	let mut wrong_context_proof = b.header.pow.proof.clone();
	wrong_context_proof.context_id = 1;
	assert!(BlockHeader::from_pre_pow_and_proof(
		0,
		pre_pow,
		b.header.pow.nonce,
		wrong_context_proof,
	)
	.is_err());

	// assert invalid pre_pow returns error
	assert!(BlockHeader::from_pre_pow_and_proof(
		0,
		"0xaf1678".to_string(),
		b.header.pow.nonce,
		b.header.pow.proof,
	)
	.is_err());
}

// Test coverage for verifying cut-through during block validation.
// It is not valid for a block to spend an output and produce a new output with the same commitment.
// This test covers the case where a plain output is spent, producing a plain output with the same commitment.
#[test]
fn test_verify_cut_through_plain() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);
	global::set_local_nrd_enabled(false);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();

	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	let builder = ProofBuilder::new(&secp, &keychain).unwrap();

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: FeeFields::new(10).unwrap(),
		},
		&[
			build::input(20, key_id1.clone()),
			build::input(20, key_id2.clone()),
			build::output(20, key_id1.clone()),
			build::output(6, key_id2.clone()),
			build::output(4, key_id3.clone()),
		],
		&keychain,
		&builder,
	)
	.expect("valid tx");

	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(0, 0, 0, 0, 0).unwrap();
	let mut block = new_block(&[tx], &keychain, &builder, &prev, &key_id);

	// The block should fail validation due to cut-through.
	assert!(matches!(
		block.validate(0, &BlindingFactor::zero(), &mut secp),
		Err(Error::Transaction(transaction::Error::CutThrough))
	));

	// The block should fail lightweight "read" validation due to cut-through.
	assert!(matches!(
		block.validate_read(0),
		Err(Error::Transaction(transaction::Error::CutThrough))
	));

	// Apply cut-through to eliminate the offending input and output.
	let mut inputs = block.inputs().into_commit_wrappers(0)?;
	let mut outputs = block.outputs().to_vec();
	let (inputs, outputs, _, _) = transaction::cut_through(0, &mut inputs[..], &mut outputs[..])?;

	block.body = block
		.body
		.replace_inputs(0, inputs.into())
		.unwrap()
		.replace_outputs(0, outputs)
		.unwrap();

	// Block validates successfully after applying cut-through.
	block.validate(0, &BlindingFactor::zero(), &mut secp)?;

	// Block validates via lightweight "read" validation.
	block.validate_read(0)?;

	Ok(())
}

// Test coverage for verifying cut-through during block validation.
// It is not valid for a block to spend an output and produce a new output with the same commitment.
// This test covers the case where a coinbase output is spent, producing a plain output with the same commitment.
#[test]
fn test_verify_cut_through_coinbase() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);
	global::set_local_nrd_enabled(false);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();

	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	let builder = ProofBuilder::new(&secp, &keychain).unwrap();

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: FeeFields::new(10).unwrap(),
		},
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id2.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::output(
				consensus::MWC_FIRST_GROUP_REWARD - 100_000_010,
				key_id2.clone(),
			),
			build::output(100_000_000, key_id3.clone()),
		],
		&keychain,
		&builder,
	)
	.expect("valid tx");

	let prev = BlockHeader::default(0);
	let key_id = ExtKeychain::derive_key_id(0, 0, 0, 0, 0).unwrap();
	let mut block = new_block(&[tx], &keychain, &builder, &prev, &key_id);

	// The block should fail validation due to cut-through.
	assert!(matches!(
		block.validate(0, &BlindingFactor::zero(), &mut secp),
		Err(Error::Transaction(transaction::Error::CutThrough))
	));

	// The block should fail lightweight "read" validation due to cut-through.
	assert!(matches!(
		block.validate_read(0),
		Err(Error::Transaction(transaction::Error::CutThrough))
	));

	// Apply cut-through to eliminate the offending input and output.
	let mut inputs = block.inputs().into_commit_wrappers(0)?;
	let mut outputs = block.outputs().to_vec();
	let (inputs, outputs, _, _) = transaction::cut_through(0, &mut inputs[..], &mut outputs[..])?;

	block.body = block
		.body
		.replace_inputs(0, inputs.into())
		.unwrap()
		.replace_outputs(0, outputs)
		.unwrap();

	// Block validates successfully after applying cut-through.
	block.validate(0, &BlindingFactor::zero(), &mut secp)?;

	// Block validates via lightweight "read" validation.
	block.validate_read(0)?;

	Ok(())
}
