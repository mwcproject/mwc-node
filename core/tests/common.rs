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

//! Common test functions

#[cfg(feature = "test-support")]
use self::build::{input, output};
use keychain::{Identifier, Keychain};
use mwc_core::core::hash::DefaultHashable;
use mwc_core::core::{Block, BlockHeader, Transaction};
#[cfg(feature = "test-support")]
use mwc_core::core::{Inputs, KernelFeatures, OutputFeatures, OutputIdentifier};
#[cfg(feature = "test-support")]
use mwc_core::libtx::proof::ProofBuilder;
use mwc_core::libtx::{proof::ProofBuild, reward};
use mwc_core::pow::Difficulty;
use mwc_core::ser::{self, Error, PMMRable, Readable, Reader, Writeable, Writer};
#[cfg(feature = "test-support")]
use mwc_crates::rand::rngs::SysRng;
#[cfg(feature = "test-support")]
use mwc_crates::secp::SecretKey;
use mwc_crates::secp::{ContextFlag, Secp256k1};
#[cfg(feature = "test-support")]
use std::convert::TryInto;

// Keep test targets compilable without exposing the production builder. Any
// affected test reaches this shim and fails with an actionable runtime error.
#[allow(dead_code, unused_imports)]
pub mod build {
	pub use mwc_core::libtx::build::*;

	#[cfg(not(feature = "test-support"))]
	pub fn output<K, B>(
		_value: u64,
		_key_id: keychain::Identifier,
	) -> Box<mwc_core::libtx::build::Append<K, B>>
	where
		K: keychain::Keychain,
		B: mwc_core::libtx::proof::ProofBuild,
	{
		panic!("test-support feature is required to run the tests");
	}
}

// utility producing a transaction with 2 inputs and a single outputs
#[allow(dead_code)]
#[cfg(feature = "test-support")]
pub fn tx2i1o() -> Transaction {
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
			fee: 2u32.try_into().unwrap(),
		},
		&[input(10, key_id1), input(11, key_id2), output(19, key_id3)],
		&keychain,
		&builder,
	)
	.unwrap();

	tx
}

#[allow(dead_code)]
#[cfg(not(feature = "test-support"))]
pub fn tx2i1o() -> Transaction {
	panic!("test-support feature is required to run the tests");
}

// utility producing a transaction with a single input and output
#[allow(dead_code)]
#[cfg(feature = "test-support")]
pub fn tx1i1o() -> Transaction {
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

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap(),
		},
		&[input(5, key_id1), output(3, key_id2)],
		&keychain,
		&builder,
	)
	.unwrap();

	tx
}

#[allow(dead_code)]
#[cfg(not(feature = "test-support"))]
pub fn tx1i1o() -> Transaction {
	panic!("test-support feature is required to run the tests");
}

#[allow(dead_code)]
#[cfg(feature = "test-support")]
pub fn tx1i10_v2_compatible() -> Transaction {
	let tx = tx1i1o();

	let inputs = tx
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
	Transaction {
		body: tx
			.body
			.replace_inputs(
				0,
				Inputs::from_output_identifiers(0, inputs.as_slice()).unwrap(),
			)
			.unwrap(),
		..tx
	}
}

#[allow(dead_code)]
#[cfg(not(feature = "test-support"))]
pub fn tx1i10_v2_compatible() -> Transaction {
	panic!("test-support feature is required to run the tests");
}

// utility producing a transaction with a single input
// and two outputs (one change output)
// Note: this tx has an "offset" kernel
#[allow(dead_code)]
#[cfg(feature = "test-support")]
pub fn tx1i2o() -> Transaction {
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
			fee: 2u32.try_into().unwrap(),
		},
		&[input(6, key_id1), output(3, key_id2), output(1, key_id3)],
		&keychain,
		&builder,
	)
	.unwrap();

	tx
}

#[allow(dead_code)]
#[cfg(not(feature = "test-support"))]
pub fn tx1i2o() -> Transaction {
	panic!("test-support feature is required to run the tests");
}

// utility to create a block without worrying about the key or previous
// header
#[allow(dead_code)]
pub fn new_block<K, B>(
	txs: &[Transaction],
	keychain: &K,
	builder: &B,
	previous_header: &BlockHeader,
	key_id: &Identifier,
) -> Block
where
	K: Keychain,
	B: ProofBuild,
{
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let fees = txs.iter().map(|tx| tx.fee().unwrap()).sum();
	let reward_output = reward::output(
		0,
		keychain,
		builder,
		&key_id,
		fees,
		false,
		previous_header.height + 1,
		&mut secp,
	)
	.unwrap();
	Block::new(
		0,
		&previous_header,
		txs,
		Difficulty::min(),
		reward_output,
		&mut secp,
	)
	.unwrap()
}

// utility producing a transaction that spends an output with the provided
// value and blinding key
#[allow(dead_code)]
#[cfg(feature = "test-support")]
pub fn txspend1i1o<K, B>(
	v: u64,
	keychain: &K,
	builder: &B,
	key_id1: Identifier,
	key_id2: Identifier,
) -> Transaction
where
	K: Keychain,
	B: ProofBuild,
{
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap(),
		},
		&[input(v, key_id1), output(3, key_id2)],
		keychain,
		builder,
	)
	.unwrap()
}

#[allow(dead_code)]
#[cfg(not(feature = "test-support"))]
pub fn txspend1i1o<K, B>(
	_v: u64,
	_keychain: &K,
	_builder: &B,
	_key_id1: Identifier,
	_key_id2: Identifier,
) -> Transaction
where
	K: Keychain,
	B: ProofBuild,
{
	panic!("test-support feature is required to run the tests");
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TestElem(pub [u32; 4]);

impl DefaultHashable for TestElem {}

impl PMMRable for TestElem {
	type E = Self;

	fn as_elmt(&self) -> Result<Self::E, Error> {
		Ok(*self)
	}

	fn elmt_size() -> Option<u16> {
		Some(16)
	}
}

impl Writeable for TestElem {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u32(self.0[0])?;
		writer.write_u32(self.0[1])?;
		writer.write_u32(self.0[2])?;
		writer.write_u32(self.0[3])
	}
}

impl Readable for TestElem {
	fn read<R: Reader>(reader: &mut R) -> Result<TestElem, ser::Error> {
		Ok(TestElem([
			reader.read_u32()?,
			reader.read_u32()?,
			reader.read_u32()?,
			reader.read_u32()?,
		]))
	}
}
