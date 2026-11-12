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

use self::build::{feature_input, height_tagged_output};
use keychain::{Identifier, Keychain};
use mwc_core::core::hash::{DefaultHashable, Hashed};
use mwc_core::core::{Block, BlockHeader, Transaction};
use mwc_core::core::{Inputs, KernelFeatures, OutputFeatures, OutputIdentifier};
use mwc_core::libtx::proof::ProofBuilder;
use mwc_core::libtx::{proof::ProofBuild, reward};
use mwc_core::pow::Difficulty;
use mwc_core::ser::{self, Error, PMMRable, Readable, Reader, Writeable, Writer};
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::SecretKey;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use std::convert::TryInto;

#[allow(unused_imports)]
pub use mwc_core::libtx::build;

// utility producing a transaction with 2 inputs and a single outputs
#[allow(dead_code)]
pub fn tx2i1o() -> Transaction {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = keychain::ExtKeychain::derive_key_id(3, 0, 0, 1, 0).unwrap();
	let key_id2 = keychain::ExtKeychain::derive_key_id(3, 0, 0, 2, 0).unwrap();
	let key_id3 = keychain::ExtKeychain::derive_key_id(3, 0, 0, 3, 0).unwrap();

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap(),
		},
		&[
			feature_input(10, OutputFeatures::Plain, key_id1),
			feature_input(11, OutputFeatures::Plain, key_id2),
			height_tagged_output(19, key_id3, 1),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	// Protocol-3 fixtures compare wire hashes and aggregated bodies.
	let inputs = Inputs::CommitOnly(tx.inputs().into_commit_wrappers(0).unwrap());
	Transaction {
		body: tx.body.replace_inputs(0, inputs).unwrap(),
		..tx
	}
}

// utility producing a transaction with a single input and output
#[allow(dead_code)]
pub fn tx1i1o() -> Transaction {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = keychain::ExtKeychain::derive_key_id(3, 0, 0, 1, 0).unwrap();
	let key_id2 = keychain::ExtKeychain::derive_key_id(3, 0, 0, 2, 0).unwrap();

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap(),
		},
		&[
			feature_input(5, OutputFeatures::Plain, key_id1),
			height_tagged_output(3, key_id2, 1),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	// Protocol-3 fixtures compare wire hashes and aggregated bodies.
	let inputs = Inputs::CommitOnly(tx.inputs().into_commit_wrappers(0).unwrap());
	Transaction {
		body: tx.body.replace_inputs(0, inputs).unwrap(),
		..tx
	}
}

#[allow(dead_code)]
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

// utility producing a transaction with a single input
// and two outputs (one change output)
// Note: this tx has an "offset" kernel
#[allow(dead_code)]
pub fn tx1i2o() -> Transaction {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = keychain::ExtKeychain::derive_key_id(3, 0, 0, 1, 0).unwrap();
	let key_id2 = keychain::ExtKeychain::derive_key_id(3, 0, 0, 2, 0).unwrap();
	let key_id3 = keychain::ExtKeychain::derive_key_id(3, 0, 0, 3, 0).unwrap();

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap(),
		},
		&[
			feature_input(6, OutputFeatures::Plain, key_id1),
			height_tagged_output(3, key_id2, 1),
			height_tagged_output(1, key_id3, 1),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	// Protocol-3 fixtures compare wire hashes and aggregated bodies.
	let inputs = Inputs::CommitOnly(tx.inputs().into_commit_wrappers(0).unwrap());
	Transaction {
		body: tx.body.replace_inputs(0, inputs).unwrap(),
		..tx
	}
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
	let height = previous_header.height + 1;
	// These fixtures exercise stateless core validation and serialization.
	// Chain tests calculate the actual input/state digest from their UTXO set.
	let (output, kernel, opening) = reward::output_s2c(
		0,
		keychain,
		builder,
		key_id,
		fees,
		height,
		&mut secp,
		previous_header.hash(0).unwrap(),
	)
	.unwrap();
	let mut block = Block::new(
		0,
		&previous_header,
		txs,
		Difficulty::min(),
		(output, kernel),
		&mut secp,
	)
	.unwrap();
	if mwc_core::consensus::is_coinbase_binding_enabled(0, height) {
		block.coinbase_opening = Some(opening);
	}
	block
}

// utility producing a transaction that spends an output with the provided
// value and blinding key
#[allow(dead_code)]
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
		&[
			feature_input(v, OutputFeatures::Plain, key_id1),
			height_tagged_output(3, key_id2, 1),
		],
		keychain,
		builder,
	)
	.unwrap()
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
