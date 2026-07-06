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

//! Core tests

pub mod common;

use crate::common::{new_block, tx1i1o, tx1i2o, tx2i1o};
use keychain::{BlindingFactor, ExtKeychain, Keychain};
use mwc_core::core::block::BlockHeader;
use mwc_core::core::block::Error::KernelLockHeight;
use mwc_core::core::hash::{Hashed, ZERO_HASH};
use mwc_core::core::{
	aggregate, deaggregate, Inputs, KernelFeatures, Output, OutputFeatures, OutputIdentifier,
	Transaction, TxKernel, Weighting,
};
use mwc_core::libtx::build::{self, initial_tx, input, output, with_excess};
use mwc_core::libtx::{aggsig, ProofBuilder};
use mwc_core::{global, ser};
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use std::convert::TryInto;

// Setup test with AutomatedTesting chain_type;
fn test_setup() {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
}

#[test]
fn simple_tx_ser() {
	test_setup();
	let tx = tx2i1o();

	// Default protocol version (3).
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &tx).expect("serialization failed");
	assert_eq!(vec.len(), 945);

	// Explicit protocol version 3.
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(3), 0, &tx).expect("serialization failed");
	assert_eq!(vec.len(), 945);

	// We need to convert the tx to v2 compatibility with "features and commitment" inputs
	// to serialize to any previous protocol version.
	// Normally we would do this conversion against the utxo and txpool but we fake it here for testing.
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
	let tx = Transaction {
		body: tx
			.body
			.replace_inputs(
				0,
				Inputs::from_output_identifiers(0, inputs.as_slice()).unwrap(),
			)
			.unwrap(),
		..tx
	};

	// Explicit protocol version 1.
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(1), 0, &tx).expect("serialization failed");
	assert_eq!(vec.len(), 955);

	// Explicit protocol version 2.
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(2), 0, &tx).expect("serialization failed");
	assert_eq!(vec.len(), 947);

	// Check we can still serialize to protocol version 3 without explicitly converting the tx.
	let mut vec = Vec::new();
	ser::serialize(&mut vec, ser::ProtocolVersion(3), 0, &tx).expect("serialization failed");
	assert_eq!(vec.len(), 945);

	// And default protocol version for completeness.
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &tx).expect("serialization failed");
	assert_eq!(vec.len(), 945);
}

#[test]
fn simple_tx_ser_deser() {
	test_setup();
	let tx = tx2i1o();
	let mut vec = Vec::new();
	ser::serialize_default(0, &mut vec, &tx).expect("serialization failed");
	let dtx: Transaction = ser::deserialize_default(0, &mut &vec[..]).unwrap();
	assert_eq!(dtx.fee().unwrap(), 2);
	assert_eq!(dtx.inputs().len(), 2);
	assert_eq!(dtx.outputs().len(), 1);
	assert_eq!(tx.hash(0).unwrap(), dtx.hash(0).unwrap());
}

#[test]
fn tx_double_ser_deser() {
	test_setup();
	// checks serializing doesn't mess up the tx and produces consistent results
	let btx = tx2i1o();

	let mut vec = Vec::new();
	assert!(ser::serialize_default(0, &mut vec, &btx).is_ok());
	let dtx: Transaction = ser::deserialize_default(0, &mut &vec[..]).unwrap();

	let mut vec2 = Vec::new();
	assert!(ser::serialize_default(0, &mut vec2, &btx).is_ok());
	let dtx2: Transaction = ser::deserialize_default(0, &mut &vec2[..]).unwrap();

	assert_eq!(btx.hash(0).unwrap(), dtx.hash(0).unwrap());
	assert_eq!(dtx.hash(0).unwrap(), dtx2.hash(0).unwrap());
}

#[test]
fn test_zero_commit_fails() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

	// blinding should be ok because zero sum currently is acceptable
	let res = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 1u64.try_into().unwrap(),
		},
		&[input(10, key_id1.clone()), output(10, key_id1)],
		&keychain,
		&builder,
	);
	assert!(res.is_err());
}

#[test]
fn build_tx_kernel() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	// first build a valid tx with corresponding blinding factor
	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap(),
		},
		&[input(10, key_id1), output(5, key_id2), output(3, key_id3)],
		&keychain,
		&builder,
	)
	.unwrap();

	// check the tx is valid
	tx.validate(0, Weighting::AsTransaction, &mut secp).unwrap();

	// check the kernel is also itself valid
	assert_eq!(tx.kernels().len(), 1);
	let kern = &tx.kernels()[0];
	kern.verify(0, &secp).unwrap();

	assert_eq!(
		kern.features,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap()
		}
	);
	assert_eq!(2, tx.fee().unwrap());
}

// Proof of concept demonstrating we can build two transactions that share
// the *same* kernel public excess. This is a key part of building a transaction as two
// "halves" for NRD kernels.
// Note: In a real world scenario multiple participants would build the kernel signature
// using signature aggregation. No party would see the full private kernel excess and
// the halves would need to be constructed with carefully crafted individual offsets to
// adjust the excess as required.
// For the sake of convenience we are simply constructing the kernel directly and we have access
// to the full private excess.
#[test]
fn build_two_half_kernels() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	// build kernel with associated private excess
	let mut kernel = TxKernel::with_features(KernelFeatures::Plain {
		fee: 2u32.try_into().unwrap(),
	})
	.unwrap();

	// Construct the message to be signed.
	let msg = kernel.msg_to_sign(0).unwrap();

	// Generate a kernel with public excess and associated signature.
	let excess = BlindingFactor::rand(&secp).unwrap();
	let skey = excess.secret_key(&secp).unwrap();
	kernel.excess = secp.commit(0, skey).unwrap();
	let pubkey = &kernel.excess.to_pubkey(&secp).unwrap();
	kernel.excess_sig = aggsig::sign_with_blinding(&secp, &msg, &excess, &pubkey).unwrap();
	kernel.verify(0, &secp).unwrap();

	let tx1 = build::transaction_with_kernel(
		0,
		&mut secp,
		&[input(10, key_id1), output(8, key_id2.clone())],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	let tx2 = build::transaction_with_kernel(
		0,
		&mut secp,
		&[input(8, key_id2), output(6, key_id3)],
		kernel.clone(),
		excess.clone(),
		&keychain,
		&builder,
	)
	.unwrap();

	assert!(tx1.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	assert!(tx2.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	// The transactions share an identical kernel.
	assert!(ser::hashes_equal(0, &tx1.kernels()[0], &tx2.kernels()[0]).unwrap());

	// The public kernel excess is shared between both "halves".
	assert_eq!(tx1.kernels()[0].excess(), tx2.kernels()[0].excess());

	// Each transaction is built from different inputs and outputs.
	// The offset differs to compensate for the shared excess commitments.
	assert!(tx1.offset != tx2.offset);

	// For completeness, these are different transactions.
	assert!(tx1.hash(0).unwrap() != tx2.hash(0).unwrap());
}

// Combine two transactions into one big transaction (with multiple kernels)
// and check it still validates.
#[test]
fn transaction_cut_through() {
	test_setup();
	let tx1 = tx1i2o();
	let tx2 = tx2i1o();

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	assert!(tx1.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx2.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	// now build a "cut_through" tx from tx1 and tx2
	let tx3 = aggregate(0, &[tx1, tx2], &secp).unwrap();

	assert!(tx3.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
}

// Attempt to deaggregate a multi-kernel transaction in a different way
#[test]
fn multi_kernel_transaction_deaggregation() {
	test_setup();
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();
	let tx4 = tx1i1o();

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	assert!(tx1.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx2.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx3.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx4.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	let tx1234 = aggregate(
		0,
		&[tx1.clone(), tx2.clone(), tx3.clone(), tx4.clone()],
		&secp,
	)
	.unwrap();
	let tx12 = aggregate(0, &[tx1, tx2], &secp).unwrap();
	let tx34 = aggregate(0, &[tx3, tx4], &secp).unwrap();

	assert!(tx1234
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx12
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx34
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());

	let deaggregated_tx34 = deaggregate(0, tx1234.clone(), &[tx12.clone()], &secp).unwrap();
	assert!(deaggregated_tx34
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx34.eq_by_hash(0, &deaggregated_tx34).unwrap());

	let deaggregated_tx12 = deaggregate(0, tx1234, &[tx34], &secp).unwrap();

	assert!(deaggregated_tx12
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx12.eq_by_hash(0, &deaggregated_tx12).unwrap());
}

#[test]
fn multi_kernel_transaction_deaggregation_2() {
	test_setup();
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	assert!(tx1.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx2.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx3.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	let tx123 = aggregate(0, &[tx1.clone(), tx2.clone(), tx3.clone()], &secp).unwrap();
	let tx12 = aggregate(0, &[tx1, tx2], &secp).unwrap();

	assert!(tx123
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx12
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());

	let deaggregated_tx3 = deaggregate(0, tx123, &[tx12], &secp).unwrap();
	assert!(deaggregated_tx3
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx3.eq_by_hash(0, &deaggregated_tx3).unwrap());
}

#[test]
fn multi_kernel_transaction_deaggregation_3() {
	test_setup();
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	assert!(tx1.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx2.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx3.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	let tx123 = aggregate(0, &[tx1.clone(), tx2.clone(), tx3.clone()], &secp).unwrap();
	let tx13 = aggregate(0, &[tx1, tx3], &secp).unwrap();
	let tx2 = aggregate(0, &[tx2], &secp).unwrap();

	assert!(tx123
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx2.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	let deaggregated_tx13 = deaggregate(0, tx123, &[tx2], &secp).unwrap();
	assert!(deaggregated_tx13
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx13.eq_by_hash(0, &deaggregated_tx13).unwrap());
}

#[test]
fn multi_kernel_transaction_deaggregation_4() {
	test_setup();
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();
	let tx4 = tx1i1o();
	let tx5 = tx1i1o();

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	assert!(tx1.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx2.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx3.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx4.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx5.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	let tx12345 = aggregate(
		0,
		&[
			tx1.clone(),
			tx2.clone(),
			tx3.clone(),
			tx4.clone(),
			tx5.clone(),
		],
		&secp,
	)
	.unwrap();
	assert!(tx12345
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());

	let deaggregated_tx5 = deaggregate(0, tx12345, &[tx1, tx2, tx3, tx4], &secp).unwrap();
	assert!(deaggregated_tx5
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx5.eq_by_hash(0, &deaggregated_tx5).unwrap());
}

#[test]
fn multi_kernel_transaction_deaggregation_5() {
	test_setup();
	let tx1 = tx1i1o();
	let tx2 = tx1i1o();
	let tx3 = tx1i1o();
	let tx4 = tx1i1o();
	let tx5 = tx1i1o();

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	assert!(tx1.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx2.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx3.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx4.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx5.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	let tx12345 = aggregate(
		0,
		&[
			tx1.clone(),
			tx2.clone(),
			tx3.clone(),
			tx4.clone(),
			tx5.clone(),
		],
		&secp,
	)
	.unwrap();
	let tx12 = aggregate(0, &[tx1, tx2], &secp).unwrap();
	let tx34 = aggregate(0, &[tx3, tx4], &secp).unwrap();

	assert!(tx12345
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());

	let deaggregated_tx5 = deaggregate(0, tx12345, &[tx12, tx34], &secp).unwrap();
	assert!(deaggregated_tx5
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx5.eq_by_hash(0, &deaggregated_tx5).unwrap());
}

// Attempt to deaggregate a multi-kernel transaction
#[test]
fn basic_transaction_deaggregation() {
	test_setup();
	let tx1 = tx1i2o();
	let tx2 = tx2i1o();

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	assert!(tx1.validate(0, Weighting::AsTransaction, &mut secp).is_ok());
	assert!(tx2.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	// now build a "cut_through" tx from tx1 and tx2
	let tx3 = aggregate(0, &[tx1.clone(), tx2.clone()], &secp).unwrap();

	assert!(tx3.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	let deaggregated_tx1 = deaggregate(0, tx3.clone(), &[tx2.clone()], &secp).unwrap();

	assert!(deaggregated_tx1
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx1.eq_by_hash(0, &deaggregated_tx1).unwrap());

	let deaggregated_tx2 = deaggregate(0, tx3, &[tx1], &secp).unwrap();

	assert!(deaggregated_tx2
		.validate(0, Weighting::AsTransaction, &mut secp)
		.is_ok());
	assert!(tx2.eq_by_hash(0, &deaggregated_tx2).unwrap());
}

#[test]
fn transaction_deaggregation_equal_nonzero_offsets_returns_zero_offset() {
	test_setup();
	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let offset = BlindingFactor::rand(&secp).unwrap();
	let tx = tx1i1o().with_offset(offset.clone());
	let mk_tx = aggregate(0, &[tx.clone()], &secp).unwrap();

	assert!(mk_tx.offset == offset);

	let deaggregated_tx = deaggregate(0, mk_tx, &[tx], &secp).unwrap();

	assert!(deaggregated_tx.offset == BlindingFactor::zero());
	assert!(deaggregated_tx.inputs().is_empty());
	assert!(deaggregated_tx.outputs().is_empty());
	assert!(deaggregated_tx.kernels().is_empty());
}

#[test]
fn hash_output() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 1u32.try_into().unwrap(),
		},
		&[input(75, key_id1), output(42, key_id2), output(32, key_id3)],
		&keychain,
		&builder,
	)
	.unwrap();
	let h = tx.outputs()[0].identifier.hash(0).unwrap();
	assert!(h != ZERO_HASH);
	let h2 = tx.outputs()[1].identifier.hash(0).unwrap();
	assert!(h != h2);
}

#[ignore]
#[test]
fn blind_tx() {
	let btx = tx2i1o();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	assert!(btx.validate(0, Weighting::AsTransaction, &mut secp).is_ok());

	// checks that the range proof on our blind output is sufficiently hiding
	let Output { proof, identifier } = btx.outputs()[0];

	let info = secp
		.verify_bullet_proof(identifier.commit, proof, None)
		.unwrap();

	assert!(info.min == 0);
	assert!(info.max == u64::max_value());
}

#[test]
fn tx_hash_diff() {
	test_setup();
	let btx1 = tx2i1o();
	let btx2 = tx1i1o();

	if btx1.hash(0).unwrap() == btx2.hash(0).unwrap() {
		panic!("diff txs have same hash")
	}
}

/// Simulate the standard exchange between 2 parties when creating a basic
/// 2 inputs, 2 outputs transaction.
#[test]
fn tx_build_exchange() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();
	let key_id4 = ExtKeychain::derive_key_id(1, 4, 0, 0, 0).unwrap();

	let (tx_alice, blind_sum) = {
		// Alice gets 2 of her pre-existing outputs to send 5 coins to Bob, they
		// become inputs in the new transaction
		let (in1, in2) = (input(4, key_id1), input(3, key_id2));

		// Alice builds her transaction, with change, which also produces the sum
		// of blinding factors before they're obscured.
		let tx = Transaction::empty();
		let (tx, sum) = build::partial_transaction(
			0,
			&mut secp,
			tx,
			&[in1, in2, output(1, key_id3)],
			&keychain,
			&builder,
		)
		.unwrap();

		(tx, sum)
	};

	// From now on, Bob only has the obscured transaction and the sum of
	// blinding factors. He adds his output, finalizes the transaction so it's
	// ready for broadcast.
	let tx_final = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u32.try_into().unwrap(),
		},
		&[
			initial_tx(tx_alice),
			with_excess(blind_sum),
			output(4, key_id4),
		],
		&keychain,
		&builder,
	)
	.unwrap();

	tx_final
		.validate(0, Weighting::AsTransaction, &mut secp)
		.unwrap();
}

#[test]
fn reward_empty_block() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

	let previous_header = BlockHeader::default(0);

	let b = new_block(&[], &keychain, &builder, &previous_header, &key_id);

	b.validate(0, &BlindingFactor::zero(), &mut secp).unwrap();
}

#[test]
fn reward_with_tx_block() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

	let tx1 = tx2i1o();
	let previous_header = BlockHeader::default(0);
	tx1.validate(0, Weighting::AsTransaction, &mut secp)
		.unwrap();

	let block = new_block(&[tx1], &keychain, &builder, &previous_header, &key_id);
	block
		.validate(0, &BlindingFactor::zero(), &mut secp)
		.unwrap();
}

#[test]
fn simple_block() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

	let tx1 = tx2i1o();
	let tx2 = tx1i1o();

	let previous_header = BlockHeader::default(0);
	let b = new_block(&[tx1, tx2], &keychain, &builder, &previous_header, &key_id);

	b.validate(0, &BlindingFactor::zero(), &mut secp).unwrap();
}

#[test]
fn test_block_with_timelocked_tx() {
	test_setup();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = keychain::ExtKeychain::from_seed(
		&secp,
		&SecretKey::new(&secp, &mut SysRng).unwrap().0,
		false,
	)
	.unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	// first check we can add a timelocked tx where lock height matches current
	// block height and that the resulting block is valid
	let tx1 = build::transaction(
		0,
		&mut secp,
		KernelFeatures::HeightLocked {
			fee: 2u32.try_into().unwrap(),
			lock_height: 1,
		},
		&[input(5, key_id1.clone()), output(3, key_id2.clone())],
		&keychain,
		&builder,
	)
	.unwrap();

	let previous_header = BlockHeader::default(0);

	let b = new_block(
		&[tx1],
		&keychain,
		&builder,
		&previous_header,
		&key_id3.clone(),
	);
	b.validate(0, &BlindingFactor::zero(), &mut secp).unwrap();

	// now try adding a timelocked tx where lock height is greater than current
	// block height
	let tx1 = build::transaction(
		0,
		&mut secp,
		KernelFeatures::HeightLocked {
			fee: 2u32.try_into().unwrap(),
			lock_height: 2,
		},
		&[input(5, key_id1), output(3, key_id2)],
		&keychain,
		&builder,
	)
	.unwrap();

	let previous_header = BlockHeader::default(0);
	let b = new_block(&[tx1], &keychain, &builder, &previous_header, &key_id3);

	match b.validate(0, &BlindingFactor::zero(), &mut secp) {
		Err(KernelLockHeight(height, _)) => {
			assert_eq!(height, 2);
		}
		_ => panic!("expecting KernelLockHeight error here"),
	}
}

#[test]
pub fn test_verify_1i1o_sig() {
	test_setup();
	let tx = tx1i1o();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	tx.validate(0, Weighting::AsTransaction, &mut secp).unwrap();
}

#[test]
pub fn test_verify_2i1o_sig() {
	test_setup();
	let tx = tx2i1o();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	tx.validate(0, Weighting::AsTransaction, &mut secp).unwrap();
}
