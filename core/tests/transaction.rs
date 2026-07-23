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

//! Transaction integration tests

pub mod common;
use crate::common::build;
use crate::common::tx1i10_v2_compatible;
use keychain::{ExtKeychain, Keychain};
use mwc_core::core::hash::Hashed;
use mwc_core::core::transaction::{self, Error};
use mwc_core::core::{
	CommitWrapper, FeeFields, Input, Inputs, KernelFeatures, NRDRelativeHeight, Output,
	OutputFeatures, OutputIdentifier, Transaction, TransactionBody, TxKernel, Weighting,
};
use mwc_core::global;
use mwc_core::libtx::proof::{self, ProofBuilder};
use mwc_core::libtx::tx_fee;
use mwc_core::{consensus, ser};
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::constants::{MAX_PROOF_SIZE, PEDERSEN_COMMITMENT_SIZE};
use mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_crates::serde_json;
use std::convert::{TryFrom, TryInto};

// We use json serialization between wallet->node when pushing transactions to the network.
// This test ensures we exercise this serialization/deserialization code.
#[test]
fn test_transaction_json_ser_deser() {
	let tx1 = tx1i10_v2_compatible();

	let value = serde_json::to_value(&tx1).unwrap();
	println!("{:?}", value);

	assert!(value["offset"].is_string());
	assert_eq!(value["body"]["inputs"][0]["features"], "Plain");
	assert!(value["body"]["inputs"][0]["commit"].is_string());
	assert_eq!(value["body"]["outputs"][0]["features"], "Plain");
	assert!(value["body"]["outputs"][0]["commit"].is_string());
	assert!(value["body"]["outputs"][0]["proof"].is_string());

	// Note: Tx kernel "features" serialize in a slightly unexpected way.
	assert_eq!(value["body"]["kernels"][0]["features"]["Plain"]["fee"], 2);
	assert!(value["body"]["kernels"][0]["excess"].is_string());
	let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly).unwrap();
	let compact_sig = tx1.kernels()[0]
		.excess_sig
		.serialize_compact(&secp)
		.unwrap();
	assert_eq!(
		value["body"]["kernels"][0]["excess_sig"].as_str().unwrap(),
		util::to_hex(&compact_sig)
	);

	let mut invalid_value = value.clone();
	invalid_value["body"]["kernels"][0]["features"]["Plain"]["fee"] = 0.into();
	let res: Result<Transaction, _> = serde_json::from_value(invalid_value);
	assert!(res.is_err());
	assert!(res.unwrap_err().to_string().contains("fee is zero"));

	let tx2: Transaction = serde_json::from_value(value).unwrap();
	assert!(tx1.eq_by_hash(0, &tx2).unwrap());

	let str = serde_json::to_string(&tx1).unwrap();
	println!("{}", str);
	let tx2: Transaction = serde_json::from_str(&str).unwrap();
	assert!(tx1.eq_by_hash(0, &tx2).unwrap());
}

#[test]
fn kernel_features_json_rejects_invalid_fee_fields() {
	let zero_fee = r#"{"Plain":{"fee":0}}"#;
	let res: Result<KernelFeatures, _> = serde_json::from_str(zero_fee);
	assert!(res.is_err());
	assert!(res.unwrap_err().to_string().contains("fee is zero"));

	let over_mask_fee = format!(r#"{{"Plain":{{"fee":{}}}}}"#, 1u64 << 40);
	let res: Result<KernelFeatures, _> = serde_json::from_str(&over_mask_fee);
	assert!(res.is_err());
	assert!(res
		.unwrap_err()
		.to_string()
		.contains("fee 1099511627776 is too high"));
}

#[test]
fn kernel_features_json_rejects_invalid_nrd_relative_height() {
	let zero_height = r#"{"NoRecentDuplicate":{"fee":10,"relative_height":0}}"#;
	let res: Result<KernelFeatures, _> = serde_json::from_str(zero_height);
	assert!(res.is_err());
	assert!(res
		.unwrap_err()
		.to_string()
		.contains("Invalid NRD kernel relative height"));

	let over_week_height = format!(
		r#"{{"NoRecentDuplicate":{{"fee":10,"relative_height":{}}}}}"#,
		consensus::WEEK_HEIGHT + 1
	);
	let res: Result<KernelFeatures, _> = serde_json::from_str(&over_week_height);
	assert!(res.is_err());
	assert!(res
		.unwrap_err()
		.to_string()
		.contains("Invalid NRD kernel relative height"));

	let features: KernelFeatures =
		serde_json::from_str(r#"{"NoRecentDuplicate":{"fee":10,"relative_height":1}}"#).unwrap();
	assert_eq!(
		features,
		KernelFeatures::NoRecentDuplicate {
			fee: 10u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(1).unwrap()
		}
	);

	let value = serde_json::to_value(&features).unwrap();
	assert_eq!(
		value["NoRecentDuplicate"]["relative_height"].as_u64(),
		Some(1)
	);
}

#[test]
fn transaction_validate_read_rejects_nrd_when_disabled() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);
	global::set_local_nrd_enabled(false);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)?;
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0)?;
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0)?;

	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::NoRecentDuplicate {
			fee: 10u32.try_into().unwrap(),
			relative_height: NRDRelativeHeight::new(1).unwrap(),
		},
		&[build::input(12, key_id1), build::output(2, key_id2)],
		&keychain,
		&builder,
	)
	.unwrap();

	assert!(matches!(
		tx.validate_read(0),
		Err(Error::NRDKernelNotEnabled)
	));
	assert!(matches!(
		tx.validate(0, Weighting::AsTransaction, &mut secp),
		Err(Error::NRDKernelNotEnabled)
	));

	Ok(())
}

#[test]
fn tx_kernel_fallible_hash_rejects_invalid_kernel() {
	let kernel = TxKernel::empty().unwrap();
	let err = kernel.hash(0).unwrap_err();

	assert!(err.to_string().contains("fee is zero"));
}

#[test]
fn transaction_body_with_output_rejects_duplicate_output_identifier() {
	let tx = tx1i10_v2_compatible();
	let output = tx.outputs()[0].clone();

	let body = TransactionBody::empty()
		.with_output(0, output.clone())
		.unwrap();
	let err = body.with_output(0, output).unwrap_err();

	assert!(matches!(err, Error::DuplicateOutput));
}

#[test]
fn transaction_body_with_commit_input_rejects_duplicate_input_identifier() {
	let tx = tx1i10_v2_compatible();
	let commit = match tx.inputs() {
		Inputs::FeaturesAndCommit(inputs) => inputs[0].commitment(),
		Inputs::CommitOnly(_) => panic!("expected feature-preserving inputs"),
	};

	let body = TransactionBody::empty()
		.with_commit_input(0, commit)
		.unwrap();
	let err = body.with_commit_input(0, commit).unwrap_err();

	assert!(matches!(err, Error::DuplicateInput));
}

#[test]
fn transaction_body_with_input_rejects_commit_only_lossy_conversion() {
	let tx = tx1i10_v2_compatible();
	let input = match tx.inputs() {
		Inputs::FeaturesAndCommit(inputs) => inputs[0].clone(),
		Inputs::CommitOnly(_) => panic!("expected feature-preserving inputs"),
	};

	let err = TransactionBody::empty().with_input(0, input).unwrap_err();

	assert!(matches!(err, Error::Generic(msg) if msg.contains("with_commit_input")));
}

#[test]
fn commit_wrapper_from_input_commitment_only_is_explicit() {
	let tx = tx1i10_v2_compatible();
	let input = match tx.inputs() {
		Inputs::FeaturesAndCommit(inputs) => inputs[0].clone(),
		Inputs::CommitOnly(_) => panic!("expected feature-preserving inputs"),
	};

	let commit = CommitWrapper::from_input_commitment_only(&input);

	assert_eq!(commit.commitment(), input.commitment());
}

#[test]
fn commit_wrapper_write_rejects_invalid_commitment() {
	let invalid_commit = Commitment::from_vec(vec![0; PEDERSEN_COMMITMENT_SIZE]).unwrap();
	let input = CommitWrapper::from(invalid_commit);
	let mut bytes = vec![];

	let err = ser::serialize_default(0, &mut bytes, &input).unwrap_err();
	assert!(err
		.to_string()
		.contains("Unable to write Pedersen commitment"));

	let err = input.hash(0).unwrap_err();
	assert!(err
		.to_string()
		.contains("Unable to write Pedersen commitment"));
}

#[test]
fn input_write_rejects_invalid_commitment() {
	let invalid_commit = Commitment::from_vec(vec![0; PEDERSEN_COMMITMENT_SIZE]).unwrap();
	let input = Input::new(OutputFeatures::Plain, invalid_commit);
	let mut bytes = vec![];

	let err = ser::serialize_default(0, &mut bytes, &input).unwrap_err();
	assert!(err
		.to_string()
		.contains("Unable to write Pedersen commitment"));

	let err = input.hash(0).unwrap_err();
	assert!(err
		.to_string()
		.contains("Unable to write Pedersen commitment"));

	let lhs = Inputs::FeaturesAndCommit(vec![input]);
	let rhs = Inputs::FeaturesAndCommit(vec![input]);
	let err = lhs.eq_by_hash(0, &rhs).unwrap_err();
	assert!(err
		.to_string()
		.contains("Unable to write Pedersen commitment"));
}

#[test]
fn output_identifier_write_rejects_invalid_commitment() {
	let invalid_commit = Commitment::from_vec(vec![0; PEDERSEN_COMMITMENT_SIZE]).unwrap();
	let identifier = OutputIdentifier {
		features: OutputFeatures::Plain,
		commit: invalid_commit,
	};
	let mut bytes = vec![];

	let err = ser::serialize_default(0, &mut bytes, &identifier).unwrap_err();
	assert!(err
		.to_string()
		.contains("Unable to write Pedersen commitment"));

	let err = identifier.hash(0).unwrap_err();
	assert!(err
		.to_string()
		.contains("Unable to write Pedersen commitment"));

	let output = identifier.into_output(RangeProof {
		plen: 0,
		proof: [0; MAX_PROOF_SIZE],
	});
	let err = ser::serialize_default(0, &mut bytes, &output).unwrap_err();
	assert!(err
		.to_string()
		.contains("Unable to write Pedersen commitment"));
}

#[test]
fn transaction_body_with_kernel_rejects_duplicate_kernel_identifier() {
	let tx = tx1i10_v2_compatible();
	let kernel = tx.kernels()[0];

	let body = TransactionBody::empty().with_kernel(0, kernel).unwrap();
	let err = body.with_kernel(0, kernel).unwrap_err();

	assert!(matches!(err, Error::DuplicateKernel));
}

#[test]
fn inputs_for_fee_points_rejects_zero_fee_points() {
	let res = Transaction::inputs_for_fee_points(0, 1, 1);

	assert!(matches!(
		res,
		Err(Error::Generic(msg)) if msg.contains("fee_points=0")
	));
}

// test transaction equal
#[test]
fn test_transaction_equal() {
	let tx1 = tx1i10_v2_compatible();
	let tx2 = tx1.clone();
	assert_eq!(tx1.offset, tx2.offset);
	assert!(tx1.body.eq_by_hash(0, &tx2.body).unwrap());
	assert!(tx1.eq_by_hash(0, &tx2).unwrap());
}

#[test]
fn test_output_ser_deser() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
			.unwrap();
	let key_id = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let switch = keychain::SwitchCommitmentType::Regular;
	let commit = keychain.commit(&secp, 5, &key_id, switch).unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let proof = proof::create(
		&mut secp, &keychain, &builder, 5, &key_id, switch, commit, None,
	)
	.unwrap();

	let out = Output::new(OutputFeatures::Plain, commit, proof);

	let mut vec = vec![];
	ser::serialize_default(0, &mut vec, &out).expect("serialized failed");
	let dout: Output = ser::deserialize_default(0, &mut &vec[..]).unwrap();

	assert_eq!(dout.features(), OutputFeatures::Plain);
	assert_eq!(dout.commitment(), out.commitment());
	assert_eq!(dout.proof, out.proof);
}

#[test]
fn output_proof_bytes_returns_canonical_proof_length() {
	let commit = Commitment::from_vec(vec![0; PEDERSEN_COMMITMENT_SIZE]).unwrap();
	let mut proof = [0; MAX_PROOF_SIZE];
	proof[..3].copy_from_slice(&[1, 2, 3]);
	proof[3] = 4;
	let output = Output::new(OutputFeatures::Plain, commit, RangeProof { plen: 3, proof });

	assert_eq!(output.proof_bytes().unwrap(), &[1, 2, 3]);
}

#[test]
fn output_proof_bytes_rejects_oversized_public_length() {
	let commit = Commitment::from_vec(vec![0; PEDERSEN_COMMITMENT_SIZE]).unwrap();
	let output = Output::new(
		OutputFeatures::Plain,
		commit,
		RangeProof {
			plen: MAX_PROOF_SIZE + 1,
			proof: [0; MAX_PROOF_SIZE],
		},
	);

	assert!(output.proof_bytes().is_err());
}

#[test]
fn output_json_ser_rejects_oversized_rangeproof_without_panic() {
	let commit = Commitment::from_vec(vec![0; PEDERSEN_COMMITMENT_SIZE]).unwrap();
	let output = Output::new(
		OutputFeatures::Plain,
		commit,
		RangeProof {
			plen: MAX_PROOF_SIZE + 1,
			proof: [0; MAX_PROOF_SIZE],
		},
	);

	let res = serde_json::to_string(&output);

	assert!(res.is_err());
}

#[test]
fn rangeproof_write_rejects_oversized_public_length() {
	let proof = RangeProof {
		plen: MAX_PROOF_SIZE + 1,
		proof: [0; MAX_PROOF_SIZE],
	};

	let mut vec = vec![];
	let err = ser::serialize_default(0, &mut vec, &proof).unwrap_err();
	assert!(matches!(err, ser::Error::TooLargeWriteErr(_)));
}

// Test coverage for verifying cut-through during transaction validation.
// It is not valid for a transaction to spend an output and produce a new output with the same commitment.
// This test covers the case where a plain output is spent, producing a plain output with the same commitment.
#[test]
fn test_verify_cut_through_plain() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);
	global::set_local_nrd_enabled(false);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)?;

	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	let builder = proof::ProofBuilder::new(&secp, &keychain).unwrap();

	let mut tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 1u32.try_into().unwrap(),
		},
		&[
			build::input(10, key_id1.clone()),
			build::input(10, key_id2.clone()),
			build::output(10, key_id1.clone()),
			build::output(6, key_id2.clone()),
			build::output(3, key_id3.clone()),
		],
		&keychain,
		&builder,
	)
	.expect("valid tx");

	// Transaction should fail validation due to cut-through.
	assert!(matches!(
		tx.validate(0, Weighting::AsTransaction, &mut secp),
		Err(Error::CutThrough)
	));

	// Transaction should fail lightweight "read" validation due to cut-through.
	assert!(matches!(tx.validate_read(0), Err(Error::CutThrough)));

	// Apply cut-through to eliminate the offending input and output.
	let mut inputs = tx.inputs().into_commit_wrappers(0)?;
	let mut outputs = tx.outputs().to_vec();
	let (inputs, outputs, _, _) = transaction::cut_through(0, &mut inputs[..], &mut outputs[..])?;

	tx.body = tx
		.body
		.replace_inputs(0, inputs.into())
		.unwrap()
		.replace_outputs(0, outputs)
		.unwrap();

	// Transaction validates successfully after applying cut-through.
	tx.validate(0, Weighting::AsTransaction, &mut secp)?;

	// Transaction validates via lightweight "read" validation as well.
	tx.validate_read(0)?;

	Ok(())
}

// Test coverage for verifying cut-through during transaction validation.
// It is not valid for a transaction to spend an output and produce a new output with the same commitment.
// This test covers the case where a coinbase output is spent, producing a plain output with the same commitment.
#[test]
fn test_verify_cut_through_coinbase() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);
	global::set_local_nrd_enabled(false);

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)?;

	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();
	let key_id2 = ExtKeychain::derive_key_id(1, 2, 0, 0, 0).unwrap();
	let key_id3 = ExtKeychain::derive_key_id(1, 3, 0, 0, 0).unwrap();

	let builder = ProofBuilder::new(&secp, &keychain).unwrap();

	let mut tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 1u32.try_into().unwrap(),
		},
		&[
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::coinbase_input(consensus::MWC_FIRST_GROUP_REWARD, key_id2.clone()),
			build::output(consensus::MWC_FIRST_GROUP_REWARD, key_id1.clone()),
			build::output(
				consensus::MWC_FIRST_GROUP_REWARD - 100_000_001,
				key_id2.clone(),
			),
			build::output(100_000_000, key_id3.clone()),
		],
		&keychain,
		&builder,
	)
	.expect("valid tx");

	// Transaction should fail validation due to cut-through.
	assert!(matches!(
		tx.validate(0, Weighting::AsTransaction, &mut secp),
		Err(Error::CutThrough)
	));

	// Transaction should fail lightweight "read" validation due to cut-through.
	assert!(matches!(tx.validate_read(0), Err(Error::CutThrough)));

	// Apply cut-through to eliminate the offending input and output.
	let mut inputs = tx.inputs().into_commit_wrappers(0)?;
	let mut outputs = tx.outputs().to_vec();
	let (inputs, outputs, _, _) = transaction::cut_through(0, &mut inputs[..], &mut outputs[..])?;

	tx.body = tx
		.body
		.replace_inputs(0, inputs.into())
		.unwrap()
		.replace_outputs(0, outputs)
		.unwrap();

	// Transaction validates successfully after applying cut-through.
	tx.validate(0, Weighting::AsTransaction, &mut secp)?;

	// Transaction validates via lightweight "read" validation as well.
	tx.validate_read(0)?;

	Ok(())
}

// Test coverage for FeeFields
#[test]
fn test_fee_fields() -> Result<(), Error> {
	global::set_local_chain_type(global::ChainTypes::UserTesting);
	global::set_local_nrd_enabled(false);

	assert!(matches!(
		FeeFields::try_from(0u32),
		Err(Error::InvalidFeeFields(msg)) if msg == "fee is zero"
	));
	assert_eq!(FeeFields::try_from(42u32)?.fee(), 42);

	let fee_json = serde_json::to_value(FeeFields::new(42).unwrap()).unwrap();
	assert_eq!(fee_json.as_u64(), Some(42));
	let fee_from_json: FeeFields = serde_json::from_value(fee_json).unwrap();
	assert_eq!(fee_from_json.fee(), 42);
	assert!(serde_json::to_value(FeeFields::zero()).is_err());

	let local_base_fee = 500_000;
	global::set_local_accept_fee_base(local_base_fee).unwrap();

	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain =
		ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)?;

	let key_id1 = ExtKeychain::derive_key_id(1, 1, 0, 0, 0).unwrap();

	let builder = ProofBuilder::new(&secp, &keychain).unwrap();

	let mut tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: FeeFields::new(42).unwrap(),
		},
		&[
			build::coinbase_input(consensus::calc_mwc_block_reward(0, 1), key_id1.clone()),
			build::output(60_000_000_000 - 84 - 42 - 21, key_id1.clone()),
		],
		&keychain,
		&builder,
	)
	.expect("valid tx");

	assert_eq!(tx.accept_fee(0).unwrap(), (1 * 4 + 1 * 1 - 1 * 1) * 500_000);
	assert_eq!(tx.fee().unwrap(), 42);
	assert_eq!(tx.accept_fee(0).unwrap(), (1 * 4 + 1 * 1 - 1 * 1) * 500_000);
	assert_eq!(tx.fee().unwrap(), 42);

	tx.body.kernels.append(&mut vec![
		TxKernel::with_features(KernelFeatures::Plain {
			fee: FeeFields::new(84).unwrap(),
		})?,
		TxKernel::with_features(KernelFeatures::Plain {
			fee: 21u32.try_into().unwrap(),
		})?,
	]);

	assert_eq!(tx.fee().unwrap(), 42 + 84 + 21); // 42+84+21 = 147
	assert_eq!(
		tx_fee(0, 1, 1, 3).unwrap(),
		(1 * 4 + 3 - 1) * local_base_fee
	);

	Ok(())
}
