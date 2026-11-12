mod common;

use keychain::{BlindingFactor, ExtKeychain, Keychain, SwitchCommitmentType};
use mwc_core::core::hash::Hashed;
use mwc_core::core::id::ShortIdentifiable;
use mwc_core::core::transaction::Weighting;
use mwc_core::core::{Block, BlockHeader, CompactBlock, KernelFeatures, OutputFeatures};
use mwc_core::global;
use mwc_core::libtx::{build, ProofBuilder};
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};

#[test]
fn valid_proof_variant_passes_compact_prevalidation_with_different_body() {
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let keychain = ExtKeychain::from_seed(&secp, &[42; 32], false).unwrap();
	let builder = ProofBuilder::new(&secp, &keychain).unwrap();
	let input_id = ExtKeychain::derive_key_id(3, 0, 0, 1, 0).unwrap();
	let output_id = ExtKeychain::derive_key_id(3, 0, 0, 2, 0).unwrap();
	let tx = build::transaction(
		0,
		&mut secp,
		KernelFeatures::Plain {
			fee: 2u64.try_into().unwrap(),
		},
		&[
			build::feature_input(5, OutputFeatures::Plain, input_id),
			build::height_tagged_output(3, output_id.clone(), 1),
		],
		&keychain,
		&builder,
	)
	.unwrap();
	tx.validate(0, Weighting::AsTransaction, &mut secp).unwrap();
	let mut variant = tx.clone();
	let blind = keychain
		.derive_key(&secp, 3, &output_id, SwitchCommitmentType::Regular)
		.unwrap();
	let rewind_nonce = SecretKey::from_slice(&secp, &[17; 32]).unwrap();
	let private_nonce = SecretKey::from_slice(&secp, &[18; 32]).unwrap();
	variant.body.outputs[0].proof = secp
		.bullet_proof(3, blind, rewind_nonce, private_nonce, None, None)
		.unwrap();
	variant
		.validate(0, Weighting::AsTransaction, &mut secp)
		.unwrap();
	assert_ne!(
		tx.outputs()[0].proof.hash(0).unwrap(),
		variant.outputs()[0].proof.hash(0).unwrap()
	);
	assert_eq!(
		tx.kernels()[0].hash(0).unwrap(),
		variant.kernels()[0].hash(0).unwrap()
	);

	let prev = BlockHeader::default(0);
	let coinbase_id = ExtKeychain::derive_key_id(3, 0, 0, 3, 0).unwrap();
	let block = common::new_block(&[tx], &keychain, &builder, &prev, &coinbase_id);
	block
		.validate(0, &BlindingFactor::zero(), &mut secp)
		.unwrap();
	let compact = CompactBlock::from(block.clone()).unwrap();
	let local_short_id = variant.kernels()[0]
		.short_id(0, &compact.hash(0).unwrap(), compact.nonce)
		.unwrap();
	assert_eq!(
		compact.kern_ids()[0].hash(0).unwrap(),
		local_short_id.hash(0).unwrap()
	);
	let hydrated = Block::hydrate_from(compact, &[variant]).unwrap();
	hydrated
		.validate(0, &prev.total_kernel_offset, &mut secp)
		.unwrap();
	assert_eq!(block.header, hydrated.header);
	let original_proof_hashes: Vec<_> = block
		.outputs()
		.iter()
		.map(|o| o.proof.hash(0).unwrap())
		.collect();
	let hydrated_proof_hashes: Vec<_> = hydrated
		.outputs()
		.iter()
		.map(|o| o.proof.hash(0).unwrap())
		.collect();
	assert_ne!(original_proof_hashes, hydrated_proof_hashes);
}
