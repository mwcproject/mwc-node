// Copyright 2026 The MWC Developers
// Licensed under the Apache License, Version 2.0.

//! Coinbase kernel S2C binding to resolved inputs and the parent UTXO bitmap.
//!
//! All integers in the consensus hash preimages use fixed-width big-endian encoding.
//! Input positions are ONE-based PMMR positions, not zero-based output leaf indexes.
//! The kernel remains an ordinary valid AggSig signature. Its public S2C opening
//! authenticates the digest without changing the Coinbase rangeproof or wallet recovery.
//! Existing coinbase balance and rangeproof checks remain required.

use crate::core::hash::Hash;
use crate::core::{pmmr, OutputIdentifier, TxKernel};
use crate::libtx::Error;
use mwc_crates::blake2_rfc::blake2b::Blake2b;
use mwc_crates::secp::s2c::Opening;
use mwc_crates::secp::{self, Secp256k1};
use std::collections::BTreeSet;

const INPUT_DOMAIN: &[u8] = b"MWC_CB_BIND_INPUTS_V1";
const BITMAP_DOMAIN: &[u8] = b"MWC_CB_BIND_BITMAP_V1";
// V3 uses a streamed bitmap hash for the state before applying the candidate block.
const CONTEXT_DOMAIN: &[u8] = b"MWC_CB_BIND_CONTEXT_V3";
/// Public data sufficient to recompute a block's binding digest.
///
/// The node derives these fields from validated branch state. Only the digest
/// is sent to the reward wallet; the complete context is not serialized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaseBindingContext {
	/// Actual network genesis block hash.
	pub genesis_hash: Hash,
	/// Parent block hash.
	pub prev_hash: Hash,
	/// Height of the block containing the coinbase.
	pub height: u64,
	/// Canonical digest of the resolved and sorted input records.
	pub input_hash: Hash,
	/// Canonical hash of the parent's full unspent-output bitmap, before this block.
	pub bitmap_hash: Hash,
	/// Parent output leaf count, including spent and unspent historical outputs.
	pub output_leaf_count: u64,
	/// Expected coinbase amount: block subsidy PLUS transaction fees.
	pub reward: u64,
}

impl CoinbaseBindingContext {
	/// Hash the V3 context encoding, binding the exact inputs and parent state.
	/// The parent bitmap and leaf count exclude every output of this block.
	pub fn digest(&self) -> Result<Hash, Error> {
		if self.height == 0 {
			return Err(Error::Other(
				"coinbase binding requires a non-genesis block".into(),
			));
		}
		let mut hash = Blake2b::new(32);
		hash.update(CONTEXT_DOMAIN);
		hash.update(self.genesis_hash.as_bytes());
		hash.update(self.prev_hash.as_bytes());
		hash.update(&self.height.to_be_bytes());
		hash.update(self.input_hash.as_bytes());
		hash.update(self.bitmap_hash.as_bytes());
		hash.update(&self.output_leaf_count.to_be_bytes());
		hash.update(&self.reward.to_be_bytes());
		Ok(Hash::from_vec(hash.finalize().as_bytes()))
	}
}

/// Hash the parent bitmap from its strictly increasing, zero-based unspent leaf indexes.
///
/// Preimage: BITMAP_DOMAIN || output_leaf_count:u64be || packed_bitmap_bytes.
/// Index zero is the high bit of the first byte. The payload contains exactly
/// ceil(output_leaf_count / 8) bytes, including zero gaps and trailing zero bytes;
/// unused low bits in the final byte are zero. The length includes spent leaves.
/// A fixed buffer streams the encoding without constructing a bitmap or Merkle tree.
pub fn unspent_bitmap_hash<I>(indices: I, output_leaf_count: u64) -> Result<Hash, pmmr::Error>
where
	I: IntoIterator<Item = Result<u64, pmmr::Error>>,
{
	let mut hash = Blake2b::new(32);
	hash.update(BITMAP_DOMAIN);
	hash.update(&output_leaf_count.to_be_bytes());
	// Dividing before rounding up also supports lengths near u64::MAX.
	let byte_count = output_leaf_count / 8 + u64::from(output_leaf_count % 8 != 0);
	let mut buffer = [0u8; 128];
	let mut bytes_hashed = 0u64;
	let mut previous: Option<u64> = None;

	for index in indices {
		let index = index?;
		if index >= output_leaf_count {
			return Err(pmmr::Error::DataCorruption(format!(
				"bitmap leaf index {} outside output leaf count {}",
				index, output_leaf_count
			)));
		}
		if let Some(prev) = previous {
			if index <= prev {
				return Err(pmmr::Error::DataCorruption(format!(
					"bitmap leaf indexes are not strictly increasing: {} after {}",
					index, prev
				)));
			}
		}
		previous = Some(index);

		let byte_index = index / 8;
		// Ascending indexes keep byte_index >= bytes_hashed. This condition
		// also keeps the increment bounded by byte_index, so it cannot overflow.
		while byte_index - bytes_hashed >= buffer.len() as u64 {
			hash.update(&buffer);
			buffer.fill(0);
			bytes_hashed += buffer.len() as u64;
		}
		buffer[(byte_index - bytes_hashed) as usize] |= 0x80 >> (index % 8);
	}

	// Include every zero byte through the declared length, even for an empty
	// live set. Do not pad the final payload to the scratch buffer's size.
	let mut remaining = byte_count - bytes_hashed;
	while remaining >= buffer.len() as u64 {
		hash.update(&buffer);
		buffer.fill(0);
		remaining -= buffer.len() as u64;
	}
	hash.update(&buffer[..remaining as usize]);
	Ok(Hash::from_vec(hash.finalize().as_bytes()))
}

/// Hash input records sorted by ascending one-based PMMR position.
///
/// Preimage: INPUT_DOMAIN || count:u64be || (pos:u64be || features:u8 || C:33)*.
/// The caller must still resolve these records against the parent branch state.
pub fn canonical_input_hash(inputs: &[(u64, OutputIdentifier)]) -> Result<Hash, Error> {
	let mut ordered = inputs.iter().collect::<Vec<_>>();
	ordered.sort_unstable_by_key(|input| input.0);
	let count = u64::try_from(ordered.len())
		.map_err(|_| Error::DataOverflow("binding input count".into()))?;
	let mut hash = Blake2b::new(32);
	hash.update(INPUT_DOMAIN);
	hash.update(&count.to_be_bytes());
	let mut previous = None;
	let mut commitments = BTreeSet::new();
	for (position, output) in ordered {
		if *position == 0 || !pmmr::is_leaf(*position - 1) {
			return Err(Error::Other(
				"binding input position is not a one-based PMMR leaf".into(),
			));
		}
		if previous == Some(*position) || !commitments.insert(output.commit.0) {
			return Err(Error::Other(
				"duplicate binding input position or commitment".into(),
			));
		}
		previous = Some(*position);
		hash.update(&position.to_be_bytes());
		hash.update(&[output.features as u8]);
		hash.update(&output.commit.0);
	}
	Ok(Hash::from_vec(hash.finalize().as_bytes()))
}

/// Verify the ordinary kernel signature and its commitment to the supplied digest.
/// Coinbase balance and ordinary output/rangeproof validation remain mandatory.
pub fn verify_coinbase_binding_digest(
	context_id: u32,
	secp: &Secp256k1,
	kernel: &TxKernel,
	opening: &Opening,
	digest: Hash,
) -> Result<(), Error> {
	if !kernel.is_coinbase() {
		return Err(Error::Signature("binding kernel is not coinbase".into()));
	}
	let msg = kernel.features.kernel_sig_msg(context_id)?;
	let public_key = kernel.excess.to_pubkey(secp)?;
	let mut data = [0; 32];
	data.copy_from_slice(digest.as_bytes());
	if !secp::s2c::verify_single(secp, &kernel.excess_sig, &msg, &public_key, &data, opening)? {
		return Err(Error::Signature(
			"coinbase kernel does not match its input/state binding".into(),
		));
	}
	Ok(())
}

/// Verify against a complete context independently reconstructed by the node.
pub fn verify_coinbase_binding(
	context_id: u32,
	secp: &Secp256k1,
	kernel: &TxKernel,
	opening: &Opening,
	context: &CoinbaseBindingContext,
) -> Result<(), Error> {
	verify_coinbase_binding_digest(context_id, secp, kernel, opening, context.digest()?)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::core::OutputFeatures;
	use crate::libtx::proof;
	use keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
	use mwc_crates::secp::key::SecretKey;
	use mwc_crates::secp::ContextFlag;
	use util::ToHex;

	fn context() -> CoinbaseBindingContext {
		CoinbaseBindingContext {
			genesis_hash: Hash::from_vec(&[1; 32]),
			prev_hash: Hash::from_vec(&[2; 32]),
			height: 3_632_000,
			input_hash: canonical_input_hash(&[]).unwrap(),
			bitmap_hash: Hash::from_vec(&[3; 32]),
			output_leaf_count: 42,
			reward: 60_000_000_123,
		}
	}

	#[test]
	fn bitmap_hash_fixed_vectors() {
		// Independently generated with Python hashlib.blake2b(digest_size=32)
		// over the specified domain, u64be length and materialized packed bytes.
		let cases: &[(u64, &[u64], &str)] = &[
			(
				0,
				&[],
				"fcb64ec848286de18c8ae42bbcfddfd0170ca1215358ea2d89b539aa9b610cdf",
			),
			(
				1,
				&[],
				"c3af9987ff79e007376b68dec519826172e1a34a6d5db31f6e82a346010d8b90",
			),
			(
				1,
				&[0],
				"eb3179a908feb2675782c4ead8bc5d9c88c4ccd3d68e98c6cac7e702ac3d68d6",
			),
			(
				8,
				&[0, 7],
				"67e3c129c8c01c829e294bb171b1cf65bea584fc0b2f4908c2190e7e2f480923",
			),
			(
				9,
				&[0, 8],
				"7a2d42f815dbec0dd0f98a9f2dbb8ebdc21a63527ddbecb58355fda76d7e9eeb",
			),
			(
				1024,
				&[0, 7, 8, 1023],
				"8264ebe42ff8a5a7caacc5e2b37b8342dd17bb9ad74a76d2ba165555c587b540",
			),
			(
				1025,
				&[0, 1023, 1024],
				"f7b5256583977f4e7fe1804a94d9040365b9b9ae7623d8d9c2098881c5e065f8",
			),
			(
				3077,
				&[0, 1023, 2048, 3076],
				"3e0bb097d359a5e18aa7a34b32cb9224ed9fa197096b0fd41090c63d67d89f2d",
			),
			(
				3077,
				&[],
				"8885606b7303202e8c1eecf3fcdff0387983747b7c713ac1559a545083e3f49f",
			),
		];
		for &(count, indices, expected) in cases {
			assert_eq!(
				unspent_bitmap_hash(indices.iter().copied().map(Ok), count)
					.unwrap()
					.to_hex(),
				expected,
				"count={}, indices={:?}",
				count,
				indices
			);
		}
	}

	#[test]
	fn bitmap_hash_matches_materialized_bits_at_boundaries_and_zero_gaps() {
		use mwc_crates::bit_vec::BitVec;

		for count in [0u64, 1, 7, 8, 9, 1023, 1024, 1025, 2048, 2051, 4097] {
			for pattern in 0..4 {
				let indices: Vec<u64> = (0..count)
					.filter(|index| match pattern {
						0 => false,
						1 => true,
						2 => index % 2 == 0,
						_ => index % 2053 == 0,
					})
					.collect();
				let mut bits = BitVec::from_elem(count as usize, false);
				for &index in &indices {
					bits.set(index as usize, true);
				}
				let mut reference = Blake2b::new(32);
				reference.update(b"MWC_CB_BIND_BITMAP_V1");
				reference.update(&count.to_be_bytes());
				reference.update(&bits.to_bytes());
				assert_eq!(
					unspent_bitmap_hash(indices.into_iter().map(Ok), count).unwrap(),
					Hash::from_vec(reference.finalize().as_bytes()),
					"count={}, pattern={}",
					count,
					pattern
				);
			}
		}
	}

	#[test]
	fn bitmap_hash_binds_length_when_packed_bytes_are_identical() {
		assert_ne!(
			unspent_bitmap_hash([Ok(0)], 1).unwrap(),
			unspent_bitmap_hash([Ok(0)], 8).unwrap()
		);
		assert_ne!(
			unspent_bitmap_hash(std::iter::empty(), 1).unwrap(),
			unspent_bitmap_hash(std::iter::empty(), 8).unwrap()
		);
	}

	#[test]
	fn bitmap_hash_rejects_invalid_indices_and_preserves_iterator_errors() {
		for (count, indices) in [
			(8, vec![0, 0]),
			(8, vec![7, 1]),
			(8, vec![8]),
			(0, vec![0]),
			(u64::MAX, vec![u64::MAX]),
		] {
			assert!(matches!(
				unspent_bitmap_hash(indices.into_iter().map(Ok), count),
				Err(pmmr::Error::DataCorruption(_))
			));
		}
		let error = unspent_bitmap_hash(
			[
				Ok(0),
				Ok(1024),
				Err(pmmr::Error::InvalidState(
					"injected iterator failure".into(),
				)),
			],
			2048,
		)
		.unwrap_err();
		assert!(
			matches!(error, pmmr::Error::InvalidState(message) if message == "injected iterator failure")
		);
		// Exercise length arithmetic at its upper bound without hashing an
		// impractically large bitmap; the original iterator error must survive.
		assert!(matches!(
			unspent_bitmap_hash(
				[Err(pmmr::Error::NotSupported("stop large input".into()))],
				u64::MAX
			),
			Err(pmmr::Error::NotSupported(message)) if message == "stop large input"
		));
	}

	#[test]
	fn canonical_context_fixed_vector_and_non_genesis_height() {
		let mut context = context();
		assert_eq!(
			context.input_hash.to_hex(),
			"e0f3df58a43c72e247e4f86c8a004f33da0750b937aef4285e0d5a4e5fe7aa43"
		);
		assert_eq!(
			context.digest().unwrap().to_hex(),
			"345da247d567085a1ef2fb8be0e7405b82b103d956e8565636ae12854c12379f"
		);
		context.height = 0;
		assert!(context.digest().is_err());
	}

	#[test]
	fn parent_bitmap_hash_and_length_are_bound_including_empty_genesis_parent() {
		let original = context();
		let digest = original.digest().unwrap();
		let mut changed = original.clone();
		changed.bitmap_hash = Hash::from_vec(&[4; 32]);
		assert_ne!(changed.digest().unwrap(), digest);
		changed = original;
		// The context also binds the explicit parent leaf count independently
		// of the bitmap hash supplied by its caller.
		changed.output_leaf_count += 1;
		assert_ne!(changed.digest().unwrap(), digest);
		changed.height = 1;
		changed.output_leaf_count = 0;
		changed.bitmap_hash = unspent_bitmap_hash(std::iter::empty(), 0).unwrap();
		assert!(changed.digest().is_ok());
		changed.height = 0;
		assert!(changed.digest().is_err());
	}

	#[test]
	fn inputs_are_canonical_unique_and_resolved_leaves() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let first = (
			1,
			OutputIdentifier {
				features: OutputFeatures::Plain,
				commit: secp
					.commit(7, SecretKey::from_slice(&secp, &[1; 32]).unwrap())
					.unwrap(),
			},
		);
		let second = (
			2,
			OutputIdentifier {
				features: OutputFeatures::Coinbase,
				commit: secp
					.commit(9, SecretKey::from_slice(&secp, &[2; 32]).unwrap())
					.unwrap(),
			},
		);
		assert_eq!(
			canonical_input_hash(&[first, second]).unwrap(),
			canonical_input_hash(&[second, first]).unwrap()
		);
		assert!(canonical_input_hash(&[first, first]).is_err());
		assert!(canonical_input_hash(&[first, (first.0, second.1)]).is_err());
		assert!(canonical_input_hash(&[first, (second.0, first.1)]).is_err());
		assert!(canonical_input_hash(&[(0, first.1)]).is_err());
		let mut non_leaf = second;
		non_leaf.0 = 3;
		assert!(canonical_input_hash(&[non_leaf]).is_err());
		let mut different = second;
		different.1.features = OutputFeatures::Plain;
		assert_ne!(
			canonical_input_hash(&[second]).unwrap(),
			canonical_input_hash(&[different]).unwrap()
		);
	}

	#[test]
	fn s2c_rewards_keep_legacy_verification_and_wallet_recovery() {
		use crate::{consensus, global};
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[42; 32], false).unwrap();
		let id = ExtKeychain::derive_key_id(3, 1, 2, 3, 0).unwrap();
		let builder = proof::ProofBuilder::new(&secp, &keychain).unwrap();
		let mut original = context();
		original.reward = consensus::reward(0, 123, original.height).unwrap();
		let mut previous: Option<(TxKernel, Opening, crate::core::Output)> = None;
		for shift in 0..3 {
			let mut changed = original.clone();
			changed.input_hash = Hash::from_vec(&[shift; 32]);
			let digest = changed.digest().unwrap();
			let (output, kernel, opening) = crate::libtx::reward::output_s2c(
				0,
				&keychain,
				&builder,
				&id,
				123,
				changed.height,
				&mut secp,
				digest,
			)
			.unwrap();
			kernel.verify(0, &secp).unwrap();
			assert_eq!(
				proof::rewind(&mut secp, &builder, output.commitment(), None, output.proof)
					.unwrap(),
				Some((changed.reward, id.clone(), SwitchCommitmentType::Regular))
			);
			verify_coinbase_binding(0, &secp, &kernel, &opening, &changed).unwrap();
			let mut wrong = changed.clone();
			wrong.reward += 1;
			assert!(verify_coinbase_binding(0, &secp, &kernel, &opening, &wrong).is_err());
			if let Some((previous_kernel, previous_opening, previous_output)) = previous {
				// The same reward key/value keeps its normal output and recovery
				// proof. A new D changes the base nonce, opening and signature.
				assert_eq!(output, previous_output);
				assert_ne!(opening, previous_opening);
				assert_ne!(kernel.excess_sig, previous_kernel.excess_sig);
				assert!(verify_coinbase_binding(
					0,
					&secp,
					&previous_kernel,
					&previous_opening,
					&changed
				)
				.is_err());
				assert!(
					verify_coinbase_binding(0, &secp, &kernel, &previous_opening, &changed)
						.is_err()
				);
			}
			let repeated = crate::libtx::reward::output_s2c(
				0,
				&keychain,
				&builder,
				&id,
				123,
				changed.height,
				&mut secp,
				digest,
			)
			.unwrap();
			assert_eq!(repeated.0, output);
			assert_eq!(repeated.1.excess, kernel.excess);
			assert_eq!(repeated.1.excess_sig, kernel.excess_sig);
			assert_eq!(repeated.2, opening);
			previous = Some((kernel, opening, output));
		}
		let (_, mut ordinary, opening) = crate::libtx::reward::output_s2c(
			0,
			&keychain,
			&builder,
			&id,
			123,
			original.height,
			&mut secp,
			original.digest().unwrap(),
		)
		.unwrap();
		verify_coinbase_binding(0, &secp, &ordinary, &opening, &original).unwrap();
		// Replace only the bound signature with an ordinary valid AggSig. The
		// same kernel key and reward remain valid, but the S2C binding is lost.
		let message = ordinary.features.kernel_sig_msg(0).unwrap();
		let public_key = ordinary.excess.to_pubkey(&secp).unwrap();
		ordinary.excess_sig = crate::libtx::aggsig::sign_from_key_id(
			&secp,
			&keychain,
			&message,
			original.reward,
			&id,
			None,
			&public_key,
		)
		.unwrap();
		ordinary.verify(0, &secp).unwrap();
		assert!(verify_coinbase_binding(0, &secp, &ordinary, &opening, &original).is_err());
	}

	#[test]
	fn opening_encoding_is_strict_and_roundtrips() {
		use crate::ser::{self, ProtocolVersion};
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let bytes =
			util::from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
				.unwrap();
		let opening = Opening::from_slice(&secp, &bytes).unwrap();
		let json = mwc_crates::serde_json::to_string(&opening).unwrap();
		assert_eq!(json, format!("\"{}\"", bytes.to_hex()));
		assert_eq!(
			mwc_crates::serde_json::from_str::<Opening>(&json).unwrap(),
			opening
		);
		let encoded = ser::ser_vec(0, &opening, ProtocolVersion(1), true).unwrap();
		assert_eq!(encoded, bytes);
		let decoded: Opening =
			ser::deserialize_strict(&mut encoded.as_slice(), ProtocolVersion(1), 0, true).unwrap();
		assert_eq!(decoded, opening);
		let mut trailing = encoded.clone();
		trailing.push(0);
		let mut uncompressed = encoded.clone();
		uncompressed[0] = 4;
		let mut invalid_point = vec![0xff; 33];
		invalid_point[0] = 2;
		for invalid in [
			vec![],
			encoded[..32].to_vec(),
			trailing,
			vec![0; 33],
			uncompressed,
			invalid_point,
		] {
			assert!(ser::deserialize_strict::<Opening, _>(
				&mut invalid.as_slice(),
				ProtocolVersion(1),
				0,
				true,
			)
			.is_err());
		}
		for invalid in [
			"".to_owned(),
			"a".repeat(65),
			"a".repeat(67),
			"g".repeat(66),
			"00".repeat(33),
			format!("04{}", "00".repeat(32)),
		] {
			assert!(
				mwc_crates::serde_json::from_value::<Opening>(mwc_crates::serde_json::json!(
					invalid
				))
				.is_err()
			);
		}
		assert!(
			mwc_crates::serde_json::from_value::<Opening>(mwc_crates::serde_json::json!(bytes))
				.is_err()
		);
	}

	#[test]
	fn activation_requires_exactly_one_coinbase_output_and_kernel() {
		use crate::core::{Block, BlockHeader, Inputs, KernelFeatures, TransactionBody};
		use crate::{consensus, global};
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		let height = consensus::COINBASE_BINDING_MAINNET_HEIGHT;
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain = ExtKeychain::from_seed(&secp, &[43; 32], false).unwrap();
		let builder = proof::ProofBuilder::new(&secp, &keychain).unwrap();
		let mut outputs = vec![];
		let mut kernels = vec![];
		for child in 1..=2 {
			let id = ExtKeychain::derive_key_id(3, 1, 2, child, 0).unwrap();
			let (output, kernel, _) = crate::libtx::reward::output_s2c(
				0,
				&keychain,
				&builder,
				&id,
				0,
				height,
				&mut secp,
				context().digest().unwrap(),
			)
			.unwrap();
			outputs.push(output);
			kernels.push(kernel);
		}
		// Two independently valid rewards sum to twice the subsidy. Include a
		// fee kernel so the legacy aggregate coinbase balance accepts that sum.
		// This test exercises coinbase validation, not complete block balance.
		let subsidy = consensus::reward(0, 0, height).unwrap();
		assert_eq!(subsidy, consensus::reward(0, 0, height - 1).unwrap());
		let mut fee_kernel = kernels[0].clone();
		fee_kernel.features = KernelFeatures::Plain {
			fee: subsidy.try_into().unwrap(),
		};
		kernels.push(fee_kernel);
		let body = TransactionBody::init(0, Inputs::default(), &outputs, &kernels, false).unwrap();
		let mut block = Block {
			header: BlockHeader::default(0),
			body,
			coinbase_opening: None,
		};
		block.header.height = height - 1;
		block.verify_coinbase(0, &secp).unwrap();
		block.header.height = height;
		assert!(matches!(
			block.verify_coinbase(0, &secp),
			Err(crate::core::block::Error::CoinbaseCardinality)
		));
	}

	#[test]
	fn activation_boundaries_are_fixed_for_every_network() {
		use crate::{consensus, global};
		for (network, height) in [
			(global::ChainTypes::Mainnet, 3_632_000),
			(global::ChainTypes::Floonet, 1_748_700),
			(global::ChainTypes::AutomatedTesting, 4),
			(global::ChainTypes::UserTesting, 4),
		] {
			global::set_local_chain_type(network);
			assert_eq!(consensus::coinbase_binding_activation_height(0), height);
			assert!(!consensus::is_coinbase_binding_enabled(0, 0));
			assert!(!consensus::is_coinbase_binding_enabled(0, height - 1));
			assert!(consensus::is_coinbase_binding_enabled(0, height));
			assert!(consensus::is_coinbase_binding_enabled(0, height + 1));
		}
	}
}
