// Copyright 2020 The Grin Developers
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

//! Builds the blinded output and related signature proof for the block
//! reward.
use crate::address::Address;
use crate::consensus::reward;
use crate::core::hash::Hashed;
use crate::core::transaction::Commit;
use crate::core::{
	IdentifierWithRnp, KernelFeatures, Output, OutputFeatures, OutputIdentifier, OutputWithRnp,
	TxKernel,
};
use crate::libtx::error::Error;
use crate::libtx::{
	aggsig,
	proof::{self, PaymentId, ProofBuild},
};
use keychain::{Identifier, Keychain, SwitchCommitmentType};
use util::{secp, secp::PublicKey, secp::SecretKey, static_secp_instance};

/// output a reward output
pub fn output<K, B>(
	keychain: &K,
	builder: &B,
	key_id: &Identifier,
	fees: u64,
	test_mode: bool,
	height: u64,
) -> Result<(Output, TxKernel), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let value = reward(fees, height);
	// TODO: proper support for different switch commitment schemes
	let switch = SwitchCommitmentType::Regular;
	let commit = keychain.commit(value, key_id, switch)?;

	trace!("Block reward - Pedersen Commit is: {:?}", commit,);

	let proof = proof::create(keychain, builder, value, key_id, switch, commit, None)?;

	let output = Output::new(OutputFeatures::Coinbase, commit, proof);

	let secp = static_secp_instance();
	let secp = secp.lock();
	let over_commit = secp.commit_value(value)?;
	let out_commit = output.commitment();
	let excess = secp::Secp256k1::commit_sum(vec![out_commit], vec![over_commit])?;
	let pubkey = excess.to_pubkey()?;

	let features = KernelFeatures::Coinbase;
	let msg = features.kernel_sig_msg()?;
	let sig = match test_mode {
		true => {
			let test_nonce = secp::key::SecretKey::from_slice(&[1; 32])?;
			aggsig::sign_from_key_id(
				&secp,
				keychain,
				&msg,
				value,
				&key_id,
				Some(&test_nonce),
				Some(&pubkey),
			)?
		}
		false => {
			aggsig::sign_from_key_id(&secp, keychain, &msg, value, &key_id, None, Some(&pubkey))?
		}
	};

	let kernel = TxKernel {
		features: KernelFeatures::Coinbase,
		excess,
		excess_sig: sig,
	};
	Ok((output, kernel))
}

/// create a reward output to a receiver address (reward with non-interactive transaction style)
pub fn nit_output<K, B>(
	keychain: &K,
	builder: &B,
	private_nonce: SecretKey,
	recipient_address: Address,
	payment_id: PaymentId,
	fees: u64,
	test_mode: bool,
	height: u64,
) -> Result<(OutputWithRnp, TxKernel), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let value = reward(fees, height);
	let switch = SwitchCommitmentType::Regular;
	let public_nonce = PublicKey::from_secret_key(keychain.secp(), &private_nonce)?;
	let (ephemeral_key_q, pp_apos) =
		recipient_address.get_ephemeral_key_for_tx(keychain.secp(), &private_nonce)?;
	let view_tag = recipient_address.get_view_tag_for_tx(keychain.secp(), &private_nonce)?;
	let commit = keychain.commit_with_key(value, ephemeral_key_q.clone(), switch)?;

	trace!("Block reward - Pedersen Commit is: {:?}", commit,);

	let output_rr_sig_msg = secp::Message::from_slice(
		(
			OutputIdentifier::new(OutputFeatures::CoinbaseWrnp, &commit),
			view_tag,
			pp_apos.serialize_vec(true).as_ref().to_vec(),
		)
			.hash()
			.to_vec()
			.as_slice(),
	)
	.unwrap();
	let r_sig = keychain.schnorr_sign(&output_rr_sig_msg, &private_nonce)?;

	let proof = proof::nit_create(
		keychain,
		builder,
		value,
		ephemeral_key_q.clone(),
		switch,
		commit,
		payment_id,
		height,
		None,
	)?;

	let output = OutputWithRnp::new(
		IdentifierWithRnp::new(
			OutputFeatures::CoinbaseWrnp,
			commit,
			public_nonce,
			r_sig,
			pp_apos,
			view_tag,
		),
		proof,
	);

	let over_commit = keychain.secp().commit_value(value)?;
	let out_commit = output.commitment();
	let excess = secp::Secp256k1::commit_sum(vec![out_commit], vec![over_commit])?;
	let pubkey = excess.to_pubkey()?;

	let features = KernelFeatures::Coinbase;
	let msg = features.kernel_sig_msg()?;
	// Calculate the actual blinding factor for commitment type of SwitchCommitmentType::Regular.
	let blind = match switch {
		SwitchCommitmentType::Regular => keychain.secp().blind_switch(value, ephemeral_key_q)?,
		SwitchCommitmentType::None => ephemeral_key_q,
	};
	let sig = match test_mode {
		true => {
			let test_nonce = secp::key::SecretKey::from_slice(&[1; 32])?;
			aggsig::sign_single(
				keychain.secp(),
				&msg,
				&blind,
				Some(&test_nonce),
				Some(&pubkey),
			)?
		}
		false => aggsig::sign_single(keychain.secp(), &msg, &blind, None, Some(&pubkey))?,
	};

	let kernel = TxKernel {
		features: KernelFeatures::Coinbase,
		excess,
		excess_sig: sig,
	};
	Ok((output, kernel))
}
