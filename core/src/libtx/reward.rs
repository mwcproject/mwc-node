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

//! Builds the blinded output and related signature proof for the block
//! reward.
use crate::consensus::reward;
use crate::core::hash::Hash;
use crate::core::{KernelFeatures, Output, OutputFeatures, TxKernel};
use crate::libtx::error::Error;
use crate::libtx::proof::{self, ProofBuild};
use keychain::{Identifier, Keychain, SwitchCommitmentType};
use mwc_crates::secp::s2c::Opening;
use mwc_crates::secp::Secp256k1;

/// Build a normal, wallet-rewindable reward output and an S2C-bound kernel.
///
/// Only the kernel nonce/signature commits to the supplied digest. The secret
/// base nonce includes the digest, so reusing a reward key for another template
/// never reuses the S2C nonce. The returned opening is public block data.
pub fn output_s2c<K, B>(
	context_id: u32,
	keychain: &K,
	builder: &B,
	key_id: &Identifier,
	fees: u64,
	height: u64,
	secp: &mut Secp256k1,
	digest: Hash,
) -> Result<(Output, TxKernel, Opening), Error>
where
	K: Keychain,
	B: ProofBuild,
{
	let value = reward(context_id, fees, height)?;
	let switch = SwitchCommitmentType::Regular;
	let commit = keychain.commit(secp, value, key_id, switch)?;
	let proof = proof::create(secp, keychain, builder, value, key_id, switch, commit)?;
	let output = Output::new(OutputFeatures::Coinbase, commit, proof);
	let over_commit = secp.commit_value(value)?;
	let excess = secp.commit_sum(vec![commit], vec![over_commit])?;
	let features = KernelFeatures::Coinbase;
	let msg = features.kernel_sig_msg(context_id)?;
	let key = keychain.derive_key(secp, value, key_id, switch)?;
	let mut data = [0; 32];
	data.copy_from_slice(digest.as_bytes());
	let (excess_sig, opening) = mwc_crates::secp::s2c::sign_single(secp, &msg, &key, &data)?;
	let kernel = TxKernel {
		features,
		excess,
		excess_sig,
	};
	Ok((output, kernel, opening))
}
