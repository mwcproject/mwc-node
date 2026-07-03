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

//! Common fuzz-test helpers.
//!
//! This module is compiled for the `pool/fuzz` libFuzzer targets, not for
//! production transaction-pool code. `PoolFuzzer::new` intentionally seeds its
//! keychain from `SysRng`, so keys and key-dependent generated transactions vary
//! across fixture constructions. Within one fixture, derived key paths, genesis
//! blocks, PMMR roots, short chains, and transactions are built predictably from
//! that seed.
//! `unwrap`/`expect` calls in this file are intentional harness invariants. If
//! one of them fails, the fuzz environment or per-fixture setup is
//! broken, so panicking is preferable to hiding the failure as a recoverable pool
//! validation result. Production code should continue returning typed errors.
//! Unchecked numeric conversions, wrapping arithmetic, and panicking timestamp
//! arithmetic in these helpers are also fuzz-only fixture behavior: they may
//! collapse arbitrary generated values onto repeatable per-fixture key paths or
//! abort impossible synthetic-chain states, which is acceptable here because
//! this code does not derive production wallet/user keys.

use mwc_chain::types::{NoopAdapter, Options};
use mwc_chain::Chain;
use mwc_core::consensus;
use mwc_core::core::hash::Hash;
use mwc_core::core::pmmr::{ReadablePMMR, VecBackend, PMMR};
use mwc_core::core::{
	Block, BlockHeader, BlockSums, Inputs, KernelFeatures, OutputIdentifier, Transaction,
};
use mwc_core::global;
use mwc_core::libtx::{build, reward, ProofBuilder};
use mwc_core::pow;
use mwc_crates::chrono::Duration;
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
use mwc_keychain::{ExtKeychain, ExtKeychainPath, Keychain};
use mwc_pool::types::*;
use mwc_pool::TransactionPool;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs;
use std::sync::Arc;

/// Build genesis block with reward (non-empty, like we have in mainnet).
// Same as from pool/tests/common.rs
pub fn genesis_block<K>(keychain: &K, secp: &mut Secp256k1) -> Block
where
	K: Keychain,
{
	let key_id = ExtKeychain::derive_key_id(1, 0, 0, 0, 0).unwrap();
	let reward = reward::output(
		0,
		keychain,
		&ProofBuilder::new(secp, keychain).unwrap(),
		&key_id,
		0,
		false,
		0,
		secp,
	)
	.unwrap();

	let mut genesis = global::get_genesis_block(secp, 0)
		.expect("testing genesis must be available")
		.with_reward(reward.0, reward.1)
		.expect("genesis block body must be empty before reward");
	set_genesis_mmr_roots(&mut genesis);

	let context_id = genesis.header.pow.proof.context_id;
	let difficulty = genesis.header.pow.total_difficulty;
	pow::pow_size(
		context_id,
		&mut genesis.header,
		difficulty,
		global::proofsize(context_id),
		global::min_edge_bits(context_id),
	)
	.expect("testing genesis PoW must be mineable");

	genesis
}

fn set_genesis_mmr_roots(genesis: &mut Block) {
	// Fuzz harness invariant: this genesis block and the VecBackend PMMRs are
	// generated locally from known-good test data. PMMR push/root failures here
	// indicate broken fixture construction, not malformed external input, so the
	// unwraps deliberately abort the fuzz run instead of returning Result.
	let context_id = genesis.header.pow.proof.context_id;

	let mut output_backend = VecBackend::new(context_id);
	let mut output_pmmr = PMMR::new(&mut output_backend);
	for output in genesis.outputs() {
		output_pmmr.push(&output.identifier()).unwrap();
	}
	genesis.header.output_mmr_size = output_pmmr.size();
	genesis.header.output_root = output_pmmr.root().unwrap();

	let mut rproof_backend = VecBackend::new(context_id);
	let mut rproof_pmmr = PMMR::new(&mut rproof_backend);
	for output in genesis.outputs() {
		rproof_pmmr.push(&output.proof()).unwrap();
	}
	genesis.header.range_proof_root = rproof_pmmr.root().unwrap();

	let mut kernel_backend = VecBackend::new(context_id);
	let mut kernel_pmmr = PMMR::new(&mut kernel_backend);
	for kernel in genesis.kernels() {
		kernel_pmmr.push(kernel).unwrap();
	}
	genesis.header.kernel_mmr_size = kernel_pmmr.size();
	genesis.header.kernel_root = kernel_pmmr.root().unwrap();
}

pub fn fuzz_tx_source(nonce: u8) -> TxSource {
	if nonce < 51 {
		TxSource::PushApi
	} else if nonce < 102 {
		TxSource::Broadcast
	} else if nonce < 153 {
		TxSource::Fluff
	} else if nonce < 204 {
		TxSource::EmbargoExpired
	} else {
		TxSource::Deaggregate
	}
}

// Same as from pool/tests/common.rs
#[derive(Clone)]
pub struct ChainAdapter {
	pub chain: Arc<Chain>,
}

// Same as from pool/tests/common.rs
impl BlockChain for ChainAdapter {
	fn chain_head(&self) -> Result<BlockHeader, PoolError> {
		self.chain
			.head_header()
			.map_err(|e| PoolError::Other(format!("failed to get chain head, {}", e)))
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, PoolError> {
		self.chain
			.get_block_header(hash)
			.map_err(|e| PoolError::Other(format!("failed to get block header, {}", e)))
	}

	fn get_block_sums(&self, hash: &Hash) -> Result<BlockSums, PoolError> {
		self.chain
			.get_block_sums(hash)
			.map_err(|e| PoolError::Other(format!("failed to get block sums, {}", e)))
	}

	fn validate_tx(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain.validate_tx(tx).map_err(|e| match e {
			mwc_chain::Error::Transaction(txe) => txe.into(),
			mwc_chain::Error::NRDRelativeHeight => PoolError::NRDKernelRelativeHeight,
			_ => PoolError::Other("failed to validate tx".into()),
		})
	}

	fn validate_inputs(&self, inputs: &Inputs) -> Result<Vec<OutputIdentifier>, PoolError> {
		self.chain
			.validate_inputs(inputs)
			.map(|outputs| outputs.into_iter().map(|(out, _)| out).collect::<Vec<_>>())
			.map_err(|_| PoolError::Other("failed to validate inputs".into()))
	}

	fn verify_coinbase_maturity(&self, inputs: &Inputs) -> Result<(), PoolError> {
		self.chain
			.verify_coinbase_maturity(inputs)
			.map_err(|e| match e {
				mwc_chain::Error::ImmatureCoinbase => PoolError::ImmatureCoinbase,
				_ => PoolError::Other(format!("failed to verify coinbase maturity, {}", e)),
			})
	}

	fn verify_tx_lock_height(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain.verify_tx_lock_height(tx).map_err(|e| match e {
			mwc_chain::Error::TxLockHeight => PoolError::ImmatureTransaction,
			_ => PoolError::Other(format!("failed to verify tx lock height, {}", e)),
		})
	}

	fn replay_attack_check(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain.replay_attack_check(tx).map_err(|e| {
			PoolError::DuplicateKernelOrDuplicateSpent(format!("Replay attack detected, {}", e))
		})
	}
}

pub fn clean_output_dir(db_root: String) {
	if let Err(e) = fs::remove_dir_all(db_root) {
		if e.kind() != std::io::ErrorKind::NotFound {
			panic!("cleaning output dir failed - {:?}", e);
		}
	}
}

/// Fuzz fixture used by the fuzz target.
///
/// Each construction uses a fresh random keychain seed from `SysRng`. The
/// synthetic chain and transactions are therefore stable only within that
/// `PoolFuzzer` instance, not across separate harness runs.
///
/// Setup/build methods intentionally panic on failed fixture invariants. The
/// fuzz target handles malformed serialized transactions at its input boundary;
/// this helper is not production code and does not model recoverable errors.
pub struct PoolFuzzer {
	pub chain: Arc<Chain>,
	pub secp: Secp256k1,
	pub keychain: ExtKeychain,
	pub pool: TransactionPool<ChainAdapter, NoopPoolAdapter>,
}

impl PoolFuzzer {
	pub fn new(db_root: &str) -> Self {
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain: ExtKeychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();

		clean_output_dir(db_root.into());

		let genesis = genesis_block(&keychain, &mut secp);
		let chain = Arc::new(Self::init_chain(db_root, &mut secp, genesis));

		// Initialize a new pool with our chain adapter.
		let pool = Self::init_transaction_pool(Arc::new(ChainAdapter {
			chain: chain.clone(),
		}));

		let mut ret = Self {
			chain,
			secp,
			keychain,
			pool,
		};

		ret.add_some_blocks(3);

		ret
	}

	pub fn test_transaction_spending_coinbase(&mut self, output_values: Vec<u64>) -> Transaction {
		let header = self.chain.get_header_by_height(1).unwrap();

		// Fuzz-only fixture math: unchecked wrapping is accepted so arbitrary
		// generated amounts can still drive deterministic transaction building.
		let mut output_sum = 0u64;
		for &s in output_values.iter() {
			output_sum = output_sum.overflowing_add(s).0;
		}

		let coinbase_reward: u64 = 2_380_952_380;
		let fees = coinbase_reward.overflowing_sub(output_sum).0;

		let mut tx_elements = Vec::new();

		// single input spending a single coinbase (deterministic key_id aka height)
		{
			// Fuzz-only key path construction: unchecked narrowing to u32 is
			// accepted for deterministic fixture keys.
			let key_id = ExtKeychain::derive_key_id(1, header.height as u32, 0, 0, 0).unwrap();
			tx_elements.push(build::coinbase_input(coinbase_reward, key_id));
		}

		for output_value in output_values {
			// Fuzz-only key path construction: unchecked narrowing of arbitrary
			// output values is accepted; collisions only reuse fixture keys here.
			let key_id = ExtKeychain::derive_key_id(1, output_value as u32, 0, 0, 0).unwrap();
			tx_elements.push(build::output(output_value, key_id));
		}

		let keychain = &self.keychain;
		let secp = &mut self.secp;
		let proof_builder = ProofBuilder::new(secp, keychain).unwrap();

		build::transaction(
			0,
			secp,
			KernelFeatures::Plain {
				// Fuzz-only fee conversion: unchecked fixture fees are accepted
				// here, and invalid values should abort harness setup loudly.
				fee: fees.try_into().unwrap(),
			},
			&tx_elements,
			keychain,
			&proof_builder,
		)
		.unwrap()
	}

	// Same as from pool/tests/common.rs,
	//   with changes for summing inputs and outputs
	pub fn test_transaction(
		&mut self,
		input_values: Vec<u64>,
		output_values: Vec<u64>,
	) -> Transaction {
		// Fuzz-only fixture math: unchecked wrapping is accepted so arbitrary
		// generated amounts can still drive deterministic transaction building.
		let mut input_sum = 0u64;
		for &s in input_values.iter() {
			input_sum = input_sum.overflowing_add(s).0;
		}

		let mut output_sum = 0u64;
		for &s in output_values.iter() {
			output_sum = output_sum.overflowing_add(s).0;
		}

		let fees = input_sum.overflowing_sub(output_sum).0;

		self.test_transaction_with_kernel_features(
			input_values,
			output_values,
			KernelFeatures::Plain {
				// Fuzz-only fee conversion: unchecked fixture fees are accepted
				// here, and invalid values should abort harness setup loudly.
				fee: fees.try_into().unwrap(),
			},
		)
	}

	pub fn test_transaction_with_kernel_features(
		&mut self,
		input_values: Vec<u64>,
		output_values: Vec<u64>,
		kernel_features: KernelFeatures,
	) -> Transaction {
		let mut tx_elements = Vec::new();

		for input_value in input_values {
			// Fuzz-only key path construction: unchecked narrowing of arbitrary
			// input values is accepted; collisions only reuse fixture keys here.
			let key_id = ExtKeychain::derive_key_id(1, input_value as u32, 0, 0, 0).unwrap();
			tx_elements.push(build::input(input_value, key_id));
		}

		for output_value in output_values {
			// Fuzz-only key path construction: unchecked narrowing of arbitrary
			// output values is accepted; collisions only reuse fixture keys here.
			let key_id = ExtKeychain::derive_key_id(1, output_value as u32, 0, 0, 0).unwrap();
			tx_elements.push(build::output(output_value, key_id));
		}

		let keychain = &self.keychain;
		let secp = &mut self.secp;
		let proof_builder = ProofBuilder::new(secp, keychain).unwrap();

		build::transaction(
			0,
			secp,
			kernel_features,
			&tx_elements,
			keychain,
			&proof_builder,
		)
		.unwrap()
	}

	fn init_chain(dir_name: &str, secp: &mut Secp256k1, genesis: Block) -> Chain {
		Chain::init(
			secp,
			0,
			dir_name.to_string(),
			Arc::new(NoopAdapter {}),
			genesis,
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
		)
		.unwrap()
	}

	// Same as from pool/tests/common.rs
	fn init_transaction_pool<B>(chain: Arc<B>) -> TransactionPool<B, NoopPoolAdapter>
	where
		B: BlockChain,
	{
		TransactionPool::new(
			0,
			PoolConfig {
				tx_fee_base: default_tx_fee_base(),
				reorg_cache_timeout: 1_440,
				max_pool_size: 50,
				max_stempool_size: 50,
				mineable_max_weight: 10_000,
			},
			chain.clone(),
			Arc::new(NoopPoolAdapter {}),
		)
	}

	// Same as from pool/tests/common.rs, with interface change
	pub fn add_some_blocks(&mut self, count: u64) {
		for _ in 0..count {
			self.add_block(vec![]);
		}
	}

	// Same as from pool/tests/common.rs, with interface change
	pub fn add_block(&mut self, txs: Vec<Transaction>) {
		let chain = &self.chain;
		let prev = chain.head_header().unwrap();
		// Fuzz-only synthetic chain arithmetic: unchecked height increments are
		// accepted for deterministic fixture blocks.
		let height = prev.height + 1;
		let mut cache_values = consensus::DifficultyCache::new();
		let next_header_info = consensus::next_difficulty(
			0,
			height,
			chain.difficulty_iter().unwrap(),
			&mut cache_values,
		)
		.unwrap();
		let fee = txs.iter().map(|x| x.fee().unwrap()).sum();
		// Fuzz-only reward key path construction: unchecked narrowing of the
		// synthetic block height is accepted for deterministic fixture keys.
		let key_id = ExtKeychainPath::new(1, height as u32, 0, 0, 0)
			.unwrap()
			.to_identifier()
			.unwrap();
		let reward = reward::output(
			0,
			&self.keychain,
			&ProofBuilder::new(&mut self.secp, &self.keychain).unwrap(),
			&key_id,
			fee,
			false,
			height,
			&mut self.secp,
		)
		.unwrap();

		let mut block = Block::new(
			0,
			&prev,
			&txs,
			next_header_info.clone().difficulty,
			reward,
			&self.secp,
		)
		.unwrap();

		// Fuzz-only timestamp arithmetic: chrono's panicking Add is accepted
		// here because block times come from this deterministic synthetic chain.
		block.header.timestamp = prev.timestamp + Duration::seconds(60);
		block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

		chain.set_txhashset_roots(&self.secp, &mut block).unwrap();

		let edge_bits = global::min_edge_bits(0);
		block.header.pow.proof.edge_bits = edge_bits;
		pow::pow_size(
			0,
			&mut block.header,
			next_header_info.difficulty,
			global::proofsize(0),
			edge_bits,
		)
		.unwrap();

		chain
			.process_block(
				&mut self.secp,
				block,
				Options::NONE,
				std::collections::HashSet::new(),
			)
			.unwrap();
	}
}
