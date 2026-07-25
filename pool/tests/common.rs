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

use mwc_chain::types::{NoopAdapter, Options};
use mwc_chain::Chain;
use mwc_core::consensus;
use mwc_core::core::hash::Hash;
use mwc_core::core::pmmr::{ReadablePMMR, VecBackend, PMMR};
use mwc_core::core::{
	Block, BlockHeader, BlockSums, Inputs, KernelFeatures, OutputIdentifier, Transaction, TxKernel,
};
use mwc_core::global;
use mwc_core::libtx::{reward, ProofBuilder};
use mwc_core::pow;
use mwc_crates::chrono::Duration;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_keychain::{BlindingFactor, ExtKeychain, ExtKeychainPath, Keychain};
use mwc_pool::types::*;
use mwc_pool::TransactionPool;
use std::collections::HashSet;
use std::convert::TryInto;
use std::fs;
use std::sync::Arc;

// Keep test targets compilable without exposing the production builder. Any
// affected test reaches this shim and fails with an actionable runtime error.
#[allow(dead_code, unused_imports)]
pub mod build {
	pub use mwc_core::libtx::build::*;

	#[cfg(not(feature = "test-support"))]
	pub fn output<K, B>(
		_value: u64,
		_key_id: mwc_keychain::Identifier,
	) -> Box<mwc_core::libtx::build::Append<K, B>>
	where
		K: mwc_keychain::Keychain,
		B: mwc_core::libtx::proof::ProofBuild,
	{
		panic!("test-support feature is required to run the tests");
	}
}

/// Build genesis block with reward (non-empty, like we have in mainnet).
pub fn genesis_block<K>(keychain: &K) -> Block
where
	K: Keychain,
{
	let key_id = ExtKeychain::derive_key_id(1, 0, 0, 0, 0).unwrap();
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
	let reward = reward::output(
		0,
		keychain,
		&ProofBuilder::new(&secp, keychain).unwrap(),
		&key_id,
		0,
		false,
		0,
		&mut secp,
	)
	.unwrap();

	let mut genesis = global::get_genesis_block(&secp, 0)
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

pub fn init_chain(secp: &Secp256k1, dir_name: &str, genesis: Block) -> Chain {
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

pub fn add_some_blocks<K>(secp: &mut Secp256k1, chain: &Chain, count: u64, keychain: &K)
where
	K: Keychain,
{
	for _ in 0..count {
		add_block(secp, chain, &[], keychain);
	}
}

pub fn add_block<K>(secp: &mut Secp256k1, chain: &Chain, txs: &[Transaction], keychain: &K)
where
	K: Keychain,
{
	let prev = chain.head_header().unwrap();
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
	let key_id = ExtKeychainPath::new(1, height as u32, 0, 0, 0)
		.unwrap()
		.to_identifier()
		.unwrap();
	let reward = reward::output(
		0,
		keychain,
		&ProofBuilder::new(secp, keychain).unwrap(),
		&key_id,
		fee,
		false,
		height,
		secp,
	)
	.unwrap();

	let mut block = Block::new(
		0,
		&prev,
		txs,
		next_header_info.clone().difficulty,
		reward,
		secp,
	)
	.unwrap();

	block.header.timestamp = prev.timestamp + Duration::seconds(60);
	block.header.pow.secondary_scaling = next_header_info.secondary_scaling;

	chain.set_txhashset_roots(secp, &mut block).unwrap();

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
		.process_block(secp, block, Options::NONE, std::collections::HashSet::new())
		.unwrap();
}

#[derive(Clone)]
pub struct ChainAdapter {
	pub chain: Arc<Chain>,
}

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
		self.chain
			.verify_tx_lock_height(tx)
			.map_err(|_| PoolError::ImmatureTransaction)
	}
	fn replay_attack_check(&self, tx: &Transaction) -> Result<(), PoolError> {
		self.chain.replay_attack_check(tx).map_err(|e| {
			PoolError::DuplicateKernelOrDuplicateSpent(format!("Replay attack detected, {}", e))
		})
	}
}

pub fn init_transaction_pool<B>(chain: Arc<B>) -> TransactionPool<B, NoopPoolAdapter>
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

pub fn test_transaction_spending_coinbase<K>(
	secp: &mut Secp256k1,
	keychain: &K,
	header: &BlockHeader,
	output_values: Vec<u64>,
) -> Transaction
where
	K: Keychain,
{
	let output_sum = output_values.iter().sum::<u64>() as i64;

	let coinbase_reward: u64 = consensus::MWC_FIRST_GROUP_REWARD;

	let fees: i64 = coinbase_reward as i64 - output_sum;
	assert!(fees >= 0);

	let mut tx_elements = Vec::new();

	// single input spending a single coinbase (deterministic key_id aka height)
	{
		let key_id = ExtKeychain::derive_key_id(1, header.height as u32, 0, 0, 0).unwrap();
		tx_elements.push(build::coinbase_input(coinbase_reward, key_id));
	}

	for output_value in output_values {
		let key_id = ExtKeychain::derive_key_id(1, output_value as u32, 0, 0, 0).unwrap();
		tx_elements.push(build::output(output_value, key_id));
	}

	build::transaction(
		0,
		secp,
		KernelFeatures::Plain {
			fee: (fees as u64).try_into().unwrap(),
		},
		&tx_elements,
		keychain,
		&ProofBuilder::new(secp, keychain).unwrap(),
	)
	.unwrap()
}

pub fn test_transaction<K>(
	secp: &mut Secp256k1,
	keychain: &K,
	input_values: Vec<u64>,
	output_values: Vec<u64>,
) -> Transaction
where
	K: Keychain,
{
	let input_sum = input_values.iter().sum::<u64>() as i64;
	let output_sum = output_values.iter().sum::<u64>() as i64;
	let fees: i64 = input_sum - output_sum;
	assert!(fees >= 0);

	test_transaction_with_kernel_features(
		secp,
		keychain,
		input_values,
		output_values,
		KernelFeatures::Plain {
			fee: (fees as u64).try_into().unwrap(),
		},
	)
}

pub fn test_transaction_with_kernel_features<K>(
	secp: &mut Secp256k1,
	keychain: &K,
	input_values: Vec<u64>,
	output_values: Vec<u64>,
	kernel_features: KernelFeatures,
) -> Transaction
where
	K: Keychain,
{
	let mut tx_elements = Vec::new();

	for input_value in input_values {
		let key_id = ExtKeychain::derive_key_id(1, input_value as u32, 0, 0, 0).unwrap();
		tx_elements.push(build::input(input_value, key_id));
	}

	for output_value in output_values {
		let key_id = ExtKeychain::derive_key_id(1, output_value as u32, 0, 0, 0).unwrap();
		tx_elements.push(build::output(output_value, key_id));
	}

	build::transaction(
		0,
		secp,
		kernel_features,
		&tx_elements,
		keychain,
		&ProofBuilder::new(secp, keychain).unwrap(),
	)
	.unwrap()
}

pub fn test_transaction_with_kernel<K>(
	secp: &mut Secp256k1,
	keychain: &K,
	input_values: Vec<u64>,
	output_values: Vec<u64>,
	kernel: TxKernel,
	excess: BlindingFactor,
) -> Transaction
where
	K: Keychain,
{
	let mut tx_elements = Vec::new();

	for input_value in input_values {
		let key_id = ExtKeychain::derive_key_id(1, input_value as u32, 0, 0, 0).unwrap();
		tx_elements.push(build::input(input_value, key_id));
	}

	for output_value in output_values {
		let key_id = ExtKeychain::derive_key_id(1, output_value as u32, 0, 0, 0).unwrap();
		tx_elements.push(build::output(output_value, key_id));
	}

	build::transaction_with_kernel(
		0,
		secp,
		&tx_elements,
		kernel,
		excess,
		keychain,
		&ProofBuilder::new(secp, keychain).unwrap(),
	)
	.unwrap()
}

pub fn test_source() -> TxSource {
	TxSource::Broadcast
}

pub fn clean_output_dir(db_root: String) {
	if let Err(e) = fs::remove_dir_all(db_root) {
		if e.kind() != std::io::ErrorKind::NotFound {
			println!("cleaning output dir failed - {:?}", e)
		}
	}
}
