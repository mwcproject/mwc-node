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

use crate::common::adapters::DandelionAdapter;
use crate::ServerTxPool;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::transaction;
use mwc_core::global;
use mwc_crates::log::{debug, error, info, warn};
use mwc_crates::rand::{rng, RngExt};
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_pool::{BlockChain, DandelionConfig, Pool, PoolEntry, PoolError, TxSource};
use mwc_util::StopState;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// A process to monitor transactions in the stempool.
/// With Dandelion, transaction can be broadcasted in stem or fluff phase.
/// When sent in stem phase, the transaction is relayed to only node: the
/// dandelion relay. In order to maintain reliability a timer is started for
/// each transaction sent in stem phase. This function will monitor the
/// stempool and test if the timer is expired for each transaction. In that case
/// the transaction will be sent in fluff phase (to multiple peers) instead of
/// sending only to the peer relay.
pub fn monitor_transactions(
	dandelion_config: DandelionConfig,
	tx_pool: ServerTxPool,
	adapter: Arc<dyn DandelionAdapter>,
	stop_state: Arc<StopState>,
) -> std::io::Result<thread::JoinHandle<()>> {
	debug!("Started Dandelion transaction monitor.");

	thread::Builder::new()
		.name("dandelion".to_string())
		.spawn(move || {
			let run_interval = Duration::from_secs(10);
			// If this fails, start_dandelion has already accepted the thread handle and
			// cannot report startup failure. Secp context creation can fail during
			// randomization, but that requires severe system RNG/resource failure and is
			// expected to be extremely rare; a startup channel just for this edge case
			// would add more complexity than it is worth.
			let mut secp = match Secp256k1::with_caps(ContextFlag::Commit) {
				Ok(s) => s,
				Err(e) => {
					error!(
						"Unable to start dandelion thread, secp acclocation error, {}",
						e
					);
					return;
				}
			};

			let mut last_run = Instant::now()
				.checked_sub(Duration::from_secs(20))
				.unwrap_or_else(Instant::now);
			loop {
				// Halt Dandelion monitor if we have been notified that we are stopping.
				if stop_state.is_stopped() {
					break;
				}

				if last_run.elapsed() > run_interval {
					let mut processing_ok = true;

					if !adapter.is_stem() {
						if let Err(e) =
							process_fluff_phase(&dandelion_config, &tx_pool, &adapter, &mut secp)
						{
							error!("dand_mon: Problem processing fluff phase. {}", e);
							processing_ok = false;
						}
					}

					// Now find all expired entries based on embargo timer.
					if let Err(e) = process_expired_entries(&dandelion_config, &tx_pool, &mut secp)
					{
						error!("dand_mon: Problem processing expired entries. {}", e);
						processing_ok = false;
					}

					// Handle the tx above *before* we transition to next epoch.
					// This gives us an opportunity to do the final "fluff" before we start
					// stemming on the subsequent epoch.
					if processing_ok && adapter.is_expired() {
						adapter.next_epoch();
					}
					last_run = Instant::now();
				}

				// Monitor loops every 10s, but check stop flag every second.
				thread::sleep(Duration::from_secs(1));
			}
		})
}

// Query the pool for transactions older than the cutoff.
// Used for both periodic fluffing and handling expired embargo timer.
fn select_txs_cutoff<B>(pool: &Pool<B>, cutoff_secs: u32) -> Vec<PoolEntry>
where
	B: BlockChain,
{
	let cutoff = Duration::from_secs(cutoff_secs as u64);
	pool.ordered_entry_refs()
		.filter(|x| x.tx_at.elapsed() > cutoff)
		.cloned()
		.collect()
}

fn process_fluff_phase(
	dandelion_config: &DandelionConfig,
	tx_pool: &ServerTxPool,
	adapter: &Arc<dyn DandelionAdapter>,
	secp: &mut Secp256k1,
) -> Result<(), PoolError> {
	// Take a write lock on the txpool for the duration of this processing.
	let mut tx_pool = tx_pool.write();

	let all_entries = tx_pool.stempool.all_entries();
	if all_entries.is_empty() {
		return Ok(());
	}

	let cutoff_secs = dandelion_config.aggregation_secs as u32;
	let cutoff_entries = select_txs_cutoff(&tx_pool.stempool, cutoff_secs);

	// If epoch is expired, fluff *all* outstanding entries in stempool.
	// If *any* entry older than aggregation_secs (30s) then fluff *all* entries.
	// Otherwise we are done for now and we can give txs more time to aggregate.
	if !adapter.is_expired() && cutoff_entries.is_empty() {
		return Ok(());
	}

	let header = tx_pool.chain_head()?;
	let context_id = tx_pool.get_context_id();

	let fluffable_txs = {
		let txpool_tx = tx_pool.txpool.all_transactions_aggregate(None, secp)?;
		let txs: Vec<_> = all_entries.iter().map(|x| x.tx.clone()).collect();
		tx_pool.stempool.validate_raw_txs(
			&txs,
			txpool_tx,
			&header,
			transaction::Weighting::NoLimit,
			secp,
		)?
	};
	let fluffable_hashes = fluffable_txs
		.iter()
		.map(|tx| tx.hash(context_id))
		.collect::<Result<HashSet<Hash>, _>>()?;
	let mut skipped = 0;
	for entry in &all_entries {
		let tx_hash = entry.tx.hash(context_id)?;
		if !fluffable_hashes.contains(&tx_hash) {
			if tx_pool.stempool.remove_tx(&entry.tx)?.is_some() {
				skipped += 1;
				debug!(
					"dand_mon: removed skipped stempool tx {} after failed aggregate validation",
					tx_hash
				);
			}
		}
	}

	debug!(
		"dand_mon: Found {} txs in local stempool to fluff, removed {} skipped txs",
		fluffable_txs.len(),
		skipped
	);

	if fluffable_txs.is_empty() {
		return Ok(());
	}

	let fluff_txs = aggregate_fluffable_txs(context_id, &fluffable_txs, secp)?;
	debug!(
		"dand_mon: fluffing {} stempool txs as {} transaction batches",
		fluffable_txs.len(),
		fluff_txs.len()
	);

	for tx in fluff_txs {
		tx_pool.add_to_pool(TxSource::Fluff, tx, false, &header, secp)?;
	}
	Ok(())
}

fn aggregate_fluffable_txs(
	context_id: u32,
	fluffable_txs: &[transaction::Transaction],
	secp: &mut Secp256k1,
) -> Result<Vec<transaction::Transaction>, PoolError> {
	let mut fluff_txs = Vec::new();
	let mut current_txs = Vec::new();
	let mut current_weight = 0;
	let max_weight = global::max_tx_weight(context_id);

	for tx in fluffable_txs {
		let tx_weight = tx.weight_size().map_err(PoolError::InvalidTx)?;
		if tx_weight > max_weight {
			return Err(PoolError::InvalidTx(transaction::Error::TooHeavy));
		}

		// Summed tx weights are a conservative upper bound on the final aggregate
		// weight because cut-through can only remove inputs and outputs.
		let candidate_weight = checked_add_weight(current_weight, tx_weight)?;
		if candidate_weight > max_weight && !current_txs.is_empty() {
			fluff_txs.push(aggregate_as_transaction(context_id, &current_txs, secp)?);
			current_txs.clear();
			current_weight = 0;
		}

		current_txs.push(tx.clone());
		current_weight = checked_add_weight(current_weight, tx_weight)?;
	}

	if !current_txs.is_empty() {
		fluff_txs.push(aggregate_as_transaction(context_id, &current_txs, secp)?);
	}

	Ok(fluff_txs)
}

fn aggregate_as_transaction(
	context_id: u32,
	txs: &[transaction::Transaction],
	secp: &mut Secp256k1,
) -> Result<transaction::Transaction, PoolError> {
	let agg_tx = transaction::aggregate(context_id, txs, secp)?;
	agg_tx
		.validate(context_id, transaction::Weighting::AsTransaction, secp)
		.map_err(PoolError::InvalidTx)?;
	Ok(agg_tx)
}

fn checked_add_weight(current_weight: u64, tx_weight: u64) -> Result<u64, PoolError> {
	current_weight.checked_add(tx_weight).ok_or_else(|| {
		PoolError::InvalidTx(transaction::Error::DataOverflow(format!(
			"aggregate_fluffable_txs weight overflow, current_weight={} tx_weight={}",
			current_weight, tx_weight
		)))
	})
}

fn process_expired_entries(
	dandelion_config: &DandelionConfig,
	tx_pool: &ServerTxPool,
	secp: &mut Secp256k1,
) -> Result<(), PoolError> {
	// Take a write lock on the txpool for the duration of this processing.
	let mut tx_pool = tx_pool.write();

	let embargo_secs = dandelion_config.embargo_secs as u32 + rng().random_range(0..31);
	let expired_entries = select_txs_cutoff(&tx_pool.stempool, embargo_secs);

	if expired_entries.is_empty() {
		return Ok(());
	}

	debug!("dand_mon: Found {} expired txs.", expired_entries.len());

	let header = tx_pool.chain_head()?;
	let context_id = tx_pool.get_context_id();

	for entry in expired_entries {
		let txhash = entry.tx.hash(context_id)?;
		match tx_pool.add_to_pool(
			TxSource::EmbargoExpired,
			entry.tx.clone(),
			false,
			&header,
			secp,
		) {
			Ok(_) => info!(
				"dand_mon: embargo expired for {}, fluffed successfully.",
				txhash
			),
			Err(e) => {
				warn!(
					"dand_mon: failed to fluff expired tx {}, evicting from stempool: {:?}",
					txhash, e
				);
				tx_pool.stempool.remove_tx(&entry.tx)?;
			}
		};
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::core::KernelFeatures;
	use mwc_core::global;
	use mwc_core::libtx::{build, ProofBuilder};
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::secp::{ContextFlag, SecretKey};
	use mwc_keychain::{ExtKeychain, Keychain};
	use std::convert::TryInto;

	fn test_transaction(
		secp: &mut Secp256k1,
		keychain: &ExtKeychain,
		idx: u32,
	) -> transaction::Transaction {
		let input_key_id = ExtKeychain::derive_key_id(1, 10_000 + idx, 0, 0, 0).unwrap();
		let output_key_id = ExtKeychain::derive_key_id(1, 20_000 + idx, 0, 0, 0).unwrap();
		let builder = ProofBuilder::new(secp, keychain).unwrap();

		build::transaction(
			0,
			secp,
			KernelFeatures::Plain {
				fee: 10u32.try_into().unwrap(),
			},
			&[
				build::input(1_000 + u64::from(idx), input_key_id),
				build::output(990 + u64::from(idx), output_key_id),
			],
			keychain,
			&builder,
		)
		.unwrap()
	}

	#[test]
	fn aggregate_fluffable_txs_splits_oversized_aggregate() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);

		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let keychain =
			ExtKeychain::from_seed(&secp, &SecretKey::new(&secp, &mut SysRng).unwrap().0, false)
				.unwrap();
		let txs = (0..10)
			.map(|idx| test_transaction(&mut secp, &keychain, idx))
			.collect::<Vec<_>>();

		let full_aggregate = transaction::aggregate(0, &txs, &secp).unwrap();
		assert!(matches!(
			full_aggregate.validate(0, transaction::Weighting::AsTransaction, &mut secp),
			Err(transaction::Error::TooHeavy)
		));

		let batches = aggregate_fluffable_txs(0, &txs, &mut secp).unwrap();
		assert!(batches.len() > 1);
		assert_eq!(
			batches.iter().map(|tx| tx.kernels().len()).sum::<usize>(),
			txs.len()
		);

		for batch in batches {
			batch
				.validate(0, transaction::Weighting::AsTransaction, &mut secp)
				.unwrap();
		}
	}
}
