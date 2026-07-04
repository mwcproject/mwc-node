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

//! Facade and handler for the rest of the blockchain implementation
//! and mostly the chain pipeline.

use crate::error::Error;
use crate::pibd_params::PibdParams;
use crate::pipe;
use crate::store;
use crate::store::{ChainOperationKind, PendingChainOperation};
use crate::txhashset;
use crate::txhashset::{Desegmenter, PMMRHandle, Segmenter, TxHashSet};
use crate::types::{
	BlockStatus, ChainAdapter, CommitPos, HashHeight, Options, SyncState, SyncStatus,
	SyncStatusUpdateThrottle, Tip, HEADERS_PER_BATCH,
};
use crate::ChainStore;
use crate::{
	store::Batch,
	txhashset::{ExtensionPair, HeaderExtension},
};
use mwc_core::consensus;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::merkle_proof::MerkleProof;
use mwc_core::core::pmmr::{ReadablePMMR, VecBackend, PMMR};
use mwc_core::core::{
	Block, BlockHeader, BlockSums, Committed, Inputs, KernelFeatures, Output, OutputIdentifier,
	Transaction, TxKernel,
};
use mwc_core::difficulty_cache::DifficultyCache;
use mwc_core::pow;
use mwc_core::ser;
use mwc_core::ser::ProtocolVersion;
use mwc_core::{genesis, global};
use mwc_crates::log::{debug, error, info, trace, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_store::types::VariableSizeMetadataValidation;
use mwc_store::Error::NotFoundErr;
use mwc_util::{StopState, ToHex};
use std::cmp::min;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{collections::HashMap, io::Cursor};

/// When evicting, very old orphans are evicted first
const MAX_ORPHAN_AGE_SECS: u64 = 3000;
const SPENT_COMMITMENT_INDEX_REBUILD_CHUNK: usize = 10_000;
const HISTORICAL_BLOCK_DELETE_CHUNK: usize = 100;

#[derive(Debug, Clone)]
pub struct Orphan {
	pub block: Block,
	pub opts: Options,
	pub source_peers: HashSet<String>,
	added: Instant,
}

pub struct OrphanBlockPool {
	// blocks indexed by their hash
	orphans: RwLock<HashMap<Hash, Orphan>>,
	// additional index of height -> hash
	// so we can efficiently identify a child block (ex-orphan) after processing a block
	height_idx: RwLock<HashMap<u64, Vec<Hash>>>,
	// accumulated number of evicted block because of MAX_ORPHAN_SIZE limitation
	evicted: AtomicUsize,
	pibd_params: Arc<PibdParams>,
}

impl OrphanBlockPool {
	fn new(pibd_params: Arc<PibdParams>) -> OrphanBlockPool {
		OrphanBlockPool {
			orphans: RwLock::new(HashMap::new()),
			height_idx: RwLock::new(HashMap::new()),
			evicted: AtomicUsize::new(0),
			pibd_params,
		}
	}

	fn len(&self) -> usize {
		let orphans = self.orphans.read_recursive();
		orphans.len()
	}

	fn len_evicted(&self) -> usize {
		self.evicted.load(Ordering::Relaxed)
	}

	fn add(&self, context_id: u32, orphan: Orphan) -> Result<(), Error> {
		let mut orphans = self.orphans.write();
		let mut height_idx = self.height_idx.write();
		{
			let height = orphan.block.header.height;
			let hash = orphan.block.hash(context_id)?;
			// The block hash is the header hash. Orphan bodies have not yet been
			// validated against the roots committed to by that header, so only
			// byte-identical orphan blocks can safely be deduplicated.
			if let Some(existing) = orphans.get_mut(&hash) {
				let existing_bytes =
					ser::ser_vec(context_id, &existing.block, ProtocolVersion::local())?;
				let orphan_bytes =
					ser::ser_vec(context_id, &orphan.block, ProtocolVersion::local())?;
				if existing_bytes != orphan_bytes {
					return Err(Error::Unfit(
						"conflicting orphan body for header".to_owned(),
					));
				}

				existing.source_peers.extend(orphan.source_peers);
			} else {
				orphans.insert(hash.clone(), orphan);
				let height_hashes = height_idx.entry(height).or_insert_with(|| vec![]);
				height_hashes.push(hash);
			}
		}

		let orphans_num_limit = self.pibd_params.get_orphans_num_limit();
		if orphans.len() > orphans_num_limit {
			let old_len = orphans.len();

			// evict too old
			orphans.retain(|_, ref mut x| {
				x.added.elapsed() < Duration::from_secs(MAX_ORPHAN_AGE_SECS)
			});
			// Evict too far ahead by whole height buckets. This is a hot
			// in-memory cache path, and height buckets are the optimal unit for
			// orphan lookup and cleanup after a parent block is accepted.
			let mut heights = height_idx.keys().cloned().collect::<Vec<u64>>();
			heights.sort_unstable();
			for h in heights.iter().rev() {
				if let Some(hs) = height_idx.remove(h) {
					for h in hs {
						let _ = orphans.remove(&h);
					}
				}
				// We intentionally evict until we are below the limit, not
				// exactly at it. The extra headroom delays the next eviction
				// pass and keeps this cache path cheaper under load.
				if orphans.len() < orphans_num_limit {
					break;
				}
			}
			// Cleanup index buckets cheaply. Mixed buckets may keep stale
			// hashes; later removals filter through `orphans`, and avoiding a
			// full rebuild keeps this cache path fast.
			height_idx.retain(|_, ref mut xs| xs.iter().any(|x| orphans.contains_key(&x)));

			self.evicted
				.fetch_add(old_len - orphans.len(), Ordering::Relaxed);
		}
		Ok(())
	}

	/// Get an orphan from the pool indexed by the hash of its parent, removing
	/// it at the same time, preventing clone
	fn remove_by_height(&self, height: u64) -> Option<Vec<Orphan>> {
		let mut orphans = self.orphans.write();
		let mut height_idx = self.height_idx.write();
		height_idx
			.remove(&height)
			.map(|hs| hs.iter().filter_map(|h| orphans.remove(h)).collect())
	}

	fn remove_by_height_header_hash(&self, height: u64, header_hash: &Hash) -> Option<Orphan> {
		let mut orphans = self.orphans.write();
		let mut height_idx = self.height_idx.write();

		if !orphans.contains_key(header_hash) {
			return None;
		}

		if let Some(mut hash_by_height) = height_idx.remove(&height) {
			hash_by_height.retain(|&hash| hash != *header_hash);
			if !hash_by_height.is_empty() {
				height_idx.insert(height.clone(), hash_by_height);
			}
		}

		return orphans.remove(&header_hash);
	}

	/// Get list of ophan's hashes
	pub fn get_orphan_list(&self) -> HashSet<Hash> {
		self.orphans
			.read_recursive()
			.iter()
			.map(|(k, _v)| k.clone())
			.collect()
	}

	/// Check if orphans is in the list
	pub fn contains(&self, hash: &Hash) -> bool {
		self.orphans.read_recursive().contains_key(hash)
	}

	/// Request orphan by hash
	pub fn get_orphan(&self, hash: &Hash) -> Option<Orphan> {
		self.orphans.read_recursive().get(hash).map(|o| o.clone())
	}

	/// Request orphan height and prev block hash. Alternative to get_orphan without much data copy
	pub fn get_orphan_height_prev_hash(&self, hash: &Hash) -> Option<(Hash, u64)> {
		self.orphans
			.read_recursive()
			.get(hash)
			.map(|o| (o.block.header.prev_hash.clone(), o.block.header.height))
	}
}

/// Facade to the blockchain block processing pipeline and storage. Provides
/// the current view of the TxHashSet according to the chain state. Also
/// maintains locking for the pipeline to avoid conflicting processing.
pub struct Chain {
	db_root: String,
	store: Arc<store::ChainStore>, // Lock order (with childrer):   3
	adapter: Arc<dyn ChainAdapter + Send + Sync>,
	orphans: Arc<OrphanBlockPool>,
	txhashset: Arc<RwLock<txhashset::TxHashSet>>, // Lock order (with childrer):   2
	header_pmmr: Arc<RwLock<txhashset::PMMRHandle<BlockHeader>>>, // Lock order  (with childrer):  1
	pibd_segmenter: Arc<RwLock<Option<Segmenter>>>,
	// POW verification function
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
	archive_mode: bool,
	genesis: Block,
	cache_header_difficulty: Arc<RwLock<DifficultyCache>>,
	pibd_params: Arc<PibdParams>,
	requires_init_recovery: Arc<AtomicBool>,
}

impl Chain {
	fn ensure_chain_robust(&self) -> Result<(), Error> {
		if self.requires_init_recovery.load(Ordering::SeqCst) {
			warn!("chain marked as requiring init recovery; attempting recovery before continuing");
			self.recover_pending_chain_operation_checked("ensure_chain_robust")?;
		}
		Ok(())
	}

	fn with_robust_header_pmmr_read<T, F>(&self, f: F) -> Result<T, Error>
	where
		F: Fn(&PMMRHandle<BlockHeader>) -> Result<T, Error>,
	{
		self.ensure_chain_robust()?;
		loop {
			let header_pmmr = self.header_pmmr.read_recursive();
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}
			return f(&header_pmmr);
		}
	}

	fn with_robust_chain_read<T, F>(&self, f: F) -> Result<T, Error>
	where
		F: Fn(&PMMRHandle<BlockHeader>, &TxHashSet) -> Result<T, Error>,
	{
		self.ensure_chain_robust()?;
		loop {
			let header_pmmr = self.header_pmmr.read_recursive();
			let txhashset = self.txhashset.read_recursive();
			// A writer may have failed while this reader was waiting for locks.
			// Do not read txhashset/header state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}
			return f(&header_pmmr, &txhashset);
		}
	}

	fn ensure_header_pmmr_locked_for_marker(&self, op_name: &str) -> Result<(), Error> {
		// Defensive invariant check: parking_lot does not expose lock ownership,
		// so this proves only that the lock is not currently free.
		if let Some(header_pmmr) = self.header_pmmr.try_write() {
			drop(header_pmmr);
			return Err(Error::Other(format!(
				"{} attempted to set a chain operation marker without holding header_pmmr lock",
				op_name
			)));
		}
		Ok(())
	}

	fn set_pending_chain_operation_checked(&self, op: &PendingChainOperation) -> Result<(), Error> {
		self.ensure_header_pmmr_locked_for_marker("set_pending_chain_operation")?;
		match self.store.set_pending_chain_operation(op) {
			Ok(()) => Ok(()),
			Err(e) => Err(e.into()),
		}
	}

	fn clear_pending_chain_operation_checked(&self) -> Result<(), Error> {
		match self.store.clear_pending_chain_operation() {
			Ok(()) => Ok(()),
			Err(e) => {
				self.requires_init_recovery.store(true, Ordering::SeqCst);
				Err(e.into())
			}
		}
	}

	fn recover_pending_chain_operation_checked(&self, recovery_context: &str) -> Result<(), Error> {
		warn!("attempting recovery: {}", recovery_context);
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		match recover_pending_chain_operation(
			&self.genesis,
			&self.store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
		) {
			Ok(()) => {
				self.requires_init_recovery.store(false, Ordering::SeqCst);
				Ok(())
			}
			Err(e) => {
				error!(
					"{} failed to recover pending chain operation: {}",
					recovery_context, e
				);
				Err(e)
			}
		}
	}

	fn handle_failed_pending_chain_operation(&self, op_name: &str, e: &Error) {
		warn!(
			"{} failed after marker was set; will attempting recovery: {}",
			op_name, e
		);
		self.requires_init_recovery.store(true, Ordering::SeqCst);
	}

	fn set_readonly_pmmr_discard_marker(&self, op_name: &str) -> Result<bool, Error> {
		if self.store.pending_chain_operation()?.is_some() {
			trace!(
				"{} using existing pending chain operation marker for readonly PMMR discard recovery",
				op_name
			);
			return Ok(false);
		}

		let op = prepare_reconcile_heads_operation(
			&self.store,
			ChainOperationKind::ReadonlyPmmrDiscard,
		)?;
		let marker_set = self.store.set_pending_chain_operation_if_absent(&op)?;
		if marker_set {
			trace!(
				"{} set readonly PMMR discard recovery marker before operation",
				op_name
			);
		} else {
			trace!(
				"{} using concurrently-set pending chain operation marker for readonly PMMR discard recovery",
				op_name
			);
		}
		Ok(marker_set)
	}

	fn finish_readonly_pmmr_discard_marker<T>(
		&self,
		op_name: &str,
		res: Result<T, Error>,
		marker_set: bool,
	) -> Result<T, Error> {
		match res {
			Ok(res) => {
				if marker_set {
					self.clear_pending_chain_operation_checked()?;
				}
				Ok(res)
			}
			Err(e) => {
				if e.is_txhashset_discard_failure() {
					error!(
						"{} failed to discard txhashset/header PMMR changes; chain marked for recovery: {}",
						op_name, e
					);
					self.requires_init_recovery.store(true, Ordering::SeqCst);
					Err(e)
				} else if marker_set {
					match self.clear_pending_chain_operation_checked() {
						Ok(()) => Err(e),
						Err(clear_err) => {
							error!(
								"{} failed before readonly PMMR state changed: {}; additionally failed to clear readonly PMMR discard recovery marker: {}",
								op_name, e, clear_err
							);
							// Keep the primary operation error as the caller-visible result.
							// clear_pending_chain_operation_checked() marks init recovery on failure;
							// the clear failure is logged here for diagnostics.
							Err(e)
						}
					}
				} else {
					Err(e)
				}
			}
		}
	}

	// Caller must hold the PMMR lock(s) for the readonly operation before
	// setting this marker. This keeps marker lifetime serialized with the
	// operation that can fail to discard PMMR state.
	fn with_locked_readonly_pmmr_discard_marker<T, F>(
		&self,
		op_name: &str,
		f: F,
	) -> Result<T, Error>
	where
		F: FnOnce() -> Result<T, Error>,
	{
		self.ensure_header_pmmr_locked_for_marker(op_name)?;

		let marker_set = self.set_readonly_pmmr_discard_marker(op_name)?;
		let res = f();
		self.finish_readonly_pmmr_discard_marker(op_name, res, marker_set)
	}

	fn finish_pending_chain_operation<T>(
		&self,
		op_name: &str,
		res: Result<T, Error>,
		state_may_have_changed: bool,
	) -> Result<T, Error> {
		match res {
			Ok(res) => {
				self.clear_pending_chain_operation_checked()?;
				Ok(res)
			}
			Err(e) => {
				if state_may_have_changed || e.is_txhashset_discard_failure() {
					self.handle_failed_pending_chain_operation(op_name, &e);
					Err(e)
				} else {
					match self.clear_pending_chain_operation_checked() {
						Ok(()) => Err(e),
						Err(clear_err) => {
							error!(
								"{} failed before chain state changed: {}; additionally failed to clear pending chain operation marker: {}",
								op_name, e, clear_err
							);
							// Returning original error, clear error doesn't matter for caller
							Err(e)
						}
					}
				}
			}
		}
	}

	/// Initializes the blockchain and returns a new Chain instance. Does a
	/// check on the current chain head to make sure it exists and creates one
	/// based on the genesis block if necessary.
	pub fn init(
		secp: &Secp256k1,
		context_id: u32,
		db_root: String,
		adapter: Arc<dyn ChainAdapter + Send + Sync>,
		genesis: Block,
		pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
		archive_mode: bool,
		invalid_blocks: HashSet<Hash>,
		sync_state: Option<Arc<SyncState>>,
		stop_state: Option<Arc<StopState>>,
	) -> Result<Chain, Error> {
		validate_genesis_for_init(secp, context_id, &genesis, pow_verifier)?;

		let store = Arc::new(store::ChainStore::new(context_id, &db_root)?);

		let pibd_params = Arc::new(PibdParams::new());

		// DB migrations to be run prior to the chain being used.
		// Migrate full blocks to protocol version v3.
		Chain::migrate_db_v2_v3(&store)?;

		// open the txhashset, creating a new one if necessary
		let mut txhashset =
			txhashset::TxHashSet::open(db_root.clone(), store.clone(), None, &secp)?;

		let mut header_pmmr = PMMRHandle::new(
			Path::new(&db_root).join("header").join("header_head"),
			false,
			ProtocolVersion(1),
			context_id,
			None,
			VariableSizeMetadataValidation::Full,
		)?;

		recover_pending_chain_operation(&genesis, &store, &mut header_pmmr, &mut txhashset, secp)?;

		setup_head(
			&genesis,
			&store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
			None,
		)?;

		// Initialize the output_pos index based on UTXO set
		// and NRD kernel_pos index based recent kernel history.
		let kernel_pos_index_complete = {
			let batch = store.batch_write()?;
			if batch.is_output_pos_index_complete()? {
				debug!("init: output_pos index is complete, skipping rebuild");
			} else {
				txhashset.init_output_pos_index(&batch, sync_state.clone(), stop_state.clone())?;
			}
			txhashset.init_recent_kernel_pos_index(
				&header_pmmr,
				&batch,
				sync_state.clone(),
				stop_state.clone(),
			)?;
			let complete = batch.is_kernel_pos_index_complete()?;
			batch.commit()?;
			complete
		};
		if !kernel_pos_index_complete {
			txhashset.init_kernel_pos_index_chunked(
				&store,
				sync_state.clone(),
				stop_state.clone(),
			)?;
		}
		Chain::init_spent_commitment_index(&store)?;

		let chain = Chain {
			db_root,
			store,
			adapter,
			orphans: Arc::new(OrphanBlockPool::new(pibd_params.clone())),
			txhashset: Arc::new(RwLock::new(txhashset)),
			header_pmmr: Arc::new(RwLock::new(header_pmmr)),
			pibd_segmenter: Arc::new(RwLock::new(None)),
			pow_verifier,
			archive_mode,
			genesis: genesis,
			cache_header_difficulty: Arc::new(RwLock::new(DifficultyCache::new())),
			pibd_params,
			requires_init_recovery: Arc::new(AtomicBool::new(false)),
		};

		chain.apply_invalid_blocks(secp, invalid_blocks)?;

		Ok(chain)
	}

	/// Apply and set invalid blocks data.
	pub fn apply_invalid_blocks(
		&self,
		secp: &Secp256k1,
		invalid_blocks: HashSet<Hash>,
	) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		// Publish the denylist before rewinding so concurrent block/header
		// processing cannot re-accept the denied hash after the rewind.
		pipe::init_invalid_block_hashes(self.get_context_id(), invalid_blocks.clone());
		self.rewind_bad_block(secp, &invalid_blocks)?;
		self.log_heads()?;
		Ok(())
	}

	/// Pibd params with envoronment monitoring
	pub fn get_pibd_params(&self) -> &Arc<PibdParams> {
		&self.pibd_params
	}

	/// Reset chain to be ready to download data with PIBD
	pub fn reset_pibd_chain(&self) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;

		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		self.set_pending_chain_operation_checked(&PendingChainOperation::PibdReset)?;
		let res = reset_pibd_chain_state(
			&self.genesis,
			&self.store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
		);

		match res {
			Ok(()) => {
				self.clear_pending_chain_operation_checked()?;
				Ok(())
			}
			Err(e) => {
				self.handle_failed_pending_chain_operation("reset_pibd_chain", &e);
				Err(e)
			}
		}
	}

	/// Reset both head and header_head to the provided header.
	/// Handles simple rewind and more complex fork scenarios.
	/// Used by the reset_chain_head owner api endpoint.
	/// Caller can choose not to rewind headers, which can be used
	/// during PIBD scenarios where it's desirable to restart the PIBD process
	/// without re-downloading the header chain
	pub fn reset_chain_head(
		&self,
		secp: &Secp256k1,
		header: &BlockHeader,
		rewind_headers: bool,
	) -> Result<(), Error> {
		self.ensure_chain_robust()?;

		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		let op = prepare_reset_chain_head_operation(&self.store, header, rewind_headers)?;
		self.set_pending_chain_operation_checked(&op)?;
		let res = reset_chain_head_state(
			&self.store,
			&mut header_pmmr,
			&mut txhashset,
			secp,
			header,
			rewind_headers,
		);

		match res {
			Ok(()) => {
				self.clear_pending_chain_operation_checked()?;
				Ok(())
			}
			Err(e) => {
				self.handle_failed_pending_chain_operation("reset_chain_head", &e);
				Err(e)
			}
		}
	}

	/// wipes the chain head down to genesis, without attempting to rewind
	/// Used upon PIBD failure, where we want to keep the header chain but
	/// restart the output PMMRs from scratch
	pub fn reset_chain_head_to_genesis(&self) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		let mut header_pmmr = self.header_pmmr.write();
		let mut txhashset = self.txhashset.write();
		self.set_pending_chain_operation_checked(&PendingChainOperation::ResetToGenesis)?;
		let res = reset_chain_head_to_genesis_state(
			&self.genesis,
			&self.store,
			&mut header_pmmr,
			&mut txhashset,
			&secp,
		);
		match res {
			Ok(()) => {
				self.clear_pending_chain_operation_checked()?;
				Ok(())
			}
			Err(e) => {
				self.handle_failed_pending_chain_operation("reset_chain_head_to_genesis", &e);
				Err(e)
			}
		}
	}

	/// Are we running with archive_mode enabled?
	pub fn archive_mode(&self) -> bool {
		self.archive_mode
	}

	/// Return our shared header MMR handle.
	/// Note, caller is responsible for locking in correct order. See the comment at declaration
	#[cfg(test)]
	pub fn get_header_pmmr_for_test(&self) -> Arc<RwLock<PMMRHandle<BlockHeader>>> {
		self.header_pmmr.clone()
	}

	/// Return our shared txhashset instance.
	/// Note, caller is responsible for locking in correct order. See the comment at declaration
	#[cfg(test)]
	pub fn get_txhashset_for_test(&self) -> Arc<RwLock<TxHashSet>> {
		self.txhashset.clone()
	}

	/// return genesis header
	pub fn genesis(&self) -> BlockHeader {
		self.genesis.header.clone()
	}

	/// Shared store instance.
	/// Note, caller is responsible for locking in correct order. See the comment at declaration
	#[cfg(test)]
	pub fn get_store_for_tests(&self) -> Arc<store::ChainStore> {
		self.store.clone()
	}

	/// Known bad block that we must rewind prior to if seen on "current chain".
	pub fn rewind_bad_block(
		&self,
		secp: &Secp256k1,
		invalid_blocks: &HashSet<Hash>,
	) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		for hash in invalid_blocks {
			let header = match self.get_block_header(hash) {
				Ok(header) => header,
				Err(Error::StoreErr(NotFoundErr(_), _)) => continue,
				Err(e) => return Err(e),
			};

			let header_hash = header.hash(context_id)?;
			let header_tip = Tip::try_from_header(&header)?;

			loop {
				self.ensure_chain_robust()?;
				let mut header_pmmr = self.header_pmmr.write();
				// A writer may have marked recovery while this call was waiting
				// for header_pmmr. Drop the lock before attempting recovery.
				if self.requires_init_recovery.load(Ordering::SeqCst) {
					drop(header_pmmr);
					continue;
				}

				let old_header_head = self
					.store
					.header_head()
					.map_err(|e| Error::StoreErr(e, "header head".to_owned()))?;
				if !self.is_on_current_chain_with_header_pmmr(
					&header_pmmr,
					header_tip,
					old_header_head.clone(),
				)? {
					break;
				}

				debug!(
					"rewind_bad_block: found header: {} at {}",
					header_hash, header.height
				);

				let read_batch = self.store.batch_read()?;
				let mut prev_header = read_batch.get_previous_header(&header)?;
				let mut skipped_denied_ancestors = Vec::new();
				// A stronger implementation could batch all denied current-chain
				// blocks into one atomic rewind, but validation is expected to
				// report a single bad block in normal operation. Keep this per-hash
				// path, but do not choose a rewind target that is also denied if a
				// HashSet happens to visit adjacent bad blocks descendant-first.
				while invalid_blocks.contains(&prev_header.hash(context_id)?) {
					skipped_denied_ancestors.push(prev_header.clone());
					prev_header = read_batch.get_previous_header(&prev_header)?;
				}
				drop(read_batch);
				let new_head = Tip::try_from_header(&prev_header)?;

				let op = prepare_reconcile_heads_operation(
					&self.store,
					ChainOperationKind::RewindBadBlock,
				)?;
				self.set_pending_chain_operation_checked(&op)?;
				let res = (|| {
					let read_batch = self.store.batch_read()?;
					let body_head = read_batch
						.head()
						.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))?;
					let mut body_rewind_header =
						if self.is_on_body_chain_with_batch(&read_batch, &header, &body_head)? {
							Some(header.clone())
						} else {
							None
						};
					for skipped_header in &skipped_denied_ancestors {
						if body_rewind_header.is_none()
							&& self.is_on_body_chain_with_batch(
								&read_batch,
								skipped_header,
								&body_head,
							)? {
							body_rewind_header = Some(skipped_header.clone());
						}
					}
					let body_block = if let Some(body_rewind_header) = body_rewind_header {
						let body_rewind_hash = body_rewind_header.hash(context_id)?;
						match read_batch.get_block(&body_rewind_hash) {
							Ok(block) => Some(block),
							Err(e @ NotFoundErr(_)) => {
								warn!(
									"rewind_bad_block: denied block {} at height {} is on the body chain \
									but the full block is missing; cannot safely rewind HEAD/txhashset",
									body_rewind_hash, body_rewind_header.height
								);
								return Err(Error::StoreErr(e, "chain get block".to_owned()));
							}
							Err(e) => {
								return Err(Error::StoreErr(e, "chain get block".to_owned()));
							}
						}
					} else {
						None
					};
					drop(read_batch);

					if let Some(block) = body_block {
						// Fix the (full) block chain.
						debug!(
							"rewind_bad_block: denied block {} at {} is on the body chain",
							block.hash(context_id)?,
							block.header.height
						);

						debug!(
							"rewind_bad_block: rewinding to prev: {} at {}",
							prev_header.hash(context_id)?,
							prev_header.height
						);

						let mut txhashset = self.txhashset.write();
						let mut batch = self.store.batch_write()?;

						let old_head = batch.head()?;

						txhashset::extending(
							&mut header_pmmr,
							&mut txhashset,
							&mut batch,
							|ext, batch| {
								self.rewind_and_apply_fork(secp, &prev_header, ext, batch)?;

								// Ensure the rewound txhashset actually matches the header
								// we are about to make active.
								ext.extension.validate_roots(&prev_header)?;
								ext.extension.validate_sizes(&prev_header)?;

								// Reset chain head.
								batch.save_body_head(&new_head)?;
								batch.save_header_head(&new_head)?;

								Ok(())
							},
						)?;

						// Cleanup all subsequent bad blocks (back from old head).
						let mut current = batch.get_block_header(&old_head.hash(context_id)?)?;
						while current.height > new_head.height {
							let prev_block = batch.get_previous_header(&current)?;
							batch.delete_block(&current.hash(context_id)?)?;
							current = prev_block;
						}

						batch.commit()?;
					} else {
						debug!(
							"rewind_bad_block: denied header {} at {} is only on the header chain",
							header_hash, header.height
						);
					}

					let mut batch = self.store.batch_write()?;

					txhashset::header_extending(&mut header_pmmr, &mut batch, |ext, batch| {
						self.rewind_and_apply_header_fork(&prev_header, ext, batch)?;

						// Reset chain head.
						batch.save_header_head(&new_head)?;

						Ok(())
					})?;

					// Use the header head captured under the header_pmmr lock, before
					// the body rewind above.
					// When the denied hash is also on the full-block chain, the body
					// rewind saves HEADER_HEAD to new_head before this branch starts.
					// Reading header_head here would then make old_header_head == new_head,
					// causing the cleanup loop to delete no denied successor headers.
					let mut current = batch.get_block_header(&old_header_head.hash(context_id)?)?;
					while current.height > new_head.height {
						let prev_hdr = batch.get_previous_header(&current)?;
						batch.delete_block_header(&current.hash(context_id)?)?;
						current = prev_hdr;
					}

					batch.commit()?;

					Ok(())
				})();
				match res {
					Ok(()) => self.clear_pending_chain_operation_checked()?,
					Err(e) => {
						self.handle_failed_pending_chain_operation("rewind_bad_block", &e);
						return Err(e);
					}
				}
				break;
			}
		}

		Ok(())
	}

	fn log_heads(&self) -> Result<(), Error> {
		let log_head = |name, head: Tip| -> Result<(), Error> {
			debug!(
				"{}: {} @ {} [{}]",
				name,
				head.total_difficulty.to_num(),
				head.height,
				head.hash(self.store.get_context_id())?,
			);
			Ok(())
		};
		log_head("head", self.head()?)?;
		let sync_head = self.header_head()?;
		log_head("header_head", sync_head)?;

		// Needed for Node State tracking...
		info!(
			"init: sync_head: {} @ {} [{}]",
			sync_head.total_difficulty.to_num(),
			sync_head.height,
			sync_head.last_block_h,
		);

		Ok(())
	}

	/// Processes a single block, then checks for orphans, processing
	/// those as well if they're found
	pub fn process_block(
		&self,
		secp: &mut Secp256k1,
		b: Block,
		opts: Options,
		source_peers: HashSet<String>,
	) -> Result<Option<Tip>, Error> {
		self.ensure_chain_robust()?;
		let block_hash = b.hash(self.store.get_context_id())?;
		let report_peers = source_peers.clone();

		// Check if block can be processed now. Overwise add it to orphans and returns error
		if let Err(e) = self.check_block(&b, opts, source_peers) {
			if e.is_bad_data() && !report_peers.is_empty() {
				self.adapter.block_rejected(&block_hash, &report_peers, &e);
			}
			return Err(e);
		}

		// block is not orphnan and it is great
		// Let's try to add several blocks from the current active branch. Adding many in a single
		// transaction is good for performance.
		let mut blocks: Vec<Block> = vec![];

		// We can't process as multiple during sync because it is slow.
		// But also we better to process blocks one by one when node running because of possible reorg.
		// Reord requires to roll back single block, not a whole package.
		let multiple_processing_height_limit = self.header_head()?.height.saturating_sub(100);
		if b.header.height < multiple_processing_height_limit {
			// if it is a block on the chain, let's try to add many of them
			match self.get_header_by_height(b.header.height) {
				Ok(header) => {
					let context_id = self.store.get_context_id();
					// this block is expected to be from the main chain, we are expecting approve long sequence, not a short branch
					if header.hash(context_id)? == b.hash(context_id)? {
						blocks.push(b.clone());
						loop {
							let last_block = blocks.last().ok_or(Error::Other(
								"Internal error, no blocks at process_block".into(),
							))?;
							let next_hegiht =
								last_block.header.height.checked_add(1).ok_or_else(|| {
									Error::DataOverflow(format!(
										"Chain::process_block, last_block.header.height={}",
										last_block.header.height
									))
								})?;
							match self.get_header_by_height(next_hegiht) {
								Ok(header) => {
									if let Some(orphan) =
										self.orphans.get_orphan(&header.hash(context_id)?)
									{
										blocks.push(orphan.block);
										continue; // can process the next block
									}
								}
								Err(e) if e.is_not_found() => {}
								Err(e) => return Err(e),
							}
							break;
						}
						if blocks
							.last()
							.ok_or(Error::Other(
								"Process block internal error, collection was empty".into(),
							))?
							.header
							.height < multiple_processing_height_limit
						{
							// good, we can process multiple blocks, it should be faster than one by one
							let mut block_hashes: Vec<(u64, Hash)> = Vec::new();
							for b in &blocks {
								block_hashes.push((b.header.height, b.hash(context_id)?));
							}
							match self.process_block_multiple(secp, &blocks, opts) {
								Ok(tip) => {
									info!(
										"Accepted multiple blocks from {} to {}",
										blocks.first().map(|b| b.header.height).unwrap_or(0),
										blocks.last().map(|b| b.header.height).unwrap_or(0)
									);
									// We are good, let's clean up the orphans
									for (height, hash) in block_hashes {
										let _ = self
											.orphans
											.remove_by_height_header_hash(height, &hash);
									}
									return Ok(tip); // Done with success
								}
								Err(e) => {
									self.ensure_chain_robust()?;
									if e.is_bad_data() {
										info!("Failed to process multiple blocks, will try process one by one. {}",e);
									} else {
										debug!("Failed to process multiple blocks, will try process one by one. {}",e);
									}
								}
							}
						}
					}
				}
				Err(e) if e.is_not_found() => {}
				Err(e) => return Err(e),
			}
		}

		// Processing blocks one by one. It is slower, but any possible error will be caught on block level.
		let height = b.header.height;
		match self.process_block_single(secp, b, opts) {
			Ok(tip) => {
				let next_height = height.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!("Chain::process_block, height={}", height))
				})?;
				self.check_orphans(secp, next_height)?;
				return Ok(tip);
			}
			Err(e) => {
				if e.is_bad_data() {
					error!("process_block_single failed with error: {}", e);
					if !report_peers.is_empty() {
						self.adapter.block_rejected(&block_hash, &report_peers, &e);
					}
				} else {
					debug!("process_block_single failed with error: {}", e);
				}
				return Err(e);
			}
		}
	}

	/// We plan to support receiving blocks with CommitOnly inputs.
	/// We also need to support relaying blocks with FeaturesAndCommit inputs to peers.
	/// So we need a way to convert blocks from CommitOnly to FeaturesAndCommit.
	/// Validating the inputs against the utxo_view allows us to look the outputs up.
	pub fn convert_block_v2(&self, secp: &Secp256k1, block: Block) -> Result<Block, Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		debug!(
			"convert_block_v2: {} at {} ({} -> v2)",
			block.header.hash(context_id)?,
			block.header.height,
			block.inputs().version_str(),
		);

		if block.inputs().is_empty() {
			return Ok(Block {
				header: block.header,
				body: block
					.body
					.replace_inputs(self.get_context_id(), Inputs::FeaturesAndCommit(vec![]))?,
			});
		}

		let inputs: Vec<_> = {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			self.with_locked_readonly_pmmr_discard_marker("convert_block_v2", || {
				txhashset::extending_readonly(
					self.store.get_context_id(),
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						let previous_header = batch.get_previous_header(&block.header)?;
						self.rewind_and_apply_fork(secp, &previous_header, ext, batch)?;
						ext.extension
							.utxo_view(ext.header_extension)
							.validate_inputs(&block.inputs(), batch)
							.map(|outputs| outputs.into_iter().map(|(out, _)| out).collect())
					},
				)
			})
		}?;
		let inputs = Inputs::from_output_identifiers(context_id, inputs.as_slice())?;
		Ok(Block {
			header: block.header,
			body: block.body.replace_inputs(self.get_context_id(), inputs)?,
		})
	}

	fn determine_status(
		&self,
		head: Option<Tip>,
		prev: Tip,
		prev_head: Tip,
		fork_point: Tip,
	) -> Result<BlockStatus, Error> {
		// If head is updated then we are either "next" block or we just experienced a "reorg" to new head.
		// Otherwise this is a "fork" off the main chain.
		if head.is_some() {
			let context_id = self.store.get_context_id();
			let fork_point_is_prev_head = fork_point.height == prev_head.height
				&& fork_point.hash(context_id)? == prev_head.hash(context_id)?;

			if fork_point_is_prev_head {
				Ok(BlockStatus::Next { prev })
			} else {
				Ok(BlockStatus::Reorg {
					prev,
					prev_head,
					fork_point,
				})
			}
		} else {
			Ok(BlockStatus::Fork {
				prev,
				head: prev_head,
				fork_point,
			})
		}
	}

	/// Quick check for "known" duplicate block up to and including current chain head.
	/// Returns an error if this block is "known".
	pub fn is_known(&self, header: &BlockHeader) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		let head = self.head()?;
		let header_hash = header.hash(context_id)?;
		if head.hash(context_id)? == header_hash {
			return Err(Error::Unfit("duplicate block".into()));
		}
		if header.total_difficulty() <= head.total_difficulty {
			if self.block_exists(&header_hash)? {
				return Err(Error::Unfit("duplicate block".into()));
			}
		}
		Ok(())
	}

	fn check_exact_known_block(&self, b: &Block) -> Result<(), Error> {
		let context_id = self.store.get_context_id();
		let bh = b.hash(context_id)?;
		let existing = match self.store.get_block(&bh) {
			Ok(existing) => existing,
			Err(NotFoundErr(_)) => return Ok(()),
			Err(e) => return Err(Error::StoreErr(e, "chain get exact known block".to_owned())),
		};

		let existing_bytes = ser::ser_vec(context_id, &existing, ProtocolVersion::local())?;
		let incoming_bytes = ser::ser_vec(context_id, b, ProtocolVersion::local())?;
		if existing_bytes != incoming_bytes {
			return Ok(());
		}

		let head = self.head()?;
		if bh == head.last_block_h || bh == head.prev_block_h {
			Err(Error::Unfit("already known in head".into()))
		} else if b.header.total_difficulty() > head.total_difficulty {
			// Stored blocks with more work may need to be applied again after a
			// reset or when a fork becomes the active body chain.
			Ok(())
		} else if b.header.height < head.height.saturating_sub(50) {
			Err(Error::OldBlock)
		} else {
			Err(Error::Unfit("already known in store".into()))
		}
	}

	// Check if the provided block is an orphan.
	// If block is an orphan add it to our orphan block pool for deferred processing.
	// If this is the "next" block immediately following current head then not an orphan.
	// Or if we have the previous full block then not an orphan.
	fn check_orphan(
		&self,
		block: &Block,
		opts: Options,
		source_peers: HashSet<String>,
	) -> Result<(), Error> {
		let head = self.head()?;
		let is_next = block.header.prev_hash == head.last_block_h;
		if is_next || self.block_exists(&block.header.prev_hash)? {
			return Ok(());
		}

		let context_id = self.store.get_context_id();
		let block_hash = block.hash(context_id)?;
		let orphan = Orphan {
			block: block.clone(),
			opts,
			source_peers,
			added: Instant::now(),
		};
		self.orphans.add(context_id, orphan)?;

		debug!(
			"is_orphan: {:?}, # orphans {}{}",
			block_hash,
			self.orphans.len(),
			if self.orphans.len_evicted() > 0 {
				format!(", # evicted {}", self.orphans.len_evicted())
			} else {
				String::new()
			},
		);

		Err(Error::Orphan(String::new()))
	}

	// Check block is starting routine from process_block_single.
	// It is separated because we are using it to deted if block is orphan
	fn check_block(
		&self,
		b: &Block,
		opts: Options,
		source_peers: HashSet<String>,
	) -> Result<(), Error> {
		// Process the header first.
		// If invalid then fail early.
		// If valid then continue with block processing with header_head committed to db etc.
		self.process_block_header(&b.header, opts)?;

		// Only exact full-block duplicates are accepted as known here. The block
		// hash is proof-derived, so a same-hash block with different serialized
		// body/header bytes must continue into normal validation.
		self.check_exact_known_block(b)?;

		// Check if this block is an orphan.
		// Only do this once we know the header PoW is valid.
		self.check_orphan(b, opts, source_peers)?;

		Ok(())
	}

	/// Attempt to add a new block to the chain.
	/// Returns true if it has been added to the longest chain
	/// or false if it has added to a fork (or orphan?).
	fn process_block_single(
		&self,
		secp: &mut Secp256k1,
		b: Block,
		opts: Options,
	) -> Result<Option<Tip>, Error> {
		let mut state_may_have_changed = false;
		let (head, fork_point, prev_head, b) = {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let op =
				prepare_reconcile_heads_operation(&self.store, ChainOperationKind::ProcessBlock)?;
			self.set_pending_chain_operation_checked(&op)?;
			let res = (|| {
				let batch = self.store.batch_write()?;
				let prev_head = batch.head()?;
				let mut ctx = self.new_ctx(opts, batch, &mut header_pmmr, &mut txhashset)?;

				let mut bv = vec![b.clone()];
				let (head, fork_point) = pipe::process_blocks_series(
					self.store.get_context_id(),
					&bv,
					&mut ctx,
					&mut state_may_have_changed,
					secp,
				)?;

				ctx.batch.commit()?;

				Ok((head, fork_point, prev_head, bv.remove(0)))
			})();
			self.finish_pending_chain_operation("process_block_single", res, state_may_have_changed)
		}?;

		let prev = self.get_previous_header(&b.header)?;
		let status = self.determine_status(
			head,
			Tip::try_from_header(&prev)?,
			prev_head,
			Tip::try_from_header(&fork_point)?,
		)?;

		info!(
			"Accepted single block {} for height {}",
			b.hash(self.store.get_context_id())?,
			b.header.height
		);
		// notifying other parts of the system of the update
		self.adapter.block_accepted(secp, &b, status, opts);

		Ok(head)
	}

	// attempt to add multiple blocks that came in the sequence from 0 first to last
	// Note, it is expected that check_block was called for all blocks at 'blocks'.
	// Since they are orphans - check_block was called to them when they were added to orphan pool.
	fn process_block_multiple(
		&self,
		secp: &mut Secp256k1,
		blocks: &Vec<Block>,
		opts: Options,
	) -> Result<Option<Tip>, Error> {
		let mut state_may_have_changed = false;
		let (head, fork_point, prev_head) = {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let op =
				prepare_reconcile_heads_operation(&self.store, ChainOperationKind::ProcessBlock)?;
			self.set_pending_chain_operation_checked(&op)?;
			let res = (|| {
				let batch = self.store.batch_write()?;
				let prev_head = batch.head()?;
				let mut ctx = self.new_ctx(opts, batch, &mut header_pmmr, &mut txhashset)?;

				let (head, fork_point) = pipe::process_blocks_series(
					self.store.get_context_id(),
					&blocks,
					&mut ctx,
					&mut state_may_have_changed,
					secp,
				)?;

				ctx.batch.commit()?;

				Ok((head, fork_point, prev_head))
			})();
			self.finish_pending_chain_operation(
				"process_block_multiple",
				res,
				state_may_have_changed,
			)
		}?;

		let last_block = blocks.last().ok_or(Error::Other(
			"Internal error, empty blocks at process_block_multiple".into(),
		))?;
		let prev = self.get_previous_header(&last_block.header)?;
		let status = self.determine_status(
			head,
			Tip::try_from_header(&prev)?,
			prev_head,
			Tip::try_from_header(&fork_point)?,
		)?;

		debug!(
			"Accepted multiple {} block from height {} to {}",
			blocks.len(),
			blocks
				.first()
				.ok_or(Error::Other(
					"Internal error, empty blocks at process_block_multiple".into()
				))?
				.header
				.height,
			blocks
				.last()
				.ok_or(Error::Other(
					"Internal error, empty blocks at process_block_multiple".into()
				))?
				.header
				.height
		);

		// Notify other parts of the system of the update.
		//
		// Known limitation: status is computed once for the whole batch, from the
		// final block, and then reused for each block notification. That means
		// prev/fork/reorg metadata is exact only for the final block in the batch.
		// Processing the batch one block at a time would avoid this, but is too
		// slow for the deep catch-up path this optimization targets.
		//
		// This path is intentionally limited by depth: process_block()
		// only calls process_block_multiple() when the final batch block is below
		// header_head - 100, so the batch tail is at least 101 blocks behind the
		// current header head. This depth guard, not the SYNC option, is what
		// makes the reused status metadata acceptable here.
		for b in blocks {
			self.adapter.block_accepted(secp, b, status, opts);
		}

		Ok(head)
	}

	/// Process a block header received during "header first" propagation.
	/// Note: This will update header MMR and corresponding header_head
	/// if total work increases (on the header chain).
	pub fn process_block_header(&self, bh: &BlockHeader, opts: Options) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let mut state_may_have_changed = false;
		{
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let op =
				prepare_reconcile_heads_operation(&self.store, ChainOperationKind::ProcessHeader)?;
			self.set_pending_chain_operation_checked(&op)?;
			let res = (|| {
				let batch = self.store.batch_write()?;
				let mut ctx = self.new_ctx(opts, batch, &mut header_pmmr, &mut txhashset)?;
				pipe::process_block_header(
					self.store.get_context_id(),
					bh,
					&mut ctx,
					&mut state_may_have_changed,
				)?;
				ctx.batch.commit()?;
				Ok(())
			})();
			self.finish_pending_chain_operation("process_block_header", res, state_may_have_changed)
		}
	}

	/// Attempt to add new headers to the header chain (or fork).
	/// This is only ever used during sync and is based on sync_head.
	/// We update header_head here if our total work increases.
	/// Returns the new sync_head (may temporarily diverge from header_head when syncing a long fork).
	pub fn sync_block_headers(
		&self,
		headers: &[BlockHeader],
		sync_head: Tip,
		opts: Options,
	) -> Result<Option<Tip>, Error> {
		self.ensure_chain_robust()?;
		{
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			let op =
				prepare_reconcile_heads_operation(&self.store, ChainOperationKind::SyncHeaders)?;
			// Set the recovery marker before validation and deliberately treat any
			// later error as recovery-worthy. Some current errors can happen before
			// PMMR or batch state changes, but this path is storage-recovery
			// sensitive: future validation changes may move mutations earlier, and
			// misclassifying a partial mutation as harmless is worse than doing an
			// unnecessary recovery pass.
			self.set_pending_chain_operation_checked(&op)?;
			let res = (|| {
				let batch = self.store.batch_write()?;

				// Sync the chunk of block headers, updating header_head if total work increases.
				let mut ctx = self.new_ctx(opts, batch, &mut header_pmmr, &mut txhashset)?;
				let sync_head = pipe::process_block_headers(
					self.store.get_context_id(),
					headers,
					sync_head,
					&mut ctx,
				)?;
				ctx.batch.commit()?;

				Ok(sync_head)
			})();
			match res {
				Ok(sync_head) => {
					self.clear_pending_chain_operation_checked()?;
					Ok(sync_head)
				}
				Err(e) => {
					self.handle_failed_pending_chain_operation("sync_block_headers", &e);
					Err(e)
				}
			}
		}
	}

	/// Build a new block processing context.
	pub fn new_ctx<'a>(
		&'a self,
		opts: Options,
		batch: store::Batch<'a>,
		header_pmmr: &'a mut txhashset::PMMRHandle<BlockHeader>,
		txhashset: &'a mut txhashset::TxHashSet,
	) -> Result<pipe::BlockContext<'a>, Error> {
		Ok(pipe::BlockContext {
			opts,
			pow_verifier: self.pow_verifier,
			header_pmmr,
			txhashset,
			batch,
			difficulty_cache: self.cache_header_difficulty.write(),
		})
	}

	/// Access to orphan pool
	pub fn get_orphans_pool(&self) -> &Arc<OrphanBlockPool> {
		&self.orphans
	}

	/// Check if hash is for a known orphan.
	pub fn is_orphan(&self, hash: &Hash) -> bool {
		self.orphans.contains(hash)
	}

	/// Get orphan data.
	pub fn get_orphan(&self, hash: &Hash) -> Option<Orphan> {
		self.orphans.get_orphan(hash)
	}

	/// Remove orphan data.
	pub fn remove_orphan(&self, height: u64, hash: &Hash) -> Option<Orphan> {
		self.orphans.remove_by_height_header_hash(height, hash)
	}

	/// Get the OrphanBlockPool accumulated evicted number of blocks
	pub fn orphans_evicted_len(&self) -> usize {
		self.orphans.len_evicted()
	}

	/// Check for orphans, once a block is successfully added
	fn check_orphans(&self, secp: &mut Secp256k1, mut height: u64) -> Result<(), Error> {
		let initial_height = height;

		// Is there an orphan in our orphans that we can now process?
		loop {
			trace!(
				"check_orphans: at {}, # orphans {}",
				height,
				self.orphans.len(),
			);

			let mut orphan_accepted = false;
			let mut height_accepted = height;

			// The orphan pool is a recoverable in-memory cache, and draining it is
			// intentionally best-effort. Many entries are expected to be stale,
			// invalid, or otherwise rejected when retried. We preserve bad-data
			// failures for peer attribution, but do not let a child orphan failure
			// make the already-accepted parent block fail. If a still-valid orphan
			// is dropped because of a validation, storage, or txhashset processing
			// error, normal sync will request the missing block again when it is
			// needed.
			if let Some(orphans) = self.orphans.remove_by_height(height) {
				let orphans_len = orphans.len();
				for (i, orphan) in orphans.into_iter().enumerate() {
					let context_id = self.store.get_context_id();
					let block_hash = orphan.block.hash(context_id)?;
					let source_peers = orphan.source_peers.clone();
					debug!(
						"check_orphans: get block {} at {}{}",
						block_hash,
						height,
						if orphans_len > 1 {
							format!(", no.{} of {} orphans", i, orphans_len)
						} else {
							String::new()
						},
					);
					let height = orphan.block.header.height;
					let res = self
						.check_block(&orphan.block, orphan.opts.clone(), source_peers.clone())
						.and_then(|_| self.process_block_single(secp, orphan.block, orphan.opts));
					match res {
						Ok(_) => {
							orphan_accepted = true;
							height_accepted = height;
						}
						Err(e) => {
							if e.is_bad_data() && !source_peers.is_empty() {
								self.adapter.block_rejected(&block_hash, &source_peers, &e);
							}
						}
					}
				}

				if orphan_accepted {
					// We accepted a block, so see if we can accept any orphans
					height = height_accepted.checked_add(1).ok_or_else(|| {
						Error::DataOverflow(format!(
							"Chain::check_orphans height_accepted={}",
							height_accepted
						))
					})?;
					continue;
				}
			}
			break;
		}

		if initial_height != height {
			debug!(
				"check_orphans: {} blocks accepted since height {}, remaining # orphans {}",
				height - initial_height,
				initial_height,
				self.orphans.len(),
			);
		}

		Ok(())
	}

	/// Returns Ok(Some((out, pos))) if output is unspent.
	/// Returns Ok(None) if output is spent.
	/// Returns Err if something went wrong beyond not finding the output.
	pub fn get_unspent(
		&self,
		commit: Commitment,
	) -> Result<Option<(OutputIdentifier, CommitPos)>, Error> {
		Ok(self
			.get_unspent_with_validated_height(commit)?
			.map(|(out, pos, _)| (out, pos)))
	}

	fn get_unspent_with_validated_height(
		&self,
		commit: Commitment,
	) -> Result<Option<(OutputIdentifier, CommitPos, BlockHeader)>, Error> {
		let mut attempted_repair = false;
		loop {
			let read_res = self.with_robust_chain_read(|header_pmmr, txhashset| {
				let batch = self
					.store
					.batch_read()
					.map_err(|e| Error::StoreErr(e, "chain get unspent batch".to_owned()))?;
				match txhashset.get_unspent(commit)? {
					Some((out, pos)) => {
						let body_head = batch
							.head()
							.map_err(|e| Error::StoreErr(e, "chain get unspent head".to_owned()))?;
						match self.body_chain_header_for_output_pos(
							header_pmmr,
							&batch,
							&body_head,
							pos,
						)? {
							Some(header) => Ok(Ok(Some((out, pos, header)))),
							None => Ok(Err(pos)),
						}
					}
					None => Ok(Ok(None)),
				}
			})?;

			let invalid_pos = match read_res {
				Ok(Some(output)) => return Ok(Some(output)),
				Ok(None) => {
					if attempted_repair {
						return Err(Error::Other(format!(
							"output_pos index entry missing for commit {} after rebuild",
							commit.to_hex(),
						)));
					}
					return Ok(None);
				}
				Err(invalid_pos) => invalid_pos,
			};

			if attempted_repair {
				return Err(Error::Other(format!(
					"output_pos index height remains invalid for commit {} at pos {} height {} after rebuild",
					commit.to_hex(),
					invalid_pos.pos,
					invalid_pos.height,
				)));
			}

			warn!(
				"output_pos index height invalid for commit {} at pos {} height {}; rebuilding output_pos index",
				commit.to_hex(),
				invalid_pos.pos,
				invalid_pos.height,
			);
			self.rebuild_output_pos_index(&commit, invalid_pos)?;
			attempted_repair = true;
		}
	}

	fn body_chain_header_for_output_pos(
		&self,
		header_pmmr: &PMMRHandle<BlockHeader>,
		batch: &Batch<'_>,
		body_head: &Tip,
		pos: CommitPos,
	) -> Result<Option<BlockHeader>, Error> {
		if pos.height > body_head.height {
			return Ok(None);
		}

		let header =
			self.body_chain_header_at_height_maybe_fast(header_pmmr, batch, body_head, pos.height)?;
		let prev_output_mmr_size = if pos.height == 0 {
			0
		} else {
			batch.get_previous_header(&header)?.output_mmr_size
		};

		if pos.pos > prev_output_mmr_size && pos.pos <= header.output_mmr_size {
			Ok(Some(header))
		} else {
			Ok(None)
		}
	}

	/// Retrieves an unspent output using its PMMR position
	pub fn get_unspent_output_at(&self, pos0: u64) -> Result<Output, Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			txhashset::utxo_view(header_pmmr, txhashset, |utxo, _| {
				utxo.get_unspent_output_at(pos0)
			})
		})
	}

	/// Validate the tx against the current UTXO set and recent kernels (NRD relative lock heights).
	pub fn validate_tx(&self, tx: &Transaction) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		self.validate_tx_against_utxo(tx)?;
		self.validate_tx_kernels(tx)?;
		Ok(())
	}

	/// Validates NRD relative height locks against "recent" kernel history.
	/// Applies the kernels to the current kernel MMR in a readonly extension.
	/// The extension and the db batch are discarded.
	/// The batch ensures duplicate NRD kernels within the tx are handled correctly.
	fn validate_tx_kernels(&self, tx: &Transaction) -> Result<(), Error> {
		let has_nrd_kernel = tx.kernels().iter().any(|k| match k.features {
			KernelFeatures::NoRecentDuplicate { .. } => true,
			_ => false,
		});
		if !has_nrd_kernel {
			return Ok(());
		}

		self.ensure_chain_robust()?;
		loop {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();

			// A writer may have failed while this thread was waiting for locks.
			// Do not validate NRD kernels against state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			return self.with_locked_readonly_pmmr_discard_marker("validate_tx_kernels", || {
				txhashset::extending_readonly(
					self.store.get_context_id(),
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						// Do not call next_block_height() here. We already hold the
						// header_pmmr and txhashset write locks, and that public path can
						// trigger init recovery which needs the same locks.
						let head = batch.head()?;
						let next_block_height = head.height.checked_add(1).ok_or_else(|| {
							Error::DataOverflow(format!(
								"Chain::validate_tx_kernels, head.height={}",
								head.height
							))
						})?;
						ext.extension
							.apply_kernels(tx.kernels(), next_block_height, batch, false)
					},
				)
			});
		}
	}

	fn validate_tx_against_utxo(
		&self,
		tx: &Transaction,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			txhashset::utxo_view(header_pmmr, txhashset, |utxo, batch| {
				utxo.validate_tx(tx, batch)
			})
		})
	}

	/// Validates inputs against the current utxo.
	/// Each input must spend an unspent output.
	/// Returns the vec of output identifiers and their pos of the outputs
	/// that would be spent by the inputs.
	pub fn validate_inputs(
		&self,
		inputs: &Inputs,
	) -> Result<Vec<(OutputIdentifier, CommitPos)>, Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			txhashset::utxo_view(header_pmmr, txhashset, |utxo, batch| {
				utxo.validate_inputs(inputs, batch)
			})
		})
	}

	fn next_block_height(&self) -> Result<u64, Error> {
		let bh = self.head_header()?;
		bh.height.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("Chain::next_block_height, bh.height={}", bh.height))
		})
	}

	/// Verify we are not attempting to spend a coinbase output
	/// that has not yet sufficiently matured.
	pub fn verify_coinbase_maturity(&self, inputs: &Inputs) -> Result<(), Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			txhashset::utxo_view(header_pmmr, txhashset, |utxo, batch| {
				let head = batch
					.head()
					.map_err(|e| Error::StoreErr(e, "coinbase maturity head".to_owned()))?;
				let height = head.height.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Chain::verify_coinbase_maturity, head.height={}",
						head.height
					))
				})?;
				utxo.verify_coinbase_maturity(self.store.get_context_id(), inputs, height, batch)?;
				Ok(())
			})
		})
	}

	/// Verify that the tx has a lock_height that is less than or equal to
	/// the height of the next block.
	pub fn verify_tx_lock_height(&self, tx: &Transaction) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let height = self.next_block_height()?;
		if tx.lock_height() <= height {
			Ok(())
		} else {
			Err(Error::TxLockHeight)
		}
	}

	/// replay attack  check
	/// when the pipe adds the block the chain, it will also do this check based on the block headerversion
	/// (need to be version 3 or bigger)
	/// Do we need to do the check here? we are doing check for every tx regardless of the kernel version.
	pub fn replay_attack_check(&self, tx: &Transaction) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		loop {
			let mut header_pmmr = self.header_pmmr.write();

			// A writer may have failed while this thread was waiting for the lock.
			// Do not validate replay state against PMMR/DB state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			return self.with_locked_readonly_pmmr_discard_marker("replay_attack_check", || {
				let batch_read = self.store.batch_read()?;
				txhashset::header_extending_readonly(&mut header_pmmr, batch_read, |ext, batch| {
					let body_header = batch.head_header()?;
					self.rewind_and_apply_header_fork(&body_header, ext, batch)?;
					pipe::check_against_spent_output(&tx.body, None, None, ext, batch)?;
					Ok(())
				})
			});
		}
	}

	/// Validate the current chain state.
	pub fn validate(&self, secp: &Secp256k1, fast_validation: bool) -> Result<(), Error> {
		self.ensure_chain_robust()?;

		loop {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();

			// A writer may have failed while this thread was waiting for locks.
			// Do not validate PMMR/txhashset state that now requires recovery.
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			return self.with_locked_readonly_pmmr_discard_marker("validate", || {
				// We want to lock first and read the header next. Otherwise after the lock header might be different
				let header = self.store.head_header()?;

				// Now create an extension from the txhashset and validate against the
				// latest block header. Rewind the extension to the specified header to
				// ensure the view is consistent.
				txhashset::extending_readonly(
					self.store.get_context_id(),
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						self.rewind_and_apply_fork(secp, &header, ext, batch)?;
						ext.extension.validate(
							&self.genesis.header,
							fast_validation,
							None,
							&header,
							None,
							secp,
						)?;
						Ok(())
					},
				)
			});
		}
	}

	/// Sets prev_root on a brand new block header by applying the previous header to the header MMR.
	pub fn set_prev_root_only(&self, header: &mut BlockHeader) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let prev_root = {
			let mut header_pmmr = self.header_pmmr.write();
			self.with_locked_readonly_pmmr_discard_marker("set_prev_root_only", || {
				let batch_read = self.store.batch_read()?;
				txhashset::header_extending_readonly(&mut header_pmmr, batch_read, |ext, batch| {
					let prev_header = batch.get_previous_header(header)?;
					self.rewind_and_apply_header_fork(&prev_header, ext, batch)?;
					ext.root()
				})
			})
		}?;

		// Set the prev_root on the header.
		header.prev_root = prev_root;

		Ok(())
	}

	/// Sets the txhashset roots on a brand new block by applying the block on
	/// the current txhashset state.
	pub fn set_txhashset_roots(&self, secp: &Secp256k1, b: &mut Block) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		let (prev_root, roots, sizes) = {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			self.with_locked_readonly_pmmr_discard_marker("set_txhashset_roots", || {
				txhashset::extending_readonly(
					self.store.get_context_id(),
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						let previous_header = batch.get_previous_header(&b.header)?;
						self.rewind_and_apply_fork(secp, &previous_header, ext, batch)?;

						let extension = &mut ext.extension;
						let header_extension = &mut ext.header_extension;

						// Retrieve the header root before we apply the new block
						let prev_root = header_extension.root()?;

						// Apply the latest block to the chain state via the extension.
						extension.apply_block(b, header_extension, batch)?;

						Ok((prev_root, extension.roots()?, extension.sizes()))
					},
				)
			})
		}?;

		// Set the output and kernel MMR sizes.
		// Note: We need to do this *before* calculating the roots as the output_root
		// depends on the output_mmr_size
		{
			// Carefully destructure these correctly...
			let (output_mmr_size, _, kernel_mmr_size) = sizes;
			b.header.output_mmr_size = output_mmr_size;
			b.header.kernel_mmr_size = kernel_mmr_size;
		}

		// Set the prev_root on the header.
		b.header.prev_root = prev_root;

		// Set the output, rangeproof and kernel MMR roots.
		b.header.output_root = roots.output_root;
		b.header.range_proof_root = roots.rproof_root;
		b.header.kernel_root = roots.kernel_root;

		Ok(())
	}

	/// Return a Merkle proof for the given commitment from the store.
	pub fn get_merkle_proof<T: AsRef<OutputIdentifier>>(
		&self,
		secp: &Secp256k1,
		out_id: T,
		header: &BlockHeader,
	) -> Result<MerkleProof, Error> {
		self.ensure_chain_robust()?;
		let merkle_proof = {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			self.with_locked_readonly_pmmr_discard_marker("get_merkle_proof", || {
				txhashset::extending_readonly(
					self.store.get_context_id(),
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						self.rewind_and_apply_fork(secp, &header, ext, batch)?;
						ext.extension.merkle_proof(out_id, batch)
					},
				)
			})
		}?;

		Ok(merkle_proof)
	}

	/// Return a merkle proof valid for the current output pmmr state at the
	/// given pos
	pub fn get_merkle_proof_for_pos(&self, commit: Commitment) -> Result<MerkleProof, Error> {
		self.ensure_chain_robust()?;
		let mut txhashset = self.txhashset.write();
		txhashset.merkle_proof(commit)
	}

	/// Rewind and apply fork with the chain specific header validation (denylist) rules.
	/// If we rewind and re-apply a "denied" block then validation will fail.
	fn rewind_and_apply_fork(
		&self,
		secp: &Secp256k1,
		header: &BlockHeader,
		ext: &mut ExtensionPair,
		batch: &Batch,
	) -> Result<BlockHeader, Error> {
		let (header, _) =
			pipe::rewind_and_apply_fork(self.store.get_context_id(), header, ext, batch, secp)?;
		Ok(header)
	}

	/// Rewind and apply fork with the chain specific header validation (denylist) rules.
	/// If we rewind and re-apply a "denied" header then validation will fail.
	fn rewind_and_apply_header_fork(
		&self,
		header: &BlockHeader,
		ext: &mut HeaderExtension,
		batch: &Batch,
	) -> Result<(), Error> {
		pipe::rewind_and_apply_header_fork(self.store.get_context_id(), header, ext, batch)
	}

	/// The segmenter is responsible for generation PIBD segments.
	/// We cache a segmenter instance based on the current archve period (new period every 12 hours).
	/// This allows us to efficiently generate bitmap segments for the current archive period.
	///
	/// It is a relatively expensive operation to initializa and cache a new segmenter instance
	/// as this involves rewinding the txhashet by approx 720 blocks (12 hours).
	///
	/// Caller is responsible for only doing this when required.
	/// Caller should verify a peer segment request is valid before calling this for example.
	///
	pub fn segmenter(&self) -> Result<Segmenter, Error> {
		self.ensure_chain_robust()?;
		// The archive header corresponds to the data we will segment.
		let ref archive_header = self.txhashset_archive_header()?;

		// Use our cached segmenter if we have one and the associated header matches.
		if let Some(x) = self.pibd_segmenter.read_recursive().as_ref() {
			if x.header() == archive_header {
				return Ok(x.clone());
			}
		}

		// We have no cached segmenter or the cached segmenter is no longer useful.
		// Take the write lock before initializing so concurrent callers do not
		// all run the expensive rewind/build path on the same cache miss.
		let mut cache = self.pibd_segmenter.write();
		if let Some(x) = cache.as_ref() {
			if x.header() == archive_header {
				return Ok(x.clone());
			}
		}

		// Initialize a new segmenter, cache it and return it.
		let segmenter = self.init_segmenter(archive_header)?;
		*cache = Some(segmenter.clone());

		return Ok(segmenter);
	}

	/// Root hash for the header hashes MMR at the provided txhashset archive header.
	pub fn header_hashes_root(&self, header: &BlockHeader) -> Result<Hash, Error> {
		let context_id = self.store.get_context_id();
		let header_hash = header.hash(context_id)?;
		self.with_robust_header_pmmr_read(|header_pmmr| {
			let current_header_hash = header_pmmr.get_header_hash_by_height(header.height)?;
			if current_header_hash != header_hash {
				return Err(Error::ChainInSyncing(format!(
					"archive header {} at {} no longer matches current header {}",
					header_hash, header.height, current_header_hash
				)));
			}

			let mut segm_header_pmmr_backend: VecBackend<Hash> = VecBackend::new(context_id);
			let mut segm_header_pmmr = PMMR::new(&mut segm_header_pmmr_backend);
			let hash_num = txhashset::calc_header_hashes_from_target_height(header.height);
			for i in 0..hash_num {
				let data = header_pmmr
					.get_header_hash_by_height(i * HEADERS_PER_BATCH as u64)
					.map_err(|e| {
						Error::Other(format!(
							"header_hashes_root internal error, header data is expected below horizon, {}",
							e
						))
					})?;
				segm_header_pmmr.push(&data).map_err(|s| {
					Error::SyncError(format!("Unable to create Headers hash MMR, {}", s))
				})?;
			}
			Ok(segm_header_pmmr.root()?)
		})
	}

	/// This is an expensive rewind to recreate bitmap state but we only need to do this once.
	/// Caller is responsible for "caching" the segmenter (per archive period) for reuse.
	fn init_segmenter(&self, header: &BlockHeader) -> Result<Segmenter, Error> {
		let now = Instant::now();
		let context_id = self.store.get_context_id();
		let header_hash = header.hash(context_id)?;
		debug!(
			"init_segmenter: initializing new segmenter for {} at {}",
			header_hash, header.height
		);

		let (bitmap_snapshot, segm_header_pmmr_backend) = {
			let mut header_pmmr = self.header_pmmr.write();
			let mut txhashset = self.txhashset.write();
			self.with_locked_readonly_pmmr_discard_marker("init_segmenter", || {
				let body_head = self
					.store
					.head()
					.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))?;
				let archive_height =
					Self::height_2_archive_height(context_id, body_head.height);
				if header.height != archive_height {
					return Err(Error::ChainInSyncing(format!(
						"archive header {} at {} no longer matches current archive height {}",
						header_hash, header.height, archive_height
					)));
				}

				let current_header_hash = header_pmmr.get_header_hash_by_height(archive_height)?;
				if current_header_hash != header_hash {
					return Err(Error::ChainInSyncing(format!(
						"archive header {} at {} no longer matches current header {}",
						header_hash, header.height, current_header_hash
					)));
				}
				let local_output_mmr_size = txhashset.output_mmr_size();
				let local_kernel_mmr_size = txhashset.kernel_mmr_size();
				let local_rangeproof_mmr_size = txhashset.rangeproof_mmr_size();

				if header.output_mmr_size > local_output_mmr_size
					|| header.kernel_mmr_size > local_kernel_mmr_size
					|| header.output_mmr_size > local_rangeproof_mmr_size
				{
					return Err(Error::ChainInSyncing(format!("Header expected mmr size: output:{} kernel:{}.  Chains mmr size: output:{} kernel:{} rangeproof:{}",
														 header.output_mmr_size, header.kernel_mmr_size, local_output_mmr_size, local_kernel_mmr_size, local_rangeproof_mmr_size)));
				}

				txhashset::extending_readonly(
					context_id,
					&mut header_pmmr,
					&mut txhashset,
					|ext, batch| {
						let extension = &mut ext.extension;
						let header_extension = &mut ext.header_extension;
						extension.rewind(header, batch, header_extension, None)?;
						Ok(extension.build_bitmap_accumulator()?)
					},
				)
				.and_then(|bitmap_snapshot| {
					// Creating headers hashes PIBD data. With that we can download headers in parallel.
					let mut segm_header_pmmr_backend: VecBackend<Hash> = VecBackend::new(context_id);
					{
						let mut segm_header_pmmr = PMMR::new(&mut segm_header_pmmr_backend);

						let hash_num = txhashset::calc_header_hashes_from_target_height(header.height);
						for i in 0..hash_num {
							let data = header_pmmr
								.get_header_hash_by_height(i * HEADERS_PER_BATCH as u64)
								.map_err(|e| {
									Error::Other(format!(
										"init_segmenter internal error, header data is expected below horizon, {}",
										e
									))
								})?;
							segm_header_pmmr.push(&data).map_err(|s| {
								Error::SyncError(format!("Unable to create Headers hash MMR, {}", s))
							})?;
						}
					}

					Ok((bitmap_snapshot, segm_header_pmmr_backend))
				})
			})
		}?;

		debug!("init_segmenter: done, took {}ms", now.elapsed().as_millis());

		// Let's check if mmr roots are matching the header
		{
			use mwc_core::core::pmmr::ReadablePMMR;

			let txhashset = self.txhashset.read_recursive();

			let output_pmmr = txhashset.output_pmmr_at(&header);
			let output_pmmr_root = output_pmmr
				.root()
				.map_err(|e| Error::Other(format!("Invalid output_pmmr, {}", e)))?;
			if header.output_root != output_pmmr_root {
				return Err(Error::InvalidRoot("output PMMR root mismatch".into()));
			}

			let rangeproof_pmmr = txhashset.rangeproof_pmmr_at(&header);
			let rangeproof_pmmr_root = rangeproof_pmmr
				.root()
				.map_err(|e| Error::Other(format!("Invalid rangeproof_pmmr, {}", e)))?;
			if header.range_proof_root != rangeproof_pmmr_root {
				return Err(Error::InvalidRoot("rangeproof PMMR root mismatch".into()));
			}

			let kernel_pmmr = txhashset.kernel_pmmr_at(&header);
			let kernel_pmmr_root = kernel_pmmr
				.root()
				.map_err(|e| Error::Other(format!("Invalid kernel_pmmr, {}", e)))?;
			if header.kernel_root != kernel_pmmr_root {
				return Err(Error::InvalidRoot("kernel PMMR root mismatch".into()));
			}
		}

		Segmenter::new(
			Arc::new(RwLock::new(segm_header_pmmr_backend)),
			self.txhashset.clone(),
			bitmap_snapshot,
			header.clone(),
		)
	}

	/// initialize a desegmenter, which is capable of extending the hashset by appending
	/// PIBD segments of the three PMMR trees + Bitmap PMMR
	/// header should be the same header as selected for the txhashset.zip archive
	pub fn init_desegmenter(
		&self,
		archive_header_hegiht: u64,
		bitmap_root_hash: Hash,
	) -> Result<Desegmenter, Error> {
		self.ensure_chain_robust()?;
		// Even not all headers are uploaded, Headers until archive must be uploaded, so we can request it
		let archive_header = self.get_header_by_height(archive_header_hegiht)?;
		debug!(
			"init_desegmenter: initializing new desegmenter for {} at {}",
			archive_header.hash(self.store.get_context_id())?,
			archive_header.height
		);

		Ok(Desegmenter::new(
			self.txhashset.clone(),
			self.header_pmmr.clone(),
			archive_header.clone(),
			bitmap_root_hash,
			self.genesis.header.clone(),
			self.store.clone(),
			self.pibd_params.clone(),
			self.requires_init_recovery.clone(),
		)?)
	}

	/// Static method to convert height to archive height. Used in chain and also in Sync process
	pub fn height_2_archive_height(context_id: u32, height: u64) -> u64 {
		let sync_threshold = u64::from(global::state_sync_threshold(context_id));
		let archive_interval = global::txhashset_archive_interval(context_id);
		let mut archive_height = height.saturating_sub(sync_threshold);
		archive_height = archive_height.saturating_sub(archive_height % archive_interval);
		archive_height
	}

	/// To support the ability to download the txhashset from multiple peers in parallel,
	/// the peers must all agree on the exact binary representation of the txhashset.
	/// This means compacting and rewinding to the exact same header.
	/// Since compaction is a heavy operation, peers can agree to compact every 12 hours,
	/// and no longer support requesting arbitrary txhashsets.
	/// Here we return the header of the txhashset we are currently offering to peers.
	pub fn txhashset_archive_header(&self) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		let body_head = self.head()?;
		let txhashset_height = Self::height_2_archive_height(context_id, body_head.height);

		debug!(
			"txhashset_archive_header: body_head - {}, {}, txhashset height - {}",
			body_head.last_block_h, body_head.height, txhashset_height,
		);

		let archive_header = self.get_header_by_height(txhashset_height)?;
		if !self.is_on_body_chain(&archive_header, body_head.clone())? {
			return Err(Error::ChainInSyncing(format!(
				"archive header {} at {} is not on body chain ending at {} at {}",
				archive_header.hash(context_id)?,
				archive_header.height,
				body_head.last_block_h,
				body_head.height,
			)));
		}

		Ok(archive_header)
	}

	/// Return the Block Header at the txhashset horizon, considering only the
	/// contents of the header PMMR
	pub fn txhashset_archive_header_header_only(&self) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		let header_head = self.header_head()?;
		let txhashset_height =
			Self::height_2_archive_height(self.store.get_context_id(), header_head.height);
		self.get_header_by_height(txhashset_height)
	}

	/// Special handling to make sure the whole kernel set matches each of its
	/// roots in each block header, without truncation. We go back header by
	/// header, rewind and check each root. This fixes a potential weakness in
	/// fast sync where a reorg past the horizon could allow a whole rewrite of
	/// the kernel set.
	pub fn validate_kernel_history(
		header: &BlockHeader,
		txhashset: &txhashset::TxHashSet,
		status: Option<&SyncState>,
		stop_state: Option<&StopState>,
	) -> Result<(), Error> {
		debug!("validate_kernel_history: rewinding and validating kernel history (readonly)");

		let mut count: u64 = 0;
		let total = header.height;
		let mut current = header.clone();
		if let Some(status) = status {
			status.update(SyncStatus::ValidatingKernelsHistory {
				headers: 0,
				headers_total: total,
			});
		}
		txhashset::rewindable_kernel_view(&txhashset, |view, batch| {
			let status_throttle = SyncStatusUpdateThrottle::new();
			while current.height > 0 {
				if let Some(stop_state) = stop_state {
					if stop_state.is_stopped() {
						return Err(Error::Stopped);
					}
				}
				view.rewind(&current)?;
				view.validate_root()?;
				current = batch.get_previous_header(&current)?;
				// Increment is safe because if can't begger that the number of the blocks. Also
				//  count used for logging, any failure will not be critical
				count += 1;
				if let Some(status) = status {
					if status_throttle.should_update(count == total) {
						status.update(SyncStatus::ValidatingKernelsHistory {
							headers: count,
							headers_total: total,
						});
					}
				}
			}
			Ok(())
		})?;

		debug!(
			"validate_kernel_history: validated kernel root on {} headers",
			count,
		);

		Ok(())
	}

	/// Finds the "fork point" where header chain diverges from full block chain.
	/// If we are syncing this will correspond to the last full block where
	/// the next header is known but we do not yet have the full block.
	/// i.e. This is the last known full block and all subsequent blocks are missing.
	pub fn fork_point(&self) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		let body_head = self.head()?;
		let mut current = self.get_block_header(&body_head.hash(self.store.get_context_id())?)?;
		while !self.is_on_current_chain(Tip::try_from_header(&current)?, body_head)? {
			current = self.get_previous_header(&current)?;
		}
		Ok(current)
	}

	/// Clean the temporary sandbox folder
	pub fn clean_txhashset_sandbox(&self) -> Result<(), Error> {
		txhashset::clean_txhashset_folder(&self.get_tmp_dir())
	}

	/// Specific tmp dir.
	/// Normally it's ~/.mwc/main/tmp for mainnet
	/// or ~/.mwc/floo/tmp for floonet
	pub fn get_tmp_dir(&self) -> PathBuf {
		let mut tmp_dir = PathBuf::from(self.db_root.clone());
		tmp_dir = match tmp_dir.parent() {
			Some(parent) => parent.to_path_buf(),
			None => tmp_dir,
		};
		tmp_dir.push("tmp");
		tmp_dir
	}

	fn validate_tmpfile_name(tmpfile_name: &str) -> Result<(), Error> {
		if tmpfile_name.is_empty() || tmpfile_name.contains('/') || tmpfile_name.contains('\\') {
			return Err(Error::Other(format!(
				"Invalid tmp file name: {}",
				tmpfile_name
			)));
		}

		let mut components = Path::new(tmpfile_name).components();
		match (components.next(), components.next()) {
			(Some(Component::Normal(_)), None) => Ok(()),
			_ => Err(Error::Other(format!(
				"Invalid tmp file name: {}",
				tmpfile_name
			))),
		}
	}

	/// Get a tmp file path in above specific tmp dir (create tmp dir if not exist)
	/// Delete file if tmp file already exists
	pub fn get_tmpfile_pathname(&self, tmpfile_name: String) -> Result<PathBuf, Error> {
		Self::validate_tmpfile_name(&tmpfile_name)?;

		let mut tmp = self.get_tmp_dir();
		mwc_util::file::ensure_owner_only_dir_all(&tmp)?;
		tmp.push(tmpfile_name);
		match fs::remove_file(&tmp) {
			Ok(()) => {}
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
			Err(e) => return Err(e.into()),
		}
		Ok(tmp)
	}

	/// Writes a reading view on a txhashset state that's been provided to us.
	/// If we're willing to accept that new state, the data stream will be
	/// read as a zip file, unzipped and the resulting state files should be
	/// rewound to the provided indexes.
	//  Note, if there are updates in this code, please check Sync code, probably it needs to be updates as well
	/*	pub fn txhashset_write(
		&self,
		h: Hash,
		txhashset_data: File,
		status: &dyn TxHashsetWriteStatus,
	) -> Result<bool, Error> {
		status.on_setup(None, None, None, None);

		// Initial check whether this txhashset is needed or not
		let fork_point = self.fork_point()?;
		if !self.check_txhashset_needed(&fork_point)? {
			warn!("txhashset_write: txhashset received but it's not needed! ignored.");
			return Err(Error::InvalidTxHashSet("not needed".to_owned()));
		}

		let header = match self.get_block_header(&h) {
			Ok(header) => header,
			Err(e) if e.is_not_found() => {
				warn!("txhashset_write: cannot find block header, {}", e);
				// This is a bannable reason
				return Ok(true);
			}
			Err(e) => return Err(e),
		};

		// Write txhashset to sandbox (in the Mwc specific tmp dir)
		let sandbox_dir = self.get_tmp_dir();
		txhashset::clean_txhashset_folder(&sandbox_dir)?;
		txhashset::zip_write(sandbox_dir.clone(), txhashset_data.try_clone()?, &header)?;

		let mut txhashset = txhashset::TxHashSet::open(
			sandbox_dir
				.to_str()
				.ok_or_else(|| Error::Other("invalid sandbox folder".into()))?
				.to_owned(),
			self.store.clone(),
			Some(&header),
			&self.secp,
		)?;

		// Validate the full kernel history.
		// Check kernel MMR root for every block header.
		// Check NRD relative height rules for full kernel history.
		{
			self.validate_kernel_history(&header, &txhashset)?;

			let header_pmmr = self.header_pmmr.read_recursive();
			let batch = self.store.batch_write()?;
			txhashset.verify_kernel_pos_index(
				&self.genesis.header,
				&header_pmmr,
				&batch,
				None,
				None,
			)?;
		}

		// all good, prepare a new batch and update all the required records
		debug!("txhashset_write: rewinding a 2nd time (writeable)");

		let mut header_pmmr = self.header_pmmr.write();
		let mut batch = self.store.batch_write()?;
		txhashset::extending(
			&mut header_pmmr,
			&mut txhashset,
			&mut batch,
			|ext, batch| {
				let extension = &mut ext.extension;
				extension.rewind(&header, batch)?;

				// Validate the extension, generating the utxo_sum and kernel_sum.
				// Full validation, including rangeproofs and kernel signature verification.
				let (utxo_sum, kernel_sum) = extension.validate(
					&self.genesis.header,
					false,
					status,
					None,
					None,
					&header,
					None,
					self.secp(),
				)?;

					// Save the block_sums (utxo_sum, kernel_sum) to the db for use later.
					batch.save_block_sums(
						&header.hash(self.store.get_context_id())?,
						BlockSums::new(utxo_sum, kernel_sum),
					)?;

				Ok(())
			},
		)?;

		debug!("txhashset_write: finished validating and rebuilding");

		status.on_save();

		// Save the new head to the db and rebuild the header by height index.
		{
			let tip = Tip::try_from_header(&header)?;
			batch.save_body_head(&tip)?;

			// Reset the body tail to the body head after a txhashset write
			batch.save_body_tail(&tip)?;
		}

		// Rebuild our output_pos index in the db based on fresh UTXO set.
		txhashset.init_output_pos_index(&batch)?;

		// Rebuild our NRD kernel_pos index based on recent kernel history.
		txhashset.init_recent_kernel_pos_index(&header_pmmr, &batch)?;

		// Rebuild the full kernel excess index based on fresh kernel history.
		txhashset.init_kernel_pos_index(&batch)?;
		batch.set_kernel_pos_index_complete(true)?;

		// Commit all the changes to the db.
		batch.commit()?;

		debug!("txhashset_write: finished committing the batch (head etc.)");

		// Sandbox full validation ok, go to overwrite txhashset on db root
		{
			let mut txhashset_ref = self.txhashset.write();

			// Before overwriting, drop file handlers in underlying txhashset
			txhashset_ref.release_backend_files();

			// Move sandbox to overwrite
			txhashset.release_backend_files();
			match txhashset::txhashset_replace(sandbox_dir, PathBuf::from(self.db_root.clone()))? {
				txhashset::TxHashSetReplaceResult::Replaced => {}
				txhashset::TxHashSetReplaceResult::ReplacedWithBackupCleanupFailure {
					backup_path,
					cleanup_error,
				} => {
					warn!(
						"txhashset_write: replaced txhashset but failed to remove backup {:?}. err: {}",
						backup_path, cleanup_error
					);
				}
			}

			// Re-open on db root dir
			txhashset = txhashset::TxHashSet::open(
				self.db_root.clone(),
				self.store.clone(),
				Some(&header),
				&self.secp,
			)?;

			// Replace the chain txhashset with the newly built one.
			*txhashset_ref = txhashset;
		}

		debug!("txhashset_write: replaced our txhashset with the new one");

		status.on_done();

		Ok(false)
	}*/

	/// Cleanup old blocks from the db.
	/// Determine the cutoff height from the horizon and the current block height.
	/// *Only* runs if we are not in archive mode.
	fn remove_historical_blocks(
		&self,
		new_tail: &BlockHeader,
		stop_state: &StopState,
	) -> Result<(), Error> {
		if self.archive_mode() {
			return Ok(());
		}
		if stop_state.is_stopped() {
			return Err(Error::Stopped);
		}

		debug!(
			"remove_historical_blocks: new_tail height: {}",
			new_tail.height
		);

		let hashes_to_delete = {
			let batch = self.store.batch_read()?;
			let mut hashes_to_delete = Vec::new();
			let context_id = self.store.get_context_id();
			// Remove old blocks (including short lived fork blocks) which height < tail.height
			for block in batch.blocks_iter()? {
				if stop_state.is_stopped() {
					return Err(Error::Stopped);
				}
				let block = block?;
				if block.header.height < new_tail.height {
					hashes_to_delete.push(block.hash(context_id)?);
				}
			}
			hashes_to_delete
		};
		let count = hashes_to_delete.len();
		for hashes in hashes_to_delete.chunks(HISTORICAL_BLOCK_DELETE_CHUNK) {
			if stop_state.is_stopped() {
				return Err(Error::Stopped);
			}
			let batch = self.store.batch_write()?;
			for hash in hashes {
				if stop_state.is_stopped() {
					return Err(Error::Stopped);
				}
				match batch.delete_block(hash) {
					Ok(()) => {}
					// Removing blocks with a best effort. If block doesn't exist - it is ok.
					Err(NotFoundErr(_)) => {}
					Err(e) => return Err(e.into()),
				}
			}
			if stop_state.is_stopped() {
				return Err(Error::Stopped);
			}
			batch.commit()?;
		}
		debug!(
			"remove_historical_blocks: removed {} blocks in chunks of {}. tail height: {}",
			count, HISTORICAL_BLOCK_DELETE_CHUNK, new_tail.height
		);
		Ok(())
	}

	fn compact_eligibility_for_heights(
		context_id: u32,
		tail_height: u64,
		head_height: u64,
	) -> (bool, u64) {
		let horizon = global::cut_through_horizon(context_id) as u64;
		let threshold = horizon.saturating_add(horizon / 10);
		let next_compact = tail_height.saturating_add(threshold);
		(next_compact <= head_height, next_compact)
	}

	fn compact_eligibility(&self) -> Result<(bool, u64), Error> {
		let tail = self
			.store
			.tail()
			.map_err(|e| Error::StoreErr(e, "chain tail".to_owned()))?;
		let head = self
			.store
			.head()
			.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))?;
		Ok(Self::compact_eligibility_for_heights(
			self.store.get_context_id(),
			tail.height,
			head.height,
		))
	}

	/// Triggers chain compaction.
	///
	/// * compacts the txhashset based on current prune_list
	/// * removes historical blocks and associated data from the db (unless archive mode)
	///
	pub fn compact(&self, stop_state: Arc<StopState>) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		if stop_state.is_stopped() {
			return Err(Error::Stopped);
		}
		// A node may be restarted multiple times in a short period of time.
		// We compact at most once per 60 blocks in this situation by comparing
		// current "head" and "tail" height to our cut-through horizon and
		// allowing an additional 60 blocks in height before allowing a further compaction.
		let (should_compact, next_compact) = self.compact_eligibility()?;
		if !should_compact {
			debug!(
				"compact: skipping startup compaction (next at {})",
				next_compact
			);
			return Ok(());
		}

		let context_id = self.store.get_context_id();

		let cleanup_tail = {
			// Take a write lock on the txhashet and start a new writeable db batch.
			let header_pmmr = self.header_pmmr.read_recursive();
			let mut txhashset = self.txhashset.write();
			if stop_state.is_stopped() {
				return Err(Error::Stopped);
			}
			// A queued compact call may have become ineligible while waiting.
			let (should_compact, next_compact) = self.compact_eligibility()?;
			if !should_compact {
				debug!(
					"compact: skipping queued compaction (next at {})",
					next_compact
				);
				Ok(None)
			} else {
				let op =
					prepare_reconcile_heads_operation(&self.store, ChainOperationKind::Compact)?;
				self.set_pending_chain_operation_checked(&op)?;
				let res = (|| {
					let batch = self.store.batch_write()?;

					// Compact the txhashset itself (rewriting the pruned backend files).

					let body_head = batch.head()?;
					let horizon_height = body_head.height.saturating_sub(
						global::cut_through_horizon(self.store.get_context_id()) as u64,
					);
					// Compaction must use the body-chain ancestor at this height. A plain
					// header-by-height lookup is against the header PMMR view, which can be
					// ahead of or different from the fully validated body chain.
					let horizon_header =
						self.body_chain_header_at_height(&batch, &body_head, horizon_height)?;
					let horizon_hash = horizon_header.hash(context_id)?;
					let header_pmmr_hash = header_pmmr.get_header_hash_by_height(horizon_height)?;
					if header_pmmr_hash != horizon_hash {
						return Err(Error::ChainInSyncing(format!(
							"compact horizon {} at {} is not on current header chain",
							horizon_hash, horizon_height
						)));
					}
					let body_head_hash = body_head.hash(context_id)?;
					let header_pmmr_body_hash =
						header_pmmr.get_header_hash_by_height(body_head.height)?;
					if header_pmmr_body_hash != body_head_hash {
						return Err(Error::ChainInSyncing(format!(
							"compact body head {} at {} is not on current header chain",
							body_head_hash, body_head.height
						)));
					}

					txhashset.compact(&horizon_header, &batch)?;
					if stop_state.is_stopped() {
						return Err(Error::Stopped);
					}

					// NOTE:  Compaction selects a different horizon
					// block from txhashset horizon/PIBD segmenter. That block is allways above or equal
					// It is expected, we don't want all nodes go into compaction at the same time becase
					// it might take a while on slow hardware.

					// Archive is 2 days + 12 hours.  horizon is a week. Guaranteed that archive_header.height is larger than horizon height
					debug_assert!(
						Self::height_2_archive_height(context_id, body_head.height)
							> horizon_header.height
					);

					batch.save_body_tail(&Tip::try_from_header(&horizon_header)?)?;

					// Make sure our output_pos index is consistent with the UTXO set.
					txhashset.init_output_pos_index(&batch, None, Some(stop_state.clone()))?;

					// TODO - Why is this part of chain compaction?
					// Rebuild our NRD kernel_pos index based on recent kernel history.
					txhashset.init_recent_kernel_pos_index(
						&header_pmmr,
						&batch,
						None,
						Some(stop_state.clone()),
					)?;

					// Commit all the above db changes.
					batch.commit()?;
					Ok(horizon_header)
				})();
				match res {
					Ok(horizon_header) => {
						self.clear_pending_chain_operation_checked()?;
						Ok(Some(horizon_header))
					}
					Err(e) => {
						self.handle_failed_pending_chain_operation("compact", &e);
						Err(e)
					}
				}
			}
		}?;

		if let Some(cleanup_tail) = cleanup_tail {
			self.remove_historical_blocks(&cleanup_tail, stop_state.as_ref())?;
		}
		Ok(())
	}

	/// Returns up to distance unpruned outputs found by scanning backward in
	/// the output sum tree. Pruned outputs do not count toward distance.
	pub fn get_last_n_output(&self, distance: u64) -> Result<Vec<(Hash, OutputIdentifier)>, Error> {
		self.with_robust_chain_read(|_, txhashset| Ok(txhashset.last_n_output(distance)?))
	}

	/// As above, for rangeproofs.
	pub fn get_last_n_rangeproof(&self, distance: u64) -> Result<Vec<(Hash, RangeProof)>, Error> {
		self.with_robust_chain_read(|_, txhashset| Ok(txhashset.last_n_rangeproof(distance)?))
	}

	/// As above, for kernels.
	pub fn get_last_n_kernel(&self, distance: u64) -> Result<Vec<(Hash, TxKernel)>, Error> {
		self.with_robust_chain_read(|_, txhashset| Ok(txhashset.last_n_kernel(distance)?))
	}

	/// Return Commit's MMR position
	pub fn get_output_pos(&self, commit: &Commitment) -> Result<u64, Error> {
		self.with_robust_chain_read(|_, txhashset| Ok(txhashset.get_output_pos(commit)?))
	}

	/// outputs by insertion index
	pub fn unspent_outputs_by_pmmr_index(
		&self,
		start_index: u64,
		max_count: u64,
		max_pmmr_index: Option<u64>,
	) -> Result<(u64, u64, Vec<Output>), Error> {
		self.with_robust_chain_read(|_, txhashset| {
			let output_mmr_size = txhashset.output_mmr_size();
			let last_index = match max_pmmr_index {
				Some(i) => min(i, output_mmr_size),
				None => output_mmr_size,
			};
			let outputs =
				txhashset.outputs_by_pmmr_index(start_index, max_count, max_pmmr_index)?;
			let rangeproofs =
				txhashset.rangeproofs_by_pmmr_index(start_index, max_count, max_pmmr_index)?;
			let (index, output_vec) =
				combine_positioned_outputs_and_rangeproofs(outputs, rangeproofs)?;
			Ok((index, last_index, output_vec))
		})
	}

	/// Return unspent outputs as above, but bounded between a particular range of blocks
	pub fn block_height_range_to_pmmr_indices(
		&self,
		start_block_height: u64,
		end_block_height: Option<u64>,
	) -> Result<(u64, u64), Error> {
		self.with_robust_header_pmmr_read(|header_pmmr| {
			let batch = self
				.store
				.batch_read()
				.map_err(|e| Error::StoreErr(e, "block height range read batch".to_owned()))?;
			let body_head = batch
				.head()
				.map_err(|e| Error::StoreErr(e, "block height range body head".to_owned()))?;
			let end_block_height = match end_block_height {
				Some(h) => h.min(body_head.height),
				None => body_head.height,
			};
			if start_block_height > end_block_height {
				return Err(Error::Other(format!(
					"Invalid block height range: start_block_height={} is greater than end_block_height={}",
					start_block_height, end_block_height
				)));
			}

			// Resolve bounds from the fully validated body chain. The header PMMR can
			// be ahead of, or forked away from, the body head during header-first sync.
			let start_mmr_size = if start_block_height == 0 {
				0
			} else {
				let start_header = self.body_chain_header_at_height_maybe_fast(
					header_pmmr,
					&batch,
					&body_head,
					start_block_height - 1,
				)?;
				start_header.output_mmr_size.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Chain::block_height_range_to_pmmr_indices, start_header.output_mmr_size={}",
						start_header.output_mmr_size
					))
				})?
			};
			let end_header = self.body_chain_header_at_height_maybe_fast(
				header_pmmr,
				&batch,
				&body_head,
				end_block_height,
			)?;
			let end_mmr_size = end_header.output_mmr_size;
			Ok((start_mmr_size, end_mmr_size))
		})
	}

	/// Orphans pool size
	pub fn orphans_len(&self) -> usize {
		self.orphans.len()
	}

	/// Tip (head) of the block chain.
	pub fn head(&self) -> Result<Tip, Error> {
		self.ensure_chain_robust()?;
		self.store
			.head()
			.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))
	}

	/// Tail of the block chain in this node after compact (cross-block cut-through)
	pub fn tail(&self) -> Result<Tip, Error> {
		self.ensure_chain_robust()?;
		self.store
			.tail()
			.map_err(|e| Error::StoreErr(e, "chain tail".to_owned()))
	}

	/// Tip (head) of the header chain.
	pub fn header_head(&self) -> Result<Tip, Error> {
		self.ensure_chain_robust()?;
		self.store
			.header_head()
			.map_err(|e| Error::StoreErr(e, "header head".to_owned()))
	}

	/// Block header for the chain head
	pub fn head_header(&self) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		self.store
			.head_header()
			.map_err(|e| Error::StoreErr(e, "chain head header".to_owned()))
	}

	/// Gets a block by hash
	pub fn get_block(&self, h: &Hash) -> Result<Block, Error> {
		self.ensure_chain_robust()?;
		self.store
			.get_block(h)
			.map_err(|e| Error::StoreErr(e, "chain get block".to_owned()))
	}

	/// Gets the earliest stored block (tail)
	pub fn get_tail(&self) -> Result<Tip, Error> {
		self.ensure_chain_robust()?;
		self.store
			.tail()
			.map_err(|e| Error::StoreErr(e, "chain get tail".to_owned()))
	}

	/// Gets a block header by hash
	pub fn get_block_header(&self, h: &Hash) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		self.store
			.get_block_header(h)
			.map_err(|e| Error::StoreErr(e, "chain get header".to_owned()))
	}

	/// Get previous block header.
	pub fn get_previous_header(&self, header: &BlockHeader) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		self.store
			.get_previous_header(header)
			.map_err(|e| Error::StoreErr(e, "chain get previous header".to_owned()))
	}

	/// Get block_sums by header hash.
	pub fn get_block_sums(&self, h: &Hash) -> Result<BlockSums, Error> {
		self.ensure_chain_robust()?;
		self.store
			.get_block_sums(h)
			.map_err(|e| Error::StoreErr(e, "chain get block_sums".to_owned()))
	}

	/// Gets the block header at the provided height.
	/// Note: Takes a read lock on the header_pmmr.
	pub fn get_header_by_height(&self, height: u64) -> Result<BlockHeader, Error> {
		self.ensure_chain_robust()?;
		let hash = self.get_header_hash_by_height(height)?;
		self.get_block_header(&hash)
	}

	/// Gets the header hash at the provided height.
	/// Note: Takes a read lock on the header_pmmr.
	fn get_header_hash_by_height(&self, height: u64) -> Result<Hash, Error> {
		self.header_pmmr
			.read_recursive()
			.get_header_hash_by_height(height)
	}

	/// Migrate our local db from v2 to v3.
	/// "commit only" inputs.
	fn migrate_db_v2_v3(store: &ChainStore) -> Result<(), Error> {
		if store.batch_read()?.is_blocks_v3_migrated()? {
			// Previously migrated so skipping.
			debug!("migrate_db_v2_v3: previously migrated, skipping");
			return Ok(());
		}
		let mut total = 0u64;
		let mut keys_to_migrate = vec![];
		let context_id = store.get_context_id();
		for item in store.batch_read()?.blocks_raw_iter()? {
			let (k, v) = item?;
			// Increment is safe because total is used for logging only
			total += 1;

			// We want to migrate all blocks that cannot be read via v3 protocol version.
			let block_v3: Result<Block, _> =
				ser::deserialize_strict(&mut Cursor::new(&v), ProtocolVersion(3), context_id);
			if let Err(v3_err) = block_v3 {
				let block_v2: Result<Block, _> =
					ser::deserialize_strict(&mut Cursor::new(&v), ProtocolVersion(2), context_id);
				match block_v2 {
					Ok(_) => keys_to_migrate.push(k),
					Err(v2_err) => {
						return Err(Error::BlockMigration {
							key: k,
							v3_err,
							v2_err,
						});
					}
				}
			}
		}
		debug!(
			"migrate_db_v2_v3: {} (of {}) blocks to migrate",
			keys_to_migrate.len(),
			total,
		);
		let mut count = 0u64;
		keys_to_migrate
			.chunks(100)
			.try_for_each(|keys| {
				let batch = store.batch_write()?;
				for key in keys {
					batch.migrate_block(&key, ProtocolVersion(2), ProtocolVersion(3))?;
					// Increment is safe because count is used for logging only
					count += 1;
				}
				batch.commit()?;
				debug!("migrate_db_v2_v3: successfully migrated {} blocks", count);
				Ok(())
			})
			.and_then(|_| {
				// Set flag to indicate we have migrated all blocks in the db.
				// We will skip migration in the future.
				let batch = store.batch_write()?;
				batch.set_blocks_v3_migrated(true)?;
				batch.commit()?;
				Ok(())
			})
	}

	fn set_retained_spent_commitment_index_complete(
		store: &ChainStore,
		complete: bool,
	) -> Result<(), Error> {
		let batch = store.batch_write().map_err(|e| {
			Error::StoreErr(
				e,
				"spent commitment index completeness write batch".to_owned(),
			)
		})?;
		batch.set_retained_spent_commitment_index_complete(complete)?;
		batch.commit().map_err(|e| {
			Error::StoreErr(e, "spent commitment index completeness commit".to_owned())
		})
	}

	fn clear_spent_commitment_index(store: &ChainStore) -> Result<(), Error> {
		loop {
			let batch = store.batch_write().map_err(|e| {
				Error::StoreErr(e, "clear spent commitment index write batch".to_owned())
			})?;
			let deleted =
				batch.clear_spent_commitment_index_chunk(SPENT_COMMITMENT_INDEX_REBUILD_CHUNK)?;
			batch.commit().map_err(|e| {
				Error::StoreErr(e, "clear spent commitment index commit".to_owned())
			})?;
			if deleted == 0 {
				return Ok(());
			}
		}
	}

	fn save_spent_commitment_index_entries(
		store: &ChainStore,
		entries: &[(Commitment, HashHeight)],
	) -> Result<(), Error> {
		if entries.is_empty() {
			return Ok(());
		}
		let batch = store.batch_write().map_err(|e| {
			Error::StoreErr(e, "rebuild spent commitment index write batch".to_owned())
		})?;
		for (commitment, hash_height) in entries {
			batch.save_spent_commitments(commitment, *hash_height)?;
		}
		batch
			.commit()
			.map_err(|e| Error::StoreErr(e, "rebuild spent commitment index commit".to_owned()))
	}

	fn retained_body_block_hashes(store: &ChainStore) -> Result<Vec<Hash>, Error> {
		// Normal nodes prune full block bodies below BODY_TAIL. This replay
		// index can only be proven complete for the retained body-chain window,
		// not for all historical chain data. Walk BODY_HEAD back to BODY_TAIL
		// and require each full block body to exist before setting the durable
		// completeness marker. Do not use a raw full-block iterator here: it can
		// include non-body-chain fork blocks and it cannot prove that the
		// retained canonical window has no gaps.
		let batch = store
			.batch_read()
			.map_err(|e| Error::StoreErr(e, "retained body block window read batch".to_owned()))?;
		let head = batch
			.head()
			.map_err(|e| Error::StoreErr(e, "retained body block window head".to_owned()))?;
		let tail = match batch.tail() {
			Ok(tail) => tail,
			// Fresh chains can have HEAD before BODY_TAIL is initialized. Treat
			// only the genesis-height case as a one-block retained window rooted at HEAD.
			Err(NotFoundErr(_)) if head.height == 0 => head.clone(),
			Err(NotFoundErr(_)) => {
				return Err(Error::Other(format!(
					"body tail is missing for non-fresh chain head height {}",
					head.height
				)));
			}
			Err(e) => {
				return Err(Error::StoreErr(
					e,
					"retained body block window tail".to_owned(),
				));
			}
		};
		if tail.height > head.height {
			return Err(Error::Other(format!(
				"body tail height {} is above body head height {}",
				tail.height, head.height
			)));
		}

		let context_id = store.get_context_id();
		let head_hash = head.hash(context_id)?;
		let tail_hash = tail.hash(context_id)?;
		let mut current = batch
			.get_block_header(&head_hash)
			.map_err(|e| Error::StoreErr(e, "retained body block window head header".to_owned()))?;
		let retained_window_len = head
			.height
			.checked_sub(tail.height)
			.and_then(|len| len.checked_add(1))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"retained_body_block_hashes length overflow: head height {}, tail height {}",
					head.height, tail.height
				))
			})?;
		let retained_window_capacity = usize::try_from(retained_window_len).map_err(|_| {
			Error::DataOverflow(format!(
				"retained_body_block_hashes length {} does not fit usize",
				retained_window_len
			))
		})?;
		let mut hashes = Vec::with_capacity(retained_window_capacity);
		let mut expected_height = head.height;
		let mut next_tail_header = None;
		for _ in 0..retained_window_len {
			let hash = current.hash(context_id)?;
			if current.height != expected_height {
				return Err(Error::Other(format!(
					"body chain retained window expected height {}, found {} at {}",
					expected_height, current.height, hash
				)));
			}
			let block_exists = batch.block_exists(&hash)?;

			if current.height == tail.height {
				if hash != tail_hash {
					return Err(Error::Other(format!(
						"body chain retained window reached {} at tail height {}, expected {}",
						hash, tail.height, tail_hash
					)));
				}
				if !block_exists {
					let next_tail_header = match next_tail_header {
						Some(h) => h,
						None => {
							error!(
								"retained spent commitment index rebuild found missing BODY_TAIL full block body with no BODY_TAIL + 1: height {}, hash {}, body_head height {}",
								tail.height, tail_hash, head.height
							);
							return Err(Error::SpentCommitmentIndexIncomplete);
						}
					};
					let next_tail = Tip::try_from_header(&next_tail_header)?;
					drop(batch);
					let write_batch = store.batch_write().map_err(|e| {
						Error::StoreErr(e, "retained body tail repair write batch".to_owned())
					})?;
					write_batch.save_body_tail(&next_tail)?;
					write_batch.commit().map_err(|e| {
						Error::StoreErr(e, "retained body tail repair commit".to_owned())
					})?;
					warn!(
						"retained spent commitment index rebuild advanced stale body_tail from height {}, hash {} to height {}, hash {}",
						tail.height, tail_hash, next_tail.height, next_tail.last_block_h
					);
					hashes.reverse();
					return Ok(hashes);
				}
				hashes.push(hash);
				if hashes.len() != retained_window_capacity {
					return Err(Error::Other(format!(
						"body chain retained window reached tail with {} blocks, expected {}",
						hashes.len(),
						retained_window_capacity
					)));
				}
				hashes.reverse();
				return Ok(hashes);
			}
			if !block_exists {
				error!(
					"retained spent commitment index rebuild is missing retained full block body: height {}, hash {}, body_head height {}, body_tail height {}",
					current.height, hash, head.height, tail.height
				);
				return Err(Error::SpentCommitmentIndexIncomplete);
			}
			hashes.push(hash);
			next_tail_header = Some(current.clone());
			expected_height = expected_height.checked_sub(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"retained_body_block_hashes expected height underflow at {}",
					current.height
				))
			})?;
			current = batch.get_previous_header(&current)?;
		}
		Err(Error::Other(format!(
			"body chain retained window did not reach tail {} after {} blocks",
			tail_hash, retained_window_len
		)))
	}

	pub(crate) fn init_spent_commitment_index(store: &ChainStore) -> Result<(), Error> {
		// Rebuild only the replay index that a local node can prove: commitments
		// spent by retained full blocks on the canonical body chain. Normal
		// nodes prune historical block bodies below BODY_TAIL, so compacted
		// historical spends cannot be reconstructed here.
		let complete = store
			.batch_read()
			.map_err(|e| Error::StoreErr(e, "spent commitment index read batch".to_owned()))?
			.is_retained_spent_commitment_index_complete()?;
		if complete {
			return Ok(());
		}

		info!("Rebuilding spent commitment replay index for retained full blocks");
		Self::set_retained_spent_commitment_index_complete(store, false)?;
		let block_hashes = Self::retained_body_block_hashes(store)?;
		Self::clear_spent_commitment_index(store)?;

		let mut entries = Vec::with_capacity(SPENT_COMMITMENT_INDEX_REBUILD_CHUNK);
		let mut blocks = 0u64;
		let mut retained_spent_commitments = 0u64;
		for block_hash in block_hashes {
			let block = store.get_block(&block_hash)?;
			let hash_height = HashHeight {
				hash: block_hash,
				height: block.header.height,
			};
			let entries_before = entries.len();
			match block.inputs() {
				Inputs::CommitOnly(inputs) => {
					for input in inputs {
						entries.push((input.commitment(), hash_height));
					}
				}
				Inputs::FeaturesAndCommit(inputs) => {
					for input in inputs {
						entries.push((input.commitment(), hash_height));
					}
				}
			}
			blocks += 1;
			retained_spent_commitments += (entries.len() - entries_before) as u64;
			if entries.len() >= SPENT_COMMITMENT_INDEX_REBUILD_CHUNK {
				Self::save_spent_commitment_index_entries(store, &entries)?;
				entries.clear();
			}
		}
		Self::save_spent_commitment_index_entries(store, &entries)?;
		Self::set_retained_spent_commitment_index_complete(store, true)?;
		info!(
			"Rebuilt spent commitment replay index for {} retained full blocks and {} retained spent commitments",
			blocks, retained_spent_commitments
		);
		Ok(())
	}

	pub(crate) fn init_empty_retained_spent_commitment_index(
		store: &ChainStore,
	) -> Result<(), Error> {
		// PIBD restores the txhashset and headers, not retained full block
		// bodies. Until the first post-PIBD full block is stored there are no
		// retained bodies to replay, so the complete retained replay index is
		// intentionally empty.
		info!("Initializing empty spent commitment replay index for PIBD state");
		Self::set_retained_spent_commitment_index_complete(store, false)?;
		Self::clear_spent_commitment_index(store)?;
		Self::set_retained_spent_commitment_index_complete(store, true)?;
		Ok(())
	}

	/// Gets the block header in which a given output appears in the txhashset.
	pub fn get_header_for_output(&self, commit: Commitment) -> Result<BlockHeader, Error> {
		match self.get_unspent_with_validated_height(commit)? {
			Some((_, _, header)) => Ok(header),
			None => Err(Error::OutputNotFound(format!(
				"Not found commit {}",
				commit.to_hex()
			))),
		}
	}

	fn rebuild_output_pos_index(
		&self,
		commit: &Commitment,
		invalid_pos: CommitPos,
	) -> Result<(), Error> {
		self.ensure_chain_robust()?;
		loop {
			let txhashset = self.txhashset.read_recursive();
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(txhashset);
				self.ensure_chain_robust()?;
				continue;
			}

			let batch = self.store.batch_write().map_err(|e| {
				Error::StoreErr(e, "rebuild output_pos index write batch".to_owned())
			})?;

			match batch.get_output_pos_height(commit)? {
				Some(current_pos) if current_pos == invalid_pos => {
					batch.delete_output_pos_height(commit)?;
				}
				_ => {}
			}

			txhashset.init_output_pos_index(&batch, None, None)?;
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(batch);
				drop(txhashset);
				self.ensure_chain_robust()?;
				continue;
			}

			return batch
				.commit()
				.map_err(|e| Error::StoreErr(e, "rebuild output_pos index commit".to_owned()));
		}
	}

	/// Gets the kernel with a given excess and the block height it is included in.
	pub fn get_kernel_height(
		&self,
		excess: &Commitment,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, Error> {
		self.with_robust_chain_read(|header_pmmr, txhashset| {
			let batch = self
				.store
				.batch_read()
				.map_err(|e| Error::StoreErr(e, "chain kernel_pos read batch".to_owned()))?;
			let head = batch
				.head()
				.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))?;

			if let (Some(min), Some(max)) = (min_height, max_height) {
				if min > max {
					return Ok(None);
				}
			}
			let min_height = min_height.unwrap_or(0);
			if min_height > head.height {
				return Ok(None);
			}
			let max_height = max_height
				.filter(|h| *h <= head.height)
				.unwrap_or(head.height);

			// Chunked rebuild commits partial kernel_pos entries while this flag is false.
			// A missing entry is not a reliable cache miss until the full index is complete.
			if !batch.is_kernel_pos_index_complete()? {
				return Err(Error::KernelPosIndexIncomplete);
			}

			let mut found = None;
			for pos in batch.kernel_pos_iter(excess)? {
				let kernel_pos = pos?;
				let kernel = txhashset
					.get_kernel_by_mmr_index(kernel_pos.pos)?
					.ok_or_else(|| {
						Error::TxHashSetErr(format!(
							"kernel_pos index points to missing kernel at pos {} for excess {:?}",
							kernel_pos.pos, excess
						))
					})?;
				if kernel.excess() != *excess {
					return Err(Error::TxHashSetErr(format!(
						"kernel_pos index mismatch for excess {:?}: index points to {:?} at pos {}",
						excess,
						kernel.excess(),
						kernel_pos.pos
					)));
				}

				let header = self.get_header_for_kernel_index_with_header_pmmr(
					header_pmmr,
					kernel_pos.pos,
					Some(0),
					Some(head.height),
				)?;
				let height = header.height;
				if height != kernel_pos.height {
					return Err(Error::TxHashSetErr(format!(
						"kernel_pos index height mismatch for excess {:?}: pos {} indexed at height {}, actual height {}",
						excess, kernel_pos.pos, kernel_pos.height, height
					)));
				}

				if height < min_height {
					continue;
				}
				if height > max_height {
					break;
				}
				found = Some((kernel, height, kernel_pos.pos));
			}

			Ok(found)
		})
	}
	/// Gets the block header in which a given kernel mmr index appears in the txhashset.
	pub fn get_header_for_kernel_index(
		&self,
		kernel_mmr_index: u64,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<BlockHeader, Error> {
		self.with_robust_header_pmmr_read(|header_pmmr| {
			self.get_header_for_kernel_index_with_header_pmmr(
				header_pmmr,
				kernel_mmr_index,
				min_height,
				max_height,
			)
		})
	}

	fn get_header_for_kernel_index_with_header_pmmr(
		&self,
		header_pmmr: &PMMRHandle<BlockHeader>,
		kernel_mmr_index: u64,
		min_height: Option<u64>,
		max_height: Option<u64>,
	) -> Result<BlockHeader, Error> {
		let batch = self
			.store
			.batch_read()
			.map_err(|e| Error::StoreErr(e, "chain kernel header read batch".to_owned()))?;
		let body_head = batch
			.head()
			.map_err(|e| Error::StoreErr(e, "chain head".to_owned()))?;
		let get_body_header = |height| {
			self.body_chain_header_at_height_maybe_fast(header_pmmr, &batch, &body_head, height)
		};

		let min_height = min_height.unwrap_or(0);
		let head_height = body_head.height;
		let max_height = max_height.unwrap_or(head_height);

		if kernel_mmr_index == 0 {
			return Err(Error::DataOverflow(
				"Chain::get_header_for_kernel_index, kernel_mmr_index=0".to_string(),
			));
		}
		if min_height > max_height {
			return Err(Error::DataOverflow(format!(
				"Chain::get_header_for_kernel_index, min_height={}, max_height={}",
				min_height, max_height
			)));
		}
		if max_height > head_height {
			return Err(Error::InvalidHeaderHeight(max_height));
		}

		let min_prev_kernel_mmr_size = if min_height == 0 {
			0
		} else {
			// min_height - 1 is safe because min_height>0
			let prev_height = min_height - 1;
			get_body_header(prev_height)?.kernel_mmr_size
		};
		let max_header = get_body_header(max_height)?;
		if kernel_mmr_index <= min_prev_kernel_mmr_size
			|| kernel_mmr_index > max_header.kernel_mmr_size
		{
			return Err(Error::DataOverflow(format!(
				"Chain::get_header_for_kernel_index, kernel_mmr_index={}, min_height={}, max_height={}",
				kernel_mmr_index, min_height, max_height
			)));
		}

		let mut min = min_height;
		let mut max = max_height;
		while min < max {
			// All operations are safe because min/max and result less or equal to max
			let search_height = min + (max - min) / 2;
			let h = get_body_header(search_height)?;
			if kernel_mmr_index <= h.kernel_mmr_size {
				max = search_height;
			} else {
				min = search_height.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"Chain::get_header_for_kernel_index, search_height={}",
						search_height
					))
				})?;
			}
		}

		let header = get_body_header(min)?;
		let prev_kernel_mmr_size = if min == 0 {
			0
		} else {
			// safe because min>0
			let prev_height = min - 1;
			get_body_header(prev_height)?.kernel_mmr_size
		};
		if kernel_mmr_index <= prev_kernel_mmr_size || kernel_mmr_index > header.kernel_mmr_size {
			return Err(Error::DataOverflow(format!(
				"Chain::get_header_for_kernel_index, kernel_mmr_index={}, height={}",
				kernel_mmr_index, header.height
			)));
		}
		Ok(header)
	}

	/// Verifies the given block header is actually on the current chain.
	/// Checks the header_by_height index to verify the header is where we say
	/// it is
	fn is_on_current_chain(&self, x: Tip, head: Tip) -> Result<bool, Error> {
		self.with_robust_header_pmmr_read(|header_pmmr| {
			self.is_on_current_chain_with_header_pmmr(header_pmmr, x, head)
		})
	}

	fn is_on_current_chain_with_header_pmmr(
		&self,
		header_pmmr: &PMMRHandle<BlockHeader>,
		x: Tip,
		head: Tip,
	) -> Result<bool, Error> {
		if x.height > head.height {
			return Ok(false);
		}

		if x.hash(self.store.get_context_id())?
			== header_pmmr.get_header_hash_by_height(x.height)?
		{
			Ok(true)
		} else {
			Ok(false)
		}
	}

	fn body_chain_header_at_height(
		&self,
		batch: &Batch<'_>,
		body_head: &Tip,
		height: u64,
	) -> Result<BlockHeader, Error> {
		if height > body_head.height {
			return Err(Error::ChainInSyncing(format!(
				"body chain head is at {}, below requested height {}",
				body_head.height, height
			)));
		}

		let context_id = self.store.get_context_id();
		let mut current = batch.get_block_header(&body_head.hash(context_id)?)?;
		while current.height > height {
			let prev = batch.get_previous_header(&current)?;
			if prev.height >= current.height {
				return Err(Error::Other(format!(
					"body chain header traversal did not decrease height: {} -> {}",
					current.height, prev.height
				)));
			}
			current = prev;
		}
		if current.height != height {
			return Err(Error::Other(format!(
				"body chain header traversal stopped at height {}, below requested height {}",
				current.height, height
			)));
		}
		Ok(current)
	}

	fn body_chain_header_at_height_maybe_fast(
		&self,
		header_pmmr: &PMMRHandle<BlockHeader>,
		batch: &Batch<'_>,
		body_head: &Tip,
		height: u64,
	) -> Result<BlockHeader, Error> {
		if height > body_head.height {
			return Err(Error::ChainInSyncing(format!(
				"body chain head is at {}, below requested height {}",
				body_head.height, height
			)));
		}

		let context_id = self.store.get_context_id();
		let header_head_height = batch
			.header_head()
			.map_err(|e| Error::StoreErr(e, "body chain header fast path header head".to_owned()))?
			.height;
		let mut current = batch.get_block_header(&body_head.hash(context_id)?)?;

		loop {
			if current.height == height {
				return Ok(current);
			}
			if current.height < height {
				return Err(Error::Other(format!(
					"body chain header traversal stopped at height {}, below requested height {}",
					current.height, height
				)));
			}

			if current.height <= header_head_height {
				let header_pmmr_hash = header_pmmr.get_header_hash_by_height(current.height)?;
				if current.hash(context_id)? == header_pmmr_hash {
					let hash = header_pmmr.get_header_hash_by_height(height)?;
					return batch.get_block_header(&hash).map_err(|e| {
						Error::StoreErr(e, "body chain header fast path get header".to_owned())
					});
				}
			}

			current = batch.get_previous_header(&current)?;
		}
	}

	fn is_on_body_chain(&self, header: &BlockHeader, body_head: Tip) -> Result<bool, Error> {
		if header.height > body_head.height {
			return Ok(false);
		}

		let context_id = self.store.get_context_id();
		let header_hash = header.hash(context_id)?;
		let mut current = self.get_block_header(&body_head.hash(context_id)?)?;
		while current.height > header.height {
			current = self.get_previous_header(&current)?;
		}

		Ok(current.hash(context_id)? == header_hash)
	}

	fn is_on_body_chain_with_batch(
		&self,
		batch: &Batch<'_>,
		header: &BlockHeader,
		body_head: &Tip,
	) -> Result<bool, Error> {
		if header.height > body_head.height {
			return Ok(false);
		}

		let context_id = self.store.get_context_id();
		let header_hash = header.hash(context_id)?;
		let current = self.body_chain_header_at_height(batch, body_head, header.height)?;

		Ok(current.hash(context_id)? == header_hash)
	}

	/// Gets multiple headers at the provided heights.
	/// Note: Uses the sync pmmr, not the header pmmr.
	/// Note: This is based on the provided sync_head to support syncing against a fork.
	pub fn get_locator_hashes(&self, sync_head: Tip, heights: &[u64]) -> Result<Vec<Hash>, Error> {
		self.ensure_chain_robust()?;
		let context_id = self.store.get_context_id();
		let sync_head_hash = sync_head.hash(context_id)?;

		loop {
			let mut header_pmmr = self.header_pmmr.write();
			if self.requires_init_recovery.load(Ordering::SeqCst) {
				drop(header_pmmr);
				self.ensure_chain_robust()?;
				continue;
			}

			return self.with_locked_readonly_pmmr_discard_marker("get_locator_hashes", || {
				let batch_read = self.store.batch_read()?;
				txhashset::header_extending_readonly(&mut header_pmmr, batch_read, |ext, batch| {
					let header = batch.get_block_header(&sync_head_hash)?;
					self.rewind_and_apply_header_fork(&header, ext, batch)?;

					let mut hashes = Vec::with_capacity(heights.len());

					for h in heights {
						if *h > sync_head.height {
							return Err(Error::InvalidHeaderHeight(*h));
						}

						let hash = ext.get_header_hash_by_height(*h)?.ok_or_else(|| {
							Error::Other(format!(
								"missing header PMMR entry for locator height {} after rewinding to sync head {} at height {}",
								h, sync_head_hash, sync_head.height
							))
						})?;
						hashes.push(hash);
					}

					Ok(hashes)
				})
			});
		}
	}

	/// Builds an iterator on blocks starting from the current chain head and
	/// running backward. Specialized to return information pertaining to block
	/// difficulty calculation (timestamp and previous difficulties).
	pub fn difficulty_iter(&self) -> Result<store::DifficultyIter<'_>, Error> {
		self.ensure_chain_robust()?;
		let head = self.head()?;
		self.difficulty_iter_from(head.last_block_h)
	}

	/// Builds an iterator on blocks starting from the provided block hash and
	/// running backward. Specialized to return information pertaining to block
	/// difficulty calculation (timestamp and previous difficulties).
	pub fn difficulty_iter_from(&self, start: Hash) -> Result<store::DifficultyIter<'_>, Error> {
		self.ensure_chain_robust()?;
		Ok(store::DifficultyIter::from(start, self.store.clone()))
	}

	/// Check whether we have a block without reading it
	pub fn block_exists(&self, h: &Hash) -> Result<bool, Error> {
		self.ensure_chain_robust()?;
		self.store
			.block_exists(h)
			.map_err(|e| Error::StoreErr(e, "chain block exists".to_owned()))
	}

	/// Locate headers from the main chain.
	pub fn locate_headers(
		&self,
		locator: &[Hash],
		block_header_num: u32,
	) -> Result<Vec<mwc_core::core::BlockHeader>, crate::Error> {
		self.ensure_chain_robust()?;
		debug!("locator: {:?}", locator);

		let header = match self.find_common_header(locator)? {
			Some(header) => header,
			None => return Ok(vec![]),
		};

		// looks like we know one, getting as many following headers as allowed
		let hh = header.height;
		let start_height = hh.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!("Chain::locate_headers, start height hh={}", hh))
		})?;
		let end_height = hh.checked_add(block_header_num as u64).ok_or_else(|| {
			Error::DataOverflow(format!(
				"Chain::locate_headers, end height hh={} block_header_num={}",
				hh, block_header_num
			))
		})?;
		let header_hashes = self.with_robust_header_pmmr_read(|header_pmmr| {
			// Do not call self.header_head() while holding header_pmmr. It can
			// trigger init recovery, which needs header_pmmr.write().
			let max_height = self
				.store
				.header_head()
				.map_err(|e| Error::StoreErr(e, "locate headers header head".to_owned()))?
				.height;
			let mut header_hashes = vec![];
			for h in start_height..=end_height {
				if h > max_height {
					break;
				}

				header_hashes.push(header_pmmr.get_header_hash_by_height(h)?);
			}
			Ok(header_hashes)
		})?;

		let mut headers = Vec::with_capacity(header_hashes.len());
		for hash in header_hashes {
			let header = self.get_block_header(&hash)?;
			headers.push(header);
		}
		debug!("returning headers: {}", headers.len());
		Ok(headers)
	}

	// Find the first locator hash that refers to a known header on our main chain.
	fn find_common_header(&self, locator: &[Hash]) -> Result<Option<BlockHeader>, Error> {
		self.with_robust_header_pmmr_read(|header_pmmr| {
			let header_head_height = self
				.store
				.header_head()
				.map_err(|e| Error::StoreErr(e, "chain header head".to_owned()))?
				.height;
			let context_id = self.store.get_context_id();
			let get_block_header = |hash: &Hash| {
				self.store
					.get_block_header(hash)
					.map_err(|e| Error::StoreErr(e, "chain get header".to_owned()))
			};
			for hash in locator {
				let header = match get_block_header(hash) {
					Ok(header) => header,
					Err(Error::StoreErr(NotFoundErr(_), _)) => continue,
					Err(e) => return Err(e),
				};
				if header.height > header_head_height {
					continue;
				}
				let hash_at_height = header_pmmr.get_header_hash_by_height(header.height)?;
				let header_at_height = get_block_header(&hash_at_height)?;
				if header.hash(context_id)? == header_at_height.hash(context_id)? {
					return Ok(Some(header));
				}
			}
			Ok(None)
		})
	}

	/// App sesion id, defines network
	pub fn get_context_id(&self) -> u32 {
		self.store.get_context_id()
	}
}

fn reset_pibd_chain_state(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
) -> Result<(), Error> {
	reset_chain_head_to_genesis_state(genesis, store, header_pmmr, txhashset, secp)?;
	Ok(())
}

fn prepare_reset_chain_head_operation(
	store: &store::ChainStore,
	header: &BlockHeader,
	rewind_headers: bool,
) -> Result<PendingChainOperation, Error> {
	let batch = store.batch_read()?;
	let original_body_head = batch.head()?;
	let original_header_head = batch.header_head()?;
	let target_header = batch.get_block_header(&header.hash(store.get_context_id())?)?;
	let target_body_head = Tip::try_from_header(&target_header)?;
	let target_header_head = if rewind_headers {
		target_body_head
	} else {
		original_header_head
	};
	Ok(PendingChainOperation::ResetChainHead {
		original_body_head,
		original_header_head,
		target_body_head,
		target_header_head,
		rewind_headers,
	})
}

fn prepare_reconcile_heads_operation(
	store: &store::ChainStore,
	kind: ChainOperationKind,
) -> Result<PendingChainOperation, Error> {
	let batch = store.batch_read()?;
	Ok(PendingChainOperation::ReconcileHeads {
		kind,
		original_body_head: batch.head()?,
		original_header_head: batch.header_head()?,
	})
}

fn recover_pending_chain_operation(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
) -> Result<(), Error> {
	let op = match store.pending_chain_operation()? {
		None => return Ok(()),
		Some(op) => op,
	};

	warn!("Detected incomplete chain operation: {:?}", op.kind());
	recover_marked_chain_operation(genesis, store, header_pmmr, txhashset, secp, &op, true)
}

fn recover_marked_chain_operation(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	op: &PendingChainOperation,
	allow_full_reset: bool,
) -> Result<(), Error> {
	let res = match op {
		PendingChainOperation::PibdReset => {
			reset_pibd_chain_state(genesis, store, header_pmmr, txhashset, secp)
		}
		PendingChainOperation::ResetToGenesis => {
			reset_chain_head_to_genesis_state(genesis, store, header_pmmr, txhashset, secp)
		}
		PendingChainOperation::ResetChainHead { .. }
		| PendingChainOperation::ReconcileHeads { .. } => {
			reconcile_pmmrs_to_db_heads(store, header_pmmr, txhashset, secp)
		}
	};

	match res {
		Ok(()) => {
			store.clear_pending_chain_operation()?;
			Ok(())
		}
		Err(e) if allow_full_reset => {
			// The original recovery error is logged but not propagated here.
			// If the full reset and marker cleanup succeed, treat recovery as
			// successful and let callers continue with the reset chain state.
			error!(
				"failed to recover {:?} by reconciling heads; resetting chain state to genesis: {}",
				op.kind(),
				e
			);
			reset_pibd_chain_state(genesis, store, header_pmmr, txhashset, secp)?;
			store.clear_pending_chain_operation()?;
			Ok(())
		}
		Err(e) => Err(e),
	}
}

fn reconcile_pmmrs_to_db_heads(
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
) -> Result<(), Error> {
	let context_id = store.get_context_id();
	let batch = store.batch_read()?;
	let body_head = batch.head()?;
	let header_head = batch.header_head()?;
	let body_header = batch.get_block_header(&body_head.hash(context_id)?)?;
	let header_header = batch.get_block_header(&header_head.hash(context_id)?)?;
	drop(batch);

	reconcile_body_pmmr_to_header(store, header_pmmr, txhashset, secp, &body_header)?;
	reconcile_header_pmmr_to_header(store, header_pmmr, &header_header)?;
	Ok(())
}

fn reconcile_body_pmmr_to_header(
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	header: &BlockHeader,
) -> Result<(), Error> {
	let mut batch = store.batch_write()?;
	txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
		pipe::rewind_and_apply_fork(store.get_context_id(), header, ext, batch, secp)?;
		ext.extension.validate_roots(header)?;
		ext.extension.validate_sizes(header)?;
		Ok(())
	})?;
	batch.commit()?;
	Ok(())
}

fn reconcile_header_pmmr_to_header(
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	header: &BlockHeader,
) -> Result<(), Error> {
	let mut batch = store.batch_write()?;
	txhashset::header_extending(header_pmmr, &mut batch, |ext, batch| {
		pipe::rewind_and_apply_header_fork(store.get_context_id(), header, ext, batch)
	})?;
	batch.commit()?;
	Ok(())
}

fn reset_chain_head_state(
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
	header: &BlockHeader,
	rewind_headers: bool,
) -> Result<(), Error> {
	let head = Tip::try_from_header(header)?;
	let mut batch = store.batch_write()?;

	let header = batch.get_block_header(&head.hash(store.get_context_id())?)?;
	// rebuilding head from loaded data, input header can be tweaked
	let head = Tip::try_from_header(&header)?;

	// Rewind and reapply blocks to reset the output/rangeproof/kernel MMR.
	txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
		pipe::rewind_and_apply_fork(store.get_context_id(), &header, ext, batch, secp)?;
		ext.extension.validate_roots(&header)?;
		ext.extension.validate_sizes(&header)?;
		batch.save_body_head(&head)?;
		Ok(())
	})?;

	if rewind_headers {
		// If the rewind of full blocks was successful then we can rewind the header MMR.
		// Rewind and reapply headers to reset the header MMR.
		txhashset::header_extending(header_pmmr, &mut batch, |ext, batch| {
			pipe::rewind_and_apply_header_fork(store.get_context_id(), &header, ext, batch)?;
			batch.save_header_head(&head)?;
			Ok(())
		})?;
	}

	batch.commit()?;
	Ok(())
}

fn combine_positioned_outputs_and_rangeproofs(
	outputs: (u64, Vec<(u64, OutputIdentifier)>),
	rangeproofs: (u64, Vec<(u64, RangeProof)>),
) -> Result<(u64, Vec<Output>), Error> {
	if outputs.0 != rangeproofs.0 || outputs.1.len() != rangeproofs.1.len() {
		return Err(Error::TxHashSetErr(String::from(
			"Output and rangeproof sets don't match",
		)));
	}

	let index = outputs.0;
	let mut output_vec = Vec::with_capacity(outputs.1.len());
	for ((output_pos, output), (rangeproof_pos, rangeproof)) in
		outputs.1.into_iter().zip(rangeproofs.1.into_iter())
	{
		// output_pos and rangeproof_pos are 1-based PMMR indexes.
		if output_pos != rangeproof_pos {
			return Err(Error::TxHashSetErr(format!(
				"Output and rangeproof PMMR positions don't match: output position {}, rangeproof position {}",
				output_pos, rangeproof_pos
			)));
		}
		output_vec.push(Output::new(
			output.features,
			output.commitment(),
			rangeproof,
		));
	}
	Ok((index, output_vec))
}

fn reset_chain_head_to_genesis_state(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut PMMRHandle<BlockHeader>,
	txhashset: &mut TxHashSet,
	secp: &Secp256k1,
) -> Result<(), Error> {
	validate_genesis_context_id(genesis, store.get_context_id())?;
	let head = Tip::try_from_header(&genesis.header)?;
	setup_head(genesis, store, header_pmmr, txhashset, secp, Some(head))
}

fn is_recoverable_mmr_corruption(e: &Error) -> bool {
	matches!(
		e,
		Error::PMMRErr(mwc_core::core::pmmr::Error::DataCorruption(_))
	)
}

fn validate_genesis_context_id(genesis: &Block, context_id: u32) -> Result<(), Error> {
	let genesis_context_id = genesis.header.pow.proof.context_id;
	if genesis_context_id != context_id {
		error!(
			"genesis proof context_id mismatch: expected {}, got {}",
			context_id, genesis_context_id
		);
		return Err(Error::InvalidGenesisHash);
	}
	Ok(())
}

fn validate_genesis_for_init(
	secp: &Secp256k1,
	context_id: u32,
	genesis: &Block,
	pow_verifier: fn(u32, &BlockHeader) -> Result<(), pow::Error>,
) -> Result<(), Error> {
	validate_genesis_context_id(genesis, context_id)?;

	if genesis.header.height != 0 {
		return Err(Error::InvalidGenesisHash);
	}

	if !consensus::valid_header_version(context_id, genesis.header.height, genesis.header.version) {
		return Err(Error::InvalidBlockVersion(genesis.header.version));
	}

	if !genesis.header.pow.is_primary(context_id) && !genesis.header.pow.is_secondary() {
		return Err(Error::LowEdgebits);
	}

	// Mainnet and Floonet genesis blocks are fixed consensus identities. Their
	// historical Cuckarood29 proofs do not pass the current runtime verifier:
	// the verifier now requires a 42-edge proof to be parity-balanced, while
	// both hardcoded genesis proofs are 23 even / 19 odd. Re-mining or editing
	// those proofs would change the genesis hash, so accept only the exact
	// hardcoded genesis block by canonical serialization. Testing chain types
	// may still rely on the supplied PoW verifier for custom genesis blocks.
	match global::get_chain_type(context_id) {
		global::ChainTypes::Floonet | global::ChainTypes::Mainnet => {
			if is_known_hardcoded_genesis(secp, context_id, genesis)? {
				return Ok(());
			}
			return Err(Error::InvalidGenesisHash);
		}
		global::ChainTypes::AutomatedTesting | global::ChainTypes::UserTesting => {
			// Accepted risk: custom testing genesis blocks are intentionally
			// validated only far enough to initialize local test chain state.
			// We validate the context/header/PoW here, and setup_head later
			// checks kernel sums plus PMMR roots and sizes, but we do not run
			// the normal Block::validate/TransactionBody::validate checks for
			// rangeproofs, kernel signatures, coinbase rules, lock heights, or
			// NRD feature rules. These chain types are for synthetic test
			// chains, so custom testing genesis blocks do not need the full
			// production body validation required by Mainnet/Floonet genesis.
		}
	}

	match pow_verifier(context_id, &genesis.header) {
		Ok(()) => Ok(()),
		Err(pow::Error::Verification(e)) => {
			debug!(
				"init: invalid PoW for genesis header with cuckoo edge_bits {}: {}",
				genesis.header.pow.edge_bits(),
				e
			);
			Err(Error::InvalidPow)
		}
		Err(e) => {
			debug!(
				"init: PoW verifier failed for genesis header with cuckoo edge_bits {}: {}",
				genesis.header.pow.edge_bits(),
				e
			);
			Err(e.into())
		}
	}
}

fn is_known_hardcoded_genesis(
	secp: &Secp256k1,
	context_id: u32,
	genesis: &Block,
) -> Result<bool, Error> {
	match global::get_chain_type(context_id) {
		global::ChainTypes::Floonet => is_exact_genesis_match(
			context_id,
			genesis,
			&genesis::genesis_floo(secp, context_id),
		),
		global::ChainTypes::Mainnet => is_exact_genesis_match(
			context_id,
			genesis,
			&genesis::genesis_main(secp, context_id),
		),
		global::ChainTypes::AutomatedTesting | global::ChainTypes::UserTesting => Ok(false),
	}
}

fn is_exact_genesis_match(
	context_id: u32,
	genesis: &Block,
	expected_genesis: &Block,
) -> Result<bool, Error> {
	let mut genesis_bytes = Vec::new();
	ser::serialize_default(context_id, &mut genesis_bytes, genesis)?;

	let mut expected_bytes = Vec::new();
	ser::serialize_default(context_id, &mut expected_bytes, expected_genesis)?;

	Ok(genesis_bytes == expected_bytes)
}

fn validate_genesis_matches_header_pmmr(
	genesis_hash: &Hash,
	header_pmmr: &txhashset::PMMRHandle<BlockHeader>,
) -> Result<(), Error> {
	if header_pmmr.size == 0 {
		return Ok(());
	}

	let stored_genesis_hash = header_pmmr.get_header_hash_by_height(0)?;
	if stored_genesis_hash != *genesis_hash {
		error!(
			"genesis hash mismatch: expected {}, got {}",
			stored_genesis_hash, genesis_hash
		);
		return Err(Error::InvalidGenesisHash);
	}
	Ok(())
}

fn genesis_block_sums(
	genesis: &Block,
	context_id: u32,
	secp: &Secp256k1,
) -> Result<BlockSums, Error> {
	if genesis.inputs().is_empty() && genesis.outputs().is_empty() && genesis.kernels().is_empty() {
		if !genesis.header.total_kernel_offset().is_zero() {
			return Err(Error::Committed(
				mwc_core::core::committed::Error::KernelSumMismatch,
			));
		}
		return Ok(BlockSums::empty());
	}

	let (utxo_sum, kernel_sum) = (BlockSums::empty(), genesis as &dyn Committed)
		.verify_kernel_sums(
			genesis.header.overage(context_id)?,
			genesis.header.total_kernel_offset(),
			secp,
		)?;
	Ok(BlockSums::new(utxo_sum, kernel_sum))
}

fn save_genesis_block_metadata(
	genesis: &Block,
	genesis_hash: &Hash,
	batch: &store::Batch<'_>,
	secp: &Secp256k1,
	context_id: u32,
) -> Result<(), Error> {
	batch.save_block(genesis)?;
	batch.save_spent_index(genesis_hash, &vec![])?;
	batch.save_block_sums(genesis_hash, genesis_block_sums(genesis, context_id, secp)?)?;
	Ok(())
}

fn setup_head(
	genesis: &Block,
	store: &store::ChainStore,
	header_pmmr: &mut txhashset::PMMRHandle<BlockHeader>,
	txhashset: &mut txhashset::TxHashSet,
	secp: &Secp256k1,
	body_head_override: Option<Tip>,
) -> Result<(), Error> {
	let context_id = store.get_context_id();
	validate_genesis_context_id(genesis, context_id)?;

	let mut batch = store.batch_write()?;
	let genesis_hash = genesis.hash(context_id)?;
	validate_genesis_matches_header_pmmr(&genesis_hash, header_pmmr)?;
	// Apply the genesis header to header and sync MMRs.
	{
		match batch.get_block_header(&genesis_hash) {
			Ok(_) => {}
			Err(NotFoundErr(_)) => {
				batch.save_block_header(&genesis.header)?;
			}
			Err(e) => return Err(Error::StoreErr(e, "chain init load genesis header".into())),
		}

		if header_pmmr.size == 0 {
			txhashset::header_extending(header_pmmr, &mut batch, |ext, _| {
				ext.apply_header(&genesis.header)
			})?;
		}
	}

	// Make sure our header PMMR is consistent with header_head from db if it exists.
	// If header_head is missing in db then use head of header PMMR.
	match batch.header_head() {
		Ok(head) => {
			header_pmmr.init_head(&head)?;
			txhashset::header_extending(header_pmmr, &mut batch, |ext, batch| {
				let header = batch.get_block_header(&head.hash(context_id)?)?;
				ext.rewind(&header)
			})?;
		}
		Err(NotFoundErr(_)) => {
			let hash = header_pmmr.head_hash()?;
			let header = batch.get_block_header(&hash)?;
			batch.save_header_head(&Tip::try_from_header(&header)?)?;
		}
		Err(e) => return Err(Error::StoreErr(e, "chain init load header head".to_owned())),
	}

	if let Some(head) = body_head_override {
		// Stage intentional HEAD resets in the same batch as the rewind and
		// validation below. Committing HEAD first can leave durable chain
		// metadata reset even if setup_head later fails while syncing or
		// rewinding PMMR state.
		if head.height == 0 && head.last_block_h == genesis_hash {
			// Recreate metadata normally created by the missing-head genesis
			// init branch, then rebuild the body MMRs from genesis instead of
			// only rewinding to the sizes committed in the genesis header.
			save_genesis_block_metadata(genesis, &genesis_hash, &batch, secp, context_id)?;

			txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
				ext.extension.reset_prune_lists()?;
				ext.extension
					.rebuild_genesis(genesis, ext.header_extension, batch)?;
				ext.extension.validate_roots(&genesis.header)?;
				ext.extension.validate_sizes(&genesis.header)?;
				batch.save_body_tail(&head)?;
				batch.save_body_head(&head)?;
				Ok(())
			})?;

			txhashset.init_output_pos_index(&batch, None, None)?;
			txhashset.init_recent_kernel_pos_index(header_pmmr, &batch, None, None)?;
			batch.commit()?;
			return Ok(());
		}
		batch.save_body_head(&head)?;
	}

	// check if we have a head in store, otherwise the genesis block is it
	let head_res = batch.head();
	let mut head: Tip;
	match head_res {
		Ok(h) => {
			head = h;
			loop {
				// Use current chain tip if we have one.
				// Note: We are rewinding and validating against a writeable extension.
				// If validation is successful we will truncate the backend files
				// to match the provided block header.
				let header = batch.get_block_header(&head.last_block_h)?;
				let output_mmr_size_before = txhashset.output_mmr_size();
				let kernel_mmr_size_before = txhashset.kernel_mmr_size();

				let res = txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
					// If we're still downloading via PIBD, don't worry about sums and validations just yet
					// We still want to rewind to the last completed block to ensure a consistent state

					pipe::rewind_and_apply_fork(store.get_context_id(), &header, ext, batch, secp)?;

					let extension = &mut ext.extension;

					extension.validate_roots(&header)?;
					extension.validate_sizes(&header)?;

					// now check we have the "block sums" for the block in question
					// if we have no sums (migrating an existing node) we need to go
					// back to the txhashset and sum the outputs and kernels
					if header.height > 0 {
						let header_hash = header.hash(context_id)?;
						match batch.get_block_sums(&header_hash) {
							Ok(_) => {}
							Err(NotFoundErr(_)) => {
								debug!(
									"init: building (missing) block sums for {} @ {}",
									header.height, header_hash
								);

								// Do a full (and slow) validation of the txhashset extension
								// to calculate the utxo_sum and kernel_sum at this block height.
								let (utxo_sum, kernel_sum) = extension.validate_kernel_sums(
									&genesis.header,
									&header,
									None,
									None,
									secp,
								)?;

								// Save the block_sums to the db for use later.
								batch.save_block_sums(
									&header_hash,
									BlockSums::new(utxo_sum, kernel_sum),
								)?;
							}
							Err(e) => {
								return Err(Error::StoreErr(
									e,
									"chain init load block sums".to_owned(),
								));
							}
						}
					}

					debug!(
						"init: rewinding and validating before we start... {} at {}",
						header.hash(context_id)?,
						header.height,
					);
					Ok(())
				});

				match res {
					Ok(()) => {
						let output_mmr_size_after = txhashset.output_mmr_size();
						let kernel_mmr_size_after = txhashset.kernel_mmr_size();
						let output_mmr_rewound = output_mmr_size_before > output_mmr_size_after;
						let kernel_mmr_rewound = kernel_mmr_size_before > kernel_mmr_size_after;
						if output_mmr_rewound {
							debug!(
								"init: output PMMR rewound from {} to {}; marking output_pos index incomplete",
								output_mmr_size_before, output_mmr_size_after
							);
							batch.set_output_pos_index_complete(false)?;
						}
						if kernel_mmr_rewound {
							debug!(
								"init: kernel PMMR rewound from {} to {}; marking kernel_pos index incomplete",
								kernel_mmr_size_before, kernel_mmr_size_after
							);
							batch.set_kernel_pos_index_complete(false)?;
						}
						if output_mmr_rewound || kernel_mmr_rewound {
							batch.set_retained_spent_commitment_index_complete(false)?;
						}
						break;
					}
					Err(e) => {
						if !is_recoverable_mmr_corruption(&e) {
							return Err(e);
						}

						// We may have corrupted the MMR backend files last time we stopped the
						// node. If this happens we rewind to the previous header,
						// delete the "bad" block and try again.
						let prev_header = batch.get_block_header(&head.prev_block_h)?;

						warn!(
							"Corrupted MMR: {}. Trying to recover it by rewinding blocks to height {}",
							e, prev_header.height
						);

						txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
							pipe::rewind_and_apply_fork(
								store.get_context_id(),
								&prev_header,
								ext,
								batch,
								secp,
							)
						})?;

						// Now "undo" the latest block and forget it ever existed.
						// We will request it from a peer during sync as necessary.
						{
							batch.delete_block(&header.hash(context_id)?)?;
							head = Tip::try_from_header(&prev_header)?;
							batch.save_body_head(&head)?;
						}
					}
				}
			}
		}
		Err(NotFoundErr(_)) => {
			// Save the genesis header with a "zero" header_root.
			// We will update this later once we have the correct header_root.
			save_genesis_block_metadata(genesis, &genesis_hash, &batch, secp, context_id)?;
			batch.save_body_head(&Tip::try_from_header(&genesis.header)?)?;

			txhashset::extending(header_pmmr, txhashset, &mut batch, |ext, batch| {
				ext.extension.reset_prune_lists()?;
				ext.extension
					.rebuild_genesis(genesis, ext.header_extension, batch)?;
				ext.extension.validate_roots(&genesis.header)?;
				ext.extension.validate_sizes(&genesis.header)?;
				Ok(())
			})?;

			info!("init: saved genesis: {}", genesis_hash);
		}
		Err(e) => return Err(Error::StoreErr(e, "chain init load head".to_owned())),
	};
	batch.commit()?;
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::core::OutputFeatures;
	use mwc_crates::secp::constants::MAX_PROOF_SIZE;

	fn reject_pow(_: u32, _: &BlockHeader) -> Result<(), pow::Error> {
		Err(pow::Error::Verification(
			"forced genesis PoW failure".into(),
		))
	}

	fn test_output_identifier() -> OutputIdentifier {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(1).unwrap();
		OutputIdentifier::new(OutputFeatures::Plain, &commit)
	}

	fn test_rangeproof() -> RangeProof {
		RangeProof {
			plen: 0,
			proof: [0; MAX_PROOF_SIZE],
		}
	}

	fn retained_test_block(height: u64, prev_hash: Hash, proof_nonce: u64) -> Block {
		let mut block = Block::default(0);
		block.header.height = height;
		block.header.prev_hash = prev_hash;
		if let Some(last_nonce) = block.header.pow.proof.nonces.last_mut() {
			*last_nonce = proof_nonce;
		}
		block
	}

	fn save_retained_test_blocks(
		store: &ChainStore,
		head: &Block,
		tail: &Block,
		blocks: &[&Block],
	) {
		let batch = store.batch_write().unwrap();
		for block in blocks {
			batch.save_block_header(&block.header).unwrap();
			batch.save_block(block).unwrap();
		}
		batch
			.save_body_head(&Tip::try_from_header(&head.header).unwrap())
			.unwrap();
		batch
			.save_body_tail(&Tip::try_from_header(&tail.header).unwrap())
			.unwrap();
		batch
			.set_retained_spent_commitment_index_complete(false)
			.unwrap();
		batch.commit().unwrap();
	}

	fn assert_retained_spent_commitment_index_incomplete(store: &ChainStore) {
		assert!(!store
			.batch_read()
			.unwrap()
			.is_retained_spent_commitment_index_complete()
			.unwrap());
	}

	#[test]
	fn replay_attack_check_fails_when_spent_commitment_index_incomplete() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/replay_attack_check_fails_when_spent_commitment_index_incomplete_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let chain = Chain::init(
			&secp,
			0,
			chain_dir.clone(),
			Arc::new(crate::types::NoopAdapter {}),
			global::get_genesis_block(&secp, 0).unwrap(),
			pow::verify_size,
			false,
			HashSet::new(),
			None,
			None,
		)
		.unwrap();

		{
			let store = chain.get_store_for_tests();
			let batch = store.batch_write().unwrap();
			batch
				.set_retained_spent_commitment_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		let err = chain
			.replay_attack_check(&Transaction::empty())
			.unwrap_err();
		assert!(matches!(err, Error::SpentCommitmentIndexIncomplete));

		drop(chain);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rebuilds_retained_blocks() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_spent_commitment_index_rebuilds_retained_blocks_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let spent_commit = secp.commit_value(7).unwrap();
		let stale_commit = secp.commit_value(8).unwrap();
		let mut block = Block::default(0);
		block.header.height = 9;
		block.body.inputs = Inputs::FeaturesAndCommit(vec![mwc_core::core::Input::new(
			OutputFeatures::Plain,
			spent_commit,
		)]);
		let block_hash = block.hash(0).unwrap();

		{
			let batch = store.batch_write().unwrap();
			let tip = Tip::try_from_header(&block.header).unwrap();
			batch.save_block_header(&block.header).unwrap();
			batch.save_block(&block).unwrap();
			batch.save_body_head(&tip).unwrap();
			batch.save_body_tail(&tip).unwrap();
			batch
				.save_spent_commitments(
					&stale_commit,
					HashHeight {
						hash: Hash::from_vec(&[9; Hash::LEN]),
						height: 99,
					},
				)
				.unwrap();
			batch
				.set_retained_spent_commitment_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		Chain::init_spent_commitment_index(&store).unwrap();

		let batch = store.batch_read().unwrap();
		assert!(batch.is_retained_spent_commitment_index_complete().unwrap());
		assert!(batch
			.get_spent_commitments(&stale_commit)
			.unwrap()
			.is_none());
		assert_eq!(
			batch.get_spent_commitments(&spent_commit).unwrap(),
			Some(vec![HashHeight {
				hash: block_hash,
				height: 9,
			}])
		);

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_empty_retained_spent_commitment_index_clears_stale_entries_without_body_tail() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_empty_retained_spent_commitment_index_clears_stale_entries_without_body_tail_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let stale_commit = secp.commit_value(8).unwrap();
		let block = retained_test_block(9, Hash::from_vec(&[1; Hash::LEN]), 1);
		let tip = Tip::try_from_header(&block.header).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&block.header).unwrap();
			batch.save_body_head(&tip).unwrap();
			batch
				.save_spent_commitments(
					&stale_commit,
					HashHeight {
						hash: Hash::from_vec(&[9; Hash::LEN]),
						height: 99,
					},
				)
				.unwrap();
			batch
				.set_retained_spent_commitment_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		Chain::init_empty_retained_spent_commitment_index(&store).unwrap();

		let batch = store.batch_read().unwrap();
		assert!(batch.tail().is_err());
		assert!(batch.is_retained_spent_commitment_index_complete().unwrap());
		assert!(batch
			.get_spent_commitments(&stale_commit)
			.unwrap()
			.is_none());

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rejects_missing_retained_block() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/init_spent_commitment_index_rejects_missing_retained_block_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let mut block = Block::default(0);
		block.header.height = 7;
		let tip = Tip::try_from_header(&block.header).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&block.header).unwrap();
			batch.save_body_head(&tip).unwrap();
			batch.save_body_tail(&tip).unwrap();
			batch
				.set_retained_spent_commitment_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		let err = Chain::init_spent_commitment_index(&store).unwrap_err();
		assert!(matches!(err, Error::SpentCommitmentIndexIncomplete));
		assert!(!store
			.batch_read()
			.unwrap()
			.is_retained_spent_commitment_index_complete()
			.unwrap());

		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_advances_stale_body_tail_when_tail_body_is_missing() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let chain_dir = format!(
			"target/init_spent_commitment_index_advances_stale_body_tail_when_tail_body_is_missing_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let spent_commit = secp.commit_value(7).unwrap();

		let old_tail = retained_test_block(1, Hash::from_vec(&[1; Hash::LEN]), 1);
		let old_tail_hash = old_tail.hash(0).unwrap();
		let mut new_tail = retained_test_block(2, old_tail_hash, 2);
		new_tail.body.inputs = Inputs::FeaturesAndCommit(vec![mwc_core::core::Input::new(
			OutputFeatures::Plain,
			spent_commit,
		)]);
		let new_tail_hash = new_tail.hash(0).unwrap();
		let head = retained_test_block(3, new_tail_hash, 3);

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&old_tail.header).unwrap();
			for block in [&new_tail, &head] {
				batch.save_block_header(&block.header).unwrap();
				batch.save_block(block).unwrap();
			}
			batch
				.save_body_head(&Tip::try_from_header(&head.header).unwrap())
				.unwrap();
			batch
				.save_body_tail(&Tip::try_from_header(&old_tail.header).unwrap())
				.unwrap();
			batch
				.set_retained_spent_commitment_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		Chain::init_spent_commitment_index(&store).unwrap();

		let batch = store.batch_read().unwrap();
		assert!(batch.is_retained_spent_commitment_index_complete().unwrap());
		assert_eq!(
			batch.tail().unwrap(),
			Tip::try_from_header(&new_tail.header).unwrap()
		);
		assert_eq!(
			batch.get_spent_commitments(&spent_commit).unwrap(),
			Some(vec![HashHeight {
				hash: new_tail_hash,
				height: 2,
			}])
		);

		drop(batch);
		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rejects_missing_middle_retained_body() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/init_spent_commitment_index_rejects_missing_middle_retained_body_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();

		let tail = retained_test_block(1, Hash::from_vec(&[1; Hash::LEN]), 1);
		let tail_hash = tail.hash(0).unwrap();
		let missing_middle = retained_test_block(2, tail_hash, 2);
		let missing_middle_hash = missing_middle.hash(0).unwrap();
		let head = retained_test_block(3, missing_middle_hash, 3);

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&tail.header).unwrap();
			batch.save_block(&tail).unwrap();
			batch.save_block_header(&missing_middle.header).unwrap();
			batch.save_block_header(&head.header).unwrap();
			batch.save_block(&head).unwrap();
			batch
				.save_body_head(&Tip::try_from_header(&head.header).unwrap())
				.unwrap();
			batch
				.save_body_tail(&Tip::try_from_header(&tail.header).unwrap())
				.unwrap();
			batch
				.set_retained_spent_commitment_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		let err = Chain::init_spent_commitment_index(&store).unwrap_err();
		assert!(matches!(err, Error::SpentCommitmentIndexIncomplete));
		assert_eq!(
			store.batch_read().unwrap().tail().unwrap(),
			Tip::try_from_header(&tail.header).unwrap()
		);
		assert_retained_spent_commitment_index_incomplete(&store);

		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rejects_missing_body_tail_on_non_fresh_chain() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/init_spent_commitment_index_rejects_missing_body_tail_on_non_fresh_chain_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();
		let mut block = Block::default(0);
		block.header.height = 7;
		let tip = Tip::try_from_header(&block.header).unwrap();

		{
			let batch = store.batch_write().unwrap();
			batch.save_block_header(&block.header).unwrap();
			batch.save_block(&block).unwrap();
			batch.save_body_head(&tip).unwrap();
			batch
				.set_retained_spent_commitment_index_complete(false)
				.unwrap();
			batch.commit().unwrap();
		}

		let err = Chain::init_spent_commitment_index(&store).unwrap_err();
		assert!(matches!(err, Error::Other(msg) if msg.contains("body tail is missing")));
		assert!(!store
			.batch_read()
			.unwrap()
			.is_retained_spent_commitment_index_complete()
			.unwrap());

		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rejects_skipped_retained_body_height() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/init_spent_commitment_index_rejects_skipped_retained_body_height_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();

		let tail = retained_test_block(1, Hash::from_vec(&[1; Hash::LEN]), 1);
		let tail_hash = tail.hash(0).unwrap();
		let head = retained_test_block(3, tail_hash, 2);
		save_retained_test_blocks(&store, &head, &tail, &[&tail, &head]);

		let err = Chain::init_spent_commitment_index(&store).unwrap_err();
		match err {
			Error::Other(msg) => assert!(
				msg.contains("expected height 2, found 1"),
				"unexpected error: {}",
				msg
			),
			other => panic!("unexpected error: {:?}", other),
		}
		assert_retained_spent_commitment_index_incomplete(&store);

		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn init_spent_commitment_index_rejects_non_descending_retained_body_height() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_nrd_enabled(false);
		let chain_dir = format!(
			"target/init_spent_commitment_index_rejects_non_descending_retained_body_height_{}",
			std::process::id()
		);
		let _ = fs::remove_dir_all(&chain_dir);
		let store = ChainStore::new(0, &chain_dir).unwrap();

		let tail = retained_test_block(1, Hash::from_vec(&[1; Hash::LEN]), 1);
		let tail_hash = tail.hash(0).unwrap();
		let same_height_prev = retained_test_block(3, tail_hash, 2);
		let same_height_prev_hash = same_height_prev.hash(0).unwrap();
		let head = retained_test_block(3, same_height_prev_hash, 3);
		save_retained_test_blocks(&store, &head, &tail, &[&tail, &same_height_prev, &head]);

		let err = Chain::init_spent_commitment_index(&store).unwrap_err();
		assert!(matches!(err, Error::Other(msg) if msg.contains("expected height 2, found 3")));
		assert_retained_spent_commitment_index_incomplete(&store);

		drop(store);
		let _ = fs::remove_dir_all(&chain_dir);
	}

	#[test]
	fn orphan_pool_merges_source_peers_for_duplicate_block() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let pool = OrphanBlockPool::new(Arc::new(PibdParams::new()));
		let block = Block::default(0);
		let hash = block.hash(0).unwrap();

		let mut first_peers = HashSet::new();
		first_peers.insert("127.0.0.1:3414".to_string());
		pool.add(
			0,
			Orphan {
				block: block.clone(),
				opts: Options::NONE,
				source_peers: first_peers,
				added: Instant::now(),
			},
		)
		.unwrap();

		let mut second_peers = HashSet::new();
		second_peers.insert("127.0.0.2:3414".to_string());
		pool.add(
			0,
			Orphan {
				block,
				opts: Options::NONE,
				source_peers: second_peers,
				added: Instant::now(),
			},
		)
		.unwrap();

		let orphan = pool.get_orphan(&hash).unwrap();
		assert_eq!(orphan.source_peers.len(), 2);
		assert!(orphan.source_peers.contains("127.0.0.1:3414"));
		assert!(orphan.source_peers.contains("127.0.0.2:3414"));

		let orphans = pool.remove_by_height(orphan.block.header.height).unwrap();
		assert_eq!(orphans.len(), 1);
	}

	#[test]
	fn orphan_pool_rejects_conflicting_body_for_same_header_hash() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let pool = OrphanBlockPool::new(Arc::new(PibdParams::new()));
		let block = Block::default(0);
		let hash = block.hash(0).unwrap();

		let mut first_peers = HashSet::new();
		first_peers.insert("127.0.0.1:3414".to_string());
		pool.add(
			0,
			Orphan {
				block,
				opts: Options::NONE,
				source_peers: first_peers,
				added: Instant::now(),
			},
		)
		.unwrap();

		let mut conflicting_block = Block::default(0);
		conflicting_block.body.outputs.push(Output {
			identifier: test_output_identifier(),
			proof: test_rangeproof(),
		});

		let mut second_peers = HashSet::new();
		second_peers.insert("127.0.0.2:3414".to_string());
		let err = pool
			.add(
				0,
				Orphan {
					block: conflicting_block,
					opts: Options::NONE,
					source_peers: second_peers,
					added: Instant::now(),
				},
			)
			.unwrap_err();

		match err {
			Error::Unfit(msg) => {
				assert_eq!(msg, "conflicting orphan body for header");
			}
			e => panic!("expected conflicting orphan body error, got {:?}", e),
		}

		let orphan = pool.get_orphan(&hash).unwrap();
		assert_eq!(orphan.source_peers.len(), 1);
		assert!(orphan.source_peers.contains("127.0.0.1:3414"));
		assert!(orphan.block.body.outputs.is_empty());
	}

	#[test]
	fn compact_eligibility_uses_tail_head_threshold() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let context_id = 0;
		let tail_height = 100;
		let horizon = global::cut_through_horizon(context_id) as u64;
		let next_compact = tail_height + horizon + horizon / 10;

		assert_eq!(
			Chain::compact_eligibility_for_heights(context_id, tail_height, next_compact - 1),
			(false, next_compact)
		);
		assert_eq!(
			Chain::compact_eligibility_for_heights(context_id, tail_height, next_compact),
			(true, next_compact)
		);
	}

	#[test]
	fn combine_positioned_outputs_and_rangeproofs_rejects_position_mismatch() {
		let outputs = (10, vec![(1, test_output_identifier())]);
		let rangeproofs = (10, vec![(2, test_rangeproof())]);

		let err = combine_positioned_outputs_and_rangeproofs(outputs, rangeproofs).unwrap_err();
		match err {
			Error::TxHashSetErr(msg) => {
				assert!(msg.contains("PMMR positions don't match"), "{}", msg);
			}
			other => panic!("expected position mismatch error, got {:?}", other),
		}
	}

	#[test]
	fn validate_tmpfile_name_accepts_single_normal_component() {
		assert!(Chain::validate_tmpfile_name("txhashset.zip").is_ok());
		assert!(Chain::validate_tmpfile_name("snapshot.tmp").is_ok());
	}

	#[test]
	fn validate_tmpfile_name_rejects_paths_and_empty_names() {
		for tmpfile_name in [
			"",
			".",
			"..",
			"txhashset/zip",
			"txhashset/",
			"/txhashset",
			"../txhashset",
			"txhashset/../zip",
			"txhashset\\zip",
			"\\txhashset",
			"C:\\txhashset",
		] {
			assert!(
				Chain::validate_tmpfile_name(tmpfile_name).is_err(),
				"accepted invalid tmpfile name: {}",
				tmpfile_name
			);
		}
	}

	#[test]
	fn exact_hardcoded_genesis_bypasses_runtime_pow_verifier() {
		global::set_local_chain_type(global::ChainTypes::Floonet);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let genesis = genesis::genesis_floo(&secp, 0);

		assert!(validate_genesis_for_init(&secp, 0, &genesis, reject_pow).is_ok());
	}

	#[test]
	fn production_genesis_requires_full_canonical_match() {
		global::set_local_chain_type(global::ChainTypes::Floonet);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut genesis = genesis::genesis_floo(&secp, 0);
		let canonical_hash = genesis.hash(0).unwrap();
		genesis.header.pow.nonce += 1;

		assert_eq!(genesis.hash(0).unwrap(), canonical_hash);
		assert!(matches!(
			validate_genesis_for_init(&secp, 0, &genesis, reject_pow),
			Err(Error::InvalidGenesisHash)
		));
	}

	#[test]
	fn testing_genesis_uses_supplied_pow_verifier() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let genesis = Block::default(0);

		assert!(matches!(
			validate_genesis_for_init(&secp, 0, &genesis, reject_pow),
			Err(Error::InvalidPow)
		));
	}

	#[test]
	fn genesis_block_sums_allows_empty_genesis_body() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let genesis = Block::default(0);

		assert!(matches!(
			genesis_block_sums(&genesis, 0, &secp),
			Ok(BlockSums::Empty)
		));
	}

	#[test]
	fn genesis_block_sums_rejects_empty_genesis_with_kernel_offset() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut genesis = Block::default(0);
		genesis.header.total_kernel_offset = mwc_keychain::BlindingFactor::from_hex(
			"0000000000000000000000000000000000000000000000000000000000000001",
		)
		.unwrap();

		let res = genesis_block_sums(&genesis, 0, &secp);
		assert!(matches!(res, Err(Error::Committed(_))), "got {:?}", res);
	}

	#[test]
	fn genesis_block_sums_rejects_output_only_genesis_body() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let mut genesis = Block::default(0);
		let output_value = consensus::calc_mwc_block_reward(0, 0) + 1;
		let output = Output::new(
			OutputFeatures::Plain,
			secp.commit_value(output_value).unwrap(),
			test_rangeproof(),
		);
		genesis.body.outputs.push(output);

		let res = genesis_block_sums(&genesis, 0, &secp);
		assert!(matches!(res, Err(Error::Committed(_))), "got {:?}", res);
	}
}
