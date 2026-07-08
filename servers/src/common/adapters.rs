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

//! Adapters connecting new block, new transaction, and accepted transaction
//! events to consumers of those events.

use mwc_crates::parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use mwc_chain::txhashset::BitmapChunk;
use mwc_chain::{self, BlockStatus, ChainAdapter, Options, SyncState, SyncStatus};

use crate::common::hooks::{ChainEvents, NetEvents};
use crate::common::types::{ChainValidationMode, DandelionEpoch};
use crate::mwc::sync::get_locator_heights;
use crate::mwc::sync::sync_manager::SyncManager;
use mwc_chain::txhashset::Segmenter;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::transaction::Transaction;
use mwc_core::core::{
	BlockHeader, BlockSums, CompactBlock, Inputs, OutputIdentifier, Segment, SegmentIdentifier,
	TxKernel,
};
use mwc_core::pow::Difficulty;
use mwc_core::ser::ProtocolVersion;
use mwc_core::{core, global};
use mwc_crates::log::{debug, error, info, warn};
use mwc_crates::secp::pedersen::RangeProof;
use mwc_crates::secp::Secp256k1;
use mwc_p2p;
use mwc_p2p::types::PeerInfo;
use mwc_p2p::PeerAddr;
use mwc_pool::{self, BlockChain, PoolAdapter};
use mwc_util::OneTime;
use std::collections::{HashMap, HashSet};

const LEGACY_V2_BLOCK_CONVERSION_BURST: u64 = 8;
const LEGACY_V2_BLOCK_CONVERSION_REFILL_PER_MIN: u64 = 30;
const LEGACY_V2_BLOCK_CONVERSION_TOKEN_SCALE: u64 = 1_000;
const LEGACY_V2_BLOCK_CONVERSION_STALE_SECS: u64 = 10 * 60;
const COMPACT_BLOCK_RECONSTRUCTION_RETRY_SECS: u64 = 15;
const COMPACT_BLOCK_RECONSTRUCTION_STALE_SECS: u64 = 10 * 60;
const COMPACT_BLOCK_RECONSTRUCTION_MAX_ENTRIES: usize = 3_000;
const EVENT_CACHE_LOCK_MILLIS: u64 = 1_000;
const CHAIN_LIVENESS_DEFER_GRACE_INTERVALS: u64 = 3;

// NetToChainAdapter need a memory cache to prevent data overloading for network core nodes (non leaf nodes)
// This cache will drop sequence of the events during the second
struct EventCache {
	event: RwLock<Hash>,
	time: RwLock<Option<Instant>>,
}

impl EventCache {
	fn new() -> Self {
		EventCache {
			event: RwLock::new(Hash::default()),
			time: RwLock::new(None),
		}
	}

	// Check if it is contain the hash value
	pub fn contains(&self, hash: &Hash, update: bool) -> bool {
		let now = Instant::now();
		let cached_at = *self.time.read_recursive();
		// This is an elapsed-time freshness check, so use monotonic time. Wall-clock
		// UTC can move backward after NTP or manual clock updates and would keep a
		// cached hash suppressed longer than the intended one-second window.
		let expired = cached_at
			.map(|cached_at| {
				now.duration_since(cached_at)
					> std::time::Duration::from_millis(EVENT_CACHE_LOCK_MILLIS)
			})
			.unwrap_or(true);

		if expired {
			if update {
				*(self.event.write()) = *hash;
				*(self.time.write()) = Some(now);
			}
			return false;
		}

		if *self.event.read_recursive() == *hash {
			true
		} else {
			if update {
				*(self.event.write()) = *hash;
				*(self.time.write()) = Some(now);
			}
			false
		}
	}
}

// Legacy protocol v0-v2 serializes block inputs as FeaturesAndCommit, but
// current blocks may be stored or relayed as CommitOnly. Reconstructing the
// feature-preserving v2 inputs is expensive: Chain::convert_block_v2 rewinds
// txhashset/PMMR state and validates inputs against the UTXO view while holding
// chain locks. A legacy peer can trigger this work by repeatedly requesting full
// blocks, so this bucket rate-limits the compatibility conversion per peer while
// still allowing a small burst for normal sync.
#[derive(Clone)]
struct LegacyV2BlockConversionBucket {
	// Scaled token count for expensive v2 conversions. One conversion costs
	// LEGACY_V2_BLOCK_CONVERSION_TOKEN_SCALE tokens, which lets us refill
	// fractional conversions using integer math.
	tokens: u64,
	// Last time we added refill tokens to this bucket.
	last_refill: Instant,
	// Last time this peer attempted a charged conversion. Used to prune old
	// peer entries so a large set of disconnected legacy peers does not grow
	// the throttle map forever.
	last_seen: Instant,
}

impl LegacyV2BlockConversionBucket {
	fn new(now: Instant) -> Self {
		LegacyV2BlockConversionBucket {
			tokens: LEGACY_V2_BLOCK_CONVERSION_BURST
				.saturating_mul(LEGACY_V2_BLOCK_CONVERSION_TOKEN_SCALE),
			last_refill: now,
			last_seen: now,
		}
	}

	fn reserve_delay(&mut self, now: Instant) -> Option<std::time::Duration> {
		// Refill before charging so a peer that waits long enough regains
		// capacity without needing a background maintenance task.
		self.refill(now);
		self.last_seen = now;

		if self.tokens >= LEGACY_V2_BLOCK_CONVERSION_TOKEN_SCALE {
			// Spend one conversion token immediately.
			self.tokens = self
				.tokens
				.saturating_sub(LEGACY_V2_BLOCK_CONVERSION_TOKEN_SCALE);
			return None;
		}

		// Not enough scaled tokens for one full conversion. Reserve the next
		// available slot and tell the caller how long to sleep after it releases
		// the throttle map lock.
		let deficit = LEGACY_V2_BLOCK_CONVERSION_TOKEN_SCALE.saturating_sub(self.tokens);
		let refill_per_min = LEGACY_V2_BLOCK_CONVERSION_REFILL_PER_MIN
			.saturating_mul(LEGACY_V2_BLOCK_CONVERSION_TOKEN_SCALE);
		let wait_ms = deficit
			.saturating_mul(60_000)
			.saturating_add(refill_per_min.saturating_sub(1))
			/ refill_per_min;
		let wait_ms = wait_ms.max(1);
		let reservation_base = if self.last_refill > now {
			self.last_refill
		} else {
			now
		};
		let reserved_at = reservation_base + std::time::Duration::from_millis(wait_ms);
		let sleep_ms = reserved_at
			.saturating_duration_since(now)
			.as_millis()
			.max(1)
			.min(u128::from(u64::MAX)) as u64;

		self.tokens = 0;
		self.last_refill = reserved_at;

		Some(std::time::Duration::from_millis(sleep_ms))
	}

	fn refill(&mut self, now: Instant) {
		let elapsed_ms = now
			.saturating_duration_since(self.last_refill)
			.as_millis()
			.min(u128::from(u64::MAX)) as u64;
		if elapsed_ms == 0 {
			return;
		}

		// Token refill is proportional to elapsed time. Scaling preserves
		// partial-token progress while keeping the bucket integer-only.
		let refill = elapsed_ms
			.saturating_mul(LEGACY_V2_BLOCK_CONVERSION_REFILL_PER_MIN)
			.saturating_mul(LEGACY_V2_BLOCK_CONVERSION_TOKEN_SCALE)
			/ 60_000;
		if refill == 0 {
			return;
		}

		// Cap at burst capacity so idle peers can recover a small burst but
		// cannot accumulate unlimited future conversion work.
		let capacity =
			LEGACY_V2_BLOCK_CONVERSION_BURST.saturating_mul(LEGACY_V2_BLOCK_CONVERSION_TOKEN_SCALE);
		self.tokens = capacity.min(self.tokens.saturating_add(refill));
		self.last_refill = now;
	}

	fn is_stale(&self, now: Instant) -> bool {
		// Staleness is based on peer activity, not refill time. A fully refilled
		// bucket for a gone peer should still be removed. Use monotonic elapsed
		// time here so wall-clock updates do not retain stale peers or reset
		// active peer burst capacity early.
		now.saturating_duration_since(self.last_seen).as_secs()
			> LEGACY_V2_BLOCK_CONVERSION_STALE_SECS
	}
}

struct LegacyV2BlockConversionThrottle {
	// Adapter-wide manager for per-peer legacy conversion buckets. The limit is
	// keyed by PeerAddr so one legacy peer cannot consume all conversion capacity.
	// Stale entries are pruned so disconnected legacy peers do not grow this map
	// indefinitely.
	peers: RwLock<HashMap<PeerAddr, LegacyV2BlockConversionBucket>>,
}

impl LegacyV2BlockConversionThrottle {
	fn new() -> Self {
		LegacyV2BlockConversionThrottle {
			peers: RwLock::new(HashMap::new()),
		}
	}

	fn throttle(&self, peer: &PeerAddr) {
		if let Some(delay) = self.delay_for_at(peer, Instant::now()) {
			debug!(
				"legacy v2 block conversion throttled for peer {}, sleeping {:?}",
				peer, delay
			);
			std::thread::sleep(delay);
		}
	}

	fn delay_for_at(&self, peer: &PeerAddr, now: Instant) -> Option<std::time::Duration> {
		let mut peers = self.peers.write();
		peers.retain(|_, bucket| !bucket.is_stale(now));

		let bucket = peers
			.entry(peer.clone())
			.or_insert_with(|| LegacyV2BlockConversionBucket::new(now));

		bucket.reserve_delay(now)
	}
}

fn reserve_compact_block_reconstruction(
	cache: &RwLock<HashMap<Hash, Instant>>,
	block_hash: &Hash,
) -> bool {
	reserve_compact_block_reconstruction_at(cache, block_hash, Instant::now())
}

/// Returns true when this compact block hash may be processed now.
///
/// Reserving writes `now` immediately, so concurrent or repeated messages for
/// the same hash skip the expensive tx-pool lookup until the retry window has
/// elapsed. Use monotonic time so wall-clock adjustments do not extend or
/// shorten the retry and stale-entry windows.
fn reserve_compact_block_reconstruction_at(
	cache: &RwLock<HashMap<Hash, Instant>>,
	block_hash: &Hash,
	now: Instant,
) -> bool {
	let mut blocks = cache.write();
	blocks.retain(|_, seen_at| {
		now.saturating_duration_since(*seen_at).as_secs() <= COMPACT_BLOCK_RECONSTRUCTION_STALE_SECS
	});

	if let Some(seen_at) = blocks.get(block_hash) {
		if now.saturating_duration_since(*seen_at)
			<= std::time::Duration::from_secs(COMPACT_BLOCK_RECONSTRUCTION_RETRY_SECS)
		{
			return false;
		}
	}

	evict_oldest_compact_block_reconstruction_if_full(&mut blocks, block_hash);
	blocks.insert(*block_hash, now);
	true
}

fn finish_compact_block_reconstruction(cache: &RwLock<HashMap<Hash, Instant>>, block_hash: &Hash) {
	finish_compact_block_reconstruction_at(cache, block_hash, Instant::now());
}

/// Refreshes the cooldown after processing finishes.
///
/// We keep the hash even after successful or rejected reconstruction because
/// the cache's purpose is to suppress repeated compact-block processing, not
/// only repeated full-block requests.
fn finish_compact_block_reconstruction_at(
	cache: &RwLock<HashMap<Hash, Instant>>,
	block_hash: &Hash,
	now: Instant,
) {
	let mut blocks = cache.write();
	evict_oldest_compact_block_reconstruction_if_full(&mut blocks, block_hash);
	blocks.insert(*block_hash, now);
}

fn evict_oldest_compact_block_reconstruction_if_full(
	blocks: &mut HashMap<Hash, Instant>,
	block_hash: &Hash,
) {
	if blocks.contains_key(block_hash) || blocks.len() < COMPACT_BLOCK_RECONSTRUCTION_MAX_ENTRIES {
		return;
	}

	let oldest_hash = blocks
		.iter()
		.min_by(|(_, first), (_, second)| first.cmp(second))
		.map(|(hash, _)| *hash);

	if let Some(oldest_hash) = oldest_hash {
		blocks.remove(&oldest_hash);
	}
}

/// Implementation of the NetAdapter for the . Gets notified when new
/// blocks and transactions are received and forwards to the chain and pool
/// implementations.
pub struct NetToChainAdapter<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	sync_state: Arc<SyncState>,
	sync_manager: Arc<SyncManager>,
	chain: Weak<mwc_chain::Chain>,
	tx_pool: Arc<RwLock<mwc_pool::TransactionPool<B, P>>>,
	peers: OneTime<Weak<mwc_p2p::Peers>>,
	chain_validation_mode: ChainValidationMode,
	hooks: Vec<Box<dyn NetEvents + Send + Sync>>,
	context_id: u32,

	// local in mem cache
	processed_transactions: EventCache,
	legacy_v2_block_conversion_throttle: LegacyV2BlockConversionThrottle,
	/// Compact-block reconstruction work tracked by block hash.
	///
	/// The timestamp is the last time we started or finished processing a compact
	/// block for this hash. While the timestamp is within
	/// COMPACT_BLOCK_RECONSTRUCTION_RETRY_SECS, repeated compact blocks for the
	/// same hash are ignored before tx-pool reconstruction. This bounds duplicate
	/// CPU work from repeated peer messages, but still permits another attempt
	/// after the retry window so a full-block fallback can be requested again.
	///
	/// Entries are also pruned by age and capped by count so hostile peers cannot
	/// grow this in-memory cache without bound.
	compact_block_reconstruction_cache: RwLock<HashMap<Hash, Instant>>,
	cached_tip: RwLock<(Difficulty, u64)>,
	chain_liveness_deferred_until: RwLock<Option<Instant>>,
}

impl<B, P> mwc_p2p::ChainAdapter for NetToChainAdapter<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	fn total_difficulty(&self) -> Result<Difficulty, mwc_chain::Error> {
		Ok(self.current_tip_for_peer_liveness()?.0)
	}

	fn total_height(&self) -> Result<u64, mwc_chain::Error> {
		Ok(self.current_tip_for_peer_liveness()?.1)
	}

	fn is_chain_liveness_deferred(&self) -> bool {
		self.is_chain_liveness_deferred_now()
	}

	fn get_transaction(
		&self,
		kernel_hash: Hash,
	) -> Result<Option<core::Transaction>, mwc_chain::Error> {
		self.tx_pool
			.read_recursive()
			.retrieve_tx_by_kernel_hash(kernel_hash)
			.map_err(|e| {
				mwc_chain::Error::Other(format!(
					"Failed to retrieve transaction from tx pool, {}",
					e
				))
			})
	}

	fn tx_kernel_received(
		&self,
		kernel_hash: Hash,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		// nothing much we can do with a new transaction while syncing
		if self.sync_state.is_syncing() {
			return Ok(true);
		}

		let has_tx = self
			.tx_pool
			.read_recursive()
			.contains_tx_by_kernel_hash(kernel_hash);

		if !has_tx {
			// Transaction kernel announcements are gossip hints. Requesting the
			// full transaction is best-effort; a dropped request is not a
			// connection-level error.
			return Ok(self.request_transaction(kernel_hash, peer_info));
		}
		Ok(true)
	}

	fn transaction_received(
		&self,
		secp: &mut Secp256k1,
		tx: core::Transaction,
		stem: bool,
	) -> Result<bool, mwc_chain::Error> {
		// nothing much we can do with a new transaction while syncing
		if self.sync_state.is_syncing() {
			return Ok(true);
		}

		let tx_hash = tx.hash(self.context_id)?;
		// For transaction we allow double processing, we want to be sure that TX will be stored in the pool
		// because there is no recovery plan for transactions. So we want to use natural retry to help us handle failures
		if self.processed_transactions.contains(&tx_hash, false) {
			debug!("transaction_received, cache for {} Rejected", tx_hash);
			return Ok(true);
		} else {
			debug!("transaction_received, cache for {} OK", tx_hash);
		}

		let source = mwc_pool::TxSource::Broadcast;
		let chain = self.chain()?;
		let header = chain.head_header()?;

		for hook in &self.hooks {
			hook.on_transaction_received(self.context_id, &tx);
		}

		let mut tx_pool = self.tx_pool.write();
		match tx_pool.add_to_pool(source, tx, stem, &header, secp) {
			Ok(_) => {
				self.processed_transactions.contains(&tx_hash, true);
				Ok(true)
			}
			Err(e) => {
				// Pool rejection is an expected outcome for transactions received from peers
				// and does not require connection-level error handling. PoolError is broad
				// and can also cover local validation infrastructure failures from the
				// chain adapter path. Treat this conservatively as best-effort transaction
				// admission: report the concrete error for visibility, but keep message
				// handling successful. There is limited value in finer error classification
				// here because every failure is logged either way.
				info!("Transaction {} rejected: {:?}", tx_hash, e);
				Ok(false)
			}
		}
	}

	fn block_received(
		&self,
		secp: &mut Secp256k1,
		b: core::Block,
		peer_info: &PeerInfo,
		opts: Options,
	) -> Result<bool, mwc_chain::Error> {
		let b_hash = b.hash(self.context_id)?;
		if self.sync_state.is_txhashset_validation() {
			info!(
				"block_received: skipping {} at {} from {} while txhashset validation holds chain PMMR locks",
				b_hash, b.header.height, peer_info.addr
			);
			return Ok(true);
		}

		let chain = self.chain()?;
		let total_blocks = chain.header_head()?.height;

		info!(
			"Received block {} of {} hash {} from {} [in/out/kern: {}/{}/{}] going to process. Prev block Hash: {}",
			b.header.height,
			total_blocks,
			b_hash,
			peer_info.addr,
			b.inputs().len(),
			b.outputs().len(),
			b.kernels().len(),
			b.header.prev_hash,
		);
		let processed = self.process_block(secp, b, peer_info, opts)?;
		Ok(processed)
	}

	fn compact_block_received(
		&self,
		secp: &mut Secp256k1,
		cb: CompactBlock,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		if self.sync_state.is_txhashset_validation() {
			let cb_hash = cb.hash(self.context_id)?;
			info!(
				"compact_block_received: skipping {} at {} from {} while txhashset validation holds chain PMMR locks",
				cb_hash, cb.header.height, peer_info.addr
			);
			return Ok(true);
		}

		// No need to process this compact block if we have previously accepted the _full block_.
		let chain = self.chain()?;
		match chain.is_known(&cb.header) {
			Ok(()) => {}
			Err(e) => {
				if let mwc_chain::Error::Unfit(msg) = &e {
					if msg == "duplicate block" {
						return Ok(true);
					}
				}
				return Err(e);
			}
		}

		let cb_hash = cb.hash(self.context_id)?;
		debug!(
				"Received compact_block {} at {} from {} [out/kern/kern_ids: {}/{}/{}] going to process.",
				cb_hash,
				cb.header.height,
				peer_info.addr,
				cb.out_full().len(),
				cb.kern_full().len(),
				cb.kern_ids().len(),
			);

		if cb.kern_ids().is_empty() {
			// push the freshly hydrated block through the chain pipeline
			match core::Block::hydrate_from(cb, &[]) {
				Ok(block) => {
					debug!(
						"successfully hydrated (empty) block: {} at {} ({})",
						block.header.hash(self.context_id)?,
						block.header.height,
						block.inputs().version_str(),
					);
					if !self.sync_state.is_syncing() {
						for hook in &self.hooks {
							hook.on_block_received(self.context_id, &block, &peer_info.addr);
						}
					}
					self.process_block(secp, block, peer_info, Options::NONE)
				}
				Err(e) => {
					debug!("Invalid hydrated block {}: {:?}", cb_hash, e);
					return Ok(false);
				}
			}
		} else {
			// check at least the header is valid before hydrating
			if let Err(e) = chain.process_block_header(&cb.header, Options::NONE) {
				debug!("Compact block header {} refused by chain: {:?}", cb_hash, e);
				if e.is_bad_data() {
					return Ok(false);
				}
				if matches!(e, mwc_chain::Error::Orphan(_)) || e.is_not_found() {
					// Missing previous headers are expected during propagation or sync races.
					// Treat them as recoverable; local chain failures still propagate below.
					return Ok(true);
				}
				return Err(e);
			}

			if !reserve_compact_block_reconstruction(
				&self.compact_block_reconstruction_cache,
				&cb_hash,
			) {
				debug!(
					"compact_block_received: skipping repeated reconstruction for {} at {}",
					cb_hash, cb.header.height,
				);
				return Ok(true);
			}

			let (txs, missing_short_ids) = match {
				self.tx_pool.read_recursive().retrieve_transactions(
					cb_hash,
					cb.nonce,
					cb.kern_ids(),
				)
			} {
				Ok(result) => result,
				Err(e) => {
					finish_compact_block_reconstruction(
						&self.compact_block_reconstruction_cache,
						&cb_hash,
					);
					return Err(mwc_chain::Error::Other(format!(
						"Failed to retrieve compact block transactions from tx pool, {}",
						e
					)));
				}
			};

			debug!(
				"compact_block_received: txs from tx pool - {}, (unknown kern_ids: {})",
				txs.len(),
				missing_short_ids.len(),
			);

			// If we have missing kernels then we know we cannot hydrate this compact block.
			if !missing_short_ids.is_empty() {
				finish_compact_block_reconstruction(
					&self.compact_block_reconstruction_cache,
					&cb_hash,
				);
				self.sync_manager.add_block_request(
					&peer_info.addr,
					cb.header.height,
					cb.header.hash(self.context_id)?,
					Options::NONE,
				);
				return Ok(true);
			}

			let block = match core::Block::hydrate_from(cb.clone(), &txs) {
				Ok(block) => {
					if !self.sync_state.is_syncing() {
						for hook in &self.hooks {
							hook.on_block_received(self.context_id, &block, &peer_info.addr);
						}
					}
					block
				}
				Err(e) => {
					debug!("Invalid hydrated block {}: {:?}", cb_hash, e);
					finish_compact_block_reconstruction(
						&self.compact_block_reconstruction_cache,
						&cb_hash,
					);
					return Ok(false);
				}
			};

			let prev = match chain.get_previous_header(&cb.header) {
				Ok(prev) => prev,
				Err(e) if e.is_not_found() => {
					debug!(
						"compact_block_received: missing previous header for {} at {}, likely syncing",
						cb_hash, cb.header.height
					);
					finish_compact_block_reconstruction(
						&self.compact_block_reconstruction_cache,
						&cb_hash,
					);
					return Ok(true);
				}
				Err(e) => {
					finish_compact_block_reconstruction(
						&self.compact_block_reconstruction_cache,
						&cb_hash,
					);
					return Err(e);
				}
			};

			// Keep compact-block reconstruction conservative: any validation
			// failure means the hydrated block is treated as invalid. This is
			// acceptable because the node can request the full block and let the
			// normal block-processing path validate it with complete data.
			if block
				.validate(self.context_id, &prev.total_kernel_offset, secp)
				.is_ok()
			{
				debug!(
					"successfully hydrated block: {} at {} ({})",
					block.header.hash(self.context_id)?,
					block.header.height,
					block.inputs().version_str(),
				);
				let result = self.process_block(secp, block, peer_info, Options::NONE);
				finish_compact_block_reconstruction(
					&self.compact_block_reconstruction_cache,
					&cb_hash,
				);
				result
			} else if self.sync_state.status() == SyncStatus::NoSync {
				debug!("adapter: block invalid after hydration, requesting full block");
				finish_compact_block_reconstruction(
					&self.compact_block_reconstruction_cache,
					&cb_hash,
				);
				self.sync_manager.add_block_request(
					&peer_info.addr,
					cb.header.height,
					cb.header.hash(self.context_id)?,
					Options::NONE,
				);
				Ok(true)
			} else {
				debug!("block invalid after hydration, ignoring it, cause still syncing");
				finish_compact_block_reconstruction(
					&self.compact_block_reconstruction_cache,
					&cb_hash,
				);
				Ok(true)
			}
		}
	}

	fn header_received(
		&self,
		bh: core::BlockHeader,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		let bh_hash = bh.hash(self.context_id)?;
		debug!("header_received, processing {}, {}", bh.height, bh_hash);

		if matches!(self.sync_state.status(), SyncStatus::HeaderSync { .. }) {
			debug!(
				"header_received: skipping single header {} at {} from {} during header sync",
				bh_hash, bh.height, peer_info.addr
			);
			return Ok(true);
		}

		if self.sync_state.is_txhashset_validation() {
			info!(
				"header_received: skipping {} at {} from {} while txhashset validation holds chain PMMR locks",
				bh_hash, bh.height, peer_info.addr
			);
			return Ok(true);
		}

		let chain = self.chain()?;
		if !self.sync_state.is_syncing() {
			for hook in &self.hooks {
				hook.on_header_received(self.context_id, &bh, &peer_info.addr);
			}
		}

		// pushing the new block header through the header chain pipeline
		// we will go ask for the block if this is a new header
		let res = chain.process_block_header(&bh, Options::NONE);

		if let Err(e) = res {
			debug!(
				"Block header {} refused by chain: {:?}",
				bh.hash(self.context_id)?,
				e
			);
			if e.is_bad_data() {
				return Ok(false);
			}

			let recoverable_header_error =
				matches!(&e, mwc_chain::Error::Orphan(_)) || e.is_not_found();
			if !recoverable_header_error {
				return Err(e);
			}

			if self.sync_state.are_headers_done() {
				// we got an error when trying to process the block header
				// but nothing serious enough to need to ban the peer upstream
				// Probably child block doesn't exist, let's request them
				let head = chain.head()?;
				debug!(
					"Got unknown header, requesting headers from the peer {} at height {}",
					peer_info.addr, head.height
				);
				let heights = get_locator_heights(head.height);
				let locator = chain.get_locator_hashes(head, &heights)?;
				self.sync_manager.add_header_request(
					&peer_info.addr,
					Some(bh_hash),
					bh.height,
					locator,
				);

				if !self.sync_state.is_syncing() {
					let tip = chain.head()?;
					// Requesting of orphans buffer is large enough to finish the job with request
					if bh.height > tip.height
						&& bh.height - tip.height
							< chain.get_pibd_params().get_orphans_num_limit() as u64
					{
						self.sync_manager.add_block_request(
							&peer_info.addr,
							bh.height,
							bh_hash,
							Options::NONE,
						);
					}
				}
			}
			return Ok(true);
		}

		// we have successfully processed a block header
		// If we already have the full block, skip the compact-block request. This
		// check is intentionally after process_block_header so a same-hash but
		// different header cannot bypass header validation.
		if chain.block_exists(&bh_hash)? {
			return Ok(true);
		}

		// we have successfully processed a new block header
		// so we can go request the block itself
		self.request_compact_block(bh_hash, peer_info)?;

		// done receiving the header
		Ok(true)
	}

	fn header_locator(&self) -> Result<Vec<Hash>, mwc_chain::Error> {
		if self.sync_state.is_txhashset_validation() {
			info!(
				"header_locator: returning empty locator while txhashset validation holds chain PMMR locks"
			);
			return Ok(vec![]);
		}
		let chain = self.chain()?;
		let head = chain.head()?;
		let heights = get_locator_heights(head.height);
		let locator = chain.get_locator_hashes(head, &heights)?;
		Ok(locator)
	}

	fn headers_received(
		&self,
		bhs: &[core::BlockHeader],
		remaining: u64,
		peer_info: &PeerInfo,
	) -> Result<(), mwc_chain::Error> {
		if bhs.is_empty() {
			return Ok(());
		}

		self.sync_manager
			.receive_headers(&peer_info.addr, bhs, remaining, self.peers()?)?;

		if let Some(last) = bhs.last() {
			if !self.sync_state.is_syncing() && last.total_difficulty() > self.total_difficulty()? {
				// check if any header
				let chain = self.chain()?;
				for bh in bhs.iter() {
					let hash = bh.hash(self.context_id)?;
					// Header is already processed, checking here if it was accepted
					match chain.get_block_header(&hash) {
						Ok(_) => {
							if !chain.block_exists(&hash)? {
								self.sync_manager.add_block_request(
									&peer_info.addr,
									bh.height,
									hash,
									Options::NONE,
								);
							}
						}
						Err(e) if e.is_not_found() => {
							break;
						}
						Err(e) => {
							return Err(e);
						}
					}
				}
			}
		}
		Ok(())
	}

	fn locate_headers(&self, locator: &[Hash]) -> Result<Vec<core::BlockHeader>, mwc_chain::Error> {
		if self.sync_state.is_txhashset_validation() {
			info!(
				"locate_headers: returning no headers while txhashset validation holds chain PMMR locks"
			);
			return Ok(vec![]);
		}
		self.chain()?
			.locate_headers(locator, mwc_p2p::MAX_BLOCK_HEADERS)
	}

	/// Gets a full block by its hash.
	/// Will convert to v2 compatibility based on peer protocol version.
	fn get_block(
		&self,
		secp: &Secp256k1,
		h: Hash,
		peer_info: &PeerInfo,
	) -> Result<Option<core::Block>, mwc_chain::Error> {
		if self.sync_state.is_txhashset_validation() {
			info!(
				"get_block: returning no block for {} while txhashset validation holds chain PMMR locks",
				h
			);
			return Ok(None);
		}
		let chain = self.chain()?;
		let block = match chain.get_block(&h) {
			Ok(block) => block,
			Err(e) if e.is_not_found() => return Ok(None),
			Err(e) => return Err(e),
		};
		match peer_info.version.value() {
			0..=2 => {
				if !block.inputs().is_empty() {
					self.legacy_v2_block_conversion_throttle
						.throttle(&peer_info.addr);
				}
				chain.convert_block_v2(secp, block).map(Some)
			}
			3..=ProtocolVersion::MAX => Ok(Some(block)),
		}
	}

	fn txhashset_archive_header(&self) -> Result<core::BlockHeader, mwc_chain::Error> {
		self.chain()?.txhashset_archive_header()
	}

	fn get_tmp_dir(&self) -> Result<PathBuf, mwc_chain::Error> {
		Ok(self.chain()?.get_tmp_dir())
	}

	fn get_tmpfile_pathname(&self, tmpfile_name: String) -> Result<PathBuf, mwc_chain::Error> {
		self.chain()?.get_tmpfile_pathname(tmpfile_name)
	}

	fn prepare_segmenter(&self) -> Result<Segmenter, mwc_chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(mwc_chain::Error::ChainInSync);
		}
		self.chain()?.segmenter()
	}

	fn get_kernel_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<TxKernel>, mwc_chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(mwc_chain::Error::ChainInSync);
		}
		let (chain, archive_header) = self.chain_and_archive_header_for_hash(hash)?;
		mwc_chain::txhashset::validate_kernel_segment_request(id, archive_header.kernel_mmr_size)?;
		let segmenter = self.segmenter_for_archive_hash_checked(&chain, hash)?;
		segmenter.kernel_segment(id)
	}

	fn get_bitmap_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<BitmapChunk>, mwc_chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(mwc_chain::Error::ChainInSync);
		}
		let (chain, archive_header) = self.chain_and_archive_header_for_hash(hash)?;
		mwc_chain::txhashset::validate_bitmap_segment_request(id, archive_header.output_mmr_size)?;
		let segmenter = self.segmenter_for_archive_hash_checked(&chain, hash)?;
		segmenter.bitmap_segment(id)
	}

	fn get_output_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<OutputIdentifier>, mwc_chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(mwc_chain::Error::ChainInSync);
		}
		let (chain, archive_header) = self.chain_and_archive_header_for_hash(hash)?;
		// Validate the peer-controlled id before Chain::segmenter(). On a cache
		// miss, segmenter initialization rewinds the txhashset and builds the
		// bitmap accumulator, so invalid requests must be rejected first.
		mwc_chain::txhashset::validate_output_segment_request(id, archive_header.output_mmr_size)?;
		let segmenter = self.segmenter_for_archive_hash_checked(&chain, hash)?;
		segmenter.output_segment(id)
	}

	fn get_rangeproof_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<RangeProof>, mwc_chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(mwc_chain::Error::ChainInSync);
		}
		let (chain, archive_header) = self.chain_and_archive_header_for_hash(hash)?;
		// Rangeproof segments use the output MMR size at the archive header.
		// Preflight keeps bogus peer ids from forcing segmenter cache creation.
		mwc_chain::txhashset::validate_rangeproof_segment_request(
			id,
			archive_header.output_mmr_size,
		)?;
		let segmenter = self.segmenter_for_archive_hash_checked(&chain, hash)?;
		segmenter.rangeproof_segment(id)
	}

	fn recieve_pibd_status(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
		output_bitmap_root: Hash,
	) -> Result<(), mwc_chain::Error> {
		info!(
			"Received PIBD handshake response from {}. Header {} at {}, root_hash {}",
			peer, header_hash, header_height, output_bitmap_root
		);
		self.sync_manager
			.recieve_pibd_status(peer, header_hash, header_height, output_bitmap_root);
		Ok(())
	}

	fn recieve_another_archive_header(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
	) -> Result<(), mwc_chain::Error> {
		info!(
			"Received another archive header response from {}. Header {} at {}",
			peer, header_hash, header_height
		);
		self.sync_manager
			.recieve_another_archive_header(peer, header_hash, header_height);
		Ok(())
	}

	fn receive_headers_hash_response(
		&self,
		peer: &PeerAddr,
		archive_height: u64,
		headers_hash_root: Hash,
	) -> Result<(), mwc_chain::Error> {
		info!(
			"Received headers hash response {}, {} from {}",
			archive_height, headers_hash_root, peer
		);
		self.sync_manager
			.receive_headers_hash_response(peer, archive_height, headers_hash_root)
	}

	fn get_header_hashes_segment(
		&self,
		header_hashes_root: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<Hash>, mwc_chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(mwc_chain::Error::ChainInSync);
		}
		let chain = self.chain()?;
		let archive_header = chain.txhashset_archive_header()?;
		mwc_chain::txhashset::validate_header_hashes_segment_request(id, archive_header.height)?;
		let archive_hash = archive_header.hash(self.context_id)?;
		let chain_header_hashes_root = chain.header_hashes_root(&archive_header)?;
		if header_hashes_root != chain_header_hashes_root {
			return Err(mwc_chain::Error::SegmenterHeaderMismatch(
				archive_hash,
				archive_header.height,
			));
		}
		let segmenter = self.segmenter_for_archive_hash_checked(&chain, archive_hash)?;
		segmenter.headers_segment(id)
	}

	fn receive_header_hashes_segment(
		&self,
		peer: &PeerAddr,
		header_hashes_root: Hash,
		segment: Segment<Hash>,
	) -> Result<(), mwc_chain::Error> {
		info!(
			"Received headers hashes segment {}, {} from {}",
			segment.id(),
			header_hashes_root,
			peer
		);
		self.sync_manager
			.receive_header_hashes_segment(peer, header_hashes_root, segment)?;
		Ok(())
	}

	fn receive_bitmap_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<BitmapChunk>,
	) -> Result<(), mwc_chain::Error> {
		info!(
			"Received bitmap segment {} for block_hash: {} from {}",
			segment.identifier(),
			archive_header_hash,
			peer
		);

		self.sync_manager.receive_bitmap_segment(
			peer,
			&archive_header_hash,
			segment,
			&self.peers()?,
		)?;
		Ok(())
	}

	fn receive_output_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<OutputIdentifier>,
	) -> Result<(), mwc_chain::Error> {
		info!(
			"Received output segment {} for block_hash: {} from {}",
			segment.identifier(),
			archive_header_hash,
			peer,
		);

		self.sync_manager.receive_output_segment(
			peer,
			&archive_header_hash,
			segment,
			&self.peers()?,
		)?;
		Ok(())
	}

	fn receive_rangeproof_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<RangeProof>,
	) -> Result<(), mwc_chain::Error> {
		info!(
			"Received proof segment {} for block_hash: {}  from {}",
			segment.identifier(),
			archive_header_hash,
			peer
		);

		self.sync_manager.receive_rangeproof_segment(
			peer,
			&archive_header_hash,
			segment,
			&self.peers()?,
		)?;
		Ok(())
	}

	fn receive_kernel_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<TxKernel>,
	) -> Result<(), mwc_chain::Error> {
		info!(
			"Received kernel segment {} for block_hash: {} from {}",
			segment.identifier(),
			archive_header_hash,
			peer
		);

		self.sync_manager.receive_kernel_segment(
			peer,
			&archive_header_hash,
			segment,
			&self.peers()?,
		)?;
		Ok(())
	}

	/// Heard total_difficulty from a connected peer (via ping/pong).
	fn peer_difficulty(&self, peer: &PeerAddr, difficulty: Difficulty, height: u64) {
		let res = || -> Result<(), mwc_chain::Error> {
			if self.is_chain_liveness_deferred_now() || self.sync_state.is_syncing() {
				return Ok(());
			}

			let chain = self.chain()?;
			let tip = chain.head()?;
			if difficulty > tip.total_difficulty && height > tip.height {
				let tip_height = tip.height;
				let heights = get_locator_heights(tip_height);
				let locator = chain.get_locator_hashes(tip, &heights)?;
				if !self.sync_state.is_syncing() {
					self.sync_manager
						.add_header_request(peer, None, tip_height + 1, locator);
				}
			}

			Ok(())
		}();

		if let Err(e) = res {
			error!(
				"peer_difficulty: failed to handle advertised difficulty from peer {} (height {}, difficulty {}): {}",
				peer, height, difficulty, e
			);
		}
	}
}

impl<B, P> NetToChainAdapter<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	/// Construct a new NetToChainAdapter instance
	pub fn new(
		context_id: u32,
		sync_state: Arc<SyncState>,
		chain: Arc<mwc_chain::Chain>,
		sync_manager: Arc<SyncManager>,
		tx_pool: Arc<RwLock<mwc_pool::TransactionPool<B, P>>>,
		chain_validation_mode: ChainValidationMode,
		hooks: Vec<Box<dyn NetEvents + Send + Sync>>,
	) -> Self {
		let cached_tip = match chain.head() {
			Ok(tip) => (tip.total_difficulty, tip.height),
			Err(e) => {
				warn!("NetToChainAdapter: unable to initialize cached tip: {}", e);
				(Difficulty::zero(), 0)
			}
		};
		NetToChainAdapter {
			sync_state,
			sync_manager,
			chain: Arc::downgrade(&chain),
			tx_pool,
			peers: OneTime::new(),
			chain_validation_mode,
			hooks,
			context_id,
			processed_transactions: EventCache::new(),
			legacy_v2_block_conversion_throttle: LegacyV2BlockConversionThrottle::new(),
			compact_block_reconstruction_cache: RwLock::new(HashMap::new()),
			cached_tip: RwLock::new(cached_tip),
			chain_liveness_deferred_until: RwLock::new(None),
		}
	}

	fn current_tip_for_peer_liveness(&self) -> Result<(Difficulty, u64), mwc_chain::Error> {
		if self.is_chain_liveness_deferred_now() {
			return Ok(*self.cached_tip.read_recursive());
		}

		let tip = self.chain()?.head()?;
		let cached_tip = (tip.total_difficulty, tip.height);
		*self.cached_tip.write() = cached_tip;
		Ok(cached_tip)
	}

	fn is_chain_liveness_deferred_now(&self) -> bool {
		let now = Instant::now();
		if self.sync_state.is_txhashset_validation()
			|| matches!(self.sync_state.status(), SyncStatus::Shutdown)
		{
			let grace = Duration::from_secs(
				(global::PEER_PING_INTERVAL_SECONDS as u64) * CHAIN_LIVENESS_DEFER_GRACE_INTERVALS,
			);
			*self.chain_liveness_deferred_until.write() = now.checked_add(grace);
			return true;
		}

		let mut deferred_until = self.chain_liveness_deferred_until.write();
		if let Some(until) = *deferred_until {
			if now <= until {
				return true;
			}
			*deferred_until = None;
		}
		false
	}

	/// Initialize a NetToChainAdaptor with reference to a Peers object.
	/// Should only be called once.
	pub fn init(&self, peers: Arc<mwc_p2p::Peers>) -> Result<(), mwc_chain::Error> {
		self.peers
			.init(Arc::downgrade(&peers))
			.map_err(|e| mwc_chain::Error::Other(e.to_string()))
	}

	fn peers(&self) -> Result<Arc<mwc_p2p::Peers>, mwc_chain::Error> {
		Ok(self
			.peers
			.borrow()
			.map_err(|e| mwc_chain::Error::Other(e.to_string()))?
			.upgrade()
			.ok_or(mwc_chain::Error::Other("Peers are not set".into()))?)
	}

	fn chain(&self) -> Result<Arc<mwc_chain::Chain>, mwc_chain::Error> {
		Ok(self
			.chain
			.upgrade()
			.ok_or(mwc_chain::Error::Other("Chain is not set".into()))?)
	}

	fn chain_and_archive_header_for_hash(
		&self,
		hash: Hash,
	) -> Result<(Arc<mwc_chain::Chain>, BlockHeader), mwc_chain::Error> {
		let chain = self.chain()?;
		let archive_header = chain.txhashset_archive_header()?;
		let head_hash = archive_header.hash(self.context_id)?;
		if head_hash != hash {
			return Err(mwc_chain::Error::SegmenterHeaderMismatch(
				head_hash,
				archive_header.height,
			));
		}
		Ok((chain, archive_header))
	}

	fn segmenter_for_archive_hash_checked(
		&self,
		chain: &mwc_chain::Chain,
		hash: Hash,
	) -> Result<Segmenter, mwc_chain::Error> {
		let segmenter = chain.segmenter()?;
		// Second check is needed because of possible race condition,  archive height can be changed
		let segmenter_hash = segmenter.header().hash(self.context_id)?;
		if segmenter_hash != hash {
			return Err(mwc_chain::Error::SegmenterHeaderMismatch(
				segmenter_hash,
				segmenter.header().height,
			));
		}
		Ok(segmenter)
	}

	// pushing the new block through the chain pipeline
	// remembering to reset the head if we have a bad block
	fn process_block(
		&self,
		secp: &mut Secp256k1,
		b: core::Block,
		peer_info: &PeerInfo,
		opts: Options,
	) -> Result<bool, mwc_chain::Error> {
		// We cannot process blocks earlier than the horizon so check for this here.
		let chain = self.chain()?;
		let peers = self.peers()?;

		let head = {
			let head = chain.head()?;
			let horizon = head
				.height
				.saturating_sub(global::cut_through_horizon(self.context_id) as u64);
			if b.header.height < horizon {
				debug!("Got block is below horizon from peer {}", peer_info.addr);
				return Ok(true);
			}
			head
		};

		let bhash = b.hash(self.context_id)?;
		match chain.process_block(
			secp,
			b.clone(),
			opts,
			std::iter::once(peer_info.addr.to_string()).collect(),
		) {
			Ok(_) => {
				self.validate_chain(secp, &bhash)?;
				//self.check_compact();  Currently Sync process does that. No needs, also we don't want collision to happens
				self.sync_manager.recieve_block_reporting(
					Some(true),
					&peer_info.addr,
					b,
					Options::SYNC,
					&peers,
				)?;
				Ok(true)
			}
			Err(e) => {
				if matches!(&e, mwc_chain::Error::OldBlock)
					|| matches!(&e, mwc_chain::Error::Unfit(msg)
						if msg == "already known in head"
							|| msg == "already known in store"
							|| msg == "duplicate block")
				{
					debug!(
						"process_block: block {} from peer {} is already known: {}",
						bhash, peer_info.addr, e
					);
					// This may still be a response to an outstanding body-sync request.
					// Clear the request tracker without running orphan bookkeeping for an
					// already-known block.
					self.sync_manager.recieve_block_reporting(
						Some(true),
						&peer_info.addr,
						b,
						opts,
						&peers,
					)?;
					return Ok(true);
				}

				if e.is_bad_data() {
					warn!("process_block: block {} from peer {} is bad. Block is rejected, peer is banned. Error: {}", bhash, peer_info.addr, e);
					self.validate_chain(secp, &bhash)?;
					self.sync_manager.recieve_block_reporting(
						Some(false),
						&peer_info.addr,
						b,
						opts,
						&peers,
					)?;
					return Ok(false);
				}

				if !(matches!(&e, mwc_chain::Error::Orphan(_)) || e.is_not_found()) {
					info!(
						"process_block: block {} from peer {} failed chain processing: {}",
						bhash, peer_info.addr, e
					);
					return Err(e);
				}
				let prev_block_hash = b.header.prev_hash.clone();
				let block_height = b.header.height;
				let previous_known = match chain.get_previous_header(&b.header) {
					Ok(_) => true,
					Err(e) if e.is_not_found() => false,
					Err(e) => return Err(e),
				};
				let need_request_prev_block = self.sync_manager.recieve_block_reporting(
					None,
					&peer_info.addr,
					b,
					opts,
					&peers,
				)?;
				if !previous_known {
					// requesting headers from that peer, intentionally without  self.sync_manager.add_header_request
					if let Some(peer) = peers.get_connected_peer(&peer_info.addr) {
						debug!("Got block with unknow headers, requesting headers from the peer {} at height {}", peer_info.addr, head.height);
						let heights = get_locator_heights(head.height);
						let locator = chain.get_locator_hashes(head, &heights)?;
						if let Err(e) = peer.send_header_request(locator) {
							warn!(
								"process_block: failed to request recovery headers from peer {}: {}",
								peer_info.addr, e
							);
						}
					}
				}
				if need_request_prev_block && block_height > 0 {
					// requesting headers from that peer
					// requesting prev block from that peer
					debug!(
						"Got block with unknown child, requesting prev block {} from the peer {}",
						prev_block_hash, peer_info.addr
					);
					self.sync_manager.add_block_request(
						&peer_info.addr,
						block_height - 1,
						prev_block_hash,
						Options::NONE,
					);
				}
				Ok(true)
			}
		}
	}

	fn validate_chain(&self, secp: &Secp256k1, bhash: &Hash) -> Result<(), mwc_chain::Error> {
		// If we are running in "validate the full chain every block" then
		// panic here if validation fails for any reason.
		// We are out of consensus at this point and want to track the problem
		// down as soon as possible.
		// Skip this if we are currently syncing (too slow).

		let chain = self.chain()?;

		if self.chain_validation_mode == ChainValidationMode::EveryBlock
			&& chain.head()?.height > 0
			&& !self.sync_state.is_syncing()
		{
			let now = Instant::now();

			debug!(
				"process_block: ***** validating full chain state at {}",
				bhash,
			);

			chain
				.validate(secp, false)
				.expect("chain validation failed, hard stop");

			debug!(
				"process_block: ***** done validating full chain state, took {}s",
				now.elapsed().as_secs(),
			);
		}
		Ok(())
	}

	fn request_transaction(&self, h: Hash, peer_info: &PeerInfo) -> bool {
		self.send_tx_request_to_peer(h, peer_info, |peer, h| peer.send_tx_request(h))
	}

	// After we have received a block header in "header first" propagation
	// we need to go request the block (compact representation) from the
	// same peer that gave us the header (unless we have already accepted the block)
	fn request_compact_block(
		&self,
		bh_hash: Hash,
		peer_info: &PeerInfo,
	) -> Result<(), mwc_chain::Error> {
		self.send_block_request_to_peer(bh_hash, peer_info, |peer, h| {
			peer.send_compact_block_request(h)
		})
	}

	fn send_tx_request_to_peer<F>(&self, h: Hash, peer_info: &PeerInfo, f: F) -> bool
	where
		F: Fn(&mwc_p2p::Peer, Hash) -> Result<(), mwc_p2p::Error>,
	{
		// Transaction request delivery is best-effort. A peer may disconnect
		// after announcing a kernel, so send failures are logged but not
		// propagated as chain or protocol errors.
		let peers = match self.peers() {
			Ok(peers) => peers,
			Err(e) => {
				error!("send_tx_request_to_peer: failed to access peers: {:?}", e);
				return false;
			}
		};

		match peers.get_connected_peer(&peer_info.addr) {
			None => {
				debug!(
					"send_tx_request_to_peer: can't send request to peer {:?}, not connected",
					peer_info.addr
				);
				false
			}
			Some(peer) => {
				if let Err(e) = f(&peer, h) {
					error!("send_tx_request_to_peer: failed: {:?}", e);
					return false;
				}
				true
			}
		}
	}

	fn send_block_request_to_peer<F>(
		&self,
		h: Hash,
		peer_info: &PeerInfo,
		f: F,
	) -> Result<(), mwc_chain::Error>
	where
		F: Fn(&mwc_p2p::Peer, Hash) -> Result<(), mwc_p2p::Error>,
	{
		let peers = self.peers()?;
		let chain = self.chain()?;

		if chain.block_exists(&h)? {
			debug!("send_block_request_to_peer: block {} already known", h);
			return Ok(());
		}

		match peers.get_connected_peer(&peer_info.addr) {
			None => Err(mwc_chain::Error::Other(format!(
				"send_block_request_to_peer: can't send request to peer {:?}, not connected",
				peer_info.addr
			))),
			Some(peer) => {
				f(&peer, h).map_err(|e| {
					mwc_chain::Error::Other(format!(
						"send_block_request_to_peer: failed to send request to peer {:?}: {}",
						peer_info.addr, e
					))
				})?;
				Ok(())
			}
		}
	}
}

/// Implementation of the ChainAdapter for the network. Gets notified when the
///  accepted a new block, asking the pool to update its state and
/// the network to broadcast the block
pub struct ChainToPoolAndNetAdapter<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	tx_pool: Arc<RwLock<mwc_pool::TransactionPool<B, P>>>,
	sync_state: Arc<SyncState>,
	peers: OneTime<Weak<mwc_p2p::Peers>>,
	hooks: Vec<Box<dyn ChainEvents + Send + Sync>>,
}

impl<B, P> ChainAdapter for ChainToPoolAndNetAdapter<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	fn block_accepted(
		&self,
		secp: &mut Secp256k1,
		b: &core::Block,
		status: BlockStatus,
		opts: Options,
	) {
		// Trigger all registered "on_block_accepted" hooks (logging and webhooks).
		let context_id = self.tx_pool.read_recursive().get_context_id();
		for hook in &self.hooks {
			hook.on_block_accepted(context_id, b, status);
		}

		// Suppress broadcast of new blocks received during sync.
		if !opts.contains(Options::SYNC) {
			// If we mined the block then we want to broadcast the compact block.
			// If we received the block from another node then broadcast "header first"
			// to minimize network traffic.
			match self.peers() {
				Ok(peers) => {
					if opts.contains(Options::MINE) {
						// propagate compact block out if we mined the block
						match CompactBlock::from(b.clone()) {
							Ok(cb) => {
								if let Err(e) = peers.broadcast_compact_block(&cb) {
									error!("Failed to broadcast compact block: {}", e);
								}
							}
							Err(e) => {
								error!("Failed convert Block into CompactBlock, {}", e);
							}
						}
					} else {
						// "header first" propagation if we are not the originator of this block
						if let Err(e) = peers.broadcast_header(&b.header) {
							error!("Failed to broadcast block header: {}", e);
						}
					}
				}
				Err(e) => {
					error!("Failed to obtain the peers list, {}", e);
				}
			}
		}

		// Reconcile the txpool against the new block *after* we have broadcast it too our peers.
		// This may be slow and we do not want to delay block propagation.
		// We only want to reconcile the txpool against the new block *if* total work has increased.

		if status.is_next() || status.is_reorg() {
			let mut tx_pool = self.tx_pool.write();

			tx_pool.reconcile_block(b, secp);

			// First "age out" any old txs in the reorg_cache.
			const MAX_REORG_CACHE_TIMEOUT_MINS: i64 = 60 * 24 * 30; // 30 days
			let timeout_mins = tx_pool
				.config
				.reorg_cache_timeout
				.clamp(0, MAX_REORG_CACHE_TIMEOUT_MINS);

			tx_pool.truncate_reorg_cache(Duration::from_secs(timeout_mins as u64 * 60));
		}

		if status.is_reorg() {
			self.tx_pool.write().reconcile_reorg_cache(&b.header, secp);
		}
	}

	fn block_rejected(&self, hash: &Hash, source_peers: &HashSet<String>, err: &mwc_chain::Error) {
		if source_peers.is_empty() {
			return;
		}
		if self.sync_state.is_syncing() && matches!(err, mwc_chain::Error::OldBlock) {
			// During sync, the same block can arrive from several peers after
			// another in-flight batch already advanced the local chain. That is
			// stale data, not a bad-block signal.
			debug!(
				"Skipping peer ban for old block {} from {:?}",
				hash, source_peers
			);
			return;
		}

		let peers = match self.peers() {
			Ok(peers) => peers,
			Err(e) => {
				error!(
					"Unable to ban peers for bad block {}: failed to obtain peers list: {}",
					hash, e
				);
				return;
			}
		};

		for source_peer in source_peers {
			let parse_peer = source_peer.strip_prefix("tor://").unwrap_or(source_peer);
			let peer_addr = match PeerAddr::from_str(parse_peer) {
				Ok(peer_addr) => peer_addr,
				Err(e) => {
					warn!(
						"Unable to parse source peer {} for bad block {}: {}",
						source_peer, hash, e
					);
					continue;
				}
			};

			let message = format!(
				"Got bad block with hash: {} during validation: {}",
				hash, err
			);
			if let Err(e) = peers.ban_peer(&peer_addr, mwc_p2p::ReasonForBan::BadBlock, &message) {
				warn!(
					"Failed to ban peer {} for bad block {}: {}",
					peer_addr, hash, e
				);
			}
		}
	}
}

impl<B, P> ChainToPoolAndNetAdapter<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	/// Construct a ChainToPoolAndNetAdapter instance.
	pub fn new(
		tx_pool: Arc<RwLock<mwc_pool::TransactionPool<B, P>>>,
		sync_state: Arc<SyncState>,
		hooks: Vec<Box<dyn ChainEvents + Send + Sync>>,
	) -> Self {
		ChainToPoolAndNetAdapter {
			tx_pool,
			sync_state,
			peers: OneTime::new(),
			hooks: hooks,
		}
	}

	/// Initialize a ChainToPoolAndNetAdapter instance with handle to a Peers
	/// object. Should only be called once.
	pub fn init(&self, peers: Arc<mwc_p2p::Peers>) -> Result<(), crate::Error> {
		self.peers
			.init(Arc::downgrade(&peers))
			.map_err(|e| crate::Error::ServerError(e.to_string()))
	}

	fn peers(&self) -> Result<Arc<mwc_p2p::Peers>, crate::Error> {
		self.peers
			.borrow()
			.map_err(|e| crate::Error::ServerError(e.to_string()))?
			.upgrade()
			.ok_or_else(|| {
				crate::Error::ServerError(
					"ChainToPoolAndNetAdapter::peers, peers reference is not available".into(),
				)
			})
	}
}

/// Adapter between the transaction pool and the network, to relay
/// transactions that have been accepted.
pub struct PoolToNetAdapter {
	peers: OneTime<Weak<mwc_p2p::Peers>>,
	dandelion_epoch: Arc<RwLock<DandelionEpoch>>,
}

/// Adapter between the Dandelion monitor and the current Dandelion "epoch".
pub trait DandelionAdapter: Send + Sync {
	/// Is the node stemming (or fluffing) transactions in the current epoch?
	fn is_stem(&self) -> bool;

	/// Is the current Dandelion epoch expired?
	fn is_expired(&self) -> bool;

	/// Transition to the next Dandelion epoch (new stem/fluff state, select new relay peer).
	///
	/// If peers are not currently available, leave the existing epoch unchanged. This keeps
	/// the expired state visible to the Dandelion monitor so it can retry the transition on
	/// a later pass after peer state becomes available again.
	fn next_epoch(&self);
}

impl DandelionAdapter for PoolToNetAdapter {
	fn is_stem(&self) -> bool {
		self.dandelion_epoch.read_recursive().is_stem()
	}

	fn is_expired(&self) -> bool {
		self.dandelion_epoch.read_recursive().is_expired()
	}

	fn next_epoch(&self) {
		match self.peers() {
			Ok(peers) => self.dandelion_epoch.write().next_epoch(&peers),
			Err(e) => {
				// Keep the current epoch state and relay peer. Since the epoch remains
				// expired, the Dandelion monitor will retry once peers are available.
				error!(
					"PoolToNetAdapter next_epoch failed because peers are not available, will retry: {}",
					e
				)
			}
		}
	}
}

impl mwc_pool::PoolAdapter for PoolToNetAdapter {
	fn tx_accepted(&self, entry: &mwc_pool::PoolEntry) -> Result<(), mwc_pool::PoolError> {
		let peers = self.peers()?;
		peers
			.broadcast_transaction(&entry.tx)
			.map_err(|e| match e {
				mwc_p2p::BroadcastError::Transaction(e) => e.into(),
				mwc_p2p::BroadcastError::P2p(e) => {
					mwc_pool::PoolError::Other(format!("broadcast transaction failed: {}", e))
				}
			})?;
		Ok(())
	}

	fn stem_tx_accepted(&self, entry: &mwc_pool::PoolEntry) -> Result<(), mwc_pool::PoolError> {
		// Take write lock on the current epoch.
		// We need to be able to update the current relay peer if not currently connected.
		let mut epoch = self.dandelion_epoch.write();

		// If "stem" epoch attempt to relay the tx to the next Dandelion relay.
		// Fallback to immediately fluffing the tx if we cannot stem for any reason.
		// If "fluff" epoch then nothing to do right now (fluff via Dandelion monitor).
		// If node is configured to always stem our (pushed via api) txs then do so.
		if epoch.is_stem() || (entry.src.is_pushed() && epoch.always_stem_our_txs()) {
			match self.peers() {
				Ok(peers) => {
					if let Some(peer) = epoch.relay_peer(&peers) {
						match peer.send_stem_transaction(&entry.tx) {
							Ok(_) => {
								info!("Stemming this epoch, relaying to next peer.");
								Ok(())
							}
							Err(e) => {
								error!("Stemming tx failed. Fluffing. {:?}", e);
								Err(mwc_pool::PoolError::DandelionError)
							}
						}
					} else {
						error!("No relay peer. Fluffing.");
						Err(mwc_pool::PoolError::DandelionError)
					}
				}
				Err(e) => {
					return Err(mwc_pool::PoolError::Other(format!(
						"PoolToNetAdapter::stem_tx_accepted, peers are not available, {}",
						e
					)))
				}
			}
		} else {
			info!("Fluff epoch. Aggregating stem tx(s). Will fluff via Dandelion monitor.");
			Ok(())
		}
	}
}

impl PoolToNetAdapter {
	/// Create a new pool to net adapter
	pub fn new(context_id: u32, config: mwc_pool::DandelionConfig) -> PoolToNetAdapter {
		PoolToNetAdapter {
			peers: OneTime::new(),
			dandelion_epoch: Arc::new(RwLock::new(DandelionEpoch::new(context_id, config))),
		}
	}

	/// Setup the p2p server on the adapter
	pub fn init(&self, peers: Arc<mwc_p2p::Peers>) -> Result<(), mwc_pool::PoolError> {
		self.peers
			.init(Arc::downgrade(&peers))
			.map_err(|e| mwc_pool::PoolError::Other(e.to_string()))
	}

	fn peers(&self) -> Result<Arc<mwc_p2p::Peers>, mwc_pool::PoolError> {
		self.peers
			.borrow()
			.map_err(|e| mwc_pool::PoolError::Other(e.to_string()))?
			.upgrade()
			.ok_or_else(|| {
				mwc_pool::PoolError::Other(
					"PoolToNetAdapter::peers, peers reference is not available".into(),
				)
			})
	}
}

/// Implements the view of the  required by the TransactionPool to
/// operate. Mostly needed to break any direct lifecycle or implementation
/// dependency between the pool and the chain.
#[derive(Clone)]
pub struct PoolToChainAdapter {
	chain: OneTime<Weak<mwc_chain::Chain>>,
}

impl PoolToChainAdapter {
	/// Create a new pool adapter
	pub fn new() -> PoolToChainAdapter {
		PoolToChainAdapter {
			chain: OneTime::new(),
		}
	}

	/// Set the pool adapter's chain. Should only be called once.
	pub fn set_chain(&self, chain_ref: Arc<mwc_chain::Chain>) -> Result<(), mwc_pool::PoolError> {
		self.chain
			.init(Arc::downgrade(&chain_ref))
			.map_err(|e| mwc_pool::PoolError::Other(e.to_string()))
	}

	fn chain(&self) -> Result<Arc<mwc_chain::Chain>, mwc_pool::PoolError> {
		self.chain
			.borrow()
			.map_err(|e| mwc_pool::PoolError::Other(e.to_string()))?
			.upgrade()
			.ok_or_else(|| {
				mwc_pool::PoolError::Other("Chain instance is not available".to_string())
			})
	}
}

fn chain_validation_error_to_pool_error(e: mwc_chain::Error, context: &str) -> mwc_pool::PoolError {
	use mwc_chain::Error as ChainError;
	use mwc_pool::PoolError;

	match e {
		ChainError::Transaction(txe) => txe.into(),
		ChainError::NRDRelativeHeight => PoolError::NRDKernelRelativeHeight,
		ChainError::TxLockHeight => PoolError::ImmatureTransaction,
		ChainError::ImmatureCoinbase => PoolError::ImmatureCoinbase,
		ChainError::DuplicateCommitment(_) => PoolError::DuplicateCommitment,
		ChainError::AlreadySpent(commit) => PoolError::DuplicateKernelOrDuplicateSpent(format!(
			"output already spent: {:?}",
			commit
		)),
		ChainError::InputMismatch(commit) => PoolError::InvalidTx(
			mwc_core::core::transaction::Error::Generic(format!("input mismatch: {:?}", commit)),
		),
		other if other.is_bad_data() => {
			PoolError::InvalidTx(mwc_core::core::transaction::Error::Generic(format!(
				"failed to {}, {}",
				context, other
			)))
		}
		other => PoolError::Other(format!("failed to {}, {}", context, other)),
	}
}

impl mwc_pool::BlockChain for PoolToChainAdapter {
	fn chain_head(&self) -> Result<BlockHeader, mwc_pool::PoolError> {
		let chain = self.chain()?;
		chain
			.head_header()
			.map_err(|e| mwc_pool::PoolError::Other(format!("failed to get head_header, {}", e)))
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, mwc_pool::PoolError> {
		let chain = self.chain()?;
		chain
			.get_block_header(hash)
			.map_err(|e| mwc_pool::PoolError::Other(format!("failed to get block_header, {}", e)))
	}

	fn get_block_sums(&self, hash: &Hash) -> Result<BlockSums, mwc_pool::PoolError> {
		let chain = self.chain()?;
		chain
			.get_block_sums(hash)
			.map_err(|e| mwc_pool::PoolError::Other(format!("failed to get block_sums, {}", e)))
	}

	fn validate_tx(&self, tx: &Transaction) -> Result<(), mwc_pool::PoolError> {
		let chain = self.chain()?;
		chain
			.validate_tx(tx)
			.map_err(|e| chain_validation_error_to_pool_error(e, "validate tx"))
	}

	fn validate_inputs(
		&self,
		inputs: &Inputs,
	) -> Result<Vec<OutputIdentifier>, mwc_pool::PoolError> {
		let chain = self.chain()?;
		chain
			.validate_inputs(inputs)
			.map(|outputs| outputs.into_iter().map(|(out, _)| out).collect::<Vec<_>>())
			.map_err(|e| chain_validation_error_to_pool_error(e, "validate inputs"))
	}

	fn verify_coinbase_maturity(&self, inputs: &Inputs) -> Result<(), mwc_pool::PoolError> {
		let chain = self.chain()?;
		chain
			.verify_coinbase_maturity(inputs)
			.map_err(|e| chain_validation_error_to_pool_error(e, "verify coinbase maturity"))
	}

	fn verify_tx_lock_height(&self, tx: &Transaction) -> Result<(), mwc_pool::PoolError> {
		let chain = self.chain()?;
		chain
			.verify_tx_lock_height(tx)
			.map_err(|e| chain_validation_error_to_pool_error(e, "verify tx lock height"))
	}

	fn replay_attack_check(&self, tx: &Transaction) -> Result<(), mwc_pool::PoolError> {
		let chain = self.chain()?;
		// Keep this deliberately simple: this chain check can fail while building
		// the historical spent-output view, but the txpool cannot safely accept a
		// tx when replay protection could not be verified. The transaction is
		// rejected either way, and the original error details are preserved in
		// the rejection message.
		chain.replay_attack_check(tx).map_err(|e| {
			mwc_pool::PoolError::DuplicateKernelOrDuplicateSpent(format!(
				"Replay attack detected, {}",
				e
			))
		})
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use mwc_crates::secp::pedersen::Commitment;
	use std::thread;
	use std::time::Duration;

	fn test_peer_addr(port: u16) -> PeerAddr {
		PeerAddr::Ip(format!("127.0.0.1:{}", port).parse().unwrap())
	}

	fn test_hash(value: u64) -> Hash {
		Hash::from_vec(&value.to_le_bytes())
	}

	#[test]
	fn chain_validation_error_preserves_transaction_error_classification() {
		let err = chain_validation_error_to_pool_error(
			mwc_chain::Error::Transaction(mwc_core::core::transaction::Error::TooHeavy),
			"validate tx",
		);

		assert!(matches!(
			err,
			mwc_pool::PoolError::InvalidTx(mwc_core::core::transaction::Error::TooHeavy)
		));
	}

	#[test]
	fn chain_validation_error_preserves_input_rejection_classification() {
		let commit = Commitment::from_vec([1; 33].to_vec()).unwrap();
		let err = chain_validation_error_to_pool_error(
			mwc_chain::Error::AlreadySpent(commit),
			"validate inputs",
		);

		assert!(matches!(
			err,
			mwc_pool::PoolError::DuplicateKernelOrDuplicateSpent(msg)
				if msg.contains("output already spent")
		));
	}

	#[test]
	fn chain_validation_error_maps_bad_data_fallback_to_invalid_tx() {
		let err = chain_validation_error_to_pool_error(
			mwc_chain::Error::OutputNotFound("missing output".into()),
			"validate inputs",
		);

		assert!(matches!(
			err,
			mwc_pool::PoolError::InvalidTx(mwc_core::core::transaction::Error::Generic(msg))
				if msg.contains("failed to validate inputs")
		));
	}

	#[test]
	fn chain_validation_error_keeps_internal_errors_internal() {
		let err = chain_validation_error_to_pool_error(
			mwc_chain::Error::Other("chain backend unavailable".into()),
			"validate tx",
		);

		assert!(matches!(
			err,
			mwc_pool::PoolError::Other(msg)
				if msg.contains("failed to validate tx")
					&& msg.contains("chain backend unavailable")
		));
	}

	#[test]
	fn chain_validation_error_classifies_tx_lock_height_context() {
		let lock_height_err = chain_validation_error_to_pool_error(
			mwc_chain::Error::TxLockHeight,
			"verify tx lock height",
		);

		assert!(matches!(
			lock_height_err,
			mwc_pool::PoolError::ImmatureTransaction
		));

		let bad_data_err = chain_validation_error_to_pool_error(
			mwc_chain::Error::DataOverflow("next block height overflow".into()),
			"verify tx lock height",
		);

		assert!(matches!(
			bad_data_err,
			mwc_pool::PoolError::InvalidTx(mwc_core::core::transaction::Error::Generic(msg))
				if msg.contains("failed to verify tx lock height")
					&& msg.contains("next block height overflow")
		));

		let internal_err = chain_validation_error_to_pool_error(
			mwc_chain::Error::Other("chain backend unavailable".into()),
			"verify tx lock height",
		);

		assert!(matches!(
			internal_err,
			mwc_pool::PoolError::Other(msg)
				if msg.contains("failed to verify tx lock height")
					&& msg.contains("chain backend unavailable")
		));
	}

	#[test]
	fn chain_validation_error_classifies_coinbase_maturity_context() {
		let immature_coinbase_err = chain_validation_error_to_pool_error(
			mwc_chain::Error::ImmatureCoinbase,
			"verify coinbase maturity",
		);

		assert!(matches!(
			immature_coinbase_err,
			mwc_pool::PoolError::ImmatureCoinbase
		));

		let bad_data_err = chain_validation_error_to_pool_error(
			mwc_chain::Error::DataOverflow("next block height overflow".into()),
			"verify coinbase maturity",
		);

		assert!(matches!(
			bad_data_err,
			mwc_pool::PoolError::InvalidTx(mwc_core::core::transaction::Error::Generic(msg))
				if msg.contains("failed to verify coinbase maturity")
					&& msg.contains("next block height overflow")
		));

		let internal_err = chain_validation_error_to_pool_error(
			mwc_chain::Error::Other("txhashset view unavailable".into()),
			"verify coinbase maturity",
		);

		assert!(matches!(
			internal_err,
			mwc_pool::PoolError::Other(msg)
				if msg.contains("failed to verify coinbase maturity")
					&& msg.contains("txhashset view unavailable")
		));
	}

	#[test]
	fn legacy_v2_block_conversion_throttle_allows_burst_then_refills() {
		let throttle = LegacyV2BlockConversionThrottle::new();
		let peer = test_peer_addr(3414);
		let now = Instant::now();

		for _ in 0..LEGACY_V2_BLOCK_CONVERSION_BURST {
			assert_eq!(throttle.delay_for_at(&peer, now), None);
		}

		let one_token_later = now + Duration::from_secs(2);
		assert_eq!(throttle.delay_for_at(&peer, one_token_later), None);
		assert_eq!(
			throttle.delay_for_at(&peer, one_token_later),
			Some(Duration::from_secs(2))
		);
	}

	#[test]
	fn legacy_v2_block_conversion_throttle_returns_sleep_after_burst() {
		let throttle = LegacyV2BlockConversionThrottle::new();
		let peer = test_peer_addr(3414);
		let now = Instant::now();

		for _ in 0..LEGACY_V2_BLOCK_CONVERSION_BURST {
			assert_eq!(throttle.delay_for_at(&peer, now), None);
		}

		assert_eq!(
			throttle.delay_for_at(&peer, now),
			Some(Duration::from_secs(2))
		);
	}

	#[test]
	fn legacy_v2_block_conversion_throttle_tracks_peers_independently() {
		let throttle = LegacyV2BlockConversionThrottle::new();
		let first = test_peer_addr(3414);
		let second = test_peer_addr(3415);
		let now = Instant::now();

		for _ in 0..LEGACY_V2_BLOCK_CONVERSION_BURST {
			assert_eq!(throttle.delay_for_at(&first, now), None);
		}

		assert_eq!(
			throttle.delay_for_at(&first, now),
			Some(Duration::from_secs(2))
		);
		assert_eq!(throttle.delay_for_at(&second, now), None);
	}

	#[test]
	fn legacy_v2_block_conversion_throttle_prunes_stale_peers() {
		let throttle = LegacyV2BlockConversionThrottle::new();
		let stale_peer = test_peer_addr(3414);
		let active_peer = test_peer_addr(3415);
		let now = Instant::now();

		assert_eq!(throttle.delay_for_at(&stale_peer, now), None);
		assert!(throttle.peers.read_recursive().contains_key(&stale_peer));

		let later = now + Duration::from_secs(LEGACY_V2_BLOCK_CONVERSION_STALE_SECS + 1);
		assert_eq!(throttle.delay_for_at(&active_peer, later), None);

		let peers = throttle.peers.read_recursive();
		assert!(!peers.contains_key(&stale_peer));
		assert!(peers.contains_key(&active_peer));
	}

	#[test]
	fn compact_block_reconstruction_cache_suppresses_attempts_for_retry_window() {
		let cache = RwLock::new(HashMap::new());
		let hash =
			Hash::from_hex("735cf2a4492b437e292a295549c31df5f1e8e6d09e58ed20abdd808c2261d1f1")
				.unwrap();
		let now = Instant::now();

		assert_eq!(
			reserve_compact_block_reconstruction_at(&cache, &hash, now),
			true
		);
		assert_eq!(
			reserve_compact_block_reconstruction_at(&cache, &hash, now),
			false
		);
		assert_eq!(
			reserve_compact_block_reconstruction_at(
				&cache,
				&hash,
				now + Duration::from_secs(COMPACT_BLOCK_RECONSTRUCTION_RETRY_SECS + 1)
			),
			true
		);
	}

	#[test]
	fn compact_block_reconstruction_cache_retries_after_window() {
		let cache = RwLock::new(HashMap::new());
		let hash =
			Hash::from_hex("735cf2a4492b437e292a295549c31df5f1e8e6d09e58ed20abdd808c2261d1f1")
				.unwrap();
		let now = Instant::now();

		assert_eq!(
			reserve_compact_block_reconstruction_at(&cache, &hash, now),
			true
		);
		finish_compact_block_reconstruction_at(&cache, &hash, now);

		assert_eq!(
			reserve_compact_block_reconstruction_at(
				&cache,
				&hash,
				now + Duration::from_secs(COMPACT_BLOCK_RECONSTRUCTION_RETRY_SECS)
			),
			false
		);
		assert_eq!(
			reserve_compact_block_reconstruction_at(
				&cache,
				&hash,
				now + Duration::from_secs(COMPACT_BLOCK_RECONSTRUCTION_RETRY_SECS + 1)
			),
			true
		);
	}

	#[test]
	fn compact_block_reconstruction_cache_prunes_stale_blocks() {
		let cache = RwLock::new(HashMap::new());
		let stale_hash =
			Hash::from_hex("735cf2a4492b437e292a295549c31df5f1e8e6d09e58ed20abdd808c2261d1f1")
				.unwrap();
		let active_hash =
			Hash::from_hex("9686b69cab945146fd431ec4459a0eef6efbcc5553480b7454edd32f9c3b4d52")
				.unwrap();
		let now = Instant::now();

		assert_eq!(
			reserve_compact_block_reconstruction_at(&cache, &stale_hash, now),
			true
		);
		finish_compact_block_reconstruction_at(&cache, &stale_hash, now);
		assert!(cache.read_recursive().contains_key(&stale_hash));

		let later = now + Duration::from_secs(COMPACT_BLOCK_RECONSTRUCTION_STALE_SECS + 1);
		assert_eq!(
			reserve_compact_block_reconstruction_at(&cache, &active_hash, later),
			true
		);

		let blocks = cache.read_recursive();
		assert!(!blocks.contains_key(&stale_hash));
		assert!(blocks.contains_key(&active_hash));
	}

	#[test]
	fn compact_block_reconstruction_cache_evicts_oldest_entry_at_capacity() {
		let cache = RwLock::new(HashMap::new());
		let now = Instant::now();
		let oldest_hash = test_hash(0);

		for idx in 0..COMPACT_BLOCK_RECONSTRUCTION_MAX_ENTRIES {
			assert_eq!(
				reserve_compact_block_reconstruction_at(
					&cache,
					&test_hash(idx as u64),
					now + Duration::from_millis(idx as u64)
				),
				true
			);
		}

		let new_hash = test_hash(COMPACT_BLOCK_RECONSTRUCTION_MAX_ENTRIES as u64);
		assert_eq!(
			reserve_compact_block_reconstruction_at(
				&cache,
				&new_hash,
				now + Duration::from_millis(COMPACT_BLOCK_RECONSTRUCTION_MAX_ENTRIES as u64)
			),
			true
		);

		let blocks = cache.read_recursive();
		assert_eq!(blocks.len(), COMPACT_BLOCK_RECONSTRUCTION_MAX_ENTRIES);
		assert!(!blocks.contains_key(&oldest_hash));
		assert!(blocks.contains_key(&new_hash));
	}

	#[test]
	fn event_cache_read_only_miss_does_not_update_cache() {
		let cache = EventCache::new();
		let hash =
			Hash::from_hex("735cf2a4492b437e292a295549c31df5f1e8e6d09e58ed20abdd808c2261d1f1")
				.unwrap();

		assert_eq!(cache.contains(&hash, false), false);
		assert_eq!(cache.contains(&hash, true), false);
		assert_eq!(cache.contains(&hash, true), true);
	}

	#[test]
	fn test_event_cache() {
		let cache = EventCache::new();
		let def_hash1 = Hash::default();
		let def_hash2 = Hash::default();
		let hash2_1 =
			Hash::from_hex("735cf2a4492b437e292a295549c31df5f1e8e6d09e58ed20abdd808c2261d1f1")
				.unwrap();
		let hash2_2 =
			Hash::from_hex("735cf2a4492b437e292a295549c31df5f1e8e6d09e58ed20abdd808c2261d1f1")
				.unwrap();
		let hash3 =
			Hash::from_hex("9686b69cab945146fd431ec4459a0eef6efbcc5553480b7454edd32f9c3b4d52")
				.unwrap();

		assert_eq!(cache.contains(&def_hash1, true), false);
		assert_eq!(cache.contains(&def_hash2, true), true);
		thread::sleep(Duration::from_millis(1050));
		assert_eq!(cache.contains(&def_hash1, false), false);
		assert_eq!(cache.contains(&def_hash1, true), false);
		assert_eq!(cache.contains(&def_hash2, true), true);
		assert_eq!(cache.contains(&hash2_2, false), false);
		assert_eq!(cache.contains(&hash2_1, true), false);
		assert_eq!(cache.contains(&hash2_2, true), true);
		assert_eq!(cache.contains(&hash3, true), false);
	}
}
