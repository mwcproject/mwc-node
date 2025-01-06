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

use crate::util::RwLock;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Instant;

use crate::chain::txhashset::BitmapChunk;
use crate::chain::{self, BlockStatus, ChainAdapter, Options, SyncState, SyncStatus};

use crate::common::hooks::{ChainEvents, NetEvents};
use crate::common::types::{ChainValidationMode, DandelionEpoch, ServerConfig};
use crate::core::core::hash::{Hash, Hashed};
use crate::core::core::transaction::Transaction;
use crate::core::core::{
	BlockHeader, BlockSums, CompactBlock, Inputs, OutputIdentifier, Segment, SegmentIdentifier,
	TxKernel,
};
use crate::core::pow::Difficulty;
use crate::core::ser::ProtocolVersion;
use crate::core::{core, global};
use crate::mwc::sync::get_locator_heights;
use crate::mwc::sync::sync_manager::SyncManager;
use crate::p2p;
use crate::p2p::types::PeerInfo;
use crate::pool::{self, BlockChain, PoolAdapter};
use crate::util::secp::pedersen::RangeProof;
use crate::util::OneTime;
use chrono::prelude::*;
use chrono::Duration;
use mwc_chain::txhashset::Segmenter;
use mwc_p2p::PeerAddr;
use mwc_util::secp::{ContextFlag, Secp256k1};
use std::sync::atomic::AtomicI64;
use std::sync::atomic::Ordering;

// NetToChainAdapter need a memory cache to prevent data overloading for network core nodes (non leaf nodes)
// This cache will drop sequence of the events during the second
struct EventCache {
	event: RwLock<Hash>,
	time: AtomicI64,
}

impl EventCache {
	fn new() -> Self {
		EventCache {
			event: RwLock::new(Hash::default()),
			time: AtomicI64::new(0),
		}
	}

	// Check if it is contain the hash value
	pub fn contains(&self, hash: &Hash, update: bool) -> bool {
		let now = Utc::now().timestamp_millis();
		let time_limit = now - 1000; // lock for a 1 second, should be enough to reduce the load.
		if self.time.load(Ordering::Relaxed) < time_limit {
			if update {
				*(self.event.write()) = *hash;
				self.time.store(now, Ordering::Relaxed);
			}
			return false;
		}

		if *self.event.read() == *hash {
			true
		} else {
			if update {
				*(self.event.write()) = *hash;
				self.time.store(now, Ordering::Relaxed);
			}
			false
		}
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
	chain: Weak<chain::Chain>,
	tx_pool: Arc<RwLock<pool::TransactionPool<B, P>>>,
	peers: OneTime<Weak<p2p::Peers>>,
	config: ServerConfig,
	hooks: Vec<Box<dyn NetEvents + Send + Sync>>,

	// local in mem cache
	processed_headers: EventCache,
	processed_blocks: EventCache,
	processed_transactions: EventCache,
}

impl<B, P> p2p::ChainAdapter for NetToChainAdapter<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	fn total_difficulty(&self) -> Result<Difficulty, chain::Error> {
		Ok(self.chain().head()?.total_difficulty)
	}

	fn total_height(&self) -> Result<u64, chain::Error> {
		Ok(self.chain().head()?.height)
	}

	fn get_transaction(&self, kernel_hash: Hash) -> Option<core::Transaction> {
		self.tx_pool.read().retrieve_tx_by_kernel_hash(kernel_hash)
	}

	fn tx_kernel_received(
		&self,
		kernel_hash: Hash,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		// nothing much we can do with a new transaction while syncing
		if self.sync_state.is_syncing() {
			return Ok(true);
		}

		let tx = self.tx_pool.read().retrieve_tx_by_kernel_hash(kernel_hash);

		if tx.is_none() {
			self.request_transaction(kernel_hash, peer_info);
		}
		Ok(true)
	}

	fn transaction_received(
		&self,
		tx: core::Transaction,
		stem: bool,
	) -> Result<bool, chain::Error> {
		// nothing much we can do with a new transaction while syncing
		if self.sync_state.is_syncing() {
			return Ok(true);
		}

		let tx_hash = tx.hash();
		// For transaction we allow double processing, we want to be sure that TX will be stored in the pool
		// because there is no recovery plan for transactions. So we want to use natural retry to help us handle failures
		if self.processed_transactions.contains(&tx_hash, false) {
			debug!("transaction_received, cache for {} Rejected", tx_hash);
			return Ok(true);
		} else {
			debug!("transaction_received, cache for {} OK", tx_hash);
		}

		let source = pool::TxSource::Broadcast;
		let chain = self.chain();
		let header = chain.head_header()?;

		for hook in &self.hooks {
			hook.on_transaction_received(&tx);
		}

		let mut tx_pool = self.tx_pool.write();
		match tx_pool.add_to_pool(source, tx, stem, &header, chain.secp()) {
			Ok(_) => {
				self.processed_transactions.contains(&tx_hash, true);
				Ok(true)
			}
			Err(e) => {
				debug!("Transaction {} rejected: {:?}", tx_hash, e);
				Ok(false)
			}
		}
	}

	fn block_received(
		&self,
		b: core::Block,
		peer_info: &PeerInfo,
		opts: chain::Options,
	) -> Result<bool, chain::Error> {
		let b_hash = b.hash();
		if self.processed_blocks.contains(&b_hash, true) {
			debug!("block_received, cache for {} Rejected", b_hash);
			return Ok(true);
		} else {
			debug!("block_received, cache for {} OK", b_hash);
		}

		if self.chain().is_known(&b.header).is_err() {
			return Ok(true);
		}

		let total_blocks = match self.chain().header_head() {
			Ok(tip) => tip.height,
			Err(_) => 0,
		};

		info!(
			"Received block {} of {} hash {} from {} [in/out/kern: {}/{}/{}] going to process. Prev block Hash: {}",
			b.header.height,
			total_blocks,
			b.hash(),
			peer_info.addr,
			b.inputs().len(),
			b.outputs().len(),
			b.kernels().len(),
			b.header.prev_hash,
		);
		self.process_block(b, peer_info, opts)
	}

	fn compact_block_received(
		&self,
		cb: core::CompactBlock,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		// No need to process this compact block if we have previously accepted the _full block_.
		let chain = self.chain();
		if chain.is_known(&cb.header).is_err() {
			return Ok(true);
		}

		let bhash = cb.hash();
		debug!(
			"Received compact_block {} at {} from {} [out/kern/kern_ids: {}/{}/{}] going to process.",
			bhash,
			cb.header.height,
			peer_info.addr,
			cb.out_full().len(),
			cb.kern_full().len(),
			cb.kern_ids().len(),
		);

		let cb_hash = cb.hash();
		if cb.kern_ids().is_empty() {
			// push the freshly hydrated block through the chain pipeline
			match core::Block::hydrate_from(cb, &[]) {
				Ok(block) => {
					debug!(
						"successfully hydrated (empty) block: {} at {} ({})",
						block.header.hash(),
						block.header.height,
						block.inputs().version_str(),
					);
					if !self.sync_state.is_syncing() {
						for hook in &self.hooks {
							hook.on_block_received(&block, &peer_info.addr);
						}
					}
					self.process_block(block, peer_info, chain::Options::NONE)
				}
				Err(e) => {
					debug!("Invalid hydrated block {}: {:?}", cb_hash, e);
					return Ok(false);
				}
			}
		} else {
			// check at least the header is valid before hydrating
			if let Err(e) = chain.process_block_header(&cb.header, chain::Options::NONE) {
				debug!("Invalid compact block header {}: {:?}", cb_hash, e);
				return Ok(!e.is_bad_data());
			}

			let (txs, missing_short_ids) = {
				self.tx_pool
					.read()
					.retrieve_transactions(cb.hash(), cb.nonce, cb.kern_ids())
			};

			debug!(
				"compact_block_received: txs from tx pool - {}, (unknown kern_ids: {})",
				txs.len(),
				missing_short_ids.len(),
			);

			// If we have missing kernels then we know we cannot hydrate this compact block.
			if !missing_short_ids.is_empty() {
				self.request_block(&cb.header, peer_info, chain::Options::NONE);
				return Ok(true);
			}

			let block = match core::Block::hydrate_from(cb.clone(), &txs) {
				Ok(block) => {
					if !self.sync_state.is_syncing() {
						for hook in &self.hooks {
							hook.on_block_received(&block, &peer_info.addr);
						}
					}
					block
				}
				Err(e) => {
					debug!("Invalid hydrated block {}: {:?}", cb.hash(), e);
					return Ok(false);
				}
			};

			if let Ok(prev) = chain.get_previous_header(&cb.header) {
				if block
					.validate(&prev.total_kernel_offset, chain.secp())
					.is_ok()
				{
					debug!(
						"successfully hydrated block: {} at {} ({})",
						block.header.hash(),
						block.header.height,
						block.inputs().version_str(),
					);
					self.process_block(block, peer_info, chain::Options::NONE)
				} else if self.sync_state.status() == SyncStatus::NoSync {
					debug!("adapter: block invalid after hydration, requesting full block");
					self.request_block(&cb.header, peer_info, chain::Options::NONE);
					Ok(true)
				} else {
					debug!("block invalid after hydration, ignoring it, cause still syncing");
					Ok(true)
				}
			} else {
				debug!("failed to retrieve previous block header (still syncing?)");
				Ok(true)
			}
		}
	}

	fn header_received(
		&self,
		bh: core::BlockHeader,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		// No need to process this header if we have previously accepted the _full block_.
		let bh_hash = bh.hash();

		// A shortcut to refuse the known bad block header.
		if bh_hash == Hash::from_hex(crate::chain::BLOCK_TO_BAN)? {
			debug!(
				"header_received: known bad header {} at {} refused by chain",
				bh_hash, bh.height,
			);
			// serious enough to need to ban the peer
			return Ok(false);
		}

		if self.processed_headers.contains(&bh_hash, true) {
			debug!("header_received, cache for {} Rejected", bh_hash);
			return Ok(true);
		} else {
			debug!("header_received, cache for {} OK", bh_hash);
		}

		let chain = self.chain();
		if chain.block_exists(&bh.hash())? {
			return Ok(true);
		}
		if !self.sync_state.is_syncing() {
			for hook in &self.hooks {
				hook.on_header_received(&bh, &peer_info.addr);
			}
		}

		// pushing the new block header through the header chain pipeline
		// we will go ask for the block if this is a new header
		let res = chain.process_block_header(&bh, chain::Options::NONE);

		if let Err(e) = res {
			debug!("Block header {} refused by chain: {:?}", bh.hash(), e);
			if e.is_bad_data() {
				return Ok(false);
			} else {
				if self.sync_state.are_headers_done() {
					// we got an error when trying to process the block header
					// but nothing serious enough to need to ban the peer upstream
					// Probably child block doesn't exist, let's request them
					if let Some(peer) = self.peers().get_connected_peer(&peer_info.addr) {
						let head = chain.head()?;
						debug!(
							"Got unknown header, requesting headers from the peer {} at height {}",
							peer_info.addr, head.height
						);
						let heights = get_locator_heights(head.height);
						let locator = chain.get_locator_hashes(head, &heights)?;
						let _ = peer.send_header_request(locator);

						if let Ok(tip) = chain.head() {
							// Requesting of orphans buffer is large enough to finish the job with request
							if bh.height.saturating_sub(tip.height)
								< chain.get_pibd_params().get_orphans_num_limit() as u64
							{
								let _ = peer.send_block_request(bh.hash(), chain::Options::NONE);
							}
						}
					}
				}
				return Err(e);
			}
		}

		// we have successfully processed a block header
		// so we can go request the block itself
		self.request_compact_block(&bh, peer_info);

		// done receiving the header
		Ok(true)
	}

	fn headers_received(
		&self,
		bhs: &[core::BlockHeader],
		remaining: u64,
		peer_info: &PeerInfo,
	) -> Result<(), chain::Error> {
		if bhs.is_empty() {
			return Ok(());
		}

		let bad_block = Hash::from_hex(chain::BLOCK_TO_BAN)?;
		if bhs.iter().find(|h| h.hash() == bad_block).is_some() {
			debug!("headers_received: found known bad header, all data is rejected");
			return Ok(());
		}

		self.sync_manager
			.receive_headers(&peer_info.addr, bhs, remaining, self.peers());
		Ok(())
	}

	fn locate_headers(&self, locator: &[Hash]) -> Result<Vec<core::BlockHeader>, chain::Error> {
		self.chain().locate_headers(locator, p2p::MAX_BLOCK_HEADERS)
	}

	/// Gets a full block by its hash.
	/// Will convert to v2 compatibility based on peer protocol version.
	fn get_block(&self, h: Hash, peer_info: &PeerInfo) -> Option<core::Block> {
		self.chain()
			.get_block(&h)
			.map(|b| match peer_info.version.value() {
				0..=2 => self.chain().convert_block_v2(b).ok(),
				3..=ProtocolVersion::MAX => Some(b),
			})
			.unwrap_or(None)
	}

	/// Provides a reading view into the current txhashset state as well as
	/// the required indexes for a consumer to rewind to a consistent state
	/// at the provided block hash.
	fn txhashset_read(&self, h: Hash) -> Option<p2p::TxHashSetRead> {
		match self.chain().txhashset_read(h.clone()) {
			Ok((out_index, kernel_index, read)) => Some(p2p::TxHashSetRead {
				output_index: out_index,
				kernel_index: kernel_index,
				reader: read,
			}),
			Err(e) => {
				warn!("Couldn't produce txhashset data for block {}: {:?}", h, e);
				None
			}
		}
	}

	fn txhashset_archive_header(&self) -> Result<core::BlockHeader, chain::Error> {
		self.chain().txhashset_archive_header()
	}

	fn get_tmp_dir(&self) -> PathBuf {
		self.chain().get_tmp_dir()
	}

	fn get_tmpfile_pathname(&self, tmpfile_name: String) -> PathBuf {
		self.chain().get_tmpfile_pathname(tmpfile_name)
	}

	fn prepare_segmenter(&self) -> Result<Segmenter, chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(chain::Error::ChainInSync);
		}
		self.chain().segmenter()
	}

	fn get_kernel_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<TxKernel>, chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(chain::Error::ChainInSync);
		}
		let segmenter = self.chain().segmenter()?;
		let head_hash = segmenter.header().hash();
		if head_hash != hash {
			return Err(chain::Error::SegmenterHeaderMismatch(
				head_hash,
				segmenter.header().height,
			));
		}
		segmenter.kernel_segment(id)
	}

	fn get_bitmap_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<BitmapChunk>, chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(chain::Error::ChainInSync);
		}
		let segmenter = self.chain().segmenter()?;
		let head_hash = segmenter.header().hash();
		if head_hash != hash {
			return Err(chain::Error::SegmenterHeaderMismatch(
				head_hash,
				segmenter.header().height,
			));
		}
		segmenter.bitmap_segment(id)
	}

	fn get_output_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<OutputIdentifier>, chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(chain::Error::ChainInSync);
		}
		let segmenter = self.chain().segmenter()?;
		let head_hash = segmenter.header().hash();
		if head_hash != hash {
			return Err(chain::Error::SegmenterHeaderMismatch(
				head_hash,
				segmenter.header().height,
			));
		}
		segmenter.output_segment(id)
	}

	fn get_rangeproof_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<RangeProof>, chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(chain::Error::ChainInSync);
		}
		let segmenter = self.chain().segmenter()?;
		let head_hash = segmenter.header().hash();
		if head_hash != hash {
			return Err(chain::Error::SegmenterHeaderMismatch(
				head_hash,
				segmenter.header().height,
			));
		}
		segmenter.rangeproof_segment(id)
	}

	fn recieve_pibd_status(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
		output_bitmap_root: Hash,
	) -> Result<(), chain::Error> {
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
	) -> Result<(), chain::Error> {
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
	) -> Result<(), chain::Error> {
		info!(
			"Received headers hash response {}, {} from {}",
			archive_height, headers_hash_root, peer
		);
		self.sync_manager
			.receive_headers_hash_response(peer, archive_height, headers_hash_root);
		Ok(())
	}

	fn get_header_hashes_segment(
		&self,
		header_hashes_root: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<Hash>, chain::Error> {
		if self.sync_state.is_syncing() {
			return Err(chain::Error::ChainInSync);
		}
		let segmenter = self.chain().segmenter()?;

		let chain_header_hashes_root = segmenter.headers_root()?;
		if header_hashes_root != chain_header_hashes_root {
			return Err(chain::Error::SegmenterHeaderMismatch(
				chain_header_hashes_root,
				segmenter.header().height,
			));
		}
		segmenter.headers_segment(id)
	}

	fn receive_header_hashes_segment(
		&self,
		peer: &PeerAddr,
		header_hashes_root: Hash,
		segment: Segment<Hash>,
	) -> Result<(), chain::Error> {
		info!(
			"Received headers hashes segment {}, {} from {}",
			segment.id(),
			header_hashes_root,
			peer
		);
		self.sync_manager
			.receive_header_hashes_segment(peer, header_hashes_root, segment);
		Ok(())
	}

	fn receive_bitmap_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<BitmapChunk>,
	) -> Result<(), chain::Error> {
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
			&self.peers(),
		);
		Ok(())
	}

	fn receive_output_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<OutputIdentifier>,
	) -> Result<(), chain::Error> {
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
			&self.peers(),
		);
		Ok(())
	}

	fn receive_rangeproof_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<RangeProof>,
	) -> Result<(), chain::Error> {
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
			&self.peers(),
		);
		Ok(())
	}

	fn receive_kernel_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<TxKernel>,
	) -> Result<(), chain::Error> {
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
			&self.peers(),
		);
		Ok(())
	}
}

impl<B, P> NetToChainAdapter<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	/// Construct a new NetToChainAdapter instance
	pub fn new(
		sync_state: Arc<SyncState>,
		chain: Arc<chain::Chain>,
		sync_manager: Arc<SyncManager>,
		tx_pool: Arc<RwLock<pool::TransactionPool<B, P>>>,
		config: ServerConfig,
		hooks: Vec<Box<dyn NetEvents + Send + Sync>>,
	) -> Self {
		NetToChainAdapter {
			sync_state,
			sync_manager,
			chain: Arc::downgrade(&chain),
			tx_pool,
			peers: OneTime::new(),
			config,
			hooks,
			processed_headers: EventCache::new(),
			processed_blocks: EventCache::new(),
			processed_transactions: EventCache::new(),
		}
	}

	/// Initialize a NetToChainAdaptor with reference to a Peers object.
	/// Should only be called once.
	pub fn init(&self, peers: Arc<p2p::Peers>) {
		self.peers.init(Arc::downgrade(&peers));
	}

	fn peers(&self) -> Arc<p2p::Peers> {
		self.peers
			.borrow()
			.upgrade()
			.expect("Failed to upgrade weak ref to our peers.")
	}

	fn chain(&self) -> Arc<chain::Chain> {
		self.chain
			.upgrade()
			.expect("Failed to upgrade weak ref to our chain.")
	}

	// pushing the new block through the chain pipeline
	// remembering to reset the head if we have a bad block
	fn process_block(
		&self,
		b: core::Block,
		peer_info: &PeerInfo,
		opts: chain::Options,
	) -> Result<bool, chain::Error> {
		// We cannot process blocks earlier than the horizon so check for this here.
		let chain = self.chain();
		let head = {
			let head = chain.head()?;
			let horizon = head
				.height
				.saturating_sub(global::cut_through_horizon() as u64);
			if b.header.height < horizon {
				debug!("Got block is below horizon from peer {}", peer_info.addr);
				return Ok(true);
			}
			head
		};

		let bhash = b.hash();
		match chain.process_block(b.clone(), opts) {
			Ok(_) => {
				self.validate_chain(&bhash);
				//self.check_compact();  Currently Sync process does that. No needs, also we don't want collosion to happens
				self.sync_manager.recieve_block_reporting(
					true,
					&peer_info.addr,
					b,
					opts,
					&self.peers(),
				);
				Ok(true)
			}
			Err(ref e) if e.is_bad_data() => {
				warn!("process_block: block {} from peer {} is bad. Block is rejected, peer is banned. Error: {}", bhash, peer_info.addr, e);
				self.validate_chain(&bhash);
				self.sync_manager.recieve_block_reporting(
					false,
					&peer_info.addr,
					b,
					opts,
					&self.peers(),
				);
				Ok(false)
			}
			Err(e) => {
				let prev_block_hash = b.header.prev_hash.clone();
				let previous = chain.get_previous_header(&b.header);
				let need_request_prev_block = self.sync_manager.recieve_block_reporting(
					!e.is_bad_data(),
					&peer_info.addr,
					b,
					opts,
					&self.peers(),
				);
				match e {
					chain::Error::StoreErr(_, _) | chain::Error::Orphan(_) => {
						if previous.is_err() {
							// requesting headers from that peer
							if let Some(peer) = self.peers().get_connected_peer(&peer_info.addr) {
								debug!("Got block with unknow headers, requesting headers from the peer {} at height {}", peer_info.addr, head.height);
								let heights = get_locator_heights(head.height);
								let locator = chain.get_locator_hashes(head, &heights)?;
								let _ = peer.send_header_request(locator);
							}
						}
						if need_request_prev_block {
							// requesting headers from that peer
							if let Some(peer) = self.peers().get_connected_peer(&peer_info.addr) {
								// requesting prev block from that peer
								debug!("Got block with unknow child, requesting prev block {} from the peer {}", prev_block_hash, peer_info.addr);
								let _ =
									peer.send_block_request(prev_block_hash, chain::Options::NONE);
							}
						}
						Ok(true)
					}
					_ => {
						info!(
							"process_block: block {} from peer {} refused by chain: {}",
							bhash, peer_info.addr, e
						);
						Ok(true)
					}
				}
			}
		}
	}

	fn validate_chain(&self, bhash: &Hash) {
		// If we are running in "validate the full chain every block" then
		// panic here if validation fails for any reason.
		// We are out of consensus at this point and want to track the problem
		// down as soon as possible.
		// Skip this if we are currently syncing (too slow).
		if self.config.chain_validation_mode == ChainValidationMode::EveryBlock
			&& self.chain().head().unwrap().height > 0
			&& !self.sync_state.is_syncing()
		{
			let now = Instant::now();

			debug!(
				"process_block: ***** validating full chain state at {}",
				bhash,
			);

			self.chain()
				.validate(true)
				.expect("chain validation failed, hard stop");

			debug!(
				"process_block: ***** done validating full chain state, took {}s",
				now.elapsed().as_secs(),
			);
		}
	}

	/*	Compact is dome form the sync thread now. Also another thread will not help much because of batch blocking
	fn check_compact(&self) {
		// Roll the dice to trigger compaction at 1/COMPACTION_CHECK chance per block,
		// uses a different thread to avoid blocking the caller thread (likely a peer)
		let mut rng = thread_rng();
		if 0 == rng.gen_range(0, global::COMPACTION_CHECK) {
			let chain = self.chain();
			let _ = thread::Builder::new()
				.name("compactor".to_string())
				.spawn(move || {
					if let Err(e) = chain.compact() {
						error!("Could not compact chain: {:?}", e);
					}
				});
		}
	}*/

	fn request_transaction(&self, h: Hash, peer_info: &PeerInfo) {
		self.send_tx_request_to_peer(h, peer_info, |peer, h| peer.send_tx_request(h))
	}

	// After receiving a compact block if we cannot successfully hydrate
	// it into a full block then fallback to requesting the full block
	// from the same peer that gave us the compact block
	// consider additional peers for redundancy?
	fn request_block(&self, bh: &BlockHeader, peer_info: &PeerInfo, opts: Options) {
		self.send_block_request_to_peer(bh.hash(), peer_info, |peer, h| {
			peer.send_block_request(h, opts)
		})
	}

	// After we have received a block header in "header first" propagation
	// we need to go request the block (compact representation) from the
	// same peer that gave us the header (unless we have already accepted the block)
	fn request_compact_block(&self, bh: &BlockHeader, peer_info: &PeerInfo) {
		self.send_block_request_to_peer(bh.hash(), peer_info, |peer, h| {
			peer.send_compact_block_request(h)
		})
	}

	fn send_tx_request_to_peer<F>(&self, h: Hash, peer_info: &PeerInfo, f: F)
	where
		F: Fn(&p2p::Peer, Hash) -> Result<(), p2p::Error>,
	{
		match self.peers().get_connected_peer(&peer_info.addr) {
			None => debug!(
				"send_tx_request_to_peer: can't send request to peer {:?}, not connected",
				peer_info.addr
			),
			Some(peer) => {
				if let Err(e) = f(&peer, h) {
					error!("send_tx_request_to_peer: failed: {:?}", e)
				}
			}
		}
	}

	fn send_block_request_to_peer<F>(&self, h: Hash, peer_info: &PeerInfo, f: F)
	where
		F: Fn(&p2p::Peer, Hash) -> Result<(), p2p::Error>,
	{
		match self.chain().block_exists(&h) {
			Ok(false) => match self.peers().get_connected_peer(&peer_info.addr) {
				None => debug!(
					"send_block_request_to_peer: can't send request to peer {:?}, not connected",
					peer_info.addr
				),
				Some(peer) => {
					if let Err(e) = f(&peer, h) {
						error!("send_block_request_to_peer: failed: {:?}", e)
					}
				}
			},
			Ok(true) => debug!("send_block_request_to_peer: block {} already known", h),
			Err(e) => error!(
				"send_block_request_to_peer: failed to check block exists: {:?}",
				e
			),
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
	tx_pool: Arc<RwLock<pool::TransactionPool<B, P>>>,
	peers: OneTime<Weak<p2p::Peers>>,
	hooks: Vec<Box<dyn ChainEvents + Send + Sync>>,
	secp: Secp256k1,
}

impl<B, P> ChainAdapter for ChainToPoolAndNetAdapter<B, P>
where
	B: BlockChain,
	P: PoolAdapter,
{
	fn block_accepted(&self, b: &core::Block, status: BlockStatus, opts: Options) {
		// Trigger all registered "on_block_accepted" hooks (logging and webhooks).
		for hook in &self.hooks {
			hook.on_block_accepted(b, status);
		}

		// Suppress broadcast of new blocks received during sync.
		if !opts.contains(chain::Options::SYNC) {
			// If we mined the block then we want to broadcast the compact block.
			// If we received the block from another node then broadcast "header first"
			// to minimize network traffic.
			if opts.contains(Options::MINE) {
				// propagate compact block out if we mined the block
				let cb: CompactBlock = b.clone().into();
				self.peers().broadcast_compact_block(&cb);
			} else {
				// "header first" propagation if we are not the originator of this block
				self.peers().broadcast_header(&b.header);
			}
		}

		// Reconcile the txpool against the new block *after* we have broadcast it too our peers.
		// This may be slow and we do not want to delay block propagation.
		// We only want to reconcile the txpool against the new block *if* total work has increased.

		if status.is_next() || status.is_reorg() {
			let mut tx_pool = self.tx_pool.write();

			let _ = tx_pool.reconcile_block(b, &self.secp);

			// First "age out" any old txs in the reorg_cache.
			let cutoff = Utc::now() - Duration::minutes(tx_pool.config.reorg_cache_timeout);
			tx_pool.truncate_reorg_cache(cutoff);
		}

		if status.is_reorg() {
			let _ = self
				.tx_pool
				.write()
				.reconcile_reorg_cache(&b.header, &self.secp);
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
		tx_pool: Arc<RwLock<pool::TransactionPool<B, P>>>,
		hooks: Vec<Box<dyn ChainEvents + Send + Sync>>,
	) -> Self {
		ChainToPoolAndNetAdapter {
			tx_pool,
			peers: OneTime::new(),
			hooks: hooks,
			secp: Secp256k1::with_caps(ContextFlag::Commit),
		}
	}

	/// Initialize a ChainToPoolAndNetAdapter instance with handle to a Peers
	/// object. Should only be called once.
	pub fn init(&self, peers: Arc<p2p::Peers>) {
		self.peers.init(Arc::downgrade(&peers));
	}

	fn peers(&self) -> Arc<p2p::Peers> {
		self.peers
			.borrow()
			.upgrade()
			.expect("Failed to upgrade weak ref to our peers.")
	}
}

/// Adapter between the transaction pool and the network, to relay
/// transactions that have been accepted.
pub struct PoolToNetAdapter {
	peers: OneTime<Weak<p2p::Peers>>,
	dandelion_epoch: Arc<RwLock<DandelionEpoch>>,
}

/// Adapter between the Dandelion monitor and the current Dandelion "epoch".
pub trait DandelionAdapter: Send + Sync {
	/// Is the node stemming (or fluffing) transactions in the current epoch?
	fn is_stem(&self) -> bool;

	/// Is the current Dandelion epoch expired?
	fn is_expired(&self) -> bool;

	/// Transition to the next Dandelion epoch (new stem/fluff state, select new relay peer).
	fn next_epoch(&self);
}

impl DandelionAdapter for PoolToNetAdapter {
	fn is_stem(&self) -> bool {
		self.dandelion_epoch.read().is_stem()
	}

	fn is_expired(&self) -> bool {
		self.dandelion_epoch.read().is_expired()
	}

	fn next_epoch(&self) {
		self.dandelion_epoch.write().next_epoch(&self.peers());
	}
}

impl pool::PoolAdapter for PoolToNetAdapter {
	fn tx_accepted(&self, entry: &pool::PoolEntry) {
		self.peers().broadcast_transaction(&entry.tx);
	}

	fn stem_tx_accepted(&self, entry: &pool::PoolEntry) -> Result<(), pool::PoolError> {
		// Take write lock on the current epoch.
		// We need to be able to update the current relay peer if not currently connected.
		let mut epoch = self.dandelion_epoch.write();

		// If "stem" epoch attempt to relay the tx to the next Dandelion relay.
		// Fallback to immediately fluffing the tx if we cannot stem for any reason.
		// If "fluff" epoch then nothing to do right now (fluff via Dandelion monitor).
		// If node is configured to always stem our (pushed via api) txs then do so.
		if epoch.is_stem() || (entry.src.is_pushed() && epoch.always_stem_our_txs()) {
			if let Some(peer) = epoch.relay_peer(&self.peers()) {
				match peer.send_stem_transaction(&entry.tx) {
					Ok(_) => {
						info!("Stemming this epoch, relaying to next peer.");
						Ok(())
					}
					Err(e) => {
						error!("Stemming tx failed. Fluffing. {:?}", e);
						Err(pool::PoolError::DandelionError)
					}
				}
			} else {
				error!("No relay peer. Fluffing.");
				Err(pool::PoolError::DandelionError)
			}
		} else {
			info!("Fluff epoch. Aggregating stem tx(s). Will fluff via Dandelion monitor.");
			Ok(())
		}
	}
}

impl PoolToNetAdapter {
	/// Create a new pool to net adapter
	pub fn new(config: pool::DandelionConfig) -> PoolToNetAdapter {
		PoolToNetAdapter {
			peers: OneTime::new(),
			dandelion_epoch: Arc::new(RwLock::new(DandelionEpoch::new(config))),
		}
	}

	/// Setup the p2p server on the adapter
	pub fn init(&self, peers: Arc<p2p::Peers>) {
		self.peers.init(Arc::downgrade(&peers));
	}

	fn peers(&self) -> Arc<p2p::Peers> {
		self.peers
			.borrow()
			.upgrade()
			.expect("Failed to upgrade weak ref to our peers.")
	}
}

/// Implements the view of the  required by the TransactionPool to
/// operate. Mostly needed to break any direct lifecycle or implementation
/// dependency between the pool and the chain.
#[derive(Clone)]
pub struct PoolToChainAdapter {
	chain: OneTime<Weak<chain::Chain>>,
}

impl PoolToChainAdapter {
	/// Create a new pool adapter
	pub fn new() -> PoolToChainAdapter {
		PoolToChainAdapter {
			chain: OneTime::new(),
		}
	}

	/// Set the pool adapter's chain. Should only be called once.
	pub fn set_chain(&self, chain_ref: Arc<chain::Chain>) {
		self.chain.init(Arc::downgrade(&chain_ref));
	}

	fn chain(&self) -> Arc<chain::Chain> {
		self.chain
			.borrow()
			.upgrade()
			.expect("Failed to upgrade the weak ref to our chain.")
	}
}

impl pool::BlockChain for PoolToChainAdapter {
	fn chain_head(&self) -> Result<BlockHeader, pool::PoolError> {
		self.chain()
			.head_header()
			.map_err(|e| pool::PoolError::Other(format!("failed to get head_header, {}", e)))
	}

	fn get_block_header(&self, hash: &Hash) -> Result<BlockHeader, pool::PoolError> {
		self.chain()
			.get_block_header(hash)
			.map_err(|e| pool::PoolError::Other(format!("failed to get block_header, {}", e)))
	}

	fn get_block_sums(&self, hash: &Hash) -> Result<BlockSums, pool::PoolError> {
		self.chain()
			.get_block_sums(hash)
			.map_err(|e| pool::PoolError::Other(format!("failed to get block_sums, {}", e)))
	}

	fn validate_tx(&self, tx: &Transaction) -> Result<(), pool::PoolError> {
		self.chain()
			.validate_tx(tx)
			.map_err(|e| pool::PoolError::Other(format!("failed to validate tx, {}", e)))
	}

	fn validate_inputs(&self, inputs: &Inputs) -> Result<Vec<OutputIdentifier>, pool::PoolError> {
		self.chain()
			.validate_inputs(inputs)
			.map(|outputs| outputs.into_iter().map(|(out, _)| out).collect::<Vec<_>>())
			.map_err(|_| pool::PoolError::Other("failed to validate tx".to_string()))
	}

	fn verify_coinbase_maturity(&self, inputs: &Inputs) -> Result<(), pool::PoolError> {
		self.chain()
			.verify_coinbase_maturity(inputs)
			.map_err(|_| pool::PoolError::ImmatureCoinbase)
	}

	fn verify_tx_lock_height(&self, tx: &Transaction) -> Result<(), pool::PoolError> {
		self.chain()
			.verify_tx_lock_height(tx)
			.map_err(|_| pool::PoolError::ImmatureTransaction)
	}

	fn replay_attack_check(&self, tx: &Transaction) -> Result<(), pool::PoolError> {
		self.chain().replay_attack_check(tx).map_err(|e| {
			pool::PoolError::DuplicateKernelOrDuplicateSpent(format!(
				"Replay attack detected, {}",
				e
			))
		})
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use std::thread;
	use std::time::Duration;

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
