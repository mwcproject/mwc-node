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

use crate::mwc::sync::sync_peers::SyncPeers;
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::Chain;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::Block;
use mwc_core::ser::{self, ProtocolVersion};
use mwc_crates::log::{info, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::rand::prelude::*;
use mwc_crates::rand::rng;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_p2p::{Peer, PeerAddr, Peers};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_UNKNOWN_BLOCK_CANDIDATES_PER_HASH: usize = 4;
const MAX_UNKNOWN_BLOCK_SOURCE_PEERS: usize = 16;
const MAX_ORPHAN_RETRY_REQUESTS_PER_PEER: usize = 1;

struct UnknownBlock {
	block: Block,
	// BLAKE2b over the canonical full-block serialization. The header hash
	// alone is not a safe identity until the body is validated against the
	// header roots.
	serialized_hash: Hash,
	added: Instant,
	source_peers: HashSet<String>,
}

struct OrphanRetryBudget {
	total_remaining: usize,
	attempted_by_peer: HashMap<PeerAddr, usize>,
}

impl OrphanRetryBudget {
	fn new(total_remaining: usize) -> OrphanRetryBudget {
		OrphanRetryBudget {
			total_remaining,
			attempted_by_peer: HashMap::new(),
		}
	}

	fn has_remaining(&self) -> bool {
		self.total_remaining > 0
	}

	fn can_send_to(&self, peer: &PeerAddr) -> bool {
		self.has_remaining()
			&& self.attempted_by_peer.get(peer).copied().unwrap_or(0)
				< MAX_ORPHAN_RETRY_REQUESTS_PER_PEER
	}

	fn record_attempt(&mut self, peer: PeerAddr) {
		if self.total_remaining == 0 {
			return;
		}
		self.total_remaining -= 1;
		*self.attempted_by_peer.entry(peer).or_insert(0) += 1;
	}
}

// We might have orphans that we can't process because there are no prev headers exist. That is why we are putting them aside
// Until header data will arrive
pub struct OrphansSync {
	chain: Arc<Chain>,
	orphans_requests: RwLock<HashMap<Hash, u32>>, // Lock 2
	pibd_params: Arc<PibdParams>,
	// Some blocks that we can't process yet. Likely there are no headers. We don't want to trigger whole sync,
	// instead let's request child blocks routinely. That should handle bad network problem with a brute force
	unknown_blocks: RwLock<HashMap<Hash, Vec<UnknownBlock>>>, // Lock 1
}

impl OrphansSync {
	pub fn new(chain: Arc<Chain>) -> OrphansSync {
		OrphansSync {
			pibd_params: chain.get_pibd_params().clone(),
			chain,
			orphans_requests: RwLock::new(HashMap::new()),
			unknown_blocks: RwLock::new(HashMap::new()),
		}
	}

	/// Process and keep a new block if it was rejected by the chain. Return true if prev block is needed
	pub fn recieve_block_reporting(
		&self,
		block: Block,
		source_peer: Option<String>,
	) -> Result<bool, mwc_chain::Error> {
		let context_id = self.chain.get_context_id();
		let bhash = block.hash(context_id)?;

		let keep_unknown_block = !self.is_above_orphan_height_window(block.header.height)?;
		let need_prev_block = if keep_unknown_block {
			self.need_prev_block_in_height_window(&block.header.prev_hash)?
		} else {
			false
		};
		if self.chain.block_exists(&bhash)? {
			return Ok(false);
		}

		if !keep_unknown_block {
			return Ok(false);
		}

		let mut unknown_blocks = self.unknown_blocks.write();
		let unknown_blocks_count: usize = unknown_blocks
			.values()
			.map(|candidates| candidates.len())
			.sum();
		if let Some(candidates) = unknown_blocks.get_mut(&bhash) {
			let serialized_hash = Self::serialized_block_hash(context_id, &block)?;
			// A block hash is only the header hash. Until a full block is
			// validated against the header roots, only byte-identical arrivals are
			// duplicates. Byte-distinct arrivals are kept as bounded alternatives
			// so a malicious first body cannot pin this cache for the header hash.
			if let Some(unknown_block) = candidates
				.iter_mut()
				.find(|candidate| candidate.serialized_hash == serialized_hash)
			{
				if let Some(source_peer) = source_peer {
					Self::insert_source_peer_capped(&mut unknown_block.source_peers, source_peer);
				}
				return Ok(need_prev_block);
			}

			if candidates.len() >= MAX_UNKNOWN_BLOCK_CANDIDATES_PER_HASH
				|| unknown_blocks_count >= self.unknown_blocks_limit()
			{
				// We still need to request prev block, even cache wasn't updated with orphan
				// Idea is requesting prev blocks until we reach the head
				return Ok(need_prev_block);
			}

			candidates.push(UnknownBlock {
				block,
				serialized_hash,
				added: Instant::now(),
				source_peers: source_peer.into_iter().collect(),
			});
			return Ok(need_prev_block);
		}

		if unknown_blocks_count >= self.unknown_blocks_limit() {
			// We still need to request prev block, even cache wasn't updated with orphan
			// Idea is requesting prev blocks until we reach the head
			return Ok(need_prev_block);
		}

		let serialized_hash = Self::serialized_block_hash(context_id, &block)?;
		unknown_blocks.insert(
			bhash,
			vec![UnknownBlock {
				block,
				serialized_hash,
				added: Instant::now(),
				source_peers: source_peer.into_iter().collect(),
			}],
		);
		Ok(need_prev_block)
	}

	// Expected that it is called ONLY when state_sync is done
	pub fn sync_orphans(
		&self,
		peers: &Arc<Peers>,
		sync_peers: &SyncPeers,
	) -> Result<(), mwc_chain::Error> {
		// check if we need something to request from the peers.
		let context_id = self.chain.get_context_id();
		let orphans_pool = self.chain.get_orphans_pool();
		let mut block_to_validate = orphans_pool.get_orphan_list();
		let mut secp = Secp256k1::with_caps(ContextFlag::Commit).map_err(mwc_chain::Error::from)?;

		// Use a local mutable context for orphan replay so nested commitment
		// serialization can still use the thread-local secp cache.
		// let's clean up the unknown_blocks first
		{
			let mut unknown_blocks = self.unknown_blocks.write();

			// Try candidates only once the previous full block is available.
			// Otherwise Chain::process_block can move one unvalidated candidate
			// into the regular orphan pool before body validation, recreating
			// first-writer poisoning there.
			let mut blocks: Vec<(Hash, Hash, Block, HashSet<String>)> = unknown_blocks
				.iter()
				.flat_map(|(hash, candidates)| {
					candidates.iter().map(move |unknown| {
						(
							hash.clone(),
							unknown.serialized_hash,
							unknown.block.clone(),
							unknown.source_peers.clone(),
						)
					})
				})
				.collect();
			blocks.sort_by_key(|(_, _, b, _)| b.header.height);
			let mut bad_candidates = Vec::new();
			for (hash, serialized_hash, b, source_peers) in blocks {
				if self.chain.block_exists(&hash)? {
					continue;
				}
				if !self.chain.block_exists(&b.header.prev_hash)? {
					continue;
				}
				match self
					.chain
					.process_block(&mut secp, b, mwc_chain::Options::NONE, source_peers)
				{
					Ok(_) => {}
					Err(mwc_chain::Error::Orphan(_)) => {}
					Err(e) if e.is_bad_data() => bad_candidates.push((hash, serialized_hash)),
					Err(e) => return Err(e),
				}
			}
			for (hash, serialized_hash) in bad_candidates {
				if let Some(candidates) = unknown_blocks.get_mut(&hash) {
					candidates.retain(|unknown| unknown.serialized_hash != serialized_hash);
				}
			}

			let mut remove_hashes = Vec::new();
			for (hash, candidates) in unknown_blocks.iter_mut() {
				if self.chain.block_exists(hash)? {
					remove_hashes.push(hash.clone());
					continue;
				}
				// 10 minutes should be enough to do something with the unknown blocks. It is not expected that the block chains will be formed
				candidates.retain(|unknown| unknown.added.elapsed() < Duration::from_secs(600));
				if candidates.is_empty() {
					remove_hashes.push(hash.clone());
				}
			}
			for hash in remove_hashes {
				unknown_blocks.remove(&hash);
			}

			if unknown_blocks
				.values()
				.map(|candidates| candidates.len())
				.sum::<usize>()
				> self.unknown_blocks_limit()
			{
				unknown_blocks.clear();
			}

			for hash in unknown_blocks.keys() {
				block_to_validate.insert(*hash);
			}
		}

		// let's go though the list of orphans and see what we can do. It is expecte that the sync_orphans
		// called once in a while, so there is nothing in transition state is expected

		// creating list of orphans children that we are missing
		let mut needed_prev_blocks = HashSet::new();
		let mut retry_budget = OrphanRetryBudget::new(self.orphan_retry_request_limit(peers));
		for orph_hash in &block_to_validate {
			let block_hash_height = match orphans_pool.get_orphan(orph_hash) {
				Some(orphan) => {
					let prev_block_hash = orphan.block.header.prev_hash.clone();
					let bl_height = orphan.block.header.height;
					if self.chain.block_exists(&prev_block_hash)? {
						// it is a stale oprphan, we can process it...
						let bl_hash = orphan.block.hash(context_id)?;
						let bl_height = orphan.block.header.height;
						match self.chain.process_block(
							&mut secp,
							orphan.block,
							orphan.opts,
							orphan.source_peers,
						) {
							Ok(_) => {
								let _ = self.chain.remove_orphan(bl_height, &bl_hash);
								info!("Processed stuck block {} at {}", bl_hash, bl_height)
							}
							Err(mwc_chain::Error::Orphan(_)) => {}
							Err(e) if e.is_bad_data() || Self::is_known_block_error(&e) => {
								let _ = self.chain.remove_orphan(bl_height, &bl_hash);
								info!(
									"Dropped terminal stuck block {} at {}. Error: {}",
									bl_hash, bl_height, e
								)
							}
							Err(e) => return Err(e),
						}
					}
					Some((prev_block_hash.clone(), bl_height))
				}
				None => self
					.unknown_blocks
					.read_recursive()
					.get(orph_hash)
					.and_then(|candidates| candidates.first())
					.map(|unknown| {
						(
							unknown.block.header.prev_hash.clone(),
							unknown.block.header.height.clone(),
						)
					}),
			};

			if let Some((prev_block_hash, bl_height)) = block_hash_height {
				if self.need_prev_block(&prev_block_hash, bl_height)? {
					needed_prev_blocks.insert(prev_block_hash.clone());
					if !retry_budget.has_remaining() {
						continue;
					}

					let retry_counter = self
						.orphans_requests
						.read_recursive()
						.get(&prev_block_hash)
						.unwrap_or(&0)
						.saturating_add(1);
					if self.send_hash_requests(
						peers,
						sync_peers,
						&mut retry_budget,
						&prev_block_hash,
						bl_height,
						retry_counter,
					) {
						self.orphans_requests
							.write()
							.insert(prev_block_hash.clone(), retry_counter);
					}
				}
			}
		}

		{
			let mut orphans_requests = self.orphans_requests.write();
			orphans_requests.retain(|hash, _| needed_prev_blocks.contains(hash));
		}

		Ok(())
	}

	fn send_hash_requests(
		&self,
		peers: &Arc<Peers>,
		sync_peers: &SyncPeers,
		retry_budget: &mut OrphanRetryBudget,
		block_hash: &Hash,
		block_height: u64,
		retry_counter: u32,
	) -> bool {
		if !retry_budget.has_remaining() {
			return false;
		}

		// skipping some opportunities if we wasn't be able to get any responses for a while
		if retry_counter > 10 {
			if retry_counter % 2 != 0 {
				return true;
			}
		}

		let peers: Vec<Arc<Peer>> = peers
			.iter()
			.connected()
			.with_min_height(block_height)
			.into_iter()
			.filter(|p| retry_budget.can_send_to(&p.info.addr))
			.collect();
		if peers.is_empty() {
			return false;
		}

		let request_count = (retry_counter as usize)
			.min(MAX_ORPHAN_RETRY_REQUESTS_PER_PEER)
			.min(retry_budget.total_remaining);
		let peers = peers.sample(&mut rng(), request_count);
		let mut request_was_sent = false;
		for p in peers {
			let peer_addr = p.info.addr.clone();
			if !retry_budget.can_send_to(&peer_addr) {
				continue;
			}
			retry_budget.record_attempt(peer_addr.clone());
			match p.send_block_request(block_hash.clone(), mwc_chain::Options::NONE) {
				Ok(_) => {
					info!(
						"Sent retry block request for block {} at {} to peer {}",
						block_hash, block_height, p.info.addr
					);
					request_was_sent = true;
				}
				Err(e) => {
					let msg = format!(
						"Failed to send orphan retry block request to peer {}, block {} at {}: {}",
						peer_addr, block_hash, block_height, e
					);
					warn!("{}", msg);
					sync_peers.report_no_response(&peer_addr, msg);
				}
			}
		}

		request_was_sent
	}

	fn need_prev_block(
		&self,
		prev_block_hash: &Hash,
		height: u64,
	) -> Result<bool, mwc_chain::Error> {
		if self.is_above_orphan_height_window(height)? {
			return Ok(false);
		}

		self.need_prev_block_in_height_window(prev_block_hash)
	}

	fn need_prev_block_in_height_window(
		&self,
		prev_block_hash: &Hash,
	) -> Result<bool, mwc_chain::Error> {
		if self
			.unknown_blocks
			.read_recursive()
			.contains_key(prev_block_hash)
		{
			return Ok(false);
		}

		if self.chain.is_orphan(&prev_block_hash) {
			return Ok(false);
		}

		if self.chain.block_exists(&prev_block_hash)? {
			return Ok(false);
		}

		Ok(true)
	}

	fn is_above_orphan_height_window(&self, height: u64) -> Result<bool, mwc_chain::Error> {
		let tip = self.chain.head()?;
		Ok(height.saturating_sub(tip.height) >= self.pibd_params.get_orphans_num_limit() as u64)
	}

	fn orphan_retry_request_limit(&self, peers: &Arc<Peers>) -> usize {
		let connected_peers = peers.iter().connected().into_iter().count();
		self.pibd_params
			.get_blocks_request_limit(None)
			.min(connected_peers.saturating_mul(MAX_ORPHAN_RETRY_REQUESTS_PER_PEER))
	}

	fn unknown_blocks_limit(&self) -> usize {
		self.pibd_params.get_orphans_num_limit()
	}

	fn insert_source_peer_capped(source_peers: &mut HashSet<String>, source_peer: String) {
		if source_peers.len() < MAX_UNKNOWN_BLOCK_SOURCE_PEERS
			|| source_peers.contains(&source_peer)
		{
			source_peers.insert(source_peer);
		}
	}

	fn serialized_block_hash(context_id: u32, block: &Block) -> Result<Hash, mwc_chain::Error> {
		let block_bytes = ser::ser_vec(context_id, block, ProtocolVersion::local())?;
		Ok(block_bytes.hash(context_id)?)
	}

	fn is_known_block_error(error: &mwc_chain::Error) -> bool {
		matches!(
			error,
			mwc_chain::Error::Unfit(msg)
				if msg == "already known in head"
					|| msg == "already known in store"
					|| msg == "duplicate block"
		)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn insert_source_peer_capped_limits_unknown_block_metadata() {
		let mut source_peers = HashSet::new();

		for idx in 0..(MAX_UNKNOWN_BLOCK_SOURCE_PEERS + 4) {
			OrphansSync::insert_source_peer_capped(&mut source_peers, format!("peer-{}", idx));
		}

		assert_eq!(source_peers.len(), MAX_UNKNOWN_BLOCK_SOURCE_PEERS);

		let retained_peer = source_peers.iter().next().unwrap().clone();
		OrphansSync::insert_source_peer_capped(&mut source_peers, retained_peer);
		assert_eq!(source_peers.len(), MAX_UNKNOWN_BLOCK_SOURCE_PEERS);

		OrphansSync::insert_source_peer_capped(&mut source_peers, "overflow-peer".to_string());
		assert_eq!(source_peers.len(), MAX_UNKNOWN_BLOCK_SOURCE_PEERS);
		assert!(!source_peers.contains("overflow-peer"));
	}
}
