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

const MAX_UNKNOWN_BLOCK_PEERS_PER_HASH: usize = 4;
const MAX_ORPHAN_RETRY_REQUESTS_PER_PEER: usize = 1;

struct UnknownBlock {
	block: Block,
	added: Instant,
	// PeerAddr equality and hashing intentionally ignore the port for non-loopback
	// IP peers. Using PeerAddr here prevents one IP from consuming multiple
	// candidate slots by reconnecting with different advertised ports.
	source_peers: HashSet<PeerAddr>,
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
		source_peer: Option<PeerAddr>,
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
		// A block already owned by the regular orphan pool must not also consume
		// space in the unknown-header cache or be replayed from both caches.
		if self.chain.is_orphan(&bhash) {
			return Ok(need_prev_block);
		}

		if !keep_unknown_block {
			return Ok(false);
		}

		let mut unknown_blocks = self.unknown_blocks.write();
		let unknown_blocks_count: usize = unknown_blocks
			.values()
			.map(|candidates| Self::unknown_block_slots(candidates))
			.sum();
		let unknown_blocks_limit = self.unknown_blocks_limit();
		if let Some(candidates) = unknown_blocks.get_mut(&bhash) {
			// A block hash is only the header hash. Until a full block is
			// validated against the header roots, only losslessly identical arrivals
			// are duplicates. Protocol-v3+ full-block serialization is not suitable
			// for this comparison because it discards input features and the input
			// representation. Distinct arrivals are kept as bounded alternatives so
			// a malicious first body cannot pin this cache for the header hash or
			// inherit an honest candidate's source peer.
			// Each peer owns at most one candidate slot for this header hash. If it
			// sends a different body, move its attribution to the new body. Identical
			// bodies remain coalesced so multiple peers can attest to one candidate
			// without duplicating the block in memory.
			Self::cache_candidate(
				context_id,
				candidates,
				block,
				source_peer,
				unknown_blocks_count,
				unknown_blocks_limit,
			)?;
			return Ok(need_prev_block);
		}

		if unknown_blocks_count >= unknown_blocks_limit {
			// We still need to request prev block, even cache wasn't updated with orphan
			// Idea is requesting prev blocks until we reach the head
			return Ok(need_prev_block);
		}

		unknown_blocks.insert(
			bhash,
			vec![UnknownBlock {
				block,
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
			// The write lock held for this whole block keeps candidate indexes stable
			// until bad candidates are removed below.
			let mut blocks: Vec<(Hash, usize, Block, HashSet<String>)> = unknown_blocks
				.iter()
				.flat_map(|(hash, candidates)| {
					candidates
						.iter()
						.enumerate()
						.map(move |(candidate_index, unknown)| {
							(
								hash.clone(),
								candidate_index,
								unknown.block.clone(),
								unknown
									.source_peers
									.iter()
									.map(|peer| peer.to_string())
									.collect(),
							)
						})
				})
				.collect();
			blocks.sort_by_key(|(_, _, b, _)| b.header.height);
			let mut bad_candidates: HashMap<Hash, HashSet<usize>> = HashMap::new();
			for (hash, candidate_index, b, source_peers) in blocks {
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
					// Another peer can commit the same block after block_exists()
					// above but before process_block() acquires the chain locks.
					// The requested result is already present, so continue the pass.
					Err(e) if e.is_known_block() => {}
					Err(e) if e.is_bad_data() => {
						bad_candidates
							.entry(hash)
							.or_default()
							.insert(candidate_index);
					}
					Err(e) => return Err(e),
				}
			}
			for (hash, bad_candidate_indexes) in bad_candidates {
				if let Some(candidates) = unknown_blocks.get_mut(&hash) {
					let mut candidate_index = 0;
					candidates.retain(|_| {
						let keep = !bad_candidate_indexes.contains(&candidate_index);
						candidate_index += 1;
						keep
					});
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
				.map(|candidates| Self::unknown_block_slots(candidates))
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
					let bl_height = orphan.block.header.height;
					// A concurrently accepted block can leave an older body for the same
					// header hash in the orphan pool. Do not replay that stale body: an
					// input-only conflict with the stored block is intentionally neither a
					// known-block nor bad-data error, so replaying it would otherwise keep
					// returning the same terminal error without evicting the orphan.
					if self.chain.block_exists(orph_hash)? {
						let _ = self.chain.remove_orphan(bl_height, orph_hash);
						info!(
							"Dropped stale orphan {} at {} because the block is already stored",
							orph_hash, bl_height
						);
						continue;
					}

					let prev_block_hash = orphan.block.header.prev_hash.clone();
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
							Err(e) if e.is_bad_data() || e.is_known_block() => {
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

	// A body without peer attribution still consumes one slot. Normally every
	// network arrival is attributed, but keeping Option<PeerAddr> support makes the
	// cache safe for internal callers as well.
	fn unknown_block_slots(candidates: &[UnknownBlock]) -> usize {
		candidates
			.iter()
			.map(|candidate| candidate.source_peers.len().max(1))
			.sum()
	}

	fn cache_candidate(
		context_id: u32,
		candidates: &mut Vec<UnknownBlock>,
		block: Block,
		source_peer: Option<PeerAddr>,
		total_slots: usize,
		total_limit: usize,
	) -> Result<(), mwc_chain::Error> {
		// Finish all fallible comparisons before mutating the cache so a
		// serialization/hash error leaves the previous candidate intact.
		let mut matching_candidate = Self::find_lossless_candidate(context_id, candidates, &block)?;
		let previous_candidate = source_peer.as_ref().and_then(|source_peer| {
			candidates
				.iter()
				.position(|candidate| candidate.source_peers.contains(source_peer))
		});

		// An exact repeat from the same peer neither consumes another slot nor
		// refreshes the candidate's expiry time.
		if matching_candidate.is_some() && matching_candidate == previous_candidate {
			return Ok(());
		}

		let replacing_peer = previous_candidate.is_some();
		let mut available_total_slots = total_slots;
		if let (Some(previous_candidate), Some(source_peer)) =
			(previous_candidate, source_peer.as_ref())
		{
			let removed = candidates[previous_candidate]
				.source_peers
				.remove(source_peer);
			debug_assert!(removed);
			available_total_slots = available_total_slots.checked_sub(1).ok_or_else(|| {
				mwc_chain::Error::DataOverflow(
					"OrphansSync::cache_candidate peer slot count underflow".to_owned(),
				)
			})?;

			if candidates[previous_candidate].source_peers.is_empty() {
				candidates.remove(previous_candidate);
				if let Some(matching_candidate) = matching_candidate.as_mut() {
					if *matching_candidate > previous_candidate {
						*matching_candidate -= 1;
					}
				}
			}
		}

		let hash_slots = Self::unknown_block_slots(candidates);
		if let Some(matching_candidate) = matching_candidate {
			if let Some(source_peer) = source_peer {
				// Adding the first peer to an anonymous candidate adopts its existing
				// slot. A replacement is also slot-neutral, so both remain possible
				// when the cache is otherwise full.
				let adopts_anonymous_slot = candidates[matching_candidate].source_peers.is_empty();
				if adopts_anonymous_slot
					|| replacing_peer
					|| (hash_slots < MAX_UNKNOWN_BLOCK_PEERS_PER_HASH
						&& available_total_slots < total_limit)
				{
					candidates[matching_candidate]
						.source_peers
						.insert(source_peer);
				}
			}
			return Ok(());
		}

		// At the global or per-hash limit, an alternative from a new peer is
		// deliberately dropped instead of evicting an existing candidate. A bad
		// first candidate cannot permanently pin the slot: once its previous full
		// block is available, sync_orphans() passes its attributed source peers to
		// Chain::process_block(). Bad-data reporting bans those peers, and this sync
		// pass removes the bad candidate, leaving room for a subsequent (or
		// re-requested) honest delivery. Sustained replacement from fresh peer
		// identities is a peer/Sybil-flood concern rather than a cache-admission
		// guarantee.
		if replacing_peer
			|| (hash_slots < MAX_UNKNOWN_BLOCK_PEERS_PER_HASH
				&& available_total_slots < total_limit)
		{
			candidates.push(UnknownBlock {
				block,
				added: Instant::now(),
				source_peers: source_peer.into_iter().collect(),
			});
		}

		Ok(())
	}

	fn blocks_equal_lossless(
		context_id: u32,
		left: &Block,
		right: &Block,
	) -> Result<bool, mwc_chain::Error> {
		if left.header != right.header
			|| !left
				.body
				.inputs
				.eq_by_hash(context_id, &right.body.inputs)?
		{
			return Ok(false);
		}

		let version = ProtocolVersion::local();
		Ok(ser::ser_vec(context_id, &left.body.outputs, version)?
			== ser::ser_vec(context_id, &right.body.outputs, version)?
			&& ser::ser_vec(context_id, &left.body.kernels, version)?
				== ser::ser_vec(context_id, &right.body.kernels, version)?)
	}

	fn find_lossless_candidate(
		context_id: u32,
		candidates: &[UnknownBlock],
		block: &Block,
	) -> Result<Option<usize>, mwc_chain::Error> {
		for (candidate_index, candidate) in candidates.iter().enumerate() {
			if Self::blocks_equal_lossless(context_id, &candidate.block, block)? {
				return Ok(Some(candidate_index));
			}
		}
		Ok(None)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::core::{CommitWrapper, Input, Inputs, OutputFeatures};
	use mwc_core::global::{self, ChainTypes};
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};

	fn candidate_block(context_id: u32, value: u64) -> Block {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(value).unwrap();
		let mut block = Block::default(context_id);
		block.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, commit)]);
		block
	}

	fn candidate_peer(ip_suffix: u8, port: u16) -> PeerAddr {
		PeerAddr::Ip(SocketAddr::new(
			IpAddr::V4(Ipv4Addr::new(8, 8, 8, ip_suffix)),
			port,
		))
	}

	fn cache_for_peer(
		context_id: u32,
		candidates: &mut Vec<UnknownBlock>,
		block: Block,
		peer: PeerAddr,
	) {
		let total_slots = OrphansSync::unknown_block_slots(candidates);
		OrphansSync::cache_candidate(
			context_id,
			candidates,
			block,
			Some(peer),
			total_slots,
			usize::MAX,
		)
		.unwrap();
	}

	#[test]
	fn same_peer_replaces_its_previous_candidate() {
		let context_id = 0;
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let mut candidates = Vec::new();
		let peer_a = candidate_peer(1, 3414);

		for value in 1..=6 {
			cache_for_peer(
				context_id,
				&mut candidates,
				candidate_block(context_id, value),
				peer_a.clone(),
			);
		}

		assert_eq!(candidates.len(), 1);
		assert_eq!(OrphansSync::unknown_block_slots(&candidates), 1);
		assert_eq!(
			candidates[0].source_peers,
			std::iter::once(peer_a).collect()
		);
		assert!(OrphansSync::blocks_equal_lossless(
			context_id,
			&candidates[0].block,
			&candidate_block(context_id, 6),
		)
		.unwrap());
	}

	#[test]
	fn peer_moves_between_coalesced_candidates() {
		let context_id = 0;
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let first = candidate_block(context_id, 1);
		let second = candidate_block(context_id, 2);
		let mut candidates = Vec::new();
		let peer_a = candidate_peer(1, 3414);
		let peer_b = candidate_peer(2, 3414);

		cache_for_peer(context_id, &mut candidates, first.clone(), peer_a.clone());
		cache_for_peer(context_id, &mut candidates, first.clone(), peer_b.clone());
		assert_eq!(candidates.len(), 1);
		assert_eq!(OrphansSync::unknown_block_slots(&candidates), 2);

		cache_for_peer(context_id, &mut candidates, second.clone(), peer_a.clone());
		assert_eq!(candidates.len(), 2);
		assert_eq!(OrphansSync::unknown_block_slots(&candidates), 2);

		let first_index = OrphansSync::find_lossless_candidate(context_id, &candidates, &first)
			.unwrap()
			.unwrap();
		let second_index = OrphansSync::find_lossless_candidate(context_id, &candidates, &second)
			.unwrap()
			.unwrap();
		assert_eq!(
			candidates[first_index].source_peers,
			std::iter::once(peer_b).collect()
		);
		assert_eq!(
			candidates[second_index].source_peers,
			std::iter::once(peer_a).collect()
		);
	}

	#[test]
	fn same_ip_with_different_ports_owns_only_one_candidate_slot() {
		let context_id = 0;
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let first = candidate_block(context_id, 1);
		let replacement = candidate_block(context_id, 2);
		let mut candidates = Vec::new();

		cache_for_peer(context_id, &mut candidates, first, candidate_peer(1, 3414));
		cache_for_peer(
			context_id,
			&mut candidates,
			replacement.clone(),
			candidate_peer(1, 4414),
		);

		assert_eq!(candidates.len(), 1);
		assert_eq!(OrphansSync::unknown_block_slots(&candidates), 1);
		assert!(
			OrphansSync::blocks_equal_lossless(context_id, &candidates[0].block, &replacement,)
				.unwrap()
		);
	}

	#[test]
	fn four_peer_cache_rejects_a_fifth_peer_but_allows_replacement() {
		let context_id = 0;
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let mut candidates = Vec::new();

		for peer_index in 0..MAX_UNKNOWN_BLOCK_PEERS_PER_HASH {
			cache_for_peer(
				context_id,
				&mut candidates,
				candidate_block(context_id, peer_index as u64 + 1),
				candidate_peer(peer_index as u8 + 1, 3414),
			);
		}
		assert_eq!(OrphansSync::unknown_block_slots(&candidates), 4);

		let replacement = candidate_block(context_id, 10);
		cache_for_peer(
			context_id,
			&mut candidates,
			replacement.clone(),
			candidate_peer(5, 3414),
		);
		assert_eq!(OrphansSync::unknown_block_slots(&candidates), 4);
		assert_eq!(
			OrphansSync::find_lossless_candidate(context_id, &candidates, &replacement).unwrap(),
			None
		);

		let peer_zero = candidate_peer(1, 3414);
		cache_for_peer(
			context_id,
			&mut candidates,
			replacement.clone(),
			peer_zero.clone(),
		);
		assert_eq!(OrphansSync::unknown_block_slots(&candidates), 4);
		let replacement_index =
			OrphansSync::find_lossless_candidate(context_id, &candidates, &replacement)
				.unwrap()
				.unwrap();
		assert!(candidates[replacement_index]
			.source_peers
			.contains(&peer_zero));
	}

	#[test]
	fn lossless_unknown_block_identity_preserves_input_features_and_representation() {
		let context_id = 0;
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(1).unwrap();

		let mut plain = Block::default(context_id);
		plain.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Plain, commit)]);

		let mut coinbase = plain.clone();
		coinbase.body.inputs =
			Inputs::FeaturesAndCommit(vec![Input::new(OutputFeatures::Coinbase, commit)]);

		// The old local-protocol fingerprint cannot distinguish these bodies.
		assert_eq!(
			ser::ser_vec(context_id, &plain, ProtocolVersion::local()).unwrap(),
			ser::ser_vec(context_id, &coinbase, ProtocolVersion::local()).unwrap()
		);
		assert!(!OrphansSync::blocks_equal_lossless(context_id, &plain, &coinbase).unwrap());
		let candidates = vec![UnknownBlock {
			block: plain.clone(),
			added: Instant::now(),
			source_peers: std::iter::once(candidate_peer(1, 3414)).collect(),
		}];
		assert_eq!(
			OrphansSync::find_lossless_candidate(context_id, &candidates, &coinbase).unwrap(),
			None
		);

		let mut commit_only = plain.clone();
		commit_only.body.inputs = Inputs::CommitOnly(vec![CommitWrapper::from(commit)]);
		assert_eq!(
			ser::ser_vec(context_id, &plain, ProtocolVersion::local()).unwrap(),
			ser::ser_vec(context_id, &commit_only, ProtocolVersion::local()).unwrap()
		);
		assert!(!OrphansSync::blocks_equal_lossless(context_id, &plain, &commit_only).unwrap());
		assert_eq!(
			OrphansSync::find_lossless_candidate(context_id, &candidates, &commit_only).unwrap(),
			None
		);
		assert_eq!(
			OrphansSync::find_lossless_candidate(context_id, &candidates, &plain).unwrap(),
			Some(0)
		);
		assert!(OrphansSync::blocks_equal_lossless(context_id, &plain, &plain).unwrap());
	}
}
