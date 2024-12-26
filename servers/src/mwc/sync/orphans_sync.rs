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

use crate::core::core::hash::{Hash, Hashed};
use chrono::{DateTime, Utc};
use mwc_chain::pibd_params::PibdParams;
use mwc_chain::Chain;
use mwc_core::core::Block;
use mwc_p2p::{Peer, Peers};
use mwc_util::RwLock;
use rand::prelude::*;
use rand::thread_rng;
use std::collections::HashMap;
use std::sync::Arc;

// We might have orphans that we can't process because there are no prev headers exist. That is why we are putting them aside
// Until header data will arrive
pub struct OrphansSync {
	chain: Arc<Chain>,
	orphans_requests: RwLock<HashMap<Hash, u32>>, // Lock 2
	pibd_params: Arc<PibdParams>,
	// Some blocks that we can't process yet. Likely there are no headers. We don't want to trigger whole sync,
	// instead let's request child blocks routinely. That should handle bad network problem with a brute force
	unknown_blocks: RwLock<HashMap<Hash, (Block, DateTime<Utc>)>>, // Lock 1
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
	pub fn recieve_block_reporting(&self, block: Block) -> bool {
		let bhash = block.hash();
		let need_prev_block = self.need_prev_block(&block.header.prev_hash, block.header.height);
		if self.unknown_blocks.read().contains_key(&bhash) {
			return need_prev_block;
		}

		if self.chain.is_orphan(&bhash) {
			return need_prev_block;
		}

		if self.chain.block_exists(&bhash).unwrap_or(false) {
			return false;
		}

		self.unknown_blocks
			.write()
			.insert(bhash, (block, Utc::now()));
		need_prev_block
	}

	// Expected that it is called ONLY when state_sync is done
	pub fn sync_orphans(&self, peers: &Arc<Peers>) -> Result<(), mwc_chain::Error> {
		// check if we need something to request from the peers.
		let orphans_pool = self.chain.get_orphans_pool();
		let mut block_to_validate = orphans_pool.get_orphan_list();

		// let's clean up the unknown_blocks first
		{
			let now = Utc::now();
			let mut unknown_blocks = self.unknown_blocks.write();

			// let's try apply blocks int the chain, we migth already has some data for that, let's apply from low height to the higher
			let mut blocks: Vec<&Block> = Vec::new();
			for (b, _) in unknown_blocks.values() {
				blocks.push(b);
			}
			blocks.sort_by_key(|b| b.header.height);
			for b in blocks {
				let _ = self
					.chain
					.process_block(b.clone(), mwc_chain::Options::NONE);
			}

			unknown_blocks.retain(|hash, (_block, time)| {
				if self.chain.is_orphan(hash) || self.chain.block_exists(hash).unwrap_or(false) {
					return false;
				}
				// 10 minutes should be enough to do something with the unknown blocks. It is not expecte dthat the lock chains will be formed
				(now - *time).num_seconds() < 600
			});

			if unknown_blocks.len() > self.pibd_params.get_orphans_num_limit() / 2 {
				unknown_blocks.clear();
			}

			for (b, _) in unknown_blocks.values() {
				block_to_validate.insert(b.hash());
			}
		}

		let unknown_blocks = self.unknown_blocks.read();
		{
			let mut orphans_requests = self.orphans_requests.write();
			orphans_requests.retain(|hash, _| block_to_validate.contains(hash));
		}

		// let's go though the list of orphans and see what we can do. It is expecte that the sync_orphans
		// called once in a while, so there is nothing in transition state is expected

		// creating list of orphans children that we are missing
		for orph_hash in &block_to_validate {
			let block_hash_height = match orphans_pool.get_orphan(orph_hash) {
				Some(orphan) => {
					let prev_block_hash = orphan.block.header.prev_hash.clone();
					let bl_height = orphan.block.header.height;
					if self.chain.block_exists(&prev_block_hash)? {
						// it is a stale oprphan, we can process it...
						let bl_hash = orphan.block.hash();
						let bl_height = orphan.block.header.height;
						match self.chain.process_block(orphan.block, orphan.opts) {
							Ok(_) => info!("Processed stuck block {} at {}", bl_hash, bl_height),
							Err(e) => info!(
								"Unable to process stuck block {} at {}. Error: {}",
								bl_hash, bl_height, e
							),
						}
					}
					Some((prev_block_hash.clone(), bl_height))
				}
				None => match unknown_blocks.get(orph_hash) {
					Some((b, _time)) => Some((b.header.prev_hash.clone(), b.header.height.clone())),
					None => None,
				},
			};

			if let Some((prev_block_hash, bl_height)) = block_hash_height {
				if self.need_prev_block(&prev_block_hash, bl_height) {
					// We need to request the child for that block
					let mut orphans_requests = self.orphans_requests.write();
					if self.send_hash_requests(
						peers,
						&prev_block_hash,
						bl_height,
						orphans_requests.get(&prev_block_hash).unwrap_or(&0) + 1,
					) {
						match orphans_requests.get_mut(&prev_block_hash) {
							Some(counter) => {
								*counter += 1;
							}
							None => {
								orphans_requests.insert(prev_block_hash.clone(), 0);
							}
						}
					}
				}
			}
		}

		Ok(())
	}

	fn send_hash_requests(
		&self,
		peers: &Arc<Peers>,
		block_hash: &Hash,
		block_height: u64,
		retry_counter: u32,
	) -> bool {
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
			.collect();
		if peers.is_empty() {
			return false;
		}

		let peers = peers.choose_multiple(&mut thread_rng(), retry_counter as usize);
		let mut resuqest_was_sent = false;
		for p in peers {
			if p.send_block_request(block_hash.clone(), mwc_chain::Options::NONE)
				.is_ok()
			{
				info!(
					"Sent retry block request for block {} at {} to peer {}",
					block_hash, block_height, p.info.addr
				);
				resuqest_was_sent = true;
			} else {
				info!(
					"Failed to send block {} at {} request to the peer {}",
					block_hash, block_height, p.info.addr
				);
			}
		}

		resuqest_was_sent
	}

	fn need_prev_block(&self, prev_block_hash: &Hash, height: u64) -> bool {
		match self.chain.head() {
			Ok(tip) => {
				if height.saturating_sub(tip.height)
					>= self.pibd_params.get_orphans_num_limit() as u64
				{
					return false;
				}
			}
			Err(_) => return false,
		}

		if self.unknown_blocks.read().contains_key(prev_block_hash) {
			return false;
		}

		if self.chain.is_orphan(&prev_block_hash) {
			return false;
		}

		if self.chain.block_exists(&prev_block_hash).unwrap_or(false) {
			return false;
		}

		true
	}
}
