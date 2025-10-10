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

use mwc_chain::Chain;
use mwc_core::core::hash::Hash;
use mwc_p2p::{PeerAddr, Peers};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::RwLock;

#[derive(Clone, Debug)]
pub struct HeadersRequest {
	pub addr: PeerAddr,
	pub head_header_hash: Option<Hash>,
	pub height: u64,
	pub locator: Vec<Hash>,
}

pub struct BlockRequest {
	pub addr: PeerAddr,
	pub height: u64,
	pub block_hash: Hash,
	pub opts: mwc_chain::Options,
}

/// Because of node active role, we might end up request too many data from the peers.
/// As a result node can be flooded with too much data. It is not optimal, we want to
/// do tracking requsts for the headers and tracking for the blocks.
pub struct HeadersBlocksRequests {
	chain: Arc<Chain>,
	headers: RwLock<VecDeque<HeadersRequest>>,
	blocks: RwLock<BTreeMap<u64, VecDeque<BlockRequest>>>,
}

impl HeadersBlocksRequests {
	pub fn new(chain: Arc<Chain>) -> Self {
		HeadersBlocksRequests {
			chain,
			headers: RwLock::new(VecDeque::new()),
			blocks: RwLock::new(BTreeMap::new()),
		}
	}

	pub fn add_header_request(
		&self,
		addr: &PeerAddr,
		head_header_hash: Option<Hash>,
		height: u64,
		locator: Vec<Hash>,
	) {
		let mut headers = self.headers.write().expect("RwLock failure");
		for req in &*headers {
			if req.addr == *addr {
				debug!("Ignored header request to {}, already in the Q", addr);
				return; // request already exist, dedup it
			}
		}
		debug!("Added header request to {}, for height {}", addr, height);
		headers.push_back(HeadersRequest {
			addr: addr.clone(),
			head_header_hash,
			height,
			locator,
		});
	}

	pub fn add_block_request(
		&self,
		addr: &PeerAddr,
		height: u64,
		block_hash: Hash,
		opts: mwc_chain::Options,
	) {
		let mut blocks = self.blocks.write().expect("RwLock failure");

		match blocks.get_mut(&height) {
			Some(requests) => {
				for req in &*requests {
					if req.addr == *addr {
						debug!(
							"Ignored block {} request to {}, for height {}",
							block_hash, addr, height
						);
						return;
					}
				}
				debug!(
					"Added block {} request to {}, for height {}",
					block_hash, addr, height
				);
				requests.push_back(BlockRequest {
					addr: addr.clone(),
					height,
					block_hash,
					opts,
				});
			}
			None => {
				debug!(
					"Added block {} request to {}, for height {}",
					block_hash, addr, height
				);
				let mut req = VecDeque::new();
				req.push_back(BlockRequest {
					addr: addr.clone(),
					height,
					block_hash,
					opts,
				});
				blocks.insert(height, req);
			}
		}
	}

	const MAX_REQUEST_PER_PEER: u32 = 3;

	pub fn process_request(&self, peers: &Arc<Peers>) -> Result<(), mwc_chain::Error> {
		let mut requests_per_peer: HashMap<PeerAddr, u32> = HashMap::new();

		// process requests for heights and for blocks.
		let head_header = self.chain.head_header()?.height;
		{
			// Requesting single heads chain
			let mut headers = self.headers.write().expect("RwLock failure");
			loop {
				// Requesting single series of headers
				match headers.pop_front() {
					Some(head_req) => {
						let known_header: bool = head_req
							.head_header_hash
							.map(|hash| self.chain.get_block_header(&hash).is_ok())
							.unwrap_or(head_req.height <= head_header);
						if !known_header {
							if let Some(peer) = peers.get_connected_peer(&head_req.addr) {
								debug!("process_request, requesting headers from {}, target height: {}", head_req.addr, head_req.height);
								// processign single headers request at a time
								if peer.send_header_request(head_req.locator).is_ok() {
									*requests_per_peer.entry(head_req.addr).or_insert(0) += 1;
									break;
								}
							}
						}
						continue;
					}
					None => break,
				}
			}
		}

		// Requesting all blocks once. I don't see how we can request just few and be not attacked.
		// My point that if we prefer any block vs others, it will be possible to organizes attack
		// to stale the node progress.
		{
			let mut blocks = self.blocks.write().expect("RwLock failure");
			for (_height, requests) in &mut *blocks {
				let mut skipped_requests = Vec::new();
				while !requests.is_empty() {
					let block_req = requests.pop_front().unwrap();
					if !self.chain.block_exists(&block_req.block_hash)? {
						if let Some(peer) = peers.get_connected_peer(&block_req.addr) {
							debug!("process_request, requesting block from {}, target height: {} , hash: {}",
                                        block_req.addr, block_req.height, block_req.block_hash);

							let cnt = requests_per_peer.entry(block_req.addr.clone()).or_insert(0);
							if *cnt < Self::MAX_REQUEST_PER_PEER {
								if peer
									.send_block_request(block_req.block_hash, block_req.opts)
									.is_ok()
								{
									*cnt += 1;
									break;
								}
							} else {
								skipped_requests.push(block_req);
							}
						}
					}
				}
				for r in skipped_requests {
					requests.push_back(r);
				}
			}
			blocks.retain(|_h, val| !val.is_empty());
		}

		Ok(())
	}
}
