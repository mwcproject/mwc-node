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
use mwc_crates::log::debug;
use mwc_crates::parking_lot::RwLock;
use mwc_p2p::{PeerAddr, Peers};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

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
	const MAX_QUEUED_BLOCK_REQUESTS: usize = 1000;
	const MAX_REQUEST_PER_PEER: u32 = 3;

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
		let mut headers = self.headers.write();
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
		let mut blocks = self.blocks.write();

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

		let mut queued_requests = blocks
			.values()
			.map(|requests| requests.len())
			.sum::<usize>();
		while queued_requests > Self::MAX_QUEUED_BLOCK_REQUESTS {
			let evict_height = match blocks.keys().next_back().cloned() {
				Some(height) => height,
				None => break,
			};

			if let Some(evicted) = blocks.remove(&evict_height) {
				debug!(
					"Evicted {} block requests for height {}, block request queue is full",
					evicted.len(),
					evict_height
				);
				queued_requests = queued_requests.saturating_sub(evicted.len());
			} else {
				break;
			}
		}
	}

	pub fn process_request(&self, peers: &Arc<Peers>) -> Result<(), mwc_chain::Error> {
		let mut requests_per_peer: HashMap<PeerAddr, u32> = HashMap::new();

		// process requests for heights and for blocks.
		let head_header = self.chain.head_header()?.height;
		{
			// Requesting single heads chain
			let mut headers = self.headers.write();
			loop {
				// Requesting single series of headers
				match headers.pop_front() {
					Some(head_req) => {
						let known_header: bool = match head_req.head_header_hash {
							Some(hash) => match self.chain.get_block_header(&hash) {
								Ok(_) => true,
								Err(e) if e.is_not_found() => false,
								Err(e) => {
									headers.push_back(head_req);
									return Err(e);
								}
							},
							None => {
								if head_req.height <= head_header {
									match self.chain.get_header_by_height(head_req.height) {
										Ok(_) => true,
										Err(e) if e.is_not_found() => false,
										Err(e) => {
											headers.push_back(head_req);
											return Err(e);
										}
									}
								} else {
									false
								}
							}
						};
						if !known_header {
							if let Some(peer) = peers.get_connected_peer(&head_req.addr) {
								debug!("process_request, requesting headers from {}, target height: {}", head_req.addr, head_req.height);
								// processign single headers request at a time
								match peer.send_header_request(head_req.locator.clone()) {
									Ok(_) => {
										*requests_per_peer.entry(head_req.addr).or_insert(0) += 1;
										break;
									}
									Err(e) => {
										let msg = format!(
												"Failed to send header request to {}, target height {}: {}",
												head_req.addr, head_req.height, e
											);
										headers.push_back(head_req);
										return Err(mwc_chain::Error::Other(msg));
									}
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
			let mut blocks = self.blocks.write();
			for (_height, requests) in &mut *blocks {
				let mut skipped_requests = Vec::new();
				while !requests.is_empty() {
					let block_req = requests.pop_front().ok_or(mwc_chain::Error::Other(
						"Internal error, blocks are empty".into(),
					))?;
					let block_exists = match self.chain.block_exists(&block_req.block_hash) {
						Ok(block_exists) => block_exists,
						Err(e) => {
							requests.push_back(block_req);
							for r in skipped_requests {
								requests.push_back(r);
							}
							return Err(e);
						}
					};
					if !block_exists {
						if let Some(peer) = peers.get_connected_peer(&block_req.addr) {
							debug!("process_request, requesting block from {}, target height: {} , hash: {}",
                                        block_req.addr, block_req.height, block_req.block_hash);

							let cnt = requests_per_peer.entry(block_req.addr.clone()).or_insert(0);
							if *cnt < Self::MAX_REQUEST_PER_PEER {
								match peer.send_block_request(block_req.block_hash, block_req.opts)
								{
									Ok(_) => {
										*cnt += 1;
										break;
									}
									Err(e) => {
										let msg = format!(
													"Failed to send block request to {}, target height {}, hash {}: {}",
													block_req.addr, block_req.height, block_req.block_hash, e
												);
										requests.push_back(block_req);
										for r in skipped_requests {
											requests.push_back(r);
										}
										return Err(mwc_chain::Error::Other(msg));
									}
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

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_chain::types::NoopAdapter;
	use mwc_core::{genesis, global, pow};
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use std::collections::HashSet;
	use std::fs;

	#[test]
	fn block_request_queue_evicts_highest_height_bucket_when_full() {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(false);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let nanos = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let dir = std::env::temp_dir().join(format!(
			"mwc_block_request_queue_{}_{}",
			std::process::id(),
			nanos
		));
		let dir_str = dir.to_string_lossy().to_string();
		let _ = fs::remove_dir_all(&dir_str);

		let chain = Arc::new(
			Chain::init(
				&secp,
				0,
				dir_str.clone(),
				Arc::new(NoopAdapter {}),
				genesis::genesis_floo(&secp, 0),
				pow::verify_size,
				false,
				HashSet::new(),
				None,
				None,
			)
			.unwrap(),
		);
		let requests = HeadersBlocksRequests::new(chain);
		let addr = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());

		for height in 0..(HeadersBlocksRequests::MAX_QUEUED_BLOCK_REQUESTS as u64 - 1) {
			requests.add_block_request(
				&addr,
				height,
				Hash::from_vec(&height.to_be_bytes()),
				mwc_chain::Options::NONE,
			);
		}

		let evicted_height = HeadersBlocksRequests::MAX_QUEUED_BLOCK_REQUESTS as u64;
		requests.add_block_request(
			&addr,
			evicted_height,
			Hash::from_vec(&evicted_height.to_be_bytes()),
			mwc_chain::Options::NONE,
		);
		requests.add_block_request(
			&PeerAddr::Ip("127.0.0.1:3415".parse().unwrap()),
			evicted_height,
			Hash::from_vec(&(evicted_height + 1).to_be_bytes()),
			mwc_chain::Options::NONE,
		);

		let blocks = requests.blocks.read_recursive();
		let queued_count = blocks
			.values()
			.map(|requests| requests.len())
			.sum::<usize>();
		assert_eq!(
			queued_count,
			HeadersBlocksRequests::MAX_QUEUED_BLOCK_REQUESTS - 1
		);
		assert!(!blocks.contains_key(&evicted_height));

		drop(blocks);
		let _ = fs::remove_dir_all(&dir_str);
	}
}
