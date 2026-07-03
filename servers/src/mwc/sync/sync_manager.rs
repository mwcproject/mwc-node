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

// sync_utils contain banch of shared between mutiple sync modules routines
// Normally we would put that into the base class, but rust doesn't support that.

use crate::mwc::sync::block_headers_request_cache::HeadersBlocksRequests;
use crate::mwc::sync::body_sync::BodySync;
use crate::mwc::sync::header_hashes_sync::{HeadersHashResponseStatus, HeadersHashSync};
use crate::mwc::sync::header_sync::HeaderSync;
use crate::mwc::sync::orphans_sync::OrphansSync;
use crate::mwc::sync::state_sync::StateSync;
use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils::{self, CachedResponse, SyncRequestResponses, SyncResponse};
use mwc_chain::txhashset::BitmapChunk;
use mwc_chain::{Chain, Error, SyncState};
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::{Block, OutputIdentifier, Segment, TxKernel};
use mwc_crates::log::{debug, error, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::rand;
use mwc_crates::rand::RngExt;
use mwc_crates::secp::pedersen::RangeProof;
use mwc_p2p::{Capabilities, PeerAddr, Peers};
use mwc_util::StopState;
use std::sync::Arc;
use std::time::Duration;

const MIN_SYNC_TARGET_RESPONSES: usize = 2;

/// Sync Manager is reponsible for coordination of all syncing process
pub struct SyncManager {
	headers_hashes: RwLock<HeadersHashSync>,
	headers: HeaderSync,
	state: StateSync,
	body: BodySync,
	orphans: OrphansSync,
	headers_block_requests: HeadersBlocksRequests,

	// Headers has complications with banning. In case of bad hashes, we will found that much later
	// when we ban many peers. That is why we need to track that separately and unban it in such case.
	headers_sync_peers: SyncPeers,
	// state & body sync
	state_sync_peers: SyncPeers,
	sync_state: Arc<SyncState>,
	stop_state: Arc<StopState>,

	cached_response: RwLock<Option<CachedResponse<SyncResponse>>>,
}

impl SyncManager {
	pub fn new(chain: Arc<Chain>, sync_state: Arc<SyncState>, stop_state: Arc<StopState>) -> Self {
		SyncManager {
			headers_hashes: RwLock::new(HeadersHashSync::new(chain.clone())),
			headers: HeaderSync::new(chain.clone()),
			state: StateSync::new(chain.clone()),
			body: BodySync::new(chain.clone()),
			orphans: OrphansSync::new(chain.clone()),
			headers_block_requests: HeadersBlocksRequests::new(chain),

			headers_sync_peers: SyncPeers::new(),
			state_sync_peers: SyncPeers::new(),
			sync_state,
			stop_state,
			cached_response: RwLock::new(None),
		}
	}

	// Routine method to process headers and blocks.
	// This queue is best-effort: request processing can fail on local chain
	// reads, hash calculation, block-existence checks, or peer send failures.
	// Keep the sync loop online by logging the error and continuing; repeated
	// failures are observable in logs but intentionally do not stop sync.
	pub fn headers_blocks_request(&self, peers: &Arc<Peers>) {
		match self.headers_block_requests.process_request(peers) {
			Ok(_) => {}
			Err(e) => error!("Failed to process headers blocks request, {}", e),
		}
	}

	pub fn add_header_request(
		&self,
		addr: &PeerAddr,
		head_header_hash: Option<Hash>,
		height: u64,
		locator: Vec<Hash>,
	) {
		self.headers_block_requests
			.add_header_request(addr, head_header_hash, height, locator);
	}

	pub fn add_block_request(
		&self,
		addr: &PeerAddr,
		height: u64,
		block_hash: Hash,
		opts: mwc_chain::Options,
	) {
		self.headers_block_requests
			.add_block_request(addr, height, block_hash, opts);
	}

	pub fn sync_request(&self, peers: &Arc<Peers>) -> Result<SyncResponse, Error> {
		let cached_response = self.cached_response.read_recursive().clone();
		if let Some(cached_response) = cached_response {
			if !cached_response.is_expired() {
				return Ok(cached_response.to_response());
			} else {
				*self.cached_response.write() = None;
			}
		}

		// Apply peers status (ban if needed)
		let mut offline1 = self.headers_sync_peers.apply_peers_status(peers);
		let mut offline2 = self.state_sync_peers.apply_peers_status(peers);

		offline1.append(&mut offline2);
		let mut rng = rand::rng();
		offline1.retain(|_| rng.random_range(0..10) != 7); // We want to exclude some, because peer might become online
		peers.set_excluded_peers(&offline1);

		let context_id = peers.get_context_id();
		let sync_target_votes: Vec<(u64, u64)> = peers
			.iter()
			.outbound()
			.connected()
			.with_capabilities(Capabilities::HEADERS_HASH)
			.into_iter()
			.filter_map(|peer| {
				let height = peer.info.height();
				if height > 0 {
					Some((Chain::height_2_archive_height(context_id, height), height))
				} else {
					None
				}
			})
			.collect();
		let required_responses = sync_target_votes.len() / 2 + 1;
		let best_height = match sync_utils::select_quorum(
			sync_target_votes.into_iter(),
			required_responses,
			MIN_SYNC_TARGET_RESPONSES,
			|(archive_height, _)| *archive_height,
		) {
			sync_utils::QuorumSelection::Selected {
				value: archive_height,
				items,
			} => {
				let height = items
					.iter()
					.map(|(_, height)| *height)
					.max()
					.unwrap_or(archive_height);
				debug!(
					"Selected sync target height {}, archive height {}",
					height, archive_height
				);
				height
			}
			sync_utils::QuorumSelection::NeedMoreResponses { responses } => {
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Capabilities::HEADERS_HASH,
					format!(
						"Need more HEADERS_HASH peers to select sync target. Has peers: {}",
						responses
					),
				));
			}
			sync_utils::QuorumSelection::NoQuorum {
				responses,
				best_count,
			} => {
				return Ok(SyncResponse::new(
					SyncRequestResponses::WaitingForPeers,
					Capabilities::HEADERS_HASH,
					format!(
						"No quorum for sync target archive height. Has peers: {}, best target peers: {}",
						responses, best_count
					),
				));
			}
		};

		let r = self
			.headers_hashes
			.read_recursive()
			.request_pre(best_height)?;
		let headers_hash_resp = match r {
			Some(resp) => resp,
			None => self.headers_hashes.write().request_impl(
				peers,
				&self.sync_state,
				&self.headers_sync_peers,
				best_height,
			)?,
		};

		debug!("headers_hash_resp: {:?}", headers_hash_resp);
		match headers_hash_resp.response {
			SyncRequestResponses::WaitingForPeers => return Ok(headers_hash_resp),
			SyncRequestResponses::Syncing => return Ok(headers_hash_resp),
			SyncRequestResponses::HeadersPibdReady | SyncRequestResponses::HeadersHashReady => {}
			_ => {
				debug_assert!(false);
			}
		}

		let mut headers_ready = false;

		let headers_hashes_snapshot = self
			.headers_hashes
			.read_recursive()
			.snapshot_for_best_height(best_height);

		let headers_resp = self.headers.request(
			peers,
			&self.sync_state,
			&self.headers_sync_peers,
			&headers_hashes_snapshot,
			best_height,
		)?;
		debug!("headers_resp: {:?}", headers_resp);
		match headers_resp.response {
			SyncRequestResponses::WaitingForPeers => {
				self.headers_hashes
					.write()
					.reset_ban_commited_to_hash(peers, &self.headers_sync_peers);
				self.headers_sync_peers.reset();
				return Ok(headers_resp);
			}
			SyncRequestResponses::Syncing => return Ok(headers_resp),
			SyncRequestResponses::HasMoreHeadersToApply => return Ok(headers_resp),
			SyncRequestResponses::WaitingForHeadersHash => {
				debug_assert!(false); // should never happen, headers_hashes above must be in sync or wait for peers
				return Ok(headers_resp);
			}
			SyncRequestResponses::HeadersPibdReady => self.headers_hashes.write().reset_hash_data(),
			SyncRequestResponses::HeadersReady => headers_ready = true,
			_ => {
				debug_assert!(false);
			}
		}

		let state_resp = self.state.request(
			peers,
			self.sync_state.clone(),
			&self.state_sync_peers,
			self.stop_state.clone(),
			best_height,
		)?;
		debug!("state_resp: {:?}", state_resp);
		match state_resp.response {
			SyncRequestResponses::Syncing => return Ok(state_resp),
			SyncRequestResponses::WaitingForPeers => return Ok(state_resp),
			SyncRequestResponses::WaitingForHeaders => return Ok(state_resp),
			SyncRequestResponses::StatePibdReady => {}
			_ => {
				debug_assert!(false);
			}
		}

		match self
			.body
			.request(peers, &self.sync_state, &self.state_sync_peers, best_height)
		{
			Ok(body_resp) => {
				debug!("body_resp: {:?}", body_resp);
				match body_resp.response {
					SyncRequestResponses::Syncing => return Ok(body_resp),
					SyncRequestResponses::BodyReady => {
						if headers_ready {
							let resp = SyncResponse::new(
								SyncRequestResponses::SyncDone,
								Capabilities::UNKNOWN,
								"DONE!".into(),
							);
							peers.set_excluded_peers(&vec![]);
							*self.cached_response.write() =
								Some(CachedResponse::new(resp.clone(), Duration::from_secs(35))?);

							// sync_orphans can fail for multiple local chain/orphan
							// processing reasons, including attack-triggered invalid
							// orphan data. Log the error but do not fail the sync
							// request; body/header sync is done and this path still
							// reports Ok(SyncDone).
							if let Err(e) = self.orphans.sync_orphans(peers, &self.state_sync_peers)
							{
								error!("Failed to sync_orphans. Error: {}", e);
							}

							return Ok(resp);
						} else {
							return Ok(SyncResponse::new(
								SyncRequestResponses::Syncing,
								self.body.get_peer_capabilities(),
								"Waiting for headers, even body is done, more is expected".into(),
							));
						}
					}
					SyncRequestResponses::WaitingForPeers => return Ok(body_resp),
					SyncRequestResponses::BadState => {
						self.state.reset_desegmenter_data();
						return Ok(body_resp);
					}
					_ => debug_assert!(false),
				}
			}
			Err(e) => {
				error!("Body request is failed, {}", e);
				return Err(e);
			}
		}

		debug_assert!(false);
		Ok(SyncResponse::new(
			SyncRequestResponses::Syncing,
			Capabilities::UNKNOWN,
			"Invalid state, internal error".into(),
		))
	}

	pub fn receive_headers_hash_response(
		&self,
		peer: &PeerAddr,
		archive_height: u64,
		headers_hash_root: Hash,
	) -> Result<(), Error> {
		match self.headers_hashes.write().receive_headers_hash_response(
			peer,
			archive_height,
			headers_hash_root,
			&self.headers_sync_peers,
		) {
			HeadersHashResponseStatus::Accepted | HeadersHashResponseStatus::Ignored => Ok(()),
			HeadersHashResponseStatus::Rejected(msg) => Err(Error::Other(msg)),
		}
	}

	pub fn receive_header_hashes_segment(
		&self,
		peer: &PeerAddr,
		header_hashes_root: Hash,
		segment: Segment<Hash>,
	) -> Result<(), Error> {
		self.headers_hashes.write().receive_header_hashes_segment(
			peer,
			header_hashes_root,
			segment,
			&self.headers_sync_peers,
		)
	}

	pub fn receive_headers(
		&self,
		peer: &PeerAddr,
		bhs: &[mwc_core::core::BlockHeader],
		remaining: u64,
		peers: Arc<Peers>,
	) -> Result<(), Error> {
		// Note, because of high throughput, it must be unblocking read, blocking write is not OK
		let headers_hash_desegmenter = self
			.headers_hashes
			.read_recursive()
			.get_headers_hash_desegmenter();
		self.headers
			.receive_headers(
				peer,
				bhs,
				remaining,
				&self.headers_sync_peers,
				headers_hash_desegmenter,
				&peers,
			)
			.map_err(|e| {
				error!("receive_headers failed with error: {}", e);
				e
			})
	}

	pub fn recieve_pibd_status(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
		output_bitmap_root: Hash,
	) {
		self.state
			.recieve_pibd_status(peer, header_hash, header_height, output_bitmap_root);
	}

	pub fn recieve_another_archive_header(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
	) {
		self.headers_hashes.write().recieve_another_archive_header(
			peer,
			&header_hash,
			header_height,
		);
		self.state
			.recieve_another_archive_header(peer, &header_hash, header_height);
	}

	pub fn receive_bitmap_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: &Hash,
		segment: Segment<BitmapChunk>,
		peers: &Arc<Peers>,
	) -> Result<(), Error> {
		self.state.receive_bitmap_segment(
			peer,
			archive_header_hash,
			segment,
			peers,
			&self.state_sync_peers,
		)
	}

	pub fn receive_output_segment(
		&self,
		peer: &PeerAddr,
		bitmap_root_hash: &Hash,
		segment: Segment<OutputIdentifier>,
		peers: &Arc<Peers>,
	) -> Result<(), Error> {
		self.state.receive_output_segment(
			peer,
			bitmap_root_hash,
			segment,
			peers,
			&self.state_sync_peers,
		)
	}

	pub fn receive_rangeproof_segment(
		&self,
		peer: &PeerAddr,
		bitmap_root_hash: &Hash,
		segment: Segment<RangeProof>,
		peers: &Arc<Peers>,
	) -> Result<(), Error> {
		self.state.receive_rangeproof_segment(
			peer,
			bitmap_root_hash,
			segment,
			peers,
			&self.state_sync_peers,
		)
	}

	pub fn receive_kernel_segment(
		&self,
		peer: &PeerAddr,
		bitmap_root_hash: &Hash,
		segment: Segment<TxKernel>,
		peers: &Arc<Peers>,
	) -> Result<(), Error> {
		self.state.receive_kernel_segment(
			peer,
			bitmap_root_hash,
			segment,
			peers,
			&self.state_sync_peers,
		)
	}

	// return true if need to request prev block
	pub fn recieve_block_reporting(
		&self,
		valid_block: Option<bool>, // Some accepted/rejected, None means pending validation.
		peer: &PeerAddr,
		b: Block,
		opts: mwc_chain::Options,
		peers: &Arc<Peers>,
	) -> Result<bool, mwc_chain::Error> {
		let bhash = b.hash(b.header.pow.proof.context_id)?;

		// BodySync reporting is post-processing bookkeeping for request scheduling
		// and peer-response accounting. Block processing has already accepted or
		// rejected the block, so reporting failures are logged without changing the
		// block result.
		if let Err(e) = self.body.recieve_block_reporting(
			valid_block,
			&bhash,
			peer,
			peers,
			&self.state_sync_peers,
		) {
			warn!("Body sync block reporting failed: {}", e);
		}

		if valid_block != Some(false) && opts == mwc_chain::Options::NONE {
			let source_peer = valid_block.is_none().then(|| peer.to_string());
			self.orphans.recieve_block_reporting(b, source_peer)
		} else {
			Ok(false)
		}
	}
}
