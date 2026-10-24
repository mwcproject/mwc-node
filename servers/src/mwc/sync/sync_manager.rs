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

use crate::mwc::sync::body_sync::BodySync;
use crate::mwc::sync::header_pibd_hashes_sync::{
	HeadersPibdHashResponseStatus, HeadersPibdHashSync,
};
use crate::mwc::sync::header_pibd_sync::HeaderPibdSync;
use crate::mwc::sync::header_sync::HeaderSync;
use crate::mwc::sync::state_sync::StateSync;
use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils::{self, SyncRequestResponses, SyncResponse};
use mwc_chain::txhashset::BitmapChunk;
use mwc_chain::{Chain, Error, SyncState, SyncStatus};
use mwc_core::core::hash::Hash;
use mwc_core::core::{Block, BlockHeader, OutputIdentifier, Segment, TxKernel};
use mwc_crates::log::{debug, info, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp::pedersen::RangeProof;
use mwc_crates::secp::Secp256k1;
use mwc_p2p::{Capabilities, PeerAddr, PeerInfo, Peers};
use mwc_util::StopState;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

const MIN_SYNC_TARGET_RESPONSES: usize = 2;
const MAX_PIBD_BLOCK_FAILURES: usize = 3;

/// Sync Manager is reponsible for coordination of all syncing process
pub struct SyncManager {
	chain: Arc<Chain>,
	// Distinct failed suppliers for the retained PIBD import. Cleared on reset/completion.
	pibd_failed_peers: RwLock<HashSet<PeerAddr>>,
	headers_hashes: RwLock<HeadersPibdHashSync>,
	pibd_headers: HeaderPibdSync,
	state: StateSync,
	body: BodySync,
	tip_headers: HeaderSync,

	// Headers has complications with banning. In case of bad hashes, we will found that much later
	// when we ban many peers. That is why we need to track that separately and unban it in such case.
	headers_sync_peers: SyncPeers,
	// state & body sync
	state_sync_peers: SyncPeers,
	sync_state: Arc<SyncState>,
	stop_state: Arc<StopState>,

	state_ready: AtomicBool,
	best_height: AtomicU64,
}

impl SyncManager {
	pub fn new(chain: Arc<Chain>, sync_state: Arc<SyncState>, stop_state: Arc<StopState>) -> Self {
		SyncManager {
			chain: chain.clone(),
			pibd_failed_peers: RwLock::new(HashSet::new()),
			headers_hashes: RwLock::new(HeadersPibdHashSync::new(chain.clone())),
			pibd_headers: HeaderPibdSync::new(chain.clone()),
			state: StateSync::new(chain.clone()),
			body: BodySync::new(chain.clone()),
			tip_headers: HeaderSync::new(chain.clone()),

			headers_sync_peers: SyncPeers::new(),
			state_sync_peers: SyncPeers::new(),
			state_ready: AtomicBool::new(!sync_state.is_syncing()),
			sync_state,
			stop_state,
			best_height: AtomicU64::new(0),
		}
	}

	#[cfg(all(test, feature = "test-support"))]
	pub(crate) fn has_block_request(&self, peer: &PeerAddr, hash: &Hash) -> bool {
		self.body.has_block_request(peer, hash)
	}

	#[cfg(all(test, feature = "test-support"))]
	pub(crate) fn header_download_for_test(
		&self,
		peer: &PeerAddr,
	) -> Option<(u64, mwc_core::pow::Difficulty)> {
		self.tip_headers.download_for_test(peer)
	}

	#[cfg(all(test, feature = "test-support"))]
	pub(crate) fn apply_header_scores_for_test(&self, peers: &Arc<Peers>) {
		self.headers_sync_peers.apply_peers_status(peers);
	}

	pub fn sync_request(&self, peers: &Arc<Peers>) -> Result<SyncResponse, Error> {
		self.clear_inactive_pibd_failures();
		self.tip_headers
			.check_header_requests(&self.headers_sync_peers, Instant::now());
		self.headers_sync_peers.apply_peers_status(peers);
		self.state_sync_peers.apply_peers_status(peers);
		if self.sync_state.is_txhashset_validation() {
			return Ok(SyncResponse::new(
				SyncRequestResponses::Syncing,
				Capabilities::PIBD_HIST,
				"Verifying state snapshot".into(),
			));
		}
		if self.state_ready.load(Ordering::Acquire) {
			let header_height = self.chain.header_head()?.height;
			// Keep the selected archive period while validating the first body
			// after an import. Afterwards follow the current canonical tip.
			let height = if self.state.imported_state().is_some() {
				self.best_height.load(Ordering::Relaxed).max(header_height)
			} else {
				header_height
			};
			return self.request_chain(peers, height);
		}
		let context_id = peers.get_context_id();
		let sync_target_votes: Vec<(u64, u64)> = peers
			.iter()
			.outbound()
			.connected()
			.with_capabilities(Capabilities::HEADERS_HASH)
			.into_iter()
			.filter_map(|peer| {
				let (height, _) = peer.info.get_height_and_difficulty();
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

		self.best_height.store(best_height, Ordering::Relaxed);
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

		let snapshot = self
			.headers_hashes
			.read_recursive()
			.snapshot_for_best_height(best_height);
		let headers = self.pibd_headers.request(
			peers,
			&self.sync_state,
			&self.headers_sync_peers,
			&snapshot,
			best_height,
		)?;
		match headers.response {
			SyncRequestResponses::HeadersPibdReady | SyncRequestResponses::HeadersReady => {}
			SyncRequestResponses::WaitingForPeers => {
				self.headers_hashes
					.write()
					.reset_ban_commited_to_hash(peers, &self.headers_sync_peers);
				self.headers_sync_peers.reset();
				return Ok(headers);
			}
			_ => return Ok(headers),
		}
		self.request_chain(peers, best_height)
	}

	/// The snapshot gate is shared by regular header and body synchronization.
	fn request_chain(&self, peers: &Arc<Peers>, best_height: u64) -> Result<SyncResponse, Error> {
		self.best_height.store(best_height, Ordering::Relaxed);
		let state = self.state.request(
			peers,
			self.sync_state.clone(),
			&self.state_sync_peers,
			self.stop_state.clone(),
			best_height,
		)?;
		self.clear_inactive_pibd_failures();
		if state.response != SyncRequestResponses::StatePibdReady {
			self.state_ready.store(false, Ordering::Release);
			self.tip_headers.reset();
			self.body.reset();
			return Ok(state);
		}
		self.state_ready.store(true, Ordering::Release);
		let headers_ready = match self.tip_headers.request(peers, &self.headers_sync_peers) {
			Ok(ready) => ready,
			Err(error) => {
				info!("Header requests failed; will retry: {}", error);
				false
			}
		};
		let body = self
			.body
			.request(peers, &self.sync_state, &self.state_sync_peers)?;
		match body.response {
			// Keep Running while new advertised headers are downloaded in the background.
			SyncRequestResponses::BodyReady
				if headers_ready || self.sync_state.status() == SyncStatus::NoSync =>
			{
				Ok(SyncResponse::new(
					SyncRequestResponses::SyncDone,
					Capabilities::UNKNOWN,
					"DONE!".into(),
				))
			}
			SyncRequestResponses::BodyReady => Ok(SyncResponse::new(
				SyncRequestResponses::Syncing,
				Capabilities::UNKNOWN,
				"Downloading advertised headers".into(),
			)),
			_ => Ok(body),
		}
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
			HeadersPibdHashResponseStatus::Accepted | HeadersPibdHashResponseStatus::Ignored => {
				Ok(())
			}
			HeadersPibdHashResponseStatus::Rejected(msg) => Err(Error::Other(msg)),
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

	/// Regular header and body processing starts only after snapshot validation.
	pub fn state_is_ready(&self) -> bool {
		self.state_ready.load(Ordering::Acquire) && !self.sync_state.is_txhashset_validation()
	}

	/// An unsolicited extension also schedules its body from the announcing peer.
	pub fn receive_header(
		&self,
		header: &BlockHeader,
		peer: &PeerInfo,
		peers: &Arc<Peers>,
	) -> Result<(), Error> {
		if !self.state_is_ready() {
			return Ok(());
		}
		if self
			.tip_headers
			.receive_header(header, peer, &self.headers_sync_peers)?
		{
			if let Some(supplier) = peers.get_connected_peer(&peer.addr) {
				self.body
					.request_header_block(header, &supplier, &self.state_sync_peers)?;
			}
		}
		Ok(())
	}

	pub fn receive_headers(
		&self,
		peer: &PeerInfo,
		bhs: &[BlockHeader],
		remaining: u64,
		peers: Arc<Peers>,
	) -> Result<bool, Error> {
		if self.sync_state.is_txhashset_validation() {
			return Ok(false);
		}
		let regular = if self.state_is_ready() {
			self.tip_headers.receive_headers(
				&peer.addr,
				bhs,
				remaining,
				&self.headers_sync_peers,
				&peers,
			)
		} else {
			Ok(false)
		};
		let result = (|| match regular {
			Ok(true) => Ok(true),
			Ok(false) if !self.state_ready.load(Ordering::Acquire) => {
				let desegmenter = self
					.headers_hashes
					.read_recursive()
					.get_headers_hash_desegmenter();
				self.pibd_headers.receive_headers(
					&peer.addr,
					bhs,
					remaining,
					&self.headers_sync_peers,
					desegmenter,
					&peers,
				)
			}
			Ok(false) => {
				// No requested response owns these headers. Accept direct extensions
				// independently, without mixing pages or transferring another peer's goal.
				for header in bhs {
					self.receive_header(header, peer, &peers)?;
				}
				Ok(true)
			}
			other => other,
		})();
		result.map_err(|e| {
			info!("receive_headers from {} failed: {}", peer.addr, e);
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

	fn clear_inactive_pibd_failures(&self) {
		// Match report_block_result's lock order so an old session observation
		// cannot clear failures recorded for a newly completed import.
		let mut failed_peers = self.pibd_failed_peers.write();
		if self.state.imported_state().is_none() {
			failed_peers.clear();
		}
	}

	/// Account for accepted blocks or invalid bodies following a PIBD import.
	pub fn report_block_result(
		&self,
		block: &Block,
		peer: &PeerAddr,
		outcome: Option<Result<(), &Error>>,
	) -> Result<(), Error> {
		let mut failed_peers = self.pibd_failed_peers.write();
		let session = match self.state.imported_state() {
			Some(session) => session,
			None => {
				failed_peers.clear();
				return Ok(());
			}
		};
		let head = self.chain.head()?;
		let archive_height = session.desegmenter.header().height;
		if head.height > archive_height {
			// Accepted blocks end this session's
			// accounting before any later failure can count against its voters.
			self.state.complete_pibd_sync();
			failed_peers.clear();
			return Ok(());
		}
		let error = match outcome {
			Some(Err(error))
				if error.is_bad_data()
					&& !error.is_known_block()
					&& !error.requires_chain_recovery() =>
			{
				error
			}
			_ => return Ok(()),
		};
		if head.last_block_h != session.archive_hash
			|| block.header.prev_hash != session.archive_hash
			|| Some(block.header.height) != archive_height.checked_add(1)
			|| self.chain.get_header_by_height(block.header.height)? != block.header
		{
			return Ok(());
		}
		if failed_peers.len() < MAX_PIBD_BLOCK_FAILURES && failed_peers.insert(peer.clone()) {
			warn!(
				"First block after PIBD failed validation from {} ({}/{}): {}",
				peer,
				failed_peers.len(),
				MAX_PIBD_BLOCK_FAILURES,
				error
			);
			if failed_peers.len() == MAX_PIBD_BLOCK_FAILURES {
				// Accepted false-ban risk: malicious body suppliers can frame
				// honest root endorsers. Queue this recovery action immediately;
				// ordinary sender bans may prevent a later sync-target quorum.
				self.state
					.ban_this_session(&session.root_hash, &self.state_sync_peers);
			}
		}
		Ok(())
	}

	/// Route full and reconstructed bodies through the same bounded task queue.
	/// Reconstructed bodies contain local guesses and must not implicate their peer.
	pub fn receive_block(
		&self,
		secp: &mut Secp256k1,
		block: &Block,
		peer: &PeerInfo,
		reconstructed: bool,
	) -> Result<bool, Error> {
		if !self.state_is_ready() {
			return Ok(true);
		}
		let accepted =
			self.body
				.receive_block(secp, block, peer, reconstructed, &self.state_sync_peers)?;
		// Application can drain several buffered blocks. The current head,
		// rather than receipt alone, determines whether PIBD has succeeded.
		self.report_block_result(block, &peer.addr, None)?;
		Ok(accepted)
	}
}

#[cfg(all(test, feature = "test-support"))]
mod pibd_successor_flow {
	use super::*;
	use mwc_chain::types::NoopAdapter;
	use mwc_core::core::hash::Hashed;
	use mwc_core::core::TransactionBody;
	use mwc_core::libtx::reward;
	use mwc_core::libtx::ProofBuilder;
	use mwc_core::pow::Difficulty;
	use mwc_core::{consensus, global, pow};
	use mwc_crates::chrono;
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_crates::tempfile::TempDir;
	use mwc_keychain::{ExtKeychain, Keychain};
	use mwc_p2p::{store::PeerStore, DummyAdapter, P2PConfig, Peers};
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};

	const ARCHIVE_HEIGHT: u64 = global::TESTING_TXHASHSET_ARCHIVE_INTERVAL;

	fn test_hash(value: u8) -> Hash {
		Hash::from_vec(&[value; 32])
	}

	struct Fixture {
		manager: SyncManager,
		chain: Arc<Chain>,
		block: Block,
		secp: Secp256k1,
		peers: Arc<Peers>,
		root: Hash,
		_chain_dir: TempDir,
		_peer_dir: TempDir,
	}

	fn peer(id: u8) -> PeerAddr {
		PeerAddr::Ip(SocketAddr::new(
			IpAddr::V4(Ipv4Addr::new(10, 1, 0, id)),
			3414,
		))
	}

	impl Fixture {
		fn new(context_id: u32) -> Self {
			global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
			global::set_local_nrd_enabled(false);
			global::init_global_chain_type(context_id, global::ChainTypes::AutomatedTesting)
				.unwrap();
			global::init_global_nrd_enabled(context_id, false).unwrap();
			let mut secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
			let chain_dir = TempDir::new().unwrap();
			let chain = Arc::new(
				Chain::init(
					&secp,
					context_id,
					chain_dir.path().to_str().unwrap().to_string(),
					Arc::new(NoopAdapter {}),
					global::get_genesis_block(&secp, context_id).unwrap(),
					pow::verify_size,
					false,
					HashSet::new(),
					None,
					None,
					false,
				)
				.unwrap(),
			);
			let keychain = ExtKeychain::from_seed(&secp, &[42; 32], false).unwrap();
			let builder = ProofBuilder::new(&secp, &keychain).unwrap();
			// Use the first real archive boundary. Mining through height 10
			// exercises activation at 4 before validating its successor at 11.
			let block = loop {
				let parent = chain.head_header().unwrap();
				let height = parent.height + 1;
				let key = ExtKeychain::derive_key_id(1, height as u32, 0, 0, 0).unwrap();
				let binding = chain
					.coinbase_binding_for_template(&secp, &parent, &TransactionBody::empty())
					.unwrap();
				let (output, kernel, opening) = reward::output_s2c(
					context_id,
					&keychain,
					&builder,
					&key,
					0,
					height,
					&mut secp,
					binding.digest().unwrap(),
				)
				.unwrap();
				let reward = (output, kernel);
				let next = consensus::next_difficulty(
					context_id,
					height,
					chain.difficulty_iter().unwrap(),
					&mut consensus::DifficultyCache::new(),
				)
				.unwrap();
				let mut block =
					Block::new(context_id, &parent, &[], next.difficulty, reward, &secp).unwrap();
				block.coinbase_opening =
					consensus::is_coinbase_binding_enabled(context_id, height).then_some(opening);
				block.header.timestamp = parent.timestamp + chrono::Duration::seconds(60);
				block.header.pow.secondary_scaling = next.secondary_scaling;
				chain.set_txhashset_roots(&secp, &mut block).unwrap();
				pow::pow_size(
					context_id,
					&mut block.header,
					next.difficulty,
					global::proofsize(context_id),
					global::min_edge_bits(context_id),
				)
				.unwrap();
				if height == ARCHIVE_HEIGHT + 1 {
					chain
						.process_block_header(&block.header, mwc_chain::Options::NONE)
						.unwrap();
					break block;
				}
				chain
					.process_block(&mut secp, block, mwc_chain::Options::NONE, HashSet::new())
					.unwrap();
			};

			let root = test_hash(31);
			let manager = SyncManager::new(
				chain.clone(),
				Arc::new(SyncState::new()),
				Arc::new(StopState::new()),
			);
			manager
				.state
				.set_imported_state_for_test(
					ARCHIVE_HEIGHT,
					root,
					(1..=5)
						.map(|id| (peer(id), if id == 5 { test_hash(32) } else { root }))
						.collect(),
				)
				.unwrap();
			let peer_dir = TempDir::new().unwrap();
			let peers = Arc::new(Peers::new(
				PeerStore::new(context_id, peer_dir.path().to_str().unwrap()).unwrap(),
				Arc::new(DummyAdapter {}),
				&P2PConfig::default(),
			));
			Self {
				manager,
				chain,
				block,
				secp,
				peers,
				root,
				_chain_dir: chain_dir,
				_peer_dir: peer_dir,
			}
		}

		fn deliver(&mut self, id: u8, valid: bool) {
			let source = peer(id);
			let mut block = self.block.clone();
			if !valid {
				// Retain the exact requested header, but supply an invalid body.
				block.body.outputs[0].proof.proof[0] ^= 1;
			}
			let result = self.chain.process_block(
				&mut self.secp,
				block.clone(),
				mwc_chain::Options::NONE,
				HashSet::from([source.to_string()]),
			);
			if valid {
				assert!(result.as_ref().unwrap().is_some());
			} else {
				assert!(result.as_ref().unwrap_err().is_bad_data());
			}
			self.manager
				.report_block_result(&block, &source, Some(result.as_ref().map(|_| ())))
				.unwrap();
		}

		fn failures(&self) -> usize {
			self.manager.pibd_failed_peers.read_recursive().len()
		}

		fn report_error(&self, block: Block, peer: PeerAddr, error: &Error) {
			self.manager
				.report_block_result(&block, &peer, Some(Err(error)))
				.unwrap();
		}

		fn poll(&self) -> SyncResponse {
			let response = self
				.manager
				.state
				.request(
					&self.peers,
					self.manager.sync_state.clone(),
					&self.manager.state_sync_peers,
					self.manager.stop_state.clone(),
					ARCHIVE_HEIGHT
						+ u64::from(global::state_sync_threshold(self.chain.get_context_id())),
				)
				.unwrap();
			self.manager.clear_inactive_pibd_failures();
			response
		}
	}

	fn connect_sync_supplier(
		fixture: &Fixture,
		id: u8,
		better: bool,
	) -> mwc_crates::crossbeam::channel::Receiver<mwc_p2p::msg::Msg> {
		let tip = fixture.chain.header_head().unwrap();
		let difficulty = if better {
			(tip.total_difficulty + Difficulty::from_num(100)).unwrap()
		} else {
			tip.total_difficulty
		};
		let info = mwc_p2p::PeerInfo {
			capabilities: Capabilities::HEADER_HIST | Capabilities::BLOCK_EXTRA,
			user_agent: "snapshot-gate-test".into(),
			version: mwc_core::ser::ProtocolVersion::local(),
			addr: peer(id),
			direction: mwc_p2p::types::Direction::Outbound,
			live_info: Arc::new(RwLock::new(mwc_p2p::types::PeerLiveInfo::new(difficulty))),
			tx_base_fee: 0,
		};
		info.update(tip.height + u64::from(better), difficulty);
		let (supplier, receiver) = mwc_p2p::Peer::connected_for_test(
			info,
			fixture.chain.get_context_id(),
			Arc::new(DummyAdapter {}),
		);
		fixture.peers.add_connected(Arc::new(supplier)).unwrap();
		receiver
	}

	#[test]
	fn regular_headers_and_bodies_wait_for_verified_snapshot() {
		let fixture = Fixture::new(961_109);
		let body_rx = connect_sync_supplier(&fixture, 1, false);
		let header_rx = connect_sync_supplier(&fixture, 2, true);
		// PIBD announcements do not create ordinary header tasks.
		assert!(fixture.manager.header_download_for_test(&peer(2)).is_none());
		assert_eq!(header_rx.try_iter().count(), 0);
		fixture.manager.sync_request(&fixture.peers).unwrap();
		assert_eq!(body_rx.try_iter().count(), 0);
		assert_eq!(header_rx.try_iter().count(), 0);

		// The original supplier can leave before the verified snapshot is ready.
		fixture.peers.remove_connected(&peer(2));
		let replacement_rx = connect_sync_supplier(&fixture, 3, true);
		// StateSync's imported-state fixture represents a verified snapshot.
		let best_height = ARCHIVE_HEIGHT
			+ u64::from(global::state_sync_threshold(fixture.chain.get_context_id()));
		fixture
			.manager
			.request_chain(&fixture.peers, best_height)
			.unwrap();
		assert_eq!(header_rx.try_iter().count(), 0);
		assert_eq!(replacement_rx.try_iter().count(), 1);
		assert!(fixture.manager.header_download_for_test(&peer(2)).is_none());
		assert_eq!(body_rx.try_iter().count(), 1);
		assert!(fixture.manager.has_block_request(
			&peer(1),
			&fixture.block.hash(fixture.chain.get_context_id()).unwrap()
		));
	}

	#[test]
	fn failed_header_send_does_not_stop_other_headers_or_body_sync() {
		let fixture = Fixture::new(961_114);
		let body_rx = connect_sync_supplier(&fixture, 1, false);
		let failed_rx = connect_sync_supplier(&fixture, 2, true);
		let header_rx = connect_sync_supplier(&fixture, 3, true);
		drop(failed_rx);
		let best_height = ARCHIVE_HEIGHT
			+ u64::from(global::state_sync_threshold(fixture.chain.get_context_id()));
		fixture
			.manager
			.request_chain(&fixture.peers, best_height)
			.unwrap();
		assert_eq!(header_rx.try_iter().count(), 1);
		assert_eq!(body_rx.try_iter().count(), 1);
		assert!(fixture.manager.header_download_for_test(&peer(2)).is_none());
		assert!(fixture.manager.header_download_for_test(&peer(3)).is_some());
		assert!(fixture.manager.has_block_request(
			&peer(1),
			&fixture.block.hash(fixture.chain.get_context_id()).unwrap()
		));
	}

	#[test]
	fn incomplete_snapshot_does_not_start_either_regular_downloader() {
		let fixture = Fixture::new(961_112);
		let body_rx = connect_sync_supplier(&fixture, 1, false);
		let header_rx = connect_sync_supplier(&fixture, 2, true);
		fixture.manager.state.reset_desegmenter_data();
		fixture.chain.reset_pibd_chain().unwrap();
		assert!(fixture.manager.header_download_for_test(&peer(2)).is_none());
		let best_height = ARCHIVE_HEIGHT
			+ u64::from(global::state_sync_threshold(fixture.chain.get_context_id()));
		let result = fixture
			.manager
			.request_chain(&fixture.peers, best_height)
			.unwrap();
		assert_ne!(result.response, SyncRequestResponses::SyncDone);
		assert!(!fixture.manager.state_ready.load(Ordering::Acquire));
		assert_eq!(body_rx.try_iter().count(), 0);
		assert_eq!(header_rx.try_iter().count(), 0);
	}

	#[test]
	fn regular_headers_and_bodies_start_only_after_validation() {
		let fixture = Fixture::new(961_113);
		let best_height = ARCHIVE_HEIGHT
			+ u64::from(global::state_sync_threshold(fixture.chain.get_context_id()));
		let header_rx = connect_sync_supplier(&fixture, 1, true);
		let body_rx = connect_sync_supplier(&fixture, 2, false);
		fixture
			.manager
			.sync_state
			.update(mwc_chain::SyncStatus::ValidatingKernelsHistory {
				headers: 0,
				headers_total: ARCHIVE_HEIGHT,
			});
		fixture.manager.sync_request(&fixture.peers).unwrap();
		assert!(!fixture.manager.state_ready.load(Ordering::Acquire));
		assert_eq!(header_rx.try_iter().count(), 0);
		assert_eq!(body_rx.try_iter().count(), 0);
		assert!(fixture.manager.header_download_for_test(&peer(1)).is_none());

		fixture.manager.sync_state.reset();
		// Leaving validation alone does not open the gate. StateSync must confirm readiness.
		assert!(!fixture.manager.state_ready.load(Ordering::Acquire));
		fixture
			.manager
			.request_chain(&fixture.peers, best_height)
			.unwrap();
		assert!(fixture.manager.state_ready.load(Ordering::Acquire));
		assert_eq!(header_rx.try_iter().count(), 1);
		assert_eq!(body_rx.try_iter().count(), 1);
	}

	#[test]
	fn three_failed_bodies_from_any_peers_ban_root_endorsers_and_reset_import() {
		let mut fixture = Fixture::new(961_101);
		// Peer 5 endorsed another root; peers 6 and 7 never endorsed any root.
		// Body validation failures count independently of those endorsements.
		for (attempt, id) in [5, 6, 7].into_iter().enumerate() {
			fixture.deliver(id, false);
			assert_eq!(fixture.failures(), attempt + 1);
			fixture
				.manager
				.state_sync_peers
				.apply_peers_status(&fixture.peers);
			if attempt < 2 {
				assert!(fixture
					.manager
					.state_sync_peers
					.get_banned_peers()
					.is_empty());
			} else {
				// Bans are queued by the third failure, before another sync poll.
				assert_eq!(
					fixture.manager.state_sync_peers.get_banned_peers(),
					(1..=4).map(peer).collect::<HashSet<_>>()
				);
			}
		}
		let response = fixture.poll();
		assert_eq!(response.response, SyncRequestResponses::Syncing);
		fixture
			.manager
			.state_sync_peers
			.apply_peers_status(&fixture.peers);
		// None of the selected-root endorsers supplied a block, and none has a
		// live connection. Their retained endorsements still select this group.
		assert_eq!(
			fixture.manager.state_sync_peers.get_banned_peers(),
			(1..=4).map(peer).collect::<HashSet<_>>()
		);
		for id in 1..=4 {
			assert!(fixture.peers.is_banned(&peer(id)).unwrap());
		}
		// This NoopAdapter fixture isolates collective bans from the ordinary
		// per-sender rejection policy: suppliers outside the group are excluded.
		for id in 5..=7 {
			assert!(!fixture.peers.is_banned(&peer(id)).unwrap());
		}
		assert!(fixture.manager.state.imported_state().is_none());
		assert_eq!(fixture.chain.head().unwrap().height, 0);
		assert_eq!(fixture.failures(), 0);
	}

	#[test]
	fn missing_openings_count_toward_pibd_group_ban() {
		let mut fixture = Fixture::new(961_110);
		let mut incomplete = fixture.block.clone();
		incomplete.coinbase_opening = None;
		// Keep the canonical header and otherwise valid body. Repeated failures
		// from one supplier still count only once.
		for (id, expected_failures) in [(6, 1), (6, 1), (7, 2), (8, 3)] {
			let source = peer(id);
			let error = fixture
				.chain
				.process_block(
					&mut fixture.secp,
					incomplete.clone(),
					mwc_chain::Options::NONE,
					HashSet::from([source.to_string()]),
				)
				.unwrap_err();
			assert!(matches!(error, mwc_chain::Error::BlockMissCoinbaseOpening));
			fixture.report_error(incomplete.clone(), source, &error);
			assert_eq!(fixture.failures(), expected_failures);
			assert_eq!(fixture.chain.head().unwrap().height, ARCHIVE_HEIGHT);
			fixture
				.manager
				.state_sync_peers
				.apply_peers_status(&fixture.peers);
			let banned = fixture.manager.state_sync_peers.get_banned_peers();
			if expected_failures < MAX_PIBD_BLOCK_FAILURES {
				assert!(banned.is_empty());
			} else {
				assert_eq!(banned, (1..=4).map(peer).collect::<HashSet<_>>());
			}
		}
		// The agreed recovery policy applies even when the imported state was
		// correct and three suppliers merely omitted the required opening.
		assert_eq!(fixture.poll().response, SyncRequestResponses::Syncing);
		assert!(fixture.manager.state.imported_state().is_none());
		assert_eq!(fixture.chain.head().unwrap().height, 0);
		assert_eq!(fixture.failures(), 0);
	}

	#[test]
	fn valid_successor_after_two_bad_bodies_completes_without_group_ban() {
		let mut fixture = Fixture::new(961_102);
		fixture.deliver(1, false);
		fixture.deliver(2, false);
		assert_eq!(fixture.failures(), 2);
		assert_eq!(fixture.chain.head().unwrap().height, ARCHIVE_HEIGHT);
		assert!(fixture.manager.state.imported_state().is_some());

		// A valid body from a peer outside the root group also completes sync.
		fixture.deliver(6, true);
		assert_eq!(fixture.chain.head().unwrap().height, ARCHIVE_HEIGHT + 1);
		assert!(fixture.manager.state.imported_state().is_none());
		let response = fixture.poll();
		assert_eq!(response.response, SyncRequestResponses::StatePibdReady);
		assert_eq!(fixture.failures(), 0);
		assert!(fixture.manager.state.imported_state().is_none());
		fixture
			.manager
			.state_sync_peers
			.apply_peers_status(&fixture.peers);
		// This fixture uses NoopAdapter, so individual block rejection does not
		// ban peers here. The PIBD counter must not add any collective bans.
		assert!(fixture
			.manager
			.state_sync_peers
			.get_banned_peers()
			.is_empty());
		for id in 1..=5 {
			assert!(!fixture.peers.is_banned(&peer(id)).unwrap());
		}
	}

	#[test]
	fn only_distinct_peers_with_canonical_bad_bodies_count() {
		let mut fixture = Fixture::new(961_103);
		fixture.deliver(6, false);
		fixture.deliver(6, false);
		assert_eq!(fixture.failures(), 1);
		let bad = mwc_chain::Error::InvalidCoinbaseBinding("invalid proof".into());
		let mut other_header = fixture.block.clone();
		other_header.header.timestamp += chrono::Duration::seconds(1);
		assert_eq!(
			other_header.hash(fixture.chain.get_context_id()).unwrap(),
			fixture.block.hash(fixture.chain.get_context_id()).unwrap()
		);
		fixture.report_error(other_header, peer(2), &bad);
		let mut other_height = fixture.block.clone();
		other_height.header.height += 1;
		fixture.report_error(other_height, peer(2), &bad);
		for error in [
			mwc_chain::Error::Other("local I/O failure".into()),
			mwc_chain::Error::ChainInSyncing("target changed".into()),
			mwc_chain::Error::Unfit("already known in store".into()),
			mwc_chain::Error::TxHashSetDiscardAfterError {
				context: "local discard failure".into(),
				primary: Box::new(mwc_chain::Error::InvalidRoot("invalid body".into())),
				discard: Box::new(mwc_chain::Error::Other("local discard failure".into())),
			},
			mwc_chain::Error::CommittedRecoveryFailed {
				context: "local recovery".into(),
				source: Box::new(mwc_chain::Error::InvalidRoot("local PMMR failure".into())),
			},
		] {
			fixture.report_error(fixture.block.clone(), peer(2), &error);
		}
		assert_eq!(fixture.failures(), 1);
		let response = fixture.poll();
		assert_eq!(response.response, SyncRequestResponses::StatePibdReady);
		assert!(fixture.manager.state.imported_state().is_some());
		fixture
			.manager
			.state_sync_peers
			.apply_peers_status(&fixture.peers);
		assert!(fixture
			.manager
			.state_sync_peers
			.get_banned_peers()
			.is_empty());
	}

	#[test]
	fn restarted_sync_session_forgets_voters_and_failures_but_validates_blocks() {
		let mut fixture = Fixture::new(961_104);
		fixture.deliver(1, false);
		fixture.deliver(2, false);
		assert_eq!(fixture.failures(), 2);
		assert!(fixture.manager.state.imported_state().is_some());

		// Restarting sync management keeps the chain state, but the preceding
		// PIBD group's endorsements and failure counter exist only in memory.
		fixture.manager = SyncManager::new(
			fixture.chain.clone(),
			Arc::new(SyncState::new()),
			Arc::new(StopState::new()),
		);
		assert!(fixture.manager.state.imported_state().is_none());
		assert!(fixture
			.manager
			.pibd_failed_peers
			.read_recursive()
			.is_empty());

		// This is an ordinary rejected block after restart, not a third vote
		// against the previous PIBD group. It must not recreate the session.
		fixture.deliver(3, false);
		assert_eq!(fixture.failures(), 0);
		assert!(fixture.manager.state.imported_state().is_none());
		assert!(fixture
			.manager
			.pibd_failed_peers
			.read_recursive()
			.is_empty());
		fixture
			.manager
			.state_sync_peers
			.apply_peers_status(&fixture.peers);
		assert!(fixture
			.manager
			.state_sync_peers
			.get_banned_peers()
			.is_empty());
		for id in 1..=5 {
			assert!(!fixture.peers.is_banned(&peer(id)).unwrap());
		}

		// Coinbase binding is still enforced by normal block processing, and
		// the honest body advances the retained state without another PIBD.
		fixture.deliver(4, true);
		assert_eq!(fixture.chain.head().unwrap().height, ARCHIVE_HEIGHT + 1);
		assert!(fixture.manager.state.imported_state().is_none());
		assert_eq!(fixture.failures(), 0);
	}
	#[test]
	fn replacement_import_does_not_inherit_first_block_failures() {
		let mut fixture = Fixture::new(961_105);
		fixture.deliver(6, false);
		fixture.deliver(7, false);
		assert_eq!(fixture.failures(), 2);

		// Production replacements pass through a reset before another import
		// completes. Let the ordinary sync entry point clear the old suppliers.
		fixture.manager.state.reset_desegmenter_data();
		fixture.manager.sync_request(&fixture.peers).unwrap();
		assert_eq!(fixture.failures(), 0);
		fixture
			.manager
			.state
			.set_imported_state_for_test(
				ARCHIVE_HEIGHT,
				fixture.root,
				(1..=4).map(|id| (peer(id), fixture.root)).collect(),
			)
			.unwrap();
		fixture.deliver(8, false);
		assert_eq!(fixture.failures(), 1);
		fixture
			.manager
			.state_sync_peers
			.apply_peers_status(&fixture.peers);
		assert!(fixture
			.manager
			.state_sync_peers
			.get_banned_peers()
			.is_empty());
	}
}
