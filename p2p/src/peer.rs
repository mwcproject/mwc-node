// Copyright 2021 The Grin Developers
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

use crate::serv::Server;
use crate::util::{Mutex, RwLock};
use std::fmt;
use std::fs::File;
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use lru_cache::LruCache;

use crate::chain;
use crate::chain::txhashset::BitmapChunk;
use crate::conn;
use crate::grin_core::core::hash::{Hash, Hashed};
use crate::grin_core::core::{OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use crate::grin_core::pow::Difficulty;
use crate::grin_core::ser::Writeable;
use crate::grin_core::{core, global};
use crate::handshake::Handshake;
use crate::msg::{
	self, ArchiveHeaderData, BanReason, GetPeerAddrs, Locator, Msg, Ping, SegmentRequest, Type,
};
use crate::protocol::Protocol;
use crate::types::{
	Capabilities, ChainAdapter, Error, NetAdapter, P2PConfig, PeerAddr, PeerInfo, ReasonForBan,
	TxHashSetRead,
};
use crate::util::secp::pedersen::RangeProof;
use chrono::prelude::{DateTime, Utc};
use grin_chain::txhashset::Segmenter;
use std::time::Instant;

const MAX_TRACK_SIZE: usize = 30;
const MAX_PEER_MSG_PER_MIN: u64 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Remind: don't mix up this 'State' with that 'State' in p2p/src/store.rs,
///   which has different 3 states: {Healthy, Banned, Defunct}.
///   For example: 'Disconnected' state here could still be 'Healthy' and could reconnect in next loop.
enum State {
	Connected,
	Banned,
}

pub struct PeerPibdStatus {
	/// Hash of the block for which the txhashset should be provided
	pub header_hash: Hash,
	/// Height of the corresponding block
	pub header_height: u64,
	/// output bitmap root hash
	pub output_bitmap_root: Option<Hash>,
	// History of commited output_bitmaps + header hashes. Needed to ban the peer in case of misbehaviour
	pub output_bitmap_root_header_history: Vec<Hash>,
	/// Time when request for pibd start was sent last time (timestamp in seconds)
	pub initiate_pibd_request_time: i64,
	/// Number of requests that was sent after success response recieved
	pub no_response_requests: u32,
	/// Time when first no responsive request was sent
	pub no_response_time: Option<i64>,
}

impl PeerPibdStatus {
	pub fn default() -> PeerPibdStatus {
		PeerPibdStatus {
			header_hash: Hash::default(),
			header_height: 0,
			output_bitmap_root: None,
			output_bitmap_root_header_history: Vec::new(),
			initiate_pibd_request_time: 0,
			no_response_requests: 0,
			no_response_time: None,
		}
	}

	pub fn update_pibd_status(
		&mut self,
		header_hash: Hash,
		header_height: u64,
		output_bitmap_root: Option<Hash>,
	) {
		self.header_hash = header_hash;
		self.header_height = header_height;

		match output_bitmap_root {
			Some(hash) => {
				let hist_hash = (hash, header_hash).hash();
				if !self.output_bitmap_root_header_history.contains(&hist_hash) {
					self.output_bitmap_root_header_history.push(hist_hash);
				}
				self.output_bitmap_root = Some(hash);
			}
			None => {
				self.output_bitmap_root = None;
			}
		}
	}
}

pub struct Peer {
	pub info: PeerInfo,
	state: Arc<RwLock<State>>,
	// set of all hashes known to this peer (so no need to send)
	tracking_adapter: TrackingAdapter,
	tracker: Arc<conn::Tracker>,
	send_handle: Mutex<conn::ConnHandle>,
	// we need a special lock for stop operation, can't reuse handle mutex for that
	// because it may be locked by different reasons, so we should wait for that, close
	// mutex can be taken only during shutdown, it happens once
	stop_handle: Mutex<conn::StopHandle>,
	// Whether or not we requested a txhashset from this peer
	state_sync_requested: Arc<AtomicBool>,
	// PIBD available data status
	pub pibd_status: Arc<Mutex<PeerPibdStatus>>,
}

impl fmt::Debug for Peer {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Peer({:?})", &self.info)
	}
}

impl Peer {
	// Only accept and connect can be externally used to build a peer
	fn new(
		info: PeerInfo,
		conn: TcpStream,
		adapter: Arc<dyn NetAdapter>,
		server: Server,
	) -> std::io::Result<Peer> {
		let state = Arc::new(RwLock::new(State::Connected));
		let state_sync_requested = Arc::new(AtomicBool::new(false));
		let tracking_adapter = TrackingAdapter::new(adapter);
		let pibd_status = Arc::new(Mutex::new(PeerPibdStatus::default()));
		let handler = Protocol::new(
			Arc::new(tracking_adapter.clone()),
			info.clone(),
			state_sync_requested.clone(),
			server,
			pibd_status.clone(),
		);
		let tracker = Arc::new(conn::Tracker::new());
		let (sendh, stoph) = conn::listen(conn, info.version, tracker.clone(), handler)?;
		let send_handle = Mutex::new(sendh);
		let stop_handle = Mutex::new(stoph);
		Ok(Peer {
			info,
			state,
			tracking_adapter,
			tracker,
			send_handle,
			stop_handle,
			state_sync_requested,
			pibd_status,
		})
	}

	pub fn accept(
		mut conn: TcpStream,
		capab: Capabilities,
		total_difficulty: Difficulty,
		hs: &Handshake,
		adapter: Arc<dyn NetAdapter>,
		server: Server,
	) -> Result<Peer, Error> {
		debug!("accept: handshaking from {:?}", conn.peer_addr());
		let info = hs.accept(capab, total_difficulty, &mut conn);
		match info {
			Ok(info) => Ok(Peer::new(info, conn, adapter, server)?),
			Err(e) => {
				debug!(
					"accept: handshaking from {:?} failed with error: {:?}",
					conn.peer_addr(),
					e
				);
				if let Err(e) = conn.shutdown(Shutdown::Both) {
					debug!("Error shutting down conn: {:?}", e);
				}
				Err(e)
			}
		}
	}

	pub fn connect(
		mut conn: TcpStream,
		capab: Capabilities,
		total_difficulty: Difficulty,
		self_addr: PeerAddr,
		hs: &Handshake,
		adapter: Arc<dyn NetAdapter>,
		peer_addr: Option<PeerAddr>,
		server: Server,
	) -> Result<Peer, Error> {
		debug!("connect: handshaking with {:?}", self_addr);

		let info = if peer_addr.is_some() {
			hs.initiate(
				capab,
				total_difficulty,
				self_addr,
				&mut conn,
				Some(peer_addr.clone().unwrap()),
			)
		} else {
			hs.initiate(capab, total_difficulty, self_addr, &mut conn, None)
		};
		match info {
			Ok(info) => Ok(Peer::new(info, conn, adapter, server)?),
			Err(e) => {
				if peer_addr.is_some() {
					debug!(
						"connect: handshaking with {:?} failed with error: {:?}",
						peer_addr.unwrap(),
						e
					);
				} else {
					debug!(
						"connect: handshaking with {:?} failed with error: {:?}",
						conn.peer_addr(),
						e
					);
				}
				if let Err(e) = conn.shutdown(Shutdown::Both) {
					debug!("Error shutting down conn: {:?}", e);
				}
				Err(e)
			}
		}
	}

	pub fn is_denied(config: &P2PConfig, peer_addr: PeerAddr) -> bool {
		if let Some(ref denied) = config.peers_deny {
			if denied.peers.contains(&peer_addr) {
				debug!(
					"checking peer allowed/denied: {:?} explicitly denied",
					peer_addr
				);
				return true;
			}
		}
		if let Some(ref allowed) = config.peers_allow {
			if allowed.peers.contains(&peer_addr) {
				debug!(
					"checking peer allowed/denied: {:?} explicitly allowed",
					peer_addr
				);
				return false;
			} else {
				debug!(
					"checking peer allowed/denied: {:?} not explicitly allowed, denying",
					peer_addr
				);
				return true;
			}
		}

		// default to allowing peer connection if we do not explicitly allow or deny
		// the peer
		false
	}

	/// Whether this peer is currently connected.
	pub fn is_connected(&self) -> bool {
		State::Connected == *self.state.read()
	}

	/// Whether this peer has been banned.
	pub fn is_banned(&self) -> bool {
		State::Banned == *self.state.read()
	}

	/// Whether this peer is stuck on sync.
	pub fn is_stuck(&self) -> (bool, Difficulty) {
		let peer_live_info = self.info.live_info.read();
		let now = Utc::now().timestamp_millis();
		// if last updated difficulty is 2 hours ago, we're sure this peer is a stuck node.
		if now > peer_live_info.stuck_detector.timestamp_millis() + global::STUCK_PEER_KICK_TIME {
			(true, peer_live_info.total_difficulty)
		} else {
			(false, peer_live_info.total_difficulty)
		}
	}

	/// Whether the peer is considered abusive, mostly for spammy nodes
	pub fn is_abusive(&self) -> bool {
		let rec = self.tracker().received_bytes.read();
		rec.count_per_min() > MAX_PEER_MSG_PER_MIN
	}

	/// Tracker tracks sent/received bytes and message counts per minute.
	pub fn tracker(&self) -> &conn::Tracker {
		&self.tracker
	}

	/// Set this peer status to banned
	pub fn set_banned(&self) {
		*self.state.write() = State::Banned;
	}

	/// Send a msg with given msg_type to our peer via the connection.
	fn send<T: Writeable>(&self, msg: T, msg_type: Type) -> Result<(), Error> {
		let msg = Msg::new(msg_type, msg, self.info.version)?;
		self.send_handle.lock().send(msg)
	}

	/// Send a ping to the remote peer, providing our local difficulty and
	/// height
	pub fn send_ping(&self, total_difficulty: Difficulty, height: u64) -> Result<(), Error> {
		let ping_msg = Ping {
			total_difficulty,
			height,
		};
		self.send(ping_msg, msg::Type::Ping)
	}

	/// Send the ban reason before banning
	pub fn send_ban_reason(&self, ban_reason: ReasonForBan) -> Result<(), Error> {
		let ban_reason_msg = BanReason { ban_reason };
		self.send(ban_reason_msg, msg::Type::BanReason).map(|_| ())
	}

	pub fn send_compact_block(&self, b: &core::CompactBlock) -> Result<bool, Error> {
		if !self.tracking_adapter.has_recv(b.hash()) {
			trace!("Send compact block {} to {}", b.hash(), self.info.addr);
			self.send(b, msg::Type::CompactBlock)?;
			Ok(true)
		} else {
			debug!(
				"Suppress compact block send {} to {} (already seen)",
				b.hash(),
				self.info.addr,
			);
			Ok(false)
		}
	}

	pub fn send_header(&self, bh: &core::BlockHeader) -> Result<bool, Error> {
		if !self.tracking_adapter.has_recv(bh.hash()) {
			debug!("Send header {} to {}", bh.hash(), self.info.addr);
			self.send(bh, msg::Type::Header)?;
			Ok(true)
		} else {
			debug!(
				"Suppress header send {} to {} (already seen)",
				bh.hash(),
				self.info.addr,
			);
			Ok(false)
		}
	}

	pub fn send_tx_kernel_hash(&self, h: Hash) -> Result<bool, Error> {
		if !self.tracking_adapter.has_recv(h) {
			debug!("Send tx kernel hash {} to {}", h, self.info.addr);
			self.send(h, msg::Type::TransactionKernel)?;
			Ok(true)
		} else {
			debug!(
				"Not sending tx kernel hash {} to {} (already seen)",
				h, self.info.addr
			);
			Ok(false)
		}
	}

	/// Sends the provided transaction to the remote peer. The request may be
	/// dropped if the remote peer is known to already have the transaction.
	/// We support broadcast of lightweight tx kernel hash
	/// so track known txs by kernel hash.
	pub fn send_transaction(&self, tx: &core::Transaction) -> Result<bool, Error> {
		let kernel = &tx.kernels()[0];

		if self
			.info
			.capabilities
			.contains(Capabilities::TX_KERNEL_HASH)
		{
			return self.send_tx_kernel_hash(kernel.hash());
		}

		if !self.tracking_adapter.has_recv(kernel.hash()) {
			debug!("Send full tx {} to {}", tx.hash(), self.info.addr);
			self.send(tx, msg::Type::Transaction)?;
			Ok(true)
		} else {
			debug!(
				"Not sending tx {} to {} (already seen)",
				tx.hash(),
				self.info.addr
			);
			Ok(false)
		}
	}

	/// Sends the provided stem transaction to the remote peer.
	/// Note: tracking adapter is ignored for stem transactions (while under
	/// embargo).
	pub fn send_stem_transaction(&self, tx: &core::Transaction) -> Result<(), Error> {
		debug!("Send (stem) tx {} to {}", tx.hash(), self.info.addr);
		self.send(tx, msg::Type::StemTransaction)
	}

	/// Sends a request for block headers from the provided block locator
	pub fn send_header_request(&self, locator: Vec<Hash>) -> Result<(), Error> {
		self.send(&Locator { hashes: locator }, msg::Type::GetHeaders)
	}

	pub fn send_tx_request(&self, h: Hash) -> Result<(), Error> {
		debug!(
			"Requesting tx (kernel hash) {} from peer {}.",
			h, self.info.addr
		);
		self.send(&h, msg::Type::GetTransaction)
	}

	/// Sends a request for a specific block by hash.
	/// Takes opts so we can track if this request was due to our node syncing or otherwise.
	pub fn send_block_request(&self, h: Hash, opts: chain::Options) -> Result<(), Error> {
		debug!("Requesting block {} from peer {}.", h, self.info.addr);
		self.tracking_adapter.push_req(h, opts);
		self.send(&h, msg::Type::GetBlock)
	}

	/// Sends a request for a specific compact block by hash
	pub fn send_compact_block_request(&self, h: Hash) -> Result<(), Error> {
		debug!("Requesting compact block {} from {}", h, self.info.addr);
		self.send(&h, msg::Type::GetCompactBlock)
	}

	pub fn send_peer_request(&self, capab: Capabilities) -> Result<(), Error> {
		trace!("Asking {} for more peers {:?}", self.info.addr, capab);
		self.send(
			&GetPeerAddrs {
				capabilities: capab,
			},
			msg::Type::GetPeerAddrs,
		)
	}

	pub fn send_txhashset_request(&self, height: u64, hash: Hash) -> Result<(), Error> {
		info!(
			"Asking {} for txhashset archive at {} {}.",
			self.info.addr, height, hash
		);
		self.state_sync_requested.store(true, Ordering::Relaxed);
		self.send(
			&ArchiveHeaderData { hash, height },
			msg::Type::TxHashSetRequest,
		)
	}

	pub fn send_start_pibd_sync_request(&self, height: u64, hash: Hash) -> Result<(), Error> {
		info!(
			"Asking peer {} for pibd sync at {} {}.",
			self.info.addr, height, hash
		);
		self.report_pibd_request();
		self.send(
			&ArchiveHeaderData { hash, height },
			msg::Type::StartPibdSyncRequest,
		)
	}

	fn report_pibd_request(&self) {
		let mut pibd_status = self.pibd_status.lock();
		pibd_status.no_response_requests += 1;
		if pibd_status.no_response_time.is_none() {
			pibd_status.no_response_time = Some(Utc::now().timestamp());
		}
	}

	pub fn send_bitmap_segment_request(
		&self,
		h: Hash,
		identifier: SegmentIdentifier,
	) -> Result<(), Error> {
		if log::log_enabled!(log::Level::Debug) {
			let pibd_status = self.pibd_status.lock();
			debug!(
				"Requesting peer {} for outputs bitmap, hash {}, id {}, output_bitmap_root: {:?}, height {}",
				self.info.addr, h, identifier, pibd_status.output_bitmap_root, pibd_status.header_height
			);
		}
		self.report_pibd_request();
		self.send(
			&SegmentRequest {
				block_hash: h,
				identifier,
			},
			msg::Type::GetOutputBitmapSegment,
		)
	}

	pub fn send_output_segment_request(
		&self,
		h: Hash,
		identifier: SegmentIdentifier,
	) -> Result<(), Error> {
		if log::log_enabled!(log::Level::Debug) {
			let pibd_status = self.pibd_status.lock();
			debug!(
				"Requesting peer {} for outputs, hash {}, id {}, output_bitmap_root: {:?}, height {}",
				self.info.addr, h, identifier, pibd_status.output_bitmap_root, pibd_status.header_height
			);
		}
		self.report_pibd_request();
		self.send(
			&SegmentRequest {
				block_hash: h,
				identifier,
			},
			msg::Type::GetOutputSegment,
		)
	}

	pub fn send_rangeproof_segment_request(
		&self,
		h: Hash,
		identifier: SegmentIdentifier,
	) -> Result<(), Error> {
		if log::log_enabled!(log::Level::Debug) {
			let pibd_status = self.pibd_status.lock();
			debug!(
				"Requesting peer {} for rangeproofs, hash {}, id {}, output_bitmap_root: {:?}, height {}",
				self.info.addr, h, identifier, pibd_status.output_bitmap_root, pibd_status.header_height
			);
		}
		self.report_pibd_request();
		self.send(
			&SegmentRequest {
				block_hash: h,
				identifier,
			},
			msg::Type::GetRangeProofSegment,
		)
	}

	pub fn send_kernel_segment_request(
		&self,
		h: Hash,
		identifier: SegmentIdentifier,
	) -> Result<(), Error> {
		if log::log_enabled!(log::Level::Debug) {
			let pibd_status = self.pibd_status.lock();
			debug!(
				"Requesting peer {} for kernels, hash {}, id {}, output_bitmap_root: {:?}, height {}",
				self.info.addr, h, identifier, pibd_status.output_bitmap_root, pibd_status.header_height
			);
		}
		self.report_pibd_request();
		self.send(
			&SegmentRequest {
				block_hash: h,
				identifier,
			},
			msg::Type::GetKernelSegment,
		)
	}

	/// Stops the peer
	pub fn stop(&self) {
		debug!("Stopping peer {:?}", self.info.addr);
		match self.stop_handle.try_lock() {
			Some(handle) => handle.stop(),
			None => error!("can't get stop lock for peer"),
		}
	}

	/// Waits until the peer's thread exit
	pub fn wait(&self) {
		debug!("Waiting for peer {:?} to stop", self.info.addr);
		match self.stop_handle.try_lock() {
			Some(mut handle) => handle.wait(),
			None => error!("can't get stop lock for peer"),
		}
	}

	/// check if this peer ever commited for specific pibd hash
	pub fn commited_to_pibd_bitmap_output_root(
		&self,
		output_bitmap_root_header_hash: &Hash,
	) -> bool {
		let status = self.pibd_status.lock();
		status
			.output_bitmap_root_header_history
			.contains(&output_bitmap_root_header_hash)
	}

	///
	pub fn get_pibd_no_response_state(&self) -> Option<(u32, i64)> {
		let status = self.pibd_status.lock();
		match status.no_response_time {
			None => None,
			Some(time) => Some((status.no_response_requests, time)),
		}
	}
}

/// Adapter implementation that forwards everything to an underlying adapter
/// but keeps track of the block and transaction hashes that were requested or
/// received.
#[derive(Clone)]
struct TrackingAdapter {
	adapter: Arc<dyn NetAdapter>,
	received: Arc<RwLock<LruCache<Hash, ()>>>,
	requested: Arc<RwLock<LruCache<Hash, chain::Options>>>,
}

impl TrackingAdapter {
	fn new(adapter: Arc<dyn NetAdapter>) -> TrackingAdapter {
		TrackingAdapter {
			adapter: adapter,
			received: Arc::new(RwLock::new(LruCache::new(MAX_TRACK_SIZE))),
			requested: Arc::new(RwLock::new(LruCache::new(MAX_TRACK_SIZE))),
		}
	}

	fn has_recv(&self, hash: Hash) -> bool {
		self.received.write().contains_key(&hash)
	}

	fn push_recv(&self, hash: Hash) {
		self.received.write().insert(hash, ());
	}

	/// Track a block or transaction hash requested by us.
	/// Track the opts alongside the hash so we know if this was due to us syncing or not.
	fn push_req(&self, hash: Hash, opts: chain::Options) {
		self.requested.write().insert(hash, opts);
	}

	fn req_opts(&self, hash: Hash) -> Option<chain::Options> {
		self.requested.write().get_mut(&hash).cloned()
	}
}

impl ChainAdapter for TrackingAdapter {
	fn total_difficulty(&self) -> Result<Difficulty, chain::Error> {
		self.adapter.total_difficulty()
	}

	fn total_height(&self) -> Result<u64, chain::Error> {
		self.adapter.total_height()
	}

	fn get_transaction(&self, kernel_hash: Hash) -> Option<core::Transaction> {
		self.adapter.get_transaction(kernel_hash)
	}

	fn tx_kernel_received(
		&self,
		kernel_hash: Hash,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		self.push_recv(kernel_hash);
		self.adapter.tx_kernel_received(kernel_hash, peer_info)
	}

	fn transaction_received(
		&self,
		tx: core::Transaction,
		stem: bool,
	) -> Result<bool, chain::Error> {
		// Do not track the tx hash for stem txs.
		// Otherwise we fail to handle the subsequent fluff or embargo expiration
		// correctly.
		if !stem {
			let kernel = &tx.kernels()[0];
			self.push_recv(kernel.hash());
		}
		self.adapter.transaction_received(tx, stem)
	}

	fn block_received(
		&self,
		b: core::Block,
		peer_info: &PeerInfo,
		opts: chain::Options,
	) -> Result<bool, chain::Error> {
		let bh = b.hash();
		self.push_recv(bh);

		// If we are currently tracking a request for this block then
		// use the opts specified when we made the request.
		// If we requested this block as part of sync then we want to
		// let our adapter know this when we receive it.
		let req_opts = self.req_opts(bh).unwrap_or(opts);
		self.adapter.block_received(b, peer_info, req_opts)
	}

	fn compact_block_received(
		&self,
		cb: core::CompactBlock,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		self.push_recv(cb.hash());
		self.adapter.compact_block_received(cb, peer_info)
	}

	fn header_received(
		&self,
		bh: core::BlockHeader,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		trace!("peer = {:?}, set header sync = false", peer_info.addr);

		let mut last_header = peer_info.last_header.lock().unwrap();
		*last_header = Instant::now();
		let mut last_header_reset = peer_info.last_header_reset.lock().unwrap();
		*last_header_reset = Instant::now();

		let val = peer_info
			.header_sync_requested
			.fetch_sub(1, Ordering::Relaxed);
		// check for wrap
		if val > 16 {
			debug!("setting a sync to 0 for peer = {}", peer_info.addr);
			peer_info.header_sync_requested.store(0, Ordering::Relaxed);
		}
		trace!("header sync for {} is {}", peer_info.addr, val);
		self.push_recv(bh.hash());
		self.adapter.header_received(bh, peer_info)
	}

	fn headers_received(
		&self,
		bh: &[core::BlockHeader],
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		trace!(
			"peer = {:?}, set header sync = false (in headers)",
			peer_info.addr
		);

		let mut last_header = peer_info.last_header.lock().unwrap();
		*last_header = Instant::now();

		let mut last_header_reset = peer_info.last_header_reset.lock().unwrap();
		*last_header_reset = Instant::now();

		let val = peer_info
			.header_sync_requested
			.fetch_sub(1, Ordering::Relaxed);
		// check for wrap
		if val > 16 {
			peer_info.header_sync_requested.store(0, Ordering::Relaxed);
		}
		trace!("header sync for {} is {}", peer_info.addr, val);
		self.adapter.headers_received(bh, peer_info)
	}

	fn locate_headers(&self, locator: &[Hash]) -> Result<Vec<core::BlockHeader>, chain::Error> {
		self.adapter.locate_headers(locator)
	}

	fn get_block(&self, h: Hash, peer_info: &PeerInfo) -> Option<core::Block> {
		self.adapter.get_block(h, peer_info)
	}

	fn txhashset_read(&self, h: Hash) -> Option<TxHashSetRead> {
		self.adapter.txhashset_read(h)
	}

	fn txhashset_archive_header(&self) -> Result<core::BlockHeader, chain::Error> {
		self.adapter.txhashset_archive_header()
	}

	fn txhashset_receive_ready(&self) -> bool {
		self.adapter.txhashset_receive_ready()
	}

	fn txhashset_write(
		&self,
		h: Hash,
		txhashset_data: File,
		peer_info: &PeerInfo,
	) -> Result<bool, chain::Error> {
		self.adapter.txhashset_write(h, txhashset_data, peer_info)
	}

	fn txhashset_download_update(
		&self,
		start_time: DateTime<Utc>,
		downloaded_size: u64,
		total_size: u64,
	) -> bool {
		self.adapter
			.txhashset_download_update(start_time, downloaded_size, total_size)
	}

	fn get_tmp_dir(&self) -> PathBuf {
		self.adapter.get_tmp_dir()
	}

	fn get_tmpfile_pathname(&self, tmpfile_name: String) -> PathBuf {
		self.adapter.get_tmpfile_pathname(tmpfile_name)
	}

	/// For MWC handshake we need to have a segmenter ready with output bitmap ready and commited.
	fn prepare_segmenter(&self) -> Result<Segmenter, chain::Error> {
		self.adapter.prepare_segmenter()
	}

	fn get_kernel_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<TxKernel>, chain::Error> {
		self.adapter.get_kernel_segment(hash, id)
	}

	fn get_bitmap_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<BitmapChunk>, chain::Error> {
		self.adapter.get_bitmap_segment(hash, id)
	}

	fn get_output_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<OutputIdentifier>, chain::Error> {
		self.adapter.get_output_segment(hash, id)
	}

	fn get_rangeproof_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<RangeProof>, chain::Error> {
		self.adapter.get_rangeproof_segment(hash, id)
	}

	fn receive_bitmap_segment(
		&self,
		block_hash: Hash,
		bitmap_root_hash: Hash,
		segment: Segment<BitmapChunk>,
	) -> Result<bool, chain::Error> {
		self.adapter
			.receive_bitmap_segment(block_hash, bitmap_root_hash, segment)
	}

	fn receive_output_segment(
		&self,
		block_hash: Hash,
		bitmap_root_hash: Hash,
		segment: Segment<OutputIdentifier>,
	) -> Result<bool, chain::Error> {
		self.adapter
			.receive_output_segment(block_hash, bitmap_root_hash, segment)
	}

	fn receive_rangeproof_segment(
		&self,
		block_hash: Hash,
		bitmap_root_hash: Hash,
		segment: Segment<RangeProof>,
	) -> Result<bool, chain::Error> {
		self.adapter
			.receive_rangeproof_segment(block_hash, bitmap_root_hash, segment)
	}

	fn receive_kernel_segment(
		&self,
		block_hash: Hash,
		bitmap_root_hash: Hash,
		segment: Segment<TxKernel>,
	) -> Result<bool, chain::Error> {
		self.adapter
			.receive_kernel_segment(block_hash, bitmap_root_hash, segment)
	}
}

impl NetAdapter for TrackingAdapter {
	fn find_peer_addrs(&self, capab: Capabilities) -> Vec<PeerAddr> {
		self.adapter.find_peer_addrs(capab)
	}

	fn peer_addrs_received(&self, addrs: Vec<PeerAddr>) {
		self.adapter.peer_addrs_received(addrs)
	}

	fn peer_difficulty(&self, addr: PeerAddr, diff: Difficulty, height: u64) {
		self.adapter.peer_difficulty(addr, diff, height)
	}

	fn is_banned(&self, addr: PeerAddr) -> bool {
		self.adapter.is_banned(addr)
	}
}
