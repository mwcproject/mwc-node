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

use crate::serv::Server;
use mwc_crates::parking_lot::{Condvar, Mutex, RwLock};
use std::fmt;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mwc_crates::lru::LruCache;

use crate::conn;
use crate::handshake::Handshake;
use crate::msg::{
	self, ArchiveHeaderData, BanReason, GetPeerAddrs, HashHeadersData, Locator, Msg, Ping,
	SegmentRequest, Type,
};
use crate::protocol::Protocol;
use crate::tor::tcp_data_stream::TcpDataStream;
use crate::types::{
	Capabilities, ChainAdapter, Error, NetAdapter, P2PConfig, PeerAddr, PeerInfo, ReasonForBan,
};
use mwc_chain;
use mwc_chain::txhashset::BitmapChunk;
use mwc_chain::txhashset::Segmenter;
use mwc_chain::SyncState;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::{OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use mwc_core::pow::Difficulty;
use mwc_core::ser::{ProtocolVersion, Writeable};
use mwc_core::{core, global};
use mwc_crates::chrono::prelude::Utc;
use mwc_crates::log::{debug, info, trace};
use mwc_crates::secp::pedersen::RangeProof;
use mwc_crates::secp::Secp256k1;

const MAX_TRACK_SIZE: usize = 2500; // Currently mac income peers limit is 256, the tracking must be much larger
const MAX_PEER_MSG_PER_MIN: u64 = 1000;
#[cfg(not(test))]
const PEER_STARTING_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
const PEER_STARTING_WAIT_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Remind: don't mix up this 'State' with that 'State' in p2p/src/store.rs,
///   which has different 3 states: {Healthy, Banned, Defunct}.
///   For example: 'Disconnected' state here could still be 'Healthy' and could reconnect in next loop.
enum State {
	Connected,
	Banned,
	Defunct,
}

pub struct Peer {
	pub info: PeerInfo,
	state: Arc<RwLock<State>>,
	// set of all hashes known to this peer (so no need to send)
	tracking_adapter: TrackingAdapter,
	tracker: Arc<conn::Tracker>,
	connection: Mutex<Option<PeerConnection>>,
	connection_changed: Condvar,
	context_id: u32,
}

enum PeerConnection {
	Starting { stop_requested: bool },
	Active(ActivePeerConnection),
}

struct ActivePeerConnection {
	send_handle: conn::ConnHandle,
	stop_handle: conn::StopHandle,
}

impl fmt::Debug for Peer {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Peer({:?})", &self.info)
	}
}

impl Peer {
	// Only accept and connect can be externally used to build a peer
	fn new(info: PeerInfo, adapter: Arc<dyn NetAdapter>, context_id: u32) -> Peer {
		let state = Arc::new(RwLock::new(State::Connected));
		let tracking_adapter = TrackingAdapter::new(context_id, adapter);
		let tracker = Arc::new(conn::Tracker::new());
		Peer {
			info,
			state,
			tracking_adapter,
			tracker,
			connection: Mutex::new(None),
			connection_changed: Condvar::new(),
			context_id,
		}
	}

	pub fn accept(
		mut conn: TcpDataStream,
		capab: Capabilities,
		total_difficulty: Difficulty,
		hs: &Handshake,
		adapter: Arc<dyn NetAdapter>,
		context_id: u32,
	) -> Result<(Peer, TcpDataStream), Error> {
		debug!("accept: handshaking from peer");
		let info = hs.accept(capab, total_difficulty, &mut conn, adapter.as_ref());
		match info {
			Ok(info) => Ok((Peer::new(info, adapter, context_id), conn)),
			Err(e) => {
				debug!("accept: handshaking failed with error: {:?}", e);
				if let Err(e) = conn.shutdown() {
					debug!("Error shutting down conn: {:?}", e);
				}
				Err(e)
			}
		}
	}

	pub fn connect(
		mut conn: TcpDataStream,
		capab: Capabilities,
		total_difficulty: Difficulty,
		self_addr: PeerAddr,
		hs: &Handshake,
		adapter: Arc<dyn NetAdapter>,
		peer_addr: &PeerAddr,
		context_id: u32,
	) -> Result<(Peer, TcpDataStream), Error> {
		match adapter.is_banned(peer_addr) {
			Ok(true) => {
				debug!("connect: peer {:?} banned, not connecting.", peer_addr);
				if let Err(e) = conn.shutdown() {
					debug!("Error shutting down conn: {:?}", e);
				}
				return Err(Error::ConnectionClose(String::from(
					"Peer denied because it is banned",
				)));
			}
			Ok(false) => {}
			Err(e) => {
				if let Err(e) = conn.shutdown() {
					debug!("Error shutting down conn: {:?}", e);
				}
				return Err(Error::ConnectionClose(format!(
					"Unable to verify ban state for {}: {}",
					peer_addr, e
				)));
			}
		}

		debug!("connect: handshaking with {:?}", peer_addr);

		let info = hs.initiate(
			capab,
			total_difficulty,
			self_addr,
			&mut conn,
			peer_addr.clone(),
		);

		match info {
			Ok(info) => Ok((Peer::new(info, adapter, context_id), conn)),
			Err(e) => {
				debug!(
					"connect: handshaking with {:?} failed with error: {:?}",
					peer_addr, e
				);

				if let Err(e) = conn.shutdown() {
					debug!("Error shutting down conn: {:?}", e);
				}
				Err(e)
			}
		}
	}

	pub fn is_denied(config: &P2PConfig, peer_addr: &PeerAddr) -> bool {
		if let Some(ref denied) = config.peers_deny {
			if denied.peers.contains(peer_addr) {
				debug!(
					"checking peer allowed/denied: {:?} explicitly denied",
					peer_addr
				);
				return true;
			}
		}
		if let Some(ref allowed) = config.peers_allow {
			if allowed.peers.contains(peer_addr) {
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

	pub fn start_listening(
		&self,
		conn: TcpDataStream,
		sync_state: Arc<SyncState>,
		server: Server,
	) -> std::io::Result<()> {
		{
			let mut connection = self.connection.lock();
			if connection.is_some() {
				return Err(std::io::Error::new(
					std::io::ErrorKind::AlreadyExists,
					format!(
						"peer {} listener already starting or started",
						self.info.addr
					),
				));
			}
			*connection = Some(PeerConnection::Starting {
				stop_requested: false,
			});
		}

		let handler = Protocol::new(
			Arc::new(self.tracking_adapter.clone()),
			self.info.clone(),
			server,
		);
		let (send_handle, stop_handle) = match conn::listen(
			conn,
			self.info.version,
			self.context_id,
			self.tracker.clone(),
			sync_state,
			self.info.addr.to_string(),
			handler,
		) {
			Ok(handles) => handles,
			Err(e) => {
				let mut connection = self.connection.lock();
				if matches!(connection.as_ref(), Some(PeerConnection::Starting { .. })) {
					*connection = None;
					self.connection_changed.notify_all();
				}
				return Err(e);
			}
		};

		let mut connection = self.connection.lock();
		debug_assert!(matches!(
			connection.as_ref(),
			Some(PeerConnection::Starting { .. })
		));
		if matches!(
			connection.as_ref(),
			Some(PeerConnection::Starting {
				stop_requested: true
			})
		) {
			stop_handle.stop();
		}
		*connection = Some(PeerConnection::Active(ActivePeerConnection {
			send_handle,
			stop_handle,
		}));
		self.connection_changed.notify_all();
		Ok(())
	}

	/// Whether this peer is currently connected.
	pub fn is_connected(&self) -> bool {
		if State::Connected != *self.state.read_recursive() {
			return false;
		}
		self.connection
			.lock()
			.as_ref()
			.map(|connection| match connection {
				PeerConnection::Active(connection) => !connection.stop_handle.is_stopped(),
				PeerConnection::Starting { .. } => false,
			})
			.unwrap_or(false)
	}

	/// Whether `wait()` can reap this peer without blocking.
	/// Removed peers can keep Tor read/write halves alive inside their
	/// connection threads; the reaper waits for readiness before joining them.
	pub(crate) fn is_wait_ready(&self) -> bool {
		self.connection
			.lock()
			.as_ref()
			.map(|connection| match connection {
				PeerConnection::Active(connection) => connection.stop_handle.is_finished(),
				PeerConnection::Starting { .. } => false,
			})
			.unwrap_or(true)
	}

	/// Whether this peer has been banned.
	pub fn is_banned(&self) -> bool {
		State::Banned == *self.state.read_recursive()
	}

	/// Whether this peer has failed in a way that should mark it defunct.
	pub fn is_defunct(&self) -> bool {
		State::Defunct == *self.state.read_recursive()
	}

	/// Whether this peer is stuck on sync.
	/// Return: (<difficulty_stuck_timeout>, <Difficulty>, <ping stuck_timeout>)
	pub fn is_stuck(&self) -> (bool, Difficulty, bool) {
		let peer_live_info = self.info.live_info.read_recursive();
		let now = Utc::now().timestamp();
		// global::PEER_PING_INTERVAL_SECONDS * 10  as i64 is safe because it is a small constant
		let dead_ping = (now - peer_live_info.last_seen.timestamp())
			> (global::PEER_PING_INTERVAL_SECONDS * 10) as i64; // 10 ping intervals considering as a reason to kick out
													   // if last updated difficulty is 2 hours ago, we're sure this peer is a stuck node.
		if peer_live_info.stuck_detector.elapsed()
			> Duration::from_secs(global::STUCK_PEER_KICK_TIME_SECONDS)
		{
			(true, peer_live_info.total_difficulty, dead_ping)
		} else {
			(false, peer_live_info.total_difficulty, dead_ping)
		}
	}

	/// Whether the peer is considered abusive, mostly for spammy nodes
	pub fn is_abusive(&self) -> bool {
		let mut rec = self.tracker().received_bytes.write();
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

	fn set_defunct(&self) {
		*self.state.write() = State::Defunct;
	}

	/// Send a msg with given msg_type to our peer via the connection.
	fn send<T: Writeable>(&self, msg: T, msg_type: Type) -> Result<(), Error> {
		let connection = self.connection.lock();
		let connection = match connection.as_ref() {
			Some(PeerConnection::Active(connection)) if !connection.stop_handle.is_stopped() => {
				connection
			}
			_ => {
				return Err(crate::types::Error::ConnectionClose(format!(
					"peer: {}",
					self.info.addr
				)));
			}
		};
		let msg = Msg::new(msg_type, msg, self.info.version, self.context_id)?;
		match connection.send_handle.send(msg) {
			Ok(()) => Ok(()),
			Err(e) => {
				debug!(
					"Error queueing message to peer {:?}, marking defunct and stopping: {:?}",
					self.info.addr, e
				);
				self.set_defunct();
				connection.stop_handle.stop();
				Err(e)
			}
		}
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
		let block_hash = b.hash(self.context_id)?;
		if !self.tracking_adapter.has_recv(block_hash) {
			trace!("Send compact block {} to {}", block_hash, self.info.addr);
			self.send(b, msg::Type::CompactBlock)?;
			Ok(true)
		} else {
			debug!(
				"Suppress compact block send {} to {} (already seen)",
				block_hash, self.info.addr,
			);
			Ok(false)
		}
	}

	pub fn send_header(&self, bh: &core::BlockHeader) -> Result<bool, Error> {
		let header_hash = bh.hash(self.context_id)?;
		if !self.tracking_adapter.has_recv(header_hash) {
			debug!("Send header {} to {}", header_hash, self.info.addr);
			self.send(bh, msg::Type::Header)?;
			Ok(true)
		} else {
			debug!(
				"Suppress header send {} to {} (already seen)",
				header_hash, self.info.addr,
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
	/// so track known txs by a representative kernel hash.
	pub fn send_transaction(&self, tx: &core::Transaction) -> Result<bool, Error> {
		let kernel = tx
			.kernels()
			.first()
			.ok_or_else(|| Error::Internal("send transaction with no kernels".into()))?;

		if self
			.info
			.capabilities
			.contains(Capabilities::TX_KERNEL_HASH)
		{
			return self.send_tx_kernel_hash(kernel.hash(self.context_id)?);
		}

		if !self
			.tracking_adapter
			.has_recv(kernel.hash(self.context_id)?)
		{
			debug!(
				"Send full tx {} to {}",
				tx.hash(self.context_id)?,
				self.info.addr
			);
			self.send(tx, msg::Type::Transaction)?;
			Ok(true)
		} else {
			debug!(
				"Not sending tx {} to {} (already seen)",
				tx.hash(self.context_id)?,
				self.info.addr
			);
			Ok(false)
		}
	}

	/// Sends the provided stem transaction to the remote peer.
	/// Note: tracking adapter is ignored for stem transactions (while under
	/// embargo).
	pub fn send_stem_transaction(&self, tx: &core::Transaction) -> Result<(), Error> {
		debug!(
			"Send (stem) tx {} to {}",
			tx.hash(self.context_id)?,
			self.info.addr
		);
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
	pub fn send_block_request(&self, h: Hash, opts: mwc_chain::Options) -> Result<(), Error> {
		debug!("Requesting block {} from peer {}.", h, self.info.addr);
		let restore = self.tracking_adapter.push_req(h, opts);
		if let Err(e) = self.send(&h, msg::Type::GetBlock) {
			self.tracking_adapter.restore_req(h, restore);
			return Err(e);
		}
		Ok(())
	}

	/// Sends a request for a specific compact block by hash
	pub fn send_compact_block_request(&self, h: Hash) -> Result<(), Error> {
		debug!("Requesting compact block {} from {}", h, self.info.addr);
		self.send(&h, msg::Type::GetCompactBlock)
	}

	pub fn send_peer_request(
		&self,
		capab: Capabilities,
		use_tor_connection: bool,
	) -> Result<(), Error> {
		let capab = if use_tor_connection {
			capab | Capabilities::TOR_ADDRESS
		} else {
			capab
		};
		trace!("Asking {} for more peers {:?}", self.info.addr, capab);
		self.send(
			&GetPeerAddrs {
				capabilities: capab,
			},
			msg::Type::GetPeerAddrs,
		)
	}

	pub fn send_start_pibd_sync_request(&self, height: u64, hash: Hash) -> Result<(), Error> {
		info!(
			"Asking peer {} for pibd sync at {} {}.",
			self.info.addr, height, hash
		);
		self.send(
			&ArchiveHeaderData { hash, height },
			msg::Type::StartPibdSyncRequest,
		)
	}

	pub fn send_start_headers_hash_sync_request(&self, archive_height: u64) -> Result<(), Error> {
		info!(
			"Asking peer {} for headers hash sync for archive_height {}.",
			self.info.addr, archive_height
		);
		self.send(
			&HashHeadersData { archive_height },
			msg::Type::StartHeadersHashRequest,
		)
	}

	pub fn send_headers_hash_segment_request(
		&self,
		headers_hash_root: Hash,
		identifier: SegmentIdentifier,
	) -> Result<(), Error> {
		debug!(
			"Requesting peer {} for headers hashs, root hash {}, id {}",
			self.info.addr, headers_hash_root, identifier
		);

		self.send(
			&SegmentRequest {
				block_hash: headers_hash_root,
				identifier,
			},
			msg::Type::GetHeadersHashesSegment,
		)
	}

	pub fn send_bitmap_segment_request(
		&self,
		h: Hash,
		identifier: SegmentIdentifier,
	) -> Result<(), Error> {
		debug!(
			"Requesting peer {} for outputs bitmap, hash {}, id {}",
			self.info.addr, h, identifier
		);
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
		debug!(
			"Requesting peer {} for outputs, hash {}, id {}",
			self.info.addr, h, identifier
		);
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
		debug!(
			"Requesting peer {} for rangeproofs, hash {}, id {}",
			self.info.addr, h, identifier
		);
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
		debug!(
			"Requesting peer {} for kernels, hash {}, id {}",
			self.info.addr, h, identifier
		);
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
		match self.connection.lock().as_mut() {
			Some(PeerConnection::Active(connection)) => connection.stop_handle.stop(),
			Some(PeerConnection::Starting { stop_requested }) => {
				*stop_requested = true;
			}
			None => {}
		}
	}

	/// Waits until the peer's thread exit
	pub fn wait(&self) -> Result<(), Error> {
		debug!("Waiting for peer {:?} to stop", self.info.addr);
		let stop_handle = {
			let mut connection = self.connection.lock();
			let starting_wait_deadline = Instant::now() + PEER_STARTING_WAIT_TIMEOUT;
			while matches!(connection.as_ref(), Some(PeerConnection::Starting { .. })) {
				let now = Instant::now();
				if now >= starting_wait_deadline {
					return Err(Error::Timeout);
				}
				let wait_result = self
					.connection_changed
					.wait_for(&mut connection, starting_wait_deadline - now);
				if wait_result.timed_out()
					&& matches!(connection.as_ref(), Some(PeerConnection::Starting { .. }))
				{
					return Err(Error::Timeout);
				}
			}

			match connection.take() {
				Some(PeerConnection::Active(active_connection)) => {
					Some(active_connection.stop_handle)
				}
				None => None,
				Some(PeerConnection::Starting { stop_requested }) => {
					*connection = Some(PeerConnection::Starting { stop_requested });
					None
				}
			}
		};

		match stop_handle {
			Some(mut stop_handle) => stop_handle.wait(),
			None => Ok(()),
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
	requested: Arc<RwLock<LruCache<Hash, RequestEntry>>>,
	next_request_id: Arc<AtomicU64>,
	context_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RequestEntry {
	opts: mwc_chain::Options,
	id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RequestRestore {
	inserted: RequestEntry,
	previous: Option<RequestEntry>,
}

impl TrackingAdapter {
	fn new(context_id: u32, adapter: Arc<dyn NetAdapter>) -> TrackingAdapter {
		// unwrap safe because build from positive constant
		let track_size = NonZeroUsize::new(MAX_TRACK_SIZE).unwrap();
		TrackingAdapter {
			adapter,
			received: Arc::new(RwLock::new(LruCache::new(track_size))),
			requested: Arc::new(RwLock::new(LruCache::new(track_size))),
			next_request_id: Arc::new(AtomicU64::new(0)),
			context_id,
		}
	}

	fn next_request_id(&self) -> u64 {
		self.next_request_id
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				// Request ids can wrap. After a full u64 cycle, duplicated ids
				// should have been retired from the bounded request cache. Even if
				// one has not, the impact is not critical for this tracking path.
				Some(current.wrapping_add(1))
			})
			// Safe because fetch_update only returns Err if the closure returns
			// None, and this closure always provides the next value.
			.expect("request id update always returns Some")
	}

	fn has_recv(&self, hash: Hash) -> bool {
		self.received.read_recursive().contains(&hash)
	}

	fn push_recv(&self, hash: Hash) {
		self.received.write().put(hash, ());
	}

	/// Track a block hash requested by us.
	/// Track the opts alongside the hash so we know if this was due to us syncing or not.
	fn push_req(&self, hash: Hash, opts: mwc_chain::Options) -> RequestRestore {
		let inserted = RequestEntry {
			opts,
			id: self.next_request_id(),
		};
		let previous = self.requested.write().put(hash, inserted);
		RequestRestore { inserted, previous }
	}

	fn restore_req(&self, hash: Hash, restore: RequestRestore) {
		let mut requested = self.requested.write();
		match requested.pop(&hash) {
			Some(current) if current == restore.inserted => {
				if let Some(previous) = restore.previous {
					requested.put(hash, previous);
				}
			}
			Some(current) => {
				requested.put(hash, current);
			}
			None => {}
		}
	}

	fn remove_req(&self, hash: Hash) -> Option<mwc_chain::Options> {
		self.requested.write().pop(&hash).map(|entry| entry.opts)
	}
}

impl ChainAdapter for TrackingAdapter {
	fn total_difficulty(&self) -> Result<Difficulty, mwc_chain::Error> {
		self.adapter.total_difficulty()
	}

	fn total_height(&self) -> Result<u64, mwc_chain::Error> {
		self.adapter.total_height()
	}

	fn is_chain_liveness_deferred(&self) -> bool {
		self.adapter.is_chain_liveness_deferred()
	}

	fn get_transaction(
		&self,
		kernel_hash: Hash,
	) -> Result<Option<core::Transaction>, mwc_chain::Error> {
		self.adapter.get_transaction(kernel_hash)
	}

	fn tx_kernel_received(
		&self,
		kernel_hash: Hash,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		self.push_recv(kernel_hash);
		self.adapter.tx_kernel_received(kernel_hash, peer_info)
	}

	fn transaction_received(
		&self,
		secp: &mut Secp256k1,
		tx: core::Transaction,
		stem: bool,
	) -> Result<bool, mwc_chain::Error> {
		// Do not track the tx hash for stem txs.
		// Otherwise we fail to handle the subsequent fluff or embargo expiration
		// correctly.
		if !stem {
			let kernel = tx.kernels().first().ok_or_else(|| {
				mwc_chain::Error::Transaction(core::transaction::Error::Generic(
					"received transaction with no kernels".into(),
				))
			})?;
			self.push_recv(kernel.hash(self.context_id)?);
		}
		self.adapter.transaction_received(secp, tx, stem)
	}

	fn block_received(
		&self,
		secp: &mut Secp256k1,
		b: core::Block,
		peer_info: &PeerInfo,
		opts: mwc_chain::Options,
	) -> Result<bool, mwc_chain::Error> {
		let bh = b.hash(self.context_id)?;
		self.push_recv(bh);

		// If we are currently tracking a request for this block then
		// use the opts specified when we made the request.
		// If we requested this block as part of sync then we want to
		// let our adapter know this when we receive it.
		let req_opts = self.remove_req(bh).unwrap_or(opts);
		self.adapter.block_received(secp, b, peer_info, req_opts)
	}

	fn compact_block_received(
		&self,
		secp: &mut Secp256k1,
		cb: core::CompactBlock,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		self.push_recv(cb.hash(self.context_id)?);
		self.adapter.compact_block_received(secp, cb, peer_info)
	}

	fn header_received(
		&self,
		bh: core::BlockHeader,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		self.push_recv(bh.hash(self.context_id)?);
		self.adapter.header_received(bh, peer_info)
	}

	fn header_locator(&self) -> Result<Vec<Hash>, mwc_chain::Error> {
		self.adapter.header_locator()
	}

	fn headers_received(
		&self,
		bh: &[core::BlockHeader],
		remaining: u64,
		peer_info: &PeerInfo,
	) -> Result<(), mwc_chain::Error> {
		// Batch headers are only expected on the sync response path.
		// These headers are normally far from the tip, so we do not track
		// them as "already seen" for broadcast suppression.
		self.adapter.headers_received(bh, remaining, peer_info)
	}

	fn locate_headers(&self, locator: &[Hash]) -> Result<Vec<core::BlockHeader>, mwc_chain::Error> {
		self.adapter.locate_headers(locator)
	}

	fn get_block(
		&self,
		secp: &Secp256k1,
		h: Hash,
		peer_info: &PeerInfo,
	) -> Result<Option<core::Block>, mwc_chain::Error> {
		self.adapter.get_block(secp, h, peer_info)
	}

	fn txhashset_archive_header(&self) -> Result<core::BlockHeader, mwc_chain::Error> {
		self.adapter.txhashset_archive_header()
	}

	fn get_tmp_dir(&self) -> Result<PathBuf, mwc_chain::Error> {
		self.adapter.get_tmp_dir()
	}

	fn get_tmpfile_pathname(&self, tmpfile_name: String) -> Result<PathBuf, mwc_chain::Error> {
		self.adapter.get_tmpfile_pathname(tmpfile_name)
	}

	fn recieve_pibd_status(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
		output_bitmap_root: Hash,
	) -> Result<(), mwc_chain::Error> {
		self.adapter
			.recieve_pibd_status(peer, header_hash, header_height, output_bitmap_root)
	}

	fn recieve_another_archive_header(
		&self,
		peer: &PeerAddr,
		header_hash: Hash,
		header_height: u64,
	) -> Result<(), mwc_chain::Error> {
		self.adapter
			.recieve_another_archive_header(peer, header_hash, header_height)
	}

	fn receive_headers_hash_response(
		&self,
		peer: &PeerAddr,
		archive_height: u64,
		headers_hash_root: Hash,
	) -> Result<(), mwc_chain::Error> {
		self.adapter
			.receive_headers_hash_response(peer, archive_height, headers_hash_root)
	}

	fn get_header_hashes_segment(
		&self,
		header_hashes_root: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<Hash>, mwc_chain::Error> {
		self.adapter
			.get_header_hashes_segment(header_hashes_root, id)
	}

	fn receive_header_hashes_segment(
		&self,
		peer: &PeerAddr,
		header_hashes_root: Hash,
		segment: Segment<Hash>,
	) -> Result<(), mwc_chain::Error> {
		self.adapter
			.receive_header_hashes_segment(peer, header_hashes_root, segment)
	}

	/// For MWC handshake we need to have a segmenter ready with output bitmap ready and commited.
	fn prepare_segmenter(&self) -> Result<Segmenter, mwc_chain::Error> {
		self.adapter.prepare_segmenter()
	}

	fn get_kernel_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<TxKernel>, mwc_chain::Error> {
		self.adapter.get_kernel_segment(hash, id)
	}

	fn get_bitmap_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<BitmapChunk>, mwc_chain::Error> {
		self.adapter.get_bitmap_segment(hash, id)
	}

	fn get_output_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<OutputIdentifier>, mwc_chain::Error> {
		self.adapter.get_output_segment(hash, id)
	}

	fn get_rangeproof_segment(
		&self,
		hash: Hash,
		id: SegmentIdentifier,
	) -> Result<Segment<RangeProof>, mwc_chain::Error> {
		self.adapter.get_rangeproof_segment(hash, id)
	}

	fn receive_bitmap_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<BitmapChunk>,
	) -> Result<(), mwc_chain::Error> {
		self.adapter
			.receive_bitmap_segment(peer, archive_header_hash, segment)
	}

	fn receive_output_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<OutputIdentifier>,
	) -> Result<(), mwc_chain::Error> {
		self.adapter
			.receive_output_segment(peer, archive_header_hash, segment)
	}

	fn receive_rangeproof_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<RangeProof>,
	) -> Result<(), mwc_chain::Error> {
		self.adapter
			.receive_rangeproof_segment(peer, archive_header_hash, segment)
	}

	fn receive_kernel_segment(
		&self,
		peer: &PeerAddr,
		archive_header_hash: Hash,
		segment: Segment<TxKernel>,
	) -> Result<(), mwc_chain::Error> {
		self.adapter
			.receive_kernel_segment(peer, archive_header_hash, segment)
	}

	fn peer_difficulty(&self, addr: &PeerAddr, diff: Difficulty, height: u64) {
		self.adapter.peer_difficulty(addr, diff, height)
	}
}

impl NetAdapter for TrackingAdapter {
	fn find_peer_addrs(&self, capab: Capabilities) -> Result<Vec<PeerAddr>, Error> {
		self.adapter.find_peer_addrs(capab)
	}

	fn peer_addrs_received(&self, source: &PeerAddr, addrs: Vec<PeerAddr>) {
		self.adapter.peer_addrs_received(source, addrs)
	}

	fn is_banned(&self, addr: &PeerAddr) -> Result<bool, Error> {
		self.adapter.is_banned(addr)
	}

	fn peer_version(&self, addr: &PeerAddr) -> Result<Option<ProtocolVersion>, Error> {
		self.adapter.peer_version(addr)
	}

	/// Ban peer
	fn ban_peer(
		&self,
		addr: &PeerAddr,
		ban_reason: ReasonForBan,
		message: &str,
	) -> Result<(), Error> {
		self.adapter.ban_peer(addr, ban_reason, message)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::serv::{set_dummy_adapter_liveness_deferred_for_test, DummyAdapter};
	use crate::types::{Direction, PeerLiveInfo};
	use std::net::SocketAddr;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::mpsc;
	use std::thread;
	use std::time::Duration;

	fn test_peer() -> Peer {
		test_peer_with_user_agent("test".to_string())
	}

	fn test_peer_with_user_agent(user_agent: String) -> Peer {
		test_peer_with_user_agent_addr_fee(user_agent, 3414, 0)
	}

	fn test_peer_with_addr_fee(port: u16, tx_base_fee: u64) -> Peer {
		test_peer_with_user_agent_addr_fee("test".to_string(), port, tx_base_fee)
	}

	fn test_peer_with_user_agent_addr_fee(user_agent: String, port: u16, tx_base_fee: u64) -> Peer {
		let peer_info = PeerInfo {
			capabilities: Capabilities::UNKNOWN,
			user_agent,
			version: ProtocolVersion::local(),
			addr: PeerAddr::Ip(SocketAddr::from(([127, 0, 0, 1], port))),
			direction: Direction::Outbound,
			live_info: Arc::new(RwLock::new(PeerLiveInfo::new(Difficulty::min()))),
			tx_base_fee,
		};
		Peer::new(peer_info, Arc::new(DummyAdapter {}), 0)
	}

	fn connected_test_peer() -> Peer {
		let peer = test_peer();
		connect_test_peer(peer)
	}

	fn connected_test_peer_with_addr_fee(port: u16, tx_base_fee: u64) -> Peer {
		let peer = test_peer_with_addr_fee(port, tx_base_fee);
		connect_test_peer(peer)
	}

	fn connect_test_peer(peer: Peer) -> Peer {
		let (send_handle, stop_handle) = conn::disconnected_test_handles();
		*peer.connection.lock() = Some(PeerConnection::Active(ActivePeerConnection {
			send_handle,
			stop_handle,
		}));
		peer
	}

	fn test_valid_signature() -> mwc_crates::secp::AggSigSignature {
		let secp = Secp256k1::with_caps(mwc_crates::secp::ContextFlag::Commit).unwrap();
		mwc_crates::secp::AggSigSignature::from_compact(
			&secp,
			&[
				155, 161, 81, 120, 148, 131, 93, 161, 94, 90, 149, 232, 60, 234, 164, 237, 129,
				149, 174, 231, 52, 76, 240, 100, 103, 219, 44, 47, 239, 151, 29, 206, 30, 146, 118,
				82, 80, 234, 239, 52, 9, 114, 15, 81, 50, 15, 179, 22, 150, 52, 166, 10, 5, 150,
				227, 164, 82, 44, 25, 66, 64, 250, 177, 170,
			],
		)
		.unwrap()
	}

	#[test]
	fn add_connected_rolls_back_live_peer_when_store_save_fails() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(test_peer_with_user_agent("x".repeat(10_001)));
		let addr = peer.info.addr.clone();

		let result = peers.add_connected(peer);

		assert!(result.is_err());
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn add_connected_refuses_banned_peer_and_rolls_back_live_peer() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(test_peer());
		let addr = peer.info.addr.clone();
		peers
			.add_banned(addr.clone(), ReasonForBan::ManualBan, "test ban")
			.unwrap();

		let result = peers.add_connected(peer);

		assert!(matches!(
			result,
			Err(Error::ConnectionClose(message)) if message.contains("banned")
		));
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
		assert_eq!(
			peers.get_peer(&addr).unwrap().flags,
			crate::store::State::Banned
		);
	}

	#[test]
	fn broadcast_transaction_local_error_does_not_remove_peer() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();

		let result = peers.broadcast_transaction(&core::Transaction::empty());

		assert!(matches!(
			result,
			Err(crate::types::BroadcastError::P2p(Error::Internal(_)))
		));
		assert!(peers.get_connected_peer(&addr).is_some());
		assert!(peers.is_known(&addr));
	}

	#[test]
	fn broadcast_peer_send_failure_removes_peer() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();

		let summary = peers
			.broadcast_for_test(|_| Err(Error::Send("test send failure".into())))
			.unwrap();

		assert_eq!(summary.sent, 0);
		assert_eq!(summary.peer_failures, 1);
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn broadcast_peer_send_failure_succeeds_when_state_persist_fails() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();
		peers.delete_peer(&addr).unwrap();

		let summary = peers
			.broadcast_for_test(|_| Err(Error::Send("test send failure".into())))
			.unwrap();

		assert_eq!(summary.sent, 0);
		assert_eq!(summary.peer_failures, 1);
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn broadcast_peer_send_failure_does_not_remove_replacement_peer() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let stale_peer = Arc::new(connected_test_peer());
		let replacement_peer = Arc::new(connected_test_peer());
		let addr = stale_peer.info.addr.clone();
		peers.add_connected(stale_peer.clone()).unwrap();

		let replaced = AtomicBool::new(false);
		let summary = peers
			.broadcast_for_test(|p| {
				if !replaced.swap(true, Ordering::SeqCst) {
					let removed = peers.remove_connected(&addr).unwrap();
					assert!(Arc::ptr_eq(&removed, &stale_peer));
					peers.add_connected(replacement_peer.clone()).unwrap();
				}
				assert!(std::ptr::eq(p, stale_peer.as_ref()));
				Err(Error::Send("test send failure".into()))
			})
			.unwrap();

		assert_eq!(summary.sent, 0);
		assert_eq!(summary.peer_failures, 1);
		let connected = peers.get_connected_peer(&addr).unwrap();
		assert!(Arc::ptr_eq(&connected, &replacement_peer));
		assert!(peers.is_known(&addr));
	}

	#[test]
	fn ping_failure_cleanup_does_not_remove_replacement_peer() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let stale_peer = Arc::new(connected_test_peer());
		let replacement_peer = Arc::new(connected_test_peer());
		let addr = stale_peer.info.addr.clone();
		peers.add_connected(stale_peer.clone()).unwrap();

		let removed = peers.remove_connected(&addr).unwrap();
		assert!(Arc::ptr_eq(&removed, &stale_peer));
		peers.add_connected(replacement_peer.clone()).unwrap();

		let removed = peers.remove_failed_ping_peer_for_test(&stale_peer).unwrap();
		assert!(!removed);

		let connected = peers.get_connected_peer(&addr).unwrap();
		assert!(Arc::ptr_eq(&connected, &replacement_peer));
		assert!(peers.is_known(&addr));
	}

	#[test]
	fn ping_failure_check_all_reports_successful_cleanup() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();

		let summary = peers.check_all(Difficulty::min(), 0);

		assert_eq!(summary.ping_failures, 1);
		assert_eq!(summary.persistence_failures, 0);
		assert!(summary.first_persistence_error().is_none());
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
		assert_eq!(
			peers.get_peer(&addr).unwrap().flags,
			crate::store::State::Defunct
		);
	}

	#[test]
	fn stop_reports_state_persistence_failure() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();
		peers.delete_peer(&addr).unwrap();

		let result = peers.stop();

		assert!(result.is_err());
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn stop_preserves_defunct_peer_state() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer.clone()).unwrap();
		peer.set_defunct();

		peers.stop().unwrap();

		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
		assert_eq!(
			peers.get_peer(&addr).unwrap().flags,
			crate::store::State::Defunct
		);
	}

	#[test]
	fn enough_outbound_peers_requires_one_fee_match_for_minimum_one() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_accept_fee_base(1000).unwrap();

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let mut config = P2PConfig::default();
		config.peer_min_preferred_outbound_count = Some(1);
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		let peer = Arc::new(connected_test_peer_with_addr_fee(3500, 2000));
		peers.add_connected(peer).unwrap();

		assert!(!peers.enough_outbound_peers());
	}

	#[test]
	fn enough_outbound_peers_uses_half_of_connected_outbound_peers_for_fee_match() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_accept_fee_base(1000).unwrap();

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let mut config = P2PConfig::default();
		config.peer_min_preferred_outbound_count = Some(3);
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		for (port, tx_base_fee) in [
			(3510, 500),
			(3511, 500),
			(3512, 2000),
			(3513, 2000),
			(3514, 2000),
		] {
			peers
				.add_connected(Arc::new(connected_test_peer_with_addr_fee(
					port,
					tx_base_fee,
				)))
				.unwrap();
		}

		assert!(!peers.enough_outbound_peers());

		peers
			.add_connected(Arc::new(connected_test_peer_with_addr_fee(3515, 500)))
			.unwrap();

		assert!(peers.enough_outbound_peers());
	}

	#[test]
	fn peer_addrs_received_rejects_unroutable_gossip_candidates() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let source = PeerAddr::Ip(SocketAddr::from(([8, 8, 8, 8], 3414)));
		let valid = PeerAddr::Ip(SocketAddr::from(([1, 1, 1, 1], 3414)));
		let private = PeerAddr::Ip(SocketAddr::from(([10, 1, 2, 3], 3414)));
		let port_zero = PeerAddr::Ip(SocketAddr::from(([8, 8, 4, 4], 0)));

		NetAdapter::peer_addrs_received(
			&peers,
			&source,
			vec![private.clone(), port_zero.clone(), valid.clone()],
		);

		let advertised = peers.ranked_advertised_peers();
		assert_eq!(advertised.len(), 1);
		assert_eq!(advertised[0].addr, valid);
		assert!(peers.exists_peer(&valid).unwrap());
		assert!(!peers.exists_peer(&private).unwrap());
		assert!(!peers.exists_peer(&port_zero).unwrap());
	}

	#[test]
	fn peer_addrs_received_allows_preferred_private_gossip_candidate() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let source = PeerAddr::Ip(SocketAddr::from(([8, 8, 8, 8], 3414)));
		let preferred = PeerAddr::Ip(SocketAddr::from(([10, 1, 2, 3], 3414)));
		let mut config = P2PConfig::default();
		config.peers_preferred = Some(crate::msg::PeerAddrs {
			peers: vec![preferred.clone()],
		});
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);

		NetAdapter::peer_addrs_received(&peers, &source, vec![preferred.clone()]);

		let advertised = peers.ranked_advertised_peers();
		assert_eq!(advertised.len(), 1);
		assert_eq!(advertised[0].addr, preferred);
		assert!(peers.exists_peer(&preferred).unwrap());
	}

	#[test]
	fn peer_addrs_received_rejects_non_exact_preferred_gossip_candidate() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let source = PeerAddr::Ip(SocketAddr::from(([8, 8, 8, 8], 3414)));
		let preferred = PeerAddr::Ip(SocketAddr::from(([8, 8, 4, 4], 3414)));
		let port_zero = PeerAddr::Ip(SocketAddr::from(([8, 8, 4, 4], 0)));
		let alternate_port = PeerAddr::Ip(SocketAddr::from(([8, 8, 4, 4], 12345)));
		let mut config = P2PConfig::default();
		config.peers_preferred = Some(crate::msg::PeerAddrs {
			peers: vec![preferred.clone()],
		});
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);

		NetAdapter::peer_addrs_received(
			&peers,
			&source,
			vec![port_zero.clone(), alternate_port.clone()],
		);

		assert!(peers.ranked_advertised_peers().is_empty());
		assert!(!peers.exists_peer(&preferred).unwrap());
		assert!(!peers.exists_peer(&port_zero).unwrap());
		assert!(!peers.exists_peer(&alternate_port).unwrap());
	}

	#[test]
	fn ping_failure_check_all_reports_persistence_failure() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();
		peers.delete_peer(&addr).unwrap();

		let summary = peers.check_all(Difficulty::min(), 0);

		assert_eq!(summary.ping_failures, 1);
		assert_eq!(summary.persistence_failures, 1);
		assert!(summary.first_persistence_error().is_some());
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn clean_peers_reports_update_state_failure_and_removes_defunct_peer() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer.clone()).unwrap();
		peer.set_defunct();
		peers.delete_peer(&addr).unwrap();

		let summary = peers.clean_peers(
			usize::MAX,
			usize::MAX,
			Capabilities::UNKNOWN,
			P2PConfig::default(),
		);

		assert_eq!(summary.removed_peers, 1);
		assert_eq!(summary.persistence_failures, 1);
		assert!(summary.first_persistence_error().is_some());
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn clean_peers_reports_healthy_state_failure_and_removes_peer() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();
		peers.delete_peer(&addr).unwrap();

		let summary = peers.clean_peers(
			usize::MAX,
			usize::MAX,
			Capabilities::UNKNOWN,
			P2PConfig::default(),
		);

		assert_eq!(summary.removed_peers, 1);
		assert_eq!(summary.persistence_failures, 1);
		assert!(summary.first_persistence_error().is_some());
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn clean_peers_preserves_dead_ping_peer_when_liveness_deferred() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		struct LivenessGuard(bool);
		impl Drop for LivenessGuard {
			fn drop(&mut self) {
				set_dummy_adapter_liveness_deferred_for_test(self.0);
			}
		}

		let previous = set_dummy_adapter_liveness_deferred_for_test(true);
		let _guard = LivenessGuard(previous);
		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peer.info.live_info.write().last_seen = mwc_crates::chrono::Utc::now()
			- mwc_crates::chrono::Duration::seconds(
				(global::PEER_PING_INTERVAL_SECONDS as i64) * 11,
			);
		peers.add_connected(peer).unwrap();

		let summary = peers.clean_peers(
			usize::MAX,
			usize::MAX,
			Capabilities::UNKNOWN,
			P2PConfig::default(),
		);

		assert_eq!(summary.removed_peers, 0);
		assert!(peers.get_connected_peer(&addr).is_some());
		assert!(peers.is_known(&addr));
	}

	#[test]
	fn broadcast_header_all_peer_send_failures_returns_error() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();

		let result = peers.broadcast_header(&core::BlockHeader::default(0));

		assert!(matches!(
			result,
			Err(Error::PeerException(message)) if message.contains("header broadcast failed")
		));
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn broadcast_compact_block_all_peer_send_failures_returns_error() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();
		let compact_block = core::CompactBlock::from(core::Block::default(0)).unwrap();

		let result = peers.broadcast_compact_block(&compact_block);

		assert!(matches!(
			result,
			Err(Error::PeerException(message)) if message.contains("compact block broadcast failed")
		));
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn broadcast_transaction_all_peer_send_failures_returns_error() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let peer = Arc::new(connected_test_peer());
		let addr = peer.info.addr.clone();
		peers.add_connected(peer).unwrap();
		let mut kernel = TxKernel::with_features(core::KernelFeatures::Plain {
			fee: core::FeeFields::new(1).unwrap(),
		})
		.unwrap();
		kernel.excess_sig = test_valid_signature();
		let tx = core::Transaction::empty().with_kernel(0, kernel).unwrap();

		let result = peers.broadcast_transaction(&tx);

		assert!(matches!(
			result,
			Err(crate::types::BroadcastError::P2p(Error::PeerException(_)))
		));
		assert!(peers.get_connected_peer(&addr).is_none());
		assert!(!peers.is_known(&addr));
	}

	#[test]
	fn restore_req_preserves_previous_block_request_opts() {
		let tracking_adapter = TrackingAdapter::new(0, Arc::new(DummyAdapter {}));
		let hash = Hash::from_vec(&[1]);

		tracking_adapter.push_req(hash, mwc_chain::Options::SYNC);
		let restore = tracking_adapter.push_req(hash, mwc_chain::Options::NONE);

		tracking_adapter.restore_req(hash, restore);

		assert_eq!(
			tracking_adapter.remove_req(hash),
			Some(mwc_chain::Options::SYNC)
		);
	}

	#[test]
	fn restore_req_removes_failed_request_without_previous_entry() {
		let tracking_adapter = TrackingAdapter::new(0, Arc::new(DummyAdapter {}));
		let hash = Hash::from_vec(&[2]);
		let restore = tracking_adapter.push_req(hash, mwc_chain::Options::NONE);

		tracking_adapter.restore_req(hash, restore);

		assert_eq!(tracking_adapter.remove_req(hash), None);
	}

	#[test]
	fn restore_req_does_not_clobber_newer_request_entry() {
		let tracking_adapter = TrackingAdapter::new(0, Arc::new(DummyAdapter {}));
		let hash = Hash::from_vec(&[3]);

		tracking_adapter.push_req(hash, mwc_chain::Options::SYNC);
		let failed_restore = tracking_adapter.push_req(hash, mwc_chain::Options::NONE);
		tracking_adapter.push_req(hash, mwc_chain::Options::MINE);

		tracking_adapter.restore_req(hash, failed_restore);

		assert_eq!(
			tracking_adapter.remove_req(hash),
			Some(mwc_chain::Options::MINE)
		);
	}

	#[test]
	fn next_request_id_restarts_from_zero_on_overflow() {
		let tracking_adapter = TrackingAdapter::new(0, Arc::new(DummyAdapter {}));
		tracking_adapter
			.next_request_id
			.store(u64::MAX, Ordering::Relaxed);

		let max_id = tracking_adapter.push_req(Hash::from_vec(&[4]), mwc_chain::Options::NONE);
		let zero_id = tracking_adapter.push_req(Hash::from_vec(&[5]), mwc_chain::Options::NONE);

		assert_eq!(max_id.inserted.id, u64::MAX);
		assert_eq!(zero_id.inserted.id, 0);
	}

	#[test]
	fn stop_records_request_while_connection_is_starting() {
		let peer = test_peer();
		*peer.connection.lock() = Some(PeerConnection::Starting {
			stop_requested: false,
		});

		peer.stop();

		match peer.connection.lock().as_ref() {
			Some(PeerConnection::Starting { stop_requested }) => assert!(*stop_requested),
			_ => panic!("expected starting connection"),
		};
	}

	#[test]
	fn wait_blocks_while_connection_is_starting() {
		let peer = Arc::new(test_peer());
		*peer.connection.lock() = Some(PeerConnection::Starting {
			stop_requested: false,
		});

		let (started_tx, started_rx) = mpsc::channel();
		let (wait_tx, wait_rx) = mpsc::channel();
		let wait_peer = peer.clone();
		let wait_thread = thread::spawn(move || {
			started_tx.send(()).unwrap();
			wait_tx.send(wait_peer.wait().is_ok()).unwrap();
		});
		started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
		assert!(matches!(
			wait_rx.recv_timeout(Duration::from_millis(50)),
			Err(mpsc::RecvTimeoutError::Timeout)
		));

		let (send_handle, stop_handle) = conn::disconnected_test_handles();
		{
			let mut connection = peer.connection.lock();
			*connection = Some(PeerConnection::Active(ActivePeerConnection {
				send_handle,
				stop_handle,
			}));
		}
		peer.connection_changed.notify_all();

		assert!(wait_rx.recv_timeout(Duration::from_secs(1)).unwrap());
		wait_thread.join().unwrap();
	}

	#[test]
	fn wait_times_out_if_connection_stays_starting() {
		let peer = test_peer();
		*peer.connection.lock() = Some(PeerConnection::Starting {
			stop_requested: false,
		});

		assert!(matches!(peer.wait(), Err(Error::Timeout)));
	}
}
