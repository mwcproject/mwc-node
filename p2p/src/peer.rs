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
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::conn;
use crate::handshake::Handshake;
use crate::msg::{
	self, ArchiveHeaderData, BanReason, GetPeerAddrs, HashHeadersData, Locator, Msg, Ping,
	SegmentRequest, Type,
};
use crate::protocol::Protocol;
use crate::tor::tcp_data_stream::TcpDataStream;
use crate::types::{Capabilities, Error, NetAdapter, P2PConfig, PeerAddr, PeerInfo, ReasonForBan};
use mwc_chain;
use mwc_chain::SyncState;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::SegmentIdentifier;
use mwc_core::pow::Difficulty;
use mwc_core::ser::Writeable;
use mwc_core::{core, global};
use mwc_crates::chrono::prelude::Utc;
use mwc_crates::log::{debug, info, trace};
use mwc_crates::lru::LruCache;
use mwc_util::LatencyTracker;

const MAX_PEER_MSG_PER_MIN: u64 = 1000;
const RECEIVED_CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(2500).unwrap();
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
	adapter: Arc<dyn NetAdapter>,
	// Hashes received from this peer, shared with the protocol to suppress rebroadcasts.
	received: Arc<RwLock<LruCache<Hash, ()>>>,
	tracker: Arc<conn::Tracker>,
	latency: Mutex<LatencyTracker>,
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
		let tracker = Arc::new(conn::Tracker::new());
		Peer {
			info,
			state,
			adapter,
			received: Arc::new(RwLock::new(LruCache::new(RECEIVED_CACHE_SIZE))),
			tracker,
			latency: Mutex::new(LatencyTracker::new()),
			connection: Mutex::new(None),
			connection_changed: Condvar::new(),
			context_id,
		}
	}

	/// Record only a complete response, measured from its request's send time.
	pub fn record_response_latency(&self, elapsed: Duration) {
		if let Ok(latency_ms) = i64::try_from(elapsed.as_millis()) {
			self.latency.lock().add_latency(latency_ms);
		}
	}

	pub fn response_latency(&self) -> Option<Duration> {
		self.latency.lock().get_average_latency()
	}

	/// Fix this budget when sending the request; partial responses do not renew it.
	pub fn request_timeout(&self) -> Duration {
		let maximum = Duration::from_secs(u64::from(
			mwc_chain::pibd_params::PIBD_REQUESTS_TIMEOUT_SECS,
		));
		self.latency.lock().get_time_out(maximum)
	}

	/// In-memory connection for cross-crate protocol/sync regression tests.
	#[cfg(any(test, feature = "test-support"))]
	pub fn connected_for_test(
		info: PeerInfo,
		context_id: u32,
		adapter: Arc<dyn NetAdapter>,
	) -> (Self, mwc_crates::crossbeam::channel::Receiver<Msg>) {
		let peer = Self::new(info, adapter, context_id);
		let (send_handle, stop_handle, receiver) = conn::test_handles();
		*peer.connection.lock() = Some(PeerConnection::Active(ActivePeerConnection {
			send_handle,
			stop_handle,
		}));
		(peer, receiver)
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

		let block_extra = self.info.is_block_extra();
		let handler = Protocol::new(
			self.adapter.clone(),
			self.info.clone(),
			server,
			self.received.clone(),
		);
		let (send_handle, stop_handle) = match conn::listen(
			conn,
			self.info.version,
			self.context_id,
			block_extra,
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

	/// Return advertised work, height and ping timeout from one live-info snapshot.
	pub fn check_liveness(&self) -> (Difficulty, u64, bool) {
		let peer_live_info = self.info.live_info.read_recursive();
		let now = Utc::now().timestamp();
		// Ten ping intervals without a response make a peer unresponsive.
		let dead_ping = (now - peer_live_info.last_seen.timestamp())
			> (global::PEER_PING_INTERVAL_SECONDS * 10) as i64;
		(
			peer_live_info.total_difficulty,
			peer_live_info.height,
			dead_ping,
		)
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
		let msg = Msg::new(
			msg_type,
			msg,
			self.info.version,
			self.context_id,
			self.info.is_block_extra(),
		)?;
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
		let has_received = self.received.read().contains(&block_hash);
		if !has_received {
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
		let has_received = self.received.read().contains(&header_hash);
		if !has_received {
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
		let has_received = self.received.read().contains(&h);
		if !has_received {
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

		let has_received = self
			.received
			.read()
			.contains(&kernel.hash(self.context_id)?);
		if !has_received {
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
	/// Note: the received cache is ignored for stem transactions (while under
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

	/// Feed decoded response fragments to the request owner in sync tests.
	#[cfg(any(test, feature = "test-support"))]
	pub fn receive_headers_for_test(
		&self,
		headers: &[core::BlockHeader],
		remaining: u64,
	) -> Result<(), mwc_chain::Error> {
		self.adapter
			.headers_received(headers, remaining, &self.info)
	}

	pub fn send_tx_request(&self, h: Hash) -> Result<(), Error> {
		debug!(
			"Requesting tx (kernel hash) {} from peer {}.",
			h, self.info.addr
		);
		self.send(&h, msg::Type::GetTransaction)
	}

	/// Sends a request for a specific block by hash.
	/// BodySync owns outstanding requests and response ordering.
	pub fn send_block_request(&self, h: Hash) -> Result<(), Error> {
		debug!("Requesting block {} from peer {}.", h, self.info.addr);
		self.send(&h, msg::Type::GetBlock)
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::serv::{set_dummy_adapter_liveness_deferred_for_test, DummyAdapter};
	use crate::types::{Direction, PeerLiveInfo};
	use mwc_core::core::TxKernel;
	use mwc_core::ser::ProtocolVersion;
	use mwc_crates::secp::Secp256k1;
	use std::net::SocketAddr;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::mpsc;
	use std::thread;
	use std::time::Duration;

	fn test_peer() -> Peer {
		test_peer_with_user_agent("test".to_string())
	}

	#[test]
	fn outbound_tip_updates_must_qualify_to_prevent_liveness_timeout() {
		// from_num(0) clamps to one; use an actual zero for invalid-work updates.
		let difficulty = |work| {
			if work == 0 {
				Difficulty::zero()
			} else {
				Difficulty::from_num(work)
			}
		};
		for direction in [
			Direction::Outbound,
			Direction::OutboundTor,
			Direction::Inbound,
			Direction::InboundTor,
		] {
			let mut peer = test_peer();
			peer.info.direction = direction;
			// Include both a fresh handshake and an established tip. Later replies
			// must meet the current stored work, even when a height is already known.
			for (old_height, old_work, height, work, refreshes_outbound) in [
				(0, 100, 0, 100, false),
				(10, 100, 0, 101, false),
				(0, 100, 11, 99, false),
				(10, 100, 11, 99, false),
				(0, 0, 1, 0, false),
				(0, 100, 11, 100, true),
				(10, 100, 12, 100, true),
				(0, 100, 11, 101, true),
				(10, 100, 8, 101, true),
			] {
				let last_seen = Utc::now()
					- mwc_crates::chrono::Duration::seconds(
						(global::PEER_PING_INTERVAL_SECONDS * 11) as i64,
					);
				{
					let mut info = peer.info.live_info.write();
					info.height = old_height;
					info.total_difficulty = difficulty(old_work);
					info.last_seen = last_seen;
				}
				peer.info.update(height, difficulty(work));
				if peer.info.is_outbound() && !refreshes_outbound {
					assert_eq!(
						peer.info.get_height_and_difficulty(),
						(old_height, difficulty(old_work)),
						"Rejected outbound updates must leave the stored tip unchanged"
					);
					assert_eq!(peer.info.last_seen(), last_seen);
				}
				assert_eq!(
					peer.check_liveness().2,
					peer.info.is_outbound() && !refreshes_outbound,
					"{:?}: stored ({}, {}), update ({}, {})",
					direction,
					old_height,
					old_work,
					height,
					work
				);
			}
		}
	}

	#[test]
	fn response_latency_is_independent_per_peer_and_connection() {
		let fast = test_peer();
		let mut slow = test_peer();
		slow.info.addr = PeerAddr::Onion(
			"oqtl7wlzukgp7r6kdp3uvyelzmc72ngknwd23lo7uw63rwornvcmg3yd.onion".into(),
		);
		// A fresh connection to the same address starts without the old history.
		let fresh = test_peer();
		fast.record_response_latency(Duration::from_millis(200));
		slow.record_response_latency(Duration::from_secs(12));
		assert_eq!(fast.request_timeout(), Duration::from_millis(8400));
		assert_eq!(slow.request_timeout(), Duration::from_secs(30));
		assert_eq!(fresh.request_timeout(), Duration::from_secs(30));
		for _ in 0..30 {
			fast.record_response_latency(Duration::from_millis(1));
		}
		assert_eq!(slow.request_timeout(), Duration::from_secs(30));
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

	fn connected_block_extra_peer(port: u16, fee: u64) -> Peer {
		let mut peer = connected_test_peer_with_addr_fee(port, fee);
		peer.info.capabilities = Capabilities::BLOCK_EXTRA;
		peer
	}

	fn connect_test_peer(peer: Peer) -> Peer {
		let (peer, receiver) = Peer::connected_for_test(peer.info, peer.context_id, peer.adapter);
		drop(receiver);
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
	fn compact_block_relay_skips_its_supplier() {
		// The protocol records a received compact hash before accepting its body.
		// A later acceptance broadcast must not queue the compact block back to
		// that same connection.
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		let (peer, receiver) =
			Peer::connected_for_test(test_peer().info, 0, Arc::new(DummyAdapter {}));
		let compact = core::CompactBlock::from(core::Block::default(0)).unwrap();
		let hash = compact.hash(0).unwrap();
		peer.received.write().put(hash, ());
		assert!(!peer.send_compact_block(&compact).unwrap());
		assert_eq!(receiver.try_iter().count(), 0);
	}

	#[test]
	fn compact_block_wire_format_uses_peer_capability() {
		use mwc_core::{consensus, ser};
		use mwc_crates::secp::s2c::Opening;

		global::set_local_chain_type(global::ChainTypes::Mainnet);
		let secp = Secp256k1::with_caps(mwc_crates::secp::ContextFlag::Commit).unwrap();
		let secret = mwc_crates::secp::SecretKey::from_slice(&secp, &[1; 32]).unwrap();
		let point = mwc_crates::secp::key::PublicKey::from_secret_key(&secp, &secret).unwrap();
		let opening =
			Opening::from_slice(&secp, &point.serialize_vec(&secp, true).unwrap()).unwrap();

		for remote in [Capabilities::UNKNOWN, Capabilities::BLOCK_EXTRA] {
			let mut info = test_peer().info;
			info.capabilities = remote;
			let peer = Peer::new(info, Arc::new(DummyAdapter {}), 0);
			let expected_extra = remote.contains(Capabilities::BLOCK_EXTRA);
			let (send_handle, stop_handle, receiver) = conn::test_handles();
			*peer.connection.lock() = Some(PeerConnection::Active(ActivePeerConnection {
				send_handle,
				stop_handle,
			}));

			for activated in [false, true] {
				let mut block = core::Block::default(0);
				block.header.height =
					consensus::COINBASE_BINDING_MAINNET_HEIGHT - u64::from(!activated);
				block.coinbase_opening = activated.then_some(opening);
				let compact = core::CompactBlock::from(block).unwrap();
				assert!(peer.send_compact_block(&compact).unwrap());
				let sent = receiver.try_recv().unwrap();
				let mut frame = Vec::new();
				msg::write_message(&mut frame, &vec![sent], peer.tracker.clone()).unwrap();
				let mut source = frame.as_slice();
				let version = ProtocolVersion::local();
				match msg::read_header(&mut source, version, 0, expected_extra).unwrap() {
					msg::MsgHeaderWrapper::Known(header) => {
						assert_eq!(header.msg_type, Type::CompactBlock);
						assert_eq!(header.msg_len, source.len());
					}
					_ => panic!("compact block must use its existing message type"),
				}
				let mut legacy = Vec::new();
				compact
					.write_no_opening(&mut ser::BinWriter::new(&mut legacy, version, 0, true))
					.unwrap();
				if expected_extra && activated {
					assert_eq!(source.len(), legacy.len() + 33);
					let restored: core::CompactBlock =
						ser::deserialize_strict(&mut source, version, 0, expected_extra).unwrap();
					assert_eq!(restored.coinbase_opening, Some(opening));
				} else {
					assert_eq!(source, legacy.as_slice());
				}
			}
		}
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
	fn block_supplier_eligibility_uses_requested_height_on_each_network() {
		for chain_type in [
			global::ChainTypes::Mainnet,
			global::ChainTypes::Floonet,
			global::ChainTypes::AutomatedTesting,
		] {
			global::set_local_chain_type(chain_type);
			let activation = mwc_core::consensus::coinbase_binding_activation_height(0);
			let mut peer = test_peer();
			peer.info.live_info.write().height = activation + 100;
			for capable in [false, true] {
				peer.info.capabilities = Capabilities::BLOCK_HIST;
				if capable {
					peer.info.capabilities |= Capabilities::BLOCK_EXTRA;
				}
				assert!(peer.info.can_serve_block(0, activation - 1));
				assert_eq!(peer.info.can_serve_block(0, activation), capable);
				assert_eq!(peer.info.can_serve_block(0, activation + 1), capable);
			}
		}
	}

	#[test]
	fn peer_discovery_and_outbound_target_follow_current_sync_stage() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_accept_fee_base(1000).unwrap();
		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let config = P2PConfig::default();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		// Discovery must work before any block-extra supplier has been found.
		for (boost, expected) in [
			(Capabilities::UNKNOWN, Capabilities::UNKNOWN),
			(Capabilities::HEADER_HIST, Capabilities::HEADER_HIST),
			(Capabilities::HEADERS_HASH, Capabilities::HEADERS_HASH),
			(Capabilities::PIBD_HIST, Capabilities::PIBD_HIST),
			(
				Capabilities::HEADER_HIST | Capabilities::BLOCK_EXTRA,
				Capabilities::HEADER_HIST,
			),
		] {
			peers.set_boost_peers_capabilities(boost);
			assert_eq!(peers.get_peer_discovery_capabilities(), expected);
			assert!(!peers.enough_outbound_peers());
		}

		let legacy_capabilities =
			Capabilities::HEADER_HIST | Capabilities::HEADERS_HASH | Capabilities::PIBD_HIST;
		for index in 0..config.peer_min_preferred_outbound_count(1, true) {
			let mut peer = connected_test_peer_with_addr_fee(3520 + index as u16, 0);
			peer.info.capabilities = legacy_capabilities;
			peers.add_connected(Arc::new(peer)).unwrap();
		}
		for boost in [
			Capabilities::HEADER_HIST,
			Capabilities::HEADERS_HASH,
			Capabilities::PIBD_HIST,
		] {
			peers.set_boost_peers_capabilities(boost);
			assert_eq!(peers.get_peer_discovery_capabilities(), boost);
			assert!(peers.enough_outbound_peers());
		}
	}

	#[test]
	fn clean_peers_does_not_reserve_block_extra_peers_during_header_or_pibd_sync() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for boost in [
			Capabilities::HEADER_HIST,
			Capabilities::HEADERS_HASH,
			Capabilities::PIBD_HIST,
		] {
			for supports_stage in [false, true] {
				let dir = mwc_crates::tempfile::TempDir::new().unwrap();
				let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
				let mut preferred = connected_test_peer_with_addr_fee(3546, 0);
				preferred.info.capabilities = boost;
				let preferred = Arc::new(preferred);
				let mut extra = connected_block_extra_peer(3547, 0);
				if supports_stage {
					extra.info.capabilities |= boost;
				}
				let extra = Arc::new(extra);
				let mut config = P2PConfig::default();
				config.peer_max_outbound_count = Some(1);
				config.peers_preferred = Some(crate::msg::PeerAddrs {
					peers: vec![preferred.info.addr.clone()],
				});
				let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
				peers.add_connected(preferred.clone()).unwrap();
				peers.add_connected(extra.clone()).unwrap();

				// Boost removes an unsuitable peer; capacity removes the excess suitable
				// peer. BLOCK_EXTRA must not exempt either from the normal rules.
				let summary = peers.clean_peers(10, 1, boost, config);

				assert_eq!(summary.removed_peers, 1);
				assert!(peers.is_known(&preferred.info.addr));
				assert!(!peers.is_known(&extra.info.addr));
			}
		}
	}

	#[test]
	fn clean_peers_respects_zero_and_single_outbound_capacity() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for (normal_limit, current_limit) in [(0, 0), (1, 1), (10, 0), (10, 1)] {
			let dir = mwc_crates::tempfile::TempDir::new().unwrap();
			let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
			let mut config = P2PConfig::default();
			config.peer_max_outbound_count = Some(normal_limit);
			let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
			for port in 3528..3530 {
				peers
					.add_connected(Arc::new(connected_block_extra_peer(port, 0)))
					.unwrap();
			}

			let summary = peers.clean_peers(10, current_limit, Capabilities::UNKNOWN, config);

			assert_eq!(summary.removed_peers as usize, 2 - current_limit);
			assert_eq!(peers.iter().outbound().connected().count(), current_limit);
		}
	}

	#[test]
	fn clean_peers_applies_health_and_capacity_cleanup_to_all_connections() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for direction in [Direction::Inbound, Direction::Outbound] {
			let dir = mwc_crates::tempfile::TempDir::new().unwrap();
			let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
			let mut dead = connected_block_extra_peer(3540, 0);
			let mut excess = connected_block_extra_peer(3541, 0);
			let mut preferred = connected_block_extra_peer(3542, 0);
			dead.info.direction = direction;
			excess.info.direction = direction;
			preferred.info.direction = direction;
			let (dead, excess, preferred) = (Arc::new(dead), Arc::new(excess), Arc::new(preferred));
			let mut config = P2PConfig::default();
			config.peer_max_outbound_count = Some(1);
			config.peers_preferred = Some(crate::msg::PeerAddrs {
				peers: vec![preferred.info.addr.clone()],
			});
			let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
			for peer in [&dead, &excess, &preferred] {
				peers.add_connected(peer.clone()).unwrap();
			}
			dead.set_defunct();

			let summary = peers.clean_peers(1, 1, Capabilities::UNKNOWN, config);

			assert_eq!(summary.removed_peers, 2);
			assert!(!peers.is_known(&dead.info.addr));
			assert!(!peers.is_known(&excess.info.addr));
			assert!(peers.is_known(&preferred.info.addr));
			assert_eq!(
				peers.get_peer(&dead.info.addr).unwrap().flags,
				crate::store::State::Defunct
			);
		}
	}

	#[test]
	fn zero_height_replies_do_not_keep_outbound_connections_alive() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for direction in [Direction::Outbound, Direction::OutboundTor] {
			let mut peer = connected_test_peer();
			peer.info.direction = direction;
			peer.info.live_info.write().last_seen = Utc::now()
				- mwc_crates::chrono::Duration::seconds(
					(global::PEER_PING_INTERVAL_SECONDS * 11) as i64,
				);
			let peer = Arc::new(peer);
			let dir = mwc_crates::tempfile::TempDir::new().unwrap();
			let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
			let mut config = P2PConfig::default();
			config.peers_preferred = Some(crate::msg::PeerAddrs {
				peers: vec![peer.info.addr.clone()],
			});
			let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
			peers.add_connected(peer.clone()).unwrap();
			for _ in 0..3 {
				peer.info.update(0, Difficulty::min());
			}
			// Health cleanup also removes a preferred peer and the last outbound.
			let summary = peers.clean_peers(10, 10, Capabilities::UNKNOWN, config);
			assert_eq!(summary.removed_peers, 1);
			assert!(!peer.is_connected());
			assert_eq!(
				peers.get_peer(&peer.info.addr).unwrap().flags,
				crate::store::State::Defunct
			);
			assert!(!peers.is_banned(&peer.info.addr).unwrap());
		}
	}

	#[test]
	fn clean_peers_counts_dead_peer_removal_before_capacity_cleanup() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for direction in [Direction::Inbound, Direction::Outbound] {
			let dir = mwc_crates::tempfile::TempDir::new().unwrap();
			let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
			let mut dead = connected_test_peer_with_addr_fee(3550, 0);
			let mut healthy = connected_test_peer_with_addr_fee(3551, 0);
			dead.info.direction = direction;
			healthy.info.direction = direction;
			dead.info.capabilities = Capabilities::HEADER_HIST;
			healthy.info.capabilities = Capabilities::HEADER_HIST;
			dead.info.live_info.write().last_seen = mwc_crates::chrono::Utc::now()
				- mwc_crates::chrono::Duration::seconds(
					(global::PEER_PING_INTERVAL_SECONDS as i64) * 11,
				);
			let (dead, healthy) = (Arc::new(dead), Arc::new(healthy));
			let mut config = P2PConfig::default();
			// A preferred dead peer cannot be selected for capacity eviction. Counting
			// its pending removal twice would therefore evict the healthy peer too.
			config.peers_preferred = Some(crate::msg::PeerAddrs {
				peers: vec![dead.info.addr.clone()],
			});
			let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
			peers.add_connected(dead.clone()).unwrap();
			peers.add_connected(healthy.clone()).unwrap();

			let summary = peers.clean_peers(1, 1, Capabilities::HEADER_HIST, config);

			assert_eq!(summary.removed_peers, 1);
			assert!(!peers.is_known(&dead.info.addr));
			assert!(peers.is_known(&healthy.info.addr));
		}
	}

	#[test]
	fn clean_peers_keeps_legacy_outbound_before_activation_in_every_stage() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for required_capabilities in [
			Capabilities::UNKNOWN,
			Capabilities::HEADER_HIST | Capabilities::BLOCK_EXTRA,
		] {
			let dir = mwc_crates::tempfile::TempDir::new().unwrap();
			let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
			let legacy_capabilities =
				Capabilities::HEADER_HIST | Capabilities::HEADERS_HASH | Capabilities::PIBD_HIST;
			let mut preferred = connected_test_peer_with_addr_fee(3552, 0);
			let mut legacy = connected_test_peer_with_addr_fee(3553, 0);
			let mut capable = connected_test_peer_with_addr_fee(3554, 0);
			let mut inbound = connected_test_peer_with_addr_fee(3555, 0);
			for peer in [&mut preferred, &mut legacy, &mut capable, &mut inbound] {
				peer.info.capabilities = legacy_capabilities;
			}
			capable.info.capabilities |= Capabilities::BLOCK_EXTRA;
			inbound.info.direction = Direction::Inbound;
			let (preferred, legacy, capable, inbound) = (
				Arc::new(preferred),
				Arc::new(legacy),
				Arc::new(capable),
				Arc::new(inbound),
			);
			let mut config = P2PConfig::default();
			config.peers_preferred = Some(crate::msg::PeerAddrs {
				peers: vec![preferred.info.addr.clone()],
			});
			let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
			for peer in [&preferred, &legacy, &capable, &inbound] {
				peers.add_connected(peer.clone()).unwrap();
			}

			// Legacy connections remain useful during header and PIBD synchronization.
			for boost in [
				Capabilities::HEADER_HIST,
				Capabilities::HEADERS_HASH,
				Capabilities::PIBD_HIST,
			] {
				let summary = peers.clean_peers(10, 10, boost, config.clone_without_secrets());
				assert_eq!(summary.removed_peers, 0);
				assert_eq!(peers.iter().connected().count(), 4);
			}

			// Missing block extras alone no longer disconnects a healthy peer.
			let summary = peers.clean_peers(10, 10, required_capabilities, config);

			assert_eq!(summary.removed_peers, 0);
			for peer in [&preferred, &legacy] {
				assert!(peers.is_known(&peer.info.addr));
				assert!(!peer.is_banned());
				assert_eq!(
					peers.get_peer(&peer.info.addr).unwrap().flags,
					crate::store::State::Healthy
				);
			}
			assert!(peers.is_known(&capable.info.addr));
			assert!(peers.is_known(&inbound.info.addr));
			assert_eq!(peers.iter().connected().count(), 4);
		}
	}

	// Supply one body-head snapshot to cleanup while controlling the activation height.
	fn cleanup_test_head(height: u64) -> core::BlockHeader {
		let mut head = core::BlockHeader::default(1);
		head.height = height;
		head
	}

	#[test]
	fn activation_rotation_preserves_capable_preferred_and_underfilled_pools() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for boost in [
			Capabilities::UNKNOWN,
			Capabilities::PIBD_HIST,
			Capabilities::HEADER_HIST,
		] {
			let dir = mwc_crates::tempfile::TempDir::new().unwrap();
			let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
			let mut config = P2PConfig::default();
			config.peer_min_preferred_outbound_count = Some(8);
			let preferred = test_peer_with_addr_fee(3707, 0).info.addr;
			config.peers_preferred = Some(crate::msg::PeerAddrs {
				peers: vec![preferred.clone()],
			});
			let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
			for index in 0..12 {
				let mut peer = connected_test_peer_with_addr_fee(3700 + index, 0);
				peer.info.capabilities = boost;
				if index < 3 || index >= 8 {
					peer.info.capabilities |= Capabilities::BLOCK_EXTRA;
				}
				if index >= 8 {
					peer.info.direction = Direction::Inbound;
				}
				peers.add_connected(Arc::new(peer)).unwrap();
			}
			let now = Instant::now();
			let activation = mwc_core::consensus::COINBASE_BINDING_TESTING_HEIGHT;
			assert_eq!(
				peers
					.clean_peers_at(
						20,
						10,
						boost,
						config.clone(),
						now,
						Some(cleanup_test_head(activation - 1))
					)
					.removed_peers,
				0
			);
			// Reaching activation with the body head enables the capability preference.
			let result = peers.clean_peers_at(
				20,
				10,
				boost,
				config.clone(),
				now,
				Some(cleanup_test_head(activation)),
			);
			assert_eq!(result.rotated_outbound_peers.len(), 2);
			assert_eq!(result.outbound_replacement_attempts, 2);
			assert_eq!(peers.iter().outbound().connected().count(), 6);
			assert_eq!(
				peers
					.iter()
					.outbound()
					.connected()
					.with_capabilities(Capabilities::BLOCK_EXTRA)
					.count(),
				3
			);
			assert_eq!(peers.iter().inbound().connected().count(), 4);
			assert!(peers.is_known(&preferred));
			for addr in result.rotated_outbound_peers {
				assert_eq!(
					peers.get_peer(&addr).unwrap().flags,
					crate::store::State::Healthy
				);
				assert!(!peers.is_banned(&addr).unwrap());
			}
			// Even an overdue timer must not drain the six remaining peers.
			assert_eq!(
				peers
					.clean_peers_at(
						20,
						10,
						boost,
						config,
						now + Duration::from_secs(1200),
						Some(cleanup_test_head(activation))
					)
					.removed_peers,
				0
			);
		}
	}

	#[test]
	fn capacity_cleanup_rechecks_block_extra_share_after_each_removal() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let mut config = P2PConfig::default();
		config.peer_min_preferred_outbound_count = Some(6);
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		for index in 0..8 {
			let mut peer = connected_test_peer_with_addr_fee(3750 + index, 0);
			peer.info.capabilities = if index < 4 {
				Capabilities::BLOCK_EXTRA
			} else {
				Capabilities::PIBD_HIST
			};
			peers.add_connected(Arc::new(peer)).unwrap();
		}
		// The sync quota selects an extra-capable peer first. The second capacity
		// eviction must select a legacy peer now that only 3 of 7 support extras.
		let result = peers.clean_peers_at(
			10,
			6,
			Capabilities::PIBD_HIST,
			config,
			Instant::now(),
			Some(cleanup_test_head(
				mwc_core::consensus::COINBASE_BINDING_TESTING_HEIGHT,
			)),
		);
		assert_eq!(result.rotated_outbound_peers.len(), 2);
		assert_eq!(result.outbound_replacement_attempts, 0);
		assert_eq!(peers.iter().outbound().connected().count(), 6);
		assert_eq!(
			peers
				.iter()
				.outbound()
				.connected()
				.with_capabilities(Capabilities::BLOCK_EXTRA)
				.count(),
			3
		);
	}

	#[test]
	fn outbound_rotation_waits_ten_minutes_and_does_not_stack_triggers() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let mut config = P2PConfig::default();
		config.peer_min_preferred_outbound_count = Some(3);
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		for port in 3720..3723 {
			peers
				.add_connected(Arc::new(connected_test_peer_with_addr_fee(port, 0)))
				.unwrap();
		}
		let now = Instant::now();
		assert_eq!(
			peers
				.clean_peers_at(
					10,
					10,
					Capabilities::UNKNOWN,
					config.clone(),
					now + Duration::from_secs(599),
					Some(cleanup_test_head(0))
				)
				.removed_peers,
			0
		);
		// Inbound churn must not reset or suppress the outbound rotation timer.
		let mut inbound = connected_test_peer_with_addr_fee(3727, 0);
		inbound.info.direction = Direction::Inbound;
		inbound.set_defunct();
		peers.add_connected(Arc::new(inbound)).unwrap();
		let result = peers.clean_peers_at(
			10,
			10,
			Capabilities::UNKNOWN,
			config.clone(),
			now + Duration::from_secs(600),
			Some(cleanup_test_head(0)),
		);
		assert_eq!(result.removed_peers, 2);
		assert_eq!(result.rotated_outbound_peers.len(), 1);
		assert_eq!(result.outbound_replacement_attempts, 1);
		peers
			.add_connected(Arc::new(connected_test_peer_with_addr_fee(3723, 0)))
			.unwrap();
		assert_eq!(
			peers
				.clean_peers_at(
					10,
					10,
					Capabilities::UNKNOWN,
					config.clone(),
					now + Duration::from_secs(1199),
					Some(cleanup_test_head(0))
				)
				.removed_peers,
			0
		);
		// Capacity, activation imbalance and the timer all apply, but share one budget.
		for port in 3724..3727 {
			peers
				.add_connected(Arc::new(connected_test_peer_with_addr_fee(port, 0)))
				.unwrap();
		}
		let result = peers.clean_peers_at(
			10,
			3,
			Capabilities::UNKNOWN,
			config,
			now + Duration::from_secs(1200),
			Some(cleanup_test_head(4)),
		);
		assert_eq!(result.rotated_outbound_peers.len(), 2);
		assert_eq!(result.outbound_replacement_attempts, 0);
		assert_eq!(peers.iter().outbound().connected().count(), 4);
	}

	#[test]
	fn rotation_exempts_preferred_peers_and_keeps_last_connection() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		for count in [1, 3] {
			let dir = mwc_crates::tempfile::TempDir::new().unwrap();
			let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
			let mut config = P2PConfig::default();
			config.peer_min_preferred_outbound_count = Some(1);
			if count > 1 {
				config.peers_preferred = Some(crate::msg::PeerAddrs {
					peers: (3740..3743)
						.map(|port| test_peer_with_addr_fee(port, 0).info.addr)
						.collect(),
				});
			}
			let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
			for port in 3740..3740 + count {
				peers
					.add_connected(Arc::new(connected_test_peer_with_addr_fee(port, 0)))
					.unwrap();
			}
			let result = peers.clean_peers_at(
				10,
				10,
				Capabilities::UNKNOWN,
				config,
				Instant::now() + Duration::from_secs(601),
				Some(cleanup_test_head(4)),
			);
			assert_eq!(result.removed_peers, 0);
		}
	}

	#[test]
	fn clean_peers_keeps_peers_when_sync_boost_quota_is_already_satisfied() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let config = P2PConfig::default();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		for port in 3560..3570 {
			let mut peer = connected_test_peer_with_addr_fee(port, 0);
			if port < 3565 {
				peer.info.capabilities = Capabilities::PIBD_HIST;
			}
			peers.add_connected(Arc::new(peer)).unwrap();
		}

		let summary = peers.clean_peers(10, 10, Capabilities::PIBD_HIST, config);

		assert_eq!(summary.removed_peers, 0);
		assert_eq!(peers.iter().outbound().connected().count(), 10);
	}

	#[test]
	fn clean_peers_counts_sync_boost_removals_before_capacity_cleanup() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let config = P2PConfig::default();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		for port in 3570..3576 {
			let mut peer = connected_test_peer_with_addr_fee(port, 0);
			if port < 3572 {
				peer.info.capabilities = Capabilities::PIBD_HIST;
			}
			peers.add_connected(Arc::new(peer)).unwrap();
		}

		let summary = peers.clean_peers(10, 4, Capabilities::PIBD_HIST, config);

		assert_eq!(summary.removed_peers, 2);
		assert_eq!(peers.iter().outbound().connected().count(), 4);
		assert_eq!(
			peers
				.iter()
				.outbound()
				.connected()
				.with_capabilities(Capabilities::PIBD_HIST)
				.count(),
			2
		);
	}

	#[test]
	fn clean_peers_limits_outbound_capacity_evictions_and_preserves_preferred_peer() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let mut preferred = connected_test_peer_with_addr_fee(3580, 0);
		preferred.info.capabilities = Capabilities::HEADER_HIST;
		let preferred = Arc::new(preferred);
		let mut config = P2PConfig::default();
		config.peers_preferred = Some(crate::msg::PeerAddrs {
			peers: vec![preferred.info.addr.clone()],
		});
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		peers.add_connected(preferred.clone()).unwrap();
		for port in 3581..3585 {
			let mut peer = connected_test_peer_with_addr_fee(port, 0);
			peer.info.capabilities = Capabilities::HEADER_HIST;
			peers.add_connected(Arc::new(peer)).unwrap();
		}

		for remaining in [3, 1] {
			let summary = peers.clean_peers(
				10,
				1,
				Capabilities::HEADER_HIST,
				config.clone_without_secrets(),
			);
			assert_eq!(summary.removed_peers, 2);
			assert_eq!(peers.iter().outbound().connected().count(), remaining);
			assert!(peers.is_known(&preferred.info.addr));
		}
	}

	#[test]
	fn enough_outbound_peers_requires_one_fee_match_for_minimum_one() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		global::set_local_accept_fee_base(1000).unwrap();

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let mut config = P2PConfig::default();
		config.peer_min_preferred_outbound_count = Some(1);
		config.peer_max_outbound_count = Some(1);
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		let peer = Arc::new(connected_block_extra_peer(3500, 2000));
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
				.add_connected(Arc::new(connected_block_extra_peer(port, tx_base_fee)))
				.unwrap();
		}

		assert!(!peers.enough_outbound_peers());

		peers
			.add_connected(Arc::new(connected_block_extra_peer(3515, 500)))
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
	fn clean_peers_bans_abusive_peers_after_disconnect() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		for defunct in [false, true] {
			for abusive in [false, true] {
				let dir = mwc_crates::tempfile::TempDir::new().unwrap();
				let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
				let config = P2PConfig::default();
				let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
				let peer = Arc::new(connected_test_peer());
				let addr = peer.info.addr.clone();
				peers.add_connected(peer.clone()).unwrap();
				for _ in 0..MAX_PEER_MSG_PER_MIN + u64::from(abusive) {
					peer.tracker().inc_received(16);
				}

				// A remote disconnect or connection failure must not erase an abuse ban.
				peer.stop();
				if defunct {
					peer.set_defunct();
				}
				assert!(!peer.is_connected());

				let summary = peers.clean_peers(10, 10, Capabilities::UNKNOWN, config);

				assert_eq!(summary.removed_peers, 1);
				assert_eq!(summary.persistence_failures, 0);
				assert!(!peers.is_known(&addr));
				let expected = if abusive {
					crate::store::State::Banned
				} else if defunct {
					crate::store::State::Defunct
				} else {
					crate::store::State::Healthy
				};
				assert_eq!(
					peers.get_peer(&addr).unwrap().flags,
					expected,
					"defunct={defunct}, abusive={abusive}"
				);
				if abusive {
					assert!(peers
						.add_connected(Arc::new(connected_test_peer()))
						.is_err());
				}
			}
		}
	}

	#[test]
	fn clean_peers_bans_abusive_peer_after_store_pruning() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = crate::store::PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let config = P2PConfig::default();
		let peers = crate::Peers::new(store, Arc::new(DummyAdapter {}), &config);
		let peer = Arc::new(connected_block_extra_peer(3414, 0));
		let addr = peer.info.addr.clone();
		peers.add_connected(peer.clone()).unwrap();
		let stored_peer = peers.get_peer(&addr).unwrap();

		// Fill the 3,000-entry cache with newer healthy peers so normal pruning
		// evicts the older record while its connection remains alive.
		let newer_peers = (4000..7000)
			.map(|port| crate::store::PeerData {
				addr: PeerAddr::Ip(SocketAddr::from(([127, 0, 0, 1], port))),
				last_connected: stored_peer.last_connected + 1,
				..stored_peer.clone()
			})
			.collect();
		peers.save_peers(newer_peers).unwrap();
		assert!(!peers.exists_peer(&addr).unwrap());
		assert!(peer.is_connected());
		assert!(peers.is_known(&addr));

		for _ in 0..=MAX_PEER_MSG_PER_MIN {
			peer.tracker().inc_received(16);
		}
		let summary = peers.clean_peers(10, 10, Capabilities::UNKNOWN, config);

		assert_eq!(summary.removed_peers, 1);
		assert_eq!(summary.persistence_failures, 0);
		assert!(summary.first_persistence_error().is_none());
		assert!(!peer.is_connected());
		assert!(!peers.is_known(&addr));
		let banned = peers.get_peer(&addr).unwrap();
		assert_eq!(banned.flags, crate::store::State::Banned);
		assert_eq!(banned.ban_reason, ReasonForBan::BadRequest);
		assert!(banned.last_banned > 0);
		assert!(matches!(
			peers.add_connected(Arc::new(connected_block_extra_peer(3414, 0))),
			Err(Error::ConnectionClose(_))
		));
		assert!(!peers.is_known(&addr));
		assert!(peers.is_banned(&addr).unwrap());
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
	fn clean_peers_preserves_dead_ping_peer_across_deferred_cleanup_passes() {
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
		let peer = Arc::new(connected_block_extra_peer(3414, 0));
		let addr = peer.info.addr.clone();
		peer.info.live_info.write().last_seen = mwc_crates::chrono::Utc::now()
			- mwc_crates::chrono::Duration::seconds(
				(global::PEER_PING_INTERVAL_SECONDS as i64) * 11,
			);
		peers.add_connected(peer).unwrap();

		// This exceeds the former five-pass performance-strike threshold. Deferred
		// liveness must not accumulate state that eventually evicts the peer.
		for _ in 0..6 {
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
	fn failed_header_request_send_returns_error() {
		let peer = test_peer();
		assert!(peer
			.send_header_request(vec![Hash::from_vec(&[22])])
			.is_err());
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
