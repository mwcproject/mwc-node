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

use mwc_crates::chrono;
use mwc_crates::parking_lot::{Mutex, RwLock};
use mwc_crates::rand;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration as StdDuration, Instant};
use std::{cmp, mem};

use mwc_crates::rand::prelude::*;

use crate::msg::PeerAddrs;
use crate::peer::Peer;
use crate::store::{PeerData, PeerStore, State};
use crate::types::{
	BroadcastError, Capabilities, ChainAdapter, Error, NetAdapter, P2PConfig, PeerAddr,
	PeerAdvertised, PeerInfo, ReasonForBan, MAX_PEER_ADDRS,
};
use mwc_chain;
use mwc_chain::txhashset::BitmapChunk;
use mwc_chain::txhashset::Segmenter;
use mwc_core::core;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::{OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use mwc_core::global;
use mwc_core::map_vec;
use mwc_core::pow::Difficulty;
use mwc_crates::chrono::prelude::*;
use mwc_crates::chrono::Duration;
use mwc_crates::log::{debug, error, info, trace, warn};
use mwc_crates::secp::pedersen::RangeProof;
use mwc_crates::secp::Secp256k1;

struct PeersCapabilities {
	capabilities: Capabilities,
	time: Option<Instant>,
}

struct AdvertisedPeerSourceLimit {
	window_start: i64,
	accepted: usize,
}

// 10 minutes is should be enough for historical data
const ADVERTISED_PEERS_HISTORY: i64 = 600;
const MAX_ADVERTISED_PEERS: usize = 100;
const MAX_ADVERTISED_PEER_SOURCE_LIMITS: usize = 1000;
const MAX_ADVERTISED_PEERS_PER_SOURCE_PER_HOUR: usize = 100;
const ADVERTISED_PEERS_SOURCE_LIMIT_WINDOW: i64 = 60 * 60;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BroadcastSummary {
	pub(crate) sent: u32,
	pub(crate) peer_failures: u32,
}

#[derive(Debug, Default)]
pub struct PeerCheckSummary {
	pub ping_failures: u32,
	pub persistence_failures: u32,
	first_persistence_error: Option<Error>,
}

impl PeerCheckSummary {
	fn record_persistence_failure(&mut self, err: Error) {
		self.persistence_failures += 1;
		if self.first_persistence_error.is_none() {
			self.first_persistence_error = Some(err);
		}
	}

	pub fn first_persistence_error(&self) -> Option<&Error> {
		self.first_persistence_error.as_ref()
	}

	pub fn into_first_persistence_error(self) -> Option<Error> {
		self.first_persistence_error
	}
}

#[derive(Debug, Default)]
pub struct PeerCleanupSummary {
	pub removed_peers: u32,
	pub persistence_failures: u32,
	first_persistence_error: Option<Error>,
}

impl PeerCleanupSummary {
	fn record_persistence_failure(&mut self, err: Error) {
		self.persistence_failures += 1;
		if self.first_persistence_error.is_none() {
			self.first_persistence_error = Some(err);
		}
	}

	pub fn first_persistence_error(&self) -> Option<&Error> {
		self.first_persistence_error.as_ref()
	}

	pub fn into_first_persistence_error(self) -> Option<Error> {
		self.first_persistence_error
	}
}

pub struct Peers {
	pub adapter: Arc<dyn ChainAdapter>,
	store: PeerStore,
	peers: RwLock<HashMap<PeerAddr, Arc<Peer>>>,
	last_add_peer_timestamp: RwLock<Option<Instant>>,
	config: P2PConfig,
	// Peers removed from the live map but whose connection threads still need
	// to be joined. Holding them here preserves the StopHandle until the reader
	// thread drops its Codec and any Tor read-half active object.
	stopped_peers: Mutex<Vec<Arc<Peer>>>,
	boost_peers_capabilities: RwLock<PeersCapabilities>,
	excluded_peers: Arc<RwLock<HashSet<PeerAddr>>>,
	out_peers_failures: Arc<RwLock<HashMap<PeerAddr, u32>>>,
	advertised_peers: Arc<RwLock<HashMap<PeerAddr, PeerAdvertised>>>,
	advertised_peer_source_limits: Arc<RwLock<HashMap<PeerAddr, AdvertisedPeerSourceLimit>>>,
}

impl Peers {
	pub fn new(store: PeerStore, adapter: Arc<dyn ChainAdapter>, config: &P2PConfig) -> Peers {
		Peers {
			adapter,
			store,
			config: config.clone_without_secrets(),
			peers: RwLock::new(HashMap::new()),
			stopped_peers: Mutex::new(Vec::new()),
			last_add_peer_timestamp: RwLock::new(None),
			boost_peers_capabilities: RwLock::new(PeersCapabilities {
				capabilities: Capabilities::UNKNOWN,
				time: None,
			}),
			excluded_peers: Arc::new(RwLock::new(HashSet::new())),
			out_peers_failures: Arc::new(RwLock::new(HashMap::new())),
			advertised_peers: Arc::new(RwLock::new(HashMap::new())),
			advertised_peer_source_limits: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	/// Mark those peers as excluded, so the will never be in 'connected' list
	pub fn set_excluded_peers(&self, peers: &Vec<PeerAddr>) {
		let mut excluded_peers = self.excluded_peers.write();
		excluded_peers.clear();
		for p in peers {
			excluded_peers.insert(p.clone());
		}
	}

	pub fn set_boost_peers_capabilities(&self, boost_peers_capabilities: Capabilities) {
		let mut bpc = self.boost_peers_capabilities.write();
		if bpc.capabilities != boost_peers_capabilities {
			*bpc = PeersCapabilities {
				capabilities: boost_peers_capabilities,
				time: Some(Instant::now()),
			}
		}
	}

	/// Boosting required fast peers num increasing, so it is limited by time
	pub fn is_boosting_mode(&self) -> bool {
		let boost_peers_capabilities = self.boost_peers_capabilities.read_recursive();
		if boost_peers_capabilities.capabilities == Capabilities::UNKNOWN {
			return false;
		}
		boost_peers_capabilities
			.time
			.map_or(false, |time| time.elapsed() < StdDuration::from_secs(120))
	}

	pub fn is_sync_mode(&self) -> bool {
		self.get_boost_peers_capabilities() != Capabilities::UNKNOWN
	}

	pub fn get_boost_peers_capabilities(&self) -> Capabilities {
		self.boost_peers_capabilities
			.read_recursive()
			.capabilities
			.clone()
	}

	/// Number of peers that already has connection. The total number of connections needs tobe be limited
	pub fn get_number_connected_peers(&self) -> usize {
		self.peers.read_recursive().len()
	}

	/// Adds the peer to our internal peer mapping. Note that the peer is still
	/// returned so the server can run it.
	///
	/// Connection-count limits are enforced by callers as a soft admission
	/// guard. This method only enforces address uniqueness under the live-map
	/// lock; temporary spikes above the configured connection limit are
	/// acceptable and are reduced by normal peer cleanup.
	pub fn add_connected(&self, peer: Arc<Peer>) -> Result<(), Error> {
		let peer_data = PeerData {
			addr: peer.info.addr.clone(),
			capabilities: peer.info.capabilities,
			user_agent: peer.info.user_agent.clone(),
			flags: State::Healthy,
			last_banned: 0,
			ban_reason: ReasonForBan::None,
			last_connected: Utc::now().timestamp(),
			version: peer.info.version,
		};
		info!("Adding newly connected Healthy peer {}.", peer_data.addr);
		{
			// Scope for peers vector lock - dont hold the peers lock while adding to lmdb
			let mut peers = self.peers.write();
			if peers.contains_key(&peer_data.addr) {
				return Err(Error::ConnectionClose(format!(
					"Peer {} already connected",
					peer_data.addr
				)));
			}
			peers.insert(peer_data.addr.clone(), peer.clone());
		}
		match self.save_peer(&peer_data) {
			Ok(true) => {}
			Ok(false) => {
				info!(
					"Refusing to add banned peer {} as connected.",
					peer_data.addr
				);
				let mut peers = self.peers.write();
				if peers
					.get(&peer_data.addr)
					.map_or(false, |current| Arc::ptr_eq(current, &peer))
				{
					peers.remove(&peer_data.addr);
				}
				return Err(Error::ConnectionClose(format!(
					"Peer {} denied because it is banned",
					peer_data.addr
				)));
			}
			Err(e) => {
				error!("Could not save connected peer address: {:?}", e);
				let mut peers = self.peers.write();
				if peers
					.get(&peer_data.addr)
					.map_or(false, |current| Arc::ptr_eq(current, &peer))
				{
					peers.remove(&peer_data.addr);
				}
				return Err(e);
			}
		}
		// Reset success outbound counter, so seed thread can boost peers connections if needed
		if peer.info.is_outbound() {
			self.reset_last_peer_add_timestamp();
		}
		Ok(())
	}

	/// Reset the last added time, so we could start counting non active time
	pub fn reset_last_peer_add_timestamp(&self) {
		*self.last_add_peer_timestamp.write() = Some(Instant::now());
	}

	/// Whether an outbound peer was added recently.
	pub fn was_peer_added_within(&self, seconds: u64) -> bool {
		self.last_add_peer_timestamp
			.read_recursive()
			.map_or(false, |time| {
				time.elapsed() < StdDuration::from_secs(seconds)
			})
	}

	/// Add a peer as banned to block future connections, usually due to failed
	/// handshake
	pub fn add_banned(
		&self,
		addr: PeerAddr,
		ban_reason: ReasonForBan,
		ban_message: &str,
	) -> Result<(), Error> {
		let peer_data = match self.get_peer(&addr) {
			Ok(peer) => PeerData {
				addr: addr.clone(),
				capabilities: peer.capabilities,
				user_agent: peer.user_agent,
				flags: State::Banned,
				last_banned: Utc::now().timestamp(),
				ban_reason,
				last_connected: peer.last_connected,
				version: peer.version,
			},
			Err(Error::Store(e)) if e.store_error_is_not_found() => PeerData {
				addr: addr.clone(),
				capabilities: Capabilities::UNKNOWN,
				user_agent: "".to_string(),
				flags: State::Banned,
				last_banned: Utc::now().timestamp(),
				ban_reason,
				last_connected: Utc::now().timestamp(),
				version: mwc_core::ser::ProtocolVersion(1),
			},
			Err(e) => return Err(e),
		};
		info!(
			"Banning peer {}, ban_reason={:?}, ban_message={}",
			addr, ban_reason, ban_message
		);
		self.save_peer(&peer_data).map(|_| ())
	}

	/// Check if this peer address is already known (are we already connected to it)?
	/// We try to get the read lock but if we experience contention
	/// and this attempt fails then return an error allowing the caller
	/// to decide how best to handle this.
	pub fn is_known(&self, addr: &PeerAddr) -> bool {
		self.peers.read_recursive().contains_key(addr)
	}

	/// Iterator over our current peers.
	/// This allows us to hide try_read_for() behind a cleaner interface.
	/// PeersIter lets us chain various adaptors for convenience.
	pub fn iter(&self) -> PeersIter<impl Iterator<Item = Arc<Peer>>> {
		let excluded_peers = self.excluded_peers.read_recursive();
		let peers: Vec<Arc<Peer>> = self
			.peers
			.read_recursive()
			.values()
			.filter(|p| !excluded_peers.contains(&p.info.addr))
			.cloned()
			.collect();

		PeersIter {
			iter: peers.into_iter(),
		}
	}

	/// Get a peer we're connected to by address.
	pub fn get_connected_peer(&self, addr: &PeerAddr) -> Option<Arc<Peer>> {
		self.iter().connected().by_addr(addr)
	}

	/// Remove a peer from the live map without changing its persisted state.
	pub fn remove_connected(&self, addr: &PeerAddr) -> Option<Arc<Peer>> {
		self.peers.write().remove(addr)
	}

	pub(crate) fn is_connected_same(&self, peer: &Arc<Peer>) -> bool {
		self.peers
			.read_recursive()
			.get(&peer.info.addr)
			.map_or(false, |current| Arc::ptr_eq(current, peer))
	}

	pub(crate) fn remove_connected_if_same(&self, peer: &Arc<Peer>) -> bool {
		let mut peers = self.peers.write();
		if peers
			.get(&peer.info.addr)
			.map_or(false, |current| Arc::ptr_eq(current, peer))
		{
			peers.remove(&peer.info.addr);
			true
		} else {
			false
		}
	}

	pub fn stop_and_reap_peer(&self, peer: Arc<Peer>) {
		peer.stop();
		{
			let mut stopped_peers = self.stopped_peers.lock();
			// `peer.stop()` only signals the reader/writer threads. Keep the peer
			// owned until we can join those threads; otherwise dropping the
			// StopHandle detaches them and Tor active objects can stay registered.
			if !stopped_peers.iter().any(|p| Arc::ptr_eq(p, &peer)) {
				stopped_peers.push(peer);
			}
		}
		self.reap_finished_stopped_peers();
	}

	fn log_peer_wait_error(peer: &Peer, err: Error) -> Option<Error> {
		let expected_disconnect = matches!(err, Error::Connection(_) | Error::ConnectionClose(_));
		if expected_disconnect {
			debug!("failed to stop peer {}: {}", peer.info.addr, err);
			None
		} else {
			error!("failed to stop peer {}: {}", peer.info.addr, err);
			Some(err)
		}
	}

	fn wait_stopped_peer(peer: Arc<Peer>) -> Option<Error> {
		match peer.wait() {
			Ok(()) => None,
			Err(e) => Self::log_peer_wait_error(&peer, e),
		}
	}

	fn reap_finished_stopped_peers(&self) {
		let mut ready_peers = Vec::new();
		{
			let mut stopped_peers = self.stopped_peers.lock();
			let mut idx = 0;
			// Normal maintenance must not block on peer thread shutdown. Move
			// only finished peers out of the queue; full node shutdown drains the
			// remaining peers with blocking waits.
			while idx < stopped_peers.len() {
				if stopped_peers[idx].is_wait_ready() {
					ready_peers.push(stopped_peers.swap_remove(idx));
				} else {
					idx += 1;
				}
			}
		}

		for peer in ready_peers {
			let _ = Self::wait_stopped_peer(peer);
		}
	}

	fn wait_stopped_peers(&self) -> Option<Error> {
		let stopped_peers = {
			let mut stopped_peers = self.stopped_peers.lock();
			// Shutdown is the synchronization point where all queued stopped
			// peers must be joined, including peers that were removed earlier by
			// cleanup, ping failure, ban, or failed broadcast paths.
			mem::take(&mut *stopped_peers)
		};

		let mut first_error = None;
		for peer in stopped_peers {
			if let Some(e) = Self::wait_stopped_peer(peer) {
				first_error.get_or_insert(e);
			}
		}
		first_error
	}

	pub fn is_banned(&self, peer_addr: &PeerAddr) -> Result<bool, Error> {
		match self.store.get_peer(peer_addr) {
			Ok(peer) => Ok(peer.flags == State::Banned),
			Err(e) if e.store_error_is_not_found() => Ok(false),
			Err(e) => Err(e.into()),
		}
	}
	/// Ban a peer, disconnecting it if we're currently connected
	pub fn ban_peer(
		&self,
		peer_addr: &PeerAddr,
		ban_reason: ReasonForBan,
		message: &str,
	) -> Result<(), Error> {
		info!(
			"Banning peer {}, ban_reason {:?}, {}",
			peer_addr, ban_reason, message
		);
		// Persist the ban even if the peer row was pruned from the peer-store
		// cache before delayed bad-block attribution fired.
		let ban_result = self.add_banned(peer_addr.clone(), ban_reason, message);

		// Remove the peer directly from the live map. Do not use
		// get_connected_peer() here because it filters excluded peers, and banning
		// must stop any live connection for the address.
		if let Some(peer) = self.remove_connected(peer_addr) {
			debug!(
				"Updating online peer with Ban {}, ban_reason {:?}",
				peer_addr, ban_reason
			);
			// Mark peer status before notifying/stopping it.
			peer.set_banned();
			// Connected-peer notification is best effort; a failed send must not
			// prevent disconnecting and removing a peer that is already banned.
			if let Err(e) = peer.send_ban_reason(ban_reason) {
				warn!(
					"Unable to send ban reason to {}, disconnecting banned peer anyway: {}",
					peer_addr, e
				);
			}
			self.stop_and_reap_peer(peer);
		}

		ban_result
	}

	/// Unban a peer, checks if it exists and banned then unban
	pub fn unban_peer(&self, peer_addr: &PeerAddr) -> Result<(), Error> {
		info!("unban_peer: peer {}", peer_addr);
		// check if peer exist
		let peer = self.get_peer(peer_addr)?;
		// This is a non-atomic check/update: update_state reloads the row and
		// does not verify it is still Banned, so a concurrent ban can be
		// overwritten by this unban. Peer ban state is local connection policy,
		// not consensus-critical state, so this narrow race is acceptable here.
		if peer.flags == State::Banned {
			self.update_state(peer_addr, State::Healthy)
		} else {
			Err(Error::PeerNotBanned)
		}
	}

	fn broadcast<F>(&self, obj_name: &str, inner: F) -> Result<BroadcastSummary, Error>
	where
		F: Fn(&Peer) -> Result<bool, Error>,
	{
		let mut summary = BroadcastSummary::default();

		for p in self.iter().connected() {
			match inner(&p) {
				Ok(true) => summary.sent += 1,
				Ok(false) => (),
				Err(e)
					if matches!(
						e,
						Error::Send(_) | Error::ConnectionClose(_) | Error::Timeout
					) =>
				{
					debug!(
						"Error sending {:?} to peer {:?}: {:?}",
						obj_name, &p.info.addr, e
					);
					summary.peer_failures += 1;
					if self.remove_connected_if_same(&p) {
						if let Err(e) = self.update_removed_peer_state(&p) {
							// Persisting removed-peer state is best effort here. Log the
							// store failure, but do not propagate it because broadcast
							// errors are treated as peer disconnect conditions by callers.
							error!(
								"Failed to persist state for peer {} removed after {:?} broadcast send failure: {}",
								p.info.addr, obj_name, e
							);
						}
					} else {
						debug!(
							"Skipping stale broadcast cleanup for replaced peer {:?}.",
							p.info.addr
						);
					}
					self.stop_and_reap_peer(p.clone());
				}
				Err(e) => {
					error!("Error broadcasting {:?}: {:?}", obj_name, e);
					return Err(e);
				}
			}
		}
		Ok(summary)
	}

	fn ensure_broadcast_progress(obj_name: &str, summary: BroadcastSummary) -> Result<(), Error> {
		if summary.sent == 0 && summary.peer_failures > 0 {
			return Err(Error::PeerException(format!(
				"{} broadcast failed for {} peer(s)",
				obj_name, summary.peer_failures
			)));
		}
		Ok(())
	}

	/// Broadcast a compact block to all our connected peers.
	/// This is only used when initially broadcasting a newly mined block.
	pub fn broadcast_compact_block(&self, b: &core::CompactBlock) -> Result<(), Error> {
		let summary = self.broadcast("compact block", |p| p.send_compact_block(b))?;
		Self::ensure_broadcast_progress("compact block", summary)?;
		debug!(
			"broadcast_compact_block: {}, {} at {}, to {} peers, done.",
			b.hash(self.store.get_context_id())
				.unwrap_or(Hash::default()),
			b.header.pow.total_difficulty,
			b.header.height,
			summary.sent,
		);
		Ok(())
	}

	/// Broadcast a block header to all our connected peers.
	/// A peer implementation may drop the broadcast request
	/// if it knows the remote peer already has the header.
	pub fn broadcast_header(&self, bh: &core::BlockHeader) -> Result<(), Error> {
		let summary = self.broadcast("header", |p| p.send_header(bh))?;
		Self::ensure_broadcast_progress("header", summary)?;
		debug!(
			"broadcast_header: {}, {} at {}, to {} peers, done.",
			bh.hash(self.store.get_context_id())
				.unwrap_or(Hash::default()),
			bh.pow.total_difficulty,
			bh.height,
			summary.sent,
		);
		Ok(())
	}

	/// Broadcasts the provided transaction to all our connected peers.
	/// A peer implementation may drop the broadcast request
	/// if it knows the remote peer already has the transaction.
	pub fn broadcast_transaction(&self, tx: &core::Transaction) -> Result<(), BroadcastError> {
		let base_fee = tx.get_base_fee()?;
		let summary = self.broadcast("transaction", |p| {
			// Sending transaction only to peers that can accept it.
			if base_fee >= p.info.tx_base_fee {
				p.send_transaction(tx)
			} else {
				Ok(false)
			}
		})?;
		if summary.sent == 0 && summary.peer_failures > 0 {
			return Err(Error::PeerException(format!(
				"transaction broadcast failed for {} peer(s)",
				summary.peer_failures
			))
			.into());
		}
		if summary.sent == 0 {
			warn!("Unable to broadcast transaction. Not found any connected peers that accepts Tx with base fee {}", base_fee);
		}
		debug!(
			"broadcast_transaction: {} to {} peers, done.",
			tx.hash(self.store.get_context_id()).map_err(Error::from)?,
			summary.sent,
		);
		Ok(())
	}

	#[cfg(test)]
	pub(crate) fn broadcast_for_test<F>(&self, inner: F) -> Result<BroadcastSummary, Error>
	where
		F: Fn(&Peer) -> Result<bool, Error>,
	{
		self.broadcast("test", inner)
	}

	#[cfg(test)]
	pub(crate) fn remove_failed_ping_peer_for_test(&self, peer: &Arc<Peer>) -> Result<bool, Error> {
		self.remove_failed_ping_peer(peer)
	}

	/// Ping all our connected peers. Always automatically expects a pong back
	/// or disconnects. This acts as a liveness test.
	pub fn check_all(&self, total_difficulty: Difficulty, height: u64) -> PeerCheckSummary {
		self.reap_finished_stopped_peers();
		let mut summary = PeerCheckSummary::default();

		for p in self.iter().connected() {
			if let Err(e) = p.send_ping(total_difficulty, height) {
				debug!("Error pinging peer {:?}: {:?}", &p.info.addr, e);
				summary.ping_failures += 1;
				if let Err(e) = self.remove_failed_ping_peer(&p) {
					error!(
						"Failed to persist state for peer {} removed after ping failure: {}",
						p.info.addr, e
					);
					summary.record_persistence_failure(e);
				}
				self.stop_and_reap_peer(p.clone());
			}
		}

		self.reap_finished_stopped_peers();
		summary
	}

	fn remove_failed_ping_peer(&self, peer: &Arc<Peer>) -> Result<bool, Error> {
		if self.remove_connected_if_same(peer) {
			self.update_removed_peer_state(peer)?;
			Ok(true)
		} else {
			debug!(
				"Skipping stale ping cleanup for replaced peer {:?}.",
				peer.info.addr
			);
			Ok(false)
		}
	}

	/// Iterator over all peers we know about (stored in our db).
	pub fn peer_data_iter(
		&self,
	) -> Result<impl Iterator<Item = Result<PeerData, Error>> + use<'_>, Error> {
		Ok(self
			.store
			.peers_iter()?
			.map(|item| item.map_err(From::from)))
	}

	/// Convenience for reading all peer data from the db.
	pub fn all_peer_data(&self, capabilities: Capabilities) -> Result<Vec<PeerData>, Error> {
		self.peer_data_iter()?
			.filter_map(|p| match p {
				Ok(p)
					if capabilities == Capabilities::UNKNOWN
						|| p.capabilities.contains(capabilities) =>
				{
					Some(Ok(p))
				}
				Ok(_) => None,
				Err(e) => Some(Err(e)),
			})
			.collect()
	}

	/// Find peers in store (not necessarily connected) and return their data
	pub fn find_peers(&self, state: State, cap: Capabilities) -> Result<Vec<PeerData>, Error> {
		self.store.find_peers(state, cap).map_err(From::from)
	}

	/// Get peer in store by address
	pub fn get_peer(&self, peer_addr: &PeerAddr) -> Result<PeerData, Error> {
		self.store.get_peer(peer_addr).map_err(From::from)
	}

	/// Get and delete peer from the store by address. It is needed for peer renaming
	pub fn delete_peer(&self, peer_addr: &PeerAddr) -> Result<(), Error> {
		self.store.delete_peer(peer_addr).map_err(From::from)
	}

	pub fn delete_peer_if_exists(&self, peer_addr: &PeerAddr) -> Result<(), Error> {
		match self.store.delete_peer_if_exists(peer_addr) {
			Ok(()) => Ok(()),
			Err(e) => Err(From::from(e)),
		}
	}

	/// Whether we've already seen a peer with the provided address
	pub fn exists_peer(&self, peer_addr: &PeerAddr) -> Result<bool, Error> {
		self.store.exists_peer(peer_addr).map_err(From::from)
	}

	/// Saves updated information about a peer
	pub fn save_peer(&self, p: &PeerData) -> Result<bool, Error> {
		self.store.save_peer(p).map_err(From::from)
	}

	/// Saves updated information about mulitple peers in batch
	pub fn save_peers(&self, p: Vec<PeerData>) -> Result<(), Error> {
		self.store.save_peers(p).map_err(From::from)
	}

	/// Updates the state of a peer in store
	pub fn update_state(&self, peer_addr: &PeerAddr, new_state: State) -> Result<(), Error> {
		self.store
			.update_state(peer_addr, new_state)
			.map_err(From::from)
	}

	/// Restores Defunct peers that were last connected at or after `connection_time_limit`.
	pub fn restore_defunct_peers_since(&self, connection_time_limit: i64) -> Result<u32, Error> {
		let mut restored = 0;
		let mut first_restore_error = None;

		for peer in self.all_peer_data(Capabilities::UNKNOWN)? {
			if peer.flags == State::Defunct && peer.last_connected >= connection_time_limit {
				if let Err(e) = self.update_state(&peer.addr, State::Healthy) {
					error!(
						"failed to restore peer {} from Defunct to Healthy: {}",
						peer.addr, e
					);
					if first_restore_error.is_none() {
						first_restore_error = Some(e);
					}
				} else {
					restored += 1;
				}
			}
		}

		if let Some(e) = first_restore_error {
			return Err(e);
		}

		Ok(restored)
	}

	/// Updates the state of a peer in store
	pub fn update_stop_healthy_state(&self, peer_addr: &PeerAddr) -> Result<(), Error> {
		self.store
			.update_stopping_healty_state(peer_addr)
			.map_err(From::from)
	}

	fn update_removed_peer_state(&self, peer: &Peer) -> Result<(), Error> {
		if peer.is_defunct() {
			self.update_state(&peer.info.addr, State::Defunct)
		} else {
			self.update_stop_healthy_state(&peer.info.addr)
		}
	}

	/// Iterate over the peer list and prune all peers we have
	/// lost connection to or have been deemed problematic.
	/// Also avoid connected peer count getting too high.
	pub fn clean_peers(
		&self,
		max_inbound_count: usize,
		max_outbound_count: usize,
		boost_capability: Capabilities,
		config: P2PConfig,
	) -> PeerCleanupSummary {
		self.reap_finished_stopped_peers();
		let mut summary = PeerCleanupSummary::default();
		let liveness_deferred = self.adapter.is_chain_liveness_deferred();
		if liveness_deferred {
			debug!("clean_peers: skipping dead-ping and stuck-peer eviction while local chain maintenance is active");
		}
		let preferred_peers = config
			.peers_preferred
			.clone()
			.unwrap_or(PeerAddrs::default());

		enum CleanupStateUpdate {
			MarkHealthyOnStop,
			PreserveState,
		}

		let mut rm = vec![];

		// build a list of peers to be cleaned up
		{
			for peer in self.iter() {
				if peer.is_banned() {
					info!("clean_peers {:?}, peer banned", peer.info.addr);
					rm.push((peer.clone(), CleanupStateUpdate::PreserveState));
				} else if peer.is_defunct() {
					info!("clean_peers {:?}, peer defunct", peer.info.addr);
					if let Err(e) = self.update_state(&peer.info.addr, State::Defunct) {
						error!("failed to mark peer {} defunct: {}", peer.info.addr, e);
						summary.record_persistence_failure(e);
					}
					rm.push((peer.clone(), CleanupStateUpdate::PreserveState));
				} else if !peer.is_connected() {
					info!("clean_peers {:?}, not connected", peer.info.addr);
					rm.push((peer.clone(), CleanupStateUpdate::MarkHealthyOnStop));
				} else if peer.is_abusive() {
					let received = peer.tracker().received_bytes.write().count_per_min();
					let sent = peer.tracker().sent_bytes.write().count_per_min();
					info!(
						"clean_peers {:?}, abusive ({} sent, {} recv)",
						peer.info.addr, sent, received,
					);
					if let Err(e) = self.update_state(&peer.info.addr, State::Banned) {
						error!(
							"failed to mark abusive peer {} banned: {}",
							peer.info.addr, e
						);
						summary.record_persistence_failure(e);
					}
					rm.push((peer.clone(), CleanupStateUpdate::PreserveState));
				} else if liveness_deferred {
					trace!(
						"clean_peers {:?}, liveness checks deferred by local chain maintenance",
						peer.info.addr
					);
				} else {
					let (stuck, diff, dead_ping) = peer.is_stuck();
					let stuck_peer = match self.adapter.total_difficulty() {
						Ok(total_difficulty) => stuck && diff < total_difficulty,
						Err(e) => {
							error!("failed to get total difficulty: {:?}", e);
							// If local chain state cannot be read, do not evict peers
							// based on stuck-peer heuristics during this cleanup pass.
							false
						}
					};
					if dead_ping || stuck_peer {
						info!(
							"clean_peers {:?}, dead ping: {} stuck peer: {}",
							peer.info.addr, dead_ping, stuck_peer
						);
						if let Err(e) = self.update_state(&peer.info.addr, State::Defunct) {
							error!(
								"failed to mark stuck peer {} defunct: {}",
								peer.info.addr, e
							);
							summary.record_persistence_failure(e);
						}
						rm.push((peer.clone(), CleanupStateUpdate::PreserveState));
					}
				}
			}
		}

		// closure to build an iterator of our inbound peers
		let outbound_peers = || self.iter().outbound().connected().into_iter();

		if boost_capability != Capabilities::UNKNOWN {
			// at max half of peers can be with wrong capability. Others let's close. Random order is fine
			let excess_outgoing_count = outbound_peers()
				.count()
				.saturating_sub(max_outbound_count / 2);
			let mut addrs = outbound_peers()
				.filter(|x| {
					!preferred_peers.contains(&x.info.addr)
						&& !x.info.capabilities.contains(boost_capability)
				})
				.map(|x| (x, CleanupStateUpdate::MarkHealthyOnStop))
				.take(excess_outgoing_count)
				.collect();
			rm.append(&mut addrs);
		}

		// check here to make sure we don't have too many outgoing connections
		// Preferred peers are treated preferentially here.
		// Also choose outbound peers with lowest total difficulty to drop.
		// Reducing outbound connection gradually
		let mut excess_outgoing_count = cmp::min(
			2,
			outbound_peers().count().saturating_sub(max_outbound_count),
		);

		// Filtering out excess and underperforming outbound peers.
		// If local chain state cannot be read, use conservative fallbacks so
		// this cleanup pass does not evict peers for low performance.
		let my_difficulty = match self.adapter.total_difficulty() {
			Ok(total_difficulty) => total_difficulty,
			Err(e) => {
				error!(
					"failed to get total difficulty during peer cleanup: {:?}",
					e
				);
				Difficulty::zero()
			}
		};
		let my_height = match self.adapter.total_height() {
			Ok(total_height) => total_height,
			Err(e) => {
				error!("failed to get total height during peer cleanup: {:?}", e);
				0
			}
		};
		let mut out_peers_failures = self.out_peers_failures.write();
		let mut next_failures = HashMap::new();

		let mut peer_infos: Vec<Arc<Peer>> = outbound_peers()
			.filter(|x| !preferred_peers.contains(&x.info.addr))
			.collect();

		let rm_sz0 = rm.len();
		for peer in &peer_infos {
			// If peer 2 blocks behind for 3 check cycyles, we want to exclude it.
			// Reason for that: we want outbound peers be high quality.
			if peer.info.height() < my_height.saturating_sub(2)
				&& peer.info.total_difficulty() < my_difficulty
			{
				let fail_counter = out_peers_failures
					.get(&peer.info.addr)
					.cloned()
					.unwrap_or(0)
					.saturating_add(1);
				if fail_counter >= 5 {
					info!(
						"Requesting disconnect for outband peer {:?} because of low performance",
						peer.info.addr
					);
					rm.push((peer.clone(), CleanupStateUpdate::MarkHealthyOnStop));
				}
				next_failures.insert(peer.info.addr.clone(), fail_counter);
			}
		}
		*out_peers_failures = next_failures;

		// rm.len() - rm_sz0 is safe because rm is only grawing since rm_sz0 was assigned to rm.len()
		excess_outgoing_count = excess_outgoing_count.saturating_sub(rm.len() - rm_sz0);
		if excess_outgoing_count > 0 {
			let my_base_fee = global::get_accept_fee_base(self.store.get_context_id());
			peer_infos.sort_unstable_by_key(|x| {
				if x.info.tx_base_fee < my_base_fee {
					x.info.total_difficulty().to_num() / 2 // we don't want to see peers with lower than we are base fee
				} else {
					x.info.total_difficulty().to_num()
				}
			});
			let mut addrs = peer_infos
				.into_iter()
				.map(|x| (x, CleanupStateUpdate::MarkHealthyOnStop))
				.take(excess_outgoing_count)
				.collect();
			rm.append(&mut addrs);
		}

		// closure to build an iterator of our inbound peers
		let inbound_peers = || self.iter().inbound().connected().into_iter();

		// check here to make sure we don't have too many incoming connections
		let excess_incoming_count = inbound_peers().count().saturating_sub(max_inbound_count);
		if excess_incoming_count > 0 {
			let mut addrs: Vec<_> = inbound_peers()
				.filter(|x| !preferred_peers.contains(&x.info.addr))
				.take(excess_incoming_count)
				.map(|x| (x, CleanupStateUpdate::MarkHealthyOnStop))
				.collect();
			rm.append(&mut addrs);
		}

		// now clean up peer map based on the list to remove
		for (peer, state_update) in rm {
			if self.remove_connected_if_same(&peer) {
				if matches!(state_update, CleanupStateUpdate::MarkHealthyOnStop) {
					if let Err(e) = self.update_stop_healthy_state(&peer.info.addr) {
						error!(
							"Failed to persist Healthy state for removed peer {}: {}",
							peer.info.addr, e
						);
						summary.record_persistence_failure(e);
					}
				}
				self.stop_and_reap_peer(peer);
				summary.removed_peers += 1;
			}
		}

		self.reap_finished_stopped_peers();
		summary
	}

	pub fn stop(&self) -> Result<(), Error> {
		// Swap the peers with empty map. Than stop all the peers
		let mut peers: HashMap<PeerAddr, Arc<Peer>> = HashMap::new();
		{
			mem::swap(&mut peers, &mut *self.peers.write());
		}

		let mut first_error = None;
		if let Some(e) = self.wait_stopped_peers() {
			first_error.get_or_insert(e);
		}
		for peer in peers.values() {
			if let Err(e) = self.update_removed_peer_state(peer) {
				error!(
					"Failed to persist state for stopped peer {}: {}",
					peer.info.addr, e
				);
				first_error.get_or_insert(e);
			}
			peer.stop();
		}
		for (_, peer) in peers.drain() {
			if let Some(e) = Self::wait_stopped_peer(peer) {
				first_error.get_or_insert(e);
			}
		}
		if let Some(e) = self.wait_stopped_peers() {
			first_error.get_or_insert(e);
		}

		if let Some(e) = first_error {
			Err(e)
		} else {
			Ok(())
		}
	}

	/// We have enough outbound connected peers
	pub fn enough_outbound_peers(&self) -> bool {
		let mut count = 0;
		let mut matched_fee_base = 0;
		let my_fee_base = global::get_accept_fee_base(self.store.get_context_id());
		for peer in self.iter().outbound().connected() {
			count += 1;
			if peer.info.tx_base_fee <= my_fee_base {
				matched_fee_base += 1;
			}
		}

		let context_id = self.store.get_context_id();
		let in_sync_mode = self.is_sync_mode();

		let need_count = self
			.config
			.peer_min_preferred_outbound_count(context_id, in_sync_mode);
		if in_sync_mode {
			count >= need_count
		} else {
			// Expected that at least half of connected outbound peers will
			// support us with base fees.
			let required_fee_matches = (count + 1) / 2;
			count >= need_count && matched_fee_base >= required_fee_matches
		}
	}

	/// Removes those peers that seem to have expired.
	/// Expiration cleanup is best effort: expired peer rows can be retried on
	/// the next maintenance pass, so storage errors are logged and not
	/// propagated to the seed loop.
	pub fn remove_expired(&self, delete_peer_chances: u32) {
		let now = Utc::now();

		// Delete defunct peers from storage
		if let Err(e) = self.store.delete_peers(delete_peer_chances, |peer| {
			// last_connected can be 0 for migrated rows, or otherwise
			// invalid for corrupted rows. These records do not carry a
			// reliable recency signal, so expiration cleanup may delete them.
			let should_remove = match Utc.timestamp_opt(peer.last_connected, 0) {
				chrono::LocalResult::Single(last_connected) => {
					let diff = now - last_connected;
					// global::PEER_EXPIRATION_REMOVE_TIME as i64 is saf because it is a small contant
					let should_remove = peer.flags == State::Defunct
						&& diff > Duration::seconds(global::PEER_EXPIRATION_REMOVE_TIME as i64);
					should_remove
				}
				_ => true,
			};

			if should_remove {
				debug!(
					"removing peer {:?}: last connected at {}",
					peer.addr, peer.last_connected,
				);
			}

			should_remove
		}) {
			warn!("failed to remove expired peers: {}", e);
		}
	}

	// App session id, defines network
	pub fn get_context_id(&self) -> u32 {
		self.store.get_context_id()
	}

	/// Resets advertised peer check timestamps after a network outage so
	/// candidates can be retried.
	pub fn reset_advertised_peer_checks(&self) {
		self.advertised_peers
			.write()
			.values_mut()
			.for_each(|peer| peer.reset_checked());
	}

	/// Returns recently advertised peers ordered by connection priority.
	pub fn ranked_advertised_peers(&self) -> Vec<PeerAdvertised> {
		let mut advertised_peers: Vec<PeerAdvertised> = self
			.advertised_peers
			.read_recursive()
			.values()
			.cloned()
			.collect();
		advertised_peers.sort_by_key(|peer| -peer.calc_rank());
		advertised_peers
	}

	/// Marks a single advertised peer as checked.
	pub fn mark_advertised_peer_checked(&self, addr: &PeerAddr, now: i64) {
		if let Some(peer) = self.advertised_peers.write().get_mut(addr) {
			peer.set_checked(now);
		}
	}

	fn prune_advertised_peers(advertised_peers: &mut HashMap<PeerAddr, PeerAdvertised>) {
		// Note, iteration though advertised_peers is acceptable because MAX_ADVERTISED_PEERS size of 100
		while advertised_peers.len() > MAX_ADVERTISED_PEERS {
			let mut per_source_counts: HashMap<PeerAddr, usize> = HashMap::new();
			for peer in advertised_peers.values() {
				*per_source_counts.entry(peer.source().clone()).or_insert(0) += 1;
			}

			let largest_source = per_source_counts
				.iter()
				.max_by_key(|(_, count)| **count)
				.map(|(source, _)| source.clone());

			let remove_addr = match largest_source {
				Some(source) => advertised_peers
					.iter()
					.filter(|(_, peer)| peer.source() == &source)
					.min_by_key(|(_, peer)| peer.calc_rank())
					.map(|(addr, _)| addr.clone()),
				None => None,
			};

			match remove_addr {
				Some(addr) => {
					advertised_peers.remove(&addr);
				}
				None => break,
			}
		}
	}

	fn prune_advertised_peer_source_limits(
		source_limits: &mut HashMap<PeerAddr, AdvertisedPeerSourceLimit>,
		retain_source: &PeerAddr,
	) {
		// MAX_ADVERTISED_PEER_SOURCE_LIMITS value is relatevly small, so we do remove items one
		// by one with a full scan
		while source_limits.len() > MAX_ADVERTISED_PEER_SOURCE_LIMITS {
			let remove_addr = source_limits
				.iter()
				.filter(|(addr, _)| *addr != retain_source)
				.min_by_key(|(_, limit)| limit.window_start)
				.map(|(addr, _)| addr.clone());

			match remove_addr {
				Some(addr) => {
					source_limits.remove(&addr);
				}
				None => break,
			}
		}
	}

	fn accept_advertised_peer_candidates(
		&self,
		source: &PeerAddr,
		peer_addrs: Vec<PeerAddr>,
		now: i64,
	) -> Vec<PeerAddr> {
		let mut seen = HashSet::new();
		let unique_peer_addrs: Vec<PeerAddr> = peer_addrs
			.into_iter()
			.filter(|addr| match self.advertised_peer_rejection_reason(addr) {
				Some(reason) => {
					debug!(
						"peer_addrs_received: rejected advertised peer {} from {}: {}",
						addr, source, reason
					);
					false
				}
				None => true,
			})
			.filter(|addr| seen.insert(addr.clone()))
			.collect();

		if unique_peer_addrs.is_empty() {
			return unique_peer_addrs;
		}

		let mut source_limits = self.advertised_peer_source_limits.write();
		source_limits.retain(|_, limit| {
			now >= limit.window_start
				&& now - limit.window_start < ADVERTISED_PEERS_SOURCE_LIMIT_WINDOW
		});

		let limit = source_limits
			.entry(source.clone())
			.or_insert(AdvertisedPeerSourceLimit {
				window_start: now,
				accepted: 0,
			});

		if now < limit.window_start
			|| now - limit.window_start >= ADVERTISED_PEERS_SOURCE_LIMIT_WINDOW
		{
			limit.window_start = now;
			limit.accepted = 0;
		}

		let remaining = MAX_ADVERTISED_PEERS_PER_SOURCE_PER_HOUR.saturating_sub(limit.accepted);
		let accepted_count = cmp::min(remaining, unique_peer_addrs.len());
		limit.accepted += accepted_count;
		Peers::prune_advertised_peer_source_limits(&mut source_limits, source);

		if accepted_count < unique_peer_addrs.len() {
			debug!(
				"peer_addrs_received: accepted {} of {} unique candidates from {} due to per-source hourly limit",
				accepted_count,
				unique_peer_addrs.len(),
				source
			);
		}

		unique_peer_addrs.into_iter().take(accepted_count).collect()
	}

	fn advertised_peer_rejection_reason(&self, addr: &PeerAddr) -> Option<&'static str> {
		// peers_preferred is user configuration. Do not reject or normalize those
		// exact values through gossip validation; honor them as the user configured
		// them. PeerAddr equality ignores non-loopback ports, so exact matching is
		// required before bypassing validation or allowing a preferred-key collision.
		if let Some(peers) = self.config.peers_preferred.as_ref() {
			if peers.contains_exact(addr) {
				return None;
			}
			if peers.contains(addr) {
				return Some("preferred peer address does not exactly match configured address");
			}
		}

		addr.gossip_rejection_reason()
	}
}

impl ChainAdapter for Peers {
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
		self.adapter.tx_kernel_received(kernel_hash, peer_info)
	}

	fn transaction_received(
		&self,
		secp: &mut Secp256k1,
		tx: core::Transaction,
		stem: bool,
	) -> Result<bool, mwc_chain::Error> {
		self.adapter.transaction_received(secp, tx, stem)
	}

	fn block_received(
		&self,
		secp: &mut Secp256k1,
		b: core::Block,
		peer_info: &PeerInfo,
		opts: mwc_chain::Options,
	) -> Result<bool, mwc_chain::Error> {
		let hash = b.hash(self.store.get_context_id())?;
		if !self.adapter.block_received(secp, b, peer_info, opts)? {
			// if the peer sent us a block that's intrinsically bad
			// they are either mistaken or malevolent, both of which require a ban
			self.ban_peer(
				&peer_info.addr,
				ReasonForBan::BadBlock,
				&format!("Got bad block with hash: {}", hash),
			)
			.map_err(|e| mwc_chain::Error::Other(format!("ban peer error {}", e)))?;
			Ok(false)
		} else {
			Ok(true)
		}
	}

	fn compact_block_received(
		&self,
		secp: &mut Secp256k1,
		cb: core::CompactBlock,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		let hash = cb.hash(self.store.get_context_id())?;
		if !self.adapter.compact_block_received(secp, cb, peer_info)? {
			// if the peer sent us a block that's intrinsically bad
			// they are either mistaken or malevolent, both of which require a ban
			let msg = format!(
				"Received a bad compact block {} from  {}, the peer will be banned",
				hash, peer_info.addr
			);
			self.ban_peer(&peer_info.addr, ReasonForBan::BadCompactBlock, &msg)
				.map_err(|e| mwc_chain::Error::Other(format!("ban peer error {}", e)))?;
			Ok(false)
		} else {
			Ok(true)
		}
	}

	fn header_received(
		&self,
		bh: core::BlockHeader,
		peer_info: &PeerInfo,
	) -> Result<bool, mwc_chain::Error> {
		if !self.adapter.header_received(bh, peer_info)? {
			// if the peer sent us a block header that's intrinsically bad
			// they are either mistaken or malevolent, both of which require a ban
			self.ban_peer(&peer_info.addr, ReasonForBan::BadBlockHeader, "Bad header")
				.map_err(|e| mwc_chain::Error::Other(format!("ban peer error {}", e)))?;
			Ok(false)
		} else {
			Ok(true)
		}
	}

	fn header_locator(&self) -> Result<Vec<Hash>, mwc_chain::Error> {
		self.adapter.header_locator()
	}

	fn headers_received(
		&self,
		headers: &[core::BlockHeader],
		remaining: u64,
		peer_info: &PeerInfo,
	) -> Result<(), mwc_chain::Error> {
		self.adapter.headers_received(headers, remaining, peer_info)
	}

	fn locate_headers(&self, hs: &[Hash]) -> Result<Vec<core::BlockHeader>, mwc_chain::Error> {
		self.adapter.locate_headers(hs)
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
		if let Some(peer) = self.get_connected_peer(addr) {
			peer.info.update(height, diff);
		}
		self.adapter.peer_difficulty(addr, diff, height)
	}
}

impl NetAdapter for Peers {
	/// Find good peers we know with the provided capability and return their
	/// addresses.
	fn find_peer_addrs(&self, capab: Capabilities) -> Result<Vec<PeerAddr>, Error> {
		let peers: Vec<PeerData> = self
			.find_peers(State::Healthy, capab)?
			.into_iter()
			.filter(|p| p.last_connected > 0) // we want to return peers that this node was used at least once. We don't want spread falsed Healthy peers
			.take(MAX_PEER_ADDRS as usize)
			.collect();
		trace!("find_peer_addrs: {} healthy peers picked", peers.len());
		Ok(map_vec!(peers, |p| p.addr.clone()))
	}

	/// A list of peers has been received from one of our peers.
	fn peer_addrs_received(&self, source: &PeerAddr, peer_addrs: Vec<PeerAddr>) {
		let received_count = peer_addrs.len();
		let now = Utc::now().timestamp();
		let peer_addrs = self.accept_advertised_peer_candidates(source, peer_addrs, now);
		debug!(
			"Received {} peer addrs from {}, accepted {} candidates, saving.",
			received_count,
			source,
			peer_addrs.len(),
		);
		// Peer address ingestion is intentionally best-effort and infallible.
		// Any failure here is an internal peer-store issue, so log it and keep
		// the connection open instead of propagating an error that would close it.
		let mut to_save: Vec<PeerData> = Vec::new();

		if !peer_addrs.is_empty() {
			// Updating history data
			let mut advertised_peers = self.advertised_peers.write();
			let advertised_peers = &mut *advertised_peers;
			let expiration_time = now - ADVERTISED_PEERS_HISTORY;
			advertised_peers.retain(|_addr, peer| peer.get_last_advertised_ts() >= expiration_time);
			let chunk_size = peer_addrs.len();
			for pa in &peer_addrs {
				match advertised_peers.get_mut(&pa) {
					Some(peer) => peer.set_advertised(chunk_size, now),
					None => {
						let _ = advertised_peers.insert(
							pa.clone(),
							PeerAdvertised::new(source.clone(), pa.clone(), chunk_size, now),
						);
					}
				}
			}
			Peers::prune_advertised_peers(advertised_peers);
		}

		for pa in peer_addrs {
			let peer = match self.get_peer(&pa) {
				Ok(_) => continue,
				Err(Error::Store(e)) if e.store_error_is_not_found() => PeerData {
					addr: pa,
					capabilities: Capabilities::UNKNOWN,
					user_agent: "".to_string(),
					flags: State::Healthy,
					last_banned: 0,
					ban_reason: ReasonForBan::None,
					// Gossip-only peers are stored as Healthy so the seed
					// loop can try them as outbound candidates. They remain
					// distinguishable from proven peers by last_connected = 0;
					// find_peer_addrs filters those out so we do not advertise
					// peers we have never successfully connected to.
					last_connected: 0,
					version: mwc_core::ser::ProtocolVersion(1),
				},
				Err(e) => {
					error!("Could not query received peer address {}: {:?}", pa, e);
					continue;
				}
			};
			to_save.push(peer);
		}
		if !to_save.is_empty() {
			info!("Received new healthy peers: {}", to_save.len());
			if let Err(e) = self.save_peers(to_save) {
				error!("Could not save received peer addresses: {:?}", e);
			}
		}
	}

	fn is_banned(&self, addr: &PeerAddr) -> Result<bool, Error> {
		Peers::is_banned(self, addr)
	}

	fn peer_version(
		&self,
		addr: &PeerAddr,
	) -> Result<Option<mwc_core::ser::ProtocolVersion>, Error> {
		match self.get_peer(addr) {
			Ok(peer) => Ok(Some(peer.version)),
			Err(Error::Store(e)) if e.store_error_is_not_found() => Ok(None),
			Err(e) => Err(e),
		}
	}

	fn ban_peer(
		&self,
		addr: &PeerAddr,
		ban_reason: ReasonForBan,
		message: &str,
	) -> Result<(), Error> {
		Peers::ban_peer(self, addr, ban_reason, message)
	}
}

pub struct PeersIter<I> {
	iter: I,
}

impl<I: Iterator> IntoIterator for PeersIter<I> {
	type Item = I::Item;
	type IntoIter = I;

	fn into_iter(self) -> Self::IntoIter {
		self.iter.into_iter()
	}
}

impl<I: Iterator<Item = Arc<Peer>>> PeersIter<I> {
	/// Filter by any feature
	pub fn filter<F>(self, f: F) -> PeersIter<impl Iterator<Item = Arc<Peer>>>
	where
		F: Fn(&Arc<Peer>) -> bool + 'static,
	{
		PeersIter {
			iter: self.iter.filter(move |p| f(p)),
		}
	}

	/// Filter peers that are currently connected.
	/// Note: This adaptor takes a read lock internally.
	/// So if we are chaining adaptors then defer this toward the end of the chain.
	pub fn connected(self) -> PeersIter<impl Iterator<Item = Arc<Peer>>> {
		PeersIter {
			iter: self.iter.filter(|p| p.is_connected()),
		}
	}

	/// Filter inbound peers.
	pub fn inbound(self) -> PeersIter<impl Iterator<Item = Arc<Peer>>> {
		PeersIter {
			iter: self.iter.filter(|p| p.info.is_inbound()),
		}
	}

	/// Filter outbound peers.
	pub fn outbound(self) -> PeersIter<impl Iterator<Item = Arc<Peer>>> {
		PeersIter {
			iter: self.iter.filter(|p| p.info.is_outbound()),
		}
	}

	/// Filter peers with the provided difficulty comparison fn.
	///
	/// with_difficulty(|x| x > diff)
	///
	/// Note: This adaptor takes a read lock internally for each peer.
	/// So if we are chaining adaptors then put this toward later in the chain.
	pub fn with_difficulty<F>(self, f: F) -> PeersIter<impl Iterator<Item = Arc<Peer>>>
	where
		F: Fn(Difficulty) -> bool,
	{
		PeersIter {
			iter: self.iter.filter(move |p| f(p.info.total_difficulty())),
		}
	}

	/// Filter peers that support the provided capabilities.
	pub fn with_capabilities(
		self,
		cap: Capabilities,
	) -> PeersIter<impl Iterator<Item = Arc<Peer>>> {
		PeersIter {
			iter: self.iter.filter(move |p| {
				if cap == Capabilities::UNKNOWN {
					true
				} else {
					p.info.capabilities.contains(cap)
				}
			}),
		}
	}

	/// Filter peers that support the provided capabilities.
	pub fn with_min_height(self, height: u64) -> PeersIter<impl Iterator<Item = Arc<Peer>>> {
		PeersIter {
			iter: self
				.iter
				.filter(move |p| p.info.live_info.read_recursive().height >= height),
		}
	}

	pub fn by_addr(&mut self, addr: &PeerAddr) -> Option<Arc<Peer>> {
		let addr_key = addr.as_key();
		self.iter.find(|p| p.info.addr.as_key() == addr_key)
	}

	/// Choose a random peer from the current (filtered) peers.
	pub fn choose_random(self) -> Option<Arc<Peer>> {
		let mut rng = rand::rng();
		self.iter.choose(&mut rng)
	}

	/// Find the max difficulty of the current (filtered) peers.
	pub fn max_difficulty(self) -> Option<Difficulty> {
		self.iter.map(|p| p.info.total_difficulty()).max()
	}

	/// Count the current (filtered) peers.
	pub fn count(self) -> usize {
		self.iter.count()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::serv::DummyAdapter;
	use mwc_core::ser::ProtocolVersion;
	use std::net::SocketAddr;

	fn test_source_addr(i: usize) -> PeerAddr {
		PeerAddr::Ip(SocketAddr::from((
			[8, (i / 256) as u8, (i % 256) as u8, 1],
			3414,
		)))
	}

	fn test_advertised_addr(i: usize) -> PeerAddr {
		PeerAddr::Ip(SocketAddr::from((
			[1, 1, (i / 250 + 1) as u8, (i % 250 + 1) as u8],
			3414,
		)))
	}

	fn test_peer_data(i: usize, flags: State, last_connected: i64) -> PeerData {
		PeerData {
			addr: test_source_addr(i),
			capabilities: Capabilities::UNKNOWN,
			user_agent: "test".to_string(),
			flags,
			last_banned: 0,
			ban_reason: ReasonForBan::None,
			last_connected,
			version: ProtocolVersion::local(),
		}
	}

	#[test]
	fn ban_peer_persists_missing_peer_row() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let addr = test_source_addr(42);

		assert!(peers.get_peer(&addr).is_err());
		peers
			.ban_peer(&addr, ReasonForBan::BadBlock, "bad block")
			.unwrap();

		assert!(peers.is_banned(&addr).unwrap());
		let stored = peers.get_peer(&addr).unwrap();
		assert_eq!(stored.flags, State::Banned);
		assert_eq!(stored.ban_reason, ReasonForBan::BadBlock);
	}

	#[test]
	fn restore_defunct_peers_since_respects_cutoff() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());

		let old_defunct = test_peer_data(1, State::Defunct, 99);
		let cutoff_defunct = test_peer_data(2, State::Defunct, 100);
		let newer_defunct = test_peer_data(3, State::Defunct, 101);
		let healthy = test_peer_data(4, State::Healthy, 101);

		peers
			.save_peers(vec![
				old_defunct.clone(),
				cutoff_defunct.clone(),
				newer_defunct.clone(),
				healthy.clone(),
			])
			.unwrap();

		assert_eq!(peers.restore_defunct_peers_since(100).unwrap(), 2);

		assert_eq!(
			peers.get_peer(&old_defunct.addr).unwrap().flags,
			State::Defunct
		);
		assert_eq!(
			peers.get_peer(&cutoff_defunct.addr).unwrap().flags,
			State::Healthy
		);
		assert_eq!(
			peers.get_peer(&newer_defunct.addr).unwrap().flags,
			State::Healthy
		);
		assert_eq!(peers.get_peer(&healthy.addr).unwrap().flags, State::Healthy);
	}

	#[test]
	fn advertised_peer_source_limits_are_capped() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);

		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let store = PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		let peers = Peers::new(store, Arc::new(DummyAdapter {}), &P2PConfig::default());
		let now = Utc::now().timestamp();

		for i in 0..=MAX_ADVERTISED_PEER_SOURCE_LIMITS {
			let source = test_source_addr(i);
			let candidate = test_advertised_addr(i);
			let accepted =
				peers.accept_advertised_peer_candidates(&source, vec![candidate], now + i as i64);
			assert_eq!(accepted.len(), 1);
		}

		let source_limits = peers.advertised_peer_source_limits.read_recursive();
		assert_eq!(source_limits.len(), MAX_ADVERTISED_PEER_SOURCE_LIMITS);
		assert!(!source_limits.contains_key(&test_source_addr(0)));
		assert!(source_limits.contains_key(&test_source_addr(MAX_ADVERTISED_PEER_SOURCE_LIMITS)));
	}
}
