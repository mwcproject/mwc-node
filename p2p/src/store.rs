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

//! Storage implementation for peer data.

use mwc_crates::chrono::Utc;
use mwc_crates::num::FromPrimitive;
use mwc_crates::rand::{self, rng, RngExt};
use mwc_crates::serde::{self, Deserialize, Serialize};
use std::cmp::{max, Reverse};

use crate::msg::validate_user_agent;
use crate::types::{Capabilities, PeerAddr, ReasonForBan};
use mwc_core::ser::{self, ProtocolVersion, Readable, Reader, Writeable, Writer};
use mwc_core::ser_multiread;
use mwc_core::ser_multiwrite;
use mwc_crates::enum_primitive::{
	enum_from_primitive, enum_from_primitive_impl, enum_from_primitive_impl_ty,
};
use mwc_crates::log::{debug, info};
use mwc_store::{self, option_to_not_found, to_key, Error};

const DB_NAME: &str = "peerV2";
const STORE_SUBPATH: &str = "peers";

const PEER_PREFIX: u8 = b'P';
const MAX_STORED_NON_BANNED_PEERS: usize = 3_000;
const MAX_STORED_BANNED_PEERS: usize = 10_000;

// Types of messages
enum_from_primitive! {
	#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
	#[serde(crate = "serde")]
	pub enum State {
		Healthy = 0,
		Banned = 1,
		Defunct = 2,
	}
}

/// Data stored for any given peer we've encountered.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub struct PeerData {
	/// Network address of the peer.
	pub addr: PeerAddr,
	/// What capabilities the peer advertises. Unknown until a successful
	/// connection.
	pub capabilities: Capabilities,
	/// The peer user agent.
	pub user_agent: String,
	/// State the peer has been detected with.
	pub flags: State,
	/// The time the peer was last banned
	pub last_banned: i64,
	/// The reason for the ban
	pub ban_reason: ReasonForBan,
	/// Time when we last connected to this peer.
	pub last_connected: i64,
	/// Last protocol version verified for this peer.
	pub version: ProtocolVersion,
}

impl Writeable for PeerData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.user_agent.len() > 10_000 {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Unreasonable long User Agent. UA length is {}",
				self.user_agent.len()
			)));
		}
		validate_user_agent(&self.user_agent, "PeerData.user_agent")?;
		self.addr.write(writer)?;
		ser_multiwrite!(
			writer,
			[write_u32, self.capabilities.bits()],
			[write_bytes, &self.user_agent],
			[write_u8, self.flags as u8],
			[write_i64, self.last_banned],
			[write_i32, self.ban_reason as i32],
			[write_i64, self.last_connected],
			[write_u32, self.version.value()]
		);
		Ok(())
	}
}

impl Readable for PeerData {
	fn read<R: Reader>(reader: &mut R) -> Result<PeerData, ser::Error> {
		let addr = PeerAddr::read(reader)?;
		let capab = reader.read_u32()?;
		let ua = reader.read_bytes_len_prefix()?;
		let (fl, lb, br) = ser_multiread!(reader, read_u8, read_i64, read_i32);

		let bytes_before_lc = reader.bytes_read();
		let lc = reader.read_i64();
		let last_connected = match lc {
			Ok(lc) => lc,
			Err(ser::Error::IOErr(err))
				if err.kind() == std::io::ErrorKind::UnexpectedEof
					&& reader.bytes_read() == bytes_before_lc
					&& !reader.has_pending_data() =>
			{
				0
			}
			Err(e) => return Err(e),
		};

		let bytes_before_version = reader.bytes_read();
		let version = match ProtocolVersion::read(reader) {
			Ok(version) => version,
			Err(ser::Error::IOErr(err))
				if err.kind() == std::io::ErrorKind::UnexpectedEof
					&& reader.bytes_read() == bytes_before_version
					&& !reader.has_pending_data() =>
			{
				ProtocolVersion(1)
			}
			Err(e) => return Err(e),
		};

		let user_agent = String::from_utf8(ua)
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read user agent, {}", e)))?;

		validate_user_agent(&user_agent, "PeerData.user_agent")?;

		// This intentionally drops unknown capability bits. Peer capabilities are
		// not treated as forward-compatible because this node cannot validate the
		// safety or semantics of data defined by a newer protocol version. Unknown
		// bits are therefore treated as unsupported instead of preserved.
		let capabilities = Capabilities::from_bits_truncate(capab);
		let ban_reason = ReasonForBan::from_i32(br).ok_or(ser::Error::CorruptedData(
			"Unable to read PeerData ban reason".to_string(),
		))?;

		match State::from_u8(fl) {
			Some(flags) => Ok(PeerData {
				addr,
				capabilities,
				user_agent,
				flags: flags,
				last_banned: lb,
				ban_reason,
				last_connected,
				version,
			}),
			None => Err(ser::Error::CorruptedData(
				"Unable to read PeerData State".to_string(),
			)),
		}
	}
}

/// Storage facility for peer data.
pub struct PeerStore {
	db: mwc_store::Store,
}

impl PeerStore {
	/// Instantiates a new peer store under the provided root path.
	pub fn new(context_id: u32, db_root: &str) -> Result<PeerStore, Error> {
		let db = mwc_store::Store::new(
			context_id,
			db_root,
			Some(DB_NAME),
			Some(STORE_SUBPATH),
			None,
		)?;
		Ok(PeerStore { db: db })
	}

	pub fn save_peer(&self, p: &PeerData) -> Result<bool, Error> {
		debug!("save_peer: {:?} marked {:?}", p.addr, p.flags);

		let key = peer_key(&p.addr);
		let batch = self.db.batch_write()?;
		let mut peer = p.clone();
		if let Some(existing_peer) = batch.get_ser::<PeerData>(&key[..])? {
			if !merge_existing_peer_for_save(&existing_peer, &mut peer) {
				debug!(
					"Preserving banned peer {:?}; ignoring save marked {:?}.",
					existing_peer.addr, peer.flags
				);
				return Ok(false);
			}
		}
		batch.put_ser(&key[..], &peer)?;
		batch.commit()?;

		self.prune_peers_for_state(peer.flags)?;
		Ok(true)
	}

	pub fn save_peers(&self, p: Vec<PeerData>) -> Result<(), Error> {
		let batch = self.db.batch_write()?;
		for mut pd in p {
			debug!("save_peers: {:?} marked {:?}", pd.addr, pd.flags);
			let key = peer_key(&pd.addr);
			if let Some(existing_peer) = batch.get_ser::<PeerData>(&key[..])? {
				if !merge_existing_peer_for_save(&existing_peer, &mut pd) {
					debug!(
						"Preserving banned peer {:?}; ignoring batch save marked {:?}.",
						existing_peer.addr, pd.flags
					);
					continue;
				}
			}
			batch.put_ser(&key[..], &pd)?;
		}
		batch.commit()?;

		self.prune_banned_peers()?;
		self.prune_non_banned_peers()?;
		Ok(())
	}

	pub fn get_peer(&self, peer_addr: &PeerAddr) -> Result<PeerData, Error> {
		option_to_not_found(self.db.get_ser(&peer_key(peer_addr)[..]), || {
			format!("Peer at address: {}", peer_addr)
		})
	}

	pub fn exists_peer(&self, peer_addr: &PeerAddr) -> Result<bool, Error> {
		self.db.exists(&peer_key(peer_addr)[..])
	}

	/// TODO - allow below added to avoid github issue reports
	pub fn delete_peer(&self, peer_addr: &PeerAddr) -> Result<(), Error> {
		let batch = self.db.batch_write()?;
		batch.delete(&peer_key(peer_addr)[..])?;
		batch.commit()
	}

	pub fn delete_peer_if_exists(&self, peer_addr: &PeerAddr) -> Result<(), Error> {
		let key = peer_key(peer_addr);
		let batch = self.db.batch_write()?;
		if batch.exists(&key[..])? {
			batch.delete(&key[..])?;
			batch.commit()?;
		}
		Ok(())
	}

	fn delete_peer_key_allow_missing(
		batch: &mwc_store::Batch<'_>,
		key: &[u8],
	) -> Result<(), Error> {
		match batch.delete(key) {
			Ok(()) => Ok(()),
			Err(e) if e.store_error_is_not_found() => Ok(()),
			Err(e) => Err(e),
		}
	}

	fn delete_corrupt_peer_rows(&self, corrupt_keys: Vec<Vec<u8>>) -> Result<(), Error> {
		if corrupt_keys.is_empty() {
			return Ok(());
		}

		let batch = self.db.batch_write()?;
		for key in corrupt_keys {
			let should_delete = match batch.get_ser::<PeerData>(&key) {
				Ok(Some(_)) => false,
				Ok(None) => true,
				Err(Error::SerErr(_)) => true,
				Err(e) => return Err(e),
			};

			if should_delete {
				Self::delete_peer_key_allow_missing(&batch, &key)?;
			}
		}
		batch.commit()
	}

	/// Find some peers in our local db.
	pub fn find_peers(&self, state: State, cap: Capabilities) -> Result<Vec<PeerData>, Error> {
		// All new peers has flags Capabilities::UNKNOWN, that is why we better to return themn as well.
		// Node will try to connect to them and find the capability.
		let mut peers = self
			.peers_iter()?
			.filter_map(|p| match p {
				Ok(p)
					if p.flags == state
						&& (p.capabilities == Capabilities::UNKNOWN
							|| p.capabilities.contains(cap)) =>
				{
					Some(Ok(p))
				}
				Ok(_) => None,
				Err(e) => Some(Err(e)),
			})
			.collect::<Result<Vec<_>, _>>()?;
		// We want last used to go first.
		let peers_num = peers.len();
		if peers_num > 1 {
			peers.sort_by_key(|p| Reverse(p.last_connected));
			// Then shuffle every second of them
			let mut rng = rng();
			for i1 in (1..peers_num).step_by(2) {
				if i1 + 2 < peers_num {
					let i2 = rng.random_range(i1 + 1..peers_num);
					peers.swap(i1, i2);
				}
			}
		}
		Ok(peers)
	}

	/// Iterator over all known peers.
	pub fn peers_iter(&self) -> Result<impl Iterator<Item = Result<PeerData, Error>> + '_, Error> {
		let key = to_key(PEER_PREFIX, "");
		let protocol_version = self.db.protocol_version();
		let context_id = self.db.get_context_id();

		let mut peers = Vec::new();
		let mut corrupt_keys = Vec::new();
		{
			let iter = self.db.iter(&key, move |k, mut v| {
				Ok(
					ser::deserialize_strict::<PeerData, _>(&mut v, protocol_version, context_id)
						.map_err(|_| k.to_vec()),
				)
			})?;

			for row in iter {
				match row? {
					Ok(peer) => peers.push(Ok(peer)),
					Err(key) => corrupt_keys.push(key),
				}
			}
		}

		// Peer rows are cache entries. If a row can no longer be deserialized,
		// re-check it after the prefix iterator has dropped its read snapshot.
		self.delete_corrupt_peer_rows(corrupt_keys)?;

		Ok(peers.into_iter())
	}

	/// List all known peers
	/// Used for /v1/peers/all api endpoint
	pub fn all_peers(&self) -> Result<Vec<PeerData>, Error> {
		self.peers_iter()?.collect()
	}

	/// Convenience method to load a peer data, update its status and save it
	/// back. If new state is Banned its last banned time will be updated too.
	pub fn update_state(&self, peer_addr: &PeerAddr, new_state: State) -> Result<(), Error> {
		let batch = self.db.batch_write()?;

		let mut peer =
			option_to_not_found(batch.get_ser::<PeerData>(&peer_key(peer_addr)[..]), || {
				format!("Peer at address: {}", peer_addr)
			})?;

		if peer.flags == State::Banned && new_state == State::Defunct {
			debug!("Preserving banned state for peer {:?}", peer_addr);
			return Ok(());
		}

		if peer.flags != new_state {
			debug!(
				"Changing peer {:?} state form {:?} to {:?}",
				peer_addr, peer.flags, new_state
			);
		}

		peer.flags = new_state;
		if new_state == State::Banned {
			peer.last_banned = Utc::now().timestamp();
		}

		batch.put_ser(&peer_key(peer_addr)[..], &peer)?;
		batch.commit()?;

		self.prune_peers_for_state(new_state)?;
		Ok(())
	}

	pub fn update_stopping_healty_state(&self, peer_addr: &PeerAddr) -> Result<(), Error> {
		let batch = self.db.batch_write()?;

		let mut peer =
			option_to_not_found(batch.get_ser::<PeerData>(&peer_key(peer_addr)[..]), || {
				format!("Peer at address: {}", peer_addr)
			})?;

		if peer.flags == State::Banned {
			debug!("Preserving banned state for stopped peer {:?}", peer_addr);
			return Ok(());
		}

		peer.flags = State::Healthy;
		peer.last_connected = Utc::now().timestamp();

		batch.put_ser(&peer_key(peer_addr)[..], &peer)?;
		batch.commit()?;
		self.prune_non_banned_peers()
	}

	/// Deletes peers from the storage that satisfy some condition `predicate`
	/// Delete peer chances is needed because we really don't want to
	pub fn delete_peers<F>(&self, delete_peer_chances: u32, predicate: F) -> Result<(), Error>
	where
		F: Fn(&PeerData) -> bool,
	{
		let mut to_remove = vec![];
		let mut candidates = 0;
		for x in self.peers_iter()? {
			let x = x?;
			if predicate(&x) {
				candidates += 1;
				if rand::rng().random_range(0..max(1, delete_peer_chances)) == 0 {
					to_remove.push(x)
				}
			}
		}

		info!(
			"Removed peers from the cache storage: {} from {}",
			to_remove.len(),
			candidates
		);

		// Delete peers in single batch
		if !to_remove.is_empty() {
			let batch = self.db.batch_write()?;
			for x in to_remove {
				Self::delete_peer_key_allow_missing(&batch, &peer_key(&x.addr)[..])?;
			}
			batch.commit()?;
		}
		Ok(())
	}

	fn prune_non_banned_peers(&self) -> Result<(), Error> {
		self.prune_peers(
			|peer| peer.flags != State::Banned,
			MAX_STORED_NON_BANNED_PEERS,
			"non-banned",
			Self::non_banned_peer_eviction_key,
		)
	}

	fn prune_banned_peers(&self) -> Result<(), Error> {
		self.prune_peers(
			|peer| peer.flags == State::Banned,
			MAX_STORED_BANNED_PEERS,
			"banned",
			Self::banned_peer_eviction_key,
		)
	}

	fn prune_peers_for_state(&self, state: State) -> Result<(), Error> {
		if state == State::Banned {
			self.prune_banned_peers()
		} else {
			self.prune_non_banned_peers()
		}
	}

	fn prune_peers<F, K>(
		&self,
		filter: F,
		max_peers: usize,
		peer_class: &str,
		eviction_key: impl Fn(&PeerData) -> K,
	) -> Result<(), Error>
	where
		F: Fn(&PeerData) -> bool,
		K: Ord,
	{
		let mut peers = self
			.peers_iter()?
			.filter_map(|peer| match peer {
				Ok(peer) if filter(&peer) => Some(Ok(peer)),
				Ok(_) => None,
				Err(e) => Some(Err(e)),
			})
			.collect::<Result<Vec<_>, _>>()?;

		if peers.len() <= max_peers {
			return Ok(());
		}

		let remove_count = peers.len() - max_peers;
		peers.sort_by_key(eviction_key);
		let to_remove: Vec<PeerData> = peers.into_iter().take(remove_count).collect();

		info!(
			"Pruning peer store: removing {} {} peers over {} limit",
			to_remove.len(),
			peer_class,
			max_peers
		);

		let batch = self.db.batch_write()?;
		for peer in to_remove {
			Self::delete_peer_key_allow_missing(&batch, &peer_key(&peer.addr)[..])?;
		}
		batch.commit()
	}

	fn non_banned_peer_eviction_key(peer: &PeerData) -> (u8, i64, String) {
		let class = if peer.flags == State::Healthy
			&& peer.capabilities == Capabilities::UNKNOWN
			&& peer.last_connected == 0
		{
			0
		} else if peer.flags == State::Defunct {
			1
		} else if peer.last_connected == 0 {
			2
		} else {
			3
		};

		(class, peer.last_connected, peer.addr.as_key())
	}

	fn banned_peer_eviction_key(peer: &PeerData) -> (i64, String) {
		(peer.last_banned, peer.addr.as_key())
	}

	/// Context Id that defines the network
	pub fn get_context_id(&self) -> u32 {
		self.db.get_context_id()
	}
}

// Ignore the port unless ip is loopback address.
fn peer_key(peer_addr: &PeerAddr) -> Vec<u8> {
	to_key(PEER_PREFIX, peer_addr.as_key())
}

fn merge_existing_peer_for_save(existing_peer: &PeerData, new_peer: &mut PeerData) -> bool {
	if existing_peer.flags == State::Banned && new_peer.flags != State::Banned {
		return false;
	}
	new_peer.version = std::cmp::max(new_peer.version, existing_peer.version);
	true
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_core::global::{set_local_chain_type, ChainTypes};
	use mwc_core::ser::ProtocolVersion;
	use mwc_crates::tempfile::TempDir;

	fn test_store() -> (TempDir, PeerStore) {
		set_local_chain_type(ChainTypes::AutomatedTesting);
		let dir = TempDir::new().unwrap();
		let store = PeerStore::new(1, dir.path().to_str().unwrap()).unwrap();
		(dir, store)
	}

	fn peer(port: u16, flags: State, last_banned: i64, last_connected: i64) -> PeerData {
		PeerData {
			addr: PeerAddr::from_str(&format!("127.0.0.1:{}", port)).unwrap(),
			capabilities: Capabilities::UNKNOWN,
			user_agent: "test".to_string(),
			flags,
			last_banned,
			ban_reason: ReasonForBan::None,
			last_connected,
			version: ProtocolVersion::local(),
		}
	}

	#[test]
	fn peer_store_prune_limits_are_configured() {
		assert_eq!(MAX_STORED_NON_BANNED_PEERS, 3_000);
		assert_eq!(MAX_STORED_BANNED_PEERS, 10_000);
	}

	#[test]
	fn prune_banned_peers_removes_oldest_bans_only() {
		let (_dir, store) = test_store();
		let oldest_ban = peer(3414, State::Banned, 10, 0);
		let newer_ban = peer(3415, State::Banned, 20, 0);
		let newest_ban = peer(3416, State::Banned, 30, 0);
		let healthy = peer(3417, State::Healthy, 0, 10);

		store
			.save_peers(vec![
				oldest_ban.clone(),
				newer_ban.clone(),
				newest_ban.clone(),
				healthy.clone(),
			])
			.unwrap();
		store
			.prune_peers(
				|peer| peer.flags == State::Banned,
				2,
				"banned-test",
				PeerStore::banned_peer_eviction_key,
			)
			.unwrap();

		assert!(store.get_peer(&oldest_ban.addr).is_err());
		assert_eq!(
			store.get_peer(&newer_ban.addr).unwrap().flags,
			State::Banned
		);
		assert_eq!(
			store.get_peer(&newest_ban.addr).unwrap().flags,
			State::Banned
		);
		assert_eq!(store.get_peer(&healthy.addr).unwrap().flags, State::Healthy);
	}

	#[test]
	fn prune_non_banned_peers_leaves_banned_peers_uncapped() {
		let (_dir, store) = test_store();
		let oldest_defunct = peer(3418, State::Defunct, 0, 10);
		let newer_defunct = peer(3419, State::Defunct, 0, 20);
		let newest_defunct = peer(3420, State::Defunct, 0, 30);
		let banned = peer(3421, State::Banned, 10, 0);

		store
			.save_peers(vec![
				oldest_defunct.clone(),
				newer_defunct.clone(),
				newest_defunct.clone(),
				banned.clone(),
			])
			.unwrap();
		store
			.prune_peers(
				|peer| peer.flags != State::Banned,
				2,
				"non-banned-test",
				PeerStore::non_banned_peer_eviction_key,
			)
			.unwrap();

		assert!(store.get_peer(&oldest_defunct.addr).is_err());
		assert_eq!(
			store.get_peer(&newer_defunct.addr).unwrap().flags,
			State::Defunct
		);
		assert_eq!(
			store.get_peer(&newest_defunct.addr).unwrap().flags,
			State::Defunct
		);
		assert_eq!(store.get_peer(&banned.addr).unwrap().flags, State::Banned);
	}

	#[test]
	fn update_stopping_healthy_state_preserves_banned_peer() {
		let (_dir, store) = test_store();
		let banned = peer(3422, State::Banned, 42, 10);

		store.save_peer(&banned).unwrap();
		store.update_stopping_healty_state(&banned.addr).unwrap();

		let stored = store.get_peer(&banned.addr).unwrap();
		assert_eq!(stored.flags, State::Banned);
		assert_eq!(stored.last_banned, 42);
		assert_eq!(stored.last_connected, 10);
	}

	#[test]
	fn update_state_defunct_preserves_banned_peer() {
		let (_dir, store) = test_store();
		let banned = peer(3423, State::Banned, 42, 10);

		store.save_peer(&banned).unwrap();
		store.update_state(&banned.addr, State::Defunct).unwrap();

		let stored = store.get_peer(&banned.addr).unwrap();
		assert_eq!(stored.flags, State::Banned);
		assert_eq!(stored.last_banned, 42);
		assert_eq!(stored.last_connected, 10);
	}

	#[test]
	fn peers_iter_skips_and_deletes_corrupt_peer_rows_after_iteration() {
		let (_dir, store) = test_store();
		let valid = peer(3422, State::Healthy, 0, 10);
		let corrupt_addr = PeerAddr::from_str("127.0.0.1:3423").unwrap();

		store.save_peer(&valid).unwrap();
		let corrupt_key = peer_key(&corrupt_addr);
		let batch = store.db.batch_write().unwrap();
		batch.put(&corrupt_key, b"bad-peer-data").unwrap();
		batch.commit().unwrap();

		let peers = store
			.peers_iter()
			.unwrap()
			.collect::<Result<Vec<_>, _>>()
			.unwrap();

		assert_eq!(peers.len(), 1);
		assert_eq!(peers[0].addr, valid.addr);
		assert!(!store.db.exists(&corrupt_key).unwrap());
	}

	#[test]
	fn corrupt_peer_cleanup_preserves_rewritten_valid_peer_row() {
		let (_dir, store) = test_store();
		let banned = peer(3424, State::Banned, 77, 10);
		let corrupt_key = peer_key(&banned.addr);

		let batch = store.db.batch_write().unwrap();
		batch.put(&corrupt_key, b"bad-peer-data").unwrap();
		batch.commit().unwrap();

		let stale_corrupt_keys = vec![corrupt_key.clone()];
		let batch = store.db.batch_write().unwrap();
		batch.put_ser(&corrupt_key, &banned).unwrap();
		batch.commit().unwrap();

		store.delete_corrupt_peer_rows(stale_corrupt_keys).unwrap();

		let stored = store.get_peer(&banned.addr).unwrap();
		assert_eq!(stored.flags, State::Banned);
		assert_eq!(stored.last_banned, 77);
		assert_eq!(stored.last_connected, 10);
	}

	#[test]
	fn delete_peers_ignores_selected_peers_already_deleted() {
		let (_dir, store) = test_store();
		let doomed = peer(3425, State::Healthy, 0, 10);

		store.save_peer(&doomed).unwrap();
		store
			.delete_peers(1, |peer| {
				if peer.addr == doomed.addr {
					store.delete_peer(&peer.addr).unwrap();
					true
				} else {
					false
				}
			})
			.unwrap();

		assert!(store.get_peer(&doomed.addr).is_err());
	}
}
