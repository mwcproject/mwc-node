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

use chrono::Utc;
use num::FromPrimitive;
use rand::thread_rng;

use crate::mwc_core::ser::{self, DeserializationMode, Readable, Reader, Writeable, Writer};
use crate::types::{Capabilities, PeerAddr, ReasonForBan};
use mwc_store::{self, option_to_not_found, to_key, Error};
use mwc_util::secp::rand::Rng;

const DB_NAME: &str = "peerV2";
const STORE_SUBPATH: &str = "peers";

const PEER_PREFIX: u8 = b'P';

// Types of messages
enum_from_primitive! {
	#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
	pub enum State {
		Healthy = 0,
		Banned = 1,
		Defunct = 2,
	}
}

/// Data stored for any given peer we've encountered.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl Writeable for PeerData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.user_agent.len() > 10_000 {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Unreasonable long User Agent. UA length is {}",
				self.user_agent.len()
			)));
		}
		self.addr.write(writer)?;
		ser_multiwrite!(
			writer,
			[write_u32, self.capabilities.bits()],
			[write_bytes, &self.user_agent],
			[write_u8, self.flags as u8],
			[write_i64, self.last_banned],
			[write_i32, self.ban_reason as i32],
			[write_i64, self.last_connected]
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

		let lc = reader.read_i64();
		// this only works because each PeerData is read in its own vector and this
		// is the last data element
		let last_connected = match lc {
			Err(_) => Utc::now().timestamp(),
			Ok(lc) => lc,
		};

		let user_agent = String::from_utf8(ua)
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read user agent, {}", e)))?;
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
	pub fn new(db_root: &str) -> Result<PeerStore, Error> {
		let db = mwc_store::Store::new(db_root, Some(DB_NAME), Some(STORE_SUBPATH), None)?;
		Ok(PeerStore { db: db })
	}

	pub fn save_peer(&self, p: &PeerData) -> Result<(), Error> {
		debug!("save_peer: {:?} marked {:?}", p.addr, p.flags);

		let batch = self.db.batch_write()?;
		batch.put_ser(&peer_key(&p.addr)[..], p)?;
		batch.commit()
	}

	pub fn save_peers(&self, p: Vec<PeerData>) -> Result<(), Error> {
		let batch = self.db.batch_write()?;
		for pd in p {
			debug!("save_peers: {:?} marked {:?}", pd.addr, pd.flags);
			batch.put_ser(&peer_key(&pd.addr)[..], &pd)?;
		}
		batch.commit()
	}

	pub fn get_peer(&self, peer_addr: &PeerAddr) -> Result<PeerData, Error> {
		option_to_not_found(self.db.get_ser(&peer_key(peer_addr)[..], None), || {
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

	/// Find some peers in our local db.
	pub fn find_peers(&self, state: State, cap: Capabilities) -> Result<Vec<PeerData>, Error> {
		// All new peers has flags Capabilities::UNKNOWN, that is why we better to return themn as well.
		// Node will try to connect to them and find the capability.
		let mut peers = self
			.peers_iter()?
			.filter(|p| {
				p.flags == state
					&& (p.capabilities == Capabilities::UNKNOWN || p.capabilities.contains(cap))
			})
			.collect::<Vec<_>>();
		// We want last used to go first.
		let peers_num = peers.len();
		if peers_num > 1 {
			peers.sort_by_key(|p| -p.last_connected);
			// Then shuffle every second of them
			let mut rng = thread_rng();
			for i1 in (1..peers_num).step_by(2) {
				if i1 + 2 < peers_num {
					let i2 = rng.gen_range(i1 + 1, peers_num);
					peers.swap(i1, i2);
				}
			}
		}
		Ok(peers)
	}

	/// Iterator over all known peers.
	pub fn peers_iter(&self) -> Result<impl Iterator<Item = PeerData>, Error> {
		let key = to_key(PEER_PREFIX, "");
		let protocol_version = self.db.protocol_version();
		self.db.iter(&key, move |_, mut v| {
			ser::deserialize(&mut v, protocol_version, DeserializationMode::default())
				.map_err(From::from)
		})
	}

	/// List all known peers
	/// Used for /v1/peers/all api endpoint
	pub fn all_peers(&self) -> Result<Vec<PeerData>, Error> {
		let peers: Vec<PeerData> = self.peers_iter()?.collect();
		Ok(peers)
	}

	/// Convenience method to load a peer data, update its status and save it
	/// back. If new state is Banned its last banned time will be updated too.
	pub fn update_state(&self, peer_addr: &PeerAddr, new_state: State) -> Result<(), Error> {
		let batch = self.db.batch_write()?;

		let mut peer = option_to_not_found(
			batch.get_ser::<PeerData>(&peer_key(peer_addr)[..], None),
			|| format!("Peer at address: {}", peer_addr),
		)?;

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
		batch.commit()
	}

	/// Deletes peers from the storage that satisfy some condition `predicate`
	pub fn delete_peers<F>(&self, predicate: F) -> Result<(), Error>
	where
		F: Fn(&PeerData) -> bool,
	{
		let mut to_remove = vec![];

		for x in self.peers_iter()? {
			if predicate(&x) {
				to_remove.push(x)
			}
		}

		// Delete peers in single batch
		if !to_remove.is_empty() {
			let batch = self.db.batch_write()?;

			for peer in to_remove {
				batch.delete(&peer_key(&peer.addr)[..])?;
			}

			batch.commit()?;
		}

		Ok(())
	}
}

// Ignore the port unless ip is loopback address.
fn peer_key(peer_addr: &PeerAddr) -> Vec<u8> {
	to_key(PEER_PREFIX, peer_addr.as_key())
}
