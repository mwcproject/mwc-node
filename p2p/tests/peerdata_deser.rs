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

use mwc_core::global::{set_local_chain_type, ChainTypes};
use mwc_core::ser::{self, BinWriter, BufReader, ProtocolVersion, Writeable, Writer};
use mwc_crates::bytes::Bytes;
use mwc_crates::tempfile::TempDir;
use mwc_p2p::PeerAddr;

fn make_peer(addr: &str) -> mwc_p2p::PeerData {
	mwc_p2p::PeerData {
		addr: PeerAddr::from_str(addr).unwrap(),
		capabilities: mwc_p2p::types::Capabilities::UNKNOWN,
		user_agent: "ok".to_string(),
		flags: mwc_p2p::State::Healthy,
		last_banned: 0,
		ban_reason: mwc_p2p::types::ReasonForBan::None,
		last_connected: 0,
		version: ProtocolVersion::local(),
	}
}

fn serialize_peer_without_version(peer: &mwc_p2p::PeerData) -> Vec<u8> {
	let mut bytes = Vec::new();
	{
		let mut writer = BinWriter::new(&mut bytes, ProtocolVersion::local(), 1);
		peer.addr.write(&mut writer).unwrap();
		writer.write_u32(peer.capabilities.bits()).unwrap();
		writer.write_bytes(&peer.user_agent).unwrap();
		writer.write_u8(peer.flags as u8).unwrap();
		writer.write_i64(peer.last_banned).unwrap();
		writer.write_i32(peer.ban_reason as i32).unwrap();
		writer.write_i64(peer.last_connected).unwrap();
	}
	bytes
}

fn serialize_peer_without_last_connected_and_version(peer: &mwc_p2p::PeerData) -> Vec<u8> {
	let mut bytes = Vec::new();
	{
		let mut writer = BinWriter::new(&mut bytes, ProtocolVersion::local(), 1);
		peer.addr.write(&mut writer).unwrap();
		writer.write_u32(peer.capabilities.bits()).unwrap();
		writer.write_bytes(&peer.user_agent).unwrap();
		writer.write_u8(peer.flags as u8).unwrap();
		writer.write_i64(peer.last_banned).unwrap();
		writer.write_i32(peer.ban_reason as i32).unwrap();
	}
	bytes
}

fn assert_buf_reader_rejects_unexpected_eof(bytes: Vec<u8>) {
	let mut bytes = Bytes::from(bytes);
	let mut reader = BufReader::new(&mut bytes, ProtocolVersion::local(), 1);

	match reader.body::<mwc_p2p::PeerData>() {
		Err(ser::Error::IOErr(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
		Ok(_) => panic!("expected truncated PeerData rejection"),
		Err(err) => panic!("expected unexpected EOF, got {:?}", err),
	}
}

#[test]
fn peer_data_read_defaults_missing_last_connected_to_zero() {
	let mut peer = make_peer("127.0.0.1:3414");
	peer.last_connected = 42;
	let mut bytes = serialize_peer_without_version(&peer);
	bytes.truncate(bytes.len() - std::mem::size_of::<i64>());

	let decoded: mwc_p2p::PeerData =
		ser::deserialize_strict(&mut &bytes[..], ProtocolVersion::local(), 1).unwrap();

	assert_eq!(decoded.last_connected, 0);
	assert_eq!(decoded.version, ProtocolVersion(1));
}

#[test]
fn peer_data_read_rejects_partial_last_connected_with_buffered_reader() {
	let peer = make_peer("127.0.0.1:3414");
	let mut bytes = serialize_peer_without_last_connected_and_version(&peer);
	bytes.extend_from_slice(&[1, 2, 3]);

	assert_buf_reader_rejects_unexpected_eof(bytes);
}

#[test]
fn peer_data_read_defaults_missing_version_to_protocol_1() {
	let peer = make_peer("127.0.0.1:3414");
	let bytes = serialize_peer_without_version(&peer);

	let decoded: mwc_p2p::PeerData =
		ser::deserialize_strict(&mut &bytes[..], ProtocolVersion::local(), 1).unwrap();

	assert_eq!(decoded.version, ProtocolVersion(1));
}

#[test]
fn peer_data_read_rejects_partial_version_with_buffered_reader() {
	let peer = make_peer("127.0.0.1:3414");
	let mut bytes = serialize_peer_without_version(&peer);
	bytes.extend_from_slice(&[1, 2]);

	assert_buf_reader_rejects_unexpected_eof(bytes);
}

#[test]
fn peer_data_roundtrips_protocol_version() {
	let mut peer = make_peer("127.0.0.1:3414");
	peer.version = ProtocolVersion(5);
	let bytes = ser::ser_vec(1, &peer, ProtocolVersion::local()).unwrap();

	let decoded: mwc_p2p::PeerData =
		ser::deserialize_strict(&mut &bytes[..], ProtocolVersion::local(), 1).unwrap();

	assert_eq!(decoded.version, ProtocolVersion(5));
}

#[test]
fn peer_data_write_rejects_invalid_user_agent() {
	let mut peer = make_peer("127.0.0.1:3414");
	peer.user_agent = "bad\0agent".to_string();

	match ser::ser_vec(1, &peer, ProtocolVersion::local()) {
		Err(ser::Error::CorruptedData(message)) => {
			assert!(
				message.contains("PeerData.user_agent contains character outside printable ASCII")
			);
		}
		Ok(_) => panic!("expected invalid user agent rejection"),
		Err(err) => panic!("expected corrupted data, got {:?}", err),
	}
}

#[test]
fn peer_store_preserves_max_protocol_version() {
	set_local_chain_type(ChainTypes::AutomatedTesting);

	let dir = TempDir::new().unwrap();
	let root = dir.path().to_str().unwrap();
	let store = mwc_p2p::store::PeerStore::new(1, root).unwrap();

	let mut peer = make_peer("127.0.0.1:3414");
	peer.version = ProtocolVersion(5);
	assert!(store.save_peer(&peer).unwrap());

	peer.version = ProtocolVersion(4);
	assert!(store.save_peer(&peer).unwrap());

	let decoded = store.get_peer(&peer.addr).unwrap();
	assert_eq!(decoded.version, ProtocolVersion(5));
}

#[test]
fn peer_store_save_peer_reports_existing_ban_without_overwrite() {
	set_local_chain_type(ChainTypes::AutomatedTesting);

	let dir = TempDir::new().unwrap();
	let root = dir.path().to_str().unwrap();
	let store = mwc_p2p::store::PeerStore::new(1, root).unwrap();

	let mut banned_peer = make_peer("127.0.0.1:3414");
	banned_peer.flags = mwc_p2p::State::Banned;
	banned_peer.last_banned = 42;
	banned_peer.ban_reason = mwc_p2p::types::ReasonForBan::ManualBan;
	banned_peer.version = ProtocolVersion(5);
	assert!(store.save_peer(&banned_peer).unwrap());

	let mut connected_peer = make_peer("127.0.0.1:3414");
	connected_peer.user_agent = "connected".to_string();
	connected_peer.last_connected = 84;
	connected_peer.version = ProtocolVersion(6);

	assert!(!store.save_peer(&connected_peer).unwrap());

	let decoded = store.get_peer(&banned_peer.addr).unwrap();
	assert_eq!(decoded.flags, mwc_p2p::State::Banned);
	assert_eq!(decoded.last_banned, 42);
	assert_eq!(decoded.ban_reason, mwc_p2p::types::ReasonForBan::ManualBan);
	assert_eq!(decoded.user_agent, "ok");
	assert_eq!(decoded.last_connected, 0);
	assert_eq!(decoded.version, ProtocolVersion(5));
}

#[test]
fn peer_store_save_peers_rejects_invalid_user_agent_without_commit() {
	set_local_chain_type(ChainTypes::AutomatedTesting);

	let dir = TempDir::new().unwrap();
	let root = dir.path().to_str().unwrap();
	let store = mwc_p2p::store::PeerStore::new(1, root).unwrap();

	let valid_peer = make_peer("127.0.0.1:3414");
	let mut invalid_peer = make_peer("127.0.0.1:3415");
	invalid_peer.user_agent = "bad\0agent".to_string();

	let err = store
		.save_peers(vec![valid_peer.clone(), invalid_peer.clone()])
		.unwrap_err();

	assert!(err
		.to_string()
		.contains("PeerData.user_agent contains character outside printable ASCII"));
	assert!(store.get_peer(&valid_peer.addr).is_err());
	assert!(store.get_peer(&invalid_peer.addr).is_err());
}

#[test]
fn peer_store_save_peers_does_not_overwrite_banned_peer_with_non_banned_peer() {
	set_local_chain_type(ChainTypes::AutomatedTesting);

	let dir = TempDir::new().unwrap();
	let root = dir.path().to_str().unwrap();
	let store = mwc_p2p::store::PeerStore::new(1, root).unwrap();

	let mut banned_peer = make_peer("127.0.0.1:3414");
	banned_peer.flags = mwc_p2p::State::Banned;
	banned_peer.last_banned = 42;
	banned_peer.ban_reason = mwc_p2p::types::ReasonForBan::ManualBan;
	banned_peer.version = ProtocolVersion(5);
	assert!(store.save_peer(&banned_peer).unwrap());

	let mut defunct_peer = make_peer("127.0.0.1:3414");
	defunct_peer.user_agent = "defunct".to_string();
	defunct_peer.last_connected = 84;
	defunct_peer.flags = mwc_p2p::State::Defunct;
	defunct_peer.version = ProtocolVersion(7);
	store.save_peers(vec![defunct_peer]).unwrap();

	let decoded = store.get_peer(&banned_peer.addr).unwrap();
	assert_eq!(decoded.flags, mwc_p2p::State::Banned);
	assert_eq!(decoded.last_banned, 42);
	assert_eq!(decoded.ban_reason, mwc_p2p::types::ReasonForBan::ManualBan);
	assert_eq!(decoded.user_agent, "ok");
	assert_eq!(decoded.last_connected, 0);
	assert_eq!(decoded.version, ProtocolVersion(5));
}
