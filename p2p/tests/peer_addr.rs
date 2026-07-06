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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use mwc_core::ser::{self, ProtocolVersion};
use mwc_crates::toml;
use mwc_p2p::{P2PConfig, PeerAddr};

// Test the behavior of a hashmap of peers keyed by peer_addr.
#[test]
fn test_peer_addr_hashing() {
	let mut peers: HashMap<PeerAddr, String> = HashMap::new();

	let socket_addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 8080);
	let peer_addr1 = PeerAddr::Ip(socket_addr1);
	peers.insert(peer_addr1.clone(), "peer1".into());

	assert!(peers.contains_key(&peer_addr1));
	assert_eq!(peers.len(), 1);

	let socket_addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 8081);
	let peer_addr2 = PeerAddr::Ip(socket_addr2);

	// Expected behavior here is to ignore the port when hashing peer_addr.
	// This means the two peer_addr instances above are seen as the same addr.
	assert!(peers.contains_key(&peer_addr1));
	assert!(peers.contains_key(&peer_addr2));

	peers.insert(peer_addr2.clone(), "peer2".into());

	// Inserting the second instance is a no-op as they are treated as the same addr.
	assert!(peers.contains_key(&peer_addr1));
	assert!(peers.contains_key(&peer_addr2));
	assert_eq!(peers.len(), 1);

	// Check they are treated as the same even though their underlying ports are different.
	assert_eq!(peer_addr1, peer_addr2);

	match peer_addr1 {
		PeerAddr::Ip(peer_addr1) => {
			assert_eq!(peer_addr1, socket_addr1);
			assert_eq!(peer_addr1, socket_addr1);
			assert_eq!(peer_addr1.port(), 8080);
		}
		_ => {
			assert_eq!(1, 0);
		} // fail here, shouldn't go here.
	}

	match peer_addr2 {
		PeerAddr::Ip(peer_addr2) => {
			assert_eq!(peer_addr2, socket_addr2);
			assert_eq!(peer_addr2.port(), 8081);
		}
		_ => {
			assert_eq!(1, 0);
		} // fail here, shouldn't go here.
	}

	let domain = "maxs4wuipojxv5gagcrvgsd3zjn7qkmi3rukiozqoq4uwtgelxbz6nqd.onion".to_string();
	let peer_addr1 = PeerAddr::Onion(domain);
	assert_eq!(peers.len(), 1); // len still 1.
	peers.insert(peer_addr1.clone(), "peer1onion".into());

	assert!(peers.contains_key(&peer_addr1));
	assert_eq!(peers.len(), 2); // now it should be 2.

	let domain = "dxnjt4e7wv7cez7nbay2x5drgzfyjtztnsl5fus64ihl3vsli3wx5bid.onion".to_string();
	let peer_addr2 = PeerAddr::Onion(domain);
	peers.insert(peer_addr2.clone(), "peer2onion".into());

	assert!(peers.contains_key(&peer_addr1));
	assert!(peers.contains_key(&peer_addr2));

	assert_eq!(peers.len(), 3); // now it should be 3.
}

#[test]
fn test_peer_addr_ipv6_deserializes_as_ipv6() {
	let peer_addr = PeerAddr::Ip("[::1]:3414".parse().unwrap());
	let bytes = ser::ser_vec(0, &peer_addr, ProtocolVersion::local()).unwrap();
	assert_eq!(bytes[0], 1);

	let mut reader = &bytes[..];
	let decoded =
		ser::deserialize_strict::<PeerAddr, _>(&mut reader, ProtocolVersion::local(), 0).unwrap();

	match decoded {
		PeerAddr::Ip(SocketAddr::V6(addr)) => {
			assert_eq!(*addr.ip(), Ipv6Addr::LOCALHOST);
			assert_eq!(addr.port(), 3414);
		}
		other => panic!("expected IPv6 peer address, got {:?}", other),
	}
}

#[test]
fn test_peer_addr_loopback_as_key_is_unambiguous() {
	let ipv4_loopback = PeerAddr::Ip("127.0.0.1:3414".parse().unwrap());
	assert_eq!(ipv4_loopback.as_key(), "127.0.0.1:3414");

	let ipv6_loopback = PeerAddr::Ip("[::1]:3414".parse().unwrap());
	let distinct_ipv6_addr = PeerAddr::Ip("[::1:3414]:9999".parse().unwrap());

	assert_eq!(ipv6_loopback.as_key(), "[::1]:3414");
	assert_eq!(distinct_ipv6_addr.as_key(), "::1:3414");
	assert_ne!(ipv6_loopback.as_key(), distinct_ipv6_addr.as_key());
}

#[test]
fn test_peer_addr_ipv4_mapped_loopback_is_loopback() {
	let ipv4_mapped_loopback = PeerAddr::Ip("[::ffff:127.0.0.1]:3414".parse().unwrap());
	let same_addr_other_port = PeerAddr::Ip("[::ffff:127.0.0.1]:3415".parse().unwrap());
	let ipv4_mapped_public = PeerAddr::Ip("[::ffff:8.8.8.8]:3414".parse().unwrap());

	assert!(ipv4_mapped_loopback.is_loopback());
	assert!(!ipv4_mapped_public.is_loopback());
	assert_eq!(ipv4_mapped_loopback.as_key(), "[::ffff:127.0.0.1]:3414");

	let mut peers: HashMap<PeerAddr, String> = HashMap::new();
	peers.insert(ipv4_mapped_loopback.clone(), "peer1".into());
	peers.insert(same_addr_other_port.clone(), "peer2".into());

	assert_ne!(ipv4_mapped_loopback, same_addr_other_port);
	assert_eq!(peers.len(), 2);
}

#[test]
fn test_peer_addr_rejects_unknown_discriminator() {
	let domain = "maxs4wuipojxv5gagcrvgsd3zjn7qkmi3rukiozqoq4uwtgelxbz6nqd.onion".to_string();
	let peer_addr = PeerAddr::Onion(domain);
	let mut bytes = ser::ser_vec(0, &peer_addr, ProtocolVersion::local()).unwrap();
	assert_eq!(bytes[0], 2);

	bytes[0] = 3;
	let mut reader = &bytes[..];
	let err = ser::deserialize_strict::<PeerAddr, _>(&mut reader, ProtocolVersion::local(), 0)
		.unwrap_err();
	match err {
		ser::Error::CorruptedData(msg) => {
			assert!(msg.contains("Invalid peer address type tag 3"));
		}
		err => panic!("unexpected error: {:?}", err),
	}
}

#[test]
fn test_peer_addr_rejects_invalid_onion_utf8() {
	let bytes = vec![2, 0, 0, 0, 0, 0, 0, 0, 1, 0xff];
	let mut reader = &bytes[..];
	let err = ser::deserialize_strict::<PeerAddr, _>(&mut reader, ProtocolVersion::local(), 0)
		.unwrap_err();

	match err {
		ser::Error::Utf8Conversion(msg) => {
			assert!(msg.contains("invalid utf-8"));
		}
		err => panic!("unexpected error: {:?}", err),
	}
}

#[test]
fn test_peer_addr_write_rejects_invalid_onion() {
	let peer_addr = PeerAddr::Onion("not-an-onion".to_string());
	let err = ser::ser_vec(0, &peer_addr, ProtocolVersion::local()).unwrap_err();

	match err {
		ser::Error::CorruptedData(msg) => {
			assert!(msg.contains("Invalid onion address string not-an-onion"));
		}
		err => panic!("unexpected error: {:?}", err),
	}
}

#[test]
fn test_peer_addr_write_rejects_onion_with_nul() {
	let peer_addr = PeerAddr::Onion(
		"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion\0".to_string(),
	);
	let err = ser::ser_vec(0, &peer_addr, ProtocolVersion::local()).unwrap_err();

	match err {
		ser::Error::CorruptedData(_) => {}
		err => panic!("unexpected error: {:?}", err),
	}
}

#[test]
fn test_peer_addr_from_str_validates_onion_addresses() {
	let valid_onion = "zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion";
	assert_eq!(
		PeerAddr::from_str(valid_onion).unwrap(),
		PeerAddr::Onion(valid_onion.to_string())
	);

	for invalid_onion in [
		"7uz3yofsjta2ffvnt7ygdhxachspwo5hnqnctnlwqgtrgp3wjedtkmtm.onion",
		"ZWECAV6DGFTSOSCYBPZUFBO77D452MK3MOX2FQZJQOCU7265BXGQ6OAD.onion",
		"7uz3yofsjta2ffvnt7ygdhxachspwo5hnqnctnlwqgtrgp3wjedtkmtm.onion:3414",
		"ZWECAV6DGFTSOSCYBPZUFBO77D452MK3MOX2FQZJQOCU7265BXGQ6OAD.ONION:3414",
	] {
		let err = PeerAddr::from_str(invalid_onion).unwrap_err();
		assert!(err.contains("invalid onion v3 address"), "{}", err);
	}
}

#[test]
fn test_peer_addr_tor_address_validates_onion_addresses() {
	let valid_onion = "zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion";
	let valid_identity = "zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad";

	assert_eq!(
		PeerAddr::Onion(valid_onion.to_string())
			.tor_address()
			.unwrap(),
		valid_identity
	);
	assert_eq!(
		PeerAddr::Onion(valid_identity.to_string())
			.tor_address()
			.unwrap(),
		valid_identity
	);

	let err = PeerAddr::Onion("not-an-onion".to_string())
		.tor_address()
		.unwrap_err();
	assert!(err.to_string().contains("invalid onion v3 address"));
}

#[test]
fn test_peer_addrs_config_deserialization_accepts_valid_entries() {
	let config: P2PConfig = toml::from_str(
		r#"
port = 3414
seeds = [
	"127.0.0.1:3414",
	"[::1]:3414",
	"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion",
]
"#,
	)
	.unwrap();

	let peers = &config.seeds.as_ref().unwrap().peers;
	assert_eq!(peers[0], PeerAddr::Ip("127.0.0.1:3414".parse().unwrap()));
	assert_eq!(peers[1], PeerAddr::Ip("[::1]:3414".parse().unwrap()));
	assert_eq!(
		peers[2],
		PeerAddr::Onion(
			"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion".to_string()
		)
	);
}

#[test]
fn test_peer_addrs_config_deserialization_rejects_invalid_entry() {
	let err = toml::from_str::<P2PConfig>(
		r#"
port = 3414
seeds = ["127.0.0.1:3414", "not-a-peer"]
"#,
	)
	.unwrap_err();

	assert!(err
		.to_string()
		.contains("invalid peer address 'not-a-peer'"));
}
