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

use mwc_core as core;
use mwc_p2p as p2p;

use mwc_util as util;
use mwc_util::StopState;

use crate::core::core::hash::Hash;
use crate::core::global;
use crate::core::pow::Difficulty;
use crate::p2p::types::PeerAddr;
use crate::p2p::Peer;
use mwc_chain::SyncState;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::{thread, time};

fn open_port() -> u16 {
	// use port 0 to allow the OS to assign an open port
	// TcpListener's Drop impl will unbind the port as soon as
	// listener goes out of scope
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	listener.local_addr().unwrap().port()
}

// Setup test with AutomatedTesting chain_type;
fn test_setup() {
	// Set "global" chain type here as we spawn peer threads for read/write.
	global::init_global_chain_type(global::ChainTypes::AutomatedTesting);
	util::init_test_logger();
}

// Starts a server and connects a client peer to it to check handshake,
// followed by a ping/pong exchange to make sure the connection is live.
#[test]
fn peer_handshake() {
	test_setup();

	let p2p_config = p2p::P2PConfig {
		host: "127.0.0.1".parse().unwrap(),
		port: open_port(),
		peers_allow: None,
		peers_deny: None,
		..p2p::P2PConfig::default()
	};
	let net_adapter = Arc::new(p2p::DummyAdapter {});
	let server_inner = p2p::Server::new(
		".mwc",
		p2p::Capabilities::UNKNOWN,
		p2p_config.clone(),
		net_adapter.clone(),
		Hash::from_vec(&vec![]),
		Arc::new(SyncState::new()),
		Arc::new(StopState::new()),
		0,
		None,
	)
	.unwrap();
	let server = Arc::new(server_inner.clone());

	let p2p_inner = server.clone();
	let _ = thread::spawn(move || p2p_inner.listen());

	thread::sleep(time::Duration::from_secs(1));

	let addr = SocketAddr::new(p2p_config.host, p2p_config.port);
	let socket = TcpStream::connect_timeout(&addr, time::Duration::from_secs(10)).unwrap();

	let my_addr = PeerAddr::Ip("127.0.0.1:5000".parse().unwrap());
	let peer = Peer::connect(
		socket,
		p2p::Capabilities::UNKNOWN,
		Difficulty::min(),
		my_addr.clone(),
		&p2p::handshake::Handshake::new(Hash::from_vec(&vec![]), p2p_config.clone(), None),
		net_adapter,
		None,
		Arc::new(SyncState::new()),
		server_inner,
	)
	.unwrap();

	assert!(peer.info.user_agent.ends_with(env!("CARGO_PKG_VERSION")));

	thread::sleep(time::Duration::from_secs(1));

	peer.send_ping(Difficulty::min(), 0).unwrap();
	thread::sleep(time::Duration::from_secs(1));

	let server_peer = server.peers.get_connected_peer(&my_addr).unwrap();
	assert_eq!(server_peer.info.total_difficulty(), Difficulty::min());
	assert!(server.peers.iter().connected().count() > 0);
}
