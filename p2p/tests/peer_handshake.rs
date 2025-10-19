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
use mwc_util::tokio::net::TcpStream;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{mpsc, Arc};
use std::{thread, time};

fn open_port() -> u16 {
	// use port 0 to allow the OS to assign an open port
	// TcpListener's Drop impl will unbind the port as soon as
	// listener goes out of scope
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	listener.local_addr().unwrap().port()
}

const HANDSHAKE_TEST_CONTEXT_ID: u32 = 100;

// Setup test with AutomatedTesting chain_type;
fn test_setup() {
	// Set "global" chain type here as we spawn peer threads for read/write.
	global::init_global_chain_type(
		HANDSHAKE_TEST_CONTEXT_ID,
		global::ChainTypes::AutomatedTesting,
	);
	global::init_global_nrd_enabled(HANDSHAKE_TEST_CONTEXT_ID, false);
	global::init_global_accept_fee_base(HANDSHAKE_TEST_CONTEXT_ID, 1000);
	util::init_test_logger();
}

// Starts a server and connects a client peer to it to check handshake,
// followed by a ping/pong exchange to make sure the connection is live.
#[test]
fn peer_handshake() {
	test_setup();

	let p2p_config = p2p::P2PConfig {
		port: open_port(),
		peers_allow: None,
		peers_deny: None,
		..p2p::P2PConfig::default()
	};
	let mut tor_config = p2p::TorConfig::default();
	tor_config.tor_enabled = Some(true);
	tor_config.tor_external = Some(true);
	tor_config.onion_address =
		Some("qwjqqd4l74ecgcy3ebkzk7nvmxu2swb7u3nyu4u3s6sa7iw3bsmzbnyd.onion".into());

	let net_adapter = Arc::new(p2p::DummyAdapter {});
	let server_inner = p2p::Server::new(
		HANDSHAKE_TEST_CONTEXT_ID,
		".mwc",
		p2p::Capabilities::UNKNOWN,
		&p2p_config,
		&tor_config,
		net_adapter.clone(),
		Hash::from_vec(&vec![]),
		Arc::new(SyncState::new()),
		Arc::new(StopState::new()),
	)
	.unwrap();
	let server = Arc::new(server_inner.clone());

	let p2p_inner = server.clone();
	let (p2p_tx, p2p_rx) = mpsc::sync_channel::<Result<(), mwc_p2p::Error>>(1);
	let _ = thread::spawn(move || p2p_inner.listen(p2p_tx));

	p2p_rx.recv().unwrap().unwrap();

	let async_rt = mwc_util::global_runtime();

	let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), p2p_config.port);
	let socket = async_rt.block_on(async {
		let socket = TcpStream::connect(&addr).await;
		socket.unwrap()
	});

	let stream = p2p::tcp_data_stream::TcpDataStream::from_tcp(socket);
	let my_addr = PeerAddr::Ip("127.0.0.1:5000".parse().unwrap());
	let peer = Peer::connect(
		stream,
		p2p::Capabilities::UNKNOWN,
		Difficulty::min(),
		my_addr.clone(),
		&p2p::handshake::Handshake::new(
			HANDSHAKE_TEST_CONTEXT_ID,
			Hash::from_vec(&vec![]),
			p2p_config.clone(),
			None,
		),
		net_adapter,
		&PeerAddr::Ip(format!("127.0.0.1:{}", p2p_config.port).parse().unwrap()),
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
