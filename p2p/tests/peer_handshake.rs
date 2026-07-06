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

use mwc_chain::SyncState;
use mwc_core::core::hash::Hash;
use mwc_core::global;
use mwc_core::pow::Difficulty;
use mwc_core::ser::{self, ProtocolVersion};
use mwc_crates::tempfile::TempDir;
use mwc_crates::tokio::net::TcpStream;
use mwc_p2p::types::PeerAddr;
use mwc_p2p::Peer;
use mwc_util::StopState;
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream as StdTcpStream};
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
const BANNED_OUTBOUND_TEST_CONTEXT_ID: u32 = 101;
const BAD_INBOUND_HANDSHAKE_TEST_CONTEXT_ID: u32 = 102;
const BANNED_OUTBOUND_PREDIAL_TEST_CONTEXT_ID: u32 = 103;

// Setup test with AutomatedTesting chain_type;
fn test_setup(context_id: u32) {
	// Set "global" chain type here as we spawn peer threads for read/write.
	global::init_global_chain_type(context_id, global::ChainTypes::AutomatedTesting).unwrap();
	global::init_global_nrd_enabled(context_id, false).unwrap();
	global::init_global_accept_fee_base(context_id, 1000).unwrap();
	mwc_util::init_test_logger().unwrap();
	mwc_util::init_global_runtime().unwrap();
}

fn write_hand_message(socket: &mut StdTcpStream, hand: mwc_p2p::msg::Hand, context_id: u32) {
	let version = ProtocolVersion::local();
	let body = ser::ser_vec(context_id, &hand, version).unwrap();
	let header = mwc_p2p::msg::MsgHeader::new(context_id, mwc_p2p::msg::Type::Hand, body.len());
	let header = ser::ser_vec(context_id, &header, version).unwrap();
	socket.write_all(&header).unwrap();
	socket.write_all(&body).unwrap();
	socket.flush().unwrap();
}

// Starts a server and connects a client peer to it to check handshake,
// followed by a ping/pong exchange to make sure the connection is live.
#[test]
fn peer_handshake() {
	test_setup(HANDSHAKE_TEST_CONTEXT_ID);

	let mut p2p_config = mwc_p2p::P2PConfig::default();
	p2p_config.port = open_port();
	p2p_config.peers_allow = None;
	p2p_config.peers_deny = None;
	let mut tor_config = mwc_p2p::TorConfig::default();
	tor_config.tor_enabled = Some(false);

	let db_root = TempDir::new().unwrap();
	let net_adapter = Arc::new(mwc_p2p::DummyAdapter {});
	let stop_state = Arc::new(StopState::new());
	let server_inner = mwc_p2p::Server::new(
		HANDSHAKE_TEST_CONTEXT_ID,
		db_root.path().to_str().unwrap(),
		mwc_p2p::Capabilities::UNKNOWN,
		&p2p_config,
		&tor_config,
		net_adapter.clone(),
		Hash::from_vec(&vec![]),
		Arc::new(SyncState::new()),
		stop_state.clone(),
	)
	.unwrap();
	let server = Arc::new(server_inner.clone());

	let p2p_inner = server.clone();
	let (p2p_tx, p2p_rx) = mpsc::sync_channel::<Result<(), mwc_p2p::Error>>(1);
	let listen_thread = thread::spawn(move || p2p_inner.listen(Some(p2p_tx)));

	p2p_rx.recv().unwrap().unwrap();

	let async_rt = mwc_util::global_runtime().unwrap();

	let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), p2p_config.port);
	let socket = async_rt.block_on(async {
		let socket = TcpStream::connect(&addr).await;
		socket.unwrap()
	});

	let stream = mwc_p2p::tor::tcp_data_stream::TcpDataStream::from_tcp(socket);
	let my_addr = PeerAddr::Ip("127.0.0.1:5000".parse().unwrap());
	let (peer, stream) = Peer::connect(
		stream,
		mwc_p2p::Capabilities::UNKNOWN,
		Difficulty::min(),
		my_addr.clone(),
		&mwc_p2p::handshake::Handshake::new(
			HANDSHAKE_TEST_CONTEXT_ID,
			Hash::from_vec(&vec![]),
			p2p_config.clone(),
			None,
			None,
		),
		net_adapter,
		&PeerAddr::Ip(format!("127.0.0.1:{}", p2p_config.port).parse().unwrap()),
		HANDSHAKE_TEST_CONTEXT_ID,
	)
	.unwrap();
	peer.start_listening(stream, Arc::new(SyncState::new()), server_inner)
		.unwrap();

	assert!(peer.info.user_agent.ends_with(env!("CARGO_PKG_VERSION")));

	thread::sleep(time::Duration::from_secs(1));

	peer.send_ping(Difficulty::min(), 0).unwrap();
	thread::sleep(time::Duration::from_secs(1));

	let server_peer = server.peers.get_connected_peer(&my_addr).unwrap();
	assert_eq!(server_peer.info.total_difficulty(), Difficulty::min());
	assert!(server.peers.iter().connected().count() > 0);

	stop_state.stop();
	listen_thread.join().unwrap().unwrap();
}

#[test]
fn peer_connect_rejects_banned_outbound_peer() {
	test_setup(BANNED_OUTBOUND_TEST_CONTEXT_ID);

	let mut p2p_config = mwc_p2p::P2PConfig::default();
	p2p_config.port = open_port();
	p2p_config.peers_allow = None;
	p2p_config.peers_deny = None;
	let mut tor_config = mwc_p2p::TorConfig::default();
	tor_config.tor_enabled = Some(false);

	let db_root = TempDir::new().unwrap();
	let net_adapter = Arc::new(mwc_p2p::DummyAdapter {});
	let server_inner = mwc_p2p::Server::new(
		BANNED_OUTBOUND_TEST_CONTEXT_ID,
		db_root.path().to_str().unwrap(),
		mwc_p2p::Capabilities::UNKNOWN,
		&p2p_config,
		&tor_config,
		net_adapter,
		Hash::from_vec(&vec![]),
		Arc::new(SyncState::new()),
		Arc::new(StopState::new()),
	)
	.unwrap();

	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let addr = listener.local_addr().unwrap();
	let accept_thread = thread::spawn(move || {
		let _ = listener.accept().unwrap();
	});

	let peer_addr = PeerAddr::Ip(addr);
	server_inner
		.peers
		.add_banned(peer_addr.clone(), mwc_p2p::ReasonForBan::BadHandshake)
		.unwrap();

	let async_rt = mwc_util::global_runtime().unwrap();
	let socket = async_rt.block_on(async { TcpStream::connect(&addr).await.unwrap() });
	let stream = mwc_p2p::tor::tcp_data_stream::TcpDataStream::from_tcp(socket);
	let my_addr = PeerAddr::Ip("127.0.0.1:5001".parse().unwrap());

	let err = match Peer::connect(
		stream,
		mwc_p2p::Capabilities::UNKNOWN,
		Difficulty::min(),
		my_addr,
		&mwc_p2p::handshake::Handshake::new(
			BANNED_OUTBOUND_TEST_CONTEXT_ID,
			Hash::from_vec(&vec![]),
			p2p_config,
			None,
			None,
		),
		server_inner.peers.clone(),
		&peer_addr,
		BANNED_OUTBOUND_TEST_CONTEXT_ID,
	) {
		Ok(_) => panic!("expected banned peer rejection"),
		Err(err) => err,
	};

	accept_thread.join().unwrap();

	match err {
		mwc_p2p::Error::ConnectionClose(message) => {
			assert_eq!(message, "Peer denied because it is banned");
		}
		other => panic!("expected banned peer rejection, got {:?}", other),
	}
	assert!(server_inner.peers.is_banned(&peer_addr).unwrap());
}

#[test]
fn server_connect_rejects_banned_peer_before_dialing() {
	test_setup(BANNED_OUTBOUND_PREDIAL_TEST_CONTEXT_ID);

	let mut p2p_config = mwc_p2p::P2PConfig::default();
	p2p_config.port = open_port();
	p2p_config.peers_allow = None;
	p2p_config.peers_deny = None;
	let mut tor_config = mwc_p2p::TorConfig::default();
	tor_config.tor_enabled = Some(false);

	let db_root = TempDir::new().unwrap();
	let server = mwc_p2p::Server::new(
		BANNED_OUTBOUND_PREDIAL_TEST_CONTEXT_ID,
		db_root.path().to_str().unwrap(),
		mwc_p2p::Capabilities::UNKNOWN,
		&p2p_config,
		&tor_config,
		Arc::new(mwc_p2p::DummyAdapter {}),
		Hash::from_vec(&vec![]),
		Arc::new(SyncState::new()),
		Arc::new(StopState::new()),
	)
	.unwrap();

	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	listener.set_nonblocking(true).unwrap();
	let peer_addr = PeerAddr::Ip(listener.local_addr().unwrap());
	server
		.peers
		.add_banned(peer_addr.clone(), mwc_p2p::ReasonForBan::ManualBan)
		.unwrap();

	match server.connect(&peer_addr) {
		Err(mwc_p2p::Error::ConnectionClose(message)) => {
			assert_eq!(message, "Peer denied because it is banned");
		}
		other => panic!("expected banned peer rejection, got {:?}", other),
	}

	match listener.accept() {
		Err(e) if e.kind() == ErrorKind::WouldBlock => {}
		Ok(_) => panic!("banned peer received an outbound dial"),
		Err(e) => panic!("unexpected listener error: {:?}", e),
	}
}

#[test]
fn inbound_bad_handshake_bans_known_ip_source() {
	test_setup(BAD_INBOUND_HANDSHAKE_TEST_CONTEXT_ID);

	let mut p2p_config = mwc_p2p::P2PConfig::default();
	p2p_config.port = open_port();
	p2p_config.peers_allow = None;
	p2p_config.peers_deny = None;
	let mut tor_config = mwc_p2p::TorConfig::default();
	tor_config.tor_enabled = Some(false);

	let db_root = TempDir::new().unwrap();
	let net_adapter = Arc::new(mwc_p2p::DummyAdapter {});
	let stop_state = Arc::new(StopState::new());
	let server_inner = mwc_p2p::Server::new(
		BAD_INBOUND_HANDSHAKE_TEST_CONTEXT_ID,
		db_root.path().to_str().unwrap(),
		mwc_p2p::Capabilities::UNKNOWN,
		&p2p_config,
		&tor_config,
		net_adapter,
		Hash::from_vec(&vec![]),
		Arc::new(SyncState::new()),
		stop_state.clone(),
	)
	.unwrap();
	let server = Arc::new(server_inner.clone());

	let p2p_inner = server.clone();
	let (p2p_tx, p2p_rx) = mpsc::sync_channel::<Result<(), mwc_p2p::Error>>(1);
	let listen_thread = thread::spawn(move || p2p_inner.listen(Some(p2p_tx)));

	p2p_rx.recv().unwrap().unwrap();

	let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), p2p_config.port);
	let mut socket = StdTcpStream::connect(server_addr).unwrap();
	let source_addr = PeerAddr::Ip(socket.local_addr().unwrap());
	let hand = mwc_p2p::msg::Hand {
		version: ProtocolVersion::local(),
		capabilities: mwc_p2p::Capabilities::UNKNOWN,
		nonce: 42,
		genesis: Hash::from_vec(&vec![]),
		total_difficulty: Difficulty::min(),
		sender_addr: PeerAddr::Onion(
			"4vrh6vagyrw7du3vdcjk4u4g42qsb6dga6vevpds23fkgh6tw363hhyd.onion".to_string(),
		),
		receiver_addr: PeerAddr::Ip(server_addr),
		user_agent: "bad-handshake-test".to_string(),
		tx_fee_base: global::get_accept_fee_base(BAD_INBOUND_HANDSHAKE_TEST_CONTEXT_ID),
		onion_sig: None,
		onion_sig_timestamp: None,
	};

	write_hand_message(&mut socket, hand, BAD_INBOUND_HANDSHAKE_TEST_CONTEXT_ID);
	drop(socket);

	let mut banned = false;
	for _ in 0..60 {
		if server.peers.is_banned(&source_addr).unwrap() {
			banned = true;
			break;
		}
		thread::sleep(time::Duration::from_millis(50));
	}

	stop_state.stop();
	listen_thread.join().unwrap().unwrap();

	assert!(
		banned,
		"expected bad inbound handshake to ban {}",
		source_addr
	);
}
