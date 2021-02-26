// Copyright 2021 The MWC Developers
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

//! Grin server implementation, glues the different parts of the system (mostly
//! the peer-to-peer server, the blockchain and the transaction pool) and acts
//! as a facade.

use libp2p::core::Multiaddr;
use libp2p::{
	core::{
		muxing::StreamMuxerBox,
		upgrade::{SelectUpgrade, Version},
		SimplePopSerializer, SimplePushSerializer,
	},
	dns::DnsConfig,
	identity::Keypair,
	mplex::MplexConfig,
	noise::{self, NoiseConfig, X25519Spec},
	swarm::SwarmBuilder,
	yamux::YamuxConfig,
	PeerId, Swarm, Transport,
};
use libp2p_tokio_socks5::Socks5TokioTcpConfig;

use libp2p::gossipsub::{
	self, GossipsubEvent, IdentTopic as Topic, MessageAuthenticity, ValidationMode,
};
use libp2p::gossipsub::{Gossipsub, MessageAcceptance, TopicHash};

use crate::{Error, ErrorKind};
use async_std::task;
use chrono::Utc;
use futures::{future, prelude::*};
use grin_p2p::PeerAddr;
use grin_util::secp::pedersen::{Commitment, RangeProof};
use grin_util::secp::rand::{thread_rng, Rng};
use grin_util::Mutex;
use libp2p::core::network::NetworkInfo;
use rand::seq::SliceRandom;
use std::{
	collections::HashMap,
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

use blake2_rfc::blake2b::blake2b;
use grin_core::core::hash::Hash;
use grin_util::secp::key::{PublicKey, SecretKey};
use grin_util::secp::{ContextFlag, Message, Secp256k1, Signature};
use std::collections::VecDeque;
use std::time::Instant;

struct TokioExecutor;
impl libp2p::core::Executor for TokioExecutor {
	fn exec(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
		tokio::spawn(future);
	}
}

lazy_static! {
	static ref LIBP2P_SWARM: Mutex<Option<Swarm<Gossipsub>>> = Mutex::new(None);
	static ref LIBP2P_PEERS: Mutex<HashMap<PeerId, (Vec<PeerId>, u64)>> =
		Mutex::new(HashMap::new());
	static ref THIS_NODE: PeerId = PeerId::random("".to_string());
}

// Message with same integrity output consensus
// History of the calls. 10 calls should be enough to compensate some glitches
pub const INTEGRITY_CALL_HISTORY_LEN_LIMIT: usize = 10;
// call interval limit, in second.
pub const INTEGRITY_CALL_MAX_PERIOD: i64 = 15;

/// Init Swarm instance. App expecting to have only single instance for everybody.
pub fn init_libp2p_swarm(swarm: Swarm<Gossipsub>) {
	LIBP2P_SWARM.lock().replace(swarm);
}
/// Report that libp2p connection is done
pub fn reset_libp2p_swarm() {
	LIBP2P_SWARM.lock().take();
}

/// Report the seed list. We will add them as a found peers. That should be enough for bootstraping
pub fn set_seed_list(seed_list: &Vec<PeerAddr>) {
	for s in seed_list {
		match s {
			PeerAddr::Onion(_) => {
				if let Err(e) = add_new_peer(s) {
					error!("Unable to add libp2p peer, {}", e);
				}
			}
			_ => {}
		}
	}
}

/// Request number of established connections to libp2p
pub fn get_libp2p_connections() -> u32 {
	match &*LIBP2P_SWARM.lock() {
		Some(swarm) => Swarm::network_info(swarm)
			.connection_counters()
			.num_connections(),
		None => 0,
	}
}

/// Reporting new discovered mwc-wallet peer. That might be libp2p reep as well
pub fn add_new_peer(peer: &PeerAddr) -> Result<(), Error> {
	info!("libp2p adding a new peer {}", peer);
	let addr = format!(
		"/onion3/{}:81",
		peer.tor_pubkey().map_err(|e| ErrorKind::LibP2P(format!(
			"Unable to retrieve TOR pk from the peer address, {}",
			e
		)))?
	);

	let p = PeerId::from_multihash(THIS_NODE.clone().into(), addr)
		.map_err(|e| ErrorKind::LibP2P(format!("Unable to build the peer id, {:?}", e)))?;
	let cur_time = Utc::now().timestamp() as u64;
	let mut peer_list = LIBP2P_PEERS.lock();
	if let Some((peers, time)) = peer_list.get_mut(&THIS_NODE) {
		if !peers.contains(&p) {
			peers.push(p);
		}
		*time = cur_time;
	} else {
		peer_list.insert(THIS_NODE.clone(), (vec![p], cur_time));
	}

	Ok(())
}

/// Created libp2p listener for Socks5 tor address.
/// tor_socks_port - listener port, param from  SocksPort 127.0.0.1:51234
/// output_validation_fn - output validation method. Return RangeProof if that output was seen during last 24 hours (last 1440 blocks)
pub async fn run_libp2p_node(
	tor_socks_port: u16,
	onion_address: String,
	libp2p_port: u16,
	output_validation_fn: impl Fn(&Commitment) -> Option<RangeProof>,
	message_handlers: HashMap<String, fn(Vec<u8>) -> ()>,
) -> Result<(), Error> {
	// need to remove '.onion' ending first
	let onion_address = &onion_address[..(onion_address.len() - ".onion".len())];

	// Init Tor address configs..
	// 80 comes from: /tor/listener/torrc   HiddenServicePort 80 0.0.0.0:13425
	let addr_str = format!("/onion3/{}:81", onion_address);
	let addr = addr_str.parse::<Multiaddr>().map_err(|e| {
		ErrorKind::NotOnion(format!("Unable to construct onion multiaddress, {}", e))
	})?;

	let mut map = HashMap::new();
	map.insert(addr.clone(), libp2p_port);

	// Build swarm (libp2p stuff)
	// Each time will join with a new p2p node ID. I think it is fine, let's keep p2p network dynamic
	let id_keys = Keypair::generate_ed25519();
	let this_peer_id = PeerId::from_public_key(id_keys.public(), addr_str.clone());

	// Building transport
	let dh_keys = noise::Keypair::<X25519Spec>::new()
		.into_authentic(&id_keys)
		.map_err(|e| ErrorKind::LibP2P(format!("Unable to build p2p keys, {}", e)))?;
	let noise = NoiseConfig::xx(dh_keys).into_authenticated(addr_str.to_string());
	let tcp = Socks5TokioTcpConfig::new(tor_socks_port)
		.nodelay(true)
		.onion_map(map);
	let transport = DnsConfig::new(tcp)
		.map_err(|e| ErrorKind::LibP2P(format!("Unable to build a transport, {}", e)))?;

	let transport = transport
		.upgrade(Version::V1)
		.authenticate(noise)
		.multiplex(SelectUpgrade::new(
			YamuxConfig::default(),
			MplexConfig::new(),
		))
		.map(|(peer, muxer), _| (peer, StreamMuxerBox::new(muxer)))
		.boxed();

	//Ping pond already works. But it is not we needed
	// mwc-node does nothing, just forming a node with aping.
	/*    let config = PingConfig::new()
			.with_keep_alive(true)
			.with_interval(Duration::from_secs(600))
			.with_timeout(Duration::from_secs(60))
			.with_max_failures( NonZeroU32::new(2).unwrap() );
		let behaviour = Ping::new(config);
	*/

	// Set a custom gossipsub
	let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
		.heartbeat_interval(Duration::from_secs(5)) // This is set to aid debugging by not cluttering the log space
		.validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
		.validate_messages() // !!!!! Now we are responsible for validation of all incoming traffic!!!!
		.build()
		.expect("Valid gossip config");

	// Here are how many connection we will try to keep...
	let connections_number_low = gossipsub_config.mesh_n_high();

	// build a gossipsub network behaviour
	let gossipsub: gossipsub::Gossipsub =
		gossipsub::Gossipsub::new(MessageAuthenticity::Signed(id_keys), gossipsub_config)
			.expect("Correct configuration");

	// subscribes to our topic

	let mut swarm = SwarmBuilder::new(transport, gossipsub, this_peer_id.clone())
		.executor(Box::new(TokioExecutor))
		.build();

	Swarm::listen_on(&mut swarm, addr.clone())
		.map_err(|e| ErrorKind::LibP2P(format!("Unable to start listening, {}", e)))?;

	/*   // It is ping pong handler
	 future::poll_fn(move |cx: &mut Context<'_>| loop {
		match swarm.poll_next_unpin(cx) {
			Poll::Ready(Some(event)) => println!("{:?}", event),
			Poll::Ready(None) => return Poll::Ready(()),
			Poll::Pending => return Poll::Pending,
		}
	})
	.await;*/

	init_libp2p_swarm(swarm);

	// Special topic for peer reporting. We don't need to listen on it and we
	// don't want the node forward that message as well
	let peer_topic = Topic::new(libp2p::gossipsub::PEER_TOPIC).hash();

	// Convert massage topics to hash
	let message_handlers: HashMap<TopicHash, fn(Vec<u8>) -> ()> = message_handlers
		.into_iter()
		.map(|(k, v)| (Topic::new(k).hash(), v))
		.collect();

	let mut requests_cash: HashMap<Commitment, VecDeque<i64>> = HashMap::new();
	let mut last_cash_clean = Instant::now();

	// Kick it off
	// Event processing future...
	task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
		let mut swarm = LIBP2P_SWARM.lock();
		match &mut *swarm {
			Some(swarm) => {
				loop {
					match swarm.poll_next_unpin(cx) {
						Poll::Ready(Some(gossip_event)) => match gossip_event {
							GossipsubEvent::Message {
								propagation_source: peer_id,
								message_id: id,
								message,
							} => {
								if message.topic == peer_topic {
									// We get new peers to connect. Let's update that
									if !Swarm::is_connected(&swarm, &peer_id) {
										error!(
											"Get topic from nodes that we are not connected to."
										);
										let gossip = swarm.get_behaviour();
										let _ = gossip.report_message_validation_result(
											&id,
											&peer_id,
											MessageAcceptance::Reject,
										);
										gossip.disconnect_peer(peer_id, true);
										continue;
									} else {
										// report validation for this message
										let gossip = swarm.get_behaviour();
										if let Err(e) = gossip.report_message_validation_result(
											&id,
											&peer_id,
											MessageAcceptance::Ignore,
										) {
											error!("report_message_validation_result failed for error {}", e);
										}
									}

									let mut serializer = SimplePopSerializer::new(&message.data);
									if serializer.version != 1 {
										warn!("Get peer info data of unexpected version. Probably your client need to be upgraded");
										continue;
									}

									let sz = serializer.pop_u16() as usize;
									if sz > gossipsub::PEER_EXCHANGE_NUMBER_LIMIT {
										warn!("Get too many peers from {}", peer_id);
										// let's ban it, probably it is an attacker...
										let gossip = swarm.get_behaviour();
										gossip.disconnect_peer(peer_id, true);
										continue;
									}

									let mut peer_arr = vec![];
									for _i in 0..sz {
										let peer_data = serializer.pop_vec();
										match PeerId::from_bytes(&peer_data) {
											Ok(peer) => {
												peer_arr.push(peer);
											}
											Err(e) => {
												warn!("Unable to decode the libp2p peer form the peer update message, {}", e);
												continue;
											}
										}
									}
									info!("Get {} peers from {}. Will process them later when we will need to increase connection number", peer_arr.len(), peer_id);
									let mut new_peers_list = LIBP2P_PEERS.lock();
									(*new_peers_list)
										.insert(peer_id, (peer_arr, Utc::now().timestamp() as u64));
								} else {
									// We get the regular message and we need to validate it now.

									let gossip = swarm.get_behaviour();
									if !validate_integrity_message(
										&peer_id,
										&message.data,
										&output_validation_fn,
										&mut requests_cash,
									) {
										let _ = gossip.report_message_validation_result(
											&id,
											&peer_id,
											MessageAcceptance::Reject,
										);
										debug!("report_message_validation_result failed because of integrity validation");
										continue;
									}

									// Message is valid, let's report that
									let _ = gossip.report_message_validation_result(
										&id,
										&peer_id,
										MessageAcceptance::Accept,
									);
									debug!("report_message_validation_result as accepted");

									// Here we can process the message. Let's check first if it is our topic
									if let Some(handler) = message_handlers.get(&message.topic) {
										(handler)(message.data);
									}
								}
							}
							_ => {}
						},
						Poll::Ready(None) | Poll::Pending => break,
					}
				}

				// let's try to make a new connection if needed
				let nw_info: NetworkInfo = Swarm::network_info(&swarm);

				if nw_info.connection_counters().num_connections() < connections_number_low as u32 {
					// Let's try to connect to somebody if we can...
					let mut address_to_connect: Option<Multiaddr> = None;
					let rng = &mut thread_rng();
					loop {
						let mut libp2p_peers = LIBP2P_PEERS.lock();
						let peers: Vec<PeerId> = libp2p_peers.keys().cloned().collect();
						if let Some(peer_id) = peers.choose(rng) {
							if let Some(peers) = libp2p_peers.get_mut(peer_id) {
								if !peers.0.is_empty() {
									let p = peers.0.remove(rng.gen::<usize>() % peers.0.len());
									if Swarm::is_connected(&swarm, &p)
										|| Swarm::is_dialing(&swarm, &p) || p == this_peer_id
									{
										continue;
									}

									match p.get_address().parse::<Multiaddr>() {
										Ok(addr) => {
											address_to_connect = Some(addr);
											break;
										}
										Err(e) => {
											warn!("Unable to construct onion multiaddress from the peer address. Will skip it, {}", e);
											continue;
										}
									}
								} else {
									libp2p_peers.remove(peer_id);
									continue;
								}
							}
							continue;
						} else {
							break; // no data is found...
						}
					}

					// The address of a new peer is selected, we can deal to it.
					if let Some(addr) = address_to_connect {
						match Swarm::dial_addr(swarm, addr.clone()) {
							Ok(_) => {
								info!("Dialling to a new peer {}", addr);
							}
							Err(con_limit) => {
								error!("Unable deal to a new peer. Connected to {} peers, connection limit {}", con_limit.current, con_limit.limit);
							}
						}
					}
				}

				// cleanup expired requests_cash values
				let history_time_limit = Utc::now().timestamp()
					- INTEGRITY_CALL_HISTORY_LEN_LIMIT as i64 * INTEGRITY_CALL_MAX_PERIOD;
				if last_cash_clean + Duration::from_secs(600) < Instant::now() {
					// Let's do clean up...
					requests_cash.retain(|_commit, history| {
						*history.back().unwrap_or(&0) > history_time_limit
					});
					last_cash_clean = Instant::now();
				}
			}
			None => (),
		};

		Poll::Pending as Poll<()>
	}));

	Ok(())
}

// return true if this message is valid. It is caller responsibility to make sure that valid_outputs cache is well maintained
fn validate_integrity_message(
	peer_id: &PeerId,
	message: &Vec<u8>,
	output_validation_fn: impl Fn(&Commitment) -> Option<RangeProof>,
	requests_cash: &mut HashMap<Commitment, VecDeque<i64>>,
) -> bool {
	let mut ser = SimplePopSerializer::new(message);
	if ser.version != 1 {
		debug!(
			"Get message with invalid version {} from peer {}",
			ser.version, peer_id
		);
		debug_assert!(false); // Upgrade me
		return false;
	}

	let integrity_commit = Commitment::from_vec(ser.pop_vec());
	let integrity_rangeproof = match (output_validation_fn)(&integrity_commit) {
		Some(r) => r.clone(),
		None => {
			debug!(
				"Get invalid message from peer {}. Integrity_commit is not found in the cache",
				peer_id
			);
			return false;
		}
	};

	let integrity_pub_key = match PublicKey::from_slice(&ser.pop_vec()) {
		Ok(p) => p,
		Err(e) => {
			debug!(
				"Get invalid message from peer {}. Unable to read integrity public key, {}",
				peer_id, e
			);
			return false;
		}
	};

	let signature = match Signature::from_compact(&ser.pop_vec()) {
		Ok(s) => s,
		Err(e) => {
			debug!(
				"Get invalid message from peer {}. Unable to read signature, {}",
				peer_id, e
			);
			return false;
		}
	};

	let secp = Secp256k1::with_caps(ContextFlag::VerifyOnly);

	// Checking if public key match the signature.
	let msg_hash = Hash::from_vec(&peer_id.to_bytes());
	let msg_message = match Message::from_slice(msg_hash.as_bytes()) {
		Ok(m) => m,
		Err(e) => {
			debug!(
				"Get invalid message from peer {}. Unable to build a message, {}",
				peer_id, e
			);
			return false;
		}
	};
	if secp
		.verify(&msg_message, &signature, &integrity_pub_key)
		.is_err()
	{
		debug!(
			"Get invalid message from peer {}. Invalid signature, public key and message",
			peer_id
		);
		return false;
	}

	// Check if public ket belong to the output...
	let rewind_hash = blake2b(32, &[], &integrity_pub_key.serialize_vec(true)[..])
		.as_bytes()
		.to_vec();
	let commit_hash = blake2b(32, &integrity_commit.0, &rewind_hash);
	let commit_nonce = match SecretKey::from_slice(commit_hash.as_bytes()) {
		Ok(s) => s,
		Err(e) => {
			debug!(
				"Get invalid message from peer {}. Unable to create nonce to check commit, {}",
				peer_id, e
			);
			return false;
		}
	};

	let info = secp.rewind_bullet_proof(integrity_commit, commit_nonce, None, integrity_rangeproof);
	if info.is_err() {
		debug!(
			"Get invalid message from peer {}. Integrity commit ownership is not provided.",
			peer_id
		);
		return false;
	}

	// Updating calls history cash.
	let now = Utc::now().timestamp();
	match requests_cash.get_mut(&integrity_commit) {
		Some(calls) => {
			calls.push_back(now);
			while calls.len() > INTEGRITY_CALL_HISTORY_LEN_LIMIT {
				calls.pop_front();
			}
		}
		None => {
			let mut calls: VecDeque<i64> = VecDeque::new();
			calls.push_back(now);
			requests_cash.insert(integrity_commit.clone(), calls);
		}
	}
	// Checking if ths peer sent too many messages
	let call_history = requests_cash.get(&integrity_commit).unwrap();
	if call_history.len() >= INTEGRITY_CALL_HISTORY_LEN_LIMIT {
		let call_period = (call_history.back().unwrap() - call_history.front().unwrap())
			/ (call_history.len() - 1) as i64;
		if call_period < INTEGRITY_CALL_MAX_PERIOD {
			debug!(
				"Get invalid message from peer {}. Message sending period is {}, limit {}",
				peer_id, call_period, INTEGRITY_CALL_MAX_PERIOD
			);
			return false;
		}
	}

	debug!("Validated the message from peer {}", peer_id);
	return true;
}

/// Skip the header and return the message data
pub fn read_integrity_message(message: &Vec<u8>) -> Vec<u8> {
	let mut ser = SimplePopSerializer::new(message);
	if ser.version != 1 {
		debug_assert!(false); // Upgrade me
		return vec![];
	}

	// Skipping header data. The header size if not known because bulletproof size can vary.
	ser.skip_vec();
	ser.skip_vec();
	ser.skip_vec();

	// Here is the data
	ser.pop_vec()
}

/// Helper method for the wallet that allow to build a message with integrity_output
/// peer_id  - libp2p peer to sign the image
/// integrity_output  - output that we are using for signature
/// integrity_pub_key & integrity_secret - secret and public key to sign the message
/// message_data - message to put into the package
pub fn build_integrity_message(
	peer_id: &PeerId,
	integrity_output: &Commitment,
	integrity_pub_key: &PublicKey,
	integrity_secret: &SecretKey,
	message_data: &[u8],
) -> Result<Vec<u8>, Error> {
	let msg_hash = Hash::from_vec(&peer_id.to_bytes());
	let msg_message = Message::from_slice(msg_hash.as_bytes())?;

	let secp = Secp256k1::new();
	let signature = secp.sign(&msg_message, integrity_secret)?;

	let mut ser = SimplePushSerializer::new(1);

	ser.push_vec(&integrity_output.0);
	ser.push_vec(&integrity_pub_key.serialize_vec(true));
	ser.push_vec(&signature.serialize_compact());

	ser.push_vec(message_data);
	Ok(ser.to_vec())
}

#[test]
fn test_integrity() -> Result<(), Error> {
	use grin_core::libtx::secp_ser;
	use grin_util::from_hex;
	use serde::de::value::{Error as ValueError, StrDeserializer};
	use serde::de::IntoDeserializer;

	let peer_id = PeerId::random("/onion3/what_ever_address:77".to_string());
	let integrity_output = Commitment::from_vec(
		from_hex("08a655eccae831ee0f76740b86d1dcfa49cc56b3d188ae0aba7f5d07437809ae9b").unwrap(),
	);
	let deserializer: StrDeserializer<ValueError> = "0ec2ad284424bced592403def7e6e0d458f7243f0f15028d9bcc23c4b2f5519524a209821cccdc0bd4cec45559462fa3acae2c0d514d45a001c2ca296ba7165107c6141b55a93993969ceffea934efed0dd39675dcce48c7e5b98d92167f835c7525a43d397ce9b0276b934b818f1190b1c302d70ca7962870be4fbdee57327d79945c76e451d83f02bbdd72b588871a155806415c6deb7d95f5ecc251955d6bbc3ff137c7767994844d0e9b5e9db7861e7970f7870f7b35a43acfbd34fa1b15597bef738f88ad12c67eb50f398c5cfdea6f17fa92ab443167eb2d58da4aa420b675b9fe63e9913c8d54de9b03c64c7933959d1891374356d4f573a54b6225b5611ef29b39d4f85a8ee8af6e2059f8cad8f0da14a93379c881e864af6cd7ea0267d59a24ca4adaaf28c8444e6a544f37fb5b38b6b61ab9513c4e8967b85b8f05d7e83840fc251f1fd178f621da1d5d76f32ee451882c2227f23ff1fa04406572e65303c931c6f0cc703b661333858c2a8ff09d6ec1c6f661f6602eb35cbcf47385b9ce5b6ed620ea97c29db273087ab9930c0312f1e8eee83666e10ebf759e05cdb361ec8ad6e5ffe9e33e1a8ddd622b8197f2fd865292c8dca24ea2c5876e4b628b8cfad44594912db6c8df788c90a96c7169c7d904d8f230974df06d0f1b4b86a713be42c011148ac734fd75e71446b5352b2693a9b824aa424f059a7f4470f73a00fb29cb4f1f845f06f85fb4f6276aa095db6c5579b7e1e4fdb907ca1ab45395265e181e051933d60a2aaf1f20667094f38925f9a23c2de1da3008aed631cef05f3382ae3024b1464c54a1f848fda85a76407bebb0ec404d657534e3909ddad34fb6c78128a076047e48912bf68b36b548029787ae3e0f855724903346214e444c1fe5e9d5ce387adc0c6cdbdcb1397d8e035158e1b120a9d58ad5bf830a9aa6cb".into_deserializer();
	let integrity_proof = secp_ser::rangeproof_from_hex(deserializer).unwrap();

	let integrity_pub_key = PublicKey::from_slice(
		&from_hex("024f2192db5d6878124108e4cf7d2621163ff1e35cb1c86e21b810aa15eb9b1226").unwrap(),
	)
	.unwrap();
	let integrity_secret = SecretKey::from_slice(
		&from_hex("e6a04d60249a1d43684308aa6528601181052f009f7732a9ec2aeb690d0fef0d").unwrap(),
	)
	.unwrap();

	let message: Vec<u8> = vec![1, 2, 3, 4, 3, 2, 1];

	let encoded_message = build_integrity_message(
		&peer_id,
		&integrity_output,
		&integrity_pub_key,
		&integrity_secret,
		&message,
	)
	.unwrap();

	// Validation use case
	let mut requests_cache: HashMap<Commitment, VecDeque<i64>> = HashMap::new();

	let empty_output_validation_fn = |_commit: &Commitment| -> Option<RangeProof> { None };

	let mut valid_outputs = HashMap::<Commitment, RangeProof>::new();
	valid_outputs.insert(integrity_output, integrity_proof);
	let output_validation_fn =
		|commit: &Commitment| -> Option<RangeProof> { valid_outputs.get(commit).cloned() };

	// Valid outputs is empty, should fail.
	assert_eq!(
		validate_integrity_message(
			&peer_id,
			&encoded_message,
			empty_output_validation_fn,
			&mut requests_cache
		),
		false
	);
	assert!(requests_cache.is_empty());

	assert_eq!(
		validate_integrity_message(
			&peer_id,
			&encoded_message,
			output_validation_fn,
			&mut requests_cache
		),
		true
	);
	assert!(requests_cache.len() == 1);
	assert!(requests_cache.get(&integrity_output).unwrap().len() == 1); // call history is onw as well

	requests_cache.clear();
	assert_eq!(
		validate_integrity_message(
			&PeerId::random("another_peer_address".to_string()),
			&encoded_message,
			output_validation_fn,
			&mut requests_cache
		),
		false
	);
	assert!(requests_cache.len() == 0);

	// Checking if ddos will be recognized.
	for i in 0..(INTEGRITY_CALL_HISTORY_LEN_LIMIT - 1) {
		assert_eq!(
			validate_integrity_message(
				&peer_id,
				&encoded_message,
				output_validation_fn,
				&mut requests_cache
			),
			true
		);
		assert!(requests_cache.len() == 1);
		assert!(requests_cache.get(&integrity_output).unwrap().len() == i + 1); // call history is onw as well
	}
	// And now all next request will got to spam
	assert_eq!(
		validate_integrity_message(
			&peer_id,
			&encoded_message,
			output_validation_fn,
			&mut requests_cache
		),
		false
	);
	assert!(
		requests_cache.get(&integrity_output).unwrap().len() == INTEGRITY_CALL_HISTORY_LEN_LIMIT
	); // call history is onw as well
	assert_eq!(
		validate_integrity_message(
			&peer_id,
			&encoded_message,
			output_validation_fn,
			&mut requests_cache
		),
		false
	);
	assert!(
		requests_cache.get(&integrity_output).unwrap().len() == INTEGRITY_CALL_HISTORY_LEN_LIMIT
	); // call history is onw as well
	assert_eq!(
		validate_integrity_message(
			&peer_id,
			&encoded_message,
			output_validation_fn,
			&mut requests_cache
		),
		false
	);
	assert!(
		requests_cache.get(&integrity_output).unwrap().len() == INTEGRITY_CALL_HISTORY_LEN_LIMIT
	); // call history is onw as well

	assert_eq!(read_integrity_message(&encoded_message), message);

	Ok(())
}
