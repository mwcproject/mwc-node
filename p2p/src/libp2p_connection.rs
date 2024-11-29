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

//! Mwc server implementation, glues the different parts of the system (mostly
//! the peer-to-peer server, the blockchain and the transaction pool) and acts
//! as a facade.

use mwc_libp2p::core::Multiaddr;
use mwc_libp2p::{
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
use mwc_libp2p_tokio_socks5::Socks5TokioTcpConfig;

use mwc_libp2p::gossipsub::{
	self, GossipsubEvent, IdentTopic as Topic, MessageAuthenticity, MessageId, ValidationMode,
};
use mwc_libp2p::gossipsub::{Gossipsub, MessageAcceptance, TopicHash};

use crate::mwc_core::global;
use crate::types::Error;
use crate::PeerAddr;
use async_std::task;
use chrono::Utc;
use ed25519_dalek::PublicKey as DalekPublicKey;
use futures::{future, prelude::*};
use mwc_core::core::hash::Hash;
use mwc_core::core::TxKernel;
use mwc_core::libtx::aggsig;
use mwc_libp2p::core::network::NetworkInfo;
use mwc_util::secp::pedersen::Commitment;
use mwc_util::secp::rand::Rng;
use mwc_util::secp::{ContextFlag, Message, Secp256k1, Signature};
use mwc_util::RwLock;
use mwc_util::{Mutex, OnionV3Address, OnionV3AddressError, ToHex};
use rand::seq::SliceRandom;
use std::collections::VecDeque;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Instant;
use std::{
	collections::HashMap,
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

struct TokioExecutor;
impl mwc_libp2p::core::Executor for TokioExecutor {
	fn exec(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
		tokio::spawn(future);
	}
}

/// Message that was received from libp2p gossipsub network
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivedMessage {
	/// Unix timestamp when this message was received
	pub timestamp: i64,
	/// Peer who send the message
	pub peer_id: String,
	/// Topic that received the message
	pub topic: String,
	/// Integrity fee that was paid
	pub fee: u64,
	/// The message.
	pub message: String,
}

const MESSAGING_RECEIVED_LIMIT: usize = 1000;

lazy_static! {
	static ref LIBP2P_SWARM: Mutex<Option<Swarm<Gossipsub>>> = Mutex::new(None);
	/// Discovered Peer Onion addresses
	static ref LIBP2P_PEERS: RwLock<HashMap<String, (Vec<String>, u64)>> =
		RwLock::new(HashMap::new());

	static ref THIS_PEER_ID: RwLock<Option<PeerId>> = RwLock::new(None);
	// Message handlers arguments: topic hash, message (no header), paid integrity fee
	//   Handler must return false if the message is incorrect, so the peer must be banned.
	static ref LIBP2P_MESSAGE_HANDLERS: RwLock<HashMap<TopicHash, (fn(sender_address: &String, topic: &TopicHash, Vec<u8>, u64) -> bool, Topic)>> = RwLock::new(HashMap::new());

	/// Seeds peer list. Will use it if not connections are available.
	static ref SEED_LIST: RwLock<Vec<PeerAddr>> = RwLock::new(vec![]);

	// Topics that we are listening now
	static ref MESSAGING_TOPICS: RwLock<HashMap<TopicHash, (String, Topic, u64)>> = RwLock::new(HashMap::new());

	/// Received messages
	static ref MESSAGING_RECEIVED: RwLock<VecDeque<ReceivedMessage>> = RwLock::new(VecDeque::new());
}

// Message with same integrity output consensus
// History of the calls. 10 calls should be enough to compensate some glitches
pub const INTEGRITY_CALL_HISTORY_LEN_LIMIT: usize = 10;
// call interval limit, in second.
pub const INTEGRITY_CALL_MAX_PERIOD: i64 = 15;

/// Number of top block when integrity fee is valid.  24 hours + 3 blocks. 3 blocks it is a minimum confirmations numbers that is required
pub const INTEGRITY_FEE_VALID_BLOCKS: u64 = 1443;
/// Minimum integrity fee value in term of Base fees
pub const INTEGRITY_FEE_MIN_X: u64 = 10;

pub fn get_this_peer_id() -> Option<PeerId> {
	THIS_PEER_ID.read().clone()
}
pub fn set_this_peer_id(peer_id: &PeerId) {
	THIS_PEER_ID.write().replace(peer_id.clone());
}

/// Init Swarm instance. App expecting to have only single instance for everybody.
pub fn init_libp2p_swarm(swarm: Swarm<Gossipsub>) {
	LIBP2P_SWARM.lock().replace(swarm);
}
/// Report that libp2p connection is done
pub fn reset_libp2p_swarm() {
	LIBP2P_SWARM.lock().take();
}

/// Report the seed list. We will add them as a found peers. That should be enough for bootstraping
pub fn set_seed_list(seed_list: &Vec<PeerAddr>, update_seed_list: bool) {
	if update_seed_list {
		*SEED_LIST.write() = seed_list.clone();
	}

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

pub fn get_libp2p_running() -> bool {
	LIBP2P_SWARM.lock().is_some()
}

/// Get topics that we are listening
pub fn get_topics() -> Vec<(String, Topic, u64)> {
	MESSAGING_TOPICS
		.read()
		.iter()
		.map(|(_k, v)| v.clone())
		.collect()
}

fn get_message_version() -> u16 {
	if global::is_mainnet() {
		1
	} else {
		256
	}
}

fn listener_handler(sender_address: &String, topic: &TopicHash, data: Vec<u8>, fee: u64) -> bool {
	if let Some((topic_str, _topic, min_fee)) = MESSAGING_TOPICS.read().get(topic) {
		if fee >= *min_fee {
			// Parse message. It should be Json string
			let message_str = match String::from_utf8(data) {
				Ok(s) => s,
				Err(_) => return false,
			};
			if serde_json::from_str::<serde_json::Value>(&message_str).is_err() {
				return false;
			}

			debug!(
				"Get a message from {}, on topic {},  data {}, fee {}",
				sender_address, topic_str, message_str, fee
			);

			// Everything looks good so far. We can keep the data
			{
				let mut messages = MESSAGING_RECEIVED.write();
				messages.retain(|m| m.message != message_str || m.peer_id != *sender_address);
				messages.push_back(ReceivedMessage {
					timestamp: Utc::now().timestamp(),
					peer_id: sender_address.clone(),
					topic: topic_str.clone(),
					fee,
					message: message_str,
				});
				while messages.len() > MESSAGING_RECEIVED_LIMIT {
					messages.pop_front();
				}
			}
		}
	}
	true
}

/// Start listening on the topic
pub fn add_topic(topic_str: &String, min_fee: u64) -> bool {
	let topic = Topic::new(topic_str.clone());

	match MESSAGING_TOPICS
		.write()
		.insert(topic.hash(), (topic_str.clone(), topic, min_fee))
	{
		Some(_) => (), // Data updated, already subscribed
		None => {
			add_topic_to_libp2p(&topic_str, listener_handler);
			return true;
		}
	}
	return false;
}

/// Remove topic from listening
pub fn remove_topic(topic_str: &String) -> bool {
	let topic = Topic::new(topic_str.clone());

	match MESSAGING_TOPICS.write().remove(&topic.hash()) {
		Some(_) => {
			remove_topic_from_libp2p(&topic_str);
			return true;
		}
		None => (),
	}
	return false;
}

pub fn inject_received_messaged(inject_msgs: Vec<ReceivedMessage>) {
	let mut messages = MESSAGING_RECEIVED.write();

	for inj_msg in inject_msgs {
		messages.retain(|m| m.message != inj_msg.message || m.peer_id != inj_msg.peer_id);
		messages.push_back(inj_msg);
	}

	while messages.len() > MESSAGING_RECEIVED_LIMIT {
		messages.pop_front();
	}
}

/// Read received messages
pub fn get_received_messages(delete: bool) -> VecDeque<ReceivedMessage> {
	if delete {
		let mut res: VecDeque<ReceivedMessage> = VecDeque::new();
		res.append(&mut *MESSAGING_RECEIVED.write());
		res
	} else {
		let mut messages = MESSAGING_RECEIVED.write();
		let time_limit = Utc::now().timestamp() - 600; // 10 minutes it is really more than enough for our needs.
		messages.retain(|m| m.timestamp > time_limit);
		messages.clone()
	}
}

/// Get number of received messages
pub fn get_received_messages_num() -> usize {
	MESSAGING_RECEIVED.read().len()
}

/// Stop listening on the topic
pub fn remove_topic_from_libp2p(topic: &str) {
	// remove topic and handler
	let topic = Topic::new(topic);
	let mut handlers = LIBP2P_MESSAGE_HANDLERS.write();
	if handlers.remove(&topic.hash()).is_some() {
		// Let's Unregister in the swarm
		match &mut *LIBP2P_SWARM.lock() {
			Some(swarm) => match swarm.unsubscribe(&topic) {
				Ok(res) => {
					if !res {
						warn!("Not found expected subscribed topic {}", topic);
					}
				}
				Err(e) => warn!("Unable to unsubscribe from the topic {}", e),
			},
			None => (),
		}
	}
}

/// Start listen on topic
/// Message handlers arguments: topic hash, message (no header), paid integrity fee
//   Handler must return false if the message is incorrect, so the peer must be banned.
pub fn add_topic_to_libp2p(
	topic: &str,
	handler: fn(sender_address: &String, topic: &TopicHash, Vec<u8>, u64) -> bool,
) {
	let mut handlers = LIBP2P_MESSAGE_HANDLERS.write();
	let topic = Topic::new(topic);
	let _ = handlers.insert(topic.hash(), (handler, topic.clone()));

	// Let's Unregister in the swarm
	match &mut *LIBP2P_SWARM.lock() {
		Some(swarm) => match swarm.subscribe(&topic) {
			Ok(_res) => (),
			Err(e) => warn!("Unable to subscribe to the topic {:?}", e),
		},
		None => (),
	}
}

pub fn publish_message(topic: &Topic, integrity_message: Vec<u8>) -> Option<MessageId> {
	match &mut *LIBP2P_SWARM.lock() {
		Some(swarm) => match swarm.publish(topic.clone(), integrity_message) {
			Ok(msg_id) => Some(msg_id),
			Err(e) => {
				warn!("Unable to publish libp2p message, {}", e);
				None
			}
		},
		None => None,
	}
}

/// Request number of established connections to libp2p
pub fn get_libp2p_connections() -> Vec<PeerId> {
	match &*LIBP2P_SWARM.lock() {
		Some(swarm) => Swarm::network_info(swarm).into_peers(),
		None => vec![],
	}
}

/// Reporting new discovered mwc-wallet peer. That might be libp2p node as well
pub fn add_new_peer(peer: &PeerAddr) -> Result<(), Error> {
	info!("libp2p adding a new peer {}", peer);
	let addr = peer.tor_address().map_err(|e| {
		Error::Libp2pError(format!(
			"Unable to retrieve TOR pk from the peer address, {}",
			e
		))
	})?;

	let cur_time = Utc::now().timestamp() as u64;
	let mut peer_list = LIBP2P_PEERS.write();
	if let Some((peers, time)) = peer_list.get_mut("SELF") {
		if !peers.contains(&addr) {
			peers.push(addr);
		}
		*time = cur_time;
	} else {
		peer_list.insert("SELF".to_string(), (vec![addr], cur_time));
	}

	Ok(())
}

/// Created libp2p listener for Socks5 tor address.
/// tor_socks_port - listener port, param from  SocksPort 127.0.0.1:51234
/// output_validation_fn - kernel excess validation method. Return height RangeProof if that output was seen during last 24 hours (last 1440 blocks)
pub async fn run_libp2p_node(
	tor_socks_port: u16,
	tor_secret: &[u8; 32],
	libp2p_port: u16,
	fee_base: u64,
	kernel_validation_fn: Arc<impl Fn(&Commitment) -> Result<Option<TxKernel>, Error>>,
	stop_mutex: std::sync::Arc<std::sync::Mutex<u32>>,
) -> Result<(), Error> {
	let secp = Arc::new(Secp256k1::with_caps(ContextFlag::Commit));

	// Generate Onion address.
	let onion_address = OnionV3Address::from_private(tor_secret)
		.map_err(|e| Error::Libp2pError(format!("Unable to build onion address, {}", e)))?;

	// Init Tor address configs..
	// 80 comes from: /tor/listener/torrc   HiddenServicePort 80 0.0.0.0:13425
	let addr_str = format!(
		"/onion3/{}:{}",
		onion_address.to_string(),
		global::get_tor_libp2p_port()
	);
	let addr = addr_str
		.parse::<Multiaddr>()
		.map_err(|e| Error::Internal(format!("Unable to construct onion multiaddress, {}", e)))?;

	let mut map = HashMap::new();
	map.insert(addr.clone(), libp2p_port);

	// Build swarm (libp2p stuff)
	// Each time will join with a new p2p node ID. I think it is fine, let's keep p2p network dynamic
	let id_keys = Keypair::ed25519_from_secret(&mut tor_secret.clone())
		.map_err(|e| Error::Libp2pError(format!("Unable to build ed25519 key pairs, {}", e)))?;
	let this_peer_id = PeerId::from_public_key(id_keys.public());
	set_this_peer_id(&this_peer_id);

	warn!("Starting libp2p, this peer: {}", this_peer_id);
	debug_assert_eq!(this_peer_id.to_string(), onion_address.to_string());

	// Building transport
	let dh_keys = noise::Keypair::<X25519Spec>::new()
		.into_authentic(&id_keys)
		.map_err(|e| Error::Libp2pError(format!("Unable to build p2p keys, {}", e)))?;
	let noise = NoiseConfig::xx(dh_keys).into_authenticated();
	let tcp = Socks5TokioTcpConfig::new(tor_socks_port)
		.nodelay(true)
		.onion_map(map);
	let transport = DnsConfig::new(tcp)
		.map_err(|e| Error::Libp2pError(format!("Unable to build a transport, {}", e)))?;

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
		.heartbeat_interval(Duration::from_secs(3)) // Default is 1, but we don't want overload network much. Instead we prefer slow adaptation network
		.validation_mode(ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
		.validate_messages() // !!!!! Now we are responsible for validation of all incoming traffic!!!!
		.accept_dalek_pk_peers_only()
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
		.map_err(|e| Error::Libp2pError(format!("Unable to start listening, {}", e)))?;

	/*   // It is ping pong handler
	 future::poll_fn(move |cx: &mut Context<'_>| loop {
		match swarm.poll_next_unpin(cx) {
			Poll::Ready(Some(event)) => info!("{:?}", event),
			Poll::Ready(None) => return Poll::Ready(()),
			Poll::Pending => return Poll::Pending,
		}
	})
	.await;*/

	// Special topic for peer reporting. We don't need to listen on it and we
	// don't want the node forward that message as well
	let peer_topic = Topic::new(mwc_libp2p::gossipsub::PEER_TOPIC).hash();

	// Subscribe to the topics that we are ready to listen
	LIBP2P_MESSAGE_HANDLERS
		.read()
		.iter()
		.for_each(|(_topic_hash, (_fn, topic))| {
			if let Err(e) = swarm.subscribe(&topic) {
				error!("Unable initial subscribe to the topic, {:?}", e);
			}
		});

	init_libp2p_swarm(swarm);

	let mut requests_cash: HashMap<Commitment, VecDeque<i64>> = HashMap::new();
	let mut last_cash_clean = Instant::now();
	let mut last_reconnect = Instant::now();
	let secp = secp.clone();
	// Kick it off
	// Event processing future...
	task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
		let mut swarm = LIBP2P_SWARM.lock();
		match &mut *swarm {
			Some(swarm) => {
				loop {
					let event = swarm.poll_next_unpin(cx);
					//debug!("swarm.poll_next_unpin event: {:?}", event);
					match event {
						Poll::Ready(Some(gossip_event)) => match gossip_event {
							GossipsubEvent::Message {
								propagation_source: peer_id,
								message_id: id,
								message,
							} => {
								debug!(
									"Get libp2p message from {}, with ID {}, topic {}, data: {}",
									peer_id,
									id,
									message.topic,
									String::from_utf8_lossy(&read_message_data(&message.data))
										.to_string(),
								);

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
											Ok(peer) => match peer.as_onion_address() {
												Ok(addr) => peer_arr.push(addr),
												Err(e) => {
													error!("Get from libp2p peer without Dalek PK {}, {}", peer, e);
													continue;
												}
											},
											Err(e) => {
												warn!("Unable to decode the libp2p peer form the peer update message, {}", e);
												continue;
											}
										}
									}
									info!("Get {} peers from {}. Will process them later when we will need to increase connection number", peer_arr.len(), peer_id);

									if let Ok(addr) = peer_id.as_onion_address() {
										let mut new_peers_list = LIBP2P_PEERS.write();

										(*new_peers_list).insert(
											addr,
											(peer_arr, Utc::now().timestamp() as u64),
										);
									} else {
										error!(
											"Internal Error. Getting peer without onion address {}",
											peer_id
										);
									}
								} else {
									// We get the regular message and we need to validate it now.

									let gossip = swarm.get_behaviour();

									let acceptance = match validate_integrity_message(
										&peer_id,
										&message.data,
										kernel_validation_fn.clone(),
										&mut requests_cash,
										fee_base,
										&secp,
									) {
										Ok((integrity_fee, sender_address)) => {
											if integrity_fee > 0 {
												let mut acceptance = MessageAcceptance::Accept;

												if let Some((handler, _topic)) =
													LIBP2P_MESSAGE_HANDLERS
														.read()
														.get(&message.topic)
												{
													if !(handler)(
														&sender_address,
														&message.topic,
														read_message_data(&message.data),
														integrity_fee,
													) {
														// false mean that message was invalid, so we can ban the peer
														acceptance = MessageAcceptance::Reject;
													}
												}
												acceptance
											} else {
												// Invalid message
												MessageAcceptance::Reject
											}
										}
										Err(e) => {
											warn!("Message is skipped, Unable to verify the message because of some error. {:?}", e);
											MessageAcceptance::Ignore
										}
									};

									debug!("report_message_validation_result as {:?}", acceptance);
									let _ = gossip.report_message_validation_result(
										&id, &peer_id, acceptance,
									);
								}
							}
							_ => {}
						},
						Poll::Ready(None) | Poll::Pending => {
							break;
						}
					}
				}

				// cleanup expired requests_cash values
				let history_time_limit = Utc::now().timestamp()
					- INTEGRITY_CALL_HISTORY_LEN_LIMIT as i64 * INTEGRITY_CALL_MAX_PERIOD;
				let now = Instant::now();
				if last_cash_clean + Duration::from_secs(600) < now {
					last_cash_clean = now;
					// Let's do clean up...
					requests_cash.retain(|_commit, history| {
						*history.back().unwrap_or(&0) > history_time_limit
					});
				}

				// Will try to reconnect if needed every 15 seconds.
				if last_reconnect + Duration::from_secs(14) < now {
					last_reconnect = now;
					// let's try to make a new connection if needed
					let nw_info: NetworkInfo = Swarm::network_info(&swarm);
					let mut rng = rand::thread_rng();

					debug!(
						"Processing libp2p reconnection task. Has connections: {},  {:?}",
						nw_info.connection_counters().num_connections(),
						nw_info.connection_counters()
					);

					// We are leaking on oputgoing connection. The leak is slow, but we really don't want to go through all libp2p code.
					// In case of leak, we will restart the swarm.
					// Note, the leak is minor, it takes about 4-5 days to build 400 leaked connections. In this case node trying to establish
					// connections constantly.
					if nw_info.connection_counters().num_pending_outgoing() > 100 {
						info!("Restarting libp2p engine...");
						return Poll::Ready(()); // Exiting
					}

					if nw_info.connection_counters().num_connections()
						< connections_number_low as u32
					{
						// Let's try to connect to somebody if we can...
						let mut address_to_connect: Option<Multiaddr> = None;
						loop {
							// cloned to unblock the mutex
							let mut libp2p_peers = LIBP2P_PEERS.write();
							let peers: Vec<String> = libp2p_peers.keys().cloned().collect();
							if let Some(peer_id) = peers.choose(&mut rng) {
								if let Some(peers) = libp2p_peers.get_mut(peer_id) {
									if !peers.0.is_empty() {
										let tor_address =
											peers.0.remove(rng.gen::<usize>() % peers.0.len());

										let res: Result<OnionV3Address, OnionV3AddressError> =
											tor_address.as_str().try_into();
										let p = match res {
											Ok(onion_addr) => match onion_addr.to_ed25519() {
												Ok(pk) => PeerId::from_public_key(
													mwc_libp2p::identity::PublicKey::Ed25519(
														mwc_libp2p::identity::ed25519::PublicKey(
															pk,
														),
													),
												),
												Err(e) => {
													error!("Unable to build PeerId form onion address {}, {}", tor_address, e);
													continue;
												}
											},
											Err(e) => {
												error!("Unable to build PeerId form onion address {}, {}", tor_address, e);
												continue;
											}
										};

										if Swarm::is_connected(&swarm, &p)
											|| Swarm::is_dialing(&swarm, &p) || p == this_peer_id
										{
											continue;
										}

										let address = match p.get_address() {
											Ok(addr) => addr,
											Err(e) => {
												warn!("Unable to get peer address to connect . Will skip it, {}", e);
												continue;
											}
										};

										let multiaddress = format!(
											"/onion3/{}:{}",
											address,
											global::get_tor_libp2p_port()
										);
										match multiaddress.parse::<Multiaddr>() {
											Ok(addr) => {
												address_to_connect = Some(addr);
												break;
											}
											Err(e) => {
												warn!("Unable to construct onion multiaddress from {} the peer address. Will skip it, {}", multiaddress, e);
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

						if address_to_connect.is_none()
							&& nw_info.connection_counters().num_connections() == 0
						{
							info!("Retry connect to libp2p seeds peers...");
							let seed_list = SEED_LIST.read().clone();
							set_seed_list(&seed_list, false);
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
				}
			}
			None => (),
		};

		if *stop_mutex.lock().unwrap() == 0 {
			info!("Exiting libp2p polling task");
			Poll::Ready(()) // Exiting
		} else {
			Poll::Pending as Poll<()>
		}
	}));

	reset_libp2p_swarm();

	Ok(())
}

// return paid fee if this message is valid. It is caller responsibility to make sure that valid_outputs cache is well maintained
//  Otherwise return 0, fee is invalid
// output_validation_fn  - lookup for the kernel excess and returns it's height
pub fn validate_integrity_message(
	peer_id: &PeerId,
	message: &Vec<u8>,
	output_validation_fn: Arc<impl Fn(&Commitment) -> Result<Option<TxKernel>, Error>>,
	requests_cash: &mut HashMap<Commitment, VecDeque<i64>>,
	fee_base: u64,
	secp: &Secp256k1,
) -> Result<(u64, String), Error> {
	let mut ser = SimplePopSerializer::new(message);
	if ser.version != get_message_version() {
		debug!(
			"Get message with invalid version {} from peer {}",
			ser.version, peer_id
		);
		// Will be rejected and peer will be banned
		return Ok((0, String::new()));
	}

	// Let's check signature first. The kernel search might take time. Signature checking should be faster.
	let integrity_kernel_excess = Commitment::from_vec(ser.pop_vec());
	let integrity_pk = match integrity_kernel_excess.to_pubkey(secp) {
		Ok(pk) => pk,
		Err(e) => {
			debug!(
				"Get invalid message from peer {}. integrity_kernel is not valid, {}",
				peer_id, e
			);
			return Ok((0, String::new()));
		}
	};

	// Checking if public key match the signature.
	let sender_address_pk = match DalekPublicKey::from_bytes(&ser.pop_vec()) {
		Ok(pk) => pk,
		Err(e) => {
			debug!(
				"Get invalid message from peer {}. Unable to decode sender address PK, {}",
				peer_id, e
			);
			return Ok((0, String::new()));
		}
	};
	let msg_hash = Hash::from_vec(&sender_address_pk.to_bytes());
	let msg_message = match Message::from_slice(msg_hash.as_bytes()) {
		Ok(m) => m,
		Err(e) => {
			debug!(
				"Get invalid message from peer {}. Unable to build a message, {}",
				peer_id, e
			);
			return Ok((0, String::new()));
		}
	};

	let sender_address = PeerId::onion_v3_from_pubkey(&sender_address_pk);

	let signature = match Signature::from_compact(&secp, &ser.pop_vec()) {
		Ok(s) => s,
		Err(e) => {
			debug!(
				"Get invalid message from peer {}. Unable to read signature, {}",
				peer_id, e
			);
			return Ok((0, String::new()));
		}
	};

	match aggsig::verify_completed_sig(
		secp,
		&signature,
		&integrity_pk,
		Some(&integrity_pk),
		&msg_message,
	) {
		Ok(()) => (),
		Err(e) => {
			debug!(
				"Get invalid message from peer {}. Integrity kernel signature is invalid, {}",
				peer_id, e
			);
			return Ok((0, String::new()));
		}
	}

	let integrity_kernel = match (output_validation_fn)(&integrity_kernel_excess)? {
		Some(r) => r.clone(),
		None => {
			debug!(
				"Get invalid message from peer {}. integrity_kernel {} is not found at the blockchain",
				peer_id, integrity_kernel_excess.to_hex()
			);
			return Ok((0, String::new()));
		}
	};

	let integrity_fee = integrity_kernel.features.get_fee_pessimistic();

	if integrity_fee < fee_base * INTEGRITY_FEE_MIN_X {
		debug!(
			"Get invalid message from peer {}. integrity_kernel fee is below minimal level of 10X accepted base fee",
			peer_id
		);
		return Ok((0, String::new()));
	}

	// Updating calls history cash.
	let now = Utc::now().timestamp();
	match requests_cash.get_mut(&integrity_kernel_excess) {
		Some(calls) => {
			calls.push_back(now);
			while calls.len() > INTEGRITY_CALL_HISTORY_LEN_LIMIT {
				calls.pop_front();
			}
		}
		None => {
			let mut calls: VecDeque<i64> = VecDeque::new();
			calls.push_back(now);
			requests_cash.insert(integrity_kernel_excess.clone(), calls);
		}
	}
	// Checking if ths peer sent too many messages
	let call_history = requests_cash.get(&integrity_kernel_excess).unwrap();
	if call_history.len() >= INTEGRITY_CALL_HISTORY_LEN_LIMIT {
		let call_period = (call_history.back().unwrap() - call_history.front().unwrap())
			/ (call_history.len() - 1) as i64;
		if call_period < INTEGRITY_CALL_MAX_PERIOD {
			debug!(
				"Get invalid message from peer {}. Message sending period is {}, limit {}",
				peer_id, call_period, INTEGRITY_CALL_MAX_PERIOD
			);
			return Ok((0, String::new()));
		}
	}

	debug!(
		"Validated the message from peer {} with integrity fee {}, sender address {}",
		peer_id, integrity_fee, sender_address
	);
	return Ok((integrity_fee, sender_address));
}

/// Skip the header and return the message data
pub fn read_message_data(message: &Vec<u8>) -> Vec<u8> {
	let mut ser = SimplePopSerializer::new(message);
	if ser.version != get_message_version() {
		// Probably wrong network. But may be wrong version as well. We don't want to read it
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
/// kernel_excess  - kernel (public key) with a fee
/// signature - the PeerId data (PK & address) must be singed with this signature. See validate_integrity_message code for deatils
/// message_data - message to send, that is written into the package
pub fn build_integrity_message(
	kernel_excess: &Commitment,
	tor_pk: &DalekPublicKey,
	signature: &Signature,
	message_data: &[u8],
	secp: &Secp256k1,
) -> Result<Vec<u8>, Error> {
	let mut ser = SimplePushSerializer::new(get_message_version());

	ser.push_vec(&kernel_excess.0);
	ser.push_vec(tor_pk.as_bytes());
	ser.push_vec(&signature.serialize_compact(secp));

	ser.push_vec(message_data);
	Ok(ser.to_vec())
}

// test need to be fixed. Currently need to push node first
#[test]
#[ignore]
fn test_integrity() -> Result<(), Error> {
	use mwc_core::core::KernelFeatures;
	use mwc_util::from_hex;
	use mwc_util::secp::ContextFlag;

	// It is peer form wallet's test. We know commit and signature for it.
	let peer_id = PeerId::from_bytes( &from_hex("000100220020720661bf2f0d7c81c2980db83bb973be2816cf5a0da2da9aacd0ad47d534215c001c2f6f6e696f6e332f776861745f657665725f616464726573733a3737").unwrap() ).unwrap();
	let peer_pk = peer_id.as_dalek_pubkey().unwrap();
	let onion_address = PeerId::onion_v3_from_pubkey(&peer_pk);

	let secp = Secp256k1::with_caps(ContextFlag::Full);

	let integrity_kernel = Commitment::from_vec(
		from_hex("08a8f99853d65cee63c973a78a005f4646b777262440a8bfa090694a339a388865").unwrap(),
	);
	let integrity_signature = Signature::from_compact(&secp, &from_hex("102a84ec71494d69c1b4cca181b7715beea1ebd0822efb4d6440a0f2be75119b56270affac659214c27903347676c27063dc7f5f2f0c6a8441cab73d16aa7ebe").unwrap()).unwrap();

	let message: Vec<u8> = vec![1, 2, 3, 4, 3, 2, 1];

	let encoded_message = build_integrity_message(
		&integrity_kernel,
		&peer_pk,
		&integrity_signature,
		&message,
		&secp,
	)
	.unwrap();

	// Validation use case
	let mut requests_cache: HashMap<Commitment, VecDeque<i64>> = HashMap::new();

	let empty_output_validation_fn =
		|_commit: &Commitment| -> Result<Option<TxKernel>, Error> { Ok(None) };
	let empty_output_validation_fn = Arc::new(empty_output_validation_fn);

	let fee_base: u64 = 1_000_000;

	let mut valid_kernels = HashMap::<Commitment, TxKernel>::new();
	let paid_integrity_fee = fee_base * 10;
	valid_kernels.insert(
		integrity_kernel,
		TxKernel::with_features(KernelFeatures::Plain {
			fee: paid_integrity_fee
				.try_into()
				.expect("Failed to convert the paid_integrity_fee"),
		}),
	);
	let output_validation_fn = |commit: &Commitment| -> Result<Option<TxKernel>, Error> {
		Ok(valid_kernels.get(commit).cloned())
	};
	let output_validation_fn = Arc::new(output_validation_fn);

	// Valid outputs is empty, should fail.
	assert_eq!(
		validate_integrity_message(
			&peer_id,
			&encoded_message,
			empty_output_validation_fn.clone(),
			&mut requests_cache,
			fee_base,
			&secp
		)
		.unwrap()
		.0,
		0
	);
	assert!(requests_cache.is_empty());

	let res = validate_integrity_message(
		&peer_id,
		&encoded_message,
		output_validation_fn.clone(),
		&mut requests_cache,
		fee_base,
		&secp,
	)
	.unwrap();

	assert_eq!(res.0, paid_integrity_fee);
	assert_eq!(res.1, onion_address);

	assert!(requests_cache.len() == 1);
	assert!(requests_cache.get(&integrity_kernel).unwrap().len() == 1); // call history is onw as well

	requests_cache.clear();
	assert_eq!(
		validate_integrity_message(
			&PeerId::random(),
			&encoded_message,
			output_validation_fn.clone(),
			&mut requests_cache,
			fee_base,
			&secp
		)
		.unwrap()
		.0,
		0
	);
	assert!(requests_cache.len() == 0);

	// Checking if ddos will be recognized.
	for i in 0..(INTEGRITY_CALL_HISTORY_LEN_LIMIT - 1) {
		assert_eq!(
			validate_integrity_message(
				&peer_id,
				&encoded_message,
				output_validation_fn.clone(),
				&mut requests_cache,
				fee_base,
				&secp
			)
			.unwrap()
			.0,
			paid_integrity_fee
		);
		assert!(requests_cache.len() == 1);
		assert!(requests_cache.get(&integrity_kernel).unwrap().len() == i + 1); // call history is onw as well
	}
	// And now all next request will got to spam
	assert_eq!(
		validate_integrity_message(
			&peer_id,
			&encoded_message,
			output_validation_fn.clone(),
			&mut requests_cache,
			fee_base,
			&secp
		)
		.unwrap()
		.0,
		0
	);
	assert!(
		requests_cache.get(&integrity_kernel).unwrap().len() == INTEGRITY_CALL_HISTORY_LEN_LIMIT
	); // call history is onw as well
	assert_eq!(
		validate_integrity_message(
			&peer_id,
			&encoded_message,
			output_validation_fn.clone(),
			&mut requests_cache,
			fee_base,
			&secp
		)
		.unwrap()
		.0,
		0
	);
	assert!(
		requests_cache.get(&integrity_kernel).unwrap().len() == INTEGRITY_CALL_HISTORY_LEN_LIMIT
	); // call history is onw as well
	assert_eq!(
		validate_integrity_message(
			&peer_id,
			&encoded_message,
			output_validation_fn.clone(),
			&mut requests_cache,
			fee_base,
			&secp
		)
		.unwrap()
		.0,
		0
	);
	assert!(
		requests_cache.get(&integrity_kernel).unwrap().len() == INTEGRITY_CALL_HISTORY_LEN_LIMIT
	); // call history is onw as well

	assert_eq!(read_message_data(&encoded_message), message);

	Ok(())
}
