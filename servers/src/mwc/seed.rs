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

//! Seeds a server with initial peers on first start and keep monitoring
//! peer counts to connect to more if neeed. Seedin strategy is
//! configurable with either no peers, a user-defined list or a preset
//! list of DNS records (the default).

use crate::core::global;
use crate::core::global::{FLOONET_DNS_SEEDS, MAINNET_DNS_SEEDS};
use crate::core::pow::Difficulty;
use crate::p2p;
#[cfg(feature = "libp2p")]
use crate::p2p::libp2p_connection;
use crate::p2p::types::PeerAddr;
use crate::p2p::ChainAdapter;
use crate::util::StopState;
use chrono::prelude::{DateTime, Utc};
use chrono::Duration;
use mwc_core::global::PEER_PING_INTERVAL_SECONDS;
use mwc_p2p::tor::arti::is_arti_healthy;
use mwc_p2p::PeerAddr::Onion;
use mwc_p2p::{msg::PeerAddrs, network_status, Capabilities, P2PConfig};
use rand::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::{thread, time};

const CONNECT_TO_SEED_INTERVAL: i64 = 30;
const EXPIRE_INTERVAL: i64 = 3600;
const PEERS_CHECK_TIME_FULL: i64 = 30;
const PEERS_CHECK_TIME_BOOST: i64 = 3;
const PEERS_MONITOR_INTERVAL: i64 = 60;
const PEERS_LISTEN_MIN_INTERVAL: i64 = 600; // Interval to add some new peers even if everything is fine

const PEER_RECONNECT_INTERVAL: i64 = 600;
const SEED_RECONNECT_INTERVAL: i64 = 60;
const PEER_MAX_INITIATE_CONNECTIONS: usize = 50;

pub fn connect_and_monitor(
	p2p_server: Arc<p2p::Server>,
	seed_list: Box<dyn Fn() -> Vec<PeerAddr> + Send>,
	config: P2PConfig,
	stop_state: Arc<StopState>,
	use_tor_connection: bool,
) -> std::io::Result<thread::JoinHandle<()>> {
	thread::Builder::new()
		.name("seed".to_string())
		.spawn(move || {
			let peers = p2p_server.peers.clone();

			// open a channel with a listener that connects every peer address sent below
			// max peer count
			let seed_list = seed_list();

			// check seeds first
			let now = Utc::now();
			let mut seed_connect_time;
			let mut peers_connect_time = now + Duration::seconds(PEERS_CHECK_TIME_BOOST);
			let mut expire_check_time = now + Duration::seconds(EXPIRE_INTERVAL);
			let mut peer_monitor_time = now.clone();
			let mut listen_time = now.clone();

			let mut connecting_history: HashMap<PeerAddr, DateTime<Utc>> = HashMap::new();
			let mut listen_q_addrs: VecDeque<PeerAddr> = VecDeque::new();

			connect_to_seeds_and_peers(
				peers.clone(),
				&mut listen_q_addrs,
				&seed_list,
				config.clone(),
			);
			seed_connect_time = Utc::now() + Duration::seconds(CONNECT_TO_SEED_INTERVAL);

			#[cfg(feature = "libp2p")]
			libp2p_connection::set_seed_list(&seed_list, true);

			let mut prev_ping = Utc::now();

			let mut connection_threads: Vec<thread::JoinHandle<()>> = Vec::new();

			let network_last_outage_time = AtomicI64::new(0);

			let mut recover_peers_num: usize = 1;

			loop {
				if stop_state.is_stopped() {
					break;
				}
				// Pause egress peer connection request. Only for tests.
				if stop_state.is_paused() || !p2p_server.is_ready() {
					thread::sleep(time::Duration::from_secs(1));
					continue;
				}

				let connected_peers = peers.iter().connected().count();

				let now = Utc::now();

				if connected_peers == 0 {
					if now > seed_connect_time {
						info!("No peers connected, trying to reconnect to seeds!");
						connect_to_seeds_and_peers(
							peers.clone(),
							&mut listen_q_addrs,
							&seed_list,
							config.clone(),
						);
						seed_connect_time = now + Duration::seconds(CONNECT_TO_SEED_INTERVAL);
					}
				}

				// Check for and remove expired peers from the storage
				if now > expire_check_time {
					peers.remove_expired();
					expire_check_time = now + Duration::seconds(EXPIRE_INTERVAL);
				}

				let request_more_connections = now > listen_time;
				let has_enough_peers = peers.enough_outbound_peers();

				let listen_q_is_empty = listen_q_addrs.is_empty();

				// monitor peers first, then process sent requests with 'listen_for_addrs'
				if now > peer_monitor_time || (request_more_connections && listen_q_is_empty) {
					// monitor additional peers if we need to add more
					monitor_peers(
						peers.clone(),
						p2p_server.config.clone(),
						use_tor_connection,
						&mut listen_q_addrs,
						request_more_connections,
						&network_last_outage_time,
						&mut connecting_history,
						recover_peers_num,
					);

					if peers.is_sync_mode() || !has_enough_peers {
						peer_monitor_time = now + Duration::seconds(PEERS_MONITOR_INTERVAL / 5); // every 12 seconds let's do the check
					} else {
						peer_monitor_time = now + Duration::seconds(PEERS_MONITOR_INTERVAL); // once a minute checking
					}
				}

				// make several attempts to get peers as quick as possible
				// with exponential backoff
				if now > peers_connect_time || request_more_connections {
					let is_boost = peers.is_boosting_mode();
					if has_enough_peers && !request_more_connections {
						peers_connect_time = now + Duration::seconds(PEERS_CHECK_TIME_FULL);
						if recover_peers_num != 1 {
							info!("Reset recovery peers to 1");
							recover_peers_num = 1;
						}
					} else {
						// try to connect to any address sent to the channel
						listen_for_addrs(
							peers.clone(),
							p2p_server.clone(),
							&mut connecting_history,
							use_tor_connection,
							&mut connection_threads,
							&mut listen_q_addrs,
							&seed_list,
						);
						let duration = if is_boost || !listen_q_addrs.is_empty() {
							PEERS_CHECK_TIME_BOOST
						} else {
							PEERS_CHECK_TIME_FULL
						};

						if !has_enough_peers && listen_q_is_empty {
							recover_peers_num = std::cmp::min(
								PEER_MAX_INITIATE_CONNECTIONS,
								recover_peers_num + std::cmp::max(1, recover_peers_num / 4),
							);
							info!("Increased recovery peers number to {}", recover_peers_num);
						}

						peers_connect_time = now + Duration::seconds(duration);
						listen_time = now + Duration::seconds(PEERS_LISTEN_MIN_INTERVAL);
					}
				}

				// Ping connected peers on every 10s to monitor peers.
				if Utc::now() - prev_ping > Duration::seconds(PEER_PING_INTERVAL_SECONDS) {
					let total_diff = peers.total_difficulty();
					let total_height = peers.total_height();
					if let (Ok(total_diff), Ok(total_height)) = (total_diff, total_height) {
						peers.check_all(total_diff, total_height);
						prev_ping = Utc::now();
					} else {
						error!("failed to get peers difficulty and/or height");
					}
				}

				thread::sleep(time::Duration::from_secs(1));
			}
		})
}

fn monitor_peers(
	peers: Arc<p2p::Peers>,
	config: p2p::P2PConfig,
	use_tor_connection: bool,
	listen_q_addrs: &mut VecDeque<PeerAddr>,
	request_more_connections: bool,
	network_last_outage_time: &AtomicI64,
	connecting_history: &mut HashMap<PeerAddr, DateTime<Utc>>,
	recover_peers_num: usize,
) {
	// regularly check if we need to acquire more peers and if so, gets
	// them from db
	let mut total_count = 0;
	let mut healthy_count = 0;
	let mut banned_count = 0;
	let mut defuncts = vec![];

	for x in peers.all_peer_data(Capabilities::UNKNOWN).into_iter() {
		match x.flags {
			p2p::State::Banned => {
				let interval = Utc::now().timestamp() - x.last_banned;
				// Unban peer
				if interval >= config.ban_window() {
					if let Err(e) = peers.unban_peer(&x.addr) {
						error!("failed to unban peer {}: {:?}", x.addr, e);
					}
					debug!(
						"monitor_peers: unbanned {} after {} seconds",
						x.addr, interval
					);
				} else {
					banned_count += 1;
				}
			}
			p2p::State::Healthy => healthy_count += 1,
			p2p::State::Defunct => defuncts.push(x),
		}
		total_count += 1;
	}

	let peers_iter = || peers.iter().connected();
	let peers_count = peers_iter().count();
	let max_diff = peers_iter().max_difficulty().unwrap_or(Difficulty::zero());
	let most_work_count = peers_iter().with_difficulty(|x| x >= max_diff).count();

	debug!(
		"monitor_peers: {} connected ({} most_work). \
		 all {} = {} healthy + {} banned + {} defunct",
		peers_count,
		most_work_count,
		total_count,
		healthy_count,
		banned_count,
		defuncts.len(),
	);

	let boost_peers_capabilities = peers.get_boost_peers_capabilities();
	let in_sync_mode = peers.is_sync_mode();

	// maintenance step first, clean up p2p server peers
	peers.clean_peers(
		config.peer_max_inbound_count() as usize,
		config.peer_max_outbound_count(in_sync_mode) as usize,
		boost_peers_capabilities,
		config.clone(),
	);

	if !request_more_connections && peers.enough_outbound_peers() {
		return;
	}

	// loop over connected peers that can provide peer lists
	// ask them for their list of peers
	for p in peers
		.iter()
		.with_capabilities(Capabilities::PEER_LIST)
		.connected()
	{
		trace!("monitor_peers: ask {} for more peers", p.info.addr,);
		let _ = p.send_peer_request(
			p2p::Capabilities::PEER_LIST | boost_peers_capabilities,
			use_tor_connection,
		);
	}

	if network_last_outage_time.load(Ordering::Relaxed) != network_status::get_network_outage_time()
	{
		network_last_outage_time
			.store(network_status::get_network_outage_time(), Ordering::Relaxed);
		let connection_time_limit = Utc::now().timestamp() - 3600;
		// Outage was recently detected, reverting Defuncts peers back to healthy
		for peer in &defuncts {
			if peer.last_connected > connection_time_limit {
				let _ = peers.update_state(&peer.addr, p2p::State::Healthy);
			}
		}
		connecting_history.clear();
	}

	if listen_q_addrs.is_empty() {
		// Attempt to connect to any preferred peers.
		let peers_preferred = config.peers_preferred.unwrap_or(PeerAddrs::default());
		for p in peers_preferred {
			if !peers.is_known(&p) {
				listen_q_addrs.push_front(p);
			}
		}

		// take a random defunct peer and mark it healthy: over a long enough period any
		// peer will see another as defunct eventually, gives us a chance to retry
		for peer in defuncts
			.into_iter()
			.choose_multiple(&mut thread_rng(), recover_peers_num)
		{
			let _ = peers.update_state(&peer.addr, p2p::State::Healthy);
		}

		// find some peers from our db
		// and queue them up for a connection attempt
		// intentionally make too many attempts (2x) as some (most?) will fail
		// as many nodes in our db are not publicly accessible
		let new_peers = peers.find_peers(p2p::State::Healthy, boost_peers_capabilities);

		// Only queue up connection attempts for candidate peers where we
		// are confident we do not yet know about this peer.
		// The call to is_known() may fail due to contention on the peers map.
		// Do not attempt any connection where is_known() fails for any reason.
		for p in new_peers {
			if !peers.is_known(&p.addr) {
				listen_q_addrs.push_back(p.addr);
			}
		}
	}
}

// Check if we have any pre-existing peer in db. If so, start with those,
// otherwise use the seeds provided.
fn connect_to_seeds_and_peers(
	peers: Arc<p2p::Peers>,
	listen_q_addrs: &mut VecDeque<PeerAddr>,
	seed_list: &Vec<PeerAddr>,
	config: P2PConfig,
) {
	let peers_deny = config.peers_deny.unwrap_or(PeerAddrs::default());
	let is_q_empty = listen_q_addrs.is_empty();

	// If "peers_allow" is explicitly configured then just use this list
	// remembering to filter out "peers_deny".
	if let Some(peers_allow) = config.peers_allow {
		for addr in peers_allow.difference(peers_deny.as_slice()) {
			if !peers.is_known(&addr) {
				listen_q_addrs.push_front(addr);
			}
		}
		return;
	}

	// Always try our "peers_preferred" remembering to filter out "peers_deny".
	if let Some(peers_preferred) = config.peers_preferred {
		for addr in peers_preferred.difference(peers_deny.as_slice()) {
			if !peers.is_known(&addr) {
				listen_q_addrs.push_front(addr);
			}
		}
	}

	// check if we have some peers in db
	// look for peers that are able to give us other peers (via PEER_LIST capability)
	let mut found_peers = Vec::new();

	if is_q_empty {
		found_peers = peers.find_peers(
			p2p::State::Healthy,
			p2p::Capabilities::PEER_LIST | peers.get_boost_peers_capabilities(),
		);
		if found_peers.is_empty() {
			found_peers = peers.find_peers(p2p::State::Healthy, p2p::Capabilities::PEER_LIST);
		}

		// if so, get their addresses, otherwise use our seeds
		let peer_addrs = if found_peers.len() > 3 {
			let mut peer_addrs = found_peers
				.iter()
				.map(|p| p.addr.clone())
				.collect::<Vec<_>>();

			if let Some(seed_addr) = seed_list.choose(&mut thread_rng()) {
				peer_addrs.push(seed_addr.clone());
			}
			peer_addrs
		} else {
			seed_list.clone()
		};

		if peer_addrs.is_empty() {
			warn!("No seeds were retrieved.");
		}

		// connect to this initial set of peer addresses (either seeds or from our local db).
		// Reverce order because we want first add the last seed peer
		for addr in peer_addrs.iter().rev() {
			if !peers_deny.as_slice().contains(&addr) {
				if !peers.is_known(&addr) {
					listen_q_addrs.push_back(addr.clone());
				}
			}
		}
	}
}

/// Regularly poll a channel receiver for new addresses and initiate a
/// connection if the max peer count isn't exceeded. A request for more
/// peers is also automatically sent after connection.
fn listen_for_addrs(
	peers: Arc<p2p::Peers>,
	p2p: Arc<p2p::Server>,
	connecting_history: &mut HashMap<PeerAddr, DateTime<Utc>>,
	use_tor_connection: bool,
	connection_threads: &mut Vec<thread::JoinHandle<()>>,
	listen_q_addrs: &mut VecDeque<PeerAddr>,
	seed_list: &Vec<PeerAddr>,
) {
	let now = Utc::now();
	let connection_time_limit = now - Duration::seconds(PEER_RECONNECT_INTERVAL);
	connecting_history.retain(|_, time| *time > connection_time_limit);

	let mut seen = HashSet::new();
	listen_q_addrs.retain(|p| {
		seen.insert(p.clone()) && (!(peers.is_known(p) || connecting_history.contains_key(p)))
	});

	if listen_q_addrs.is_empty() {
		if let Some(seed_adr) = seed_list.choose(&mut thread_rng()) {
			match connecting_history.get(seed_adr) {
				Some(time) => {
					let seed_time_limit = now - Duration::seconds(SEED_RECONNECT_INTERVAL);
					if *time < seed_time_limit {
						listen_q_addrs.push_back(seed_adr.clone());
					}
				}
				None => {
					listen_q_addrs.push_back(seed_adr.clone());
				}
			}
		}
	}

	connection_threads.retain(|h| !h.is_finished());

	let q_start_len = listen_q_addrs.len();

	while !listen_q_addrs.is_empty() {
		if connection_threads.len() > PEER_MAX_INITIATE_CONNECTIONS {
			break;
		}

		let addr = match listen_q_addrs.pop_front() {
			Some(a) => a,
			None => continue,
		};

		// Note, is_arti_healthy might wait for a long time it Arti is restarting. Foir this case it is totally fine
		if use_tor_connection && !is_arti_healthy() {
			// waiting for arti to restore it connection
			info!("Waiting for Arti become online before continue with peers discovery...");
			listen_q_addrs.push_front(addr);
			break;
		}

		connecting_history.insert(addr.clone(), now);

		if !use_tor_connection {
			match &addr {
				Onion(_) => {
					continue;
				}
				_ => {}
			}
		}

		let addr_c = addr.clone();
		let peers_c = peers.clone();
		let p2p_c = p2p.clone();
		let thr = thread::Builder::new()
			.name(format!("peer_connect_{}", addr))
			.spawn(move || {
				// if we don't have a socks port, and it's onion, don't set as defunct because
				// we don't know.
				match p2p_c.connect(&addr_c) {
					Ok(p) => {
						debug!(
							"New peer {} is connected as outbound! Capability: {:b}",
							p.info.addr, p.info.capabilities
						);
						// If peer advertizes PEER_LIST then ask it for more peers that support PEER_LIST.
						// We want to build a local db of possible peers to connect to.
						// We do not necessarily care (at this point in time) what other capabilities these peers support.
						if p.info.capabilities.contains(Capabilities::PEER_LIST) {
							debug!("Sending peer request to {}", addr_c);
							match p.send_peer_request(
								Capabilities::PEER_LIST | peers_c.get_boost_peers_capabilities(),
								use_tor_connection,
							) {
								Ok(_) => {
									match addr_c {
										PeerAddr::Onion(_) => {
											#[cfg(feature = "libp2p")]
											if let Err(_) = libp2p_connection::add_new_peer(&addr_c)
											{
												error!("Unable to add libp2p peer {}", addr_c);
											}
										}
										_ => (),
									};
								}
								Err(e) => {
									error!(
										"Failed send_peer_request to {}, Error: {}",
										p.info.addr, e
									);
								}
							}
						}
						// Requesting ping as well, need to know the height asap
						let total_diff = peers_c.total_difficulty().unwrap_or(Difficulty::zero());
						let total_height = peers_c.total_height().unwrap_or(0);
						if let Err(e) = p.send_ping(total_diff, total_height) {
							error!("Failed send_ping to {}, Error: {}", p.info.addr, e);
						}

						let _ = peers_c.update_state(&addr_c, p2p::State::Healthy);
					}
					Err(mwc_p2p::Error::TorNotInitialized) => {
						debug!("Trying connect when Tor is offline, skipping the attempt");
					}
					Err(e) => {
						let error_str = e.to_string();
						if error_str.contains("Invalid onion address") {
							debug!("Cleaning up the invalid peer address, {}", addr_c);
							let _ = peers_c.delete_peer(&addr_c);
						} else {
							debug!("Connection to the peer {} was rejected, {}", addr_c, e);
							let _ = peers_c.update_state(&addr_c, p2p::State::Defunct);
						}
					}
				}
			});

		match thr {
			Ok(thr) => connection_threads.push(thr),
			Err(e) => error!("failed to launch peer_connect thread, {}", e),
		}
	}

	let q_finish_len = listen_q_addrs.len();
	info!(
		"Trying connect to another {} peers addresses. Q len: {}",
		(q_start_len - q_finish_len),
		q_finish_len
	);
}

pub fn default_dns_seeds(context_id: u32) -> Box<dyn Fn() -> Vec<PeerAddr> + Send> {
	Box::new(move || {
		let net_seeds = if global::is_floonet(context_id) {
			FLOONET_DNS_SEEDS
		} else {
			MAINNET_DNS_SEEDS
		};
		resolve_dns_to_addrs(
			&net_seeds
				.iter()
				.map(|s| {
					if s.ends_with(".onion") {
						s.to_string()
					} else {
						s.to_string()
							+ if global::is_floonet(context_id) {
								":13414"
							} else {
								":3414"
							}
					}
				})
				.collect(),
		)
	})
}

/// Convenience function to resolve dns addresses from DNS records
pub fn resolve_dns_to_addrs(dns_records: &Vec<String>) -> Vec<PeerAddr> {
	let mut addresses: Vec<PeerAddr> = vec![];
	for dns in dns_records {
		if dns.ends_with(".onion") {
			addresses.push(PeerAddr::from_str(&dns))
		} else {
			debug!("Retrieving addresses from dns {}", dns);
			match dns.to_socket_addrs() {
				Ok(addrs) => addresses.append(
					&mut addrs
						.map(PeerAddr::Ip)
						.filter(|addr| !addresses.contains(addr))
						.collect(),
				),
				Err(e) => debug!("Failed to resolve dns {:?} got error {:?}", dns, e),
			};
		}
	}
	debug!("Resolved addresses: {:?}", addresses);
	addresses
}

/// Convenience function when the seed list is immediately known. Mostly used
/// for tests.
pub fn predefined_seeds(addrs: Vec<PeerAddr>) -> Box<dyn Fn() -> Vec<PeerAddr> + Send> {
	Box::new(move || addrs.clone())
}
