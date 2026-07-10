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

use mwc_core::global;
use mwc_core::global::PEER_PING_INTERVAL_SECONDS;
use mwc_core::global::{FLOONET_DNS_SEEDS, MAINNET_DNS_SEEDS};
use mwc_core::pow::Difficulty;
use mwc_crates::chrono::Utc;
use mwc_crates::log::{debug, error, info, trace, warn};
use mwc_crates::rand::prelude::IndexedRandom;
use mwc_crates::rand::prelude::IteratorRandom;
use mwc_crates::rand::rng;
use mwc_crates::sysinfo::{CpuRefreshKind, RefreshKind, System};
use mwc_p2p;
use mwc_p2p::tor::arti::is_arti_healthy;
use mwc_p2p::types::{OutboundConnectFailure, PeerAddr, BAN_WINDOW, PEER_MAX_INBOUND_COUNT};
use mwc_p2p::ChainAdapter;
use mwc_p2p::PeerAddr::Onion;
use mwc_p2p::{msg::PeerAddrs, network_status, Capabilities, P2PConfig};
use mwc_util::StopState;
use std::any::Any;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::{thread, time};

const CONNECT_TO_SEED_INTERVAL: u64 = 30;
const EXPIRE_INTERVAL: u64 = 3600;
const PEERS_CHECK_TIME_FULL: u64 = 60;
const PEERS_CHECK_TIME_BOOST: u64 = 10;
const PEERS_MONITOR_INTERVAL: u64 = 60;
const PEERS_LISTEN_MIN_INTERVAL: u64 = 600; // Interval to add some new peers even if everything is fine
const PEER_ACTIVE_BOOST_INTERVAL: u64 = 40; // How many seconds we can explore peers actively since any a new one was discovered

const PEER_RECONNECT_INTERVAL: u64 = 600;
const SEED_RECONNECT_INTERVAL: u64 = 60;
const PEER_Q_EXPECTED_SIZE: usize = 30;
const PEER_CONNECT_POOL_SIZE: usize = PEER_Q_EXPECTED_SIZE;

// Clean up peers chances 1/100. Cleaning interval is 1 hour. I think we should be good with preventing much of the noise.
const DELETE_ABSOLETE_PEER_CHANCES: u32 = 150;

type PeerConnectThread = thread::JoinHandle<Result<(), mwc_p2p::Error>>;

// Peer discovery and monitoring is intentionally best-effort. The returned
// Result only reports whether the monitor thread was spawned; once running, the
// JoinHandle returns () and callers cannot observe individual peer-store,
// cleanup, worker-join, or chain-state read failures. The monitor must stay
// online despite these errors, so it logs them and continues processing.
pub fn connect_and_monitor(
	p2p_server: Arc<mwc_p2p::Server>,
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
			let now = time::Instant::now();
			let mut seed_connect_time;
			let mut peers_connect_time = now + time::Duration::from_secs(PEERS_CHECK_TIME_BOOST);
			let mut expire_check_time = now + time::Duration::from_secs(EXPIRE_INTERVAL);
			let mut peer_monitor_time = now;
			let mut listen_time = now;

			let mut connecting_history: HashMap<PeerAddr, time::Instant> = HashMap::new();
			let mut listen_q_addrs: VecDeque<PeerAddr> = VecDeque::new();

			if let Err(e) = connect_to_seeds_and_peers(
				peers.clone(),
				&mut listen_q_addrs,
				&seed_list,
				config.clone(),
				PEER_Q_EXPECTED_SIZE,
			) {
				error!("failed to connect to seeds and peers: {:?}", e);
			}
			seed_connect_time =
				time::Instant::now() + time::Duration::from_secs(CONNECT_TO_SEED_INTERVAL);

			let mut prev_ping = time::Instant::now();

			let mut connection_threads: Vec<PeerConnectThread> = Vec::new();

			let mut last_peer_restore_time_limit = 0;

			peers.reset_last_peer_add_timestamp();

			// CPU usage in the range 0.0 - 1.0
			let mut cpu_usage: f64 = 0.0;

			loop {
				if stop_state.is_stopped() {
					break;
				}
				let (finished_connection_attempts, finished_connection_error) =
					join_finished_connection_threads(&mut connection_threads);
				if let Some(e) = finished_connection_error {
					error!("failed to process completed peer connection thread: {}", e);
				}
				// Pause egress peer connection request. Only for tests.
				if stop_state.is_paused() || !p2p_server.is_ready() {
					thread::sleep(time::Duration::from_secs(1));
					cpu_usage = 0.0;
					continue;
				}

				let connected_peers = peers.iter().connected().count();

				let now = time::Instant::now();

				if connected_peers == 0 {
					if now > seed_connect_time {
						info!("No peers connected, trying to reconnect to seeds!");
						if let Err(e) = connect_to_seeds_and_peers(
							peers.clone(),
							&mut listen_q_addrs,
							&seed_list,
							config.clone(),
							PEER_Q_EXPECTED_SIZE,
						) {
							error!("failed to reconnect to seeds and peers: {:?}", e);
						}
						seed_connect_time =
							now + time::Duration::from_secs(CONNECT_TO_SEED_INTERVAL);
					}
				}

				// Check for and remove expired peers from the storage
				if now > expire_check_time {
					peers.remove_expired(DELETE_ABSOLETE_PEER_CHANCES);
					expire_check_time = now + time::Duration::from_secs(EXPIRE_INTERVAL);
				}

				let request_more_connections = now >= listen_time;
				let has_enough_peers = peers.enough_outbound_peers();

				let listen_q_is_empty = listen_q_addrs.is_empty();

				// monitor peers first, then process sent requests with 'listen_for_addrs'
				if now > peer_monitor_time || (request_more_connections && listen_q_is_empty) {
					// monitor additional peers if we need to add more
					if let Err(e) = monitor_peers(
						peers.clone(),
						p2p_server.config.clone_without_secrets(),
						use_tor_connection,
						&mut listen_q_addrs,
						request_more_connections,
						&mut last_peer_restore_time_limit,
						&mut connecting_history,
						PEER_Q_EXPECTED_SIZE,
					) {
						error!("failed to monitor peers: {:?}", e);
					}

					if peers.is_sync_mode() || !has_enough_peers {
						peer_monitor_time = now
							+ time::Duration::from_secs(
								PEERS_MONITOR_INTERVAL / 5
									+ (PEERS_MONITOR_INTERVAL as f64 * 4.0 / 5.0 * cpu_usage)
										as u64,
							); // every 12 seconds let's do the check
					} else {
						peer_monitor_time = now + time::Duration::from_secs(PEERS_MONITOR_INTERVAL);
						// once a minute checking
					}

					listen_time = now + time::Duration::from_secs(PEERS_LISTEN_MIN_INTERVAL);
				}

				// make several attempts to get peers as quick as possible
				// with exponential backoff
				if now > peers_connect_time
					|| request_more_connections
					|| (!has_enough_peers && finished_connection_attempts > 0)
				{
					let is_boost = peers.is_boosting_mode();
					if has_enough_peers {
						peers_connect_time = now + time::Duration::from_secs(PEERS_CHECK_TIME_FULL);
					} else {
						if connection_threads.len() < PEER_CONNECT_POOL_SIZE {
							// try to connect to any address sent to the channel
							if let Err(e) = listen_for_addrs(
								peers.clone(),
								p2p_server.clone(),
								&mut connecting_history,
								use_tor_connection,
								&mut connection_threads,
								&mut listen_q_addrs,
								&seed_list,
							) {
								error!("failed to listen for peer addresses: {}", e);
							}
						}

						let outbound_was_discovered_boost =
							peers.was_peer_added_within(PEER_ACTIVE_BOOST_INTERVAL);

						let duration = if is_boost && outbound_was_discovered_boost {
							PEERS_CHECK_TIME_BOOST
								+ ((PEERS_CHECK_TIME_FULL - PEERS_CHECK_TIME_BOOST) as f64
									* cpu_usage) as u64
						} else {
							PEERS_CHECK_TIME_FULL
						};

						peers_connect_time = now + time::Duration::from_secs(duration);
					}
				}

				// Ping connected peers on every 10s to monitor peers.
				if prev_ping.elapsed() > time::Duration::from_secs(PEER_PING_INTERVAL_SECONDS) {
					let total_diff = peers.total_difficulty();
					let total_height = peers.total_height();
					if let (Ok(total_diff), Ok(total_height)) = (total_diff, total_height) {
						let summary = peers.check_all(total_diff, total_height);
						if summary.persistence_failures > 0 {
							if let Some(e) = summary.first_persistence_error() {
								error!(
									"failed to persist peer state for {} peer(s) removed after ping failure: {}",
									summary.persistence_failures, e
								);
							}
						}
						prev_ping = time::Instant::now();
					} else {
						error!("failed to get peers difficulty and/or height");
					}
				}

				let mut system = System::new_with_specifics(
					RefreshKind::nothing().with_cpu(CpuRefreshKind::nothing().with_cpu_usage()),
				);

				thread::sleep(time::Duration::from_secs(1));
				system.refresh_cpu_usage();

				cpu_usage = normalized_cpu_usage(system.cpus().iter().map(|cpu| cpu.cpu_usage()));
			}

			if let Err(e) = join_connection_threads(&mut connection_threads) {
				error!(
					"failed to process remaining peer connection thread during shutdown: {}",
					e
				);
			}
		})
}

fn monitor_peers(
	peers: Arc<mwc_p2p::Peers>,
	config: P2PConfig,
	use_tor_connection: bool,
	listen_q_addrs: &mut VecDeque<PeerAddr>,
	request_more_connections: bool,
	last_peer_restore_time_limit: &mut i64,
	connecting_history: &mut HashMap<PeerAddr, time::Instant>,
	q_expected_size: usize,
) -> Result<(), mwc_p2p::Error> {
	// regularly check if we need to acquire more peers and if so, gets
	// them from db
	let mut total_count = 0;
	let mut healthy_count = 0;
	let mut banned_count = 0;
	let mut defuncts = vec![];

	let peer_data = peers.all_peer_data(Capabilities::UNKNOWN)?;

	for x in peer_data.into_iter() {
		match x.flags {
			mwc_p2p::State::Banned => {
				let interval = Utc::now().timestamp().saturating_sub(x.last_banned);
				// Unban peer
				if interval >= config.ban_window.unwrap_or(BAN_WINDOW) {
					match peers.unban_peer(&x.addr) {
						Ok(()) => debug!(
							"monitor_peers: unbanned {} after {} seconds",
							x.addr, interval
						),
						Err(e) => {
							error!("failed to unban peer {}: {:?}", x.addr, e);
							return Err(e);
						}
					}
				} else {
					banned_count += 1;
				}
			}
			mwc_p2p::State::Healthy => healthy_count += 1,
			mwc_p2p::State::Defunct => defuncts.push(x),
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
	let summary = peers.clean_peers(
		config
			.peer_max_inbound_count
			.unwrap_or(PEER_MAX_INBOUND_COUNT) as usize,
		config.peer_max_outbound_count(in_sync_mode) as usize,
		boost_peers_capabilities,
		config.clone_without_secrets(),
	);
	let persistence_failures = summary.persistence_failures;
	if let Some(e) = summary.into_first_persistence_error() {
		error!(
			"failed to persist peer state for {} peer(s) removed during peer cleanup: {}",
			persistence_failures, e
		);
		return Err(e);
	}

	if !request_more_connections && peers.enough_outbound_peers() {
		return Ok(());
	}

	// loop over connected peers that can provide peer lists
	// ask them for their list of peers
	for p in peers
		.iter()
		.with_capabilities(Capabilities::PEER_LIST)
		.connected()
	{
		trace!("monitor_peers: ask {} for more peers", p.info.addr,);
		if let Err(e) = p.send_peer_request(
			Capabilities::PEER_LIST | boost_peers_capabilities,
			use_tor_connection,
		) {
			error!("Failed send_peer_request to {}, Error: {}", p.info.addr, e);
		}
	}

	let restore_time_limit = network_status::get_last_network_reliable_time();
	if *last_peer_restore_time_limit != restore_time_limit {
		// Outage was recently detected, reverting recent Defuncts peers back to healthy
		// Taking extra 3 minutes into the safe connecitons time
		peers.restore_defunct_peers_since(restore_time_limit.saturating_sub(60 * 3))?;

		*last_peer_restore_time_limit = restore_time_limit;
		// reset connection history
		connecting_history.clear();
		peers.reset_advertised_peer_checks();
	}

	if listen_q_addrs.len() < q_expected_size {
		// Attempt to connect to any preferred peers.
		let peers_preferred = config
			.peers_preferred
			.clone()
			.unwrap_or(PeerAddrs::default());
		for p in peers_preferred {
			if !peers.is_known(&p) {
				listen_q_addrs.push_front(p);
			}
		}

		let advertised_stage_sz = (q_expected_size + listen_q_addrs.len()) / 2;

		// Taking some from advertized peers. Event if we check them before, still want to try them once more
		{
			let advertized = peers.ranked_advertised_peers();
			let now = Utc::now().timestamp();
			for p in advertized {
				peers.mark_advertised_peer_checked(&p.addr, now);
				if !peers.is_known(&p.addr) && !connecting_history.contains_key(&p.addr) {
					listen_q_addrs.push_back(p.addr.clone());

					if listen_q_addrs.len() > advertised_stage_sz {
						break;
					}
				}
			}
		}

		// find some peers from our db
		// and queue them up for a connection attempt
		// intentionally make too many attempts (2x) as some (most?) will fail
		// as many nodes in our db are not publicly accessible
		let new_peers = peers.find_peers(mwc_p2p::State::Healthy, boost_peers_capabilities)?;
		for p in new_peers.iter() {
			if !peers.is_known(&p.addr) && !connecting_history.contains_key(&p.addr) {
				listen_q_addrs.push_back(p.addr.clone());
				if listen_q_addrs.len() >= q_expected_size {
					break;
				}
			}
		}

		if listen_q_addrs.len() < q_expected_size {
			for peer in defuncts
				.into_iter()
				.filter(|p| p.last_connected > 0)
				.sample(&mut rng(), q_expected_size - listen_q_addrs.len())
			{
				listen_q_addrs.push_back(peer.addr.clone());
			}
		}
	}

	Ok(())
}

// Check if we have any pre-existing peer in db. If so, start with those,
// otherwise use the seeds provided.
fn connect_to_seeds_and_peers(
	peers: Arc<mwc_p2p::Peers>,
	listen_q_addrs: &mut VecDeque<PeerAddr>,
	seed_list: &Vec<PeerAddr>,
	config: P2PConfig,
	q_expected_size: usize,
) -> Result<(), mwc_p2p::Error> {
	let peers_deny = config.peers_deny.clone().unwrap_or(PeerAddrs::default());

	// If "peers_allow" is explicitly configured then just use this list
	// remembering to filter out "peers_deny".
	if let Some(peers_allow) = &config.peers_allow {
		for addr in peers_allow.difference(peers_deny.as_slice()) {
			if !peers.is_known(&addr) {
				listen_q_addrs.push_front(addr);
			}
		}
		return Ok(());
	}

	// Always try our "peers_preferred" remembering to filter out "peers_deny".
	if let Some(peers_preferred) = &config.peers_preferred {
		for addr in peers_preferred.difference(peers_deny.as_slice()) {
			if !peers.is_known(&addr) {
				listen_q_addrs.push_front(addr);
			}
		}
	}

	if listen_q_addrs.len() < q_expected_size {
		// check if we have some peers in db
		// look for peers that are able to give us other peers (via PEER_LIST capability)
		let mut found_peers = peers.find_peers(
			mwc_p2p::State::Healthy,
			Capabilities::PEER_LIST | peers.get_boost_peers_capabilities(),
		)?;
		if found_peers.is_empty() {
			found_peers = peers.find_peers(mwc_p2p::State::Healthy, Capabilities::PEER_LIST)?;
		}
		info!(
			"Found known healthy peers to reconnect: {}",
			found_peers.len()
		);

		// if so, get their addresses, otherwise use our seeds
		let peer_addrs = if found_peers.len() > 3 {
			let mut peer_addrs = found_peers
				.iter()
				.map(|p| p.addr.clone())
				.collect::<Vec<_>>();

			if let Some(seed_addr) = seed_list.choose(&mut rng()) {
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
					if listen_q_addrs.len() >= q_expected_size {
						break;
					}
				}
			}
		}
	}

	Ok(())
}

fn join_finished_connection_threads(
	connection_threads: &mut Vec<PeerConnectThread>,
) -> (usize, Option<mwc_p2p::Error>) {
	let mut first_error = None;
	let mut completed = 0;
	let mut i = 0;
	while i < connection_threads.len() {
		if !connection_threads[i].is_finished() {
			i += 1;
			continue;
		}

		let thread = connection_threads.swap_remove(i);
		completed += 1;
		if let Err(e) = join_connection_thread(thread) {
			if first_error.is_none() {
				first_error = Some(e);
			}
		}
	}

	(completed, first_error)
}

fn join_connection_threads(
	connection_threads: &mut Vec<PeerConnectThread>,
) -> Result<(), mwc_p2p::Error> {
	let mut first_error = None;
	while let Some(thread) = connection_threads.pop() {
		if let Err(e) = join_connection_thread(thread) {
			if first_error.is_none() {
				first_error = Some(e);
			}
		}
	}

	if let Some(e) = first_error {
		Err(e)
	} else {
		Ok(())
	}
}

fn join_connection_thread(thread: PeerConnectThread) -> Result<(), mwc_p2p::Error> {
	let thread_name = thread.thread().name().unwrap_or("peer_connect").to_string();
	match thread.join() {
		Ok(Ok(())) => Ok(()),
		Ok(Err(e)) => {
			error!("{} thread failed: {}", thread_name, e);
			Err(e)
		}
		Err(payload) => {
			let panic_message = panic_payload_message(&*payload);
			error!("{} thread panicked: {}", thread_name, panic_message);
			Err(mwc_p2p::Error::PeerThreadPanic(format!(
				"{}: {}",
				thread_name, panic_message
			)))
		}
	}
}

fn normalized_cpu_usage<I>(cpu_usages: I) -> f64
where
	I: IntoIterator<Item = f32>,
{
	let mut cpu_count = 0usize;
	let mut cpu_usage_sum = 0.0;
	for usage in cpu_usages {
		cpu_count += 1;
		let usage = usage as f64 / 100.0;
		if usage.is_finite() {
			cpu_usage_sum += usage.clamp(0.0, 1.0);
		}
	}

	if cpu_count == 0 {
		0.0
	} else {
		(cpu_usage_sum / cpu_count as f64).clamp(0.0, 1.0)
	}
}

fn panic_payload_message(payload: &(dyn Any + Send + 'static)) -> String {
	if let Some(message) = payload.downcast_ref::<&str>() {
		(*message).to_string()
	} else if let Some(message) = payload.downcast_ref::<String>() {
		message.clone()
	} else {
		"non-string panic payload".to_string()
	}
}

/// Regularly poll a channel receiver for new addresses and initiate a
/// connection if the max peer count isn't exceeded. A request for more
/// peers is also automatically sent after connection.
fn listen_for_addrs(
	peers: Arc<mwc_p2p::Peers>,
	p2p: Arc<mwc_p2p::Server>,
	connecting_history: &mut HashMap<PeerAddr, time::Instant>,
	use_tor_connection: bool,
	connection_threads: &mut Vec<PeerConnectThread>,
	listen_q_addrs: &mut VecDeque<PeerAddr>,
	seed_list: &Vec<PeerAddr>,
) -> Result<(), mwc_p2p::Error> {
	let now = time::Instant::now();
	connecting_history
		.retain(|_, time| time.elapsed() < time::Duration::from_secs(PEER_RECONNECT_INTERVAL));

	let mut seen = HashSet::new();
	listen_q_addrs.retain(|p| {
		seen.insert(p.clone()) && (!(peers.is_known(p) || connecting_history.contains_key(p)))
	});

	if listen_q_addrs.is_empty() {
		if let Some(seed_adr) = seed_list.choose(&mut rng()) {
			match connecting_history.get(seed_adr) {
				Some(time) => {
					if time.elapsed() >= time::Duration::from_secs(SEED_RECONNECT_INTERVAL) {
						listen_q_addrs.push_back(seed_adr.clone());
					}
				}
				None => {
					listen_q_addrs.push_back(seed_adr.clone());
				}
			}
		}
	}

	let active_start_len = connection_threads.len();

	while !listen_q_addrs.is_empty() {
		if connection_threads.len() >= PEER_CONNECT_POOL_SIZE {
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
			.spawn(move || -> Result<(), mwc_p2p::Error> {
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
							if let Err(e) = p.send_peer_request(
								Capabilities::PEER_LIST | peers_c.get_boost_peers_capabilities(),
								use_tor_connection,
							) {
								mark_peer_defunct_after_initial_send_failure(
									&peers_c,
									&addr_c,
									"send_peer_request",
									&e,
								)?;
								return Err(e);
							}
						}
						// Requesting ping as well, need to know the height asap
						let total_diff = match peers_c.total_difficulty() {
							Ok(total_diff) => Some(total_diff),
							Err(e) => {
								error!(
									"Failed to get total difficulty before pinging {}: {}",
									p.info.addr, e
								);
								None
							}
						};
						let total_height = match peers_c.total_height() {
							Ok(total_height) => Some(total_height),
							Err(e) => {
								error!(
									"Failed to get total height before pinging {}: {}",
									p.info.addr, e
								);
								None
							}
						};
						if let (Some(total_diff), Some(total_height)) = (total_diff, total_height) {
							if let Err(e) = p.send_ping(total_diff, total_height) {
								mark_peer_defunct_after_initial_send_failure(
									&peers_c,
									&addr_c,
									"send_ping",
									&e,
								)?;
								return Err(e);
							}
						}
					}
					Err(e) => match e.outbound_connect_failure() {
						OutboundConnectFailure::Ignore => {
							// Ignore means "do not mark this peer Defunct", not
							// that connect was perfect. Server::connect can fail
							// for local/thread/transport conditions where there
							// is no peer reputation update to make. Log the error
							// and let the worker complete so peer discovery stays
							// best-effort; peer-fault cases are handled below.
							debug!(
								"Skipping peer state update for local connect failure {}: {}",
								addr_c, e
							);
						}
						OutboundConnectFailure::MarkDefunct => {
							debug!("Connection to the peer {} was rejected, {}", addr_c, e);
							if let Err(e) = peers_c.update_state(&addr_c, mwc_p2p::State::Defunct) {
								error!(
									"Failed to persist Defunct state for peer {}: {}",
									addr_c, e
								);
								return Err(e);
							}
						}
					},
				}
				Ok(())
			});

		match thr {
			Ok(thr) => {
				connecting_history.insert(addr, now);
				connection_threads.push(thr);
			}
			Err(e) => {
				error!("failed to launch peer_connect thread for {}, {}", addr, e);
				// Note, we don't return address back into listen_q_addrs because that
				// will prevent the loop from exiting
				return Err(e.into());
			}
		}
	}

	let q_finish_len = listen_q_addrs.len();
	let started_attempts = connection_threads.len().saturating_sub(active_start_len);
	info!(
		"Started {} peer connect attempt(s). Q len: {}, active attempts: {}",
		started_attempts,
		q_finish_len,
		connection_threads.len()
	);
	Ok(())
}

fn mark_peer_defunct_after_initial_send_failure(
	peers: &Arc<mwc_p2p::Peers>,
	addr: &PeerAddr,
	action: &str,
	send_err: &mwc_p2p::Error,
) -> Result<(), mwc_p2p::Error> {
	error!(
		"Failed {} to {}, marking peer Defunct. Error: {}",
		action, addr, send_err
	);
	if let Err(e) = peers.update_state(addr, mwc_p2p::State::Defunct) {
		error!("Failed to persist Defunct state for peer {}: {}", addr, e);
		return Err(e);
	}
	Ok(())
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
					if seed_addr_onion_host(s) {
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

fn seed_addr_onion_host(addr: &str) -> bool {
	let host = match addr.rsplit_once(':') {
		Some((host, _port)) => host,
		None => addr,
	};
	let host = host.strip_suffix('.').unwrap_or(host);

	host.as_bytes()
		.get(host.len().saturating_sub(".onion".len())..)
		.map(|suffix| suffix.eq_ignore_ascii_case(b".onion"))
		.unwrap_or(false)
}

/// Convenience function to resolve DNS addresses from DNS records.
///
/// Seed resolution is intentionally best-effort: an invalid onion seed or a
/// failed DNS lookup is logged and skipped while the remaining seeds are
/// still tried. Callers cannot recover from individual seed resolution
/// failures beyond logging them, so this function returns the successfully
/// resolved peer addresses rather than failing the whole discovery pass.
pub fn resolve_dns_to_addrs(dns_records: &Vec<String>) -> Vec<PeerAddr> {
	let mut addresses: Vec<PeerAddr> = vec![];
	for dns in dns_records {
		if seed_addr_onion_host(dns.as_str()) {
			match PeerAddr::from_str(dns.as_str()) {
				Ok(addr) => addresses.push(addr),
				Err(e) => error!("Failed to parse onion seed {:?}: {}", dns, e),
			}
		} else {
			debug!("Retrieving addresses from dns {}", dns);
			match dns.to_socket_addrs() {
				Ok(addrs) => {
					for addr in addrs.map(PeerAddr::Ip) {
						if let Some(reason) = addr.gossip_rejection_reason() {
							warn!(
								"Ignoring non-gossipable dns seed address {} from {}: {}",
								addr, dns, reason
							);
							continue;
						}
						if !addresses.contains(&addr) {
							addresses.push(addr);
						}
					}
				}
				Err(e) => error!("Failed to resolve dns {:?} got error {:?}", dns, e),
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

#[cfg(test)]
mod tests {
	use super::*;

	const VALID_ONION: &str = "zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion";

	#[test]
	fn join_connection_threads_collects_remaining_worker_errors() {
		let mut connection_threads = vec![thread::Builder::new()
			.name("peer_connect_test".to_string())
			.spawn(|| Err(mwc_p2p::Error::Internal("worker failed".to_string())))
			.unwrap()];

		let err = join_connection_threads(&mut connection_threads).unwrap_err();

		assert!(connection_threads.is_empty());
		match err {
			mwc_p2p::Error::Internal(message) => assert_eq!(message, "worker failed"),
			e => panic!("unexpected error: {:?}", e),
		}
	}

	#[test]
	fn join_finished_connection_threads_reports_completed_workers() {
		let mut connection_threads = vec![
			thread::Builder::new()
				.name("peer_connect_ok_test".to_string())
				.spawn(|| Ok(()))
				.unwrap(),
			thread::Builder::new()
				.name("peer_connect_err_test".to_string())
				.spawn(|| Err(mwc_p2p::Error::Internal("worker failed".to_string())))
				.unwrap(),
		];

		while connection_threads
			.iter()
			.any(|thread| !thread.is_finished())
		{
			thread::sleep(time::Duration::from_millis(1));
		}

		let (completed, err) = join_finished_connection_threads(&mut connection_threads);

		assert_eq!(completed, 2);
		assert!(connection_threads.is_empty());
		match err {
			Some(mwc_p2p::Error::Internal(message)) => assert_eq!(message, "worker failed"),
			e => panic!("unexpected error: {:?}", e),
		}
	}

	#[test]
	fn normalized_cpu_usage_handles_empty_cpu_list() {
		assert_eq!(normalized_cpu_usage(Vec::<f32>::new()), 0.0);
	}

	#[test]
	fn normalized_cpu_usage_sanitizes_invalid_values() {
		let usage = normalized_cpu_usage(vec![
			50.0,
			f32::NAN,
			f32::INFINITY,
			f32::NEG_INFINITY,
			-25.0,
			125.0,
		]);

		assert_eq!(usage, 0.25);
		assert!(usage.is_finite());
		assert!((0.0..=1.0).contains(&usage));
	}

	#[test]
	fn seed_addr_onion_host_matches_port_case_and_trailing_dot() {
		for addr in [
			VALID_ONION,
			"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.ONION",
			"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion.",
			"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion:3414",
			"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.ONION:3414",
		] {
			assert!(seed_addr_onion_host(addr), "{}", addr);
		}

		for addr in ["example.com:3414", "127.0.0.1:3414", "[::1]:3414"] {
			assert!(!seed_addr_onion_host(addr), "{}", addr);
		}
	}

	#[test]
	fn resolve_dns_to_addrs_keeps_onion_like_inputs_out_of_dns() {
		let addrs = resolve_dns_to_addrs(&vec![VALID_ONION.to_string()]);
		assert_eq!(addrs, vec![PeerAddr::Onion(VALID_ONION.to_string())]);

		let addrs = resolve_dns_to_addrs(&vec![
			"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.ONION".to_string(),
			"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion.".to_string(),
			"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion:3414".to_string(),
		]);
		assert!(addrs.is_empty());
	}

	#[test]
	fn resolve_dns_to_addrs_filters_non_gossipable_dns_results() {
		let addrs = resolve_dns_to_addrs(&vec![
			"8.8.8.8:3414".to_string(),
			"127.0.0.1:3414".to_string(),
			"10.0.0.1:3414".to_string(),
			"192.0.2.1:3414".to_string(),
			"8.8.8.8:0".to_string(),
			"[::1]:3414".to_string(),
			"[2001:db8::1]:3414".to_string(),
		]);

		assert_eq!(addrs, vec![PeerAddr::Ip("8.8.8.8:3414".parse().unwrap())]);
	}
}
