// Copyright 2025 The MWC Developers
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

use crate::network_status;
use crate::tor::arti;
use crate::types::TorConfig;
use crate::Error;
use mwc_crates::arti_client::config::pt::TransportConfigBuilder;
use mwc_crates::arti_client::config::BridgeConfigBuilder;
use mwc_crates::arti_client::{BootstrapBehavior, TorClient, TorClientConfig};
use mwc_crates::chrono::Utc;
use mwc_crates::digest::Digest;
use mwc_crates::futures;
use mwc_crates::futures::future::{select, Either};
use mwc_crates::futures::StreamExt;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::log::{error, info};
use mwc_crates::rand;
use mwc_crates::rand::seq::IndexedRandom;
use mwc_crates::rand::RngExt;
use mwc_crates::rustls;
use mwc_crates::safelog::DisplayRedacted;
use mwc_crates::sha2::Sha256;
use mwc_crates::tokio;
use mwc_crates::tokio::runtime::{Handle, Runtime};
use mwc_crates::tokio::time::interval;
use mwc_crates::tokio_util::sync::CancellationToken;
use mwc_crates::tor_config::{BoolOrAuto, ExplicitOrAuto};
use mwc_crates::tor_error::ErrorReport;
use mwc_crates::tor_hscrypto::pk::HsId;
use mwc_crates::tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use mwc_crates::tor_hsservice;
use mwc_crates::tor_hsservice::config::OnionServiceConfigBuilder;
use mwc_crates::tor_keymgr::config::{ArtiKeystoreKind, CfgPath};
use mwc_crates::tor_llcrypto::pk::ed25519;
use mwc_crates::tor_rtcompat::PreferredRuntime;
use mwc_crates::zeroize::{Zeroize, Zeroizing};
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use std::{fs, thread};

static COMMUNITY_TNLS: &[&str] = &[
	"010D2A4DD97D7E58698FBE84788986387016AA74",
	"explorer.floonet.mwc.mw",
	"",
	"8E67E5AFA67083259FA67A7AD4150D39BA4F2691",
	"mwc7132.mwc.mw",
	"mwc7132",
	"E930242BA63962484760BDAEBA30903054A42672",
	"host1.mwc.mw",
	"host1",
	"FE913D629480F54C92F9C70CC5E64C1604C0898B",
	"host2.mwc.mw",
	"host2",
	"9DADEB404DFA3896737326676A7FB9F8440B6FC8",
	"mwc713.mwc.mw",
	"713",
	"392170959815E0227C185A1EC8807BAFF31C2074",
	"host4.mwc.mw",
	"host4",
	"CA1D23F317B14992EF74DF60BA8ABCD1A3AC8E5C",
	"host5.mwc.mw",
	"hst5",
	"A61D94F88CE58CA0F92F54E733052A5051AE84DD",
	"seed1.mwc.mw",
	"sd1",
	"19C9B10CAC330B8CC4ED8563104C1050E2C59320",
	"host6.mwc.mw",
	"h6",
	"799B148FDAF71E5AED9550B8FB6B4D597FCBE4EA",
	"mwc7135.mwc.mw",
	"c7135",
	"4731F1D06F75E78FD18F5D64A64C4E2CA5DD0FB9",
	"mainnet.seed2.mwc.mw",
	"mseed2",
	"16AE81F9464924F8BEA110B6089017E14461E9D5",
	"host8.mwc.mw",
	"ht8",
	"795455F7DFBD4B6FB6A6D18E06658F91666D1AAE",
	"host9.mwc.mw",
	"hot9",
	"1FC6FA74E7AC1B804A15D90241DFD2DF4F670054",
	"mwc7134.mwc.mw",
	"7134",
	"51F94DC699C4433947FB7F72B74A55FD8F596D1A",
	"host10.mwc.mw",
	"ht10",
	"9DF6CCC1C2D3941CD885EA23B126C94A04C8B9BE",
	"host7.mwc.mw",
	"host7",
	"730D9CB09F0E61B158CBD53AB8B99F29B285BA79",
	"seed2.mwc.mw",
	"sd2",
	"5C0F860654F2746B13302D259828B85FB3EE83C5",
	"mwcseed.ddns.net",
	"mwseed",
	"F346EE08880288F4D9DD56B27E366CC18EB79B7C",
	"explorer.mwc.mw",
	"expmn",
	"C144204E91CE41B28E040EB99CE8F8CF3DE83FF6",
	"host11.mwc.mw",
	"h11",
	"6AA6EE7EF3D9A0318AEAEC17612F6B18FA681B08",
	"mqs.mwc.mw",
	"mqs",
	"FB1502CA83CC6AD00831B15C4362D7F0327615CE",
	"ftp.mwc.mw",
	"ftp",
	"76DFFC7657F839FB123241CB92A050F686B33FC4",
	"host13.mwc.mw",
	"hs13",
	"9DF6CCC1C2D3941CD885EA23B126C94A04C8B9BE",
	"host7.mwc.mw",
	"host7",
	"F2508B6EE2004317142CF950EDCD8BA57C37C1D9",
	"host14.mwc.mw",
	"host14",
	"CA4F7DE40C06D2DB092E1CA54C4E0244803BB488",
	"host12.mwc.mw",
	"st12",
];

static ARTI_OBJECT_ID: AtomicU64 = AtomicU64::new(1);

/// Parse an onion identity key in Arti's expanded Ed25519 format.
///
/// The expanded form is `scalar || hash_prefix`. This parser can verify that
/// the scalar half is usable and nonzero after Arti's scalar reduction, but it
/// cannot prove that `hash_prefix` was derived from an Ed25519 seed or has
/// enough entropy. Ed25519 signing uses `hash_prefix` to derive the
/// deterministic nonce, so a predictable prefix can make signatures leak the
/// scalar.
///
/// Format selection: `node_tor_id` and `p2p_config.onion_expanded_key` keep the
/// legacy 64-byte expanded Ed25519 secret format used by Tor's onion service
/// key material. We intentionally accept parseable non-canonical scalar bytes
/// here and do not rewrite them, because operators copy this value between the
/// Tor binary key file, node_tor_id, and config to preserve the same onion
/// address.
///
/// Accepted risk: this value comes from local node configuration or from the
/// stored Tor identity file, and the operator is responsible for providing
/// secret, securely generated data. In the normal deployment path the data is
/// copied from an external Tor service configuration, where it is expected to
/// have been generated securely.
pub fn parse_onion_expanded_key(
	expanded_key: &Zeroizing<[u8; 64]>,
) -> Result<ed25519::ExpandedKeypair, &'static str> {
	let keypair = ed25519::ExpandedKeypair::from_secret_key_bytes(*expanded_key.clone())
		.ok_or("invalid expanded Ed25519 key")?;
	let mut normalized_key = keypair.to_secret_key_bytes();

	if normalized_key[..32].iter().all(|byte| *byte == 0) {
		normalized_key.zeroize();
		return Err("zero Ed25519 scalar");
	}
	normalized_key.zeroize();

	Ok(keypair)
}

fn onion_address_from_id_keypair(id_keypair: &HsIdKeypair) -> String {
	let id_key = HsIdKey::from(id_keypair);
	id_key.id().display_unredacted().to_string()
}

pub fn onion_address_from_expanded_key(
	expanded_key: &Zeroizing<[u8; 64]>,
) -> Result<String, &'static str> {
	let expanded_keypair = parse_onion_expanded_key(expanded_key)?;
	let id_keypair = HsIdKeypair::from(expanded_keypair);
	Ok(onion_address_from_id_keypair(&id_keypair))
}

const PROBE_URLS_HTTP: &[&str] = &[
	"www.google.com",
	"www.msftconnecttest.com",
	"detectportal.firefox.com",
	"www.apple.com",
];

/// Expiraiton time for Arti data. We are expectign the the data can degradate, so we better do clean up once a day
pub const ARTI_DATA_EXPIRATION_TIME_SEC: i64 = 3600 * 24;

/// Return a random probe URL.
pub fn random_http_probe_url() -> &'static str {
	match PROBE_URLS_HTTP.choose(&mut rand::rng()) {
		Some(s) => s,
		None => "www.google.com",
	}
}

lazy_static! {
	// It is a tor server only running instance, in case of libraries can be shared by multiple nodes and wallets
	static ref TOR_ARTI_INSTANCE: mwc_crates::parking_lot::RwLock<Option<ArtiCore>> = mwc_crates::parking_lot::RwLock::new(None);
	// Tor instance ID. We can't store it with ArtiCore because of the access
	static ref TOR_ARTI_INSTANCE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
	// Tor service full restart request. Value 0 - not requsted. Otherwise next ArtiCore instance_id
	static ref TOR_RESTART_REQUEST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
	// Last restarting time (need to understand how long the tor was online without any issue)
	static ref TOR_RESTART_TIME: mwc_crates::parking_lot::RwLock<Option<Instant>> = mwc_crates::parking_lot::RwLock::new(None);
	// Monitoring thread. Only one instance is allowed
	static ref TOR_MONITORING_THREAD : mwc_crates::parking_lot::RwLock<Option<std::thread::JoinHandle<()>>> = mwc_crates::parking_lot::RwLock::new(None);
	// Stores monitor thread panics observed outside stop_arti() so synchronous cleanup can report them.
	static ref TOR_MONITORING_THREAD_ERROR: mwc_crates::parking_lot::RwLock<Option<String>> = mwc_crates::parking_lot::RwLock::new(None);
	// Serialize start/stop so callers never observe a partially published Arti startup or shutdown.
	static ref TOR_ARTI_START_STOP_LOCK: mwc_crates::parking_lot::Mutex<()> = mwc_crates::parking_lot::Mutex::new(());
	// Reistered active objects. We don't want to restart TOR until any onject does exist
	static ref TOR_ACTIVE_OBJECTS:  mwc_crates::parking_lot::RwLock<HashSet<String>> = mwc_crates::parking_lot::RwLock::new(HashSet::new());
	// Since arti os global, using the global flag for Atri beetstrap interruption.
	// Needed for clear exit while tor is still starting
	static ref SHUTDOWN_ARTI: CancellationToken = CancellationToken::new();
	/// It is ARTI session long token. For example when we want stop the wallet/node, but not the whole app.
	static ref CANCELLING_ARTI: mwc_crates::parking_lot::RwLock<HashMap<u32,CancellationToken>> = mwc_crates::parking_lot::RwLock::new(HashMap::new());
}

pub fn init_arti_cancelling(context_id: u32) {
	if let Some(token) = CANCELLING_ARTI
		.write()
		.insert(context_id, CancellationToken::new())
	{
		token.cancel();
	}
}

pub fn init_arti_cancelling_all(context_ids: Vec<u32>) {
	let mut guard = CANCELLING_ARTI.write();

	for id in context_ids {
		if let Some(token) = guard.insert(id, CancellationToken::new()) {
			token.cancel();
		}
	}
}

pub fn release_arti_cancelling(context_id: u32) {
	if let Some(token) = CANCELLING_ARTI.write().remove(&context_id) {
		// cancelling it so cloned instance will stop waiting as well
		token.cancel();
	}
}

// Trigger all cancelling events. Used in cases like arti restart, so all arti users will be dropped.
// Return all context Ids so we could recreate it
pub fn release_arti_cancelling_all() -> Vec<u32> {
	let mut res: Vec<u32> = Vec::new();
	CANCELLING_ARTI.write().retain(|id, token| {
		res.push(id.clone());
		token.cancel();
		false
	});

	debug_assert!(CANCELLING_ARTI.read_recursive().is_empty());

	res
}

pub fn is_arti_cancelled(context_id: u32) -> bool {
	// Cancellation tokens are optional context guards; Arti may still run with no
	// token registered. Treating a missing registration as cancelled is the more
	// conservative behavior we want for context-scoped operations.
	!CANCELLING_ARTI.read_recursive().contains_key(&context_id)
}

/// Return a context cancellation token for waiters.
///
/// Callers only need to observe Arti context cancellation. Return a child token
/// so parent cancellation wakes them, but cancelling the returned token cannot
/// cancel the shared token stored in CANCELLING_ARTI.
pub fn get_arti_cancell_token(context_id: u32) -> Option<CancellationToken> {
	CANCELLING_ARTI
		.read_recursive()
		.get(&context_id)
		.map(|token| token.child_token())
}

/// Request Arti shutdown by cancelling the global shutdown token.
///
/// This is a signal-only API. It does not drop TOR_ARTI_INSTANCE, join
/// TOR_MONITORING_THREAD, or verify that the Tor runtime has stopped. Callers
/// that need synchronous cleanup should use stop_arti().
pub fn shutdown_arti() {
	SHUTDOWN_ARTI.cancel();
}

pub(crate) fn is_shutdown_arti() -> bool {
	SHUTDOWN_ARTI.is_cancelled()
}

pub(crate) fn get_shutdown_arti_token() -> CancellationToken {
	SHUTDOWN_ARTI.clone()
}

pub fn request_arti_restart(reason: &str) {
	info!("Requestion Arti restart. Reason: {}", reason);
	let next_id = TOR_ARTI_INSTANCE_ID
		.load(Ordering::SeqCst)
		.saturating_add(1);
	TOR_RESTART_REQUEST.store(next_id, Ordering::SeqCst);
}

pub fn get_next_arti_instance_id() -> u64 {
	TOR_RESTART_REQUEST.load(Ordering::SeqCst)
}

pub fn get_current_arti_instance_id() -> u64 {
	TOR_ARTI_INSTANCE_ID.load(Ordering::SeqCst)
}

fn panic_payload_to_string(payload: Box<dyn Any + Send + 'static>) -> String {
	match payload.downcast::<String>() {
		Ok(msg) => *msg,
		Err(payload) => match payload.downcast::<&'static str>() {
			Ok(msg) => (*msg).to_owned(),
			Err(_) => "unknown panic payload".to_owned(),
		},
	}
}

fn join_arti_monitor_thread(monitoring_thread: thread::JoinHandle<()>) -> Option<String> {
	let thread_id = monitoring_thread.thread().id();
	if let Err(payload) = monitoring_thread.join() {
		let panic_msg = panic_payload_to_string(payload);
		let err_msg = format!("thread {:?}: {}", thread_id, panic_msg);
		error!("Tor monitoring thread panicked, {}", err_msg);
		Some(err_msg)
	} else {
		None
	}
}

fn is_arti_monitor_running() -> bool {
	let mut monitoring_thread = TOR_MONITORING_THREAD.write();
	match monitoring_thread.as_ref() {
		Some(thread) if thread.is_finished() => {}
		Some(_) => return !is_shutdown_arti(),
		None => return false,
	}

	// Keep TOR_MONITORING_THREAD locked while joining the finished handle and
	// publishing any panic, so callers cannot observe "no monitor, no error".
	if let Some(finished_thread) = monitoring_thread.take() {
		if let Some(err_msg) = join_arti_monitor_thread(finished_thread) {
			*TOR_MONITORING_THREAD_ERROR.write() = Some(err_msg);
		}
	}

	false
}

// "Started" means the Arti monitoring thread is alive and shutdown has not been
// requested. The Tor client itself can temporarily be absent during a restart,
// while the monitoring thread remains the orchestrator responsible for stopping,
// starting, and health-checking it.
pub fn is_arti_started() -> bool {
	is_arti_monitor_running()
}

pub fn get_arti_restart_time() -> Option<Instant> {
	if is_arti_healthy() {
		TOR_RESTART_TIME.read_recursive().clone()
	} else {
		None
	}
}

pub fn is_arti_healthy() -> bool {
	if !is_arti_monitor_running() {
		return false;
	}

	let guard = match TOR_ARTI_INSTANCE.try_read_recursive() {
		Some(guard) => guard,
		None => return false,
	};
	if guard.is_none() {
		return false;
	}

	let restart_requested = TOR_RESTART_REQUEST.load(Ordering::SeqCst);
	let tor_version = TOR_ARTI_INSTANCE_ID.load(Ordering::SeqCst);
	restart_requested == tor_version
}

pub fn is_arti_restarting() -> bool {
	let restart_requested = TOR_RESTART_REQUEST.load(Ordering::SeqCst);
	let tor_version = TOR_ARTI_INSTANCE_ID.load(Ordering::SeqCst);
	tor_version < restart_requested
}

fn shutdown_arti_core(arti: ArtiCore) {
	let ArtiCore {
		tor_runtime,
		tor_client,
		..
	} = arti;
	drop(tor_client);
	tor_runtime.shutdown_timeout(Duration::from_secs(10));
}

fn shutdown_bootstrapped_tor_client(tor_rt: Option<(Arc<TorClient<PreferredRuntime>>, Runtime)>) {
	if let Some((tor_client, tor_runtime)) = tor_rt {
		drop(tor_client);
		tor_runtime.shutdown_timeout(Duration::from_secs(10));
	}
}

// Such allocate object ID is pretty robust becuase all our objects are short lived, As a result
// after the wrapping all old ids will be free
pub fn allocate_arti_object_id() -> u64 {
	ARTI_OBJECT_ID
		.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
			Some(current.wrapping_add(1))
		})
		.unwrap_or(0)
}

pub fn register_arti_active_object(obj_name: String) -> Result<(), Error> {
	let mut active_objects = TOR_ACTIVE_OBJECTS.write();
	if !active_objects.insert(obj_name.clone()) {
		return Err(Error::Internal(format!(
			"Duplicate Arti active object registration: {}",
			obj_name
		)));
	}
	Ok(())
}

pub fn unregister_arti_active_object(obj_name: &str) -> Result<(), Error> {
	let mut active_objects = TOR_ACTIVE_OBJECTS.write();
	if !active_objects.remove(obj_name) {
		return Err(Error::Internal(format!(
			"Missing Arti active object unregistration: {}",
			obj_name
		)));
	}
	Ok(())
}

pub fn start_arti(
	config: &TorConfig,
	base_dir: &Path,
	print_start_message: bool,
	cleanup_arti_data: bool,
) -> Result<(), Error> {
	let _start_stop_guard = TOR_ARTI_START_STOP_LOCK.lock();

	if is_shutdown_arti() {
		return Err(Error::Interrupted);
	}

	if is_arti_monitor_running() {
		return Ok(());
	}

	if let Some(err) = TOR_MONITORING_THREAD_ERROR.write().take() {
		return Err(Error::PeerThreadPanic(err));
	}

	if rustls::crypto::CryptoProvider::get_default().is_none()
		&& rustls::crypto::ring::default_provider()
			.install_default()
			.is_err()
		&& rustls::crypto::CryptoProvider::get_default().is_none()
	{
		return Err(Error::TorProcess(
			"Unable to init Arti default CryptoProvider".into(),
		));
	}

	let previous_instance_id = TOR_ARTI_INSTANCE_ID.load(Ordering::SeqCst);
	let tor_id = previous_instance_id.saturating_add(1);

	let (new_arti, expiration_time) =
		ArtiCore::new(config, base_dir, print_start_message, cleanup_arti_data)?;
	if is_shutdown_arti() {
		shutdown_arti_core(new_arti);
		return Err(Error::Interrupted);
	}

	let (monitor_registered_tx, monitor_registered_rx) = mpsc::channel();

	// Starting tor monitoring thread if it is not running
	let mon_thread = match thread::Builder::new()
		.name("arti_checker".to_string())
		.spawn(move || {
			if monitor_registered_rx.recv().is_err() {
				return;
			}

			let mut last_running_time = Instant::now();
			let mut expiration_time = expiration_time;
			loop {
				if TOR_MONITORING_THREAD.read_recursive().is_none() || is_shutdown_arti() {
					break;
				}

				let need_arti_restart = {
					let connected = match arti::access_arti(|arti| {
						let connected = arti_async_block(async {
							match ArtiCore::test_circuit(arti).await {
								Ok(_) => true,
								Err(e) => {
									info!("Tor monitoring connection is failed with error: {}", e);
									false
								}
							}
						})?;
						Ok(connected)
					}) {
						Ok(connected) => connected,
						Err(Error::TorNotInitialized) => {
							thread::sleep(Duration::from_secs(30));
							continue;
						}
						Err(_) => false,
					};

					let need_arti_restart = if connected {
						last_running_time = Instant::now();
						false
					} else {
						let elapsed = Instant::now().duration_since(last_running_time);
						// Giving 3 minutes to arti to restore
						elapsed > Duration::from_secs(60)
					};
					need_arti_restart
						|| TOR_RESTART_REQUEST.load(Ordering::Relaxed)
							> TOR_ARTI_INSTANCE_ID.load(Ordering::SeqCst)
						|| Utc::now().timestamp() > expiration_time
				};

				if need_arti_restart {
					expiration_time = stop_start_arti(true);
					continue;
				}
				for _ in 0..30 {
					if TOR_MONITORING_THREAD.read_recursive().is_none() || is_shutdown_arti() {
						break;
					}
					thread::sleep(Duration::from_secs(1));
				}
			}
		}) {
		Ok(mon_thread) => mon_thread,
		Err(e) => {
			shutdown_arti_core(new_arti);
			return Err(Error::Internal(format!(
				"Unable to start arti_checker thread, {}",
				e
			)));
		}
	};

	let previous_arti = TOR_ARTI_INSTANCE.write().replace(new_arti);
	TOR_ARTI_INSTANCE_ID.store(tor_id, Ordering::SeqCst);
	let _ = TOR_RESTART_REQUEST.fetch_max(tor_id, Ordering::SeqCst);
	*TOR_RESTART_TIME.write() = Some(Instant::now());

	let mut monitoring_thread = TOR_MONITORING_THREAD.write();
	debug_assert!(monitoring_thread.is_none());
	*monitoring_thread = Some(mon_thread);

	let registration_failed = monitor_registered_tx.send(()).is_err();
	if registration_failed || is_shutdown_arti() {
		let failed_monitoring_thread = monitoring_thread.take();
		drop(monitoring_thread);
		let monitor_error = failed_monitoring_thread.and_then(join_arti_monitor_thread);
		let new_arti = TOR_ARTI_INSTANCE.write().take();
		// Startup failed after publishing partial state. Leave Arti stopped with
		// no running generation instead of restoring a possibly unmonitored old
		// instance. Keep TOR_RESTART_REQUEST monotonic so concurrent restart
		// requests are not erased.
		TOR_ARTI_INSTANCE_ID.store(previous_instance_id, Ordering::SeqCst);
		*TOR_RESTART_TIME.write() = None;
		if let Some(new_arti) = new_arti {
			shutdown_arti_core(new_arti);
		}
		if let Some(previous_arti) = previous_arti {
			shutdown_arti_core(previous_arti);
		}
		if let Some(err_msg) = monitor_error {
			return Err(Error::PeerThreadPanic(err_msg));
		}
		if registration_failed {
			return Err(Error::Internal(
				"Unable to start arti_checker thread: registration failed".into(),
			));
		}
		return Err(Error::Interrupted);
	}

	drop(monitoring_thread);
	if let Some(previous_arti) = previous_arti {
		shutdown_arti_core(previous_arti);
	}
	Ok(())
}

// respond with a next expiration time
fn stop_start_arti(start_new_client: bool) -> i64 {
	let reason = if start_new_client {
		"starting new Arti client"
	} else {
		"stopping Arti client"
	};
	request_arti_restart(reason);

	// Block new Arti users first, then cancel existing context waiters so active
	// Tor streams/services can unwind and unregister before the runtime is
	// destroyed. This drain is intentionally unbounded: forcing shutdown while
	// active objects remain can leak Arti-owned resources.
	let context_ids = release_arti_cancelling_all();

	let mut wait_counter = 0;
	while TOR_ACTIVE_OBJECTS.read_recursive().len() > 0 {
		thread::sleep(Duration::from_secs(1));
		wait_counter += 1;
		if wait_counter % 20 == 0 {
			let objects = TOR_ACTIVE_OBJECTS
				.read_recursive()
				.iter()
				.cloned()
				.collect::<Vec<_>>()
				.join(", ");
			info!("Waiting for Tor Active Objects: {}", objects);
		}
	}

	restart_arti(start_new_client, context_ids)
}

pub fn stop_arti() -> Result<(), Error> {
	let _start_stop_guard = TOR_ARTI_START_STOP_LOCK.lock();
	shutdown_arti();
	let mut first_error = TOR_MONITORING_THREAD_ERROR
		.write()
		.take()
		.map(Error::PeerThreadPanic);
	let monitoring_thread = TOR_MONITORING_THREAD.write().take();
	if let Some(monitoring_thread) = monitoring_thread {
		if let Some(err_msg) = join_arti_monitor_thread(monitoring_thread) {
			first_error.get_or_insert(Error::PeerThreadPanic(err_msg));
		}
	}

	if TOR_ARTI_INSTANCE.read_recursive().is_some() {
		stop_start_arti(false);
		TOR_RESTART_REQUEST.store(
			TOR_ARTI_INSTANCE_ID.load(Ordering::SeqCst),
			Ordering::SeqCst,
		);
	}

	// Checking if nothing left alive
	debug_assert!(TOR_ARTI_INSTANCE.read_recursive().is_none());
	debug_assert!(TOR_MONITORING_THREAD.read_recursive().is_none());
	debug_assert!(TOR_ACTIVE_OBJECTS.read_recursive().len() == 0);

	if let Some(e) = first_error {
		Err(e)
	} else {
		Ok(())
	}
}

pub fn access_arti<F, R>(f: F) -> Result<R, Error>
where
	F: FnOnce(&TorClient<PreferredRuntime>) -> Result<R, Error>,
{
	if is_arti_restarting() {
		return Err(Error::TorRestarting);
	}
	let guard = TOR_ARTI_INSTANCE.read_recursive();
	let arti = guard.as_ref().ok_or(Error::TorNotInitialized)?;
	f(&arti.tor_client)
}

/// Run async block inside sync environment. Allwais save Tokio runtime is used
pub fn arti_async_block<F, R>(fut: F) -> Result<R, Error>
where
	F: Future<Output = R> + Send,
	R: Send,
{
	if is_arti_restarting() {
		return Err(Error::TorRestarting);
	}

	let guard = TOR_ARTI_INSTANCE.read_recursive();
	let arti = guard.as_ref().ok_or(Error::TorNotInitialized)?;
	let atri_rt = &arti.tor_runtime;

	if Handle::try_current().is_err() {
		return Ok(atri_rt.block_on(fut));
	}

	// slow path: already inside the global runtime → spawn + join
	let res = thread::scope(|s| {
		let r = s
			.spawn(|| {
				atri_rt.block_on(fut) // runs on different thread
			})
			.join()
			.map_err(|_| Error::Internal("run_async_block join error".into()))?;
		Ok::<R, Error>(r)
	})?;
	Ok(res)
}

// Return the next Arti expiration time. A return value of 0 means no
// replacement client was started and the monitor should retry on its next
// iteration.
fn restart_arti(start_new_client: bool, context_ids: Vec<u32>) -> i64 {
	error!("Stopping ARTI...");
	let (tor_runtime, config, base_dir) = {
		let mut guard = TOR_ARTI_INSTANCE.write();

		match guard.take() {
			Some(arti) => {
				drop(arti.tor_client);
				drop(guard);
				(arti.tor_runtime, arti.config, arti.base_dir)
			}
			None => {
				error!("restart_arti called for empty instance. Ignoring this call");
				return 0;
			}
		}
	};
	// shutdown_timeout consumes the runtime and gives us a bounded stop path.
	// Tokio may leave long-running blocking work alive after the timeout; that is
	// acceptable here because active Arti-owned objects were drained before this
	// point, and we do not want shutdown to block forever on internal work.
	tor_runtime.shutdown_timeout(Duration::from_secs(10));

	if !start_new_client {
		return 0;
	}

	// Keep retrying by design. Arti startup can fail for transient bootstrap or
	// network reasons, and keeping the monitor in this loop lets the node
	// reconnect without manual intervention once Tor/network conditions recover.
	//
	// ArtiCore::new can also fail before bootstrap for local setup/configuration
	// reasons such as malformed bridge config, missing webtunnelclient,
	// invalid create_time.txt, or filesystem errors. Separating those permanent
	// failures from retryable bootstrap failures would require more state than
	// this monitor currently carries: restart_arti/stop_start_arti would need to
	// return Result, restart request counters would need to be reconciled on
	// fatal failure, and callers would need a persisted failure state instead of
	// only observing TorRestarting/TorNotInitialized while the monitor owns the
	// restart. We intentionally keep this path simple. In normal operation,
	// setup/config errors are caught on the first start_arti() call, where
	// ArtiCore::new returns the error to the caller for display; this retry loop
	// is mainly for failures after a valid Arti instance was already running.
	// Global shutdown interrupts the retry sleep below.
	loop {
		info!("Starting a new Arti client");
		match ArtiCore::new(&config, base_dir.as_path(), false, false) {
			Ok((arti_core, expiration_time)) => {
				info!("New Arti instance is successfully created.");
				*TOR_ARTI_INSTANCE.write() = Some(arti_core);
				let tor_id = TOR_ARTI_INSTANCE_ID
					.load(Ordering::SeqCst)
					.saturating_add(1);
				init_arti_cancelling_all(context_ids);
				TOR_ARTI_INSTANCE_ID.store(tor_id, Ordering::SeqCst);
				// Restart requests are coalesced, not counted. Requests that
				// arrive while this replacement client is still being published
				// are treated as satisfied by this start, even if they observed
				// the freshly incremented instance id.
				TOR_RESTART_REQUEST.store(tor_id, Ordering::SeqCst);
				*TOR_RESTART_TIME.write() = Some(Instant::now());
				network_status::update_network_outage_time(Utc::now().timestamp());
				return expiration_time;
			}
			Err(e) => {
				error!("Unable to create Arti instance, {}", e);
				info!("Waiting for 60 seconds before retry to create Arti instance.");
				for _ in 0..60 {
					std::thread::sleep(Duration::from_secs(1));
					if is_shutdown_arti() {
						// No new Arti instance was created. Return a near-future
						// retry timestamp so the monitor does not immediately spin
						// if shutdown is cleared and startup is attempted again.
						return Utc::now().timestamp().saturating_add(600);
					}
				}
			}
		}
	}
}

/// Embedded tor server - Atri
pub struct ArtiCore {
	// Using special runtime because it is the only reliable way to kill the tor_client.
	tor_runtime: Runtime,
	tor_client: Arc<TorClient<PreferredRuntime>>,
	config: TorConfig,
	base_dir: PathBuf,
}

const WEB: &str = "web";
const TNL: &str = "tunnel";

impl ArtiCore {
	/// Init tor service. Note, the service might be reset and recreated, so all dependent objects might be dropped
	/// Return: <ArtiCore, expiration time>
	fn new(
		config: &TorConfig,
		base_dir: &Path,
		print_start_message: bool,
		cleanup_arti_data: bool,
	) -> Result<(Self, i64), Error> {
		if !config.is_tor_enabled() {
			return Err(Error::TorConfig(format!(
				"ArtiCore init with not applicabe config {:?}",
				config
			)));
		}

		if is_shutdown_arti() {
			return Err(Error::Interrupted);
		}

		let (mut tor_client_config, mut expiration_time) = Self::build_config(
			&config.webtunnel_bridge,
			base_dir,
			print_start_message,
			cleanup_arti_data,
		)?;
		// We now let the Arti client start and bootstrap a connection to the network.
		// (This takes a while to gather the necessary consensus state, etc.)

		let (mut tor_rt, mut error) = match Self::bootstrap_tor_client(tor_client_config) {
			Ok(tor_rt) => (Some(tor_rt), None),
			Err(e) => {
				if print_start_message {
					println!("Unable to start Tor with direct connection to Tor network...");
				}
				(None, Some(e))
			}
		};

		if is_shutdown_arti() {
			shutdown_bootstrapped_tor_client(tor_rt.take());
			return Err(Error::Interrupted);
		}

		if tor_rt.is_none() && config.webtunnel_bridge.is_none() {
			// connecting to the bridges

			// Let's try to connect to some of community bridges
			let mut bridge_num = 0;
			let mut rng = rand::rng();
			for _ in 0..3 {
				debug_assert!(COMMUNITY_TNLS.len() % 3 == 0);
				let br_idx = rng.random_range(0..COMMUNITY_TNLS.len() / 3);

				let bridge = format!(
					"{}{} {} {} url=https://{}/{}{}{}",
					WEB,
					TNL,
					"10.0.0.2:443",
					COMMUNITY_TNLS[br_idx * 3],
					COMMUNITY_TNLS[br_idx * 3 + 1],
					WEB,
					TNL,
					COMMUNITY_TNLS[br_idx * 3 + 2]
				);

				(tor_client_config, expiration_time) = Self::build_config(
					&Some(bridge.to_string()),
					base_dir,
					print_start_message,
					cleanup_arti_data,
				)?;

				(tor_rt, error) = match Self::bootstrap_tor_client(tor_client_config) {
					Ok(cl) => (Some(cl), None),
					Err(e) => (None, Some(e)),
				};

				if is_shutdown_arti() {
					shutdown_bootstrapped_tor_client(tor_rt.take());
					return Err(Error::Interrupted);
				}

				bridge_num += 1;
				if tor_rt.is_some() || bridge_num >= 3 {
					break;
				}
			}
		}

		match tor_rt {
			Some((tor_client, rt)) => Ok((
				ArtiCore {
					tor_runtime: rt,
					tor_client,
					config: config.clone(),
					base_dir: base_dir.into(),
				},
				expiration_time,
			)),
			None => {
				let error = error.unwrap_or(Error::Internal("Unknown tor bootstrap error".into()));
				info!("Arti bootstrap error report: {}", error.report());
				return Err(error);
			}
		}
	}

	fn bootstrap_tor_client(
		tor_client_config: TorClientConfig,
	) -> Result<(Arc<TorClient<PreferredRuntime>>, Runtime), Error> {
		async fn abort_bootstrap_process(
			bootstap_process: tokio::task::JoinHandle<Result<(), mwc_crates::arti_client::Error>>,
			fallback_error: Error,
		) -> Error {
			bootstap_process.abort();
			match bootstap_process.await {
				Ok(Ok(())) => fallback_error,
				Ok(Err(e)) => Error::TorProcess(format!("Unable to bootstrap arti, {}", e)),
				Err(e) if e.is_cancelled() => fallback_error,
				Err(e) => Error::TorProcess(format!("Arti bootstrap tokio error, {}", e)),
			}
		}

		if Handle::try_current().is_ok() {
			return Err(Error::TorProcess(
				"Unable allocate tor runtime to run bootstrap".into(),
			));
		}

		// Special runtime for the atri client. Needed because we will need to shutdown RT in order to stop the client.
		let arti_rt = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()
			.map_err(|e| Error::Internal(format!("failed to start Tokio runtime, {}", e)))?;

		let tor_client_future = async move {
			// rt will be created base on the current runtime, which is arti_rt
			let rt = PreferredRuntime::current().map_err(|e| {
				Error::TorProcess(format!("Failed to get current PreferredRuntime, {}", e))
			})?;

			let tor_client = Arc::new(
				TorClient::with_runtime(rt)
					.config(tor_client_config)
					.local_resource_timeout(Duration::from_secs(3))
					.bootstrap_behavior(BootstrapBehavior::Manual)
					.create_unbootstrapped()
					.map_err(|e| {
						Error::TorProcess(format!(
							"Unable to build unbootstrapped Arti instance, {}",
							e
						))
					})?,
			);

			let tor_client2 = tor_client.clone();
			let mut bootstap_process = tokio::spawn(async move { tor_client2.bootstrap().await });

			// Waiting for bootstrap to finish, monitoring the progress
			let mut ticker = interval(Duration::from_secs(1));
			let mut last_new_progress_time = Instant::now();
			let mut last_progress = 0.0;
			loop {
				match select(&mut bootstap_process, pin!(ticker.tick())).await {
					Either::Left((bootstrap_res, _)) => {
						bootstrap_res
							.map_err(|e| {
								Error::TorProcess(format!("Arti bootstrap tokio error, {}", e))
							})?
							.map_err(|e| {
								Error::TorProcess(format!("Unable to bootstrap arti, {}", e))
							})?;
						info!("Tor Client bootstrap is finished successfully");
						break;
					}
					Either::Right((_, _)) => {
						if is_shutdown_arti() {
							info!("Arti bootstrap interrupted, stopping client");
							let error =
								abort_bootstrap_process(bootstap_process, Error::Interrupted).await;
							drop(tor_client);
							return Err(error);
						}
						let progress = tor_client.bootstrap_status().as_frac();
						if progress > last_progress {
							last_progress = progress;
							last_new_progress_time = Instant::now();
							info!("Arti bootstrap making some progress: {}%", progress * 100.0);
						} else {
							let elapsed = Instant::now().duration_since(last_new_progress_time);
							if elapsed >= Duration::from_secs(120) {
								error!("Arti not able to make any bootstrap progress during {} seconds", elapsed.as_secs());
								let error = abort_bootstrap_process(
									bootstap_process,
									Error::TorProcess(
										"Arti not able to make bootstrap progress during long time"
											.into(),
									),
								)
								.await;
								drop(tor_client);
								return Err(error);
							}
						}
					}
				}
			}

			if is_shutdown_arti() {
				info!("Arti bootstrap interrupted, stopping client");
				drop(tor_client);
				return Err(Error::Interrupted);
			}

			if let Err(e) = Self::test_circuit(&tor_client).await {
				error!("Unable to build a test Tor circle, {}", e);
				info!("Stopping failed Arti client");
				drop(tor_client);
				info!("Failed arti is stopped");
				return Err(e);
			}
			info!("Arti circuit test was passed");

			match Arc::try_unwrap(tor_client) {
				Ok(tor_client) => Ok(tor_client),
				Err(_) => {
					error!("tor_client is still shared!");
					Err(Error::TorProcess("tor_client is still shared".into()))
				}
			}
		};

		let tor_client = arti_rt.block_on(tor_client_future);

		match tor_client {
			Ok(tor_client) => Ok((tor_client, arti_rt)),
			Err(e) => {
				arti_rt.shutdown_timeout(Duration::from_secs(5));
				Err(e)
			}
		}
	}

	/// Start onion service.
	/// service_nickname - name of the service, must be unique for the app
	/// expanded_key - Build with:  ExpandedSecretKey::from(sec_key)
	/// Return: (onion service, onion address, stream for incoming request)
	pub fn start_onion_service(
		context_id: u32,
		tor_client: &TorClient<PreferredRuntime>,
		service_nickname: String,
		expanded_key: &Zeroizing<[u8; 64]>,
	) -> Result<
		(
			Arc<tor_hsservice::RunningOnionService>,
			String,
			impl futures::Stream<Item = tor_hsservice::RendRequest> + Send,
		),
		Error,
	> {
		info!("Prepating to start onion service for {}", service_nickname);

		// launch_onion_service_with_hsid expecting expanding 64 byte keys.
		let expanded_keypair = parse_onion_expanded_key(expanded_key).map_err(|e| {
			crate::types::Error::Internal(format!("Unable to build tor keys, {}", e))
		})?;
		let id_keypair = HsIdKeypair::from(expanded_keypair);
		// The onion address is deterministic from KP_hs_id. Derive it before
		// the service is reachable so p2p can advertise its own address without
		// waiting for hidden-service publication.
		let onion_address = onion_address_from_id_keypair(&id_keypair);

		let svc_cfg = OnionServiceConfigBuilder::default()
			.nickname(service_nickname.parse().map_err(|e| {
				Error::TorOnionService(format!("Invalid nickname {}, {}", service_nickname, e))
			})?)
			.build()
			.map_err(|e| {
				Error::TorOnionService(format!("Unable to build onion service config, {}", e))
			})?;

		if is_arti_restarting() {
			return Err(Error::TorRestarting);
		}

		if is_arti_cancelled(context_id) {
			return Err(Error::Interrupted);
		}

		if let Some((service, request_stream)) = tor_client
			.launch_onion_service_with_hsid(svc_cfg, id_keypair)
			.map_err(|e| Error::TorOnionService(format!("Unable to start onion service, {}", e)))?
		{
			info!(
				"Onion service {} is successfully started. Onion address: {}",
				service_nickname, onion_address
			);

			Ok((service, onion_address, request_stream))
		} else {
			return Err(Error::TorOnionService(
				"Unable to start onion service, it is disabled in config".into(),
			));
		}
	}

	// We can't add that condition to
	async fn wait_shutdown_poll(context_id: u32, timeout_seconds: u64) -> Result<(), Error> {
		let deadline = Instant::now()
			.checked_add(Duration::from_secs(timeout_seconds))
			.ok_or_else(|| {
				Error::DataOverflow(format!(
					"wait_shutdown_poll timeout_seconds={}",
					timeout_seconds
				))
			})?;

		loop {
			if is_arti_restarting() {
				return Err(Error::TorRestarting);
			}
			if is_shutdown_arti() || is_arti_cancelled(context_id) {
				return Err(Error::Interrupted);
			}

			let now = Instant::now();
			if now >= deadline {
				return Ok(()); // timed out
			}

			// Sleep in small chunks, but don't oversleep past the deadline
			let remaining = deadline - now;
			let step = remaining.min(Duration::from_millis(100));
			tokio::time::sleep(step).await;
		}
	}

	/// Utility method to wait for onion service advertise itself
	pub fn wait_until_started(
		context_id: u32,
		onion_service: &Arc<tor_hsservice::RunningOnionService>,
		timeout_seconds: u64,
	) -> Result<(), Error> {
		if is_arti_restarting() {
			return Err(Error::TorRestarting);
		}
		if is_shutdown_arti() || is_arti_cancelled(context_id) {
			return Err(Error::Interrupted);
		}

		let status_stream = onion_service.status_events();
		let mut binding = status_stream.filter(|status| {
			futures::future::ready({
				//let status_dump = format!("{:?}", status.state());
				status.state().is_fully_reachable()
			})
		});

		let next_status = binding.next();

		let res = arti_async_block(async {
			tokio::select! {
				// If a status event arrives first:
				maybe = next_status => {
					match maybe {
						Some(_) => {
							info!("Onion service is fully reachable.");
							Ok(())
						}
						None => Err(Error::TorOnionService("Status stream ended unexpectedly.".into())),
					}
				}

				// If shutdown/restart/timeout happens first:
				shutdown_or_timeout = Self::wait_shutdown_poll(context_id, timeout_seconds) => {
					match shutdown_or_timeout {
						Err(e) => Err(e), // Interrupted or TorNotInitialized
						Ok(()) => {
							info!("Timeout waiting for service to become reachable. You can still attempt to visit the service.");
							Ok(())
						}
					}
				}
			}
		})?;

		res
	}

	// return config and expiration time
	fn build_config(
		webtunnel_bridge: &Option<String>,
		base_dir: &Path,
		print_start_message: bool,
		cleanup_arti_data: bool,
	) -> Result<(TorClientConfig, i64), Error> {
		let mut builder = TorClientConfig::builder();

		// Usually we are using tunnel if without tunnel tor didn't start
		let mut connection_path = "direct".to_string();
		if let Some(bridge_line) = webtunnel_bridge {
			// bridge_line - tunnel connection string
			// Tor bridge lines are not treated as secrets here; normally they are
			// publicly available bridge descriptors rather than credentials.
			connection_path = format!("bridge_{}", Self::hash_str(bridge_line));

			if print_start_message {
				println!("Starting Tor with a bridge connection to Tor network, please wait...");
			}

			info!("Starting Arti with a bridge {}", bridge_line);
			// webtunnelclient location. Should be located in the same dir where our executable is located
			let exe = std::env::current_exe().map_err(|e| {
				Error::TorConfig(format!("Failed to locate executable path, {}", e))
			})?; // /full/path/to/my_bin
			let path = exe
				.parent()
				.ok_or(Error::TorConfig("Failed to locate executable path".into()))?;
			let client_path = path.join("webtunnelclient");

			if !client_path.try_exists().map_err(|e| {
				Error::TorConfig(format!(
					"Unable to check pluggable webtunnel client {}: {}",
					client_path.display(),
					e
				))
			})? {
				return Err(Error::TorConfig(format!(
					"Unable to find pluggable webtunnel client {}",
					client_path.display()
				)));
			}

			let bridge: BridgeConfigBuilder = bridge_line.parse().map_err(|e| {
				Error::TorConfig(format!(
					"Unable to parse the bridge line: {}  Error: {}",
					bridge_line, e
				))
			})?;
			builder.bridges().bridges().push(bridge);
			let mut transport = TransportConfigBuilder::default();
			transport
				.protocols(vec!["webtunnel".parse().map_err(|e| {
					Error::TorConfig(format!("Unknown protocol, {}", e))
				})?])
				.path(CfgPath::new_literal(client_path))
				.run_on_startup(true);
			builder.bridges().transports().push(transport);
		} else {
			if print_start_message {
				println!("Starting Tor with a direct connection to Tor network, please wait...");
			}
			info!("Starting Arti without a bridge");
		}

		// Setup Ethemeral Key Store because we don't want store tor keys anywhere
		builder
			.storage()
			.keystore()
			.enabled(BoolOrAuto::Explicit(true))
			.primary()
			.kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));

		let base_data_dir = base_dir.join("arti").join(connection_path);

		let creation_timestamp_fn = base_data_dir.join("create_time.txt");
		let creation_timestamp = match fs::read_to_string(&creation_timestamp_fn) {
			Ok(s) => s.trim().parse::<i64>().map_err(|e| {
				Error::TorConfig(format!(
					"Invalid Arti creation timestamp in {}: {}",
					creation_timestamp_fn.display(),
					e
				))
			})?,
			Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
			Err(e) => return Err(e.into()),
		};

		let now = Utc::now().timestamp();
		let creation_age_seconds = now.checked_sub(creation_timestamp).filter(|age| *age >= 0);
		let cleanup_expired_arti_data = creation_age_seconds
			.map(|age| age > ARTI_DATA_EXPIRATION_TIME_SEC)
			.unwrap_or(true);
		let expiration_timestamp_base = if cleanup_arti_data || cleanup_expired_arti_data {
			let age_description = creation_age_seconds
				.map(|age| format!("{:.2} hours", age as f64 / 3600.0))
				.unwrap_or_else(|| "invalid timestamp".to_string());
			info!(
				"Cleaning up Arti data because it is requested {} or expired - {}",
				cleanup_arti_data, age_description
			);
			// Clean up the data in the directory
			match fs::remove_dir_all(&base_data_dir) {
				Ok(()) => {}
				Err(e) if e.kind() == io::ErrorKind::NotFound => {}
				Err(e) => return Err(e.into()),
			}

			fs::create_dir_all(base_data_dir.clone())?;
			let mut f = File::create(creation_timestamp_fn)?;
			writeln!(f, "{now}")?;
			now
		} else {
			creation_timestamp
		};
		let arti_data_expiraiton_time = expiration_timestamp_base
			.checked_add(ARTI_DATA_EXPIRATION_TIME_SEC)
			.and_then(|timestamp| timestamp.checked_add(3600))
			.unwrap_or(i64::MAX);

		builder
			.storage()
			.cache_dir(CfgPath::new_literal(base_data_dir.join("cache")));
		builder
			.storage()
			.state_dir(CfgPath::new_literal(base_data_dir.join("state")));

		builder
			.stream_timeouts()
			.connect_timeout(Duration::from_secs(40))
			.resolve_ptr_timeout(Duration::from_secs(40))
			.resolve_timeout(Duration::from_secs(40));

		// These network-parameter overrides intentionally favor usability on
		// slow or unreliable networks over Tor's strongest default path-safety
		// and timeout behavior. MWC uses Tor as a transport privacy layer for
		// wallet/node connectivity, and the default Arti thresholds can make the
		// service unavailable for users with poor connectivity. For this use
		// case, Tor still provides sufficient privacy even with these degraded
		// connectivity settings, so we accept some reduction in the default
		// anonymity/safety margin in exchange for keeping the wallet/node usable.
		let net_params = builder.override_net_params();
		net_params.insert("cbtdisabled".into(), 1);
		net_params.insert("cbtinitialtimeout".into(), 120_000);
		net_params.insert("cbtmintimeout".into(), 60_000);
		net_params.insert("guard-internet-likely-down-interval".into(), 1800);
		net_params.insert("guard-nonprimary-guard-connect-timeout".into(), 60);
		net_params.insert("guard-nonprimary-guard-idle-timeout".into(), 1800);
		net_params.insert("hs_service_max_rdv_failures".into(), 5);
		net_params.insert("min_paths_for_circs_pct".into(), 40);
		net_params.insert("cbtlearntimeout".into(), 600);
		net_params.insert("cbtquantile".into(), 70);

		Ok((
			builder
				.build()
				.map_err(|e| Error::TorConfig(format!("Unable to build arti config, {}", e)))?,
			arti_data_expiraiton_time,
		))
	}

	pub async fn test_circuit(tor_client: &TorClient<PreferredRuntime>) -> Result<(), Error> {
		let mut connection_error: Error = Error::Internal("NONE".into());

		let hosts = network_status::get_random_http_probe_host(2);
		for probe_host in hosts {
			let arti_shutdown = get_shutdown_arti_token();
			let connect_res = tokio::select! {
				res = tor_client.connect((probe_host.as_str(), 443)) => res,
				_ = arti_shutdown.cancelled() => {
					return Err(Error::Interrupted);
				},
			};
			match connect_res {
				Ok(_stream) => {
					// Note, commented because of possible tor private data leaking into the logs.
					/*					let tunnel = stream
						.client_stream_ctrl()
						.ok_or(Error::TorProcess(
							"failed to get client stream ctrl?!".into(),
						))?
						.tunnel()
						.ok_or(Error::TorProcess("failed to get client circuit?!".into()))?;
					let paths = tunnel.all_paths();
					for (i, circ) in paths.into_iter().enumerate() {
						debug!("Circ {i}:");
						for node in circ.iter() {
							debug!("\tNode: {node}");
						}
					}*/
					info!("Attempting to build circuit to {} - OK", probe_host);
					return Ok(());
				}
				Err(e) => {
					info!("Attempting to build circuit to {} - FAILED", probe_host);
					connection_error =
						Error::TorProcess(format!("Unable connect to the {}, {}", probe_host, e));
					continue;
				}
			}
		}

		Err(connection_error)
	}

	fn hash_str(s: &str) -> String {
		let digest = Sha256::digest(s.as_bytes());
		mwc_crates::hex::encode(digest)
	}
}

/// Return the canonical v3 onion address if the input is already canonical.
pub fn canonical_onion_v3(onion: &str) -> Option<String> {
	if onion.len() != 62 || !onion.is_ascii() {
		return None;
	}

	let hsid = HsId::from_str(onion).ok()?;
	let canonical = hsid.display_unredacted().to_string();
	if onion == canonical {
		Some(canonical)
	} else {
		None
	}
}

/// Validate a canonical v3 onion address.
pub fn is_valid_onion_v3(onion: &str) -> bool {
	canonical_onion_v3(onion).is_some()
}

#[test]
#[ignore]
fn test_arti_connection() {
	use mwc_crates::rand::rngs::SysRng;
	use mwc_crates::secp::{ContextFlag, Secp256k1, SecretKey};
	use mwc_crates::tor_llcrypto::pk::ed25519::{ExpandedKeypair, Keypair};
	use mwc_crates::zeroize::Zeroize;
	use std::pin::Pin;

	let res = start_arti(&TorConfig::default(), Path::new("/tmp/arti/"), true, false);
	assert!(res.is_ok());

	let (onion_service, onion_address, _incoming_requests): (
		Arc<tor_hsservice::RunningOnionService>,
		String,
		Pin<Box<dyn futures::Stream<Item = tor_hsservice::StreamRequest> + Send>>,
	) = arti::access_arti(|tor_client| {
		let secp = Secp256k1::with_caps(ContextFlag::None).unwrap();
		let sec_key = SecretKey::new(&secp, &mut SysRng).unwrap();

		// It is how Arti want as constract the keys. Our goal is to extract 32b of secret following 32b of hash.
		// It is what to_secret_key_bytes does.
		let keypair = Keypair::from_bytes(&sec_key.0);
		let exp_key = ExpandedKeypair::from(&keypair);
		let mut exp_key_bytes = Zeroizing::new(exp_key.to_secret_key_bytes());

		let service = ArtiCore::start_onion_service(
			0,
			&tor_client,
			"onion-service-test".to_string(),
			&exp_key_bytes,
		);
		exp_key_bytes.zeroize();
		let (onion_service, onion_address, incoming_requests) = service?;
		Ok((
			onion_service,
			onion_address,
			Box::pin(tor_hsservice::handle_rend_requests(incoming_requests))
				as Pin<Box<dyn futures::Stream<Item = _> + Send>>,
		))
	})
	.expect("Onion service unable to start");

	// Not necessary wait for a long time. We can continue with listening even without any waiting
	arti::ArtiCore::wait_until_started(0, &onion_service, 20)
		.expect("Onion service unable to start");

	println!("Onion listener started at {}", onion_address);

	for i in 0..100 {
		let connected = arti::access_arti(|arti| {
			let connected = arti_async_block(async {
				let connected = arti
					.connect((
						"4vrh6vagyrw7du3vdcjk4u4g42qsb6dga6vevpds23fkgh6tw363hhyd.onion",
						//onion_address.as_str(),
						80,
					))
					.await;
				connected
			})?;
			Ok(connected)
		})
		.expect("arti::access_arti failure");
		if connected.is_ok() {
			println!("Connected from attempt {}", i);
			break;
		}
		println!(
			"Unable connect attempt {}, error: {}",
			i,
			connected.err().unwrap()
		);
	}
	//	assert!(connected.is_ok())
}

#[test]
fn test_is_valid_onion_v3() {
	assert!(is_valid_onion_v3(
		"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion"
	));
	assert!(!is_valid_onion_v3(
		"7uz3yofsjta2ffvnt7ygdhxachspwo5hnqnctnlwqgtrgp3wjedtkmtm.onion"
	));
	assert!(!is_valid_onion_v3(
		"ZWECAV6DGFTSOSCYBPZUFBO77D452MK3MOX2FQZJQOCU7265BXGQ6OAD.onion"
	));
	assert!(!is_valid_onion_v3(
		"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oadaaaaaaaa.onion"
	));
	assert!(!is_valid_onion_v3(
		"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad"
	));
	assert!(!is_valid_onion_v3(
		"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oé.onion"
	));
}

#[test]
fn parse_onion_expanded_key_accepts_canonical_key() {
	let keypair = ed25519::Keypair::from_bytes(&[7u8; 32]);
	let expanded_key =
		Zeroizing::new(ed25519::ExpandedKeypair::from(&keypair).to_secret_key_bytes());

	assert!(parse_onion_expanded_key(&expanded_key).is_ok());
}

#[test]
fn onion_address_from_expanded_key_matches_identity_seed() {
	let seed = [7u8; 32];
	let keypair = ed25519::Keypair::from_bytes(&seed);
	let expanded_key =
		Zeroizing::new(ed25519::ExpandedKeypair::from(&keypair).to_secret_key_bytes());

	let onion_address = onion_address_from_expanded_key(&expanded_key).unwrap();
	let expected_onion_address = format!(
		"{}.onion",
		mwc_util::OnionV3Address::from_private(&seed)
			.unwrap()
			.to_ov3_str()
	);

	assert_eq!(onion_address, expected_onion_address);
}

#[test]
fn parse_onion_expanded_key_accepts_non_canonical_scalar() {
	let mut expanded_key = [0u8; 64];
	// Ed25519 group order plus one in little-endian form. It reduces to one
	// when reconstructed as a scalar, so the round-trip bytes do not match.
	expanded_key[..32].copy_from_slice(&[
		0xee, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
		0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x10,
	]);
	expanded_key[32..].fill(42);

	assert!(parse_onion_expanded_key(&Zeroizing::new(expanded_key)).is_ok());
}

#[test]
fn parse_onion_expanded_key_rejects_zero_scalar() {
	let mut expanded_key = [1u8; 64];
	expanded_key[..32].fill(0);

	assert_eq!(
		parse_onion_expanded_key(&Zeroizing::new(expanded_key))
			.err()
			.unwrap(),
		"zero Ed25519 scalar"
	);
}

#[test]
fn build_config_handles_extreme_creation_timestamps() {
	for timestamp in [i64::MIN, i64::MAX] {
		let dir = mwc_crates::tempfile::TempDir::new().unwrap();
		let data_dir = dir.path().join("arti").join("direct");
		fs::create_dir_all(&data_dir).unwrap();
		let timestamp_file = data_dir.join("create_time.txt");
		fs::write(&timestamp_file, timestamp.to_string()).unwrap();

		let before = Utc::now().timestamp();
		let (_, expiration_time) = ArtiCore::build_config(&None, dir.path(), false, false).unwrap();
		let rewritten_timestamp = fs::read_to_string(&timestamp_file)
			.unwrap()
			.trim()
			.parse::<i64>()
			.unwrap();

		assert!(rewritten_timestamp >= before);
		assert_ne!(rewritten_timestamp, timestamp);
		assert_eq!(
			expiration_time,
			rewritten_timestamp + ARTI_DATA_EXPIRATION_TIME_SEC + 3600
		);
	}
}

#[test]
fn build_config_rejects_malformed_creation_timestamp_without_cleanup() {
	let dir = mwc_crates::tempfile::TempDir::new().unwrap();
	let data_dir = dir.path().join("arti").join("direct");
	fs::create_dir_all(&data_dir).unwrap();
	let timestamp_file = data_dir.join("create_time.txt");
	let marker_file = data_dir.join("marker");
	fs::write(&timestamp_file, "not-a-timestamp").unwrap();
	fs::write(&marker_file, "keep").unwrap();

	let res = ArtiCore::build_config(&None, dir.path(), false, false);

	assert!(matches!(
		res,
		Err(Error::TorConfig(msg))
			if msg.contains("Invalid Arti creation timestamp")
				&& msg.contains("create_time.txt")
	));
	assert!(marker_file.exists());
}

#[test]
fn bridge_cache_key_uses_stable_sha256_digest() {
	assert_eq!(
		ArtiCore::hash_str("abc"),
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	);
}

#[test]
fn active_object_tracking_rejects_duplicate_and_missing_entries() {
	let name = format!("test_arti_active_object_{}", allocate_arti_object_id());

	register_arti_active_object(name.clone()).unwrap();
	assert!(register_arti_active_object(name.clone()).is_err());

	unregister_arti_active_object(&name).unwrap();
	assert!(unregister_arti_active_object(&name).is_err());
}
