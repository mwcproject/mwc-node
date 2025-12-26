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
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::BridgeConfigBuilder;
use arti_client::{BootstrapBehavior, TorClient, TorClientConfig};
use chrono::Utc;
use futures::future::{select, Either};
use futures::StreamExt;
use lazy_static::lazy_static;
use mwc_util::secp::rand::Rng;
use mwc_util::tokio;
use mwc_util::tokio::runtime::{Handle, Runtime};
use mwc_util::tokio::time::interval;
use rand::seq::SliceRandom;
use safelog::DisplayRedacted;
use std::collections::HashSet;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use tor_config::{BoolOrAuto, ExplicitOrAuto};
use tor_error::ErrorReport;
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_keymgr::config::{ArtiKeystoreKind, CfgPath};
use tor_llcrypto::pk::ed25519;
use tor_proto::client::stream::ClientStreamCtrl;
use tor_rtcompat::PreferredRuntime;

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

const PROBE_URLS_HTTP: &[&str] = &[
	"www.google.com",
	"www.msftconnecttest.com",
	"detectportal.firefox.com",
	"www.apple.com",
];

/// Return a random probe URL.
pub fn random_http_probe_url() -> &'static str {
	PROBE_URLS_HTTP
		.choose(&mut rand::thread_rng())
		.expect("non-empty slice")
}

lazy_static! {
	// It is a tor server only running instance, in case of libraries can be shared by multiple nodes and wallets
	static ref TOR_ARTI_INSTANCE: std::sync::RwLock<Option<ArtiCore>> = std::sync::RwLock::new(None);
	// Tor service full restart request
	static ref TOR_RESTART_REQUEST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
	// Monitoring thread. Only one instance is allowed
	static ref TOR_MONITORING_THREAD : std::sync::RwLock<Option<std::thread::JoinHandle<()>>> = std::sync::RwLock::new(None);
	// Reistered active objects. We don't want to restart TOR until any onject does exist
	static ref TOR_ACTIVE_OBJECTS:  std::sync::RwLock<HashSet<String>> = std::sync::RwLock::new(HashSet::new());
	// Since arti os global, using the global flag for Atri beetstrap interruption.
	// Needed for clear exit while tor is still starting
	static ref SHOUTDOWN_ARTI: AtomicBool = AtomicBool::new(false);
}

pub fn shoutdown_arti() {
	SHOUTDOWN_ARTI.store(true, Ordering::Relaxed);
}

pub(crate) fn is_shoutdown_arti() -> bool {
	SHOUTDOWN_ARTI.load(Ordering::Relaxed)
}

pub fn request_arti_restart(reason: &str) {
	info!("Requestion Arti restart. Reason: {}", reason);
	TOR_RESTART_REQUEST.store(true, Ordering::Relaxed);
}

pub fn is_arti_started() -> bool {
	TOR_MONITORING_THREAD
		.read()
		.expect("RwLock failure")
		.is_some()
}

pub fn is_arti_healthy() -> bool {
	let has_tor = match TOR_ARTI_INSTANCE.try_read() {
		Ok(guard) => guard.is_some(),
		Err(_) => false,
	};
	let restart_requested = TOR_RESTART_REQUEST.load(Ordering::Relaxed);
	has_tor && !restart_requested
}

pub fn is_arti_restarting() -> bool {
	TOR_RESTART_REQUEST.load(Ordering::Relaxed)
}

pub fn register_arti_active_object(obj_name: String) {
	let mut active_objects = TOR_ACTIVE_OBJECTS.write().expect("RwLockFailure");
	debug_assert!(!active_objects.contains(&obj_name));
	active_objects.insert(obj_name);
}

pub fn unregister_arti_active_object(obj_name: &String) {
	let mut active_objects = TOR_ACTIVE_OBJECTS.write().expect("RwLockFailure");
	debug_assert!(active_objects.contains(obj_name));
	active_objects.remove(obj_name);
}

pub fn start_arti(config: &TorConfig, base_dir: &Path) -> Result<(), Error> {
	if TOR_ARTI_INSTANCE.read().unwrap().is_some() {
		return Ok(());
	}

	let mut atri_writer = TOR_ARTI_INSTANCE.write().expect("RwLock failure");

	let mut create_arti_res = ArtiCore::new(config, base_dir, false);
	if create_arti_res.is_err() {
		// retry with data clean up
		create_arti_res = ArtiCore::new(config, base_dir, true)
	}
	let a = create_arti_res?;
	TOR_RESTART_REQUEST.store(false, Ordering::Relaxed);

	*atri_writer = Some(a);

	// Starting tor monitoring thread if it is not running
	let mut monitoring_thread = TOR_MONITORING_THREAD.write().expect("RwLock failure");
	if monitoring_thread.is_none() {
		let mon_thread = thread::Builder::new()
			.name("arti_checker".to_string())
			.spawn(move || {
				let mut last_running_time = Instant::now();
				loop {
					if TOR_MONITORING_THREAD
						.read()
						.expect("RwLock Failure")
						.is_none() || is_shoutdown_arti()
					{
						break;
					}

					let need_arti_restart = {
						let connected = match arti::access_arti(|arti| {
							let connected =
								arti_async_block(async {
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
						need_arti_restart || TOR_RESTART_REQUEST.load(Ordering::Relaxed)
					};

					if need_arti_restart {
						stop_start_arti(true);
						break;
					}
					for _ in 0..30 {
						if TOR_MONITORING_THREAD
							.read()
							.expect("RwLock Failure")
							.is_none() || is_shoutdown_arti()
						{
							break;
						}
						thread::sleep(Duration::from_secs(1));
					}
				}
			})
			.expect("Unable to start arti_checker thread");

		*monitoring_thread = Some(mon_thread);
	}
	Ok(())
}

fn stop_start_arti(start_new_client: bool) {
	let reason = if start_new_client {
		"starting new Arti client"
	} else {
		"stopping Arti client"
	};
	request_arti_restart(reason);

	// Waiting for other service to stop
	let mut wait_counter = 0;
	while TOR_ACTIVE_OBJECTS.read().expect("RwLock failure").len() > 0 {
		thread::sleep(Duration::from_secs(1));
		wait_counter += 1;
		if wait_counter % 20 == 0 {
			let objects = TOR_ACTIVE_OBJECTS
				.read()
				.expect("RwLock failure")
				.iter()
				.cloned()
				.collect::<Vec<_>>()
				.join(", ");
			info!("Waiting for Tor Active Objects: {}", objects);
		}
	}

	restart_arti(start_new_client);
}

pub fn stop_arti() {
	let monitoring_thread = TOR_MONITORING_THREAD
		.write()
		.expect("RwLock Failure")
		.take();
	if monitoring_thread.is_none() {
		return; // Nothing to stop
	}
	let monitoring_thread = monitoring_thread.unwrap();
	let _ = monitoring_thread.join();

	// Stopping the arti
	stop_start_arti(false);
	TOR_RESTART_REQUEST.store(false, Ordering::Relaxed);
	// Checking if nothing left alive
	debug_assert!(TOR_ARTI_INSTANCE.read().expect("RwLock failure").is_none());
	debug_assert!(TOR_MONITORING_THREAD
		.read()
		.expect("RwLock failure")
		.is_none());
	debug_assert!(TOR_ACTIVE_OBJECTS.read().expect("RwLock failure").len() == 0);
}

pub fn access_arti<F, R>(f: F) -> Result<R, Error>
where
	F: FnOnce(&TorClient<PreferredRuntime>) -> Result<R, Error>,
{
	if is_arti_restarting() {
		return Err(Error::TorNotInitialized);
	}
	let guard = TOR_ARTI_INSTANCE.read().unwrap(); // ? converts PoisonError to E
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
		return Err(Error::TorNotInitialized);
	}

	let guard = TOR_ARTI_INSTANCE.read().unwrap(); // ? converts PoisonError to E
	let arti = guard.as_ref().ok_or(Error::TorNotInitialized)?;
	let atri_rt = &arti.tor_runtime;

	if Handle::try_current().is_err() {
		return Ok(atri_rt.block_on(fut));
	}

	// slow path: already inside the global runtime → spawn + join
	let res = thread::scope(|s| {
		s.spawn(|| {
			atri_rt.block_on(fut) // runs on different thread
		})
		.join()
		.expect("panic at run_async_block join")
	});
	Ok(res)
}

fn restart_arti(start_new_client: bool) {
	error!("Stopping ARTI...");
	let (tor_runtime, config, base_dir, restart_senders) = {
		let mut guard = TOR_ARTI_INSTANCE.write().expect("RwLock failure"); // ? converts PoisonError to E
		match guard.take() {
			Some(arti) => {
				drop(arti.tor_client);
				drop(guard);
				(
					arti.tor_runtime,
					arti.config,
					arti.base_dir,
					arti.restart_senders,
				)
			}
			None => {
				error!("restart_arti called for empty instance. Ignoring this call");
				return;
			}
		}
	};
	tor_runtime.shutdown_timeout(Duration::from_secs(10));

	if !start_new_client {
		return;
	}

	loop {
		info!("Starting a new Arti client");
		match ArtiCore::new(&config, base_dir.as_path(), true) {
			Ok(arti_core) => {
				info!("New Arti instance is successfully created.");
				*TOR_ARTI_INSTANCE.write().expect("RwLock failure") = Some(arti_core);
				TOR_RESTART_REQUEST.store(false, Ordering::Relaxed);
				network_status::update_network_outage_time(Utc::now().timestamp());
				for sender in restart_senders {
					let _ = sender.send(());
				}
				break;
			}
			Err(e) => {
				error!("Unable to create Arti instance, {}", e);
				info!("Waiting for 60 seconds before retry to create Arti instance.");
				std::thread::sleep(Duration::from_secs(60));
			}
		}
	}
}

pub fn register_arti_restart_event() -> Result<std::sync::mpsc::Receiver<()>, Error> {
	let mut arti_core = TOR_ARTI_INSTANCE.write().expect("RwLock failure");
	match &mut *arti_core {
		Some(arti_core) => {
			let (tx, rx) = mpsc::channel::<()>();
			arti_core.restart_senders.push(tx);
			Ok(rx)
		}
		None => Err(Error::TorProcess("Arti is not running".into())),
	}
}

/// Embedded tor server - Atri
pub struct ArtiCore {
	// Using special runtime because it is the only reliable way to kill the tor_client.
	tor_runtime: Runtime,
	tor_client: TorClient<PreferredRuntime>,
	config: TorConfig,
	base_dir: PathBuf,
	restart_senders: Vec<std::sync::mpsc::Sender<()>>,
}

const WEB: &str = "web";
const TNL: &str = "tunnel";

impl ArtiCore {
	/// Init tor service. Note, the service might be reset and recreated, so all dependent objects might be dropped
	fn new(config: &TorConfig, base_dir: &Path, clean_up_arti_data: bool) -> Result<Self, Error> {
		if !config.is_tor_enabled() || config.is_tor_external() {
			return Err(Error::TorConfig(format!(
				"ArtiCore init with not applicabe config {:?}",
				config
			)));
		}

		if is_shoutdown_arti() {
			return Err(Error::Interrupted);
		}

		let mut tor_client_config =
			Self::build_config(&config.webtunnel_bridge, base_dir, clean_up_arti_data)?;
		// We now let the Arti client start and bootstrap a connection to the network.
		// (This takes a while to gather the necessary consensus state, etc.)

		let (mut tor_rt, mut error) = match Self::bootstrap_tor_client(tor_client_config) {
			Ok(tor_rt) => (Some(tor_rt), None),
			Err(e) => (None, Some(e)),
		};

		if is_shoutdown_arti() {
			return Err(Error::Interrupted);
		}

		if tor_rt.is_none() && config.webtunnel_bridge.is_none() {
			// connecting to the bridges

			// Let's try to connect to some of community bridges
			let mut bridge_num = 0;
			let mut rng = rand::thread_rng();
			for _ in 0..3 {
				debug_assert!(COMMUNITY_TNLS.len() % 3 == 0);
				let br_idx = rng.gen_range(0, COMMUNITY_TNLS.len() / 3);

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

				tor_client_config =
					Self::build_config(&Some(bridge.to_string()), base_dir, clean_up_arti_data)?;

				(tor_rt, error) = match Self::bootstrap_tor_client(tor_client_config) {
					Ok(cl) => (Some(cl), None),
					Err(e) => (None, Some(e)),
				};

				if is_shoutdown_arti() {
					return Err(Error::Interrupted);
				}

				bridge_num += 1;
				if tor_rt.is_some() || bridge_num >= 3 {
					break;
				}
			}
		}

		if tor_rt.is_none() {
			let error = error.unwrap();
			info!("Arti bootstrap error report: {}", error.report());
			return Err(error);
		}

		let (tor_client, rt) = tor_rt.unwrap();

		Ok(ArtiCore {
			tor_runtime: rt,
			tor_client,
			config: config.clone(),
			base_dir: base_dir.into(),
			restart_senders: Vec::new(),
		})
	}

	fn bootstrap_tor_client(
		tor_client_config: TorClientConfig,
	) -> Result<(TorClient<PreferredRuntime>, Runtime), Error> {
		// Special tunitime for the atri client. Needed because we will need to shoutdown RT in order to stop the client.
		let arti_rt = mwc_util::tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()
			.expect("failed to start Tokio runtime");

		let tor_client = arti_rt.block_on(async move {
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
			let mut bootstap_process =
				mwc_util::tokio::spawn(async move { tor_client2.bootstrap().await });

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
						if is_shoutdown_arti() {
							info!("Arti bootstrap interrupted, stopping client");
							bootstap_process.abort();
							let _ = bootstap_process.await;
							let stop_f = tor_client.wait_for_stop();
							drop(tor_client);
							stop_f.await;
							return Err(Error::Interrupted);
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
								bootstap_process.abort();
								let _ = bootstap_process.await;
								let stop_f = tor_client.wait_for_stop();
								drop(tor_client);
								stop_f.await;
								return Err(Error::TorProcess(
									"Arti not able to make bootstrap progress during long time"
										.into(),
								));
							}
						}
					}
				}
			}

			if is_shoutdown_arti() {
				info!("Arti bootstrap interrupted, stopping client");
				let stop_f = tor_client.wait_for_stop();
				drop(tor_client);
				stop_f.await;
				return Err(Error::Interrupted);
			}

			let test_circuit = tokio::select! {
				res = Self::test_circuit(&tor_client) => {
					res
			   }
			   _ = Self::wait_until_stopped() => {
					Err(Error::Interrupted)
			   }
			};

			if let Err(e) = test_circuit {
				error!("Unable to build a test Tor circle, {}", e);
				info!("Stopping failed Arti client");
				let stop_f = tor_client.wait_for_stop();
				drop(tor_client);
				stop_f.await;
				info!("Failed arti is stopped");
				return Err(Error::TorProcess(
					"Bootstrap was finished, but test circuit was failed".into(),
				));
			}
			info!("Arti circuit test was passed");

			match Arc::try_unwrap(tor_client) {
				Ok(tor_client) => Ok(tor_client),
				Err(_) => panic!("tor_client is stoll shared!"),
			}
		});

		match tor_client {
			Ok(tor_client) => Ok((tor_client, arti_rt)),
			Err(e) => {
				arti_rt.shutdown_timeout(Duration::from_secs(5));
				Err(e)
			}
		}
	}

	async fn wait_until_stopped() {
		while !is_shoutdown_arti() {
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}

	/// Start onion service.
	/// service_nickname - name of the service, must be unique for the app
	/// expanded_key - Build with:  ExpandedSecretKey::from(sec_key)
	/// Return: (onion service, onion address, stream for incoming request)
	pub fn start_onion_service(
		tor_client: &TorClient<PreferredRuntime>,
		service_nickname: String,
		expanded_key: [u8; 64],
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
		let id_keypair = HsIdKeypair::from(
			ed25519::ExpandedKeypair::from_secret_key_bytes(expanded_key).unwrap(),
		);

		let svc_cfg = OnionServiceConfigBuilder::default()
			.nickname(service_nickname.parse().map_err(|e| {
				Error::TorOnionService(format!("Invalid nickname {}, {}", service_nickname, e))
			})?)
			.build()
			.map_err(|e| {
				Error::TorOnionService(format!("Unable to build onion service config, {}", e))
			})?;

		if is_arti_restarting() {
			return Err(Error::TorNotInitialized);
		}

		if let Some((service, request_stream)) = tor_client
			.launch_onion_service_with_hsid(svc_cfg, id_keypair)
			.map_err(|e| Error::TorOnionService(format!("Unable to start onion service, {}", e)))?
		{
			let onion_address = service
				.onion_address()
				.ok_or(Error::TorOnionService(
					"Not found onion address for started service".into(),
				))?
				.display_unredacted()
				.to_string();

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
	async fn wait_shutdown_poll(timeout_seconds: u64) -> Result<(), Error> {
		let deadline = Instant::now() + Duration::from_secs(timeout_seconds);

		loop {
			if is_arti_restarting() {
				return Err(Error::TorNotInitialized);
			}
			if is_shoutdown_arti() {
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
		onion_service: &Arc<tor_hsservice::RunningOnionService>,
		timeout_seconds: u64,
	) -> Result<(), Error> {
		if is_arti_restarting() {
			return Err(Error::TorNotInitialized);
		}
		if is_shoutdown_arti() {
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
				shutdown_or_timeout = Self::wait_shutdown_poll(timeout_seconds) => {
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

	fn build_config(
		webtunnel_bridge: &Option<String>,
		base_dir: &Path,
		clean_up_arti_data: bool,
	) -> Result<TorClientConfig, Error> {
		let mut builder = TorClientConfig::builder();

		// Usually we are using tunnel if without tunnel tor didn't start
		let mut connection_path = "direct".to_string();
		if webtunnel_bridge.is_some() {
			// tunnel conneciton string
			let bridge_line = webtunnel_bridge.as_ref().unwrap();

			let bridge_hash = Self::hash_str(&bridge_line);
			connection_path = format!("bridge_{:X}", bridge_hash);

			info!("Starting Arti with a bridge {}", bridge_line);
			// webtunnelclient location. Should be located in the same dir where our executable is located
			let exe = std::env::current_exe().map_err(|e| {
				Error::TorConfig(format!("Failed to locate executable path, {}", e))
			})?; // /full/path/to/my_bin
			let path = exe
				.parent()
				.ok_or(Error::TorConfig("Failed to locate executable path".into()))?;
			let client_path = path
				.join("webtunnelclient")
				.into_os_string()
				.into_string()
				.map_err(|e| Error::TorConfig(format!("Failed to build the path, {:?}", e)))?;

			if !std::path::Path::new(&client_path).exists() {
				return Err(Error::TorConfig(format!(
					"Unable to find pluggale webtunnel client {}",
					client_path
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
				.path(CfgPath::new(client_path))
				.run_on_startup(true);
			builder.bridges().transports().push(transport);
		} else {
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

		if clean_up_arti_data {
			let _ = std::fs::remove_dir_all(base_data_dir.clone());
		}

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
		// Disabling vanguard because we want to work on slow networks
		net_params.insert("vanguards-enabled".into(), 0);
		net_params.insert("vanguards-hs-service".into(), 0);

		builder
			.build()
			.map_err(|e| Error::TorConfig(format!("Unable to build arti config, {}", e)))
	}

	pub async fn test_circuit(tor_client: &TorClient<PreferredRuntime>) -> Result<(), Error> {
		info!("Attempting to build circuit...");
		let probe_host = network_status::get_random_http_probe_host();
		match tor_client.connect((probe_host.as_str(), 80)).await {
			Ok(stream) => {
				let tunnel = stream
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
				}

				Ok(())
			}
			Err(e) => Err(Error::TorProcess(format!(
				"Unable connect to the {}, {}",
				probe_host, e
			))),
		}
	}

	fn hash_str(s: &str) -> u64 {
		let mut hasher = std::collections::hash_map::DefaultHasher::new();
		s.hash(&mut hasher); // &str implements Hash
		hasher.finish()
	}
}

/// Validate a v3 onion address (with or without ".onion").
pub fn is_valid_onion_v3(onion: &str) -> bool {
	tor_hscrypto::pk::HsId::from_str(onion).is_ok()
}

#[test]
#[ignore]
fn test_arti_connection() {
	use ed25519_dalek::ExpandedSecretKey;
	use mwc_util::secp::{Secp256k1, SecretKey};
	use std::pin::Pin;

	let res = start_arti(&TorConfig::default(), Path::new("/tmp/arti/"));
	assert!(res.is_ok());

	let (onion_service, onion_address, _incoming_requests): (
		Arc<tor_hsservice::RunningOnionService>,
		String,
		Pin<Box<dyn futures::Stream<Item = tor_hsservice::StreamRequest> + Send>>,
	) = arti::access_arti(|tor_client| {
		let secp = Secp256k1::with_caps(mwc_util::secp::ContextFlag::None);
		let sec_key = SecretKey::new(&secp, &mut rand::thread_rng());
		let sec_key = ed25519_dalek::SecretKey::from_bytes(&sec_key.0).map_err(|e| {
			Error::TorOnionService(format!("Unable to build a DalekSecretKey, {}", e))
		})?;
		let exp_key = ExpandedSecretKey::from(&sec_key);
		let exp_key = exp_key.to_bytes();

		let (onion_service, onion_address, incoming_requests) =
			ArtiCore::start_onion_service(&tor_client, "onion-service-test".to_string(), exp_key)?;
		Ok((
			onion_service,
			onion_address,
			Box::pin(tor_hsservice::handle_rend_requests(incoming_requests))
				as Pin<Box<dyn futures::Stream<Item = _> + Send>>,
		))
	})
	.expect("Onion service unbale to start");

	// Not necessary wait for a long time. We can continue with listening even without any waiting
	arti::ArtiCore::wait_until_started(&onion_service, 20).expect("Onion service unable to start");

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
}
