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

use crate::tor::arti;
use crate::tor::arti::{arti_async_block, ArtiCore};
use crate::tor::tcp_data_stream::TcpDataStream;
use crate::{Error, PeerAddr};
use async_std::stream::StreamExt;
use mwc_util::StopState;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::status::State;
use tor_proto::client::stream::IncomingStreamRequest;

static SERVICE_COUNTER: AtomicU32 = AtomicU32::new(0);

// started_service_callback accepting onion address
fn start_arti<F>(
	context_id: u32,
	onion_expanded_key: &[u8; 64],
	service_name: &str,
	started_service_callback: &Option<F>,
) -> Result<
	(
		Arc<tor_hsservice::RunningOnionService>,
		Pin<Box<dyn futures::Stream<Item = tor_hsservice::StreamRequest> + Send>>,
	),
	Error,
>
where
	F: Fn(Option<String>),
{
	// Types : (Arc<tor_hsservice::RunningOnionService>,String, Pin<Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send>>)
	let (onion_service, onion_address, incoming_requests): (
		Arc<tor_hsservice::RunningOnionService>,
		String,
		Pin<Box<dyn futures::Stream<Item = tor_hsservice::StreamRequest> + Send>>,
	) = arti::access_arti(|tor_client| {
		let (onion_service, onion_address, incoming_requests) = ArtiCore::start_onion_service(
			&tor_client,
			format!(
				"onion-service-{}-{}-{}",
				service_name,
				context_id,
				SERVICE_COUNTER.fetch_add(1, Ordering::Relaxed)
			),
			onion_expanded_key.clone(),
		)?;
		Ok((
			onion_service,
			onion_address,
			Box::pin(tor_hsservice::handle_rend_requests(incoming_requests))
				as Pin<Box<dyn futures::Stream<Item = _> + Send>>,
		))
	})?;

	// Not necessary wait for a long time. We can continue with listening even without any waiting
	info!("Waiting for onion service to be reachable");
	arti::ArtiCore::wait_until_started(&onion_service, 120)?;

	info!("Onion listener started at {}", onion_address);

	if let Some(started_service_callback) = started_service_callback {
		started_service_callback(Some(onion_address.clone()));
	}

	Ok((onion_service, incoming_requests))
}

/// Listening on Onion service.
/// Here is we have a full workflow that monitors the onion service, restarting on network failre. It is
/// Used at both mwc-node and mwc-wallet.
pub fn listen_onion_service<F, G, H, K>(
	context_id: u32,
	stop_state: Arc<StopState>,
	onion_expanded_key: [u8; 64],
	service_name: &str,
	started_service_callback: Option<F>,
	failed_service_callback: Option<G>,
	service_status_callback: Option<K>,
	handle_new_peer_callback: H,
) -> Result<(), Error>
where
	F: Fn(Option<String>),
	G: Fn(&Error) -> bool, // return true if want to exit on falure
	H: Fn(TcpDataStream, Option<PeerAddr>),
	K: Fn(bool) + Send + 'static + std::marker::Sync, // return true if want to exit on falure
{
	//
	//let handle_new_peer_callback = Arc::new(handle_new_peer_callback);
	let arti_streams = AtomicI64::new(0);

	let service_status_callback = Arc::new(service_status_callback);
	if let Some(f) = &(*service_status_callback) {
		f(false);
	};

	loop {
		if stop_state.is_stopped() {
			break;
		}

		info!("Starting Arti service {}...", service_name);
		match start_arti(
			context_id,
			&onion_expanded_key,
			service_name,
			&started_service_callback,
		) {
			Ok((onion_service, mut incoming_requests)) => {
				let onion_service_object = format!("{}_onion_service_{}", service_name, context_id);
				let incoming_requests_object =
					format!("{}_incoming_requests_{}", service_name, context_id);

				arti::register_arti_active_object(onion_service_object.clone());
				arti::register_arti_active_object(incoming_requests_object.clone());

				let restarted_rc = arti::register_arti_restart_event()?;

				let stop_state2 = stop_state.clone();
				let context_id2 = context_id;
				let service_name2 = String::from(service_name);
				let service_status_callback2 = service_status_callback.clone();

				let monitoring = thread::Builder::new()
					.name(format!(
						"{}_onion_service_checker_{}",
						service_name2, context_id2
					))
					.spawn(move || {
						let mut last_running_time = Instant::now();
						if let Some(f) = &(*service_status_callback2) {
							f(false);
						};
						loop {
							if stop_state2.is_stopped() {
								arti::unregister_arti_active_object(&onion_service_object);
								drop(onion_service);
								break;
							}
							let need_arti_restart = {
								let onion_service_status = onion_service.status().state();
								let ready_for_traffic = arti::access_arti(|arti| {
									let ready_for_traffic =
										arti.bootstrap_status().ready_for_traffic();
									Ok(ready_for_traffic)
								})
								.unwrap_or(false);

								info!(
									"Current {} onion service status: {:?},  ready for traffic: {}",
									service_name2, onion_service_status, ready_for_traffic
								);

								let need_arti_restart = if ready_for_traffic {
									match onion_service_status {
										State::Bootstrapping
										| State::DegradedReachable
										| State::DegradedUnreachable
										| State::Running => {
											last_running_time = Instant::now();
											if let Some(f) = &(*service_status_callback2) {
												f(true);
											};
											false
										}
										State::Broken => true,
										_ => {
											if let Some(f) = &(*service_status_callback2) {
												f(false);
											};
											let elapsed =
												Instant::now().duration_since(last_running_time);
											// Giving 3 minutes to arti to restore
											elapsed > Duration::from_secs(180)
										}
									}
								} else {
									let elapsed = Instant::now().duration_since(last_running_time);
									// Giving 3 minutes to arti to restore
									elapsed > Duration::from_secs(180)
								};
								need_arti_restart
							};

							if need_arti_restart || arti::is_arti_restarting() {
								drop(onion_service);
								arti::unregister_arti_active_object(&onion_service_object);
								if !arti::is_arti_restarting() {
									arti::request_arti_restart("Onion service is dead, restarting");
								}
								break;
							}

							for _ in 0..30 {
								if stop_state2.is_stopped() || arti::is_arti_restarting() {
									break;
								}
								thread::sleep(Duration::from_secs(1));
							}
						}
						if let Some(f) = &(*service_status_callback2) {
							f(false);
						};
					})
					.expect(&format!(
						"Unable to start {} onion_service_checker thread",
						service_name
					));

				let stop_state = stop_state.clone();
				loop {
					let request_res = arti_async_block(async {
						mwc_util::tokio::time::timeout(
							mwc_util::tokio::time::Duration::from_secs(1),
							incoming_requests.next(),
						)
						.await
					})?;

					match request_res {
						Ok(Some(stream_request)) => {
							if stop_state.is_stopped() || arti::is_arti_restarting() {
								break;
							}

							// Incoming connection.
							let request: &IncomingStreamRequest = stream_request.request();
							match request {
								IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
									let accept_result = arti_async_block(async move {
										stream_request.accept(Connected::new_empty()).await
									})?;

									match accept_result {
										Ok(onion_service_stream) => {
											let stream_id =
												arti_streams.fetch_add(1, Ordering::Relaxed);

											handle_new_peer_callback(
												TcpDataStream::from_data(
													onion_service_stream,
													format!("mwc_nodeLdata_stream_{}", stream_id),
												),
												None,
											);
										}
										Err(err) => error!("Client error: {}", err),
									}
								}
								_ => {
									let _ = stream_request.shutdown_circuit();
								}
							}
						}
						Ok(None) => {
							break; // channel is closed
						}
						Err(_) => {
							// timeout
							if stop_state.is_stopped() || arti::is_arti_restarting() {
								break;
							}
						}
					}
				}
				if monitoring.join().is_err() {
					break;
				}
				arti::unregister_arti_active_object(&incoming_requests_object);

				warn!(
					"Onion listening service for {}-{} is stopped",
					service_name, context_id
				);

				// Waiting while arti is started
				while !stop_state.is_stopped() {
					if restarted_rc.recv_timeout(Duration::from_secs(1)).is_ok() {
						break;
					}
				}

				if stop_state.is_stopped() {
					break;
				}

				warn!(
					"Restarting {}-{} onion listening service...",
					service_name, context_id
				);
			}
			Err(Error::TorNotInitialized) => {
				thread::sleep(Duration::from_secs(5));
			}
			Err(e) => {
				if stop_state.is_stopped() {
					break;
				}

				if let Some(failed_service_callback) = &failed_service_callback {
					if failed_service_callback(&e) {
						return Err(e);
					}
				}

				error!("Unable to restart onion service. Will retry soon. {}", e);
				// restarting arti first
				arti::request_arti_restart(&format!("Unable to restart onion service, {}", e));
			}
		}
	}

	Ok(())
}
