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
use crate::tor::arti::is_arti_restarting;
use crate::tor::arti_tracked::ArtiRegistrator;
use crate::tor::tcp_data_stream::TcpDataStream;
use crate::{Error, PeerAddr};
use mwc_crates::async_std::stream::StreamExt;
use mwc_crates::futures;
use mwc_crates::log::{error, info, warn};
use mwc_crates::tokio;
use mwc_crates::tor_cell::relaycell::msg::Connected;
use mwc_crates::tor_hsservice;
use mwc_crates::tor_proto::client::stream::IncomingStreamRequest;
use mwc_crates::zeroize::Zeroizing;
use mwc_util::StopState;
use std::any::Any;
use std::pin::Pin;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

// started_service_callback accepting onion address
fn start_onion_service<F>(
	context_id: u32,
	onion_expanded_key: &Zeroizing<[u8; 64]>,
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
	let service_instance_id = arti::allocate_arti_object_id();
	let service_nickname = format!(
		"onion-service-{}-{}-{}",
		service_name, context_id, service_instance_id
	);

	// Types : (Arc<tor_hsservice::RunningOnionService>,String, Pin<Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send>>)
	let (onion_service, onion_address, incoming_requests): (
		Arc<tor_hsservice::RunningOnionService>,
		String,
		Pin<Box<dyn futures::Stream<Item = tor_hsservice::StreamRequest> + Send>>,
	) = arti::access_arti(|tor_client| {
		let (onion_service, onion_address, incoming_requests) =
			arti::ArtiCore::start_onion_service(
				context_id,
				&tor_client,
				service_nickname,
				onion_expanded_key,
			)?;
		Ok((
			onion_service,
			onion_address,
			Box::pin(tor_hsservice::handle_rend_requests(incoming_requests))
				as Pin<Box<dyn futures::Stream<Item = _> + Send>>,
		))
	})?;

	if arti::is_shutdown_arti() || arti::is_arti_cancelled(context_id) {
		return Err(Error::Interrupted);
	}

	info!(
		"Onion listener started at {}; reachability will be monitored in background",
		onion_address
	);

	if let Some(started_service_callback) = started_service_callback {
		// The onion address is derived from our service identity key and is
		// already known once launch succeeds. Do not block node startup on
		// descriptor publication; the monitor thread below reports reachability
		// and restarts Arti if the service stays unhealthy.
		started_service_callback(Some(onion_address.clone()));
	}

	Ok((onion_service, incoming_requests))
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

/// Listening on Onion service.
/// Here is we have a full workflow that monitors the onion service, restarting on network failre. It is
/// Used at both mwc-node and mwc-wallet.
pub fn listen_onion_service<F, G, H, K>(
	context_id: u32,
	stop_state: Arc<StopState>,
	onion_expanded_key: Zeroizing<[u8; 64]>,
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
	let service_status_callback = Arc::new(service_status_callback);
	if let Some(f) = &(*service_status_callback) {
		f(false);
	};

	loop {
		while is_arti_restarting() && !stop_state.is_stopped() {
			thread::sleep(Duration::from_millis(500));
		}
		if stop_state.is_stopped() {
			break;
		}

		info!("Starting Arti service {}...", service_name);
		match start_onion_service(
			context_id,
			&onion_expanded_key,
			service_name,
			&started_service_callback,
		) {
			Ok((onion_service, mut incoming_requests)) => {
				let listener_id = arti::allocate_arti_object_id();
				let onion_service_object = format!(
					"{}_onion_service_{}_{}",
					service_name, context_id, listener_id
				);
				let incoming_requests_object = format!(
					"{}_incoming_requests_{}_{}",
					service_name, context_id, listener_id
				);

				let incoming_requests_guard =
					match ArtiRegistrator::new(incoming_requests_object.clone()) {
						Ok(registrator) => registrator,
						Err(err) => {
							error!(
								"Unable to register {} active object: {}",
								incoming_requests_object, err
							);
							if let Some(f) = &(*service_status_callback) {
								f(false);
							};
							if let Some(failed_service_callback) = &failed_service_callback {
								let _ = failed_service_callback(&err);
							}
							return Err(err);
						}
					};

				let stop_state2 = stop_state.clone();
				let context_id2 = context_id;
				let service_name2 = String::from(service_name);
				let service_status_callback2 = service_status_callback.clone();
				let (monitor_failure_tx, monitor_failure_rx) = mpsc::channel();
				let monitor_thread_name =
					format!("{}_onion_service_checker_{}", service_name2, context_id2);
				let monitor_thread_name_for_panic = monitor_thread_name.clone();

				let monitoring =
					match thread::Builder::new()
						.name(monitor_thread_name)
						.spawn(move || {
							let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
								|| -> Result<(), Error> {
									// Guard is needed for
									let _arti_guard = ArtiRegistrator::new(onion_service_object)?;
									let mut last_running_time = Instant::now();
									if let Some(f) = &(*service_status_callback2) {
										f(false);
									};
									loop {
										if stop_state2.is_stopped() {
											break;
										}
										let need_arti_restart = {
											let onion_service_status =
												onion_service.status().state();
											let ready_for_traffic =
												match arti::access_arti(|arti| {
													Ok(arti.bootstrap_status().ready_for_traffic())
												}) {
													Ok(ready_for_traffic) => ready_for_traffic,
													Err(Error::TorRestarting) => {
														info!(
															"Unable to check {} onion service traffic readiness: Arti is restarting",
															service_name2
														);
														false
													}
													Err(Error::TorNotInitialized) => {
														info!(
															"Unable to check {} onion service traffic readiness: Tor is not initialized",
															service_name2
														);
														false
													}
													Err(Error::Interrupted) => {
														info!(
															"Unable to check {} onion service traffic readiness: interrupted",
															service_name2
														);
														false
													}
													Err(err) => {
														error!(
															"Unable to check {} onion service traffic readiness: {}",
															service_name2, err
														);
														return Err(err);
													}
												};

											info!(
												"Current {} onion service status: {:?}, ready for traffic: {}",
												service_name2,
												onion_service_status,
												ready_for_traffic,
											);

											if ready_for_traffic {
												// Removed state.is_fully_reachable() because in reality it doesn't work as expected.
												// Tor can work fine and be in the booting state for a very long time. There is
												//  not much what we can do. ready_for_traffic arti.bootstrap_status().ready_for_traffic()
												// is the best indicator so far.
												last_running_time = Instant::now();
												false
											} else {
												if let Some(f) = &(*service_status_callback2) {
													f(false);
												};
												let elapsed = Instant::now()
													.duration_since(last_running_time);
												// Giving 3 minutes to arti to restore
												elapsed > Duration::from_secs(180)
											}
										};

										if need_arti_restart || arti::is_arti_restarting() {
											arti::request_arti_restart(
												"Onion service is dead, restarting",
											);
											break;
										}

										for _ in 0..30 {
											if stop_state2.is_stopped()
												|| arti::is_arti_restarting()
											{
												break;
											}
											thread::sleep(Duration::from_secs(1));
										}
									}
									if let Some(f) = &(*service_status_callback2) {
										f(false);
									};
									Ok(())
								},
							));
							match result {
								Ok(Ok(())) => {}
								Ok(Err(err)) => {
									error!(
										"{} onion_service_checker thread failed: {}",
										service_name2, err
									);
									let err_msg =
										format!("{}: {}", monitor_thread_name_for_panic, err);
									let _ = monitor_failure_tx.send(err_msg);
									arti::request_arti_restart(
										"Onion service checker failed, restarting",
									);
								}
								Err(payload) => {
									let panic_msg = panic_payload_to_string(payload);
									let err_msg =
										format!("{}: {}", monitor_thread_name_for_panic, panic_msg);
									error!(
										"{} onion_service_checker thread panicked: {}",
										service_name2, panic_msg
									);
									let _ = monitor_failure_tx.send(err_msg);
									arti::request_arti_restart(
										"Onion service checker panicked, restarting",
									);
								}
							}
						}) {
						Ok(handle) => handle,
						Err(e) => {
							let err = Error::Connection(e);
							error!(
								"Unable to start {} onion_service_checker thread, {}",
								service_name, err
							);
							if let Some(f) = &(*service_status_callback) {
								f(false);
							};
							drop(incoming_requests_guard);
							if let Some(failed_service_callback) = &failed_service_callback {
								if failed_service_callback(&err) {
									error!(
									"listen_onion_service exited because of callback response and error: {}",
									err
								);
									return Err(err);
								}
							}
							arti::request_arti_restart(&format!(
								"Unable to start {} onion_service_checker thread",
								service_name
							));
							continue;
						}
					};

				let stop_state = stop_state.clone();
				let mut listener_error = None;
				loop {
					match monitor_failure_rx.try_recv() {
						Ok(err_msg) => {
							let err = Error::PeerThreadPanic(err_msg);
							error!("Onion service monitor failed: {}", err);
							if let Some(f) = &(*service_status_callback) {
								f(false);
							};
							if let Some(failed_service_callback) = &failed_service_callback {
								if failed_service_callback(&err) {
									listener_error = Some(err);
								}
							}
							break;
						}
						Err(mpsc::TryRecvError::Empty) => {}
						Err(mpsc::TryRecvError::Disconnected) => {}
					}

					let request_res = match arti::arti_async_block(async {
						tokio::time::timeout(
							tokio::time::Duration::from_secs(1),
							incoming_requests.next(),
						)
						.await
					}) {
						Ok(res) => res,
						Err(Error::TorRestarting | Error::TorNotInitialized) => {
							break;
						}
						Err(err) => {
							error!(
								"listen_onion_service polling incoming request error: {}",
								err
							);
							if let Some(f) = &(*service_status_callback) {
								f(false);
							};
							if let Some(failed_service_callback) = &failed_service_callback {
								if failed_service_callback(&err) {
									listener_error = Some(err);
									break;
								}
							}
							// Prefer a conservative approach for unexpected async runtime
							// errors. The service state may be unknown, and restarting Arti is
							// safer than leaving the listener and monitor out of sync.
							if !stop_state.is_stopped() {
								arti::request_arti_restart(&format!(
									"Onion service listener error, restarting Arti: {}",
									err
								));
							}
							break;
						}
					};

					match request_res {
						Ok(Some(stream_request)) => {
							if stop_state.is_stopped() || arti::is_arti_restarting() {
								break;
							}

							// Incoming connection.
							let request: &IncomingStreamRequest = stream_request.request();
							match request {
								IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
									let accept_result = match arti::arti_async_block(async move {
										tokio::time::timeout(
											tokio::time::Duration::from_secs(10),
											stream_request.accept(Connected::new_empty()),
										)
										.await
									}) {
										Ok(res) => res,
										Err(Error::TorRestarting | Error::TorNotInitialized) => {
											break;
										}
										Err(err) => {
											error!(
												"listen_onion_service accepting stream async error: {}",
												err
											);
											if let Some(f) = &(*service_status_callback) {
												f(false);
											};
											if let Some(failed_service_callback) =
												&failed_service_callback
											{
												if failed_service_callback(&err) {
													listener_error = Some(err);
													break;
												}
											}
											// Prefer a conservative approach for unexpected async runtime
											// errors. The service state may be unknown, and restarting Arti is
											// safer than leaving the listener and monitor out of sync.
											if !stop_state.is_stopped() {
												arti::request_arti_restart(&format!(
													"Onion service accept error, restarting Arti: {}",
													err
												));
											}
											break;
										}
									};

									match accept_result {
										Ok(accept_result) => match accept_result {
											Ok(onion_service_stream) => {
												let stream_id = arti::allocate_arti_object_id();
												let stream_name = format!(
													"mwc_nodeLdata_stream_{}_{}",
													listener_id, stream_id
												);
												let stream = match TcpDataStream::from_data(
													onion_service_stream,
													stream_name.clone(),
												) {
													Ok(stream) => stream,
													Err(err) => {
														error!(
															"Unable to register Arti stream {}: {}",
															stream_name, err
														);
														if let Some(failed_service_callback) =
															&failed_service_callback
														{
															if failed_service_callback(&err) {
																listener_error = Some(err);
																break;
															}
														}
														continue;
													}
												};

												handle_new_peer_callback(stream, None);
											}
											Err(err) => {
												error!("listen_onion_service accepting stream error: {}", err);
											}
										},
										Err(_) => {
											// timeout, nothing can be done. Stream will be dropped and closed automatically.
										}
									}
								}
								_ => {
									if let Err(err) = stream_request.shutdown_circuit() {
										error!(
											"listen_onion_service shutting down unsupported stream request error: {}",
											err
										);
									}
								}
							}
						}
						Ok(None) => {
							// The incoming stream ends as a side effect of Arti stopping or
							// restarting. The listener cannot recover additional detail from
							// this path, so just leave the accept loop.
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

				let thread_id = monitoring.thread().id();
				if let Err(payload) = monitoring.join() {
					let panic_msg = panic_payload_to_string(payload);
					let err =
						Error::PeerThreadPanic(format!("thread {:?}: {}", thread_id, panic_msg));
					error!(
						"failed to stop {} onion_service_checker thread {:?}: {}",
						service_name, thread_id, panic_msg
					);
					if listener_error.is_none() {
						if let Some(f) = &(*service_status_callback) {
							f(false);
						};
						if let Some(failed_service_callback) = &failed_service_callback {
							if failed_service_callback(&err) {
								listener_error = Some(err);
							}
						}
						if listener_error.is_none() && !stop_state.is_stopped() {
							arti::request_arti_restart(
								"Onion service checker panicked, restarting",
							);
						}
					}
				}
				let expected_tor_instance_id = arti::get_next_arti_instance_id();
				drop(incoming_requests_guard);

				if let Some(err) = listener_error {
					return Err(err);
				}

				warn!(
					"Onion listening service for {}-{} is stopped",
					service_name, context_id
				);

				// Waiting while arti is started
				while !stop_state.is_stopped() {
					if arti::get_current_arti_instance_id() >= expected_tor_instance_id {
						break;
					}
					thread::sleep(Duration::from_millis(300));
				}

				if stop_state.is_stopped() {
					break;
				}

				warn!(
					"Restarting {}-{} onion listening service...",
					service_name, context_id
				);
			}
			Err(Error::TorRestarting) => {
				if stop_state.is_stopped() {
					break;
				}
				thread::sleep(Duration::from_millis(500));
			}
			Err(e @ Error::TorNotInitialized) => {
				if stop_state.is_stopped() {
					break;
				}

				if let Some(f) = &(*service_status_callback) {
					f(false);
				}
				if let Some(failed_service_callback) = &failed_service_callback {
					if failed_service_callback(&e) {
						error!("listen_onion_service exited because of callback response and error: {}", e);
						return Err(e);
					}
				}
				thread::sleep(Duration::from_millis(500));
			}
			Err(e) => {
				if stop_state.is_stopped() {
					break;
				}

				if let Some(failed_service_callback) = &failed_service_callback {
					if failed_service_callback(&e) {
						error!(
							"listen_onion_service exited because of callback response and error: {}",
							e
						);
						return Err(e);
					}
				}

				error!("Unable to restart onion service. Will restart Arti. {}", e);
				// restarting arti first
				arti::request_arti_restart(&format!("Unable to start onion service, {}", e));
				let expected_tor_instance_id = arti::get_next_arti_instance_id();
				while !stop_state.is_stopped() {
					if arti::get_current_arti_instance_id() >= expected_tor_instance_id {
						break;
					}
					thread::sleep(Duration::from_millis(300));
				}
			}
		}
	}
	Ok(())
}
