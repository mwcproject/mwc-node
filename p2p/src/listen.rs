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

use crate::tor::tcp_data_stream::TcpDataStream;
use crate::{Error, PeerAddr, TorConfig};
use mwc_util::tokio::net::TcpListener;
use mwc_util::{run_global_async_block, StopState};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use std::{io, thread};

pub fn listen<F, G, H, K>(
	context_id: u32,
	stop_state: Arc<StopState>,
	tor_config: Option<TorConfig>,
	listen_addr: Option<SocketAddr>, // Port in needed in not internal tor will be used
	onion_expanded_key: Option<[u8; 64]>,
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
	let tor_config = tor_config.unwrap_or(TorConfig::no_tor_config());

	// Empty handshake means that we still can't listen. We need to know own onion address. In case of
	// listen_onion_service that will happens after the service will be started. That takes time...
	if tor_config.is_tor_enabled() {
		if !tor_config.is_tor_external() {
			// running own tor service
			listen_onion_service(
				context_id,
				stop_state,
				onion_expanded_key,
				started_service_callback,
				failed_service_callback,
				service_status_callback,
				handle_new_peer_callback,
			)
		} else {
			// Listening on external Tor, listening on sockets
			let onion_address = tor_config.onion_address.clone().ok_or(Error::ConfigError(
				"For tor external config, internal onion address is not specified.".into(),
			))?;
			let port = listen_addr
				.ok_or(Error::Internal("listening port in not set".into()))?
				.port();

			listen_socket(
				stop_state,
				IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
				port,
				Some(onion_address),
				started_service_callback,
				failed_service_callback,
				service_status_callback,
				handle_new_peer_callback,
			)
		}
	} else {
		let addr = listen_addr.ok_or(Error::Internal("listening port in not set".into()))?;
		listen_socket(
			stop_state,
			addr.ip(),
			addr.port(),
			None,
			started_service_callback,
			failed_service_callback,
			service_status_callback,
			handle_new_peer_callback,
		)
	}
}

fn listen_onion_service<F, G, H, K>(
	context_id: u32,
	stop_state: Arc<StopState>,
	onion_expanded_key: Option<[u8; 64]>,
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
	info!("Starting TOR (Arti) service...");

	let onion_expanded_key = onion_expanded_key.ok_or(Error::TorConnect(
		"onion_expanded_key is not defined".into(),
	))?;

	crate::tor::listen_onion_service(
		context_id,
		stop_state.clone(),
		onion_expanded_key,
		"mwc-node",
		started_service_callback,
		failed_service_callback,
		service_status_callback,
		handle_new_peer_callback,
	)
}

/// Starts a new TCP server and listen to incoming connections. This is a
/// blocking call until the TCP server stops.
fn listen_socket<F, G, H, K>(
	stop_state: Arc<StopState>,
	host: IpAddr,
	port: u16,
	onion_service_address: Option<String>,
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
	// start TCP listener and handle incoming connections
	let addr = SocketAddr::new(host, port);
	let listener = match run_global_async_block(async { TcpListener::bind(addr).await }) {
		Ok(listener) => {
			if let Some(f) = service_status_callback.as_ref() {
				f(true)
			}
			if let Some(started_service_callback) = started_service_callback {
				started_service_callback(onion_service_address);
			}
			listener
		}
		Err(e) => {
			if let Some(f) = service_status_callback.as_ref() {
				f(false)
			}
			let err = Error::TorProcess(format!(
				"Unable to start listening on {}:{}, {}",
				host, port, e
			));
			if let Some(failed_service_callback) = failed_service_callback {
				let _ = failed_service_callback(&err);
			}
			return Err(err);
		}
	};

	loop {
		// Pause peer ingress connection request. Only for tests.
		if stop_state.is_paused() {
			thread::sleep(Duration::from_secs(1));
			continue;
		}

		if stop_state.is_stopped() {
			break;
		}

		match run_global_async_block(async {
			match mwc_util::tokio::time::timeout(
				mwc_util::tokio::time::Duration::from_secs(1),
				listener.accept(),
			)
			.await
			{
				Ok(r) => r,
				Err(_) => Err(io::Error::new(
					io::ErrorKind::WouldBlock,
					"expected waiting timeout",
				)),
			}
		}) {
			Ok((stream, peer_addr)) => {
				// We want out TCP stream to be in blocking mode.
				// The TCP listener is in nonblocking mode so we *must* explicitly
				// move the accepted TCP stream into blocking mode (or all kinds of
				// bad things can and will happen).
				// A nonblocking TCP listener will accept nonblocking TCP streams which
				// we do not want.

				let mut peer_addr = PeerAddr::Ip(peer_addr);

				// attempt to see if it an ipv4-mapped ipv6
				// if yes convert to ipv4
				match peer_addr {
					PeerAddr::Ip(socket_addr) => {
						if socket_addr.is_ipv6() {
							if let IpAddr::V6(ipv6) = socket_addr.ip() {
								if let Some(ipv4) = ipv6.to_ipv4() {
									peer_addr = PeerAddr::Ip(SocketAddr::V4(SocketAddrV4::new(
										ipv4,
										socket_addr.port(),
									)))
								}
							}
						}
					}
					_ => {}
				}

				handle_new_peer_callback(TcpDataStream::from_tcp(stream), Some(peer_addr));
			}
			Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
				// nothing to do, will retry in next iteration
			}
			Err(e) => {
				debug!("Couldn't establish new client connection: {:?}", e);
			}
		}
		thread::sleep(Duration::from_millis(5));
	}
	if let Some(f) = service_status_callback.as_ref() {
		f(false)
	}

	Ok(())
}
