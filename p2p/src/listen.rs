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
use mwc_crates::log::{info, warn};
use mwc_crates::tokio;
use mwc_crates::tokio::net::TcpListener;
use mwc_crates::zeroize::Zeroizing;
use mwc_util::{run_global_async_block, StopState};
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use std::{io, thread};

pub fn listen<F, G, H, K>(
	context_id: u32,
	stop_state: Arc<StopState>,
	tor_config: Option<TorConfig>,
	listen_addr: Option<SocketAddr>,
	onion_expanded_key: Option<Zeroizing<[u8; 64]>>,
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

	// Empty handshake means that we still can't connect to peers. For Tor the
	// onion address is derived from the local identity key once the onion
	// service is launched; full reachability is reported separately.
	if tor_config.is_tor_enabled() {
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
	onion_expanded_key: Option<Zeroizing<[u8; 64]>>,
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
	let mut listener_healthy = false;
	let listener = match run_global_async_block(async { TcpListener::bind(addr).await })
		.map_err(|e| Error::Internal(format!("call TcpListener::bind errore, {}", e)))?
	{
		Ok(listener) => {
			set_listener_service_status(
				service_status_callback.as_ref(),
				&mut listener_healthy,
				true,
			);
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
				// result is ignored because we are exiting in any case.
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
			match tokio::time::timeout(tokio::time::Duration::from_secs(1), listener.accept()).await
			{
				Ok(r) => r,
				Err(_) => Err(io::Error::new(
					io::ErrorKind::WouldBlock,
					"expected waiting timeout",
				)),
			}
		})
		.map_err(|e| Error::Internal(e.to_string()))?
		{
			Ok((stream, peer_addr)) => {
				set_listener_service_status(
					service_status_callback.as_ref(),
					&mut listener_healthy,
					true,
				);

				// We want out TCP stream to be in blocking mode.
				// The TCP listener is in nonblocking mode so we *must* explicitly
				// move the accepted TCP stream into blocking mode (or all kinds of
				// bad things can and will happen).
				// A nonblocking TCP listener will accept nonblocking TCP streams which
				// we do not want.

				let peer_addr = PeerAddr::Ip(normalize_transport_socket_addr(peer_addr));

				handle_new_peer_callback(TcpDataStream::from_tcp(stream), Some(peer_addr));
			}
			Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
				set_listener_service_status(
					service_status_callback.as_ref(),
					&mut listener_healthy,
					true,
				);
				// nothing to do, will retry in next iteration
			}
			Err(e) => {
				handle_listener_accept_error(
					host,
					port,
					e,
					failed_service_callback.as_ref(),
					service_status_callback.as_ref(),
					&mut listener_healthy,
				)?;
			}
		}
		thread::sleep(Duration::from_millis(5));
	}
	set_listener_service_status(
		service_status_callback.as_ref(),
		&mut listener_healthy,
		false,
	);

	Ok(())
}

fn normalize_transport_socket_addr(socket_addr: SocketAddr) -> SocketAddr {
	match socket_addr {
		SocketAddr::V6(ipv6_addr) => ipv6_addr
			.ip()
			.to_ipv4_mapped()
			.map(|ipv4| SocketAddr::V4(SocketAddrV4::new(ipv4, ipv6_addr.port())))
			.unwrap_or(SocketAddr::V6(ipv6_addr)),
		SocketAddr::V4(_) => socket_addr,
	}
}

fn set_listener_service_status<K>(
	service_status_callback: Option<&K>,
	listener_healthy: &mut bool,
	healthy: bool,
) where
	K: Fn(bool),
{
	if *listener_healthy == healthy {
		return;
	}
	*listener_healthy = healthy;
	if let Some(f) = service_status_callback {
		f(healthy);
	}
}

fn handle_listener_accept_error<G, K>(
	host: IpAddr,
	port: u16,
	err: io::Error,
	failed_service_callback: Option<&G>,
	service_status_callback: Option<&K>,
	listener_healthy: &mut bool,
) -> Result<(), Error>
where
	G: Fn(&Error) -> bool,
	K: Fn(bool),
{
	let err = Error::TorProcess(format!(
		"Unable to accept incoming connection on {}:{}, {}",
		host, port, err
	));
	warn!("{}", err);

	set_listener_service_status(service_status_callback, listener_healthy, false);

	let should_exit = failed_service_callback.map_or(true, |f| f(&err));
	if should_exit {
		Err(err)
	} else {
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::{Arc, Mutex};

	#[test]
	fn accept_error_without_failure_callback_marks_service_down_and_returns() {
		let statuses = Arc::new(Mutex::new(Vec::new()));
		let statuses_for_callback = statuses.clone();
		let status_callback = Some(move |healthy| {
			statuses_for_callback.lock().unwrap().push(healthy);
		});
		let mut listener_healthy = true;

		let err = handle_listener_accept_error(
			"127.0.0.1".parse().unwrap(),
			3414,
			io::Error::new(io::ErrorKind::Other, "fd exhausted"),
			None::<&fn(&Error) -> bool>,
			status_callback.as_ref(),
			&mut listener_healthy,
		)
		.unwrap_err();

		match err {
			Error::TorProcess(message) => assert!(message.contains("fd exhausted")),
			err => panic!("expected TorProcess, got {:?}", err),
		}
		assert!(!listener_healthy);
		assert_eq!(*statuses.lock().unwrap(), vec![false]);
	}

	#[test]
	fn accept_error_can_continue_and_later_mark_service_healthy() {
		let statuses = Arc::new(Mutex::new(Vec::new()));
		let statuses_for_callback = statuses.clone();
		let status_callback = Some(move |healthy| {
			statuses_for_callback.lock().unwrap().push(healthy);
		});

		let failures = Arc::new(Mutex::new(Vec::new()));
		let failures_for_callback = failures.clone();
		let failed_callback = Some(move |err: &Error| {
			failures_for_callback.lock().unwrap().push(err.to_string());
			false
		});

		let mut listener_healthy = true;
		handle_listener_accept_error(
			"127.0.0.1".parse().unwrap(),
			3414,
			io::Error::new(io::ErrorKind::Other, "temporary listener error"),
			failed_callback.as_ref(),
			status_callback.as_ref(),
			&mut listener_healthy,
		)
		.unwrap();

		assert!(!listener_healthy);
		assert_eq!(failures.lock().unwrap().len(), 1);

		set_listener_service_status(status_callback.as_ref(), &mut listener_healthy, true);

		assert!(listener_healthy);
		assert_eq!(*statuses.lock().unwrap(), vec![false, true]);
	}

	#[test]
	fn transport_socket_addr_normalizes_only_ipv4_mapped_ipv6() {
		let mapped: SocketAddr = "[::ffff:203.0.113.8]:3414".parse().unwrap();
		let compatible: SocketAddr = "[::203.0.113.8]:3414".parse().unwrap();
		let localhost: SocketAddr = "[::1]:3414".parse().unwrap();

		assert_eq!(
			normalize_transport_socket_addr(mapped),
			"203.0.113.8:3414".parse::<SocketAddr>().unwrap()
		);
		assert_eq!(normalize_transport_socket_addr(compatible), compatible);
		assert_eq!(normalize_transport_socket_addr(localhost), localhost);
	}
}
