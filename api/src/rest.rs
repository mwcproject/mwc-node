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

//! RESTful API server to easily expose services as RESTful JSON/HTTP endpoints.
//! Fairly constrained on what the service API must look like by design.
//!
//! To use it, just have your service(s) implement the ApiEndpoint trait and
//! register them on a ApiServer.

use crate::router::{Handler, HandlerObj, ResponseFuture, Router, RouterError};
use crate::web::response;
use mwc_crates::bytes::Bytes;
use mwc_crates::futures::channel::oneshot;
use mwc_crates::http::request::Parts;
use mwc_crates::http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use mwc_crates::hyper::body::Incoming;
use mwc_crates::hyper::header::CONTENT_LENGTH;
use mwc_crates::hyper::service::{service_fn, Service};
use mwc_crates::hyper::{body::Body, Request, Response, StatusCode};
use mwc_crates::hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use mwc_crates::hyper_util::server::conn::auto::Builder as AutoBuilder;
use mwc_crates::hyper_util::server::graceful::GracefulShutdown;
use mwc_crates::log::{debug, error, info, warn};
use mwc_crates::parking_lot::Mutex;
use mwc_crates::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use mwc_crates::rustls::ServerConfig;
use mwc_crates::rustls_pemfile;
use mwc_crates::serde::{Deserialize, Serialize};
use mwc_crates::tokio;
use mwc_crates::tokio::net::TcpListener;
use mwc_crates::tokio_rustls::TlsAcceptor;
use mwc_crates::zeroize::{Zeroize, Zeroizing};
use mwc_crates::{rustls, secp};
use mwc_util::run_global_async_block;
use std::convert::TryFrom;
use std::error::Error as StdError;
use std::fs::File;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use std::{io, io::Read, thread};

// Request size 4Mb should cover all cases
const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_REST_API_CONNECTIONS: usize = 256;
const REST_API_IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Errors that can be returned by an ApiEndpoint implementation.
#[derive(Debug, Serialize, Deserialize, thiserror::Error)]
#[serde(crate = "mwc_crates::serde")]
pub enum Error {
	#[error("Secp error: {0}")]
	SecpError(secp::Error),
	#[error("API IO error: {0}")]
	#[serde(skip)]
	IO(#[from] io::Error),
	#[error("API Chain error: {0}")]
	#[serde(skip)]
	Chain(#[from] mwc_chain::Error),
	#[error("API Internal error: {0}")]
	Internal(String),
	#[error("API Bad arguments: {0}")]
	Argument(String),
	#[error("API Not found: {0}")]
	NotFound(String),
	#[error("API Request error: {0}")]
	RequestError(String),
	#[error("API ResponseError error: {0}")]
	ResponseError(String),
	#[error("API Router error: {source:?}")]
	Router {
		#[from]
		source: RouterError,
	},
	#[error("API P2P error: {0}")]
	P2pError(String),
}

impl Error {
	pub fn chain_read_error(error: mwc_chain::Error, not_found_msg: String) -> Error {
		if error.is_not_found() || matches!(&error, mwc_chain::Error::InvalidHeaderHeight(_)) {
			Error::NotFound(not_found_msg)
		} else {
			error.into()
		}
	}
}

impl From<secp::Error> for Error {
	fn from(err: secp::Error) -> Self {
		Error::SecpError(err)
	}
}

/// TLS config
#[derive(Clone, Debug)]
pub struct TLSConfig {
	pub certificate: String,
	pub private_key: String,
}

impl TLSConfig {
	pub fn new(certificate: String, private_key: String) -> TLSConfig {
		TLSConfig {
			certificate,
			private_key,
		}
	}

	fn load_certs(&self) -> Result<Vec<CertificateDer<'static>>, Error> {
		let certfile = File::open(&self.certificate).map_err(|e| {
			Error::Internal(format!(
				"load_certs failed to open file {}, {}",
				self.certificate, e
			))
		})?;
		let mut reader = io::BufReader::new(certfile);

		rustls_pemfile::certs(&mut reader)
			.collect::<Result<Vec<_>, _>>()
			.map_err(|e| Error::Internal(format!("failed to load certificate, {}", e)))
	}

	fn load_private_key(&self) -> Result<PrivateKeyDer<'static>, Error> {
		let mut keyfile = File::open(&self.private_key).map_err(|e| {
			Error::Internal(format!(
				"load_private_key failed to open file {}, {}",
				self.private_key, e
			))
		})?;
		let keyfile_len = usize::try_from(validate_private_key_file(&keyfile, &self.private_key)?)
			.map_err(|_| {
				Error::Internal(format!(
					"private key file {} is too large to load",
					self.private_key
				))
			})?;

		let mut key_pem = Zeroizing::new(vec![0; keyfile_len]);
		keyfile.read_exact(&mut key_pem[..]).map_err(|e| {
			Error::Internal(format!(
				"load_private_key failed to read file {}, {}",
				self.private_key, e
			))
		})?;
		let mut extra = [0u8; 1];
		let extra_bytes = keyfile.read(&mut extra).map_err(|e| {
			Error::Internal(format!(
				"load_private_key failed to verify file size {}, {}",
				self.private_key, e
			))
		})?;
		extra.zeroize();
		if extra_bytes != 0 {
			return Err(Error::Internal(format!(
				"private key file {} changed while reading",
				self.private_key
			)));
		}
		let mut reader = io::Cursor::new(key_pem.as_slice());

		rustls_pemfile::private_key(&mut reader)
			.map_err(|e| Error::Internal(format!("failed to load private key, {}", e)))?
			.ok_or_else(|| Error::Internal("no private key found".to_string()))
	}

	pub fn build_server_config(&self) -> Result<Arc<rustls::ServerConfig>, Error> {
		let certs = self.load_certs()?;
		let key = self.load_private_key()?;

		let cfg = server_config_with_single_cert_zeroized(certs, key)
			.map_err(|e| Error::Internal(format!("set single certificate failed, {}", e)))?;
		Ok(Arc::new(cfg))
	}
}

fn validate_private_key_file(keyfile: &File, path: &str) -> Result<u64, Error> {
	let metadata = keyfile.metadata().map_err(|e| {
		Error::Internal(format!(
			"load_private_key failed to read file metadata {}, {}",
			path, e
		))
	})?;

	if !metadata.is_file() {
		return Err(Error::Internal(format!(
			"private key file {} is not a regular file",
			path
		)));
	}

	#[cfg(unix)]
	{
		let mode = metadata.permissions().mode();
		if mode & 0o077 != 0 {
			return Err(Error::Internal(format!(
				"private key file {} permissions {:o} are too open; expected owner-only permissions",
				path,
				mode & 0o777
			)));
		}
	}

	Ok(metadata.len())
}

fn server_config_with_single_cert_zeroized(
	certs: Vec<CertificateDer<'static>>,
	mut key: PrivateKeyDer<'static>,
) -> Result<ServerConfig, rustls::Error> {
	// Keep ownership of the plaintext DER so we can wipe it immediately after
	// rustls/ring has parsed it into an owned signing key.
	let signing_key = rustls::crypto::ring::sign::any_supported_type(&key);
	key.zeroize();
	let signing_key = signing_key?;

	let certified_key = rustls::sign::CertifiedKey::new(certs, signing_key);
	match certified_key.keys_match() {
		Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {}
		Err(e) => return Err(e),
	}

	Ok(
		ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
			.with_safe_default_protocol_versions()?
			.with_no_client_auth()
			.with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
				certified_key,
			))),
	)
}

/// HTTP server allowing the registration of ApiEndpoint implementations.
pub struct ApiServer {
	shutdown_sender: Option<oneshot::Sender<()>>,
}

type ApiStartupSender = Arc<Mutex<Option<mpsc::Sender<Result<(), String>>>>>;

fn report_api_startup(startup_sender: &ApiStartupSender, result: Result<(), String>) {
	if let Some(tx) = startup_sender.lock().take() {
		if tx.send(result).is_err() {
			error!("API startup receiver dropped before startup could be reported");
		}
	}
}

fn log_api_thread_join_error(err: Box<dyn std::any::Any + Send + 'static>) {
	let panic_msg = if let Some(msg) = err.downcast_ref::<&str>() {
		*msg
	} else if let Some(msg) = err.downcast_ref::<String>() {
		msg.as_str()
	} else {
		"unknown panic payload"
	};

	error!("API server thread panicked during startup: {}", panic_msg);
}

fn wait_for_api_startup(
	shutdown_sender: &mut Option<oneshot::Sender<()>>,
	handle: thread::JoinHandle<()>,
	startup_rx: mpsc::Receiver<Result<(), String>>,
) -> Result<thread::JoinHandle<()>, Error> {
	match startup_rx.recv() {
		Ok(Ok(())) => Ok(handle),
		Ok(Err(e)) => {
			*shutdown_sender = None;
			if let Err(err) = handle.join() {
				log_api_thread_join_error(err);
			}
			Err(Error::Internal(e))
		}
		Err(e) => {
			*shutdown_sender = None;
			if let Err(err) = handle.join() {
				log_api_thread_join_error(err);
			}
			Err(Error::Internal(format!(
				"API server thread stopped before startup was reported, {}",
				e
			)))
		}
	}
}

#[derive(Debug)]
enum RequestBodyError {
	TooLarge,
	Read(String),
}

fn content_length_exceeds_limit(parts: &Parts) -> Result<bool, &'static str> {
	let mut values = parts.headers.get_all(CONTENT_LENGTH).iter();
	let Some(value) = values.next() else {
		return Ok(false);
	};
	if values.next().is_some() {
		return Err("multiple Content-Length headers");
	}

	let value = value
		.to_str()
		.map_err(|_| "invalid Content-Length header")?;
	if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
		return Err("invalid Content-Length header");
	}

	let len = value
		.parse::<u64>()
		.map_err(|_| "invalid Content-Length header")?;
	Ok(len > MAX_REQUEST_BODY_BYTES as u64)
}

async fn collect_limited_body<B>(body: B, limit: usize) -> Result<Bytes, RequestBodyError>
where
	B: Body,
	B::Error: Into<Box<dyn StdError + Send + Sync>>,
{
	match Limited::new(body, limit).collect().await {
		Ok(body) => Ok(body.to_bytes()),
		Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => Err(RequestBodyError::TooLarge),
		Err(e) => Err(RequestBodyError::Read(e.to_string())),
	}
}

fn rest_connection_builder() -> AutoBuilder<TokioExecutor> {
	// Known limitation: the auto protocol detection performed by
	// serve_connection_with_upgrades reads initial application bytes before the
	// HTTP/1 header_read_timeout or HTTP/2 keepalive settings below are active.
	// A peer can therefore hold a connection slot by sending no bytes, or by
	// slowly trickling a valid HTTP/2 preface prefix. We intentionally do not add
	// a separate initial-read timeout here: MAX_REST_API_CONNECTIONS is already
	// low, so a determined attacker can exhaust the public REST API connection
	// slots anyway. Public-node DDoS resistance is not a goal for this interface;
	// users who need secure node access are expected to run their own instance.
	let mut builder = AutoBuilder::new(TokioExecutor::new());
	builder
		.http1()
		.timer(TokioTimer::new())
		.header_read_timeout(REST_API_IO_TIMEOUT);
	builder
		.http2()
		.timer(TokioTimer::new())
		.keep_alive_interval(REST_API_IO_TIMEOUT)
		.keep_alive_timeout(REST_API_IO_TIMEOUT);
	builder
}

async fn shutdown_rest_connections(
	protocol: &str,
	graceful_shutdown: GracefulShutdown,
	connection_tasks: &mut tokio::task::JoinSet<()>,
) {
	if connection_tasks.len() == 0 {
		return;
	}

	if tokio::time::timeout(REST_API_IO_TIMEOUT, graceful_shutdown.shutdown())
		.await
		.is_err()
	{
		warn!(
			"{} API graceful connection shutdown timed out after {:?}; aborting remaining tasks",
			protocol, REST_API_IO_TIMEOUT
		);
		connection_tasks.abort_all();
	}

	if tokio::time::timeout(REST_API_IO_TIMEOUT, async {
		while let Some(result) = connection_tasks.join_next().await {
			if let Err(e) = result {
				warn!("{} API connection task failed: {}", protocol, e);
			}
		}
	})
	.await
	.is_err()
	{
		warn!(
			"{} API connection task drain timed out after {:?}; aborting remaining tasks",
			protocol, REST_API_IO_TIMEOUT
		);
		connection_tasks.abort_all();
		while let Some(result) = connection_tasks.join_next().await {
			if let Err(e) = result {
				warn!("{} API connection task failed: {}", protocol, e);
			}
		}
	}
}

async fn serve_api_request(
	router: Router,
	req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, RouterError> {
	let (parts, body) = req.into_parts();

	if let Some(response) = router.pre_body_response(&parts) {
		return response.await;
	}

	match content_length_exceeds_limit(&parts) {
		Ok(true) => {
			return response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large").await;
		}
		Ok(false) => {}
		Err(e) => {
			return response(StatusCode::BAD_REQUEST, e).await;
		}
	}

	let body = match tokio::time::timeout(
		REST_API_IO_TIMEOUT,
		collect_limited_body(body, MAX_REQUEST_BODY_BYTES),
	)
	.await
	{
		Ok(Ok(body)) => body,
		Ok(Err(RequestBodyError::TooLarge)) => {
			return response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large").await;
		}
		Ok(Err(RequestBodyError::Read(e))) => {
			return Err(RouterError::Internal(format!(
				"failed to read request body: {}",
				e
			)));
		}
		Err(_) => {
			return response(StatusCode::REQUEST_TIMEOUT, "request body timeout").await;
		}
	};

	router.call(Request::from_parts(parts, body)).await
}

impl ApiServer {
	/// Creates a new ApiServer that will serve ApiEndpoint implementations
	/// under the root URL.
	pub fn new() -> ApiServer {
		ApiServer {
			shutdown_sender: None,
		}
	}

	/// Starts ApiServer at the provided address.
	/// TODO support stop operation
	pub fn start(
		&mut self,
		addr: SocketAddr,
		router: Router,
		conf: Option<TLSConfig>,
	) -> Result<thread::JoinHandle<()>, Error> {
		match conf {
			Some(conf) => self.start_tls(addr, router, conf),
			None => self.start_no_tls(addr, router),
		}
	}

	/// Starts the ApiServer at the provided address.
	fn start_no_tls(
		&mut self,
		addr: SocketAddr,
		router: Router,
	) -> Result<thread::JoinHandle<()>, Error> {
		if self.shutdown_sender.is_some() {
			return Err(Error::Internal(
				"Can't start HTTP API server, it's running already".to_string(),
			));
		}

		let (tx, mut rx): (oneshot::Sender<()>, oneshot::Receiver<()>) = oneshot::channel();
		self.shutdown_sender = Some(tx);
		let (startup_tx, startup_rx) = mpsc::channel();
		let startup_tx = Arc::new(Mutex::new(Some(startup_tx)));

		let handle = match thread::Builder::new()
			.name("apis".to_string())
			.spawn(move || {
				let server_startup_tx = startup_tx.clone();
				let server = async move {
					let listener = match TcpListener::bind(addr).await {
						Ok(listener) => {
							report_api_startup(&server_startup_tx, Ok(()));
							listener
						}
						Err(e) => {
							let err = format!("Unable to bind to {:?}, {}", addr, e);
							report_api_startup(&server_startup_tx, Err(err.clone()));
							return Err(Error::Internal(err));
						}
					};

					let connection_slots =
						Arc::new(tokio::sync::Semaphore::new(MAX_REST_API_CONNECTIONS));
					let graceful_shutdown = GracefulShutdown::new();
					let mut connection_tasks = tokio::task::JoinSet::new();

					loop {
						tokio::select! {
							_ = &mut rx => {
								break;
							}
							joined = connection_tasks.join_next(), if connection_tasks.len() > 0 => {
								if let Some(result) = joined {
									if let Err(e) = result {
										warn!("HTTP API connection task failed: {}", e);
									}
								}
							}
							accepted = listener.accept() => {
								let (stream, peer_addr) = match accepted {
									Ok(v) => v,
									Err(e) => {
										warn!("Error accepting connection: {}", e);
										continue;
									}
								};

								let connection_permit = match connection_slots.clone().try_acquire_owned() {
									Ok(permit) => permit,
									Err(_) => {
										warn!(
											"HTTP API connection limit reached ({}), rejecting connection from {}",
											MAX_REST_API_CONNECTIONS, peer_addr
										);
										continue;
									}
								};

								let router = router.clone();
								let watcher = graceful_shutdown.watcher();
								connection_tasks.spawn(async move {
									let _connection_permit = connection_permit;
									let io = TokioIo::new(stream);
									let service = service_fn(move |req: Request<Incoming>| {
										let router = router.clone();
										serve_api_request(router, req)
									});

									let builder = rest_connection_builder();
									let connection = builder.serve_connection_with_upgrades(io, service);
									if let Err(e) = watcher.watch(connection).await
									{
										warn!("HTTP API connection error: {}", e);
									}
								});
							}
						}
					}

					shutdown_rest_connections("HTTP", graceful_shutdown, &mut connection_tasks)
						.await;
					Ok::<(), Error>(())
				};

				match run_global_async_block(server) {
					Ok(res) => {
						if let Err(e) = res {
							error!("HTTP API server error: {}", e);
						}
					}
					Err(e) => {
						let err = format!("Unable to start no tls api server, {}", e);
						report_api_startup(&startup_tx, Err(err.clone()));
						error!("{}", err);
					}
				}
			}) {
			Ok(handle) => handle,
			Err(e) => {
				self.shutdown_sender = None;
				return Err(Error::Internal(format!(
					"failed to spawn API thread. {}",
					e
				)));
			}
		};

		wait_for_api_startup(&mut self.shutdown_sender, handle, startup_rx)
	}

	/// Starts the TLS ApiServer at the provided address.
	/// TODO support stop operation
	fn start_tls(
		&mut self,
		addr: SocketAddr,
		router: Router,
		conf: TLSConfig,
	) -> Result<thread::JoinHandle<()>, Error> {
		if self.shutdown_sender.is_some() {
			return Err(Error::Internal(
				"Can't start HTTPS API server, it's running already".to_string(),
			));
		}

		// Building certificates here because we want to handle certificates failures with panic.
		// It is a fatal error on node start, not a regular error to log
		let certs = conf.load_certs()?;
		let keys = conf.load_private_key()?;

		let config = server_config_with_single_cert_zeroized(certs, keys).map_err(|e| {
			Error::Argument(format!("invalid key or certificate {:?}, {}", conf, e))
		})?;

		let acceptor = TlsAcceptor::from(Arc::new(config));

		let (tx, mut rx): (oneshot::Sender<()>, oneshot::Receiver<()>) = oneshot::channel();
		self.shutdown_sender = Some(tx);
		let (startup_tx, startup_rx) = mpsc::channel();
		let startup_tx = Arc::new(Mutex::new(Some(startup_tx)));

		let handle = match thread::Builder::new()
			.name("apis".to_string())
			.spawn(move || {
				let server_startup_tx = startup_tx.clone();
				let server = async move {
					let listener = match TcpListener::bind(addr).await {
						Ok(listener) => {
							report_api_startup(&server_startup_tx, Ok(()));
							listener
						}
						Err(e) => {
							let err = format!("Unable to bind to {:?}, {}", addr, e);
							report_api_startup(&server_startup_tx, Err(err.clone()));
							return Err(Error::Internal(err));
						}
					};

					let connection_slots =
						Arc::new(tokio::sync::Semaphore::new(MAX_REST_API_CONNECTIONS));
					let graceful_shutdown = GracefulShutdown::new();
					let mut connection_tasks = tokio::task::JoinSet::new();

					loop {
						tokio::select! {
							_ = &mut rx => {
								break;
							}
							joined = connection_tasks.join_next(), if connection_tasks.len() > 0 => {
								if let Some(result) = joined {
									if let Err(e) = result {
										warn!("HTTPS API connection task failed: {}", e);
									}
								}
							}
							accepted = listener.accept() => {
								let (socket, peer_addr) = match accepted {
									Ok(conn) => conn,
									Err(e) => {
										warn!("Error accepting connection: {}", e);
										continue;
									}
								};

								let connection_permit = match connection_slots.clone().try_acquire_owned() {
									Ok(permit) => permit,
									Err(_) => {
										warn!(
											"HTTPS API connection limit reached ({}), rejecting connection from {}",
											MAX_REST_API_CONNECTIONS, peer_addr
										);
										continue;
									}
								};

								let acceptor = acceptor.clone();
								let router = router.clone();

								let watcher = graceful_shutdown.watcher();
								connection_tasks.spawn(async move {
									let _connection_permit = connection_permit;
									let tls_stream = match tokio::time::timeout(
										REST_API_IO_TIMEOUT,
										acceptor.accept(socket),
									)
									.await
									{
										Ok(Ok(stream)) => stream,
										Ok(Err(e)) => {
											warn!("TLS handshake error from {}: {}", peer_addr, e);
											return;
										}
										Err(_) => {
											warn!("TLS handshake timeout from {}", peer_addr);
											return;
										}
									};

									let io = TokioIo::new(tls_stream);
									let service = service_fn(move |req: Request<Incoming>| {
										let router = router.clone();
										serve_api_request(router, req)
									});

									let builder = rest_connection_builder();
									let connection = builder.serve_connection_with_upgrades(io, service);
									if let Err(e) = watcher.watch(connection).await
									{
										warn!("Error serving TLS connection from {}: {}", peer_addr, e);
									}
								});
							}
						}
					}

					shutdown_rest_connections("HTTPS", graceful_shutdown, &mut connection_tasks)
						.await;
					Ok::<(), Error>(())
				};

				match run_global_async_block(server) {
					Ok(res) => {
						if let Err(e) = res {
							error!("HTTP API server error: {}", e)
						}
					}
					Err(e) => {
						let err = format!("Unable to start tls api server, {}", e);
						report_api_startup(&startup_tx, Err(err.clone()));
						error!("{}", err);
					}
				}
			}) {
			Ok(handle) => handle,
			Err(e) => {
				self.shutdown_sender = None;
				return Err(Error::Internal(format!(
					"failed to spawn API thread. {}",
					e
				)));
			}
		};

		wait_for_api_startup(&mut self.shutdown_sender, handle, startup_rx)
	}

	/// Stops the API server, returning false if shutdown could not be signaled.
	pub fn stop(&mut self) -> bool {
		match self.shutdown_sender.take() {
			Some(tx) => {
				if tx.send(()).is_err() {
					error!("Failed to stop API server");
					return false;
				}
				info!("API server has been stopped");
				true
			}
			None => {
				error!("Can't stop API server, it's not running or doesn't support stop operation");
				false
			}
		}
	}
}

pub struct LoggingMiddleware {}

impl Handler for LoggingMiddleware {
	fn call(
		&self,
		req: Request<Bytes>,
		mut handlers: Box<dyn Iterator<Item = HandlerObj>>,
	) -> ResponseFuture {
		debug!("REST call: {} {}", req.method(), req.uri().path());
		match handlers.next() {
			Some(handler) => handler.call(req, handlers),
			None => response(StatusCode::INTERNAL_SERVER_ERROR, "no handler found"),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::futures::executor::block_on;

	#[test]
	fn collect_limited_body_rejects_over_limit() {
		let err = block_on(collect_limited_body(
			Full::new(Bytes::from_static(b"abcd")),
			3,
		))
		.unwrap_err();

		assert!(matches!(err, RequestBodyError::TooLarge));
	}

	#[test]
	fn content_length_over_limit_is_rejected_before_body_read() {
		let req = Request::builder()
			.header(
				CONTENT_LENGTH,
				(MAX_REQUEST_BODY_BYTES as u64 + 1).to_string(),
			)
			.body(())
			.unwrap();
		let (parts, _) = req.into_parts();

		assert!(content_length_exceeds_limit(&parts).unwrap());
	}

	#[test]
	fn invalid_content_length_is_rejected() {
		let req = Request::builder()
			.header(CONTENT_LENGTH, "not-a-number")
			.body(())
			.unwrap();
		let (parts, _) = req.into_parts();

		assert_eq!(
			content_length_exceeds_limit(&parts),
			Err("invalid Content-Length header")
		);
	}

	#[test]
	fn overflowing_content_length_is_rejected() {
		let req = Request::builder()
			.header(CONTENT_LENGTH, "18446744073709551616")
			.body(())
			.unwrap();
		let (parts, _) = req.into_parts();

		assert_eq!(
			content_length_exceeds_limit(&parts),
			Err("invalid Content-Length header")
		);
	}

	#[test]
	fn duplicate_content_length_is_rejected() {
		let req = Request::builder()
			.header(CONTENT_LENGTH, "1")
			.header(CONTENT_LENGTH, "2")
			.body(())
			.unwrap();
		let (parts, _) = req.into_parts();

		assert_eq!(
			content_length_exceeds_limit(&parts),
			Err("multiple Content-Length headers")
		);
	}

	#[test]
	fn chain_read_error_maps_invalid_header_height_to_not_found() {
		let err = Error::chain_read_error(
			mwc_chain::Error::InvalidHeaderHeight(42),
			"missing header".to_string(),
		);

		match err {
			Error::NotFound(msg) => assert_eq!(msg, "missing header"),
			other => panic!("expected NotFound, got {:?}", other),
		}
	}
}
