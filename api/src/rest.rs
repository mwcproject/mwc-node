// Copyright 2020 The Grin Developers
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

use crate::p2p::Error as P2pError;
use crate::router::{Handler, HandlerObj, ResponseFuture, Router, RouterError};
use crate::web::response;
use failure::{Backtrace, Context, Fail};
use futures::channel::oneshot;
use futures::TryStreamExt;
use hyper::server::accept;
use hyper::service::make_service_fn;
use hyper::{Body, Request, Server, StatusCode};
use rustls;
use rustls::internal::pemfile;
use rustls::{NoClientAuth, ServerConfig};
use std::convert::Infallible;
use std::fmt::{self, Display};
use std::fs::File;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{io, thread};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio_rustls::TlsAcceptor;

/// Errors that can be returned by an ApiEndpoint implementation.
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

#[derive(Clone, Eq, PartialEq, Debug, Fail, Serialize, Deserialize)]
pub enum ErrorKind {
	#[fail(display = "API Internal error: {}", _0)]
	Internal(String),
	#[fail(display = "API Bad arguments: {}", _0)]
	Argument(String),
	#[fail(display = "API Not found: {}", _0)]
	NotFound(String),
	#[fail(display = "API Request error: {}", _0)]
	RequestError(String),
	#[fail(display = "API ResponseError error: {}", _0)]
	ResponseError(String),
	#[fail(display = "API Router error: {}", _0)]
	Router(RouterError),
	#[fail(display = "API P2P error: {}", _0)]
	P2pError(String),
}

impl Fail for Error {
	fn cause(&self) -> Option<&dyn Fail> {
		self.inner.cause()
	}

	fn backtrace(&self) -> Option<&Backtrace> {
		self.inner.backtrace()
	}
}

impl Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		Display::fmt(&self.inner, f)
	}
}

impl Error {
	pub fn kind(&self) -> &ErrorKind {
		self.inner.get_context()
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error {
			inner: Context::new(kind),
		}
	}
}

impl From<Context<ErrorKind>> for Error {
	fn from(inner: Context<ErrorKind>) -> Error {
		Error { inner: inner }
	}
}

impl From<RouterError> for Error {
	fn from(error: RouterError) -> Error {
		Error {
			inner: Context::new(ErrorKind::Router(error)),
		}
	}
}

impl From<crate::chain::Error> for Error {
	fn from(error: crate::chain::Error) -> Error {
		Error {
			inner: Context::new(ErrorKind::Internal(error.to_string())),
		}
	}
}

impl From<P2pError> for Error {
	fn from(error: P2pError) -> Error {
		Error {
			inner: Context::new(ErrorKind::P2pError(format!("{}", error))),
		}
	}
}

/// TLS config
#[derive(Clone)]
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

	fn load_certs(&self) -> Result<Vec<rustls::Certificate>, Error> {
		let certfile = File::open(&self.certificate).map_err(|e| {
			ErrorKind::Internal(format!(
				"load_certs failed to open file {}, {}",
				self.certificate, e
			))
		})?;
		let mut reader = io::BufReader::new(certfile);

		pemfile::certs(&mut reader)
			.map_err(|_| ErrorKind::Internal("failed to load certificate".to_string()).into())
	}

	fn load_private_key(&self) -> Result<rustls::PrivateKey, Error> {
		let keyfile = File::open(&self.private_key).map_err(|e| {
			ErrorKind::Internal(format!(
				"load_private_key failed to open file {}, {}",
				self.private_key, e
			))
		})?;
		let mut reader = io::BufReader::new(keyfile);

		let keys = pemfile::pkcs8_private_keys(&mut reader)
			.map_err(|_| ErrorKind::Internal("failed to load private key".to_string()))?;
		if keys.len() != 1 {
			return Err(ErrorKind::Internal(format!(
				"load_private_key expected a single private key, found {}",
				keys.len()
			)))?;
		}
		Ok(keys[0].clone())
	}

	pub fn build_server_config(&self) -> Result<Arc<rustls::ServerConfig>, Error> {
		let certs = self.load_certs()?;
		let key = self.load_private_key()?;
		let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
		cfg.set_single_cert(certs, key)
			.map_err(|e| ErrorKind::Internal(format!("set single certificate failed, {}", e)))?;
		Ok(Arc::new(cfg))
	}
}

/// HTTP server allowing the registration of ApiEndpoint implementations.
pub struct ApiServer {
	shutdown_sender: Option<oneshot::Sender<()>>,
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
		api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>),
	) -> Result<thread::JoinHandle<()>, Error> {
		match conf {
			Some(conf) => self.start_tls(addr, router, conf, api_chan),
			None => self.start_no_tls(addr, router, api_chan),
		}
	}

	/// Starts the ApiServer at the provided address.
	fn start_no_tls(
		&mut self,
		addr: SocketAddr,
		router: Router,
		api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>),
	) -> Result<thread::JoinHandle<()>, Error> {
		if self.shutdown_sender.is_some() {
			return Err(ErrorKind::Internal(
				"Can't start HTTP API server, it's running already".to_string(),
			)
			.into());
		}
		let rx = &mut api_chan.1;
		let tx = &mut api_chan.0;

		// Jones's trick to update memory
		let m = oneshot::channel::<()>();
		let tx = std::mem::replace(tx, m.0);
		self.shutdown_sender = Some(tx);
		thread::Builder::new()
			.name("apis".to_string())
			.spawn(move || {
				let server = async move {
					let server = Server::bind(&addr)
						.serve(make_service_fn(move |_| {
							let router = router.clone();
							async move { Ok::<_, Infallible>(router) }
						}))
						.with_graceful_shutdown(async {
							rx.await.ok();
						});

					server.await
				};

				let mut rt = Runtime::new()
					.map_err(|e| error!("HTTP API server error: {}", e))
					.unwrap();
				if let Err(e) = rt.block_on(server) {
					error!("HTTP API server error: {}", e)
				}
			})
			.map_err(|e| ErrorKind::Internal(format!("failed to spawn API thread. {}", e)).into())
	}

	/// Starts the TLS ApiServer at the provided address.
	/// TODO support stop operation
	fn start_tls(
		&mut self,
		addr: SocketAddr,
		router: Router,
		conf: TLSConfig,
		api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>),
	) -> Result<thread::JoinHandle<()>, Error> {
		if self.shutdown_sender.is_some() {
			return Err(ErrorKind::Internal(
				"Can't start HTTPS API server, it's running already".to_string(),
			)
			.into());
		}
		let rx = &mut api_chan.1;
		let tx = &mut api_chan.0;

		let m = oneshot::channel::<()>();
		let tx = std::mem::replace(tx, m.0);
		self.shutdown_sender = Some(tx);

		let certs = conf.load_certs()?;
		let keys = conf.load_private_key()?;

		let mut config = ServerConfig::new(NoClientAuth::new());
		config
			.set_single_cert(certs, keys)
			.expect("invalid key or certificate");
		let acceptor = TlsAcceptor::from(Arc::new(config));

		thread::Builder::new()
			.name("apis".to_string())
			.spawn(move || {
				let server = async move {
					let mut listener = TcpListener::bind(&addr).await.expect("failed to bind");
					let listener = listener.incoming().and_then(move |s| acceptor.accept(s));

					let server = Server::builder(accept::from_stream(listener))
						.serve(make_service_fn(move |_| {
							let router = router.clone();
							async move { Ok::<_, Infallible>(router) }
						}))
						.with_graceful_shutdown(async {
							rx.await.ok();
						});

					server.await
				};

				let mut rt = Runtime::new()
					.map_err(|e| error!("HTTP API server error: {}", e))
					.unwrap();
				if let Err(e) = rt.block_on(server) {
					error!("HTTP API server error: {}", e)
				}
			})
			.map_err(|e| ErrorKind::Internal(format!("failed to spawn API thread. {}", e)).into())
	}

	/// Stops the API server, it panics in case of error
	pub fn stop(&mut self) -> bool {
		if self.shutdown_sender.is_some() {
			let tx = self.shutdown_sender.as_mut().unwrap();
			let m = oneshot::channel::<()>();
			let tx = std::mem::replace(tx, m.0);
			tx.send(()).expect("Failed to stop API server");
			info!("API server has been stopped");
			true
		} else {
			error!("Can't stop API server, it's not running or doesn't spport stop operation");
			false
		}
	}
}

pub struct LoggingMiddleware {}

impl Handler for LoggingMiddleware {
	fn call(
		&self,
		req: Request<Body>,
		mut handlers: Box<dyn Iterator<Item = HandlerObj>>,
	) -> ResponseFuture {
		debug!("REST call: {} {}", req.method(), req.uri().path());
		match handlers.next() {
			Some(handler) => handler.call(req, handlers),
			None => response(StatusCode::INTERNAL_SERVER_ERROR, "no handler found"),
		}
	}
}
