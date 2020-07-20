// Copyright 2018 The Grin Developers
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

//! High level JSON/HTTP client API

use crate::core::global;
use crate::util::to_base64;
use crossbeam_utils::thread::scope;
use failure::{Backtrace, Context, Fail};
use hyper::body;
use hyper::client::HttpConnector;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use hyper::{self, Body, Client as HyperClient, Request, Uri};
use hyper_rustls;
use hyper_timeout::TimeoutConnector;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Builder;

/// Errors that can be returned by an ApiEndpoint implementation.
#[derive(Debug)]
pub struct Error {
	inner: Context<ErrorKind>,
}

#[derive(Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
	#[fail(display = "Internal error: {}", _0)]
	Internal(String),
	#[fail(display = "Bad arguments: {}", _0)]
	Argument(String),
	#[fail(display = "Request error: {}", _0)]
	RequestError(String),
	#[fail(display = "ResponseError error: {}", _0)]
	#[allow(dead_code)]
	ResponseError(String),
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
	pub fn _kind(&self) -> &ErrorKind {
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

#[derive(Clone)]
pub struct Client {
	// At the same time only one client can exist. Probably it is a better way to write that, but we don't want
	// to change signature.
	/// Normal http(s) client.
	https_client:
		Arc<Option<hyper::Client<TimeoutConnector<hyper_rustls::HttpsConnector<HttpConnector>>>>>,
	/// Socks proxy client
	socks_client: Arc<
		Option<
			hyper::Client<
				TimeoutConnector<
					hyper_socks2::SocksConnector<hyper_rustls::HttpsConnector<HttpConnector>>,
				>,
			>,
		>,
	>,
}

impl Client {
	/// New client
	pub fn new(use_socks: bool, socks_proxy_addr: Option<SocketAddr>) -> Result<Self, Error> {
		let (https_client, socks_client) = Self::construct_client(use_socks, socks_proxy_addr)?;
		Ok(Client {
			https_client: Arc::new(https_client),
			socks_client: Arc::new(socks_client),
		})
	}

	fn construct_client(
		use_socks: bool,
		socks_proxy_addr: Option<SocketAddr>,
	) -> Result<
		(
			Option<hyper::Client<TimeoutConnector<hyper_rustls::HttpsConnector<HttpConnector>>>>,
			Option<
				hyper::Client<
					TimeoutConnector<
						hyper_socks2::SocksConnector<hyper_rustls::HttpsConnector<HttpConnector>>,
					>,
				>,
			>,
		),
		Error,
	> {
		if !use_socks {
			let https = hyper_rustls::HttpsConnector::new();
			let mut connector = TimeoutConnector::new(https);
			connector.set_connect_timeout(Some(Duration::from_secs(20)));
			connector.set_read_timeout(Some(Duration::from_secs(20)));
			connector.set_write_timeout(Some(Duration::from_secs(20)));
			let client = HyperClient::builder()
				.pool_idle_timeout(Duration::from_secs(120))
				.build::<_, Body>(connector);
			Ok((Some(client), None))
		} else {
			let addr = socks_proxy_addr.ok_or_else(|| {
				ErrorKind::RequestError("Missing Socks proxy address".to_string())
			})?;
			let auth = format!("{}:{}", addr.ip(), addr.port());

			let https = hyper_rustls::HttpsConnector::new();
			let socks = hyper_socks2::SocksConnector {
				proxy_addr: hyper::Uri::builder()
					.scheme("socks5")
					.authority(auth.as_str())
					.path_and_query("/")
					.build()
					.map_err(|_| {
						ErrorKind::RequestError("Can't parse Socks proxy address".to_string())
					})?,
				auth: None,
				connector: https,
			};
			let mut connector = TimeoutConnector::new(socks);
			connector.set_connect_timeout(Some(Duration::from_secs(20)));
			connector.set_read_timeout(Some(Duration::from_secs(20)));
			connector.set_write_timeout(Some(Duration::from_secs(20)));
			let client = HyperClient::builder()
				.pool_idle_timeout(Duration::from_secs(120))
				.build::<_, Body>(connector);
			Ok((None, Some(client)))
		}
	}

	/// Helper function to easily issue a HTTP GET request against a given URL that
	/// returns a JSON object. Handles request building, JSON deserialization and
	/// response code checking.
	pub fn _get<'a, T>(&self, url: &'a str, api_secret: Option<String>) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de>,
	{
		self._handle_request(self.build_request(url, "GET", None, api_secret, None)?)
	}

	/// Helper function to easily issue an async HTTP GET request against a given
	/// URL that returns a future. Handles request building, JSON deserialization
	/// and response code checking.
	pub async fn _get_async<'a, T>(
		&self,
		url: &'a str,
		api_secret: Option<String>,
	) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de> + Send + 'static,
	{
		self._handle_request_async(self.build_request(url, "GET", None, api_secret, None)?)
			.await
	}

	/// Helper function to easily issue a HTTP GET request
	/// on a given URL that returns nothing. Handles request
	/// building and response code checking.
	pub fn _get_no_ret(&self, url: &str, api_secret: Option<String>) -> Result<(), Error> {
		let req = self.build_request(url, "GET", None, api_secret, None)?;
		self.send_request(req)?;
		Ok(())
	}

	/// Helper function to easily issue a HTTP POST request with the provided JSON
	/// object as body on a given URL that returns a JSON object. Handles request
	/// building, JSON serialization and deserialization, and response code
	/// checking.
	pub fn _post<IN, OUT>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: &IN,
	) -> Result<OUT, Error>
	where
		IN: Serialize,
		for<'de> OUT: Deserialize<'de>,
	{
		let req = self._create_post_request(url, None, api_secret, input)?;
		self._handle_request(req)
	}

	/// Helper function to easily issue an async HTTP POST request with the
	/// provided JSON object as body on a given URL that returns a future. Handles
	/// request building, JSON serialization and deserialization, and response code
	/// checking.
	pub async fn _post_async<IN, OUT>(
		&self,
		url: &str,
		input: &IN,
		api_secret: Option<String>,
	) -> Result<OUT, Error>
	where
		IN: Serialize,
		OUT: Send + 'static,
		for<'de> OUT: Deserialize<'de>,
	{
		self._handle_request_async(self._create_post_request(url, None, api_secret, input)?)
			.await
	}

	/// Helper function to easily issue a HTTP POST request with the provided JSON
	/// object as body on a given URL that returns nothing. Handles request
	/// building, JSON serialization, and response code
	/// checking.
	pub fn _post_no_ret<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: &IN,
	) -> Result<(), Error>
	where
		IN: Serialize,
	{
		let req = self._create_post_request(url, None, api_secret, input)?;
		self.send_request(req)?;
		Ok(())
	}

	/// Helper function to easily issue an async HTTP POST request with the
	/// provided JSON object as body on a given URL that returns a future. Handles
	/// request building, JSON serialization and deserialization, and response code
	/// checking.
	pub async fn _post_no_ret_async<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		input: &IN,
	) -> Result<(), Error>
	where
		IN: Serialize,
	{
		self.send_request_async(self._create_post_request(url, None, api_secret, input)?)
			.await?;
		Ok(())
	}

	fn build_request(
		&self,
		url: &str,
		method: &str,
		basic_auth_key: Option<String>, // In Node will be generated. Specify None if talk to the Node. Another wallet wants 'mwc'
		api_secret: Option<String>,
		body: Option<String>,
	) -> Result<Request<Body>, Error> {
		let basic_auth_key = basic_auth_key.unwrap_or(if global::is_mainnet() {
			"mwcmain".to_string()
		} else if global::is_floonet() {
			"mwcfloo".to_string()
		} else {
			"mwc".to_string()
		});

		self.build_request_ex(
			url,
			method,
			api_secret,
			Some(basic_auth_key.to_string()),
			body,
		)
	}

	fn build_request_ex(
		&self,
		url: &str,
		method: &str,
		api_secret: Option<String>,
		basic_auth_key: Option<String>,
		body: Option<String>,
	) -> Result<Request<Body>, Error> {
		let uri: Uri = url
			.parse()
			.map_err(|e| ErrorKind::Argument(format!("Invalid url {}, {}", url, e)))?;
		let mut builder = Request::builder();
		if basic_auth_key.is_some() && api_secret.is_some() {
			let auth_key = format!("{}:{}", basic_auth_key.unwrap(), api_secret.unwrap());
			let base64_key = to_base64(&auth_key);
			let basic_auth = format!("Basic {}", base64_key);
			builder = builder.header(AUTHORIZATION, basic_auth);
		}

		builder
			.method(method)
			.uri(uri)
			.header(USER_AGENT, "mwc-client")
			.header(ACCEPT, "application/json")
			.header(CONTENT_TYPE, "application/json")
			.body(match body {
				None => Body::empty(),
				Some(json) => json.into(),
			})
			.map_err(|e| {
				ErrorKind::RequestError(format!("Bad request {} {}: {}", method, url, e)).into()
			})
	}

	pub fn _create_post_request<IN>(
		&self,
		url: &str,
		basic_auth_key: Option<String>, // Specify None if talk to the Node. Another wallet wants 'mwc'
		api_secret: Option<String>,
		input: &IN,
	) -> Result<Request<Body>, Error>
	where
		IN: Serialize,
	{
		let json = serde_json::to_string(input)
			.map_err(|e| ErrorKind::Internal(format!("Could not serialize data to JSON, {}", e)))?;
		self.build_request(url, "POST", basic_auth_key, api_secret, Some(json))
	}

	pub fn create_get_request(
		&self,
		url: &str,
		basic_auth_key: Option<String>, // Specify None if talk to the Node. Another wallet wants 'mwc'
		api_secret: Option<String>,
	) -> Result<Request<Body>, Error> {
		self.build_request(url, "GET", basic_auth_key, api_secret, None)
	}

	pub fn _create_post_request_ex<IN>(
		&self,
		url: &str,
		api_secret: Option<String>,
		basic_auth_key: Option<String>,
		input: &IN,
	) -> Result<Request<Body>, Error>
	where
		IN: Serialize,
	{
		let json = serde_json::to_string(input)
			.map_err(|e| ErrorKind::Internal(format!("Could not serialize data to JSON, {}", e)))?;
		self.build_request_ex(url, "POST", api_secret, basic_auth_key, Some(json))
	}

	fn _handle_request<T>(&self, req: Request<Body>) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de>,
	{
		let data = self.send_request(req)?;
		serde_json::from_str(&data).map_err(|e| {
			ErrorKind::ResponseError(format!("Cannot parse response {}, {}", data, e)).into()
		})
	}

	async fn _handle_request_async<T>(&self, req: Request<Body>) -> Result<T, Error>
	where
		for<'de> T: Deserialize<'de> + Send + 'static,
	{
		let data = self.send_request_async(req).await?;
		let ser = serde_json::from_str(&data).map_err(|e| {
			ErrorKind::ResponseError(format!("Cannot parse response {}, {}", data, e))
		})?;
		Ok(ser)
	}

	async fn send_request_async(&self, req: Request<Body>) -> Result<String, Error> {
		let resp = if self.https_client.is_some() {
			let client = self.https_client.iter().next().unwrap();
			client.request(req).await
		} else {
			debug_assert!(self.socks_client.is_some());
			self.socks_client.iter().next().unwrap().request(req).await
		};

		let resp =
			resp.map_err(|e| ErrorKind::RequestError(format!("Cannot make request: {}", e)))?;

		let raw = body::to_bytes(resp)
			.await
			.map_err(|e| ErrorKind::RequestError(format!("Cannot read response body: {}", e)))?;

		Ok(String::from_utf8_lossy(&raw).to_string())
	}

	pub fn send_request(&self, req: Request<Body>) -> Result<String, Error> {
		let task = self.send_request_async(req);
		scope(|s| {
			let handle = s.spawn(|_| {
				let mut rt = Builder::new()
					.basic_scheduler()
					.enable_all()
					.build()
					.map_err(|e| {
						ErrorKind::Internal(format!("can't create Tokio runtime, {}", e))
					})?;
				rt.block_on(task)
			});
			handle.join().unwrap()
		})
		.unwrap()
	}
}
