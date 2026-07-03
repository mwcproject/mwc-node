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

use crate::router::{Handler, HandlerObj, ResponseFuture};
use crate::web::response;
use crate::RouterError;
use mwc_crates::base64::{self, Engine};
use mwc_crates::bytes::Bytes;
use mwc_crates::digest::Digest;
use mwc_crates::futures::future::{err, ok};
use mwc_crates::http::request::Parts;
use mwc_crates::http_body_util::Full;
use mwc_crates::hyper::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use mwc_crates::hyper::{Request, Response, StatusCode};
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::sha2::Sha256;
use mwc_crates::subtle::ConstantTimeEq;
use mwc_crates::zeroize::Zeroizing;

const AUTH_DIGEST_LEN: usize = 32;
const CORS_ALLOW_METHODS: &str = "GET, POST";
type AuthDigest = Zeroizing<[u8; AUTH_DIGEST_LEN]>;

lazy_static! {
	pub static ref MWC_BASIC_REALM: HeaderValue =
		HeaderValue::from_static("Basic realm=\"MWC-API\"");
	pub static ref MWC_FOREIGN_BASIC_REALM: HeaderValue =
		HeaderValue::from_static("Basic realm=\"MWCForeignAPI\"");
}

// Basic Authentication Middleware
pub struct BasicAuthMiddleware {
	api_basic_auth_digest: AuthDigest,
	basic_realm: &'static HeaderValue,
	ignore_uri: Option<String>,
}

impl BasicAuthMiddleware {
	pub fn new(
		api_basic_auth: String,
		basic_realm: &'static HeaderValue,
		ignore_uri: Option<String>,
	) -> BasicAuthMiddleware {
		let api_basic_auth = Zeroizing::new(api_basic_auth);
		BasicAuthMiddleware {
			api_basic_auth_digest: basic_auth_digest(api_basic_auth.as_bytes()),
			basic_realm,
			ignore_uri,
		}
	}

	pub(crate) fn from_api_secret(
		basic_auth_key: &str,
		api_secret: &Zeroizing<String>,
		basic_realm: &'static HeaderValue,
		ignore_uri: Option<String>,
	) -> BasicAuthMiddleware {
		BasicAuthMiddleware {
			api_basic_auth_digest: basic_auth_digest_from_parts(basic_auth_key, api_secret),
			basic_realm,
			ignore_uri,
		}
	}
}

impl Handler for BasicAuthMiddleware {
	fn pre_body_response(&self, parts: &Parts) -> Option<ResponseFuture> {
		if parts.method.as_str() == "OPTIONS" {
			return Some(cors_preflight_response());
		}
		if let Some(u) = self.ignore_uri.as_ref() {
			if parts.uri.path() == u {
				return None;
			}
		}
		if is_authorized(
			parts.headers.get(AUTHORIZATION),
			&self.api_basic_auth_digest,
		) {
			None
		} else {
			Some(unauthorized_response(&self.basic_realm))
		}
	}

	fn call(
		&self,
		req: Request<Bytes>,
		mut handlers: Box<dyn Iterator<Item = HandlerObj>>,
	) -> ResponseFuture {
		if req.method().as_str() == "OPTIONS" {
			return cors_preflight_response();
		}
		let next_handler = match handlers.next() {
			Some(h) => h,
			None => return response(StatusCode::INTERNAL_SERVER_ERROR, "no handler found"),
		};
		if let Some(u) = self.ignore_uri.as_ref() {
			if req.uri().path() == u {
				return next_handler.call(req, handlers);
			}
		}
		// Only one Authorization header is expected; multiple values are not
		// handled intentionally.
		if is_authorized(
			req.headers().get(AUTHORIZATION),
			&self.api_basic_auth_digest,
		) {
			next_handler.call(req, handlers)
		} else {
			// Unauthorized 401
			unauthorized_response(&self.basic_realm)
		}
	}
}

// Basic Authentication Middleware
pub struct BasicAuthURIMiddleware {
	api_basic_auth_digest: AuthDigest,
	basic_realm: &'static HeaderValue,
	target_uri: String,
}

impl BasicAuthURIMiddleware {
	pub fn new(
		api_basic_auth: Zeroizing<String>,
		basic_realm: &'static HeaderValue,
		target_uri: String,
	) -> BasicAuthURIMiddleware {
		BasicAuthURIMiddleware {
			api_basic_auth_digest: basic_auth_digest(api_basic_auth.as_bytes()),
			basic_realm,
			target_uri,
		}
	}

	pub(crate) fn from_api_secret(
		basic_auth_key: &str,
		api_secret: &Zeroizing<String>,
		basic_realm: &'static HeaderValue,
		target_uri: String,
	) -> BasicAuthURIMiddleware {
		BasicAuthURIMiddleware {
			api_basic_auth_digest: basic_auth_digest_from_parts(basic_auth_key, api_secret),
			basic_realm,
			target_uri,
		}
	}
}

impl Handler for BasicAuthURIMiddleware {
	fn pre_body_response(&self, parts: &Parts) -> Option<ResponseFuture> {
		if parts.method.as_str() == "OPTIONS" {
			return Some(cors_preflight_response());
		}
		if parts.uri.path() == self.target_uri {
			if is_authorized(
				parts.headers.get(AUTHORIZATION),
				&self.api_basic_auth_digest,
			) {
				None
			} else {
				Some(unauthorized_response(&self.basic_realm))
			}
		} else {
			None
		}
	}

	fn call(
		&self,
		req: Request<Bytes>,
		mut handlers: Box<dyn Iterator<Item = HandlerObj>>,
	) -> ResponseFuture {
		if req.method().as_str() == "OPTIONS" {
			return cors_preflight_response();
		}
		let next_handler = match handlers.next() {
			Some(h) => h,
			None => return response(StatusCode::INTERNAL_SERVER_ERROR, "no handler found"),
		};
		if req.uri().path() == self.target_uri {
			// Only one Authorization header is expected; multiple values are not
			// handled intentionally.
			if is_authorized(
				req.headers().get(AUTHORIZATION),
				&self.api_basic_auth_digest,
			) {
				next_handler.call(req, handlers)
			} else {
				// Unauthorized 401
				unauthorized_response(&self.basic_realm)
			}
		} else {
			next_handler.call(req, handlers)
		}
	}
}

fn cors_preflight_response() -> ResponseFuture {
	// The API intentionally does not restrict or validate the Origin header.
	// RPC endpoints are expected to accept browser requests from any origin;
	// authentication is enforced on the actual non-OPTIONS request.
	match Response::builder()
		.status(StatusCode::OK)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.header("access-control-allow-methods", CORS_ALLOW_METHODS)
		.body(Full::new(Bytes::new()))
	{
		Ok(resp) => Box::pin(ok(resp)),
		Err(e) => Box::pin(err(RouterError::Internal(format!(
			"Response build error, {}",
			e
		)))),
	}
}

fn basic_auth_digest(api_basic_auth: &[u8]) -> AuthDigest {
	let mut hasher = Sha256::new();
	hasher.update(api_basic_auth);
	finalize_auth_digest(hasher)
}

fn basic_auth_digest_from_parts(
	basic_auth_key: &str,
	api_secret: &Zeroizing<String>,
) -> AuthDigest {
	let encoded_credentials = basic_auth_credentials_base64(basic_auth_key, api_secret);
	let mut hasher = Sha256::new();
	hasher.update(b"Basic ");
	hasher.update(encoded_credentials.as_bytes());
	finalize_auth_digest(hasher)
}

fn finalize_auth_digest(hasher: Sha256) -> AuthDigest {
	let mut auth_digest = Zeroizing::new([0; AUTH_DIGEST_LEN]);
	mwc_crates::digest::DynDigest::finalize_into(hasher, &mut auth_digest[..])
		.expect("SHA-256 output length must match AuthDigest length");
	auth_digest
}

fn basic_auth_credentials_base64(
	basic_auth_key: &str,
	api_secret: &Zeroizing<String>,
) -> Zeroizing<String> {
	let mut credentials = Zeroizing::new(Vec::with_capacity(
		basic_auth_key.len() + 1 + api_secret.len(),
	));
	credentials.extend_from_slice(basic_auth_key.as_bytes());
	credentials.push(b':');
	credentials.extend_from_slice(api_secret.as_bytes());
	Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(&*credentials))
}

pub(crate) fn build_basic_auth_header_value(
	basic_auth_key: &str,
	api_secret: &Zeroizing<String>,
) -> Zeroizing<String> {
	let encoded_credentials = basic_auth_credentials_base64(basic_auth_key, api_secret);
	let mut value = Zeroizing::new(String::with_capacity(
		"Basic ".len() + encoded_credentials.len(),
	));
	value.push_str("Basic ");
	value.push_str(encoded_credentials.as_str());
	value
}

fn is_authorized(authorization: Option<&HeaderValue>, expected_digest: &AuthDigest) -> bool {
	authorization
		.map(|authorization| {
			let authorization_digest = basic_auth_digest(authorization.as_bytes());
			let authorization_digest: &[u8] = authorization_digest.as_ref();
			let expected_digest: &[u8] = expected_digest.as_ref();
			authorization_digest.ct_eq(expected_digest).into()
		})
		.unwrap_or(false)
}

fn unauthorized_response(basic_realm: &HeaderValue) -> ResponseFuture {
	match Response::builder()
		.status(StatusCode::UNAUTHORIZED)
		.header(WWW_AUTHENTICATE, basic_realm)
		.body(Full::new(Bytes::new()))
	{
		Ok(resp) => Box::pin(ok(resp)),
		Err(e) => Box::pin(err(RouterError::Internal(format!(
			"Respose build error, {}",
			e
		)))),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::router::Router;
	use mwc_crates::futures::executor::block_on;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::Arc;

	struct CountingHandler {
		calls: AtomicUsize,
	}

	impl CountingHandler {
		fn new() -> CountingHandler {
			CountingHandler {
				calls: AtomicUsize::new(0),
			}
		}

		fn calls(&self) -> usize {
			self.calls.load(Ordering::SeqCst)
		}
	}

	impl Handler for CountingHandler {
		fn call(
			&self,
			_req: Request<Bytes>,
			_handlers: Box<dyn Iterator<Item = HandlerObj>>,
		) -> ResponseFuture {
			self.calls.fetch_add(1, Ordering::SeqCst);
			response(StatusCode::OK, "downstream")
		}
	}

	#[test]
	fn build_basic_auth_header_value_matches_basic_auth_encoding() {
		let value = build_basic_auth_header_value("mwc", &Zeroizing::new("secret".into()));

		assert_eq!(value.as_str(), "Basic bXdjOnNlY3JldA==");
	}

	#[test]
	fn basic_auth_digest_from_parts_matches_full_header_digest() {
		let digest = basic_auth_digest_from_parts("mwc", &Zeroizing::new("secret".into()));
		let expected = basic_auth_digest(b"Basic bXdjOnNlY3JldA==");

		assert_eq!(digest.as_ref(), expected.as_ref());
	}

	#[test]
	fn basic_auth_middleware_options_returns_cors_without_calling_downstream() {
		let middleware = BasicAuthMiddleware::new("Basic secret".into(), &MWC_BASIC_REALM, None);
		let next = Arc::new(CountingHandler::new());
		let next_handler: HandlerObj = next.clone();
		let req = Request::builder()
			.method("OPTIONS")
			.uri("/v2/owner")
			.body(Bytes::new())
			.unwrap();

		let resp =
			block_on(middleware.call(req, Box::new(vec![next_handler].into_iter()))).unwrap();

		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(next.calls(), 0);
		assert_eq!(
			resp.headers()
				.get("access-control-allow-origin")
				.unwrap()
				.to_str()
				.unwrap(),
			"*"
		);
		assert_eq!(
			resp.headers()
				.get("access-control-allow-headers")
				.unwrap()
				.to_str()
				.unwrap(),
			"Content-Type, Authorization"
		);
		assert_eq!(
			resp.headers()
				.get("access-control-allow-methods")
				.unwrap()
				.to_str()
				.unwrap(),
			CORS_ALLOW_METHODS
		);
	}

	#[test]
	fn router_pre_body_response_rejects_basic_auth_before_downstream() {
		let mut router = Router::new();
		router.add_middleware(Arc::new(BasicAuthMiddleware::new(
			"Basic secret".into(),
			&MWC_BASIC_REALM,
			None,
		)));
		let next = Arc::new(CountingHandler::new());
		let next_handler: HandlerObj = next.clone();
		router.add_route("/v2/owner", next_handler).unwrap();
		let req = Request::builder()
			.method("POST")
			.uri("/v2/owner")
			.body(Bytes::new())
			.unwrap();
		let (parts, _) = req.into_parts();

		let resp = block_on(
			router
				.pre_body_response(&parts)
				.expect("expected pre-body auth response"),
		)
		.unwrap();

		assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
		assert_eq!(next.calls(), 0);
	}

	#[test]
	fn basic_auth_uri_middleware_options_returns_cors_without_calling_downstream() {
		let middleware = BasicAuthURIMiddleware::new(
			Zeroizing::new("Basic secret".into()),
			&MWC_FOREIGN_BASIC_REALM,
			"/v2/foreign".into(),
		);
		let next = Arc::new(CountingHandler::new());
		let next_handler: HandlerObj = next.clone();
		let req = Request::builder()
			.method("OPTIONS")
			.uri("/v2/foreign")
			.body(Bytes::new())
			.unwrap();

		let resp =
			block_on(middleware.call(req, Box::new(vec![next_handler].into_iter()))).unwrap();

		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(next.calls(), 0);
		assert_eq!(
			resp.headers()
				.get("access-control-allow-origin")
				.unwrap()
				.to_str()
				.unwrap(),
			"*"
		);
		assert_eq!(
			resp.headers()
				.get("access-control-allow-headers")
				.unwrap()
				.to_str()
				.unwrap(),
			"Content-Type, Authorization"
		);
		assert_eq!(
			resp.headers()
				.get("access-control-allow-methods")
				.unwrap()
				.to_str()
				.unwrap(),
			CORS_ALLOW_METHODS
		);
	}
}
