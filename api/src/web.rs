// Copyright 2026 The MWC Developers
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

use crate::rest::*;
use crate::router::ResponseFuture;
use mwc_crates::bytes::Bytes;
use mwc_crates::futures::future::ok;
use mwc_crates::http_body_util::Full;
use mwc_crates::hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use mwc_crates::hyper::{Request, Response, StatusCode};
use mwc_crates::log::error;
use mwc_crates::serde::{Deserialize, Serialize};
use mwc_crates::serde_json;
use std::collections::HashMap;
use std::io::Cursor;

const INTERNAL_SERVER_ERROR_BODY: &str = "Internal server error";

/// Parse request body
pub async fn parse_body<T>(req: Request<Bytes>) -> Result<T, Error>
where
	for<'de> T: Deserialize<'de> + Send + 'static,
{
	let raw = req.into_body();

	let cursor = Cursor::new(raw);
	serde_json::from_reader(cursor)
		.map_err(|e| Error::RequestError(format!("Invalid request body (expected json), {}", e)))
}

/// Convert Result to ResponseFuture
pub fn result_to_response<T>(res: Result<T, Error>) -> ResponseFuture
where
	T: Serialize,
{
	match res {
		Ok(s) => json_response_pretty(&s),
		Err(e) => match e {
			Error::Argument(msg) => response(StatusCode::BAD_REQUEST, msg.clone()),
			Error::RequestError(msg) => response(StatusCode::BAD_REQUEST, msg.clone()),
			Error::NotFound(msg) => response(StatusCode::NOT_FOUND, msg.clone()),
			Error::Internal(_)
			| Error::ResponseError(_)
			| Error::Router { .. }
			| Error::P2pError(_)
			| Error::SecpError(_)
			| Error::IO(_)
			| Error::Chain(_) => internal_error_response(e),
		},
	}
}

fn internal_error_response(e: Error) -> ResponseFuture {
	error!("REST API internal error: {}", e);
	response(
		StatusCode::INTERNAL_SERVER_ERROR,
		INTERNAL_SERVER_ERROR_BODY,
	)
}

/// Utility to serialize a struct into JSON and produce a sensible Response
/// out of it.
pub fn json_response<T>(s: &T) -> ResponseFuture
where
	T: Serialize,
{
	match serde_json::to_string(s) {
		Ok(json) => json_response_body(StatusCode::OK, json),
		Err(e) => json_serialization_error_response("json_response", e),
	}
}

/// Pretty-printed version of json response as future
pub fn json_response_pretty<T>(s: &T) -> ResponseFuture
where
	T: Serialize,
{
	match serde_json::to_string_pretty(s) {
		Ok(json) => json_response_body(StatusCode::OK, json),
		Err(e) => json_serialization_error_response("json_response_pretty", e),
	}
}

fn json_serialization_error_response(context: &str, e: serde_json::Error) -> ResponseFuture {
	error!("REST API {} serialization error: {}", context, e);
	response(
		StatusCode::INTERNAL_SERVER_ERROR,
		INTERNAL_SERVER_ERROR_BODY,
	)
}

fn json_response_body<T: Into<Bytes>>(status: StatusCode, text: T) -> ResponseFuture {
	let mut resp = just_response(status, text);
	let headers = resp.headers_mut();
	headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
	headers.insert(
		HeaderName::from_static("x-content-type-options"),
		HeaderValue::from_static("nosniff"),
	);
	Box::pin(ok(resp))
}

/// Text response as HTTP response
pub fn just_response<T: Into<Bytes>>(status: StatusCode, text: T) -> Response<Full<Bytes>> {
	let mut resp = Response::new(Full::new(text.into()));
	*resp.status_mut() = status;
	resp
}

/// Text response as future
pub fn response<T: Into<Bytes>>(status: StatusCode, text: T) -> ResponseFuture {
	Box::pin(ok(just_response(status, text)))
}

pub struct QueryParams {
	params: HashMap<String, Vec<String>>,
}

impl QueryParams {
	pub fn from_query(query_string: Option<&str>) -> Result<Self, Error> {
		match query_string {
			Some(query_string) => Self::from_query_str(query_string),
			None => Ok(QueryParams {
				params: HashMap::new(),
			}),
		}
	}

	pub fn from_query_str(query_string: &str) -> Result<Self, Error> {
		let mut params = HashMap::new();

		for pair in query_string.as_bytes().split(|&b| b == b'&') {
			if pair.is_empty() {
				continue;
			}

			let mut split = pair.splitn(2, |&b| b == b'=');
			let name = split.next().unwrap_or(&[]);
			let value = split.next().unwrap_or(&[]);
			let name = decode_query_component(name)?;
			let value = decode_query_component(value)?;
			params.entry(name).or_insert_with(Vec::new).push(value);
		}

		Ok(QueryParams { params })
	}

	pub fn process_multival_param<F, E>(&self, name: &str, mut f: F) -> Result<(), E>
	where
		F: FnMut(&str) -> Result<(), E>,
	{
		if let Some(ids) = self.params.get(name) {
			for id in ids {
				for id in id.split(',') {
					f(id)?;
				}
			}
		}
		Ok(())
	}

	pub fn get(&self, name: &str) -> Result<Option<&String>, Error> {
		match self.params.get(name).map(|v| v.as_slice()) {
			None | Some([]) => Ok(None),
			Some([value]) => Ok(Some(value)),
			Some(_) => Err(Error::RequestError(format!(
				"duplicate query parameter {}",
				name
			))),
		}
	}

	pub fn names(&self) -> impl Iterator<Item = &str> {
		self.params.keys().map(String::as_str)
	}
}

fn decode_query_component(input: &[u8]) -> Result<String, Error> {
	let mut decoded = Vec::with_capacity(input.len());
	let mut pos = 0;

	while pos < input.len() {
		match input[pos] {
			b'+' => {
				decoded.push(b' ');
				pos += 1;
			}
			b'%' => {
				if pos + 2 >= input.len() {
					return Err(invalid_query_percent_encoding());
				}
				let high = hex_value(input[pos + 1]).ok_or_else(invalid_query_percent_encoding)?;
				let low = hex_value(input[pos + 2]).ok_or_else(invalid_query_percent_encoding)?;
				decoded.push((high << 4) | low);
				pos += 3;
			}
			byte => {
				decoded.push(byte);
				pos += 1;
			}
		}
	}

	String::from_utf8(decoded)
		.map_err(|_| Error::RequestError("invalid UTF-8 in query string".to_string()))
}

fn hex_value(byte: u8) -> Option<u8> {
	match byte {
		b'0'..=b'9' => Some(byte - b'0'),
		b'a'..=b'f' => Some(byte - b'a' + 10),
		b'A'..=b'F' => Some(byte - b'A' + 10),
		_ => None,
	}
}

fn invalid_query_percent_encoding() -> Error {
	Error::RequestError("invalid percent-encoding in query string".to_string())
}

#[macro_export]
macro_rules! right_path_element(
	($req: expr) =>(
		match $req.uri().path().trim_end_matches('/').rsplit('/').next() {
			None => return response(StatusCode::BAD_REQUEST, "invalid url"),
			Some(el) => el,
		}
	));

#[macro_export]
macro_rules! must_get_query(
	($req: expr) =>(
		match $req.uri().query() {
			Some(q) => q,
			None => return Err(Error::RequestError( format!("no query string at uri {}",$req.uri())))?,
		}
	));

#[macro_export]
macro_rules! parse_param(
	($param: expr, $name: expr, $default: expr) =>(
	match $param.get($name)? {
		None => $default,
		Some(val) =>  match val.parse() {
			Ok(val) => val,
			Err(_) => return Err(Error::RequestError(format!("invalid value of parameter {}", $name))),
		}
	}
	));

#[macro_export]
macro_rules! parse_param_no_err(
	($param: expr, $name: expr, $default: expr) =>(
	match $param.get($name)? {
		None => $default,
		Some(val) =>  match val.parse() {
			Ok(val) => val,
			Err(_) => $default,
		}
	}
	));

#[macro_export]
macro_rules! w_fut(
	($p: expr) =>(
		match w($p) {
			Ok(p) => p,
			Err(_) => return response(StatusCode::INTERNAL_SERVER_ERROR, "weak reference upgrade failed" ),
		}
	));

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::futures::executor::block_on;
	use mwc_crates::http_body_util::BodyExt;
	use mwc_crates::serde::Serializer;

	const X_CONTENT_TYPE_OPTIONS: &str = "x-content-type-options";

	struct FailsSerialize;

	impl Serialize for FailsSerialize {
		fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
		where
			S: Serializer,
		{
			Err(mwc_crates::serde::ser::Error::custom(
				"secret serialization detail",
			))
		}
	}

	fn future_body(response: ResponseFuture) -> (StatusCode, Bytes) {
		let response = block_on(response).unwrap();
		let status = response.status();
		let body = block_on(response.into_body().collect()).unwrap().to_bytes();
		(status, body)
	}

	#[test]
	fn query_params_get_returns_unique_value() {
		let params = QueryParams::from_query_str("name=a").unwrap();

		assert_eq!(params.get("name").unwrap().map(|v| v.as_str()), Some("a"));
		assert!(params.get("missing").unwrap().is_none());
	}

	#[test]
	fn query_params_get_rejects_duplicate_scalar_parameter() {
		let params = QueryParams::from_query_str("name=a&name=b").unwrap();

		match params.get("name").unwrap_err() {
			Error::RequestError(msg) => {
				assert!(msg.contains("duplicate query parameter name"), "{}", msg);
			}
			other => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn query_params_strictly_decodes_valid_utf8() {
		let params = QueryParams::from_query_str("name=hello+world&id=%E2%82%AC").unwrap();

		assert_eq!(
			params.get("name").unwrap().map(|v| v.as_str()),
			Some("hello world")
		);
		assert_eq!(
			params.get("id").unwrap().map(|v| v.as_str()),
			Some("\u{20ac}")
		);
	}

	#[test]
	fn query_params_rejects_percent_decoded_invalid_utf8() {
		match QueryParams::from_query_str("id=%FF") {
			Ok(_) => panic!("expected invalid UTF-8 to be rejected"),
			Err(Error::RequestError(msg)) => {
				assert!(msg.contains("invalid UTF-8 in query string"), "{}", msg);
			}
			Err(other) => panic!("expected request error, got {:?}", other),
		}
	}

	#[test]
	fn query_params_rejects_invalid_percent_encoding() {
		for query in ["id=%", "id=%F", "id=%GG"] {
			match QueryParams::from_query_str(query) {
				Ok(_) => panic!("expected invalid percent-encoding to be rejected"),
				Err(Error::RequestError(msg)) => {
					assert!(msg.contains("invalid percent-encoding"), "{}", msg);
				}
				Err(other) => panic!("expected request error, got {:?}", other),
			}
		}
	}

	#[test]
	fn json_response_sets_json_headers() {
		let resp = block_on(json_response(&serde_json::json!({ "ok": true }))).unwrap();

		assert_eq!(
			resp.headers().get(CONTENT_TYPE).unwrap(),
			HeaderValue::from_static("application/json")
		);
		assert_eq!(
			resp.headers().get(X_CONTENT_TYPE_OPTIONS).unwrap(),
			HeaderValue::from_static("nosniff")
		);
	}

	#[test]
	fn json_response_pretty_sets_json_headers() {
		let resp = block_on(json_response_pretty(&serde_json::json!({ "ok": true }))).unwrap();

		assert_eq!(
			resp.headers().get(CONTENT_TYPE).unwrap(),
			HeaderValue::from_static("application/json")
		);
		assert_eq!(
			resp.headers().get(X_CONTENT_TYPE_OPTIONS).unwrap(),
			HeaderValue::from_static("nosniff")
		);
	}

	#[test]
	fn text_response_does_not_set_json_headers() {
		let resp = block_on(response(StatusCode::OK, "ok")).unwrap();

		assert!(resp.headers().get(CONTENT_TYPE).is_none());
		assert!(resp.headers().get(X_CONTENT_TYPE_OPTIONS).is_none());
	}

	#[test]
	fn json_response_hides_serialization_error_messages() {
		let cases = [
			future_body(json_response(&FailsSerialize)),
			future_body(json_response_pretty(&FailsSerialize)),
		];

		for (status, body) in cases {
			assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
			assert_eq!(body, Bytes::from(INTERNAL_SERVER_ERROR_BODY));
		}
	}

	fn response_body<T: Serialize>(res: Result<T, Error>) -> (StatusCode, Bytes) {
		future_body(result_to_response(res))
	}

	#[test]
	fn result_to_response_preserves_client_error_messages() {
		let cases = [
			(
				Err::<(), _>(Error::Argument("bad argument".to_string())),
				StatusCode::BAD_REQUEST,
				"bad argument",
			),
			(
				Err::<(), _>(Error::RequestError("bad request".to_string())),
				StatusCode::BAD_REQUEST,
				"bad request",
			),
			(
				Err::<(), _>(Error::NotFound("missing".to_string())),
				StatusCode::NOT_FOUND,
				"missing",
			),
		];

		for (err, expected_status, expected_body) in cases {
			let (status, body) = response_body(err);

			assert_eq!(status, expected_status);
			assert_eq!(body, Bytes::from(expected_body));
		}
	}

	#[test]
	fn result_to_response_hides_internal_error_messages() {
		let cases = [
			Error::Internal("commitment mismatch at position 42".to_string()),
			Error::ResponseError("filesystem path /tmp/node/db".to_string()),
			Error::Router {
				source: crate::router::RouterError::Internal("router detail".to_string()),
			},
			Error::P2pError("peer 127.0.0.1:13414 failed".to_string()),
			Error::IO(std::io::Error::new(
				std::io::ErrorKind::Other,
				"/tmp/node/db",
			)),
			Error::Chain(mwc_chain::Error::FileReadErr("chain detail".to_string())),
		];

		for err in cases {
			let (status, body) = response_body(Err::<(), _>(err));

			assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
			assert_eq!(body, Bytes::from(INTERNAL_SERVER_ERROR_BODY));
		}
	}
}
