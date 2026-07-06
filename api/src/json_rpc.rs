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
// Derived from https://github.com/apoelstra/rust-jsonrpc

//! JSON RPC Client functionality
use mwc_crates::easy_jsonrpc_mwc::{self, Handler, MaybeReply, Value};
use mwc_crates::hyper;
use mwc_crates::serde;
use mwc_crates::serde::{Deserialize, Serialize};
use mwc_crates::serde_json;
use std::{error, fmt};

/// Builds a request
pub fn build_request<'a, 'b>(
	n: u32,
	name: &'a str,
	params: &'b serde_json::Value,
) -> Request<'a, 'b> {
	Request {
		method: name,
		params: params,
		id: From::from(n),
		jsonrpc: Some("2.0"),
	}
}

// Rustdoc doctests link the normal crate artifact, so hidden doctest macros call
// this Result-returning helper instead of exposing panic-only parser functions.
#[doc(hidden)]
pub fn doctest_assert_json_rpc_response(
	request: &str,
	expected_response: &str,
	method_args: &'static [(&'static str, &'static [&'static str])],
) -> Result<(), DoctestJsonRpcError> {
	let expected_response: Value = easy_jsonrpc_mwc::serde_json::from_str(expected_response)
		.map_err(DoctestJsonRpcError::InvalidExpectedResponse)?;
	let request_val: Value = easy_jsonrpc_mwc::serde_json::from_str(request)
		.map_err(DoctestJsonRpcError::InvalidRequest)?;
	let api = JsonRpcDoctest {
		expected_response: expected_response.clone(),
		method_args,
	};
	let response = match api.handle_request(request_val) {
		MaybeReply::Reply(response) => response,
		MaybeReply::DontReply => return Err(DoctestJsonRpcError::NoResponse),
	};

	if response != expected_response {
		return Err(DoctestJsonRpcError::ResponseMismatch {
			response,
			expected_response,
		});
	}

	Ok(())
}

struct JsonRpcDoctest<'a> {
	expected_response: Value,
	method_args: &'a [(&'static str, &'static [&'static str])],
}

impl JsonRpcDoctest<'_> {
	fn expected_result_value(&self) -> Result<Value, easy_jsonrpc_mwc::Error> {
		self.expected_response
			.get("result")
			.cloned()
			.ok_or_else(|| {
				easy_jsonrpc_mwc::Error::invalid_params(
					"doctest expected response must contain result".to_string(),
				)
			})
	}
}

impl Handler for JsonRpcDoctest<'_> {
	fn handle(
		&self,
		method: &str,
		params: easy_jsonrpc_mwc::Params,
	) -> Result<Value, easy_jsonrpc_mwc::Error> {
		let arg_names = self
			.method_args
			.iter()
			.find_map(|(method_name, arg_names)| (*method_name == method).then_some(*arg_names))
			.ok_or_else(easy_jsonrpc_mwc::Error::method_not_found)?;
		// This doctest fixture intentionally validates only method lookup and
		// argument shape: arity plus named-key mapping. Unlike the generated
		// production handler, it does not deserialize each JSON value into the real
		// RPC argument type, so malformed values can still pass here. We accept
		// that tradeoff to keep this doctest shim simple.
		params
			.get_rpc_args(arg_names)
			.map_err(|err| -> easy_jsonrpc_mwc::Error { err.into() })?;
		self.expected_result_value()
	}
}

#[doc(hidden)]
#[derive(Debug)]
pub enum DoctestJsonRpcError {
	InvalidExpectedResponse(serde_json::Error),
	InvalidRequest(serde_json::Error),
	NoResponse,
	ResponseMismatch {
		response: Value,
		expected_response: Value,
	},
}

impl fmt::Display for DoctestJsonRpcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			DoctestJsonRpcError::InvalidExpectedResponse(err) => {
				write!(f, "invalid doctest JSON-RPC expected response: {}", err)
			}
			DoctestJsonRpcError::InvalidRequest(err) => {
				write!(f, "invalid doctest JSON-RPC request: {}", err)
			}
			DoctestJsonRpcError::NoResponse => {
				write!(f, "doctest JSON-RPC request produced no response")
			}
			DoctestJsonRpcError::ResponseMismatch {
				response,
				expected_response,
			} => {
				let response =
					serde_json::to_string_pretty(response).unwrap_or_else(|_| response.to_string());
				let expected_response = serde_json::to_string_pretty(expected_response)
					.unwrap_or_else(|_| expected_response.to_string());
				write!(
					f,
					"(left != right) \nleft: {}\nright: {}",
					response, expected_response
				)
			}
		}
	}
}

impl error::Error for DoctestJsonRpcError {}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(crate = "serde")]
/// A JSONRPC request object
pub struct Request<'a, 'b> {
	/// The name of the RPC call
	pub method: &'a str,
	/// Parameters to the RPC call
	pub params: &'b serde_json::Value,
	/// Identifier for this Request, which should appear in the response
	pub id: serde_json::Value,
	/// jsonrpc field, MUST be "2.0"
	pub jsonrpc: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(crate = "serde")]
/// A JSONRPC response object
pub struct Response {
	/// A result if there is one, or null
	pub result: Option<serde_json::Value>,
	/// An error if there is one, or null
	pub error: Option<RpcError>,
	/// Identifier for this Request, which should match that of the request
	pub id: serde_json::Value,
	/// jsonrpc field, expected to be "2.0" when present
	pub jsonrpc: Option<String>,
}

impl Response {
	fn check_jsonrpc_version(&self) -> Result<(), Error> {
		match self.jsonrpc.as_deref() {
			None | Some("2.0") => Ok(()),
			Some(_) => Err(Error::VersionMismatch),
		}
	}

	/// Extract the result from a response
	pub fn result<T: serde::de::DeserializeOwned>(&self) -> Result<T, Error> {
		self.check_jsonrpc_version()?;

		if let Some(ref e) = self.error {
			return Err(Error::Rpc(e.clone()));
		}

		let result = match self.result.as_ref() {
			Some(r) => {
				// Avoid Value indexing here: r["Ok"] silently returns Null for
				// non-objects and missing keys, which can deserialize as success
				// for nullable/unit targets and hide malformed RPC responses.
				let obj = r.as_object().ok_or_else(|| {
					Error::MalformedResponse(
						"RPC result must be an object containing an Ok field".to_string(),
					)
				})?;
				if let Some(err) = obj.get("Err") {
					return Err(Error::Method(format_result_error(err)));
				}
				let ok = obj.get("Ok").ok_or_else(|| {
					Error::MalformedResponse(
						"RPC result must be an object containing an Ok field".to_string(),
					)
				})?;
				serde_json::from_value(ok.clone()).map_err(Error::Json)
			}
			None => Err(Error::MalformedResponse(
				"RPC result must be an object containing an Ok field".to_string(),
			)),
		}?;
		Ok(result)
	}

	/// Extract the result from a response, consuming the response
	pub fn into_result<T: serde::de::DeserializeOwned>(self) -> Result<T, Error> {
		self.result()
	}

	/// Return the RPC error, if there was one, but do not check the result
	pub fn _check_error(self) -> Result<(), Error> {
		if let Some(e) = self.error {
			Err(Error::Rpc(e))
		} else {
			Ok(())
		}
	}

	/// Returns whether or not the `result` field is empty
	pub fn _is_none(&self) -> bool {
		self.result.is_none()
	}
}

fn format_result_error(err: &serde_json::Value) -> String {
	match err {
		serde_json::Value::String(msg) => msg.clone(),
		serde_json::Value::Object(obj) if obj.len() == 1 => {
			let (kind, payload) = obj.iter().next().expect("checked object length");
			match payload {
				serde_json::Value::Null => kind.clone(),
				serde_json::Value::String(msg) => format!("{}: {}", kind, msg),
				serde_json::Value::Array(values) if values.len() == 1 => {
					match values.first().expect("checked array length") {
						serde_json::Value::String(msg) => format!("{}: {}", kind, msg),
						value => format!("{}: {}", kind, value),
					}
				}
				value => format!("{}: {}", kind, value),
			}
		}
		value => value.to_string(),
	}
}

/// A library error
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Json error
	#[error("JSON decode error: {0}")]
	Json(#[from] serde_json::Error),
	/// Client error
	#[error("Hyper error: {0}")]
	Hyper(#[from] hyper::Error),
	/// Error response
	#[error("RPC error response: {0:?}")]
	Rpc(#[from] RpcError),
	/// Application-level error returned inside the RPC result wrapper.
	#[error("RPC method error: {0}")]
	Method(String),
	/// Response result did not match the expected RPC success wrapper shape.
	#[error("Malformed RPC response: {0}")]
	MalformedResponse(String),
	/// Response to a request did not have the expected nonce
	#[error("Nonce of response did not match nonce of request")]
	_NonceMismatch,
	/// Response to a request had a jsonrpc field other than "2.0"
	#[error("`jsonrpc` field set to non-\"2.0\"")]
	VersionMismatch,
	/// Batches can't be empty
	#[error("batches can't be empty")]
	_EmptyBatch,
	/// Too many responses returned in batch
	#[error("too many responses returned in batch")]
	_WrongBatchResponseSize,
	/// Batch response contained a duplicate ID
	#[error("duplicate RPC batch response ID: {0}")]
	_BatchDuplicateResponseId(serde_json::Value),
	/// Batch response contained an ID that didn't correspond to any request ID
	#[error("wrong RPC batch response ID: {0}")]
	_WrongBatchResponseId(serde_json::Value),
}

/// Standard error responses, as described at at
/// http://www.jsonrpc.org/specification#error_object
///
/// # Documentation Copyright
/// Copyright (C) 2007-2010 by the JSON-RPC Working Group
///
/// This document and translations of it may be used to implement JSON-RPC, it
/// may be copied and furnished to others, and derivative works that comment
/// on or otherwise explain it or assist in its implementation may be prepared,
/// copied, published and distributed, in whole or in part, without restriction
/// of any kind, provided that the above copyright notice and this paragraph
/// are included on all such copies and derivative works. However, this document
/// itself may not be modified in any way.
///
/// The limited permissions granted above are perpetual and will not be revoked.
///
/// This document and the information contained herein is provided "AS IS" and
/// ALL WARRANTIES, EXPRESS OR IMPLIED are DISCLAIMED, INCLUDING BUT NOT LIMITED
/// TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY
/// RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A
/// PARTICULAR PURPOSE.
///
#[allow(dead_code)]
#[derive(Debug)]
pub enum StandardError {
	/// Invalid JSON was received by the server.
	/// An error occurred on the server while parsing the JSON text.
	ParseError,
	/// The JSON sent is not a valid Request object.
	InvalidRequest,
	/// The method does not exist / is not available.
	MethodNotFound,
	/// Invalid method parameter(s).
	InvalidParams,
	/// Internal JSON-RPC error.
	InternalError,
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(crate = "serde")]
/// A JSONRPC error object
pub struct RpcError {
	/// The integer identifier of the error
	pub code: i32,
	/// A string describing the error
	pub message: String,
	/// Additional data specific to the error
	pub data: Option<serde_json::Value>,
}

impl fmt::Display for RpcError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match &self.data {
			Some(data) => write!(f, "{} (code {}, data: {})", self.message, self.code, data),
			None => write!(f, "{} (code {})", self.message, self.code),
		}
	}
}

impl error::Error for RpcError {}

/// Create a standard error responses
pub fn _standard_error(code: StandardError, data: Option<serde_json::Value>) -> RpcError {
	match code {
		StandardError::ParseError => RpcError {
			code: -32700,
			message: "Parse error".to_string(),
			data: data,
		},
		StandardError::InvalidRequest => RpcError {
			code: -32600,
			message: "Invalid Request".to_string(),
			data: data,
		},
		StandardError::MethodNotFound => RpcError {
			code: -32601,
			message: "Method not found".to_string(),
			data: data,
		},
		StandardError::InvalidParams => RpcError {
			code: -32602,
			message: "Invalid params".to_string(),
			data: data,
		},
		StandardError::InternalError => RpcError {
			code: -32603,
			message: "Internal error".to_string(),
			data: data,
		},
	}
}

/// Converts a Rust `Result` to a JSONRPC response object
pub fn _result_to_response(
	result: Result<serde_json::Value, RpcError>,
	id: serde_json::Value,
) -> Response {
	match result {
		Ok(data) => Response {
			result: Some(data),
			error: None,
			id: id,
			jsonrpc: Some(String::from("2.0")),
		},
		Err(err) => Response {
			result: None,
			error: Some(err),
			id: id,
			jsonrpc: Some(String::from("2.0")),
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn response_with_version(jsonrpc: Option<&str>) -> Response {
		Response {
			result: Some(serde_json::from_str(r#"{"Ok":7}"#).unwrap()),
			error: None,
			id: serde_json::Value::from(1),
			jsonrpc: jsonrpc.map(String::from),
		}
	}

	fn assert_malformed_ok_field(err: Error) {
		match err {
			Error::MalformedResponse(msg) => {
				assert!(msg.contains("Ok field"), "{}", msg);
			}
			other => panic!("expected malformed response error, got {:?}", other),
		}
	}

	#[test]
	fn result_accepts_jsonrpc_2_0_response() {
		let result: u64 = response_with_version(Some("2.0")).result().unwrap();
		assert_eq!(result, 7);
	}

	#[test]
	fn result_accepts_missing_jsonrpc_as_expected_version() {
		let result: u64 = response_with_version(None).result().unwrap();
		assert_eq!(result, 7);
	}

	#[test]
	fn result_rejects_wrong_jsonrpc_version() {
		let err = response_with_version(Some("1.0"))
			.result::<u64>()
			.unwrap_err();

		match err {
			Error::VersionMismatch => {}
			other => panic!("expected version mismatch, got {:?}", other),
		}
	}

	#[test]
	fn into_result_rejects_wrong_jsonrpc_version() {
		let err = response_with_version(Some("1.0"))
			.into_result::<u64>()
			.unwrap_err();

		match err {
			Error::VersionMismatch => {}
			other => panic!("expected version mismatch, got {:?}", other),
		}
	}

	#[test]
	fn result_returns_method_error_from_err_wrapper() {
		let response = Response {
			result: Some(serde_json::from_str(r#"{"Err":{"RequestError":"bad result"}}"#).unwrap()),
			error: None,
			id: serde_json::Value::from(1),
			jsonrpc: Some(String::from("2.0")),
		};

		let err = response.result::<Option<u64>>().unwrap_err();

		match err {
			Error::Method(msg) => {
				assert!(msg.contains("RequestError"), "{}", msg);
				assert!(msg.contains("bad result"), "{}", msg);
			}
			other => panic!("expected method error, got {:?}", other),
		}
	}

	#[test]
	fn result_rejects_object_without_ok_field() {
		let response = Response {
			result: Some(serde_json::from_str(r#"{"unexpected":null}"#).unwrap()),
			error: None,
			id: serde_json::Value::from(1),
			jsonrpc: Some(String::from("2.0")),
		};

		let err = response.result::<Option<u64>>().unwrap_err();

		assert_malformed_ok_field(err);
	}

	#[test]
	fn result_rejects_non_object_result() {
		let response = Response {
			result: Some(serde_json::Value::from(7)),
			error: None,
			id: serde_json::Value::from(1),
			jsonrpc: Some(String::from("2.0")),
		};

		let err = response.result::<Option<u64>>().unwrap_err();

		assert_malformed_ok_field(err);
	}

	#[test]
	fn result_rejects_missing_result_field() {
		let response: Response =
			serde_json::from_str(r#"{"error":null,"id":1,"jsonrpc":"2.0"}"#).unwrap();

		assert_malformed_ok_field(response.result::<Option<u64>>().unwrap_err());
		assert_malformed_ok_field(response.result::<()>().unwrap_err());
		assert_malformed_ok_field(response.result::<serde_json::Value>().unwrap_err());
	}

	#[test]
	fn result_rejects_null_result_field() {
		let response: Response =
			serde_json::from_str(r#"{"result":null,"error":null,"id":1,"jsonrpc":"2.0"}"#).unwrap();

		assert_malformed_ok_field(response.result::<Option<u64>>().unwrap_err());
		assert_malformed_ok_field(response.result::<()>().unwrap_err());
		assert_malformed_ok_field(response.result::<serde_json::Value>().unwrap_err());
	}
}
