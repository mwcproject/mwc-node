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

//! High level JSON/HTTP client API

use crate::auth::build_basic_auth_header_value;
use crate::rest::Error;
use mwc_core::global;
use mwc_crates::serde_json;
use mwc_crates::serde_json::Value;
use mwc_crates::ureq;
use mwc_crates::zeroize::Zeroizing;
use std::time::Duration;

#[derive(Clone)]
pub struct HttpClient {
	agent: ureq::Agent,
	api_secret: Option<Zeroizing<String>>,
	context_id: u32,
}

impl HttpClient {
	pub fn new(context_id: u32, timeout: Duration, api_secret: Option<Zeroizing<String>>) -> Self {
		let config = ureq::Agent::config_builder()
			.timeout_global(Some(timeout))
			.proxy(None)
			.build();
		HttpClient {
			agent: config.into(),
			api_secret,
			context_id,
		}
	}

	pub fn post_request(&self, url: &str, req_body: &Value) -> Result<Value, Error> {
		let request = serde_json::to_string(req_body).map_err(|e| {
			Error::Internal(format!("Post Request, Can't serialize data to JSON, {}", e))
		})?;

		//debug!("Building http POST request to {}, Body: {}", url, req_body);

		let mut builder = self
			.agent
			.post(url)
			.header("user-agent", "mwc-client")
			.header("accept", "application/json")
			.header("content-type", "application/json");

		// Do not force a specific protocol here: callers may use local or otherwise
		// secured transports, and deployments are responsible for choosing an
		// endpoint that is secure enough when api_secret is configured.
		if let Some(basic_auth) = self.build_basic_auth_value() {
			builder = builder.header("authorization", basic_auth.as_str());
		}

		let mut resp = builder.send(&request).map_err(|e| {
			Error::Internal(format!("Fails to make post request to {}, {}", url, e))
		})?;

		let response = resp
			.body_mut()
			.read_to_vec()
			.map_err(|e| Error::Internal(format!("Fails to read response from {}, {}", url, e)))?;

		let response_str = std::str::from_utf8(&response).unwrap_or("<non-UTF8 response>");
		//debug!("Got response: {}", response_str);

		let res: Value = serde_json::from_slice(&response).map_err(|e| {
			// Note, in case of error we want to reveal url and response_str. Even it can leak some data
			// into the logs, it is needed for debugging.
			Error::Internal(format!(
				"Invalid response from {}, Response: {}, Error: {}",
				url, response_str, e
			))
		})?;
		Ok(res)
	}

	pub fn get(&self, url: &str) -> Result<Value, Error> {
		//debug!("Building http Get request to {}", url);

		let mut builder = self
			.agent
			.get(url)
			.header("user-agent", "mwc-client")
			.header("accept", "application/json")
			.header("content-type", "application/json");

		// Do not force a specific protocol here: callers may use local or otherwise
		// secured transports, and deployments are responsible for choosing an
		// endpoint that is secure enough when api_secret is configured.
		if let Some(basic_auth) = self.build_basic_auth_value() {
			builder = builder.header("authorization", basic_auth.as_str());
		}

		let mut resp = builder
			.call()
			.map_err(|e| Error::Internal(format!("Fails to make get request to {}, {}", url, e)))?;

		let response = resp
			.body_mut()
			.read_to_vec()
			.map_err(|e| Error::Internal(format!("Fails to read response from {}, {}", url, e)))?;

		let response_str = std::str::from_utf8(&response).unwrap_or("<non-UTF8 response>");
		//debug!("Got response: {}", response_str);

		let res: Value = serde_json::from_slice(&response).map_err(|e| {
			// Note, even url and response_str can provide some info, but it is not expecte dto have any
			// sensitive information at node interaction. In this case url and response_str data
			// is valuable for debugging
			Error::Internal(format!(
				"Invalid response from {}, Response: {}, Error: {}",
				url, response_str, e
			))
		})?;
		Ok(res)
	}

	fn build_basic_auth_value(&self) -> Option<Zeroizing<String>> {
		match &self.api_secret {
			Some(api_secret) => {
				let basic_auth_key = if global::is_mainnet(self.context_id) {
					"mwcmain"
				} else if global::is_floonet(self.context_id) {
					"mwcfloo"
				} else {
					"mwc"
				};

				Some(build_basic_auth_header_value(basic_auth_key, api_secret))
			}
			None => None,
		}
	}
}
