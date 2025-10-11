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

use crate::core::global;
use crate::rest::Error;
use crate::util::to_base64;
use serde_json::Value;
use std::time::Duration;

#[derive(Clone)]
pub struct HttpClient {
	agent: ureq::Agent,
	api_secret: Option<String>,
	context_id: u32,
}

impl HttpClient {
	pub fn new(context_id: u32, timeout: Duration, api_secret: Option<String>) -> Self {
		let config = ureq::Agent::config_builder()
			.timeout_global(Some(timeout))
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

		debug!("Building http POST request to {}, Body: {}", url, req_body);

		let mut builder = self
			.agent
			.post(url)
			.header("user-agent", "mwc-client")
			.header("accept", "application/json")
			.header("content-type", "application/json");

		if let Some(basic_auth) = self.build_basic_auth_value() {
			builder = builder.header("authorization", basic_auth);
		}

		let mut resp = builder.send(&request).map_err(|e| {
			Error::Internal(format!("Fails to make post request to {}, {}", url, e))
		})?;

		let response_str = resp
			.body_mut()
			.read_to_string()
			.map_err(|e| Error::Internal(format!("Fails to read response from {}, {}", url, e)))?;

		debug!("Got response: {}", response_str);

		let res: Value = serde_json::from_str(&response_str).map_err(|e| {
			Error::Internal(format!(
				"Invalid response from {}, Response: {}, Error: {}",
				url, response_str, e
			))
		})?;
		Ok(res)
	}

	pub fn get(&self, url: &str) -> Result<Value, Error> {
		debug!("Building http Get request to {}", url);

		let mut builder = self
			.agent
			.get(url)
			.header("user-agent", "mwc-client")
			.header("accept", "application/json")
			.header("content-type", "application/json");

		if let Some(basic_auth) = self.build_basic_auth_value() {
			builder = builder.header("authorization", basic_auth);
		}

		let mut resp = builder
			.call()
			.map_err(|e| Error::Internal(format!("Fails to make get request to {}, {}", url, e)))?;

		let response_str = resp
			.body_mut()
			.read_to_string()
			.map_err(|e| Error::Internal(format!("Fails to read response from {}, {}", url, e)))?;

		debug!("Got response: {}", response_str);

		let res: Value = serde_json::from_str(&response_str).map_err(|e| {
			Error::Internal(format!(
				"Invalid response from {}, Response: {}, Error: {}",
				url, response_str, e
			))
		})?;
		Ok(res)
	}

	fn build_basic_auth_value(&self) -> Option<String> {
		match &self.api_secret {
			Some(api_secret) => {
				let basic_auth_key = if global::is_mainnet(self.context_id) {
					"mwcmain"
				} else if global::is_floonet(self.context_id) {
					"mwcfloo"
				} else {
					"mwc"
				};

				let basic_auth = format!(
					"Basic {}",
					to_base64(&format!("{}:{}", basic_auth_key, api_secret))
				);
				Some(basic_auth)
			}
			None => None,
		}
	}
}
