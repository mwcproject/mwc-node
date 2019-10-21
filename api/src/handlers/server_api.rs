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

use super::utils::w;
use crate::chain;
use crate::p2p;
use crate::rest::*;
use crate::router::{Handler, ResponseFuture};
use crate::types::*;
use crate::web::*;
use hyper::{Body, Request, StatusCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

// RESTful index of available api endpoints
// GET /v1/
pub struct IndexHandler {
	pub list: Vec<String>,
}

impl IndexHandler {}

impl Handler for IndexHandler {
	fn get(&self, _req: Request<Body>) -> ResponseFuture {
		json_response_pretty(&self.list)
	}
}

pub struct KernelDownloadHandler {
	pub peers: Weak<p2p::Peers>,
}

impl Handler for KernelDownloadHandler {
	fn post(&self, _req: Request<Body>) -> ResponseFuture {
		if let Some(peer) = w_fut!(&self.peers).most_work_peer() {
			match peer.send_kernel_data_request() {
				Ok(_) => response(StatusCode::OK, "{}"),
				Err(e) => response(
					StatusCode::INTERNAL_SERVER_ERROR,
					format!("requesting kernel data from peer failed: {:?}", e),
				),
			}
		} else {
			response(
				StatusCode::INTERNAL_SERVER_ERROR,
				format!("requesting kernel data from peer failed (no peers)"),
			)
		}
	}
}

/// Status handler. Post a summary of the server status
/// GET /v1/status
pub struct StatusHandler {
	pub chain: Weak<chain::Chain>,
	pub peers: Weak<p2p::Peers>,
	pub server_running: Arc<AtomicBool>,
}

impl StatusHandler {
	fn get_status(&self) -> Result<Status, Error> {
		let head = w(&self.chain)?
			.head()
			.map_err(|e| ErrorKind::Internal(format!("can't get head: {}", e)))?;
		Ok(Status::from_tip_and_peers(
			head,
			w(&self.peers)?.peer_count(),
		))
	}
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StatusOutput {
	// Processed actions
	pub processed: Vec<String>,
}

impl StatusOutput {
	pub fn new(processed: &Vec<String>) -> StatusOutput {
		StatusOutput {
			processed: processed.clone(),
		}
	}
}

impl Handler for StatusHandler {
	fn get(&self, _req: Request<Body>) -> ResponseFuture {
		result_to_response(self.get_status())
	}

	fn post(&self, req: Request<Body>) -> ResponseFuture {
		if let Some(query) = req.uri().query() {
			let mut commitments: Vec<String> = vec![];

			let params = QueryParams::from(query);
			params.process_multival_param("action", |id| commitments.push(id.to_owned()));

			let mut processed = vec![];
			for action_str in commitments {
				if action_str == "stop_node" {
					warn!("Stopping the node by API request...");
					processed.push(action_str);
					self.server_running.store(false, Ordering::SeqCst);
				}
			}

			// stop the server...
			result_to_response(Ok(StatusOutput::new(&processed)))
		} else {
			response(
				StatusCode::BAD_REQUEST,
				format!("Expected 'action' parameter at request"),
			)
		}
	}
}
