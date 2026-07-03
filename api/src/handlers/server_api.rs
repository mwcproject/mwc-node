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

use super::utils::w;
use crate::rest::*;
use crate::router::{Handler, ResponseFuture};
use crate::types::*;
use crate::web::*;
use mwc_chain::{Chain, SyncState, SyncStatus};
use mwc_crates::bytes::Bytes;
use mwc_crates::hyper::Request;
use mwc_crates::serde_json;
use mwc_crates::serde_json::json;
use std::convert::TryInto;
use std::sync::Weak;

// RESTful index of available api endpoints
// GET /v1/
pub struct IndexHandler {
	pub list: Vec<String>,
}

impl IndexHandler {}

impl Handler for IndexHandler {
	fn get(&self, _req: Request<Bytes>) -> ResponseFuture {
		json_response_pretty(&self.list)
	}
}

/// Status handler. Post a summary of the server status
/// GET /v1/status
pub struct StatusHandler {
	pub chain: Weak<Chain>,
	pub peers: Weak<mwc_p2p::Peers>,
	pub sync_state: Weak<SyncState>,
}

impl StatusHandler {
	pub fn get_status(&self) -> Result<Status, Error> {
		let head = w(&self.chain)?
			.head()
			.map_err(|e| Error::Internal(format!("Unable to get chain tip, {}", e)))?;
		let sync_status = w(&self.sync_state)?.status();
		let (api_sync_status, api_sync_info) = sync_status_to_api(sync_status);
		Ok(Status::from_tip_and_peers(
			head,
			w(&self.peers)?
				.iter()
				.connected()
				.count()
				.try_into()
				.map_err(|e| Error::Internal(format!("Failed to get peer cound value, {}", e)))?,
			api_sync_status,
			api_sync_info,
		))
	}
}

impl Handler for StatusHandler {
	fn get(&self, _req: Request<Bytes>) -> ResponseFuture {
		result_to_response(self.get_status())
	}
}

/// Convert a SyncStatus in a readable API representation
fn sync_status_to_api(sync_status: SyncStatus) -> (String, Option<serde_json::Value>) {
	match sync_status {
		SyncStatus::Initial => ("initial".to_string(), None),
		SyncStatus::NoSync => ("no_sync".to_string(), None),
		SyncStatus::AwaitingPeers => ("awaiting_peers".to_string(), None),
		SyncStatus::HeaderHashSync {
			completed_blocks,
			total_blocks,
		} => (
			"header_hash_sync".to_string(),
			Some(json!({ "completed_blocks": completed_blocks, "total_blocks": total_blocks })),
		),
		SyncStatus::HeaderSync {
			current_height,
			archive_height,
			..
		} => (
			"header_sync".to_string(),
			Some(json!({ "current_height": current_height, "highest_height": archive_height })),
		),
		SyncStatus::ValidatingKernelsHistory {
			headers,
			headers_total,
		} => (
			"validating_kernels_history".to_string(),
			Some(json!({ "headers": headers, "headers_total": headers_total })),
		),
		SyncStatus::TxHashsetKernelsPosValidation {
			kernel_pos,
			kernel_pos_total,
		} => (
			"txhashset_kernels_pos_validation".to_string(),
			Some(json!({ "kernel_pos": kernel_pos, "kernel_pos_total": kernel_pos_total })),
		),
		SyncStatus::TxHashsetPibd {
			recieved_segments,
			total_segments,
		} => (
			"txhashset_pibd".to_string(),
			Some(
				json!({ "recieved_segments": recieved_segments, "total_segments": total_segments }),
			),
		),
		SyncStatus::TxHashsetOutputPosIndexBuild {
			outputs,
			outputs_total,
		} => (
			"txhashset_output_pos_index_build".to_string(),
			Some(json!({ "outputs": outputs, "outputs_total": outputs_total })),
		),
		SyncStatus::TxHashsetKernelPosIndexBuild {
			kernels,
			kernels_total,
		} => (
			"txhashset_kernel_pos_index_build".to_string(),
			Some(json!({ "kernels": kernels, "kernels_total": kernels_total })),
		),
		SyncStatus::TxHashsetStateValidation {
			stage,
			current,
			total,
		} => (
			"txhashset_state_validation".to_string(),
			Some(json!({
				"stage": stage.api_name(),
				"current": current,
				"total": total,
			})),
		),
		SyncStatus::TxHashsetRangeProofsValidation {
			rproofs,
			rproofs_total,
		} => (
			"txhashset_rangeproofs_validation".to_string(),
			Some(json!({ "rproofs": rproofs, "rproofs_total": rproofs_total })),
		),
		SyncStatus::TxHashsetKernelsValidation {
			kernels,
			kernels_total,
		} => (
			"txhashset_kernels_validation".to_string(),
			Some(json!({ "kernels": kernels, "kernels_total": kernels_total })),
		),
		SyncStatus::BodySync {
			archive_height,
			current_height,
			highest_height,
		} => (
			"body_sync".to_string(),
			Some(
				json!({ "archive_height":archive_height, "current_height": current_height, "highest_height": highest_height }),
			),
		),
		SyncStatus::Shutdown => ("shutdown".to_string(), None),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sync_status_to_api_maps_active_progress_states() {
		let cases = [
			(SyncStatus::Initial, "initial", None),
			(
				SyncStatus::HeaderHashSync {
					completed_blocks: 2,
					total_blocks: 5,
				},
				"header_hash_sync",
				Some(json!({ "completed_blocks": 2, "total_blocks": 5 })),
			),
			(
				SyncStatus::TxHashsetPibd {
					recieved_segments: 3,
					total_segments: 7,
				},
				"txhashset_pibd",
				Some(json!({ "recieved_segments": 3, "total_segments": 7 })),
			),
			(
				SyncStatus::TxHashsetOutputPosIndexBuild {
					outputs: 11,
					outputs_total: 13,
				},
				"txhashset_output_pos_index_build",
				Some(json!({ "outputs": 11, "outputs_total": 13 })),
			),
			(
				SyncStatus::TxHashsetKernelPosIndexBuild {
					kernels: 17,
					kernels_total: 19,
				},
				"txhashset_kernel_pos_index_build",
				Some(json!({ "kernels": 17, "kernels_total": 19 })),
			),
		];

		for (sync_status, expected_status, expected_info) in cases {
			let (api_status, api_info) = sync_status_to_api(sync_status);

			assert_eq!(api_status, expected_status);
			assert_eq!(api_info, expected_info);
		}
	}
}
