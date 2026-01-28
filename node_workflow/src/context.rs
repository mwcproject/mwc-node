// Copyright 2025 The MWC Developers
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

// Context ids management. Add Context clean up calls here

use crate::Error;
use lazy_static::lazy_static;
use mwc_core::global;
use mwc_core::global::ChainTypes;
use mwc_p2p::tor::arti;
use std::sync::RwLock;

lazy_static! {
	/// Global chain status flags. It is expected that init call will set them first for every needed context
	/// Note, both node and wallet will need to set it up. Any param can be set once
	static ref USED_CONTEXTS: RwLock<u64> = RwLock::new(0);
}

/// Generate a new context Id
pub fn allocate_new_context(
	chain_type: ChainTypes,
	accept_fee_base: Option<u64>,
	nrd_feature_enabled: Option<bool>,
) -> Result<u32, Error> {
	let mut contexts = USED_CONTEXTS.write().unwrap_or_else(|e| e.into_inner());

	for c_id in 1..64 {
		let mask = 1u64 << c_id;
		if *contexts & mask == 0 {
			*contexts |= mask;

			// initializing the context
			mwc_core::global::init_global_chain_type(c_id, chain_type);
			mwc_core::global::init_global_accept_fee_base(
				c_id,
				accept_fee_base.unwrap_or(mwc_core::global::DEFAULT_ACCEPT_FEE_BASE),
			);

			arti::init_arti_cancelling(c_id);

			let nrd_feature_enabled = match nrd_feature_enabled {
				Some(enabled) => enabled,
				None => {
					match chain_type {
						global::ChainTypes::Mainnet => {
							// Set various mainnet specific feature flags.
							false
						}
						_ => {
							// Set various non-mainnet feature flags.
							true
						}
					}
				}
			};
			global::init_global_nrd_enabled(c_id, nrd_feature_enabled);

			info!("Context id {} is created", c_id);
			return Ok(c_id);
		}
	}
	Err(Error::ContextError(
		"Not found free context slot. Did you deleted unused contexts?".into(),
	))
}

/// Release app context
pub fn release_context(context_id: u32) -> Result<(), Error> {
	info!("Releasing context id {}", context_id);
	arti::release_arti_cancelling(context_id);
	let mut contexts = USED_CONTEXTS.write().unwrap_or_else(|e| e.into_inner());
	let mask = 1u64 << context_id;
	if *contexts & mask == 0 {
		return Err(Error::ContextError(format!(
			"Context id {} doesn't exist",
			context_id
		)));
	}

	*contexts ^= mask;

	crate::server::release_server(context_id);
	mwc_core::global::release_context_data(context_id);
	mwc_chain::pipe::release_context_data(context_id);

	Ok(())
}
