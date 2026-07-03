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
use mwc_core::global;
use mwc_core::global::ChainTypes;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::log::info;
use mwc_crates::parking_lot::RwLock;
use mwc_p2p::tor::arti;
use std::sync::atomic::{AtomicU32, Ordering};

const MIN_CONTEXT_ID: u32 = 1;
const MAX_CONTEXT_ID: u32 = 60;
const CONTEXT_ID_COUNT: u32 = MAX_CONTEXT_ID - MIN_CONTEXT_ID + 1;

lazy_static! {
	/// Context lifecycle flags.
	/// `reserved` keeps ids unavailable while allocation or release is in progress.
	/// `ready` contains fully initialized ids that can be released.
	static ref CONTEXTS: RwLock<ContextRegistry> = RwLock::new(ContextRegistry::default());
	/// Context id index. We don't want to reuse imediatelly. Let's have some cooling down time instead.
	static ref CURRENT_CONTEXT_IDX: AtomicU32 = AtomicU32::new(0);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ContextRegistry {
	reserved: u64,
	ready: u64,
}

struct ReservedContext {
	context_id: u32,
	committed: bool,
}

impl ReservedContext {
	fn new(context_id: u32) -> Self {
		ReservedContext {
			context_id,
			committed: false,
		}
	}

	fn commit(mut self) -> Result<(), Error> {
		commit_context_allocation(self.context_id)?;
		self.committed = true;
		Ok(())
	}
}

impl Drop for ReservedContext {
	fn drop(&mut self) {
		if !self.committed {
			rollback_context_allocation(self.context_id);
		}
	}
}

fn reserve_context_id() -> Option<u32> {
	for _ in 1..64 {
		let c_id =
			MIN_CONTEXT_ID + CURRENT_CONTEXT_IDX.fetch_add(1, Ordering::Relaxed) % CONTEXT_ID_COUNT;
		let mask = context_mask(c_id)?;
		let mut contexts = CONTEXTS.write();
		if (contexts.reserved | contexts.ready) & mask == 0 {
			contexts.reserved |= mask;
			return Some(c_id);
		}
	}
	None
}

fn context_mask(context_id: u32) -> Option<u64> {
	if !(MIN_CONTEXT_ID..=MAX_CONTEXT_ID).contains(&context_id) {
		return None;
	}

	1u64.checked_shl(context_id)
}

fn rollback_context_allocation(context_id: u32) {
	let Some(mask) = context_mask(context_id) else {
		return;
	};

	arti::release_arti_cancelling(context_id);
	mwc_core::global::release_context_data(context_id);
	mwc_chain::pipe::release_context_data(context_id);

	let mut contexts = CONTEXTS.write();
	contexts.reserved &= !mask;
}

fn commit_context_allocation(context_id: u32) -> Result<(), Error> {
	let mask = context_mask(context_id).ok_or_else(|| {
		Error::ContextError(format!(
			"Invalid context id {}. Expected {}..={}",
			context_id, MIN_CONTEXT_ID, MAX_CONTEXT_ID
		))
	})?;

	let mut contexts = CONTEXTS.write();
	if contexts.reserved & mask == 0 {
		return Err(Error::ContextError(format!(
			"Context id {} is not reserved",
			context_id
		)));
	}

	contexts.reserved &= !mask;
	contexts.ready |= mask;
	Ok(())
}

/// Return the chain type for an allocated context.
pub fn get_chain_type(context_id: u32) -> Result<ChainTypes, Error> {
	let mask = context_mask(context_id).ok_or_else(|| {
		Error::ContextError(format!(
			"Invalid context id {}. Expected {}..={}",
			context_id, MIN_CONTEXT_ID, MAX_CONTEXT_ID
		))
	})?;

	let contexts = CONTEXTS.read();
	if contexts.ready & mask == 0 {
		return Err(Error::ContextError(format!(
			"Context id {} doesn't exist",
			context_id
		)));
	}

	Ok(global::get_chain_type(context_id))
}

/// Generate a new context Id
pub fn allocate_new_context(
	chain_type: ChainTypes,
	accept_fee_base: Option<u64>,
	nrd_feature_enabled: Option<bool>,
) -> Result<u32, Error> {
	let c_id = reserve_context_id().ok_or_else(|| {
		Error::ContextError("Not found free context slot. Did you deleted unused contexts?".into())
	})?;
	let reserved_context = ReservedContext::new(c_id);

	// initializing the context
	mwc_core::global::init_global_chain_type(c_id, chain_type)
		.map_err(|e| Error::ContextError(e.to_string()))?;
	mwc_core::global::init_global_accept_fee_base(
		c_id,
		accept_fee_base.unwrap_or(mwc_core::global::DEFAULT_ACCEPT_FEE_BASE),
	)
	.map_err(|e| Error::ContextError(e.to_string()))?;

	arti::init_arti_cancelling(c_id);

	let nrd_feature_enabled = match nrd_feature_enabled {
		Some(enabled) => enabled,
		None => match chain_type {
			global::ChainTypes::Mainnet => {
				// Set various mainnet specific feature flags.
				false
			}
			_ => {
				// Set various non-mainnet feature flags.
				true
			}
		},
	};
	global::init_global_nrd_enabled(c_id, nrd_feature_enabled)
		.map_err(|e| Error::ContextError(e.to_string()))?;

	mwc_util::init_global_runtime()
		.map_err(|e| Error::ContextError(format!("Unable initialize global runtime, {}", e)))?;

	reserved_context.commit()?;
	info!("Context id {} is created", c_id);
	Ok(c_id)
}

/// Release app context
pub fn release_context(context_id: u32) -> Result<(), Error> {
	let mask = context_mask(context_id).ok_or_else(|| {
		Error::ContextError(format!(
			"Invalid context id {}. Expected {}..={}",
			context_id, MIN_CONTEXT_ID, MAX_CONTEXT_ID
		))
	})?;

	info!("Releasing context id {}", context_id);
	{
		let mut contexts = CONTEXTS.write();
		if contexts.ready & mask == 0 {
			return Err(Error::ContextError(format!(
				"Context id {} doesn't exist",
				context_id
			)));
		}

		contexts.ready &= !mask;
		contexts.reserved |= mask;
	}

	arti::release_arti_cancelling(context_id);
	crate::server::release_server(context_id);
	mwc_core::global::release_context_data(context_id);
	mwc_chain::pipe::release_context_data(context_id);

	let mut contexts = CONTEXTS.write();
	contexts.reserved &= !mask;

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Mutex;

	static CONTEXT_TEST_LOCK: Mutex<()> = Mutex::new(());

	#[test]
	fn failed_allocation_releases_reserved_context() {
		let _guard = CONTEXT_TEST_LOCK.lock().unwrap();
		let contexts_before = *CONTEXTS.read();

		for _ in 0..64 {
			let res = allocate_new_context(ChainTypes::AutomatedTesting, Some(0), Some(true));
			assert!(res.is_err());
			assert_eq!(*CONTEXTS.read(), contexts_before);
		}

		let context_id = allocate_new_context(
			ChainTypes::AutomatedTesting,
			Some(global::DEFAULT_ACCEPT_FEE_BASE),
			Some(true),
		)
		.unwrap();

		release_context(context_id).unwrap();
		assert_eq!(*CONTEXTS.read(), contexts_before);
	}

	#[test]
	fn release_context_rejects_reserved_context_id() {
		let _guard = CONTEXT_TEST_LOCK.lock().unwrap();
		let contexts_before = *CONTEXTS.read();
		let context_id = reserve_context_id().unwrap();
		let reserved_context = ReservedContext::new(context_id);
		let mask = context_mask(context_id).unwrap();
		let contexts_with_reservation = *CONTEXTS.read();

		assert!(contexts_with_reservation.reserved & mask != 0);
		assert_eq!(contexts_with_reservation.ready & mask, 0);

		let res = release_context(context_id);
		assert!(res.is_err());
		assert_eq!(*CONTEXTS.read(), contexts_with_reservation);

		drop(reserved_context);
		assert_eq!(*CONTEXTS.read(), contexts_before);
	}

	#[test]
	fn release_context_rejects_out_of_range_ids() {
		let _guard = CONTEXT_TEST_LOCK.lock().unwrap();
		let context_id = allocate_new_context(
			ChainTypes::AutomatedTesting,
			Some(global::DEFAULT_ACCEPT_FEE_BASE),
			Some(true),
		)
		.unwrap();
		let contexts_with_context = *CONTEXTS.read();

		for invalid_context_id in [0, MAX_CONTEXT_ID + 1, 64, 65, u32::MAX] {
			let res = release_context(invalid_context_id);
			assert!(res.is_err());
			assert_eq!(*CONTEXTS.read(), contexts_with_context);
		}

		release_context(context_id).unwrap();
	}

	#[test]
	fn get_chain_type_checks_context_lifecycle() {
		let _guard = CONTEXT_TEST_LOCK.lock().unwrap();
		let contexts_before = *CONTEXTS.read();
		let context_id = allocate_new_context(
			ChainTypes::AutomatedTesting,
			Some(global::DEFAULT_ACCEPT_FEE_BASE),
			Some(true),
		)
		.unwrap();

		assert_eq!(
			get_chain_type(context_id).unwrap(),
			ChainTypes::AutomatedTesting
		);

		release_context(context_id).unwrap();
		assert!(get_chain_type(context_id).is_err());
		assert_eq!(*CONTEXTS.read(), contexts_before);
	}
}
