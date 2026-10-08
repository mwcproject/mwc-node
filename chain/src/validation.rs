// Copyright 2026 The MWC Developers
// Licensed under the Apache License, Version 2.0.

//! Whole-chain validation completion, shared by context until reset or release.
//! Callers serialize validation and reset with the existing chain PMMR locks.
//! Normal block/header admission continues to validate every new block/header.
//! Rewinds and compaction preserve completion; replacing chain data clears it.

use crate::Error;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::log::info;
use mwc_crates::parking_lot::RwLock;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ValidationFlags {
	pub header_ancestry: bool,
	pub output_mmr: bool,
	pub rangeproof_mmr: bool,
	pub kernel_mmr: bool,
	pub roots: bool,
	pub sizes: bool,
	pub output_rangeproof_leaf_sets: bool,
	pub output_pos_index: bool,
	pub kernel_sums: bool,
	pub rangeproofs: bool,
	pub kernel_signatures: bool,
	pub kernel_history: bool,
	pub kernel_pos_index: bool,
}

lazy_static! {
	static ref CONTEXT_VALIDATIONS: RwLock<HashMap<u32, ValidationFlags>> =
		RwLock::new(HashMap::new());
}

pub(crate) fn get(context_id: u32) -> ValidationFlags {
	CONTEXT_VALIDATIONS
		.read()
		.get(&context_id)
		.copied()
		.unwrap_or_default()
}

pub(crate) fn reset(context_id: u32) {
	CONTEXT_VALIDATIONS
		.write()
		.insert(context_id, ValidationFlags::default());
}

/// Replacing bodies does not invalidate the retained, authenticated headers.
pub(crate) fn reset_body(context_id: u32) {
	if let Some(flags) = CONTEXT_VALIDATIONS.write().get_mut(&context_id) {
		*flags = ValidationFlags {
			header_ancestry: flags.header_ancestry,
			..ValidationFlags::default()
		};
	}
}

/// Explicit chain validation reruns only the checks performed by Extension::validate.
pub(crate) fn reset_txhashset(context_id: u32, fast_validation: bool) {
	if let Some(flags) = CONTEXT_VALIDATIONS.write().get_mut(&context_id) {
		*flags = ValidationFlags {
			header_ancestry: flags.header_ancestry,
			output_pos_index: flags.output_pos_index,
			kernel_history: flags.kernel_history,
			kernel_pos_index: flags.kernel_pos_index,
			rangeproofs: fast_validation && flags.rangeproofs,
			kernel_signatures: fast_validation && flags.kernel_signatures,
			..ValidationFlags::default()
		};
	}
}

pub(crate) fn release_context(context_id: u32) {
	CONTEXT_VALIDATIONS.write().remove(&context_id);
}

pub(crate) fn mark_done(context_id: u32, flag: fn(&mut ValidationFlags) -> &mut bool) {
	// A completed operation must not recreate a released context.
	if let Some(flags) = CONTEXT_VALIDATIONS.write().get_mut(&context_id) {
		*flag(flags) = true;
	}
}

/// The global lock is held only while reading/writing a boolean, never scanning.
pub(crate) fn run(
	context_id: u32,
	name: &str,
	flag: fn(&mut ValidationFlags) -> &mut bool,
	validate: impl FnOnce() -> Result<(), Error>,
) -> Result<(), Error> {
	if *flag(&mut get(context_id)) {
		info!("validation: {} already completed", name);
		return Ok(());
	}
	validate()?;
	mark_done(context_id, flag);
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn flags_are_independent_and_only_success_completes_a_check() {
		let id = 0;
		reset(id);
		run(id, "headers", |v| &mut v.header_ancestry, || Ok(())).unwrap();
		run(
			id,
			"headers",
			|v| &mut v.header_ancestry,
			|| panic!("repeated scan"),
		)
		.unwrap();
		assert!(!get(id).rangeproofs);
		assert!(run(id, "proofs", |v| &mut v.rangeproofs, || Err(Error::Stopped)).is_err());
		assert!(!get(id).rangeproofs);
		reset(id);
		assert_eq!(get(id), ValidationFlags::default());
		release_context(id);
	}

	#[test]
	fn contexts_are_independent_and_release_removes_flags() {
		let a = 0;
		let b = 1;
		reset(a);
		reset(b);
		mark_done(a, |v| &mut v.header_ancestry);
		mark_done(a, |v| &mut v.output_pos_index);
		mark_done(a, |v| &mut v.kernel_history);
		mark_done(a, |v| &mut v.kernel_pos_index);
		mark_done(a, |v| &mut v.kernel_sums);
		mark_done(a, |v| &mut v.rangeproofs);
		mark_done(a, |v| &mut v.kernel_signatures);
		assert_eq!(get(b), ValidationFlags::default());
		reset_txhashset(a, true);
		assert!(get(a).rangeproofs && get(a).kernel_signatures);
		assert!(!get(a).kernel_sums);
		reset_txhashset(a, false);
		assert_eq!(
			get(a),
			ValidationFlags {
				header_ancestry: true,
				output_pos_index: true,
				kernel_history: true,
				kernel_pos_index: true,
				..ValidationFlags::default()
			}
		);
		mark_done(a, |v| &mut v.kernel_sums);
		reset_body(a);
		assert!(get(a).header_ancestry);
		assert!(!get(a).kernel_sums);
		release_context(a);
		mark_done(a, |v| &mut v.header_ancestry);
		assert!(!CONTEXT_VALIDATIONS.read().contains_key(&a));
		reset(a);
		assert_eq!(get(a), ValidationFlags::default());
		release_context(a);
		release_context(b);
	}
}
