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

//! Thread-local secp256k1 contexts to avoid repeated initialization overhead
//! without sharing a context across threads.

use mwc_crates::log::debug;
use mwc_crates::secp;
use mwc_crates::secp::constants;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use std::cell::RefCell;
use std::thread::LocalKey;

type CachedContext = RefCell<Result<Secp256k1, secp::Error>>;

thread_local! {
	static SECP_NONE: CachedContext = RefCell::new(Secp256k1::without_caps());
	static SECP_FULL: CachedContext = RefCell::new(Secp256k1::with_caps(ContextFlag::Full));
	static SECP_VERIFY_ONLY: CachedContext =
		RefCell::new(Secp256k1::with_caps(ContextFlag::VerifyOnly));
	static SECP_COMMIT: CachedContext = RefCell::new(Secp256k1::with_caps(ContextFlag::Commit));
}

fn create_context(caps: ContextFlag) -> Result<Secp256k1, secp::Error> {
	match caps {
		ContextFlag::None => Secp256k1::without_caps(),
		caps => Secp256k1::with_caps(caps),
	}
}

fn with_context<T, E, F, M>(
	context: &'static LocalKey<CachedContext>,
	caps: ContextFlag,
	map_context_error: M,
	f: F,
) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	context.with(|context| match context.try_borrow() {
		Ok(cached) => match &*cached {
			Ok(secp) => f(secp),
			Err(e) => Err(map_context_error(*e)),
		},
		Err(e) => {
			debug!(
				"Thread-local secp256k1 {:?} context is already mutably borrowed; using temporary context: {}",
				caps, e
			);
			let secp = create_context(caps).map_err(map_context_error)?;
			f(&secp)
		}
	})
}

fn with_context_mut<T, E, F, M>(
	context: &'static LocalKey<CachedContext>,
	caps: ContextFlag,
	map_context_error: M,
	f: F,
) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	context.with(|context| match context.try_borrow_mut() {
		Ok(mut cached) => match &mut *cached {
			Ok(secp) => f(secp),
			Err(e) => Err(map_context_error(*e)),
		},
		Err(e) => {
			debug!(
				"Thread-local secp256k1 {:?} context is already borrowed; using temporary context: {}",
				caps, e
			);
			let mut secp = create_context(caps).map_err(map_context_error)?;
			f(&mut secp)
		}
	})
}

/// Uses this thread's cached context with no secp256k1 capabilities.
pub fn with_none<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context(&SECP_NONE, ContextFlag::None, map_context_error, f)
}

/// Uses this thread's cached mutable context with no secp256k1 capabilities.
pub fn with_none_mut<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context_mut(&SECP_NONE, ContextFlag::None, map_context_error, f)
}

/// Uses this thread's cached full secp256k1 context.
pub fn with_full<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context(&SECP_FULL, ContextFlag::Full, map_context_error, f)
}

/// Uses this thread's cached mutable full secp256k1 context.
pub fn with_full_mut<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context_mut(&SECP_FULL, ContextFlag::Full, map_context_error, f)
}

/// Uses this thread's cached verify-only secp256k1 context.
pub fn with_verify_only<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context(
		&SECP_VERIFY_ONLY,
		ContextFlag::VerifyOnly,
		map_context_error,
		f,
	)
}

/// Uses this thread's cached mutable verify-only secp256k1 context.
pub fn with_verify_only_mut<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context_mut(
		&SECP_VERIFY_ONLY,
		ContextFlag::VerifyOnly,
		map_context_error,
		f,
	)
}

/// Uses this thread's cached commitment-capable secp256k1 context.
pub fn with_commit<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context(&SECP_COMMIT, ContextFlag::Commit, map_context_error, f)
}

/// Uses this thread's cached mutable commitment-capable secp256k1 context.
pub fn with_commit_mut<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context_mut(&SECP_COMMIT, ContextFlag::Commit, map_context_error, f)
}

/// Convenient way to generate a commitment to zero.
pub fn commit_to_zero_value() -> secp::pedersen::Commitment {
	// Unwrap is safe because it build form the constant
	secp::pedersen::Commitment::from_vec(vec![0u8; constants::PEDERSEN_COMMITMENT_SIZE]).unwrap()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reentrant_access_uses_temporary_context() {
		let res = with_commit_mut(
			|e| e,
			|_secp| {
				with_commit(|e| e, |_nested| Ok(()))?;
				with_commit_mut(|e| e, |_nested| Ok(()))?;
				Ok(())
			},
		);
		assert!(res.is_ok());
	}
}
