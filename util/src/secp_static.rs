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

//! Thread-local secp256k1 context pools to avoid repeated initialization overhead
//! without sharing a context across threads. Each pool grows on demand when a
//! call recursively requests another context and retains that context for reuse.

use mwc_crates::log::warn;
use mwc_crates::secp;
use mwc_crates::secp::constants;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::thread::LocalKey;

type CachedContext = Result<Secp256k1, secp::Error>;
type CachedContextSlot = Rc<RefCell<CachedContext>>;

struct ContextPool {
	caps: ContextFlag,
	contexts: RefCell<Vec<CachedContextSlot>>,
	active: Cell<usize>,
}

impl ContextPool {
	fn new(caps: ContextFlag) -> Self {
		Self {
			caps,
			contexts: RefCell::new(Vec::new()),
			active: Cell::new(0),
		}
	}

	/// Acquires the context for the current recursion depth, creating it if this
	/// thread has not reached that depth before.
	fn acquire(&self) -> (CachedContextSlot, ContextLease<'_>) {
		let index = self.active.get();
		// Checked arithmetic is unnecessary here: `index` is the number of live
		// recursive calls on this thread. The thread would exhaust its stack long
		// before reaching `usize::MAX`; normally this pool contains only a few contexts.
		let depth = index + 1;
		let (context, grew) = {
			let mut contexts = self.contexts.borrow_mut();
			let grew = index == contexts.len();
			if grew {
				contexts.push(Rc::new(RefCell::new(create_context(self.caps))));
			}
			(Rc::clone(&contexts[index]), grew)
		};

		self.active.set(depth);
		let lease = ContextLease {
			active: &self.active,
		};
		if grew && index >= 4 {
			warn!(
				"Thread-local secp256k1 {:?} context pool at recursion depth {}",
				self.caps, depth
			);
		}
		(context, lease)
	}
}

struct ContextLease<'a> {
	active: &'a Cell<usize>,
}

impl Drop for ContextLease<'_> {
	fn drop(&mut self) {
		let active = self.active.get();
		debug_assert!(active > 0);
		self.active.set(active - 1);
	}
}

thread_local! {
	static SECP_NONE: ContextPool = ContextPool::new(ContextFlag::None);
	static SECP_FULL: ContextPool = ContextPool::new(ContextFlag::Full);
	static SECP_VERIFY_ONLY: ContextPool = ContextPool::new(ContextFlag::VerifyOnly);
	static SECP_COMMIT: ContextPool = ContextPool::new(ContextFlag::Commit);
}

fn create_context(caps: ContextFlag) -> Result<Secp256k1, secp::Error> {
	match caps {
		ContextFlag::None => Secp256k1::without_caps(),
		caps => Secp256k1::with_caps(caps),
	}
}

fn use_context<T, E, F, M>(cached: &CachedContext, map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	match cached {
		Ok(secp) => f(secp),
		Err(e) => Err(map_context_error(*e)),
	}
}

fn with_context<T, E, F, M>(
	context: &'static LocalKey<ContextPool>,
	map_context_error: M,
	f: F,
) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	context.with(|pool| {
		let (context, _lease) = pool.acquire();
		let cached = context.borrow();
		use_context(&cached, map_context_error, f)
	})
}

fn with_context_mut<T, E, F, M>(
	context: &'static LocalKey<ContextPool>,
	map_context_error: M,
	f: F,
) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	context.with(|pool| {
		let (context, _lease) = pool.acquire();
		let mut cached = context.borrow_mut();
		match &mut *cached {
			Ok(secp) => f(secp),
			Err(e) => Err(map_context_error(*e)),
		}
	})
}

/// Uses this thread's cached context with no secp256k1 capabilities.
pub fn with_none<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context(&SECP_NONE, map_context_error, f)
}

/// Uses this thread's cached mutable context with no secp256k1 capabilities.
pub fn with_none_mut<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context_mut(&SECP_NONE, map_context_error, f)
}

/// Uses this thread's cached full secp256k1 context.
pub fn with_full<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context(&SECP_FULL, map_context_error, f)
}

/// Uses this thread's cached mutable full secp256k1 context.
pub fn with_full_mut<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context_mut(&SECP_FULL, map_context_error, f)
}

/// Uses this thread's cached verify-only secp256k1 context.
pub fn with_verify_only<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context(&SECP_VERIFY_ONLY, map_context_error, f)
}

/// Uses this thread's cached mutable verify-only secp256k1 context.
pub fn with_verify_only_mut<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context_mut(&SECP_VERIFY_ONLY, map_context_error, f)
}

/// Uses this thread's cached commitment-capable secp256k1 context.
pub fn with_commit<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context(&SECP_COMMIT, map_context_error, f)
}

/// Uses this thread's cached mutable commitment-capable secp256k1 context.
pub fn with_commit_mut<T, E, F, M>(map_context_error: M, f: F) -> Result<T, E>
where
	F: FnOnce(&mut Secp256k1) -> Result<T, E>,
	M: FnOnce(secp::Error) -> E,
{
	with_context_mut(&SECP_COMMIT, map_context_error, f)
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
	fn reentrant_mutable_access_grows_and_reuses_the_context_pool() {
		fn recurse(
			remaining: usize,
			contexts: &mut Vec<*const Secp256k1>,
		) -> Result<(), secp::Error> {
			if remaining == 0 {
				return Ok(());
			}
			with_commit_mut(
				|e| e,
				|secp| {
					contexts.push(secp as *const Secp256k1);
					recurse(remaining - 1, contexts)
				},
			)
		}

		std::thread::spawn(|| {
			const RECURSION_DEPTH: usize = 6;

			SECP_COMMIT.with(|pool| assert!(pool.contexts.borrow().is_empty()));

			let mut first_use = Vec::new();
			recurse(RECURSION_DEPTH, &mut first_use).unwrap();
			assert_eq!(first_use.len(), RECURSION_DEPTH);
			assert!(first_use
				.iter()
				.enumerate()
				.all(|(index, context)| !first_use[..index].contains(context)));
			SECP_COMMIT.with(|pool| {
				assert_eq!(pool.active.get(), 0);
				assert_eq!(pool.contexts.borrow().len(), RECURSION_DEPTH);
			});

			let mut second_use = Vec::new();
			recurse(RECURSION_DEPTH, &mut second_use).unwrap();
			assert_eq!(second_use, first_use);
			SECP_COMMIT.with(|pool| {
				assert_eq!(pool.active.get(), 0);
				assert_eq!(pool.contexts.borrow().len(), RECURSION_DEPTH);
			});
		})
		.join()
		.unwrap();
	}

	#[test]
	fn reentrant_shared_access_uses_the_next_context() {
		std::thread::spawn(|| {
			let mut outer_address = std::ptr::null();
			let mut inner_address = std::ptr::null();

			with_commit(
				|e| e,
				|outer| {
					outer_address = outer;
					with_commit(
						|e| e,
						|inner| {
							inner_address = inner;
							Ok(())
						},
					)
				},
			)
			.unwrap();

			assert!(!std::ptr::eq(outer_address, inner_address));
			SECP_COMMIT.with(|pool| {
				assert_eq!(pool.active.get(), 0);
				assert_eq!(pool.contexts.borrow().len(), 2);
			});

			with_commit(
				|e| e,
				|reused| {
					assert!(std::ptr::eq(outer_address, reused));
					Ok(())
				},
			)
			.unwrap();
		})
		.join()
		.unwrap();
	}

	#[test]
	fn panic_restores_the_active_context_index() {
		std::thread::spawn(|| {
			let mut first_address = std::ptr::null();
			let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
				let _: Result<(), secp::Error> = with_none(
					|e| e,
					|secp| {
						first_address = secp;
						panic!("test callback panic");
					},
				);
			}));
			assert!(panic.is_err());

			SECP_NONE.with(|pool| {
				assert_eq!(pool.active.get(), 0);
				assert_eq!(pool.contexts.borrow().len(), 1);
			});
			with_none(
				|e| e,
				|reused| {
					assert!(std::ptr::eq(first_address, reused));
					Ok(())
				},
			)
			.unwrap();
		})
		.join()
		.unwrap();
	}
}
