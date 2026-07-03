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

use mwc_crates::parking_lot::Mutex;
use mwc_crates::tokio;
use mwc_crates::tokio::runtime::{Handle, Runtime, RuntimeFlavor};
use mwc_crates::tokio::task;
use std::future::Future;
use std::sync::{Arc, OnceLock};

use crate::Error;

static GLOBAL_ASYNC_RUNTIME: OnceLock<Arc<Runtime>> = OnceLock::new();
static GLOBAL_ASYNC_RUNTIME_INIT_LOCK: Mutex<()> = Mutex::new(());

/// Init global runtime. App should call at the start. Currently allocate_new_context
/// calling this api.
pub fn init_global_runtime() -> Result<(), Error> {
	let _guard = GLOBAL_ASYNC_RUNTIME_INIT_LOCK.lock();

	if GLOBAL_ASYNC_RUNTIME.get().is_some() {
		return Ok(());
	}

	// Tokio reads TOKIO_WORKER_THREADS when worker_threads is not set. We leave
	// that external environment contract to Tokio; invalid values are deployment
	// misconfiguration and may panic rather than being converted into Error.
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()
		.map_err(|e| Error::AsyncRuntime(format!("init_global_runtime, {}", e)))?;

	GLOBAL_ASYNC_RUNTIME.set(Arc::new(runtime)).map_err(|_| {
		Error::AsyncRuntime("init_global_runtime, runtime initialized concurrently".into())
	})?;

	Ok(())
}

/// Global tokio runtime
pub fn global_runtime() -> Result<&'static Arc<Runtime>, Error> {
	GLOBAL_ASYNC_RUNTIME.get().ok_or_else(|| {
		Error::AsyncRuntime("global_runtime, runtime used before initialization".into())
	})
}

/// Run async block inside sync environment. Always save Tokio runtime is used
/// Note, it is expected that LocalSet is not used, MWC doesn't use such mode
pub fn run_global_async_block<F, R>(fut: F) -> Result<R, Error>
where
	F: Future<Output = R>,
{
	match Handle::try_current() {
		Err(err) if err.is_missing_context() => Ok(global_runtime()?.block_on(fut)),
		Err(err) if err.is_thread_local_destroyed() => Err(Error::AsyncRuntime(format!(
			"run_global_async_block, cannot enter runtime because thread-local state has been destroyed: {}",
			err
		))),
		Err(err) => Err(Error::AsyncRuntime(format!(
			"run_global_async_block, cannot enter runtime: {}",
			err
		))),
		Ok(handle) => match handle.runtime_flavor() {
			RuntimeFlavor::MultiThread => Ok(task::block_in_place(move || handle.block_on(fut))),
			_ => Err(Error::AsyncRuntime(
				"run_global_async_block, cannot block on async work from a current-thread runtime"
					.into(),
			)),
		},
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_async_from_async() {
		init_global_runtime().unwrap();
		run_global_async_block(async {
			println!("First async call");

			run_global_async_block(async {
				println!("Second async call");

				run_global_async_block(async {
					println!("Third async call");
				})
				.unwrap();
			})
			.unwrap();
		})
		.unwrap();
	}
}
