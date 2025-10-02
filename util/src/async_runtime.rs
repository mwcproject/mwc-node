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

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::thread;
use tokio::runtime::{Handle, Runtime};

static GLOBAL_ASYNC_RUNTIME: OnceLock<Arc<Runtime>> = OnceLock::new();

/// Global tokio runtime
pub fn global_runtime() -> &'static Arc<Runtime> {
	GLOBAL_ASYNC_RUNTIME.get_or_init(|| {
		Arc::new(
			tokio::runtime::Builder::new_multi_thread()
				.enable_all()
				.build()
				.expect("failed to start Tokio runtime"),
		)
	})
}

/// Run async block inside sync environment. Allwais save Tokio runtime is used
pub fn run_global_async_block<F, R>(fut: F) -> R
where
	F: Future<Output = R> + Send,
	R: Send,
{
	if Handle::try_current().is_err() {
		return global_runtime().block_on(fut);
	}

	// slow path: already inside the global runtime → spawn + join
	thread::scope(|s| {
		s.spawn(|| {
			global_runtime().block_on(fut) // runs on different thread
		})
		.join()
		.expect("panic at run_async_block join")
	})
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_async_from_async() {
		run_global_async_block(async {
			println!("First async call");

			run_global_async_block(async {
				println!("Second async call");
			});
		});
	}
}
