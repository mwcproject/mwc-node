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

//! Utility structs to handle the 3 hashtrees (output, range proof,
//! kernel) more conveniently and transactionally.

use crate::error::Error;
use mwc_core::core::pmmr::peak_sizes_height;

mod bitmap_accumulator;
mod desegmenter;
mod headers_desegmenter;
/// Requests lookup interface.
pub mod request_lookup;
mod rewindable_kernel_view;
mod segmenter;
mod segments_cache;
mod txhashset;
mod utxo_view;

pub use self::bitmap_accumulator::*;
pub use self::desegmenter::*;
pub use self::headers_desegmenter::*;
pub use self::rewindable_kernel_view::*;
pub use self::segmenter::*;
pub use self::txhashset::*;
pub use self::utxo_view::*;

/// Verify that a PMMR size represents a complete MMR boundary.
pub fn ensure_complete_pmmr_size(size: u64) -> Result<(), Error> {
	let (_, next_height) = peak_sizes_height(size);
	if next_height != 0 {
		return Err(Error::InvalidMMRSize);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::ensure_complete_pmmr_size;
	use crate::error::Error;

	#[test]
	fn complete_pmmr_size_rejects_incomplete_subtree_boundaries() {
		for size in [0, 1, 3, 4, 7, 8, 10] {
			assert!(ensure_complete_pmmr_size(size).is_ok());
		}

		for size in [2, 5, 6, 9] {
			assert!(matches!(
				ensure_complete_pmmr_size(size),
				Err(Error::InvalidMMRSize)
			));
		}
	}
}
