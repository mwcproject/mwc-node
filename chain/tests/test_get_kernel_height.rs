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

#[path = "../src/tests/chain_test_helper.rs"]
mod chain_test_helper;

use self::chain_test_helper::{clean_output_dir, mine_chain};
use mwc_chain::{ChainStore, Error};
use mwc_core::core::hash::Hashed;
use mwc_util::secp_static;

fn assert_data_overflow<T>(result: Result<T, Error>) {
	match result {
		Err(Error::DataOverflow(_)) => {}
		Err(other) => panic!("expected data overflow error, got {:?}", other),
		Ok(_) => panic!("expected data overflow error, got Ok"),
	}
}

#[test]
fn test_get_kernel_height() {
	let chain_dir = ".mwc.get_kernel_height";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 5);
	assert_eq!(chain.head().unwrap().height, 4);
	let empty_commit = secp_static::commit_to_zero_value();

	let assert_missing = |min_height, max_height| {
		assert!(chain
			.get_kernel_height(&empty_commit, min_height, max_height)
			.unwrap()
			.is_none());
	};

	// check we can safely look for non-existent kernel with min_height=None, max_height=None
	assert_missing(None, None);

	// check we can safely look for non-existent kernel with min_height=1, max_height=1
	assert_missing(Some(1), Some(1));

	// check we can safely look for non-existent kernel with min_height=1, max_height=100
	assert_missing(Some(1), Some(100));

	// check we can safely look for non-existent kernel with min_height=100, max_height=100
	assert_missing(Some(100), Some(100));

	// check we can safely look for non-existent kernel with min_height=0, max_height=1
	assert_missing(Some(0), Some(1));

	// check we can safely look for non-existent kernel with min_height=0, max_height=100
	assert_missing(Some(0), Some(100));

	// check we can safely look for non-existent kernel with min_height=0, max_height=None
	assert_missing(Some(0), None);

	// check we can safely look for non-existent kernel with min_height=100, max_height=None
	assert_missing(Some(100), None);

	// check we can safely look for non-existent kernel with min_height=2, max_height=1
	assert_missing(Some(2), Some(1));

	// check we can safely look for non-existent kernel with min_height=100, max_height=99
	assert_missing(Some(100), Some(99));

	let header = chain.get_header_by_height(2).unwrap();
	let block = chain.get_block(&header.hash(0).unwrap()).unwrap();
	let located = chain
		.get_kernel_height(&block.kernels()[0].excess, None, None)
		.unwrap()
		.unwrap();
	assert_eq!(located.1, 2);

	let located = chain
		.get_kernel_height(&block.kernels()[0].excess, Some(2), Some(2))
		.unwrap()
		.unwrap();
	assert_eq!(located.1, 2);

	let store = ChainStore::new(0, chain_dir).unwrap();
	{
		let batch = store.batch_write().unwrap();
		batch.set_kernel_pos_index_complete(false).unwrap();
		batch.commit().unwrap();
	}
	match chain.get_kernel_height(&block.kernels()[0].excess, None, None) {
		Err(Error::KernelPosIndexIncomplete) => {}
		other => panic!("expected incomplete kernel index error, got {:?}", other),
	}
	drop(store);

	clean_output_dir(chain_dir);
}

#[test]
fn get_header_for_kernel_index_rejects_invalid_bounds() {
	let chain_dir = ".mwc.get_header_for_kernel_index_bounds";
	clean_output_dir(chain_dir);
	let chain = mine_chain(chain_dir, 5);
	let head = chain.head_header().unwrap();

	assert_data_overflow(chain.get_header_for_kernel_index(0, None, None));
	assert_data_overflow(chain.get_header_for_kernel_index(1, Some(3), Some(2)));

	let too_high_index = head.kernel_mmr_size.checked_add(1).unwrap();
	assert_data_overflow(chain.get_header_for_kernel_index(too_high_index, None, None));

	let prev_header = chain.get_header_by_height(1).unwrap();
	let bounded_index = prev_header.kernel_mmr_size.checked_add(1).unwrap();
	let header = chain
		.get_header_for_kernel_index(bounded_index, Some(2), Some(2))
		.unwrap();
	assert_eq!(header.height, 2);

	assert_data_overflow(chain.get_header_for_kernel_index(
		prev_header.kernel_mmr_size,
		Some(2),
		None,
	));

	clean_output_dir(chain_dir);
}
