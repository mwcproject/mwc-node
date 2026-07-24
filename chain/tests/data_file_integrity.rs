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

use self::chain_test_helper::{clean_output_dir, init_chain, mine_chain};
use mwc_core::core::hash::Hashed;
use mwc_core::core::Block;
use mwc_core::global;
use mwc_crates::secp::{ContextFlag, Secp256k1};

#[path = "../src/tests/chain_test_helper.rs"]
mod chain_test_helper;

#[test]
fn data_files() {
	mwc_util::init_test_logger().unwrap();
	global::set_local_nrd_enabled(false);

	let chain_dir = ".mwc_df";
	clean_output_dir(chain_dir);

	let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();

	// Mine a few blocks on a new chain.
	let genesis: Block = {
		let chain = mine_chain(chain_dir, 4);
		chain.validate(&secp, false).unwrap();
		assert_eq!(chain.head().unwrap().height, 3);
		chain
			.get_block(&chain.get_header_by_height(0).unwrap().hash(0).unwrap())
			.unwrap()
	};

	// Now reload the chain from existing data files and check it is valid.
	{
		let chain = init_chain(&secp, chain_dir, genesis, true);
		chain.validate(&secp, false).unwrap();
		assert_eq!(chain.head().unwrap().height, 3);
	}

	// Cleanup chain directory
	clean_output_dir(chain_dir);
}
