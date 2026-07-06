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

use mwc_chain::linked_list::{ListIndex, ListWrapper, PruneableListIndex, RewindableListIndex};
use mwc_chain::store::{self, ChainStore};
use mwc_chain::types::CommitPos;
use mwc_core::global;
use mwc_crates::secp::pedersen::Commitment;
use mwc_store;
#[path = "../src/tests/chain_test_helper.rs"]
mod chain_test_helper;
use self::chain_test_helper::clean_output_dir;
use mwc_store::Error;
use mwc_util::secp_static;

fn setup_test() {
	mwc_util::init_test_logger().unwrap();
	global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
	global::set_local_nrd_enabled(false);
}

#[test]
fn test_store_kernel_idx() {
	setup_test();
	let chain_dir = ".mwc_idx_1";
	clean_output_dir(chain_dir);

	let commit = secp_static::commit_to_zero_value();

	let store = ChainStore::new(0, chain_dir).unwrap();
	let batch = store.batch_write().unwrap();
	let index = store::nrd_recent_kernel_index();

	assert!(matches!(index.peek_pos(&batch, commit), Ok(None)));
	assert!(matches!(index.get_list(&batch, commit), Ok(None)));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 1, height: 1 }),
		Ok(()),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 1, height: 1 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 1, height: 1 }
		})),
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 2, height: 2 }),
		Ok(()),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 2, height: 2 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 2, tail: 1 })),
	));

	// Pos must always increase.
	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 1, height: 1 }),
		Err(Error::OtherErr(ref msg)) if msg == "pos must be increasing"
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 2, height: 2 }),
		Err(Error::OtherErr(ref msg)) if msg == "pos must be increasing"
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 3, height: 3 }),
		Ok(()),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 3, height: 3 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 3, tail: 1 })),
	));

	assert!(matches!(
		index.pop_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 3, height: 3 })),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 2, height: 2 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 2, tail: 1 })),
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 3, height: 3 }),
		Ok(()),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 3, height: 3 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 3, tail: 1 })),
	));

	assert!(matches!(
		index.pop_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 3, height: 3 })),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 2, height: 2 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 2, tail: 1 })),
	));

	assert!(matches!(
		index.pop_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 2, height: 2 })),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 1, height: 1 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 1, height: 1 }
		})),
	));
	assert!(matches!(index.get_entry(&batch, commit, 1), Ok(None)));
	assert!(matches!(index.get_entry(&batch, commit, 2), Ok(None)));

	assert!(matches!(
		index.pop_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 1, height: 1 })),
	));

	assert!(matches!(index.peek_pos(&batch, commit), Ok(None)));
	assert!(matches!(index.get_list(&batch, commit), Ok(None)));

	// Cleanup chain directory
	clean_output_dir(chain_dir);
}

#[test]
fn test_store_kernel_idx_pop_back() {
	setup_test();
	let chain_dir = ".mwc_idx_2";
	clean_output_dir(chain_dir);

	let commit = secp_static::commit_to_zero_value();

	let store = ChainStore::new(0, chain_dir).unwrap();
	let batch = store.batch_write().unwrap();
	let index = store::nrd_recent_kernel_index();

	assert!(matches!(index.peek_pos(&batch, commit), Ok(None)));
	assert!(matches!(index.get_list(&batch, commit), Ok(None)));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 1, height: 1 }),
		Ok(()),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 1, height: 1 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 1, height: 1 }
		})),
	));

	assert!(matches!(
		index.pop_pos_back(&batch, commit),
		Ok(Some(CommitPos { pos: 1, height: 1 })),
	));

	assert!(matches!(index.peek_pos(&batch, commit), Ok(None)));
	assert!(matches!(index.get_list(&batch, commit), Ok(None)));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 1, height: 1 }),
		Ok(()),
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 2, height: 2 }),
		Ok(()),
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 3, height: 3 }),
		Ok(()),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 3, height: 3 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 3, tail: 1 })),
	));

	assert!(matches!(
		index.pop_pos_back(&batch, commit),
		Ok(Some(CommitPos { pos: 1, height: 1 })),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 3, height: 3 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 3, tail: 2 })),
	));

	assert!(matches!(
		index.pop_pos_back(&batch, commit),
		Ok(Some(CommitPos { pos: 2, height: 2 })),
	));

	assert!(matches!(
		index.peek_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 3, height: 3 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 3, height: 3 }
		})),
	));
	assert!(matches!(index.get_entry(&batch, commit, 2), Ok(None)));
	assert!(matches!(index.get_entry(&batch, commit, 3), Ok(None)));

	assert!(matches!(
		index.pop_pos_back(&batch, commit),
		Ok(Some(CommitPos { pos: 3, height: 3 })),
	));

	assert!(matches!(index.peek_pos(&batch, commit), Ok(None)));
	assert!(matches!(index.get_list(&batch, commit), Ok(None)));

	clean_output_dir(chain_dir);
}

#[test]
fn test_store_kernel_idx_rewind() {
	setup_test();
	let chain_dir = ".mwc_idx_3";
	clean_output_dir(chain_dir);

	let commit = secp_static::commit_to_zero_value();

	let store = ChainStore::new(0, chain_dir).unwrap();
	let batch = store.batch_write().unwrap();
	let index = store::nrd_recent_kernel_index();

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 1, height: 1 }),
		Ok(()),
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 2, height: 2 }),
		Ok(()),
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 3, height: 3 }),
		Ok(()),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 3, tail: 1 })),
	));

	assert!(matches!(index.rewind(&batch, commit, 1), Ok(()),));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 1, height: 1 }
		})),
	));

	// Check we can safely noop rewind.
	assert!(matches!(index.rewind(&batch, commit, 2), Ok(()),));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 1, height: 1 }
		})),
	));

	assert!(matches!(index.rewind(&batch, commit, 1), Ok(()),));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 1, height: 1 }
		})),
	));

	// Check we can rewind back to 0.
	assert!(matches!(index.rewind(&batch, commit, 0), Ok(()),));

	assert!(matches!(index.get_list(&batch, commit), Ok(None),));

	assert!(matches!(index.rewind(&batch, commit, 0), Ok(()),));

	// Now check we can rewind past the end of a list safely.

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 1, height: 1 }),
		Ok(()),
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 2, height: 2 }),
		Ok(()),
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 3, height: 3 }),
		Ok(()),
	));

	assert!(matches!(
		index.pop_pos_back(&batch, commit),
		Ok(Some(CommitPos { pos: 1, height: 1 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 3, tail: 2 })),
	));

	assert!(matches!(index.rewind(&batch, commit, 1), Ok(()),));

	assert!(matches!(index.get_list(&batch, commit), Ok(None),));

	clean_output_dir(chain_dir);
}

#[test]
fn test_store_kernel_idx_multiple_commits() {
	setup_test();
	let chain_dir = ".mwc_idx_4";
	clean_output_dir(chain_dir);

	let commit = secp_static::commit_to_zero_value();
	let commit2 = Commitment::from_vec(vec![1; 33]).unwrap();

	let store = ChainStore::new(0, chain_dir).unwrap();
	let batch = store.batch_write().unwrap();
	let index = store::nrd_recent_kernel_index();

	assert!(matches!(index.get_list(&batch, commit), Ok(None)));
	assert!(matches!(index.get_list(&batch, commit2), Ok(None)));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 1, height: 1 }),
		Ok(()),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 1, height: 1 }
		})),
	));

	assert!(matches!(index.get_list(&batch, commit2), Ok(None)));

	assert!(matches!(
		index.push_pos(&batch, commit2, CommitPos { pos: 2, height: 2 }),
		Ok(()),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 1, height: 1 }
		})),
	));

	assert!(matches!(
		index.get_list(&batch, commit2),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 2, height: 2 }
		})),
	));

	assert!(matches!(
		index.push_pos(&batch, commit, CommitPos { pos: 3, height: 3 }),
		Ok(()),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Multi { head: 3, tail: 1 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit2),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 2, height: 2 }
		})),
	));

	assert!(matches!(
		index.pop_pos(&batch, commit),
		Ok(Some(CommitPos { pos: 3, height: 3 })),
	));

	assert!(matches!(
		index.get_list(&batch, commit),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 1, height: 1 }
		})),
	));

	assert!(matches!(
		index.get_list(&batch, commit2),
		Ok(Some(ListWrapper::Single {
			pos: CommitPos { pos: 2, height: 2 }
		})),
	));

	clean_output_dir(chain_dir);
}

#[test]
fn test_store_kernel_idx_clear() -> Result<(), Error> {
	setup_test();
	let chain_dir = ".mwc_idx_clear";
	clean_output_dir(chain_dir);

	let commit = secp_static::commit_to_zero_value();
	let commit2 = Commitment::from_vec(vec![1; 33]).unwrap();

	let store = ChainStore::new(0, chain_dir)?;
	let index = store::nrd_recent_kernel_index();

	// Add a couple of single entries to the index and commit the batch.
	{
		let batch = store.batch_write()?;
		assert!(matches!(index.peek_pos(&batch, commit), Ok(None)));
		assert!(matches!(index.get_list(&batch, commit), Ok(None)));

		assert!(matches!(
			index.push_pos(&batch, commit, CommitPos { pos: 1, height: 1 }),
			Ok(()),
		));

		assert!(matches!(
			index.push_pos(
				&batch,
				commit2,
				CommitPos {
					pos: 10,
					height: 10,
				}
			),
			Ok(()),
		));

		assert!(matches!(
			index.peek_pos(&batch, commit),
			Ok(Some(CommitPos { pos: 1, height: 1 })),
		));

		assert!(matches!(
			index.get_list(&batch, commit),
			Ok(Some(ListWrapper::Single {
				pos: CommitPos { pos: 1, height: 1 }
			})),
		));

		assert!(matches!(
			index.peek_pos(&batch, commit2),
			Ok(Some(CommitPos {
				pos: 10,
				height: 10
			})),
		));

		assert!(matches!(
			index.get_list(&batch, commit2),
			Ok(Some(ListWrapper::Single {
				pos: CommitPos {
					pos: 10,
					height: 10
				}
			})),
		));

		batch.commit()?;
	}

	// Clear the index and confirm everything was deleted as expected.
	{
		let batch = store.batch_write()?;
		assert!(matches!(index.clear(&batch), Ok(())));
		assert!(matches!(index.peek_pos(&batch, commit), Ok(None)));
		assert!(matches!(index.get_list(&batch, commit), Ok(None)));
		assert!(matches!(index.peek_pos(&batch, commit2), Ok(None)));
		assert!(matches!(index.get_list(&batch, commit2), Ok(None)));
		batch.commit()?;
	}

	// Add multiple entries to the index, commit the batch.
	{
		let batch = store.batch_write()?;
		assert!(matches!(
			index.push_pos(&batch, commit, CommitPos { pos: 1, height: 1 }),
			Ok(()),
		));
		assert!(matches!(
			index.push_pos(&batch, commit, CommitPos { pos: 2, height: 2 }),
			Ok(()),
		));
		assert!(matches!(
			index.peek_pos(&batch, commit),
			Ok(Some(CommitPos { pos: 2, height: 2 })),
		));
		assert!(matches!(
			index.get_list(&batch, commit),
			Ok(Some(ListWrapper::Multi { head: 2, tail: 1 })),
		));
		batch.commit()?;
	}

	// Clear the index and confirm everything was deleted as expected.
	{
		let batch = store.batch_write()?;
		assert!(matches!(index.clear(&batch), Ok(())));
		assert!(matches!(index.peek_pos(&batch, commit), Ok(None)));
		assert!(matches!(index.get_list(&batch, commit), Ok(None)));
		batch.commit()?;
	}

	clean_output_dir(chain_dir);
	Ok(())
}
