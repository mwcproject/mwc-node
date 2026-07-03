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

use mwc_store::prune_list::PruneList;

#[test]
fn test_is_pruned() {
	let mut pl = PruneList::empty().unwrap();

	assert_eq!(pl.len(), 0);
	assert_eq!(pl.is_pruned(0).unwrap(), false);
	assert_eq!(pl.is_pruned(1).unwrap(), false);
	assert_eq!(pl.is_pruned(2).unwrap(), false);

	pl.append(1).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.iter().collect::<Vec<_>>(), [2]);
	assert_eq!(pl.is_pruned(0).unwrap(), false);
	assert_eq!(pl.is_pruned(1).unwrap(), true);
	assert_eq!(pl.is_pruned(2).unwrap(), false);
	assert_eq!(pl.is_pruned(3).unwrap(), false);

	let mut pl = PruneList::empty().unwrap();
	pl.append(0).unwrap();
	pl.append(1).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.len(), 1);
	assert_eq!(pl.iter().collect::<Vec<_>>(), [3]);
	assert_eq!(pl.is_pruned(0).unwrap(), true);
	assert_eq!(pl.is_pruned(1).unwrap(), true);
	assert_eq!(pl.is_pruned(2).unwrap(), true);
	assert_eq!(pl.is_pruned(3).unwrap(), false);

	pl.append(3).unwrap();

	// Flushing the prune_list removes any individual leaf positions.
	// This assumes we will track these outside the prune_list via the leaf_set.
	pl.flush().unwrap();

	assert_eq!(pl.len(), 2);
	assert_eq!(pl.to_vec(), [3, 4]);
	assert_eq!(pl.is_pruned(0).unwrap(), true);
	assert_eq!(pl.is_pruned(1).unwrap(), true);
	assert_eq!(pl.is_pruned(2).unwrap(), true);
	assert_eq!(pl.is_pruned(3).unwrap(), true);
	assert_eq!(pl.is_pruned(4).unwrap(), false);
}

#[test]
fn test_get_leaf_shift() {
	let mut pl = PruneList::empty().unwrap();

	// start with an empty prune list (nothing shifted)
	assert_eq!(pl.len(), 0);
	assert_eq!(pl.get_leaf_shift(4).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(1).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(2).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(3).unwrap(), 0);

	// now add a single leaf pos to the prune list
	// leaves will not shift shift anything
	// we only start shifting after pruning a parent
	pl.append(0).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.iter().collect::<Vec<_>>(), [1]);
	assert_eq!(pl.get_leaf_shift(0).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(1).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(2).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(3).unwrap(), 0);

	// now add the sibling leaf pos (pos 1) which will prune the parent
	// at pos 2 this in turn will "leaf shift" the leaf at pos 2 by 2
	pl.append(1).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.len(), 1);
	assert_eq!(pl.get_leaf_shift(0).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(1).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(2).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(3).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(4).unwrap(), 2);

	// now prune an additional leaf at pos 3
	// leaf offset of subsequent pos will be 2
	// 00100120
	pl.append(3).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.len(), 2);
	assert_eq!(pl.iter().collect::<Vec<_>>(), [3, 4]);
	assert_eq!(pl.get_leaf_shift(0).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(1).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(2).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(3).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(4).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(5).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(6).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(7).unwrap(), 2);

	// now prune the sibling at pos 4
	// the two smaller subtrees (pos 2 and pos 5) are rolled up to larger subtree
	// (pos 6) the leaf offset is now 4 to cover entire subtree containing first
	// 4 leaves 00100120
	pl.append(4).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.len(), 1);
	assert_eq!(pl.iter().collect::<Vec<_>>(), [7]);
	assert_eq!(pl.get_leaf_shift(0).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(1).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(2).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(3).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(4).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(5).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(6).unwrap(), 4);
	assert_eq!(pl.get_leaf_shift(7).unwrap(), 4);
	assert_eq!(pl.get_leaf_shift(8).unwrap(), 4);

	// now check we can prune some unconnected nodes
	// and that leaf_shift is correct for various pos
	let mut pl = PruneList::empty().unwrap();
	pl.append(3).unwrap();
	pl.append(4).unwrap();
	pl.append(10).unwrap();
	pl.append(11).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.len(), 2);
	assert_eq!(pl.iter().collect::<Vec<_>>(), [6, 13]);
	assert_eq!(pl.get_leaf_shift(1).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(3).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(7).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(8).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(12).unwrap(), 4);
	assert_eq!(pl.get_leaf_shift(13).unwrap(), 4);
}

#[test]
fn test_get_shift() {
	let mut pl = PruneList::empty().unwrap();
	assert!(pl.is_empty());
	assert_eq!(pl.get_shift(0).unwrap(), 0);
	assert_eq!(pl.get_shift(1).unwrap(), 0);
	assert_eq!(pl.get_shift(2).unwrap(), 0);

	// prune a single leaf node
	// pruning only a leaf node does not shift any subsequent pos
	// we will only start shifting when a parent can be pruned
	pl.append(0).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.iter().collect::<Vec<_>>(), [1]);
	assert_eq!(pl.get_shift(0).unwrap(), 0);
	assert_eq!(pl.get_shift(1).unwrap(), 0);
	assert_eq!(pl.get_shift(2).unwrap(), 0);

	pl.append(1).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.iter().collect::<Vec<_>>(), [3]);
	assert_eq!(pl.get_shift(0).unwrap(), 0);
	assert_eq!(pl.get_shift(1).unwrap(), 0);
	assert_eq!(pl.get_shift(2).unwrap(), 2);
	assert_eq!(pl.get_shift(3).unwrap(), 2);
	assert_eq!(pl.get_shift(4).unwrap(), 2);
	assert_eq!(pl.get_shift(5).unwrap(), 2);

	pl.append(3).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.iter().collect::<Vec<_>>(), [3, 4]);
	assert_eq!(pl.get_shift(0).unwrap(), 0);
	assert_eq!(pl.get_shift(1).unwrap(), 0);
	assert_eq!(pl.get_shift(2).unwrap(), 2);
	assert_eq!(pl.get_shift(3).unwrap(), 2);
	assert_eq!(pl.get_shift(4).unwrap(), 2);
	assert_eq!(pl.get_shift(5).unwrap(), 2);

	pl.append(4).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.iter().collect::<Vec<_>>(), [7]);
	assert_eq!(pl.get_shift(0).unwrap(), 0);
	assert_eq!(pl.get_shift(1).unwrap(), 0);
	assert_eq!(pl.get_shift(2).unwrap(), 0);
	assert_eq!(pl.get_shift(3).unwrap(), 0);
	assert_eq!(pl.get_shift(4).unwrap(), 0);
	assert_eq!(pl.get_shift(5).unwrap(), 0);
	assert_eq!(pl.get_shift(6).unwrap(), 6);
	assert_eq!(pl.get_shift(7).unwrap(), 6);
	assert_eq!(pl.get_shift(8).unwrap(), 6);

	// prune a bunch more
	for x in 5..999 {
		if !pl.is_pruned(x).unwrap() {
			pl.append(x).unwrap();
		}
	}
	pl.flush().unwrap();

	// and check we shift by a large number (hopefully the correct number...)
	assert_eq!(pl.get_shift(1009).unwrap(), 996);

	// now check we can do some sparse pruning
	let mut pl = PruneList::empty().unwrap();
	pl.append(3).unwrap();
	pl.append(4).unwrap();
	pl.append(7).unwrap();
	pl.append(8).unwrap();
	pl.flush().unwrap();

	assert_eq!(pl.iter().collect::<Vec<_>>(), [6, 10]);
	assert_eq!(pl.get_shift(0).unwrap(), 0);
	assert_eq!(pl.get_shift(1).unwrap(), 0);
	assert_eq!(pl.get_shift(2).unwrap(), 0);
	assert_eq!(pl.get_shift(3).unwrap(), 0);
	assert_eq!(pl.get_shift(4).unwrap(), 0);
	assert_eq!(pl.get_shift(5).unwrap(), 2);
	assert_eq!(pl.get_shift(6).unwrap(), 2);
	assert_eq!(pl.get_shift(7).unwrap(), 2);
	assert_eq!(pl.get_shift(8).unwrap(), 2);
	assert_eq!(pl.get_shift(9).unwrap(), 4);
	assert_eq!(pl.get_shift(10).unwrap(), 4);
	assert_eq!(pl.get_shift(11).unwrap(), 4);
}

#[test]
pub fn test_iter() {
	let mut pl = PruneList::empty().unwrap();
	pl.append(0).unwrap();
	pl.append(1).unwrap();
	pl.append(3).unwrap();
	assert_eq!(pl.iter().collect::<Vec<_>>(), [3, 4]);

	let mut pl = PruneList::empty().unwrap();
	pl.append(0).unwrap();
	pl.append(1).unwrap();
	pl.append(4).unwrap();
	assert_eq!(pl.iter().collect::<Vec<_>>(), [3, 5]);
}

#[test]
pub fn test_pruned_bintree_range_iter() {
	let mut pl = PruneList::empty().unwrap();
	pl.append(0).unwrap();
	pl.append(1).unwrap();
	pl.append(3).unwrap();
	assert_eq!(
		pl.pruned_bintree_range_iter()
			.map(|r| r.unwrap())
			.collect::<Vec<_>>(),
		[1..4, 4..5]
	);

	let mut pl = PruneList::empty().unwrap();
	pl.append(0).unwrap();
	pl.append(1).unwrap();
	pl.append(4).unwrap();
	assert_eq!(
		pl.pruned_bintree_range_iter()
			.map(|r| r.unwrap())
			.collect::<Vec<_>>(),
		[1..4, 5..6]
	);
}

#[test]
pub fn test_unpruned_iter() {
	let pl = PruneList::empty().unwrap();
	assert_eq!(
		pl.unpruned_iter(5).unwrap().collect::<Vec<_>>(),
		[1, 2, 3, 4, 5]
	);

	let mut pl = PruneList::empty().unwrap();
	pl.append(1).unwrap();
	assert_eq!(pl.iter().collect::<Vec<_>>(), [2]);
	assert_eq!(
		pl.pruned_bintree_range_iter()
			.map(|r| r.unwrap())
			.collect::<Vec<_>>(),
		[2..3]
	);
	assert_eq!(pl.unpruned_iter(4).unwrap().collect::<Vec<_>>(), [1, 3, 4]);

	let mut pl = PruneList::empty().unwrap();
	pl.append(1).unwrap();
	pl.append(3).unwrap();
	pl.append(4).unwrap();
	assert_eq!(pl.iter().collect::<Vec<_>>(), [2, 6]);
	assert_eq!(
		pl.pruned_bintree_range_iter()
			.map(|r| r.unwrap())
			.collect::<Vec<_>>(),
		[2..3, 4..7]
	);
	assert_eq!(
		pl.unpruned_iter(9).unwrap().collect::<Vec<_>>(),
		[1, 3, 7, 8, 9]
	);
}

#[test]
fn test_unpruned_leaf_iter() {
	let pl = PruneList::empty().unwrap();
	assert_eq!(
		pl.unpruned_leaf_iter(8).unwrap().collect::<Vec<_>>(),
		[1, 2, 4, 5, 8]
	);

	let mut pl = PruneList::empty().unwrap();
	pl.append(1).unwrap();
	assert_eq!(pl.iter().collect::<Vec<_>>(), [2]);
	assert_eq!(
		pl.pruned_bintree_range_iter()
			.map(|r| r.unwrap())
			.collect::<Vec<_>>(),
		[2..3]
	);
	assert_eq!(
		pl.unpruned_leaf_iter(5).unwrap().collect::<Vec<_>>(),
		[1, 4, 5]
	);

	let mut pl = PruneList::empty().unwrap();
	pl.append(1).unwrap();
	pl.append(3).unwrap();
	pl.append(4).unwrap();
	assert_eq!(pl.iter().collect::<Vec<_>>(), [2, 6]);
	assert_eq!(
		pl.pruned_bintree_range_iter()
			.map(|r| r.unwrap())
			.collect::<Vec<_>>(),
		[2..3, 4..7]
	);
	assert_eq!(
		pl.unpruned_leaf_iter(9).unwrap().collect::<Vec<_>>(),
		[1, 8, 9]
	);
}

pub fn test_append_pruned_subtree() {
	let mut pl = PruneList::empty().unwrap();

	// append a pruned leaf pos (shift and leaf shift are unaffected).
	pl.append(0).unwrap();

	assert_eq!(pl.to_vec(), [1]);
	assert_eq!(pl.get_shift(1).unwrap(), 0);
	assert_eq!(pl.get_leaf_shift(1).unwrap(), 0);

	pl.append(2).unwrap();

	// subtree beneath root at 2 is pruned
	// pos 3 is shifted by 2 pruned hashes [1, 2]
	// pos 3 is shifted by 2 leaves [1, 2]
	assert_eq!(pl.to_vec(), [3]);
	assert_eq!(pl.get_shift(3).unwrap(), 2);
	assert_eq!(pl.get_leaf_shift(3).unwrap(), 2);

	// append another pruned subtree (ancester of previous one)
	pl.append(6).unwrap();

	// subtree beneath root at 6 is pruned
	// pos 7 is shifted by 6 pruned hashes [1, 2, 3, 4, 5, 6]
	// pos 3 is shifted by 4 leaves [1, 2, 4, 5]
	assert_eq!(pl.to_vec(), [7]);
	assert_eq!(pl.get_shift(7).unwrap(), 6);
	assert_eq!(pl.get_leaf_shift(7).unwrap(), 4);

	// now append another pruned leaf pos
	pl.append(7).unwrap();

	// additional pruned leaf does not affect the shift or leaf shift
	// pos 8 is shifted by 6 pruned hashes [1, 2, 3, 4, 5, 6]
	// pos 8 is shifted by 4 leaves [1, 2, 4, 5]
	assert_eq!(pl.to_vec(), [7, 8]);
	assert_eq!(pl.get_shift(8).unwrap(), 6);
	assert_eq!(pl.get_leaf_shift(8).unwrap(), 4);
}

#[test]
fn test_recreate_prune_list() {
	let mut pl = PruneList::empty().unwrap();
	pl.append(3).unwrap();
	pl.append(4).unwrap();
	pl.append(10).unwrap();

	let pl2 = PruneList::new(None, vec![4, 5, 11].into_iter().collect()).unwrap();

	assert_eq!(pl.to_vec(), pl2.to_vec());
	assert_eq!(pl.shift_cache(), pl2.shift_cache());
	assert_eq!(pl.leaf_shift_cache(), pl2.leaf_shift_cache());

	let pl3 = PruneList::new(None, vec![6, 11].into_iter().collect()).unwrap();

	assert_eq!(pl.to_vec(), pl3.to_vec());
	assert_eq!(pl.shift_cache(), pl3.shift_cache());
	assert_eq!(pl.leaf_shift_cache(), pl3.leaf_shift_cache());
}

#[test]
fn discard_restores_last_flushed_prune_list() {
	let mut pl = PruneList::empty().unwrap();
	pl.append(0).unwrap();
	pl.flush().unwrap();

	let flushed = pl.to_vec();
	let flushed_shift_cache = pl.shift_cache().to_vec();
	let flushed_leaf_shift_cache = pl.leaf_shift_cache().to_vec();

	pl.append(1).unwrap();
	assert_ne!(pl.to_vec(), flushed);

	pl.discard().unwrap();

	assert_eq!(pl.to_vec(), flushed);
	assert_eq!(pl.shift_cache(), flushed_shift_cache.as_slice());
	assert_eq!(pl.leaf_shift_cache(), flushed_leaf_shift_cache.as_slice());
}
