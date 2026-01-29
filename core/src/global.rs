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

//! Values that should be shared across all modules, without necessarily
//! having to pass them all over the place, but aren't consensus values.
//! should be used sparingly.

use crate::consensus;
use crate::consensus::{
	graph_weight, HeaderDifficultyInfo, BASE_EDGE_BITS, BLOCK_KERNEL_WEIGHT, BLOCK_OUTPUT_WEIGHT,
	BLOCK_TIME_SEC, COINBASE_MATURITY, CUT_THROUGH_HORIZON, DAY_HEIGHT, DEFAULT_MIN_EDGE_BITS,
	DIFFICULTY_ADJUST_WINDOW, INITIAL_DIFFICULTY, MAX_BLOCK_WEIGHT, PROOFSIZE,
	SECOND_POW_EDGE_BITS, STATE_SYNC_THRESHOLD,
};
use crate::core::block::Block;
use crate::genesis;
use crate::pow::{self, new_cuckarood_ctx, new_cuckatoo_ctx, PoWContext, Proof};
use crate::ser::ProtocolVersion;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::sync::RwLock;

/// An enum collecting sets of parameters used throughout the
/// code wherever mining is needed. This should allow for
/// different sets of parameters for different purposes,
/// e.g. CI, User testing, production values
/// Define these here, as they should be developer-set, not really tweakable
/// by users

/// The default "local" protocol version for this node.
/// We negotiate compatible versions with each peer via Hand/Shake.
/// Note: We also use a specific (possible different) protocol version
/// for both the backend database and MMR data files.
/// NOTE, mwc bump the protocol version to 1000, but in any case so far 1,2,3 are supported.
/// 3 -> 4 Added extra param (base_fee) for handshake, bumping protocol version for that
pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion(4);

/// Automated testing edge_bits
pub const AUTOMATED_TESTING_MIN_EDGE_BITS: u8 = 10;

/// Automated testing proof size
pub const AUTOMATED_TESTING_PROOF_SIZE: usize = 8;

/// User testing edge_bits
pub const USER_TESTING_MIN_EDGE_BITS: u8 = 15;

/// User testing proof size
pub const USER_TESTING_PROOF_SIZE: usize = 42;

/// Automated testing coinbase maturity
pub const AUTOMATED_TESTING_COINBASE_MATURITY: u64 = 3;

/// User testing coinbase maturity
pub const USER_TESTING_COINBASE_MATURITY: u64 = 3;

/// Testing cut through horizon in blocks
pub const AUTOMATED_TESTING_CUT_THROUGH_HORIZON: u32 = 70;

/// Testing cut through horizon in blocks
pub const USER_TESTING_CUT_THROUGH_HORIZON: u32 = 70;

/// Testing state sync threshold in blocks
pub const TESTING_STATE_SYNC_THRESHOLD: u32 = 20;

/// Testing initial graph weight
pub const TESTING_INITIAL_GRAPH_WEIGHT: u32 = 1;

/// Testing initial block difficulty
pub const TESTING_INITIAL_DIFFICULTY: u64 = 1;

/// Testing max_block_weight (artifically low, just enough to support a few txs).
pub const TESTING_MAX_BLOCK_WEIGHT: u64 = 250;

///Note, the default fees was reduced on Jul 13 2025. There is no hardfork because of that
/// Default unit of fee per tx weight, making each output cost about a Mwccent/100
pub const DEFAULT_ACCEPT_FEE_BASE: u64 = consensus::MILLI_MWC / 1000; // Keeping default base is same, no changes for MWC     MWC_BASE / 100 / 20; // 500_000

/// If a peer's last updated difficulty is 2 hours ago and its difficulty's lower than ours,
/// we're sure this peer is a stuck node, and we will kick out such kind of stuck peers.
pub const STUCK_PEER_KICK_TIME_SECONDS: i64 = 2 * 3600;

/// Peers ping interval. It is expected that peers should respond for the ping. Otherwise peer
/// will be kicked out
pub const PEER_PING_INTERVAL_SECONDS: i64 = 10;

/// If a peer's last seen time is 2 weeks ago we will forget such kind of defunct peers.
const PEER_EXPIRATION_DAYS: i64 = 7 * 2;

/// Constant that expresses defunct peer timeout in seconds to be used in checks.
pub const PEER_EXPIRATION_REMOVE_TIME: i64 = PEER_EXPIRATION_DAYS * 24 * 3600;

/// Trigger compaction check on average every day for all nodes.
/// Randomized per node - roll the dice on every block to decide.
/// Will compact the txhashset to remove pruned data.
/// Will also remove old blocks and associated data from the database.
/// For a node configured as "archival_mode = true" only the txhashset will be compacted.
pub const COMPACTION_CHECK: u64 = DAY_HEIGHT;

/// Number of blocks to reuse a txhashset zip for (automated testing and user testing).
pub const TESTING_TXHASHSET_ARCHIVE_INTERVAL: u64 = 10;

/// Number of blocks to reuse a txhashset zip for.
pub const TXHASHSET_ARCHIVE_INTERVAL: u64 = 12 * 60;

/// MWC - all DNS hosts are updated with seed1.mwc.mw/seed2.mwc.mw and others
pub const MAINNET_DNS_SEEDS: &'static [&'static str] = &[
	"mainnet.seed2.mwc.mw", // cpg
	"mwcseed.ddns.net",     // cpg
	"t5p26dycaa7w6vzc424mahhykncv2w2tt24isaluraszhpoc6viwcqyd.onion",
	"6y2r3zcscduyaqvak4nr5muo72n46fqacz2bnfqnxmf3oksapjepkcyd.onion",
	"3.132.79.177",
	"18.217.245.152",
	"xsjhexie5v7gxmdkvzkzb4qifywnolb6v22wzvppscs2gog6ljribuad.onion",
	// mb
	"p5qo2pgkv5qpjnrlxzesf4ikcxyvvtwg6aolpamp24es5lic3btshrqd.onion",
	"ltjbwsexjixh5p2qxjohxd342fxhag7ljuvkjnnmkuu6wer6cg4skoad.onion",
	"3.6.231.127",
	"52.78.112.116",
	"plnrnhuuwjcowtjejqx6ou4m2bxkvkqq2rj4ot6cwgf53chgw2keu7yd.onion",
	"q3l5s4idfo7ukmbvz6mgowe3w65bt4w4skeskzs4g2ixpmw2euvxxvyd.onion",
	"z5ys2rogjas46tpyu343m4tamkiog6pkpznfwpu3iff55b7xypd3wcad.onion",
	"q3l5s4idfo7ukmbvz6mgowe3w65bt4w4skeskzs4g2ixpmw2euvxxvyd.onion",
	"n4ac7b65tgtachkh5ii5zytmjkbqc3bq64rhllhz4npyrbxvz7ic5byd.onion",
];
/// DNS Seed for floonet
pub const FLOONET_DNS_SEEDS: &'static [&'static str] = &[
	"seed1.mwc.mw",
	"seed2.mwc.mw",
	"zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion",
	"3.97.39.110",
	"5xwjlg6fykkj2hhvlnernj4s2jmuv5en5i3i32qld3k5jznuzpbiblid.onion",
	"13.209.51.140",
	"oqtl7wlzukgp7r6kdp3uvyelzmc72ngknwd23lo7uw63rwornvcmg3yd.onion",
	"wt635fgwmhokk25lv7y2jvrg63mokg7nfni5owrtzalz3nx22dgjytid.onion",
];

/// Types of chain a server can run with, dictates the genesis block and
/// and mining parameters used.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ChainTypes {
	/// For CI testing
	AutomatedTesting,
	/// For User testing
	UserTesting,
	/// Protocol testing network
	Floonet,
	/// Main production network
	Mainnet,
}

impl ChainTypes {
	/// Short name representing the chain type ("floo", "main", etc.)
	pub fn shortname(&self) -> String {
		match *self {
			ChainTypes::AutomatedTesting => "auto".to_owned(),
			ChainTypes::UserTesting => "user".to_owned(),
			ChainTypes::Floonet => "floo".to_owned(),
			ChainTypes::Mainnet => "main".to_owned(),
		}
	}
}

impl Default for ChainTypes {
	fn default() -> ChainTypes {
		ChainTypes::Mainnet
	}
}

struct ChainGlobalParams {
	/// Global chain status flags. It is expected that init call will set them first for every needed context
	chain_type: Option<ChainTypes>,
	/// Global chain_type that must be initialized once on node startup.
	/// This is accessed via get_chain_type() which allows the global value
	/// to be overridden on a per-thread basis (for testing).
	accept_fee_base: Option<u64>,
	/// Global feature flag for NRD kernel support.
	/// If enabled NRD kernels are treated as valid after HF3 (based on header version).
	/// If disabled NRD kernels are invalid regardless of header version or block height.
	nrd_feature_enabled: Option<bool>,
}

impl ChainGlobalParams {
	// Creates new empty instance. It is expected that values are still need to be set
	fn new() -> Self {
		ChainGlobalParams {
			chain_type: None,
			accept_fee_base: None,
			nrd_feature_enabled: None,
		}
	}
}

lazy_static! {
	/// Global chain status flags. It is expected that init call will set them first for every needed context
	/// Note, both node and wallet will need to set it up. Any param can be set once
	static ref GLOBAL_CHAIN_PARAMS: RwLock<HashMap<u32, ChainGlobalParams>> = RwLock::new(HashMap::new());
}

thread_local! {
	/// Local chain status flags. Normally used by tests. Any param can be set multiple times.
	static LOCAL_CHAIN_PARAMS: RefCell<ChainGlobalParams> = RefCell::new(ChainGlobalParams::new());
}

/// Release
pub fn release_context_data(context_id: u32) {
	let mut params = GLOBAL_CHAIN_PARAMS
		.write()
		.unwrap_or_else(|e| e.into_inner());
	let params = &mut *params;
	let _ = params.remove(&context_id);
}

/// Set the chain type on a per-thread basis via thread_local storage.
pub fn set_local_chain_type(new_type: ChainTypes) {
	LOCAL_CHAIN_PARAMS.with(|chain_params| chain_params.borrow_mut().chain_type = Some(new_type));
}

/// Get the chain type via thread_local, fallback to global chain_type.
pub fn get_chain_type(context_id: u32) -> ChainTypes {
	LOCAL_CHAIN_PARAMS.with(|chain_params| match chain_params.borrow().chain_type {
		None => {
			let params = GLOBAL_CHAIN_PARAMS.read().unwrap_or_else(|e| e.into_inner());
			match params.get(&context_id) {
				Some(params) => {
					match &params.chain_type {
						Some (chain_type) => return chain_type.clone(),
						None => {
							panic!("chain_type is not set for context {}. Consider set_local_chain_type() in tests.", context_id);
						}
					}
				}
				None => {
					panic!("chain_type is not set, context {} is empty. Consider set_local_chain_type() in tests.", context_id);
				}
			}
		}
		Some(chain_type) => return chain_type,
	})
}

/// Return genesis block for the active chain type
pub fn get_genesis_block(context_id: u32) -> Block {
	match get_chain_type(context_id) {
		ChainTypes::Mainnet => genesis::genesis_main(context_id),
		ChainTypes::Floonet => genesis::genesis_floo(context_id),
		_ => genesis::genesis_dev(context_id),
	}
}

/// One time initialization of the global chain_type.
/// Will panic if we attempt to re-initialize this (via OneTime).
pub fn init_global_chain_type(context_id: u32, new_type: ChainTypes) {
	let mut params = GLOBAL_CHAIN_PARAMS
		.write()
		.unwrap_or_else(|e| e.into_inner());
	let params = &mut *params;
	let params = params
		.entry(context_id)
		.or_insert_with(|| ChainGlobalParams::new());
	// It is not allowed to change the chain type on the fly. For a single instance it must be a contant
	assert!(params.chain_type.is_none());
	params.chain_type = Some(new_type);
}

/// One time initialization of the global chain_type.
/// Will panic if we attempt to re-initialize this (via OneTime).
pub fn init_global_nrd_enabled(context_id: u32, enabled: bool) {
	let mut params = GLOBAL_CHAIN_PARAMS
		.write()
		.unwrap_or_else(|e| e.into_inner());
	let params = &mut *params;
	let params = params
		.entry(context_id)
		.or_insert_with(|| ChainGlobalParams::new());
	// It is not allowed to change the chain type on the fly. For a single instance it must be a contant
	assert!(params.nrd_feature_enabled.is_none());
	params.nrd_feature_enabled = Some(enabled);
}

/// Explicitly enable the NRD global feature flag.
pub fn set_local_nrd_enabled(enabled: bool) {
	LOCAL_CHAIN_PARAMS
		.with(|chain_params| chain_params.borrow_mut().nrd_feature_enabled = Some(enabled));
}

/// Is the NRD feature flag enabled?
/// Look at thread local config first. If not set fallback to global config.
/// Default to false if global config unset.
pub fn is_nrd_enabled(context_id: u32) -> bool {
	LOCAL_CHAIN_PARAMS.with(|chain_params| match chain_params.borrow().nrd_feature_enabled {
		None => {
			let params = GLOBAL_CHAIN_PARAMS.read().unwrap_or_else(|e| e.into_inner());
			match params.get(&context_id) {
				Some(params) => {
					match &params.nrd_feature_enabled {
						Some (nrd_feature_enabled) => return nrd_feature_enabled.clone(),
						None => {
							panic!("nrd_feature_enabled is not set for context {}. Consider set_local_nrd_enabled() in tests.", context_id);
						}
					}
				}
				None => {
					panic!("nrd_feature_enabled is not set, context {} is empty. Consider set_local_nrd_enabled() in tests.", context_id);
				}
			}
		}
		Some(nrd_feature_enabled) => return nrd_feature_enabled,
	})
}

/// One time initialization of the global accept fee base
/// Will panic if we attempt to re-initialize this (via OneTime).
pub fn init_global_accept_fee_base(context_id: u32, new_base: u64) {
	let mut params = GLOBAL_CHAIN_PARAMS
		.write()
		.unwrap_or_else(|e| e.into_inner());
	let params = &mut *params;
	let params = params
		.entry(context_id)
		.or_insert_with(|| ChainGlobalParams::new());
	// It is not allowed to change the chain type on the fly. For a single instance it must be a contant
	assert!(params.accept_fee_base.is_none());
	params.accept_fee_base = Some(new_base);
}

/// Set the accept fee base on a per-thread basis via thread_local storage.
pub fn set_local_accept_fee_base(new_base: u64) {
	LOCAL_CHAIN_PARAMS
		.with(|chain_params| chain_params.borrow_mut().accept_fee_base = Some(new_base));
}

/// Accept Fee Base
/// Look at thread local config first. If not set fallback to global config.
/// Default to mwc-cent/20 if global config unset.
pub fn get_accept_fee_base(context_id: u32) -> u64 {
	LOCAL_CHAIN_PARAMS.with(|chain_params| match chain_params.borrow().accept_fee_base {
		None => {
			let params = GLOBAL_CHAIN_PARAMS.read().unwrap_or_else(|e| e.into_inner());
			match params.get(&context_id) {
				Some(params) => {
					match &params.accept_fee_base {
						Some (accept_fee_base) => return accept_fee_base.clone(),
						None => {
							panic!("accept_fee_base is not set for context {}. Consider set_local_accept_fee_base() in tests.", context_id);
						}
					}
				}
				None => {
					panic!("accept_fee_base is not set, context {} is empty. Consider set_local_accept_fee_base() in tests.", context_id);
				}
			}
		}
		Some(accept_fee_base) => return accept_fee_base,
	})
}

/// Return either a cuckoo context or a cuckatoo context
/// Single change point
/// MWC: We modify this to launch with cuckarood only on both floonet and mainnet
pub fn create_pow_context<T>(
	context_id: u32,
	_height: u64,
	edge_bits: u8,
	proof_size: usize,
	max_sols: u32,
) -> Result<Box<dyn PoWContext>, pow::Error> {
	let chain_type = get_chain_type(context_id);
	match chain_type {
		// Mainnet has Cuckaroo(d)29 for AR and Cuckatoo31+ for AF
		ChainTypes::Mainnet if edge_bits > 29 => {
			new_cuckatoo_ctx(context_id, edge_bits, proof_size, max_sols)
		}
		ChainTypes::Mainnet => new_cuckarood_ctx(context_id, edge_bits, proof_size),

		// Same for Floonet
		ChainTypes::Floonet if edge_bits > 29 => {
			new_cuckatoo_ctx(context_id, edge_bits, proof_size, max_sols)
		}
		ChainTypes::Floonet => new_cuckarood_ctx(context_id, edge_bits, proof_size),

		// Everything else is Cuckatoo only
		_ => new_cuckatoo_ctx(context_id, edge_bits, proof_size, max_sols),
	}
}

/// The minimum acceptable edge_bits
pub fn min_edge_bits(context_id: u32) -> u8 {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => AUTOMATED_TESTING_MIN_EDGE_BITS,
		ChainTypes::UserTesting => USER_TESTING_MIN_EDGE_BITS,
		_ => DEFAULT_MIN_EDGE_BITS,
	}
}

/// Reference edge_bits used to compute factor on higher Cuck(at)oo graph sizes,
/// while the min_edge_bits can be changed on a soft fork, changing
/// base_edge_bits is a hard fork.
pub fn base_edge_bits(context_id: u32) -> u8 {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => AUTOMATED_TESTING_MIN_EDGE_BITS,
		ChainTypes::UserTesting => USER_TESTING_MIN_EDGE_BITS,
		_ => BASE_EDGE_BITS,
	}
}

/// The proofsize
pub fn proofsize(context_id: u32) -> usize {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => AUTOMATED_TESTING_PROOF_SIZE,
		ChainTypes::UserTesting => USER_TESTING_PROOF_SIZE,
		_ => PROOFSIZE,
	}
}

/// Coinbase maturity for coinbases to be spent
pub fn coinbase_maturity(context_id: u32) -> u64 {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => AUTOMATED_TESTING_COINBASE_MATURITY,
		ChainTypes::UserTesting => USER_TESTING_COINBASE_MATURITY,
		_ => COINBASE_MATURITY,
	}
}

/// Initial mining difficulty
pub fn initial_block_difficulty(context_id: u32) -> u64 {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => TESTING_INITIAL_DIFFICULTY,
		ChainTypes::UserTesting => TESTING_INITIAL_DIFFICULTY,
		ChainTypes::Floonet => INITIAL_DIFFICULTY,
		ChainTypes::Mainnet => INITIAL_DIFFICULTY,
	}
}
/// Initial mining secondary scale
pub fn initial_graph_weight(context_id: u32) -> u32 {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => TESTING_INITIAL_GRAPH_WEIGHT,
		ChainTypes::UserTesting => TESTING_INITIAL_GRAPH_WEIGHT,
		ChainTypes::Floonet => graph_weight(context_id, 0, SECOND_POW_EDGE_BITS) as u32,
		ChainTypes::Mainnet => graph_weight(context_id, 0, SECOND_POW_EDGE_BITS) as u32,
	}
}

/// Maximum allowed block weight.
pub fn max_block_weight(context_id: u32) -> u64 {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => TESTING_MAX_BLOCK_WEIGHT,
		ChainTypes::UserTesting => TESTING_MAX_BLOCK_WEIGHT,
		ChainTypes::Floonet => MAX_BLOCK_WEIGHT,
		ChainTypes::Mainnet => MAX_BLOCK_WEIGHT,
	}
}

/// Maximum allowed transaction weight (1 weight unit ~= 32 bytes)
pub fn max_tx_weight(context_id: u32) -> u64 {
	let coinbase_weight = BLOCK_OUTPUT_WEIGHT + BLOCK_KERNEL_WEIGHT;
	max_block_weight(context_id).saturating_sub(coinbase_weight) as u64
}

/// Horizon at which we can cut-through and do full local pruning
pub fn cut_through_horizon(context_id: u32) -> u32 {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => AUTOMATED_TESTING_CUT_THROUGH_HORIZON,
		ChainTypes::UserTesting => USER_TESTING_CUT_THROUGH_HORIZON,
		_ => CUT_THROUGH_HORIZON,
	}
}

/// Threshold at which we can request a txhashset (and full blocks from)
pub fn state_sync_threshold(context_id: u32) -> u32 {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => TESTING_STATE_SYNC_THRESHOLD,
		ChainTypes::UserTesting => TESTING_STATE_SYNC_THRESHOLD,
		_ => STATE_SYNC_THRESHOLD,
	}
}

/// Number of blocks to reuse a txhashset zip for.
pub fn txhashset_archive_interval(context_id: u32) -> u64 {
	match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => TESTING_TXHASHSET_ARCHIVE_INTERVAL,
		ChainTypes::UserTesting => TESTING_TXHASHSET_ARCHIVE_INTERVAL,
		_ => TXHASHSET_ARCHIVE_INTERVAL,
	}
}

/// Are we in production mode?
/// Production defined as a live public network, testnet[n] or mainnet.
pub fn is_production_mode(context_id: u32) -> bool {
	match get_chain_type(context_id) {
		ChainTypes::Floonet => true,
		ChainTypes::Mainnet => true,
		_ => false,
	}
}

/// Are we in floonet?
/// Note: We do not have a corresponding is_mainnet() as we want any tests to be as close
/// as possible to "mainnet" configuration as possible.
/// We want to avoid missing any mainnet only code paths.
pub fn is_floonet(context_id: u32) -> bool {
	match get_chain_type(context_id) {
		ChainTypes::Floonet => true,
		_ => false,
	}
}

/// Are we for real?
pub fn is_mainnet(context_id: u32) -> bool {
	match get_chain_type(context_id) {
		ChainTypes::Mainnet => true,
		_ => false,
	}
}

/// Tor port for libp2p network
pub fn get_tor_libp2p_port(context_id: u32) -> u16 {
	if is_mainnet(context_id) {
		81
	} else {
		82
	}
}

/// Get a network name
pub fn get_network_name(context_id: u32) -> String {
	let name = match get_chain_type(context_id) {
		ChainTypes::AutomatedTesting => "automatedtests",
		ChainTypes::UserTesting => "usertestnet",
		ChainTypes::Floonet => "floonet",
		ChainTypes::Mainnet => "mainnet",
	};
	name.to_string()
}

/// Converts an iterator of block difficulty data to more a more manageable
/// vector and pads if needed (which will) only be needed for the first few
/// blocks after genesis
/// cache_values is needed becuase during headers sync process, this step taking almost 50% of time (cpmparable to header POW verification time)
pub fn difficulty_data_to_vector<T>(
	context_id: u32,
	cursor: T,
	cache_values: &mut VecDeque<HeaderDifficultyInfo>,
) -> Vec<HeaderDifficultyInfo>
where
	T: IntoIterator<Item = HeaderDifficultyInfo>,
{
	// Convert iterator to vector, so we can append to it if necessary
	let needed_block_count = DIFFICULTY_ADJUST_WINDOW as usize + 1;

	// In debug mode we want to validate the cache. It is expected that last_n are exactly the same with and without a cache
	#[cfg(debug_assertions)]
	let test_last_n: Vec<HeaderDifficultyInfo> = cursor.into_iter().take(needed_block_count).collect();
	#[cfg(debug_assertions)]
	let cursor = test_last_n.clone().into_iter();

	let mut last_n: Vec<HeaderDifficultyInfo> = Vec::with_capacity(needed_block_count);

	let mut iter = cursor.into_iter();
	while let Some(item) = iter.next() {
		if !cache_values.is_empty() {
			let cache_tail = cache_values.front().unwrap();
			let cache_head = cache_values.back().unwrap();

			if item.height
				>= cache_tail.height + (needed_block_count - 1) as u64 - last_n.len() as u64
				&& item.height <= cache_head.height
			{
				let item_idx = (item.height - cache_tail.height) as usize;
				debug_assert!(cache_values[item_idx].height == item.height);
				if cache_values[item_idx].hash == item.hash {
					let base_idx = item_idx + last_n.len();
					// cash hit, can finish the query
					while let Some(h) = last_n.pop() {
						debug_assert!(cache_values.back().unwrap().height + 1 == h.height);
						cache_values.push_back(h);
					}
					debug_assert!(last_n.is_empty());
					for i in 0..needed_block_count {
						last_n.push(cache_values[base_idx - i].clone());
					}
					// done with cursor, last_n is full
					break;
				} else {
					// cache is invalid, probably there are branches
					cache_values.clear();
				}
			}
		}
		last_n.push(item);
		if last_n.len() == needed_block_count && needed_block_count > 2 {
			// cache is absolete, lets init it, but hirst we want to invalidate the data
			// In test cases there are cases that we can't cache well
			let mut last_n_valid = true;

			for i in 1..last_n.len() {
				let h1 = &last_n[i - 1];
				let h2 = &last_n[i];
				if h1.height <= h2.height
					|| h1.hash.is_none()
					|| h1.difficulty <= h2.difficulty
					|| h1.timestamp <= h2.timestamp
				{
					last_n_valid = false;
					break;
				}
			}

			cache_values.clear();
			if last_n_valid {
				cache_values.extend(last_n.iter().rev().cloned());
			}
			break;
		}
	}

	if cache_values.len() > needed_block_count * 10 {
		cache_values.drain(0..(cache_values.len() - needed_block_count * 7));
	}

	#[cfg(debug_assertions)]
	{
		assert!(test_last_n == last_n);
	}

	// Only needed just after blockchain launch... basically ensures there's
	// always enough data by simulating perfectly timed pre-genesis
	// blocks at the genesis difficulty as needed.
	let n = last_n.len();
	if needed_block_count > n {
		let last_ts_delta = if n > 1 {
			last_n[0].timestamp - last_n[1].timestamp
		} else {
			BLOCK_TIME_SEC
		};
		let last_diff = last_n[0].difficulty;

		// fill in simulated blocks with values from the previous real block
		let mut last_ts = last_n.last().unwrap().timestamp;
		for _ in n..needed_block_count {
			last_ts = last_ts.saturating_sub(last_ts_delta);
			last_n.push(HeaderDifficultyInfo::from_ts_diff(
				context_id, last_ts, last_diff,
			));
		}
	}
	last_n.reverse();
	last_n
}

/// Calculates the size of a header (in bytes) given a number of edge bits in the PoW
#[inline]
pub fn header_size_bytes(context_id: u32, edge_bits: u8) -> usize {
	let size = 2 + 2 * 8 + 5 * 32 + 32 + 2 * 8;
	let proof_size = 8 + 4 + 8 + 1 + Proof::pack_len(context_id, edge_bits);
	size + proof_size
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::core::Block;
	use crate::genesis::*;
	use crate::pow::mine_genesis_block;
	use crate::ser::{BinWriter, Writeable};

	fn test_header_len(genesis: Block) {
		let mut raw = Vec::<u8>::with_capacity(1_024);
		let mut writer = BinWriter::new(&mut raw, ProtocolVersion::local());
		genesis.header.write(&mut writer).unwrap();
		assert_eq!(
			raw.len(),
			header_size_bytes(0, genesis.header.pow.edge_bits())
		);
	}

	#[test]
	fn automated_testing_header_len() {
		set_local_chain_type(ChainTypes::AutomatedTesting);
		test_header_len(mine_genesis_block(0).unwrap());
	}

	#[test]
	fn user_testing_header_len() {
		set_local_chain_type(ChainTypes::UserTesting);
		test_header_len(mine_genesis_block(0).unwrap());
	}

	#[test]
	fn floonet_header_len() {
		set_local_chain_type(ChainTypes::Floonet);
		test_header_len(genesis_floo(0));
	}

	#[test]
	fn mainnet_header_len() {
		set_local_chain_type(ChainTypes::Mainnet);
		test_header_len(genesis_main(0));
	}
}
