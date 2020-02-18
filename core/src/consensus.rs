// Copyright 2019 The Grin Developers
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

//! All the rules required for a cryptocurrency to have reach consensus across
//! the whole network are complex and hard to completely isolate. Some can be
//! simple parameters (like block reward), others complex algorithms (like
//! Merkle sum trees or reorg rules). However, as long as they're simple
//! enough, consensus-relevant constants and short functions should be kept
//! here.
//! da8f798fb502cf30dde067af3e7a095c786bab0afda34c851d78cf9cca99ccc6

use crate::core::block::HeaderVersion;
use crate::core::hash::{Hash, ZERO_HASH};
use crate::global;
use crate::pow::Difficulty;
use std::cmp::{max, min};

/// A grin is divisible to 10^9, following the SI prefixes
pub const GRIN_BASE: u64 = 1_000_000_000;
/// Milligrin, a thousand of a grin
pub const MILLI_GRIN: u64 = GRIN_BASE / 1_000;
/// Microgrin, a thousand of a milligrin
pub const MICRO_GRIN: u64 = MILLI_GRIN / 1_000;
/// Nanogrin, smallest unit, takes a billion to make a grin
pub const NANO_GRIN: u64 = 1;

/// Block interval, in seconds, the network will tune its next_target for. Note
/// that we may reduce this value in the future as we get more data on mining
/// with Cuckoo Cycle, networks improve and block propagation is optimized
/// (adjusting the reward accordingly).
pub const BLOCK_TIME_SEC: u64 = 60;

/// MWC - Here is a block reward.
/// The block subsidy amount, one grin per second on average
//pub const REWARD: u64 = BLOCK_TIME_SEC * GRIN_BASE;

/// Actual block reward for a given total fee amount
pub fn reward(fee: u64, height: u64) -> u64 {
	// MWC has block reward schedule similar to bitcoin
	let block_reward = calc_mwc_block_reward(height);
	block_reward.saturating_add(fee)
}

/// MWC  genesis block reward in nanocoins (10M coins)
pub const GENESIS_BLOCK_REWARD: u64 = 10_000_000_000_000_000 + 41_800_000;

/// Nominal height for standard time intervals, hour is 60 blocks
pub const HOUR_HEIGHT: u64 = 3600 / BLOCK_TIME_SEC;
/// A day is 1440 blocks
pub const DAY_HEIGHT: u64 = 24 * HOUR_HEIGHT;
/// A week is 10_080 blocks
pub const WEEK_HEIGHT: u64 = 7 * DAY_HEIGHT;
/// A year is 524_160 blocks
pub const YEAR_HEIGHT: u64 = 52 * WEEK_HEIGHT;

/// Number of blocks before a coinbase matures and can be spent
pub const COINBASE_MATURITY: u64 = DAY_HEIGHT;

/// Target ratio of secondary proof of work to primary proof of work,
/// as a function of block height (time). Starts at 90% losing a percent
/// approximately every week. Represented as an integer between 0 and 100.
/// MWC: note we are changing this to an initial 45% (since we launch
/// approximately 1 year after grin) and we also make it go to 0
/// over the course of 1 year. This will roughly keep us inline with grin.
pub fn secondary_pow_ratio(height: u64) -> u64 {
	45u64.saturating_sub(height / (YEAR_HEIGHT / 45))
}

/// The AR scale damping factor to use. Dependent on block height
/// to account for pre HF behavior on testnet4.
fn ar_scale_damp_factor(_height: u64) -> u64 {
	AR_SCALE_DAMP_FACTOR
}

/// Cuckoo-cycle proof size (cycle length)
pub const PROOFSIZE: usize = 42;

// MWC want to keep this value: pub const DEFAULT_MIN_EDGE_BITS: u8 = 31;
/// Default Cuckatoo Cycle edge_bits, used for mining and validating.
pub const DEFAULT_MIN_EDGE_BITS: u8 = 31;

// MWC want to keep this value: pub const SECOND_POW_EDGE_BITS: u8 = 29;
/// Cuckaroo* proof-of-work edge_bits, meant to be ASIC resistant.
pub const SECOND_POW_EDGE_BITS: u8 = 29;

/// Original reference edge_bits to compute difficulty factors for higher
/// Cuckoo graph sizes, changing this would hard fork
pub const BASE_EDGE_BITS: u8 = 24;

/// Default number of blocks in the past when cross-block cut-through will start
/// happening. Needs to be long enough to not overlap with a long reorg.
/// Rational
/// behind the value is the longest bitcoin fork was about 30 blocks, so 5h. We
/// add an order of magnitude to be safe and round to 7x24h of blocks to make it
/// easier to reason about.
pub const CUT_THROUGH_HORIZON: u32 = WEEK_HEIGHT as u32;

/// Default number of blocks in the past to determine the height where we request
/// a txhashset (and full blocks from). Needs to be long enough to not overlap with
/// a long reorg.
/// Rational behind the value is the longest bitcoin fork was about 30 blocks, so 5h.
/// We add an order of magnitude to be safe and round to 2x24h of blocks to make it
/// easier to reason about.
pub const STATE_SYNC_THRESHOLD: u32 = 2 * DAY_HEIGHT as u32;

/// Weight of an input when counted against the max block weight capacity
pub const BLOCK_INPUT_WEIGHT: usize = 1;

/// Weight of an output when counted against the max block weight capacity
pub const BLOCK_OUTPUT_WEIGHT: usize = 21;

/// Weight of a kernel when counted against the max block weight capacity
pub const BLOCK_KERNEL_WEIGHT: usize = 3;

/// Total maximum block weight. At current sizes, this means a maximum
/// theoretical size of:
/// * `(674 + 33 + 1) * (40_000 / 21) = 1_348_571` for a block with only outputs
/// * `(1 + 8 + 8 + 33 + 64) * (40_000 / 3) = 1_520_000` for a block with only kernels
/// * `(1 + 33) * 40_000 = 1_360_000` for a block with only inputs
///
/// Regardless of the relative numbers of inputs/outputs/kernels in a block the maximum
/// block size is around 1.5MB
/// For a block full of "average" txs (2 inputs, 2 outputs, 1 kernel) we have -
/// `(1 * 2) + (21 * 2) + (3 * 1) = 47` (weight per tx)
/// `40_000 / 47 = 851` (txs per block)
///
pub const MAX_BLOCK_WEIGHT: usize = 40_000;

/// Check whether the block version is valid at a given height
/// MWC doesn't want like grin change the algorithms for mining. So version is constant
pub fn header_version(height: u64) -> HeaderVersion {
	if height < get_c31_hard_fork_block_height() {
		HeaderVersion(1)
	} else {
		HeaderVersion(2)
	}
}

/// Check whether the block version is valid at a given height.
/// Currently we only use the default version. No hard forks planned.
pub fn valid_header_version(height: u64, version: HeaderVersion) -> bool {
	if height < get_c31_hard_fork_block_height() {
		version == HeaderVersion(1)
	} else {
		version == HeaderVersion(2)
	}
}

/// Number of blocks used to calculate difficulty adjustments
pub const DIFFICULTY_ADJUST_WINDOW: u64 = HOUR_HEIGHT;

/// Average time span of the difficulty adjustment window
pub const BLOCK_TIME_WINDOW: u64 = DIFFICULTY_ADJUST_WINDOW * BLOCK_TIME_SEC;

/// Clamp factor to use for difficulty adjustment
/// Limit value to within this factor of goal
pub const CLAMP_FACTOR: u64 = 2;

/// Dampening factor to use for difficulty adjustment
pub const DIFFICULTY_DAMP_FACTOR: u64 = 3;

/// Dampening factor to use for AR scale calculation.
pub const AR_SCALE_DAMP_FACTOR: u64 = 13;

/// Compute weight of a graph as number of siphash bits defining the graph
/// Must be made dependent on height to phase out C31 in early 2020
/// Later phase outs are on hold for now
/// MWC modification: keep the initial calculation permanently so always favor C31.
pub fn graph_weight(height: u64, edge_bits: u8) -> u64 {
	if height < get_c31_hard_fork_block_height() || edge_bits <= 31 {
		(2u64 << ((edge_bits as u64) - global::base_edge_bits() as u64) as u64) * (edge_bits as u64)
	} else {
		1
	}
}

/// Minimum difficulty, enforced in diff retargetting
/// avoids getting stuck when trying to increase difficulty subject to dampening
pub const MIN_DIFFICULTY: u64 = DIFFICULTY_DAMP_FACTOR;

/// Minimum scaling factor for AR pow, enforced in diff retargetting
/// avoids getting stuck when trying to increase ar_scale subject to dampening
pub const MIN_AR_SCALE: u64 = AR_SCALE_DAMP_FACTOR;

/// unit difficulty, equal to graph_weight(SECOND_POW_EDGE_BITS)
pub const UNIT_DIFFICULTY: u64 =
	((2 as u64) << (SECOND_POW_EDGE_BITS - BASE_EDGE_BITS)) * (SECOND_POW_EDGE_BITS as u64);

/// The initial difficulty at launch. This should be over-estimated
/// and difficulty should come down at launch rather than up
/// Currently grossly over-estimated at 10% of current
/// ethereum GPUs (assuming 1GPU can solve a block at diff 1 in one block interval)
pub const INITIAL_DIFFICULTY: u64 = 1_000_000 * UNIT_DIFFICULTY;

/// Minimal header information required for the Difficulty calculation to
/// take place
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderInfo {
	/// Block hash, ZERO_HASH when this is a sythetic entry.
	pub block_hash: Hash,
	/// Timestamp of the header, 1 when not used (returned info)
	pub timestamp: u64,
	/// Network difficulty or next difficulty to use
	pub difficulty: Difficulty,
	/// Network secondary PoW factor or factor to use
	pub secondary_scaling: u32,
	/// Whether the header is a secondary proof of work
	pub is_secondary: bool,
}

impl HeaderInfo {
	/// Default constructor
	pub fn new(
		block_hash: Hash,
		timestamp: u64,
		difficulty: Difficulty,
		secondary_scaling: u32,
		is_secondary: bool,
	) -> HeaderInfo {
		HeaderInfo {
			block_hash,
			timestamp,
			difficulty,
			secondary_scaling,
			is_secondary,
		}
	}

	/// Constructor from a timestamp and difficulty, setting a default secondary
	/// PoW factor
	pub fn from_ts_diff(timestamp: u64, difficulty: Difficulty) -> HeaderInfo {
		HeaderInfo {
			block_hash: ZERO_HASH,
			timestamp,
			difficulty,
			secondary_scaling: global::initial_graph_weight(),

			is_secondary: true,
		}
	}

	/// Constructor from a difficulty and secondary factor, setting a default
	/// timestamp
	pub fn from_diff_scaling(difficulty: Difficulty, secondary_scaling: u32) -> HeaderInfo {
		HeaderInfo {
			block_hash: ZERO_HASH,
			timestamp: 1,
			difficulty,
			secondary_scaling,
			is_secondary: true,
		}
	}
}

/// Move value linearly toward a goal
pub fn damp(actual: u64, goal: u64, damp_factor: u64) -> u64 {
	(actual + (damp_factor - 1) * goal) / damp_factor
}

/// limit value to be within some factor from a goal
pub fn clamp(actual: u64, goal: u64, clamp_factor: u64) -> u64 {
	max(goal / clamp_factor, min(actual, goal * clamp_factor))
}

/// Computes the proof-of-work difficulty that the next block should comply
/// with. Takes an iterator over past block headers information, from latest
/// (highest height) to oldest (lowest height).
///
/// The difficulty calculation is based on both Digishield and GravityWave
/// family of difficulty computation, coming to something very close to Zcash.
/// The reference difficulty is an average of the difficulty over a window of
/// DIFFICULTY_ADJUST_WINDOW blocks. The corresponding timespan is calculated
/// by using the difference between the median timestamps at the beginning
/// and the end of the window.
///
/// The secondary proof-of-work factor is calculated along the same lines, as
/// an adjustment on the deviation against the ideal value.
pub fn next_difficulty<T>(height: u64, cursor: T) -> HeaderInfo
where
	T: IntoIterator<Item = HeaderInfo>,
{
	// Create vector of difficulty data running from earliest
	// to latest, and pad with simulated pre-genesis data to allow earlier
	// adjustment if there isn't enough window data length will be
	// DIFFICULTY_ADJUST_WINDOW + 1 (for initial block time bound)
	let diff_data = global::difficulty_data_to_vector(cursor);

	// First, get the ratio of secondary PoW vs primary, skipping initial header
	let sec_pow_scaling = secondary_pow_scaling(height, &diff_data[1..]);

	// Get the timestamp delta across the window
	let ts_delta: u64 =
		diff_data[DIFFICULTY_ADJUST_WINDOW as usize].timestamp - diff_data[0].timestamp;

	// Get the difficulty sum of the last DIFFICULTY_ADJUST_WINDOW elements
	let diff_sum: u64 = diff_data
		.iter()
		.skip(1)
		.map(|dd| dd.difficulty.to_num())
		.sum();

	// adjust time delta toward goal subject to dampening and clamping
	let adj_ts = clamp(
		damp(ts_delta, BLOCK_TIME_WINDOW, DIFFICULTY_DAMP_FACTOR),
		BLOCK_TIME_WINDOW,
		CLAMP_FACTOR,
	);
	// minimum difficulty avoids getting stuck due to dampening
	let difficulty = max(MIN_DIFFICULTY, diff_sum * BLOCK_TIME_SEC / adj_ts);

	HeaderInfo::from_diff_scaling(Difficulty::from_num(difficulty), sec_pow_scaling)
}

/// Count, in units of 1/100 (a percent), the number of "secondary" (AR) blocks in the provided window of blocks.
pub fn ar_count(_height: u64, diff_data: &[HeaderInfo]) -> u64 {
	100 * diff_data.iter().filter(|n| n.is_secondary).count() as u64
}

/// Factor by which the secondary proof of work difficulty will be adjusted
pub fn secondary_pow_scaling(height: u64, diff_data: &[HeaderInfo]) -> u32 {
	// Get the scaling factor sum of the last DIFFICULTY_ADJUST_WINDOW elements
	let scale_sum: u64 = diff_data.iter().map(|dd| dd.secondary_scaling as u64).sum();

	// compute ideal 2nd_pow_fraction in pct and across window
	let target_pct = secondary_pow_ratio(height);
	let target_count = DIFFICULTY_ADJUST_WINDOW * target_pct;

	// Get the secondary count across the window, adjusting count toward goal
	// subject to dampening and clamping.
	let adj_count = clamp(
		damp(
			ar_count(height, diff_data),
			target_count,
			ar_scale_damp_factor(height),
		),
		target_count,
		CLAMP_FACTOR,
	);
	let scale = scale_sum * target_pct / max(1, adj_count);

	// minimum AR scale avoids getting stuck due to dampening
	max(MIN_AR_SCALE, scale) as u32
}

/// Hard fork modifications:

fn get_c31_hard_fork_block_height() -> u64 {
	// return 202_500 for mainnet and 270_000 for floonet
	if *global::CHAIN_TYPE.read() == global::ChainTypes::Floonet {
		270_000
	} else {
		202_500
	}
}

fn get_epoch_block_offset(epoch: u8) -> u64 {
	let mut ret = get_c31_hard_fork_block_height();
	if epoch >= 2 {
		if *global::CHAIN_TYPE.read() == global::ChainTypes::Floonet {
			ret += DAY_HEIGHT;
		} else {
			ret += WEEK_HEIGHT;
		}
	}

	let mut i = 3;
	while i <= epoch {
		ret += get_epoch_duration(i - 1);
		i = i + 1;
	}
	ret
}

fn get_epoch_duration(epoch: u8) -> u64 {
	match epoch {
		2 => {
			// second epoch is 1 day on floonet and 120 days on mainnet
			if *global::CHAIN_TYPE.read() == global::ChainTypes::Floonet {
				DAY_HEIGHT
			} else {
				120 * DAY_HEIGHT
			}
		}
		3 => {
			// third epoch is 1 day on floonet and 60 days on mainnet
			if *global::CHAIN_TYPE.read() == global::ChainTypes::Floonet {
				DAY_HEIGHT
			} else {
				60 * DAY_HEIGHT
			}
		}
		4 => {
			// fourth epoch is 120 days
			120 * DAY_HEIGHT
		}
		5 => {
			// fifth epoch is 180 days
			180 * DAY_HEIGHT
		}
		6 => {
			// sixth epoch is 180 days
			180 * DAY_HEIGHT
		}
		7 => {
			// seventh epoch is 1 year
			YEAR_HEIGHT
		}
		8 => {
			// eigth epoch is 1 year
			YEAR_HEIGHT
		}
		9 => {
			// nineth epoch is 6 years
			6 * YEAR_HEIGHT
		}
		10 => {
			// tenth epoch is 10 years
			10 * YEAR_HEIGHT
		}
		_ => {
			// eleventh epoch is 1667+ years
			// epoch 11
			876_349_148 // Just over 1667 years.
		}
	}
}

fn get_epoch_reward(epoch: u8) -> u64 {
	match epoch {
		0 => GENESIS_BLOCK_REWARD,
		1 => MWC_FIRST_GROUP_REWARD,
		2 => {
			600_000_000 // 0.6 MWC
		}
		3 => {
			450_000_000 // 0.45 MWC
		}
		4 => {
			300_000_000 // 0.30 MWC
		}
		5 => {
			250_000_000 // 0.25 MWC
		}
		6 => {
			200_000_000 // 0.20 MWC
		}
		7 => {
			150_000_000 // 0.15 MWC
		}
		8 => {
			100_000_000 // 0.10 MWC
		}
		9 => {
			50_000_000 // 0.05 MWC
		}
		10 => {
			25_000_000 // 0.025 MWC
		}
		11 => {
			10_000_000 // 0.01 MWC
		}
		_ => {
			/* epoch == 12 */
			MWC_LAST_BLOCK_REWARD // final block reward just to make it to be 20M coins.
		}
	}
}

/// MWC Block reward for the first group - pre hard fork
pub const MWC_FIRST_GROUP_REWARD: u64 = 2_380_952_380;

/// We have a reward after the last epoch. This is just to get exactly 20M MWC.
pub const MWC_LAST_BLOCK_REWARD: u64 = 2_211_980;

/// Calculate MWC block reward.
pub fn calc_mwc_block_reward(height: u64) -> u64 {
	if height == 0 {
		// Genesis block
		return get_epoch_reward(0);
	}

	if height < get_epoch_block_offset(2) {
		return get_epoch_reward(1);
	} else if height < get_epoch_block_offset(3) {
		return get_epoch_reward(2);
	} else if height < get_epoch_block_offset(4) {
		return get_epoch_reward(3);
	} else if height < get_epoch_block_offset(5) {
		return get_epoch_reward(4);
	} else if height < get_epoch_block_offset(6) {
		return get_epoch_reward(5);
	} else if height < get_epoch_block_offset(7) {
		return get_epoch_reward(6);
	} else if height < get_epoch_block_offset(8) {
		return get_epoch_reward(7);
	} else if height < get_epoch_block_offset(9) {
		return get_epoch_reward(8);
	} else if height < get_epoch_block_offset(10) {
		return get_epoch_reward(9);
	} else if height < get_epoch_block_offset(11) {
		return get_epoch_reward(10);
	} else if height < get_epoch_block_offset(11) + get_epoch_duration(11) {
		return get_epoch_reward(11);
	} else if height == get_epoch_block_offset(11) + get_epoch_duration(11) {
		// last block
		return get_epoch_reward(12);
	}

	return 0;
}

/// MWC  calculate the total number of rewarded coins in all blocks including this one
pub fn calc_mwc_block_overage(height: u64, genesis_had_reward: bool) -> u64 {
	// including this one happens implicitly.
	// Because "this block is included", but 0 block (genesis) block is excluded, we will keep height as it is
	let mut overage: u64 = get_epoch_reward(0); // genesis block reward
	if !genesis_had_reward {
		overage -= get_epoch_reward(0);
	}

	if height < get_epoch_block_offset(2) {
		return overage + height * get_epoch_reward(1);
	}
	overage += get_epoch_reward(1) * (get_epoch_block_offset(2) - 1);

	if height < get_epoch_block_offset(3) {
		return overage + ((height + 1) - get_epoch_block_offset(2)) * get_epoch_reward(2);
	}
	overage += get_epoch_reward(2) * (get_epoch_block_offset(3) - get_epoch_block_offset(2));

	if height < get_epoch_block_offset(4) {
		return overage + ((height + 1) - get_epoch_block_offset(3)) * get_epoch_reward(3);
	}
	overage += get_epoch_reward(3) * (get_epoch_block_offset(4) - get_epoch_block_offset(3));

	if height < get_epoch_block_offset(5) {
		return overage + ((height + 1) - get_epoch_block_offset(4)) * get_epoch_reward(4);
	}
	overage += get_epoch_reward(4) * (get_epoch_block_offset(5) - get_epoch_block_offset(4));

	if height < get_epoch_block_offset(6) {
		return overage + ((height + 1) - get_epoch_block_offset(5)) * get_epoch_reward(5);
	}
	overage += get_epoch_reward(5) * (get_epoch_block_offset(6) - get_epoch_block_offset(5));

	if height < get_epoch_block_offset(7) {
		return overage + ((height + 1) - get_epoch_block_offset(6)) * get_epoch_reward(6);
	}
	overage += get_epoch_reward(6) * (get_epoch_block_offset(7) - get_epoch_block_offset(6));

	if height < get_epoch_block_offset(8) {
		return overage + ((height + 1) - get_epoch_block_offset(7)) * get_epoch_reward(7);
	}
	overage += get_epoch_reward(7) * (get_epoch_block_offset(8) - get_epoch_block_offset(7));

	if height < get_epoch_block_offset(9) {
		return overage + ((height + 1) - get_epoch_block_offset(8)) * get_epoch_reward(8);
	}
	overage += get_epoch_reward(8) * (get_epoch_block_offset(9) - get_epoch_block_offset(8));

	if height < get_epoch_block_offset(10) {
		return overage + ((height + 1) - get_epoch_block_offset(9)) * get_epoch_reward(9);
	}
	overage += get_epoch_reward(9) * (get_epoch_block_offset(10) - get_epoch_block_offset(9));

	if height < get_epoch_block_offset(11) {
		return overage + ((height + 1) - get_epoch_block_offset(10)) * get_epoch_reward(10);
	}
	overage += get_epoch_reward(10) * (get_epoch_block_offset(11) - get_epoch_block_offset(10));

	if height < get_epoch_block_offset(11) + get_epoch_duration(11) {
		return overage + ((height + 1) - get_epoch_block_offset(11)) * get_epoch_reward(11);
	}
	overage += get_epoch_reward(11) * (get_epoch_duration(11));

	// we add the last block reward to get us to 20 million
	if height > get_epoch_block_offset(11) + get_epoch_duration(11) {
		overage += get_epoch_reward(12);
	}

	overage
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_graph_weight() {
		// initial weights
		assert_eq!(graph_weight(1, 31), 256 * 31);
		assert_eq!(graph_weight(1, 32), 512 * 32);
		assert_eq!(graph_weight(1, 33), 1024 * 33);

		// one year in, 31 starts going down, the rest stays the same
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(YEAR_HEIGHT, 31), 256 * 31);
		assert_eq!(graph_weight(YEAR_HEIGHT, 32), 1);
		assert_eq!(graph_weight(YEAR_HEIGHT, 33), 1);

		// 31 loses one factor per week
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(YEAR_HEIGHT + WEEK_HEIGHT, 31), 256 * 31);
		assert_eq!(graph_weight(YEAR_HEIGHT + 2 * WEEK_HEIGHT, 31), 256 * 31);
		assert_eq!(graph_weight(YEAR_HEIGHT + 32 * WEEK_HEIGHT, 31), 256 * 31);

		// 2 years in, 31 still at 0, 32 starts decreasing
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(2 * YEAR_HEIGHT, 31), 256 * 31);
		assert_eq!(graph_weight(2 * YEAR_HEIGHT, 32), 1);
		assert_eq!(graph_weight(2 * YEAR_HEIGHT, 33), 1);

		// 32 phaseout on hold
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(2 * YEAR_HEIGHT + WEEK_HEIGHT, 32), 1);
		assert_eq!(graph_weight(2 * YEAR_HEIGHT + WEEK_HEIGHT, 31), 256 * 31);
		assert_eq!(graph_weight(2 * YEAR_HEIGHT + 30 * WEEK_HEIGHT, 32), 1);
		assert_eq!(graph_weight(2 * YEAR_HEIGHT + 31 * WEEK_HEIGHT, 32), 1);

		// 3 years in, nothing changes
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(3 * YEAR_HEIGHT, 31), 256 * 31);
		assert_eq!(graph_weight(3 * YEAR_HEIGHT, 32), 1);
		assert_eq!(graph_weight(3 * YEAR_HEIGHT, 33), 1);

		// 4 years in, still on hold
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(4 * YEAR_HEIGHT, 31), 256 * 31);
		assert_eq!(graph_weight(4 * YEAR_HEIGHT, 32), 1);
		assert_eq!(graph_weight(4 * YEAR_HEIGHT, 33), 1);
	}

	// MWC test the epoch dates
	#[test]
	fn test_epoch_dates() {
		assert_eq!(get_c31_hard_fork_block_height(), 202_500); // April 1, 2020 hard fork date
		assert_eq!(get_epoch_block_offset(2), 212_580); // April 7, 2020 second epoch begins
		assert_eq!(get_epoch_block_offset(3), 385_380); // August 7, 2020 third epoch begins
		assert_eq!(get_epoch_block_offset(4), 471_780); // October 7, 2020 fourth epoch begins
		assert_eq!(get_epoch_block_offset(5), 644_580); // February 7, 2021 fifth epoch begins
		assert_eq!(get_epoch_block_offset(6), 903_780); // August 7, 2021 sixth epoch begins
		assert_eq!(get_epoch_block_offset(7), 1_162_980); // February 7, 2022 seventh epoch begins
		assert_eq!(get_epoch_block_offset(8), 1_687_140); // February 7, 2023 eighth epoch begins
		assert_eq!(get_epoch_block_offset(9), 2_211_300); // February 7, 2024 nineth epoch begins
		assert_eq!(get_epoch_block_offset(10), 5_356_260); // February 7, 2030 tenth epoch begins
		assert_eq!(get_epoch_block_offset(11), 10_597_860); // February 7, 2040 eleventh epoch begins
		assert_eq!(
			get_epoch_block_offset(11) + get_epoch_duration(11),
			886_947_008
		);
	}

	// MWC  testing calc_mwc_block_reward output for the scedule that documented at definition of calc_mwc_block_reward
	#[test]
	fn test_calc_mwc_block_reward() {
		// first blocks
		assert_eq!(calc_mwc_block_reward(1), 2_380_952_380);
		assert_eq!(calc_mwc_block_reward(2), 2_380_952_380);

		// a little deeper
		assert_eq!(calc_mwc_block_reward(100000), 2_380_952_380);

		// pre hard fork block
		assert_eq!(
			calc_mwc_block_reward(get_c31_hard_fork_block_height() - 1),
			2_380_952_380
		);
		assert_eq!(
			calc_mwc_block_reward(get_c31_hard_fork_block_height()),
			2_380_952_380
		);

		assert_eq!(
			calc_mwc_block_reward(get_c31_hard_fork_block_height() + WEEK_HEIGHT - 1),
			2_380_952_380
		);

		// reward changes 1 week after HF
		assert_eq!(
			calc_mwc_block_reward(get_c31_hard_fork_block_height() + WEEK_HEIGHT),
			600_000_000
		);

		// check epoch 2
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(2)),
			600_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(2) - 1),
			2_380_952_380
		);

		// check epoch 3
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(3)),
			450_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(3) - 1),
			600_000_000
		);

		// check epoch 4
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(4)),
			300_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(4) - 1),
			450_000_000
		);

		// check epoch 5
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(5)),
			250_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(5) - 1),
			300_000_000
		);

		// check epoch 6
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(6)),
			200_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(6) - 1),
			250_000_000
		);

		// check epoch 7
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(7)),
			150_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(7) - 1),
			200_000_000
		);

		// check epoch 8
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(8)),
			100_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(8) - 1),
			150_000_000
		);

		// check epoch 9
		assert_eq!(calc_mwc_block_reward(get_epoch_block_offset(9)), 50_000_000);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(9) - 1),
			100_000_000
		);

		// check epoch 10
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(10)),
			25_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(10) - 1),
			50_000_000
		);

		// check epoch 11
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(11)),
			10_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(11) - 1),
			25_000_000
		);

		// last block reward is special
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(11) + get_epoch_duration(11)),
			MWC_LAST_BLOCK_REWARD
		);

		// 0
		assert_eq!(
			calc_mwc_block_reward(get_epoch_block_offset(11) + get_epoch_duration(11) + 1),
			0
		);

		// far far future
		assert_eq!(calc_mwc_block_reward(2_100_000 * 320000000 + 200), 0); // no reward
	}

	// MWC  testing calc_mwc_block_overage output for the schedule that documented at definition of calc_mwc_block_reward
	#[test]
	fn test_calc_mwc_block_overage() {
		let genesis_reward: u64 = GENESIS_BLOCK_REWARD;

		assert_eq!(calc_mwc_block_overage(0, true), genesis_reward); // Doesn't make sense to call for the genesis block
		assert_eq!(calc_mwc_block_overage(0, false), 0); // Doesn't make sense to call for the genesis block
		assert_eq!(
			calc_mwc_block_overage(1, true),
			genesis_reward + MWC_FIRST_GROUP_REWARD * 1
		);

		assert_eq!(
			calc_mwc_block_overage(get_c31_hard_fork_block_height(), true),
			genesis_reward + MWC_FIRST_GROUP_REWARD * get_c31_hard_fork_block_height()
		);

		assert_eq!(
			calc_mwc_block_overage(get_c31_hard_fork_block_height() + WEEK_HEIGHT - 1, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_c31_hard_fork_block_height() + WEEK_HEIGHT - 1)
		);

		assert_eq!(
			calc_mwc_block_overage(get_c31_hard_fork_block_height() + WEEK_HEIGHT, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_c31_hard_fork_block_height() + WEEK_HEIGHT - 1)
				+ get_epoch_reward(2) * 1
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(2), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_c31_hard_fork_block_height() + WEEK_HEIGHT - 1)
				+ get_epoch_reward(2) * 1
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(3) - 1, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(3), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ get_epoch_reward(3)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(3) + 1, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ get_epoch_reward(3) * 2
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(4), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ get_epoch_reward(4)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(4) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ get_epoch_reward(4) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(5), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ get_epoch_reward(5)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(5) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ get_epoch_reward(5) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(6), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ get_epoch_reward(6)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(6) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ get_epoch_reward(6) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(7), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ get_epoch_reward(7)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(7) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ get_epoch_reward(7) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(8), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ (get_epoch_block_offset(8) - get_epoch_block_offset(7)) * get_epoch_reward(7)
				+ get_epoch_reward(8)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(8) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ (get_epoch_block_offset(8) - get_epoch_block_offset(7)) * get_epoch_reward(7)
				+ get_epoch_reward(8) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(9), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ (get_epoch_block_offset(8) - get_epoch_block_offset(7)) * get_epoch_reward(7)
				+ (get_epoch_block_offset(9) - get_epoch_block_offset(8)) * get_epoch_reward(8)
				+ get_epoch_reward(9)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(9) + 39, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ (get_epoch_block_offset(8) - get_epoch_block_offset(7)) * get_epoch_reward(7)
				+ (get_epoch_block_offset(9) - get_epoch_block_offset(8)) * get_epoch_reward(8)
				+ get_epoch_reward(9) * 40
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(10), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ (get_epoch_block_offset(8) - get_epoch_block_offset(7)) * get_epoch_reward(7)
				+ (get_epoch_block_offset(9) - get_epoch_block_offset(8)) * get_epoch_reward(8)
				+ (get_epoch_block_offset(10) - get_epoch_block_offset(9)) * get_epoch_reward(9)
				+ get_epoch_reward(10)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(10) + 1, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ (get_epoch_block_offset(8) - get_epoch_block_offset(7)) * get_epoch_reward(7)
				+ (get_epoch_block_offset(9) - get_epoch_block_offset(8)) * get_epoch_reward(8)
				+ (get_epoch_block_offset(10) - get_epoch_block_offset(9)) * get_epoch_reward(9)
				+ get_epoch_reward(10) * 2
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(11), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ (get_epoch_block_offset(8) - get_epoch_block_offset(7)) * get_epoch_reward(7)
				+ (get_epoch_block_offset(9) - get_epoch_block_offset(8)) * get_epoch_reward(8)
				+ (get_epoch_block_offset(10) - get_epoch_block_offset(9)) * get_epoch_reward(9)
				+ (get_epoch_block_offset(11) - get_epoch_block_offset(10)) * get_epoch_reward(10)
				+ get_epoch_reward(11)
		);

		assert_eq!(
			calc_mwc_block_overage(get_epoch_block_offset(11) + 39, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(2) - 1)
				+ (get_epoch_block_offset(3) - get_epoch_block_offset(2)) * get_epoch_reward(2)
				+ (get_epoch_block_offset(4) - get_epoch_block_offset(3)) * get_epoch_reward(3)
				+ (get_epoch_block_offset(5) - get_epoch_block_offset(4)) * get_epoch_reward(4)
				+ (get_epoch_block_offset(6) - get_epoch_block_offset(5)) * get_epoch_reward(5)
				+ (get_epoch_block_offset(7) - get_epoch_block_offset(6)) * get_epoch_reward(6)
				+ (get_epoch_block_offset(8) - get_epoch_block_offset(7)) * get_epoch_reward(7)
				+ (get_epoch_block_offset(9) - get_epoch_block_offset(8)) * get_epoch_reward(8)
				+ (get_epoch_block_offset(10) - get_epoch_block_offset(9)) * get_epoch_reward(9)
				+ (get_epoch_block_offset(11) - get_epoch_block_offset(10)) * get_epoch_reward(10)
				+ get_epoch_reward(11) * 40
		);

		// Calculating the total number of coins
		let total_blocks_reward = calc_mwc_block_overage(2_100_000_000 * 1000, true);
		// Expected 20M in total. The coin base is exactly 20M
		assert_eq!(total_blocks_reward, 20000000000000000);
	}
}
