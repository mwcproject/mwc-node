// Copyright 2019 The Grin Developers
// Copyright 2024 The MWC Developers
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

use crate::core::block::HeaderVersion;
use crate::core::hash::Hash;
use crate::global;
use crate::pow::Difficulty;
use std::cmp::{max, min};
use std::convert::TryFrom;

pub use crate::difficulty_cache::DifficultyCache;

/// Errors thrown by consensus calculations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Data overflow error
	#[error("Consensus data overflow error, {0}")]
	DataOverflow(String),
	/// Not enough history data. This error can be triggered by data storage failure or data corruption.
	/// If needed data is not accessible this error will be returned
	#[error("Blocks history is too short, less than a window size")]
	HistoryTooShort,
	/// Unable to read header difficulty data.
	#[error("Unable to read header difficulty data, {0}")]
	HeaderIO(String),
	/// Invalid edge bits value
	#[error("Invalid edge bits value {0}")]
	InvalidEdgeBits(u8),
	/// Already initialized
	#[error("Already initialized: {0}")]
	AlreadyInitialized(String),
	/// Invalid parameter
	#[error("Invalid parameter: {0}")]
	InvalidParameter(String),
}

/// A mwc is divisible to 10^9, following the SI prefixes
pub const MWC_BASE: u64 = 1_000_000_000;
/// Millimwc, a thousand of a mwc
pub const MILLI_MWC: u64 = MWC_BASE / 1_000;
/// Micromwc, a thousand of a millimwc
pub const MICRO_MWC: u64 = MILLI_MWC / 1_000;
/// Nanomwc, smallest unit, takes a billion to make a mwc
pub const NANO_MWC: u64 = 1;

/// Block interval, in seconds, the network will tune its next_target for. Note
/// that we may reduce this value in the future as we get more data on mining
/// with Cuckoo Cycle, networks improve and block propagation is optimized
/// (adjusting the reward accordingly).
pub const BLOCK_TIME_SEC: u64 = 60;

/// MWC - Here is a block reward.
/// The block subsidy amount, one mwc per second on average
//pub const REWARD: u64 = BLOCK_TIME_SEC * MWC_BASE;

/// Actual block reward for a given total fee amount
pub fn reward(context_id: u32, fee: u64, height: u64) -> Result<u64, Error> {
	// MWC has block reward schedule similar to bitcoin
	let block_reward = calc_mwc_block_reward(context_id, height);
	block_reward.checked_add(fee).ok_or_else(|| {
		Error::DataOverflow(format!(
			"consensus::reward, block_reward={} fee={}",
			block_reward, fee
		))
	})
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
/// approximately 1 year after mwc) and we also make it go to 0
/// over the course of 1 year. This will roughly keep us inline with mwc.
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

/// Size Weight of an input when counted against the max block weight capacity
pub const BLOCK_INPUT_WEIGHT: u64 = 1;

/// Size Weight of an output when counted against the max block weight capacity
pub const BLOCK_OUTPUT_WEIGHT: u64 = 21;

/// Size Weight of a kernel when counted against the max block weight capacity
pub const BLOCK_KERNEL_WEIGHT: u64 = 3;

/// Transaction fee weight of input
pub const TXFEE_INPUT_WEIGHT: u64 = 1;

/// Transaction fee weight of output
pub const TXFEE_OUTPUT_WEIGHT: u64 = 4;

/// Transaction fee weight of kernel
pub const TXFEE_KERNEL_WEIGHT: u64 = 1;

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
pub const MAX_BLOCK_WEIGHT: u64 = 40_000;

// We want to keep the mwc test cases for NRD kernels.
// note!!! Currently NRD is disabled in MWC network. We need hardfork to activate it

/// AutomatedTesting and UserTesting HF1 height.
pub const TESTING_FIRST_HARD_FORK: u64 = 3;
/// AutomatedTesting and UserTesting HF2 height.
pub const TESTING_SECOND_HARD_FORK: u64 = 6;
/// AutomatedTesting and UserTesting HF3 height.
pub const TESTING_THIRD_HARD_FORK: u64 = 9;

/// Fork every 3 blocks
pub const TESTING_HARD_FORK_INTERVAL: u64 = 3;

/// Check whether the block version is valid at a given height
/// MWC doesn't want like mwc change the algorithms for mining. So version is constant
pub fn header_version(context_id: u32, height: u64) -> HeaderVersion {
	let chain_type = global::get_chain_type(context_id);
	match chain_type {
		global::ChainTypes::Mainnet | global::ChainTypes::Floonet => {
			if height < get_c31_hard_fork_block_height(context_id) {
				HeaderVersion(1)
			} else {
				HeaderVersion(2)
			}
		}
		// Note!!!! We need that to cover NRD tests.
		global::ChainTypes::AutomatedTesting | global::ChainTypes::UserTesting => {
			if height < TESTING_FIRST_HARD_FORK {
				HeaderVersion(1)
			} else if height < TESTING_SECOND_HARD_FORK {
				HeaderVersion(2)
			} else if height < TESTING_THIRD_HARD_FORK {
				HeaderVersion(3)
			} else {
				HeaderVersion(4)
			}
		}
	}
}

/// Check whether the block version is valid at a given height.
/// Currently we only use the default version. No hard forks planned.
pub fn valid_header_version(context_id: u32, height: u64, version: HeaderVersion) -> bool {
	let chain_type = global::get_chain_type(context_id);
	match chain_type {
		global::ChainTypes::Mainnet | global::ChainTypes::Floonet => {
			if height < get_c31_hard_fork_block_height(context_id) {
				version == HeaderVersion(1)
			} else {
				version == HeaderVersion(2)
			}
		}
		// Note!!!! We need that to cover NRD tests.
		global::ChainTypes::AutomatedTesting | global::ChainTypes::UserTesting => {
			if height < TESTING_FIRST_HARD_FORK {
				version == HeaderVersion(1)
			} else if height < TESTING_SECOND_HARD_FORK {
				version == HeaderVersion(2)
			} else if height < TESTING_THIRD_HARD_FORK {
				version == HeaderVersion(3)
			} else {
				version == HeaderVersion(4)
			}
		}
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
pub fn graph_weight(context_id: u32, height: u64, edge_bits: u8) -> Result<u64, Error> {
	if edge_bits < global::base_edge_bits(context_id) {
		return Err(Error::InvalidEdgeBits(edge_bits));
	}
	if height < get_c31_hard_fork_block_height(context_id) || edge_bits <= 31 {
		// Safe because all values are constants, no data overflow is possible
		let weight_base = 2u64
			.checked_shl((edge_bits as u32) - global::base_edge_bits(context_id) as u32)
			.ok_or_else(|| Error::DataOverflow(format!("graph_weight edge_bits={}", edge_bits)))?;
		let res_base = weight_base.checked_mul(edge_bits as u64).ok_or_else(|| {
			Error::DataOverflow(format!(
				"graph_weight edge_bits={} weight_base={}",
				edge_bits, weight_base
			))
		})?;
		Ok(res_base)
	} else {
		Ok(1)
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
/// take place. Used to iterate through a number of blocks. Note that an instance
/// of this is unable to calculate its own hash, due to an optimization that prevents
/// the header's PoW proof nonces from being deserialized on read
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderDifficultyInfo {
	/// Height if this block
	pub height: u64,
	/// Hash of this block
	pub hash: Option<Hash>,
	/// Timestamp of the header, 1 when not used (returned info)
	pub timestamp: u64,
	/// Network difficulty or next difficulty to use
	pub difficulty: Difficulty,
	/// Network secondary PoW factor or factor to use
	pub secondary_scaling: u32,
	/// Whether the header is a secondary proof of work
	pub is_secondary: bool,
}

/// Converts difficulty iterator items into header difficulty data.
pub trait IntoHeaderDifficultyInfo {
	/// Convert into header difficulty data.
	fn into_header_difficulty_info(self) -> Result<HeaderDifficultyInfo, Error>;
}

impl IntoHeaderDifficultyInfo for HeaderDifficultyInfo {
	fn into_header_difficulty_info(self) -> Result<HeaderDifficultyInfo, Error> {
		Ok(self)
	}
}

impl IntoHeaderDifficultyInfo for Result<HeaderDifficultyInfo, Error> {
	fn into_header_difficulty_info(self) -> Result<HeaderDifficultyInfo, Error> {
		self
	}
}

impl HeaderDifficultyInfo {
	/// Default constructor
	pub fn new(
		height: u64,
		hash: Option<Hash>,
		timestamp: u64,
		difficulty: Difficulty,
		secondary_scaling: u32,
		is_secondary: bool,
	) -> HeaderDifficultyInfo {
		HeaderDifficultyInfo {
			height,
			hash,
			timestamp,
			difficulty,
			secondary_scaling,
			is_secondary,
		}
	}

	/// Constructor from a timestamp and difficulty, setting a default secondary
	/// PoW factor
	pub fn from_ts_diff(
		context_id: u32,
		timestamp: u64,
		difficulty: Difficulty,
	) -> HeaderDifficultyInfo {
		HeaderDifficultyInfo {
			height: 0,
			hash: None,
			timestamp,
			difficulty,
			secondary_scaling: global::initial_graph_weight(context_id),

			is_secondary: true,
		}
	}

	/// Constructor from a difficulty and secondary factor, setting a default
	/// timestamp
	pub fn from_diff_scaling(
		difficulty: Difficulty,
		secondary_scaling: u32,
	) -> HeaderDifficultyInfo {
		HeaderDifficultyInfo {
			height: 0,
			hash: None,
			timestamp: 1,
			difficulty,
			secondary_scaling,
			is_secondary: true,
		}
	}
}

/// Move value linearly toward a goal
pub fn damp(actual: u64, goal: u64, damp_factor: u64) -> Result<u64, Error> {
	//(actual + (damp_factor - 1) * goal) / damp_factor
	damp_factor
		.checked_sub(1)
		.and_then(|n| n.checked_mul(goal))
		.and_then(|n| n.checked_add(actual))
		.and_then(|n| n.checked_div(damp_factor))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"consensus::damp, actual={} goal={} damp_factor={}",
				actual, goal, damp_factor
			))
		})
}

/// limit value to be within some factor from a goal
pub fn clamp(actual: u64, goal: u64, clamp_factor: u64) -> Result<u64, Error> {
	// max(goal / clamp_factor, min(actual, goal * clamp_factor))
	let lower = goal.checked_div(clamp_factor);
	let upper = goal.checked_mul(clamp_factor);

	match (lower, upper) {
		(Some(lower), Some(upper)) => Ok(max(lower, min(actual, upper))),
		_ => Err(Error::DataOverflow(format!(
			"consensus::clamp, actual={} goal={} clamp_factor={}",
			actual, goal, clamp_factor
		))),
	}
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
pub fn next_difficulty<T>(
	context_id: u32,
	height: u64,
	cursor: T,
	cache_values: &mut DifficultyCache,
) -> Result<HeaderDifficultyInfo, Error>
where
	T: IntoIterator,
	T::Item: IntoHeaderDifficultyInfo,
{
	// Create vector of difficulty data running from earliest
	// to latest, and pad with simulated pre-genesis data to allow earlier
	// adjustment if there isn't enough window data length will be
	// DIFFICULTY_ADJUST_WINDOW + 1 (for initial block time bound)
	let diff_data = global::difficulty_data_to_vector(context_id, cursor, cache_values)?;

	next_difficulty_from_diff_data(height, &diff_data)
}

pub(crate) fn next_difficulty_from_diff_data(
	height: u64,
	diff_data: &[HeaderDifficultyInfo],
) -> Result<HeaderDifficultyInfo, Error> {
	let expected_len = DIFFICULTY_ADJUST_WINDOW as usize + 1;
	if diff_data.len() != expected_len {
		return Err(Error::InvalidParameter(format!(
			"difficulty data length {} does not match expected window length {}",
			diff_data.len(),
			expected_len
		)));
	}

	validate_difficulty_data_sequence(height, diff_data)?;

	// First, get the ratio of secondary PoW vs primary, skipping initial header
	let sec_pow_scaling = secondary_pow_scaling(height, &diff_data[1..])?;

	// Get the timestamp delta across the window
	let last_timestamp = diff_data[DIFFICULTY_ADJUST_WINDOW as usize].timestamp;
	let first_timestamp = diff_data[0].timestamp;
	let ts_delta = last_timestamp.checked_sub(first_timestamp).ok_or_else(|| {
		Error::DataOverflow(format!(
			"consensus::next_difficulty, last_timestamp={} first_timestamp={}",
			last_timestamp, first_timestamp
		))
	})?;

	// 128 bit sum is safe. DIFFICULTY_ADJUST_WINDOW size is relatevly small
	let diff_sum: u128 = diff_data
		.iter()
		.skip(1)
		.map(|dd| dd.difficulty.to_num() as u128)
		.sum();

	// adjust time delta toward goal subject to dampening and clamping
	let adj_ts = clamp(
		damp(ts_delta, BLOCK_TIME_WINDOW, DIFFICULTY_DAMP_FACTOR)?,
		BLOCK_TIME_WINDOW,
		CLAMP_FACTOR,
	)?;

	// diff_sum * BLOCK_TIME_SEC / adj_ts
	let res_difficulty = diff_sum
		.checked_mul(BLOCK_TIME_SEC as u128)
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"consensus::next_difficulty, diff_sum={} block_time_sec={}",
				diff_sum, BLOCK_TIME_SEC
			))
		})? / max(1u128, adj_ts as u128);
	// It is implicit change in consensus, in case if difficulty will skyrocket, we don't want to go offline because of that.
	// In case of overflow we will specify maximum possible difficulty
	let res_difficulty = match u64::try_from(res_difficulty) {
		Ok(r) => r,
		Err(_) => u64::MAX - 1,
	};
	// minimum difficulty avoids getting stuck due to dampening
	let difficulty = max(MIN_DIFFICULTY, res_difficulty);

	Ok(HeaderDifficultyInfo::from_diff_scaling(
		Difficulty::from_num(difficulty),
		sec_pow_scaling,
	))
}

fn validate_difficulty_data_sequence(
	height: u64,
	diff_data: &[HeaderDifficultyInfo],
) -> Result<(), Error> {
	if let Some(latest_real_header) = diff_data.iter().rev().find(|entry| entry.hash.is_some()) {
		let expected_height = latest_real_header.height.checked_add(1).ok_or_else(|| {
			Error::DataOverflow(format!(
				"consensus::validate_difficulty_data_sequence, latest_real_header.height={}",
				latest_real_header.height
			))
		})?;
		if height != expected_height {
			return Err(Error::InvalidParameter(format!(
				"difficulty height {} does not follow latest difficulty data height {}",
				height, latest_real_header.height
			)));
		}
	}

	let mut saw_real_header = false;
	for entry in diff_data {
		if entry.hash.is_some() {
			saw_real_header = true;
		} else if saw_real_header {
			return Err(Error::InvalidParameter(
				"synthetic difficulty data appears after real header data".to_string(),
			));
		}
	}

	for pair in diff_data.windows(2) {
		let prev = &pair[0];
		let next = &pair[1];

		if next.timestamp < prev.timestamp {
			return Err(Error::InvalidParameter(format!(
				"difficulty data timestamps are descreasing: height {} timestamp {} follows height {} timestamp {}",
				next.height, next.timestamp, prev.height, prev.timestamp
			)));
		}

		// Synthetic pre-genesis padding cannot represent true negative block
		// heights in this u64 field. Validate real header continuity and rely
		// on timestamp ordering across the synthetic-to-real boundary.
		if prev.hash.is_some() && next.hash.is_some() {
			let expected_height = prev.height.checked_add(1).ok_or_else(|| {
				Error::DataOverflow(format!(
					"consensus::validate_difficulty_data_sequence, prev.height={}",
					prev.height
				))
			})?;
			if next.height != expected_height {
				return Err(Error::InvalidParameter(format!(
					"difficulty data is not contiguous: height {} follows {}",
					next.height, prev.height
				)));
			}
		}
	}

	Ok(())
}

/// Count, in units of 1/100 (a percent), the number of "secondary" (AR) blocks in the provided window of blocks.
pub fn ar_count(_height: u64, diff_data: &[HeaderDifficultyInfo]) -> u64 {
	// Safe because diff_data.len() is much smaller than u64, 100 is a small constant
	100 * diff_data.iter().filter(|n| n.is_secondary).count() as u64
}

/// Factor by which the secondary proof of work difficulty will be adjusted
pub fn secondary_pow_scaling(
	height: u64,
	diff_data: &[HeaderDifficultyInfo],
) -> Result<u32, Error> {
	// Get the scaling factor sum of the last DIFFICULTY_ADJUST_WINDOW elements
	// Safe because dd.secondary_scaling is u32, so the values are small to overflow the sum
	let scale_sum: u64 = diff_data.iter().map(|dd| dd.secondary_scaling as u64).sum();

	// compute ideal 2nd_pow_fraction in pct and across window
	let target_pct = secondary_pow_ratio(height);
	// safe because target_pct is less than 54, DIFFICULTY_ADJUST_WINDOW is a small constant
	let target_count = DIFFICULTY_ADJUST_WINDOW * target_pct;

	// Get the secondary count across the window, adjusting count toward goal
	// subject to dampening and clamping.
	let adj_count = clamp(
		damp(
			ar_count(height, diff_data),
			target_count,
			ar_scale_damp_factor(height),
		)?,
		target_count,
		CLAMP_FACTOR,
	)?;

	// Safe because scale_sum is much smaller than u64::MAX, target_pct is less than 45,
	let scale = scale_sum * target_pct / max(1, adj_count);

	// Keep the historical wrapping cast here. This value is consensus-critical
	// and existing Floonet/Mainnet headers were mined with the legacy `as u32`
	// behavior when the balancing formula exceeds u32::MAX. Saturating instead
	// changes the expected secondary scale and causes valid peers to be rejected.
	Ok(max(MIN_AR_SCALE, scale) as u32)
}

/// Hard fork modifications:

fn get_c31_hard_fork_block_height(context_id: u32) -> u64 {
	// return 202_500 for mainnet and 270_000 for floonet
	if global::get_chain_type(context_id) == global::ChainTypes::Floonet {
		270_000
	} else {
		202_500
	}
}

fn get_epoch_block_offset(context_id: u32, epoch: u8) -> u64 {
	// Safe because get_c31_hard_fork_block_height is a constant, DAY_HEIGHT & WEEK_HEIGHT are constants as well
	let mut ret = get_c31_hard_fork_block_height(context_id);
	if epoch >= 2 {
		if global::get_chain_type(context_id) == global::ChainTypes::Floonet {
			ret += DAY_HEIGHT;
		} else {
			ret += WEEK_HEIGHT;
		}
	}

	// Safe because get_epoch_duration are constants as well and there sum much smaller than u64::MAX
	let mut i = 3;
	while i <= epoch {
		match get_epoch_duration(context_id, i - 1) {
			Some(len) => ret += len,
			None => return u64::MAX, // None mean that the length is unlimited, so the prev offset is the resulting one.
		}
		let (next_i, overflowed) = i.overflowing_add(1);
		if overflowed {
			break;
		}
		i = next_i;
	}
	ret
}

fn get_epoch_duration(context_id: u32, epoch: u8) -> Option<u64> {
	match epoch {
		2 => {
			// second epoch is 1 day on floonet and 120 days on mainnet
			if global::get_chain_type(context_id) == global::ChainTypes::Floonet {
				Some(DAY_HEIGHT)
			} else {
				Some(120 * DAY_HEIGHT)
			}
		}
		3 => {
			// third epoch is 1 day on floonet and 60 days on mainnet
			if global::get_chain_type(context_id) == global::ChainTypes::Floonet {
				Some(DAY_HEIGHT)
			} else {
				Some(60 * DAY_HEIGHT)
			}
		}
		4 => {
			// fourth epoch is 120 days
			Some(120 * DAY_HEIGHT)
		}
		5 => {
			// fifth epoch is 180 days
			Some(180 * DAY_HEIGHT)
		}
		6 => {
			// sixth epoch is 180 days
			Some(180 * DAY_HEIGHT)
		}
		7 => {
			// seventh epoch is 1 year
			Some(YEAR_HEIGHT)
		}
		8 => {
			// eigth epoch is 1 year
			Some(YEAR_HEIGHT)
		}
		9 => {
			// nineth epoch is 6 years
			Some(6 * YEAR_HEIGHT)
		}
		10 => {
			// tenth epoch is 10 years
			Some(10 * YEAR_HEIGHT)
		}
		11 => {
			// eleventh epoch is 1667+ years
			// epoch 11
			Some(876_349_148) // Just over 1667 years.
		}
		12 => {
			Some(1) // One block to mine MWC_LAST_BLOCK_REWARD
		}
		_ => None, // Next epoches don't have any limitations on the length
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
		12 => {
			MWC_LAST_BLOCK_REWARD // final block reward just to make it to be 20M coins.
		}
		_ => {
			/* epoch == 13  - no rewards */
			0
		}
	}
}

/// MWC Block reward for the first group - pre hard fork
pub const MWC_FIRST_GROUP_REWARD: u64 = 2_380_952_380;

/// We have a reward after the last epoch. This is just to get exactly 20M MWC.
pub const MWC_LAST_BLOCK_REWARD: u64 = 2_211_980;

/// Calculate MWC block reward.
pub fn calc_mwc_block_reward(context_id: u32, height: u64) -> u64 {
	if height == 0 {
		// Genesis block
		return get_epoch_reward(0);
	}
	// edge case, even impossible but let's handle it
	if height == u64::MAX {
		return 0;
	}

	for epoch in 2u8..255u8 {
		if height < get_epoch_block_offset(context_id, epoch) {
			return get_epoch_reward(epoch - 1);
		}
	}
	panic!("calc_mwc_block_reward internal error");
}

/// MWC  calculate the total number of rewarded coins in all blocks including this one
pub fn calc_mwc_block_overage(context_id: u32, height: u64, genesis_had_reward: bool) -> u64 {
	// height u64::MAX is an edge case. Total reward is the same as u64::MAX - 1
	// because rewards are already zero in the final unbounded epoch.
	if height == u64::MAX {
		return calc_mwc_block_overage(context_id, height - 1, genesis_had_reward);
	}

	// including this one happens implicitly.
	// Because "this block is included", but 0 block (genesis) block is excluded, we will keep height as it is
	let mut overage: u64 = get_epoch_reward(0); // genesis block reward
	if !genesis_had_reward {
		overage -= get_epoch_reward(0);
	}

	if height < get_epoch_block_offset(context_id, 2) {
		return overage + height * get_epoch_reward(1);
	}
	overage += get_epoch_reward(1) * (get_epoch_block_offset(context_id, 2) - 1);

	for epoch in 3u8..255u8 {
		let prev_epoch_offset = get_epoch_block_offset(context_id, epoch - 1);
		let epoch_block_offset = get_epoch_block_offset(context_id, epoch);
		if height < epoch_block_offset {
			let blocks_in_epoch = height - prev_epoch_offset + 1;
			return overage + blocks_in_epoch * get_epoch_reward(epoch - 1);
		}
		overage += get_epoch_reward(epoch - 1) * (epoch_block_offset - prev_epoch_offset);
	}
	panic!("Internal calc_mwc_block_overage error");
}

#[cfg(test)]
mod test {
	use super::*;

	fn real_difficulty_data() -> Vec<HeaderDifficultyInfo> {
		(0..=DIFFICULTY_ADJUST_WINDOW)
			.map(|height| {
				HeaderDifficultyInfo::new(
					height,
					Some(Hash::from_vec(&height.to_le_bytes())),
					1_000 + height * BLOCK_TIME_SEC,
					Difficulty::from_num(100),
					1,
					false,
				)
			})
			.collect()
	}

	fn real_difficulty_next_height() -> u64 {
		DIFFICULTY_ADJUST_WINDOW + 1
	}

	#[test]
	fn next_difficulty_rejects_short_difficulty_window() {
		let mut diff_data = real_difficulty_data();
		diff_data.pop();

		let err =
			next_difficulty_from_diff_data(real_difficulty_next_height(), &diff_data).unwrap_err();
		assert!(matches!(err, Error::InvalidParameter(_)));
	}

	#[test]
	fn next_difficulty_rejects_overlong_difficulty_window() {
		let mut diff_data = real_difficulty_data();
		diff_data.push(HeaderDifficultyInfo::new(
			DIFFICULTY_ADJUST_WINDOW + 1,
			Some(Hash::from_vec(
				&(DIFFICULTY_ADJUST_WINDOW + 1).to_le_bytes(),
			)),
			1_000 + (DIFFICULTY_ADJUST_WINDOW + 1) * BLOCK_TIME_SEC,
			Difficulty::from_num(100),
			1,
			false,
		));

		let err =
			next_difficulty_from_diff_data(DIFFICULTY_ADJUST_WINDOW + 2, &diff_data).unwrap_err();
		assert!(matches!(err, Error::InvalidParameter(_)));
	}

	#[test]
	fn next_difficulty_rejects_non_contiguous_real_difficulty_heights() {
		let mut diff_data = real_difficulty_data();
		diff_data[10].height += 1;

		let err =
			next_difficulty_from_diff_data(real_difficulty_next_height(), &diff_data).unwrap_err();
		assert!(matches!(err, Error::InvalidParameter(_)));
	}

	#[test]
	fn next_difficulty_rejects_descreased_real_difficulty_timestamps() {
		let mut diff_data = real_difficulty_data();
		diff_data[10].timestamp = diff_data[9].timestamp;

		// Not increasing is fine - it is part of cncensus.
		next_difficulty_from_diff_data(real_difficulty_next_height(), &diff_data).unwrap();

		// Decriasing is not allowed, must be rejected
		diff_data[10].timestamp = diff_data[9].timestamp.saturating_sub(1);
		let err =
			next_difficulty_from_diff_data(real_difficulty_next_height(), &diff_data).unwrap_err();
		assert!(matches!(err, Error::InvalidParameter(_)));
	}

	#[test]
	fn next_difficulty_rejects_height_that_does_not_follow_latest_real_header() {
		let diff_data = real_difficulty_data();

		let err = next_difficulty_from_diff_data(real_difficulty_next_height() + 1, &diff_data)
			.unwrap_err();
		assert!(matches!(err, Error::InvalidParameter(_)));
	}

	#[test]
	fn next_difficulty_allows_synthetic_padding_before_real_header() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);

		let real_header = HeaderDifficultyInfo::new(
			0,
			Some(Hash::from_vec(&[0])),
			DIFFICULTY_ADJUST_WINDOW * BLOCK_TIME_SEC,
			Difficulty::from_num(100),
			1,
			false,
		);
		let mut cache_values = DifficultyCache::new();
		let diff_data =
			global::difficulty_data_to_vector(0, vec![real_header], &mut cache_values).unwrap();

		for pair in diff_data.windows(2) {
			assert!(pair[1].timestamp > pair[0].timestamp);
		}
		for (idx, entry) in diff_data
			.iter()
			.take_while(|entry| entry.hash.is_none())
			.enumerate()
		{
			assert_eq!(entry.height, idx as u64);
		}
		next_difficulty_from_diff_data(1, &diff_data).unwrap();
	}

	#[test]
	fn secondary_pow_scaling_preserves_legacy_u32_wrapping() {
		let diff_data = (0..DIFFICULTY_ADJUST_WINDOW)
			.map(|height| {
				HeaderDifficultyInfo::new(
					height,
					Some(Hash::from_vec(&height.to_le_bytes())),
					1_000 + height * BLOCK_TIME_SEC,
					Difficulty::from_num(100),
					u32::MAX,
					false,
				)
			})
			.collect::<Vec<_>>();

		let target_pct = secondary_pow_ratio(1);
		let target_count = DIFFICULTY_ADJUST_WINDOW * target_pct;
		let adj_count = clamp(
			damp(
				ar_count(1, &diff_data),
				target_count,
				ar_scale_damp_factor(1),
			)
			.unwrap(),
			target_count,
			CLAMP_FACTOR,
		)
		.unwrap();
		let scale_sum = diff_data
			.iter()
			.map(|dd| dd.secondary_scaling as u64)
			.sum::<u64>();
		let raw_scale = scale_sum * target_pct / max(1, adj_count);
		assert!(raw_scale > u32::MAX as u64);

		assert_eq!(
			secondary_pow_scaling(1, &diff_data).unwrap(),
			max(MIN_AR_SCALE, raw_scale) as u32
		);
	}

	#[test]
	fn test_graph_weight() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		global::set_local_nrd_enabled(false);

		// initial weights
		assert_eq!(graph_weight(0, 1, 31).unwrap(), 256 * 31);
		assert_eq!(graph_weight(0, 1, 32).unwrap(), 512 * 32);
		assert_eq!(graph_weight(0, 1, 33).unwrap(), 1024 * 33);

		// one year in, 31 starts going down, the rest stays the same
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(0, YEAR_HEIGHT, 31).unwrap(), 256 * 31);
		assert_eq!(graph_weight(0, YEAR_HEIGHT, 32).unwrap(), 1);
		assert_eq!(graph_weight(0, YEAR_HEIGHT, 33).unwrap(), 1);

		// 31 loses one factor per week
		// after hard fork, constant values despite height
		assert_eq!(
			graph_weight(0, YEAR_HEIGHT + WEEK_HEIGHT, 31).unwrap(),
			256 * 31
		);
		assert_eq!(
			graph_weight(0, YEAR_HEIGHT + 2 * WEEK_HEIGHT, 31).unwrap(),
			256 * 31
		);
		assert_eq!(
			graph_weight(0, YEAR_HEIGHT + 32 * WEEK_HEIGHT, 31).unwrap(),
			256 * 31
		);

		// 2 years in, 31 still at 0, 32 starts decreasing
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(0, 2 * YEAR_HEIGHT, 31).unwrap(), 256 * 31);
		assert_eq!(graph_weight(0, 2 * YEAR_HEIGHT, 32).unwrap(), 1);
		assert_eq!(graph_weight(0, 2 * YEAR_HEIGHT, 33).unwrap(), 1);

		// 32 phaseout on hold
		// after hard fork, constant values despite height
		assert_eq!(
			graph_weight(0, 2 * YEAR_HEIGHT + WEEK_HEIGHT, 32).unwrap(),
			1
		);
		assert_eq!(
			graph_weight(0, 2 * YEAR_HEIGHT + WEEK_HEIGHT, 31).unwrap(),
			256 * 31
		);
		assert_eq!(
			graph_weight(0, 2 * YEAR_HEIGHT + 30 * WEEK_HEIGHT, 32).unwrap(),
			1
		);
		assert_eq!(
			graph_weight(0, 2 * YEAR_HEIGHT + 31 * WEEK_HEIGHT, 32).unwrap(),
			1
		);

		// 3 years in, nothing changes
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(0, 3 * YEAR_HEIGHT, 31).unwrap(), 256 * 31);
		assert_eq!(graph_weight(0, 3 * YEAR_HEIGHT, 32).unwrap(), 1);
		assert_eq!(graph_weight(0, 3 * YEAR_HEIGHT, 33).unwrap(), 1);

		// 4 years in, still on hold
		// after hard fork, constant values despite height
		assert_eq!(graph_weight(0, 4 * YEAR_HEIGHT, 31).unwrap(), 256 * 31);
		assert_eq!(graph_weight(0, 4 * YEAR_HEIGHT, 32).unwrap(), 1);
		assert_eq!(graph_weight(0, 4 * YEAR_HEIGHT, 33).unwrap(), 1);
	}

	// MWC test the epoch dates
	#[test]
	fn test_epoch_dates() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		global::set_local_nrd_enabled(false);

		assert_eq!(get_c31_hard_fork_block_height(0), 202_500); // April 1, 2020 hard fork date
		assert_eq!(get_epoch_block_offset(0, 2), 212_580); // April 7, 2020 second epoch begins
		assert_eq!(get_epoch_block_offset(0, 3), 385_380); // August 7, 2020 third epoch begins
		assert_eq!(get_epoch_block_offset(0, 4), 471_780); // October 7, 2020 fourth epoch begins
		assert_eq!(get_epoch_block_offset(0, 5), 644_580); // February 7, 2021 fifth epoch begins
		assert_eq!(get_epoch_block_offset(0, 6), 903_780); // August 7, 2021 sixth epoch begins
		assert_eq!(get_epoch_block_offset(0, 7), 1_162_980); // February 7, 2022 seventh epoch begins
		assert_eq!(get_epoch_block_offset(0, 8), 1_687_140); // February 7, 2023 eighth epoch begins
		assert_eq!(get_epoch_block_offset(0, 9), 2_211_300); // February 7, 2024 nineth epoch begins
		assert_eq!(get_epoch_block_offset(0, 10), 5_356_260); // February 7, 2030 tenth epoch begins
		assert_eq!(get_epoch_block_offset(0, 11), 10_597_860); // February 7, 2040 eleventh epoch begins
		assert_eq!(
			get_epoch_block_offset(0, 11) + get_epoch_duration(0, 11).unwrap(),
			886_947_008
		);
		assert_eq!(
			get_epoch_block_offset(0, 11) + get_epoch_duration(0, 11).unwrap(),
			get_epoch_block_offset(0, 12)
		);
		assert_eq!(
			get_epoch_block_offset(0, 12) + get_epoch_duration(0, 12).unwrap(),
			886_947_009
		);
		assert_eq!(
			get_epoch_block_offset(0, 12) + get_epoch_duration(0, 12).unwrap(),
			get_epoch_block_offset(0, 13)
		);
		assert_eq!(get_epoch_block_offset(0, 13), 886_947_009);
		assert_eq!(get_epoch_block_offset(0, 14), u64::MAX);
		assert_eq!(get_epoch_block_offset(0, 15), u64::MAX);
		assert!(get_epoch_duration(0, 13).is_none());
		assert!(get_epoch_duration(0, 14).is_none());
		assert!(get_epoch_duration(0, 15).is_none());
		assert!(get_epoch_duration(0, 16).is_none());
	}

	// MWC  testing calc_mwc_block_reward output for the scedule that documented at definition of calc_mwc_block_reward
	#[test]
	fn test_calc_mwc_block_reward() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		global::set_local_nrd_enabled(false);

		// first blocks
		assert_eq!(calc_mwc_block_reward(0, 1), 2_380_952_380);
		assert_eq!(calc_mwc_block_reward(0, 2), 2_380_952_380);

		// a little deeper
		assert_eq!(calc_mwc_block_reward(0, 100000), 2_380_952_380);

		// pre hard fork block
		assert_eq!(
			calc_mwc_block_reward(0, get_c31_hard_fork_block_height(0) - 1),
			2_380_952_380
		);
		assert_eq!(
			calc_mwc_block_reward(0, get_c31_hard_fork_block_height(0)),
			2_380_952_380
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_c31_hard_fork_block_height(0) + WEEK_HEIGHT - 1),
			2_380_952_380
		);

		// reward changes 1 week after HF
		assert_eq!(
			calc_mwc_block_reward(0, get_c31_hard_fork_block_height(0) + WEEK_HEIGHT),
			600_000_000
		);

		// check epoch 2
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 2)),
			600_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 2) - 1),
			2_380_952_380
		);

		// check epoch 3
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 3)),
			450_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 3) - 1),
			600_000_000
		);

		// check epoch 4
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 4)),
			300_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 4) - 1),
			450_000_000
		);

		// check epoch 5
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 5)),
			250_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 5) - 1),
			300_000_000
		);

		// check epoch 6
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 6)),
			200_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 6) - 1),
			250_000_000
		);

		// check epoch 7
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 7)),
			150_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 7) - 1),
			200_000_000
		);

		// check epoch 8
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 8)),
			100_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 8) - 1),
			150_000_000
		);

		// check epoch 9
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 9)),
			50_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 9) - 1),
			100_000_000
		);

		// check epoch 10
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 10)),
			25_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 10) - 1),
			50_000_000
		);

		// check epoch 11
		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 11)),
			10_000_000
		);

		assert_eq!(
			calc_mwc_block_reward(0, get_epoch_block_offset(0, 11) - 1),
			25_000_000
		);

		let last_block_idx = get_epoch_block_offset(0, 11) + get_epoch_duration(0, 11).unwrap();

		// last block reward is special
		assert_eq!(
			calc_mwc_block_reward(0, last_block_idx),
			MWC_LAST_BLOCK_REWARD
		);

		// 0
		assert_eq!(calc_mwc_block_reward(0, last_block_idx + 1), 0);
		assert_eq!(calc_mwc_block_reward(0, last_block_idx + 2), 0);
		assert_eq!(calc_mwc_block_reward(0, last_block_idx + 200), 0);
		assert_eq!(calc_mwc_block_reward(0, last_block_idx + 20000), 0);

		// far far future
		assert_eq!(calc_mwc_block_reward(0, 2_100_000 * 320000000 + 200), 0); // no reward
	}

	// MWC  testing calc_mwc_block_overage output for the schedule that documented at definition of calc_mwc_block_reward
	#[test]
	fn test_calc_mwc_block_overage() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		global::set_local_nrd_enabled(false);

		let genesis_reward: u64 = GENESIS_BLOCK_REWARD;

		assert_eq!(calc_mwc_block_overage(0, 0, true), genesis_reward); // Doesn't make sense to call for the genesis block
		assert_eq!(calc_mwc_block_overage(0, 0, false), 0); // Doesn't make sense to call for the genesis block
		assert_eq!(
			calc_mwc_block_overage(0, 1, true),
			genesis_reward + MWC_FIRST_GROUP_REWARD * 1
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_c31_hard_fork_block_height(0), true),
			genesis_reward + MWC_FIRST_GROUP_REWARD * get_c31_hard_fork_block_height(0)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_c31_hard_fork_block_height(0) + WEEK_HEIGHT - 1, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_c31_hard_fork_block_height(0) + WEEK_HEIGHT - 1)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_c31_hard_fork_block_height(0) + WEEK_HEIGHT, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_c31_hard_fork_block_height(0) + WEEK_HEIGHT - 1)
				+ get_epoch_reward(2) * 1
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 2), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_c31_hard_fork_block_height(0) + WEEK_HEIGHT - 1)
				+ get_epoch_reward(2) * 1
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 3) - 1, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 3), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ get_epoch_reward(3)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 3) + 1, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ get_epoch_reward(3) * 2
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 4), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ get_epoch_reward(4)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 4) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ get_epoch_reward(4) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 5), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ get_epoch_reward(5)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 5) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ get_epoch_reward(5) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 6), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ get_epoch_reward(6)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 6) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ get_epoch_reward(6) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 7), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ get_epoch_reward(7)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 7) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ get_epoch_reward(7) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 8), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ (get_epoch_block_offset(0, 8) - get_epoch_block_offset(0, 7))
					* get_epoch_reward(7)
				+ get_epoch_reward(8)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 8) + 3, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ (get_epoch_block_offset(0, 8) - get_epoch_block_offset(0, 7))
					* get_epoch_reward(7)
				+ get_epoch_reward(8) * 4
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 9), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ (get_epoch_block_offset(0, 8) - get_epoch_block_offset(0, 7))
					* get_epoch_reward(7)
				+ (get_epoch_block_offset(0, 9) - get_epoch_block_offset(0, 8))
					* get_epoch_reward(8)
				+ get_epoch_reward(9)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 9) + 39, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ (get_epoch_block_offset(0, 8) - get_epoch_block_offset(0, 7))
					* get_epoch_reward(7)
				+ (get_epoch_block_offset(0, 9) - get_epoch_block_offset(0, 8))
					* get_epoch_reward(8)
				+ get_epoch_reward(9) * 40
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 10), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ (get_epoch_block_offset(0, 8) - get_epoch_block_offset(0, 7))
					* get_epoch_reward(7)
				+ (get_epoch_block_offset(0, 9) - get_epoch_block_offset(0, 8))
					* get_epoch_reward(8)
				+ (get_epoch_block_offset(0, 10) - get_epoch_block_offset(0, 9))
					* get_epoch_reward(9)
				+ get_epoch_reward(10)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 10) + 1, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ (get_epoch_block_offset(0, 8) - get_epoch_block_offset(0, 7))
					* get_epoch_reward(7)
				+ (get_epoch_block_offset(0, 9) - get_epoch_block_offset(0, 8))
					* get_epoch_reward(8)
				+ (get_epoch_block_offset(0, 10) - get_epoch_block_offset(0, 9))
					* get_epoch_reward(9)
				+ get_epoch_reward(10) * 2
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 11), true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ (get_epoch_block_offset(0, 8) - get_epoch_block_offset(0, 7))
					* get_epoch_reward(7)
				+ (get_epoch_block_offset(0, 9) - get_epoch_block_offset(0, 8))
					* get_epoch_reward(8)
				+ (get_epoch_block_offset(0, 10) - get_epoch_block_offset(0, 9))
					* get_epoch_reward(9)
				+ (get_epoch_block_offset(0, 11) - get_epoch_block_offset(0, 10))
					* get_epoch_reward(10)
				+ get_epoch_reward(11)
		);

		assert_eq!(
			calc_mwc_block_overage(0, get_epoch_block_offset(0, 11) + 39, true),
			genesis_reward
				+ MWC_FIRST_GROUP_REWARD * (get_epoch_block_offset(0, 2) - 1)
				+ (get_epoch_block_offset(0, 3) - get_epoch_block_offset(0, 2))
					* get_epoch_reward(2)
				+ (get_epoch_block_offset(0, 4) - get_epoch_block_offset(0, 3))
					* get_epoch_reward(3)
				+ (get_epoch_block_offset(0, 5) - get_epoch_block_offset(0, 4))
					* get_epoch_reward(4)
				+ (get_epoch_block_offset(0, 6) - get_epoch_block_offset(0, 5))
					* get_epoch_reward(5)
				+ (get_epoch_block_offset(0, 7) - get_epoch_block_offset(0, 6))
					* get_epoch_reward(6)
				+ (get_epoch_block_offset(0, 8) - get_epoch_block_offset(0, 7))
					* get_epoch_reward(7)
				+ (get_epoch_block_offset(0, 9) - get_epoch_block_offset(0, 8))
					* get_epoch_reward(8)
				+ (get_epoch_block_offset(0, 10) - get_epoch_block_offset(0, 9))
					* get_epoch_reward(9)
				+ (get_epoch_block_offset(0, 11) - get_epoch_block_offset(0, 10))
					* get_epoch_reward(10)
				+ get_epoch_reward(11) * 40
		);

		// Calculating the total number of coins
		let total_blocks_reward = calc_mwc_block_overage(0, 2_100_000_000 * 1000, true);
		// Expected 20M in total. The coin base is exactly 20M
		assert_eq!(total_blocks_reward, 20000000000000000);

		let max_height_reward = calc_mwc_block_overage(0, u64::MAX - 1, true);
		assert_eq!(max_height_reward, total_blocks_reward);
		assert_eq!(calc_mwc_block_overage(0, u64::MAX, true), max_height_reward);

		let max_height_reward_without_genesis = calc_mwc_block_overage(0, u64::MAX - 1, false);
		assert_eq!(
			calc_mwc_block_overage(0, u64::MAX, false),
			max_height_reward_without_genesis
		);
	}

	// Brute force test to validate that calc_mwc_block_reward and calc_mwc_block_overage are in sync fo all blocks
	// Please note, the test is slow, it checking values for every block that will be generated until reward will be gone
	// Test is 'ignore' because it takes about an hour to run
	#[test]
	#[ignore]
	fn test_rewards_full_cycle() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		global::set_local_nrd_enabled(false);

		let mut total_coins: u64 = GENESIS_BLOCK_REWARD;
		let mut height: u64 = 0;
		let mut zero_reward_blocks = 0;

		let total_blocks = get_epoch_block_offset(0, 12);

		while zero_reward_blocks < 100 {
			assert_eq!(calc_mwc_block_overage(0, height, true), total_coins);
			height += 1;
			let r = calc_mwc_block_reward(0, height);
			total_coins += r;
			if r == 0 {
				zero_reward_blocks += 1;
			}
			if height % 1000000 == 0 {
				println!(
					"Current height={}, reward={}, coins={}, progress={:.1}%",
					height,
					r,
					total_coins,
					height as f64 / total_blocks as f64 * 100.0
				);
			}
		}

		println!(
			"Finished with height={}, reward={}, coins={}",
			height,
			calc_mwc_block_reward(0, height),
			total_coins
		);

		assert_eq!(total_coins, 20000000000000000);
		assert!(height >= get_epoch_block_offset(0, 13) + 99);

		// Test finished with output:
		//		Current height=884000000, reward=10000000, coins=19970529927788020, progress=99.7%
		//		Current height=885000000, reward=10000000, coins=19980529927788020, progress=99.8%
		//		Current height=886000000, reward=10000000, coins=19990529927788020, progress=99.9%
		//		Finished with height=886947108, reward=0, coins=20000000000000000
		//		test consensus::test::test_rewards_full_cycle ... ok
	}

	// Testing last 1M blocks, srating from the event: height=886000000, reward=10000000, coins=19990529927788020, progress=99.9%
	#[test]
	fn test_last_epoch() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		global::set_local_nrd_enabled(false);

		let mut total_coins: u64 = 19990529927788020;
		let mut height: u64 = 886000000;
		let mut zero_reward_blocks = 0;

		while zero_reward_blocks < 100 {
			assert_eq!(calc_mwc_block_overage(0, height, true), total_coins);
			height += 1;
			let r = calc_mwc_block_reward(0, height);
			total_coins += r;
			if r == 0 {
				zero_reward_blocks += 1;
			}
		}
		assert_eq!(total_coins, 20000000000000000);
		assert!(height > get_epoch_block_offset(0, 12) + 99);
	}
}
