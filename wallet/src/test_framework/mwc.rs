// Copyright 2019 The MWC Developers
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

//! Test client that acts against a local instance of a node
//! so that wallet API can be fully exercised
//! Operates directly on a chain instance

/// How much times WMC block reward is smaller than the grin one.
/// Grin has 60 coins per block, MWC 2.28 per first group of blocks
const MWC2GRIN_BLOCK_REWARD: u64 = 25;

/// Convert testing amount of coins from grin test to MWC test.
/// This conversion extected to be used in the tests only so it will respect the
/// amount to block reward proportion
pub fn grin_coins_2_wmc(amount: f64) -> f64 {
	amount / (MWC2GRIN_BLOCK_REWARD as f64)
}

/// Convert testing amount of coins from grin test to MWC test.
/// This conversion extected to be used in the tests only so it will respect the
/// amount to block reward proportion
pub fn grin_reward_2_wmc(amount: u64) -> u64 {
	amount / MWC2GRIN_BLOCK_REWARD
}
