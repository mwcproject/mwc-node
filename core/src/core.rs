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

//! Core types

pub mod block;
pub mod block_sums;
pub mod committed;
pub mod compact_block;
pub mod hash;
pub mod id;
pub mod merkle_proof;
pub mod pmmr;
pub mod transaction;

pub use self::block::*;
pub use self::block_sums::*;
pub use self::committed::Committed;
pub use self::compact_block::*;
pub use self::id::ShortId;
pub use self::pmmr::segment::*;
pub use self::transaction::*;
use crate::consensus::MWC_BASE;
use mwc_crates::secp;
pub(crate) use secp::pedersen::Commitment;

/// Common errors
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum Error {
	/// Human readable represenation of amount is invalid
	#[error("Invalid amount string, {0}")]
	InvalidAmountString(String),
	/// Generic error
	#[error("{0}")]
	GenericError(String),
	/// Data overflow occurred.
	#[error("Data overflow error, {0}")]
	DataOverflow(String),
}

/// Common method for parsing an amount from human-readable, and converting
/// to internally-compatible u64

pub fn amount_from_hr_string(amount: &str) -> Result<u64, Error> {
	// no i18n yet, make sure we use '.' as the separator
	if amount.find(',').is_some() {
		return Err(Error::InvalidAmountString(
			"Found separator ',', expected '.'".to_string(),
		));
	}
	let (mwcs, nmwcs) = match amount.find('.') {
		None => (parse_mwcs(amount)?, 0),
		Some(pos) => {
			let (gs, tail) = amount.split_at(pos);
			(parse_mwcs(gs)?, parse_nmwcs(&tail[1..])?)
		}
	};
	// total_mwc = mwcs * MWC_BASE + nmwcs
	let total_mwc = mwcs
		.checked_mul(MWC_BASE)
		.and_then(|n| n.checked_add(nmwcs))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"amount_from_hr_string mwcs={} nmwcs={}",
				mwcs, nmwcs
			))
		})?;

	Ok(total_mwc)
}

fn parse_mwcs(amount: &str) -> Result<u64, Error> {
	if amount.is_empty() {
		// Empty string
		Err(Error::InvalidAmountString("Get empty MWC amount. Please don't use short notation for the decimals, specify zeroes".into()))
	} else if !amount.bytes().all(|b| b.is_ascii_digit()) {
		Err(Error::InvalidAmountString(format!(
			"Invalid MWC amount {}, expected digits only",
			amount
		)))
	} else {
		amount
			.parse::<u64>()
			.map_err(|e| Error::InvalidAmountString(format!("Unable to parse {}, {}", amount, e)))
	}
}

const WIDTH: usize = MWC_BASE.ilog10() as usize;

fn parse_nmwcs(amount: &str) -> Result<u64, Error> {
	if amount.len() > WIDTH {
		return Err(Error::InvalidAmountString(format!(
			"Too many digits in nano MWC {}, maximum suported digits {}",
			amount, WIDTH
		)));
	}
	if !amount.bytes().all(|b| b.is_ascii_digit()) {
		return Err(Error::InvalidAmountString(format!(
			"Invalid nano MWC amount {}, expected digits only",
			amount
		)));
	}

	format!("{:0<width$}", amount, width = WIDTH)
		.parse::<u64>()
		.map_err(|e| {
			Error::InvalidAmountString(format!("Unable to parse nano value {}, {}", amount, e))
		})
}

/// Common method for converting an amount to a human-readable string

pub fn amount_to_hr_string(amount: u64, truncate: bool) -> String {
	let mwcs = amount / MWC_BASE;
	let nmwcs = amount % MWC_BASE;
	let hr = format!("{}.{:0width$}", mwcs, nmwcs, width = WIDTH);
	if truncate {
		let nzeros = hr.chars().rev().take_while(|x| x == &'0').count();
		if nzeros < WIDTH {
			return hr.trim_end_matches('0').to_string();
		} else {
			return format!("{}0", hr.trim_end_matches('0'));
		}
	}
	hr
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	pub fn test_amount_from_hr() {
		assert_eq!(9, WIDTH);

		assert!(50123456789 == amount_from_hr_string("50.123456789").unwrap());
		assert!(amount_from_hr_string("+1").is_err());
		assert!(amount_from_hr_string("+1.0").is_err());
		assert!(amount_from_hr_string("1.+0").is_err());
		assert!(amount_from_hr_string("50.1234567899").is_err()); // Too many digits in nano MWC 1234567899, maximum suported digits 9
		assert!(50 == amount_from_hr_string("0.000000050").unwrap());
		assert!(amount_from_hr_string(".000000050").is_err());
		assert!(1 == amount_from_hr_string("0.000000001").unwrap());
		assert!(amount_from_hr_string(".000000001").is_err());
		assert!(amount_from_hr_string(".0000000009").is_err());
		assert!(amount_from_hr_string("0.0000000009").is_err()); // too many decimals
		assert!(500_000_000_000 == amount_from_hr_string("500").unwrap());
		assert!(
			5_000_000_000_000_000_000 == amount_from_hr_string("5000000000.000000000").unwrap()
		);
		assert!(5_000_000_000_000_000_000 == amount_from_hr_string("5000000000.00000").unwrap());
		assert!(amount_from_hr_string("5000000000.00000000000").is_err());
		assert!(66_600_000_000 == amount_from_hr_string("66.6").unwrap());
		assert!(66_000_000_000 == amount_from_hr_string("66.").unwrap());
	}

	#[test]
	pub fn test_amount_to_hr() {
		assert!("50.123456789" == amount_to_hr_string(50123456789, false));
		assert!("50.123456789" == amount_to_hr_string(50123456789, true));
		assert!("0.000000050" == amount_to_hr_string(50, false));
		assert!("0.00000005" == amount_to_hr_string(50, true));
		assert!("0.000000001" == amount_to_hr_string(1, false));
		assert!("0.000000001" == amount_to_hr_string(1, true));
		assert!("500.000000000" == amount_to_hr_string(500_000_000_000, false));
		assert!("500.0" == amount_to_hr_string(500_000_000_000, true));
		assert!("5000000000.000000000" == amount_to_hr_string(5_000_000_000_000_000_000, false));
		assert!("5000000000.0" == amount_to_hr_string(5_000_000_000_000_000_000, true));
		assert!("66.6" == amount_to_hr_string(66600000000, true));
		assert!("9007199.254740992" == amount_to_hr_string(9_007_199_254_740_992, false));
		assert!("9007699.000000002" == amount_to_hr_string(9_007_699_000_000_002, false));
		assert!("18446744073.709551615" == amount_to_hr_string(u64::MAX, false));
	}
}
