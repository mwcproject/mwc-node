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

//! Library containing lower-level transaction building functions needed by
//! all wallets.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

pub mod aggsig;
pub mod build;
mod error;
pub mod proof;
pub mod reward;
pub mod secp_ser;
mod zeroizing_blake2b;

use crate::core::Transaction;
use crate::global::get_accept_fee_base;

pub use self::proof::ProofBuilder;
pub use crate::libtx::error::Error;

/// Transaction fee calculation given numbers of inputs, outputs, and kernels
pub fn tx_fee(
	context_id: u32,
	input_len: usize,
	output_len: usize,
	kernel_len: usize,
) -> Result<u64, Error> {
	// Transaction::weight_for_fee(input_len as u64, output_len as u64, kernel_len as u64)
	//	* get_accept_fee_base(context_id)
	let weight =
		Transaction::weight_for_fee(input_len as u64, output_len as u64, kernel_len as u64);
	let fee_base = get_accept_fee_base(context_id);
	weight.checked_mul(fee_base).ok_or_else(|| {
		Error::DataOverflow(format!(
			"libtx::tx_fee, context_id={} weight={} fee_base={}",
			context_id, weight, fee_base
		))
	})
}

/// How many min number of inputs needed to maintain minimum possible fee
pub fn inputs_for_minimal_fee(output_len: usize, kernel_len: usize) -> Result<usize, Error> {
	Ok(Transaction::inputs_for_minimal_fee(
		output_len as u64,
		kernel_len as u64,
	)?)
}

/// How many min number of inputs needed to maintain the fee
pub fn inputs_for_fee_points(
	context_id: u32,
	fee: u64,
	output_len: usize,
	kernel_len: usize,
) -> Result<usize, Error> {
	let fee_points = fee
		.checked_div(get_accept_fee_base(context_id))
		.ok_or_else(|| {
			Error::DataOverflow(format!(
				"libtx::inputs_for_fee_points, context_id={} fee={}",
				context_id, fee
			))
		})?;
	Ok(Transaction::inputs_for_fee_points(
		fee_points,
		output_len as u64,
		kernel_len as u64,
	)?)
}
