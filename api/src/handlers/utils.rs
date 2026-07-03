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

use crate::rest::*;
use crate::types::*;
use mwc_chain::types::CommitPos;
use mwc_core::core::OutputIdentifier;
use mwc_core::libtx::secp_ser;
use mwc_crates::secp::constants::PEDERSEN_COMMITMENT_SIZE;
use mwc_crates::secp::pedersen::Commitment;
use mwc_crates::secp::Secp256k1;
use mwc_crates::serde::de::IntoDeserializer;
use std::sync::{Arc, Weak};

// All handlers use `Weak` references instead of `Arc` to avoid cycles that
// can never be destroyed. These 2 functions are simple helpers to reduce the
// boilerplate of dealing with `Weak`.
pub fn w<T>(weak: &Weak<T>) -> Result<Arc<T>, Error> {
	weak.upgrade()
		.ok_or_else(|| Error::Internal("failed to upgrade weak reference".to_owned()))
}

/// Internal function to retrieves an output by a given commitment
fn get_unspent(
	chain: &Arc<mwc_chain::Chain>,
	id: &str,
) -> Result<Option<(OutputIdentifier, CommitPos)>, Error> {
	let commit = parse_commitment(id)?;
	let res = chain.get_unspent(commit)?;
	Ok(res)
}

/// Parses commitment-shaped hex from an API parameter.
pub(super) fn parse_commitment(id: &str) -> Result<Commitment, Error> {
	let id_hex = id.trim();
	let normalized_id_hex = id_hex.strip_prefix("0x").unwrap_or(id_hex);
	let expected_hex_len = PEDERSEN_COMMITMENT_SIZE * 2;
	if normalized_id_hex.len() != expected_hex_len {
		return Err(Error::Argument(format!(
			"invalid commitment hex length {}, expected {}",
			normalized_id_hex.len(),
			expected_hex_len
		)));
	}

	let deserializer: mwc_crates::serde::de::value::StrDeserializer<
		mwc_crates::serde::de::value::Error,
	> = id_hex.into_deserializer();
	secp_ser::commitment_from_hex(deserializer)
		.map_err(|_| Error::Argument("Not a valid commitment".to_string()))
}

/// Retrieves an output from the chain given a commitment.
pub fn get_output(
	chain: &Weak<mwc_chain::Chain>,
	id: &str,
) -> Result<Option<(Output, OutputIdentifier)>, Error> {
	let chain = w(chain)?;
	let (out, pos) = match get_unspent(&chain, id)? {
		Some(x) => x,
		None => return Ok(None),
	};

	Ok(Some((
		Output::new(&out.commitment(), pos.height, pos.pos),
		out,
	)))
}

/// Retrieves an output from the chain given a commit id (a tiny bit iteratively)
pub fn get_output_v2(
	secp: &Secp256k1,
	chain: &Weak<mwc_chain::Chain>,
	id: &str,
	include_proof: bool,
	include_merkle_proof: bool,
) -> Result<Option<(OutputPrintable, OutputIdentifier)>, Error> {
	let chain = w(chain)?;
	let (out, pos) = match get_unspent(&chain, id)? {
		Some(x) => x,
		None => return Ok(None),
	};

	let output = chain.get_unspent_output_at(pos.pos - 1)?;
	if output.commitment() != out.commitment() {
		return Err(Error::Internal(format!(
			"output commitment mismatch at position {}: requested {:?}, found {:?}",
			pos.pos,
			out.commitment(),
			output.commitment()
		)));
	}

	let header = if include_merkle_proof && output.is_coinbase() {
		Some(chain.get_header_for_output(out.commitment()).map_err(|e| {
			let msg = format!("Header for output {:?}, {}", out, e);
			Error::chain_read_error(e, msg)
		})?)
	} else {
		None
	};

	let output_printable = OutputPrintable::from_output(
		secp,
		&output,
		&chain,
		header.as_ref(),
		include_proof,
		include_merkle_proof,
	)?;

	Ok(Some((output_printable, out)))
}

#[cfg(test)]
mod tests {
	use super::*;

	const VALID_COMMIT: &str = "083eafae5d61a85ab07b12e1a51b3918d8e6de11fc6cde641d54af53608aa77b9f";

	#[test]
	fn parse_commitment_accepts_normalized_commitment_hex() {
		parse_commitment(&format!("  0x{}  ", VALID_COMMIT)).unwrap();
	}

	#[test]
	fn parse_commitment_rejects_invalid_commitment() {
		let commit = "00".repeat(PEDERSEN_COMMITMENT_SIZE);
		let err = parse_commitment(&commit).unwrap_err();

		match err {
			Error::Argument(msg) => {
				assert!(msg.contains("Not a valid commitment"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected argument error, got {:?}", other),
		}
	}

	#[test]
	fn parse_commitment_rejects_overlong_hex_with_bounded_error() {
		let commit = "00".repeat(PEDERSEN_COMMITMENT_SIZE + 1);
		let err = parse_commitment(&commit).unwrap_err();

		match err {
			Error::Argument(msg) => {
				assert!(msg.contains("invalid commitment hex length"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected argument error, got {:?}", other),
		}
	}

	#[test]
	fn parse_commitment_rejects_invalid_hex_with_bounded_error() {
		let commit = "zz".repeat(PEDERSEN_COMMITMENT_SIZE);
		let err = parse_commitment(&commit).unwrap_err();

		match err {
			Error::Argument(msg) => {
				assert!(msg.contains("Not a valid commitment"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected argument error, got {:?}", other),
		}
	}

	#[test]
	fn parse_commitment_rejects_double_prefixed_hex_as_argument_error() {
		let commit = format!("0x0x{}", "00".repeat(PEDERSEN_COMMITMENT_SIZE - 1));
		let err = parse_commitment(&commit).unwrap_err();

		match err {
			Error::Argument(msg) => {
				assert!(msg.contains("Not a valid commitment"), "{}", msg);
				assert!(msg.len() < 100, "{}", msg);
			}
			other => panic!("expected argument error, got {:?}", other),
		}
	}
}
