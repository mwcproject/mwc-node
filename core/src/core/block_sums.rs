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

//! BlockSums per-block running totals for utxo_sum and kernel_sum.
//! Allows fast "full" verification of kernel sums at a given block height.

use crate::core::committed::{Committed, Error};
use crate::ser::{self, Readable, Reader, Writeable, Writer};
use mwc_crates::secp::pedersen::Commitment;
use util::secp_static;

/// The output_sum and kernel_sum for a given block.
/// This is used to validate the next block being processed by applying
/// the inputs, outputs, kernels and kernel_offset from the new block
/// and checking everything sums correctly.
#[derive(Debug, Clone)]
pub enum BlockSums {
	/// No previous block sums exist yet.
	Empty,
	/// Running sums for a non-empty chain state.
	NonEmpty {
		/// The sum of the unspent outputs.
		utxo_sum: Commitment,
		/// The sum of all kernels.
		kernel_sum: Commitment,
	},
}

impl BlockSums {
	/// Build non-empty block sums from the supplied commitment sums.
	pub fn new(utxo_sum: Commitment, kernel_sum: Commitment) -> BlockSums {
		BlockSums::NonEmpty {
			utxo_sum,
			kernel_sum,
		}
	}

	/// Build empty block sums for the beginning of the chain.
	pub fn empty() -> BlockSums {
		BlockSums::Empty
	}
}

impl Writeable for BlockSums {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		match self {
			BlockSums::Empty => {
				let zero_commit = secp_static::commit_to_zero_value();
				writer.write_fixed_bytes(&zero_commit)?;
				writer.write_fixed_bytes(&zero_commit)?;
			}
			BlockSums::NonEmpty {
				utxo_sum,
				kernel_sum,
			} => {
				let zero_commit = secp_static::commit_to_zero_value();
				if *utxo_sum == zero_commit || *kernel_sum == zero_commit {
					return Err(ser::Error::CorruptedData(
						"Invalid non-empty BlockSums: legacy empty sentinel is not a valid sum"
							.into(),
					));
				}
				secp_static::with_commit(ser::Error::from, |secp| {
					secp.validate_commitment(utxo_sum).map_err(|e| {
						ser::Error::CorruptedData(format!(
							"Unable to write BlockSums utxo commitment, {}",
							e
						))
					})?;
					secp.validate_commitment(kernel_sum).map_err(|e| {
						ser::Error::CorruptedData(format!(
							"Unable to write BlockSums kernel commitment, {}",
							e
						))
					})?;
					Ok(())
				})?;
				writer.write_fixed_bytes(utxo_sum)?;
				writer.write_fixed_bytes(kernel_sum)?;
			}
		}
		Ok(())
	}
}

impl Readable for BlockSums {
	fn read<R: Reader>(reader: &mut R) -> Result<BlockSums, ser::Error> {
		let utxo_sum =
			reader.read_fixed_bytes(mwc_crates::secp::constants::PEDERSEN_COMMITMENT_SIZE)?;
		let kernel_sum =
			reader.read_fixed_bytes(mwc_crates::secp::constants::PEDERSEN_COMMITMENT_SIZE)?;
		let utxo_sum = Commitment::from_vec(utxo_sum)?;
		let kernel_sum = Commitment::from_vec(kernel_sum)?;
		let zero_commit = secp_static::commit_to_zero_value();
		match (utxo_sum == zero_commit, kernel_sum == zero_commit) {
			(true, true) => Ok(BlockSums::Empty),
			(false, false) => {
				secp_static::with_commit(ser::Error::from, |secp| {
					secp.validate_commitment(&utxo_sum).map_err(|e| {
						ser::Error::CorruptedData(format!(
							"Unable to read BlockSums utxo commitment, {}",
							e
						))
					})?;
					secp.validate_commitment(&kernel_sum).map_err(|e| {
						ser::Error::CorruptedData(format!(
							"Unable to read BlockSums kernel commitment, {}",
							e
						))
					})?;
					Ok(())
				})?;
				Ok(BlockSums::new(utxo_sum, kernel_sum))
			}
			_ => Err(ser::Error::CorruptedData(
				"Invalid BlockSums: only one commitment is the legacy empty sentinel".into(),
			)),
		}
	}
}

/// It's a tuple but we can verify the "full" kernel sums on it.
/// This means we can take a previous block_sums, apply a new block to it
/// and verify the full kernel sums (full UTXO and kernel sets).
impl<'a> Committed for (BlockSums, &'a dyn Committed) {
	fn inputs_committed(&self) -> Result<crate::core::committed::CommitmentIterator<'_>, Error> {
		self.1.inputs_committed()
	}

	fn outputs_committed(&self) -> Result<crate::core::committed::CommitmentIterator<'_>, Error> {
		let output_sum = match &self.0 {
			BlockSums::Empty => None,
			BlockSums::NonEmpty {
				utxo_sum,
				kernel_sum: _,
			} => {
				let zero_commit = secp_static::commit_to_zero_value();
				if *utxo_sum == zero_commit {
					return Err(Error::Other("Invalid non-empty BlockSums".into()));
				}
				Some(*utxo_sum)
			}
		};
		let outputs = self.1.outputs_committed()?;
		Ok(Box::new(
			output_sum
				.into_iter()
				.map(Ok::<Commitment, Error>)
				.chain(outputs),
		))
	}

	fn kernels_committed(&self) -> Result<crate::core::committed::CommitmentIterator<'_>, Error> {
		let kernel_sum = match &self.0 {
			BlockSums::Empty => None,
			BlockSums::NonEmpty {
				utxo_sum: _,
				kernel_sum,
			} => {
				let zero_commit = secp_static::commit_to_zero_value();
				if *kernel_sum == zero_commit {
					return Err(Error::Other("Invalid non-empty BlockSums".into()));
				}
				Some(*kernel_sum)
			}
		};
		let kernels = self.1.kernels_committed()?;
		Ok(Box::new(
			kernel_sum
				.into_iter()
				.map(Ok::<Commitment, Error>)
				.chain(kernels),
		))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ser::{deserialize_default, serialize_default, BinWriter};
	use mwc_crates::secp::{ContextFlag, Secp256k1};

	fn commitment(value: u64) -> Commitment {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		secp.commit_value(value).unwrap()
	}

	fn invalid_commitment() -> Commitment {
		Commitment::from_vec(vec![
			1;
			mwc_crates::secp::constants::PEDERSEN_COMMITMENT_SIZE
		])
		.unwrap()
	}

	fn legacy_bytes(utxo_sum: Commitment, kernel_sum: Commitment) -> Vec<u8> {
		let mut bytes = vec![];
		{
			let mut writer = BinWriter::default(0, &mut bytes);
			writer.write_fixed_bytes(&utxo_sum).unwrap();
			writer.write_fixed_bytes(&kernel_sum).unwrap();
		}
		bytes
	}

	#[test]
	fn empty_block_sums_round_trip_as_legacy_zero_pair() {
		let sums = BlockSums::empty();
		let zero_commit = secp_static::commit_to_zero_value();
		let mut bytes = vec![];

		serialize_default(0, &mut bytes, &sums).unwrap();

		assert_eq!(bytes, legacy_bytes(zero_commit, zero_commit));
		let decoded: BlockSums = deserialize_default(0, &mut &bytes[..]).unwrap();
		assert!(matches!(decoded, BlockSums::Empty));
	}

	#[test]
	fn non_empty_block_sums_keep_legacy_two_commitment_format() {
		let utxo_sum = commitment(1);
		let kernel_sum = commitment(2);
		let sums = BlockSums::new(utxo_sum, kernel_sum);
		let mut bytes = vec![];

		serialize_default(0, &mut bytes, &sums).unwrap();

		assert_eq!(bytes, legacy_bytes(utxo_sum, kernel_sum));
		let decoded: BlockSums = deserialize_default(0, &mut &bytes[..]).unwrap();
		match decoded {
			BlockSums::NonEmpty {
				utxo_sum: decoded_utxo_sum,
				kernel_sum: decoded_kernel_sum,
			} => {
				assert_eq!(decoded_utxo_sum, utxo_sum);
				assert_eq!(decoded_kernel_sum, kernel_sum);
			}
			BlockSums::Empty => panic!("expected non-empty block sums"),
		}
	}

	#[test]
	fn mixed_legacy_empty_sentinel_is_rejected() {
		let zero_commit = secp_static::commit_to_zero_value();
		let bytes = legacy_bytes(zero_commit, commitment(1));

		match deserialize_default::<BlockSums, _>(0, &mut &bytes[..]) {
			Err(ser::Error::CorruptedData(msg)) => {
				assert!(msg.contains("legacy empty sentinel"), "{}", msg);
			}
			other => panic!("expected mixed sentinel rejection, got {:?}", other),
		}
	}

	#[test]
	fn non_empty_block_sums_reject_legacy_empty_sentinel() {
		let sums = BlockSums::new(secp_static::commit_to_zero_value(), commitment(1));
		let mut bytes = vec![];

		match serialize_default(0, &mut bytes, &sums) {
			Err(ser::Error::CorruptedData(msg)) => {
				assert!(msg.contains("legacy empty sentinel"), "{}", msg);
			}
			other => panic!("expected non-empty sentinel rejection, got {:?}", other),
		}
	}

	#[test]
	fn non_empty_block_sums_reject_invalid_commitments_on_write() {
		for (sums, expected) in [
			(
				BlockSums::new(invalid_commitment(), commitment(1)),
				"Unable to write BlockSums utxo commitment",
			),
			(
				BlockSums::new(commitment(1), invalid_commitment()),
				"Unable to write BlockSums kernel commitment",
			),
		] {
			let mut bytes = vec![];

			match serialize_default(0, &mut bytes, &sums) {
				Err(ser::Error::CorruptedData(msg)) => {
					assert!(msg.contains(expected), "{}", msg);
				}
				other => panic!("expected invalid commitment rejection, got {:?}", other),
			}
		}
	}
}
