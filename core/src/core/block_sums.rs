// Copyright 2020 The Grin Developers
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

//! BlockSums per-block running totals for utxo_sum, rmp_sum and kernel_sum.
//! Allows fast "full" verification of kernel sums at a given block height.

use crate::core::committed::Committed;
use crate::ser::{self, Readable, Reader, Writeable, Writer};
use util::secp::pedersen::Commitment;
use util::secp_static;

/// The output_sum, rmp_sum and kernel_sum for a given block.
/// This is used to validate the next block being processed by applying
/// the inputs, outputs, kernels and kernel_offset from the new block
/// and checking everything sums correctly.
#[derive(Debug, Clone)]
pub struct BlockSums {
	/// The sum of the unspent outputs commitment.
	pub utxo_sum: Commitment,
	/// The sum of all kernels excess.
	pub kernel_sum: Commitment,
	/// The sum of all outputs (R-P'). Note the difference from total_spent_rmp in block header which is only for spent outputs.
	/// Option type for compatibility of old version.
	pub rmp_sum: Option<Commitment>,
}

impl Writeable for BlockSums {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_fixed_bytes(&self.utxo_sum)?;
		writer.write_fixed_bytes(&self.kernel_sum)?;
		if let Some(rmp_sum) = self.rmp_sum {
			writer.write_fixed_bytes(&rmp_sum)?;
		}
		Ok(())
	}
}

impl Readable for BlockSums {
	fn read<R: Reader>(reader: &mut R) -> Result<BlockSums, ser::Error> {
		Ok(BlockSums {
			utxo_sum: Commitment::read(reader)?,
			kernel_sum: Commitment::read(reader)?,
			rmp_sum: Commitment::read(reader).ok(),
		})
	}
}

impl Default for BlockSums {
	fn default() -> BlockSums {
		let zero_commit = secp_static::commit_to_zero_value();
		BlockSums {
			utxo_sum: zero_commit,
			kernel_sum: zero_commit,
			rmp_sum: Some(zero_commit),
		}
	}
}

/// It's a tuple but we can verify the "full" kernel sums on it.
/// This means we can take a previous block_sums, apply a new block to it
/// and verify the full kernel sums (full UTXO and kernel sets).
impl<'a> Committed for (BlockSums, &'a dyn Committed) {
	fn outputs_r_committed(&self) -> Vec<Commitment> {
		let mut outputs = vec![self
			.0
			.rmp_sum
			.unwrap_or(secp_static::commit_to_zero_value())];
		outputs.extend(&self.1.outputs_r_committed());
		outputs
	}

	fn inputs_committed(&self) -> Vec<Commitment> {
		self.1.inputs_committed()
	}

	fn outputs_committed(&self) -> Vec<Commitment> {
		let mut outputs = vec![self.0.utxo_sum];
		outputs.extend(&self.1.outputs_committed());
		outputs
	}

	fn kernels_committed(&self) -> Vec<Commitment> {
		let mut kernels = vec![self.0.kernel_sum];
		kernels.extend(&self.1.kernels_committed());
		kernels
	}
}
