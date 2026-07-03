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

//! Compact Blocks.

use crate::core::block::{Block, BlockHeader, Error, UntrustedBlockHeader};
use crate::core::hash::{DefaultHashable, Hashed};
use crate::core::id::ShortIdentifiable;
use crate::core::{Output, ShortId, TransactionBody, TxKernel};
use crate::ser::{self, read_multi, Readable, Reader, Writeable, Writer};
use mwc_crates::rand::rngs::SysRng;
use mwc_crates::rand::TryRng;

/// Container for full (full) outputs and kernels and kern_ids for a compact block.
#[derive(Debug, Clone)]
pub struct CompactBlockBody {
	/// List of full outputs - specifically the coinbase output(s)
	pub out_full: Vec<Output>,
	/// List of full kernels - specifically the coinbase kernel(s)
	pub kern_full: Vec<TxKernel>,
	/// List of transaction kernels, excluding those in the full list
	/// (short_ids)
	pub kern_ids: Vec<ShortId>,
}

impl CompactBlockBody {
	fn init(
		context_id: u32,
		out_full: Vec<Output>,
		kern_full: Vec<TxKernel>,
		kern_ids: Vec<ShortId>,
		verify_sorted: bool,
	) -> Result<Self, Error> {
		let body = CompactBlockBody {
			out_full,
			kern_full,
			kern_ids,
		};

		if verify_sorted {
			// If we are verifying sort order then verify and
			// return an error if not sorted lexicographically.
			body.verify_sorted(context_id)?;
			Ok(body)
		} else {
			// If we are not verifying sort order then sort in place and return.
			let mut body = body;
			body.sort(context_id)?;
			body.verify_sorted(context_id)?;
			Ok(body)
		}
	}

	/// Sort everything.
	fn sort(&mut self, context_id: u32) -> Result<(), Error> {
		ser::sort_by_hash_key(context_id, &mut self.out_full, |output| &output.identifier)?;
		ser::sort_by_hash(context_id, &mut self.kern_full)?;
		ser::sort_by_hash(context_id, &mut self.kern_ids)?;
		Ok(())
	}

	/// "Lightweight" validation.
	fn validate_read(&self, context_id: u32) -> Result<(), Error> {
		TransactionBody::verify_compact_block_read_weight_for_size(
			context_id,
			self.out_full.len() as u64,
			self.kern_full.len() as u64,
			self.kern_ids.len() as u64,
		)
		.map_err(|e| match e {
			ser::Error::TooLargeReadErr(_) | ser::Error::TooLargeWriteErr(_) => Error::TooHeavy,
			ser::Error::DataOverflow(msg) => Error::DataOverflow(msg),
			other => Error::Serialization(other),
		})?;
		self.verify_sorted(context_id)?;
		self.verify_coinbase_full_entries()?;
		Ok(())
	}

	fn verify_coinbase_full_entries(&self) -> Result<(), Error> {
		if self.out_full.iter().any(|out| !out.is_coinbase()) {
			return Err(Error::Other(
				"Compact block contains non-coinbase full output".into(),
			));
		}
		if self.kern_full.iter().any(|kernel| !kernel.is_coinbase()) {
			return Err(Error::Other(
				"Compact block contains non-coinbase full kernel".into(),
			));
		}
		Ok(())
	}

	// Verify everything is sorted in lexicographical order and no duplicates present.
	fn verify_sorted(&self, context_id: u32) -> Result<(), Error> {
		ser::verify_sorted_and_unique_by_hash_key(context_id, &self.out_full, |output| {
			&output.identifier
		})?;
		ser::verify_sorted_and_unique_by_hash(context_id, &self.kern_full)?;
		ser::verify_sorted_and_unique_by_hash(context_id, &self.kern_ids)?;
		Ok(())
	}
}

impl Readable for CompactBlockBody {
	fn read<R: Reader>(reader: &mut R) -> Result<CompactBlockBody, ser::Error> {
		let (out_full_len, kern_full_len, kern_id_len) =
			ser_multiread!(reader, read_u64, read_u64, read_u64);

		TransactionBody::verify_compact_block_read_weight_for_size(
			reader.get_context_id(),
			out_full_len,
			kern_full_len,
			kern_id_len,
		)?;

		let out_full = read_multi(reader, out_full_len)?;
		let kern_full = read_multi(reader, kern_full_len)?;
		let kern_ids = read_multi(reader, kern_id_len)?;

		// Initialize compact block body, verifying sort order.
		let body =
			CompactBlockBody::init(reader.get_context_id(), out_full, kern_full, kern_ids, true)
				.map_err(|e| {
					ser::Error::CorruptedData(format!("Unable to read compact block, {}", e))
				})?;
		body.verify_coinbase_full_entries().map_err(|e| {
			ser::Error::CorruptedData(format!("Unable to read compact block, {}", e))
		})?;

		Ok(body)
	}
}

impl Writeable for CompactBlockBody {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		TransactionBody::verify_compact_block_write_weight_for_size(
			writer.get_context_id(),
			self.out_full.len() as u64,
			self.kern_full.len() as u64,
			self.kern_ids.len() as u64,
		)?;

		ser_multiwrite!(
			writer,
			[write_u64, self.out_full.len() as u64],
			[write_u64, self.kern_full.len() as u64],
			[write_u64, self.kern_ids.len() as u64]
		);

		self.out_full.write(writer)?;
		self.kern_full.write(writer)?;
		self.kern_ids.write(writer)?;

		Ok(())
	}
}

impl Into<CompactBlockBody> for CompactBlock {
	fn into(self) -> CompactBlockBody {
		self.body
	}
}

/// Compact representation of a full block.
/// Each input/output/kernel is represented as a short_id.
/// A node is reasonably likely to have already seen all tx data (tx broadcast
/// before block) and can go request missing tx data from peers if necessary to
/// hydrate a compact block into a full block.
#[derive(Debug, Clone)]
pub struct CompactBlock {
	/// The header with metadata and commitments to the rest of the data
	pub header: BlockHeader,
	/// Nonce for connection specific short_ids
	pub nonce: u64,
	/// Container for out_full, kern_full and kern_ids in the compact block.
	body: CompactBlockBody,
}

impl DefaultHashable for CompactBlock {}

impl CompactBlock {
	/// "Lightweight" validation.
	fn validate_read(&self, context_id: u32) -> Result<(), Error> {
		self.body.validate_read(context_id)?;
		Ok(())
	}

	/// Get kern_ids
	pub fn kern_ids(&self) -> &[ShortId] {
		&self.body.kern_ids
	}

	/// Get full (coinbase) kernels
	pub fn kern_full(&self) -> &[TxKernel] {
		&self.body.kern_full
	}

	/// Get full (coinbase) outputs
	pub fn out_full(&self) -> &[Output] {
		&self.body.out_full
	}

	/// Convert Block into Compact block. Can't use From trait because conversion can return error
	pub fn from(block: Block) -> Result<Self, Error> {
		let header = block.header.clone();
		let context_id = header.pow.proof.context_id;
		let nonce = SysRng
			.try_next_u64()
			.map_err(|e| Error::Other(format!("SysRng error: {}", e)))?;

		let out_full = block
			.outputs()
			.iter()
			.filter(|x| x.is_coinbase())
			.cloned()
			.collect::<Vec<_>>();

		let mut kern_full = vec![];
		let mut kern_ids = vec![];
		let header_hash = header.hash(context_id)?;

		for k in block.kernels() {
			if k.is_coinbase() {
				kern_full.push(k.clone());
			} else {
				kern_ids.push(k.short_id(context_id, &header_hash, nonce)?);
			}
		}

		// Initialize a compact block body and sort everything.
		let body = CompactBlockBody::init(context_id, out_full, kern_full, kern_ids, false)?;

		Ok(CompactBlock {
			header,
			nonce,
			body,
		})
	}
}

/// Implementation of Writeable for a compact block, defines how to write the
/// block to a binary writer. Differentiates between writing the block for the
/// purpose of full serialization and the one of just extracting a hash.
impl Writeable for CompactBlock {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.header.write(writer)?;

		if writer.serialization_mode() != ser::SerializationMode::Hash {
			writer.write_u64(self.nonce)?;
			self.body.write(writer)?;
		}

		Ok(())
	}
}

/// Implementation of Readable for a compact block, defines how to read a
/// compact block from a binary stream.
impl Readable for CompactBlock {
	fn read<R: Reader>(reader: &mut R) -> Result<CompactBlock, ser::Error> {
		let header = BlockHeader::read(reader)?;
		let nonce = reader.read_u64()?;
		let body = CompactBlockBody::read(reader)?;

		Ok(CompactBlock {
			header,
			nonce,
			body,
		})
	}
}

impl From<UntrustedCompactBlock> for CompactBlock {
	fn from(ucb: UntrustedCompactBlock) -> Self {
		ucb.0
	}
}

/// Compackt block which does lightweight validation as part of deserialization,
/// it supposed to be used when we can't trust the channel (eg network)
#[derive(Debug)]
pub struct UntrustedCompactBlock(CompactBlock);

impl UntrustedCompactBlock {
	/// The underlying compact block, after lightweight read validation.
	pub fn as_compact_block(&self) -> &CompactBlock {
		&self.0
	}
}

/// Implementation of Readable for an untrusted compact block, defines how to read a
/// compact block from a binary stream.
impl Readable for UntrustedCompactBlock {
	fn read<R: Reader>(reader: &mut R) -> Result<UntrustedCompactBlock, ser::Error> {
		let header = UntrustedBlockHeader::read(reader)?;
		let nonce = reader.read_u64()?;
		let body = CompactBlockBody::read(reader)?;

		let cb = CompactBlock {
			header: header.into(),
			nonce,
			body,
		};

		// Now validate the compact block and treat any validation error as corrupted data.
		cb.validate_read(reader.get_context_id()).map_err(|e| {
			ser::Error::CorruptedData(format!("Failed to validate compact block, {}", e))
		})?;

		Ok(UntrustedCompactBlock(cb))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{consensus, global};

	#[test]
	fn compact_block_body_validate_read_rejects_overweight_body() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let overweight_kernel_ids =
			global::max_block_weight(0) / consensus::BLOCK_KERNEL_WEIGHT + 1;
		let body = CompactBlockBody {
			out_full: vec![],
			kern_full: vec![],
			kern_ids: vec![ShortId::zero(); overweight_kernel_ids as usize],
		};

		assert!(matches!(body.validate_read(0), Err(Error::TooHeavy)));
	}
}
