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

//! Merkle Proofs

use crate::core::hash::Hash;
use crate::core::pmmr;
use crate::ser;
use crate::ser::{PMMRIndexHashable, Readable, Reader, Writeable, Writer};
use mwc_crates::serde::{self, Deserialize, Serialize};
use util::ToHex;

/// Merkle proof errors.
#[derive(thiserror::Error, Debug)]
pub enum MerkleProofError {
	/// Merkle proof root hash does not match when attempting to verify.
	#[error("Merkle Proof root mismatch")]
	RootMismatch,
	/// Underlying IO error.
	#[error("Merkle Proof IO error, {0}")]
	IO(#[from] std::io::Error),
	/// Geeneric error
	#[error("{0}")]
	Generic(String),
}

/// A Merkle proof that proves a particular element exists in the MMR.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, PartialOrd, Ord)]
#[serde(crate = "serde")]
pub struct MerkleProof {
	/// The size of the MMR at the time the proof was created.
	pub mmr_size: u64,
	/// The sibling path from the leaf up to the final sibling hashing to the
	/// root.
	pub path: Vec<Hash>,
}

impl Writeable for MerkleProof {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		MerkleProof::validate_path_len(
			self.mmr_size,
			self.path.len() as u64,
			ser::Error::TooLargeWriteErr,
		)?;
		writer.write_u64(self.mmr_size)?;
		writer.write_u64(self.path.len() as u64)?;
		self.path.write(writer)?;
		Ok(())
	}
}

impl Readable for MerkleProof {
	fn read<R: Reader>(reader: &mut R) -> Result<MerkleProof, ser::Error> {
		let mmr_size = reader.read_u64()?;
		let path_len = reader.read_u64()?;
		MerkleProof::validate_path_len(mmr_size, path_len, ser::Error::TooLargeReadErr)?;
		let mut path = Vec::with_capacity(path_len as usize);
		for _ in 0..path_len {
			let hash = Hash::read(reader)?;
			path.push(hash);
		}

		Ok(MerkleProof { mmr_size, path })
	}
}

impl Default for MerkleProof {
	fn default() -> MerkleProof {
		MerkleProof::empty()
	}
}

impl MerkleProof {
	fn validate_path_len(
		mmr_size: u64,
		path_len: u64,
		too_large_err: fn(String) -> ser::Error,
	) -> Result<(), ser::Error> {
		if path_len > ser::READ_VEC_SIZE_LIMIT {
			return Err(too_large_err(format!(
				"MerkleProof path length {} exceeds limit {}",
				path_len,
				ser::READ_VEC_SIZE_LIMIT
			)));
		}
		if mmr_size == 0 {
			return if path_len == 0 {
				Ok(())
			} else {
				Err(ser::Error::CorruptedData(format!(
					"MerkleProof path length {} is invalid for empty MMR",
					path_len
				)))
			};
		}

		let peaks = pmmr::peaks(mmr_size).map_err(|e| {
			ser::Error::CorruptedData(format!("Invalid MerkleProof mmr_size {}, {}", mmr_size, e))
		})?;
		if peaks.is_empty() {
			return Err(ser::Error::CorruptedData(format!(
				"Invalid MerkleProof mmr_size {}",
				mmr_size
			)));
		}
		let n_leaves = pmmr::n_leaves(mmr_size).map_err(|e| {
			ser::Error::CorruptedData(format!("Invalid MerkleProof mmr_size {}, {}", mmr_size, e))
		})?;
		let max_tree_path = u64::from(u64::BITS - 1 - n_leaves.leading_zeros());
		let max_peak_path = peaks.len().saturating_sub(1) as u64;
		let max_path_len = max_tree_path.checked_add(max_peak_path).ok_or_else(|| {
			ser::Error::DataOverflow(format!(
				"MerkleProof path bound overflow, mmr_size={}",
				mmr_size
			))
		})?;
		if path_len > max_path_len {
			return Err(ser::Error::CorruptedData(format!(
				"MerkleProof path length {} exceeds max {} for mmr_size {}",
				path_len, max_path_len, mmr_size
			)));
		}

		Ok(())
	}

	/// The "empty" Merkle proof.
	pub fn empty() -> MerkleProof {
		MerkleProof {
			mmr_size: 0,
			path: Vec::default(),
		}
	}

	/// Serialize the Merkle proof as a hex string (for api json endpoints)
	pub fn to_hex(&self, context_id: u32) -> Result<String, MerkleProofError> {
		let mut vec = Vec::new();
		match ser::serialize_default(context_id, &mut vec, &self) {
			Ok(_) => Ok(vec.to_hex()),
			Err(e) => Err(MerkleProofError::Generic(format!(
				"serializetion error, {}",
				e
			))),
		}
	}

	/// Convert hex string representation back to a Merkle proof instance
	pub fn from_hex(context_id: u32, hex: &str) -> Result<MerkleProof, MerkleProofError> {
		let bytes = util::from_hex(hex)
			.map_err(|e| MerkleProofError::Generic(format!("MerkleProof::from_hex, {}", e)))?;
		let mut input = &bytes[..];
		let res = ser::deserialize_default(context_id, &mut input).map_err(|e| {
			MerkleProofError::Generic(format!("MerkleProof::from_hex, deserialize failed, {}", e))
		})?;
		if !input.is_empty() {
			return Err(MerkleProofError::Generic(format!(
				"MerkleProof::from_hex, trailing bytes after proof: {}",
				input.len()
			)));
		}
		Ok(res)
	}

	/// Verifies the Merkle proof against the provided
	/// root hash, element and position in the MMR.
	pub fn verify(
		&self,
		context_id: u32,
		root: Hash,
		element: &dyn PMMRIndexHashable,
		node_pos: u64,
	) -> Result<(), MerkleProofError> {
		MerkleProof::validate_path_len(
			self.mmr_size,
			self.path.len() as u64,
			ser::Error::CorruptedData,
		)
		.map_err(|e| MerkleProofError::Generic(format!("Invalid MerkleProof, {}", e)))?;

		if self.mmr_size == 0 {
			return Err(MerkleProofError::Generic(
				"Invalid MerkleProof, cannot verify against empty MMR".into(),
			));
		}
		if node_pos >= self.mmr_size {
			return Err(MerkleProofError::Generic(format!(
				"Invalid MerkleProof, node position {} is outside MMR size {}",
				node_pos, self.mmr_size
			)));
		}
		if !pmmr::is_leaf(node_pos) {
			return Err(MerkleProofError::Generic(format!(
				"Invalid MerkleProof, node position {} is not a PMMR leaf",
				node_pos
			)));
		}

		// calculate the peaks once as these are based on overall MMR size
		// (and will not change)
		let peaks_pos = pmmr::peaks(self.mmr_size)
			.map_err(|e| MerkleProofError::Generic(format!("PMMR peaks error, {}", e)))?;

		let mut node_pos0 = node_pos;
		let mut node_hash =
			MerkleProof::hash_with_mmr_index(context_id, element, node_pos0, self.mmr_size)?;

		for sibling in &self.path {
			let (parent_pos0, sibling_pos0) = pmmr::family(node_pos0)
				.map_err(|e| MerkleProofError::Generic(format!("PMMR family error, {}", e)))?;

			let parent = if let Ok(x) = peaks_pos.binary_search(&node_pos0) {
				if x == peaks_pos.len() - 1 {
					(*sibling, node_hash)
				} else {
					(node_hash, *sibling)
				}
			} else if parent_pos0 >= self.mmr_size {
				(*sibling, node_hash)
			} else if pmmr::is_left_sibling(sibling_pos0).map_err(|e| {
				MerkleProofError::Generic(format!("PMMR is_left_sibling error, {}", e))
			})? {
				(*sibling, node_hash)
			} else {
				(node_hash, *sibling)
			};

			node_hash =
				MerkleProof::hash_with_mmr_index(context_id, &parent, parent_pos0, self.mmr_size)?;
			node_pos0 = parent_pos0;
		}

		if root == node_hash {
			Ok(())
		} else {
			Err(MerkleProofError::RootMismatch)
		}
	}

	fn hash_with_mmr_index(
		context_id: u32,
		element: &dyn PMMRIndexHashable,
		node_pos0: u64,
		mmr_size: u64,
	) -> Result<Hash, MerkleProofError> {
		let hash_pos0 = if node_pos0 >= mmr_size {
			mmr_size
		} else {
			node_pos0
		};
		Ok(element.hash_with_index(context_id, hash_pos0)?)
	}
}
