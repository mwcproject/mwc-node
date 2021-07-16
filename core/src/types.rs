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

//! core trait and its common types.

use crate::core::OutputFeatures;
use crate::ser::{self, Readable, Reader, Writeable, Writer};

/// Minimal struct representing a known MMR position and associated block height for a commitment, including the Output feature.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CommitPos {
	/// The output features
	pub features: OutputFeatures,
	/// MMR position
	pub pos: u64,
	/// Block height
	pub height: u64,
}

impl Readable for CommitPos {
	fn read<R: Reader>(reader: &mut R) -> Result<CommitPos, ser::Error> {
		let features = OutputFeatures::read(reader)?;
		let pos = reader.read_u64()?;
		let height = reader.read_u64()?;
		Ok(CommitPos {
			features,
			pos,
			height,
		})
	}
}

impl Writeable for CommitPos {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(self.features as u8)?;
		writer.write_u64(self.pos)?;
		writer.write_u64(self.height)?;
		Ok(())
	}
}

/// Minimal struct representing a known MMR position and associated block height.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CommitPosHt {
	/// MMR position
	pub pos: u64,
	/// Block height
	pub height: u64,
}

impl Readable for CommitPosHt {
	fn read<R: Reader>(reader: &mut R) -> Result<CommitPosHt, ser::Error> {
		let pos = reader.read_u64()?;
		let height = reader.read_u64()?;
		Ok(CommitPosHt { pos, height })
	}
}

impl Writeable for CommitPosHt {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.pos)?;
		writer.write_u64(self.height)?;
		Ok(())
	}
}
