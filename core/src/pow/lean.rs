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

//! Lean miner for Cuckatoo Cycle

use mwc_crates::croaring::Bitmap64;

use crate::pow::common::CuckooParams;
use crate::pow::cuckatoo::CuckatooContext;
use crate::pow::error::Error;
use crate::pow::Proof;

/// Lean miner implementation aiming to be as short and simple as possible.
/// As a consequence, it's a little less than 10 times slower than John
/// Tromp's implementation, as it's not optimized for performance and reuses
/// croaring which is likely sub-optimal for this task.
pub struct Lean {
	params: CuckooParams,
	edges: Bitmap64,
}

impl Lean {
	fn full_edges(num_edges: u64) -> Bitmap64 {
		let mut edges = Bitmap64::new();
		edges.flip_inplace(0..num_edges);
		edges
	}

	/// Instantiates a new lean miner based on some Cuckatoo parameters
	pub fn new(edge_bits: u8) -> Result<Lean, Error> {
		// note that proof size doesn't matter to a lean miner
		let params = CuckooParams::new(edge_bits, edge_bits, 42)?;

		// edge bitmap, before trimming all of them are on
		let edges = Lean::full_edges(params.num_edges);

		Ok(Lean { params, edges })
	}

	/// Sets the header and nonce to seed the graph
	pub fn set_header_nonce(&mut self, header: Vec<u8>, nonce: u32) -> Result<(), Error> {
		self.params.reset_header_nonce(header, Some(nonce))?;
		self.edges = Lean::full_edges(self.params.num_edges);
		Ok(())
	}

	/// Trim edges in the Cuckatoo graph. This applies multiple trimming rounds
	/// and works well for Cuckatoo size above 18.
	pub fn trim(&mut self) -> Result<(), Error> {
		// trimming successively
		let trim_threshold = 7 * (self.params.num_edges >> 8) / 8;
		while self.edges.cardinality() > trim_threshold {
			let before = self.edges.cardinality();
			self.count_and_kill()?;
			if self.edges.cardinality() >= before {
				return Err(Error::NoSolution);
			}
		}
		Ok(())
	}

	/// Finds the Cuckatoo Cycles on the remaining edges. Delegates the finding
	/// to a context, passing the trimmed edges iterator.
	pub fn find_cycles(&self, mut ctx: CuckatooContext) -> Result<Vec<Proof>, Error> {
		ctx.find_cycles_iter(self.edges.iter())
	}

	fn count_and_kill(&mut self) -> Result<(), Error> {
		// on each side u or v of the bipartite graph
		for uorv in 0..2 {
			let mut nodes = Bitmap64::new();
			// increment count for each node
			for e in self.edges.iter() {
				let node = self.params.sipnode(e, uorv)?;
				nodes.add(node);
			}

			// then kill edges with lone nodes (no neighbour at ^1)
			let mut to_kill = Bitmap64::new();
			for e in self.edges.iter() {
				let node = self.params.sipnode(e, uorv)?;
				if !nodes.contains(node ^ 1) {
					to_kill.add(e);
				}
			}
			self.edges.andnot_inplace(&to_kill);
		}
		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::global;
	use crate::pow::types::PoWContext;

	#[test]
	fn lean_new_uses_full_64_bit_edge_range() {
		let lean32 = Lean::new(32).unwrap();
		assert_eq!(lean32.edges.cardinality(), 1u64 << 32);
		assert!(lean32.edges.contains(u64::from(u32::MAX)));
		assert!(!lean32.edges.contains(1u64 << 32));

		let lean33 = Lean::new(33).unwrap();
		assert_eq!(lean33.edges.cardinality(), 1u64 << 33);
		assert!(lean33.edges.contains(1u64 << 32));
		assert!(!lean33.edges.contains(1u64 << 33));
	}

	#[test]
	fn set_header_nonce_resets_trimmed_edges() {
		let edge_bits = 19;
		let mut lean = Lean::new(edge_bits).unwrap();
		let full_edges = lean.edges.cardinality();

		lean.set_header_nonce([0u8; 84].to_vec(), 15465723).unwrap();
		lean.trim().unwrap();
		assert!(lean.edges.cardinality() < full_edges);

		lean.set_header_nonce([1u8; 84].to_vec(), 15465724).unwrap();
		assert_eq!(lean.edges.cardinality(), full_edges);
		assert!(lean.edges.contains((1u64 << edge_bits) - 1));
	}

	#[test]
	fn trim_returns_error_when_fixed_point_stays_above_threshold() {
		let mut lean = Lean::new(3).unwrap();
		assert!(matches!(lean.trim(), Err(Error::NoSolution)));
	}

	#[test]
	fn find_cycles_initializes_fresh_context() {
		let lean = Lean::new(3).unwrap();
		let ctx = CuckatooContext::new_impl(3, 42, 10, 0).unwrap();
		let _ = lean.find_cycles(ctx);
	}

	#[test]
	fn lean_miner() {
		global::set_local_chain_type(global::ChainTypes::Mainnet);
		global::set_local_nrd_enabled(false);
		let nonce = 15465723;
		let header = [0u8; 84].to_vec(); // with nonce
		let edge_bits = 19;

		let mut lean = Lean::new(edge_bits).unwrap();
		lean.set_header_nonce(header.clone(), nonce).unwrap();
		lean.trim().unwrap();

		let mut ctx_u32 = CuckatooContext::new_impl(edge_bits, 42, 10, 0u32).unwrap();
		ctx_u32.set_header_nonce(header, Some(nonce), true).unwrap();
		lean.find_cycles(ctx_u32).unwrap();
	}
}
