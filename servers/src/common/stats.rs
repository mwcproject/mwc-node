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

//! Server stat collection types, to be used by tests, logging or GUI/TUI
//! to collect information about server status

use crate::util::RwLock;
use atomic_float::AtomicF64;
use std::sync::atomic::*;
use std::sync::Arc;
use std::time::SystemTime;

use crate::core::core::hash::Hash;
use crate::core::ser::ProtocolVersion;

use chrono::prelude::*;

use crate::chain::SyncStatus;
use crate::p2p;
use crate::p2p::Capabilities;
use mwc_core::pow::Difficulty;

/// Server state info collection struct, to be passed around into internals
/// and populated when required
#[derive(Clone)]
pub struct ServerStateInfo {
	/// Stratum stats
	pub stratum_stats: Arc<StratumStats>,
}

impl Default for ServerStateInfo {
	fn default() -> ServerStateInfo {
		ServerStateInfo {
			stratum_stats: Arc::new(StratumStats::default()),
		}
	}
}
/// Simpler thread-unaware version of above to be populated and returned to
/// consumers might be interested in, such as test results or UI
#[derive(Debug, Clone)]
pub struct ServerStats {
	/// Number of peers
	pub peer_count: u32,
	/// Chain head
	pub chain_stats: ChainStats,
	/// Header head (may differ from chain head)
	pub header_stats: ChainStats,
	/// Whether we're currently syncing
	pub sync_status: SyncStatus,
	/// Handle to current stratum server stats
	pub stratum_stats: Arc<StratumStats>,
	/// Peer stats
	pub peer_stats: Vec<PeerStats>,
	/// Difficulty calculation statistics
	pub diff_stats: DiffStats,
	/// Transaction pool statistics
	pub tx_stats: Option<TxStats>,
	/// Disk usage in GB
	pub disk_usage_gb: String,
}

/// Chain Statistics
#[derive(Clone, Serialize, Debug)]
pub struct ChainStats {
	/// Height of the tip (max height of the fork)
	pub height: u64,
	/// Last block pushed to the fork
	pub last_block_h: Hash,
	/// Total difficulty accumulated on that fork
	pub total_difficulty: Difficulty,
	/// Timestamp of highest block or header
	pub latest_timestamp: DateTime<Utc>,
}
/// Transaction Statistics
#[derive(Clone, Serialize, Debug)]
pub struct TxStats {
	/// Number of transactions in the transaction pool
	pub tx_pool_size: usize,
	/// Number of transaction kernels in the transaction pool
	pub tx_pool_kernels: usize,
	/// Number of transactions in the stem pool
	pub stem_pool_size: usize,
	/// Number of transaction kernels in the stem pool
	pub stem_pool_kernels: usize,
}
/// Struct to return relevant information about stratum workers
#[derive(Clone, Serialize, Debug)]
pub struct WorkerStats {
	/// Unique ID for this worker
	pub id: String,
	/// whether stratum worker is currently connected
	pub is_connected: bool,
	/// Timestamp of most recent communication with this worker
	pub last_seen: SystemTime,
	/// which block height it starts mining
	pub initial_block_height: u64,
	/// pow difficulty this worker is using
	pub pow_difficulty: u64,
	/// number of valid shares submitted
	pub num_accepted: u64,
	/// number of invalid shares submitted
	pub num_rejected: u64,
	/// number of shares submitted too late
	pub num_stale: u64,
	/// number of valid blocks found
	pub num_blocks_found: u64,
}

/// Struct to return relevant information about the stratum server
#[derive(Debug)]
pub struct StratumStats {
	/// whether stratum server is enabled
	pub is_enabled: AtomicBool,
	/// whether stratum server is running
	pub is_running: AtomicBool,
	/// Number of connected workers
	pub num_workers: AtomicUsize,
	/// what block height we're mining at
	pub block_height: AtomicU64,
	/// current network difficulty we're working on
	pub network_difficulty: AtomicU64,
	/// cuckoo size of last share submitted
	pub edge_bits: AtomicU16,
	/// Number of blocks found by all workers
	pub blocks_found: AtomicUsize,
	/// current network Hashrate (for edge_bits)
	pub network_hashrate: atomic_float::AtomicF64,
	/// The minimum acceptable share difficulty to request from miners
	pub minimum_share_difficulty: AtomicU64,
	/// Individual worker status
	worker_stats: RwLock<Vec<WorkerStats>>,
}

/// Stats on the last WINDOW blocks and the difficulty calculation
#[derive(Debug, Clone)]
pub struct DiffStats {
	/// latest height
	pub height: u64,
	/// Last WINDOW block data
	pub last_blocks: Vec<DiffBlock>,
	/// Average block time for last WINDOW blocks
	pub average_block_time: u64,
	/// Average WINDOW difficulty
	pub average_difficulty: u64,
	/// WINDOW size
	pub window_size: u64,
}

/// Last n blocks for difficulty calculation purposes
#[derive(Clone, Debug)]
pub struct DiffBlock {
	/// Block height (can be negative for a new chain)
	pub block_height: i64,
	/// Block hash (may be synthetic for a new chain)
	pub block_hash: Hash,
	/// Block network difficulty
	pub difficulty: u64,
	/// Time block was found (epoch seconds)
	pub time: u64,
	/// Duration since previous block (epoch seconds)
	pub duration: u64,
	/// secondary scaling
	pub secondary_scaling: u32,
	/// is secondary
	pub is_secondary: bool,
}

/// Struct to return relevant information about peers
#[derive(Clone, Debug)]
pub struct PeerStats {
	/// Current state of peer
	pub state: String,
	/// Address
	pub addr: String,
	/// version running
	pub version: ProtocolVersion,
	/// Peer user agent string.
	pub user_agent: String,
	/// difficulty reported by peer
	pub total_difficulty: u64,
	/// height reported by peer on ping
	pub height: u64,
	/// direction
	pub direction: String,
	/// Last time we saw a ping/pong from this peer.
	pub last_seen: DateTime<Utc>,
	/// Number of bytes we've sent to the peer.
	pub sent_bytes_per_sec: u64,
	/// Number of bytes we've received from the peer.
	pub received_bytes_per_sec: u64,
	/// Peer advertised capability flags.
	pub capabilities: Capabilities,
}

impl PartialEq for PeerStats {
	fn eq(&self, other: &PeerStats) -> bool {
		*self.addr == other.addr
	}
}

impl PartialEq for WorkerStats {
	fn eq(&self, other: &WorkerStats) -> bool {
		*self.id == other.id
	}
}

impl PartialEq for DiffBlock {
	fn eq(&self, other: &DiffBlock) -> bool {
		self.block_height == other.block_height
	}
}

impl StratumStats {
	/// Allocate a new slot for the worker. Assuming that caller will never fail.
	/// returns worker Id for the Worker tist
	pub fn allocate_new_worker(&self, pow_difficulty: u64) -> usize {
		let mut worker_stats = self.worker_stats.write();

		let worker_id = worker_stats
			.iter()
			.position(|stat| !stat.is_connected)
			.unwrap_or(worker_stats.len());

		let mut stats = WorkerStats::default();
		stats.is_connected = true;
		stats.id = worker_id.to_string();
		stats.pow_difficulty = pow_difficulty;

		if worker_id < worker_stats.len() {
			worker_stats[worker_id] = stats;
		} else {
			worker_stats.push(stats);
		}

		worker_id
	}

	/// Get worker Stat info
	pub fn get_stats(&self, worker_id: usize) -> Option<WorkerStats> {
		self.worker_stats.read().get(worker_id).map(|ws| ws.clone())
	}

	/// Update stats record for the worker
	/// callback expected to be short and non locking
	pub fn update_stats(&self, worker_id: usize, f: impl FnOnce(&mut WorkerStats) -> ()) {
		let mut worker_stats = self.worker_stats.write();
		f(&mut worker_stats[worker_id]);
	}

	/// Copy stat data. Expected that caller is understand the impact of this call.
	pub fn get_worker_stats(&self) -> Vec<WorkerStats> {
		self.worker_stats.read().clone()
	}
}

impl PeerStats {
	/// Convert from a peer directly
	pub fn from_peer(peer: &p2p::Peer) -> PeerStats {
		// State
		let state = if peer.is_banned() {
			"Banned"
		} else if peer.is_connected() {
			"Connected"
		} else {
			"Disconnected"
		};
		let addr = peer.info.addr.to_string();
		let direction = match peer.info.direction {
			p2p::types::Direction::Inbound => "Inbound",
			p2p::types::Direction::Outbound => "Outbound",
			p2p::types::Direction::InboundTor => "Inbound  (TOR)",
			p2p::types::Direction::OutboundTor => "Outbound (TOR)",
		};
		PeerStats {
			state: state.to_string(),
			addr: addr,
			version: peer.info.version,
			user_agent: peer.info.user_agent.clone(),
			total_difficulty: peer.info.total_difficulty().to_num(),
			height: peer.info.height(),
			direction: direction.to_string(),
			last_seen: peer.info.last_seen(),
			sent_bytes_per_sec: peer.tracker().sent_bytes.read().bytes_per_min() / 60,
			received_bytes_per_sec: peer.tracker().received_bytes.read().bytes_per_min() / 60,
			capabilities: peer.info.capabilities,
		}
	}
}

impl Default for WorkerStats {
	fn default() -> WorkerStats {
		WorkerStats {
			id: String::from("unknown"),
			is_connected: false,
			last_seen: SystemTime::now(),
			initial_block_height: 0,
			pow_difficulty: 0,
			num_accepted: 0,
			num_rejected: 0,
			num_stale: 0,
			num_blocks_found: 0,
		}
	}
}

impl Default for StratumStats {
	fn default() -> StratumStats {
		StratumStats {
			is_enabled: AtomicBool::new(false),
			is_running: AtomicBool::new(false),
			num_workers: AtomicUsize::new(0),
			block_height: AtomicU64::new(0),
			network_difficulty: AtomicU64::new(0),
			edge_bits: AtomicU16::new(0),
			blocks_found: AtomicUsize::new(0),
			network_hashrate: AtomicF64::new(0.0),
			minimum_share_difficulty: AtomicU64::new(1),
			worker_stats: RwLock::new(Vec::new()),
		}
	}
}
