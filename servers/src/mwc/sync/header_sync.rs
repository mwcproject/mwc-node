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

use crate::mwc::sync::sync_peers::SyncPeers;
use crate::mwc::sync::sync_utils::get_locator_heights;
use mwc_chain::{pibd_params, pipe, Chain};
use mwc_core::core::{
	hash::{Hash, Hashed},
	BlockHeader,
};
use mwc_core::pow::Difficulty;
use mwc_crates::log::info;
use mwc_crates::parking_lot::RwLock;
use mwc_p2p::{Peer, PeerAddr, PeerInfo, Peers};
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct HeadersRequest {
	addr: PeerAddr,
	locator: Vec<Hash>,
	sent: Option<Instant>,
	response_headers: Vec<BlockHeader>,
	init_ts: u64,
	// Downloads wait for a nonzero height and must prove the complete advertised
	// height/work pair captured when the task starts.
	expected_height: u64,
	expected_difficulty: Difficulty,
}

#[derive(Debug, PartialEq, Eq)]
enum HeaderProgressError {
	NoProgress,
	TargetMismatch,
}

impl HeadersRequest {
	// Called with the request lock held, so the send time is recorded before
	// a response or timeout check can access this request.
	fn send(&mut self, peer: &Peer, scores: &SyncPeers) -> Result<(), mwc_chain::Error> {
		let sent_at = Instant::now();
		peer.send_header_request(self.locator.clone())
			.map_err(|error| {
				let message = format!("Failed to send headers request to {}: {}", self.addr, error);
				scores.report_no_response(&self.addr, message.clone());
				mwc_chain::Error::Other(message)
			})?;
		self.sent = Some(sent_at);
		Ok(())
	}

	/// Records response progress and returns whether more headers need to be requested.
	fn needs_more_headers(
		&mut self,
		res_ts: u64,
		headers: &[BlockHeader],
	) -> Result<bool, HeaderProgressError> {
		let init_ts = self.init_ts;
		self.init_ts = self.init_ts.max(res_ts);
		let last = headers.last().ok_or(HeaderProgressError::NoProgress)?;
		if headers.iter().any(|header| {
			header.height == self.expected_height
				&& header.total_difficulty() == self.expected_difficulty
		}) {
			return Ok(false);
		}
		// No received header matched the advertised height/work pair. Valid ancestry
		// increases in both values, so once either target has been reached,
		// continuing along this branch cannot supply the missing pair.
		if last.height >= self.expected_height
			|| last.total_difficulty() >= self.expected_difficulty
		{
			return Err(HeaderProgressError::TargetMismatch);
		}
		if res_ts <= init_ts {
			return Err(HeaderProgressError::NoProgress);
		}
		Ok(true)
	}
}

/// Ordinary header downloads, with one independent request per supplier.
pub struct HeaderSync {
	chain: Arc<Chain>,
	headers: RwLock<VecDeque<HeadersRequest>>,
}

impl HeaderSync {
	pub fn new(chain: Arc<Chain>) -> Self {
		HeaderSync {
			chain,
			headers: RwLock::new(VecDeque::new()),
		}
	}

	#[cfg(all(test, feature = "test-support"))]
	pub(crate) fn download_for_test(&self, peer: &PeerAddr) -> Option<(u64, Difficulty)> {
		self.headers
			.read_recursive()
			.iter()
			.find(|req| req.addr == *peer)
			.map(|req| (req.init_ts, req.expected_difficulty))
	}

	/// Called by the sync loop to expire unanswered requests, even when fully synced.
	pub fn check_header_requests(&self, sync_peers: &SyncPeers, now: Instant) -> bool {
		let mut expired = Vec::new();
		let timeout = Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64);
		self.headers.write().retain(|req| {
			if req
				.sent
				.is_some_and(|sent_at| now.saturating_duration_since(sent_at) >= timeout)
			{
				expired.push((req.addr.clone(), req.locator[0]));
				false
			} else {
				true
			}
		});
		for (peer, anchor) in &expired {
			sync_peers.report_no_response(peer, format!("Headers after {} timed out", anchor));
		}
		!expired.is_empty()
	}

	/// Download advertised work and check equal-work peers with a different height.
	pub(super) fn request(
		&self,
		peers: &Arc<Peers>,
		scores: &SyncPeers,
	) -> Result<bool, mwc_chain::Error> {
		// The handshake supplies work without height. Wait for a nonzero height
		// advertisement so every download can verify the complete height/work pair.
		let connected: Vec<_> = peers
			.iter()
			.connected()
			.into_iter()
			.filter_map(|peer| {
				let (height, difficulty) = peer.info.get_height_and_difficulty();
				(height != 0).then_some((peer, height, difficulty))
			})
			.collect();
		let mut headers = self.headers.write();
		headers.retain(|req| {
			connected
				.iter()
				.any(|(peer, _, _)| peer.info.addr == req.addr)
		});
		if connected.is_empty() {
			return Ok(true);
		}
		let head = self.chain.header_head()?;
		let mut locators = HashMap::new();
		let mut send_errors = Vec::new();
		for (peer, height, difficulty) in &connected {
			let index = match headers.iter().position(|req| req.addr == peer.info.addr) {
				Some(index) => index,
				None => {
					// A peer can advertise our header tip's work with a different height.
					// This prevents truncate_header_head() from falling back, but excludes
					// the peer from body downloads because its height/work pair does not
					// match our chain. Requesting only greater work would let it keep
					// answering pings without ever serving data or receiving a timeout.
					// Request headers for equal-work height mismatches too, so an unproven
					// claim is subject to the normal response and timeout penalties.
					if *difficulty < head.total_difficulty
						|| (*difficulty == head.total_difficulty && *height == head.height)
					{
						continue;
					}
					// Responses start after the matching locator, so begin below the
					// claimed height to allow it to be included in the response.
					let locator_height = head.height.min(height.saturating_sub(1));
					let locator = match locators.entry(locator_height) {
						Entry::Occupied(entry) => entry.into_mut(),
						Entry::Vacant(entry) => entry.insert(
							self.chain
								.get_locator_hashes(head, &get_locator_heights(locator_height))?,
						),
					};
					let index = headers.len();
					headers.push_back(HeadersRequest {
						addr: peer.info.addr.clone(),
						locator: locator.clone(),
						sent: None,
						response_headers: Vec::new(),
						init_ts: 0,
						expected_height: *height,
						expected_difficulty: *difficulty,
					});
					index
				}
			};
			let req = &mut headers[index];
			if req.sent.is_some() {
				continue;
			}
			if let Err(error) = req.send(peer, scores) {
				headers.remove(index);
				send_errors.push(error.to_string());
			}
		}
		if !send_errors.is_empty() {
			return Err(mwc_chain::Error::Other(send_errors.join("; ")));
		}
		Ok(headers.is_empty())
	}

	pub(super) fn reset(&self) {
		self.headers.write().clear();
	}

	fn get_locator(&self, tip: mwc_chain::Tip) -> Result<Vec<Hash>, mwc_chain::Error> {
		self.chain
			.get_locator_hashes(tip, &get_locator_heights(tip.height))
	}

	/// Accept an unsolicited direct extension without changing any pending response.
	/// Returns true only when this header advances the selected header chain.
	pub(super) fn receive_header(
		&self,
		header: &BlockHeader,
		peer: &PeerInfo,
		scores: &SyncPeers,
	) -> Result<bool, mwc_chain::Error> {
		// Serialize with requested headers and other announcements so repeats do
		// not earn success events or replace another supplier's partial response.
		let _requests = self.headers.write();
		let tip = self.chain.header_head()?;
		if header.prev_hash != tip.last_block_h || tip.height.checked_add(1) != Some(header.height)
		{
			// This is only an advertisement. A better fork needs its ancestry
			// downloaded by the regular sync loop before it can become our head.
			peer.update(header.height, header.total_difficulty());
			return Ok(false);
		}
		if let Err(error) = self
			.chain
			.process_block_header(header, mwc_chain::Options::NONE)
		{
			if error.is_bad_data() && !error.requires_chain_recovery() {
				scores.report_error_response(&peer.addr, format!("Invalid header: {}", error));
			}
			return Err(error);
		}
		peer.update(header.height, header.total_difficulty());
		let advanced =
			self.chain.header_head()?.last_block_h == header.hash(self.chain.get_context_id())?;
		if advanced {
			scores.report_ok_response(&peer.addr);
		}
		Ok(advanced)
	}

	/// Returns whether this response belongs to an ordinary header download.
	pub(super) fn receive_headers(
		&self,
		peer: &PeerAddr,
		bhs: &[BlockHeader],
		remaining: u64,
		sync_peers: &SyncPeers,
		peers: &Arc<Peers>,
	) -> Result<bool, mwc_chain::Error> {
		let context_id = self.chain.get_context_id();
		// Serialize receipt, validation and request updates with sends and timeout checks.
		let mut requests = self.headers.write();
		let Some(index) = requests
			.iter()
			.position(|req| req.addr == *peer && req.sent.is_some())
		else {
			return Ok(false);
		};
		// All fallible processing stays inside this result so every error below
		// removes the task before it reaches the coordinator's error log.
		let result = (|| -> Result<bool, mwc_chain::Error> {
			let req = &mut requests[index];
			let Some(first) = bhs.first() else {
				return Ok(false);
			};
			if let Some(last) = req.response_headers.last() {
				if last.hash(context_id)? != first.prev_hash {
					return Ok(false);
				}
			} else if !req.locator.contains(&first.prev_hash) {
				return Ok(false);
			}
			if req.response_headers.len().saturating_add(bhs.len())
				> mwc_p2p::MAX_BLOCK_HEADERS as usize
			{
				return Err(mwc_chain::Error::InvalidBlocksSeries(
					"Headers response exceeds maximum size".into(),
				));
			}
			// Fragments share the original deadline. remaining == 0 completes a response
			// of any permitted size; it need not contain MAX_BLOCK_HEADERS headers.
			req.response_headers.extend_from_slice(bhs);
			if remaining > 0 {
				return Ok(true);
			}
			let bhs = std::mem::take(&mut req.response_headers);

			for header in &bhs {
				pipe::validate_header_hash(context_id, &header.hash(context_id)?)?;
			}
			let received_at = u64::try_from(mwc_crates::chrono::Utc::now().timestamp_micros())
				.map_err(|_| {
					mwc_chain::Error::Other("negative local header receipt time".into())
				})?;
			let progress_time =
				self.chain
					.sync_block_headers(&bhs, mwc_chain::Options::NONE, received_at)?;
			let last = bhs
				.last()
				.ok_or_else(|| mwc_chain::Error::Other("Empty header response".into()))?;
			// The last validated header has the most work, possibly beyond the advertised tip.
			let supplier = peers.get_connected_peer(peer);
			if let Some(supplier) = &supplier {
				supplier.info.update(last.height, last.total_difficulty());
			}
			req.sent = None;
			match req.needs_more_headers(progress_time, &bhs) {
				Ok(false) => {
					requests.remove(index);
					sync_peers.report_ok_response(peer);
				}
				Ok(true) => {
					// Continue on the supplier's branch, even before it becomes our head.
					req.locator = self.get_locator(mwc_chain::Tip::try_from_header(last)?)?;
					let supplier = supplier.ok_or_else(|| {
						mwc_chain::Error::Other(format!(
							"Peer {} disconnected before header download could continue",
							peer
						))
					})?;
					req.send(&supplier, sync_peers)?;
					sync_peers.report_ok_response(peer);
				}
				Err(error) => {
					let message = match error {
						// Retain the progress marker so replays cannot restart from zero.
						HeaderProgressError::NoProgress => "Headers response made no progress",
						HeaderProgressError::TargetMismatch => {
							// A reorg can invalidate an advertisement. Fine this attempt,
							// then let a new task capture the peer's latest advertised pair.
							requests.remove(index);
							"Headers response did not match the advertised height and difficulty"
						}
					};
					info!("Header download from {} will retry: {}", peer, message);
					sync_peers.report_no_response(peer, message.into());
				}
			}
			Ok(true)
		})();
		if let Err(error) = &result {
			requests.remove(index);
			if error.is_bad_data() {
				sync_peers
					.report_error_response(peer, format!("Invalid headers response: {}", error));
			}
		}
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_chain::pibd_params;
	use mwc_chain::types::NoopAdapter;
	use mwc_core::{genesis, global, pow, ser::ProtocolVersion};
	use mwc_crates::secp::{ContextFlag, Secp256k1};
	use mwc_p2p::types::{Capabilities, Direction, PeerLiveInfo};
	use mwc_p2p::PeerInfo;
	use std::collections::HashSet;
	use std::fs;
	use std::time::Duration;

	fn header_at(height: u64, work: u64) -> BlockHeader {
		let mut header = BlockHeader::default(0);
		header.height = height;
		header.pow.total_difficulty = Difficulty::from_num(work);
		header
	}

	// Advance a download toward its advertised tip, then replay equal and older timestamps.
	// Only increasing timestamps permit continuation; reaching the height/work target completes
	// the download even when the final headers have an older stored timestamp.
	#[test]
	fn header_download_requires_progress_until_advertised_tip_is_proven() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let mut req = HeadersRequest {
			addr: peer_info(3414, Capabilities::HEADER_HIST).addr,
			locator: vec![Hash::from_vec(&[1; 32])],
			sent: None,
			response_headers: Vec::new(),
			init_ts: 0,
			expected_height: 10,
			expected_difficulty: Difficulty::from_num(100),
		};
		assert_eq!(req.needs_more_headers(10, &[header_at(3, 30)]), Ok(true));
		assert_eq!(req.init_ts, 10);
		assert!(req.needs_more_headers(10, &[header_at(3, 30)]).is_err());
		assert!(req.needs_more_headers(9, &[header_at(3, 31)]).is_err());
		assert_eq!(req.init_ts, 10);
		assert_eq!(req.needs_more_headers(20, &[header_at(4, 40)]), Ok(true));
		assert_eq!(req.init_ts, 20);
		// Reaching the goal completes even if the final headers were already known.
		assert_eq!(
			req.needs_more_headers(10, &[header_at(10, 100), header_at(11, 110)]),
			Ok(false)
		);
		assert_eq!(req.expected_height, 10);
		assert_eq!(req.expected_difficulty, Difficulty::from_num(100));
	}

	#[test]
	fn advertised_tip_requires_height_and_work_from_the_same_header() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let mut req = HeadersRequest {
			addr: peer_info(3414, Capabilities::HEADER_HIST).addr,
			locator: Vec::new(),
			sent: None,
			response_headers: Vec::new(),
			init_ts: 0,
			expected_height: 10,
			expected_difficulty: Difficulty::from_num(100),
		};
		// Neither reaching the work early nor reaching the height with different
		// work proves the pair. A response that passes the target must include it.
		for response in [
			vec![header_at(9, 100)],
			vec![header_at(10, 99)],
			vec![header_at(9, 100), header_at(10, 110)],
			vec![header_at(11, 110)],
		] {
			assert_eq!(
				req.needs_more_headers(10, &response),
				Err(HeaderProgressError::TargetMismatch)
			);
		}
	}

	fn test_requests() -> (HeaderSync, String) {
		global::set_local_chain_type(global::ChainTypes::Floonet);
		global::set_local_nrd_enabled(false);

		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let nanos = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_nanos();
		let dir = std::env::temp_dir().join(format!(
			"mwc_block_request_queue_{}_{}",
			std::process::id(),
			nanos
		));
		let dir_str = dir.to_string_lossy().to_string();
		let _ = fs::remove_dir_all(&dir_str);

		let chain = Arc::new(
			Chain::init(
				&secp,
				0,
				dir_str.clone(),
				Arc::new(NoopAdapter {}),
				genesis::genesis_floo(&secp, 0),
				pow::verify_size,
				false,
				HashSet::new(),
				None,
				None,
				false,
			)
			.unwrap(),
		);
		(HeaderSync::new(chain), dir_str)
	}

	fn peer_info(port: u16, capabilities: Capabilities) -> PeerInfo {
		PeerInfo {
			capabilities,
			user_agent: "queue-test".into(),
			version: ProtocolVersion::local(),
			addr: PeerAddr::Ip(([127, 0, 0, 1], port).into()),
			direction: Direction::Outbound,
			live_info: Arc::new(RwLock::new(PeerLiveInfo::new(pow::Difficulty::min()))),
			tx_base_fee: 0,
		}
	}

	#[cfg(feature = "test-support")]
	mod headers {
		use super::*;
		use mwc_core::core::{hash::Hashed, BlockHeader};
		use mwc_p2p::{msg::Msg, Peer};

		// Start with a genesis-only chain and a connected peer advertising more work.
		// The receiver exposes outgoing requests without using a network connection.
		struct Fixture {
			requests: HeaderSync,
			peers: Arc<Peers>,
			peer: Arc<Peer>,
			receiver: mwc_crates::crossbeam::channel::Receiver<Msg>,
			scores: SyncPeers,
			_peer_dir: mwc_crates::tempfile::TempDir,
			chain_dir: String,
		}

		impl Fixture {
			fn new() -> Self {
				let (requests, chain_dir) = test_requests();
				let peer_dir = mwc_crates::tempfile::TempDir::new().unwrap();
				let store =
					mwc_p2p::store::PeerStore::new(0, peer_dir.path().to_str().unwrap()).unwrap();
				let peers = Arc::new(Peers::new(
					store,
					Arc::new(mwc_p2p::DummyAdapter {}),
					&mwc_p2p::P2PConfig::default(),
				));
				let (peer, receiver) = Peer::connected_for_test(
					peer_info(3451, Capabilities::UNKNOWN),
					0,
					Arc::new(mwc_p2p::DummyAdapter {}),
				);
				let peer = Arc::new(peer);
				let head = requests.chain.header_head().unwrap();
				peer.info.update(
					head.height + 100,
					(head.total_difficulty + Difficulty::from_num(100)).unwrap(),
				);
				peers.add_connected(peer.clone()).unwrap();
				Self {
					requests,
					peers,
					peer,
					receiver,
					scores: SyncPeers::new(),
					_peer_dir: peer_dir,
					chain_dir,
				}
			}

			fn dispatch(&self) {
				self.requests.request(&self.peers, &self.scores).unwrap();
			}

			fn expected_difficulty(&self) -> Difficulty {
				(self.requests.chain.header_head().unwrap().total_difficulty
					+ Difficulty::from_num(100))
				.unwrap()
			}

			fn deadline(&self) -> Instant {
				self.requests
					.headers
					.read_recursive()
					.iter()
					.filter_map(|req| req.sent)
					.max()
					.unwrap() + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)
			}

			fn check(&self, now: Instant) -> bool {
				self.requests.check_header_requests(&self.scores, now)
			}
		}

		impl Drop for Fixture {
			fn drop(&mut self) {
				let _ = fs::remove_dir_all(&self.chain_dir);
			}
		}

		// These synthetic headers exercise response matching and buffering. They are
		// not valid mined headers, so a complete response must fail chain validation.
		fn response(prev: Hash) -> BlockHeader {
			let mut header = BlockHeader::default(0);
			header.prev_hash = prev;
			header
		}

		// Start one download, then add peers with more work or an inconsistent equal-work tip.
		// Peers requiring verification get one request; existing downloads keep their deadline and
		// advertised target, including when their peer later advertises less work.
		#[test]
		fn starts_all_ahead_peers_and_preserves_existing_downloads() {
			let f = Fixture::new();
			let local_difficulty = f.requests.chain.header_head().unwrap().total_difficulty;
			let difficulty = f.expected_difficulty();
			f.peer.info.update(10, difficulty);
			f.requests.request(&f.peers, &f.scores).unwrap();
			let sent_at = f.requests.headers.read_recursive()[0].sent;
			let mut receivers = Vec::new();
			for port in 3460..3472 {
				let info = peer_info(port, Capabilities::UNKNOWN);
				let work = (difficulty + Difficulty::from_num(u64::from(port - 3450))).unwrap();
				info.update(20, work);
				let (peer, receiver) =
					Peer::connected_for_test(info, 0, Arc::new(mwc_p2p::DummyAdapter {}));
				f.peers.add_connected(Arc::new(peer)).unwrap();
				receivers.push(receiver);
			}
			let mut ignored = Vec::new();
			for (port, height, work) in [
				(3472, 15, local_difficulty),
				(
					3473,
					15,
					(local_difficulty - Difficulty::from_num(1)).unwrap(),
				),
				(3474, 0, local_difficulty),
				(3475, 0, difficulty),
			] {
				let info = peer_info(port, Capabilities::UNKNOWN);
				// Seed handshake work directly; update() cannot lower the helper's
				// initial minimum difficulty, which exceeds Floonet genesis work.
				info.live_info.write().total_difficulty = work;
				info.update(height, work);
				assert_eq!(info.get_height_and_difficulty(), (height, work));
				let (peer, receiver) =
					Peer::connected_for_test(info, 0, Arc::new(mwc_p2p::DummyAdapter {}));
				f.peers.add_connected(Arc::new(peer)).unwrap();
				if height != 0 && work == local_difficulty {
					receivers.push(receiver);
				} else {
					ignored.push(receiver);
				}
			}
			assert!(!f.requests.request(&f.peers, &f.scores).unwrap());
			assert_eq!(f.receiver.try_iter().count(), 1);
			assert!(receivers.iter().all(|rx| rx.try_iter().count() == 1));
			assert!(ignored.iter().all(|rx| rx.try_iter().count() == 0));
			assert_eq!(f.requests.headers.read_recursive().len(), 14);
			assert_eq!(f.requests.headers.read_recursive()[0].sent, sent_at);
			assert_eq!(f.requests.headers.read_recursive()[0].expected_height, 100);
			// A new advertisement cannot move either part of an active task's target.
			f.peer
				.info
				.update(200, (difficulty + Difficulty::from_num(1)).unwrap());
			f.requests.request(&f.peers, &f.scores).unwrap();
			assert_eq!(f.receiver.try_iter().count(), 0);
			assert!(receivers.iter().all(|rx| rx.try_iter().count() == 0));
			// A lower advertised difficulty must not stop an existing download's retry.
			f.peer.info.update(10, local_difficulty);
			assert_eq!(
				f.peer.info.get_height_and_difficulty().1,
				(difficulty + Difficulty::from_num(1)).unwrap()
			);
			f.requests.headers.write()[0].sent = None;
			f.dispatch();
			assert_eq!(f.receiver.try_iter().count(), 1);
			assert_eq!(
				f.requests.headers.read_recursive()[0].expected_difficulty,
				difficulty
			);
			assert_eq!(f.requests.headers.read_recursive()[0].expected_height, 100);
			assert!(receivers.iter().all(|rx| rx.try_iter().count() == 0));
			assert!(ignored.iter().all(|rx| rx.try_iter().count() == 0));
		}

		// Poll with no peer ahead, then with a download already awaiting its response.
		// Holding the PMMR read locks makes any unnecessary locator rebuild block;
		// both polls must return promptly and send no additional requests.
		#[test]
		fn idle_and_active_downloads_do_not_build_a_new_locator() {
			let f = Fixture::new();
			let head = f.requests.chain.header_head().unwrap();
			for active in [false, true] {
				// Set up each fixture state directly; announcements cannot lower the best tip.
				{
					let mut info = f.peer.info.live_info.write();
					info.height = if active {
						head.height + 100
					} else {
						head.height
					};
					info.total_difficulty = if active {
						f.expected_difficulty()
					} else {
						head.total_difficulty
					};
				}
				f.dispatch();
				assert_eq!(f.receiver.try_iter().count(), usize::from(active));
				std::thread::scope(|scope| {
					f.requests
						.chain
						.with_output_read_snapshot(|_| {
							// Locator construction would block on the PMMR read locks held here.
							let (completed, result) = std::sync::mpsc::channel();
							let f = &f;
							scope.spawn(move || {
								global::set_local_chain_type(global::ChainTypes::Floonet);
								global::set_local_nrd_enabled(false);
								completed
									.send(f.requests.request(&f.peers, &f.scores))
									.unwrap();
							});
							assert_eq!(
								result
									.recv_timeout(Duration::from_secs(5))
									.unwrap()
									.unwrap(),
								!active
							);
							Ok::<_, mwc_chain::Error>(())
						})
						.unwrap();
				});
				assert_eq!(f.receiver.try_iter().count(), 0);
			}
		}

		// Poll repeatedly around one request's deadline. Polling must neither resend nor
		// extend it; expiration removes the task, and the next poll sends one fresh request.
		#[test]
		fn repeated_requests_preserve_deadline_and_retry_only_after_expiration() {
			let f = Fixture::new();
			// Repeated sync polls share the original task and its send time.
			f.requests.request(&f.peers, &f.scores).unwrap();
			assert_eq!(f.receiver.try_iter().count(), 1);
			assert_eq!(f.requests.headers.read_recursive().len(), 1);
			let deadline = f.deadline();
			f.requests.request(&f.peers, &f.scores).unwrap();
			f.dispatch();
			assert_eq!(f.receiver.try_iter().count(), 0);
			assert_eq!(f.deadline(), deadline);

			assert!(!f.check(deadline - Duration::from_millis(1)));
			assert!(f.check(deadline));

			assert!(f.requests.headers.read_recursive().is_empty());
			f.requests.request(&f.peers, &f.scores).unwrap();
			assert_eq!(f.receiver.try_iter().count(), 1);
			f.dispatch();
			assert_eq!(f.receiver.try_iter().count(), 0);
		}

		#[test]
		fn equal_work_wrong_height_peer_is_banned_after_header_timeouts() {
			let f = Fixture::new();
			let head = f.requests.chain.header_head().unwrap();
			{
				let mut info = f.peer.info.live_info.write();
				info.height = head.height + 1;
				info.total_difficulty = head.total_difficulty;
			}
			for attempt in 0..7 {
				f.dispatch();
				assert_eq!(f.receiver.try_iter().count(), 1);
				let deadline = f.deadline();
				// Ping/Pong and repeated sync passes cannot renew the header deadline.
				f.peer.info.update(head.height + 1, head.total_difficulty);
				f.dispatch();
				assert_eq!(f.receiver.try_iter().count(), 0);
				assert_eq!(f.deadline(), deadline);
				assert!(f.check(deadline));
				assert!(!f.check(deadline));
				f.scores.apply_peers_status(&f.peers);
				assert_eq!(f.peers.is_banned(&f.peer.info.addr).unwrap(), attempt == 6);
			}
			f.dispatch();
			assert!(f.requests.headers.read_recursive().is_empty());
		}

		// Keep the peer connected and advertising more work while withholding all headers.
		// Each expired attempt is removed and fined once; retries use a fresh task, and
		// the seventh timeout bans the supplier so no further request is sent.
		#[test]
		fn tip_download_retries_the_same_peer_until_repeated_timeouts_ban_it() {
			let f = Fixture::new();
			let addr = &f.peer.info.addr;
			let expected_difficulty = f.expected_difficulty();
			f.requests.request(&f.peers, &f.scores).unwrap();
			f.requests.headers.write()[0].init_ts = 42;
			for attempt in 0..7 {
				f.dispatch();
				assert_eq!(f.receiver.try_iter().count(), 1);
				{
					let headers = f.requests.headers.read_recursive();
					assert_eq!(headers.len(), 1);
					assert_eq!(headers[0].addr, *addr);
					assert_eq!(
						headers[0].expected_difficulty,
						f.peer.info.get_height_and_difficulty().1
					);
					if attempt > 0 {
						assert_eq!(headers[0].init_ts, 0);
						assert_eq!(
							headers[0].locator[0],
							f.requests.chain.header_head().unwrap().last_block_h
						);
					}
				}
				// Live Ping/Pong does not excuse an unanswered header request.
				f.peer.info.update(
					1000,
					(expected_difficulty + Difficulty::from_num(1000)).unwrap(),
				);
				let deadline = f.deadline();
				assert!(f.check(deadline));
				for _ in 0..20 {
					assert!(!f.check(deadline + Duration::from_secs(60)));
				}
				assert!(f.requests.headers.read_recursive().is_empty());
				f.scores.apply_peers_status(&f.peers);
				assert_eq!(f.peers.is_banned(addr).unwrap(), attempt == 6);
			}
			f.receiver.try_iter().for_each(drop);
			f.dispatch();
			assert!(f.requests.headers.read_recursive().is_empty());
			assert_eq!(f.receiver.try_iter().count(), 0);
		}

		// Ignore a wrong anchor, then assemble matching fragments and reach validation.
		// The synthetic headers fail validation and remove that task. On a new attempt,
		// broken fragment links must leave the request pending until its deadline.
		#[test]
		fn full_matching_fork_response_completes_but_wrong_or_broken_response_times_out() {
			let f = Fixture::new();
			let peer = &f.peer.info.addr;
			let newest = f.requests.chain.header_head().unwrap().last_block_h;
			let wrong = Hash::from_vec(&[3; 32]);
			f.requests.request(&f.peers, &f.scores).unwrap();
			f.dispatch();
			let deadline = f.deadline();
			assert!(!f
				.requests
				.receive_headers(peer, &[response(wrong)], 1, &f.scores, &f.peers)
				.unwrap());
			let first = response(newest);
			let last = response(first.hash(0).unwrap());
			assert!(f
				.requests
				.receive_headers(peer, &[first], 1, &f.scores, &f.peers)
				.unwrap());
			assert_eq!(f.deadline(), deadline);
			assert!(!f.check(deadline - Duration::from_millis(1)));
			// Invalid synthetic headers must return the chain error and cancel the task.
			f.requests
				.receive_headers(peer, &[last], 0, &f.scores, &f.peers)
				.unwrap_err();
			assert!(!f.check(deadline + Duration::from_secs(60)));
			assert!(f.requests.headers.read_recursive().is_empty());
			// Start a separate attempt for the broken-fragment case below.
			f.requests.request(&f.peers, &f.scores).unwrap();
			f.dispatch();
			let deadline = f.deadline();
			assert!(f
				.requests
				.receive_headers(peer, &[response(newest)], 2, &f.scores, &f.peers)
				.unwrap());
			assert!(!f
				.requests
				.receive_headers(peer, &[response(wrong)], 1, &f.scores, &f.peers)
				.unwrap());
			assert!(!f
				.requests
				.receive_headers(peer, &[response(newest)], 0, &f.scores, &f.peers)
				.unwrap());
			assert!(f.check(deadline));
		}

		// Buffer the first fragment, expire the request, and start another attempt.
		// Its buffer must be empty: the old continuation is ignored, while a new first
		// fragment matching the locator is accepted.
		#[test]
		fn timeout_discards_partial_headers_before_retry() {
			let f = Fixture::new();
			let peer = &f.peer.info.addr;
			let anchor = f.requests.chain.header_head().unwrap().last_block_h;
			f.requests.request(&f.peers, &f.scores).unwrap();
			f.dispatch();
			let first = response(anchor);
			let last = response(first.hash(0).unwrap());
			assert!(f
				.requests
				.receive_headers(peer, &[first], 1, &f.scores, &f.peers)
				.unwrap());
			assert!(f.check(f.deadline()));
			assert!(f.requests.headers.read_recursive().is_empty());
			f.dispatch();
			assert!(!f
				.requests
				.receive_headers(peer, &[last], 0, &f.scores, &f.peers)
				.unwrap());
			assert!(f
				.requests
				.receive_headers(peer, &[response(anchor)], 1, &f.scores, &f.peers)
				.unwrap());
		}

		// Pause response validation behind chain read locks and run expiration concurrently.
		// Expiration must wait for validation to finish; the invalid response removes its
		// task first, leaving nothing to report as a network timeout.
		#[test]
		fn local_validation_keeps_request_and_stops_network_timeout() {
			let f = Fixture::new();
			let anchor = f.requests.chain.header_head().unwrap().last_block_h;
			f.requests.request(&f.peers, &f.scores).unwrap();
			let expired_at = f.deadline() + Duration::from_secs(60);
			std::thread::scope(|scope| {
				// Hold the chain read locks so receive_headers pauses at chain validation.
				let (receive, check, checked) = f
					.requests
					.chain
					.with_output_read_snapshot(|_| {
						let receive = scope.spawn(|| {
							global::set_local_chain_type(global::ChainTypes::Floonet);
							global::set_local_nrd_enabled(false);
							f.requests.receive_headers(
								&f.peer.info.addr,
								&[response(anchor)],
								0,
								&f.scores,
								&f.peers,
							)
						});
						let wait_until = Instant::now() + Duration::from_secs(5);
						while f.requests.headers.try_read().is_some() {
							assert!(
								Instant::now() < wait_until,
								"Response did not lock its request"
							);
							std::thread::yield_now();
						}
						let (completed, checked) = std::sync::mpsc::channel();
						let requests = &f.requests;
						let scores = &f.scores;
						let check = scope.spawn(move || {
							completed
								.send(requests.check_header_requests(scores, expired_at))
								.unwrap();
						});
						assert!(matches!(
							checked.recv_timeout(Duration::from_millis(50)),
							Err(std::sync::mpsc::RecvTimeoutError::Timeout)
						));
						Ok::<_, mwc_chain::Error>((receive, check, checked))
					})
					.unwrap();
				// Validation can now finish. Its result is recorded before timeout checking.
				assert!(receive.join().unwrap().unwrap_err().is_bad_data());
				assert!(!checked.recv_timeout(Duration::from_secs(5)).unwrap());
				check.join().unwrap();
			});
			assert!(f.requests.headers.read_recursive().is_empty());
		}

		// Request the same locator from two peers, with the second deadline slightly later.
		// Buffer data from the second peer and expire only the first: retrying the first
		// must preserve the second peer's buffer and must not resend its active request.
		#[test]
		fn same_locator_from_different_peers_is_independent() {
			let f = Fixture::new();
			let (other, receiver) = Peer::connected_for_test(
				peer_info(3452, Capabilities::HEADER_HIST),
				0,
				Arc::new(mwc_p2p::DummyAdapter {}),
			);
			let other = Arc::new(other);
			other.info.update(100, f.expected_difficulty());
			f.peers.add_connected(other.clone()).unwrap();
			let anchor = f.requests.chain.header_head().unwrap().last_block_h;
			f.requests.request(&f.peers, &f.scores).unwrap();
			f.requests.request(&f.peers, &f.scores).unwrap();
			f.requests.request(&f.peers, &f.scores).unwrap();
			f.dispatch();
			assert_eq!(f.receiver.try_iter().count(), 1);
			assert_eq!(receiver.try_iter().count(), 1);
			let deadline = {
				let mut requests = f.requests.headers.write();
				let first_sent = requests
					.iter()
					.find(|req| req.addr == f.peer.info.addr)
					.unwrap()
					.sent
					.unwrap();
				// The second request was sent later and must retain its own deadline.
				requests
					.iter_mut()
					.find(|req| req.addr == other.info.addr)
					.unwrap()
					.sent = Some(first_sent + Duration::from_secs(1));
				first_sent + Duration::from_secs(pibd_params::PIBD_REQUESTS_TIMEOUT_SECS as u64)
			};
			assert!(f
				.requests
				.receive_headers(
					&other.info.addr,
					&[response(anchor)],
					1,
					&f.scores,
					&f.peers
				)
				.unwrap());
			assert!(f.check(deadline));
			{
				let requests = f.requests.headers.read_recursive();
				assert!(!requests.iter().any(|req| req.addr == f.peer.info.addr));
				let second = requests
					.iter()
					.find(|req| req.addr == other.info.addr)
					.unwrap();
				assert!(second.sent.is_some());
				assert_eq!(second.response_headers.len(), 1);
			}
			f.dispatch();
			assert_eq!(f.receiver.try_iter().count(), 1);
			assert_eq!(receiver.try_iter().count(), 0);
		}

		// Close the outgoing channel before scheduling. The send error must identify the
		// peer and remove its task; later expiration and polling must not revive that task.
		#[test]
		fn failed_send_returns_error_and_cancels_task() {
			let mut f = Fixture::new();
			let (_, replacement) = mwc_crates::crossbeam::channel::unbounded();
			drop(std::mem::replace(&mut f.receiver, replacement));
			let error = f.requests.request(&f.peers, &f.scores).unwrap_err();
			assert!(error.to_string().contains("Failed to send headers request"));
			assert!(error.to_string().contains(&f.peer.info.addr.to_string()));
			assert!(f.requests.headers.read_recursive().is_empty());

			assert!(!f.check(Instant::now() + Duration::from_secs(300)));
			assert!(!f.peer.is_connected());
			assert!(f.requests.request(&f.peers, &f.scores).unwrap());
			assert!(f.requests.headers.read_recursive().is_empty());
		}

		// Connect two peers ahead of us and break the first peer's outgoing channel.
		// Scheduling must still send to the other peer, then return the first send error
		// with only the successfully sent request left in the queue.
		#[test]
		fn failed_send_does_not_skip_other_ahead_peers() {
			let mut f = Fixture::new();
			let info = peer_info(3452, Capabilities::UNKNOWN);
			info.update(100, f.expected_difficulty());
			let (other, other_receiver) =
				Peer::connected_for_test(info, 0, Arc::new(mwc_p2p::DummyAdapter {}));
			f.peers.add_connected(Arc::new(other)).unwrap();
			// Fail whichever peer the scheduler will encounter first.
			let failed = f
				.peers
				.iter()
				.connected()
				.into_iter()
				.next()
				.unwrap()
				.info
				.addr
				.clone();
			let (_, replacement) = mwc_crates::crossbeam::channel::unbounded();
			let receiver = if failed == f.peer.info.addr {
				drop(std::mem::replace(&mut f.receiver, replacement));
				other_receiver
			} else {
				drop(other_receiver);
				std::mem::replace(&mut f.receiver, replacement)
			};
			let error = f.requests.request(&f.peers, &f.scores).unwrap_err();
			assert!(error.to_string().contains(&failed.to_string()));
			assert_eq!(receiver.try_iter().count(), 1);
			let requests = f.requests.headers.read_recursive();
			assert_eq!(requests.len(), 1);
			assert_ne!(requests[0].addr, failed);
		}

		// Send a matching response containing one header over the protocol limit.
		// Reject it as an invalid series and remove the task so it cannot time out later.
		#[test]
		fn oversized_response_returns_error_and_cancels_task() {
			let f = Fixture::new();
			let anchor = f.requests.chain.header_head().unwrap().last_block_h;
			f.requests.request(&f.peers, &f.scores).unwrap();
			let headers = vec![response(anchor); mwc_p2p::MAX_BLOCK_HEADERS as usize + 1];
			let error = f
				.requests
				.receive_headers(&f.peer.info.addr, &headers, 0, &f.scores, &f.peers)
				.unwrap_err();
			assert!(matches!(error, mwc_chain::Error::InvalidBlocksSeries(_)));
			assert!(f.requests.headers.read_recursive().is_empty());
			assert!(!f.check(Instant::now() + Duration::from_secs(300)));
		}
	}
}
