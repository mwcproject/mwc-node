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

use chrono::prelude::{DateTime, Utc};
use chrono::Duration;
use mwc_core::core::hash::Hash;
use mwc_core::core::BlockHeader;
use mwc_p2p::ReasonForBan;
use mwc_util::secp::rand::Rng;
use rand::seq::SliceRandom;
use std::sync::Arc;
use std::{thread, time};

use crate::chain::{self, pibd_params, SyncState, SyncStatus};
use crate::core::core::{hash::Hashed, pmmr::segment::SegmentType};
use crate::core::global;
use crate::core::pow::Difficulty;
use crate::p2p::{self, Capabilities, Peer};
use crate::util::StopState;

/// Fast sync has 3 "states":
/// * syncing headers
/// * once all headers are sync'd, requesting the txhashset state
/// * once we have the state, get blocks after that
///
/// The StateSync struct implements and monitors the middle step.
pub struct StateSync {
	sync_state: Arc<SyncState>,
	peers: Arc<p2p::Peers>,
	chain: Arc<chain::Chain>,

	prev_state_sync: Option<DateTime<Utc>>,
	state_sync_peer: Option<Arc<Peer>>,

	last_logged_time: i64,
	last_download_size: u64,

	pibd_aborted: bool,
	earliest_zero_pibd_peer_time: Option<DateTime<Utc>>,

	// Used bitmap_output_root, in case of error we better to bun all related peers
	output_bitmap_root_header_hash: Option<Hash>,
}

impl StateSync {
	pub fn new(
		sync_state: Arc<SyncState>,
		peers: Arc<p2p::Peers>,
		chain: Arc<chain::Chain>,
	) -> StateSync {
		StateSync {
			sync_state,
			peers,
			chain,
			prev_state_sync: None,
			state_sync_peer: None,
			last_logged_time: 0,
			last_download_size: 0,
			pibd_aborted: false,
			earliest_zero_pibd_peer_time: None,
			output_bitmap_root_header_hash: None,
		}
	}

	/// Record earliest time at which we had no suitable
	/// peers for continuing PIBD
	pub fn set_earliest_zero_pibd_peer_time(&mut self, t: Option<DateTime<Utc>>) {
		self.earliest_zero_pibd_peer_time = t;
	}

	/// Flag to abort PIBD process within StateSync, intentionally separate from `sync_state`,
	/// which can be reset between calls
	pub fn set_pibd_aborted(&mut self) {
		self.pibd_aborted = true;
	}

	fn reset_chain(&mut self) {
		if let Err(e) = self.chain.reset_pibd_head() {
			error!("pibd_sync restart: reset pibd_head error = {}", e);
		}
		if let Err(e) = self.chain.reset_chain_head_to_genesis() {
			error!("pibd_sync restart: chain reset to genesis error = {}", e);
		}
		if let Err(e) = self.chain.reset_prune_lists() {
			error!("pibd_sync restart: reset prune lists error = {}", e);
		}
	}

	/// Check whether state sync should run and triggers a state download when
	/// it's time (we have all headers). Returns true as long as state sync
	/// needs monitoring, false when it's either done or turned off.
	pub fn check_run(
		&mut self,
		header_head: &chain::Tip,
		head: &chain::Tip,
		tail: &chain::Tip,
		highest_height: u64,
		stop_state: Arc<StopState>,
	) -> bool {
		trace!("state_sync: head.height: {}, tail.height: {}. header_head.height: {}, highest_height: {}",
			   head.height, tail.height, header_head.height, highest_height,
		);

		let mut sync_need_restart = false;

		// check sync error
		if let Some(sync_error) = self.sync_state.sync_error() {
			error!("state_sync: error = {}. restart fast sync", sync_error);
			sync_need_restart = true;
		}

		// Determine whether we're going to try using PIBD or whether we've already given up
		// on it
		let using_pibd = !matches!(
			self.sync_state.status(),
			SyncStatus::TxHashsetPibd { aborted: true, .. },
		) && !self.pibd_aborted;

		// Check whether we've errored and should restart pibd
		if using_pibd {
			if let SyncStatus::TxHashsetPibd { errored: true, .. } = self.sync_state.status() {
				// So far in case of error, it is allways something bad happens, we was under attack, data that we got
				// is not valid as whole, even all the blocks was fine.

				// That is why we really want to ban all perrs that supported original bitmap_output hash
				// Reason for that - that so far it is the only way to fool the node. All other hashes are part of the headers

				if let Some(output_bitmap_root_header_hash) = self.output_bitmap_root_header_hash {
					// let's check for supporters and ban who ever commited to the same hash
					warn!("Because of PIBD sync error banning peers that was involved. output_bitmap_root_header_hash={}", output_bitmap_root_header_hash);
					for peer in self.peers.iter() {
						if peer.commited_to_pibd_bitmap_output_root(&output_bitmap_root_header_hash)
						{
							if let Err(err) = self
								.peers
								.ban_peer(peer.info.addr.clone(), ReasonForBan::PibdFailure)
							{
								error!("Unable to ban the peer {}, error {}", &peer.info.addr, err);
							}
						}
					}
					self.output_bitmap_root_header_hash = None;
				}

				let archive_header = self.chain.txhashset_archive_header_header_only().unwrap();
				error!("PIBD Reported Failure - Restarting Sync");
				// reset desegmenter state
				self.chain.reset_desegmenter();
				self.reset_chain();
				self.sync_state
					.update_pibd_progress(false, false, 0, 1, &archive_header);
				sync_need_restart = true;
			}
		}

		// check peer connection status of this sync
		if !using_pibd {
			if let Some(ref peer) = self.state_sync_peer {
				if let SyncStatus::TxHashsetDownload { .. } = self.sync_state.status() {
					if !peer.is_connected() {
						sync_need_restart = true;
						info!(
							"state_sync: peer connection lost: {:?}. restart",
							peer.info.addr,
						);
					}
				}
			}
		}

		// if txhashset downloaded and validated successfully, we switch to BodySync state,
		// and we need call state_sync_reset() to make it ready for next possible state sync.
		let done = self.sync_state.update_if(
			SyncStatus::BodySync {
				current_height: 0,
				highest_height: 0,
			},
			|s| match s {
				SyncStatus::TxHashsetDone => true,
				_ => false,
			},
		);

		if sync_need_restart || done {
			self.state_sync_reset();
			self.sync_state.clear_sync_error();
		}

		if done {
			return false;
		}

		// run fast sync if applicable, normally only run one-time, except restart in error
		if sync_need_restart || header_head.height == highest_height {
			if using_pibd {
				if sync_need_restart {
					return true;
				}
				let (launch, _download_timeout) = self.state_sync_due();
				let archive_header = { self.chain.txhashset_archive_header_header_only().unwrap() };
				if launch {
					self.sync_state
						.update_pibd_progress(false, false, 0, 1, &archive_header);
				}

				let archive_header = self.chain.txhashset_archive_header_header_only().unwrap();

				self.ban_inactive_pibd_peers();
				self.make_pibd_hand_shake(&archive_header);

				let mut has_segmenter = true;
				if self.chain.get_desegmenter(&archive_header).read().is_none() {
					has_segmenter = false;
					if let Some(bitmap_output_root) =
						self.select_pibd_bitmap_output_root(&archive_header)
					{
						self.output_bitmap_root_header_hash =
							Some((bitmap_output_root, archive_header.hash()).hash());
						// Restting chain because PIBD is not tolarate to the output bitmaps change.
						// Sinse we dont handle that (it is posible to handle by merging bitmaps), we
						// better to reset the chain.
						// Note, every 12 hours the root will be changed, so PIBD process must finish before
						self.reset_chain();
						if let Err(e) = self
							.chain
							.create_desegmenter(&archive_header, bitmap_output_root)
						{
							error!(
								"Unable to create desegmenter for header at {}, Error: {}",
								archive_header.height, e
							);
						} else {
							has_segmenter = true;
						}
					}
				}

				if has_segmenter {
					// Sleeping some extra time because checking request is CPU time consuming, not much optimization
					// going through all the data. That is why at lease let's not over do with that.
					thread::sleep(time::Duration::from_millis(500));

					// Continue our PIBD process (which returns true if all segments are in)
					match self.continue_pibd(&archive_header) {
						Ok(true) => {
							let desegmenter = self.chain.get_desegmenter(&archive_header);
							// All segments in, validate
							if let Some(d) = desegmenter.write().as_mut() {
								if let Ok(true) = d.check_progress(self.sync_state.clone()) {
									if let Err(e) = d.check_update_leaf_set_state() {
										error!("error updating PIBD leaf set: {}", e);
										self.sync_state.update_pibd_progress(
											false,
											true,
											0,
											1,
											&archive_header,
										);
										return false;
									}
									if let Err(e) = d.validate_complete_state(
										self.sync_state.clone(),
										stop_state.clone(),
									) {
										error!("error validating PIBD state: {}", e);
										self.sync_state.update_pibd_progress(
											false,
											true,
											0,
											1,
											&archive_header,
										);
										return false;
									}
									return true;
								}
							};
						}
						Ok(false) => (), // nothing to do, continue
						Err(e) => {
							// need to restart the sync process, but not ban the peers, it is not there fault
							error!("Need to restart the PIBD resync because of the error {}", e);
							// resetting to none, so no peers will be banned
							self.output_bitmap_root_header_hash = None;
							self.sync_state.update_pibd_progress(
								false,
								true,
								0,
								1,
								&archive_header,
							);
							return false;
						}
					}
				}
			} else {
				let (go, download_timeout) = self.state_sync_due();

				if let SyncStatus::TxHashsetDownload { .. } = self.sync_state.status() {
					if download_timeout {
						error!("state_sync: TxHashsetDownload status timeout in 10 minutes!");
						self.sync_state
							.set_sync_error(chain::Error::SyncError(format!(
								"{:?}",
								p2p::Error::Timeout
							)));
					}
				}

				if go {
					self.state_sync_peer = None;
					match self.request_state(&header_head) {
						Ok(peer) => {
							self.state_sync_peer = Some(peer);
						}
						Err(e) => self
							.sync_state
							.set_sync_error(chain::Error::SyncError(format!("{:?}", e))),
					}

					self.sync_state
						.update(SyncStatus::TxHashsetDownload(Default::default()));
				}
			}
		}
		true
	}

	fn get_pibd_qualify_peers(&self, archive_header: &BlockHeader) -> Vec<Arc<Peer>> {
		// First, get max difficulty or greater peers
		self.peers
			.iter()
			.connected()
			.into_iter()
			.filter(|peer| {
				peer.info.height() > archive_header.height
					&& peer.info.capabilities.contains(Capabilities::PIBD_HIST)
			})
			.collect()
	}

	fn get_pibd_ready_peers(&self) -> Vec<Arc<Peer>> {
		if let Some(output_bitmap_root_header_hash) = self.output_bitmap_root_header_hash.as_ref() {
			// First, get max difficulty or greater peers
			self.peers
				.iter()
				.connected()
				.into_iter()
				.filter(|peer| {
					let pibd_status = peer.pibd_status.lock();
					match &pibd_status.output_bitmap_root {
						Some(output_bitmap_root) => {
							let peer_output_bitmap_root_header_hash =
								(output_bitmap_root, pibd_status.header_hash).hash();
							output_bitmap_root_header_hash == &peer_output_bitmap_root_header_hash
								&& pibd_status.no_response_requests
									<= pibd_params::STALE_REQUESTS_PER_PEER
						}
						None => false,
					}
				})
				.collect()
		} else {
			vec![]
		}
	}

	fn ban_inactive_pibd_peers(&self) {
		let none_active_time_limit =
			Utc::now().timestamp() - pibd_params::SEGMENT_REQUEST_TIMEOUT_SECS;
		let mut banned_peers: Vec<Arc<Peer>> = Vec::new();
		for peer in self.peers.iter().connected().into_iter() {
			if let Some((requests, time)) = peer.get_pibd_no_response_state() {
				// we can ban this peer if during long time we didn't hear back any correct responses
				if time < none_active_time_limit && requests > pibd_params::STALE_REQUESTS_PER_PEER
				{
					banned_peers.push(peer.clone());
				}
			}
		}
		for peer in banned_peers {
			if let Err(err) = self
				.peers
				.ban_peer(peer.info.addr.clone(), ReasonForBan::PibdInactive)
			{
				error!("Unable to ban the peer {}, error {}", &peer.info.addr, err);
			}
		}
	}

	fn make_pibd_hand_shake(&self, archive_header: &BlockHeader) {
		let peers = self.get_pibd_qualify_peers(archive_header);

		// Minimal interval to send request for starting the PIBD sync process

		let last_handshake_time =
			Utc::now().timestamp() - pibd_params::SEGMENT_REQUEST_TIMEOUT_SECS;

		for peer in peers {
			let mut need_sync = false;
			{
				// we don't want keep lock for a long time, that is why using need_sync to make api call later
				let mut pibd_status = peer.pibd_status.lock();
				if (pibd_status.header_height < archive_header.height
					|| pibd_status.output_bitmap_root.is_none())
					&& pibd_status.initiate_pibd_request_time < last_handshake_time
				{
					pibd_status.initiate_pibd_request_time = last_handshake_time;
					need_sync = true;
				}
			}

			if need_sync {
				if let Err(e) =
					peer.send_start_pibd_sync_request(archive_header.height, archive_header.hash())
				{
					warn!(
						"Error sending start_pibd_sync_request to peer at {}, reason: {:?}",
						peer.info.addr, e
					);
				} else {
					info!(
						"Sending handshake start_pibd_sync_request to peer at {}",
						peer.info.addr
					);
				}
			}
		}
	}

	// Select a random peer and take it hash.
	// Alternative approach is select the largest group, but I think it is less attack resistant.
	// Download process takes time, so even if we ban all group after, still majority will be able to control
	// the sync process. Using random will give a chances to even single 'good' peer.
	fn select_pibd_bitmap_output_root(&self, archive_header: &BlockHeader) -> Option<Hash> {
		let header_hash = archive_header.hash();

		let handshake_time_limit =
			Utc::now().timestamp() - pibd_params::SEGMENT_REQUEST_TIMEOUT_SECS / 2;

		let mut min_handshake_time = handshake_time_limit + 1;

		let mut rng = rand::thread_rng();

		let output_bitmap_roots: Vec<Hash> = self
			.peers
			.iter()
			.into_iter()
			.filter_map(|peer| {
				let pibd_status = peer.pibd_status.lock();
				if pibd_status.header_height == archive_header.height
					&& pibd_status.header_hash == header_hash
					&& pibd_status.output_bitmap_root.is_some()
				{
					min_handshake_time =
						std::cmp::min(min_handshake_time, pibd_status.initiate_pibd_request_time);
					Some(pibd_status.output_bitmap_root.unwrap())
				} else {
					None
				}
			})
			.collect();

		if output_bitmap_roots.is_empty()
			|| (min_handshake_time >= handshake_time_limit && output_bitmap_roots.len() < 3)
		{
			return None;
		}

		info!(
			"selecting pibd bitmap_output_root from {:?}",
			output_bitmap_roots
		);
		return Some(output_bitmap_roots[rng.gen_range(0, output_bitmap_roots.len())]);
	}

	/// Continue the PIBD process, returning true if the desegmenter is reporting
	/// that the process is done
	fn continue_pibd(&mut self, archive_header: &BlockHeader) -> Result<bool, mwc_chain::Error> {
		// Check the state of our chain to figure out what we should be requesting next
		let desegmenter = self.chain.get_desegmenter(&archive_header);

		// Remove stale requests, if we haven't recieved the segment within a minute re-request
		// TODO: verify timing
		self.sync_state
			.remove_stale_pibd_requests(pibd_params::SEGMENT_REQUEST_TIMEOUT_SECS);

		// Apply segments... TODO: figure out how this should be called, might
		// need to be a separate thread.
		if let Some(mut de) = desegmenter.try_write() {
			if let Some(d) = de.as_mut() {
				let res = d.apply_next_segments();
				if let Err(e) = res {
					error!("error applying segment: {}", e);
					self.sync_state
						.update_pibd_progress(false, true, 0, 1, &archive_header);
					return Ok(false);
				}
			}
		}

		let pibd_peers = self.get_pibd_ready_peers();

		// Choose a random "most work" peer, preferring outbound if at all possible.
		let mut outbound_peers: Vec<Arc<Peer>> = Vec::new();
		let mut inbound_peers: Vec<Arc<Peer>> = Vec::new();
		let mut rng = rand::thread_rng();

		for p in pibd_peers {
			if p.info.is_outbound() {
				outbound_peers.push(p);
			} else if p.info.is_inbound() {
				inbound_peers.push(p);
			}
		}

		let peer_num = if outbound_peers.len() > 0 {
			outbound_peers.len()
		} else {
			inbound_peers.len()
		};

		let desired_segments_num = std::cmp::min(
			pibd_params::SEGMENT_REQUEST_LIMIT,
			pibd_params::SEGMENT_REQUEST_PER_PEER * peer_num,
		);

		let mut next_segment_ids = vec![];
		if let Some(d) = desegmenter.write().as_mut() {
			if let Ok(true) = d.check_progress(self.sync_state.clone()) {
				return Ok(true);
			}
			// Figure out the next segments we need
			// (12 is divisible by 3, to try and evenly spread the requests among the 3
			// main pmmrs. Bitmaps segments will always be requested first)
			next_segment_ids = d.next_desired_segments(std::cmp::max(1, desired_segments_num))?;
		}

		// For each segment, pick a desirable peer and send message
		// (Provided we're not waiting for a response for this message from someone else)
		for seg_id in next_segment_ids.iter() {
			if self.sync_state.contains_pibd_segment(seg_id) {
				trace!("Request list contains, continuing: {:?}", seg_id);
				continue;
			}

			let peer = outbound_peers
				.choose(&mut rng)
				.or_else(|| inbound_peers.choose(&mut rng));
			debug!(
				"Has {} PIBD ready peers, Chosen peer is {:?}",
				peer_num, peer
			);

			match peer {
				None => {
					// If there are no suitable PIBD-Enabled peers, AND there hasn't been one for a minute,
					// abort PIBD and fall back to txhashset download
					// Waiting a minute helps ensures that the cancellation isn't simply due to a single non-PIBD enabled
					// peer having the max difficulty
					if let None = self.earliest_zero_pibd_peer_time {
						self.set_earliest_zero_pibd_peer_time(Some(Utc::now()));
					}
					if self.earliest_zero_pibd_peer_time.unwrap()
						+ Duration::seconds(pibd_params::TXHASHSET_ZIP_FALLBACK_TIME_SECS)
						< Utc::now()
					{
						// random abort test
						info!("No PIBD-enabled max-difficulty peers for the past {} seconds - Aborting PIBD and falling back to TxHashset.zip download", pibd_params::TXHASHSET_ZIP_FALLBACK_TIME_SECS);
						self.sync_state
							.update_pibd_progress(true, true, 0, 1, &archive_header);
						self.sync_state
							.set_sync_error(chain::Error::AbortingPIBDError);
						self.set_pibd_aborted();
						return Ok(false);
					}
				}
				Some(p) => {
					self.set_earliest_zero_pibd_peer_time(None);

					self.sync_state.add_pibd_segment(seg_id);
					let res = match seg_id.segment_type {
						SegmentType::Bitmap => p.send_bitmap_segment_request(
							archive_header.hash(),
							seg_id.identifier.clone(),
						),
						SegmentType::Output => p.send_output_segment_request(
							archive_header.hash(),
							seg_id.identifier.clone(),
						),
						SegmentType::RangeProof => p.send_rangeproof_segment_request(
							archive_header.hash(),
							seg_id.identifier.clone(),
						),
						SegmentType::Kernel => p.send_kernel_segment_request(
							archive_header.hash(),
							seg_id.identifier.clone(),
						),
					};
					if let Err(e) = res {
						info!(
							"Error sending request to peer at {}, reason: {:?}",
							p.info.addr, e
						);
						self.sync_state.remove_pibd_segment(seg_id);
					}
				}
			}
		}
		Ok(false)
	}

	fn request_state(&self, header_head: &chain::Tip) -> Result<Arc<Peer>, p2p::Error> {
		let threshold = global::state_sync_threshold() as u64;
		let archive_interval = global::txhashset_archive_interval();
		let mut txhashset_height = header_head.height.saturating_sub(threshold);
		txhashset_height = txhashset_height.saturating_sub(txhashset_height % archive_interval);

		let peers_iter = || {
			self.peers
				.iter()
				.with_capabilities(Capabilities::TXHASHSET_HIST)
				.connected()
		};

		// Filter peers further based on max difficulty.
		let max_diff = peers_iter().max_difficulty().unwrap_or(Difficulty::zero());
		let peers_iter = || peers_iter().with_difficulty(|x| x >= max_diff);

		// Choose a random "most work" peer, preferring outbound if at all possible.
		let peer = peers_iter().outbound().choose_random().or_else(|| {
			warn!("no suitable outbound peer for state sync, considering inbound");
			peers_iter().inbound().choose_random()
		});

		if let Some(peer) = peer {
			// ask for txhashset at state_sync_threshold
			let mut txhashset_head = self
				.chain
				.get_block_header(&header_head.prev_block_h)
				.map_err(|e| {
					let err_msg = format!(
						"chain error during getting a block header {}, {}",
						header_head.prev_block_h, e
					);
					error!("{}", err_msg);
					p2p::Error::Internal(err_msg)
				})?;
			while txhashset_head.height > txhashset_height {
				txhashset_head = self
					.chain
					.get_previous_header(&txhashset_head)
					.map_err(|e| {
						let err_msg = format!(
							"chain error during getting a previous block header {}, {}",
							txhashset_head.hash(),
							e
						);
						error!("{}", err_msg);
						p2p::Error::Internal(err_msg)
					})?;
			}
			let bhash = txhashset_head.hash();
			debug!(
				"state_sync: before txhashset request, header head: {} / {}, txhashset_head: {} / {}",
				header_head.height,
				header_head.last_block_h,
				txhashset_head.height,
				bhash
			);
			if let Err(e) = peer.send_txhashset_request(txhashset_head.height, bhash) {
				error!("state_sync: send_txhashset_request err! {:?}", e);
				return Err(e);
			}
			return Ok(peer);
		}
		Err(p2p::Error::PeerException(
			"peer, most_work_peer is not found".to_string(),
		))
	}

	// For now this is a one-time thing (it can be slow) at initial startup.
	fn state_sync_due(&mut self) -> (bool, bool) {
		let now = Utc::now();
		let mut download_timeout = false;

		if let SyncStatus::TxHashsetDownload(status) = self.sync_state.status() {
			if self.last_download_size < status.downloaded_size {
				self.prev_state_sync = Some(now); // reset the timer
				self.last_download_size = status.downloaded_size;

				let pass_time = now.timestamp() - self.last_logged_time;
				if pass_time > 5 {
					info!(
						"Downloading {} MB chain state, done {} MB",
						status.total_size / 1_048_576,
						status.downloaded_size / 1_048_576
					);

					self.last_logged_time += pass_time;
				}
			}
		}

		match self.prev_state_sync {
			None => {
				self.prev_state_sync = Some(now);
				(true, download_timeout)
			}
			Some(prev) => {
				if now - prev > Duration::minutes(10) {
					download_timeout = true;
				}
				(false, download_timeout)
			}
		}
	}

	fn state_sync_reset(&mut self) {
		self.prev_state_sync = None;
		self.state_sync_peer = None;
		self.last_logged_time = 0;
		self.last_download_size = 0;
	}
}
