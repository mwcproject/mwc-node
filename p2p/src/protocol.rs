// Copyright 2021 The Grin Developers
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

use crate::conn::MessageHandler;
use crate::grin_core::core::{hash::Hashed, CompactBlock};
use crate::{chain, Capabilities};

use crate::msg::{
	ArchiveHeaderData, Consumed, Headers, Message, Msg, OutputBitmapSegmentResponse,
	OutputSegmentResponse, PeerAddrs, PibdSyncState, Pong, SegmentRequest, SegmentResponse,
	TxHashSetArchive, Type,
};
use crate::peer::PeerPibdStatus;
use crate::serv::Server;
use crate::types::{AttachmentMeta, Error, NetAdapter, PeerAddr, PeerAddr::Onion, PeerInfo};
use chrono::prelude::Utc;
use grin_core::core::hash::Hash;
use grin_util::Mutex;
use rand::{thread_rng, Rng};
use std::fs::{self, File};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct Protocol {
	adapter: Arc<dyn NetAdapter>,
	peer_info: PeerInfo,
	state_sync_requested: Arc<AtomicBool>,
	server: Server,
	pibd_status: Arc<Mutex<PeerPibdStatus>>,
}

impl Protocol {
	pub fn new(
		adapter: Arc<dyn NetAdapter>,
		peer_info: PeerInfo,
		state_sync_requested: Arc<AtomicBool>,
		server: Server,
		pibd_status: Arc<Mutex<PeerPibdStatus>>,
	) -> Protocol {
		Protocol {
			adapter,
			peer_info,
			state_sync_requested,
			server,
			pibd_status,
		}
	}

	fn report_pibd_response(&self, success: bool) {
		if success {
			let mut pibd_status = self.pibd_status.lock();
			pibd_status.no_response_requests = 0;
			pibd_status.no_response_time = None;
		}
	}

	fn get_peer_output_bitmap_root(&self) -> Option<Hash> {
		let pibd_status = self.pibd_status.lock();
		pibd_status.output_bitmap_root.clone()
	}
}

impl MessageHandler for Protocol {
	fn consume(&self, message: Message) -> Result<Consumed, Error> {
		let adapter = &self.adapter;

		// If we received a msg from a banned peer then log and drop it.
		// If we are getting a lot of these then maybe we are not cleaning
		// banned peers up correctly?
		if adapter.is_banned(self.peer_info.addr.clone()) {
			debug!(
				"handler: consume: peer {:?} banned, received: {}, dropping.",
				self.peer_info.addr, message,
			);
			return Ok(Consumed::Disconnect);
		}

		let consumed = match message {
			Message::Attachment(update, _) => {
				self.adapter.txhashset_download_update(
					update.meta.start_time,
					(update.meta.size - update.left) as u64,
					update.meta.size as u64,
				);

				if update.left == 0 {
					let meta = update.meta;
					trace!(
						"handle_payload: txhashset archive save to file {:?} success",
						meta.path,
					);

					let zip = File::open(meta.path.clone())?;
					let res =
						self.adapter
							.txhashset_write(meta.hash.clone(), zip, &self.peer_info)?;

					debug!(
						"handle_payload: txhashset archive for {} at {}, DONE. Data Ok: {}",
						meta.hash, meta.height, !res
					);

					if let Err(e) = fs::remove_file(meta.path.clone()) {
						warn!("fail to remove tmp file: {:?}. err: {}", meta.path, e);
					}
				}

				Consumed::None
			}

			Message::Ping(ping) => {
				adapter.peer_difficulty(
					self.peer_info.addr.clone(),
					ping.total_difficulty,
					ping.height,
				);
				Consumed::Response(Msg::new(
					Type::Pong,
					Pong {
						total_difficulty: adapter.total_difficulty()?,
						height: adapter.total_height()?,
					},
					self.peer_info.version,
				)?)
			}

			Message::Pong(pong) => {
				adapter.peer_difficulty(
					self.peer_info.addr.clone(),
					pong.total_difficulty,
					pong.height,
				);
				Consumed::None
			}

			Message::BanReason(ban_reason) => {
				error!("handle_payload: BanReason {:?}", ban_reason);
				Consumed::Disconnect
			}

			Message::TransactionKernel(h) => {
				debug!("handle_payload: received tx kernel: {}", h);
				adapter.tx_kernel_received(h, &self.peer_info)?;
				Consumed::None
			}

			Message::GetTransaction(h) => {
				debug!("handle_payload: GetTransaction: {}", h);
				let tx = adapter.get_transaction(h);
				if let Some(tx) = tx {
					Consumed::Response(Msg::new(Type::Transaction, tx, self.peer_info.version)?)
				} else {
					Consumed::None
				}
			}

			Message::Transaction(tx) => {
				debug!("handle_payload: received tx");
				adapter.transaction_received(tx, false)?;
				Consumed::None
			}

			Message::StemTransaction(tx) => {
				debug!("handle_payload: received stem tx");
				adapter.transaction_received(tx, true)?;
				Consumed::None
			}

			Message::GetBlock(h) => {
				trace!("handle_payload: GetBlock: {}", h);
				let bo = adapter.get_block(h, &self.peer_info);
				if let Some(b) = bo {
					Consumed::Response(Msg::new(Type::Block, b, self.peer_info.version)?)
				} else {
					Consumed::None
				}
			}

			Message::Block(b) => {
				debug!("handle_payload: received block");
				// We default to NONE opts here as we do not know know yet why this block was
				// received.
				// If we requested this block from a peer due to our node syncing then
				// the peer adapter will override opts to reflect this.
				adapter.block_received(b.into(), &self.peer_info, chain::Options::NONE)?;
				Consumed::None
			}

			Message::GetCompactBlock(h) => {
				if let Some(b) = adapter.get_block(h, &self.peer_info) {
					let cb: CompactBlock = b.into();
					Consumed::Response(Msg::new(Type::CompactBlock, cb, self.peer_info.version)?)
				} else {
					Consumed::None
				}
			}

			Message::CompactBlock(b) => {
				debug!("handle_payload: received compact block");
				adapter.compact_block_received(b.into(), &self.peer_info)?;
				Consumed::None
			}
			Message::TorAddress(tor_address) => {
				info!(
					"TorAddress received from {:?}, address = {:?}",
					self.peer_info, tor_address
				);

				let new_peer_addr = PeerAddr::Onion(tor_address.address.clone());
				error!("new peer = {:?}", new_peer_addr);
				if self.server.peers.is_banned(new_peer_addr.clone()) {
					let peer = self.server.peers.get_peer(self.peer_info.addr.clone())?;
					warn!("banned peer tried to connect! {:?}", peer);
				} else {
					let peer = self.server.peers.get_peer(self.peer_info.addr.clone());
					if peer.is_ok() {
						let mut peer = peer.unwrap();
						peer.addr = new_peer_addr;
						self.server.peers.save_peer(&peer)?;
					}
				}
				Consumed::None
			}

			Message::GetHeaders(loc) => {
				// load headers from the locator
				let headers = adapter.locate_headers(&loc.hashes)?;

				// serialize and send all the headers over
				Consumed::Response(Msg::new(
					Type::Headers,
					Headers { headers },
					self.peer_info.version,
				)?)
			}

			// "header first" block propagation - if we have not yet seen this block
			// we can go request it from some of our peers
			Message::Header(header) => {
				adapter.header_received(header.into(), &self.peer_info)?;
				Consumed::None
			}

			Message::Headers(data) => {
				adapter.headers_received(&data.headers, &self.peer_info)?;
				Consumed::None
			}

			Message::GetPeerAddrs(get_peers) => {
				let peers =
					adapter.find_peer_addrs(get_peers.capabilities & !Capabilities::TOR_ADDRESS);

				// if this peer does not support TOR, do not send them the tor peers.
				// doing so will cause them to ban us because it's not part of the old protocol.
				let peers = if !get_peers.capabilities.contains(Capabilities::TOR_ADDRESS) {
					let mut peers_filtered = vec![];
					for peer in peers {
						match peer.clone() {
							PeerAddr::Onion(_) => {}
							_ => {
								peers_filtered.push(peer);
							}
						}
					}
					peers_filtered
				} else {
					peers
				};

				Consumed::Response(Msg::new(
					Type::PeerAddrs,
					PeerAddrs { peers },
					self.peer_info.version,
				)?)
			}

			Message::PeerAddrs(peer_addrs) => {
				let mut peers: Vec<PeerAddr> = Vec::new();
				for peer in peer_addrs.peers {
					match peer.clone() {
						Onion(address) => {
							let self_address = self.server.self_onion_address.as_ref();
							if self_address.is_none() {
								peers.push(peer);
							} else {
								if &address != self_address.unwrap() {
									peers.push(peer);
								} else {
									debug!("Not pushing self onion address = {}", address);
								}
							}
						}
						_ => {
							peers.push(peer);
						}
					}
				}
				adapter.peer_addrs_received(peers);
				Consumed::None
			}

			Message::TxHashSetRequest(sm_req) => {
				debug!(
					"handle_payload: txhashset req for {} at {}",
					sm_req.hash, sm_req.height
				);

				let txhashset_header = self.adapter.txhashset_archive_header()?;
				let txhashset_header_hash = txhashset_header.hash();
				let txhashset = self.adapter.txhashset_read(txhashset_header_hash);

				if let Some(txhashset) = txhashset {
					let file_sz = txhashset.reader.metadata()?.len();
					let mut resp = Msg::new(
						Type::TxHashSetArchive,
						&TxHashSetArchive {
							height: txhashset_header.height as u64,
							hash: txhashset_header_hash,
							bytes: file_sz,
						},
						self.peer_info.version,
					)?;
					resp.add_attachment(txhashset.reader);
					Consumed::Response(resp)
				} else {
					Consumed::None
				}
			}

			Message::TxHashSetArchive(sm_arch) => {
				info!(
					"handle_payload: txhashset archive for {} at {}. size={}",
					sm_arch.hash, sm_arch.height, sm_arch.bytes,
				);
				if !self.adapter.txhashset_receive_ready() {
					error!(
						"handle_payload: txhashset archive received but SyncStatus not on TxHashsetDownload",
					);
					return Err(Error::BadMessage);
				}
				if !self.state_sync_requested.load(Ordering::Relaxed) {
					error!("handle_payload: txhashset archive received but from the wrong peer",);
					return Err(Error::BadMessage);
				}
				// Update the sync state requested status
				self.state_sync_requested.store(false, Ordering::Relaxed);

				let start_time = Utc::now();
				self.adapter
					.txhashset_download_update(start_time, 0, sm_arch.bytes);

				let nonce: u32 = thread_rng().gen_range(0, 1_000_000);
				let path = self.adapter.get_tmpfile_pathname(format!(
					"txhashset-{}-{}.zip",
					start_time.timestamp(),
					nonce
				));

				let file = fs::OpenOptions::new()
					.write(true)
					.create_new(true)
					.open(path.clone())?;

				let meta = AttachmentMeta {
					size: sm_arch.bytes as usize,
					hash: sm_arch.hash,
					height: sm_arch.height,
					start_time,
					path,
				};

				Consumed::Attachment(Arc::new(meta), file)
			}
			Message::StartPibdSyncRequest(sm_req) => {
				debug!(
					"handle_payload: start PIBD request for {} at {}",
					sm_req.hash, sm_req.height
				);
				match self.adapter.prepare_segmenter() {
					Ok(segmenter) => {
						let header = segmenter.header();
						let header_hash = header.hash();
						if header_hash == sm_req.hash && header.height == sm_req.height {
							if let Ok(bitmap_root_hash) = segmenter.bitmap_root() {
								// we can start the sync process, let's prepare the segmenter
								Consumed::Response(Msg::new(
									Type::PibdSyncState,
									&PibdSyncState {
										header_height: header.height,
										header_hash: header_hash,
										output_bitmap_root: bitmap_root_hash,
									},
									self.peer_info.version,
								)?)
							} else {
								Consumed::None
							}
						} else {
							Consumed::Response(Msg::new(
								Type::HasAnotherArchiveHeader,
								&ArchiveHeaderData {
									height: header.height,
									hash: header_hash,
								},
								self.peer_info.version,
							)?)
						}
					}
					Err(e) => {
						warn!(
							"Unable to prepare segment for PIBD request for {} at {}. Error: {}",
							sm_req.hash, sm_req.height, e
						);
						Consumed::None
					}
				}
			}
			Message::GetOutputBitmapSegment(req) => {
				let SegmentRequest {
					block_hash,
					identifier,
				} = req;

				match self.adapter.get_bitmap_segment(block_hash, identifier) {
					Ok(segment) => Consumed::Response(Msg::new(
						Type::OutputBitmapSegment,
						OutputBitmapSegmentResponse {
							block_hash,
							segment: segment.into(),
						},
						self.peer_info.version,
					)?),
					Err(chain::Error::SegmenterHeaderMismatch(hash, height)) => {
						Consumed::Response(Msg::new(
							Type::HasAnotherArchiveHeader,
							&ArchiveHeaderData {
								height: height,
								hash: hash,
							},
							self.peer_info.version,
						)?)
					}
					Err(e) => {
						warn!("Failed to process GetOutputBitmapSegment for block_hash={} and identifier={:?}. Error: {}", block_hash, identifier, e);
						Consumed::None
					}
				}
			}
			Message::GetOutputSegment(req) => {
				let SegmentRequest {
					block_hash,
					identifier,
				} = req;

				match self.adapter.get_output_segment(block_hash, identifier) {
					Ok(segment) => Consumed::Response(Msg::new(
						Type::OutputSegment,
						OutputSegmentResponse {
							response: SegmentResponse {
								block_hash,
								segment,
							},
						},
						self.peer_info.version,
					)?),
					Err(chain::Error::SegmenterHeaderMismatch(hash, height)) => {
						Consumed::Response(Msg::new(
							Type::HasAnotherArchiveHeader,
							&ArchiveHeaderData {
								height: height,
								hash: hash,
							},
							self.peer_info.version,
						)?)
					}
					Err(e) => {
						warn!("Failed to process GetOutputSegment for block_hash={} and identifier={:?}. Error: {}", block_hash, identifier, e);
						Consumed::None
					}
				}
			}
			Message::GetRangeProofSegment(req) => {
				let SegmentRequest {
					block_hash,
					identifier,
				} = req;
				match self.adapter.get_rangeproof_segment(block_hash, identifier) {
					Ok(segment) => Consumed::Response(Msg::new(
						Type::RangeProofSegment,
						SegmentResponse {
							block_hash,
							segment,
						},
						self.peer_info.version,
					)?),
					Err(chain::Error::SegmenterHeaderMismatch(hash, height)) => {
						Consumed::Response(Msg::new(
							Type::HasAnotherArchiveHeader,
							&ArchiveHeaderData {
								height: height,
								hash: hash,
							},
							self.peer_info.version,
						)?)
					}
					Err(e) => {
						warn!("Failed to process GetRangeProofSegment for block_hash={} and identifier={:?}. Error: {}", block_hash, identifier, e);
						Consumed::None
					}
				}
			}
			Message::GetKernelSegment(req) => {
				let SegmentRequest {
					block_hash,
					identifier,
				} = req;

				match self.adapter.get_kernel_segment(block_hash, identifier) {
					Ok(segment) => Consumed::Response(Msg::new(
						Type::KernelSegment,
						SegmentResponse {
							block_hash,
							segment,
						},
						self.peer_info.version,
					)?),
					Err(chain::Error::SegmenterHeaderMismatch(hash, height)) => {
						Consumed::Response(Msg::new(
							Type::HasAnotherArchiveHeader,
							&ArchiveHeaderData {
								height: height,
								hash: hash,
							},
							self.peer_info.version,
						)?)
					}
					Err(e) => {
						warn!("Failed to process GetKernelSegment for block_hash={} and identifier={:?}. Error: {}", block_hash, identifier, e);
						Consumed::None
					}
				}
			}
			Message::PibdSyncState(req) => {
				self.report_pibd_response(true);
				debug!("Received PibdSyncState from peer {:?}. Header height={}, output_bitmap_root={}", self.peer_info.addr, req.header_height, req.output_bitmap_root);
				{
					let mut status = self.pibd_status.lock();
					status.update_pibd_status(
						req.header_hash,
						req.header_height,
						Some(req.output_bitmap_root),
					);
				}
				Consumed::None
			}
			Message::HasAnotherArchiveHeader(req) => {
				debug!(
					"Received HasAnotherArchiveHeader from peer {:?}. Has header at height {}",
					self.peer_info.addr, req.height
				);
				let mut status = self.pibd_status.lock();
				status.update_pibd_status(req.hash, req.height, None);
				Consumed::None
			}
			Message::OutputBitmapSegment(req) => {
				let OutputBitmapSegmentResponse {
					block_hash,
					segment,
				} = req;
				debug!("Received Output Bitmap Segment: bh: {}", block_hash);

				if let Some(output_bitmap_root) = self.get_peer_output_bitmap_root() {
					adapter
						.receive_bitmap_segment(block_hash, output_bitmap_root, segment.into())
						.and_then(|ok| {
							self.report_pibd_response(ok);
							Ok(ok)
						})?;
				}
				Consumed::None
			}
			Message::OutputSegment(req) => {
				let OutputSegmentResponse { response } = req;
				debug!("Received Output Segment: bh, {}", response.block_hash,);
				if let Some(output_bitmap_root) = self.get_peer_output_bitmap_root() {
					adapter
						.receive_output_segment(
							response.block_hash,
							output_bitmap_root,
							response.segment.into(),
						)
						.and_then(|ok| {
							self.report_pibd_response(ok);
							Ok(ok)
						})?;
				}
				Consumed::None
			}
			Message::RangeProofSegment(req) => {
				let SegmentResponse {
					block_hash,
					segment,
				} = req;
				debug!("Received Rangeproof Segment: bh: {}", block_hash);
				if let Some(output_bitmap_root) = self.get_peer_output_bitmap_root() {
					adapter
						.receive_rangeproof_segment(block_hash, output_bitmap_root, segment.into())
						.and_then(|ok| {
							self.report_pibd_response(ok);
							Ok(ok)
						})?;
				}
				Consumed::None
			}
			Message::KernelSegment(req) => {
				let SegmentResponse {
					block_hash,
					segment,
				} = req;
				debug!("Received Kernel Segment: bh: {}", block_hash);
				if let Some(output_bitmap_root) = self.get_peer_output_bitmap_root() {
					adapter
						.receive_kernel_segment(block_hash, output_bitmap_root, segment.into())
						.and_then(|ok| {
							self.report_pibd_response(ok);
							Ok(ok)
						})?;
				}
				Consumed::None
			}
			Message::Unknown(_) => Consumed::None,
		};
		Ok(consumed)
	}
}
