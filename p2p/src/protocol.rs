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

use crate::conn::MessageHandler;
use crate::mwc_core::core::{hash::Hashed, CompactBlock};
use crate::{chain, Capabilities, ReasonForBan};

use crate::msg::{
	ArchiveHeaderData, Consumed, Headers, HeadersHashSegmentResponse, Message, Msg,
	OutputBitmapSegmentResponse, OutputSegmentResponse, PeerAddrs, PibdSyncState, Pong,
	SegmentRequest, SegmentResponse, StartHeadersHashResponse, TxHashSetArchive, Type,
};
use crate::serv::Server;
use crate::types::{Error, NetAdapter, PeerAddr, PeerAddr::Onion, PeerInfo};
use std::sync::Arc;

pub struct Protocol {
	adapter: Arc<dyn NetAdapter>,
	peer_info: PeerInfo,
	server: Server,
}

impl Protocol {
	pub fn new(adapter: Arc<dyn NetAdapter>, peer_info: PeerInfo, server: Server) -> Protocol {
		Protocol {
			adapter,
			peer_info,
			server,
		}
	}
}

impl MessageHandler for Protocol {
	fn consume(&self, message: Message) -> Result<Consumed, Error> {
		let adapter = &self.adapter;

		// If we received a msg from a banned peer then log and drop it.
		// If we are getting a lot of these then maybe we are not cleaning
		// banned peers up correctly?
		if adapter.is_banned(&self.peer_info.addr) {
			debug!(
				"handler: consume: peer {:?} banned, received: {}, dropping.",
				self.peer_info.addr, message,
			);
			return Ok(Consumed::Disconnect);
		}

		let consumed = match message {
			Message::Attachment(_update, _) => {
				error!("handle_payload: Message::Attachment received but we never requested it. It is disabled in this version of node");
				adapter.ban_peer(
					&self.peer_info.addr,
					ReasonForBan::BadRequest,
					"Message::Attachment received but we never requested it",
				);
				return Err(Error::BadMessage);
			}

			Message::Ping(ping) => {
				adapter.peer_difficulty(&self.peer_info.addr, ping.total_difficulty, ping.height);
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
				adapter.peer_difficulty(&self.peer_info.addr, pong.total_difficulty, pong.height);
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
				if self.server.peers.is_banned(&new_peer_addr) {
					let peer = self.server.peers.get_peer(&self.peer_info.addr)?;
					warn!("banned peer tried to connect! {:?}", peer);
				} else {
					let peer = self.server.peers.get_peer(&self.peer_info.addr);
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
				adapter.headers_received(&data.headers, data.remaining, &self.peer_info)?;
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

			Message::TxHashSetArchive(_sm_arch) => {
				error!("handle_payload: txhashset archive received but we never requested it. It is disabled in this version of node");
				adapter.ban_peer(
					&self.peer_info.addr,
					ReasonForBan::BadRequest,
					"txhashset archive received but we never requested it",
				);
				return Err(Error::BadMessage);
			}
			Message::StartHeadersHashRequest(sm_req) => {
				debug!(
					"handle_payload: start Headers Hash request for archive hegiht {}",
					sm_req.archive_height
				);
				match self.adapter.prepare_segmenter() {
					Ok(segmenter) => {
						let header = segmenter.header();
						if header.height == sm_req.archive_height {
							Consumed::Response(Msg::new(
								Type::StartHeadersHashResponse,
								&StartHeadersHashResponse {
									archive_height: header.height,
									headers_root_hash: segmenter.headers_root()?,
								},
								self.peer_info.version,
							)?)
						} else {
							Consumed::Response(Msg::new(
								Type::HasAnotherArchiveHeader,
								&ArchiveHeaderData {
									height: header.height,
									hash: header.hash(),
								},
								self.peer_info.version,
							)?)
						}
					}
					Err(e) => {
						warn!(
							"Unable to prepare segmented Headers Hash request {}. Error: {}",
							sm_req.archive_height, e
						);
						Consumed::None
					}
				}
			}
			Message::StartHeadersHashResponse(sm_req) => {
				let StartHeadersHashResponse {
					archive_height,
					headers_root_hash,
				} = sm_req;
				debug!(
					"Received Headers Hash Response for {}, {}",
					archive_height, headers_root_hash
				);

				adapter.receive_headers_hash_response(
					&self.peer_info.addr,
					archive_height,
					headers_root_hash,
				)?;
				Consumed::None
			}
			Message::GetHeadersHashesSegment(req) => {
				let SegmentRequest {
					block_hash: header_hashes_root,
					identifier,
				} = req;

				match self
					.adapter
					.get_header_hashes_segment(header_hashes_root, identifier)
				{
					Ok(segment) => Consumed::Response(Msg::new(
						Type::OutputHeadersHashesSegment,
						HeadersHashSegmentResponse {
							headers_root_hash: header_hashes_root,
							response: SegmentResponse {
								block_hash: header_hashes_root,
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
						warn!("Failed to process GetHeadersHashesSegment for header_hashes_root={} and identifier={:?}. Error: {}", header_hashes_root, identifier, e);
						Consumed::None
					}
				}
			}
			Message::OutputHeadersHashesSegment(req) => {
				let HeadersHashSegmentResponse {
					headers_root_hash,
					response,
				} = req;
				debug!(
					"Received Headers Hash Segment: {}, {}",
					headers_root_hash,
					response.segment.id()
				);
				self.adapter.receive_header_hashes_segment(
					&self.peer_info.addr,
					headers_root_hash,
					response.segment.into(),
				)?;
				Consumed::None
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
				debug!("Received PibdSyncState from peer {:?}. Header height={}, output_bitmap_root={}", self.peer_info.addr, req.header_height, req.output_bitmap_root);
				self.adapter.recieve_pibd_status(
					&self.peer_info.addr,
					req.header_hash,
					req.header_height,
					req.output_bitmap_root,
				)?;
				Consumed::None
			}
			Message::HasAnotherArchiveHeader(req) => {
				debug!(
					"Received HasAnotherArchiveHeader from peer {:?}. Has header at height {}",
					self.peer_info.addr, req.height
				);
				self.adapter.recieve_another_archive_header(
					&self.peer_info.addr,
					req.hash,
					req.height,
				)?;
				Consumed::None
			}
			Message::OutputBitmapSegment(req) => {
				let OutputBitmapSegmentResponse {
					block_hash,
					segment,
				} = req;
				debug!(
					"Received Output Bitmap Segment: bh: {}, segment {}",
					block_hash, segment.identifier
				);

				adapter.receive_bitmap_segment(&self.peer_info.addr, block_hash, segment.into())?;
				Consumed::None
			}
			Message::OutputSegment(req) => {
				let OutputSegmentResponse { response } = req;
				debug!(
					"Received Output Segment: bh {}, {}",
					response.block_hash,
					response.segment.id()
				);
				adapter.receive_output_segment(
					&self.peer_info.addr,
					response.block_hash,
					response.segment,
				)?;
				Consumed::None
			}
			Message::RangeProofSegment(req) => {
				let SegmentResponse {
					block_hash,
					segment,
				} = req;
				debug!(
					"Received Rangeproof Segment: bh {}, {}",
					block_hash,
					segment.id()
				);
				adapter.receive_rangeproof_segment(&self.peer_info.addr, block_hash, segment)?;
				Consumed::None
			}
			Message::KernelSegment(req) => {
				let SegmentResponse {
					block_hash,
					segment,
				} = req;
				debug!(
					"Received Kernel Segment: bh {}, {}",
					block_hash,
					segment.id()
				);
				adapter.receive_kernel_segment(&self.peer_info.addr, block_hash, segment)?;
				Consumed::None
			}
			Message::Unknown(_) => Consumed::None,
		};
		Ok(consumed)
	}
}
