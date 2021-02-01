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

use crate::chain;
use crate::conn::{Message, MessageHandler, Tracker};
use crate::core::core::{self, hash::Hash, hash::Hashed, CompactBlock, HeaderVersion};
use crate::core::ser::ProtocolVersion;
use crate::serv::Server;
use crate::types::PeerAddr::Onion;

use crate::msg::{
	BanReason, GetPeerAddrs, Headers, Locator, Msg, PeerAddrs, Ping, Pong, TorAddress,
	TxHashSetArchive, TxHashSetRequest, Type,
};

use crate::types::Capabilities;
use crate::types::PeerAddr;
use crate::types::{Error, NetAdapter, PeerInfo};
use chrono::prelude::Utc;
use rand::{thread_rng, Rng};
use std::cmp;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub struct Protocol {
	adapter: Arc<dyn NetAdapter>,
	peer_info: PeerInfo,
	state_sync_requested: Arc<AtomicBool>,
	header_cache_size: u64,
	server: Server,
}

impl Protocol {
	pub fn new(
		adapter: Arc<dyn NetAdapter>,
		peer_info: PeerInfo,
		state_sync_requested: Arc<AtomicBool>,
		header_cache_size: u64,
		server: Server,
	) -> Protocol {
		Protocol {
			adapter,
			peer_info,
			state_sync_requested,
			header_cache_size,
			server,
		}
	}
}

impl MessageHandler for Protocol {
	fn consume<R: Read>(
		&mut self,
		mut msg: Message<R>,
		stopped: Arc<AtomicBool>,
		tracker: Arc<Tracker>,
	) -> Result<Option<Msg>, Error> {
		let adapter = &self.adapter;
		let header_cache_size = self.header_cache_size;

		// If we received a msg from a banned peer then log and drop it.
		// If we are getting a lot of these then maybe we are not cleaning
		// banned peers up correctly?
		if adapter.is_banned(self.peer_info.addr.clone()) {
			debug!(
				"handler: consume: peer {:?} banned, received: {:?}, dropping.",
				self.peer_info.addr, msg.header.msg_type,
			);
			return Ok(None);
		}

		match msg.header.msg_type {
			Type::Ping => {
				let ping: Ping = msg.body()?;
				adapter.peer_difficulty(
					self.peer_info.addr.clone(),
					ping.total_difficulty,
					ping.height,
				);

				Ok(Some(Msg::new(
					Type::Pong,
					Pong {
						total_difficulty: adapter.total_difficulty()?,
						height: adapter.total_height()?,
					},
					self.peer_info.version,
				)?))
			}

			Type::Pong => {
				let pong: Pong = msg.body()?;
				adapter.peer_difficulty(
					self.peer_info.addr.clone(),
					pong.total_difficulty,
					pong.height,
				);
				Ok(None)
			}

			Type::BanReason => {
				let ban_reason: BanReason = msg.body()?;
				error!("handle_payload: BanReason {:?}", ban_reason);
				Ok(None)
			}

			Type::TransactionKernel => {
				let h: Hash = msg.body()?;
				debug!(
					"handle_payload: received tx kernel: {}, msg_len: {}",
					h, msg.header.msg_len
				);
				adapter.tx_kernel_received(h, &self.peer_info)?;
				Ok(None)
			}

			Type::GetTransaction => {
				let h: Hash = msg.body()?;
				debug!(
					"handle_payload: GetTransaction: {}, msg_len: {}",
					h, msg.header.msg_len,
				);
				let tx = adapter.get_transaction(h);
				if let Some(tx) = tx {
					match self.peer_info.version.value() {
						// Versions before HF2
						0..=3 => {
							if let Ok(v1_tx) = tx.to_v1() {
								Ok(Some(Msg::new(
									Type::Transaction,
									v1_tx,
									self.peer_info.version,
								)?))
							} else {
								Ok(None)
							}
						}
						// HF2 version
						1000..=1999 => Ok(Some(Msg::new(
							Type::Transaction,
							tx,
							self.peer_info.version,
						)?)),
						// don't send to versions with big jump and undefined versions.
						_ => Ok(None),
					}
				} else {
					Ok(None)
				}
			}

			Type::Transaction => {
				debug!(
					"handle_payload: received tx: msg_len: {}",
					msg.header.msg_len
				);
				let tx: core::Transaction = msg.body()?;
				adapter.transaction_received(tx.into(), false)?;
				Ok(None)
			}

			Type::StemTransaction => {
				debug!(
					"handle_payload: received stem tx: msg_len: {}",
					msg.header.msg_len
				);
				let tx: core::Transaction = msg.body()?;
				adapter.transaction_received(tx.into(), true)?;
				Ok(None)
			}

			Type::GetBlock => {
				let h: Hash = msg.body()?;
				trace!(
					"handle_payload: GetBlock: {}, msg_len: {}",
					h,
					msg.header.msg_len,
				);

				let bo = adapter.get_block(h, &self.peer_info);
				if let Some(b) = bo {
					if is_compatible_node(b.header.version, self.peer_info.version) {
						Ok(Some(Msg::new(Type::Block, b, self.peer_info.version)?))
					} else {
						Ok(None)
					}
				} else {
					Ok(None)
				}
			}

			Type::Block => {
				debug!(
					"handle_payload: received block: msg_len: {}",
					msg.header.msg_len
				);
				let b: core::UntrustedBlock = msg.body()?;

				// We default to NONE opts here as we do not know know yet why this block was
				// received.
				// If we requested this block from a peer due to our node syncing then
				// the peer adapter will override opts to reflect this.
				adapter.block_received(b.into(), &self.peer_info, chain::Options::NONE)?;
				Ok(None)
			}

			Type::GetCompactBlock => {
				let h: Hash = msg.body()?;
				if let Some(b) = adapter.get_block(h, &self.peer_info) {
					if is_compatible_node(b.header.version, self.peer_info.version) {
						let cb: CompactBlock = b.into();
						Ok(Some(Msg::new(
							Type::CompactBlock,
							cb,
							self.peer_info.version,
						)?))
					} else {
						Ok(None)
					}
				} else {
					Ok(None)
				}
			}

			Type::CompactBlock => {
				debug!(
					"handle_payload: received compact block: msg_len: {}",
					msg.header.msg_len
				);
				let b: core::UntrustedCompactBlock = msg.body()?;

				adapter.compact_block_received(b.into(), &self.peer_info)?;
				Ok(None)
			}
			Type::TorAddress => {
				let tor_address: TorAddress = msg.body()?;
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
				Ok(None)
			}

			Type::GetHeaders => {
				// load headers from the locator
				let loc: Locator = msg.body()?;
				let headers = adapter.locate_headers(&loc.hashes)?;

				// serialize and send all the headers over
				if let Some(h) = headers.last() {
					if is_compatible_node(h.version, self.peer_info.version) {
						Ok(Some(Msg::new(
							Type::Headers,
							Headers { headers },
							self.peer_info.version,
						)?))
					} else {
						Ok(None)
					}
				} else {
					Ok(None)
				}
			}

			// "header first" block propagation - if we have not yet seen this block
			// we can go request it from some of our peers
			Type::Header => {
				let header: core::UntrustedBlockHeader = msg.body()?;
				adapter.header_received(header.into(), &self.peer_info)?;
				Ok(None)
			}

			Type::Headers => {
				let mut total_bytes_read = 0;

				// Read the count (u16) so we now how many headers to read.
				let (count, bytes_read): (u16, _) = msg.streaming_read()?;
				total_bytes_read += bytes_read;

				// Read chunks of headers off the stream and pass them off to the adapter.
				let chunk_size = 32u16;
				let mut headers = Vec::with_capacity(chunk_size as usize);
				for i in 1..=count {
					let (header, bytes_read) =
						msg.streaming_read::<core::UntrustedBlockHeader>()?;
					headers.push(header.into());
					total_bytes_read += bytes_read;
					if i % chunk_size == 0 || i == count {
						adapter.headers_received(&headers, &self.peer_info, header_cache_size)?;
						headers.clear();
					}
				}

				// Now check we read the correct total number of bytes off the stream.
				if total_bytes_read != msg.header.msg_len {
					return Err(Error::MsgLen);
				}

				Ok(None)
			}

			Type::GetPeerAddrs => {
				let get_peers: GetPeerAddrs = msg.body()?;
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

				Ok(Some(Msg::new(
					Type::PeerAddrs,
					PeerAddrs { peers },
					self.peer_info.version,
				)?))
			}

			Type::PeerAddrs => {
				let peer_addrs: PeerAddrs = msg.body()?;
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
				Ok(None)
			}
			Type::TxHashSetRequest => {
				let sm_req: TxHashSetRequest = msg.body()?;
				debug!(
					"handle_payload: txhashset req for {} at {}",
					sm_req.hash, sm_req.height
				);

				let txhashset_header = self.adapter.txhashset_archive_header()?;
				if is_compatible_node(txhashset_header.version, self.peer_info.version) {
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
						Ok(Some(resp))
					} else {
						Ok(None)
					}
				} else {
					Ok(None)
				}
			}

			Type::TxHashSetArchive => {
				let sm_arch: TxHashSetArchive = msg.body()?;
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

				let download_start_time = Utc::now();
				self.adapter
					.txhashset_download_update(download_start_time, 0, sm_arch.bytes);

				let nonce: u32 = thread_rng().gen_range(0, 1_000_000);
				let tmp = self.adapter.get_tmpfile_pathname(format!(
					"txhashset-{}-{}.zip",
					download_start_time.timestamp(),
					nonce
				));
				let mut now = Instant::now();
				let mut save_txhashset_to_file = |file| -> Result<(), Error> {
					let mut tmp_zip =
						BufWriter::new(OpenOptions::new().write(true).create_new(true).open(file)?);
					let total_size = sm_arch.bytes as usize;
					let mut downloaded_size: usize = 0;
					let mut request_size = cmp::min(48_000, total_size);
					while request_size > 0 {
						let size = msg.copy_attachment(request_size, &mut tmp_zip)?;
						downloaded_size += size;
						request_size = cmp::min(48_000, total_size - downloaded_size);
						self.adapter.txhashset_download_update(
							download_start_time,
							downloaded_size as u64,
							total_size as u64,
						);
						if now.elapsed().as_secs() > 10 {
							now = Instant::now();
							debug!(
								"handle_payload: txhashset archive: {}/{}",
								downloaded_size, total_size
							);
						}
						// Increase received bytes quietly (without affecting the counters).
						// Otherwise we risk banning a peer as "abusive".
						tracker.inc_quiet_received(size as u64);

						// check the close channel
						if stopped.load(Ordering::Relaxed) {
							debug!("stopping txhashset download early");
							return Err(Error::ConnectionClose);
						}
					}
					debug!(
						"handle_payload: txhashset archive: {}/{} ... DONE",
						downloaded_size, total_size
					);
					tmp_zip
						.into_inner()
						.map_err(|e| {
							Error::Internal(format!("Unable to save txhashset data, {}", e))
						})?
						.sync_all()?;
					Ok(())
				};

				if let Err(e) = save_txhashset_to_file(tmp.clone()) {
					error!(
						"handle_payload: txhashset archive save to file fail. err={:?}",
						e
					);
					return Err(e);
				}

				trace!(
					"handle_payload: txhashset archive save to file {:?} success",
					tmp,
				);

				let tmp_zip = File::open(tmp.clone())?;
				let res = self
					.adapter
					.txhashset_write(sm_arch.hash, tmp_zip, &self.peer_info)?;

				info!(
					"handle_payload: txhashset archive for {} at {}, DONE. Data Ok: {}",
					sm_arch.hash, sm_arch.height, res
				);

				if let Err(e) = fs::remove_file(tmp.clone()) {
					warn!("fail to remove tmp file: {:?}. err: {}", tmp, e);
				}

				Ok(None)
			}
			Type::Error | Type::Hand | Type::Shake => {
				debug!("Received an unexpected msg: {:?}", msg.header.msg_type);
				Ok(None)
			}
		}
	}
}

// Util to check whether the peer protocol version is compatible with the block header version.
fn is_compatible_node(h_version: HeaderVersion, p_version: ProtocolVersion) -> bool {
	match h_version.value() {
		0..=2 => true,
		3..=HeaderVersion::MAX => {
			// avoid sending HF2 blocks to nodes with old versions.
			if p_version < ProtocolVersion(1000) {
				false
			} else {
				true
			}
		}
	}
}
