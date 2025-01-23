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

//! Message types that transit over the network and related serialization code.

use crate::chain::txhashset::BitmapSegment;
use crate::conn::Tracker;
use crate::mwc_core::core::hash::Hash;
use crate::mwc_core::core::transaction::{OutputIdentifier, TxKernel};
use crate::mwc_core::core::{
	BlockHeader, Segment, SegmentIdentifier, Transaction, UntrustedBlock, UntrustedBlockHeader,
	UntrustedCompactBlock,
};
use crate::mwc_core::pow::Difficulty;
use crate::mwc_core::ser::{
	self, DeserializationMode, ProtocolVersion, Readable, Reader, StreamingReader, Writeable,
	Writer,
};
use crate::mwc_core::{consensus, global};
use crate::types::{
	AttachmentMeta, AttachmentUpdate, Capabilities, Error, PeerAddr, ReasonForBan,
	MAX_BLOCK_HEADERS, MAX_LOCATORS, MAX_PEER_ADDRS,
};
use crate::util::secp::pedersen::RangeProof;
use bytes::Bytes;
use num::FromPrimitive;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;
use std::{fmt, thread, time::Duration};

/// Mwc's user agent with current version
pub const USER_AGENT: &str = concat!("MW/MWC ", env!("CARGO_PKG_VERSION"));

// MWC - Magic number are updated to be different from mwc.
/// Magic numbers expected in the header of every message
const OTHER_MAGIC: [u8; 2] = [21, 19];
const FLOONET_MAGIC: [u8; 2] = [17, 36];
const MAINNET_MAGIC: [u8; 2] = [13, 77];

// Types of messages.
// Note: Values here are *important* so we should only add new values at the
// end.
enum_from_primitive! {
	#[derive(Debug, Clone, Copy, PartialEq)]
	pub enum Type {
		Error = 0,
		Hand = 1,
		Shake = 2,
		Ping = 3,
		Pong = 4,
		GetPeerAddrs = 5,
		PeerAddrs = 6,
		GetHeaders = 7,
		Header = 8,
		Headers = 9,
		GetBlock = 10,
		Block = 11,
		GetCompactBlock = 12,
		CompactBlock = 13,
		StemTransaction = 14,
		Transaction = 15,
		TxHashSetRequest = 16,
		TxHashSetArchive = 17,
		BanReason = 18,
		GetTransaction = 19,
		TransactionKernel = 20,
		TorAddress = 23,
		StartPibdSyncRequest = 24,
		GetOutputBitmapSegment = 25,
		OutputBitmapSegment = 26,
		GetOutputSegment = 27,
		OutputSegment = 28,
		GetRangeProofSegment = 29,
		RangeProofSegment = 30,
		GetKernelSegment = 31,
		KernelSegment = 32,
		HasAnotherArchiveHeader = 33,
		PibdSyncState = 34,
		StartHeadersHashRequest = 35,
		StartHeadersHashResponse = 36,
		GetHeadersHashesSegment = 37,
		OutputHeadersHashesSegment = 38,
	}
}

/// Max theoretical size of a block filled with outputs.
fn max_block_size() -> u64 {
	(global::max_block_weight() / consensus::BLOCK_OUTPUT_WEIGHT * 708) as u64
}

// Max msg size when msg type is unknown.
fn default_max_msg_size() -> u64 {
	max_block_size()
}

// Max msg size for each msg type.
fn max_msg_size(msg_type: Type) -> u64 {
	match msg_type {
		Type::Error => 0,
		Type::Hand => 128,
		Type::Shake => 88,
		Type::Ping => 16,
		Type::Pong => 16,
		Type::GetPeerAddrs => 4,
		Type::PeerAddrs => 4 + (1 + 16 + 2) * MAX_PEER_ADDRS as u64,
		Type::GetHeaders => 1 + 32 * MAX_LOCATORS as u64,
		Type::Header => 365,
		Type::Headers => 2 + 365 * MAX_BLOCK_HEADERS as u64,
		Type::GetBlock => 32,
		Type::Block => max_block_size(),
		Type::GetCompactBlock => 32,
		Type::CompactBlock => max_block_size() / 10,
		Type::StemTransaction => max_block_size(),
		Type::Transaction => max_block_size(),
		Type::TxHashSetRequest => 40, // 32+8=40
		Type::TxHashSetArchive => 64,
		Type::BanReason => 64,
		Type::GetTransaction => 32,
		Type::TransactionKernel => 32,
		Type::TorAddress => 128,
		Type::StartHeadersHashRequest => 8,
		Type::StartHeadersHashResponse => 40, // 8+32=40
		Type::GetHeadersHashesSegment => 41,
		Type::OutputHeadersHashesSegment => 2 * max_block_size(),
		Type::GetOutputBitmapSegment => 41,
		Type::OutputBitmapSegment => 2 * max_block_size(),
		Type::GetOutputSegment => 41,
		Type::OutputSegment => 2 * max_block_size(),
		Type::GetRangeProofSegment => 41,
		Type::RangeProofSegment => 2 * max_block_size(),
		Type::GetKernelSegment => 41,
		Type::KernelSegment => 2 * max_block_size(),
		Type::StartPibdSyncRequest => 40, // 32+8=40
		Type::HasAnotherArchiveHeader => 40,
		Type::PibdSyncState => 72, // 32 + 8 + 32 = 72
	}
}

fn magic() -> [u8; 2] {
	match global::get_chain_type() {
		global::ChainTypes::Floonet => FLOONET_MAGIC,
		global::ChainTypes::Mainnet => MAINNET_MAGIC,
		_ => OTHER_MAGIC,
	}
}

pub struct Msg {
	header: MsgHeader,
	body: Vec<u8>,
	attachment: Option<File>,
	version: ProtocolVersion,
}

impl Msg {
	pub fn new<T: Writeable>(
		msg_type: Type,
		msg: T,
		version: ProtocolVersion,
	) -> Result<Msg, Error> {
		let body = ser::ser_vec(&msg, version)?;
		Ok(Msg {
			header: MsgHeader::new(msg_type, body.len() as u64),
			body,
			attachment: None,
			version,
		})
	}

	pub fn add_attachment(&mut self, attachment: File) {
		self.attachment = Some(attachment)
	}
}

/// Read a header from the provided stream without blocking if the
/// underlying stream is async. Typically headers will be polled for, so
/// we do not want to block.
///
/// Note: We return a MsgHeaderWrapper here as we may encounter an unknown msg type.
///
pub fn read_header<R: Read>(
	stream: &mut R,
	version: ProtocolVersion,
) -> Result<MsgHeaderWrapper, Error> {
	let mut head = vec![0u8; MsgHeader::LEN];
	stream.read_exact(&mut head)?;
	let header: MsgHeaderWrapper =
		ser::deserialize(&mut &head[..], version, DeserializationMode::default())?;
	Ok(header)
}

/// Read a single item from the provided stream, always blocking until we
/// have a result (or timeout).
/// Returns the item and the total bytes read.
pub fn read_item<T: Readable, R: Read>(
	stream: &mut R,
	version: ProtocolVersion,
) -> Result<(T, u64), Error> {
	let mut reader = StreamingReader::new(stream, version);
	let res = T::read(&mut reader)?;
	Ok((res, reader.total_bytes_read()))
}

/// Read a message body from the provided stream, always blocking
/// until we have a result (or timeout).
pub fn read_body<T: Readable, R: Read>(
	h: &MsgHeader,
	stream: &mut R,
	version: ProtocolVersion,
) -> Result<T, Error> {
	let mut body = vec![0u8; h.msg_len as usize];
	stream.read_exact(&mut body)?;
	ser::deserialize(&mut &body[..], version, DeserializationMode::default()).map_err(From::from)
}

/// Read (an unknown) message from the provided stream and discard it.
pub fn read_discard<R: Read>(msg_len: u64, stream: &mut R) -> Result<(), Error> {
	let mut buffer = vec![0u8; msg_len as usize];
	stream.read_exact(&mut buffer)?;
	Ok(())
}

/// Reads a full message from the underlying stream.
pub fn read_message<T: Readable, R: Read>(
	stream: &mut R,
	version: ProtocolVersion,
	msg_type: Type,
) -> Result<T, Error> {
	match read_header(stream, version)? {
		MsgHeaderWrapper::Known(header) => {
			if header.msg_type == msg_type {
				read_body(&header, stream, version)
			} else {
				Err(Error::BadMessage)
			}
		}
		MsgHeaderWrapper::Unknown(msg_len, _) => {
			read_discard(msg_len, stream)?;
			Err(Error::BadMessage)
		}
	}
}

pub fn write_message<W: Write>(
	stream: &mut W,
	msgs: &Vec<Msg>,
	tracker: Arc<Tracker>,
) -> Result<(), Error> {
	// Introduce a delay so messages are spaced at least 150ms apart.
	// This gives a max msg rate of 60000/150 = 400 messages per minute.
	// Exceeding 500 messages per minute will result in being banned as abusive.
	if let Some(elapsed) = tracker.sent_bytes.read().elapsed_since_last_msg() {
		let min_interval: u64 = 150;
		let sleep_ms = min_interval.saturating_sub(elapsed);
		if sleep_ms > 0 {
			thread::sleep(Duration::from_millis(sleep_ms))
		}
	}

	// sending tmp buffer.
	let mut tmp_buf: Vec<u8> = vec![];

	for msg in msgs {
		tmp_buf.extend(ser::ser_vec(&msg.header, msg.version)?);
		tmp_buf.extend(&msg.body[..]);
		if let Some(file) = &msg.attachment {
			// finalize what we have before attachments...
			if !tmp_buf.is_empty() {
				stream.write_all(&tmp_buf[..])?;
				tracker.inc_sent(tmp_buf.len() as u64);
				tmp_buf.clear();
			}
			let mut file = file.try_clone()?;
			let mut buf = [0u8; 8000];
			loop {
				match file.read(&mut buf[..]) {
					Ok(0) => break,
					Ok(n) => {
						stream.write_all(&buf[..n])?;
						// Increase sent bytes "quietly" without incrementing the counter.
						// (In a loop here for the single attachment).
						tracker.inc_quiet_sent(n as u64);
					}
					Err(e) => return Err(From::from(e)),
				}
			}
		}
	}

	if !tmp_buf.is_empty() {
		stream.write_all(&tmp_buf[..])?;
		tracker.inc_sent(tmp_buf.len() as u64);
		tmp_buf.clear();
	}

	Ok(())
}

/// A wrapper around a message header. If the header is for an unknown msg type
/// then we will be unable to parse the msg itself (just a bunch of random bytes).
/// But we need to know how many bytes to discard to discard the full message.
#[derive(Clone)]
pub enum MsgHeaderWrapper {
	/// A "known" msg type with deserialized msg header.
	Known(MsgHeader),
	/// An unknown msg type with corresponding msg size in bytes.
	Unknown(u64, u8),
}

/// Header of any protocol message, used to identify incoming messages.
#[derive(Clone)]
pub struct MsgHeader {
	magic: [u8; 2],
	/// Type of the message.
	pub msg_type: Type,
	/// Total length of the message in bytes.
	pub msg_len: u64,
}

impl MsgHeader {
	// 2 magic bytes + 1 type byte + 8 bytes (msg_len)
	pub const LEN: usize = 2 + 1 + 8;

	/// Creates a new message header.
	pub fn new(msg_type: Type, len: u64) -> MsgHeader {
		MsgHeader {
			magic: magic(),
			msg_type: msg_type,
			msg_len: len,
		}
	}
}

impl Writeable for MsgHeader {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		ser_multiwrite!(
			writer,
			[write_u8, self.magic[0]],
			[write_u8, self.magic[1]],
			[write_u8, self.msg_type as u8],
			[write_u64, self.msg_len]
		);
		Ok(())
	}
}

impl Readable for MsgHeaderWrapper {
	fn read<R: Reader>(reader: &mut R) -> Result<MsgHeaderWrapper, ser::Error> {
		let m = magic();
		reader.expect_u8(m[0])?;
		reader.expect_u8(m[1])?;

		// Read the msg header.
		// We do not yet know if the msg type is one we support locally.
		let (t, msg_len) = ser_multiread!(reader, read_u8, read_u64);

		// Attempt to convert the msg type byte into one of our known msg type enum variants.
		// Check the msg_len while we are at it.
		match Type::from_u8(t) {
			Some(msg_type) => {
				// TODO 4x the limits for now to leave ourselves space to change things.
				let max_len = max_msg_size(msg_type) * 4;
				if msg_len > max_len {
					let err_msg = format!(
						"Too large read {:?}, max_len: {}, msg_len: {}.",
						msg_type, max_len, msg_len
					);
					error!("{}", err_msg);
					return Err(ser::Error::TooLargeReadErr(err_msg));
				}

				Ok(MsgHeaderWrapper::Known(MsgHeader {
					magic: m,
					msg_type,
					msg_len,
				}))
			}
			None => {
				// Unknown msg type, but we still want to limit how big the msg is.
				let max_len = default_max_msg_size() * 4;
				if msg_len > max_len {
					let err_msg = format!(
						"Too large read (unknown msg type) {:?}, max_len: {}, msg_len: {}.",
						t, max_len, msg_len
					);
					error!("{}", err_msg);
					return Err(ser::Error::TooLargeReadErr(err_msg));
				}

				Ok(MsgHeaderWrapper::Unknown(msg_len, t))
			}
		}
	}
}

/// First part of a handshake, sender advertises its version and
/// characteristics.
pub struct Hand {
	/// protocol version of the sender
	pub version: ProtocolVersion,
	/// capabilities of the sender
	pub capabilities: Capabilities,
	/// randomly generated for each handshake, helps detect self
	pub nonce: u64,
	/// genesis block of our chain, only connect to peers on the same chain
	pub genesis: Hash,
	/// total difficulty accumulated by the sender, used to check whether sync
	/// may be needed
	pub total_difficulty: Difficulty,
	/// network address of the sender
	pub sender_addr: PeerAddr,
	/// network address of the receiver
	pub receiver_addr: PeerAddr,
	/// name of version of the software
	pub user_agent: String,
}

impl Writeable for Hand {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.version.write(writer)?;
		ser_multiwrite!(
			writer,
			[write_u32, self.capabilities.bits()],
			[write_u64, self.nonce]
		);
		self.total_difficulty.write(writer)?;
		self.sender_addr.write(writer)?;
		self.receiver_addr.write(writer)?;
		if self.user_agent.len() > 10_000 {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Unreasonable long User Agent. UA length is {}",
				self.user_agent.len()
			)));
		}
		writer.write_bytes(&self.user_agent)?;
		self.genesis.write(writer)?;
		Ok(())
	}
}

impl Readable for Hand {
	fn read<R: Reader>(reader: &mut R) -> Result<Hand, ser::Error> {
		let version = ProtocolVersion::read(reader)?;
		let (capab, nonce) = ser_multiread!(reader, read_u32, read_u64);
		let capabilities = Capabilities::from_bits_truncate(capab);
		let total_difficulty = Difficulty::read(reader)?;
		let sender_addr = PeerAddr::read(reader)?;
		let receiver_addr = PeerAddr::read(reader)?;
		let ua = reader.read_bytes_len_prefix()?;
		let user_agent = String::from_utf8(ua)
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read User Agent, {}", e)))?;
		let genesis = Hash::read(reader)?;
		Ok(Hand {
			version,
			capabilities,
			nonce,
			genesis,
			total_difficulty,
			sender_addr,
			receiver_addr,
			user_agent,
		})
	}
}

/// Second part of a handshake, receiver of the first part replies with its own
/// version and characteristics.
pub struct Shake {
	/// sender version
	pub version: ProtocolVersion,
	/// sender capabilities
	pub capabilities: Capabilities,
	/// genesis block of our chain, only connect to peers on the same chain
	pub genesis: Hash,
	/// total difficulty accumulated by the sender, used to check whether sync
	/// may be needed
	pub total_difficulty: Difficulty,
	/// name of version of the software
	pub user_agent: String,
}

impl Writeable for Shake {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.version.write(writer)?;
		writer.write_u32(self.capabilities.bits())?;
		self.total_difficulty.write(writer)?;
		if self.user_agent.len() > 10_000 {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Unreasonable long User Agent. UA length is {}",
				self.user_agent.len()
			)));
		}
		writer.write_bytes(&self.user_agent)?;
		self.genesis.write(writer)?;
		Ok(())
	}
}

impl Readable for Shake {
	fn read<R: Reader>(reader: &mut R) -> Result<Shake, ser::Error> {
		let version = ProtocolVersion::read(reader)?;
		let capab = reader.read_u32()?;
		let capabilities = Capabilities::from_bits_truncate(capab);
		let total_difficulty = Difficulty::read(reader)?;
		let ua = reader.read_bytes_len_prefix()?;
		let user_agent = String::from_utf8(ua)
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read User Agent, {}", e)))?;
		let genesis = Hash::read(reader)?;
		Ok(Shake {
			version,
			capabilities,
			genesis,
			total_difficulty,
			user_agent,
		})
	}
}

/// Ask for other peers addresses, required for network discovery.
#[derive(Debug)]
pub struct GetPeerAddrs {
	/// Filters on the capabilities we'd like the peers to have
	pub capabilities: Capabilities,
}

impl Writeable for GetPeerAddrs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u32(self.capabilities.bits())
	}
}

impl Readable for GetPeerAddrs {
	fn read<R: Reader>(reader: &mut R) -> Result<GetPeerAddrs, ser::Error> {
		let capab = reader.read_u32()?;
		let capabilities = Capabilities::from_bits_truncate(capab);
		Ok(GetPeerAddrs { capabilities })
	}
}

/// Peer addresses we know of that are fresh enough, in response to
/// GetPeerAddrs.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PeerAddrs {
	pub peers: Vec<PeerAddr>,
}

impl Writeable for PeerAddrs {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.peers.len() > MAX_PEER_ADDRS as usize {
			return Err(ser::Error::TooLargeWriteErr(
				"peer.len larger then the limit".to_string(),
			));
		}
		writer.write_u32(self.peers.len() as u32)?;
		for p in &self.peers {
			p.write(writer)?;
		}
		Ok(())
	}
}

impl Readable for PeerAddrs {
	fn read<R: Reader>(reader: &mut R) -> Result<PeerAddrs, ser::Error> {
		let peer_count = reader.read_u32()?;
		if peer_count > MAX_PEER_ADDRS {
			return Err(ser::Error::TooLargeReadErr(
				"peer_count larger then the limit".to_string(),
			));
		} else if peer_count == 0 {
			return Ok(PeerAddrs { peers: vec![] });
		}
		let mut peers = Vec::with_capacity(peer_count as usize);
		for _ in 0..peer_count {
			peers.push(PeerAddr::read(reader)?);
		}
		Ok(PeerAddrs { peers })
	}
}

impl IntoIterator for PeerAddrs {
	type Item = PeerAddr;
	type IntoIter = std::vec::IntoIter<Self::Item>;
	fn into_iter(self) -> Self::IntoIter {
		self.peers.into_iter()
	}
}

impl Default for PeerAddrs {
	fn default() -> Self {
		PeerAddrs { peers: vec![] }
	}
}

impl PeerAddrs {
	pub fn as_slice(&self) -> &[PeerAddr] {
		self.peers.as_slice()
	}

	pub fn contains(&self, addr: &PeerAddr) -> bool {
		self.peers.contains(addr)
	}

	pub fn difference(&self, other: &[PeerAddr]) -> PeerAddrs {
		let peers = self
			.peers
			.iter()
			.filter(|x| !other.contains(x))
			.cloned()
			.collect();
		PeerAddrs { peers }
	}
}

/// We found some issue in the communication, sending an error back, usually
/// followed by closing the connection.
pub struct PeerError {
	/// error code
	pub code: u32,
	/// slightly more user friendly message
	pub message: String,
}

impl Writeable for PeerError {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.message.len() > 10_000 {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Unreasonable long PeerError message. length is {}",
				self.message.len()
			)));
		}
		ser_multiwrite!(writer, [write_u32, self.code], [write_bytes, &self.message]);
		Ok(())
	}
}

impl Readable for PeerError {
	fn read<R: Reader>(reader: &mut R) -> Result<PeerError, ser::Error> {
		let code = reader.read_u32()?;
		let msg = reader.read_bytes_len_prefix()?;
		let message = String::from_utf8(msg)
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read message, {}", e)))?;
		Ok(PeerError {
			code: code,
			message: message,
		})
	}
}

/// Serializable wrapper for the block locator.
#[derive(Debug)]
pub struct Locator {
	pub hashes: Vec<Hash>,
}

impl Writeable for Locator {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		if self.hashes.len() > MAX_LOCATORS as usize {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Storing too many locators: {}",
				self.hashes.len()
			)));
		}
		writer.write_u8(self.hashes.len() as u8)?;
		for h in &self.hashes {
			h.write(writer)?
		}
		Ok(())
	}
}

impl Readable for Locator {
	fn read<R: Reader>(reader: &mut R) -> Result<Locator, ser::Error> {
		let len = reader.read_u8()?;
		if len > (MAX_LOCATORS as u8) {
			return Err(ser::Error::TooLargeReadErr(format!(
				"Get too many locators: {}",
				len
			)));
		}
		let mut hashes = Vec::with_capacity(len as usize);
		for _ in 0..len {
			hashes.push(Hash::read(reader)?);
		}
		Ok(Locator { hashes: hashes })
	}
}

/// Serializable wrapper for a list of block headers.
pub struct Headers {
	pub headers: Vec<BlockHeader>,
}

impl Writeable for Headers {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u16(self.headers.len() as u16)?;
		for h in &self.headers {
			h.write(writer)?
		}
		Ok(())
	}
}

#[derive(Debug)]
pub struct Ping {
	/// total difficulty accumulated by the sender, used to check whether sync
	/// may be needed
	pub total_difficulty: Difficulty,
	/// total height
	pub height: u64,
}

impl Writeable for Ping {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.total_difficulty.write(writer)?;
		self.height.write(writer)?;
		Ok(())
	}
}

impl Readable for Ping {
	fn read<R: Reader>(reader: &mut R) -> Result<Ping, ser::Error> {
		let total_difficulty = Difficulty::read(reader)?;
		let height = reader.read_u64()?;
		Ok(Ping {
			total_difficulty,
			height,
		})
	}
}

#[derive(Debug)]
pub struct Pong {
	/// total difficulty accumulated by the sender, used to check whether sync
	/// may be needed
	pub total_difficulty: Difficulty,
	/// height accumulated by sender
	pub height: u64,
}

impl Writeable for Pong {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.total_difficulty.write(writer)?;
		self.height.write(writer)?;
		Ok(())
	}
}

impl Readable for Pong {
	fn read<R: Reader>(reader: &mut R) -> Result<Pong, ser::Error> {
		let total_difficulty = Difficulty::read(reader)?;
		let height = reader.read_u64()?;
		Ok(Pong {
			total_difficulty,
			height,
		})
	}
}

#[derive(Debug)]
pub struct BanReason {
	/// the reason for the ban
	pub ban_reason: ReasonForBan,
}

impl Writeable for BanReason {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let ban_reason_i32 = self.ban_reason as i32;
		ban_reason_i32.write(writer)?;
		Ok(())
	}
}

impl Readable for BanReason {
	fn read<R: Reader>(reader: &mut R) -> Result<BanReason, ser::Error> {
		let ban_reason_i32 = match reader.read_i32() {
			Ok(h) => h,
			Err(_) => 0,
		};

		let ban_reason = ReasonForBan::from_i32(ban_reason_i32).ok_or(
			ser::Error::CorruptedData("Fail to read ban reason".to_string()),
		)?;

		Ok(BanReason { ban_reason })
	}
}

#[derive(Debug)]
pub struct HashHeadersData {
	/// Height of the archive block to what we are expecting to get headers hashes
	pub archive_height: u64,
}

impl Writeable for HashHeadersData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.archive_height)?;
		Ok(())
	}
}

impl Readable for HashHeadersData {
	fn read<R: Reader>(reader: &mut R) -> Result<HashHeadersData, ser::Error> {
		Ok(HashHeadersData {
			archive_height: reader.read_u64()?,
		})
	}
}

#[derive(Debug)]
pub struct StartHeadersHashResponse {
	pub archive_height: u64,
	pub headers_root_hash: Hash,
}

impl Writeable for StartHeadersHashResponse {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u64(self.archive_height)?;
		self.headers_root_hash.write(writer)?;
		Ok(())
	}
}

impl Readable for StartHeadersHashResponse {
	fn read<R: Reader>(reader: &mut R) -> Result<StartHeadersHashResponse, ser::Error> {
		Ok(StartHeadersHashResponse {
			archive_height: reader.read_u64()?,
			headers_root_hash: Hash::read(reader)?,
		})
	}
}

pub struct HeadersHashSegmentResponse {
	/// The hash of the block the MMR is associated with
	pub headers_root_hash: Hash,
	/// The segment response
	pub response: SegmentResponse<Hash>,
}

impl Readable for HeadersHashSegmentResponse {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let headers_root_hash = Readable::read(reader)?;
		let response = Readable::read(reader)?;
		Ok(Self {
			headers_root_hash,
			response,
		})
	}
}

impl Writeable for HeadersHashSegmentResponse {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		Writeable::write(&self.headers_root_hash, writer)?;
		Writeable::write(&self.response, writer)
	}
}

/// Request to get PIBD sync request
#[derive(Debug)]
pub struct ArchiveHeaderData {
	/// Hash of the block for which the txhashset should be provided
	pub hash: Hash,
	/// Height of the corresponding block
	pub height: u64,
}

impl Writeable for ArchiveHeaderData {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.hash.write(writer)?;
		writer.write_u64(self.height)?;
		Ok(())
	}
}

impl Readable for ArchiveHeaderData {
	fn read<R: Reader>(reader: &mut R) -> Result<ArchiveHeaderData, ser::Error> {
		Ok(ArchiveHeaderData {
			hash: Hash::read(reader)?,
			height: reader.read_u64()?,
		})
	}
}

#[derive(Debug)]
pub struct PibdSyncState {
	/// Hash of the block for which the txhashset should be provided
	pub header_hash: Hash,
	/// Height of the corresponding block
	pub header_height: u64,
	/// output bitmap root hash
	pub output_bitmap_root: Hash,
}

impl Writeable for PibdSyncState {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.header_hash.write(writer)?;
		writer.write_u64(self.header_height)?;
		self.output_bitmap_root.write(writer)?;
		Ok(())
	}
}

impl Readable for PibdSyncState {
	fn read<R: Reader>(reader: &mut R) -> Result<PibdSyncState, ser::Error> {
		Ok(PibdSyncState {
			header_hash: Hash::read(reader)?,
			header_height: reader.read_u64()?,
			output_bitmap_root: Hash::read(reader)?,
		})
	}
}

/// Request to get a segment of a (P)MMR at a particular block.
#[derive(Debug)]
pub struct SegmentRequest {
	/// The hash of the block the MMR is associated with
	pub block_hash: Hash,
	/// The identifier of the requested segment
	pub identifier: SegmentIdentifier,
}

impl Readable for SegmentRequest {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let block_hash = Readable::read(reader)?;
		let identifier = Readable::read(reader)?;
		Ok(Self {
			block_hash,
			identifier,
		})
	}
}

impl Writeable for SegmentRequest {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		Writeable::write(&self.block_hash, writer)?;
		Writeable::write(&self.identifier, writer)
	}
}

/// Response to a (P)MMR segment request.
pub struct SegmentResponse<T> {
	/// The hash of the archive header - block the MMR is associated with
	pub block_hash: Hash,
	/// The MMR segment
	pub segment: Segment<T>,
}

impl<T: Readable> Readable for SegmentResponse<T> {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let block_hash = Readable::read(reader)?;
		let segment = Readable::read(reader)?;
		Ok(Self {
			block_hash,
			segment,
		})
	}
}

impl<T: Writeable> Writeable for SegmentResponse<T> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		Writeable::write(&self.block_hash, writer)?;
		Writeable::write(&self.segment, writer)
	}
}

/// Response to an output PMMR segment request.
pub struct OutputSegmentResponse {
	/// The segment response
	pub response: SegmentResponse<OutputIdentifier>,
}

impl Readable for OutputSegmentResponse {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let response = Readable::read(reader)?;
		Ok(Self { response })
	}
}

impl Writeable for OutputSegmentResponse {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		Writeable::write(&self.response, writer)
	}
}

/// Response to an output bitmap MMR segment request.
pub struct OutputBitmapSegmentResponse {
	/// The hash of the block the MMR is associated with
	pub block_hash: Hash,
	/// The MMR segment
	pub segment: BitmapSegment,
}

impl Readable for OutputBitmapSegmentResponse {
	fn read<R: Reader>(reader: &mut R) -> Result<Self, ser::Error> {
		let block_hash = Readable::read(reader)?;
		let segment = Readable::read(reader)?;
		Ok(Self {
			block_hash,
			segment,
		})
	}
}

impl Writeable for OutputBitmapSegmentResponse {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		Writeable::write(&self.block_hash, writer)?;
		Writeable::write(&self.segment, writer)
	}
}

pub enum Message {
	Unknown(u8),
	Ping(Ping),
	Pong(Pong),
	BanReason(BanReason),
	TransactionKernel(Hash),
	GetTransaction(Hash),
	Transaction(Transaction),
	StemTransaction(Transaction),
	GetBlock(Hash),
	Block(UntrustedBlock),
	GetCompactBlock(Hash),
	CompactBlock(UntrustedCompactBlock),
	GetHeaders(Locator),
	Header(UntrustedBlockHeader),
	Headers(HeadersData),
	GetPeerAddrs(GetPeerAddrs),
	PeerAddrs(PeerAddrs),
	TxHashSetRequest(ArchiveHeaderData),
	TxHashSetArchive(TxHashSetArchive),
	Attachment(AttachmentUpdate, Option<Bytes>),
	TorAddress(TorAddress),
	StartHeadersHashRequest(HashHeadersData),
	StartHeadersHashResponse(StartHeadersHashResponse),
	GetHeadersHashesSegment(SegmentRequest),
	OutputHeadersHashesSegment(HeadersHashSegmentResponse),
	StartPibdSyncRequest(ArchiveHeaderData),
	PibdSyncState(PibdSyncState),
	GetOutputBitmapSegment(SegmentRequest),
	OutputBitmapSegment(OutputBitmapSegmentResponse),
	GetOutputSegment(SegmentRequest),
	OutputSegment(OutputSegmentResponse),
	GetRangeProofSegment(SegmentRequest),
	RangeProofSegment(SegmentResponse<RangeProof>),
	GetKernelSegment(SegmentRequest),
	KernelSegment(SegmentResponse<TxKernel>),
	HasAnotherArchiveHeader(ArchiveHeaderData),
}

/// We receive 512 headers from a peer.
/// But we process them in smaller batches of 32 headers.
/// HeadersData wraps the current batch and a count of the headers remaining after this batch.
pub struct HeadersData {
	/// Batch of headers currently being processed.
	pub headers: Vec<BlockHeader>,
	/// Number of headers stil to be processed after this current batch.
	/// 0 indicates this is the final batch from the larger set of headers received from the peer.
	pub remaining: u64,
}

impl fmt::Display for Message {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Message::Unknown(i) => write!(f, "Unknown({})", i),
			Message::Ping(ping) => write!(f, "{:?}", ping),
			Message::Pong(pong) => write!(f, "{:?}", pong),
			Message::BanReason(ban_reason) => write!(f, "{:?}", ban_reason),
			Message::TransactionKernel(hash) => write!(f, "TransactionKernel({})", hash),
			Message::GetTransaction(hash) => write!(f, "GetTransaction({})", hash),
			Message::Transaction(tx) => write!(f, "{:?}", tx),
			Message::StemTransaction(tx) => write!(f, "STEM[{:?}]", tx),
			Message::GetBlock(hash) => write!(f, "GetBlock({})", hash),
			Message::Block(block) => write!(f, "{:?}", block),
			Message::GetCompactBlock(hash) => write!(f, "GetCompactBlock({})", hash),
			Message::CompactBlock(com_block) => write!(f, "{:?}", com_block),
			Message::GetHeaders(loc) => write!(f, "GetHeaders({:?})", loc),
			Message::Header(header) => write!(f, "Header({:?})", header),
			Message::Headers(headers) => match headers.headers.first() {
				Some(header) => write!(
					f,
					"Headers(H:{} Num:{}, Rem:{})",
					header.height,
					headers.headers.len(),
					headers.remaining
				),
				None => write!(f, "Headers(EMPTY)"),
			},
			Message::GetPeerAddrs(peer_addr) => write!(f, "{:?}", peer_addr),
			Message::PeerAddrs(peer_addrs) => write!(f, "{:?}", peer_addrs),
			Message::TxHashSetRequest(arch) => write!(f, "TxHashSetRequest({:?})", arch),
			Message::TxHashSetArchive(hash_set) => write!(f, "{:?}", hash_set),
			Message::Attachment(meta, _) => write!(f, "Attachment({:?})", meta),
			Message::TorAddress(addr) => write!(f, "{:?}", addr),
			Message::StartHeadersHashRequest(req) => {
				write!(f, "StartHeadersHashRequest({:?})", req)
			}
			Message::StartHeadersHashResponse(resp) => {
				write!(f, "StartHeadersHashResponse({:?})", resp)
			}
			Message::GetHeadersHashesSegment(seg_req) => {
				write!(f, "GetHeadersHashesSegment({:?})", seg_req)
			}
			Message::OutputHeadersHashesSegment(segm) => write!(
				f,
				"OutputHeadersHashesSegment({:?}, root:{})",
				segm.response.segment.id(),
				segm.headers_root_hash
			),
			Message::GetOutputBitmapSegment(segm) => {
				write!(f, "GetOutputBitmapSegment({:?})", segm)
			}
			Message::OutputBitmapSegment(segm) => write!(
				f,
				"OutputBitmapSegment({:?}, root:{})",
				segm.segment.identifier, segm.block_hash
			),
			Message::GetOutputSegment(segm) => write!(f, "GetOutputSegment({:?})", segm),
			Message::OutputSegment(segm) => write!(
				f,
				"OutputSegment({:?}, root:{})",
				segm.response.segment.id(),
				segm.response.block_hash
			),
			Message::GetRangeProofSegment(segm) => write!(f, "GetRangeProofSegment({:?})", segm),
			Message::RangeProofSegment(segm) => write!(
				f,
				"RangeProofSegment({:?}, root:{})",
				segm.segment.id(),
				segm.block_hash
			),
			Message::GetKernelSegment(segm) => write!(f, "GetKernelSegment({:?})", segm),
			Message::KernelSegment(segm) => write!(
				f,
				"KernelSegment({:?}, root:{})",
				segm.segment.id(),
				segm.block_hash
			),
			Message::PibdSyncState(state) => write!(f, "{:?}", state),
			Message::StartPibdSyncRequest(dt) => write!(f, "StartPibdSyncRequest({:?})", dt),
			Message::HasAnotherArchiveHeader(dt) => write!(f, "HasAnotherArchiveHeader({:?})", dt),
		}
	}
}

impl fmt::Debug for Message {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "Consume({})", self)
	}
}

pub enum Consumed {
	Response(Msg),
	Attachment(Arc<AttachmentMeta>, File),
	None,
	Disconnect,
}

impl fmt::Debug for Consumed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Consumed::Response(msg) => write!(f, "Consumed::Response({:?})", msg.header.msg_type),
			Consumed::Attachment(meta, _) => write!(f, "Consumed::Attachment({:?})", meta.size),
			Consumed::None => write!(f, "Consumed::None"),
			Consumed::Disconnect => write!(f, "Consumed::Disconnect"),
		}
	}
}

/// Response to a txhashset archive request, must include a zip stream of the
/// archive after the message body.
#[derive(Debug)]
pub struct TxHashSetArchive {
	/// Hash of the block for which the txhashset are provided
	pub hash: Hash,
	/// Height of the corresponding block
	pub height: u64,
	/// Size in bytes of the archive
	pub bytes: u64,
}

impl Writeable for TxHashSetArchive {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		self.hash.write(writer)?;
		ser_multiwrite!(writer, [write_u64, self.height], [write_u64, self.bytes]);
		Ok(())
	}
}

impl Readable for TxHashSetArchive {
	fn read<R: Reader>(reader: &mut R) -> Result<TxHashSetArchive, ser::Error> {
		let hash = Hash::read(reader)?;
		let (height, bytes) = ser_multiread!(reader, read_u64, read_u64);

		Ok(TxHashSetArchive {
			hash,
			height,
			bytes,
		})
	}
}

#[derive(Debug)]
pub struct TorAddress {
	pub address: String,
}

impl TorAddress {
	/// Creates a new message TorAddress.
	pub fn new(address: String) -> TorAddress {
		TorAddress { address }
	}
}

impl Writeable for TorAddress {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		ser_multiwrite!(writer, [write_bytes, &self.address]);
		Ok(())
	}
}

impl Readable for TorAddress {
	fn read<R: Reader>(reader: &mut R) -> Result<TorAddress, ser::Error> {
		let address = String::from_utf8(reader.read_bytes_len_prefix()?);

		match address {
			Ok(address) => Ok(TorAddress { address }),
			Err(e) => Err(ser::Error::Utf8Conversion(e.to_string())),
		}
	}
}
