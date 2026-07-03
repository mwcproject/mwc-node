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

use crate::conn::Tracker;
use crate::tor::arti::canonical_onion_v3;
use crate::types::{
	AttachmentUpdate, Capabilities, Error, PeerAddr, ReasonForBan, MAX_BLOCK_HEADERS, MAX_LOCATORS,
	MAX_PEER_ADDRS,
};
use mwc_chain::txhashset::BitmapSegment;
use mwc_core::core::hash::{Hash, Hashed};
use mwc_core::core::transaction::{OutputIdentifier, TxKernel};
use mwc_core::core::{
	BlockHeader, Segment, SegmentIdentifier, Transaction, UntrustedBlock, UntrustedBlockHeader,
	UntrustedCompactBlock,
};
use mwc_core::pow::Difficulty;
use mwc_core::ser::{self, ProtocolVersion, Readable, Reader, StreamingReader, Writeable, Writer};
use mwc_core::ser_multiread;
use mwc_core::ser_multiwrite;
use mwc_core::{consensus, global};
use mwc_crates::bytes::Bytes;
use mwc_crates::enum_primitive::{
	enum_from_primitive, enum_from_primitive_impl, enum_from_primitive_impl_ty,
};
use mwc_crates::log::{error, trace};
use mwc_crates::num::FromPrimitive;
use mwc_crates::secp::pedersen::RangeProof;
use mwc_crates::serde::{self, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::io::{Read, Write};
use std::sync::Arc;

/// Mwc's user agent with current version
pub const USER_AGENT: &str = concat!("MW/MWC ", env!("CARGO_PKG_VERSION"));
pub const ONION_PROOF_SIGNATURE_LEN: usize = 64;
pub const ONION_PROOF_TIMESTAMP_LEN: usize = 8;

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
		TorAddress = 23, // Not used, but keeping as reserved for backward compatibility
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
fn max_block_size(context_id: u32) -> u64 {
	(global::max_block_weight(context_id) / consensus::BLOCK_OUTPUT_WEIGHT * 708) as u64
}

// Max msg size when msg type is unknown.
fn default_max_msg_size(context_id: u32) -> u64 {
	max_block_size(context_id)
}

// Max msg size for each msg type.
fn max_msg_size(context_id: u32, msg_type: Type) -> u64 {
	match msg_type {
		Type::Error => 0,
		Type::Hand => 128 + 8 + ONION_PROOF_SIGNATURE_LEN as u64 + ONION_PROOF_TIMESTAMP_LEN as u64,
		Type::Shake => 88 + 8,
		Type::Ping => 16,
		Type::Pong => 16,
		Type::GetPeerAddrs => 4,
		Type::PeerAddrs => 4 + (1 + 16 + 2) * MAX_PEER_ADDRS as u64,
		Type::GetHeaders => 1 + 32 * MAX_LOCATORS as u64,
		Type::Header => 365,
		Type::Headers => 2 + 365 * MAX_BLOCK_HEADERS as u64,
		Type::GetBlock => 32,
		Type::Block => max_block_size(context_id),
		Type::GetCompactBlock => 32,
		Type::CompactBlock => max_block_size(context_id) / 10,
		Type::StemTransaction => max_block_size(context_id),
		Type::Transaction => max_block_size(context_id),
		Type::TxHashSetRequest => 40, // 32+8=40
		Type::TxHashSetArchive => 64,
		Type::BanReason => 64,
		Type::GetTransaction => 32,
		Type::TransactionKernel => 32,
		Type::TorAddress => 128, // Not used, keeping for backward compatibility
		Type::StartHeadersHashRequest => 8,
		Type::StartHeadersHashResponse => 40, // 8+32=40
		Type::GetHeadersHashesSegment => 41,
		Type::OutputHeadersHashesSegment => 2 * max_block_size(context_id),
		Type::GetOutputBitmapSegment => 41,
		Type::OutputBitmapSegment => 2 * max_block_size(context_id),
		Type::GetOutputSegment => 41,
		Type::OutputSegment => 2 * max_block_size(context_id),
		Type::GetRangeProofSegment => 41,
		Type::RangeProofSegment => 2 * max_block_size(context_id),
		Type::GetKernelSegment => 41,
		Type::KernelSegment => 2 * max_block_size(context_id),
		Type::StartPibdSyncRequest => 40, // 32+8=40
		Type::HasAnotherArchiveHeader => 40,
		Type::PibdSyncState => 72, // 32 + 8 + 32 = 72
	}
}

fn magic(context_id: u32) -> [u8; 2] {
	match global::get_chain_type(context_id) {
		global::ChainTypes::Floonet => FLOONET_MAGIC,
		global::ChainTypes::Mainnet => MAINNET_MAGIC,
		_ => OTHER_MAGIC,
	}
}

pub struct Msg {
	header: MsgHeader,
	body: Vec<u8>,
	version: ProtocolVersion,
	context_id: u32,
}

impl Msg {
	pub fn new<T: Writeable>(
		msg_type: Type,
		msg: T,
		version: ProtocolVersion,
		context_id: u32,
	) -> Result<Msg, Error> {
		let body = ser::ser_vec(context_id, &msg, version)?;
		// Inbound message headers are checked against max_msg_size() because the
		// advertised length is peer-controlled. Outbound messages are produced by
		// local send paths after local validation, so this constructor deliberately
		// frames the serialized body without repeating the per-type wire-size
		// check. If a future outbound path passes peer-controlled or otherwise
		// unbounded data through here, add a TooLargeWriteErr check at this
		// boundary before constructing MsgHeader.
		Ok(Msg {
			header: MsgHeader::new(context_id, msg_type, body.len()),
			body,
			version,
			context_id,
		})
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
	context_id: u32,
) -> Result<MsgHeaderWrapper, Error> {
	let mut head = vec![0u8; MsgHeader::LEN];
	stream.read_exact(&mut head)?;
	let header: MsgHeaderWrapper = ser::deserialize_strict(&mut &head[..], version, context_id)?;
	Ok(header)
}

/// Read a single item from the provided stream, always blocking until we
/// have a result (or timeout).
/// Returns the item and the total bytes read.
pub fn read_item<T: Readable, R: Read>(
	stream: &mut R,
	version: ProtocolVersion,
	context_id: u32,
) -> Result<(T, u64), Error> {
	let mut reader = StreamingReader::new(stream, version, context_id);
	let res = T::read(&mut reader)?;
	Ok((res, reader.total_bytes_read()))
}

/// Read a message body from the provided stream, always blocking
/// until we have a result (or timeout).
pub fn read_body<T: Readable, R: Read>(
	h: &MsgHeader,
	stream: &mut R,
	version: ProtocolVersion,
	context_id: u32,
) -> Result<T, Error> {
	let mut body = vec![0u8; h.msg_len];
	stream.read_exact(&mut body)?;
	// From the stream we might drop ending data because of forward compatibility. Future versions
	// might have some extra data.
	ser::deserialize_permissive(&mut &body[..], version, context_id).map_err(From::from)
}

/// Read (an unknown) message from the provided stream and discard it.
pub fn read_discard<R: Read>(msg_len: usize, stream: &mut R) -> Result<(), Error> {
	let mut buffer = vec![0u8; msg_len];
	stream.read_exact(&mut buffer)?;
	Ok(())
}

/// Reads a full message from the underlying stream.
pub fn read_message<T: Readable, R: Read>(
	stream: &mut R,
	version: ProtocolVersion,
	context_id: u32,
	msg_type: Type,
) -> Result<T, Error> {
	match read_header(stream, version, context_id)? {
		MsgHeaderWrapper::Known(header) => {
			if header.msg_type == msg_type {
				read_body(&header, stream, version, context_id)
			} else {
				Err(Error::BadMessage(format!(
					"header.msg_type={:?} but expected {:?}",
					header.msg_type, msg_type
				)))
			}
		}
		MsgHeaderWrapper::Unknown(msg_len, tp) => {
			read_discard(msg_len, stream)?;
			Err(Error::BadMessage(format!(
				"Unknown massage of length {} and type {}",
				msg_len, tp
			)))
		}
	}
}

pub fn write_message<W: Write>(
	stream: &mut W,
	msgs: &Vec<Msg>,
	tracker: Arc<Tracker>,
) -> Result<(), Error> {
	// sending tmp buffer.
	let mut tmp_buf: Vec<u8> = vec![];

	for msg in msgs {
		trace!(
			"Sending message to the peer stream: {:?}",
			msg.header.msg_type
		);
		tmp_buf.extend(ser::ser_vec(msg.context_id, &msg.header, msg.version)?);
		tmp_buf.extend(&msg.body[..]);
	}

	if !tmp_buf.is_empty() {
		tracker.inc_sent(tmp_buf.len() as u64);
		trace!("Sending {} bytes of data to the peer stream", tmp_buf.len());
		stream.write_all(&tmp_buf[..])?;
		tmp_buf.clear();
	}

	// Flush is needed for Arti. Arti buffer the data and never send.
	stream.flush()?;

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
	Unknown(usize, u8),
}

/// Header of any protocol message, used to identify incoming messages.
#[derive(Clone)]
pub struct MsgHeader {
	magic: [u8; 2],
	/// Type of the message.
	pub msg_type: Type,
	/// Total length of the message in bytes.
	pub msg_len: usize,
}

impl MsgHeader {
	// 2 magic bytes + 1 type byte + 8 bytes (msg_len)
	pub const LEN: usize = 2 + 1 + 8;

	/// Creates a new message header.
	pub fn new(context_id: u32, msg_type: Type, len: usize) -> MsgHeader {
		MsgHeader {
			magic: magic(context_id),
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
			[write_u64, self.msg_len as u64]
		);
		Ok(())
	}
}

impl Readable for MsgHeaderWrapper {
	fn read<R: Reader>(reader: &mut R) -> Result<MsgHeaderWrapper, ser::Error> {
		let m = magic(reader.get_context_id());
		reader.expect_u8(m[0])?;
		reader.expect_u8(m[1])?;

		// Read the msg header.
		// We do not yet know if the msg type is one we support locally.
		let (t, msg_len) = ser_multiread!(reader, read_u8, read_u64);

		// Attempt to convert the msg type byte into one of our known msg type enum variants.
		// Check the msg_len while we are at it.
		match Type::from_u8(t) {
			Some(msg_type) => {
				trace!(
					"Reading from peer message {:?} with length {}",
					msg_type,
					msg_len
				);
				// TODO 4x the limits for now to leave ourselves space to change things.
				let max_len = max_msg_size(reader.get_context_id(), msg_type) * 4;
				if msg_len > max_len {
					let err_msg = format!(
						"Too large read {:?}, max_len: {}, msg_len: {}.",
						msg_type, max_len, msg_len
					);
					error!("{}", err_msg);
					return Err(ser::Error::TooLargeReadErr(err_msg));
				}

				let msg_len = usize::try_from(msg_len).map_err(|_| {
					ser::Error::DataOverflow(format!("MsgHeaderWrapper::read, msg_len={}", msg_len))
				})?;

				Ok(MsgHeaderWrapper::Known(MsgHeader {
					magic: m,
					msg_type,
					msg_len,
				}))
			}
			None => {
				trace!(
					"Reading from peer - got unknown message type {} with length {}",
					t,
					msg_len
				);
				// Unknown msg type, but we still want to limit how big the msg is.
				let max_len = default_max_msg_size(reader.get_context_id()) * 4;
				if msg_len > max_len {
					let err_msg = format!(
						"Too large read (unknown msg type) {:?}, max_len: {}, msg_len: {}.",
						t, max_len, msg_len
					);
					error!("{}", err_msg);
					return Err(ser::Error::TooLargeReadErr(err_msg));
				}

				let msg_len = usize::try_from(msg_len).map_err(|_| {
					ser::Error::DataOverflow(format!("MsgHeaderWrapper::read, msg_len={}", msg_len))
				})?;

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
	/// base fee (For protocol version 4)
	pub tx_fee_base: u64,
	/// Optional onion identity proof signature for protocol version 5+.
	pub onion_sig: Option<[u8; ONION_PROOF_SIGNATURE_LEN]>,
	/// Optional timestamp signed as part of the onion identity proof.
	pub onion_sig_timestamp: Option<i64>,
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
		if self.version.value() > 3 {
			writer.write_u64(self.tx_fee_base)?;
		}
		match (&self.onion_sig, self.onion_sig_timestamp) {
			(Some(onion_sig), Some(timestamp)) => {
				writer.write_fixed_bytes(onion_sig)?;
				writer.write_i64(timestamp)?;
			}
			(Some(_), None) => {
				return Err(ser::Error::CorruptedData(
					"onion proof signature timestamp is missing".into(),
				));
			}
			(None, Some(_)) => {
				return Err(ser::Error::CorruptedData(
					"onion proof timestamp without signature".into(),
				));
			}
			(None, None) => {}
		}
		Ok(())
	}
}

impl Readable for Hand {
	fn read<R: Reader>(reader: &mut R) -> Result<Hand, ser::Error> {
		let version = ProtocolVersion::read(reader)?;
		let (capab, nonce) = ser_multiread!(reader, read_u32, read_u64);
		// Handshake capability bits are optional peer features, not consensus
		// data. Accept unknown future bits and downgrade them to the capabilities
		// this binary knows how to negotiate.
		let capabilities = Capabilities::from_bits_truncate(capab);
		let total_difficulty = Difficulty::read(reader)?;
		let sender_addr = PeerAddr::read(reader)?;
		let receiver_addr = PeerAddr::read(reader)?;
		let ua = reader.read_bytes_len_prefix()?;
		let user_agent = String::from_utf8(ua)
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read User Agent, {}", e)))?;
		validate_user_agent(&user_agent, "Hand.user_agent")?;
		let genesis = Hash::read(reader)?;
		let tx_fee_base = if version.value() > 3 {
			reader.read_u64()?
		} else {
			// Default base fee before we start lowering it.
			consensus::MILLI_MWC
		};
		let onion_sig = read_optional_onion_sig(reader)?;
		let onion_sig_timestamp = if onion_sig.is_some() {
			read_optional_onion_sig_timestamp(reader)?
		} else {
			None
		};
		Ok(Hand {
			version,
			capabilities,
			nonce,
			genesis,
			total_difficulty,
			sender_addr,
			receiver_addr,
			user_agent,
			tx_fee_base,
			onion_sig,
			onion_sig_timestamp,
		})
	}
}

pub(crate) fn validate_user_agent(user_agent: &str, field: &str) -> Result<(), ser::Error> {
	if user_agent.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
		return Err(ser::Error::CorruptedData(format!(
			"{} contains character outside printable ASCII",
			field
		)));
	}
	Ok(())
}

fn read_optional_onion_sig<R: Reader>(
	reader: &mut R,
) -> Result<Option<[u8; ONION_PROOF_SIGNATURE_LEN]>, ser::Error> {
	let bytes_before = reader.bytes_read();
	match reader.read_fixed_bytes(ONION_PROOF_SIGNATURE_LEN) {
		Ok(bytes) => {
			let sig =
				<[u8; ONION_PROOF_SIGNATURE_LEN]>::try_from(bytes.as_slice()).map_err(|_| {
					ser::Error::CorruptedData("Invalid onion proof signature length".to_string())
				})?;
			Ok(Some(sig))
		}
		Err(ser::Error::IOErr(err))
			if err.kind() == std::io::ErrorKind::UnexpectedEof
				&& reader.bytes_read() == bytes_before
				&& !reader.has_pending_data() =>
		{
			Ok(None)
		}
		Err(e) => Err(e),
	}
}

fn read_optional_onion_sig_timestamp<R: Reader>(reader: &mut R) -> Result<Option<i64>, ser::Error> {
	let bytes_before = reader.bytes_read();
	match reader.read_i64() {
		Ok(timestamp) => Ok(Some(timestamp)),
		Err(ser::Error::IOErr(err))
			if err.kind() == std::io::ErrorKind::UnexpectedEof
				&& reader.bytes_read() == bytes_before
				&& !reader.has_pending_data() =>
		{
			Ok(None)
		}
		Err(e) => Err(e),
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
	/// base fee (For protocol version 4)
	pub tx_fee_base: u64,
}

impl Writeable for Shake {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		let protocol_version = writer.protocol_version();
		let user_agent_len = self.user_agent.len() as u64;
		let tx_fee_len = if protocol_version.value() > 3 { 8 } else { 0 };
		let msg_len = 4 + 4 + 8 + 8 + user_agent_len + 32 + tx_fee_len;
		let max_len = max_msg_size(writer.get_context_id(), Type::Shake) * 4;
		if msg_len > max_len {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"Too large Shake write, max_len: {}, msg_len: {}, user_agent_len: {}.",
				max_len,
				msg_len,
				self.user_agent.len()
			)));
		}

		protocol_version.write(writer)?;
		writer.write_u32(self.capabilities.bits())?;
		self.total_difficulty.write(writer)?;
		writer.write_bytes(&self.user_agent)?;
		self.genesis.write(writer)?;
		if protocol_version.value() > 3 {
			writer.write_u64(self.tx_fee_base)?;
		}
		Ok(())
	}
}

impl Readable for Shake {
	fn read<R: Reader>(reader: &mut R) -> Result<Shake, ser::Error> {
		let version = ProtocolVersion::read(reader)?;
		let capab = reader.read_u32()?;
		// Handshake capability bits are optional peer features, not consensus
		// data. Accept unknown future bits and downgrade them to the capabilities
		// this binary knows how to negotiate.
		let capabilities = Capabilities::from_bits_truncate(capab);
		let total_difficulty = Difficulty::read(reader)?;
		let ua = reader.read_bytes_len_prefix()?;
		let user_agent = String::from_utf8(ua)
			.map_err(|e| ser::Error::CorruptedData(format!("Fail to read User Agent, {}", e)))?;
		validate_user_agent(&user_agent, "Shake.user_agent")?;
		let genesis = Hash::read(reader)?;
		let tx_fee_base = if version.value() > 3 {
			reader.read_u64()?
		} else {
			// Default base fee before we start lowering it.
			consensus::MILLI_MWC
		};
		Ok(Shake {
			version,
			capabilities,
			genesis,
			total_difficulty,
			user_agent,
			tx_fee_base,
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
		// Capability bits can come from a future node version, so we may not
		// recognize every bit yet. Drop unknown bits before peer filtering:
		// unknown network data is untrusted, and treating it as meaningful
		// capability state would be unsafe.
		let capabilities = Capabilities::from_bits_truncate(capab);
		Ok(GetPeerAddrs { capabilities })
	}
}

/// Peer addresses we know of that are fresh enough, in response to
/// GetPeerAddrs.
/// Peer lists are public network data, so they do not need zeroization when
/// serialized in config templates.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(crate = "serde")]
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

	pub fn contains_exact(&self, addr: &PeerAddr) -> bool {
		self.peers.iter().any(|peer| peer.matches_exactly(addr))
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
		if self.headers.len() > MAX_BLOCK_HEADERS as usize {
			return Err(ser::Error::TooLargeWriteErr(format!(
				"too many block headers: {}, max: {}",
				self.headers.len(),
				MAX_BLOCK_HEADERS
			)));
		}
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
		let ban_reason_i32 = reader.read_i32()?;

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
	TorAddress(TorAddress), // Not used, keeping for backward compatibility
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
			Message::Transaction(tx) => write!(
				f,
				"Transaction(inputs:{}, outputs:{}, kernels:{})",
				tx.body.inputs.len(),
				tx.body.outputs.len(),
				tx.body.kernels.len()
			),
			Message::StemTransaction(tx) => write!(
				f,
				"StemTransaction(inputs:{}, outputs:{}, kernels:{})",
				tx.body.inputs.len(),
				tx.body.outputs.len(),
				tx.body.kernels.len()
			),
			Message::GetBlock(hash) => write!(f, "GetBlock({})", hash),
			Message::Block(block) => {
				let block = block.as_block();
				// Hash calculation can fail, but Display should only fail if writing fails.
				let hash = block
					.hash(block.header.pow.proof.context_id)
					.unwrap_or(Hash::default());
				write!(
					f,
					"Block(hash:{}, height:{}, inputs:{}, outputs:{}, kernels:{})",
					hash,
					block.header.height,
					block.body.inputs.len(),
					block.body.outputs.len(),
					block.body.kernels.len()
				)
			}
			Message::GetCompactBlock(hash) => write!(f, "GetCompactBlock({})", hash),
			Message::CompactBlock(com_block) => {
				let com_block = com_block.as_compact_block();
				// Hash calculation can fail, but Display should only fail if writing fails.
				let hash = com_block
					.hash(com_block.header.pow.proof.context_id)
					.unwrap_or(Hash::default());
				write!(
					f,
					"CompactBlock(hash:{}, height:{}, full_outputs:{}, full_kernels:{}, kernel_ids:{})",
					hash,
					com_block.header.height,
					com_block.out_full().len(),
					com_block.kern_full().len(),
					com_block.kern_ids().len()
				)
			}
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
	fn fmt(&self, f2: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f2, "Consume({})", self)
	}
}

pub enum Consumed {
	Response(Msg),
	None,
	Disconnect,
}

impl fmt::Debug for Consumed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Consumed::Response(msg) => write!(f, "Consumed::Response({:?})", msg.header.msg_type),
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

// Not used, keeping for backward compatibility
#[derive(Debug)]
pub struct TorAddress {
	pub address: String,
}

impl TorAddress {
	/// Creates a new message TorAddress.
	#[cfg(test)]
	pub(crate) fn new(address: String) -> TorAddress {
		TorAddress { address }
	}
}

#[cfg(test)]
impl Writeable for TorAddress {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		ser_multiwrite!(writer, [write_bytes, &self.address]);
		Ok(())
	}
}

// Not used, keeping for backward compatibility
impl Readable for TorAddress {
	fn read<R: Reader>(reader: &mut R) -> Result<TorAddress, ser::Error> {
		let address = String::from_utf8(reader.read_bytes_len_prefix()?);

		match address {
			Ok(address) => match canonical_onion_v3(&address) {
				Some(address) => Ok(TorAddress { address }),
				None => Err(ser::Error::CorruptedData(format!(
					"Invalid onion address string {}",
					address
				))),
			},
			Err(e) => Err(ser::Error::Utf8Conversion(e.to_string())),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::types::PeerAddr;
	use mwc_core::ser::{BinReader, BufReader, ProtocolVersion};
	use mwc_crates::bytes::Bytes;
	use std::io;
	use std::net::{IpAddr, Ipv4Addr, SocketAddr};

	const FUTURE_CAPABILITY_BIT: u32 = 0x0000_0100;

	fn test_hand(onion_sig: Option<[u8; ONION_PROOF_SIGNATURE_LEN]>) -> Hand {
		let onion_sig_timestamp = onion_sig.map(|_| 42);
		Hand {
			version: ProtocolVersion::local(),
			capabilities: Capabilities::UNKNOWN,
			nonce: 7,
			genesis: Hash::from_vec(&[]),
			total_difficulty: Difficulty::min(),
			sender_addr: PeerAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)),
			receiver_addr: PeerAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2)),
			user_agent: "test".to_string(),
			tx_fee_base: consensus::MILLI_MWC,
			onion_sig,
			onion_sig_timestamp,
		}
	}

	fn test_shake(user_agent_len: usize) -> Shake {
		Shake {
			version: ProtocolVersion(5),
			capabilities: Capabilities::UNKNOWN,
			genesis: Hash::from_vec(&[]),
			total_difficulty: Difficulty::min(),
			user_agent: "a".repeat(user_agent_len),
			tx_fee_base: consensus::MILLI_MWC,
		}
	}

	fn inject_handshake_capability_bits(bytes: &mut [u8], capab: u32) {
		bytes[4..8].copy_from_slice(&capab.to_be_bytes());
	}

	#[test]
	fn ban_reason_read_propagates_truncated_input() {
		let mut source = &[][..];
		let mut reader = BinReader::new(&mut source, ProtocolVersion::local(), 0);

		match BanReason::read(&mut reader) {
			Err(ser::Error::IOErr(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {}
			other => panic!("expected unexpected EOF, got {:?}", other),
		}
	}

	#[test]
	fn tor_address_read_accepts_valid_onion_v3() {
		let onion = "zwecav6dgftsoscybpzufbo77d452mk3mox2fqzjqocu7265bxgq6oad.onion";
		let bytes = ser::ser_vec(
			0,
			&TorAddress::new(onion.to_string()),
			ProtocolVersion::local(),
		)
		.unwrap();
		let address =
			ser::deserialize_strict::<TorAddress, _>(&mut &bytes[..], ProtocolVersion::local(), 0)
				.unwrap();

		assert_eq!(address.address, onion);
	}

	#[test]
	fn tor_address_read_rejects_invalid_onion() {
		let bytes = ser::ser_vec(
			0,
			&TorAddress::new("not-an-onion".to_string()),
			ProtocolVersion::local(),
		)
		.unwrap();
		let err =
			ser::deserialize_strict::<TorAddress, _>(&mut &bytes[..], ProtocolVersion::local(), 0)
				.unwrap_err();

		match err {
			ser::Error::CorruptedData(msg) => {
				assert!(msg.contains("Invalid onion address string not-an-onion"));
			}
			err => panic!("unexpected error: {:?}", err),
		}
	}

	#[test]
	fn tor_address_read_rejects_noncanonical_onion() {
		let onion = "ZWECAV6DGFTSOSCYBPZUFBO77D452MK3MOX2FQZJQOCU7265BXGQ6OAD.onion";
		let bytes = ser::ser_vec(
			0,
			&TorAddress::new(onion.to_string()),
			ProtocolVersion::local(),
		)
		.unwrap();
		let err =
			ser::deserialize_strict::<TorAddress, _>(&mut &bytes[..], ProtocolVersion::local(), 0)
				.unwrap_err();

		match err {
			ser::Error::CorruptedData(msg) => {
				assert!(msg.contains("Invalid onion address string"));
			}
			err => panic!("unexpected error: {:?}", err),
		}
	}

	#[test]
	fn hand_read_accepts_absent_onion_signature() {
		let bytes = ser::ser_vec(0, &test_hand(None), ProtocolVersion::local()).unwrap();
		let hand = ser::deserialize_strict::<Hand, _>(&mut &bytes[..], ProtocolVersion::local(), 0)
			.unwrap();

		assert!(hand.onion_sig.is_none());
		assert!(hand.onion_sig_timestamp.is_none());
	}

	#[test]
	fn hand_read_accepts_full_onion_proof() {
		let sig = [42u8; ONION_PROOF_SIGNATURE_LEN];
		let bytes = ser::ser_vec(0, &test_hand(Some(sig)), ProtocolVersion::local()).unwrap();
		let hand = ser::deserialize_strict::<Hand, _>(&mut &bytes[..], ProtocolVersion::local(), 0)
			.unwrap();

		assert_eq!(hand.onion_sig, Some(sig));
		assert_eq!(hand.onion_sig_timestamp, Some(42));
	}

	#[test]
	fn hand_read_silently_downgrades_unknown_capability_bits() {
		let known_capabilities = Capabilities::PEER_LIST | Capabilities::TX_KERNEL_HASH;
		let wire_capabilities = known_capabilities.bits() | FUTURE_CAPABILITY_BIT;
		assert!(Capabilities::from_bits(wire_capabilities).is_none());

		let mut bytes = ser::ser_vec(0, &test_hand(None), ProtocolVersion::local()).unwrap();
		inject_handshake_capability_bits(&mut bytes, wire_capabilities);

		let hand = ser::deserialize_strict::<Hand, _>(&mut &bytes[..], ProtocolVersion::local(), 0)
			.unwrap();

		assert_eq!(hand.capabilities, known_capabilities);
	}

	#[test]
	fn hand_read_rejects_user_agent_outside_printable_ascii() {
		for user_agent in [
			"bad\0agent",
			"bad\u{1b}[2Jagent",
			"bad\u{7f}agent",
			"bad\u{202e}agent",
			"bad\u{e9}agent",
		] {
			let mut hand = test_hand(None);
			hand.user_agent = user_agent.to_string();
			let bytes = ser::ser_vec(0, &hand, ProtocolVersion::local()).unwrap();

			match ser::deserialize_strict::<Hand, _>(&mut &bytes[..], ProtocolVersion::local(), 0) {
				Err(ser::Error::CorruptedData(msg)) => {
					assert!(
						msg.contains("Hand.user_agent contains character outside printable ASCII"),
						"{}",
						msg
					);
				}
				Ok(_) => panic!("expected non-printable ASCII user agent rejection"),
				Err(err) => panic!("expected corrupted data error, got {:?}", err),
			}
		}
	}

	#[test]
	fn hand_read_accepts_legacy_onion_signature_without_timestamp() {
		let sig = [42u8; ONION_PROOF_SIGNATURE_LEN];
		let mut bytes = ser::ser_vec(0, &test_hand(None), ProtocolVersion::local()).unwrap();
		bytes.extend_from_slice(&sig);

		let hand = ser::deserialize_strict::<Hand, _>(&mut &bytes[..], ProtocolVersion::local(), 0)
			.unwrap();

		assert_eq!(hand.onion_sig, Some(sig));
		assert!(hand.onion_sig_timestamp.is_none());
	}

	#[test]
	fn hand_read_rejects_partial_onion_signature() {
		let mut bytes = ser::ser_vec(0, &test_hand(None), ProtocolVersion::local()).unwrap();
		bytes.push(1);

		match ser::deserialize_permissive::<Hand, _>(&mut &bytes[..], ProtocolVersion::local(), 0) {
			Err(ser::Error::IOErr(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {}
			Ok(_) => panic!("expected partial signature EOF, got decoded Hand"),
			Err(err) => panic!("expected partial signature EOF, got {:?}", err),
		}
	}

	#[test]
	fn hand_read_rejects_partial_onion_signature_with_buf_reader() {
		let mut bytes =
			Bytes::from(ser::ser_vec(0, &test_hand(None), ProtocolVersion::local()).unwrap());
		let mut reader = BufReader::new(&mut bytes, ProtocolVersion::local(), 0);
		let hand: Hand = reader.body().unwrap();
		assert!(hand.onion_sig.is_none());

		let mut bytes = ser::ser_vec(0, &test_hand(None), ProtocolVersion::local()).unwrap();
		bytes.push(1);
		let mut bytes = Bytes::from(bytes);
		let mut reader = BufReader::new(&mut bytes, ProtocolVersion::local(), 0);

		match reader.body::<Hand>() {
			Err(ser::Error::IOErr(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {}
			Ok(_) => panic!("expected partial signature EOF, got decoded Hand"),
			Err(err) => panic!("expected partial signature EOF, got {:?}", err),
		}
	}

	#[test]
	fn hand_read_rejects_partial_onion_timestamp() {
		let sig = [42u8; ONION_PROOF_SIGNATURE_LEN];
		let mut bytes = ser::ser_vec(0, &test_hand(Some(sig)), ProtocolVersion::local()).unwrap();
		bytes.pop();

		match ser::deserialize_permissive::<Hand, _>(&mut &bytes[..], ProtocolVersion::local(), 0) {
			Err(ser::Error::IOErr(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {}
			Ok(_) => panic!("expected partial timestamp EOF, got decoded Hand"),
			Err(err) => panic!("expected partial timestamp EOF, got {:?}", err),
		}
	}

	#[test]
	fn hand_read_rejects_partial_onion_timestamp_with_buf_reader() {
		let sig = [42u8; ONION_PROOF_SIGNATURE_LEN];
		let mut bytes = ser::ser_vec(0, &test_hand(Some(sig)), ProtocolVersion::local()).unwrap();
		bytes.pop();
		let mut bytes = Bytes::from(bytes);
		let mut reader = BufReader::new(&mut bytes, ProtocolVersion::local(), 0);

		match reader.body::<Hand>() {
			Err(ser::Error::IOErr(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {}
			Ok(_) => panic!("expected partial timestamp EOF, got decoded Hand"),
			Err(err) => panic!("expected partial timestamp EOF, got {:?}", err),
		}
	}

	#[test]
	fn shake_read_rejects_user_agent_outside_printable_ascii() {
		for user_agent in [
			"bad\0agent",
			"bad\u{1b}[2Jagent",
			"bad\u{7f}agent",
			"bad\u{202e}agent",
			"bad\u{e9}agent",
		] {
			let mut shake = test_shake(0);
			shake.user_agent = user_agent.to_string();
			let bytes = ser::ser_vec(0, &shake, ProtocolVersion::local()).unwrap();

			match ser::deserialize_strict::<Shake, _>(&mut &bytes[..], ProtocolVersion::local(), 0)
			{
				Err(ser::Error::CorruptedData(msg)) => {
					assert!(
						msg.contains("Shake.user_agent contains character outside printable ASCII"),
						"{}",
						msg
					);
				}
				Ok(_) => panic!("expected non-printable ASCII user agent rejection"),
				Err(err) => panic!("expected corrupted data error, got {:?}", err),
			}
		}
	}

	#[test]
	fn shake_read_silently_downgrades_unknown_capability_bits() {
		let known_capabilities = Capabilities::PEER_LIST | Capabilities::TX_KERNEL_HASH;
		let wire_capabilities = known_capabilities.bits() | FUTURE_CAPABILITY_BIT;
		assert!(Capabilities::from_bits(wire_capabilities).is_none());

		let mut bytes = ser::ser_vec(0, &test_shake(0), ProtocolVersion::local()).unwrap();
		inject_handshake_capability_bits(&mut bytes, wire_capabilities);

		let shake =
			ser::deserialize_strict::<Shake, _>(&mut &bytes[..], ProtocolVersion::local(), 0)
				.unwrap();

		assert_eq!(shake.capabilities, known_capabilities);
	}

	#[test]
	fn shake_write_enforces_effective_message_limit() {
		let protocol_version = ProtocolVersion(5);
		let max_len = max_msg_size(0, Type::Shake) * 4;
		let fixed_len = 4 + 4 + 8 + 8 + 32 + 8;
		let max_user_agent_len = usize::try_from(max_len - fixed_len).unwrap();

		let bytes = ser::ser_vec(0, &test_shake(max_user_agent_len), protocol_version).unwrap();
		assert_eq!(bytes.len(), usize::try_from(max_len).unwrap());

		match ser::ser_vec(0, &test_shake(max_user_agent_len + 1), protocol_version) {
			Err(ser::Error::TooLargeWriteErr(message)) => {
				assert!(message.contains("Too large Shake write"));
			}
			Ok(_) => panic!("expected oversized Shake write to fail"),
			Err(err) => panic!("expected TooLargeWriteErr, got {:?}", err),
		}
	}

	#[test]
	fn headers_write_rejects_count_above_max_block_headers() {
		global::set_local_chain_type(global::ChainTypes::AutomatedTesting);
		let headers = Headers {
			headers: vec![BlockHeader::default(0); MAX_BLOCK_HEADERS as usize + 1],
		};

		match ser::ser_vec(0, &headers, ProtocolVersion::local()) {
			Err(ser::Error::TooLargeWriteErr(msg)) => {
				assert!(msg.contains("too many block headers"), "{}", msg);
			}
			Ok(_) => panic!("expected oversized headers write rejection"),
			Err(err) => panic!("expected too large write rejection, got {:?}", err),
		}
	}
}
