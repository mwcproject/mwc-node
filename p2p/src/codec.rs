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

//! Provides a connection wrapper that handles the lower level tasks in sending
//! or receiving data from the TCP socket, as well as dealing with timeouts.
//!
//! Because of a few idiosyncracies in the Rust `TcpStream`, this has to use
//! async I/O to be able to both read *and* write on the connection. Which
//! forces us to go through some additional gymnastic to loop over the async
//! stream and make sure we get the right number of bytes out.

use crate::msg::HeadersData;
use crate::msg::{Message, MsgHeader, MsgHeaderWrapper, Type};
use crate::tor::tcp_data_stream::TcpDataReadHalfStream;
use crate::types::{Error, MAX_BLOCK_HEADERS};
use mwc_core::core::block::{BlockHeader, UntrustedBlockHeader};
use mwc_core::global::header_size_bytes;
use mwc_core::ser::Reader;
use mwc_core::ser::{BufReader, ProtocolVersion, Readable};
use mwc_crates::bytes::{Buf, Bytes, BytesMut};
use std::cmp::min;
use std::convert::TryFrom;
use std::io::{self, Read};
use std::mem;
use std::time::{Duration, Instant};
use MsgHeaderWrapper::*;
use State::*;

const HEADER_IO_TIMEOUT: Duration = Duration::from_millis(1000);
pub const BODY_IO_TIMEOUT: Duration = Duration::from_millis(60000);
const HEADER_BATCH_SIZE: usize = 32;
const READ_CHUNK_SIZE: usize = 8 * 1024;

enum State {
	None,
	Header(MsgHeaderWrapper),
	BlockHeaders {
		bytes_left: usize,
		items_left: usize,
		headers: Vec<BlockHeader>,
	},
}

impl State {
	fn _is_none(&self) -> bool {
		match self {
			State::None => true,
			_ => false,
		}
	}
}

pub struct Codec {
	pub version: ProtocolVersion,
	context_id: u32,
	stream: TcpDataReadHalfStream,
	buffer: BytesMut,
	state: State,
	bytes_read: usize,
	body_deadline: Option<Instant>,
}

impl Codec {
	pub fn new(version: ProtocolVersion, context_id: u32, stream: TcpDataReadHalfStream) -> Self {
		Self {
			version,
			context_id,
			stream,
			buffer: BytesMut::with_capacity(8 * 1024),
			state: None,
			bytes_read: 0,
			body_deadline: Option::None,
		}
	}

	/// Destroy the codec and return the reader
	pub fn _stream(self) -> TcpDataReadHalfStream {
		self.stream
	}

	pub fn is_none_state(&self) -> bool {
		match self.state {
			None => true,
			_ => false,
		}
	}

	pub fn has_buffered_data(&self) -> bool {
		!self.buffer.is_empty()
	}

	/// Length of the next item we are expecting, could be msg header, body, block header or attachment chunk
	fn next_len(&self) -> Result<usize, Error> {
		match &self.state {
			None => Ok(MsgHeader::LEN),
			Header(Known(h)) if h.msg_type == Type::Headers => {
				// If we are receiving a list of headers, read off the item count first
				Ok(min(h.msg_len, 2))
			}
			Header(Known(header)) => Ok(header.msg_len),
			Header(Unknown(len, _)) => Ok(*len),
			BlockHeaders { bytes_left, .. } => {
				// The header length varies with the number of edge bits. Therefore we overestimate
				// its size and only actually read the bytes we need
				Ok(min(*bytes_left, header_size_bytes(self.context_id, 63)))
			}
		}
	}

	/// Set stream timeout for the next low-level read.
	fn set_stream_timeout(&mut self, timeout: Duration) -> Result<(), Error> {
		self.stream.set_read_timeout(timeout);
		Ok(())
	}

	fn read_deadline(&mut self) -> Instant {
		if matches!(&self.state, State::None) {
			Instant::now() + HEADER_IO_TIMEOUT
		} else {
			*self
				.body_deadline
				.get_or_insert_with(|| Instant::now() + BODY_IO_TIMEOUT)
		}
	}

	fn read_until_buffered(&mut self, next_len: usize) -> Result<(), Error> {
		let to_read = next_len.saturating_sub(self.buffer.len());
		if to_read == 0 {
			return Ok(());
		}

		self.buffer.reserve(to_read);
		let mut read_buf = vec![0; min(READ_CHUNK_SIZE, to_read)];
		let deadline = self.read_deadline();

		while self.buffer.len() < next_len {
			let timeout = deadline
				.checked_duration_since(Instant::now())
				.ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "read deadline elapsed"))?;
			if timeout.is_zero() {
				return Err(
					io::Error::new(io::ErrorKind::TimedOut, "read deadline elapsed").into(),
				);
			}

			self.set_stream_timeout(timeout)?;
			let remaining = next_len - self.buffer.len();
			let read_len = min(read_buf.len(), remaining);
			match self.stream.read(&mut read_buf[..read_len]) {
				Ok(0) => {
					return Err(io::Error::new(
						io::ErrorKind::UnexpectedEof,
						"failed to fill whole buffer",
					)
					.into())
				}
				Ok(read) => {
					self.buffer.extend_from_slice(&read_buf[..read]);
					self.bytes_read = self.bytes_read.checked_add(read).ok_or_else(|| {
						Error::DataOverflow(format!(
							"Codec::read_inner, bytes_read={} read={}",
							self.bytes_read, read
						))
					})?;
				}
				Err(e) => return Err(e.into()),
			}
		}

		Ok(())
	}

	fn read_inner(&mut self) -> Result<Message, Error> {
		self.bytes_read = 0;
		loop {
			let next_len = self.next_len()?;
			self.read_until_buffered(next_len)?;
			match &mut self.state {
				None => {
					// Parse header and keep reading
					let mut raw = self.buffer.split_to(next_len).freeze();
					let mut reader = BufReader::new(&mut raw, self.version, self.context_id);
					let header = MsgHeaderWrapper::read(&mut reader)?;
					self.state = Header(header);
				}
				Header(Known(header)) => {
					let mut raw = self.buffer.split_to(next_len).freeze();
					if header.msg_type == Type::Headers {
						// Special consideration for a list of headers, as we want to verify and process
						// them as they come in instead of only after the full list has been received
						let mut reader = BufReader::new(&mut raw, self.version, self.context_id);
						let items_left = reader.read_u16()? as usize;
						if items_left > MAX_BLOCK_HEADERS as usize {
							return Err(Error::BadMessage(format!(
								"Too many block headers: {}, max: {}",
								items_left, MAX_BLOCK_HEADERS
							)));
						}
						// Zero headers are not welcome as well - looks like a spam
						if items_left == 0 {
							return Err(Error::BadMessage("Empty headers message".into()));
						}
						self.state = BlockHeaders {
							bytes_left: header.msg_len.checked_sub(2).ok_or_else(|| {
								Error::DataOverflow(format!(
									"Codec::read_inner, msg_len={}",
									header.msg_len
								))
							})?,
							items_left,
							headers: Vec::with_capacity(min(HEADER_BATCH_SIZE, items_left)),
						};
					} else {
						// Return full message
						let msg = decode_message(header, &mut raw, self.version, self.context_id);
						self.state = None;
						self.body_deadline = Option::None;
						return msg;
					}
				}
				Header(Unknown(_, msg_type)) => {
					// Discard body and return
					let msg_type = *msg_type;
					self.buffer.advance(next_len);
					self.state = None;
					self.body_deadline = Option::None;
					return Ok(Message::Unknown(msg_type));
				}
				BlockHeaders {
					bytes_left,
					items_left,
					headers,
				} => {
					if *bytes_left == 0 {
						let items_left = *items_left;
						self.state = None;
						self.body_deadline = Option::None;
						if items_left > 0 {
							return Err(Error::BadMessage("Headers read error".into()));
						}
						return Ok(Message::Headers(HeadersData {
							headers: vec![],
							remaining: 0,
						}));
					}

					let mut reader =
						BufReader::new(&mut self.buffer, self.version, self.context_id);
					let header: UntrustedBlockHeader = reader.body()?;
					let bytes_read = usize::try_from(reader.bytes_read()).map_err(|_| {
						Error::DataOverflow(format!(
							"Codec::read_inner, bytes_read={}",
							reader.bytes_read()
						))
					})?;
					headers.push(header.into());
					*bytes_left = bytes_left.saturating_sub(bytes_read);
					*items_left = items_left.checked_sub(1).ok_or_else(|| {
						Error::DataOverflow(format!(
							"Codec::read_inner, items_left={}",
							*items_left
						))
					})?;
					let remaining = *items_left as u64;
					if headers.len() == HEADER_BATCH_SIZE || remaining == 0 {
						let mut h = Vec::with_capacity(min(HEADER_BATCH_SIZE, *items_left));
						mem::swap(headers, &mut h);
						if remaining == 0 {
							let bytes_left = *bytes_left;
							self.state = None;
							self.body_deadline = Option::None;
							if bytes_left > 0 {
								return Err(Error::BadMessage("Headers read error".into()));
							}
						}
						return Ok(Message::Headers(HeadersData {
							headers: h,
							remaining,
						}));
					}
				}
			}
		}
	}

	/// Blocking read of the next message
	pub fn read(&mut self) -> (Result<Message, Error>, usize) {
		let msg = self.read_inner();
		(msg, self.bytes_read)
	}
}

// TODO: replace with a macro?
fn decode_message(
	header: &MsgHeader,
	body: &mut Bytes,
	version: ProtocolVersion,
	context_id: u32,
) -> Result<Message, Error> {
	let mut msg = BufReader::new(body, version, context_id);
	let c = match header.msg_type {
		Type::Ping => Message::Ping(msg.body_full()?),
		Type::Pong => Message::Pong(msg.body_full()?),
		Type::BanReason => Message::BanReason(msg.body_full()?),
		Type::TransactionKernel => Message::TransactionKernel(msg.body_full()?),
		Type::GetTransaction => Message::GetTransaction(msg.body_full()?),
		Type::Transaction => Message::Transaction(msg.body_full()?),
		Type::StemTransaction => Message::StemTransaction(msg.body_full()?),
		Type::GetBlock => Message::GetBlock(msg.body_full()?),
		Type::Block => Message::Block(msg.body_full()?),
		Type::GetCompactBlock => Message::GetCompactBlock(msg.body_full()?),
		Type::CompactBlock => Message::CompactBlock(msg.body_full()?),
		Type::GetHeaders => Message::GetHeaders(msg.body_full()?),
		Type::Header => Message::Header(msg.body_full()?),
		Type::GetPeerAddrs => Message::GetPeerAddrs(msg.body_full()?),
		Type::PeerAddrs => Message::PeerAddrs(msg.body_full()?),
		Type::TxHashSetRequest => Message::TxHashSetRequest(msg.body_full()?),
		Type::TxHashSetArchive => Message::TxHashSetArchive(msg.body_full()?),
		Type::GetHeadersHashesSegment => Message::GetHeadersHashesSegment(msg.body_full()?),
		Type::OutputHeadersHashesSegment => Message::OutputHeadersHashesSegment(msg.body_full()?),
		Type::GetOutputBitmapSegment => Message::GetOutputBitmapSegment(msg.body_full()?),
		Type::OutputBitmapSegment => Message::OutputBitmapSegment(msg.body_full()?),
		Type::StartPibdSyncRequest => Message::StartPibdSyncRequest(msg.body_full()?),
		Type::StartHeadersHashRequest => Message::StartHeadersHashRequest(msg.body_full()?),
		Type::StartHeadersHashResponse => Message::StartHeadersHashResponse(msg.body_full()?),
		Type::PibdSyncState => Message::PibdSyncState(msg.body_full()?),
		Type::GetOutputSegment => Message::GetOutputSegment(msg.body_full()?),
		Type::OutputSegment => Message::OutputSegment(msg.body_full()?),
		Type::GetRangeProofSegment => Message::GetRangeProofSegment(msg.body_full()?),
		Type::RangeProofSegment => Message::RangeProofSegment(msg.body_full()?),
		Type::GetKernelSegment => Message::GetKernelSegment(msg.body_full()?),
		Type::KernelSegment => Message::KernelSegment(msg.body_full()?),
		Type::HasAnotherArchiveHeader => Message::HasAnotherArchiveHeader(msg.body_full()?),
		Type::Error | Type::Hand | Type::Shake | Type::Headers => {
			return Err(Error::UnexpectedMessage(format!(
				"get message with type {:?} (code {})",
				header.msg_type, header.msg_type as u32
			)))
		}
		// Note, Type::TorAddress is depricated and will be ignored. Keeping here for backward compatibility
		Type::TorAddress => Message::TorAddress(msg.body_full()?),
	};
	Ok(c)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::msg::Ping;
	use crate::tor::tcp_data_stream::TcpDataStream;
	use mwc_core::global::{self, ChainTypes};
	use mwc_core::pow::Difficulty;
	use mwc_core::ser::{self, BinWriter, Writeable, Writer};
	use mwc_crates::tokio::io::AsyncWriteExt;
	use mwc_crates::tokio::net::{TcpListener, TcpStream};

	fn codec_with_input(bytes: Vec<u8>) -> Codec {
		let async_rt = mwc_util::global_runtime().unwrap();
		let (mut client, server) = async_rt.block_on(async {
			let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
			let addr = listener.local_addr().unwrap();
			let client = TcpStream::connect(addr).await.unwrap();
			let (server, _) = listener.accept().await.unwrap();
			(client, server)
		});
		async_rt.block_on(async { client.write_all(&bytes).await.unwrap() });

		let stream = TcpDataStream::from_tcp(server);
		let (reader, _) = stream.split().unwrap();
		Codec::new(ProtocolVersion::local(), 0, reader)
	}

	fn setup() {
		mwc_util::init_global_runtime().unwrap();
		global::set_local_chain_type(ChainTypes::AutomatedTesting);
	}

	fn ping_body() -> Vec<u8> {
		let ping = Ping {
			total_difficulty: Difficulty::from_num(7),
			height: 42,
		};
		let mut bytes = Vec::new();
		let mut writer = BinWriter::new(&mut bytes, ProtocolVersion::local(), 0);
		ping.write(&mut writer).unwrap();
		bytes
	}

	fn headers_message_with_count_only(count: u16) -> Vec<u8> {
		let header = MsgHeader::new(0, Type::Headers, 2);
		let mut bytes = ser::ser_vec(0, &header, ProtocolVersion::local()).unwrap();
		let mut writer = BinWriter::new(&mut bytes, ProtocolVersion::local(), 0);
		writer.write_u16(count).unwrap();
		bytes
	}

	fn headers_message_with_len_and_count(msg_len: usize, count: u16) -> Vec<u8> {
		let header = MsgHeader::new(0, Type::Headers, msg_len);
		let mut bytes = ser::ser_vec(0, &header, ProtocolVersion::local()).unwrap();
		let mut writer = BinWriter::new(&mut bytes, ProtocolVersion::local(), 0);
		writer.write_u16(count).unwrap();
		bytes
	}

	fn partial_header_bytes() -> Vec<u8> {
		let header = MsgHeader::new(0, Type::Ping, 0);
		let mut bytes = ser::ser_vec(0, &header, ProtocolVersion::local()).unwrap();
		bytes.truncate(MsgHeader::LEN - 1);
		bytes
	}

	#[test]
	fn decode_message_accepts_exact_body() {
		setup();
		let bytes = ping_body();
		let header = MsgHeader::new(0, Type::Ping, bytes.len());
		let mut body = Bytes::from(bytes);

		match decode_message(&header, &mut body, ProtocolVersion::local(), 0) {
			Ok(Message::Ping(ping)) => assert_eq!(ping.height, 42),
			Ok(_) => panic!("expected ping message"),
			Err(err) => panic!("expected successful ping decode, got {:?}", err),
		}
	}

	#[test]
	fn decode_message_rejects_trailing_body_bytes() {
		setup();
		let mut bytes = ping_body();
		bytes.push(0);
		let header = MsgHeader::new(0, Type::Ping, bytes.len());
		let mut body = Bytes::from(bytes);

		match decode_message(&header, &mut body, ProtocolVersion::local(), 0) {
			Err(Error::Serialization(ser::Error::CorruptedData(msg))) => {
				assert!(msg.contains("Trailing bytes"), "{}", msg);
			}
			Ok(_) => panic!("expected trailing body byte rejection"),
			Err(err) => panic!("expected corrupted data rejection, got {:?}", err),
		}
	}

	#[test]
	fn headers_read_rejects_missing_declared_header_bytes() {
		setup();
		let mut codec = codec_with_input(headers_message_with_count_only(1));

		match codec.read_inner() {
			Err(Error::BadMessage(msg)) => assert!(msg.contains("Headers read error"), "{}", msg),
			Ok(_) => panic!("expected missing header bytes rejection"),
			Err(err) => panic!("expected bad message rejection, got {:?}", err),
		}
	}

	#[test]
	fn headers_read_rejects_count_above_max_block_headers() {
		setup();
		let mut codec = codec_with_input(headers_message_with_count_only(
			MAX_BLOCK_HEADERS as u16 + 1,
		));

		match codec.read_inner() {
			Err(Error::BadMessage(msg)) => {
				assert!(msg.contains("Too many block headers"), "{}", msg);
			}
			Ok(_) => panic!("expected oversized headers count rejection"),
			Err(err) => panic!("expected bad message rejection, got {:?}", err),
		}
	}

	#[test]
	fn headers_read_rejects_zero_count_with_non_empty_body() {
		setup();
		let mut codec = codec_with_input(headers_message_with_len_and_count(3, 0));

		match codec.read_inner() {
			Err(Error::BadMessage(msg)) => {
				assert!(msg.contains("Empty headers message"), "{}", msg)
			}
			Ok(_) => panic!("expected inconsistent headers body rejection"),
			Err(err) => panic!("expected bad message rejection, got {:?}", err),
		}
	}

	#[test]
	fn read_preserves_partial_header_bytes_on_error() {
		setup();
		let bytes = partial_header_bytes();
		let mut codec = codec_with_input(bytes.clone());

		let (msg, bytes_read) = codec.read();

		match msg {
			Err(Error::Connection(err)) => assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof),
			Ok(_) => panic!("expected truncated header rejection"),
			Err(err) => panic!("expected connection error, got {:?}", err),
		}
		assert_eq!(bytes_read, bytes.len());
		assert_eq!(codec.buffer.len(), bytes.len());
		assert_eq!(&codec.buffer[..], &bytes[..]);
		assert!(codec.is_none_state());
		assert!(codec.has_buffered_data());
	}
}
