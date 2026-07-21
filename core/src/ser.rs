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

//! Serialization and deserialization layer specialized for binary encoding.
//! Ensures consistency and safety. Basically a minimal subset or
//! rustc_serialize customized for our need.
//!
//! To use it simply implement `Writeable` or `Readable` and then use the
//! `serialize` or `deserialize` functions on them as appropriate.

use crate::core::hash::{DefaultHashable, Hash, Hashed};
use crate::global::PROTOCOL_VERSION;
use keychain::{BlindingFactor, Identifier, IDENTIFIER_SIZE};
use mwc_crates::byteorder::{BigEndian, ByteOrder};
use mwc_crates::bytes::Buf;
use mwc_crates::secp;
use mwc_crates::secp::constants::{
	AGG_SIGNATURE_SIZE, COMPRESSED_PUBLIC_KEY_SIZE, MAX_PROOF_SIZE, PEDERSEN_COMMITMENT_SIZE,
	SECRET_KEY_SIZE,
};
use mwc_crates::secp::key::PublicKey;
use mwc_crates::secp::pedersen::{Commitment, RangeProof};
use mwc_crates::secp::AggSigSignature;
use mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_crates::zeroize::Zeroizing;
use std::fmt::{self, Debug};
use std::io::{self, Read, Write};
use std::{cmp, marker};
use util::secp_static;

/// Serialization size limit for a single chunk/object or array.
/// WARNING!!! You can increase the number, but never decrease
pub const READ_CHUNK_LIMIT: usize = 100_000;
/// Serialization size limit for number in arrays.
/// WARNING!!! You can increase the number, but never decrease
pub const READ_VEC_SIZE_LIMIT: u64 = 100_000;

/// Possible errors deriving from serializing or deserializing.
#[derive(thiserror::Error, Debug)]
pub enum Error {
	/// Wraps an io error produced when reading or writing
	#[error("Serialization IO error {0}")]
	IOErr(#[from] io::Error),
	/// Wraps secp256k1 error
	#[error("Serialization Secp error, {0}")]
	SecpError(secp::Error),
	/// Expected a given value that wasn't found
	#[error("Unexpected Data, expected {expected:?}, got {received:?}")]
	UnexpectedData {
		/// What we wanted
		expected: Vec<u8>,
		/// What we got
		received: Vec<u8>,
	},
	/// Data wasn't in a consumable format
	#[error("Serialization Corrupted data, {0}")]
	CorruptedData(String),
	/// Data overflow error
	#[error("Serialization data overflow error, {0}")]
	DataOverflow(String),
	/// Incorrect number of elements (when deserializing a vec via read_multi say).
	#[error("Serialization Count error, {0}")]
	CountError(String),
	/// When asked to read too much data
	#[error("Serialization Too large write, {0}")]
	TooLargeWriteErr(String),
	/// When asked to read too much data
	#[error("Serialization Too large read, {0}")]
	TooLargeReadErr(String),
	/// Error from from_hex deserialization
	#[error("Serialization Hex error {0}")]
	HexError(String),
	/// Inputs/outputs/kernels must be sorted lexicographically.
	#[error("Serialization Broken Sort order")]
	SortError,
	/// Inputs/outputs/kernels must be unique.
	#[error("Serialization Unexpected Duplicate")]
	DuplicateError,
	/// Block header version (hard-fork schedule).
	#[error("Serialization Invalid block version, {0}")]
	InvalidBlockVersion(String),
	/// utf8 conversion failed
	#[error("UTF8 conversion failed")]
	Utf8Conversion(String),
	/// Unsupported protocol version
	#[error("unsupported protocol version, {0}")]
	UnsupportedProtocolVersion(String),
}

impl From<secp::Error> for Error {
	fn from(e: secp::Error) -> Error {
		Error::SecpError(e)
	}
}

/// Signal to a serializable object how much of its data should be serialized
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum SerializationMode {
	/// Serialize everything sufficiently to fully reconstruct the object
	Full,
	/// Serialize the data that defines the object
	Hash,
}

impl SerializationMode {
	/// Hash mode?
	pub fn is_hash_mode(&self) -> bool {
		match self {
			SerializationMode::Hash => true,
			_ => false,
		}
	}
}

/// Implementations defined how different numbers and binary structures are
/// written to an underlying stream or container (depending on implementation).
pub trait Writer {
	/// The mode this serializer is writing in
	fn serialization_mode(&self) -> SerializationMode;

	/// Protocol version for version specific serialization rules.
	fn protocol_version(&self) -> ProtocolVersion;

	/// Return context Id for this writing session
	fn get_context_id(&self) -> u32;

	/// Writes a u8 as bytes
	fn write_u8(&mut self, n: u8) -> Result<(), Error> {
		self.write_fixed_bytes(&[n])
	}

	/// Writes a u16 as bytes
	fn write_u16(&mut self, n: u16) -> Result<(), Error> {
		let mut bytes = [0; 2];
		BigEndian::write_u16(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a u32 as bytes
	fn write_u32(&mut self, n: u32) -> Result<(), Error> {
		let mut bytes = [0; 4];
		BigEndian::write_u32(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a u32 as bytes
	fn write_i32(&mut self, n: i32) -> Result<(), Error> {
		let mut bytes = [0; 4];
		BigEndian::write_i32(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a u64 as bytes
	fn write_u64(&mut self, n: u64) -> Result<(), Error> {
		let mut bytes = [0; 8];
		BigEndian::write_u64(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a i64 as bytes
	fn write_i64(&mut self, n: i64) -> Result<(), Error> {
		let mut bytes = [0; 8];
		BigEndian::write_i64(&mut bytes, n);
		self.write_fixed_bytes(&bytes)
	}

	/// Writes a variable number of bytes. The length is encoded as a 64-bit
	/// prefix.
	fn write_bytes<T: AsRef<[u8]>>(&mut self, bytes: T) -> Result<(), Error> {
		self.write_u64(bytes.as_ref().len() as u64)?;
		self.write_fixed_bytes(bytes)
	}

	/// Writes a fixed number of bytes. The reader is expected to know the actual length on read.
	fn write_fixed_bytes<T: AsRef<[u8]>>(&mut self, bytes: T) -> Result<(), Error>;

	/// Writes a fixed length of "empty" bytes.
	fn write_empty_bytes(&mut self, length: usize) -> Result<(), Error> {
		self.write_fixed_bytes(vec![0u8; length])
	}
}

/// Implementations defined how different numbers and binary structures are
/// read from an underlying stream or container (depending on implementation).
pub trait Reader {
	/// Total bytes consumed by this reader.
	fn bytes_read(&self) -> u64;
	/// True when this reader can prove unread bytes are still buffered.
	fn has_pending_data(&self) -> bool {
		false
	}
	/// Read a u8 from the underlying Read
	fn read_u8(&mut self) -> Result<u8, Error>;
	/// Read a u16 from the underlying Read
	fn read_u16(&mut self) -> Result<u16, Error>;
	/// Read a u32 from the underlying Read
	fn read_u32(&mut self) -> Result<u32, Error>;
	/// Read a u64 from the underlying Read
	fn read_u64(&mut self) -> Result<u64, Error>;
	/// Read a i32 from the underlying Read
	fn read_i32(&mut self) -> Result<i32, Error>;
	/// Read a i64 from the underlying Read
	fn read_i64(&mut self) -> Result<i64, Error>;
	/// Read a u64 len prefix followed by that number of exact bytes.
	fn read_bytes_len_prefix(&mut self) -> Result<Vec<u8>, Error>;
	/// Read a fixed number of bytes from the underlying reader.
	fn read_fixed_bytes(&mut self, length: usize) -> Result<Vec<u8>, Error>;
	/// Consumes a byte from the reader, producing an error if it doesn't have
	/// the expected value
	fn expect_u8(&mut self, val: u8) -> Result<u8, Error>;
	/// Access to underlying protocol version to support
	/// version specific deserialization logic.
	fn protocol_version(&self) -> ProtocolVersion;

	/// Return context Id for this reading session
	fn get_context_id(&self) -> u32;

	/// Read a fixed number of "empty" bytes from the underlying reader.
	/// It is an error if any non-empty bytes encountered.
	fn read_empty_bytes(&mut self, length: usize) -> Result<(), Error> {
		for _ in 0..length {
			if self.read_u8()? != 0u8 {
				return Err(Error::CorruptedData(
					"Not found expected 'empty' bytes".to_string(),
				));
			}
		}
		Ok(())
	}
}

/// Trait that every type that can be serialized as binary must implement.
/// Writes directly to a Writer, a utility type thinly wrapping an
/// underlying Write implementation.
pub trait Writeable {
	/// Write the data held by this Writeable to the provided writer
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error>;
}

/// Reader that exposes an Iterator interface.
pub struct IteratingReader<'a, T, R: Reader> {
	count: u64,
	curr: u64,
	reader: &'a mut R,
	_marker: marker::PhantomData<T>,
}

impl<'a, T, R: Reader> IteratingReader<'a, T, R> {
	/// Constructor to create a new iterating reader for the provided underlying reader.
	/// Takes a count so we know how many to iterate over.
	pub fn new(reader: &'a mut R, count: u64) -> Self {
		let curr = 0;
		IteratingReader {
			count,
			curr,
			reader,
			_marker: marker::PhantomData,
		}
	}
}

impl<'a, T, R> Iterator for IteratingReader<'a, T, R>
where
	T: Readable,
	R: Reader,
{
	type Item = Result<T, Error>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.curr >= self.count {
			return None;
		}
		self.curr += 1;
		Some(T::read(self.reader))
	}
}

/// Reads multiple serialized items into a Vec.
pub fn read_multi<T, R>(reader: &mut R, count: u64) -> Result<Vec<T>, Error>
where
	T: Readable,
	R: Reader,
{
	// Very rudimentary check to ensure we do not overflow anything
	// attempting to read huge amounts of data.
	// Probably better than checking if count * size overflows a u64 though.
	// Note!!! Caller on Write responsible to data size checking.
	// This issue normally should never happen. If you see this error, it is mean there are
	// data validation issue at write method.
	debug_assert!(count <= READ_VEC_SIZE_LIMIT);
	if count > READ_VEC_SIZE_LIMIT {
		return Err(Error::TooLargeReadErr(format!(
			"Try to read {} items, limit is 100K",
			count
		)));
	}

	let res: Vec<T> = IteratingReader::new(reader, count).collect::<Result<Vec<T>, Error>>()?;
	Ok(res)
}

/// Protocol version for serialization/deserialization.
/// Note: This is used in various places including but limited to
/// the p2p layer and our local db storage layer.
/// We may speak multiple versions to various peers and a potentially *different*
/// version for our local db.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialOrd, PartialEq, Serialize)]
#[serde(crate = "serde")]
pub struct ProtocolVersion(pub u32);

impl ProtocolVersion {
	/// The max protocol version supported.
	pub const MAX: u32 = std::u32::MAX;

	/// Protocol version as u32 to allow for convenient exhaustive matching on values.
	pub fn value(self) -> u32 {
		self.0
	}

	/// Our default "local" protocol version.
	/// This protocol version is provided to peers as part of the Hand/Shake
	/// negotiation in the p2p layer. Connected peers will negotiate a suitable
	/// protocol version for serialization/deserialization of p2p messages.
	pub fn local() -> ProtocolVersion {
		PROTOCOL_VERSION
	}

	/// We need to specify a protocol version for our local database.
	/// Regardless of specific version used when sending/receiving data between peers
	/// we need to take care with serialization/deserialization of data locally in the db.
	pub fn local_db() -> ProtocolVersion {
		ProtocolVersion(1)
	}
}

impl fmt::Display for ProtocolVersion {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl From<ProtocolVersion> for u32 {
	fn from(v: ProtocolVersion) -> u32 {
		v.0
	}
}

impl Writeable for ProtocolVersion {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_u32(self.0)
	}
}

impl Readable for ProtocolVersion {
	fn read<R: Reader>(reader: &mut R) -> Result<ProtocolVersion, Error> {
		let version = reader.read_u32()?;
		Ok(ProtocolVersion(version))
	}
}

/// Trait that every type that can be deserialized from binary must implement.
/// Reads directly to a Reader, a utility type thinly wrapping an
/// underlying Read implementation.
pub trait Readable
where
	Self: Sized,
{
	/// Reads the data necessary to this Readable from the provided reader
	fn read<R: Reader>(reader: &mut R) -> Result<Self, Error>;
}

/// Deserializes a Readable and requires the input to end exactly after it.
pub fn deserialize_strict<T: Readable, R: Read>(
	source: &mut R,
	version: ProtocolVersion,
	context_id: u32,
) -> Result<T, Error> {
	let mut reader = BinReader::new(source, version, context_id);
	let value = T::read(&mut reader)?;
	reader.expect_end()?;
	Ok(value)
}

/// Deserializes a Readable while allowing forward-compatible trailing bytes.
pub fn deserialize_permissive<T: Readable, R: Read>(
	source: &mut R,
	version: ProtocolVersion,
	context_id: u32,
) -> Result<T, Error> {
	let mut reader = BinReader::new(source, version, context_id);
	T::read(&mut reader)
}

/// Deserialize a Readable based on our default "local" protocol version.
pub fn deserialize_default<T: Readable, R: Read>(
	context_id: u32,
	source: &mut R,
) -> Result<T, Error> {
	deserialize_strict(source, ProtocolVersion::local(), context_id)
}

/// Serializes a Writeable into any std::io::Write implementation.
pub fn serialize<W: Writeable>(
	sink: &mut dyn Write,
	version: ProtocolVersion,
	context_id: u32,
	thing: &W,
) -> Result<(), Error> {
	let mut writer = BinWriter::new(sink, version, context_id);
	thing.write(&mut writer)
}

/// Serialize a Writeable according to our default "local" protocol version.
pub fn serialize_default<W: Writeable>(
	context_id: u32,
	sink: &mut dyn Write,
	thing: &W,
) -> Result<(), Error> {
	serialize(sink, ProtocolVersion::local(), context_id, thing)
}

/// Utility function to serialize a writeable directly in memory using a
/// Vec<u8>.
pub fn ser_vec<W: Writeable>(
	context_id: u32,
	thing: &W,
	version: ProtocolVersion,
) -> Result<Vec<u8>, Error> {
	let mut vec = vec![];
	serialize(&mut vec, version, context_id, thing)?;
	Ok(vec)
}

/// Utility to read from a binary source
pub struct BinReader<'a, R: Read> {
	source: &'a mut R,
	version: ProtocolVersion,
	context_id: u32,
	bytes_read: u64,
}

impl<'a, R: Read> BinReader<'a, R> {
	/// Constructor for a new BinReader for the provided source and protocol version.
	pub fn new(source: &'a mut R, version: ProtocolVersion, context_id: u32) -> Self {
		BinReader {
			source,
			version,
			context_id,
			bytes_read: 0,
		}
	}

	fn read_exact_counted(&mut self, buf: &mut [u8]) -> Result<(), Error> {
		read_exact_counted(self.source, buf, &mut self.bytes_read)
	}

	fn expect_end(&mut self) -> Result<(), Error> {
		let mut buf = [0u8; 1];
		loop {
			match self.source.read(&mut buf) {
				Ok(0) => return Ok(()),
				Ok(_) => {
					return Err(Error::CorruptedData(
						"Trailing bytes after serialized object".to_string(),
					));
				}
				Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
				Err(err) => return Err(map_io_err(err)),
			}
		}
	}
}

fn map_io_err(err: io::Error) -> Error {
	Error::IOErr(err)
}

fn add_bytes_read(bytes_read: &mut u64, read: usize) -> Result<(), Error> {
	*bytes_read = bytes_read
		.checked_add(read as u64)
		.ok_or_else(|| Error::DataOverflow("bytes read counter overflow".to_string()))?;
	Ok(())
}

fn read_exact_counted<R: Read + ?Sized>(
	source: &mut R,
	buf: &mut [u8],
	bytes_read: &mut u64,
) -> Result<(), Error> {
	let mut read = 0;
	while read < buf.len() {
		match source.read(&mut buf[read..]) {
			Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
			Ok(n) => {
				add_bytes_read(bytes_read, n)?;
				read += n;
			}
			Err(ref err) if err.kind() == io::ErrorKind::Interrupted => {}
			Err(err) => return Err(map_io_err(err)),
		}
	}
	Ok(())
}

fn check_len(len: u64) -> Result<usize, Error> {
	if len > READ_CHUNK_LIMIT as u64 {
		return Err(Error::TooLargeReadErr(format!(
			"Try to read {} bytes, limit is 100K",
			len
		)));
	}
	if len > usize::MAX as u64 {
		return Err(Error::DataOverflow(format!(
			"Length prefix {} exceeds usize::MAX",
			len
		)));
	}
	Ok(len as usize)
}

/// Utility wrapper for an underlying byte Reader. Defines higher level methods
/// to read numbers, byte vectors, hashes, etc.
impl<'a, R: Read> Reader for BinReader<'a, R> {
	fn bytes_read(&self) -> u64 {
		self.bytes_read
	}
	fn read_u8(&mut self) -> Result<u8, Error> {
		let mut buf = [0u8; 1];
		self.read_exact_counted(&mut buf)?;
		Ok(buf[0])
	}
	fn read_u16(&mut self) -> Result<u16, Error> {
		let mut buf = [0u8; 2];
		self.read_exact_counted(&mut buf)?;
		Ok(BigEndian::read_u16(&buf))
	}
	fn read_u32(&mut self) -> Result<u32, Error> {
		let mut buf = [0u8; 4];
		self.read_exact_counted(&mut buf)?;
		Ok(BigEndian::read_u32(&buf))
	}
	fn read_i32(&mut self) -> Result<i32, Error> {
		let mut buf = [0u8; 4];
		self.read_exact_counted(&mut buf)?;
		Ok(BigEndian::read_i32(&buf))
	}
	fn read_u64(&mut self) -> Result<u64, Error> {
		let mut buf = [0u8; 8];
		self.read_exact_counted(&mut buf)?;
		Ok(BigEndian::read_u64(&buf))
	}
	fn read_i64(&mut self) -> Result<i64, Error> {
		let mut buf = [0u8; 8];
		self.read_exact_counted(&mut buf)?;
		Ok(BigEndian::read_i64(&buf))
	}
	/// Read a variable size vector from the underlying Read. Expects a usize
	fn read_bytes_len_prefix(&mut self) -> Result<Vec<u8>, Error> {
		let len = self.read_u64()?;
		self.read_fixed_bytes(check_len(len)?)
	}

	/// Read a fixed number of bytes.
	fn read_fixed_bytes(&mut self, len: usize) -> Result<Vec<u8>, Error> {
		// not reading more than 100k bytes in a single read
		if len > READ_CHUNK_LIMIT {
			return Err(Error::TooLargeReadErr(format!(
				"Try to read {} bytes, limit is 100K",
				len
			)));
		}
		let mut buf = vec![0; len];
		self.read_exact_counted(&mut buf)?;
		Ok(buf)
	}

	fn expect_u8(&mut self, val: u8) -> Result<u8, Error> {
		let b = self.read_u8()?;
		if b == val {
			Ok(b)
		} else {
			Err(Error::UnexpectedData {
				expected: vec![val],
				received: vec![b],
			})
		}
	}

	fn protocol_version(&self) -> ProtocolVersion {
		self.version
	}

	fn get_context_id(&self) -> u32 {
		self.context_id
	}
}

/// A reader that reads straight off a stream.
/// Tracks total bytes read so we can verify we read the right number afterwards.
pub struct StreamingReader<'a> {
	total_bytes_read: u64,
	version: ProtocolVersion,
	context_id: u32,
	stream: &'a mut dyn Read,
}

impl<'a> StreamingReader<'a> {
	/// Create a new streaming reader with the provided underlying stream.
	/// Also takes a duration to be used for each individual read_exact call.
	pub fn new(
		stream: &'a mut dyn Read,
		version: ProtocolVersion,
		context_id: u32,
	) -> StreamingReader<'a> {
		StreamingReader {
			total_bytes_read: 0,
			version,
			context_id,
			stream,
		}
	}

	/// Returns the total bytes read via this streaming reader.
	pub fn total_bytes_read(&self) -> u64 {
		self.total_bytes_read
	}
}

/// Note: We use read_fixed_bytes() here to ensure our "async" I/O behaves as expected.
impl<'a> Reader for StreamingReader<'a> {
	fn bytes_read(&self) -> u64 {
		self.total_bytes_read
	}
	fn read_u8(&mut self) -> Result<u8, Error> {
		let buf = self.read_fixed_bytes(1)?;
		Ok(buf[0])
	}
	fn read_u16(&mut self) -> Result<u16, Error> {
		let buf = self.read_fixed_bytes(2)?;
		Ok(BigEndian::read_u16(&buf[..]))
	}
	fn read_u32(&mut self) -> Result<u32, Error> {
		let buf = self.read_fixed_bytes(4)?;
		Ok(BigEndian::read_u32(&buf[..]))
	}
	fn read_i32(&mut self) -> Result<i32, Error> {
		let buf = self.read_fixed_bytes(4)?;
		Ok(BigEndian::read_i32(&buf[..]))
	}
	fn read_u64(&mut self) -> Result<u64, Error> {
		let buf = self.read_fixed_bytes(8)?;
		Ok(BigEndian::read_u64(&buf[..]))
	}
	fn read_i64(&mut self) -> Result<i64, Error> {
		let buf = self.read_fixed_bytes(8)?;
		Ok(BigEndian::read_i64(&buf[..]))
	}

	/// Read a variable size vector from the underlying stream. Expects a usize
	fn read_bytes_len_prefix(&mut self) -> Result<Vec<u8>, Error> {
		let len = self.read_u64()?;
		self.read_fixed_bytes(check_len(len)?)
	}

	/// Read a fixed number of bytes.
	fn read_fixed_bytes(&mut self, len: usize) -> Result<Vec<u8>, Error> {
		// not reading more than 100k bytes in a single read
		if len > READ_CHUNK_LIMIT {
			return Err(Error::TooLargeReadErr(format!(
				"Try to read {} bytes, limit is 100K",
				len
			)));
		}
		let mut buf = vec![0u8; len];
		read_exact_counted(self.stream, &mut buf, &mut self.total_bytes_read)?;
		Ok(buf)
	}

	fn expect_u8(&mut self, val: u8) -> Result<u8, Error> {
		let b = self.read_u8()?;
		if b == val {
			Ok(b)
		} else {
			Err(Error::UnexpectedData {
				expected: vec![val],
				received: vec![b],
			})
		}
	}

	fn protocol_version(&self) -> ProtocolVersion {
		self.version
	}

	fn get_context_id(&self) -> u32 {
		self.context_id
	}
}

/// Protocol version-aware wrapper around a `Buf` impl
pub struct BufReader<'a, B: Buf> {
	inner: &'a mut B,
	version: ProtocolVersion,
	context_id: u32,
	bytes_read: u64,
}

impl<'a, B: Buf> BufReader<'a, B> {
	/// Construct a new BufReader
	pub fn new(buf: &'a mut B, version: ProtocolVersion, context_id: u32) -> Self {
		Self {
			inner: buf,
			version,
			context_id,
			bytes_read: 0,
		}
	}

	/// Check whether the buffer has enough bytes remaining to perform a read
	fn has_remaining(&mut self, len: usize) -> Result<(), Error> {
		if self.inner.remaining() >= len {
			// Safe: bytes_read tracks bytes consumed from this buffer, and the
			// remaining-byte check guarantees this read stays within the buffer's
			// original usize-sized length.
			add_bytes_read(&mut self.bytes_read, len)?;
			Ok(())
		} else {
			Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
		}
	}

	/// The total bytes read
	pub fn bytes_read(&self) -> u64 {
		self.bytes_read
	}

	/// Convenience function to read from the buffer and deserialize
	pub fn body<T: Readable>(&mut self) -> Result<T, Error> {
		T::read(self)
	}

	/// Deserialize a complete body, rejecting bytes left in the buffer.
	pub fn body_full<T: Readable>(&mut self) -> Result<T, Error> {
		let body = T::read(self)?;
		if self.inner.has_remaining() {
			return Err(Error::CorruptedData(format!(
				"Trailing bytes after serialized body: {} bytes",
				self.inner.remaining()
			)));
		}
		Ok(body)
	}
}

impl<'a, B: Buf> Reader for BufReader<'a, B> {
	fn bytes_read(&self) -> u64 {
		self.bytes_read
	}

	fn has_pending_data(&self) -> bool {
		self.inner.has_remaining()
	}

	fn read_u8(&mut self) -> Result<u8, Error> {
		self.has_remaining(1)?;
		Ok(self.inner.get_u8())
	}

	fn read_u16(&mut self) -> Result<u16, Error> {
		self.has_remaining(2)?;
		Ok(self.inner.get_u16())
	}

	fn read_u32(&mut self) -> Result<u32, Error> {
		self.has_remaining(4)?;
		Ok(self.inner.get_u32())
	}

	fn read_u64(&mut self) -> Result<u64, Error> {
		self.has_remaining(8)?;
		Ok(self.inner.get_u64())
	}

	fn read_i32(&mut self) -> Result<i32, Error> {
		self.has_remaining(4)?;
		Ok(self.inner.get_i32())
	}

	fn read_i64(&mut self) -> Result<i64, Error> {
		self.has_remaining(8)?;
		Ok(self.inner.get_i64())
	}

	fn read_bytes_len_prefix(&mut self) -> Result<Vec<u8>, Error> {
		let len = self.read_u64()?;
		self.read_fixed_bytes(check_len(len)?)
	}

	fn read_fixed_bytes(&mut self, len: usize) -> Result<Vec<u8>, Error> {
		// not reading more than 100k bytes in a single read
		if len > 100_000 {
			return Err(Error::TooLargeReadErr(format!(
				"read unexpected large chunk of {} bytes",
				len
			)));
		}
		self.has_remaining(len)?;

		let mut buf = vec![0; len];
		self.inner.copy_to_slice(&mut buf[..]);
		Ok(buf)
	}

	fn expect_u8(&mut self, val: u8) -> Result<u8, Error> {
		let b = self.read_u8()?;
		if b == val {
			Ok(b)
		} else {
			Err(Error::UnexpectedData {
				expected: vec![val],
				received: vec![b],
			})
		}
	}

	fn protocol_version(&self) -> ProtocolVersion {
		self.version
	}

	fn get_context_id(&self) -> u32 {
		self.context_id
	}
}

impl Readable for Commitment {
	fn read<R: Reader>(reader: &mut R) -> Result<Commitment, Error> {
		let a = reader.read_fixed_bytes(PEDERSEN_COMMITMENT_SIZE)?;
		let mut c = [0; PEDERSEN_COMMITMENT_SIZE];
		c[..PEDERSEN_COMMITMENT_SIZE].clone_from_slice(&a[..PEDERSEN_COMMITMENT_SIZE]);
		let commit = Commitment(c);
		secp_static::with_commit(Error::from, |secp| {
			secp.validate_commitment(&commit).map_err(|e| {
				Error::CorruptedData(format!("Unable to read Pedersen commitment, {}", e))
			})
		})?;
		Ok(commit)
	}
}

impl Writeable for Commitment {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_fixed_bytes(self)
	}
}

impl Writeable for BlindingFactor {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_fixed_bytes(self)
	}
}

impl Readable for BlindingFactor {
	fn read<R: Reader>(reader: &mut R) -> Result<BlindingFactor, Error> {
		let bytes = Zeroizing::new(reader.read_fixed_bytes(SECRET_KEY_SIZE)?);
		BlindingFactor::from_slice(&bytes)
			.map_err(|e| Error::CorruptedData(format!("BlindingFactor read error, {}", e)))
	}
}

impl Writeable for Identifier {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		writer.write_fixed_bytes(self)
	}
}

impl Readable for Identifier {
	fn read<R: Reader>(reader: &mut R) -> Result<Identifier, Error> {
		let bytes = reader.read_fixed_bytes(IDENTIFIER_SIZE)?;
		Identifier::from_bytes(&bytes)
			.map_err(|e| Error::CorruptedData(format!("corrupted Identifier data, {}", e)))
	}
}

impl Writeable for RangeProof {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		if self.plen > MAX_PROOF_SIZE {
			return Err(Error::TooLargeWriteErr(format!(
				"RangeProof length {}, but max is {}",
				self.plen, MAX_PROOF_SIZE
			)));
		}
		writer.write_bytes(self)
	}
}

impl Readable for RangeProof {
	fn read<R: Reader>(reader: &mut R) -> Result<RangeProof, Error> {
		let len = reader.read_u64()?;
		if len > MAX_PROOF_SIZE as u64 {
			return Err(Error::TooLargeReadErr(format!(
				"RangeProof length {}, but max is {}",
				len, MAX_PROOF_SIZE
			)));
		}
		let max_len = cmp::min(len as usize, MAX_PROOF_SIZE);
		let p = reader.read_fixed_bytes(max_len)?;
		let mut proof = [0; MAX_PROOF_SIZE];
		proof[..p.len()].clone_from_slice(&p[..]);
		Ok(RangeProof {
			plen: p.len(),
			proof,
		})
	}
}

/// Fixed-size on-disk PMMR representation for range proofs.
///
/// Ordinary RangeProof serialization writes only `plen` bytes. The rangeproof
/// PMMR uses fixed-size storage, so its element format stores the logical
/// length followed by a zero-padded proof buffer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RangeProofPmmr {
	proof: RangeProof,
}

impl RangeProofPmmr {
	/// Return the logical range proof without PMMR padding.
	pub fn into_inner(self) -> RangeProof {
		self.proof
	}
}

impl From<RangeProof> for RangeProofPmmr {
	fn from(proof: RangeProof) -> Self {
		RangeProofPmmr { proof }
	}
}

impl From<RangeProofPmmr> for RangeProof {
	fn from(proof: RangeProofPmmr) -> Self {
		proof.into_inner()
	}
}

impl PMMRIndexHashable for RangeProofPmmr {
	fn hash_with_index(&self, context_id: u32, index: u64) -> Result<Hash, std::io::Error> {
		self.proof.hash_with_index(context_id, index)
	}
}

impl Writeable for RangeProofPmmr {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		if self.proof.plen > MAX_PROOF_SIZE {
			return Err(Error::TooLargeWriteErr(format!(
				"RangeProof PMMR length {}, but max is {}",
				self.proof.plen, MAX_PROOF_SIZE
			)));
		}

		writer.write_u64(self.proof.plen as u64)?;
		let mut proof = [0; MAX_PROOF_SIZE];
		proof[..self.proof.plen].copy_from_slice(&self.proof.proof[..self.proof.plen]);
		writer.write_fixed_bytes(&proof)
	}
}

impl Readable for RangeProofPmmr {
	fn read<R: Reader>(reader: &mut R) -> Result<RangeProofPmmr, Error> {
		let len = reader.read_u64()?;
		if len > MAX_PROOF_SIZE as u64 {
			return Err(Error::TooLargeReadErr(format!(
				"RangeProof PMMR length {}, but max is {}",
				len, MAX_PROOF_SIZE
			)));
		}
		// Conversion is safe becasue len is capped by the small constant MAX_PROOF_SIZE
		let plen = len as usize;
		let p = reader.read_fixed_bytes(MAX_PROOF_SIZE)?;
		if p[plen..].iter().any(|&b| b != 0) {
			return Err(Error::CorruptedData(
				"RangeProof PMMR element contains non-zero padding".to_string(),
			));
		}
		let mut proof = [0; MAX_PROOF_SIZE];
		proof[..plen].clone_from_slice(&p[..plen]);
		Ok(RangeProofPmmr {
			proof: RangeProof { plen, proof },
		})
	}
}

impl PMMRable for RangeProof {
	type E = RangeProofPmmr;

	fn as_elmt(&self) -> Result<RangeProofPmmr, Error> {
		if self.plen > MAX_PROOF_SIZE {
			return Err(Error::CorruptedData(format!(
				"RangeProof PMMR element length {}, max {}",
				self.plen, MAX_PROOF_SIZE
			)));
		}
		Ok(RangeProofPmmr::from(*self))
	}

	// Size is length prefix (8 bytes for u64) + MAX_PROOF_SIZE.
	fn elmt_size() -> Option<u16> {
		// safe conversion because MAX_PROOF_SIZE is a small constant
		Some(8 + MAX_PROOF_SIZE as u16)
	}
}

// The legacy ECDSA compact codec reverses the byte order of each 32-byte
// aggregate-signature component. Binary consensus encoding uses canonical
// `(R.x || s)` bytes, so convert at the compact API boundary. The operation is
// symmetric and is used for both serialization and deserialization.
fn reverse_aggsig_component_byte_order(bytes: &mut [u8; AGG_SIGNATURE_SIZE]) {
	let (rx, s) = bytes.split_at_mut(AGG_SIGNATURE_SIZE / 2);
	rx.reverse();
	s.reverse();
}

impl Readable for AggSigSignature {
	fn read<R: Reader>(reader: &mut R) -> Result<AggSigSignature, Error> {
		let a = reader.read_fixed_bytes(AGG_SIGNATURE_SIZE)?;
		// An all-zero aggregate signature means "not signed yet". Wallets need
		// this sentinel to deserialize stored partial transactions while their
		// slates are still being negotiated. It remains invalid for transaction
		// validation and must never be accepted as a completed kernel signature.
		if a.iter().all(|byte| *byte == 0) {
			return Ok(AggSigSignature::blank());
		}
		let mut c = [0; AGG_SIGNATURE_SIZE];
		c[..AGG_SIGNATURE_SIZE].clone_from_slice(&a[..AGG_SIGNATURE_SIZE]);
		reverse_aggsig_component_byte_order(&mut c);
		secp_static::with_none(Error::from, |secp| {
			Ok(AggSigSignature::from_compact(secp, &c)?)
		})
	}
}

impl Writeable for AggSigSignature {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		// Treat the all-zero signature as an absent signature so wallets can
		// persist partial transactions (slates) before aggregation is complete.
		// This is only a serialization exception; signature validation still
		// rejects the blank value for finalized transactions and blocks.
		if *self == AggSigSignature::blank() {
			return writer.write_fixed_bytes([0; AGG_SIGNATURE_SIZE]);
		}
		let mut bytes = secp_static::with_none(Error::from, |secp| {
			if !self.is_valid(secp) {
				return Err(Error::CorruptedData(
					"Unable to write AggSigSignature, invalid signature".to_string(),
				));
			}
			self.serialize_compact(secp).map_err(|e| {
				Error::CorruptedData(format!("Unable to write AggSigSignature, {}", e))
			})
		})?;
		reverse_aggsig_component_byte_order(&mut bytes);
		writer.write_fixed_bytes(bytes)
	}
}

impl Writeable for PublicKey {
	// Write the public key in compressed form
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		let bytes =
			secp_static::with_none(Error::from, |secp| Ok(self.serialize_vec(secp, true)?))?;
		writer.write_fixed_bytes(bytes)?;
		Ok(())
	}
}

impl Readable for PublicKey {
	// Read the public key in compressed form
	fn read<R: Reader>(reader: &mut R) -> Result<Self, Error> {
		let buf = reader.read_fixed_bytes(COMPRESSED_PUBLIC_KEY_SIZE)?;
		let pk = secp_static::with_none(Error::from, |secp| {
			PublicKey::from_slice(secp, &buf)
				.map_err(|e| Error::CorruptedData(format!("Unable to read public key, {}", e)))
		})?;
		Ok(pk)
	}
}

/// Collections of items must be sorted lexicographically and all unique.
pub trait VerifySortedAndUnique<T> {
	/// Verify a collection of items is sorted and all unique.
	fn verify_sorted_and_unique(&self) -> Result<(), Error>;
}

impl<T: Ord> VerifySortedAndUnique<T> for Vec<T> {
	fn verify_sorted_and_unique(&self) -> Result<(), Error> {
		for pair in self.windows(2) {
			if pair[0] > pair[1] {
				return Err(Error::SortError);
			} else if pair[0] == pair[1] {
				return Err(Error::DuplicateError);
			}
		}
		Ok(())
	}
}

/// Sort hashable values by their consensus hash.
pub fn sort_by_hash<T: Hashed>(context_id: u32, items: &mut Vec<T>) -> Result<(), Error> {
	sort_slice_by_hash(context_id, items.as_mut_slice())
}

/// Sort values by the consensus hash of a projected key.
pub fn sort_by_hash_key<T, K, F>(
	context_id: u32,
	items: &mut Vec<T>,
	key_fn: F,
) -> Result<(), Error>
where
	K: Hashed,
	F: Fn(&T) -> &K,
{
	sort_slice_by_hash_key(context_id, items.as_mut_slice(), key_fn)
}

/// Sort hashable values by their consensus hash.
pub fn sort_slice_by_hash<T: Hashed>(context_id: u32, items: &mut [T]) -> Result<(), Error> {
	sort_slice_by_hash_key(context_id, items, |item| item)
}

/// Sort values by the consensus hash of a projected key.
pub fn sort_slice_by_hash_key<T, K, F>(
	context_id: u32,
	items: &mut [T],
	key_fn: F,
) -> Result<(), Error>
where
	K: Hashed,
	F: Fn(&T) -> &K,
{
	let mut keys = Vec::with_capacity(items.len());
	for (index, item) in items.iter().enumerate() {
		keys.push((key_fn(item).hash(context_id)?, index));
	}
	keys.sort_unstable_by(|lhs, rhs| lhs.0.cmp(&rhs.0));

	let mut old_at_pos = (0..items.len()).collect::<Vec<_>>();
	let mut pos_of_old = old_at_pos.clone();
	for (new_pos, (_, old_needed)) in keys.into_iter().enumerate() {
		let current_pos = pos_of_old[old_needed];
		if current_pos == new_pos {
			continue;
		}

		items.swap(new_pos, current_pos);

		let old_at_new_pos = old_at_pos[new_pos];
		let old_at_current_pos = old_at_pos[current_pos];
		old_at_pos.swap(new_pos, current_pos);
		pos_of_old[old_at_new_pos] = current_pos;
		pos_of_old[old_at_current_pos] = new_pos;
	}
	Ok(())
}

/// Insert a hashable value into an already hash-sorted vec, skipping duplicates.
pub fn insert_unique_by_hash<T: Hashed>(
	context_id: u32,
	items: &mut Vec<T>,
	item: T,
) -> Result<bool, Error> {
	insert_unique_by_hash_key(context_id, items, item, |item| item)
}

/// Insert a value into an already hash-sorted vec by projected hash key, skipping duplicates.
pub fn insert_unique_by_hash_key<T, K, F>(
	context_id: u32,
	items: &mut Vec<T>,
	item: T,
	key_fn: F,
) -> Result<bool, Error>
where
	K: Hashed,
	F: Fn(&T) -> &K,
{
	let item_hash = key_fn(&item).hash(context_id)?;
	let mut left = 0;
	let mut right = items.len();
	while left < right {
		let mid = left + (right - left) / 2;
		match key_fn(&items[mid]).hash(context_id)?.cmp(&item_hash) {
			cmp::Ordering::Less => left = mid + 1,
			cmp::Ordering::Greater => right = mid,
			cmp::Ordering::Equal => return Ok(false),
		}
	}
	items.insert(left, item);
	Ok(true)
}

/// Verify a hashable collection is sorted by consensus hash and contains no duplicates.
pub fn verify_sorted_and_unique_by_hash<T: Hashed>(
	context_id: u32,
	items: &[T],
) -> Result<(), Error> {
	verify_sorted_and_unique_by_hash_key(context_id, items, |item| item)
}

/// Verify a collection is sorted by projected consensus hash and contains no duplicates.
pub fn verify_sorted_and_unique_by_hash_key<T, K, F>(
	context_id: u32,
	items: &[T],
	key_fn: F,
) -> Result<(), Error>
where
	K: Hashed,
	F: Fn(&T) -> &K,
{
	let mut prev_hash: Option<Hash> = None;
	for item in items {
		let hash = key_fn(item).hash(context_id)?;
		if let Some(prev_hash) = prev_hash {
			if prev_hash > hash {
				return Err(Error::SortError);
			} else if prev_hash == hash {
				return Err(Error::DuplicateError);
			}
		}
		prev_hash = Some(hash);
	}
	Ok(())
}

/// Compare two hashable values for equality by consensus hash.
pub fn hashes_equal<T: Hashed>(context_id: u32, lhs: &T, rhs: &T) -> Result<bool, Error> {
	Ok(lhs.hash(context_id)? == rhs.hash(context_id)?)
}

/// Compare two slices for equality by pairwise consensus hashes.
pub fn slices_equal_by_hash<T: Hashed>(
	context_id: u32,
	lhs: &[T],
	rhs: &[T],
) -> Result<bool, Error> {
	if lhs.len() != rhs.len() {
		return Ok(false);
	}
	for (lhs, rhs) in lhs.iter().zip(rhs) {
		if !hashes_equal(context_id, lhs, rhs)? {
			return Ok(false);
		}
	}
	Ok(true)
}

/// Compare two slices for equality by pairwise projected consensus hashes.
pub fn slices_equal_by_hash_key<T, K, F>(
	context_id: u32,
	lhs: &[T],
	rhs: &[T],
	key_fn: F,
) -> Result<bool, Error>
where
	K: Hashed,
	F: Fn(&T) -> &K,
{
	if lhs.len() != rhs.len() {
		return Ok(false);
	}
	for (lhs, rhs) in lhs.iter().zip(rhs) {
		if !hashes_equal(context_id, key_fn(lhs), key_fn(rhs))? {
			return Ok(false);
		}
	}
	Ok(true)
}

/// Check for a hashable value in a slice by consensus hash.
pub fn contains_by_hash<T: Hashed>(
	context_id: u32,
	items: &[T],
	needle: &T,
) -> Result<bool, Error> {
	contains_by_hash_key(context_id, items, needle, |item| item)
}

/// Check for a value in a slice by projected consensus hash.
pub fn contains_by_hash_key<T, K, F>(
	context_id: u32,
	items: &[T],
	needle: &T,
	key_fn: F,
) -> Result<bool, Error>
where
	K: Hashed,
	F: Fn(&T) -> &K,
{
	let needle_hash = key_fn(needle).hash(context_id)?;
	for item in items {
		if key_fn(item).hash(context_id)? == needle_hash {
			return Ok(true);
		}
	}
	Ok(false)
}

/// Utility wrapper for an underlying byte Writer. Defines higher level methods
/// to write numbers, byte vectors, hashes, etc.
pub struct BinWriter<'a> {
	sink: &'a mut dyn Write,
	version: ProtocolVersion,
	context_id: u32,
}

impl<'a> BinWriter<'a> {
	/// Wraps a standard Write in a new BinWriter
	pub fn new(
		sink: &'a mut dyn Write,
		version: ProtocolVersion,
		context_id: u32,
	) -> BinWriter<'a> {
		BinWriter {
			sink,
			version,
			context_id,
		}
	}

	/// Constructor for BinWriter with default "local" protocol version.
	pub fn default(context_id: u32, sink: &'a mut dyn Write) -> BinWriter<'a> {
		BinWriter::new(sink, ProtocolVersion::local(), context_id)
	}
}

impl<'a> Writer for BinWriter<'a> {
	fn serialization_mode(&self) -> SerializationMode {
		SerializationMode::Full
	}

	fn write_fixed_bytes<T: AsRef<[u8]>>(&mut self, bytes: T) -> Result<(), Error> {
		self.sink.write_all(bytes.as_ref())?;
		Ok(())
	}

	fn protocol_version(&self) -> ProtocolVersion {
		self.version
	}

	fn get_context_id(&self) -> u32 {
		self.context_id
	}
}

macro_rules! impl_int {
	($int:ty, $w_fn:ident, $r_fn:ident) => {
		impl Writeable for $int {
			fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
				writer.$w_fn(*self)
			}
		}

		impl Readable for $int {
			fn read<R: Reader>(reader: &mut R) -> Result<$int, Error> {
				reader.$r_fn()
			}
		}
	};
}

impl_int!(u8, write_u8, read_u8);
impl_int!(u16, write_u16, read_u16);
impl_int!(u32, write_u32, read_u32);
impl_int!(i32, write_i32, read_i32);
impl_int!(u64, write_u64, read_u64);
impl_int!(i64, write_i64, read_i64);

impl<T> Readable for Vec<T>
where
	T: Readable,
{
	fn read<R: Reader>(reader: &mut R) -> Result<Vec<T>, Error> {
		let mut buf = Vec::new();
		loop {
			let bytes_before = reader.bytes_read();
			let elem = T::read(reader);
			match elem {
				Ok(e) => {
					if reader.bytes_read() == bytes_before {
						return Err(Error::CorruptedData(
							"Vector element read consumed no bytes".to_string(),
						));
					}
					if buf.len() as u64 >= READ_VEC_SIZE_LIMIT {
						return Err(Error::TooLargeReadErr(format!(
							"Try to read more than {} items, limit is 100K",
							READ_VEC_SIZE_LIMIT
						)));
					}
					buf.push(e);
				}
				Err(Error::IOErr(ref err)) if err.kind() == io::ErrorKind::UnexpectedEof => {
					if reader.bytes_read() == bytes_before {
						if reader.has_pending_data() {
							return Err(io::Error::new(
								io::ErrorKind::UnexpectedEof,
								"Unexpected EOF while reading vector element",
							)
							.into());
						}
						break;
					}
					return Err(io::Error::new(
						io::ErrorKind::UnexpectedEof,
						"Unexpected EOF while reading vector element",
					)
					.into());
				}
				Err(e) => return Err(e),
			}
		}
		Ok(buf)
	}
}

impl<T> Writeable for Vec<T>
where
	T: Writeable,
{
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		for elmt in self {
			elmt.write(writer)?;
		}
		Ok(())
	}
}

impl<'a, A: Writeable> Writeable for &'a A {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		Writeable::write(*self, writer)
	}
}

impl<A: Writeable, B: Writeable> Writeable for (A, B) {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		Writeable::write(&self.0, writer)?;
		Writeable::write(&self.1, writer)
	}
}

impl<A: Readable, B: Readable> Readable for (A, B) {
	fn read<R: Reader>(reader: &mut R) -> Result<(A, B), Error> {
		Ok((Readable::read(reader)?, Readable::read(reader)?))
	}
}

impl<A: Writeable, B: Writeable, C: Writeable> Writeable for (A, B, C) {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		Writeable::write(&self.0, writer)?;
		Writeable::write(&self.1, writer)?;
		Writeable::write(&self.2, writer)
	}
}

impl<A: Writeable, B: Writeable, C: Writeable, D: Writeable> Writeable for (A, B, C, D) {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), Error> {
		Writeable::write(&self.0, writer)?;
		Writeable::write(&self.1, writer)?;
		Writeable::write(&self.2, writer)?;
		Writeable::write(&self.3, writer)
	}
}

impl<A: Readable, B: Readable, C: Readable> Readable for (A, B, C) {
	fn read<R: Reader>(reader: &mut R) -> Result<(A, B, C), Error> {
		Ok((
			Readable::read(reader)?,
			Readable::read(reader)?,
			Readable::read(reader)?,
		))
	}
}

impl<A: Readable, B: Readable, C: Readable, D: Readable> Readable for (A, B, C, D) {
	fn read<R: Reader>(reader: &mut R) -> Result<(A, B, C, D), Error> {
		Ok((
			Readable::read(reader)?,
			Readable::read(reader)?,
			Readable::read(reader)?,
			Readable::read(reader)?,
		))
	}
}

/// Trait for types that can be added to a PMMR.
pub trait PMMRable: Writeable + Clone + Debug + DefaultHashable {
	/// The type of element actually stored in the MMR data file.
	/// This allows us to store Hash elements in the header MMR for variable size BlockHeaders.
	type E: Readable + Writeable + Debug;

	/// Convert the pmmrable into the element to be stored in the MMR data file.
	fn as_elmt(&self) -> Result<Self::E, Error>;

	/// Size of each element if "fixed" size. Elements are "variable" size if None.
	fn elmt_size() -> Option<u16>;
}

/// Generic trait to ensure PMMR elements can be hashed with an index
pub trait PMMRIndexHashable {
	/// Hash with a given index
	fn hash_with_index(&self, context_id: u32, index: u64) -> Result<Hash, std::io::Error>;
}

impl<T: DefaultHashable> PMMRIndexHashable for T {
	fn hash_with_index(&self, context_id: u32, index: u64) -> Result<Hash, std::io::Error> {
		(index, self).hash(context_id)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_crates::secp::{ContextFlag, Secp256k1};

	#[derive(Debug)]
	struct EmptyReadable;

	impl Readable for EmptyReadable {
		fn read<R: Reader>(_reader: &mut R) -> Result<Self, Error> {
			Ok(EmptyReadable)
		}
	}

	#[test]
	fn commitment_read_rejects_invalid_pedersen_commitment() {
		let bytes = [1u8; PEDERSEN_COMMITMENT_SIZE];

		match deserialize_default::<Commitment, _>(0, &mut &bytes[..]) {
			Err(Error::CorruptedData(msg)) => {
				assert!(msg.contains("Pedersen commitment"), "{}", msg);
			}
			other => panic!("expected invalid commitment rejection, got {:?}", other),
		}
	}

	#[test]
	fn commitment_read_accepts_valid_pedersen_commitment() {
		let secp = Secp256k1::with_caps(ContextFlag::Commit).unwrap();
		let commit = secp.commit_value(1).unwrap();
		let mut bytes = vec![];

		serialize_default(0, &mut bytes, &commit).unwrap();
		let decoded: Commitment = deserialize_default(0, &mut &bytes[..]).unwrap();

		assert_eq!(decoded, commit);
	}

	#[test]
	fn aggsig_blank_signature_roundtrips_for_partial_transactions() {
		let sig = AggSigSignature::blank();
		let mut bytes = vec![];

		serialize_default(0, &mut bytes, &sig).unwrap();
		assert_eq!(bytes, [0; AGG_SIGNATURE_SIZE]);

		let decoded: AggSigSignature = deserialize_default(0, &mut &bytes[..]).unwrap();
		assert_eq!(decoded, sig);
		assert!(!decoded.is_valid(&Secp256k1::without_caps().unwrap()));
	}

	#[test]
	fn aggsig_signature_read_rejects_nonzero_invalid_signature() {
		let mut bytes = [0; AGG_SIGNATURE_SIZE];
		bytes[AGG_SIGNATURE_SIZE - 1] = 1;

		assert!(deserialize_default::<AggSigSignature, _>(0, &mut &bytes[..]).is_err());
	}

	#[test]
	fn aggsig_signature_binary_encoding_is_canonical() {
		let secp = Secp256k1::without_caps().unwrap();
		let compact = [
			155, 161, 81, 120, 148, 131, 93, 161, 94, 90, 149, 232, 60, 234, 164, 237, 129, 149,
			174, 231, 52, 76, 240, 100, 103, 219, 44, 47, 239, 151, 29, 206, 30, 146, 118, 82, 80,
			234, 239, 52, 9, 114, 15, 81, 50, 15, 179, 22, 150, 52, 166, 10, 5, 150, 227, 164, 82,
			44, 25, 66, 64, 250, 177, 170,
		];
		let canonical = [
			206, 29, 151, 239, 47, 44, 219, 103, 100, 240, 76, 52, 231, 174, 149, 129, 237, 164,
			234, 60, 232, 149, 90, 94, 161, 93, 131, 148, 120, 81, 161, 155, 170, 177, 250, 64, 66,
			25, 44, 82, 164, 227, 150, 5, 10, 166, 52, 150, 22, 179, 15, 50, 81, 15, 114, 9, 52,
			239, 234, 80, 82, 118, 146, 30,
		];
		let sig = AggSigSignature::from_compact(&secp, &compact).unwrap();
		let mut bytes = vec![];

		serialize_default(0, &mut bytes, &sig).unwrap();
		assert_eq!(bytes, canonical);

		let decoded: AggSigSignature = deserialize_default(0, &mut &bytes[..]).unwrap();
		assert_eq!(decoded, sig);
	}

	#[test]
	fn deserialize_rejects_trailing_bytes() {
		let bytes = [7u8, 8u8];

		match deserialize_default::<u8, _>(0, &mut &bytes[..]) {
			Err(Error::CorruptedData(msg)) => {
				assert!(msg.contains("Trailing bytes"), "{}", msg);
			}
			other => panic!("expected trailing bytes rejection, got {:?}", other),
		}
	}

	#[test]
	fn read_len_prefix_rejects_oversized_u64_before_cast() {
		let bytes = u64::MAX.to_be_bytes();
		let mut source = &bytes[..];
		let mut reader = BinReader::new(&mut source, ProtocolVersion::local(), 0);

		match reader.read_bytes_len_prefix() {
			Err(Error::TooLargeReadErr(_)) => {}
			other => panic!("expected oversized length rejection, got {:?}", other),
		}
	}

	#[test]
	fn streaming_reader_rejects_oversized_fixed_read_before_allocation() {
		let mut source = io::empty();
		let mut reader = StreamingReader::new(&mut source, ProtocolVersion::local(), 0);

		match reader.read_fixed_bytes(READ_CHUNK_LIMIT + 1) {
			Err(Error::TooLargeReadErr(_)) => {}
			other => panic!("expected oversized fixed read rejection, got {:?}", other),
		}
	}

	#[test]
	fn rangeproof_pmmr_element_rejects_oversized_lengths() {
		let proof = RangeProof {
			plen: MAX_PROOF_SIZE + 1,
			proof: [0; MAX_PROOF_SIZE],
		};

		match proof.as_elmt() {
			Err(Error::CorruptedData(msg)) => {
				assert!(msg.contains("PMMR element length"), "{}", msg);
			}
			other => panic!(
				"expected oversized PMMR rangeproof rejection, got {:?}",
				other
			),
		}
	}

	#[test]
	fn rangeproof_pmmr_element_accepts_variable_size_length() {
		for plen in [0, 3, MAX_PROOF_SIZE] {
			let proof = RangeProof {
				plen,
				proof: [0; MAX_PROOF_SIZE],
			};

			assert_eq!(proof.as_elmt().unwrap().into_inner(), proof);
		}
	}

	#[test]
	fn rangeproof_pmmr_serialization_pads_to_fixed_size() {
		let mut proof = [9; MAX_PROOF_SIZE];
		proof[..3].copy_from_slice(&[1, 2, 3]);
		let proof = RangeProof { plen: 3, proof };
		let mut bytes = vec![];

		serialize_default(0, &mut bytes, &proof.as_elmt().unwrap()).unwrap();

		assert_eq!(bytes.len(), 8 + MAX_PROOF_SIZE);
		assert_eq!(&bytes[8..11], &[1, 2, 3]);
		assert!(bytes[11..].iter().all(|&b| b == 0));

		let decoded: RangeProofPmmr = deserialize_default(0, &mut &bytes[..]).unwrap();
		assert_eq!(
			decoded.into_inner(),
			RangeProof {
				plen: 3,
				proof: {
					let mut p = [0; MAX_PROOF_SIZE];
					p[..3].copy_from_slice(&[1, 2, 3]);
					p
				},
			}
		);
	}

	#[test]
	fn rangeproof_pmmr_read_rejects_nonzero_padding() {
		let mut bytes = vec![];
		bytes.extend_from_slice(&3u64.to_be_bytes());
		bytes.extend_from_slice(&[1, 2, 3]);
		bytes.extend_from_slice(&vec![0; MAX_PROOF_SIZE - 4]);
		bytes.push(1);

		match deserialize_default::<RangeProofPmmr, _>(0, &mut &bytes[..]) {
			Err(Error::CorruptedData(msg)) => {
				assert!(msg.contains("non-zero padding"), "{}", msg);
			}
			other => panic!("expected non-zero PMMR padding rejection, got {:?}", other),
		}
	}

	#[test]
	fn rangeproof_pmmr_hashes_like_inner_proof() {
		let mut proof_bytes = [9; MAX_PROOF_SIZE];
		proof_bytes[..3].copy_from_slice(&[1, 2, 3]);
		let proof = RangeProof {
			plen: 3,
			proof: proof_bytes,
		};
		let elmt = proof.as_elmt().unwrap();

		assert_eq!(
			elmt.hash_with_index(0, 42).unwrap(),
			proof.hash_with_index(0, 42).unwrap()
		);
	}

	#[test]
	fn vec_read_accepts_clean_eof_after_complete_elements() {
		let bytes = [0u8, 1u8, 0u8, 2u8];

		let decoded: Vec<u16> = deserialize_default(0, &mut &bytes[..]).unwrap();

		assert_eq!(decoded, vec![1, 2]);
	}

	#[test]
	fn vec_read_rejects_partial_final_element() {
		let bytes = [0u8];

		match deserialize_default::<Vec<u16>, _>(0, &mut &bytes[..]) {
			Err(Error::IOErr(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {}
			other => panic!(
				"expected truncated vector element rejection, got {:?}",
				other
			),
		}
	}

	#[test]
	fn vec_read_rejects_partial_final_element_with_buf_reader() {
		let bytes = [0u8];
		let mut source = &bytes[..];
		let mut reader = BufReader::new(&mut source, ProtocolVersion::local(), 0);

		match Vec::<u16>::read(&mut reader) {
			Err(Error::IOErr(err)) if err.kind() == io::ErrorKind::UnexpectedEof => {}
			other => panic!(
				"expected truncated vector element rejection, got {:?}",
				other
			),
		}
	}

	#[test]
	fn vec_read_rejects_zero_byte_elements() {
		let bytes = [1u8];

		match deserialize_default::<Vec<EmptyReadable>, _>(0, &mut &bytes[..]) {
			Err(Error::CorruptedData(msg)) => {
				assert!(msg.contains("consumed no bytes"), "{}", msg);
			}
			other => panic!("expected zero-byte element rejection, got {:?}", other),
		}
	}

	#[test]
	fn vec_read_rejects_too_many_elements() {
		let bytes = vec![0u8; READ_VEC_SIZE_LIMIT as usize + 1];

		match deserialize_default::<Vec<u8>, _>(0, &mut &bytes[..]) {
			Err(Error::TooLargeReadErr(msg)) => {
				assert!(msg.contains("limit is 100K"), "{}", msg);
			}
			other => panic!("expected oversized vector rejection, got {:?}", other),
		}
	}
}
