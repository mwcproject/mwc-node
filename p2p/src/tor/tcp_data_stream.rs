// Copyright 2025 The MWC Developers
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

use crate::tor::arti;
use crate::tor::arti::arti_async_block;
use crate::tor::arti_tracked::ArtiTrackedData;
use crate::{Error, PeerAddr};
use mwc_crates::futures::task::noop_waker;
use mwc_crates::tokio;
use mwc_crates::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use mwc_crates::tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use mwc_crates::tokio::net::TcpStream;
use mwc_crates::tor_proto::client::stream::{DataReader, DataStream, DataWriter};
use mwc_util::run_global_async_block;
use std::io::{ErrorKind, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

pub enum TcpData {
	Tcp(TcpStream),
	Tor(ArtiTrackedData<DataStream>),
}

pub enum TcpDataReadHalf {
	Tcp(OwnedReadHalf),
	Tor(ArtiTrackedData<DataReader>),
}

pub enum TcpDataWriteHalf {
	Tcp(OwnedWriteHalf),
	Tor(ArtiTrackedData<DataWriter>),
}

/// We need something to read/write form both TcpStream and DataStream
pub struct TcpDataStream {
	pub stream: TcpData,
	read_timeout: Duration,
	write_timeout: Duration,
}

pub struct TcpDataReadHalfStream {
	stream: TcpDataReadHalf,
	read_timeout: Duration,
}

pub struct TcpDataWriteHalfStream {
	stream: TcpDataWriteHalf,
	write_timeout: Duration,
}

///////////////////////////////////////////////////////////////////////
// Tcp Data

impl TcpDataStream {
	pub fn from_tcp(tcp_stream: TcpStream) -> Self {
		TcpDataStream {
			stream: TcpData::Tcp(tcp_stream),
			read_timeout: Duration::from_secs(5),
			write_timeout: Duration::from_secs(5),
		}
	}
	pub fn from_data(tor_stream: DataStream, name: String) -> Result<Self, Error> {
		Ok(TcpDataStream {
			stream: TcpData::Tor(ArtiTrackedData::new(tor_stream, name)?),
			read_timeout: Duration::from_secs(5),
			write_timeout: Duration::from_secs(5),
		})
	}

	pub fn set_read_timeout(&mut self, read_timeout: Duration) {
		self.read_timeout = read_timeout;
	}

	pub fn set_write_timeout(&mut self, write_timeout: Duration) {
		self.write_timeout = write_timeout;
	}

	pub fn is_alive(&mut self) -> bool {
		match &mut self.stream {
			TcpData::Tcp(s) => {
				let waker = noop_waker();
				let mut cx = Context::from_waker(&waker);
				let mut buf = [0u8; 1];
				let mut read_buf = ReadBuf::new(&mut buf);

				match s.poll_peek(&mut cx, &mut read_buf) {
					Poll::Ready(Ok(n)) => n != 0,
					// Callers only need the liveness state here, not the exact reason
					// why the stream is no longer alive. Hiding the error is intentional,
					// and logging it would flood logs with expected disconnect noise.
					Poll::Ready(Err(_)) => false,
					Poll::Pending => true,
				}
			}
			TcpData::Tor(s) => !arti::is_arti_restarting() && s.is_connected(),
		}
	}

	/// Gracefully shuts down the underlying stream.
	///
	/// This intentionally does not use `write_timeout`. Shutdown is also the
	/// transport cleanup path, and cancelling it with a timeout can interrupt
	/// Arti/Tor close bookkeeping before resources are released.
	pub fn shutdown(self) -> Result<(), Error> {
		self.stream.shutdown()
	}

	pub fn split(self) -> Result<(TcpDataReadHalfStream, TcpDataWriteHalfStream), Error> {
		match self.stream {
			TcpData::Tcp(s) => {
				let (r, w) = s.into_split();
				Ok((
					TcpDataReadHalfStream {
						stream: TcpDataReadHalf::Tcp(r),
						read_timeout: self.read_timeout,
					},
					TcpDataWriteHalfStream {
						stream: TcpDataWriteHalf::Tcp(w),
						write_timeout: self.write_timeout,
					},
				))
			}
			TcpData::Tor(s) => {
				let (reader, writer) = s.split()?;
				Ok((
					TcpDataReadHalfStream {
						stream: TcpDataReadHalf::Tor(reader),
						read_timeout: self.read_timeout,
					},
					TcpDataWriteHalfStream {
						stream: TcpDataWriteHalf::Tor(writer),
						write_timeout: self.write_timeout,
					},
				))
			}
		}
	}

	pub fn peer_addr(&self) -> Result<PeerAddr, Error> {
		let peer_addr = match &self.stream {
			TcpData::Tcp(tcp) => PeerAddr::Ip(tcp.peer_addr().map_err(|e| {
				Error::Internal(format!("Unable to get peer IP peer address, {}", e))
			})?),
			TcpData::Tor(_) => return Err(Error::IpAddressRequestFromTor),
		};
		Ok(peer_addr)
	}
}

impl TcpData {
	pub fn shutdown(self) -> Result<(), Error> {
		// Do not wrap these shutdown futures in tokio::time::timeout. Unlike a
		// normal write or flush, shutdown is responsible for completing the close
		// path; cancelling it on timeout can leave transport resources queued or
		// registered instead of letting the runtime release them.
		match self {
			TcpData::Tcp(mut s) => run_global_async_block(async { s.shutdown().await })
				.map_err(|e| Error::Internal(format!("Unable to shutdown stream, {}", e)))?
				.map_err(Error::Connection),
			TcpData::Tor(mut s) => arti_async_block(async { s.shutdown().await })?
				.map_err(|e| Error::TorConnect(format!("Unable to shutdown stream, {}", e))),
		}
	}
}

impl AsyncRead for TcpData {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpData::Tcp(s) => Pin::new(s).poll_read(cx, buf),
			TcpData::Tor(s) => {
				if arti::is_arti_restarting() {
					return Poll::Ready(Err(std::io::Error::new(
						std::io::ErrorKind::NetworkDown,
						"Arti is restarting",
					)));
				}
				Pin::new(s).poll_read(cx, buf)
			}
		}
	}
}

impl AsyncWrite for TcpData {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		match &mut *self {
			TcpData::Tcp(s) => Pin::new(s).poll_write(cx, buf),
			TcpData::Tor(s) => {
				if arti::is_arti_restarting() {
					return Poll::Ready(Err(std::io::Error::new(
						std::io::ErrorKind::NetworkDown,
						"Arti is restarting",
					)));
				}
				Pin::new(s).poll_write(cx, buf)
			}
		}
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpData::Tcp(s) => Pin::new(s).poll_flush(cx),
			TcpData::Tor(s) => {
				if arti::is_arti_restarting() {
					return Poll::Ready(Err(std::io::Error::new(
						std::io::ErrorKind::NetworkDown,
						"Arti is restarting",
					)));
				}
				Pin::new(s).poll_flush(cx)
			}
		}
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpData::Tcp(s) => Pin::new(s).poll_shutdown(cx),
			TcpData::Tor(s) => Pin::new(s).poll_shutdown(cx),
		}
	}
}

/* ---------- std::io::Read ---------- */
impl Read for TcpDataStream {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
		let read_timeout = &self.read_timeout;
		let r = match &mut self.stream {
			TcpData::Tcp(s) => run_global_async_block(async {
				tokio::time::timeout(*read_timeout, s.read(buf)).await
			})
			.map_err(|e| std::io::Error::new(ErrorKind::Other, e))?,
			TcpData::Tor(s) => {
				arti_async_block(async { tokio::time::timeout(*read_timeout, s.read(buf)).await })
					.map_err(|e| arti_async_block_error(e, "read"))?
			}
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "read timeout"))?
	}
}

/* ---------- std::io::Write ---------- */
impl Write for TcpDataStream {
	fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		let write_timeout = &self.write_timeout;
		let r = match &mut self.stream {
			TcpData::Tcp(s) => run_global_async_block(async {
				tokio::time::timeout(*write_timeout, s.write(buf)).await
			})
			.map_err(|e| std::io::Error::new(ErrorKind::Other, e))?,
			TcpData::Tor(s) => {
				arti_async_block(async { tokio::time::timeout(*write_timeout, s.write(buf)).await })
					.map_err(|e| arti_async_block_error(e, "write"))?
			}
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "write timeout"))?
	}

	#[allow(unused_mut)]
	fn write_all(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
		let write_timeout = &self.write_timeout;
		let r = match &mut self.stream {
			TcpData::Tcp(s) => run_global_async_block(async {
				tokio::time::timeout(*write_timeout, s.write_all(buf)).await
			})
			.map_err(|e| std::io::Error::new(ErrorKind::Other, e))?,
			TcpData::Tor(s) => arti_async_block(async {
				tokio::time::timeout(*write_timeout, s.write_all(buf)).await
			})
			.map_err(|e| arti_async_block_error(e, "write_all"))?,
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "write_all timeout"))?
	}

	fn flush(&mut self) -> Result<(), std::io::Error> {
		let write_timeout = &self.write_timeout;
		let r = match &mut self.stream {
			TcpData::Tcp(s) => run_global_async_block(async {
				tokio::time::timeout(*write_timeout, s.flush()).await
			})
			.map_err(|e| std::io::Error::new(ErrorKind::Other, e))?,
			TcpData::Tor(s) => {
				arti_async_block(async { tokio::time::timeout(*write_timeout, s.flush()).await })
					.map_err(|e| arti_async_block_error(e, "flush"))?
			}
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "write timeout"))?
	}
}

//////////////////////////////////////////////////////////////////////////////
// Read/Write Half

impl TcpDataReadHalfStream {
	pub fn set_read_timeout(&mut self, read_timeout: Duration) {
		self.read_timeout = read_timeout;
	}
}

impl TcpDataWriteHalfStream {
	pub fn set_write_timeout(&mut self, write_timeout: Duration) {
		self.write_timeout = write_timeout;
	}

	/// Gracefully shuts down the write half.
	///
	/// This intentionally does not use `write_timeout` because cancelling the
	/// close path can prevent transport resources from being released.
	pub fn shutdown(self) -> Result<(), Error> {
		self.stream.shutdown()
	}
}

impl TcpDataWriteHalf {
	pub fn shutdown(self) -> Result<(), Error> {
		// Keep shutdown unbounded for the same reason as TcpData::shutdown:
		// timeout cancellation can interrupt cleanup and leak resources.
		match self {
			TcpDataWriteHalf::Tcp(mut s) => run_global_async_block(async { s.shutdown().await })
				.map_err(|e| Error::Internal(format!("Unable to shutdown stream, {}", e)))?
				.map_err(Error::Connection),
			TcpDataWriteHalf::Tor(mut s) => arti_async_block(async { s.shutdown().await })?
				.map_err(|e| Error::TorConnect(format!("Unable to shutdown stream, {}", e))),
		}
	}
}

fn read_timeout_result(
	result: Result<std::io::Result<usize>, mwc_crates::tokio::time::error::Elapsed>,
) -> std::io::Result<usize> {
	match result {
		Ok(read_result) => read_result,
		Err(_) => Err(std::io::Error::new(ErrorKind::TimedOut, "read timeout")),
	}
}

fn arti_async_block_error(err: Error, operation: &str) -> std::io::Error {
	let kind = match &err {
		Error::TorRestarting | Error::TorNotInitialized => ErrorKind::NotConnected,
		_ => ErrorKind::Other,
	};
	std::io::Error::new(kind, format!("arti {} error: {}", operation, err))
}

impl AsyncRead for TcpDataReadHalf {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpDataReadHalf::Tcp(s) => Pin::new(s).poll_read(cx, buf),
			TcpDataReadHalf::Tor(s) => Pin::new(s).poll_read(cx, buf),
		}
	}
}

impl AsyncWrite for TcpDataWriteHalf {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		match &mut *self {
			TcpDataWriteHalf::Tcp(s) => Pin::new(s).poll_write(cx, buf),
			TcpDataWriteHalf::Tor(s) => Pin::new(s).poll_write(cx, buf),
		}
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpDataWriteHalf::Tcp(s) => Pin::new(s).poll_flush(cx),
			TcpDataWriteHalf::Tor(s) => Pin::new(s).poll_flush(cx),
		}
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpDataWriteHalf::Tcp(s) => Pin::new(s).poll_shutdown(cx),
			TcpDataWriteHalf::Tor(s) => Pin::new(s).poll_shutdown(cx),
		}
	}
}

/* ---------- std::io::Read ---------- */
impl Read for TcpDataReadHalfStream {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
		let read_timeout = &self.read_timeout;
		let read_result = match &mut self.stream {
			TcpDataReadHalf::Tcp(s) => run_global_async_block(async {
				tokio::time::timeout(*read_timeout, s.read(buf)).await
			})
			.map_err(|e| std::io::Error::new(ErrorKind::Other, e))?,
			TcpDataReadHalf::Tor(s) => {
				arti_async_block(async { tokio::time::timeout(*read_timeout, s.read(buf)).await })
					.map_err(|e| arti_async_block_error(e, "read"))?
			}
		};

		read_timeout_result(read_result)
	}
}

/* ---------- std::io::Write ---------- */
impl Write for TcpDataWriteHalfStream {
	fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		let write_timeout = &self.write_timeout;
		let r = match &mut self.stream {
			TcpDataWriteHalf::Tcp(s) => run_global_async_block(async {
				tokio::time::timeout(*write_timeout, s.write(buf)).await
			})
			.map_err(|e| std::io::Error::new(ErrorKind::Other, e))?,
			TcpDataWriteHalf::Tor(s) => {
				arti_async_block(async { tokio::time::timeout(*write_timeout, s.write(buf)).await })
					.map_err(|e| arti_async_block_error(e, "write"))?
			}
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "write timeout"))?
	}

	#[allow(unused_mut)]
	fn write_all(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
		let write_timeout = &self.write_timeout;
		let r = match &mut self.stream {
			TcpDataWriteHalf::Tcp(s) => run_global_async_block(async {
				tokio::time::timeout(*write_timeout, s.write_all(buf)).await
			})
			.map_err(|e| std::io::Error::new(ErrorKind::Other, e))?,
			TcpDataWriteHalf::Tor(s) => arti_async_block(async {
				tokio::time::timeout(*write_timeout, s.write_all(buf)).await
			})
			.map_err(|e| arti_async_block_error(e, "write_all"))?,
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "write_all timeout"))?
	}

	fn flush(&mut self) -> Result<(), std::io::Error> {
		let write_timeout = &self.write_timeout;
		let r = match &mut self.stream {
			TcpDataWriteHalf::Tcp(s) => run_global_async_block(async {
				tokio::time::timeout(*write_timeout, s.flush()).await
			})
			.map_err(|e| std::io::Error::new(ErrorKind::Other, e))?,
			TcpDataWriteHalf::Tor(s) => {
				arti_async_block(async { tokio::time::timeout(*write_timeout, s.flush()).await })
					.map_err(|e| arti_async_block_error(e, "flush"))?
			}
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "flush timeout"))?
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn read_timeout_result_preserves_inner_read_error_kind() {
		let err = read_timeout_result(Ok(Err(std::io::Error::new(
			ErrorKind::ConnectionReset,
			"reset",
		))))
		.expect_err("inner read error should be returned");

		assert_eq!(err.kind(), ErrorKind::ConnectionReset);
	}

	#[test]
	fn arti_async_block_error_preserves_runtime_failure_kind() {
		let restarting = arti_async_block_error(Error::TorRestarting, "read");
		assert_eq!(restarting.kind(), ErrorKind::NotConnected);
		assert!(restarting.to_string().contains("Tor is restarting"));

		let not_initialized = arti_async_block_error(Error::TorNotInitialized, "read");
		assert_eq!(not_initialized.kind(), ErrorKind::NotConnected);
		assert!(not_initialized
			.to_string()
			.contains("Tor is not initialized"));

		let internal = arti_async_block_error(Error::Internal("join error".into()), "read");
		assert_eq!(internal.kind(), ErrorKind::Other);
		assert!(internal.to_string().contains("join error"));
	}
}
