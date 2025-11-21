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
use mwc_util::run_global_async_block;
use mwc_util::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use mwc_util::tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use mwc_util::tokio::net::TcpStream;
use std::io::{ErrorKind, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tor_proto::client::stream::{DataReader, DataStream, DataWriter};

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
	pub fn from_data(tor_stream: DataStream, name: String) -> Self {
		TcpDataStream {
			stream: TcpData::Tor(ArtiTrackedData::new(tor_stream, name)),
			read_timeout: Duration::from_secs(5),
			write_timeout: Duration::from_secs(5),
		}
	}

	pub fn set_read_timeout(&mut self, read_timeout: Duration) {
		self.read_timeout = read_timeout;
	}

	pub fn set_write_timeout(&mut self, write_timeout: Duration) {
		self.write_timeout = write_timeout;
	}

	pub fn is_alive(&mut self) -> bool {
		let mut buf = [0u8; 0];
		<Self as std::io::Read>::read_exact(self, &mut buf).is_ok()
	}

	pub fn shutdown(self) -> Result<(), Error> {
		self.stream
			.shutdown()
			.map_err(|e| Error::TorConnect(e.to_string()))
	}

	pub fn split(self) -> (TcpDataReadHalfStream, TcpDataWriteHalfStream) {
		match self.stream {
			TcpData::Tcp(s) => {
				let (r, w) = s.into_split();
				(
					TcpDataReadHalfStream {
						stream: TcpDataReadHalf::Tcp(r),
						read_timeout: self.read_timeout,
					},
					TcpDataWriteHalfStream {
						stream: TcpDataWriteHalf::Tcp(w),
						write_timeout: self.write_timeout,
					},
				)
			}
			TcpData::Tor(s) => {
				let base_name = s.get_name();
				let (r, w) = s.stream.split();
				(
					TcpDataReadHalfStream {
						stream: TcpDataReadHalf::Tor(ArtiTrackedData::new(
							r,
							base_name.clone() + "_RH",
						)),
						read_timeout: self.read_timeout,
					},
					TcpDataWriteHalfStream {
						stream: TcpDataWriteHalf::Tor(ArtiTrackedData::new(w, base_name + "_WH")),
						write_timeout: self.write_timeout,
					},
				)
			}
		}
	}

	pub fn peer_addr(&self) -> Result<PeerAddr, Error> {
		let peer_addr = match &self.stream {
			TcpData::Tcp(tcp) => PeerAddr::Ip(tcp.peer_addr().map_err(|e| {
				Error::Internal(format!("Unable to get peer IP peer address, {}", e))
			})?),
			TcpData::Tor(_) => {
				return Err(Error::Internal(
					"Requesting peer address for tor connection".into(),
				))
			}
		};
		Ok(peer_addr)
	}
}

impl TcpData {
	pub fn shutdown(self) -> Result<(), std::io::Error> {
		match self {
			TcpData::Tcp(mut s) => run_global_async_block(async { s.shutdown().await }),
			TcpData::Tor(mut s) => arti_async_block(async { s.stream.shutdown().await })
				.map_err(|_| std::io::Error::new(ErrorKind::Other, "arti not running"))?,
		}
	}
}

impl AsyncRead for TcpData {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut mwc_util::tokio::io::ReadBuf<'_>,
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
				unsafe { Pin::new_unchecked(&mut s.stream).poll_read(cx, buf) }
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
				unsafe { Pin::new_unchecked(&mut s.stream).poll_write(cx, buf) }
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
				unsafe { Pin::new_unchecked(&mut s.stream).poll_flush(cx) }
			}
		}
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpData::Tcp(s) => Pin::new(s).poll_shutdown(cx),
			TcpData::Tor(s) => unsafe { Pin::new_unchecked(&mut s.stream).poll_shutdown(cx) },
		}
	}
}

/* ---------- std::io::Read ---------- */
impl Read for TcpDataStream {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
		let read_timeout = &self.read_timeout;
		let r = match &mut self.stream {
			TcpData::Tcp(s) => run_global_async_block(async {
				mwc_util::tokio::time::timeout(*read_timeout, s.read(buf)).await
			}),
			TcpData::Tor(s) => arti_async_block(async {
				mwc_util::tokio::time::timeout(*read_timeout, s.stream.read(buf)).await
			})
			.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "read timeout"))?,
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
				mwc_util::tokio::time::timeout(*write_timeout, s.write(buf)).await
			}),
			TcpData::Tor(s) => arti_async_block(async {
				mwc_util::tokio::time::timeout(*write_timeout, s.stream.write(buf)).await
			})
			.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "write timeout"))?,
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "write timeout"))?
	}

	fn flush(&mut self) -> Result<(), std::io::Error> {
		let write_timeout = &self.write_timeout;
		let r = match &mut self.stream {
			TcpData::Tcp(s) => run_global_async_block(async {
				mwc_util::tokio::time::timeout(*write_timeout, s.flush()).await
			}),
			TcpData::Tor(s) => arti_async_block(async {
				mwc_util::tokio::time::timeout(*write_timeout, s.stream.flush()).await
			})
			.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "write timeout"))?,
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

	pub fn shutdown(self) -> Result<(), Error> {
		self.stream
			.shutdown()
			.map_err(|e| Error::TorConnect(format!("Unable to shutdown stream, {}", e)))
	}
}

impl TcpDataWriteHalf {
	pub fn shutdown(mut self) -> Result<(), std::io::Error> {
		let r = match &mut self {
			TcpDataWriteHalf::Tcp(s) => run_global_async_block(async { s.shutdown().await }),
			TcpDataWriteHalf::Tor(s) => arti_async_block(async { s.stream.shutdown().await })
				.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "tor is not running"))?,
		};
		r
	}
}

impl AsyncRead for TcpDataReadHalf {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut mwc_util::tokio::io::ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpDataReadHalf::Tcp(s) => Pin::new(s).poll_read(cx, buf),
			TcpDataReadHalf::Tor(s) => unsafe {
				Pin::new_unchecked(&mut s.stream).poll_read(cx, buf)
			},
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
			TcpDataWriteHalf::Tor(s) => unsafe {
				Pin::new_unchecked(&mut s.stream).poll_write(cx, buf)
			},
		}
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpDataWriteHalf::Tcp(s) => Pin::new(s).poll_flush(cx),
			TcpDataWriteHalf::Tor(s) => unsafe { Pin::new_unchecked(&mut s.stream).poll_flush(cx) },
		}
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		match &mut *self {
			TcpDataWriteHalf::Tcp(s) => Pin::new(s).poll_shutdown(cx),
			TcpDataWriteHalf::Tor(s) => unsafe {
				Pin::new_unchecked(&mut s.stream).poll_shutdown(cx)
			},
		}
	}
}

/* ---------- std::io::Read ---------- */
impl Read for TcpDataReadHalfStream {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
		let read_timeout = &self.read_timeout;
		match &mut self.stream {
			TcpDataReadHalf::Tcp(s) => run_global_async_block(async {
				mwc_util::tokio::time::timeout(*read_timeout, s.read(buf)).await
			}),
			TcpDataReadHalf::Tor(s) => arti_async_block(async {
				mwc_util::tokio::time::timeout(*read_timeout, s.stream.read(buf)).await
			})
			.map_err(|_| std::io::Error::new(ErrorKind::NotConnected, "read arti error"))?,
		}
		.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "read timeout"))?
	}
}

/* ---------- std::io::Write ---------- */
impl Write for TcpDataWriteHalfStream {
	fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
		let write_timeout = &self.write_timeout;
		let r = match &mut self.stream {
			TcpDataWriteHalf::Tcp(s) => run_global_async_block(async {
				mwc_util::tokio::time::timeout(*write_timeout, s.write(buf)).await
			}),
			TcpDataWriteHalf::Tor(s) => arti_async_block(async {
				mwc_util::tokio::time::timeout(*write_timeout, s.stream.write(buf)).await
			})
			.map_err(|_| std::io::Error::new(ErrorKind::NotConnected, "write arti error"))?,
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "write timeout"))?
	}

	fn flush(&mut self) -> Result<(), std::io::Error> {
		let write_timeout = &self.write_timeout;
		let r = match &mut self.stream {
			TcpDataWriteHalf::Tcp(s) => run_global_async_block(async {
				mwc_util::tokio::time::timeout(*write_timeout, s.flush()).await
			}),
			TcpDataWriteHalf::Tor(s) => arti_async_block(async {
				mwc_util::tokio::time::timeout(*write_timeout, s.stream.flush()).await
			})
			.map_err(|_| std::io::Error::new(ErrorKind::NotConnected, "write arti error"))?,
		};
		r.map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "flush timeout"))?
	}
}
