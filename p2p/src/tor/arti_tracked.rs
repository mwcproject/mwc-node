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
use crate::Error;
use mwc_crates::log::error;
use mwc_crates::tokio::io::{AsyncRead, AsyncWrite};
use mwc_crates::tor_proto::client::stream::{DataReader, DataStream, DataWriter};
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct ArtiRegistrator {
	name: String,
}

impl ArtiRegistrator {
	pub fn new(name: String) -> Result<Self, Error> {
		arti::register_arti_active_object(name.clone())?;
		Ok(ArtiRegistrator { name })
	}
}

impl Drop for ArtiRegistrator {
	fn drop(&mut self) {
		if let Err(e) = arti::unregister_arti_active_object(&self.name) {
			error!(
				"Unable to unregister Arti active object {}: {}",
				self.name, e
			);
		}
	}
}

pub struct ArtiTrackedData<S> {
	stream: S,
	regist: ArtiRegistrator,
}

impl<S> ArtiTrackedData<S> {
	pub fn new(stream: S, name: String) -> Result<Self, Error> {
		Ok(ArtiTrackedData {
			stream,
			regist: ArtiRegistrator::new(name)?,
		})
	}

	pub fn get_name(&self) -> String {
		self.regist.name.clone()
	}
}

impl ArtiTrackedData<DataStream> {
	pub fn is_connected(&self) -> bool {
		self.stream
			.client_stream_ctrl()
			.map(|ctrl| ctrl.is_connected())
			.unwrap_or(false)
	}

	pub fn split(
		self,
	) -> Result<(ArtiTrackedData<DataReader>, ArtiTrackedData<DataWriter>), Error> {
		let base_name = self.regist.name.clone();
		let (reader, writer) = self.stream.split();
		Ok((
			ArtiTrackedData::new(reader, base_name.clone() + "_RH")?,
			ArtiTrackedData::new(writer, base_name + "_WH")?,
		))
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for ArtiTrackedData<S> {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut mwc_crates::tokio::io::ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		if arti::is_arti_restarting() {
			return Poll::Ready(Err(std::io::Error::new(
				std::io::ErrorKind::NetworkDown,
				"Arti is restarting",
			)));
		}
		let this = self.get_mut();
		Pin::new(&mut this.stream).poll_read(cx, buf)
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ArtiTrackedData<S> {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		if arti::is_arti_restarting() {
			return Poll::Ready(Err(std::io::Error::new(
				std::io::ErrorKind::NetworkDown,
				"Arti is restarting",
			)));
		}
		let this = self.get_mut();
		Pin::new(&mut this.stream).poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		if arti::is_arti_restarting() {
			return Poll::Ready(Err(std::io::Error::new(
				std::io::ErrorKind::NetworkDown,
				"Arti is restarting",
			)));
		}
		let this = self.get_mut();
		Pin::new(&mut this.stream).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		Pin::new(&mut this.stream).poll_shutdown(cx)
	}
}
