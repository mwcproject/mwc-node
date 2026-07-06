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

use crate::codec::{Codec, BODY_IO_TIMEOUT};
use crate::msg::{write_message, Consumed, Message, Msg};
use crate::tor::tcp_data_stream::TcpDataStream;
use crate::types::Error;
use mwc_chain::SyncState;
use mwc_core::ser::ProtocolVersion;
use mwc_crates::crossbeam;
use mwc_crates::crossbeam::channel::{RecvTimeoutError, TryRecvError};
use mwc_crates::log::{debug, error, info, trace, warn};
use mwc_crates::parking_lot::RwLock;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_util::RateCounter;
use std::any::Any;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

// Potentially there can be large messages, like 1.5mb blocks. The Cap is for single peer, we really don't want overflow the network
// That is don't put too large number here. 10 looks reasonable for this case
pub const SEND_CHANNEL_CAP: usize = 32 + 8; // Every request for 512 headers takes 16 chanks. Let's have space for 2 such requests plus for a few extras.

const CHANNEL_TIMEOUT: Duration = Duration::from_millis(1000);

/// A trait to be implemented in order to receive messages from the
/// connection. Allows providing an optional response.
pub trait MessageHandler: Send + 'static {
	fn consume(&self, secp: &mut Secp256k1, message: Message) -> Result<Consumed, Error>;
}

// Macro to simplify the boilerplate around retryable I/O and MWC error handling.
macro_rules! try_return {
	($inner:expr, $stage:expr, $peer:expr) => {
		match $inner {
			Ok(v) => Some(v),
			Err(e) => {
				if let Error::Connection(io_err) = &e {
					if io_err.kind() == io::ErrorKind::WouldBlock {
						// to avoid the heavy polling which will consume CPU 100%
						thread::sleep(Duration::from_millis(100));
						None
					} else {
						if io_err.kind() == io::ErrorKind::TimedOut {
							info!(
								"try_return: exit the loop at {} for {}: {:?}",
								$stage, $peer, e
							);
						} else {
							debug!(
								"try_return: exit the loop at {} for {}: {:?}",
								$stage, $peer, e
							);
						}
						return Err(e);
					}
				} else {
					debug!(
						"try_return: exit the loop at {} for {}: {:?}",
						$stage, $peer, e
					);
					return Err(e);
				}
			}
		}
	};
}

fn recv_send_batch(
	send_rx: &crossbeam::channel::Receiver<Msg>,
) -> Result<Vec<Msg>, RecvTimeoutError> {
	let mut data = match send_rx.recv_timeout(CHANNEL_TIMEOUT) {
		Ok(msg) => {
			let mut data = Vec::with_capacity(SEND_CHANNEL_CAP);
			data.push(msg);
			data
		}
		Err(e) => return Err(e),
	};

	// The channel capacity bounds queued messages, but drained messages move into
	// this local batch. Keep each write batch bounded as well.
	while data.len() < SEND_CHANNEL_CAP {
		match send_rx.try_recv() {
			Ok(msg) => {
				data.push(msg);
			}
			Err(TryRecvError::Empty) => break,
			Err(TryRecvError::Disconnected) => {
				// A disconnected send queue means the peer connection is being
				// closed by another task. There is no reason to write a partially
				// drained batch because the writer will exit and the peer will not
				// be able to respond to us.
				return Err(RecvTimeoutError::Disconnected);
			}
		}
	}

	Ok(data)
}

struct StopOnDrop {
	stopped: Arc<AtomicBool>,
}

impl Drop for StopOnDrop {
	fn drop(&mut self) {
		self.stopped.store(true, Ordering::Relaxed);
	}
}

pub struct StopHandle {
	/// Channel to close the connection
	stopped: Arc<AtomicBool>,
	// we need Option to take ownhership of the handle in stop()
	reader_thread: Option<JoinHandle<Result<(), Error>>>,
	writer_thread: Option<JoinHandle<Result<(), Error>>>,
}

impl StopHandle {
	/// Schedule this connection to safely close via the async close_channel.
	pub fn stop(&self) {
		self.stopped.store(true, Ordering::Relaxed);
	}

	pub fn is_stopped(&self) -> bool {
		self.stopped.load(Ordering::Relaxed)
	}

	pub fn wait(&mut self) -> Result<(), Error> {
		let mut first_error = None;
		if let Some(reader_thread) = self.reader_thread.take() {
			if let Err(e) = Self::join_thread(reader_thread) {
				first_error.get_or_insert(e);
			}
		}
		if let Some(writer_thread) = self.writer_thread.take() {
			if let Err(e) = Self::join_thread(writer_thread) {
				first_error.get_or_insert(e);
			}
		}

		if let Some(e) = first_error {
			Err(e)
		} else {
			Ok(())
		}
	}

	fn join_thread(peer_thread: JoinHandle<Result<(), Error>>) -> Result<(), Error> {
		// wait only if other thread is calling us, eg shutdown
		if thread::current().id() != peer_thread.thread().id() {
			let thread_id = peer_thread.thread().id();
			debug!("waiting for thread {:?} exit", thread_id);
			match peer_thread.join() {
				Ok(Ok(())) => {}
				Ok(Err(e)) => return Err(e),
				Err(e) => {
					let panic_msg = Self::panic_payload_to_string(e);
					error!("failed to stop peer thread {:?}: {}", thread_id, panic_msg);
					return Err(Error::PeerThreadPanic(format!(
						"thread {:?}: {}",
						thread_id, panic_msg
					)));
				}
			}
		} else {
			debug!(
				"attempt to stop thread {:?} from itself",
				peer_thread.thread().id()
			);
		}

		Ok(())
	}

	fn panic_payload_to_string(payload: Box<dyn Any + Send + 'static>) -> String {
		match payload.downcast::<String>() {
			Ok(msg) => *msg,
			Err(payload) => match payload.downcast::<&'static str>() {
				Ok(msg) => (*msg).to_owned(),
				Err(_) => "unknown panic payload".to_owned(),
			},
		}
	}
}

#[derive(Clone)]
pub struct ConnHandle {
	/// Channel to allow sending data through the connection
	pub send_channel: crossbeam::channel::Sender<Msg>,
}

impl ConnHandle {
	/// Send msg via the synchronous, bounded channel (sync_sender).
	/// Two possible failure cases -
	/// * Disconnected: Propagate this up to the caller so the peer connection can be closed.
	/// * Full: Propagate this up to the caller so the backpressured peer can be closed.
	pub fn send(&self, msg: Msg) -> Result<(), Error> {
		match self.send_channel.try_send(msg) {
			Ok(()) => Ok(()),
			Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
				Err(Error::Send("try_send disconnected".to_owned()))
			}
			Err(crossbeam::channel::TrySendError::Full(_msg)) => {
				Err(Error::Send("try_send full".to_owned()))
			}
		}
	}
}

#[cfg(test)]
pub(crate) fn disconnected_test_handles() -> (ConnHandle, StopHandle) {
	let (send_tx, send_rx) = crossbeam::channel::bounded(SEND_CHANNEL_CAP);
	drop(send_rx);

	(
		ConnHandle {
			send_channel: send_tx,
		},
		StopHandle {
			stopped: Arc::new(AtomicBool::new(false)),
			reader_thread: None,
			writer_thread: None,
		},
	)
}

pub struct Tracker {
	/// Bytes we've sent.
	pub sent_bytes: Arc<RwLock<RateCounter>>,
	/// Bytes we've received.
	pub received_bytes: Arc<RwLock<RateCounter>>,
}

impl Tracker {
	pub fn new() -> Tracker {
		let received_bytes = Arc::new(RwLock::new(RateCounter::new()));
		let sent_bytes = Arc::new(RwLock::new(RateCounter::new()));
		Tracker {
			received_bytes,
			sent_bytes,
		}
	}

	pub fn inc_received(&self, size: u64) {
		self.received_bytes.write().inc(size);
	}

	pub fn inc_sent(&self, size: u64) {
		self.sent_bytes.write().inc(size);
	}
}

/// Start listening on the provided connection and wraps it. Does not hang
/// the current thread, instead just returns a future and the Connection
/// itself.
pub fn listen<H>(
	stream: TcpDataStream,
	version: ProtocolVersion,
	context_id: u32,
	tracker: Arc<Tracker>,
	sync_state: Arc<SyncState>,
	peer_name: String,
	handler: H,
) -> io::Result<(ConnHandle, StopHandle)>
where
	H: MessageHandler,
{
	let (send_tx, send_rx) = crossbeam::channel::bounded(SEND_CHANNEL_CAP);

	let stopped = Arc::new(AtomicBool::new(false));

	let conn_handle = ConnHandle {
		send_channel: send_tx,
	};

	let (reader_thread, writer_thread) = poll(
		stream,
		conn_handle.clone(),
		version,
		context_id,
		handler,
		send_rx,
		stopped.clone(),
		tracker,
		sync_state,
		peer_name,
	)?;

	Ok((
		conn_handle,
		StopHandle {
			stopped,
			reader_thread: Some(reader_thread),
			writer_thread: Some(writer_thread),
		},
	))
}

fn poll<H>(
	conn: TcpDataStream,
	conn_handle: ConnHandle,
	version: ProtocolVersion,
	context_id: u32,
	handler: H,
	send_rx: crossbeam::channel::Receiver<Msg>,
	stopped: Arc<AtomicBool>,
	tracker: Arc<Tracker>,
	sync_state: Arc<SyncState>,
	peer_name: String,
) -> io::Result<(JoinHandle<Result<(), Error>>, JoinHandle<Result<(), Error>>)>
where
	H: MessageHandler,
{
	// Split out tcp stream out into separate reader/writer halves.
	let reader_stopped = stopped.clone();

	let reader_tracker = tracker.clone();
	let writer_tracker = tracker;
	let writer_stopped = stopped.clone();

	let (reader, mut writer) = conn
		.split()
		.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
	let peer_name1 = peer_name.clone();
	let peer_name_for_cleanup = peer_name.clone();

	let reader_thread = thread::Builder::new()
		.name(format!("peer_read_{}", peer_name1))
		.spawn(move || -> Result<(), Error> {
			let _stop_on_drop = StopOnDrop {
				stopped: reader_stopped.clone(),
			};
			debug!("Started peer_read thread for {}", peer_name1);
			let mut codec = Codec::new(version, context_id, reader);

			let mut secp = match Secp256k1::with_caps(ContextFlag::Commit) {
				Ok(s) => s,
				Err(e) => {
					error!(
						"peer_read for {} failed to start. Unable create secp concext, {}",
						peer_name1, e
					);
					return Err(Error::SecpError(e));
				}
			};

			loop {
				// check the close channel
				if reader_stopped.load(Ordering::Relaxed) {
					debug!("Exited {} because stop was requested", peer_name1);
					break;
				}

				// Note, we are processing messages from a single peer one by one intentionally. Even we can process them in parallel,
				// we don't want to do that because DDOS attacks. One peer can't get more than a single thread of this node.

				// check the read end
				let (next, bytes_read) = codec.read();

				// retry on TimedOut & WouldBlock
				if codec.is_none_state() && !codec.has_buffered_data() {
					match &next {
						Err(Error::Connection(io_err)) => {
							if io_err.kind() == io::ErrorKind::TimedOut
								|| io_err.kind() == io::ErrorKind::WouldBlock
							{
								continue;
							}
						}
						_ => {}
					}
				}

				// During sync process we don't want to ban peers because of abuse. It is expected to maintain high traffic for fast sync
				if !sync_state.is_syncing() {
					// increase the appropriate counter
					reader_tracker.inc_received(bytes_read as u64)
				}

				let message = match try_return!(next, "read income message", peer_name1) {
					Some(message) => message,
					None => continue,
				};

				if reader_stopped.load(Ordering::Relaxed) {
					debug!(
						"Exited {} because stop was requested after read",
						peer_name1
					);
					break;
				}

				let message = match message {
					Message::Unknown(type_byte) => {
						debug!(
							"Received unknown message, type {:?}, len {}.",
							type_byte, bytes_read
						);
						continue;
					}

					message => {
						trace!("Received message, type {}, len {}.", message, bytes_read);
						message
					}
				};

				//debug!("IN_{} {}: {:?}", counter, peer_addr, message);
				let consumed = handler.consume(&mut secp, message)?;
				//debug!("OUT_{} {}: {:?}", counter, peer_addr, consumed);
				match consumed {
					Consumed::Response(resp_msg) => {
						conn_handle.send(resp_msg)?;
					}
					Consumed::Disconnect => {
						debug!("Exited {} because got Consumed::Disconnect", peer_name1);
						break;
					}
					Consumed::None => {}
				}
			}

			debug!("Exiting reader for {}", peer_name1);
			Ok(())
		})?;

	let writer_thread = match thread::Builder::new()
		.name(format!("peer_write_{}", peer_name))
		.spawn(move || -> Result<(), Error> {
			let _stop_on_drop = StopOnDrop {
				stopped: writer_stopped.clone(),
			};
			debug!("Started peer_write thread for {}", peer_name);
			let result = (|| -> Result<(), Error> {
				let mut retry_send = Err(());
				writer.set_write_timeout(BODY_IO_TIMEOUT);
				loop {
					let maybe_data = retry_send.or_else(|_| recv_send_batch(&send_rx));
					retry_send = Err(());
					match maybe_data {
						Ok(data) => {
							let written = try_return!(
								write_message(&mut writer, &data, writer_tracker.clone()),
								"write_message",
								peer_name
							);
							if written.is_none() {
								retry_send = Ok(data);
							}
						}
						Err(RecvTimeoutError::Disconnected) => {
							debug!(
								"peer_write: mpsc channel disconnected during recv_timeout for {}",
								peer_name
							);
							break;
						}
						Err(RecvTimeoutError::Timeout) => {}
					}

					// check the close channel
					if writer_stopped.load(Ordering::Relaxed) {
						debug!("Exiting peer_write thread for {}", peer_name);
						break;
					}
				}
				Ok(())
			})();

			debug!("Shutting down writer connection for {}", peer_name);
			// Intentionally do not propagate shutdown errors here. Callers are
			// interested in the writer loop result; shutdown is best-effort
			// cleanup after that result has already been determined.
			if let Err(e) = writer.shutdown() {
				warn!(
					"Failed to shutdown writer connection for {}: {}",
					peer_name, e
				);
			}
			result
		}) {
		Ok(writer_thread) => writer_thread,
		Err(e) => {
			return Err(stop_reader_after_writer_spawn_error(
				&stopped,
				reader_thread,
				e,
				&peer_name_for_cleanup,
			));
		}
	};
	Ok((reader_thread, writer_thread))
}

fn stop_reader_after_writer_spawn_error(
	stopped: &Arc<AtomicBool>,
	reader_thread: JoinHandle<Result<(), Error>>,
	spawn_error: io::Error,
	peer_name: &str,
) -> io::Error {
	stopped.store(true, Ordering::Relaxed);
	if let Err(e) = StopHandle::join_thread(reader_thread) {
		// Keep this setup-failure path simple: the writer spawn error remains
		// the returned cause, while the reader cleanup failure is logged here.
		error!(
			"failed to stop peer_read thread after peer_write spawn failure for {}: {}",
			peer_name, e
		);
	}
	spawn_error
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::msg::{Ping, Type};
	use mwc_core::global;
	use mwc_core::pow::Difficulty;

	#[test]
	fn send_returns_error_when_channel_is_full() {
		const SEND_FULL_TEST_CONTEXT_ID: u32 = 230;
		global::init_global_chain_type(
			SEND_FULL_TEST_CONTEXT_ID,
			global::ChainTypes::AutomatedTesting,
		)
		.unwrap();
		let (send_channel, _recv_channel) = crossbeam::channel::bounded(0);
		let conn_handle = ConnHandle { send_channel };
		let msg = Msg::new(
			Type::Ping,
			Ping {
				total_difficulty: Difficulty::min(),
				height: 0,
			},
			ProtocolVersion(5),
			SEND_FULL_TEST_CONTEXT_ID,
		)
		.unwrap();

		let err = conn_handle
			.send(msg)
			.expect_err("full send queue should be reported as an error");

		match err {
			Error::Send(message) => assert_eq!(message, "try_send full"),
			other => panic!("expected send error for full queue, got {:?}", other),
		}
	}

	#[test]
	fn recv_send_batch_caps_drained_messages() {
		const SEND_BATCH_TEST_CONTEXT_ID: u32 = 231;
		global::init_global_chain_type(
			SEND_BATCH_TEST_CONTEXT_ID,
			global::ChainTypes::AutomatedTesting,
		)
		.unwrap();
		let (send_channel, recv_channel) = crossbeam::channel::unbounded();

		for _ in 0..(SEND_CHANNEL_CAP + 1) {
			let msg = Msg::new(
				Type::Ping,
				Ping {
					total_difficulty: Difficulty::min(),
					height: 0,
				},
				ProtocolVersion(5),
				SEND_BATCH_TEST_CONTEXT_ID,
			)
			.unwrap();
			send_channel.send(msg).unwrap();
		}

		let data = recv_send_batch(&recv_channel).unwrap();

		assert_eq!(data.len(), SEND_CHANNEL_CAP);
		assert_eq!(recv_channel.len(), 1);
	}

	#[test]
	fn stop_on_drop_sets_stopped_during_panic_unwind() {
		let stopped = Arc::new(AtomicBool::new(false));
		let stopped1 = stopped.clone();

		let result = std::panic::catch_unwind(move || {
			let _stop_on_drop = StopOnDrop { stopped: stopped1 };
			panic!("reader panic");
		});

		assert!(result.is_err());
		assert!(stopped.load(Ordering::Relaxed));
	}

	#[test]
	fn wait_returns_error_when_peer_thread_panics() {
		let reader_thread = thread::spawn(|| panic!("reader panic"));
		let writer_thread = thread::spawn(|| Ok(()));
		let mut stop_handle = StopHandle {
			stopped: Arc::new(AtomicBool::new(false)),
			reader_thread: Some(reader_thread),
			writer_thread: Some(writer_thread),
		};

		let err = stop_handle
			.wait()
			.expect_err("wait should report peer thread panic");

		match err {
			Error::PeerThreadPanic(msg) => assert!(msg.contains("reader panic")),
			e => panic!("unexpected error: {:?}", e),
		}
		assert!(stop_handle.reader_thread.is_none());
		assert!(stop_handle.writer_thread.is_none());
	}

	#[test]
	fn wait_returns_error_when_peer_thread_returns_error() {
		let reader_thread = thread::spawn(|| Err(Error::Internal("reader failed".into())));
		let writer_thread = thread::spawn(|| Ok(()));
		let mut stop_handle = StopHandle {
			stopped: Arc::new(AtomicBool::new(false)),
			reader_thread: Some(reader_thread),
			writer_thread: Some(writer_thread),
		};

		let err = stop_handle
			.wait()
			.expect_err("wait should report peer thread error");

		match err {
			Error::Internal(msg) => assert!(msg.contains("reader failed")),
			e => panic!("unexpected error: {:?}", e),
		}
		assert!(stop_handle.reader_thread.is_none());
		assert!(stop_handle.writer_thread.is_none());
	}

	#[test]
	fn writer_spawn_failure_stops_and_joins_reader_thread() {
		let stopped = Arc::new(AtomicBool::new(false));
		let reader_stopped = stopped.clone();
		let reader_exited = Arc::new(AtomicBool::new(false));
		let reader_exited1 = reader_exited.clone();
		let reader_thread = thread::spawn(move || {
			while !reader_stopped.load(Ordering::Relaxed) {
				thread::sleep(Duration::from_millis(10));
			}
			reader_exited1.store(true, Ordering::Relaxed);
			Ok(())
		});
		let spawn_error = io::Error::new(io::ErrorKind::Other, "writer spawn failed");

		let err =
			stop_reader_after_writer_spawn_error(&stopped, reader_thread, spawn_error, "test_peer");

		assert_eq!(err.kind(), io::ErrorKind::Other);
		assert!(stopped.load(Ordering::Relaxed));
		assert!(reader_exited.load(Ordering::Relaxed));
	}
}
