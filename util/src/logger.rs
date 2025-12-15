// Copyright 2019 The Grin Developers
// Copyright 2024 The MWC Developers
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

//! Logging wrapper to be used throughout all crates in the workspace
use std::ops::Deref;
use std::sync::{Arc, Mutex};

use backtrace::Backtrace;
use log::{Level, Record};
use log4rs::append::console::ConsoleAppender;
use log4rs::append::file::FileAppender;
use log4rs::append::rolling_file::{
	policy::compound::roll::fixed_window::FixedWindowRoller,
	policy::compound::trigger::size::SizeTrigger, policy::compound::CompoundPolicy,
	RollingFileAppender,
};
use log4rs::append::Append;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::encode::writer::simple::SimpleWriter;
use log4rs::encode::Encode;
use log4rs::filter::{threshold::ThresholdFilter, Filter, Response};
use std::collections::VecDeque;
use std::fmt::{Debug, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::SyncSender;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{panic, thread};
use tracing::field::{Field, Visit};
use tracing::Event;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

lazy_static! {
	/// Flag to observe whether logging was explicitly initialised (don't output otherwise)
	static ref TEST_LOGGER_WAS_INIT: Mutex<bool> = Mutex::new(false);

	static ref LOGGER_BUFFER: Mutex<Option<LogBuffer>> = Mutex::new(None);

	static ref CONSOLE_OUTPUT_ENABLED: AtomicBool = AtomicBool::new(true);
}

/// True if everything is running as a console app. Otherwice it is a library,
/// so no console output is expected
pub fn is_console_output_enabled() -> bool {
	CONSOLE_OUTPUT_ENABLED.load(Ordering::Relaxed)
}

const LOGGING_PATTERN: &str = "{d(%Y%m%d %H:%M:%S%.3f)} {h({l})} {M} - {m}{n}";

/// 32 log files to rotate over by default
const DEFAULT_ROTATE_LOG_FILES: u32 = 32 as u32;

/// Log Entry
#[derive(Clone, Serialize, Debug)]
pub struct LogEntry {
	/// The log message
	pub log: String,
	/// The log levelO
	pub level: Level,
}

/// Log entry for the buffer based logging
#[derive(Clone, Serialize, Debug)]
pub struct LogBufferedEntry {
	/// The log message
	pub log_entry: LogEntry,
	/// time in ms
	pub time_stamp: u64,
	/// id
	pub id: u64,
}

/// Log buffer for buffered/callback logging
pub struct LogBuffer {
	// The log messages
	buffer: VecDeque<LogBufferedEntry>,
	log_buffer_size: usize,
	// current id
	last_id: u64,
}

/// Logging config
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoggingConfig {
	/// whether to log to stdout
	pub log_to_stdout: bool,
	/// logging level for stdout
	pub stdout_log_level: Level,
	/// whether to log to file
	pub log_to_file: bool,
	/// log file level
	pub file_log_level: Level,
	/// Log file path
	pub log_file_path: String,
	/// Whether to append to log or replace
	pub log_file_append: bool,
	/// Size of the log in bytes to rotate over (optional)
	pub log_max_size: Option<u64>,
	/// Number of the log files to rotate over (optional)
	pub log_max_files: Option<u32>,
	/// Whether the tui is running (optional)
	pub tui_running: Option<bool>,
}

impl Default for LoggingConfig {
	fn default() -> LoggingConfig {
		LoggingConfig {
			log_to_stdout: true,
			stdout_log_level: Level::Warn,
			log_to_file: true,
			file_log_level: Level::Info,
			log_file_path: String::from("mwc.log"),
			log_file_append: true,
			log_max_size: Some(1024 * 1024 * 16), // 16 megabytes default
			log_max_files: Some(DEFAULT_ROTATE_LOG_FILES),
			tui_running: None,
		}
	}
}

/// Logging config
#[derive(Clone)]
pub struct CallbackLoggingConfig {
	/// logging level for stdout
	pub log_level: Level,
	/// Logging buffer Size
	pub log_buffer_size: usize,
	/// Callback for logs
	pub callback: Arc<Option<Box<dyn Fn(LogEntry) + Send + Sync>>>,
}

/// This filter is rejecting messages that doesn't start with "mwc"
/// in order to save log space for only Mwc-related records
#[derive(Debug)]
struct MwcFilter;

impl Filter for MwcFilter {
	fn filter(&self, record: &Record<'_>) -> Response {
		if let Some(module_path) = record.module_path() {
			// We don't want libp2p logs for now
			if module_path.starts_with("mwc") && !module_path.contains("libp2p") {
				return Response::Neutral;
			}
		}

		Response::Reject
	}
}

struct MessageVisitor {
	message: Option<String>,
}

impl Visit for MessageVisitor {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		if field.name() == "message" {
			self.message = Some(format!("{:?}", value));
		}
	}
}

struct Log4rsLayer;

impl<S> Layer<S> for Log4rsLayer
where
	S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
	fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
		let mut visitor = MessageVisitor { message: None };
		event.record(&mut visitor);

		if let Some(message) = visitor.message {
			let target = event.metadata().target();
			//let file = event.metadata().file();
			//let line = event.metadata().line();

			// Using very somple event redirection. Otherwise it doesn't work for us
			match *event.metadata().level() {
				tracing::Level::ERROR => error!("{} {}", target, message),
				tracing::Level::WARN => warn!("{} {}", target, message),
				tracing::Level::INFO => info!("{} {}", target, message),
				tracing::Level::DEBUG => debug!("{} {}", target, message),
				tracing::Level::TRACE => trace!("{} {}", target, message),
			}
		}
	}
}

#[derive(Debug)]
struct ChannelAppender {
	output: Mutex<SyncSender<LogEntry>>,
	encoder: Box<dyn Encode>,
}

impl Append for ChannelAppender {
	fn append(&self, record: &Record) -> Result<(), anyhow::Error> {
		let mut writer = SimpleWriter(Vec::new());
		self.encoder.encode(&mut writer, record)?;

		let log = String::from_utf8_lossy(writer.0.as_slice()).to_string();

		let _ = self
			.output
			.lock()
			.expect("Mutex failure")
			.try_send(LogEntry {
				log,
				level: record.level(),
			});

		Ok(())
	}

	fn flush(&self) {}
}

/// Initialize the logger with the given configuration
pub fn init_logger(config: Option<&LoggingConfig>, logs_tx: Option<mpsc::SyncSender<LogEntry>>) {
	if let Some(c) = config {
		let tui_running = c.tui_running.unwrap_or(false);

		let level_stdout = c.stdout_log_level.to_level_filter();
		let level_file = c.file_log_level.to_level_filter();

		// Determine minimum logging level for Root logger
		let level_minimum = if level_stdout > level_file {
			level_stdout
		} else {
			level_file
		};

		// Start logger
		let stdout = ConsoleAppender::builder()
			.encoder(Box::new(PatternEncoder::new(&LOGGING_PATTERN)))
			.build();

		let mut root = Root::builder();

		let mut appenders = vec![];

		if tui_running {
			let channel_appender = ChannelAppender {
				encoder: Box::new(PatternEncoder::new(&LOGGING_PATTERN)),
				output: Mutex::new(logs_tx.unwrap()),
			};

			appenders.push(
				Appender::builder()
					.filter(Box::new(ThresholdFilter::new(level_stdout)))
					.filter(Box::new(MwcFilter))
					.build("tui", Box::new(channel_appender)),
			);
			root = root.appender("tui");
		} else if c.log_to_stdout {
			appenders.push(
				Appender::builder()
					.filter(Box::new(ThresholdFilter::new(level_stdout)))
					.filter(Box::new(MwcFilter))
					.build("stdout", Box::new(stdout)),
			);
			root = root.appender("stdout");
		}

		if c.log_to_file {
			// If maximum log size is specified, use rolling file appender
			// or use basic one otherwise
			let filter = Box::new(ThresholdFilter::new(level_file));
			let file: Box<dyn Append> = {
				if let Some(size) = c.log_max_size {
					let count = c.log_max_files.unwrap_or_else(|| DEFAULT_ROTATE_LOG_FILES);
					let roller = FixedWindowRoller::builder()
						.build(&format!("{}.{{}}.gz", c.log_file_path), count)
						.unwrap();
					let trigger = SizeTrigger::new(size);

					let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

					Box::new(
						RollingFileAppender::builder()
							.append(c.log_file_append)
							.encoder(Box::new(PatternEncoder::new(&LOGGING_PATTERN)))
							.build(c.log_file_path.clone(), Box::new(policy))
							.expect("Failed to create logfile"),
					)
				} else {
					Box::new(
						FileAppender::builder()
							.append(c.log_file_append)
							.encoder(Box::new(PatternEncoder::new(&LOGGING_PATTERN)))
							.build(c.log_file_path.clone())
							.expect("Failed to create logfile"),
					)
				}
			};

			appenders.push(
				Appender::builder()
					.filter(filter)
					.filter(Box::new(MwcFilter))
					.build("file", file),
			);
			root = root.appender("file");
		}

		let config = Config::builder()
			.appenders(appenders)
			.build(root.build(level_minimum))
			.unwrap();

		let _ = log4rs::init_config(config).unwrap();

		// forward tracing events into the `log` crate (i.e. into log4rs)
		// Then set up tracing with your custom layer
		let subscriber = tracing_subscriber::registry().with(Log4rsLayer);
		tracing::subscriber::set_global_default(subscriber).unwrap();

		info!(
			"log4rs is initialized, file level: {:?}, stdout level: {:?}, min. level: {:?}",
			level_file, level_stdout, level_minimum
		);

		// Now, tracing macros will go through your layer and into log4rs
		tracing::info!("Tracing logs are redirected!");
	}

	send_panic_to_log();
}

/// Initializes the logger for unit and integration tests
pub fn init_test_logger() {
	let mut was_init_ref = TEST_LOGGER_WAS_INIT.lock().expect("Mutex failure");
	if *was_init_ref.deref() {
		return;
	}
	let mut logger = LoggingConfig::default();
	logger.log_to_file = false;
	logger.stdout_log_level = Level::Debug;

	let level_stdout = logger.stdout_log_level.to_level_filter();
	let level_minimum = level_stdout; // minimum logging level for Root logger

	// Start logger
	let stdout = ConsoleAppender::builder()
		.encoder(Box::new(PatternEncoder::default()))
		.build();

	let mut root = Root::builder();

	let mut appenders = vec![];

	{
		let filter = Box::new(ThresholdFilter::new(level_stdout));
		appenders.push(
			Appender::builder()
				.filter(filter)
				//.filter(Box::new(MwcFilter))
				.build("stdout", Box::new(stdout)),
		);

		root = root.appender("stdout");
	}

	let config = Config::builder()
		.appenders(appenders)
		.build(root.build(level_minimum))
		.unwrap();

	let _ = log4rs::init_config(config).unwrap();

	info!(
		"log4rs is initialized, stdout level: {:?}, min. level: {:?}",
		level_stdout, level_minimum
	);

	*was_init_ref = true;
}

struct CallbackAppender {
	// Logg message formatter
	encoder: Box<dyn Encode>,
	// Callback for logs
	callback: Arc<Option<Box<dyn Fn(LogEntry) + Send + Sync>>>,
}

impl Debug for CallbackAppender {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("CallbackAppender").finish()
	}
}

impl Append for CallbackAppender {
	fn append(&self, record: &Record) -> Result<(), anyhow::Error> {
		let mut writer = SimpleWriter(Vec::new());
		self.encoder.encode(&mut writer, record)?;

		let log = String::from_utf8_lossy(writer.0.as_slice()).to_string();
		let entry = LogEntry {
			log,
			level: record.level(),
		};

		if let Some(cb) = &*self.callback {
			(cb)(entry.clone());
		}

		let mut logger_buffer = LOGGER_BUFFER.lock().expect("Mutex failure");
		if let Some(logger_buffer) = &mut *logger_buffer {
			while logger_buffer.buffer.len() >= logger_buffer.log_buffer_size {
				let _ = logger_buffer.buffer.pop_front();
			}
			logger_buffer.buffer.push_back(LogBufferedEntry {
				log_entry: entry,
				time_stamp: SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap()
					.as_millis() as u64,
				id: logger_buffer.last_id,
			});
			logger_buffer.last_id += 1;
		}
		Ok(())
	}

	fn flush(&self) {}
}

/// Init logs as a callback logs
pub fn init_callback_logger(config: CallbackLoggingConfig) {
	CONSOLE_OUTPUT_ENABLED.store(false, Ordering::Relaxed);

	{
		let mut logger_buffer = LOGGER_BUFFER.lock().expect("Mutex failure");
		*logger_buffer = Some(LogBuffer {
			buffer: VecDeque::with_capacity(config.log_buffer_size),
			log_buffer_size: config.log_buffer_size,
			// current id
			last_id: 0,
		});
	}

	let callback_appender = CallbackAppender {
		// Logg message formatter
		encoder: Box::new(PatternEncoder::new(&LOGGING_PATTERN)),
		callback: config.callback.clone(),
	};

	let mut root = Root::builder();
	let appenders = vec![Appender::builder()
		.filter(Box::new(ThresholdFilter::new(
			config.log_level.to_level_filter(),
		)))
		.filter(Box::new(MwcFilter))
		.build("callback", Box::new(callback_appender))];
	root = root.appender("callback");

	let log4rs_config = Config::builder()
		.appenders(appenders)
		.build(root.build(config.log_level.to_level_filter()))
		.unwrap();

	let _ = log4rs::init_config(log4rs_config).unwrap();

	// forward tracing events into the `log` crate (i.e. into log4rs)
	// Then set up tracing with your custom layer
	let subscriber = tracing_subscriber::registry().with(Log4rsLayer);
	tracing::subscriber::set_global_default(subscriber).unwrap();

	let cb_enabled = if config.callback.is_some() {
		"ON"
	} else {
		"OFF"
	};

	info!(
		"log4rs is initialized, level: {:?}, buffer size: {}, Callback is {}",
		config.log_level, config.log_buffer_size, cb_enabled
	);
}

/// Read log entries from the buffer
pub fn read_buffered_logs(
	last_known_entry_id: Option<u64>,
	result_size_limit: usize,
) -> Result<Vec<LogBufferedEntry>, String> {
	let logger_buffer = LOGGER_BUFFER.lock().expect("Mutex failure");
	match &*logger_buffer {
		Some(log_buffer) => {
			let starting_id = last_known_entry_id.unwrap_or(0);
			if log_buffer.buffer.back().map(|l| l.id).unwrap_or(0) <= starting_id {
				return Ok(vec![]);
			}

			let mut start_idx = 0;
			if log_buffer.buffer[0].id >= starting_id {
				start_idx = log_buffer.buffer[0].id.saturating_sub(starting_id) as usize;
			}

			let mut result = Vec::new();
			for i in start_idx..log_buffer.buffer.len() {
				match log_buffer.buffer.get(i) {
					Some(itm) => {
						if itm.id > starting_id {
							result.push(itm.clone());
							if result.len() >= result_size_limit {
								break;
							}
						}
					}
					None => break,
				}
			}
			Ok(result)
		}
		None => Err("Buffered/Callback logs are not initialized".into()),
	}
}

/// hook to send panics to logs as well as stderr
fn send_panic_to_log() {
	panic::set_hook(Box::new(|info| {
		let backtrace = Backtrace::new();

		let thread = thread::current();
		let thread = thread.name().unwrap_or("unnamed");

		let msg = match info.payload().downcast_ref::<&'static str>() {
			Some(s) => *s,
			None => match info.payload().downcast_ref::<String>() {
				Some(s) => &**s,
				None => "Box<Any>",
			},
		};

		match info.location() {
			Some(location) => {
				error!(
					"\nthread '{}' panicked at '{}': {}:{}{:?}\n\n",
					thread,
					msg,
					location.file(),
					location.line(),
					backtrace
				);
			}
			None => error!("thread '{}' panicked at '{}'{:?}", thread, msg, backtrace),
		}
		// Node should never print to stdout/std error because it can run without terminal access
	}));
}
