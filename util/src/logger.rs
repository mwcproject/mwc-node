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
use mwc_crates::anyhow;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::log4rs;
use mwc_crates::parking_lot::Mutex;
use mwc_crates::tracing;
use std::ops::Deref;
use std::sync::Arc;

use crate::Error;
use mwc_crates::backtrace::Backtrace;
use mwc_crates::log::{error, info};
use mwc_crates::log::{Level, Record};
use mwc_crates::log4rs::append::console::ConsoleAppender;
use mwc_crates::log4rs::append::file::FileAppender;
use mwc_crates::log4rs::append::rolling_file::{
	policy::compound::roll::fixed_window::FixedWindowRoller,
	policy::compound::trigger::size::SizeTrigger, policy::compound::CompoundPolicy,
	RollingFileAppender,
};
use mwc_crates::log4rs::append::Append;
use mwc_crates::log4rs::config::{init_config_with_err_handler, Appender, Config, Root};
use mwc_crates::log4rs::encode::pattern::PatternEncoder;
use mwc_crates::log4rs::encode::writer::simple::SimpleWriter;
use mwc_crates::log4rs::encode::Encode;
use mwc_crates::log4rs::filter::threshold::ThresholdFilter;
use mwc_crates::serde::{self, Deserialize, Serialize};
use mwc_crates::tracing::field::{Field, Visit};
use mwc_crates::tracing::Event;
use mwc_crates::tracing_subscriber;
use mwc_crates::tracing_subscriber::layer::SubscriberExt;
use mwc_crates::tracing_subscriber::registry::LookupSpan;
use mwc_crates::tracing_subscriber::Layer;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::fmt::{Debug, Formatter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{panic, thread};

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
#[serde(crate = "serde")]
pub struct LogEntry {
	/// The log message
	pub log: String,
	/// The log levelO
	pub level: Level,
}

/// Log entry for the buffer based logging
#[derive(Clone, Serialize, Debug)]
#[serde(crate = "serde")]
pub struct LogBufferedEntry {
	/// The log message
	pub log_entry: LogEntry,
	/// time in ms
	pub time_stamp: u128,
	/// id
	pub id: u64,
}

/// Log buffer for buffered/callback logging
pub struct LogBuffer {
	// The log messages
	buffer: VecDeque<LogBufferedEntry>,
	// Note, even with log_buffer_size value 0, buffer will have at least one entry
	// Note, buffer retains up to log_buffer_size + 1 recirds
	log_buffer_size: usize,
	// current id
	last_id: u64,
}

/// Logging config
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(crate = "serde")]
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

struct EventVisitor {
	message: Option<String>,
	fields: Vec<String>,
}

#[derive(Debug)]
struct SanitizingEncoder {
	inner: PatternEncoder,
}

impl SanitizingEncoder {
	fn new(pattern: &str) -> Self {
		Self {
			inner: PatternEncoder::new(pattern),
		}
	}
}

impl Encode for SanitizingEncoder {
	fn encode(
		&self,
		w: &mut dyn mwc_crates::log4rs::encode::Write,
		record: &Record,
	) -> anyhow::Result<()> {
		let mut message = String::new();
		write!(&mut message, "{}", record.args())
			.map_err(|_| anyhow::Error::msg("failed to format log record message"))?;
		// Escape untrusted log text before the terminal/TUI sees it.
		let message = crate::escape_to_printable_ascii(&message);
		let log_args = format_args!("{}", message);
		let sanitized_record = Record::builder()
			.args(log_args)
			.level(record.level())
			.target(record.target())
			.module_path(record.module_path())
			.file(record.file())
			.line(record.line())
			.build();

		self.inner.encode(w, &sanitized_record)
	}
}

impl EventVisitor {
	fn record_value(&mut self, field: &Field, value: String) {
		if field.name() == "message" {
			self.message = Some(value);
		} else {
			self.fields.push(format!("{}={}", field.name(), value));
		}
	}

	fn into_log_message(self) -> Option<String> {
		let message = match (self.message, self.fields.is_empty()) {
			(Some(message), true) => Some(message),
			(Some(message), false) => Some(format!("{} {}", message, self.fields.join(" "))),
			(None, false) => Some(self.fields.join(" ")),
			(None, true) => None,
		}?;

		Some(message)
	}
}

impl Visit for EventVisitor {
	fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
		self.record_value(field, format!("{:?}", value));
	}
}

struct Log4rsLayer;

fn should_skip_log(target: &str, msg: &str) -> bool {
	// Filtering Arti false alarm messages.
	// Intentionally the event level is not checked. msg.contains used to suppress noisy massages that user don't
	//  to know about.
	if target == "tor_hsservice::ipt_mgr"
		&& msg.contains("missing previous key")
		&& msg.contains("Regenerating")
	{
		return true;
	}

	false
}

impl<S> Layer<S> for Log4rsLayer
where
	S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
	fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
		let mut visitor = EventVisitor {
			message: None,
			fields: Vec::new(),
		};
		event.record(&mut visitor);

		if let Some(message) = visitor.into_log_message() {
			let target = event.metadata().target();

			if should_skip_log(target, &message) {
				return;
			}

			let level = match *event.metadata().level() {
				tracing::Level::ERROR => Level::Error,
				tracing::Level::WARN => Level::Warn,
				tracing::Level::INFO => Level::Info,
				tracing::Level::DEBUG => Level::Debug,
				tracing::Level::TRACE => Level::Trace,
			};

			let log_args = format_args!("{}", message);
			let record = Record::builder()
				.args(log_args)
				.level(level)
				.target(target)
				.module_path(Some(target))
				.file(event.metadata().file())
				.line(event.metadata().line())
				.build();

			mwc_crates::log::logger().log(&record);
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

		let entry = LogEntry {
			log,
			level: record.level(),
		};

		match self.output.lock().try_send(entry) {
			Ok(()) => Ok(()),
			Err(TrySendError::Full(_entry)) => Err(anyhow::Error::msg("TUI log channel is full")),
			Err(TrySendError::Disconnected(_entry)) => {
				Err(anyhow::Error::msg("TUI log channel is disconnected"))
			}
		}
	}

	fn flush(&self) {}
}

/// Initialize the logger with the given configuration
pub fn init_logger(
	config: Option<&LoggingConfig>,
	logs_tx: Option<mpsc::SyncSender<LogEntry>>,
) -> Result<(), Error> {
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
			.encoder(Box::new(SanitizingEncoder::new(&LOGGING_PATTERN)))
			.build();

		let mut root = Root::builder();

		let mut appenders = vec![];

		if tui_running {
			let logs_tx =
				logs_tx.ok_or_else(|| Error::Logging("init_logger, logs_tx is empty".into()))?;
			let channel_appender = ChannelAppender {
				encoder: Box::new(SanitizingEncoder::new(&LOGGING_PATTERN)),
				output: Mutex::new(logs_tx),
			};

			appenders.push(
				Appender::builder()
					.filter(Box::new(ThresholdFilter::new(level_stdout)))
					.build("tui", Box::new(channel_appender)),
			);
			root = root.appender("tui");
		} else if c.log_to_stdout {
			appenders.push(
				Appender::builder()
					.filter(Box::new(ThresholdFilter::new(level_stdout)))
					.build("stdout", Box::new(stdout)),
			);
			root = root.appender("stdout");
		}

		if c.log_to_file {
			// If maximum log size is specified, use rolling file appender
			// or use basic one otherwise
			// Note, we don't want enforcing restrictive file or directory permissions and without validating ownership/symlink status
			//       because it is overcomplicated the setup for users. Instead we never log security related data.
			let filter = Box::new(ThresholdFilter::new(level_file));
			let file: Box<dyn Append> = {
				if let Some(size) = c.log_max_size {
					let count = c.log_max_files.unwrap_or_else(|| DEFAULT_ROTATE_LOG_FILES);
					let roller = FixedWindowRoller::builder()
						.build(&format!("{}.{{}}.gz", c.log_file_path), count)
						.map_err(|e| {
							Error::Logging(format!(
								"init_logger, unable to build FixedWindowRoller, {}",
								e
							))
						})?;
					let trigger = SizeTrigger::new(size);

					let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

					Box::new(
						RollingFileAppender::builder()
							.append(c.log_file_append)
							.encoder(Box::new(SanitizingEncoder::new(&LOGGING_PATTERN)))
							.build(c.log_file_path.clone(), Box::new(policy))
							.map_err(|e| {
								Error::Logging(format!(
									"init_logger, failed to create logfile at {}, {}",
									c.log_file_path, e
								))
							})?,
					)
				} else {
					Box::new(
						FileAppender::builder()
							.append(c.log_file_append)
							.encoder(Box::new(SanitizingEncoder::new(&LOGGING_PATTERN)))
							.build(c.log_file_path.clone())
							.map_err(|e| {
								Error::Logging(format!(
									"init_logger, failed to create logfile at {}, {}",
									c.log_file_path, e
								))
							})?,
					)
				}
			};

			appenders.push(Appender::builder().filter(filter).build("file", file));
			root = root.appender("file");
		}

		let config = Config::builder()
			.appenders(appenders)
			.build(root.build(level_minimum))
			.map_err(|e| {
				Error::Logging(format!("init_logger, failed to build Config object, {}", e))
			})?;

		let _ =
			init_config_with_err_handler(config, Box::new(|err| println!("Logger error: {}", err)))
				.map_err(|e| {
					Error::Logging(format!("init_logger, failed to init log4rs, {}", e))
				})?;

		// forward tracing events into the `log` crate (i.e. into log4rs)
		// Then set up tracing with your custom layer
		let subscriber = tracing_subscriber::registry().with(Log4rsLayer);
		tracing::subscriber::set_global_default(subscriber).map_err(|e| {
			Error::Logging(format!(
				"init_logger, failed to redirect logs with tracing, {}",
				e
			))
		})?;

		info!(
			"log4rs is initialized, file level: {:?}, stdout level: {:?}, min. level: {:?}",
			level_file, level_stdout, level_minimum
		);

		// Now, tracing macros will go through your layer and into log4rs
		tracing::info!("Tracing logs are redirected!");
	}

	send_panic_to_log();

	Ok(())
}

/// Initializes the logger for unit and integration tests
pub fn init_test_logger() -> Result<(), Error> {
	let mut was_init_ref = TEST_LOGGER_WAS_INIT.lock();
	if *was_init_ref.deref() {
		return Ok(());
	}
	let mut logger = LoggingConfig::default();
	logger.log_to_file = false;
	logger.stdout_log_level = Level::Debug;

	let level_stdout = logger.stdout_log_level.to_level_filter();
	let level_minimum = level_stdout; // minimum logging level for Root logger

	// Start logger
	let stdout = ConsoleAppender::builder()
		.encoder(Box::new(SanitizingEncoder::new(&LOGGING_PATTERN)))
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
		.map_err(|e| {
			Error::Logging(format!(
				"init_test_logger, unable to build log config, {}",
				e
			))
		})?;

	_ = log4rs::init_config(config).map_err(|e| {
		Error::Logging(format!(
			"init_test_logger, unable to init the testing logs, {}",
			e
		))
	})?;

	info!(
		"log4rs is initialized, stdout level: {:?}, min. level: {:?}",
		level_stdout, level_minimum
	);

	*was_init_ref = true;

	Ok(())
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

		let mut logger_buffer = LOGGER_BUFFER.lock();
		if let Some(logger_buffer) = &mut *logger_buffer {
			// logger_buffer.buffer will have at least one entry
			while logger_buffer.buffer.len() > logger_buffer.log_buffer_size {
				let _ = logger_buffer.buffer.pop_front();
			}

			let time_stamp = match SystemTime::now().duration_since(UNIX_EPOCH) {
				Ok(dur) => dur.as_millis(),
				Err(_) => return Err(anyhow::Error::msg("Invalid system time")),
			};

			let id = logger_buffer.last_id;
			logger_buffer.last_id = logger_buffer.last_id.checked_add(1).ok_or_else(|| {
				anyhow::Error::msg("last_id reach a limit, log buffering will be stopped")
			})?;

			logger_buffer.buffer.push_back(LogBufferedEntry {
				log_entry: entry,
				time_stamp,
				id,
			});
		} else {
			return Err(anyhow::Error::msg("LOGGER_BUFFER is not initialized yet"));
		}
		Ok(())
	}

	fn flush(&self) {}
}

/// Init logs as a callback logs. By design the first callback and cached buffer remain active for
/// the process lifetime. It is expected that logging system can be set once and never changed after.
pub fn init_callback_logger(config: CallbackLoggingConfig) -> Result<(), Error> {
	let mut logger_buffer = LOGGER_BUFFER.lock();
	if logger_buffer.is_some() {
		return Err(Error::Logging(
			"init_callback_logger, CallbackLoggingConfig is already set".into(),
		));
	}

	let callback_appender = CallbackAppender {
		// Logg message formatter
		encoder: Box::new(SanitizingEncoder::new(&LOGGING_PATTERN)),
		callback: config.callback.clone(),
	};

	let mut root = Root::builder();
	let appenders = vec![Appender::builder()
		.filter(Box::new(ThresholdFilter::new(
			config.log_level.to_level_filter(),
		)))
		.build("callback", Box::new(callback_appender))];
	root = root.appender("callback");

	let log4rs_config = Config::builder()
		.appenders(appenders)
		.build(root.build(config.log_level.to_level_filter()))
		.map_err(|e| {
			Error::Logging(format!(
				"init_callback_logger, unable to build log4rs config, {}",
				e
			))
		})?;

	let _ = log4rs::init_config(log4rs_config).map_err(|e| {
		Error::Logging(format!(
			"init_callback_logger, unable to init log4rs, {}",
			e
		))
	})?;

	CONSOLE_OUTPUT_ENABLED.store(false, Ordering::Relaxed);

	*logger_buffer = Some(LogBuffer {
		buffer: VecDeque::with_capacity(config.log_buffer_size),
		log_buffer_size: config.log_buffer_size,
		// current id
		last_id: 0,
	});

	drop(logger_buffer);

	// forward tracing events into the `log` crate (i.e. into log4rs)
	// Then set up tracing with your custom layer
	let subscriber = tracing_subscriber::registry().with(Log4rsLayer);
	if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
		// Logs capturing is not fatal error, so we can go forward
		error!(
			"Unable to capture Arti/Tor logs. tracing set_global_default failed with error: {}",
			e
		);
	}

	let cb_enabled = if config.callback.is_some() {
		"ON"
	} else {
		"OFF"
	};

	info!(
		"log4rs is initialized, level: {:?}, buffer size: {}, Callback is {}",
		config.log_level, config.log_buffer_size, cb_enabled
	);

	Ok(())
}

/// Read log entries from the buffer
/// Note, because of logs rotation some log records can be skipped.
pub fn read_buffered_logs(
	last_known_entry_id: Option<u64>,
	result_size_limit: usize,
) -> Result<Vec<LogBufferedEntry>, Error> {
	if result_size_limit == 0 {
		return Ok(vec![]);
	}

	let logger_buffer = LOGGER_BUFFER.lock();
	match &*logger_buffer {
		Some(log_buffer) => {
			let starting_id = match last_known_entry_id {
				Some(id) => id.checked_add(1).ok_or_else(|| {
					Error::DataOverflow(format!(
						"LogBuffer::read_buffered_logs, last_known_entry_id={}",
						id
					))
				})?,
				None => 0,
			};

			match log_buffer.buffer.back() {
				Some(dt) => {
					if dt.id < starting_id {
						return Ok(vec![]);
					}
				}
				None => return Ok(vec![]),
			};

			let mut start_idx: usize = 0;
			if log_buffer.buffer[0].id < starting_id {
				// Safe: subtraction is guarded by the comparison above.
				start_idx =
					usize::try_from(starting_id - log_buffer.buffer[0].id).map_err(|_| {
						Error::DataOverflow("loggers::read_buffered_logs for start_idx".into())
					})?;
			}

			let mut result = Vec::new();
			// log_buffer.buffer.len() is limited by log_buffer_size. log_buffer_size is relatevly
			// small number to garantee be less than u32 max.
			for i in start_idx..log_buffer.buffer.len() {
				match log_buffer.buffer.get(i) {
					Some(itm) => {
						if itm.id >= starting_id {
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
		None => Err(Error::Logging(
			"LogBuffer::read_buffered_logs, logger buffer is not initialized".into(),
		)),
	}
}

/// hook to send panics to logs as well as stderr.
/// We understand that the backtraces will persist in log files and accept it. It is more important to
/// be able to debug possible issue, than hide runtime data
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
