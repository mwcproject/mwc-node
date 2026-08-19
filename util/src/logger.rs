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

//! Logging wrapper to be used throughout all crates in the workspace.
//!
//! This module exclusively owns the process-global [`log`](mwc_crates::log)
//! logger. External code must never install a global `log` logger directly;
//! every logger installation must use one of this module's initialization
//! functions so repeated and concurrent calls can be rejected before file
//! appenders are constructed.
use mwc_crates::anyhow;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::parking_lot::Mutex;
use mwc_crates::tracing;
use std::cell::RefCell;
use std::ops::Deref;
use std::sync::Arc;

use crate::Error;
use mwc_crates::backtrace::Backtrace;
use mwc_crates::log::{error, info};
use mwc_crates::log::{Level, LevelFilter, Record};
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
use mwc_crates::tracing_subscriber::filter::LevelFilter as TracingLevelFilter;
use mwc_crates::tracing_subscriber::layer::SubscriberExt;
use mwc_crates::tracing_subscriber::registry::LookupSpan;
use mwc_crates::tracing_subscriber::Layer;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::fmt::{Debug, Formatter, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{panic, thread};

lazy_static! {
	/// Flag to observe whether logging was explicitly initialised (don't output otherwise)
	static ref TEST_LOGGER_WAS_INIT: Mutex<bool> = Mutex::new(false);

	static ref LOGGER_BUFFER: Mutex<Option<LogBuffer>> = Mutex::new(None);

	/// Serializes all process-global logger initialization paths. This module is
	/// the exclusive owner of the global `log` logger; external code must never
	/// install one directly.
	static ref LOGGER_INITIALIZED: Mutex<bool> = Mutex::new(false);

	static ref CONSOLE_OUTPUT_ENABLED: AtomicBool = AtomicBool::new(true);
}

std::thread_local! {
	/// Prevents a callback from recursively dispatching records to itself on the same thread.
	/// Nested records still pass through the appender and are retained in `LOGGER_BUFFER`.
	static CALLBACK_DISPATCH_GUARD: RefCell<()> = const { RefCell::new(()) };
}

/// True if everything is running as a console app. Otherwice it is a library,
/// so no console output is expected
pub fn is_console_output_enabled() -> bool {
	CONSOLE_OUTPUT_ENABLED.load(Ordering::Relaxed)
}

const LOGGING_PATTERN: &str = "{d(%Y%m%d %H:%M:%S%.3f)} {h({l})} {M} - {m}{n}";

/// Three archived log files to retain by default.
const DEFAULT_ROTATE_LOG_FILES: u32 = 3 as u32;

/// Number of recent log entries retained for the TUI.
pub const TUI_LOG_BUFFER_CAPACITY: usize = 200;

/// Log Entry
#[derive(Clone, Serialize, Debug)]
#[serde(crate = "serde")]
pub struct LogEntry {
	/// The log message
	pub log: String,
	/// The log levelO
	pub level: Level,
}

/// A batch of pending TUI log entries and the number of older entries omitted.
#[derive(Debug)]
pub struct TuiLogBatch {
	/// Pending entries, ordered from oldest to newest.
	pub entries: Vec<LogEntry>,
	/// Number of older entries overwritten since the previous drain.
	pub omitted: u64,
}

#[derive(Debug)]
struct TuiLogBufferInner {
	entries: VecDeque<LogEntry>,
	omitted: u64,
	capacity: usize,
}

/// Bounded, shared buffer that retains the most recent log entries for the TUI.
#[derive(Clone, Debug)]
pub struct TuiLogBuffer {
	inner: Arc<Mutex<TuiLogBufferInner>>,
}

impl TuiLogBuffer {
	/// Creates a TUI log buffer with the standard capacity.
	pub fn new() -> Self {
		Self::with_capacity(TUI_LOG_BUFFER_CAPACITY)
	}

	fn with_capacity(capacity: usize) -> Self {
		debug_assert!(capacity > 0);
		Self {
			inner: Arc::new(Mutex::new(TuiLogBufferInner {
				entries: VecDeque::with_capacity(capacity),
				omitted: 0,
				capacity,
			})),
		}
	}

	fn push(&self, entry: LogEntry) {
		let mut inner = self.inner.lock();
		if inner.entries.len() == inner.capacity {
			let _ = inner.entries.pop_front();
			// Logging must remain infallible even if this diagnostic counter is exhausted.
			inner.omitted = inner.omitted.saturating_add(1);
		}
		inner.entries.push_back(entry);
	}

	/// Removes all pending entries and resets the omitted-entry counter.
	pub fn drain(&self) -> TuiLogBatch {
		let mut inner = self.inner.lock();
		let entries = inner.entries.drain(..).collect();
		let omitted = std::mem::take(&mut inner.omitted);
		TuiLogBatch { entries, omitted }
	}
}

impl Default for TuiLogBuffer {
	fn default() -> Self {
		Self::new()
	}
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
			log_max_size: Some(1024 * 1024 * 4), // 4 MiB by default
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

fn tracing_level_to_log(level: &tracing::Level) -> Level {
	match *level {
		tracing::Level::ERROR => Level::Error,
		tracing::Level::WARN => Level::Warn,
		tracing::Level::INFO => Level::Info,
		tracing::Level::DEBUG => Level::Debug,
		tracing::Level::TRACE => Level::Trace,
	}
}

fn log_level_to_tracing_filter(level: LevelFilter) -> TracingLevelFilter {
	match level {
		LevelFilter::Off => TracingLevelFilter::OFF,
		LevelFilter::Error => TracingLevelFilter::ERROR,
		LevelFilter::Warn => TracingLevelFilter::WARN,
		LevelFilter::Info => TracingLevelFilter::INFO,
		LevelFilter::Debug => TracingLevelFilter::DEBUG,
		LevelFilter::Trace => TracingLevelFilter::TRACE,
	}
}

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

	if target == "tor_circmgr::mgr"
		&& (msg.contains("All tunnel attempts failed due to timeout")
			|| msg.contains("Request failed"))
	{
		return true;
	}

	if target == "tor_circmgr"
		&& msg.contains("Failed to build preemptive circuit")
		&& msg.contains("Spent too long trying to construct circuits")
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
		let metadata = event.metadata();
		let level = tracing_level_to_log(metadata.level());
		if !mwc_crates::log::log_enabled!(target: metadata.target(), level) {
			return;
		}

		let mut visitor = EventVisitor {
			message: None,
			fields: Vec::new(),
		};
		event.record(&mut visitor);

		if let Some(message) = visitor.into_log_message() {
			let target = metadata.target();

			if should_skip_log(target, &message) {
				return;
			}

			let log_args = format_args!("{}", message);
			let record = Record::builder()
				.args(log_args)
				.level(level)
				.target(target)
				.module_path(Some(target))
				.file(metadata.file())
				.line(metadata.line())
				.build();

			mwc_crates::log::logger().log(&record);
		}
	}
}

#[derive(Debug)]
struct TuiLogAppender {
	buffer: TuiLogBuffer,
	encoder: Box<dyn Encode>,
}

impl Append for TuiLogAppender {
	fn append(&self, record: &Record) -> Result<(), anyhow::Error> {
		let mut writer = SimpleWriter(Vec::new());
		self.encoder.encode(&mut writer, record)?;

		let log = String::from_utf8_lossy(writer.0.as_slice()).to_string();

		let entry = LogEntry {
			log,
			level: record.level(),
		};

		self.buffer.push(entry);
		Ok(())
	}

	fn flush(&self) {}
}

fn active_root_level(config: &LoggingConfig, tui_running: bool) -> LevelFilter {
	[
		(tui_running || config.log_to_stdout).then_some(config.stdout_log_level.to_level_filter()),
		config
			.log_to_file
			.then_some(config.file_log_level.to_level_filter()),
	]
	.into_iter()
	.flatten()
	.max()
	.unwrap_or(LevelFilter::Off)
}

fn install_tracing_bridge(level: LevelFilter) {
	let subscriber = tracing_subscriber::registry()
		.with(Log4rsLayer.with_filter(log_level_to_tracing_filter(level)));
	if let Err(e) = tracing::subscriber::set_global_default(subscriber) {
		// Log4rs is already committed and cannot be rolled back. An embedding
		// application may legitimately own the tracing subscriber.
		error!(
			"Unable to capture Arti/Tor logs. tracing set_global_default failed with error: {}",
			e
		);
	}
}

/// Initialize the process-global logger with the given configuration.
///
/// Initialization is one-shot: after the first successful configuration, every
/// later or concurrent call returns a logging error. An attempt that fails
/// before configuration is committed may be retried.
pub fn init_logger(
	config: Option<&LoggingConfig>,
	tui_logs: Option<TuiLogBuffer>,
) -> Result<(), Error> {
	if let Some(c) = config {
		let mut initialized = LOGGER_INITIALIZED.lock();
		if *initialized {
			return Err(Error::Logging(
				"init_logger, logging is already initialized".into(),
			));
		}

		let tui_running = c.tui_running.unwrap_or(false);

		let level_stdout = c.stdout_log_level.to_level_filter();
		let level_file = c.file_log_level.to_level_filter();
		let root_level = active_root_level(c, tui_running);

		// Start logger
		let stdout = ConsoleAppender::builder()
			.encoder(Box::new(SanitizingEncoder::new(&LOGGING_PATTERN)))
			.build();

		let mut root = Root::builder();

		let mut appenders = vec![];

		if tui_running {
			let tui_logs =
				tui_logs.ok_or_else(|| Error::Logging("init_logger, tui_logs is empty".into()))?;
			let tui_appender = TuiLogAppender {
				encoder: Box::new(SanitizingEncoder::new(&LOGGING_PATTERN)),
				buffer: tui_logs,
			};

			appenders.push(
				Appender::builder()
					.filter(Box::new(ThresholdFilter::new(level_stdout)))
					.build("tui", Box::new(tui_appender)),
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
			// Note, we don't want enforcing restrictive file or directory permissions and without validating ownership/symlink status
			//       because it is overcomplicated the setup for users. Instead we never log security related data.
			let filter = Box::new(ThresholdFilter::new(level_file));
			let file: Box<dyn Append> = if let Some(size) = c.log_max_size {
				let count = c.log_max_files.unwrap_or(DEFAULT_ROTATE_LOG_FILES);
				let roller = FixedWindowRoller::builder()
					.build(&format!("{}.{{}}.gz", c.log_file_path), count)
					.map_err(|e| {
						Error::Logging(format!(
							"init_logger, unable to build FixedWindowRoller, {}",
							e
						))
					})?;
				let policy =
					CompoundPolicy::new(Box::new(SizeTrigger::new(size)), Box::new(roller));

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
			};

			appenders.push(Appender::builder().filter(filter).build("file", file));
			root = root.appender("file");
		}

		let config = Config::builder()
			.appenders(appenders)
			.build(root.build(root_level))
			.map_err(|e| {
				Error::Logging(format!("init_logger, failed to build Config object, {}", e))
			})?;

		init_config_with_err_handler(config, Box::new(|err| println!("Logger error: {}", err)))
			.map_err(|e| {
				Error::Logging(format!("init_logger, failed to register log4rs, {}", e))
			})?;
		*initialized = true;
		drop(initialized);

		install_tracing_bridge(root_level);

		info!(
			"log4rs is initialized, file level: {:?}, stdout level: {:?}, root level: {:?}",
			level_file, level_stdout, root_level
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
	let mut initialized = LOGGER_INITIALIZED.lock();
	if *initialized {
		return Err(Error::Logging(
			"init_test_logger, logging is already initialized".into(),
		));
	}

	let mut logger = LoggingConfig::default();
	logger.log_to_file = false;
	logger.stdout_log_level = Level::Debug;

	let level_stdout = logger.stdout_log_level.to_level_filter();
	let root_level = level_stdout;

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
		.build(root.build(root_level))
		.map_err(|e| {
			Error::Logging(format!(
				"init_test_logger, unable to build log config, {}",
				e
			))
		})?;

	init_config_with_err_handler(config, Box::new(|err| println!("Logger error: {}", err)))
		.map_err(|e| {
			Error::Logging(format!(
				"init_test_logger, failed to register log4rs, {}",
				e
			))
		})?;
	*initialized = true;

	info!(
		"log4rs is initialized, stdout level: {:?}, root level: {:?}",
		level_stdout, root_level
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
			CALLBACK_DISPATCH_GUARD.with(|guard| {
				if let Ok(_dispatch_guard) = guard.try_borrow_mut() {
					(cb)(entry.clone());
				}
			});
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
	let mut initialized = LOGGER_INITIALIZED.lock();
	if *initialized {
		return Err(Error::Logging(
			"init_callback_logger, logging is already initialized".into(),
		));
	}
	let mut logger_buffer = LOGGER_BUFFER.lock();
	if logger_buffer.is_some() {
		return Err(Error::Logging(
			"init_callback_logger, CallbackLoggingConfig is already set".into(),
		));
	}
	let root_level = config.log_level.to_level_filter();

	let callback_appender = CallbackAppender {
		// Logg message formatter
		encoder: Box::new(SanitizingEncoder::new(&LOGGING_PATTERN)),
		callback: config.callback.clone(),
	};

	let mut root = Root::builder();
	let appenders = vec![Appender::builder()
		.filter(Box::new(ThresholdFilter::new(root_level)))
		.build("callback", Box::new(callback_appender))];
	root = root.appender("callback");

	let log4rs_config = Config::builder()
		.appenders(appenders)
		.build(root.build(root_level))
		.map_err(|e| {
			Error::Logging(format!(
				"init_callback_logger, unable to build log4rs config, {}",
				e
			))
		})?;

	*logger_buffer = Some(LogBuffer {
		buffer: VecDeque::with_capacity(config.log_buffer_size),
		log_buffer_size: config.log_buffer_size,
		// current id
		last_id: 0,
	});
	if let Err(e) = init_config_with_err_handler(
		log4rs_config,
		Box::new(|err| println!("Logger error: {}", err)),
	) {
		*logger_buffer = None;
		return Err(Error::Logging(format!(
			"init_callback_logger, failed to register log4rs, {}",
			e
		)));
	}
	*initialized = true;

	CONSOLE_OUTPUT_ENABLED.store(false, Ordering::Relaxed);

	drop(logger_buffer);
	drop(initialized);

	install_tracing_bridge(root_level);

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

#[cfg(test)]
mod tests {
	use super::*;
	use std::process::Command;
	use std::sync::atomic::AtomicUsize;

	const LOGGER_TEST_MODE: &str = "MWC_UTIL_LOGGER_TEST_MODE";
	const LOGGER_TEST_PATH: &str = "MWC_UTIL_LOGGER_TEST_PATH";

	fn file_logging_config(path: String) -> LoggingConfig {
		LoggingConfig {
			log_to_stdout: false,
			log_to_file: true,
			log_file_path: path,
			log_file_append: false,
			log_max_size: None,
			..LoggingConfig::default()
		}
	}

	fn run_logger_child(mode: &str) {
		let tempdir = mwc_crates::tempfile::tempdir().unwrap();
		let log_path = tempdir.path().join("logger.log");
		let output = Command::new(std::env::current_exe().unwrap())
			.arg("logger_process_child")
			.arg("--nocapture")
			.env(LOGGER_TEST_MODE, mode)
			.env(LOGGER_TEST_PATH, &log_path)
			.output()
			.unwrap();

		assert!(
			output.status.success(),
			"logger child failed: stdout={} stderr={}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr)
		);
	}

	fn log_entry(number: usize) -> LogEntry {
		LogEntry {
			log: number.to_string(),
			level: Level::Warn,
		}
	}

	#[test]
	fn active_root_level_uses_only_active_destinations() {
		let mut config = LoggingConfig {
			log_to_stdout: true,
			stdout_log_level: Level::Warn,
			log_to_file: false,
			file_log_level: Level::Debug,
			..LoggingConfig::default()
		};
		assert_eq!(active_root_level(&config, false), LevelFilter::Warn);

		config.log_to_stdout = false;
		assert_eq!(active_root_level(&config, false), LevelFilter::Off);
		assert_eq!(active_root_level(&config, true), LevelFilter::Warn);

		config.log_to_file = true;
		assert_eq!(active_root_level(&config, false), LevelFilter::Debug);
	}

	#[test]
	fn tracing_level_filter_skips_disabled_field_evaluation() {
		let evaluations = AtomicUsize::new(0);
		let subscriber =
			tracing_subscriber::registry().with(Log4rsLayer.with_filter(TracingLevelFilter::WARN));

		tracing::subscriber::with_default(subscriber, || {
			tracing::debug!(
				expensive = evaluations.fetch_add(1, Ordering::SeqCst),
				"filtered event"
			);
		});

		assert_eq!(evaluations.load(Ordering::SeqCst), 0);
	}

	#[test]
	fn repeated_initialization_does_not_truncate_active_log() {
		run_logger_child("repeat");
	}

	#[test]
	fn concurrent_initialization_has_exactly_one_winner() {
		run_logger_child("concurrent");
	}

	#[test]
	fn existing_tracing_subscriber_is_degraded_success() {
		run_logger_child("existing_tracing");
	}

	#[test]
	fn reentrant_callback_is_suppressed_but_nested_logs_are_buffered() {
		run_logger_child("reentrant_callback");
	}

	#[test]
	fn logger_process_child() {
		let Some(mode) = std::env::var_os(LOGGER_TEST_MODE) else {
			return;
		};
		let path = std::env::var_os(LOGGER_TEST_PATH).unwrap();
		let path_string = std::path::PathBuf::from(&path)
			.to_string_lossy()
			.into_owned();

		match mode.to_string_lossy().as_ref() {
			"repeat" => {
				let config = file_logging_config(path_string);
				init_logger(Some(&config), None).unwrap();
				mwc_crates::log::warn!("first initialization marker");
				assert!(init_logger(Some(&config), None).is_err());
				assert!(std::fs::read_to_string(path)
					.unwrap()
					.contains("first initialization marker"));
			}
			"concurrent" => {
				let config = Arc::new(file_logging_config(path_string));
				let barrier = Arc::new(std::sync::Barrier::new(2));
				let calls = (0..2)
					.map(|_| {
						let config = Arc::clone(&config);
						let barrier = Arc::clone(&barrier);
						std::thread::spawn(move || {
							barrier.wait();
							init_logger(Some(&config), None)
						})
					})
					.collect::<Vec<_>>();
				let results = calls
					.into_iter()
					.map(|call| call.join().unwrap())
					.collect::<Vec<_>>();

				assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
				assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
				let error = results.into_iter().find_map(Result::err).unwrap();
				assert!(error.to_string().contains("logging is already initialized"));
			}
			"existing_tracing" => {
				tracing::subscriber::set_global_default(tracing_subscriber::registry()).unwrap();
				let config = file_logging_config(path_string);
				init_logger(Some(&config), None).unwrap();
				mwc_crates::log::warn!("log4rs remains active");
				assert!(std::fs::read_to_string(path)
					.unwrap()
					.contains("log4rs remains active"));
			}
			"reentrant_callback" => {
				let callback_calls = Arc::new(AtomicUsize::new(0));
				let calls_from_callback = Arc::clone(&callback_calls);
				let callback: Box<dyn Fn(LogEntry) + Send + Sync> = Box::new(move |_| {
					calls_from_callback.fetch_add(1, Ordering::SeqCst);
					mwc_crates::log::info!("nested callback marker");
				});

				init_callback_logger(CallbackLoggingConfig {
					log_level: Level::Info,
					log_buffer_size: 16,
					callback: Arc::new(Some(callback)),
				})
				.unwrap();

				assert_eq!(callback_calls.load(Ordering::SeqCst), 1);

				mwc_crates::log::info!("top-level callback marker");
				assert_eq!(callback_calls.load(Ordering::SeqCst), 2);

				let buffered = read_buffered_logs(None, usize::MAX).unwrap();
				assert_eq!(
					buffered
						.iter()
						.filter(|entry| entry.log_entry.log.contains("nested callback marker"))
						.count(),
					2
				);
				assert!(buffered
					.iter()
					.any(|entry| entry.log_entry.log.contains("top-level callback marker")));
			}
			mode => panic!("unknown logger child mode: {}", mode),
		}
	}

	#[test]
	fn skips_expected_tor_circuit_manager_noise() {
		assert!(should_skip_log(
			"tor_circmgr::mgr",
			"All tunnel attempts failed due to timeout"
		));
		assert!(should_skip_log("tor_circmgr::mgr", "Request failed"));
		assert!(should_skip_log(
			"tor_circmgr",
			"Failed to build preemptive circuit [scrubbed] error=Unable to find or build a tunnel: Spent too long trying to construct circuits for this request"
		));

		assert!(!should_skip_log(
			"tor_circmgr::mgr",
			"A different circuit manager warning"
		));
		assert!(!should_skip_log(
			"another_target",
			"All tunnel attempts failed due to timeout"
		));
		assert!(!should_skip_log(
			"tor_circmgr",
			"Failed to build preemptive circuit for a different reason"
		));
	}

	#[test]
	fn tui_log_buffer_retains_latest_entries_and_aggregates_omissions() {
		let buffer = TuiLogBuffer::with_capacity(3);
		let producer = buffer.clone();

		for number in 0..5 {
			producer.push(log_entry(number));
		}

		let batch = buffer.drain();
		assert_eq!(batch.omitted, 2);
		assert_eq!(
			batch
				.entries
				.iter()
				.map(|entry| entry.log.as_str())
				.collect::<Vec<_>>(),
			vec!["2", "3", "4"]
		);

		let next_batch = buffer.drain();
		assert!(next_batch.entries.is_empty());
		assert_eq!(next_batch.omitted, 0);
	}

	#[test]
	fn tui_log_buffer_handles_observed_tor_burst() {
		let buffer = TuiLogBuffer::new();
		for number in 0..363 {
			buffer.push(log_entry(number));
		}

		let batch = buffer.drain();
		assert_eq!(batch.entries.len(), TUI_LOG_BUFFER_CAPACITY);
		assert_eq!(batch.omitted, 163);
		assert_eq!(
			batch.entries.first().map(|entry| entry.log.as_str()),
			Some("163")
		);
		assert_eq!(
			batch.entries.last().map(|entry| entry.log.as_str()),
			Some("362")
		);
	}
}
