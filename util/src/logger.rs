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
use crate::Mutex;
use std::ops::Deref;

use backtrace::Backtrace;
use std::{panic, thread};

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
use std::sync::mpsc;
use std::sync::mpsc::SyncSender;
use tracing::field::{Field, Visit};
use tracing::Event;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

lazy_static! {
	/// Flag to observe whether logging was explicitly initialised (don't output otherwise)
	static ref WAS_INIT: Mutex<bool> = Mutex::new(false);
	/// Static Logging configuration, should only be set once, before first logging call
	static ref LOGGING_CONFIG: Mutex<LoggingConfig> = Mutex::new(LoggingConfig::default());
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

		let _ = self.output.lock().try_send(LogEntry {
			log,
			level: record.level(),
		});

		Ok(())
	}

	fn flush(&self) {}
}

/// Initialize the logger with the given configuration
pub fn init_logger(config: Option<LoggingConfig>, logs_tx: Option<mpsc::SyncSender<LogEntry>>) {
	if let Some(c) = config {
		let tui_running = c.tui_running.unwrap_or(false);
		let mut was_init_ref = WAS_INIT.lock();

		// Save current logging configuration
		let mut config_ref = LOGGING_CONFIG.lock();
		*config_ref = c.clone();

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
							.build(c.log_file_path, Box::new(policy))
							.expect("Failed to create logfile"),
					)
				} else {
					Box::new(
						FileAppender::builder()
							.append(c.log_file_append)
							.encoder(Box::new(PatternEncoder::new(&LOGGING_PATTERN)))
							.build(c.log_file_path)
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

		// Mark logger as initialized
		*was_init_ref = true;
	}

	send_panic_to_log();
}

/// Initializes the logger for unit and integration tests
pub fn init_test_logger() {
	let mut was_init_ref = WAS_INIT.lock();
	if *was_init_ref.deref() {
		return;
	}
	let mut logger = LoggingConfig::default();
	logger.log_to_file = false;
	logger.stdout_log_level = Level::Debug;

	// Save current logging configuration
	let mut config_ref = LOGGING_CONFIG.lock();
	*config_ref = logger;

	let level_stdout = config_ref.stdout_log_level.to_level_filter();
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
