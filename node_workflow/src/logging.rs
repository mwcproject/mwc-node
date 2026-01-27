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

// Loggers setup

use mwc_util::logger::{CallbackLoggingConfig, LogEntry, LoggingConfig};
use std::sync::mpsc;

/// Init logs for binaries
pub fn init_bin_logs(
	logging_config: &LoggingConfig,
) -> Result<Option<mpsc::Receiver<LogEntry>>, String> {
	let (logs_tx, logs_rx) = if logging_config.tui_running.unwrap_or(false) {
		let (logs_tx, logs_rx) = mpsc::sync_channel::<LogEntry>(200);
		(Some(logs_tx), Some(logs_rx))
	} else {
		(None, None)
	};
	mwc_util::logger::init_logger(Some(logging_config), logs_tx)?;

	info!("Logging is initialized");

	Ok(logs_rx)
}

/// Init logs for libraries
pub fn init_buffered_logs(logging_config: CallbackLoggingConfig) -> Result<(), String> {
	mwc_util::logger::init_callback_logger(logging_config)?;
	info!("Buffered/Callback logging is initialized");
	Ok(())
}

/// Get log entries from the buffer
pub fn get_buffered_logs(
	last_known_entry_id: Option<u64>,
	result_size_limit: usize,
) -> Result<Vec<mwc_util::logger::LogBufferedEntry>, String> {
	mwc_util::logger::read_buffered_logs(last_known_entry_id, result_size_limit)
}
