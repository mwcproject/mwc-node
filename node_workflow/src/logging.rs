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

use mwc_util::init_logger;
use mwc_util::logger::{LogEntry, LoggingConfig};
use std::sync::mpsc;

/// Init logs for binaries
pub fn init_bin_logs(logging_config: &LoggingConfig) -> Option<mpsc::Receiver<LogEntry>> {
	let (logs_tx, logs_rx) = if logging_config.tui_running.unwrap_or(false) {
		let (logs_tx, logs_rx) = mpsc::sync_channel::<LogEntry>(200);
		(Some(logs_tx), Some(logs_rx))
	} else {
		(None, None)
	};
	init_logger(Some(logging_config), logs_tx);

	info!("Logging is initialized");

	logs_rx
}
