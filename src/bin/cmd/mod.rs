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

mod client;
mod config;
mod error;
mod server;

pub use self::client::client_command;
pub use self::config::config_command_server;
pub use self::error::Error;
pub use self::server::server_command;

pub(super) fn utf8_arg_value<'a>(name: &str, value: &'a std::ffi::OsStr) -> Result<&'a str, Error> {
	value.to_str().ok_or_else(|| {
		Error::ArgumentError(format!(
			"Invalid value for --{}: value must be valid UTF-8",
			name
		))
	})
}
