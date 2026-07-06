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

use mwc_crates::cursive::view::View;
use mwc_crates::cursive::Cursive;
use mwc_crates::log::error;

mod constants;
mod logs;
mod menu;
mod mining;
mod peers;
mod status;
mod types;
pub mod ui;
mod version;

fn call_on_name_or_log<V, F>(c: &mut Cursive, context: &str, name: &str, callback: F)
where
	V: View,
	F: FnOnce(&mut V),
{
	if c.call_on_name(name, callback).is_none() {
		error!(
			"TUI {} update target '{}' not found or has unexpected type",
			context, name
		);
	}
}
