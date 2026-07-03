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

//! Mining status view definition

use std::cmp::Ordering;
use std::convert::TryFrom;

use mwc_crates::chrono::prelude::{DateTime, Utc};
use mwc_crates::cursive::direction::Orientation;
use mwc_crates::cursive::event::Key;
use mwc_crates::cursive::traits::{Nameable, Resizable};
use mwc_crates::cursive::view::View;
use mwc_crates::cursive::views::{
	Button, Dialog, LinearLayout, OnEventView, Panel, ResizedView, StackView, TextView,
};
use mwc_crates::cursive::Cursive;
use mwc_crates::log::error;
use std::sync::atomic;
use std::time;

use super::call_on_name_or_log;
use crate::tui::constants::{
	MAIN_MENU, SUBMENU_MINING_BUTTON, TABLE_MINING_DIFF_STATUS, TABLE_MINING_STATUS, VIEW_MINING,
};
use crate::tui::types::TUIStatusListener;

use mwc_crates::cursive_table_view::{TableView, TableViewItem};
use mwc_servers::{DiffBlock, ServerStats, WorkerStats};

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum StratumWorkerColumn {
	Id,
	IsConnected,
	LastSeen,
	PowDifficulty,
	NumAccepted,
	NumRejected,
	NumStale,
	NumBlocksFound,
}

impl StratumWorkerColumn {
	fn _as_str(&self) -> &str {
		match *self {
			StratumWorkerColumn::Id => "ID",
			StratumWorkerColumn::IsConnected => "Connected",
			StratumWorkerColumn::LastSeen => "Last Seen",
			StratumWorkerColumn::PowDifficulty => "PowDifficulty",
			StratumWorkerColumn::NumAccepted => "Num Accepted",
			StratumWorkerColumn::NumRejected => "Num Rejected",
			StratumWorkerColumn::NumStale => "Num Stale",
			StratumWorkerColumn::NumBlocksFound => "Blocks Found",
		}
	}
}

impl TableViewItem<StratumWorkerColumn> for WorkerStats {
	fn to_column(&self, column: StratumWorkerColumn) -> String {
		match column {
			StratumWorkerColumn::Id => self.id.clone(),
			StratumWorkerColumn::IsConnected => self.is_connected.to_string(),
			StratumWorkerColumn::LastSeen => format_worker_last_seen(self.last_seen),
			StratumWorkerColumn::PowDifficulty => self.pow_difficulty.to_string(),
			StratumWorkerColumn::NumAccepted => self.num_accepted.to_string(),
			StratumWorkerColumn::NumRejected => self.num_rejected.to_string(),
			StratumWorkerColumn::NumStale => self.num_stale.to_string(),
			StratumWorkerColumn::NumBlocksFound => self.num_blocks_found.to_string(),
		}
	}

	fn cmp(&self, other: &Self, column: StratumWorkerColumn) -> Ordering
	where
		Self: Sized,
	{
		match column {
			StratumWorkerColumn::Id => self.id.cmp(&other.id),
			StratumWorkerColumn::IsConnected => self.is_connected.cmp(&other.is_connected),
			StratumWorkerColumn::LastSeen => self.last_seen.cmp(&other.last_seen),
			StratumWorkerColumn::PowDifficulty => self.pow_difficulty.cmp(&other.pow_difficulty),
			StratumWorkerColumn::NumAccepted => self.num_accepted.cmp(&other.num_accepted),
			StratumWorkerColumn::NumRejected => self.num_rejected.cmp(&other.num_rejected),
			StratumWorkerColumn::NumStale => self.num_stale.cmp(&other.num_stale),
			StratumWorkerColumn::NumBlocksFound => {
				self.num_blocks_found.cmp(&other.num_blocks_found)
			}
		}
	}
}

fn format_worker_last_seen(last_seen: time::SystemTime) -> String {
	system_time_to_utc(last_seen)
		.map(|datetime| datetime.to_string())
		.unwrap_or_else(|| "invalid timestamp".to_string())
}

fn format_diff_block_time(time: u64) -> String {
	i64::try_from(time)
		.ok()
		.and_then(|timestamp| DateTime::<Utc>::from_timestamp(timestamp, 0))
		.map(|datetime| datetime.to_string())
		.unwrap_or_else(|| "invalid timestamp".to_string())
}

fn system_time_to_utc(system_time: time::SystemTime) -> Option<DateTime<Utc>> {
	let (seconds, nanos) = match system_time.duration_since(time::UNIX_EPOCH) {
		Ok(duration) => {
			let seconds = i64::try_from(duration.as_secs()).ok()?;
			(seconds, duration.subsec_nanos())
		}
		Err(error) => {
			let duration = error.duration();
			let seconds = i64::try_from(duration.as_secs()).ok()?;
			let nanos = duration.subsec_nanos();
			if nanos == 0 {
				(seconds.checked_neg()?, 0)
			} else {
				(
					seconds.checked_add(1)?.checked_neg()?,
					1_000_000_000 - nanos,
				)
			}
		}
	};

	DateTime::<Utc>::from_timestamp(seconds, nanos)
}

fn show_mining_stack_layer(c: &mut Cursive, layer_name: &str) {
	match c.call_on_name("mining_stack_view", |sv: &mut StackView| {
		if let Some(pos) = sv.find_layer_from_name(layer_name) {
			sv.move_to_front(pos);
			true
		} else {
			false
		}
	}) {
		Some(true) => {}
		Some(false) => {
			error!("TUI mining stack layer '{}' not found", layer_name);
		}
		None => {
			error!(
				"TUI mining stack view 'mining_stack_view' not found or has unexpected type while switching to '{}'",
				layer_name
			);
		}
	}
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
enum DiffColumn {
	Height,
	Hash,
	Difficulty,
	Time,
	Duration,
}

impl DiffColumn {
	fn _as_str(&self) -> &str {
		match *self {
			DiffColumn::Height => "Height",
			DiffColumn::Hash => "Hash",
			DiffColumn::Difficulty => "Network Difficulty",
			DiffColumn::Time => "Block Time",
			DiffColumn::Duration => "Duration",
		}
	}
}

impl TableViewItem<DiffColumn> for DiffBlock {
	fn to_column(&self, column: DiffColumn) -> String {
		match column {
			DiffColumn::Height => self.block_height.to_string(),
			DiffColumn::Hash => self.block_hash.to_string(),
			DiffColumn::Difficulty => self.difficulty.to_string(),
			DiffColumn::Time => format_diff_block_time(self.time),
			DiffColumn::Duration => format!("{}s", self.duration),
		}
	}

	fn cmp(&self, other: &Self, column: DiffColumn) -> Ordering
	where
		Self: Sized,
	{
		match column {
			DiffColumn::Height => self.block_height.cmp(&other.block_height),
			DiffColumn::Hash => self.block_hash.cmp(&other.block_hash),
			DiffColumn::Difficulty => self.difficulty.cmp(&other.difficulty),
			DiffColumn::Time => self.time.cmp(&other.time),
			DiffColumn::Duration => self.duration.cmp(&other.duration),
		}
	}
}
/// Mining status view
pub struct TUIMiningView;

impl TUIMiningView {
	/// Create the mining view
	pub fn create() -> impl View {
		let devices_button = Button::new_raw("Mining Server Status", |s| {
			show_mining_stack_layer(s, "mining_device_view");
		})
		.with_name(SUBMENU_MINING_BUTTON);
		let difficulty_button = Button::new_raw("Difficulty", |s| {
			show_mining_stack_layer(s, "mining_difficulty_view");
		});
		let mining_submenu = LinearLayout::new(Orientation::Horizontal)
			.child(Panel::new(devices_button))
			.child(Panel::new(difficulty_button));

		let mut table_view = TableView::<WorkerStats, StratumWorkerColumn>::new()
			.column(StratumWorkerColumn::Id, "ID", |c| c.width_percent(6))
			.column(StratumWorkerColumn::IsConnected, "Connected", |c| {
				c.width_percent(14)
			})
			.column(StratumWorkerColumn::LastSeen, "Last Seen", |c| {
				c.width_percent(20)
			})
			.column(StratumWorkerColumn::PowDifficulty, "Difficulty", |c| {
				c.width_percent(10)
			})
			.column(StratumWorkerColumn::NumAccepted, "Accepted", |c| {
				c.width_percent(5)
			})
			.column(StratumWorkerColumn::NumRejected, "Rejected", |c| {
				c.width_percent(5)
			})
			.column(StratumWorkerColumn::NumStale, "Stale", |c| {
				c.width_percent(5)
			})
			.column(StratumWorkerColumn::NumBlocksFound, "Blocks Found", |c| {
				c.width_percent(35)
			})
			.default_column(StratumWorkerColumn::IsConnected);
		table_view.sort_by(StratumWorkerColumn::IsConnected, Ordering::Greater);

		let status_view = LinearLayout::new(Orientation::Vertical)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("  ").with_name("stratum_config_status")),
			)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("  ").with_name("stratum_is_running_status")),
			)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("  ").with_name("stratum_num_workers_status")),
			)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("  ").with_name("stratum_block_height_status")),
			)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("  ").with_name("stratum_blocks_found_status")),
			)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("  ").with_name("stratum_network_difficulty_status")),
			)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("  ").with_name("stratum_network_hashrate")),
			);

		let mining_device_view = LinearLayout::new(Orientation::Vertical)
			.child(status_view)
			.child(ResizedView::with_full_screen(
				Dialog::around(table_view.with_name(TABLE_MINING_STATUS).min_size((50, 20)))
					.title("Mining Workers"),
			))
			.with_name("mining_device_view");

		let diff_status_view = LinearLayout::new(Orientation::Vertical)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("Tip Height: "))
					.child(TextView::new("").with_name("diff_cur_height")),
			)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("Difficulty Adjustment Window: "))
					.child(TextView::new("").with_name("diff_adjust_window")),
			)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("Average Block Time: "))
					.child(TextView::new("").with_name("diff_avg_block_time")),
			)
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(TextView::new("Average Difficulty: "))
					.child(TextView::new("").with_name("diff_avg_difficulty")),
			);

		let diff_table_view = TableView::<DiffBlock, DiffColumn>::new()
			.column(DiffColumn::Height, "Height", |c| c.width_percent(15))
			.column(DiffColumn::Hash, "Hash", |c| c.width_percent(15))
			.column(DiffColumn::Difficulty, "Network Difficulty", |c| {
				c.width_percent(15)
			})
			.column(DiffColumn::Time, "Block Time", |c| c.width_percent(30))
			.column(DiffColumn::Duration, "Duration", |c| c.width_percent(25))
			.default_column(DiffColumn::Height);

		let mining_difficulty_view = LinearLayout::new(Orientation::Vertical)
			.child(diff_status_view)
			.child(ResizedView::with_full_screen(
				Dialog::around(
					diff_table_view
						.with_name(TABLE_MINING_DIFF_STATUS)
						.min_size((50, 20)),
				)
				.title("Mining Difficulty Data"),
			))
			.with_name("mining_difficulty_view");

		let view_stack = StackView::new()
			.layer(mining_difficulty_view)
			.layer(mining_device_view)
			.with_name("mining_stack_view");

		let mining_view = LinearLayout::new(Orientation::Vertical)
			.child(mining_submenu)
			.child(view_stack);

		let mining_view = OnEventView::new(mining_view).on_pre_event(Key::Esc, move |c| {
			if let Err(e) = c.focus_name(MAIN_MENU) {
				error!(
					"TUI main menu focus target '{}' not found or cannot be focused: {:?}",
					MAIN_MENU, e
				);
			}
		});

		mining_view.with_name(VIEW_MINING)
	}
}

impl TUIStatusListener for TUIMiningView {
	/// update
	fn update(c: &mut Cursive, stats: &ServerStats) {
		call_on_name_or_log(c, "mining", "diff_cur_height", |t: &mut TextView| {
			t.set_content(stats.diff_stats.height.to_string());
		});
		call_on_name_or_log(c, "mining", "diff_adjust_window", |t: &mut TextView| {
			t.set_content(stats.diff_stats.window_size.to_string());
		});
		let dur = time::Duration::from_secs(stats.diff_stats.average_block_time);
		call_on_name_or_log(c, "mining", "diff_avg_block_time", |t: &mut TextView| {
			t.set_content(format!("{} Secs", dur.as_secs()));
		});
		call_on_name_or_log(c, "mining", "diff_avg_difficulty", |t: &mut TextView| {
			t.set_content(stats.diff_stats.average_difficulty.to_string());
		});

		let mut diff_stats = stats.diff_stats.last_blocks.clone();
		diff_stats.reverse();
		call_on_name_or_log(
			c,
			"mining",
			TABLE_MINING_DIFF_STATUS,
			|t: &mut TableView<DiffBlock, DiffColumn>| {
				t.set_items(diff_stats);
			},
		);
		let stratum_stats = &stats.stratum_stats;
		let worker_stats = stratum_stats.get_worker_stats();
		let stratum_enabled = format!(
			"Mining server enabled: {}",
			stratum_stats.is_enabled.load(atomic::Ordering::Relaxed)
		);
		let stratum_is_running = format!(
			"Mining server running: {}",
			stratum_stats.is_running.load(atomic::Ordering::Relaxed)
		);
		let num_workers = stratum_stats.num_workers.load(atomic::Ordering::Relaxed);
		let stratum_num_workers = format!("Active workers:        {}", num_workers);
		let stratum_blocks_found = format!(
			"Blocks Found:          {}",
			stratum_stats.blocks_found.load(atomic::Ordering::Relaxed)
		);
		let stratum_block_height = match num_workers {
			0 => "Solving Block Height:  n/a".to_string(),
			_ => format!(
				"Solving Block Height:  {}",
				stratum_stats.block_height.load(atomic::Ordering::Relaxed)
			),
		};
		let stratum_network_difficulty = match num_workers {
			0 => "Network Difficulty:    n/a".to_string(),
			_ => format!(
				"Network Difficulty:    {}",
				stratum_stats
					.network_difficulty
					.load(atomic::Ordering::Relaxed)
			),
		};
		let stratum_network_hashrate = match num_workers {
			0 => "Network Hashrate:      n/a".to_string(),
			_ => format!(
				"Network Hashrate C{}:  {:.*}",
				stratum_stats.edge_bits.load(atomic::Ordering::Relaxed),
				2,
				stratum_stats
					.network_hashrate
					.load(atomic::Ordering::Relaxed)
			),
		};

		call_on_name_or_log(c, "mining", "stratum_config_status", |t: &mut TextView| {
			t.set_content(stratum_enabled);
		});
		call_on_name_or_log(
			c,
			"mining",
			"stratum_is_running_status",
			|t: &mut TextView| {
				t.set_content(stratum_is_running);
			},
		);
		call_on_name_or_log(
			c,
			"mining",
			"stratum_num_workers_status",
			|t: &mut TextView| {
				t.set_content(stratum_num_workers);
			},
		);
		call_on_name_or_log(
			c,
			"mining",
			"stratum_blocks_found_status",
			|t: &mut TextView| {
				t.set_content(stratum_blocks_found);
			},
		);
		call_on_name_or_log(
			c,
			"mining",
			"stratum_block_height_status",
			|t: &mut TextView| {
				t.set_content(stratum_block_height);
			},
		);
		call_on_name_or_log(
			c,
			"mining",
			"stratum_network_difficulty_status",
			|t: &mut TextView| {
				t.set_content(stratum_network_difficulty);
			},
		);
		call_on_name_or_log(
			c,
			"mining",
			"stratum_network_hashrate",
			|t: &mut TextView| {
				t.set_content(stratum_network_hashrate);
			},
		);
		call_on_name_or_log(
			c,
			"mining",
			TABLE_MINING_STATUS,
			|t: &mut TableView<WorkerStats, StratumWorkerColumn>| {
				t.set_items_stable(worker_stats);
			},
		);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn format_worker_last_seen_handles_valid_system_time() {
		let last_seen = time::UNIX_EPOCH + time::Duration::new(1, 123_000_000);
		let expected = DateTime::<Utc>::from_timestamp(1, 123_000_000)
			.unwrap()
			.to_string();

		assert_eq!(format_worker_last_seen(last_seen), expected);
	}

	#[test]
	fn format_worker_last_seen_rejects_chrono_out_of_range_system_time() {
		let seconds = DateTime::<Utc>::MAX_UTC.timestamp() as u64 + 1;
		let Some(last_seen) = time::UNIX_EPOCH.checked_add(time::Duration::from_secs(seconds))
		else {
			return;
		};

		assert_eq!(format_worker_last_seen(last_seen), "invalid timestamp");
	}

	#[test]
	fn format_diff_block_time_handles_valid_timestamp() {
		let expected = DateTime::<Utc>::from_timestamp(1, 0).unwrap().to_string();

		assert_eq!(format_diff_block_time(1), expected);
	}

	#[test]
	fn format_diff_block_time_rejects_i64_overflow() {
		assert_eq!(format_diff_block_time(u64::MAX), "invalid timestamp");
	}

	#[test]
	fn format_diff_block_time_rejects_chrono_out_of_range_timestamp() {
		let timestamp = DateTime::<Utc>::MAX_UTC.timestamp() as u64 + 1;

		assert_eq!(format_diff_block_time(timestamp), "invalid timestamp");
	}

	#[test]
	fn system_time_to_utc_handles_subsecond_times_before_unix_epoch() {
		let last_seen = time::UNIX_EPOCH - time::Duration::new(0, 100);
		let expected = DateTime::<Utc>::from_timestamp(-1, 999_999_900).unwrap();

		assert_eq!(system_time_to_utc(last_seen), Some(expected));
	}
}
