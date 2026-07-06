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

//! Basic status view definition

use mwc_crates::cursive::direction::Orientation;
use mwc_crates::cursive::traits::Nameable;
use mwc_crates::cursive::view::View;
use mwc_crates::cursive::views::{LinearLayout, ResizedView, TextView};
use mwc_crates::cursive::Cursive;
use std::borrow::Cow;

use super::call_on_name_or_log;
use crate::tui::constants::VIEW_BASIC_STATUS;
use crate::tui::types::TUIStatusListener;

use mwc_chain::SyncStatus;
use mwc_servers::ServerStats;

pub struct TUIStatusView;

impl TUIStatusView {
	fn percent(numerator: u64, denominator: u64) -> u128 {
		if denominator == 0 {
			0
		} else {
			u128::from(numerator) * 100 / u128::from(denominator)
		}
	}

	pub fn update_sync_status(sync_status: SyncStatus) -> Cow<'static, str> {
		match sync_status {
			SyncStatus::Initial => Cow::Borrowed("Initializing"),
			SyncStatus::NoSync => Cow::Borrowed("Running"),
			SyncStatus::AwaitingPeers => Cow::Borrowed("Waiting for peers"),
			SyncStatus::HeaderHashSync {
				completed_blocks,
				// total number of leaves required by archive header
				total_blocks,
			} => Cow::Owned(format!(
				"Sync step 1/10: Downloading headers hashes - {}/{}",
				completed_blocks, total_blocks
			)),
			SyncStatus::HeaderSync {
				current_height,
				archive_height,
			} => {
				let percent = Self::percent(current_height, archive_height);
				Cow::Owned(format!("Sync step 1/10: Downloading headers: {}%", percent))
			}
			SyncStatus::TxHashsetPibd {
				recieved_segments,
				total_segments,
			} => {
				if recieved_segments == 0 && total_segments == 100 {
					Cow::Owned(
						"Sync step 2/10: Selecting peers, waiting for PIBD root hash".to_string(),
					)
				} else {
					let percent = Self::percent(recieved_segments as u64, total_segments as u64);
					Cow::Owned(format!(
						"Sync step 2/10: Downloading Tx state (PIBD) - {} / {} segments - {}%",
						recieved_segments, total_segments, percent
					))
				}
			}
			SyncStatus::ValidatingKernelsHistory {
				headers,
				headers_total,
			} => {
				let percent = Self::percent(headers, headers_total);
				Cow::Owned(format!(
					"Sync step 3/10: Validating kernels history - {}%",
					percent
				))
			}
			SyncStatus::TxHashsetKernelsPosValidation {
				kernel_pos,
				kernel_pos_total,
			} => {
				let percent = Self::percent(kernel_pos, kernel_pos_total);
				Cow::Owned(format!(
					"Sync step 4/10: Validation kernel position - {}%",
					percent
				))
			}
			SyncStatus::TxHashsetOutputPosIndexBuild {
				outputs,
				outputs_total,
			} => {
				let percent = Self::percent(outputs, outputs_total);
				Cow::Owned(format!(
					"Sync step 8/10: Building output position index - {}%",
					percent
				))
			}
			SyncStatus::TxHashsetKernelPosIndexBuild {
				kernels,
				kernels_total,
			} => {
				let percent = Self::percent(kernels, kernels_total);
				Cow::Owned(format!(
					"Sync step 9/10: Building kernel position index - {}%",
					percent
				))
			}
			SyncStatus::TxHashsetStateValidation {
				stage,
				current: _,
				total: _,
			} => Cow::Owned(format!(
				"Sync step 5/10: Validating chain state - {}",
				stage.display_name(),
			)),
			SyncStatus::TxHashsetRangeProofsValidation {
				rproofs,
				rproofs_total,
			} => {
				let r_percent = Self::percent(rproofs, rproofs_total);
				Cow::Owned(format!(
					"Sync step 6/10: Validating chain state - range proofs: {}%",
					r_percent
				))
			}
			SyncStatus::TxHashsetKernelsValidation {
				kernels,
				kernels_total,
			} => {
				let k_percent = Self::percent(kernels, kernels_total);
				Cow::Owned(format!(
					"Sync step 7/10: Validating chain state - kernels: {}%",
					k_percent
				))
			}
			SyncStatus::BodySync {
				archive_height,
				current_height,
				highest_height,
			} => {
				let percent = Self::percent(
					current_height.saturating_sub(archive_height),
					highest_height.saturating_sub(archive_height),
				);
				Cow::Owned(format!("Sync step 10/10: Downloading blocks: {}%", percent))
			}
			SyncStatus::Shutdown => Cow::Borrowed("Shutting down, closing connections"),
		}
	}

	/// Create basic status view
	pub fn create() -> impl View {
		let basic_status_view = ResizedView::with_full_screen(
			LinearLayout::new(Orientation::Vertical)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Current Status:               "))
						.child(TextView::new("Starting").with_name("basic_current_status")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Connected Peers:              "))
						.child(TextView::new("0").with_name("connected_peers")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Disk Usage (GB):              "))
						.child(TextView::new("0").with_name("disk_usage")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal).child(TextView::new(
						"--------------------------------------------------------",
					)),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Header Tip Hash:              "))
						.child(TextView::new("  ").with_name("basic_header_tip_hash")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Header Chain Height:          "))
						.child(TextView::new("  ").with_name("basic_header_chain_height")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Header Cumulative Difficulty: "))
						.child(TextView::new("  ").with_name("basic_header_total_difficulty")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Header Tip Timestamp:         "))
						.child(TextView::new("  ").with_name("basic_header_timestamp")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal).child(TextView::new(
						"--------------------------------------------------------",
					)),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Chain Tip Hash:               "))
						.child(TextView::new("  ").with_name("tip_hash")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Chain Height:                 "))
						.child(TextView::new("  ").with_name("chain_height")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Chain Cumulative Difficulty:  "))
						.child(TextView::new("  ").with_name("basic_total_difficulty")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Chain Tip Timestamp:          "))
						.child(TextView::new("  ").with_name("chain_timestamp")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal).child(TextView::new(
						"--------------------------------------------------------",
					)),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Transaction Pool Size:        "))
						.child(TextView::new("0").with_name("tx_pool_size"))
						.child(TextView::new(" ("))
						.child(TextView::new("0").with_name("tx_pool_kernels"))
						.child(TextView::new(")")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("Stem Pool Size:               "))
						.child(TextView::new("0").with_name("stem_pool_size"))
						.child(TextView::new(" ("))
						.child(TextView::new("0").with_name("stem_pool_kernels"))
						.child(TextView::new(")")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal).child(TextView::new(
						"--------------------------------------------------------",
					)),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("  ").with_name("basic_mining_config_status")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("  ").with_name("basic_mining_status")),
				)
				.child(
					LinearLayout::new(Orientation::Horizontal)
						.child(TextView::new("  ").with_name("basic_network_info")),
				), //.child(logo_view)
		);
		basic_status_view.with_name(VIEW_BASIC_STATUS)
	}
}

impl TUIStatusListener for TUIStatusView {
	fn update(c: &mut Cursive, stats: &ServerStats) {
		let basic_status = TUIStatusView::update_sync_status(stats.sync_status);

		call_on_name_or_log(
			c,
			"basic status",
			"basic_current_status",
			|t: &mut TextView| {
				t.set_content(basic_status);
			},
		);
		call_on_name_or_log(c, "basic status", "connected_peers", |t: &mut TextView| {
			t.set_content(stats.peer_count.to_string());
		});
		call_on_name_or_log(c, "basic status", "disk_usage", |t: &mut TextView| {
			t.set_content(stats.disk_usage_gb.clone());
		});
		call_on_name_or_log(c, "basic status", "tip_hash", |t: &mut TextView| {
			t.set_content(stats.chain_stats.last_block_h.to_string() + "...");
		});
		call_on_name_or_log(c, "basic status", "chain_height", |t: &mut TextView| {
			t.set_content(stats.chain_stats.height.to_string());
		});
		call_on_name_or_log(
			c,
			"basic status",
			"basic_total_difficulty",
			|t: &mut TextView| {
				t.set_content(stats.chain_stats.total_difficulty.to_string());
			},
		);
		call_on_name_or_log(c, "basic status", "chain_timestamp", |t: &mut TextView| {
			t.set_content(stats.chain_stats.latest_timestamp.to_string());
		});
		call_on_name_or_log(
			c,
			"basic status",
			"basic_header_tip_hash",
			|t: &mut TextView| {
				t.set_content(stats.header_stats.last_block_h.to_string() + "...");
			},
		);
		call_on_name_or_log(
			c,
			"basic status",
			"basic_header_chain_height",
			|t: &mut TextView| {
				t.set_content(stats.header_stats.height.to_string());
			},
		);
		call_on_name_or_log(
			c,
			"basic status",
			"basic_header_total_difficulty",
			|t: &mut TextView| {
				t.set_content(stats.header_stats.total_difficulty.to_string());
			},
		);
		call_on_name_or_log(
			c,
			"basic status",
			"basic_header_timestamp",
			|t: &mut TextView| {
				t.set_content(stats.header_stats.latest_timestamp.to_string());
			},
		);
		if let Some(tx_stats) = &stats.tx_stats {
			call_on_name_or_log(c, "basic status", "tx_pool_size", |t: &mut TextView| {
				t.set_content(tx_stats.tx_pool_size.to_string());
			});
			call_on_name_or_log(c, "basic status", "stem_pool_size", |t: &mut TextView| {
				t.set_content(tx_stats.stem_pool_size.to_string());
			});
			call_on_name_or_log(c, "basic status", "tx_pool_kernels", |t: &mut TextView| {
				t.set_content(tx_stats.tx_pool_kernels.to_string());
			});
			call_on_name_or_log(
				c,
				"basic status",
				"stem_pool_kernels",
				|t: &mut TextView| {
					t.set_content(tx_stats.stem_pool_kernels.to_string());
				},
			);
		}
	}
}

#[test]
fn test_status_txhashset_kernels() {
	let status = SyncStatus::TxHashsetKernelsValidation {
		kernels: 201,
		kernels_total: 5000,
	};
	let basic_status = TUIStatusView::update_sync_status(status);
	assert!(basic_status.contains("4%"), "{}", basic_status);
}

#[test]
fn test_status_txhashset_rproofs() {
	let status = SyncStatus::TxHashsetRangeProofsValidation {
		rproofs: 643,
		rproofs_total: 1000,
	};
	let basic_status = TUIStatusView::update_sync_status(status);
	assert!(basic_status.contains("64%"), "{}", basic_status);
}

#[test]
fn test_status_validating_kernels_history_has_sync_step() {
	let basic_status = TUIStatusView::update_sync_status(SyncStatus::ValidatingKernelsHistory {
		headers: 250,
		headers_total: 1000,
	});
	assert!(
		basic_status.contains("Sync step 3/10: Validating kernels history"),
		"{}",
		basic_status
	);
	assert!(basic_status.contains("25%"), "{}", basic_status);
}

#[test]
fn test_status_txhashset_output_pos_index_build_has_sync_step() {
	let basic_status =
		TUIStatusView::update_sync_status(SyncStatus::TxHashsetOutputPosIndexBuild {
			outputs: 40,
			outputs_total: 100,
		});
	assert!(
		basic_status.contains("Sync step 8/10: Building output position index"),
		"{}",
		basic_status
	);
	assert!(basic_status.contains("40%"), "{}", basic_status);
}

#[test]
fn test_status_txhashset_kernel_pos_index_build_has_sync_step() {
	let basic_status =
		TUIStatusView::update_sync_status(SyncStatus::TxHashsetKernelPosIndexBuild {
			kernels: 50,
			kernels_total: 100,
		});
	assert!(
		basic_status.contains("Sync step 9/10: Building kernel position index"),
		"{}",
		basic_status
	);
	assert!(basic_status.contains("50%"), "{}", basic_status);
}

#[test]
fn test_status_txhashset_state_validation_has_sync_step() {
	let basic_status = TUIStatusView::update_sync_status(SyncStatus::TxHashsetStateValidation {
		stage: mwc_chain::TxHashsetStateValidationStage::ValidateKernelSums,
		current: 3,
		total: 4,
	});
	assert!(
		basic_status.contains("Sync step 5/10: Validating chain state"),
		"{}",
		basic_status
	);
	assert!(basic_status.contains("kernel sums"), "{}", basic_status);
}

#[test]
fn test_status_txhashset_state_validation_displays_running_step_from_one() {
	let basic_status = TUIStatusView::update_sync_status(SyncStatus::TxHashsetStateValidation {
		stage: mwc_chain::TxHashsetStateValidationStage::ValidateMmrs,
		current: 0,
		total: 4,
	});
	assert!(basic_status.contains("MMR validation"), "{}", basic_status);
}

#[test]
fn test_status_percent_uses_u128_arithmetic() {
	let statuses = [
		SyncStatus::HeaderSync {
			current_height: u64::MAX,
			archive_height: u64::MAX,
		},
		SyncStatus::TxHashsetPibd {
			recieved_segments: usize::MAX,
			total_segments: usize::MAX,
		},
		SyncStatus::ValidatingKernelsHistory {
			headers: u64::MAX,
			headers_total: u64::MAX,
		},
		SyncStatus::TxHashsetKernelsPosValidation {
			kernel_pos: u64::MAX,
			kernel_pos_total: u64::MAX,
		},
		SyncStatus::TxHashsetOutputPosIndexBuild {
			outputs: u64::MAX,
			outputs_total: u64::MAX,
		},
		SyncStatus::TxHashsetKernelPosIndexBuild {
			kernels: u64::MAX,
			kernels_total: u64::MAX,
		},
		SyncStatus::TxHashsetRangeProofsValidation {
			rproofs: u64::MAX,
			rproofs_total: u64::MAX,
		},
		SyncStatus::TxHashsetKernelsValidation {
			kernels: u64::MAX,
			kernels_total: u64::MAX,
		},
		SyncStatus::BodySync {
			archive_height: 0,
			current_height: u64::MAX,
			highest_height: u64::MAX,
		},
	];

	for status in statuses {
		let basic_status = TUIStatusView::update_sync_status(status);
		assert!(basic_status.contains("100%"), "{}", basic_status);
	}
}
