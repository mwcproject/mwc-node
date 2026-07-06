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

//! Basic TUI to better output the overall system status and status
//! of various subsystems

use mwc_crates::cursive;
use mwc_crates::cursive::direction::Orientation;
use mwc_crates::cursive::theme::BaseColor::{Black, Blue, Cyan, White};
use mwc_crates::cursive::theme::Color::Dark;
use mwc_crates::cursive::theme::PaletteColor::{
	Background, Highlight, HighlightInactive, Primary, Shadow, View,
};
use mwc_crates::cursive::theme::{BaseColor, BorderStyle, Color, Theme};
use mwc_crates::cursive::traits::{Nameable, Resizable};
use mwc_crates::cursive::utils::markup::StyledString;
use mwc_crates::cursive::views::{
	CircularFocus, Dialog, LinearLayout, Panel, SelectView, StackView, TextView,
};
use mwc_crates::cursive::{CursiveRunnable, CursiveRunner};
use std::sync::mpsc;
use std::time::{self, Instant};

use super::constants::MAIN_MENU;
use crate::built_info;
use crate::tui::constants::{ROOT_STACK, VIEW_BASIC_STATUS, VIEW_MINING, VIEW_PEER_SYNC};
use crate::tui::types::{TUIStatusListener, UIMessage};
use crate::tui::{logs, menu, mining, peers, status, version};
use mwc_core::global;
use mwc_crates::log::{error, warn};
use mwc_util::logger::LogEntry;

pub struct UI {
	cursive: CursiveRunner<CursiveRunnable>,
	ui_rx: mpsc::Receiver<UIMessage>,
	ui_tx: mpsc::Sender<UIMessage>,
	controller_tx: mpsc::Sender<ControllerMessage>,
	logs_rx: mpsc::Receiver<LogEntry>,
}

fn modify_theme(theme: &mut Theme) {
	theme.shadow = false;
	theme.borders = BorderStyle::Simple;
	theme.palette[Background] = Dark(Black);
	theme.palette[Shadow] = Dark(Black);
	theme.palette[View] = Dark(Black);
	theme.palette[Primary] = Dark(White);
	theme.palette[Highlight] = Dark(Cyan);
	theme.palette[HighlightInactive] = Dark(Blue);
	// also secondary, tertiary, TitlePrimary, TitleSecondary
}

impl UI {
	/// Create a new UI
	pub fn new(
		context_id: u32,
		controller_tx: mpsc::Sender<ControllerMessage>,
		logs_rx: mpsc::Receiver<LogEntry>,
	) -> Result<UI, String> {
		let (ui_tx, ui_rx) = mpsc::channel::<UIMessage>();
		let cursive = cursive::default()
			.try_into_runner()
			.map_err(|e| format!("Unable to initialize TUI backend: {}", e))?;

		let mut mwc_ui = UI {
			cursive,
			ui_tx,
			ui_rx,
			controller_tx,
			logs_rx,
		};

		// Create UI objects, etc
		let status_view = status::TUIStatusView::create();
		let mining_view = mining::TUIMiningView::create();
		let peer_view = peers::TUIPeerView::create();
		let logs_view = logs::TUILogsView::create();
		let version_view = version::TUIVersionView::create();

		let main_menu = menu::create();

		let root_stack = StackView::new()
			.layer(version_view)
			.layer(mining_view)
			.layer(peer_view)
			.layer(logs_view)
			.layer(status_view)
			.with_name(ROOT_STACK)
			.full_height();

		let mut title_string = StyledString::new();
		title_string.append(StyledString::styled(
			format!(
				"MWC Version {} [{:?}]",
				built_info::PKG_VERSION,
				global::get_chain_type(context_id)
			),
			Color::Dark(BaseColor::Green),
		));

		let main_layer = LinearLayout::new(Orientation::Vertical)
			.child(Panel::new(TextView::new(title_string).full_width()))
			.child(
				LinearLayout::new(Orientation::Horizontal)
					.child(Panel::new(main_menu))
					.child(Panel::new(root_stack)),
			);

		//set theme
		let mut theme = mwc_ui.cursive.current_theme().clone();
		modify_theme(&mut theme);
		mwc_ui.cursive.set_theme(theme);
		mwc_ui.cursive.add_fullscreen_layer(main_layer);

		// Configure a callback (shutdown, for the first test)
		let controller_tx_clone = mwc_ui.controller_tx.clone();
		mwc_ui.cursive.add_global_callback('q', move |c| {
			let content = StyledString::styled("Shutting down...", Color::Light(BaseColor::Yellow));
			c.add_layer(CircularFocus::new(Dialog::around(TextView::new(content))).wrap_tab());
			if let Err(e) = controller_tx_clone.send(ControllerMessage::Shutdown) {
				warn!("Unable to send shutdown message to TUI controller: {}", e);
			}
		});
		mwc_ui.cursive.set_fps(5);
		Ok(mwc_ui)
	}

	/// Step the UI by calling into Cursive's step function, then
	/// processing any UI messages
	pub fn step(&mut self) -> bool {
		if !self.cursive.is_running() {
			return false;
		}

		while let Some(message) = self.logs_rx.try_iter().next() {
			logs::TUILogsView::update(&mut self.cursive, message);
		}

		// Process any pending UI messages
		while let Some(message) = self.ui_rx.try_iter().next() {
			if let Some(menu) = self.cursive.find_name::<SelectView<&str>>(MAIN_MENU) {
				if let Some(selection) = menu.selection() {
					match message {
						UIMessage::UpdateStatus(update) => match *selection {
							VIEW_BASIC_STATUS => {
								status::TUIStatusView::update(&mut self.cursive, &update)
							}
							VIEW_MINING => {
								mining::TUIMiningView::update(&mut self.cursive, &update)
							}
							VIEW_PEER_SYNC => {
								peers::TUIPeerView::update(&mut self.cursive, &update)
							}
							_ => {}
						},
					}
				}
			}
		}

		// Step the UI
		self.cursive.step();
		true
	}

	/// Stop the UI
	pub fn stop(&mut self) {
		self.cursive.quit();
	}
}

pub struct Controller {
	rx: mpsc::Receiver<ControllerMessage>,
	ui: UI,
}

pub enum ControllerMessage {
	Shutdown,
}

impl Controller {
	/// Create a new controller
	pub fn new(context_id: u32, logs_rx: mpsc::Receiver<LogEntry>) -> Result<Controller, String> {
		let (tx, rx) = mpsc::channel::<ControllerMessage>();
		Ok(Controller {
			rx,
			ui: UI::new(context_id, tx, logs_rx)?,
		})
	}

	/// Run the controller
	pub fn run(&mut self, context_id: u32) {
		let stat_update_interval = time::Duration::from_millis(200);
		let stats_error_log_interval = time::Duration::from_secs(60);
		let mut next_stat_update = Instant::now() + stat_update_interval;
		let mut next_stats_error_log = Instant::now();
		while self.ui.step() {
			if let Some(message) = self.rx.try_iter().next() {
				match message {
					ControllerMessage::Shutdown => {
						warn!("Shutdown in progress, please wait");
						self.ui.stop();
						mwc_node_workflow::server::release_server(context_id);
						return;
					}
				}
			}

			if Instant::now() > next_stat_update {
				let now = Instant::now();
				next_stat_update = now + stat_update_interval;
				match mwc_node_workflow::server::get_server_stats(context_id) {
					Ok(stats) => {
						if let Err(e) = self.ui.ui_tx.send(UIMessage::UpdateStatus(stats)) {
							error!("Unable to send status update to TUI: {}", e);
						}
					}
					Err(e) => {
						if now >= next_stats_error_log {
							error!("Unable to get server stats for TUI: {}", e);
							next_stats_error_log = now + stats_error_log_interval;
						}
					}
				}
			}
		}
		mwc_node_workflow::server::release_server(context_id);
	}
}
