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

//! Main Menu definition

use mwc_crates::cursive::align::HAlign;
use mwc_crates::cursive::direction::Orientation;
use mwc_crates::cursive::event::Key;
use mwc_crates::cursive::view::Nameable;
use mwc_crates::cursive::view::View;
use mwc_crates::cursive::views::{
	LinearLayout, OnEventView, ResizedView, SelectView, StackView, TextView,
};
use mwc_crates::cursive::Cursive;
use mwc_crates::log::error;

use crate::tui::constants::{
	MAIN_MENU, ROOT_STACK, SUBMENU_MINING_BUTTON, VIEW_BASIC_STATUS, VIEW_LOGS, VIEW_MINING,
	VIEW_PEER_SYNC, VIEW_VERSION,
};

pub fn create() -> impl View {
	let mut main_menu = SelectView::new().h_align(HAlign::Left).with_name(MAIN_MENU);
	main_menu
		.get_mut()
		.add_item("Basic Status", VIEW_BASIC_STATUS);
	main_menu
		.get_mut()
		.add_item("Peers and Sync", VIEW_PEER_SYNC);
	main_menu.get_mut().add_item("Mining", VIEW_MINING);
	main_menu.get_mut().add_item("Logs", VIEW_LOGS);
	main_menu.get_mut().add_item("Version Info", VIEW_VERSION);
	let change_view = |s: &mut Cursive, v: &&str| {
		if v.is_empty() {
			return;
		}

		match s.call_on_name(ROOT_STACK, |sv: &mut StackView| {
			if let Some(pos) = sv.find_layer_from_name(v) {
				sv.move_to_front(pos);
				true
			} else {
				false
			}
		}) {
			Some(true) => {}
			Some(false) => {
				error!("TUI root stack layer not found for menu selection: {}", v);
			}
			None => {
				error!(
					"TUI root stack '{}' not found or has unexpected type for menu selection: {}",
					ROOT_STACK, v
				);
			}
		}
	};

	main_menu.get_mut().set_on_select(change_view);
	main_menu
		.get_mut()
		.set_on_submit(|c: &mut Cursive, v: &str| {
			if v == VIEW_MINING {
				if let Err(e) = c.focus_name(SUBMENU_MINING_BUTTON) {
					error!(
						"TUI mining submenu focus target '{}' not found or cannot be focused: {:?}",
						SUBMENU_MINING_BUTTON, e
					);
				}
			}
		});
	let main_menu = OnEventView::new(main_menu)
		.on_pre_event('j', move |c| {
			if let Some(mut s) = c.find_name::<SelectView<&str>>(MAIN_MENU) {
				s.select_down(1)(c);
			} else {
				error!(
					"TUI main menu '{}' not found or has unexpected type while handling 'j'",
					MAIN_MENU
				);
			}
		})
		.on_pre_event('k', move |c| {
			if let Some(mut s) = c.find_name::<SelectView<&str>>(MAIN_MENU) {
				s.select_up(1)(c);
			} else {
				error!(
					"TUI main menu '{}' not found or has unexpected type while handling 'k'",
					MAIN_MENU
				);
			}
		})
		.on_pre_event(Key::Tab, move |c| {
			if let Some(mut s) = c.find_name::<SelectView<&str>>(MAIN_MENU) {
				match (s.selected_id(), s.len().checked_sub(1)) {
					(Some(selected), Some(last)) if selected == last => s.set_selection(0)(c),
					(Some(_), Some(_)) => s.select_down(1)(c),
					_ => {}
				}
			} else {
				error!(
					"TUI main menu '{}' not found or has unexpected type while handling Tab",
					MAIN_MENU
				);
			}
		});
	let main_menu = LinearLayout::new(Orientation::Vertical)
		.child(ResizedView::with_full_height(main_menu))
		.child(TextView::new("------------------"))
		.child(TextView::new("Tab/Arrow : Cycle "))
		.child(TextView::new("Enter     : Select"))
		.child(TextView::new("Esc       : Back  "))
		.child(TextView::new("Q         : Quit  "));
	main_menu
}
