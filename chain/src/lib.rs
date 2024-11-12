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

//! The block chain itself, validates and accepts new blocks, handles reorgs.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate enum_primitive;

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

use mwc_core as core;
use mwc_keychain as keychain;
use mwc_util as util;

mod chain;
mod error;
pub mod linked_list;
pub mod pibd_params;
pub mod pipe;
pub mod store;
pub mod txhashset;
pub mod types;

// Re-export the base interface

pub use crate::chain::{Chain, BLOCK_TO_BAN, MAX_ORPHAN_SIZE};
pub use crate::error::Error;
pub use crate::store::ChainStore;
pub use crate::types::{
	BlockStatus, ChainAdapter, Options, SyncState, SyncStatus, Tip, TxHashsetDownloadStats,
	TxHashsetWriteStatus,
};
