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

//! Networking code to connect to other peers and exchange block, transactions,
//! etc.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

mod codec;
mod conn;
pub mod handshake;
mod listen;
pub mod msg;
pub mod network_status;
mod peer;
mod peers;
mod protocol;
mod serv;
pub mod store;
pub mod tor;
pub mod types;

pub use crate::conn::SEND_CHANNEL_CAP;
pub use crate::peer::Peer;
pub use crate::peers::{PeerCleanupSummary, Peers};
pub use crate::serv::{DummyAdapter, Server};
pub use crate::store::{PeerData, State};
pub use crate::types::{
	BroadcastError, Capabilities, ChainAdapter, Direction, Error, P2PConfig, PeerAddr, PeerInfo,
	ReasonForBan, Seeding, TorConfig, MAX_BLOCK_HEADERS, MAX_LOCATORS, MAX_PEER_ADDRS,
};

pub use listen::listen;
