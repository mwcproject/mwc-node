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

use mwc_p2p as p2p;

use mwc_core::global::{set_local_chain_type, ChainTypes};
use mwc_p2p::PeerAddr;
use tempfile::TempDir;

fn make_peer(addr: &str) -> p2p::PeerData {
	p2p::PeerData {
		addr: p2p::types::PeerAddr::from_str(addr),
		capabilities: p2p::types::Capabilities::UNKNOWN,
		user_agent: "ok".to_string(),
		flags: p2p::State::Healthy,
		last_banned: 0,
		ban_reason: p2p::types::ReasonForBan::None,
		last_connected: 0,
	}
}

#[test]
fn test_peers_iter_drops_corrupt_records() {
	set_local_chain_type(ChainTypes::AutomatedTesting);

	let dir = TempDir::new().unwrap();
	let root = dir.path().to_str().unwrap();
	let context_id = 1;

	let store = p2p::store::PeerStore::new(context_id, root).unwrap();

	let good = make_peer("127.0.0.1:3414");
	let corrupted1 =
		make_peer("11plnrnhuuwjcowtjejqx6ou4m2bxkvkqq2rj4ot6cwgf53chgw2keu7yd%0.onion");
	let mut corrupted2 = make_peer("12.1.3.5:1234");
	corrupted2.user_agent = String::from("bad\0 agent");
	store.save_peer(&good).unwrap();
	store.save_peer(&corrupted1).unwrap();
	for i in 3..200 {
		let good = make_peer(format!("127.0.{}.1:3414", i).as_str());
		store.save_peer(&good).unwrap();
	}
	store.save_peer(&corrupted2).unwrap();

	let peers: Vec<p2p::PeerData> = store.peers_iter().unwrap().collect();
	assert_eq!(peers.len(), 200 - 3 + 1);
	assert_eq!(peers[0].addr, good.addr);

	assert!(store.exists_peer(&good.addr).unwrap());
	assert!(!store.exists_peer(&corrupted1.addr).unwrap());
	assert!(!store.exists_peer(&corrupted2.addr).unwrap());
	for i in 3..200 {
		assert!(store
			.exists_peer(&PeerAddr::from_str(format!("127.0.{}.1:3414", i).as_str()))
			.unwrap());
	}
}
