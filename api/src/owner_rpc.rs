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

//! JSON-RPC Stub generation for the Owner API

use crate::owner::Owner;
use crate::rest::Error;
use crate::types::Status;
use mwc_crates::easy_jsonrpc_mwc;
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_p2p::types::PeerInfoDisplayLegacy;
use mwc_p2p::PeerData;
use std::net::SocketAddr;

/// Public definition used to generate Node jsonrpc api.
/// * When running `mwc` with defaults, the V2 api is available at
/// `localhost:3413/v2/owner`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mwc::rpc]
pub trait OwnerRpc: Sync + Send {
	/**
	Networked version of [Owner::get_status](struct.Owner.html#method.get_status).

	# Json rpc example

	```
	# mwc_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_status",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
			"protocol_version": "2",
			"user_agent": "MW/MWC 2.x.x",
			"connections": "8",
			"tip": {
				"height": 371553,
				"last_block_pushed": "00001d1623db988d7ed10c5b6319360a52f20c89b4710474145806ba0e8455ec",
				"prev_block_to_last": "0000029f51bacee81c49a27b4bc9c6c446e03183867c922890f90bb17108d89f",
				"total_difficulty": 1127628411943045
			},
			"sync_status": "header_sync",
			"sync_info": {
				"current_height": 371553,
				"highest_height": 0
			}
			}
		}
	}
	# "#
	# );
	```
	 */
	fn get_status(&self) -> Result<Status, Error>;

	/**
	Networked version of [Owner::validate_chain](struct.Owner.html#method.validate_chain).

	# Json rpc example

	```
	# mwc_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "validate_chain",
		"params": ["false"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# );
	```
	 */
	fn validate_chain(&self, assume_valid_rangeproofs_kernels: bool) -> Result<(), Error>;

	/**
	Networked version of [Owner::compact_chain](struct.Owner.html#method.compact_chain).

	# Json rpc example

	```
	# mwc_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "compact_chain",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# );
	```
	 */
	fn compact_chain(&self) -> Result<(), Error>;

	fn reset_chain_head(&self, hash: String) -> Result<(), Error>;

	/**
	Add hashes to the runtime ban list for headers. Existing banned hashes remain active;
	omitted hashes are not removed, and an empty list does not clear the runtime cache.
	This appends to the same in-process cache initialized from 'invalid_block_hashes'
	in the config file. If you need to make those settings permanent, update
	mwc-server.toml.

	```
	# mwc_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "invalidate_header",
		"params": {
			"hash" : ["000297d0bd21d692f271d348d6ed096632b5502e4aaed58a1b301c6bd1780d37","ed3f5d67dbb5cb25574b8bc7db60ad28fa6a1b246ee3d09b9305d00ab37942ca"]
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# );
	```
	 */
	fn invalidate_header(&self, hash: Vec<String>) -> Result<(), Error>;

	/**
	Networked version of [Owner::get_peers](struct.Owner.html#method.get_peers).

	# Json rpc example

	```
	# mwc_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_peers",
		"params": ["70.50.33.130:3414"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
			{
				"addr": "70.50.33.130:3414",
				"ban_reason": "None",
				"capabilities": {
				"bits": 15
				},
				"flags": "Defunct",
				"last_banned": 0,
				"last_connected": 1570129317,
				"user_agent": "MW/MWC 2.0.0"
			}
			]
		}
	}
	# "#
	# );
	```
	 */
	fn get_peers(&self, peer_addr: Option<SocketAddr>) -> Result<Vec<PeerData>, Error>;

	/**
	Networked version of [Owner::get_connected_peers](struct.Owner.html#method.get_connected_peers).

	# Json rpc example

	```
	# mwc_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_connected_peers",
		"params": [],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
			{
				"addr": "35.176.195.242:3414",
				"capabilities": {
				"bits": 15
				},
				"direction": "Outbound",
				"height": 374510,
				"total_difficulty": 1133954621205750,
				"user_agent": "MW/MWC 2.0.0",
				"version": 1
			},
			{
				"addr": "47.97.198.21:3414",
				"capabilities": {
				"bits": 15
				},
				"direction": "Outbound",
				"height": 374510,
				"total_difficulty": 1133954621205750,
				"user_agent": "MW/MWC 2.0.0",
				"version": 1
			},
			{
				"addr": "148.251.16.13:3414",
				"capabilities": {
				"bits": 15
				},
				"direction": "Outbound",
				"height": 374510,
				"total_difficulty": 1133954621205750,
				"user_agent": "MW/MWC 2.0.0",
				"version": 1
			},
			{
				"addr": "68.195.18.155:3414",
				"capabilities": {
				"bits": 15
				},
				"direction": "Outbound",
				"height": 374510,
				"total_difficulty": 1133954621205750,
				"user_agent": "MW/MWC 2.0.0",
				"version": 1
			},
			{
				"addr": "52.53.221.15:3414",
				"capabilities": {
				"bits": 15
				},
				"direction": "Outbound",
				"height": 0,
				"total_difficulty": 1133954621205750,
				"user_agent": "MW/MWC 2.0.0",
				"version": 1
			},
			{
				"addr": "109.74.202.16:3414",
				"capabilities": {
				"bits": 15
				},
				"direction": "Outbound",
				"height": 374510,
				"total_difficulty": 1133954621205750,
				"user_agent": "MW/MWC 2.0.0",
				"version": 1
			},
			{
				"addr": "121.43.183.180:3414",
				"capabilities": {
				"bits": 15
				},
				"direction": "Outbound",
				"height": 374510,
				"total_difficulty": 1133954621205750,
				"user_agent": "MW/MWC 2.0.0",
				"version": 1
			},
			{
				"addr": "35.157.247.209:23414",
				"capabilities": {
				"bits": 15
				},
				"direction": "Outbound",
				"height": 374510,
				"total_difficulty": 1133954621205750,
				"user_agent": "MW/MWC 2.0.0",
				"version": 1
			}
			]
		}
	}
	# "#
	# );
	```
	 */
	fn get_connected_peers(&self) -> Result<Vec<PeerInfoDisplayLegacy>, Error>;

	/**
	Networked version of [Owner::ban_peer](struct.Owner.html#method.ban_peer).

	# Json rpc example

	```
	# mwc_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "ban_peer",
		"params": ["70.50.33.130:3414"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# );
	```
	 */
	fn ban_peer(&self, peer_addr: SocketAddr) -> Result<(), Error>;

	/**
	Networked version of [Owner::unban_peer](struct.Owner.html#method.unban_peer).

	# Json rpc example

	```
	# mwc_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "unban_peer",
		"params": ["70.50.33.130:3414"],
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# );
	```
	 */
	fn unban_peer(&self, peer_addr: SocketAddr) -> Result<(), Error>;
}

impl OwnerRpc for Owner {
	fn get_status(&self) -> Result<Status, Error> {
		Owner::get_status(self)
	}

	fn validate_chain(&self, assume_valid_rangeproofs_kernels: bool) -> Result<(), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		Owner::validate_chain(self, &secp, assume_valid_rangeproofs_kernels)
	}

	fn reset_chain_head(&self, hash: String) -> Result<(), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		Owner::reset_chain_head(self, &secp, hash)
	}

	fn invalidate_header(&self, hash: Vec<String>) -> Result<(), Error> {
		let secp = Secp256k1::with_caps(ContextFlag::Commit)?;
		Owner::invalidate_header(self, &secp, hash)
	}

	fn compact_chain(&self) -> Result<(), Error> {
		Owner::compact_chain(self)
	}

	fn get_peers(&self, addr: Option<SocketAddr>) -> Result<Vec<PeerData>, Error> {
		Owner::get_peers(self, addr)
	}

	fn get_connected_peers(&self) -> Result<Vec<PeerInfoDisplayLegacy>, Error> {
		Owner::get_connected_peers(self)
	}

	fn ban_peer(&self, addr: SocketAddr) -> Result<(), Error> {
		Owner::ban_peer(self, addr)
	}

	fn unban_peer(&self, addr: SocketAddr) -> Result<(), Error> {
		Owner::unban_peer(self, addr)
	}
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr) => {{
		$crate::json_rpc::doctest_assert_json_rpc_response(
			$request,
			$expected_response,
			&[
				("get_status", &[]),
				("validate_chain", &["assume_valid_rangeproofs_kernels"]),
				("reset_chain_head", &["hash"]),
				("invalidate_header", &["hash"]),
				("compact_chain", &[]),
				("get_peers", &["peer_addr"]),
				("get_connected_peers", &[]),
				("ban_peer", &["peer_addr"]),
				("unban_peer", &["peer_addr"]),
			],
		)
		.unwrap_or_else(|err| panic!("{}", err));
	}};
}
