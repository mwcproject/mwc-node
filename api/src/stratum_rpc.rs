// Copyright 2020 The MWC Developers
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

//! JSON-RPC Stub generation for the Stratum API

use crate::core::stratum;
use crate::rest::*;
use crate::stratum::Stratum;

/// Public definition used to generate Node jsonrpc api.
/// * When running `mwc` with defaults, the V2 api is available at
/// `localhost:3413/v2/stratum`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mw::rpc]
pub trait StratumRpc: Sync + Send {
	/**
	Get all IP addresses from stratum IP pool

	Request:
	{
	   "jsonrpc": "2.0",
	   "method": "get_ip_list",
	   "params": {
		  "banned": null
		},
		"id": 1
	}

	Respond:
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  {
			"ban": false,
			"failed_login": 0,
			"failed_requests": 0,
			"ip": "192.168.1.10",
			"last_connect_time_ms": 1584407722094,
			"ok_logins": 0,
			"ok_shares": 0,
			"workers": 1
		  },
		  {
			"ban": false,
			"failed_login": 0,
			"failed_requests": 0,
			"ip": "127.0.0.1",
			"last_connect_time_ms": 1584407626893,
			"ok_logins": 100,
			"ok_shares": 0,
			"workers": 100
		  }
		]
	  }
	}
	*/
	fn get_ip_list(
		&self,
		banned: Option<bool>,
	) -> Result<Vec<stratum::connections::StratumIpPrintable>, Error>;

	/**
	Clean IP data. As a result, if it is banned, it will become active.

	Request:
	{
	   "jsonrpc": "2.0",
	   "method": "clean_ip",
	   "params": {
		  "ip": "127.0.0.1"
		},
		"id": 1
	}
	Respond:
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": null
	  }
	}

	*/
	fn clean_ip(&self, ip: String) -> Result<(), Error>;

	/*
	 Get single IP info stratum IP pool

	Request:
	{
	   "jsonrpc": "2.0",
	   "method": "get_ip_info",
	   "params": {
		  "ip": "192.168.1.10",
		},
		"id": 1
	}

	Respond:
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok":
		  {
			"ban": false,
			"failed_login": 0,
			"failed_requests": 0,
			"ip": "192.168.1.10",
			"last_connect_time_ms": 1584407722094,
			"ok_logins": 0,
			"ok_shares": 0,
			"workers": 1
		  }
	  }
	}
	*/
	fn get_ip_info(&self, ip: String) -> Result<stratum::connections::StratumIpPrintable, Error>;
}

impl StratumRpc for Stratum {
	fn get_ip_list(
		&self,
		banned: Option<bool>,
	) -> Result<Vec<stratum::connections::StratumIpPrintable>, Error> {
		Stratum::get_ip_list(self, banned)
	}

	fn clean_ip(&self, ip: String) -> Result<(), Error> {
		Stratum::clean_ip(self, &ip)
	}

	fn get_ip_info(&self, ip: String) -> Result<stratum::connections::StratumIpPrintable, Error> {
		Stratum::get_ip_info(self, &ip)
	}
}
