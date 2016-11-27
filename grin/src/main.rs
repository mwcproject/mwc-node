// Copyright 2016 The Grin Developers
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

//! Main crate putting together all the other crates that compose Grin into a
//! binary.

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate rand;
extern crate time;

extern crate grin_chain as chain;
extern crate grin_core as core;
extern crate grin_store as store;
extern crate secp256k1zkp as secp;

mod miner;

use store::Store;
use core::genesis::genesis;

fn main() {
  env_logger::init().unwrap();

	let gen = genesis();
	let db = Store::open("./store").unwrap();
	let mut key = "block:".to_string().into_bytes();
	let mut hash_vec = gen.hash().to_vec();
	key.append(&mut hash_vec);
	db.put_ser(&key[..], &gen);
}
