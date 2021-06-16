// Copyright 2020 The Grin Developers
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

mod common;

use chrono::prelude::*;
use grin_core::address::*;
use grin_core::global::ChainTypes;
use keychain::{ExtKeychain, Keychain};
use rand::{distributions::Uniform, thread_rng, Rng};
use std::str::FromStr;
use util;
use util::secp::key::{PublicKey, SecretKey};
use util::ToHex;

fn round_trips(addr: &Address) {
	assert_eq!(Address::from_str(&addr.to_string()).unwrap(), *addr,);
}

fn check_pubkeys(addr: &str, view: &PublicKey, spend: &PublicKey) {
	let addr = Address::from_str(addr).unwrap();
	assert_eq!(addr.get_inner_pubkeys(), (view, spend));
}

// A lite version of generating some wrong characters, without the checking of duplicate positions.
fn simulate_wrong_characters(
	num_mistakes: usize,
	original_string: &str,
	index_range: std::ops::Range<usize>,
) -> String {
	let mut wrong_string = original_string.to_string();

	// pick some random positions
	let range = Uniform::from(index_range);
	let indexes: Vec<usize> = rand::thread_rng()
		.sample_iter(&range)
		.take(num_mistakes)
		.collect();
	// pick some random mistake characters from the bech32 table, which has values between 0 and 32.
	let range = Uniform::from(0..32);
	let mistakes: Vec<u8> = rand::thread_rng()
		.sample_iter(&range)
		.take(num_mistakes)
		.collect();
	let u5_vec = mistakes
		.iter()
		.map(|u8| bech32::u5::try_from_u8(*u8).unwrap())
		.collect::<Vec<bech32::u5>>();
	let mistakes = bech32::encode("m", &u5_vec).unwrap();

	for i in 0..num_mistakes {
		//println!("{}: {}", indexes[i], &mistakes[i+2..i+3]);
		wrong_string.replace_range(indexes[i]..indexes[i] + 1, &mistakes[i + 2..i + 3]);
	}
	wrong_string
}

#[test]
#[ignore]
fn test_bech32_error_detection() {
	let addr_strs = vec![
		"mwc1q34g5r9yvzupw3j2lgwyp272tslmsd2x5e54lltgac9tsjugr9jdcxrtgdd",
		"mwc1q80yvs0zjmat3yg569aezqmvsry3kdsmy9r9scy4k47vrynvhh77gdgunyk",
	];

	let addr_str_len = addr_strs[0].len();
	const TOTAL_TESTS: usize = 1_000_000;
	let _invalid_checksum = format!("{}", bech32::Error::InvalidChecksum);

	// 4-random-mistakes always can be detected.
	let mut valid_count = 0;
	'million_tests_a: loop {
		for addr in &addr_strs {
			let wrong_addr = simulate_wrong_characters(4, addr, 4..addr_str_len);
			let res = Address::from_str(&wrong_addr);
			match res {
				Ok(_) => {
					assert_eq!(*addr, wrong_addr);
				}
				Err(Error::Bech32(_invalid_checksum)) => {
					valid_count += 1;
					if valid_count % 10_000 == 0 {
						println!("4-random-mistakes passed {} tests", valid_count);
					}
					if valid_count >= TOTAL_TESTS {
						break 'million_tests_a;
					}
				}
				_ => {
					panic!("4-random-mistakes must be always detectable");
				}
			}
		}
	}
	println!();

	let _invalid_checksum = format!("{}", bech32::Error::InvalidChecksum);
	// 99.999% 16-random-mistakes can be detected.
	let mut detected = 0;
	let mut missed = 0;
	'million_tests_b: loop {
		for addr in &addr_strs {
			let wrong_addr = simulate_wrong_characters(16, addr, 4..addr_str_len);
			let res = Address::from_str(&wrong_addr);
			match res {
				Ok(_) => {
					if *addr != wrong_addr {
						missed += 1;
						println!("detection missed: {}", wrong_addr);
					}
				}
				Err(Error::Bech32(_invalid_checksum)) => {
					detected += 1;
					if detected % 10_000 == 0 {
						println!("6-random-mistakes passed {} tests", detected);
					}
					if detected + missed >= TOTAL_TESTS {
						break 'million_tests_b;
					}
				}
				_ => {
					panic!("6-random-mistakes must be always detectable");
				}
			}
		}
	}
	let ratio = detected as f64 / ((detected + missed) as f64) * 100.0;
	println!(
		"for 16 random mistakes, the detection rate is close to {}%",
		ratio
	);
	assert!(ratio >= 99.999);
}

#[test]
fn test_lite_address() {
	// get address from a public key
	let addr_str = "mwc1q34g5r9yvzupw3j2lgwyp272tslmsd2x5e54lltgac9tsjugr9jdcxrtgdd";
	let pubkey = PublicKey::from_slice(
		&util::from_hex(
			"048d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b\
             6042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183",
		)
		.unwrap(),
	)
	.unwrap();
	let addr = Address::from_one_pubkey(&pubkey, ChainTypes::Mainnet);
	assert_eq!(&addr.to_string(), addr_str);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pubkey, &pubkey);

	// same public key as above but in compressed form
	let pubkey = PublicKey::from_slice(
		&util::from_hex("038d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b")
			.unwrap(),
	)
	.unwrap();
	let addr = Address::from_one_pubkey(&pubkey, ChainTypes::Mainnet);
	assert_eq!(&addr.to_string(), addr_str);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pubkey, &pubkey);

	// another public key
	let pubkey = PublicKey::from_slice(
		&util::from_hex("033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc")
			.unwrap(),
	)
	.unwrap();
	let addr = Address::from_one_pubkey(&pubkey, ChainTypes::Mainnet);
	assert_eq!(
		&addr.to_string(),
		"mwc1q80yvs0zjmat3yg569aezqmvsry3kdsmy9r9scy4k47vrynvhh77gdgunyk"
	);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pubkey, &pubkey);

	// test the hrp
	let addr = Address::from_one_pubkey(&pubkey, ChainTypes::Floonet);
	assert_eq!(
		&addr.to_string(),
		"mwt1q80yvs0zjmat3yg569aezqmvsry3kdsmy9r9scy4k47vrynvhh77g6tcfm6"
	);
	round_trips(&addr);

	let addr = Address::from_one_pubkey(&pubkey, ChainTypes::UserTesting);
	assert_eq!(
		&addr.to_string(),
		"mwu1q80yvs0zjmat3yg569aezqmvsry3kdsmy9r9scy4k47vrynvhh77gmhxs03"
	);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pubkey, &pubkey);

	assert_eq!(addr.to_string().len(), 63);

	// an useful address which will be used for tests in all other module.
	let prikey = SecretKey::from_slice(&[2; 32]).unwrap();
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let pubkey = PublicKey::from_secret_key(keychain.secp(), &prikey).unwrap();
	let addr = Address::from_one_pubkey(&pubkey, ChainTypes::Mainnet);
	assert_eq!(
		&addr.to_string(),
		"mwc1qf49ke5fkzqev4x7j46uajq92f4zan6kcpty5yvm5c3g6wf2dqanq0wszju"
	);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pubkey, &pubkey);

	let addr = Address::from_one_pubkey(&pubkey, ChainTypes::AutomatedTesting);
	assert_eq!(
		&addr.to_string(),
		"mwa1qf49ke5fkzqev4x7j46uajq92f4zan6kcpty5yvm5c3g6wf2dqanqdl9en2"
	);
}

#[test]
fn test_stealth_address() {
	// get address from 2 public keys
	let addr_str = "mwc1q34g5r9yvzupw3j2lgwyp272tslmsd2x5e54lltgac9tsjugr9jdkqs4qgvw76frckhyu7tvpcyj2tetng73uv0hsuackea2dvya6rq6mtwc03";
	let pubkey_view = PublicKey::from_slice(
		&util::from_hex("028d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b")
			.unwrap(),
	)
	.unwrap();
	let pubkey_spend = PublicKey::from_slice(
		&util::from_hex("036042a0431ded2478b5c9cf2d81c124a5e57347a3c63ef0e7716cf54d613ba183")
			.unwrap(),
	)
	.unwrap();
	let addr = Address::from_pubkey(&pubkey_view, &pubkey_spend, ChainTypes::Mainnet);
	assert_eq!(&addr.to_string(), addr_str);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pubkey_view, &pubkey_spend);

	// test the hrp
	let addr = Address::from_pubkey(&pubkey_view, &pubkey_spend, ChainTypes::Floonet);
	assert_eq!(
        &addr.to_string(),
        "mwt1q34g5r9yvzupw3j2lgwyp272tslmsd2x5e54lltgac9tsjugr9jdkqs4qgvw76frckhyu7tvpcyj2tetng73uv0hsuackea2dvya6rq6upwkys"
    );
	round_trips(&addr);

	assert_eq!(addr.to_string().len(), 114);
}

#[test]
fn test_ephemeral_key() {
	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let (_pri_spend, pub_spend) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

	//--- tests for address::InnerAddr::StealthAddr ---

	let addr = Address::from_pubkey(&pub_view, &pub_spend, ChainTypes::Mainnet);
	println!("address: {}", addr);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pub_view, &pub_spend);

	// check the shared ephemeral key is same both on rx and tx sides.
	let (private_nonce, public_nonce) =
		keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let e1 = addr
		.get_ephemeral_key_for_rx(keychain.secp(), &pri_view, &public_nonce)
		.unwrap();
	let e1_tx = addr
		.get_ephemeral_key_for_tx(keychain.secp(), &private_nonce)
		.unwrap();
	assert_eq!(e1, e1_tx);

	// check different nonce get different ephemeral key
	let (_private_nonce, public_nonce) =
		keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let e2 = addr
		.get_ephemeral_key_for_rx(keychain.secp(), &pri_view, &public_nonce)
		.unwrap();

	assert_ne!(e1.0, e2.0);
	assert_ne!(e1.1, e2.1);

	//--- repeat above tests for address::InnerAddr::LiteStealthAddr ---

	let addr = Address::from_one_pubkey(&pub_view, ChainTypes::Mainnet);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pub_view, &pub_view);

	// check the shared ephemeral key is same both on rx and tx sides.
	let (private_nonce, public_nonce) =
		keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let e1 = addr
		.get_ephemeral_key_for_rx(keychain.secp(), &pri_view, &public_nonce)
		.unwrap();
	let e1_tx = addr
		.get_ephemeral_key_for_tx(keychain.secp(), &private_nonce)
		.unwrap();
	assert_eq!(e1, e1_tx);

	// check different nonce get different ephemeral key
	let (_private_nonce, public_nonce) =
		keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let e2 = addr
		.get_ephemeral_key_for_rx(keychain.secp(), &pri_view, &public_nonce)
		.unwrap();

	assert_ne!(e1.0, e2.0);
	assert_ne!(e1.1, e2.1);
}

#[test]
fn test_calculations_complexity() {
	let nano_to_millis = 1.0 / 1_000_000.0;

	let keychain = ExtKeychain::from_random_seed(false).unwrap();
	let (pri_view, pub_view) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();
	let (_pri_spend, pub_spend) = keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

	let addr = Address::from_pubkey(&pub_view, &pub_spend, ChainTypes::Mainnet);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pub_view, &pub_spend);

	let (private_nonce, public_nonce) =
		keychain.secp().generate_keypair(&mut thread_rng()).unwrap();

	let start = Utc::now().timestamp_nanos();
	for _ in 0..10_000 {
		assert_eq!(
			addr.get_ephemeral_key_for_rx(keychain.secp(), &pri_view, &public_nonce)
				.unwrap(),
			addr.get_ephemeral_key_for_tx(keychain.secp(), &private_nonce)
				.unwrap(),
		);
	}
	let fin = Utc::now().timestamp_nanos();
	let full_dur_ms = (fin - start) as f64 * nano_to_millis;
	println!(
		"ephemeral key calculation complexity: {}ms/1k",
		full_dur_ms / 20.0
	);

	// the "view tag" indeed accelerate the scanning greatly.

	let start = Utc::now().timestamp_nanos();
	for _ in 0..10_000 {
		assert_eq!(
			Address::get_view_tag_for_rx(keychain.secp(), &pri_view, &public_nonce).unwrap(),
			addr.get_view_tag_for_tx(keychain.secp(), &private_nonce)
				.unwrap(),
		);
	}
	let fin = Utc::now().timestamp_nanos();
	let dur_ms = (fin - start) as f64 * nano_to_millis;
	println!("view tag calculation complexity: {}ms/1k", dur_ms / 20.0);

	// the "view tag" can speed up the scanning triple times!
	assert!(dur_ms / full_dur_ms < 0.35);
}

#[test]
fn test_default_display() {
	let pubkey_str = "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc";
	let pubkey = PublicKey::from_slice(&util::from_hex(pubkey_str).unwrap()).unwrap();
	let mut addr = Address {
		bech32_addr: Bech32Addr {
			version: bech32::u5::try_from_u8(0).unwrap(),
			inner_addr: InnerAddr::LiteStealthAddr { pubkey },
		},
		network: ChainTypes::Mainnet,
	};
	assert_eq!(Address::from_one_pubkey(&pubkey, ChainTypes::Mainnet), addr);

	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pubkey, &pubkey);
	println!(
		"pubkey: {}, mainnet address: {}, string len: {}",
		pubkey_str,
		addr,
		addr.to_string().len()
	);
	addr.network = ChainTypes::Floonet;
	println!(
		"pubkey: {}, floonet address: {}, string len: {}",
		pubkey_str,
		addr,
		addr.to_string().len()
	);
	println!();

	let pubkey_view_str = "028d5141948c1702e8c95f438815794b87f706a8d4cd2bffad1dc1570971032c9b";
	let pubkey_view = PublicKey::from_slice(&util::from_hex(pubkey_view_str).unwrap()).unwrap();
	let addr = Address::from_pubkey(&pubkey_view, &pubkey, ChainTypes::Mainnet);
	round_trips(&addr);
	check_pubkeys(&addr.to_string(), &pubkey_view, &pubkey);
	println!("pubkeys: ({},{})", pubkey_view_str, pubkey_str);
	println!(
		"mainnet address: {}, address string len: {}",
		addr,
		addr.to_string().len()
	);
}

#[test]
fn test_vectors() {
	let valid_vectors = [
		(
			"mwc1q80yvs0zjmat3yg569aezqmvsry3kdsmy9r9scy4k47vrynvhh77gdgunyk",
			"033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc",
			"033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc",
		),
		(
			"mwc1qwr3suqp5g9nwkppucuxzt7ssnrs3me4nw4ahxap22nht46qd5kzakmrf8haee68d70dvuqlagqsq9ukrx5rs0rvpucl396hj5wuh3evqsq46p",
			"0370e30e00344166eb043cc70c25fa1098e11de6b3757b73742a54eebae80da585",
			"02db6c693dfb9ce8edf3dace03fd402002f2c33507078d81e63f12eaf2a3b978e5",
		),
		(
			"mwt1qyr8cyze0exy4r475ylkm094fran2cpkv7u2szr7mxrn675sdk5k0l3dtdt47hf7ke5l6s08tcayzxw7vzuvktfu9pakzwhxdyrhmssu2yy03p",
			"0320cf820b2fc98951d7d427edb796a91f66ac06ccf715010fdb30e7af520db52c",
			"02ffc5ab6aebeba7d6cd3fa83cebc748233bcc171965a7850f6c275ccd20efb843",
		)
	];

	for vector in &valid_vectors {
		let addr = Address::from_str(vector.0).unwrap();
		assert_eq!(
			&addr
				.get_view_pubkey()
				.serialize_vec(true)
				.as_ref()
				.to_vec()
				.to_hex(),
			vector.1
		);
		assert_eq!(
			&addr
				.get_spend_pubkey()
				.serialize_vec(true)
				.as_ref()
				.to_vec()
				.to_hex(),
			vector.2
		);
		round_trips(&addr);
	}

	let invalid_vectors = [
		"mwc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
		"mwc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
		"MWC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
		"mwc1rw5uspcuh",
		"mwc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
		"MWT1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
		"mwt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
		"mwc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
		"mwt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
		"mwc1gmk9yu",
	];
	for vector in &invalid_vectors {
		let res = Address::from_str(vector);
		println!("{} : {:?}", vector, res);
		assert!(res.is_err());
	}
}
