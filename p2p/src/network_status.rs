// Copyright 2025 The MWC Developers
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

// Network related status. We need to know when if was offline/back online so we could
// start using Defunct peers faster

use rand::prelude::SliceRandom;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

static NETWORK_OUTAGE_TIME: AtomicI64 = AtomicI64::new(0);

pub fn get_network_outage_time() -> i64 {
	NETWORK_OUTAGE_TIME.load(Ordering::Relaxed)
}

pub fn update_network_outage_time(time: i64) {
	NETWORK_OUTAGE_TIME.store(time, Ordering::Relaxed);
}

static PROBE_URLS_HTTP: OnceLock<Vec<String>> = OnceLock::new();

/// Return the live probe list (filtered on first call, **blocking**).
fn probe_urls_http() -> &'static Vec<String> {
	PROBE_URLS_HTTP.get_or_init(|| {
        let candidates = vec![
            "www.google.com",
            "www.msftconnecttest.com",
            "detectportal.firefox.com",
            "www.apple.com",
        ];

        let mut live = Vec::with_capacity(candidates.len());
        for url in &candidates {
            if check_http_probe(url) {
                live.push(url.to_string());
            }
        }

        if live.is_empty() {
            error!("Unable to build list of probe domains, all reported as offline. Do you have internet conneciton issues?");
			for url in &candidates {
				live.push(url.to_string());
			}
        }

        live
    })
}

/// Blocking TCP probe: open, send HEAD, expect HTTP/1.1 2xx.
fn check_http_probe(host: &str) -> bool {
	let addr = match (host, 80).to_socket_addrs() {
		Ok(mut addr) => match addr.next() {
			Some(addr) => addr,
			None => return false,
		},
		Err(_) => return false,
	};
	let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
		Ok(s) => s,
		Err(_) => return false,
	};

	let req = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
	if stream.write_all(req.as_bytes()).is_err() {
		return false;
	}
	if stream.flush().is_err() {
		return false;
	}

	let mut buf = [0u8; 32];
	match stream.read(&mut buf) {
		Ok(n) if n > 10 => buf[..n].starts_with(b"HTTP/1.1"),
		_ => false,
	}
}

/// Pick a random **live** URL (after first-call filtering).
pub fn get_random_http_probe_host() -> String {
	let urls = probe_urls_http();
	urls.choose(&mut rand::thread_rng())
		.expect("non-empty")
		.clone()
}

#[test]
fn test_probe_urls() {
	let domains = probe_urls_http();
	assert!(domains.len() > 0);

	let domain = get_random_http_probe_host();
	assert!(domain.len() > 5);
}
