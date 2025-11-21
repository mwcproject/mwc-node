use mwc_api as api;
use mwc_util as util;

use crate::api::*;
use hyper::{Body, Request, StatusCode};
use mwc_api::client::HttpClient;
use mwc_core::global;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{thread, time};

struct IndexHandler {
	list: Vec<String>,
}

impl IndexHandler {}

impl Handler for IndexHandler {
	fn get(&self, _req: Request<Body>) -> ResponseFuture {
		json_response_pretty(&self.list)
	}
}

pub struct CounterMiddleware {
	counter: AtomicUsize,
}

impl CounterMiddleware {
	fn new() -> CounterMiddleware {
		CounterMiddleware {
			counter: AtomicUsize::new(0),
		}
	}

	fn value(&self) -> usize {
		self.counter.load(Ordering::SeqCst)
	}
}

impl Handler for CounterMiddleware {
	fn call(
		&self,
		req: Request<Body>,
		mut handlers: Box<dyn Iterator<Item = HandlerObj>>,
	) -> ResponseFuture {
		self.counter.fetch_add(1, Ordering::SeqCst);
		match handlers.next() {
			Some(h) => h.call(req, handlers),
			None => return response(StatusCode::INTERNAL_SERVER_ERROR, "no handler found"),
		}
	}
}

fn build_router() -> Router {
	let route_list = vec!["get blocks".to_string(), "get chain".to_string()];
	let index_handler = IndexHandler { list: route_list };
	let mut router = Router::new();
	router
		.add_route("/v1/*", Arc::new(index_handler))
		.expect("add_route failed")
		.add_middleware(Arc::new(LoggingMiddleware {}));
	router
}

#[cfg(not(windows))]
#[test]
fn test_start_api() {
	global::set_local_chain_type(global::ChainTypes::Floonet);
	global::set_local_nrd_enabled(false);
	util::init_test_logger();
	let mut server = ApiServer::new();
	let mut router = build_router();
	let counter = Arc::new(CounterMiddleware::new());
	// add middleware to the root
	router.add_middleware(counter.clone());
	let server_addr = "127.0.0.1:14434";
	let addr: SocketAddr = server_addr.parse().expect("unable to parse server address");
	assert!(server.start(addr, router, None).is_ok());
	let url = format!("http://{}/v1/", server_addr);
	let index = request_with_retry(0, url.as_str()).unwrap();
	assert_eq!(index.len(), 2);
	assert_eq!(counter.value(), 1);
	assert!(server.stop());
	thread::sleep(time::Duration::from_millis(1_000));
}

// To enable this test you need a trusted PKCS12 (p12) certificate bundle
// Hyper-tls client doesn't accept self-signed certificates. The easiest way is to use mkcert
// https://github.com/FiloSottile/mkcert to install CA and generate a certificate on your local machine.
// You need to put the file to api/tests folder
#[ignore]
#[test]
fn test_start_api_tls() {
	global::set_local_chain_type(global::ChainTypes::Floonet);
	global::set_local_nrd_enabled(false);
	util::init_test_logger();
	let tls_conf = TLSConfig::new(
		"tests/fullchain.pem".to_string(),
		"tests/privkey.pem".to_string(),
	);
	let mut server = ApiServer::new();
	let router = build_router();
	let server_addr = "0.0.0.0:14444";
	let addr: SocketAddr = server_addr.parse().expect("unable to parse server address");
	assert!(server.start(addr, router, Some(tls_conf)).is_ok());
	let index = request_with_retry(0, "https://yourdomain.com:14444/v1/").unwrap();
	assert_eq!(index.len(), 2);
	assert!(!server.stop());
}

fn request_with_retry(context_id: u32, url: &str) -> Result<Vec<String>, api::Error> {
	let mut tries = 0;
	let client = HttpClient::new(context_id, Duration::from_secs(20), None);
	loop {
		match client.get(url) {
			Ok(res) => {
				return Ok(serde_json::from_value(res)
					.map_err(|e| Error::Internal(format!("Failed to parse response, {}", e)))?)
			}
			Err(e) => {
				if tries > 5 {
					return Err(Error::Internal(format!(
						"Failed to make get request, {}",
						e
					)));
				}
			}
		}
		tries += 1;
		thread::sleep(time::Duration::from_millis(500));
	}
}
