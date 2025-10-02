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

use anyhow::Result;
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BoolOrAuto, BridgeConfigBuilder, CfgPath};
use arti_client::{BootstrapBehavior, TorAddrError, TorClient, TorClientConfig};
use futures::future::{select, Either};
use futures::{Stream, StreamExt};
use hex::FromHex;
use log::{error, info};
use safelog::DisplayRedacted;
use std::io;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{interval, Instant};
use tor_cell::relaycell::msg::Connected;
use tor_config::ExplicitOrAuto;
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::StreamRequest;
use tor_keymgr::config::ArtiKeystoreKind;
use tor_llcrypto::pk::ed25519;
use tor_proto::client::stream::{DataReader, DataWriter, IncomingStreamRequest};
use tor_rtcompat::PreferredRuntime;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("p2p Connection error, {0}")]
	Connection(io::Error),
	/// Header type does not match the expected message type
	#[error("p2p bad message")]
	BadMessage,
	#[error("p2p unexpected message {0}")]
	UnexpectedMessage(String),
	#[error("p2p message Length error")]
	MsgLen,
	#[error("p2p banned")]
	Banned,
	#[error("p2p closed connection, {0}")]
	ConnectionClose(String),
	#[error("p2p timeout")]
	Timeout,
	#[error("peer with self")]
	PeerWithSelf,
	#[error("p2p no dandelion relay")]
	NoDandelionRelay,
	#[error("p2p send error, {0}")]
	Send(String),
	#[error("peer not found")]
	PeerNotFound,
	#[error("peer not banned")]
	PeerNotBanned,
	#[error("peer exception, {0}")]
	PeerException(String),
	#[error("p2p internal error: {0}")]
	Internal(String),
	#[error("libp2p error: {0}")]
	Libp2pError(String),
	#[error("configuration error: {0}")]
	ConfigError(String),
	/// Tor Configuration Error
	#[error("Tor Config Error: {0}")]
	TorConfig(String),
	/// Tor Process error
	#[error("Tor Process Error: {0}")]
	TorProcess(String),
	/// Tor is not initialized
	#[error("Tor is not initialized")]
	TorNotInitialized,
	/// Tor Process error
	#[error("Onion Service Error: {0}")]
	TorOnionService(String),
	/// Tor Connect error
	#[error("Tor outbound connection error: {0}")]
	TorConnect(String),
}

const PROBE_URLS_HTTP: &[&str] = &[
	"www.google.com",
	"www.msftconnecttest.com",
	"detectportal.firefox.com",
	"www.apple.com",
];

fn main() -> Result<(), Error> {
	// Arti uses the `tracing` crate for logging. Install a handler for this, to print Arti's logs.
	tracing_subscriber::fmt::init();

	let _global_tokio_runtime = tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()
		.expect("failed to start Tokio runtime");

	for i in 1..=5 {
		error!("Trying to build tor instance, try {} from 5", i);

		let arti_rt = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.build()
			.expect("failed to start Tokio runtime");

		// Creating the tor client and return what we can do with ok
		let tor_client: Result<TorClient<PreferredRuntime>, Error> = arti_rt.block_on(async {
			let tor_client_config = build_config(
				None, // Some("webtunnel 10.0.0.2:443 010D2A4DD97D7E58698FBE84788986387016AA74 url=https://explorer.floonet.mwc.mw/webtunnel".into()),
				"webtunnel",
				"/Users/mw/webtunnelclient",
			)
			.map_err(|e| Error::TorProcess(format!("Build config error, {}", e)))?;

			let rt = PreferredRuntime::current().map_err(|e| {
				Error::TorProcess(format!("Failed to get current PreferredRuntime, {}", e))
			})?;

			let tor_client = Arc::new(
				TorClient::with_runtime(rt)
					.config(tor_client_config)
					.bootstrap_behavior(BootstrapBehavior::Manual)
					.create_unbootstrapped()
					.map_err(|e| {
						Error::TorProcess(format!(
							"Unable to build unbootstrapped Arti instance, {}",
							e
						))
					})?,
			);

			let tor_client2 = Arc::downgrade(&tor_client);
			let mut bootstap_process = tokio::spawn(async move {
				if let Some(tor_client) = tor_client2.upgrade() {
					tor_client.bootstrap().await
				} else {
					// I can't specify correct error, returning what is possible.
					Err(TorAddrError::NoPort.into())
				}
			});

			// Waiting for bootstrap to finish, monitoring the progress
			let mut ticker = interval(Duration::from_secs(10));
			let mut last_new_progress_time = Instant::now();
			let mut last_progress = 0.0f32;
			loop {
				match select(&mut bootstap_process, pin!(ticker.tick())).await {
					Either::Left((bootstrap_res, _)) => {
						bootstrap_res
							.map_err(|e| {
								Error::TorProcess(format!("Arti bootstrap tokio error, {}", e))
							})?
							.map_err(|e| {
								Error::TorProcess(format!("Unable to bootstrap arti, {}", e))
							})?;
						info!("Tor Client bootstrap is finished successfully");
						break;
					}
					Either::Right((_, _)) => {
						let progress = tor_client.bootstrap_status().as_frac();
						if progress > last_progress {
							last_progress = progress;
							last_new_progress_time = Instant::now();
							info!("Arti bootstrap making some progress: {}%", progress * 100.0);
						} else {
							let elapsed = Instant::now().duration_since(last_new_progress_time);
							if elapsed >= Duration::from_secs(90) {
								error!("Arti not able to make any bootstrap progress during {} seconds", elapsed.as_secs());
								info!("Stopping failed Arti client");
								//bootstap_process.abort();
								//let _ = bootstap_process.await;
								drop(tor_client);
								info!("Failed arti is stopped");
								return Err(Error::TorProcess(
									"Arti not able to make bootstrap progress during long time"
										.into(),
								));
							}
						}
					}
				}
			}

			match Arc::try_unwrap(tor_client) {
				Ok(tor_client) => Ok(tor_client),
				Err(_) => panic!("tor_client is stoll shared!"),
			}
		});

		let tor_client = match tor_client {
			Ok(t) => t,
			Err(e) => {
				error!("Failed to bootstrap, {}", e);
				arti_rt.shutdown_timeout(Duration::from_secs(10));
				info!("Arti should be deleted, no tor logs are expected");

				std::thread::sleep(Duration::from_secs(20));
				continue;
			}
		};

		let bytes = Vec::from_hex("20fe699c1ab9b0d42f31ee907eeb337dee53aa3214a3cc06bcd8acd5841abe5c053e953439ad9e4f58362477cfe2aa6b61e8b23ce19ffa3ec7e233c0ac52f71b").unwrap();
		let key: [u8; 64] = bytes.try_into().unwrap();

		let id_keypair =
			HsIdKeypair::from(ed25519::ExpandedKeypair::from_secret_key_bytes(key).unwrap());

		eprintln!("[+] Launching onion service...");
		let svc_cfg = OnionServiceConfigBuilder::default()
			.nickname("mwc-node".parse().unwrap())
			.build()
			.unwrap();
		let (service, request_stream) = tor_client
			.launch_onion_service_with_hsid(svc_cfg, id_keypair)
			.unwrap();

		let onion_address = service
			.onion_address()
			.expect("Onion address not found")
			.display_unredacted()
			.to_string();

		eprintln!("[+] Onion address: {}", onion_address);

		// `is_fully_reachable` might remain false even if the service is reachable in practice;
		// after a timeout, we stop waiting for that and try anyway.
		let timeout_seconds = 60;
		let status_stream = service.status_events();
		let mut binding = status_stream.filter(|status| {
			futures::future::ready({
				//let status_dump = format!("{:?}", status.state());
				status.state().is_fully_reachable() /*|| status_dump.contains("DegradedUnreachable")*/
				// DegradedUnreachable in my case stais forever. Let's concider it is ok
			})
		});

		arti_rt.block_on( async {
            match tokio::time::timeout(Duration::from_secs(timeout_seconds), binding.next()).await {
                Ok(Some(_)) => eprintln!("[+] Onion service is fully reachable."),
                Ok(None) => eprintln!("[-] Status stream ended unexpectedly."),
                Err(_) => eprintln!(
                    "[-] Timeout waiting for service to become reachable. You can still attempt to visit the service."
                ),
            }

            // 4. Spawn the listener task (accepts connections from the Internet).
            let stream = tor_hsservice::handle_rend_requests(request_stream);
            tokio::spawn(serve_loop(stream));

            for probe_url in PROBE_URLS_HTTP {
                eprintln!("connecting to {}", probe_url);

                // Initiate a connection over Tor to example.com, port 80.
                let mut stream_req = tor_client.connect((*probe_url, 80)).await.unwrap();

                eprintln!("sending request...");

                stream_req
                    .write_all( format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", *probe_url).as_bytes())
                    .await.unwrap();

                // IMPORTANT: Make sure the request was written.
                // Arti buffers data, so flushing the buffer is usually required.
                stream_req.flush().await.unwrap();
                eprintln!("reading response...");

                // Read and print the result.
                let mut buf = Vec::new();
                stream_req.read_to_end(&mut buf).await.unwrap();
                stream_req.shutdown().await.unwrap();
                drop(stream_req);
                println!("{}", String::from_utf8_lossy(&buf));
            }

            Ok(())
        })?;

		for _ in 0..2 {
			let _ = std::thread::sleep(Duration::from_secs(1));
			println!("Waiting to try second instance");
		}

		println!("Waiting to stop");
		let _res = tor_client.wait_for_stop();
		drop(tor_client);
		drop(service);
		//drop(request_stream);
		arti_rt.shutdown_timeout(Duration::from_secs(10));
		println!("It is stopped!");
	}

	Ok(())
}

async fn serve_loop(
	/*_service: Arc<RunningOnionService>,*/
	mut requests: impl Stream<Item = StreamRequest> + Unpin + 'static,
) {
	while let Some(stream_request) = requests.next().await {
		// Incoming connection.
		tokio::spawn(async move {
			let request = stream_request.request();
			match request {
				IncomingStreamRequest::Begin(begin) if begin.port() == 80 => {
					match stream_request.accept(Connected::new_empty()).await {
						Ok(onion_service_stream) => {
							let (recv, send) = onion_service_stream.split(); // or whatever API the request gives you
							if let Err(e) = serve_data_exchange(recv, send).await {
								println!("IO error: {}", e)
							}
						}
						Err(err) => println!("Client error: {}", err),
					}
				}
				_ => {
					let _ = stream_request.shutdown_circuit();
				}
			}
		});
	}
}

async fn serve_data_exchange(reader: DataReader, mut writer: DataWriter) -> Result<()> {
	let mut buf_reader = BufReader::new(reader);
	let mut line = String::new();

	// read one UTF-8 line (includes '\n')
	buf_reader.read_line(&mut line).await?;
	println!("Get the line: {}", line);

	writer.write_all("OK, get it!\n\n".as_bytes()).await?;
	writer.flush().await?;

	//tokio::time::sleep(Duration::from_secs(1)).await;

	writer.shutdown().await?;

	//    let mut buf = Vec::new();
	//    buf_reader.read_to_end(&mut buf).await?;

	Ok(())
}

fn build_config(
	bridge_line: Option<String>,
	protocol_name: &str,
	client_path: &str,
) -> Result<TorClientConfig> {
	let mut builder = TorClientConfig::builder();

	if let Some(bridge_line) = bridge_line {
		let bridge: BridgeConfigBuilder = bridge_line.parse()?;
		builder.bridges().bridges().push(bridge);
		let mut transport = TransportConfigBuilder::default();
		transport
			.protocols(vec![protocol_name.parse()?])
			.path(CfgPath::new(client_path.into()))
			.run_on_startup(true);
		builder.bridges().transports().push(transport);
	}

	// Setup Ethemeral Key Store
	builder
		.storage()
		.keystore()
		.enabled(BoolOrAuto::Explicit(true))
		.primary()
		.kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));

	let _ = std::fs::remove_dir_all("/Users/bay/arti_data");

	builder
		.storage()
		.cache_dir(CfgPath::new_literal("/Users/bay/arti_data/cache"));
	builder
		.storage()
		.state_dir(CfgPath::new_literal("/Users/bay/arti_data/state"));

	Ok(builder.build()?)
}
