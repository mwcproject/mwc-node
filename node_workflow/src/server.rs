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

// Server management routine

use crate::Error;
use mwc_api::Router;
use mwc_crates::bytes::Bytes;
use mwc_crates::futures;
use mwc_crates::http;
use mwc_crates::http_body_util::Full;
use mwc_crates::hyper::service::Service;
use mwc_crates::lazy_static::lazy_static;
use mwc_crates::log::error;
use mwc_crates::parking_lot::{Condvar, Mutex, RwLock};
use mwc_crates::secp::{ContextFlag, Secp256k1};
use mwc_p2p::tor::arti;
use mwc_p2p::TorConfig;
use mwc_servers::{Server, ServerConfig, ServerStats};
use mwc_util::StopState;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Weak};

lazy_static! {
		/// Global chain status flags. It is expected that init call will set them first for every needed context
		/// Note, both node and wallet will need to set it up. Any param can be set once
	static ref SERVER_CONTEXT: RwLock<HashMap<u32, RegisteredServer>> =
		RwLock::new(HashMap::new());

	static ref SERVER_LIFECYCLE_CONTEXT: RwLock<HashMap<u32, Weak<ServerLifecycle>>> =
		RwLock::new(HashMap::new());

	static ref CALL_ROUTER_CONTEXT: RwLock<HashMap<u32, Arc<CallRouterEntry>>> =
		RwLock::new(HashMap::new());
}

/// Identity token for one server instance stored under a reusable context ID.
struct ServerGeneration;

struct RegisteredServer {
	generation: Arc<ServerGeneration>,
	server: Server,
}

impl RegisteredServer {
	fn new(server: Server) -> Self {
		RegisteredServer {
			generation: Arc::new(ServerGeneration),
			server,
		}
	}
}

fn same_server_generation(
	current: &Arc<ServerGeneration>,
	expected: &Arc<ServerGeneration>,
) -> bool {
	Arc::ptr_eq(current, expected)
}

enum ServerLifecycleState {
	Idle,
	Starting(Arc<StopState>),
	Releasing,
}

struct ServerLifecycle {
	/// Serializes create/release work for this context without blocking other contexts.
	operation: Mutex<()>,
	state: Mutex<ServerLifecycleState>,
	release_finished: Condvar,
}

impl ServerLifecycle {
	fn new() -> Self {
		ServerLifecycle {
			operation: Mutex::new(()),
			state: Mutex::new(ServerLifecycleState::Idle),
			release_finished: Condvar::new(),
		}
	}
}

struct CallRouterEntry {
	/// `None` permanently closes this generation after all active readers finish.
	router: RwLock<Option<Router>>,
}

impl CallRouterEntry {
	fn new(router: Router) -> Self {
		CallRouterEntry {
			router: RwLock::new(Some(router)),
		}
	}

	fn close_and_wait(&self) {
		self.router.write().take();
	}
}

enum BeginServerRelease {
	Acquired(Option<Arc<StopState>>),
	CompletedByConcurrentRelease,
}

fn server_lifecycle(context_id: u32) -> Arc<ServerLifecycle> {
	if let Some(lifecycle) = SERVER_LIFECYCLE_CONTEXT
		.read_recursive()
		.get(&context_id)
		.and_then(Weak::upgrade)
	{
		return lifecycle;
	}

	let mut lifecycles = SERVER_LIFECYCLE_CONTEXT.write();
	// Context IDs are normally bounded, but release_server() is deliberately
	// idempotent for arbitrary IDs. Prune completed weak entries so invalid calls
	// cannot grow this registry indefinitely.
	lifecycles.retain(|_, lifecycle| lifecycle.strong_count() > 0);
	if let Some(lifecycle) = lifecycles.get(&context_id).and_then(Weak::upgrade) {
		return lifecycle;
	}

	let lifecycle = Arc::new(ServerLifecycle::new());
	lifecycles.insert(context_id, Arc::downgrade(&lifecycle));
	lifecycle
}

fn register_server_start(
	lifecycle: &ServerLifecycle,
	stop_state: Arc<StopState>,
) -> Result<(), Error> {
	let mut state = lifecycle.state.lock();
	match &*state {
		ServerLifecycleState::Starting(_) => Err(Error::ContextError(
			"Node server is already starting for this context".into(),
		)),
		ServerLifecycleState::Releasing => Err(Error::ContextError(
			"Node server is being released for this context".into(),
		)),
		ServerLifecycleState::Idle => {
			*state = ServerLifecycleState::Starting(stop_state);
			Ok(())
		}
	}
}

fn finish_server_start(lifecycle: &ServerLifecycle, stop_state: &Arc<StopState>) {
	let mut state = lifecycle.state.lock();
	let owns_starting_state = matches!(
		&*state,
		ServerLifecycleState::Starting(current) if Arc::ptr_eq(current, stop_state)
	);
	if owns_starting_state {
		*state = ServerLifecycleState::Idle;
	}
}

fn begin_server_release(lifecycle: &ServerLifecycle) -> BeginServerRelease {
	let mut state = lifecycle.state.lock();
	if matches!(&*state, ServerLifecycleState::Releasing) {
		while matches!(&*state, ServerLifecycleState::Releasing) {
			lifecycle.release_finished.wait(&mut state);
		}
		return BeginServerRelease::CompletedByConcurrentRelease;
	}

	match &*state {
		ServerLifecycleState::Starting(stop_state) => {
			let stop_state = stop_state.clone();
			*state = ServerLifecycleState::Releasing;
			BeginServerRelease::Acquired(Some(stop_state))
		}
		ServerLifecycleState::Idle => {
			*state = ServerLifecycleState::Releasing;
			BeginServerRelease::Acquired(None)
		}
		ServerLifecycleState::Releasing => unreachable!("handled above"),
	}
}

fn finish_server_release(lifecycle: &ServerLifecycle) {
	let mut state = lifecycle.state.lock();
	if matches!(&*state, ServerLifecycleState::Releasing) {
		*state = ServerLifecycleState::Idle;
		lifecycle.release_finished.notify_all();
	}
}

fn replace_call_router(context_id: u32, router: Router) {
	let old_entry = CALL_ROUTER_CONTEXT
		.write()
		.insert(context_id, Arc::new(CallRouterEntry::new(router)));
	if let Some(old_entry) = old_entry {
		old_entry.close_and_wait();
	}
}

fn remove_and_drain_call_router(context_id: u32) {
	let entry = CALL_ROUTER_CONTEXT.write().remove(&context_id);
	if let Some(entry) = entry {
		// Existing calls hold a read guard. Taking the router waits for those calls,
		// and makes stale Arc clones reject a late attempt to start.
		entry.close_and_wait();
	}
}

/// Stop the server jobs and release the server.
///
/// This is a best-effort, idempotent cleanup operation. If the server for this
/// context was already released or was never created, the call still succeeds
/// after clearing any remaining per-context router/chain data.
pub fn release_server(context_id: u32) {
	let lifecycle = server_lifecycle(context_id);
	// Publish the release before touching any per-context data. A replacement
	// create_server() cannot start until all cleanup below has completed.
	let startup_stop_state = match begin_server_release(&lifecycle) {
		BeginServerRelease::Acquired(stop_state) => stop_state,
		BeginServerRelease::CompletedByConcurrentRelease => return,
	};
	if let Some(stop_state) = &startup_stop_state {
		stop_state.stop();
	}
	let _operation = lifecycle.operation.lock();

	let server = {
		let mut servers = SERVER_CONTEXT.write();
		servers.remove(&context_id)
	};
	if let Some(server) = &server {
		// Give active API operations a chance to stop before waiting for them.
		server.server.stop_state.stop();
	}
	remove_and_drain_call_router(context_id);
	if let Some(server) = server {
		server.server.stop();
		mwc_chain::pipe::release_context_data(context_id);
	} else if startup_stop_state.is_none() {
		mwc_chain::pipe::release_context_data(context_id);
	}
	finish_server_release(&lifecycle);
}

/// Tor client needs to be started once, no context_id is requred
pub fn start_tor(config: &TorConfig, base_dir: &str) -> Result<(), Error> {
	arti::start_arti(
		config,
		PathBuf::from(base_dir).as_path(),
		mwc_util::is_console_output_enabled(),
		false,
	)
	.map_err(|e| Error::TorError(format!("Arti start error, {}", e)))?;
	Ok(())
}

/// Get ro status: <started, healthy>
pub fn tor_status() -> (bool, bool) {
	(arti::is_arti_started(), arti::is_arti_healthy())
}

/// Create a new server instance. No jobs will be started.
///
/// The provided stop state is registered before chain initialization begins,
/// allowing callers to cancel txhashset startup indexing before the server is
/// fully constructed.
pub fn create_server(
	context_id: u32,
	config: ServerConfig,
	stop_state: Arc<StopState>,
	skip_start_blockchain_validation: bool,
) -> Result<(), Error> {
	let lifecycle = server_lifecycle(context_id);
	let _operation = lifecycle.operation.lock();
	register_server_start(&lifecycle, stop_state.clone())?;

	if SERVER_CONTEXT.read_recursive().contains_key(&context_id) {
		finish_server_start(&lifecycle, &stop_state);
		return Err(Error::ContextError(
			"Node server already created for this context".into(),
		));
	}
	if context_id != 0 {
		if let Err(e) = crate::context::get_chain_type(context_id) {
			finish_server_start(&lifecycle, &stop_state);
			return Err(e);
		}
	}

	let secp = match Secp256k1::with_caps(ContextFlag::Commit) {
		Ok(secp) => secp,
		Err(e) => {
			finish_server_start(&lifecycle, &stop_state);
			return Err(Error::ServerError(format!(
				"Secp instance creation error, {}",
				e
			)));
		}
	};

	let serv = match Server::create_server(
		&secp,
		context_id,
		config,
		stop_state.clone(),
		skip_start_blockchain_validation,
	) {
		Ok(serv) => serv,
		Err(e) => {
			mwc_chain::pipe::release_context_data(context_id);
			finish_server_start(&lifecycle, &stop_state);
			return Err(Error::ServerError(format!(
				"Unable to create server, {}",
				e
			)));
		}
	};

	if stop_state.is_stopped() {
		serv.stop();
		mwc_chain::pipe::release_context_data(context_id);
		finish_server_start(&lifecycle, &stop_state);
		return Err(Error::ServerError(
			"Server start was cancelled during blockchain indexing".into(),
		));
	}

	SERVER_CONTEXT
		.write()
		.insert(context_id, RegisteredServer::new(serv));
	if stop_state.is_stopped() {
		let serv = SERVER_CONTEXT
			.write()
			.remove(&context_id)
			.expect("server was just inserted for this lifecycle operation");
		serv.server.stop();
		mwc_chain::pipe::release_context_data(context_id);
		finish_server_start(&lifecycle, &stop_state);
		return Err(Error::ServerError(
			"Server start was cancelled during blockchain indexing".into(),
		));
	}

	finish_server_start(&lifecycle, &stop_state);
	Ok(())
}

/// Start Stratum protocol, needed for the mining
pub fn start_stratum(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.server
			.start_stratum()
			.map_err(|e| Error::ServerError(format!("Unable to start stratum, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}

	Ok(())
}

/// Start pees discovery p2p peers job
pub fn start_discover_peers(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.server
			.start_discover_peers()
			.map_err(|e| Error::ServerError(format!("Unable to start discover peers, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Start node syncing job
pub fn start_sync_monitoring(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.server
			.start_sync_monitoring()
			.map_err(|e| Error::ServerError(format!("Unable to start sync thread, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Start p2p listening job. Needed for inbound peers connection
pub fn start_listen_peers(context_id: u32) -> Result<(), Error> {
	let (pending_listener, server_generation) = {
		let mut servers = SERVER_CONTEXT.write();
		match servers.get_mut(&context_id) {
			Some(serv) => {
				let pending_listener = serv.server.begin_start_listen_peers().map_err(|e| {
					Error::ServerError(format!("Unable to start listening for peers, {}", e))
				})?;
				(pending_listener, serv.generation.clone())
			}
			None => {
				return Err(Error::ServerError(format!(
					"Server not exist for context {}",
					context_id
				)));
			}
		}
	};

	let startup_result = pending_listener.wait_for_startup();

	let mut servers = SERVER_CONTEXT.write();
	// Context IDs can be reused after release. Only finalize against the exact
	// server instance that created this pending listener.
	match servers.get_mut(&context_id) {
		Some(serv) if same_server_generation(&serv.generation, &server_generation) => {
			match startup_result {
				Ok(started_listener) => serv
					.server
					.finish_start_listen_peers(started_listener)
					.map_err(|e| {
						Error::ServerError(format!("Unable to start listening for peers, {}", e))
					})?,
				Err(e) => {
					serv.server.finish_failed_listen_peers_startup();
					return Err(Error::ServerError(format!(
						"Unable to start listening for peers, {}",
						e
					)));
				}
			}
		}
		Some(_) => {
			drop(servers);
			if let Ok(started_listener) = startup_result {
				started_listener.wait_for_shutdown();
			}
			return Err(Error::ServerError(format!(
				"Server was replaced while peer listener was starting for context {}",
				context_id
			)));
		}
		None => {
			drop(servers);
			if let Ok(started_listener) = startup_result {
				started_listener.wait_for_shutdown();
			}
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Starting node rest API, needed for communication with mwc-wallet
pub fn start_rest_api(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.server
			.start_rest_api()
			.map_err(|e| Error::ServerError(format!("Unable to start node rest api, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Init router for lib based API
pub fn init_call_api(context_id: u32) -> Result<(), Error> {
	let servers = SERVER_CONTEXT.read_recursive();
	let router = match servers.get(&context_id) {
		Some(serv) => serv
			.server
			.build_api_router_no_secrets()
			.map_err(|e| Error::ServerError(format!("Unable to build node call api, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	};
	replace_call_router(context_id, router);
	Ok(())
}

/// Process rest API related call
pub fn process_call(
	context_id: u32,
	method: String,
	uri: String,
	body: String,
) -> Result<http::Response<Full<Bytes>>, Error> {
	let router_entry = {
		let routers = CALL_ROUTER_CONTEXT.read_recursive();
		routers.get(&context_id).cloned()
	}
	.ok_or_else(|| Error::ServerError(format!("Call API not exist for context {}", context_id)))?;

	let method = http::Method::from_bytes(method.as_bytes()).map_err(|e| {
		Error::ServerError(format!("HTTP request get invalid method {}, {}", method, e))
	})?;
	let uri = uri
		.parse::<http::Uri>()
		.map_err(|e| Error::ServerError(format!("HTTP request get invalid Uri {}, {}", uri, e)))?;

	let request = http::Request::builder()
		.method(method)
		.uri(uri)
		.version(http::Version::HTTP_10)
		.body(Bytes::from(body))
		.map_err(|e| Error::ServerError(format!("Unable to build a request, {}", e)))?;

	// Keep this per-context read guard until the response is complete. Shutdown
	// removes the registry entry, then takes the write guard to drain these calls.
	let router_guard = router_entry.router.read_recursive();
	let router = router_guard.as_ref().ok_or_else(|| {
		Error::ServerError(format!(
			"Call API is shutting down for context {}",
			context_id
		))
	})?;
	let response = futures::executor::block_on(router.call(request));
	match response {
		Ok(response) => Ok(response),
		Err(e) => {
			error!("Unable to process API request, {}", e);
			Err(Error::ServerError(format!(
				"Unable to process API request, {}",
				e
			)))
		}
	}
}

/// Start dandelion protocol. Needed for publishing transactions
pub fn start_dandelion(context_id: u32) -> Result<(), Error> {
	let mut servers = SERVER_CONTEXT.write();
	match servers.get_mut(&context_id) {
		Some(serv) => serv
			.server
			.start_dandelion()
			.map_err(|e| Error::ServerError(format!("Unable to start dandelion, {}", e)))?,
		None => {
			return Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			)));
		}
	}
	Ok(())
}

/// Get server stats data, used by node UI.
pub fn get_server_stats(context_id: u32) -> Result<ServerStats, Error> {
	match SERVER_CONTEXT.try_read_recursive() {
		Some(servers) => match servers.get(&context_id) {
			Some(serv) => Ok(serv.server.get_server_stats().map_err(|e| {
				Error::ServerError(format!("Unable to get server stat data, {}", e))
			})?),
			None => Err(Error::ServerError(format!(
				"Server not exist for context {}",
				context_id
			))),
		},
		None => Err(Error::ServerError("Server is busy".into())),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use mwc_api::{Handler, ResponseFuture};
	use std::sync::{mpsc, Mutex as StdMutex};
	use std::thread;
	use std::time::{Duration, Instant};

	struct BlockingHandler {
		started_tx: mpsc::SyncSender<()>,
		continue_rx: StdMutex<mpsc::Receiver<()>>,
	}

	impl Handler for BlockingHandler {
		fn get(&self, _req: http::Request<Bytes>) -> ResponseFuture {
			self.started_tx
				.send(())
				.expect("test must wait for the handler to start");
			self.continue_rx
				.lock()
				.expect("test continue channel mutex must not be poisoned")
				.recv()
				.expect("test must allow the handler to finish");
			Box::pin(futures::future::ok(http::Response::new(Full::new(
				Bytes::new(),
			))))
		}
	}

	#[test]
	fn listener_start_generation_does_not_match_replacement() {
		let original_generation = Arc::new(ServerGeneration);
		let pending_generation = original_generation.clone();
		let replacement_generation = Arc::new(ServerGeneration);

		assert!(same_server_generation(
			&original_generation,
			&pending_generation
		));
		assert!(!same_server_generation(
			&replacement_generation,
			&pending_generation
		));
	}

	#[test]
	fn release_marker_blocks_replacement_until_cleanup_finishes() {
		let context_id = u32::MAX;
		let lifecycle = server_lifecycle(context_id);
		let starting_stop_state = Arc::new(StopState::new());
		register_server_start(&lifecycle, starting_stop_state.clone()).unwrap();

		let registered_stop_state = match begin_server_release(&lifecycle) {
			BeginServerRelease::Acquired(Some(stop_state)) => stop_state,
			_ => panic!("release did not take ownership of the active startup"),
		};
		assert!(Arc::ptr_eq(&registered_stop_state, &starting_stop_state));
		registered_stop_state.stop();

		// Cleanup by the displaced startup must not remove the release marker.
		finish_server_start(&lifecycle, &starting_stop_state);
		let replacement_stop_state = Arc::new(StopState::new());
		assert!(register_server_start(&lifecycle, replacement_stop_state.clone()).is_err());

		let concurrent_lifecycle = lifecycle.clone();
		let (waiting_tx, waiting_rx) = mpsc::sync_channel(1);
		let (finished_tx, finished_rx) = mpsc::sync_channel(1);
		let concurrent_release = thread::spawn(move || {
			waiting_tx.send(()).unwrap();
			let result = begin_server_release(&concurrent_lifecycle);
			finished_tx
				.send(matches!(
					result,
					BeginServerRelease::CompletedByConcurrentRelease
				))
				.unwrap();
		});
		waiting_rx.recv_timeout(Duration::from_secs(1)).unwrap();
		assert!(finished_rx
			.recv_timeout(Duration::from_millis(100))
			.is_err());

		finish_server_release(&lifecycle);
		assert!(finished_rx.recv_timeout(Duration::from_secs(1)).unwrap());
		concurrent_release.join().unwrap();

		register_server_start(&lifecycle, replacement_stop_state.clone()).unwrap();
		finish_server_start(&lifecycle, &replacement_stop_state);
	}

	#[test]
	fn release_waits_for_active_call_and_closes_stale_router_clones() {
		let context_id = u32::MAX - 1;
		let (started_tx, started_rx) = mpsc::sync_channel(1);
		let (continue_tx, continue_rx) = mpsc::sync_channel(1);
		let mut router = Router::new();
		router
			.add_route(
				"/block",
				Arc::new(BlockingHandler {
					started_tx,
					continue_rx: StdMutex::new(continue_rx),
				}),
			)
			.unwrap();
		replace_call_router(context_id, router);
		let stale_entry = CALL_ROUTER_CONTEXT
			.read_recursive()
			.get(&context_id)
			.cloned()
			.unwrap();

		let call_thread = thread::spawn(move || {
			process_call(context_id, "GET".into(), "/block".into(), String::new())
		});
		started_rx.recv_timeout(Duration::from_secs(1)).unwrap();

		let (released_tx, released_rx) = mpsc::sync_channel(1);
		let release_thread = thread::spawn(move || {
			release_server(context_id);
			released_tx.send(()).unwrap();
		});

		let deadline = Instant::now() + Duration::from_secs(1);
		while CALL_ROUTER_CONTEXT
			.read_recursive()
			.contains_key(&context_id)
		{
			assert!(
				Instant::now() < deadline,
				"release did not revoke the router"
			);
			thread::yield_now();
		}
		assert!(released_rx
			.recv_timeout(Duration::from_millis(100))
			.is_err());

		continue_tx.send(()).unwrap();
		assert!(call_thread.join().unwrap().is_ok());
		released_rx.recv_timeout(Duration::from_secs(1)).unwrap();
		release_thread.join().unwrap();
		assert!(stale_entry.router.read_recursive().is_none());
	}

	#[test]
	fn lifecycle_operations_are_scoped_to_one_context() {
		let first = server_lifecycle(u32::MAX - 2);
		let second = server_lifecycle(u32::MAX - 3);
		let _first_operation = first.operation.lock();

		assert!(second.operation.try_lock().is_some());
	}

	#[test]
	fn completed_lifecycle_entries_do_not_stay_alive() {
		let context_id = u32::MAX - 4;
		let prune_trigger_id = u32::MAX - 5;
		let lifecycle = server_lifecycle(context_id);
		let lifecycle_weak = Arc::downgrade(&lifecycle);
		drop(lifecycle);

		assert!(lifecycle_weak.upgrade().is_none());
		drop(server_lifecycle(prune_trigger_id));
		assert!(!SERVER_LIFECYCLE_CONTEXT
			.read_recursive()
			.contains_key(&context_id));
	}
}
