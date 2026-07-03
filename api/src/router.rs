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

use mwc_crates::bytes::Bytes;
use mwc_crates::futures::future::{self, Future};
use mwc_crates::http::request::Parts;
use mwc_crates::http_body_util::Full;
use mwc_crates::hyper::service::Service;
use mwc_crates::hyper::{Method, Request, Response, StatusCode};
use mwc_crates::serde::{self, Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;

const WILDCARD: &str = "*";
const WILDCARD_STOP: &str = "**";

pub type ResponseFuture =
	Pin<Box<dyn Future<Output = Result<Response<Full<Bytes>>, RouterError>> + Send>>;

pub trait Handler {
	fn pre_body_response(&self, _parts: &Parts) -> Option<ResponseFuture> {
		None
	}

	fn get(&self, _req: Request<Bytes>) -> ResponseFuture {
		not_found()
	}

	fn post(&self, _req: Request<Bytes>) -> ResponseFuture {
		not_found()
	}

	fn put(&self, _req: Request<Bytes>) -> ResponseFuture {
		not_found()
	}

	fn patch(&self, _req: Request<Bytes>) -> ResponseFuture {
		not_found()
	}

	fn delete(&self, _req: Request<Bytes>) -> ResponseFuture {
		not_found()
	}

	fn head(&self, _req: Request<Bytes>) -> ResponseFuture {
		not_found()
	}

	fn options(&self, _req: Request<Bytes>) -> ResponseFuture {
		not_found()
	}

	fn trace(&self, _req: Request<Bytes>) -> ResponseFuture {
		not_found()
	}

	fn connect(&self, _req: Request<Bytes>) -> ResponseFuture {
		not_found()
	}

	fn call(
		&self,
		req: Request<Bytes>,
		mut _handlers: Box<dyn Iterator<Item = HandlerObj>>,
	) -> ResponseFuture {
		match *req.method() {
			Method::GET => self.get(req),
			Method::POST => self.post(req),
			Method::PUT => self.put(req),
			Method::DELETE => self.delete(req),
			Method::PATCH => self.patch(req),
			Method::OPTIONS => self.options(req),
			Method::CONNECT => self.connect(req),
			Method::TRACE => self.trace(req),
			Method::HEAD => self.head(req),
			_ => not_found(),
		}
	}
}

#[derive(Clone, thiserror::Error, Eq, Debug, PartialEq, Serialize, Deserialize)]
#[serde(crate = "serde")]
pub enum RouterError {
	#[error("Route {0} already exists")]
	RouteAlreadyExists(String),
	#[error("Route {0} not found")]
	RouteNotFound(String),
	#[error("Route value not found for {0}")]
	NoValue(String),
	#[error("Path {0} must start with '/'")]
	InvalidPath(String),
	#[error("{0}")]
	Internal(String),
}

#[derive(Clone)]
pub struct Router {
	nodes: Vec<Node>,
}

#[derive(Debug, Clone, Copy)]
struct NodeId(usize);

const MAX_CHILDREN: usize = 16;

pub type HandlerObj = Arc<dyn Handler + Send + Sync>;

#[derive(Clone)]
pub struct Node {
	segment: String,
	value: Option<HandlerObj>,
	children: [NodeId; MAX_CHILDREN],
	children_count: usize,
	mws: Option<Vec<HandlerObj>>,
}

impl Router {
	pub fn new() -> Router {
		let root = Node::new("", None);
		let mut nodes = vec![];
		nodes.push(root);
		Router { nodes }
	}

	pub fn add_middleware(&mut self, mw: HandlerObj) {
		self.node_mut(NodeId(0)).add_middleware(mw);
	}

	fn root(&self) -> NodeId {
		NodeId(0)
	}

	fn node(&self, id: NodeId) -> &Node {
		&self.nodes[id.0]
	}

	fn node_mut(&mut self, id: NodeId) -> &mut Node {
		&mut self.nodes[id.0]
	}

	fn find_exact(&self, parent: NodeId, segment: &str) -> Option<NodeId> {
		let node = self.node(parent);
		node.children
			.iter()
			.take(node.children_count)
			.find(|&id| self.node(*id).segment == segment)
			.cloned()
	}

	fn find_route_match(&self, parent: NodeId, segment: &str) -> Option<NodeId> {
		self.find_exact(parent, segment)
			.or_else(|| self.find_exact(parent, WILDCARD))
			.or_else(|| self.find_exact(parent, WILDCARD_STOP))
	}

	fn add_empty_node(&mut self, parent: NodeId, segment: &str) -> Result<NodeId, RouterError> {
		self.node(parent).ensure_child_capacity()?;
		let id = NodeId(self.nodes.len());
		self.nodes.push(Node::new(segment, None));
		self.node_mut(parent).add_child(id)?;
		Ok(id)
	}

	pub fn add_route(
		&mut self,
		route: &'static str,
		value: HandlerObj,
	) -> Result<&mut Node, RouterError> {
		let segments = generate_path(route)?;
		let mut node_id = self.root();
		for segment in segments {
			node_id = match self.find_exact(node_id, segment) {
				Some(node_id) => node_id,
				None => self.add_empty_node(node_id, segment)?,
			};
		}
		match self.node(node_id).value() {
			None => {
				let node = self.node_mut(node_id);
				node.set_value(value);
				Ok(node)
			}
			Some(_) => Err(RouterError::RouteAlreadyExists(route.to_string())),
		}
	}

	pub fn get(&self, path: &str) -> Result<impl Iterator<Item = HandlerObj>, RouterError> {
		let segments = generate_path(path)?;
		let mut handlers = vec![];
		let mut node_id = self.root();
		collect_node_middleware(&mut handlers, self.node(node_id));
		for segment in segments {
			node_id = self
				.find_route_match(node_id, segment)
				.ok_or(RouterError::RouteNotFound(path.to_string()))?;
			let node = self.node(node_id);
			collect_node_middleware(&mut handlers, node);
			if node.segment == WILDCARD_STOP {
				break;
			}
		}

		if let Some(h) = self.node(node_id).value() {
			handlers.push(h);
			Ok(handlers.into_iter())
		} else {
			Err(RouterError::NoValue(path.to_string()))
		}
	}

	pub fn pre_body_response(&self, parts: &Parts) -> Option<ResponseFuture> {
		let handlers = self.get(parts.uri.path()).ok()?;
		for handler in handlers {
			if let Some(response) = handler.pre_body_response(parts) {
				return Some(response);
			}
		}
		None
	}
}

impl Service<Request<Bytes>> for Router {
	type Response = Response<Full<Bytes>>;
	type Error = RouterError;
	type Future = ResponseFuture;

	fn call(&self, req: Request<Bytes>) -> Self::Future {
		match self.get(req.uri().path()) {
			Err(_) => not_found(),
			Ok(mut handlers) => match handlers.next() {
				None => not_found(),
				Some(h) => h.call(req, Box::new(handlers)),
			},
		}
	}
}

impl Node {
	fn new(segment: &str, value: Option<HandlerObj>) -> Node {
		Node {
			segment: segment.to_string(),
			value,
			children: [NodeId(0); MAX_CHILDREN],
			children_count: 0,
			mws: None,
		}
	}

	pub fn add_middleware(&mut self, mw: HandlerObj) -> &mut Node {
		if self.mws.is_none() {
			self.mws = Some(vec![]);
		}
		if let Some(ref mut mws) = self.mws {
			mws.push(mw.clone());
		}
		self
	}

	fn value(&self) -> Option<HandlerObj> {
		match &self.value {
			None => None,
			Some(v) => Some(v.clone()),
		}
	}

	fn set_value(&mut self, value: HandlerObj) {
		self.value = Some(value);
	}

	fn ensure_child_capacity(&self) -> Result<(), RouterError> {
		if self.children_count >= MAX_CHILDREN {
			return Err(RouterError::Internal(
				"Can't add a route, children limit exceeded".into(),
			));
		}
		Ok(())
	}

	fn add_child(&mut self, child_id: NodeId) -> Result<(), RouterError> {
		self.ensure_child_capacity()?;
		self.children[self.children_count] = child_id;
		self.children_count += 1;
		Ok(())
	}
}

pub fn not_found() -> ResponseFuture {
	let mut response = Response::new(Full::new(Bytes::new()));
	*response.status_mut() = StatusCode::NOT_FOUND;
	Box::pin(future::ok(response))
}

fn generate_path(route: &str) -> Result<Vec<&str>, RouterError> {
	if !route.starts_with('/') {
		return Err(RouterError::InvalidPath(route.to_string()));
	}
	Ok(route.split('/').skip(1).collect())
}

fn collect_node_middleware(handlers: &mut Vec<HandlerObj>, node: &Node) {
	if let Some(ref mws) = node.mws {
		for mw in mws {
			handlers.push(mw.clone());
		}
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use mwc_crates::futures::executor::block_on;

	struct HandlerImpl(u16);

	impl Handler for HandlerImpl {
		fn get(&self, _req: Request<Bytes>) -> ResponseFuture {
			let code = self.0;
			Box::pin(async move {
				let res = Response::builder()
					.status(code)
					.body(Full::new(Bytes::new()))
					.unwrap();
				Ok(res)
			})
		}
	}

	#[test]
	fn test_add_route() {
		let mut routes = Router::new();
		let h1 = Arc::new(HandlerImpl(1));
		let h2 = Arc::new(HandlerImpl(2));
		let h3 = Arc::new(HandlerImpl(3));
		routes.add_route("/v1/users", h1.clone()).unwrap();
		assert!(routes.add_route("/v1/users", h2.clone()).is_err());
		routes.add_route("/v1/users/xxx", h3.clone()).unwrap();
		routes.add_route("/v1/users/xxx/yyy", h3.clone()).unwrap();
		routes.add_route("/v1/zzz/*", h3.clone()).unwrap();
		routes.add_route("/v1/zzz/ccc", h2.clone()).unwrap();
		assert!(routes.add_route("/v1/zzz/ccc", h2.clone()).is_err());
		routes
			.add_route("/v1/zzz/*/zzz", Arc::new(HandlerImpl(6)))
			.unwrap();
	}

	#[test]
	fn test_rejected_child_limit_does_not_leak_node() {
		let mut routes = Router::new();
		let route_names = [
			"/route0", "/route1", "/route2", "/route3", "/route4", "/route5", "/route6", "/route7",
			"/route8", "/route9", "/route10", "/route11", "/route12", "/route13", "/route14",
			"/route15",
		];

		assert_eq!(route_names.len(), MAX_CHILDREN);
		for (i, route) in route_names.iter().enumerate() {
			routes
				.add_route(*route, Arc::new(HandlerImpl(i as u16)))
				.unwrap();
		}

		let node_count = routes.nodes.len();
		assert!(routes
			.add_route("/too_many_routes", Arc::new(HandlerImpl(999)))
			.is_err());
		assert_eq!(routes.nodes.len(), node_count);
	}

	#[test]
	fn test_rejects_relative_route_paths() {
		let mut routes = Router::new();
		let node_count = routes.nodes.len();

		assert!(matches!(
			routes.add_route("v1/users", Arc::new(HandlerImpl(201))),
			Err(RouterError::InvalidPath(route)) if route == "v1/users"
		));
		assert!(matches!(
			routes.add_route("v1", Arc::new(HandlerImpl(202))),
			Err(RouterError::InvalidPath(route)) if route == "v1"
		));
		assert_eq!(routes.nodes.len(), node_count);
	}

	#[test]
	fn test_get() {
		let mut routes = Router::new();
		routes
			.add_route("/v1/users", Arc::new(HandlerImpl(101)))
			.unwrap();
		routes
			.add_route("/v1/users/xxx", Arc::new(HandlerImpl(103)))
			.unwrap();
		routes
			.add_route("/v1/users/xxx/yyy", Arc::new(HandlerImpl(103)))
			.unwrap();
		routes
			.add_route("/v1/zzz/*", Arc::new(HandlerImpl(103)))
			.unwrap();
		routes
			.add_route("/v1/zzz/*/zzz", Arc::new(HandlerImpl(106)))
			.unwrap();

		let call_handler = |url| {
			let task = async {
				let resp = routes
					.get(url)
					.unwrap()
					.next()
					.unwrap()
					.get(Request::new(Bytes::new()))
					.await
					.unwrap();
				resp.status().as_u16()
			};
			block_on(task)
		};

		assert_eq!(call_handler("/v1/users"), 101);
		assert_eq!(call_handler("/v1/users/xxx"), 103);
		assert!(routes.get("/v1/users/yyy").is_err());
		assert_eq!(call_handler("/v1/users/xxx/yyy"), 103);
		assert!(routes.get("/v1/zzz").is_err());
		assert_eq!(call_handler("/v1/zzz/1"), 103);
		assert_eq!(call_handler("/v1/zzz/2"), 103);
		assert_eq!(call_handler("/v1/zzz/2/zzz"), 106);
	}

	#[test]
	fn test_get_rejects_relative_paths() {
		let mut routes = Router::new();
		routes
			.add_route("/v1/users", Arc::new(HandlerImpl(201)))
			.unwrap();

		assert!(matches!(
			routes.get("v1/users"),
			Err(RouterError::InvalidPath(path)) if path == "v1/users"
		));
		assert!(matches!(
			routes.get("v1"),
			Err(RouterError::InvalidPath(path)) if path == "v1"
		));
	}

	#[test]
	fn test_add_route_does_not_reuse_wildcard_node_for_exact_route() {
		let mut routes = Router::new();
		routes
			.add_route("/a/*/b", Arc::new(HandlerImpl(201)))
			.unwrap();
		routes
			.add_route("/a/c", Arc::new(HandlerImpl(202)))
			.unwrap();

		let call_handler = |url| {
			let task = async {
				let resp = routes
					.get(url)
					.unwrap()
					.next()
					.unwrap()
					.get(Request::new(Bytes::new()))
					.await
					.unwrap();
				resp.status().as_u16()
			};
			block_on(task)
		};

		assert_eq!(call_handler("/a/c"), 202);
		assert!(routes.get("/a/d").is_err());
		assert_eq!(call_handler("/a/d/b"), 201);
	}
}
