// Copyright 2026 The MWC Developers
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

//! Explicit connection configuration shared by the node and wallet.

use crate::types::{Error, TorBridgeConfig, TorTransportConfig};
use mwc_crates::arti_client::config::pt::TransportConfigBuilder;
use mwc_crates::arti_client::config::{
	BoolOrAuto, BridgeConfigBuilder, CfgPath, PtTransportName, TorClientConfigBuilder, TransportId,
};
use mwc_crates::toml;
use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

// Bridge parameters, executable arguments, and proxy URIs can all contain
// credentials. Neither Debug nor validation errors should reveal their values.
impl fmt::Debug for TorBridgeConfig {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("TorBridgeConfig")
			.field("bridge_count", &self.bridges.len())
			.field("transport_count", &self.transports.len())
			.field("proxy_configured", &self.proxy.is_some())
			.finish()
	}
}

impl fmt::Debug for TorTransportConfig {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("TorTransportConfig")
			.field("protocol_count", &self.protocols.len())
			.field("managed", &self.path.is_some())
			.field("argument_count", &self.arguments.len())
			.field("run_on_startup", &self.run_on_startup)
			.field("proxy_configured", &self.proxy_addr.is_some())
			.finish()
	}
}

impl TorBridgeConfig {
	/// Serialize this setting as a TOML value suitable for one configuration line.
	pub fn to_inline_toml(&self) -> Result<String, toml::ser::Error> {
		Ok(inline_value(&toml::Value::try_from(self)?))
	}
}

// TOML's default serializer can choose multiline strings even inside an inline
// table. Always use escaped basic strings so this setting stays on one line,
// including when a helper argument contains a line break or other control byte.
fn inline_string(value: &str) -> String {
	let mut output = String::from("\"");
	for character in value.chars() {
		match character {
			'"' => output.push_str("\\\""),
			'\\' => output.push_str("\\\\"),
			'\n' => output.push_str("\\n"),
			'\r' => output.push_str("\\r"),
			'\t' => output.push_str("\\t"),
			'\u{8}' => output.push_str("\\b"),
			'\u{c}' => output.push_str("\\f"),
			'\0'..='\u{1f}' | '\u{7f}' => {
				output.push_str(&format!("\\u{:04X}", character as u32));
			}
			_ => output.push(character),
		}
	}
	output.push('"');
	output
}

fn inline_value(value: &toml::Value) -> String {
	match value {
		toml::Value::String(value) => inline_string(value),
		toml::Value::Array(values) => format!(
			"[{}]",
			values
				.iter()
				.map(inline_value)
				.collect::<Vec<_>>()
				.join(", ")
		),
		toml::Value::Table(values) => format!(
			"{{ {} }}",
			values
				.iter()
				.map(|(key, value)| format!("{key} = {}", inline_value(value)))
				.collect::<Vec<_>>()
				.join(", ")
		),
		_ => value.to_string(),
	}
}

fn config_error(message: &str) -> Error {
	Error::TorConfig(format!("tor_bridge: {message}"))
}

impl TorBridgeConfig {
	/// Apply only this explicitly selected connection mode, without any fallback.
	pub(crate) fn apply(&self, builder: &mut TorClientConfigBuilder) -> Result<(), Error> {
		if self.bridges.is_empty() && self.proxy.is_none() {
			return Err(config_error(
				"specify at least one bridge or proxy, or omit tor_bridge for direct Tor",
			));
		}
		if self.bridges.is_empty() && !self.transports.is_empty() {
			return Err(config_error("transports require at least one bridge"));
		}

		// Stage all changes so a validation error cannot partially change a caller's config.
		let mut candidate = builder.clone();
		let mut protocols = HashSet::new();
		let mut transports = Vec::with_capacity(self.transports.len());
		for (index, configured) in self.transports.iter().enumerate() {
			let context = |message: &str| config_error(&format!("transports[{index}]: {message}"));
			if configured.protocols.is_empty() {
				return Err(context("protocols must not be empty"));
			}
			let mut names = Vec::with_capacity(configured.protocols.len());
			for name in &configured.protocols {
				let protocol: PtTransportName = name
					.parse()
					.map_err(|_| context("invalid transport protocol name"))?;
				if !protocols.insert(protocol.clone()) {
					return Err(context("a protocol is assigned more than once"));
				}
				names.push(protocol);
			}
			let mut transport = TransportConfigBuilder::default();
			transport.protocols(names);
			match (&configured.path, &configured.proxy_addr) {
				(Some(path), None) => {
					if !Path::new(path).is_absolute() {
						return Err(context("path must be an absolute helper executable path"));
					}
					transport
						.path(CfgPath::new_literal(path))
						.arguments(configured.arguments.clone());
					if let Some(run_on_startup) = configured.run_on_startup {
						transport.run_on_startup(run_on_startup);
					}
				}
				(None, Some(address)) => {
					if self.proxy.is_some() {
						return Err(context(
							"an upstream proxy cannot be enforced for an unmanaged transport; configure its proxy externally",
						));
					}
					if !configured.arguments.is_empty() || configured.run_on_startup.is_some() {
						return Err(context(
							"proxy_addr cannot be combined with arguments or run_on_startup",
						));
					}
					let address: SocketAddr = address
						.parse()
						.map_err(|_| context("proxy_addr must be an IP address and port"))?;
					if address.port() == 0 || address.ip().is_unspecified() {
						return Err(context(
							"proxy_addr must be a connectable IP address and port",
						));
					}
					transport.proxy_addr(address);
				}
				_ => return Err(context("specify exactly one of path or proxy_addr")),
			}
			transport
				.build()
				.map_err(|_| context("invalid Arti transport configuration"))?;
			transports.push(transport);
		}

		let mut bridges = Vec::with_capacity(self.bridges.len());
		for (index, line) in self.bridges.iter().enumerate() {
			let invalid_bridge = || config_error(&format!("bridges[{index}]: invalid bridge line"));
			let bridge: BridgeConfigBuilder = line.parse().map_err(|_| invalid_bridge())?;
			bridge.build().map_err(|_| invalid_bridge())?;
			let transport: TransportId = bridge
				.get_transport()
				.unwrap_or_default()
				.parse()
				.map_err(|_| invalid_bridge())?;
			if let Some(protocol) = transport.into_pluggable() {
				if !protocols.contains(&protocol) {
					return Err(config_error(&format!(
						"bridges[{index}]: no transport configured for the bridge protocol"
					)));
				}
			}
			bridges.push(bridge);
		}

		*candidate.bridges().bridges() = bridges;
		*candidate.bridges().transports() = transports;
		candidate
			.bridges()
			.enabled(BoolOrAuto::Explicit(!self.bridges.is_empty()));
		candidate.bridges().build().map_err(|_| {
			config_error("bridge and transport settings are inconsistent or unsupported by Arti")
		})?;
		let proxy = self
			.proxy
			.as_ref()
			.map(|proxy| {
				proxy.parse().map_err(|_| {
					config_error("invalid proxy URI; use socks4://, socks5://, or http:// with an IP address and explicit port")
				})
			})
			.transpose()?;
		candidate.channel().outbound_proxy(proxy);
		*builder = candidate;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::types::TorConfig;
	use mwc_crates::arti_client::TorClientConfig;

	const FINGERPRINT: &str = "0123456789ABCDEF0123456789ABCDEF01234567";

	fn parse(value: &str) -> Result<TorConfig, toml::de::Error> {
		toml::from_str(&format!("tor_bridge = {value}"))
	}

	fn validated(value: &str) -> Result<TorBridgeConfig, Error> {
		let connection = parse(value)
			.expect("valid TOML")
			.tor_bridge
			.expect("configured connection");
		connection.apply(&mut TorClientConfig::builder())?;
		Ok(connection)
	}

	fn helper_path() -> String {
		std::env::current_exe()
			.unwrap()
			.with_file_name("example-transport")
			.to_str()
			.unwrap()
			.to_owned()
	}

	fn managed(protocol: &str) -> TorBridgeConfig {
		TorBridgeConfig {
			bridges: vec![format!("{protocol} 192.0.2.1:443 {FINGERPRINT}")],
			transports: vec![TorTransportConfig {
				protocols: vec![protocol.to_owned()],
				path: Some(helper_path()),
				arguments: vec!["--example-option".to_owned()],
				run_on_startup: Some(true),
				..TorTransportConfig::default()
			}],
			proxy: None,
		}
	}

	#[test]
	fn direct_is_default_and_empty_settings_are_rejected() {
		assert!(TorConfig::default().tor_bridge.is_none());
		for value in ["{}", "{ bridges = [] }", "{ proxy = '' }"] {
			assert!(validated(value).is_err(), "accepted {value}");
		}
	}

	#[test]
	fn plain_bridges_build_without_a_helper() {
		let connection = validated(&format!(
			"{{ bridges = ['192.0.2.1:9001 {FINGERPRINT}', '[2001:db8::1]:9001 {FINGERPRINT}'] }}"
		))
		.unwrap();
		let mut builder = TorClientConfig::builder();
		connection.apply(&mut builder).unwrap();
		assert_eq!(builder.bridges().bridges().len(), 2);
		assert!(builder.bridges().transports().is_empty());
		assert_eq!(
			toml::Value::try_from(&*builder.bridges()).unwrap()["enabled"].as_bool(),
			Some(true)
		);
		builder.build().unwrap();
	}

	#[test]
	fn managed_transports_allow_common_and_custom_protocols() {
		for protocol in [
			"obfs4",
			"webtunnel",
			"snowflake",
			"meek_lite",
			"custom_transport",
		] {
			let connection = managed(protocol);
			let inline = connection.to_inline_toml().unwrap();
			assert!(!inline.contains('\n'));
			assert_eq!(validated(&inline).unwrap(), connection);
			let mut builder = TorClientConfig::builder();
			connection.apply(&mut builder).unwrap();
			assert_eq!(builder.bridges().transports().len(), 1);
			builder.build().unwrap();
		}
	}

	#[test]
	fn inline_serialization_keeps_control_characters_on_one_line() {
		let mut connection = managed("custom_transport");
		connection.transports[0].arguments = vec![
			"line\nbreak\r\n\twith\u{7f}control\u{1}bytes".into(),
			"quotes \" and \\ slashes ' plus 日本語".into(),
		];
		let output = connection.to_inline_toml().unwrap();
		assert!(!output.contains(['\n', '\r']));
		assert_eq!(parse(&output).unwrap().tor_bridge.unwrap(), connection);
	}

	#[test]
	fn unmanaged_transport_and_proxy_variants_build() {
		let connection = validated(&format!(
			"{{ bridges = ['obfs4 192.0.2.1:443 {FINGERPRINT}'], transports = [{{ protocols = ['obfs4'], proxy_addr = '127.0.0.1:1080' }}] }}"
		))
		.unwrap();
		let mut builder = TorClientConfig::builder();
		connection.apply(&mut builder).unwrap();
		builder.build().unwrap();

		for proxy in [
			"socks4://127.0.0.1:1080",
			"socks4a://alice@127.0.0.1:1080",
			"socks5://alice:secret@127.0.0.1:1080",
			"socks5h://[::1]:1080",
			"http://alice:secret@127.0.0.1:8080",
		] {
			let connection = validated(&format!("{{ proxy = '{proxy}' }}")).unwrap();
			let mut builder = TorClientConfig::builder();
			connection.apply(&mut builder).unwrap();
			assert!(builder.bridges().bridges().is_empty());
			assert_eq!(
				toml::Value::try_from(&*builder.bridges()).unwrap()["enabled"].as_bool(),
				Some(false)
			);
			assert!(builder
				.channel()
				.build()
				.unwrap()
				.outbound_proxy()
				.is_some());
			builder.build().unwrap();
		}
	}

	#[test]
	fn changing_connection_replaces_routing_and_errors_leave_it_intact() {
		let mut builder = TorClientConfig::builder();
		managed("webtunnel").apply(&mut builder).unwrap();
		validated("{ proxy = 'socks5://127.0.0.1:1080' }")
			.unwrap()
			.apply(&mut builder)
			.unwrap();
		assert!(builder.bridges().bridges().is_empty());
		assert!(builder.bridges().transports().is_empty());
		assert!(builder
			.channel()
			.build()
			.unwrap()
			.outbound_proxy()
			.is_some());
		let mut invalid = managed("webtunnel");
		invalid.proxy = Some("invalid".into());
		assert!(invalid.apply(&mut builder).is_err());
		assert!(builder.bridges().bridges().is_empty());
		assert!(builder
			.channel()
			.build()
			.unwrap()
			.outbound_proxy()
			.is_some());
		managed("webtunnel").apply(&mut builder).unwrap();
		assert!(builder
			.channel()
			.build()
			.unwrap()
			.outbound_proxy()
			.is_none());
	}

	#[test]
	fn every_bridge_protocol_must_be_defined_and_unambiguous() {
		let mut connection = managed("obfs4");
		connection
			.bridges
			.push(format!("webtunnel 192.0.2.2:443 {FINGERPRINT}"));
		assert!(connection.apply(&mut TorClientConfig::builder()).is_err());
		connection.bridges.pop();
		connection.transports.push(connection.transports[0].clone());
		assert!(connection.apply(&mut TorClientConfig::builder()).is_err());
		connection.transports.pop();
		connection.transports[0].proxy_addr = Some("127.0.0.1:1080".to_owned());
		assert!(connection.apply(&mut TorClientConfig::builder()).is_err());
	}

	#[test]
	fn malformed_or_ineffective_settings_are_rejected() {
		for value in [
			"{ bridges = ['invalid'] }",
			"{ proxy = 'https://127.0.0.1:8080' }",
			"{ proxy = 'socks5://proxy.example:1080' }",
			"{ proxy = 'socks4://alice:secret@127.0.0.1:1080' }",
			"{ proxy = 'socks5://127.0.0.1:1080', transports = [{ protocols = ['obfs4'], proxy_addr = '127.0.0.1:1081' }] }",
		] {
			assert!(validated(value).is_err(), "accepted {value}");
		}
		for value in [
			"{ proxy = 'socks5://127.0.0.1:1080', unknown = true }",
			"{ transports = [{ protocols = ['obfs4'], unknown = true }] }",
		] {
			assert!(parse(value).is_err());
		}
		for mutate in [
			|transport: &mut TorTransportConfig| transport.path = Some("relative-helper".into()),
			|transport: &mut TorTransportConfig| transport.path = None,
			|transport: &mut TorTransportConfig| transport.protocols.clear(),
			|transport: &mut TorTransportConfig| transport.protocols = vec!["bad name".into()],
			|transport: &mut TorTransportConfig| {
				transport.path = None;
				transport.proxy_addr = Some("127.0.0.1:1080".into());
			},
		] {
			let mut connection = managed("obfs4");
			mutate(&mut connection.transports[0]);
			assert!(connection.apply(&mut TorClientConfig::builder()).is_err());
		}
	}

	#[test]
	fn obsolete_bridge_names_and_string_values_are_rejected() {
		let bridge =
			format!("webtunnel 192.0.2.1:443 {FINGERPRINT} url=https://bridge.example/path");
		assert!(parse(&format!("'{bridge}'")).is_err());
		for obsolete_value in [
			format!("'{bridge}'"),
			"{ proxy = 'socks5://127.0.0.1:1080' }".into(),
		] {
			assert!(
				toml::from_str::<TorConfig>(&format!("webtunnel_bridge = {obsolete_value}"))
					.is_err()
			);
		}
	}

	#[test]
	fn debug_and_validation_errors_do_not_expose_credentials() {
		let config =
			parse("{ proxy = 'https://user:private-password@proxy.example:8080' }").unwrap();
		assert!(!format!("{config:?}").contains("private-password"));
		assert!(!config
			.tor_bridge
			.as_ref()
			.unwrap()
			.apply(&mut TorClientConfig::builder())
			.unwrap_err()
			.to_string()
			.contains("private-password"));
		let config = parse("{ bridges = ['invalid private-password'] }").unwrap();
		assert!(!config
			.tor_bridge
			.as_ref()
			.unwrap()
			.apply(&mut TorClientConfig::builder())
			.unwrap_err()
			.to_string()
			.contains("private-password"));
		let mut connection = managed("obfs4");
		connection.transports[0]
			.arguments
			.push("private-password".into());
		assert!(!format!("{:?}", connection.transports[0]).contains("private-password"));
	}
}
